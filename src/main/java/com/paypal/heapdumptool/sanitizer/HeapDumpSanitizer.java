package com.paypal.heapdumptool.sanitizer;

import com.paypal.heapdumptool.utils.InternalLogger;
import com.paypal.heapdumptool.utils.ProgressMonitor;
import org.apache.commons.lang3.function.Failable;
import org.apache.commons.lang3.mutable.MutableLong;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static com.paypal.heapdumptool.sanitizer.HeapRecord.HEAP_DUMP;
import static com.paypal.heapdumptool.sanitizer.HeapRecord.HEAP_DUMP_SEGMENT;
import static com.paypal.heapdumptool.sanitizer.HeapRecord.LOAD_CLASS;
import static com.paypal.heapdumptool.sanitizer.HeapRecord.STRING_IN_UTF8;
import static org.apache.commons.lang3.BooleanUtils.isFalse;

/**
 * Heavily based on: <br>
 *
 * <a href="https://html-preview.github.io/?url=https://github.com/JetBrains/jdk8u_jdk/blob/master/src/share/demo/jvmti/hprof/manual.html">
 * Heap Dump Binary Format Spec
 * </a> (highly recommended to make sense of the code in any meaningful way)
 * <br>
 *
 * <a href="https://github.com/openjdk/jdk/blob/a2bbf933d96dc4a911ac4b429519937d8dd83200/src/hotspot/share/services/heapDumper.cpp">
 * JDK heapDumper.cpp
 * </a>
 * <br>
 *
 * <a href="https://github.com/AdoptOpenJDK/jheappo">
 * JHeappo
 * </a> (clean modern code)
 * <br>
 *
 * <a href="https://github.com/apache/netbeans/tree/f2611e358c181935500ea4d9d9142fb850504a72/profiler/lib.profiler/src/org/netbeans/lib/profiler/heap">
 * NetBeans/VisualVM HeapDump code (old but reference)
 * </a>
 */
public class HeapDumpSanitizer {

    private static final String STRING_CODER_FIELD = "coder";
    private static final String STRING_VALUE_FIELD = "value";

    // Upper bound on the reusable tile buffer in applySanitization. Rounded down to a whole number
    // of tiles, so the effective size is at most this and at least one tile.
    private static final int TILED_BUFFER_SIZE = 8192;

    private static final InternalLogger LOGGER = InternalLogger.getLogger(HeapDumpSanitizer.class);

    // for debugging/testing
    private static final boolean ENABLE_SANITIZATION = isFalse(Boolean.getBoolean("disable-sanitization"));

    private InputStream inputStream;
    private OutputStream outputStream;
    private ProgressMonitor progressMonitor;
    private SanitizeCommand sanitizeCommand;

    /*
     * Resolved once per sanitize() run, not per query. SanitizeCommand.getSanitizationPolicy()
     * deliberately re-resolves the recorded flags on every call (a memo goes stale because picocli
     * parses the same command object more than once), so it allocates. The scope questions below are
     * asked once per field of every instance dump, which is as hot as this code gets.
     */
    private SanitizationPolicy sanitizationPolicy;

    private final Map<Long, String> stringIdToStringMap = new HashMap<>();
    private final Map<Long, Long> classObjectIdToStringIdMap = new HashMap<>();

    /*
     * Field layouts, keyed by class object id rather than class name. Class names are not unique in a
     * heap dump -- the same name loaded by two class loaders yields two distinct classes with
     * distinct layouts -- and sharing one layout between them mis-slots every field after the first
     * divergence: OBJECT references get classified as primitives and overwritten, and the widths
     * disagree so the reader runs off the end of the record. Class object ids are unique by
     * construction.
     */
    private final Map<Long, ClassObject> classObjectIdToClassObjectMap = new HashMap<>();
    private final Set<Long> excludeStringObjectIds = new HashSet<>();
    private final Set<Long> excludeStringValueArrayObjectIds = new HashSet<>();

    public void setInputStream(final InputStream inputStream) {
        this.inputStream = inputStream;
    }

    public void setOutputStream(final OutputStream outputStream) {
        this.outputStream = outputStream;
    }

    public void setProgressMonitor(final ProgressMonitor numBytesWrittenMonitor) {
        this.progressMonitor = numBytesWrittenMonitor;
    }

    public void setSanitizeCommand(final SanitizeCommand sanitizeCommand) {
        this.sanitizeCommand = sanitizeCommand;
    }

    public void sanitize() throws IOException {
        sanitizationPolicy = sanitizeCommand.getSanitizationPolicy();

        final Pipe pipe = new Pipe(inputStream, outputStream, progressMonitor);

        /*
         * The basic fields in the binary output are u1 (1 byte), u2 (2 byte), u4 (4 byte), and u8 (8 byte).
         *
         * The binary output begins with the information:
         * [u1]* An initial NULL terminated series of bytes representing the format name and version
         * u4 size of identifiers. Identifiers are used to represent UTF8 strings, objects, stack traces, etc.
         * u4 high word of number of milliseconds since 0:00 GMT, 1/1/70
         * u4 low word of number of milliseconds since 0:00 GMT, 1/1/70
         */
        final String version = pipe.pipeNullTerminatedString().trim();
        LOGGER.debug("Heap Dump Version: {}", version);

        pipe.setIdSize((int) pipe.pipeU4());
        LOGGER.debug("Id Size: {}", pipe.getIdSize());
        pipe.pipe(8);

        /*
         * Followed by a sequence of records that look like:
         * u1		TAG: denoting the type of the record
         * u4		TIME: number of microseconds since the time stamp in the header
         * u4		LENGTH: number of bytes that follow this u4 field and belong to this record
         * [u1]*	BODY: as many bytes as specified in the above u4 field
         */

        while (true) {
            final int tag = pipe.pipeU1IfPossible();
            if (tag == -1) {
                break;
            }
            final HeapRecord heapRecord = HeapRecord.findByTag(tag);

            pipe.pipeU4(); // timestamp
            final long length = pipe.pipeU4();
            LOGGER.debug("Tag: {}", tag);
            LOGGER.debug("Length: {}", length);

            if (heapRecord == HEAP_DUMP || heapRecord == HEAP_DUMP_SEGMENT) {
                final Pipe heapPipe = pipe.newInputBoundedPipe(length);
                copyHeapDumpRecord(heapPipe);

            } else if (heapRecord == STRING_IN_UTF8) {
                copyStringInUtf8Record(pipe, length);

            } else if (heapRecord == LOAD_CLASS) {
                copyLoadClassRecord(pipe);

            } else {
                pipe.pipe(length);
            }
        }
    }

    private void copyLoadClassRecord(final Pipe pipe) throws IOException {
        pipe.pipeU4(); // class serial number
        final long classObjectId = pipe.pipeId();// class object ID
        pipe.pipeU4(); // stack trace serial number
        final long id = pipe.pipeId();// class name string ID
        if (shouldTrackClassMetadata() || isStringClass(classObjectId)) {
            classObjectIdToStringIdMap.put(classObjectId, id);
        }
    }

    private boolean isStringClass(final long classObjectId) {
        return getClassName(classObjectId).equals(String.class.getName());
    }

    private void copyStringInUtf8Record(final Pipe pipe, final long length) throws IOException {
        final long id = pipe.pipeId();
        final Pipe dataPipe = pipe.newInputBoundedPipe(length - pipe.getIdSize());
        final String string = dataPipe.pipeString(length);
        if (shouldTrackClassMetadata() || sanitizeCommand.isForceMatchStringCoder()) {
            stringIdToStringMap.put(id, string.replace("/", "."));
        }
    }

    private void copyHeapDumpRecord(final Pipe pipe) throws IOException {
        while (true) {
            final int tag = pipe.pipeU1IfPossible();
            if (tag == -1) {
                break;
            }
            LOGGER.debug("Heap Dump Tag: {}", tag);

            final long id = pipe.pipeId();
            switch (tag) {
                case 0xFF:
                    break;

                case 0x01:
                    pipe.pipeId();
                    break;

                case 0x02:
                case 0x03:
                    pipe.pipe(4 + 4);
                    break;

                case 0x04:
                    pipe.pipeU4();
                    break;

                case 0x05:
                    break;

                case 0x06:
                    pipe.pipeU4();
                    break;

                case 0x07:
                    break;

                case 0x08:
                    pipe.pipe(4 + 4);
                    break;

                case 0x20:
                    copyHeapDumpClassDump(pipe, id);
                    break;

                case 0x21:
                    copyHeapDumpInstanceDump(pipe, id);
                    break;

                case 0x22:
                    copyHeapDumpObjectArrayDump(pipe);
                    break;

                case 0x23:
                    copyHeapDumpPrimitiveArrayDump(pipe, id);
                    break;

                default:
                    throw new IllegalArgumentException("" + tag);
            }
        }
    }

    private void copyHeapDumpClassDump(final Pipe pipe, final long classObjectId) throws IOException {
        pipe.pipeU4(); // stacktrace
        final long superClassObjectId = pipe.pipeId();
        pipe.pipeId(); // class loader object id
        pipe.pipeId(); // signers object id
        pipe.pipeId(); // protection domain
        pipe.pipeId(); // reserved
        pipe.pipeId(); // reserved
        pipe.pipeU4(); // instance size

        final int numConstantPoolRecords = pipe.pipeU2();
        for (int i = 0; i < numConstantPoolRecords; i++) {
            pipe.pipeU2();
            final int entryType = pipe.pipeU1();
            pipeBasicType(pipe, entryType);
        }

        final int numStaticFields = pipe.pipeU2();
        for (int i = 0; i < numStaticFields; i++) {
            pipe.pipeId(); // field name id
            final int entryType = pipe.pipeU1();
            pipeStaticField(pipe, entryType);
        }

        final ClassObject classObject = new ClassObject(classObjectId, superClassObjectId);
        if (shouldTrackClassMetadata() || isStringClass(classObjectId)) {
            classObjectIdToClassObjectMap.putIfAbsent(classObjectId, classObject);
        }
        final int numInstanceFields = pipe.pipeU2();
        for (int i = 0; i < numInstanceFields; i++) {
            final long fieldNameStringId = pipe.pipeId();
            final int fieldType = pipe.pipeU1();
            final String fieldName = stringIdToStringMap.getOrDefault(fieldNameStringId, "");
            final BasicType basicType = BasicType.findByU1Code(fieldType).orElseThrow(IllegalStateException::new);
            classObject.fields.add(new Field(fieldName, basicType));
        }
    }

    private boolean shouldTrackClassMetadata() {
        return !sanitizeCommand.getExcludeStringFields().isEmpty()
                || sanitizationPolicy.isAnyFieldSanitized();
    }

    private boolean isAssignableClassWithExcludeStringField(final long classObjectId) {
        return getClassNameHierarchy(classObjectId)
                .anyMatch(sanitizeCommand::isExactClassWithExcludeStringField);
    }

    private void pipeStaticField(final Pipe pipe, final int entryType) throws IOException {
        final int valueSize = BasicType.findValueSize(entryType, pipe.getIdSize());
        if (shouldSanitizeField(entryType)) {
            final BasicType basicType = BasicType.findByU1Code(entryType).orElseThrow(IllegalStateException::new);
            applySanitization(pipe, basicType, valueSize);
        } else {
            pipe.pipe(valueSize);
        }
    }

    private void pipeBasicType(final Pipe pipe, final int entryType) throws IOException {
        final int valueSize = BasicType.findValueSize(entryType, pipe.getIdSize());
        pipe.pipe(valueSize);
    }

    /*
     *
     * INSTANCE DUMP    0x21
     *
     * ID  object ID
     * u4  stack trace serial number
     * ID  class object ID
     * u4  number of bytes that follow
     * [value]*  instance field values (this class, followed by super class, etc)
     */
    private void copyHeapDumpInstanceDump(final Pipe pipe, final long objectId) throws IOException {
        pipe.pipeU4();
        final long classObjectId = pipe.pipeId();
        final long numBytes = pipe.pipeU4();
        final String className = getClassName(classObjectId);

        if (classObjectIdToClassObjectMap.get(classObjectId) == null) {
            /*
             * No CLASS DUMP was seen for this class, so its field layout is unknown. A LOAD_CLASS
             * record without a matching CLASS DUMP does occur in real dumps. Walking fields needs an
             * exact layout: guessing one mis-slots every field, which overwrites OBJECT references
             * and desynchronizes the reader from the record boundary. Pipe the body through instead.
             */
            pipe.pipe(numBytes);

        } else if (sanitizeCommand.isForceMatchStringCoder() && className.equals(String.class.getName())) {
            copyStringsInstanceFields(pipe, classObjectId, objectId, numBytes);

        } else if (isAssignableClassWithExcludeStringField(classObjectId)
                || sanitizationPolicy.isAnyFieldSanitized()) {
            copyInstanceAndSanitizeSomeFields(pipe, classObjectId, objectId, numBytes);

        } else {
            // nothing to sanitize in the instance dump; arrays are handled in the array dump section
            pipe.pipe(numBytes);
        }
    }

    /*
     * java.lang.String gets its own field walk because String.coder is never a generic BYTE field.
     * On JDK 9+, coder selects how the backing byte[] is decoded (LATIN1=0, UTF16=1); every other
     * value is illegal and breaks string rendering for the whole dump in MAT and JVisualVM. So the
     * only two things that may be written are the original value and, when the backing array is
     * genuinely being replaced with single-byte values, 0.
     *
     * On JDK 8 String has no coder field at all, and the loop simply never matches it.
     */
    private void copyStringsInstanceFields(final Pipe pipe,
                                           final long classObjectId,
                                           final long objectId,
                                           long numBytes) throws IOException {
        // never null: copyHeapDumpInstanceDump checks the layout before choosing this branch
        final ClassObject classObject = classObjectIdToClassObjectMap.get(classObjectId);
        for (final Field field : classObject.fields) {
            final int fieldSize = field.type.getValueSize(pipe.getIdSize());

            if (STRING_CODER_FIELD.equals(field.name)) {
                pipeStringCoder(pipe, objectId);

            } else if (STRING_VALUE_FIELD.equals(field.name)) {
                final long id = pipe.pipeId();
                if (excludeStringObjectIds.contains(objectId)) {
                    excludeStringValueArrayObjectIds.add(id);
                }

            } else if (shouldSanitizeField(field.type.getU1Code())) {
                applySanitization(pipe, field.type, fieldSize);

            } else {
                pipe.pipe(fieldSize);
            }

            numBytes -= fieldSize;
        }

        pipe.pipe(numBytes);
    }

    /*
     * Forces the coder to LATIN1 if and only if THIS String's backing byte[] is actually being
     * overwritten with a single-byte replacement, which every byte[] replacement is. Then any
     * surviving coder==1 would claim the replaced bytes are UTF-16 code units and render as garbage,
     * so 0 is the truthful value. That is:
     *
     *     --force-string-coder-match=true
     *  && byte arrays are in scope (not --sanitize-byte-arrays=false, not --sanitize-all=false)
     *  && this String is not itself excluded by --exclude-string-fields
     *
     * The last condition is per-object, not global: --exclude-string-fields preserves the backing
     * array of the specific Strings it names (via excludeStringValueArrayObjectIds, checked in
     * shouldApplyArraySanitization) while every other byte[] in the dump is still replaced. Forcing 0
     * over such a surviving UTF-16 array reinterprets each code unit as two LATIN1 characters, i.e.
     * mojibake at double length. It matters by default, because -e defaults to the thread and thread
     * group name fields.
     *
     * In every other case the original coder is piped through unchanged.
     */
    private void pipeStringCoder(final Pipe pipe, final long objectId) throws IOException {
        final boolean forceLatin1 = sanitizeCommand.isForceMatchStringCoder()
                && sanitizationPolicy.sanitizeArray(BasicType.BYTE)
                && !excludeStringObjectIds.contains(objectId);
        if (forceLatin1) {
            pipe.readU1();
            pipe.writeU1(0);
        } else {
            pipe.pipeU1();
        }
    }

    private Stream<ClassObject> getClassHierarchy(final long classObjectId) {
        ClassObject classObject = classObjectIdToClassObjectMap.get(classObjectId);
        Stream<ClassObject> stream = Stream.of();
        while (classObject != null) {
            stream = Stream.concat(stream, Stream.of(classObject));
            classObject = classObjectIdToClassObjectMap.get(classObject.superClassObjectId);
        }
        return stream;
    }

    private Stream<String> getClassNameHierarchy(final long classObjectId) {
        return getClassHierarchy(classObjectId)
                .map(classObject -> classObject.id)
                .map(this::getClassName);
    }

    private Stream<Field> getAllFieldsInClassHierarchy(final long classObjectId) {
        return getClassHierarchy(classObjectId).flatMap(classObject -> classObject.fields.stream());
    }

    private Collection<String> getExcludeStringFieldsInClassHierarchy(final long classObjectId) {
        return getClassNameHierarchy(classObjectId)
                .map(sanitizeCommand::getExcludeStringFields)
                .flatMap(Collection::stream)
                .collect(Collectors.toList());
    }

    private void copyInstanceAndSanitizeSomeFields(final Pipe pipe,
                                                   final long classObjectId,
                                                   final long objectId,
                                                   final long numBytes) throws IOException {
        final Collection<String> excludeStringFields = getExcludeStringFieldsInClassHierarchy(classObjectId);
        // reached for java.lang.String only when --force-string-coder-match=false
        final boolean isStringClass = isStringClass(classObjectId);
        final MutableLong numBytesMutable = new MutableLong(numBytes);
        getAllFieldsInClassHierarchy(classObjectId).forEach(field -> {
            final int fieldSize = field.type.getValueSize(pipe.getIdSize());

            if (excludeStringFields.contains(field.name)) {
                final long id = Failable.call(pipe::pipeId);
                excludeStringObjectIds.add(id);

            } else if (isStringClass && STRING_CODER_FIELD.equals(field.name)) {
                // never a generic BYTE field: see pipeStringCoder
                Failable.run(() -> pipeStringCoder(pipe, objectId));

            } else if (shouldSanitizeField(field.type.getU1Code())) {
                Failable.run(() -> applySanitization(pipe, field.type, fieldSize));

            } else {
                Failable.run(() -> pipe.pipe(fieldSize));
            }
            numBytesMutable.subtract(fieldSize);
        });

        pipe.pipe(numBytesMutable.longValue());
    }

    private String getClassName(final long classObjectId) {
        final Long stringId = classObjectIdToStringIdMap.get(classObjectId);
        return stringIdToStringMap.getOrDefault(stringId, "");
    }

    private boolean shouldSanitizeField(final int fieldType) {
        if (!ENABLE_SANITIZATION) {
            return false;
        }

        final BasicType basicType = BasicType.findByU1Code(fieldType).orElse(BasicType.OBJECT);
        return sanitizationPolicy.sanitizeField(basicType);
    }

    private void copyHeapDumpObjectArrayDump(final Pipe pipe) throws IOException {
        pipe.pipeU4();
        final long numElements = pipe.pipeU4();
        pipe.pipeId();
        for (long i = 0; i < numElements; i++) {
            pipe.pipeId();
        }
    }

    /*
     * PRIMITIVE ARRAY DUMP	 * 	0x23
     * 	ID	array object ID
     * 	u4	stack trace serial number
     * 	u4	number of elements
     * 	u1	element type (See Basic Type)
     * 	[u1]*	elements (packed array)
     */
    private void copyHeapDumpPrimitiveArrayDump(final Pipe pipe, final long objectId) throws IOException {
        pipe.pipeU4();
        final long numElements = pipe.pipeU4();

        final int elementType = pipe.pipeU1();
        final long elementSize = BasicType.findValueSize(elementType, pipe.getIdSize());

        final long numBytes = Math.multiplyExact(numElements, elementSize);

        if (shouldApplyArraySanitization(objectId, elementType)) {
            final BasicType basicType = BasicType.findByU1Code(elementType).orElseThrow(IllegalStateException::new);
            applySanitization(pipe, basicType, numBytes);
        } else {
            pipe.pipe(numBytes);
        }
    }

    private boolean shouldApplyArraySanitization(final long objectId, final int elementType) {
        if (!ENABLE_SANITIZATION) {
            return false;
        }

        if (excludeStringValueArrayObjectIds.contains(objectId)) {
            return false;
        }

        return BasicType.findByU1Code(elementType)
                .filter(sanitizationPolicy::sanitizeArray)
                .isPresent();
    }

    /*
     * Overwrites the region by tiling the type's replacement bytes across it.
     *
     * Tiling is always exactly aligned: a non-array field's size is its type's width, and a
     * primitive array's region is numElements * elementSize. So numBytes is always a whole multiple
     * of the replacement's length, no partial tile can occur, and every sanitized value reads back
     * as exactly the requested replacement. The tiled buffer holds a whole number of tiles for the
     * same reason: any prefix of it whose length is a multiple of the replacement's length is itself
     * correctly tiled, so writing it in chunks cannot shift the alignment.
     *
     * Deliberately not commons-io InfiniteCircularInputStream: it rejects any repeated byte equal to
     * -1, so a perfectly legal replacement containing 0xFF -- e.g. --sanitize-byte-replacement=-1,
     * --sanitize-int-replacement=255, or --sanitize-double-replacement=-1.0 -- would throw the first
     * time a matching slot was sanitized, aborting the run mid-stream and leaving a truncated
     * output file behind.
     */
    private void applySanitization(final Pipe pipe, final BasicType type, final long numBytes) throws IOException {
        pipe.skipInput(numBytes);
        final byte[] replacement = sanitizationPolicy.replacement(type);
        final byte[] tiledBuffer = newTiledBuffer(replacement, numBytes);

        long numBytesRemaining = numBytes;
        while (numBytesRemaining > 0) {
            final int count = (int) Math.min(tiledBuffer.length, numBytesRemaining);
            pipe.write(tiledBuffer, 0, count);
            numBytesRemaining -= count;
        }
    }

    /**
     * A buffer of whole replacement tiles, no larger than the region it will fill.
     */
    private static byte[] newTiledBuffer(final byte[] replacement, final long numBytes) {
        final long wantedSize = Math.min(numBytes, TILED_BUFFER_SIZE);
        final int numTiles = Math.max(1, (int) (wantedSize / replacement.length));
        final byte[] buffer = new byte[numTiles * replacement.length];

        if (replacement.length == 1) {
            Arrays.fill(buffer, replacement[0]);
        } else {
            for (int offset = 0; offset < buffer.length; offset += replacement.length) {
                System.arraycopy(replacement, 0, buffer, offset, replacement.length);
            }
        }
        return buffer;
    }
}
