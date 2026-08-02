package com.paypal.heapdumptool.sanitizer;

import com.paypal.heapdumptool.utils.InternalLogger;
import com.paypal.heapdumptool.utils.ProgressMonitor;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static com.paypal.heapdumptool.sanitizer.HeapRecord.HEAP_DUMP;
import static com.paypal.heapdumptool.sanitizer.HeapRecord.HEAP_DUMP_SEGMENT;
import static com.paypal.heapdumptool.sanitizer.HeapRecord.LOAD_CLASS;
import static com.paypal.heapdumptool.sanitizer.HeapRecord.STRING_IN_UTF8;
import static org.apache.commons.lang3.BooleanUtils.isFalse;

/**
 * Heavily based on: <br>
 *
 * <a href="https://html-preview.github.io/?url=https://github.com/openjdk/jdk8/blob/master/jdk/src/share/demo/jvmti/hprof/manual.html">
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

    private static final InternalLogger LOGGER = InternalLogger.getLogger(HeapDumpSanitizer.class);

    private InputStream inputStream;
    private OutputStream outputStream;
    private ProgressMonitor progressMonitor;
    private SanitizeCommand sanitizeCommand;

    /*
     * Debugging switch to disable sanitization. Useful for verifying that the tool is able to correctly parse and
     * create valid heap dump files.
     */
    private boolean sanitizationEnabled = isFalse(Boolean.getBoolean("disable-sanitization"));

    /*
     * True for the metadata-collection pass, whose output is discarded.
     */
    private boolean preprocessingOnly;

    /*
     * Resolved once per sanitize() run, not per query. SanitizeCommand.getSanitizationPolicy()
     * deliberately re-resolves the recorded flags on every call (a memo goes stale because picocli
     * parses the same command object more than once), so it allocates. The scope questions below are
     * asked once per field of every instance dump, which is as hot as this code gets.
     */
    private SanitizationPolicy sanitizationPolicy;

    /*
     * Also resolved once per run, for the same reason: getExcludeStringFields() is memoized but the
     * emptiness question is asked once per instance dump and once per class dump.
     */
    private boolean hasExcludeStringFields;

    private final Map<Long, String> stringIdToStringMap = new HashMap<>();
    private final Map<Long, Long> classObjectIdToStringIdMap = new HashMap<>();

    /*
     * The string ids this run actually reads back, recorded during the metadata pass and consulted by
     * the writing pass.
     *
     * stringIdToStringMap is queried for exactly two things -- class names (getClassName) and instance
     * field names (class dumps) -- but STRING_IN_UTF8 records carry every string in the heap, so on a
     * 1.2 GB dump it stored around 1.4 mil entries of which only about 100k were ever looked up. The
     * other ~90% are heap object contents that nothing queries, retaining a few hundred MB for the
     * length of the run.
     *
     * The ids cannot be known on a single pass: STRING_IN_UTF8 records precede the LOAD_CLASS and class
     * dump records that reference them. They can be known on the second, because both passes share one
     * instance -- so the metadata pass notes every id it queries, and the writing pass keeps only
     * those. Null until a metadata pass has finished, meaning "keep everything", which is what a
     * single-pass run and the metadata pass itself both need.
     */
    private Set<Long> neededStringIds;
    private Set<Long> queriedStringIds;

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

    public void setPreprocessingOnly(final boolean preprocessingOnly) {
        this.preprocessingOnly = preprocessingOnly;
        this.sanitizationEnabled = !preprocessingOnly && isFalse(Boolean.getBoolean("disable-sanitization"));
        if (preprocessingOnly) {
            /*
             * Entering the metadata pass: start recording which string ids get read back, and keep
             * every string for the duration, since the set is not known until this pass ends.
             */
            queriedStringIds = new HashSet<>();
            neededStringIds = null;
        } else if (queriedStringIds != null) {
            /*
             * Leaving it: the recorded ids are the only ones the writing pass can read back, because
             * both passes see the same records in the same order and ask the same questions of them.
             * Dropping the recorder also stops the writing pass from growing a set nothing consults.
             */
            neededStringIds = queriedStringIds;
            queriedStringIds = null;

            /*
             * Both passes share this map, so the entries the metadata pass already stored have to go
             * too -- gating the writing pass's puts alone would leave all of them resident. The
             * writing pass repopulates what it keeps from the same records, in the same order.
             */
            final int storedBefore = stringIdToStringMap.size();
            stringIdToStringMap.keySet().retainAll(neededStringIds);
            LOGGER.debug("Retained {} of {} strings for the sanitization pass", stringIdToStringMap.size(), storedBefore);
        }
    }

    public void sanitize() throws IOException {
        sanitizationPolicy = sanitizeCommand.getSanitizationPolicy();
        hasExcludeStringFields = !sanitizeCommand.getExcludeStringFields().isEmpty();

        final Pipe pipe = preprocessingOnly
                          ? Pipe.readOnlyPipe(inputStream, progressMonitor)
                          : new Pipe(inputStream, outputStream, progressMonitor);

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

    /*
     * STRING IN UTF8  0x01
     *
     * ID     string id
     * [u1]*  UTF8 bytes, for the rest of the record (no trailing NUL)
     *
     * The body length is the record length less the leading id, and the pipe now reads exactly that many
     * bytes. Previously the body was read through a per-record bounded child pipe, which is where the
     * correct length lived: the length argument was the whole record length, over-long by idSize, and
     * only the child's bound stopped it from reading into the next record. Passing the true length makes
     * the bound redundant, which drops three allocations (child Pipe, DataInputStream,
     * BoundedInputStream) from the most numerous record type in a dump.
     */
    private void copyStringInUtf8Record(final Pipe pipe, final long length) throws IOException {
        final long id = pipe.pipeId();
        final long bodyLength = length - pipe.getIdSize();

        /*
         * Decided before reading, so a record nothing will store is never decoded. The map keeps only
         * about 100k of some 1.4 mil records on a 1.2 GB dump, so the other ~90% were being turned into
         * a String -- and, for the half of them containing a slash, a second String -- to be dropped.
         */
        if (isNeededStringId(id) && (shouldTrackClassMetadata() || sanitizeCommand.isForceMatchStringCoder())) {
            stringIdToStringMap.put(id, pipe.pipeStringReplacing(bodyLength, '/', '.'));
        } else {
            pipe.pipeExactly(bodyLength);
        }
    }

    /*
     * The body of a HEAP DUMP or HEAP DUMP SEGMENT record: a series of sub-records, each with its own
     * u1 tag and its own layout.
     *
     * ROOT UNKNOWN         0xFF  ID object id
     * ROOT JNI GLOBAL      0x01  ID object id; ID JNI global ref id
     * ROOT JNI LOCAL       0x02  ID object id; u4 thread serial; u4 frame number (-1 for empty)
     * ROOT JAVA FRAME      0x03  ID object id; u4 thread serial; u4 frame number (-1 for empty)
     * ROOT NATIVE STACK    0x04  ID object id; u4 thread serial
     * ROOT STICKY CLASS    0x05  ID object id
     * ROOT THREAD BLOCK    0x06  ID object id; u4 thread serial
     * ROOT MONITOR USED    0x07  ID object id
     * ROOT THREAD OBJECT   0x08  ID thread object id; u4 thread serial; u4 stack trace serial
     * CLASS DUMP           0x20  ID class object id; ...
     * INSTANCE DUMP        0x21  ID object id; ...
     * OBJECT ARRAY DUMP    0x22  ID array object id; ...
     * PRIMITIVE ARRAY DUMP 0x23  ID array object id; ...
     *
     * Only the last four DUMP types hold the field values and array elements this tool sanitizes.
     *
     * An unknown tag throws instead of being skipped over. A sub-record's size is only knowable from
     * its layout, so there is no length to skip by: a tag this switch does not know means the rest of
     * the body can no longer be located, and carrying on would write a corrupt dump.
     */
    private void copyHeapDumpRecord(final Pipe pipe) throws IOException {
        while (true) {
            final int tag = pipe.pipeU1IfPossible();
            if (tag == -1) {
                break;
            }
            LOGGER.debug("Heap Dump Tag: {}", tag);

            final long id = pipe.pipeId();
            switch (tag) {
                case 0xFF: // ROOT UNKNOWN
                    break;

                case 0x01: // ROOT JNI GLOBAL
                    pipe.pipeId(); // JNI global ref id
                    break;

                case 0x02: // ROOT JNI LOCAL
                case 0x03: // ROOT JAVA FRAME
                    pipe.pipe(4 + 4); // thread serial, frame number
                    break;

                case 0x04: // ROOT NATIVE STACK
                    pipe.pipeU4(); // thread serial
                    break;

                case 0x05: // ROOT STICKY CLASS
                    break;

                case 0x06: // ROOT THREAD BLOCK
                    pipe.pipeU4(); // thread serial
                    break;

                case 0x07: // ROOT MONITOR USED
                    break;

                case 0x08: // ROOT THREAD OBJECT
                    pipe.pipe(4 + 4); // thread serial, stack trace serial
                    break;

                case 0x20: // CLASS DUMP
                    copyHeapDumpClassDump(pipe, id);
                    break;

                case 0x21: // INSTANCE DUMP
                    copyHeapDumpInstanceDump(pipe, id);
                    break;

                case 0x22: // OBJECT ARRAY DUMP
                    // the array object id is not needed: elements are references, never sanitized
                    copyHeapDumpObjectArrayDump(pipe);
                    break;

                case 0x23: // PRIMITIVE ARRAY DUMP
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
            recordStringIdQuery(fieldNameStringId);
            final String fieldName = stringIdToStringMap.getOrDefault(fieldNameStringId, "");
            final BasicType basicType = requireBasicType(fieldType);
            classObject.fields.add(new Field(fieldName, basicType));
        }
    }

    /**
     * The type for a code that has already been validated as a basic type, e.g. by a preceding
     * {@link BasicType#findValueSize(int, int)} or scope check.
     */
    private static BasicType requireBasicType(final int u1Code) {
        final BasicType basicType = BasicType.byU1Code(u1Code);
        if (basicType == null) {
            throw new IllegalStateException("Unknown basic type code: " + u1Code);
        }
        return basicType;
    }

    private boolean shouldTrackClassMetadata() {
        return !sanitizeCommand.getExcludeStringFields().isEmpty()
                || sanitizationPolicy.isAnyFieldSanitized();
    }

    private boolean isAssignableClassWithExcludeStringField(final long classObjectId) {
        for (ClassObject c = classHierarchyStart(classObjectId); c != null; c = superClassOf(c)) {
            if (sanitizeCommand.isExactClassWithExcludeStringField(getClassName(c.id))) {
                return true;
            }
        }
        return false;
    }

    private void pipeStaticField(final Pipe pipe, final int entryType) throws IOException {
        final int valueSize = BasicType.findValueSize(entryType, pipe.getIdSize());
        if (shouldSanitizeField(entryType)) {
            final BasicType basicType = requireBasicType(entryType);
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

        } else if ((sanitizeCommand.isForceMatchStringCoder() || hasExcludeStringFields)
                && className.equals(String.class.getName())) {
            /*
             * Not gated on -f alone. -e selects fields to preserve and -f controls how coder is
             * rewritten, so they must stay independent -- but only this walk reads String.value,
             * which is the sole bridge from an excluded String's instance id to its backing array
             * id. Gating the walk on -f let -f=false silently disable -e: the bridge never ran,
             * excludeStringValueArrayObjectIds stayed empty, and every excluded String's payload
             * was replaced anyway. pipeStringCoder keeps -f's own observable behavior.
             */
            copyStringsInstanceFields(pipe, classObjectId, objectId, numBytes);

        } else if (isAssignableClassWithExcludeStringField(classObjectId)
                || sanitizationPolicy.isAnyFieldSanitized()) {
            copyInstanceAndSanitizeSomeFields(pipe, classObjectId, numBytes);

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

        /*
         * This String's backing array id, once the value field has been read. Tracked so the coder
         * decision can be made from the ARRAY's preservation state rather than this instance's id:
         * two Strings can share one backing byte[] (new String(String), substring(0) and the other
         * zero-copy paths all alias it), so a String that is not itself named by -e can still sit
         * over an array that -e preserved on another String's behalf.
         */
        long valueArrayObjectId = -1;
        boolean sawValueField = false;

        for (final Field field : classObject.fields) {
            final int fieldSize = field.type.getValueSize(pipe.getIdSize());

            if (field.type == BasicType.BYTE && STRING_CODER_FIELD.equals(field.name)) {
                /*
                 * An unread value field means the layout puts coder first, so the backing array is
                 * not yet known. Treat it as preserved: piping a coder through is the conservative
                 * error (at worst a replaced payload renders as escapes rather than '*'), whereas
                 * forcing 0 over a surviving UTF-16 array corrupts a value -e was asked to keep.
                 */
                final boolean backingArrayPreserved = !sawValueField
                        || excludeStringValueArrayObjectIds.contains(valueArrayObjectId);
                pipeStringCoder(pipe, backingArrayPreserved);

            } else if (field.type == BasicType.OBJECT && STRING_VALUE_FIELD.equals(field.name)) {
                final long id = pipe.pipeId();
                valueArrayObjectId = id;
                sawValueField = true;
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
     * Forces the coder to LATIN1 if and only if the backing byte[] this String reads is actually
     * being overwritten with a single-byte replacement, which every byte[] replacement is. Then any
     * surviving coder==1 would claim the replaced bytes are UTF-16 code units and render as garbage,
     * so 0 is the truthful value. That is:
     *
     *     --force-string-coder-match=true
     *  && byte arrays are in scope (not excluded by --target)
     *  && the backing array is not preserved by --exclude-string-fields
     *
     * The last condition is keyed by the BACKING ARRAY, not by this String's own object id, because
     * the two are not interchangeable: on JDK 9+ several String instances can share one backing
     * byte[] -- new String(String), substring(0) and the other zero-copy paths all alias it -- so a
     * String that -e never named can still read an array that -e preserved on another String's
     * behalf. Keying on the instance id forced 0 over such a surviving UTF-16 array, reinterpreting
     * each code unit as two LATIN1 characters: mojibake at double length, in a String whose bytes
     * were in fact preserved. Array preservation is decided in shouldApplyArraySanitization from the
     * same excludeStringValueArrayObjectIds set, so the two answers now agree by construction.
     *
     * In every other case the original coder is piped through unchanged.
     */
    private void pipeStringCoder(final Pipe pipe, final boolean backingArrayPreserved) throws IOException {
        final boolean forceLatin1 = sanitizeCommand.isForceMatchStringCoder()
                && sanitizationPolicy.sanitizeArray(BasicType.BYTE)
                && !backingArrayPreserved;
        if (forceLatin1) {
            pipe.readU1();
            pipe.writeU1(0);
        } else {
            pipe.pipeU1();
        }
    }

    /*
     * The class object a hierarchy walk starts from, or null if no CLASS DUMP was seen for the id.
     * Walk on with superClassOf. Each walk visits the class then its ancestors, which is the order
     * HPROF lays instance fields in.
     *
     * Iterating the chain in place rather than collecting it: the walk runs up to three times per
     * instance dump, and the previous Stream.concat-per-level version was one of the largest
     * allocation sites in a profiled run -- each level added a concatenated stream, a spliterator and
     * a lambda capture. Collecting into a list per walk is cheaper but still allocates per instance;
     * in place allocates nothing at all.
     *
     * Deliberately not memoized per class object id: a CLASS DUMP can appear after instances of the
     * class it describes, so a hierarchy captured from an earlier instance can be shorter than the
     * truth.
     */
    private ClassObject classHierarchyStart(final long classObjectId) {
        return classObjectIdToClassObjectMap.get(classObjectId);
    }

    private ClassObject superClassOf(final ClassObject classObject) {
        return classObjectIdToClassObjectMap.get(classObject.superClassObjectId);
    }

    /*
     * Returns the empty list without allocating in the common case: -e names a handful of classes, so
     * almost no instance dump in a real heap contributes anything here.
     */
    private Collection<String> getExcludeStringFieldsInClassHierarchy(final long classObjectId) {
        List<String> fields = null;
        for (ClassObject c = classHierarchyStart(classObjectId); c != null; c = superClassOf(c)) {
            final List<String> classFields = sanitizeCommand.getExcludeStringFields(getClassName(c.id));
            if (!classFields.isEmpty()) {
                if (fields == null) {
                    fields = new ArrayList<>(classFields);
                } else {
                    fields.addAll(classFields);
                }
            }
        }
        return fields == null ? Collections.<String>emptyList() : fields;
    }

    private void copyInstanceAndSanitizeSomeFields(final Pipe pipe,
                                                   final long classObjectId,
                                                   final long numBytes) throws IOException {
        final Collection<String> excludeStringFields = getExcludeStringFieldsInClassHierarchy(classObjectId);
        // reached for java.lang.String only when -f=false AND -e names nothing, i.e. when there is
        // no coder to force and no exclusion to bridge; copyStringsInstanceFields handles the rest
        final boolean isStringClass = isStringClass(classObjectId);
        long numBytesRemaining = numBytes;
        for (ClassObject c = classHierarchyStart(classObjectId); c != null; c = superClassOf(c)) {
            for (final Field field : c.fields) {
                final int fieldSize = field.type.getValueSize(pipe.getIdSize());

                if (field.type == BasicType.OBJECT && excludeStringFields.contains(field.name)) {
                    /*
                     * Only a reference field can name a String whose payload is preserved, and the
                     * type check is what keeps the walk aligned. pipeId() always reads getIdSize()
                     * bytes while the ledger below subtracts the field's real width, so taking this
                     * arm for a narrower field -- -e=java.lang.String#coder, or any byte/int/char
                     * field -- over-read the difference, mis-sliced every following field, lost the
                     * sub-record boundary and aborted the run on a garbage tag, leaving a truncated
                     * output. A non-reference -e target is treated like any other field instead.
                     */
                    final long id = pipe.pipeId();
                    excludeStringObjectIds.add(id);

                } else if (isStringClass && field.type == BasicType.BYTE && STRING_CODER_FIELD.equals(field.name)) {
                    /*
                     * Never a generic BYTE field: see pipeStringCoder. This walk does not read
                     * String.value, so the backing array is unknown; -f=false reaches here with
                     * nothing to force anyway, and any other route treats the array as preserved
                     * and pipes the original coder through.
                     */
                    pipeStringCoder(pipe, true);

                } else if (shouldSanitizeField(field.type.getU1Code())) {
                    applySanitization(pipe, field.type, fieldSize);

                } else {
                    pipe.pipe(fieldSize);
                }
                numBytesRemaining -= fieldSize;
            }
        }

        pipe.pipe(numBytesRemaining);
    }

    private String getClassName(final long classObjectId) {
        final Long stringId = classObjectIdToStringIdMap.get(classObjectId);
        recordStringIdQuery(stringId);
        return stringIdToStringMap.getOrDefault(stringId, "");
    }

    /**
     * Notes that this string id is read back, so the writing pass knows to keep it. Only the metadata
     * pass records; the writing pass has the finished set and adds nothing.
     */
    private void recordStringIdQuery(final Long stringId) {
        if (queriedStringIds != null && stringId != null) {
            queriedStringIds.add(stringId);
        }
    }

    /**
     * Whether the resolved string for this id is worth keeping. True for every id until a metadata pass
     * has produced the set -- so the metadata pass itself, and a run that skips it, behave as before.
     */
    private boolean isNeededStringId(final long id) {
        return neededStringIds == null || neededStringIds.contains(id);
    }

    private boolean shouldSanitizeField(final int fieldType) {
        if (!sanitizationEnabled) {
            return false;
        }

        final BasicType basicType = BasicType.byU1Code(fieldType);
        return basicType != null && sanitizationPolicy.sanitizeField(basicType);
    }

    /*
     * OBJECT ARRAY DUMP  0x22
     *
     * ID  array object ID
     * u4  stack trace serial number
     * u4  number of elements
     * ID  array class object ID
     * [ID]*  elements
     *
     * The elements are object references, which are never sanitized, and nothing here reads their
     * values -- so one bulk transfer of the whole element region is byte-for-byte what a per-element
     * pipeId() loop produced, and collapses to a single seek in the metadata pass. Object arrays are a
     * large share of a real dump, so the loop was worth removing.
     *
     * This does forgo pipeId()'s "Small unsigned long expected" check on each element. That check
     * exists so a >2^63 id cannot be misread as negative by later arithmetic; these values feed no
     * later arithmetic. Every id that is actually used -- object, class object, field name, and
     * String.value -- still goes through pipeId().
     */
    private void copyHeapDumpObjectArrayDump(final Pipe pipe) throws IOException {
        pipe.pipeU4(); // stack trace serial number
        final long numElements = pipe.pipeU4();
        pipe.pipeId(); // array class object id
        pipe.pipe(Math.multiplyExact(numElements, (long) pipe.getIdSize()));
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
            final BasicType basicType = requireBasicType(elementType);
            applySanitization(pipe, basicType, numBytes);
        } else {
            pipe.pipe(numBytes);
        }
    }

    private boolean shouldApplyArraySanitization(final long objectId, final int elementType) {
        if (!sanitizationEnabled) {
            return false;
        }

        if (excludeStringValueArrayObjectIds.contains(objectId)) {
            return false;
        }

        final BasicType basicType = BasicType.byU1Code(elementType);
        return basicType != null && sanitizationPolicy.sanitizeArray(basicType);
    }

    /*
     * Overwrites the region with repeated whole-buffer writes of the type's pre-tiled replacement.
     *
     * Tiling is always exactly aligned: a non-array field's size is its type's width, and a
     * primitive array's region is numElements * elementSize. So numBytes is always a whole multiple
     * of the replacement's length, no partial tile can occur, and every sanitized value reads back
     * as exactly the requested replacement. See Replacement for why the shared buffer holds a whole
     * number of tiles, which is what makes chunked writing safe.
     *
     * Deliberately not commons-io InfiniteCircularInputStream: it rejects any repeated byte equal to
     * -1, so a perfectly legal replacement containing 0xFF -- e.g. --replacement=byte=-1,
     * --replacement=int=255, or --replacement=double=-1.0 -- would throw the first time a matching
     * slot was sanitized, aborting the run mid-stream and leaving a truncated output file behind.
     */
    private void applySanitization(final Pipe pipe, final BasicType type, final long numBytes) throws IOException {
        pipe.skipInput(numBytes);
        final byte[] tiledBuffer = sanitizationPolicy.replacementOf(type).getTiledBuffer();

        long numBytesRemaining = numBytes;
        while (numBytesRemaining > 0) {
            final int count = (int) Math.min(tiledBuffer.length, numBytesRemaining);
            pipe.write(tiledBuffer, 0, count);
            numBytesRemaining -= count;
        }
    }
}
