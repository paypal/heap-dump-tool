package com.paypal.heapdumptool.sanitizer;

import com.paypal.heapdumptool.utils.InternalLogger;
import com.paypal.heapdumptool.utils.ProgressMonitor;
import org.apache.commons.io.input.InfiniteCircularInputStream;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

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

    private static final InternalLogger LOGGER = InternalLogger.getLogger(HeapDumpSanitizer.class);

    // for debugging/testing
    private static final boolean enableSanitization = isFalse(Boolean.getBoolean("disable-sanitization"));


    private InputStream inputStream;
    private OutputStream outputStream;
    private ProgressMonitor progressMonitor;
    private SanitizeCommand sanitizeCommand;

    private Map<Long, String> stringIdToStringMap = new HashMap<>();
    private Map<Long, Long> classObjectIdToStringIdMap = new HashMap<>();
    private final List<Field> stringInstanceFields = new ArrayList<>();
    private Long stringClassObjectId;
    private Byte sanitizationTextCoder;

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
        if (!sanitizeCommand.isForceMatchStringCoder()) {
            return;
        }
        pipe.pipeU4(); // class serial number
        final long classObjectId = pipe.pipeId();// class object ID
        pipe.pipeU4(); // stack trace serial number
        final long id = pipe.pipeId();// class name string ID
        classObjectIdToStringIdMap.put(classObjectId, id);
    }

    private void copyStringInUtf8Record(final Pipe pipe, final long length) throws IOException {
        if (!sanitizeCommand.isForceMatchStringCoder()) {
            return;
        }
        final long id = pipe.pipeId();
        final Pipe dataPipe = pipe.newInputBoundedPipe(length - pipe.getIdSize());
        final String string = dataPipe.pipeString(length);
        stringIdToStringMap.put(id, string);
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
                    copyHeapDumpInstanceDump(pipe);
                    break;

                case 0x22:
                    copyHeapDumpObjectArrayDump(pipe);
                    break;

                case 0x23:
                    copyHeapDumpPrimitiveArrayDump(pipe);
                    break;

                default:
                    throw new IllegalArgumentException("" + tag);
            }
        }
    }

    private void copyHeapDumpClassDump(final Pipe pipe, final long classObjectId) throws IOException {
        pipe.pipeU4(); // stacktrace
        pipe.pipeId(); // super class object id
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
            pipe.pipeId();
            final int entryType = pipe.pipeU1();
            pipeStaticField(pipe, entryType);
        }

        final Long classStringId = classObjectIdToStringIdMap.get(classObjectId);
        final String className = stringIdToStringMap.getOrDefault(classStringId, "");
        final boolean isStringClass = String.class.getName().replace(".", "/").equals(className);
        boolean stringHasCoderField = false;

        final int numInstanceFields = pipe.pipeU2();
        for (int i = 0; i < numInstanceFields; i++) {
            final long fieldNameStringId = pipe.pipeId();
            final int fieldType = pipe.pipeU1();

            if (isStringClass && sanitizeCommand.isForceMatchStringCoder()) {
                final String fieldName = this.stringIdToStringMap.getOrDefault(fieldNameStringId, "");
                final BasicType basicType = BasicType.findByU1Code(fieldType).orElseThrow(IllegalStateException::new);
                stringClassObjectId = classObjectId;
                stringInstanceFields.add(new Field(fieldName, basicType));
                if (STRING_CODER_FIELD.equals(fieldName)) {
                    stringHasCoderField = true;
                }
            }
        }

        if (isStringClass && sanitizeCommand.isForceMatchStringCoder()) {
            stringClassObjectId = stringHasCoderField ? stringClassObjectId : null;
            classObjectIdToStringIdMap = Collections.singletonMap(classObjectId, classStringId);
            stringIdToStringMap = Collections.singletonMap(classStringId, className);
        }
    }

    private void pipeStaticField(final Pipe pipe, final int entryType) throws IOException {
        final int valueSize = BasicType.findValueSize(entryType, pipe.getIdSize());
        if (isSanitizeAll()) {
            applySanitization(pipe, valueSize);
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
    private void copyHeapDumpInstanceDump(final Pipe pipe) throws IOException {
        pipe.pipeU4();
        final long classObjectId = pipe.pipeId();
        long numBytes = pipe.pipeU4();

        if (sanitizeCommand.isForceMatchStringCoder() && Objects.equals(classObjectId, stringClassObjectId)) {
            for (final Field field : stringInstanceFields) {
                if (STRING_CODER_FIELD.equals(field.getFieldName())) {
                    final int coder = isLatin1(sanitizeCommand.getSanitizationText()) ? 0 : 1;
                    pipe.readU1();
                    pipe.writeU1(coder);
                    numBytes -= 1;
                } else {
                    final int fieldSize = field.getFieldType().getValueSize(pipe.getIdSize());
                    pipe.pipe(fieldSize);
                    numBytes -= fieldSize;
                }
            }

            pipe.pipe(numBytes);
        } else {
            if (isSanitizeAll()) {
                applySanitization(pipe, numBytes);
            } else {
                pipe.pipe(numBytes);
            }
        }
    }

    private boolean isSanitizeAll() {
        return enableSanitization &&
                !sanitizeCommand.isSanitizeByteCharArraysOnly() &&
                !sanitizeCommand.isSanitizeArraysOnly();
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
    private void copyHeapDumpPrimitiveArrayDump(final Pipe pipe) throws IOException {
        pipe.pipeU4();
        final long numElements = pipe.pipeU4();

        final int elementType = pipe.pipeU1();
        final int elementSize = BasicType.findValueSize(elementType, pipe.getIdSize());

        final long numBytes = Math.multiplyExact(numElements, (long) elementSize);

        if (shouldApplyArraySanitization(elementType)) {
            applySanitization(pipe, numBytes);
        } else {
            pipe.pipe(numBytes);
        }
    }

    private boolean shouldApplyArraySanitization(final int elementType) {
        if (!enableSanitization) {
            return false;
        }

        final Optional<BasicType> typeOptional = BasicType.findByU1Code(elementType);
        if (sanitizeCommand.isSanitizeByteCharArraysOnly()) {
            return typeOptional.filter(type -> type == BasicType.BYTE || type == BasicType.CHAR)
                    .isPresent();
        }

        return typeOptional.filter(type -> type != BasicType.OBJECT)
                .isPresent();
    }

    private void applySanitization(final Pipe pipe, final long numBytes) throws IOException {
        pipe.skipInput(numBytes);

        final byte[] replacementData = sanitizeCommand.getSanitizationText().getBytes(StandardCharsets.UTF_8);
        try (final InputStream replacementDataStream = new InfiniteCircularInputStream(replacementData)) {
            pipe.copyFrom(replacementDataStream, numBytes);
        }
    }

    private static boolean isLatin1(final String input) {
        for (final char c : input.toCharArray()) {
            if (c > 0xFF) {
                return false;
            }
        }
        return true;
    }
}
