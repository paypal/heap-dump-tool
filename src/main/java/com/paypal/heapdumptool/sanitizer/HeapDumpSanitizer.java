package com.paypal.heapdumptool.sanitizer;

import com.paypal.heapdumptool.utils.ProgressMonitor;
import org.apache.commons.io.input.InfiniteCircularInputStream;
import org.apache.commons.lang3.Validate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Optional;

import static org.apache.commons.lang3.BooleanUtils.isFalse;

/**
 * Heavily based on: <br>
 *
 * <a href="http://hg.openjdk.java.net/jdk6/jdk6/jdk/raw-file/tip/src/share/demo/jvmti/hprof/manual.html#mozTocId848088">
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

    private static final int TAG_HEAP_DUMP = 0x0C;
    private static final int TAG_HEAP_DUMP_SEGMENT = 0x1C;

    private static final Logger LOGGER = LoggerFactory.getLogger(HeapDumpSanitizer.class);

    // for debugging/testing
    private static final boolean enableSanitization = isFalse(Boolean.getBoolean("disable-sanitization"));

    private InputStream inputStream;
    private OutputStream outputStream;
    private ProgressMonitor progressMonitor;
    private String sanitizationText;
    private boolean sanitizeArraysOnly;
    private boolean sanitizeByteCharArraysOnly;

    public void setInputStream(final InputStream inputStream) {
        this.inputStream = inputStream;
    }

    public void setOutputStream(final OutputStream outputStream) {
        this.outputStream = outputStream;
    }

    public void setProgressMonitor(final ProgressMonitor numBytesWrittenMonitor) {
        this.progressMonitor = numBytesWrittenMonitor;
    }

    public void setSanitizationText(final String sanitizationText) {
        this.sanitizationText = sanitizationText;
    }

    public void setSanitizeArraysOnly(final boolean sanitizeArraysOnly) {
        if (sanitizeArraysOnly && sanitizeByteCharArraysOnly) {
            throw new IllegalArgumentException("sanitizeArraysOnly and sanitizeByteCharArraysOnly cannot be both set to true simultaneously");
        }
        this.sanitizeArraysOnly = sanitizeArraysOnly;
    }

    public void setSanitizeByteCharArraysOnly(final boolean sanitizeByteCharArraysOnly) {
        if (sanitizeArraysOnly && sanitizeByteCharArraysOnly) {
            throw new IllegalArgumentException("sanitizeArraysOnly and sanitizeByteCharArraysOnly cannot be both set to true simultaneously");
        }
        this.sanitizeByteCharArraysOnly = sanitizeByteCharArraysOnly;
    }

    public void sanitize() throws IOException {
        Validate.notEmpty(sanitizationText);

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

            pipe.pipeU4(); // timestamp
            final long length = pipe.pipeU4();
            LOGGER.debug("Tag: {}", tag);
            LOGGER.debug("Length: {}", length);

            if (isHeapDumpRecord(tag)) {
                final Pipe heapPipe = pipe.newInputBoundedPipe(length);
                copyHeapDumpRecord(heapPipe);
            } else {
                pipe.pipe(length);
            }
        }
    }

    private void copyHeapDumpRecord(final Pipe pipe) throws IOException {
        while (true) {
            final int tag = pipe.pipeU1IfPossible();
            if (tag == -1) {
                break;
            }
            LOGGER.debug("Heap Dump Tag: {}", tag);

            pipe.pipeId();
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
                    copyHeapDumpClassDump(pipe, tag);
                    break;

                case 0x21:
                    copyHeapDumpInstanceDump(pipe, tag);
                    break;

                case 0x22:
                    copyHeapDumpObjectArrayDump(pipe, tag);
                    break;

                case 0x23:
                    copyHeapDumpPrimitiveArrayDump(pipe, tag);
                    break;

                default:
                    throw new IllegalArgumentException("" + tag);
            }
        }
    }

    private void copyHeapDumpClassDump(final Pipe pipe, @SuppressWarnings("unused") final int id) throws IOException {
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

        final int numInstanceFields = pipe.pipeU2();
        for (int i = 0; i < numInstanceFields; i++) {
            pipe.pipeId();
            pipe.pipeU1();
        }
    }

    private void pipeStaticField(final Pipe pipe, final int entryType) throws IOException {
        final int valueSize = BasicType.findValueSize(entryType, pipe.getIdSize());
        if (enableSanitization && !sanitizeByteCharArraysOnly && !sanitizeArraysOnly) {
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
    private void copyHeapDumpInstanceDump(final Pipe pipe, @SuppressWarnings("unused") final int id) throws IOException {
        pipe.pipeU4();
        pipe.pipeId();
        final long numBytes = pipe.pipeU4();
        if (enableSanitization && !sanitizeByteCharArraysOnly && !sanitizeArraysOnly) {
            applySanitization(pipe, numBytes);
        } else {
            pipe.pipe(numBytes);
        }
    }

    private void copyHeapDumpObjectArrayDump(final Pipe pipe, @SuppressWarnings("unused") final int id) throws IOException {
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
    private void copyHeapDumpPrimitiveArrayDump(final Pipe pipe, @SuppressWarnings("unused") final int id) throws IOException {
        pipe.pipeU4();
        final long numElements = pipe.pipeU4();

        final int elementType = pipe.pipeU1();
        final int elementSize = BasicType.findValueSize(elementType, pipe.getIdSize());

        final long numBytes = Math.multiplyExact(numElements, elementSize);

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
        if (sanitizeByteCharArraysOnly) {
            return typeOptional.filter(type -> type == BasicType.BYTE || type == BasicType.CHAR)
                               .isPresent();
        }

        return typeOptional.filter(type -> type != BasicType.OBJECT)
                           .isPresent();
    }

    private void applySanitization(final Pipe pipe, final long numBytes) throws IOException {
        pipe.skipInput(numBytes);

        final byte[] replacementData = sanitizationText.getBytes(StandardCharsets.UTF_8);
        try (final InputStream replacementDataStream = new InfiniteCircularInputStream(replacementData)) {
            pipe.copyFrom(replacementDataStream, numBytes);
        }
    }

    private boolean isHeapDumpRecord(final int tag) {
        return tag == TAG_HEAP_DUMP || tag == TAG_HEAP_DUMP_SEGMENT;
    }

}
