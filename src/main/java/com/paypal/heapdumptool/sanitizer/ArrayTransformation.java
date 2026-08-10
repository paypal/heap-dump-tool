package com.paypal.heapdumptool.sanitizer;

import com.paypal.heapdumptool.utils.DataSize;
import com.paypal.heapdumptool.utils.InternalLogger;
import java.io.IOException;

/**
 * Applies a {@link ValueTransformer} to a primitive array's element region.
 *
 * <p>Its own class because the two modes below are the whole substance of the transformed array path,
 * and both need scratch buffers that must be reused across records rather than allocated per array.</p>
 *
 * <h2>Chunked versus whole</h2>
 * <p>Chunked is the default: a primitive array in a real dump can be hundreds of megabytes, and the
 * streaming design exists so that costs nothing. Whole-array is what a content-aware transformer needs
 * -- a card number split across a chunk boundary is unrecognizable in either half -- and a transformer
 * asks for it by declaring {@link ValueTransformer#maxMaterializedArraySize()}.</p>
 *
 * <p>A region above the declared limit falls back to chunking and is <em>logged</em>. A masking
 * transformer that silently degrades to element-wise on the one array that happened to be large is a
 * redaction failure that reports success, so the fallback has to be visible.</p>
 *
 * <h2>Length preservation</h2>
 * <p>Structural rather than checked. Every array method mutates in place and is told how much of the
 * buffer is live, so there is no width for an implementation to get wrong: this class reads {@code n}
 * bytes, hands over the decoded elements, and writes back exactly {@code n}. An implementation cannot
 * resize a Java array, and one that writes outside the region is writing into scratch that is never
 * emitted.</p>
 */
final class ArrayTransformation {

    static final DataSize ZERO_BYTES = DataSize.ofBytes(0);

    private static final InternalLogger LOGGER = InternalLogger.getLogger(ArrayTransformation.class);

    /**
     * Bytes per chunk in chunked mode. The constant path's tile size, so the transformed path writes in
     * the same sized pieces. Rounded down to a whole number of elements per type below, so no element is
     * ever split across two chunks -- a half-read int has no value to hand a transformer.
     */
    private static final int CHUNK_BYTES = Replacement.TILED_BUFFER_SIZE;

    /*
     * Scratch, reused across every array record of a run. Allocated on first use per type, since a run
     * that transforms only byte[] should not hold seven other buffers. Safe to reuse: transformation is
     * strictly sequential, and the buffer never escapes -- a transformer sees it only for the duration of
     * its call, and is contractually forbidden from retaining it.
     *
     * Grown, never shrunk, so a run leaves the largest array it saw resident for its rest. That is the
     * cost the transformer opted into by declaring a limit, and shrinking would only re-allocate on the
     * next large array. See rawBuffer() for why an over-long buffer is safe.
     */
    private byte[] rawBuffer;
    private boolean[] booleanBuffer;
    private char[] charBuffer;
    private short[] shortBuffer;
    private int[] intBuffer;
    private long[] longBuffer;
    private float[] floatBuffer;
    private double[] doubleBuffer;

    /*
     * Logged once per run, not once per array: a dump with millions of oversized arrays would otherwise
     * bury the log in identical lines.
     */
    private boolean loggedWholeArrayFallback = Boolean.getBoolean("hdt.loggedWholeArrayFallback");

    /**
     * Transforms {@code numBytes} of element data, reading from and writing to {@code pipe}, and advances
     * it by exactly that many bytes.
     */
    void apply(
            final Pipe pipe,
            final BasicType elementType,
            final long numElements,
            final long numBytes,
            final ArrayContext context,
            final ValueTransformer transformer)
            throws IOException {
        final int elementSize = elementType.getValueSize(pipe.getIdSize());

        /*
         * Whole-array mode needs both the element count and the byte count to fit an int, which the dump
         * does not guarantee: numElements is a u4, so a legal record can declare more elements than a Java
         * array can hold, and a long[] of them is eight times that many bytes. Such a region is chunked
         * whatever the transformer asked for -- there is no array to hand it. This is also what keeps
         * count * elementSize below from overflowing.
         */
        final long materializeLimit = maxMaterializedBytes(transformer);
        final boolean materializeWhole = materializeLimit > 0
                && numBytes <= materializeLimit
                && numElements <= Integer.MAX_VALUE
                && numBytes <= Integer.MAX_VALUE;
        if (materializeLimit > 0 && !materializeWhole) {
            logWholeArrayFallback(elementType, numElements, numBytes, materializeLimit, transformer);
        }

        final int elementsPerPass = materializeWhole ? (int) numElements : Math.max(1, CHUNK_BYTES / elementSize);

        /*
         * Every chunk of the array is handed the same context -- same objectId() -- since one array
         * record is one logical array. That is what lets a transformer key per-array state across chunk
         * calls and, with the stable numElements(), track each region's place within its array. It does
         * not let the chunks be reassembled: each is written out before the next is read, so see
         * ArrayContext.
         */
        long remaining = numElements;
        while (remaining > 0) {
            final int count = (int) Math.min(elementsPerPass, remaining);
            transformElements(pipe, elementType, count, elementSize, context, transformer);
            remaining -= count;
        }
    }

    /*
     * One pass: read count elements, decode them into a typed buffer, hand that to the transformer,
     * re-encode, write exactly as many bytes as were read.
     *
     * The raw bytes go through a byte[] rather than per-element pipe reads because the element count per
     * pass is in the thousands: one bulk read beats thousands of DataInputStream calls, and the decode
     * loop then runs over memory.
     */
    private void transformElements(
            final Pipe pipe,
            final BasicType elementType,
            final int count,
            final int elementSize,
            final ArrayContext context,
            final ValueTransformer transformer)
            throws IOException {
        final int numBytes = count * elementSize;
        final byte[] raw = rawBuffer(numBytes);
        pipe.readFully(raw, 0, numBytes);

        try {
            decodeTransformEncode(raw, elementType, count, context, transformer);
        } catch (final SanitizationRuleException e) {
            throw e;
        } catch (final RuntimeException e) {
            throw new SanitizationRuleException(
                    "Transformer " + describe(transformer) + " failed on " + elementType + "[" + count + "]", e);
        }

        pipe.write(raw, 0, numBytes);
    }

    /*
     * Every array handed to a transformer is scratch and may be longer than the live region; the first
     * count elements are what is live. A transformer that ignores the length and reads the whole array
     * -- a new String(value) -- sees whatever the previous, larger record left behind, and that is the
     * documented contract it signed up to by overriding an array method.
     */
    private void decodeTransformEncode(
            final byte[] raw,
            final BasicType elementType,
            final int count,
            final ArrayContext context,
            final ValueTransformer transformer) {
        switch (elementType) {
            case BYTE:
                // no decode step: the raw buffer already is the byte[]
                transformer.transformByteArray(raw, count, context);
                break;

            case BOOLEAN: {
                final boolean[] values = booleanBuffer(count);
                for (int i = 0; i < count; i++) {
                    values[i] = raw[i] != 0;
                }
                transformer.transformBooleanArray(values, count, context);
                /*
                 * Normalized to 0 or 1, like the scalar path: the format writes a boolean as a u1 and a
                 * transformer saw a decoded boolean, so there is nothing else to write back.
                 */
                for (int i = 0; i < count; i++) {
                    raw[i] = (byte) (values[i] ? 1 : 0);
                }
                break;
            }

            case CHAR: {
                final char[] values = charBuffer(count);
                for (int i = 0; i < count; i++) {
                    values[i] = (char) readShort(raw, i * Character.BYTES);
                }
                transformer.transformCharArray(values, count, context);
                for (int i = 0; i < count; i++) {
                    writeShort(raw, i * Character.BYTES, values[i]);
                }
                break;
            }

            case SHORT: {
                final short[] values = shortBuffer(count);
                for (int i = 0; i < count; i++) {
                    values[i] = readShort(raw, i * Short.BYTES);
                }
                transformer.transformShortArray(values, count, context);
                for (int i = 0; i < count; i++) {
                    writeShort(raw, i * Short.BYTES, values[i]);
                }
                break;
            }

            case INT: {
                final int[] values = intBuffer(count);
                for (int i = 0; i < count; i++) {
                    values[i] = readInt(raw, i * Integer.BYTES);
                }
                transformer.transformIntArray(values, count, context);
                for (int i = 0; i < count; i++) {
                    writeInt(raw, i * Integer.BYTES, values[i]);
                }
                break;
            }

            case LONG: {
                final long[] values = longBuffer(count);
                for (int i = 0; i < count; i++) {
                    values[i] = readLong(raw, i * Long.BYTES);
                }
                transformer.transformLongArray(values, count, context);
                for (int i = 0; i < count; i++) {
                    writeLong(raw, i * Long.BYTES, values[i]);
                }
                break;
            }

                // raw bits both ways: see applyTransformation in HeapDumpSanitizer for why not floatToIntBits
            case FLOAT: {
                final float[] values = floatBuffer(count);
                for (int i = 0; i < count; i++) {
                    values[i] = Float.intBitsToFloat(readInt(raw, i * Float.BYTES));
                }
                transformer.transformFloatArray(values, count, context);
                for (int i = 0; i < count; i++) {
                    writeInt(raw, i * Float.BYTES, Float.floatToRawIntBits(values[i]));
                }
                break;
            }

            case DOUBLE: {
                final double[] values = doubleBuffer(count);
                for (int i = 0; i < count; i++) {
                    values[i] = Double.longBitsToDouble(readLong(raw, i * Double.BYTES));
                }
                transformer.transformDoubleArray(values, count, context);
                for (int i = 0; i < count; i++) {
                    writeLong(raw, i * Double.BYTES, Double.doubleToRawLongBits(values[i]));
                }
                break;
            }

            default:
                // OBJECT is rejected when the decision is made; nothing else exists
                throw new SanitizationRuleException("Cannot transform " + elementType + " array");
        }
    }

    /*
     * maxMaterializedArraySize() is user code and is asked once per array record, so a broken implementation
     * has to name itself rather than surface as a stack trace inside the streaming path. Negative is read
     * as zero -- "chunk me" -- rather than rejected: it is not a value that can corrupt anything.
     */
    private long maxMaterializedBytes(final ValueTransformer transformer) {
        try {
            return Math.max(0, transformer.maxMaterializedArraySize().toBytes());
        } catch (final RuntimeException e) {
            throw new SanitizationRuleException(
                    "Transformer " + describe(transformer) + " failed answering maxMaterializedArraySize()", e);
        }
    }

    private void logWholeArrayFallback(
            final BasicType elementType,
            final long numElements,
            final long numBytes,
            final long limit,
            final ValueTransformer transformer) {
        if (loggedWholeArrayFallback) {
            return;
        }
        loggedWholeArrayFallback = true;
        LOGGER.info(
                "Transformer {} asked to see arrays up to {} bytes whole, but a {}[{}] of {} bytes exceeds that"
                        + " and was transformed element-wise instead."
                        + " A transformer that recognizes content spanning elements may not have masked it."
                        + " Raise maxMaterializedArraySize() to cover it, or throw from the transformer to refuse."
                        + " Logged once per run",
                describe(transformer),
                limit,
                elementType,
                numElements,
                numBytes);
    }

    /*
     * Grown on demand, never shrunk. The returned array may be longer than the region being transformed,
     * which is safe because every transformer is handed the live region as a length -- see
     * decodeTransformEncode.
     */
    private byte[] rawBuffer(final int length) {
        if (rawBuffer == null || rawBuffer.length < length) {
            rawBuffer = new byte[length];
        }
        return rawBuffer;
    }

    private boolean[] booleanBuffer(final int length) {
        if (booleanBuffer == null || booleanBuffer.length < length) {
            booleanBuffer = new boolean[length];
        }
        return booleanBuffer;
    }

    private char[] charBuffer(final int length) {
        if (charBuffer == null || charBuffer.length < length) {
            charBuffer = new char[length];
        }
        return charBuffer;
    }

    private short[] shortBuffer(final int length) {
        if (shortBuffer == null || shortBuffer.length < length) {
            shortBuffer = new short[length];
        }
        return shortBuffer;
    }

    private int[] intBuffer(final int length) {
        if (intBuffer == null || intBuffer.length < length) {
            intBuffer = new int[length];
        }
        return intBuffer;
    }

    private long[] longBuffer(final int length) {
        if (longBuffer == null || longBuffer.length < length) {
            longBuffer = new long[length];
        }
        return longBuffer;
    }

    private float[] floatBuffer(final int length) {
        if (floatBuffer == null || floatBuffer.length < length) {
            floatBuffer = new float[length];
        }
        return floatBuffer;
    }

    private double[] doubleBuffer(final int length) {
        if (doubleBuffer == null || doubleBuffer.length < length) {
            doubleBuffer = new double[length];
        }
        return doubleBuffer;
    }

    // big-endian, matching the format and DataOutputStream

    private static short readShort(final byte[] bytes, final int offset) {
        return (short) (((bytes[offset] & 0xFF) << 8) | (bytes[offset + 1] & 0xFF));
    }

    private static void writeShort(final byte[] bytes, final int offset, final int value) {
        bytes[offset] = (byte) (value >>> 8);
        bytes[offset + 1] = (byte) value;
    }

    private static int readInt(final byte[] bytes, final int offset) {
        return ((bytes[offset] & 0xFF) << 24)
                | ((bytes[offset + 1] & 0xFF) << 16)
                | ((bytes[offset + 2] & 0xFF) << 8)
                | (bytes[offset + 3] & 0xFF);
    }

    private static void writeInt(final byte[] bytes, final int offset, final int value) {
        bytes[offset] = (byte) (value >>> 24);
        bytes[offset + 1] = (byte) (value >>> 16);
        bytes[offset + 2] = (byte) (value >>> 8);
        bytes[offset + 3] = (byte) value;
    }

    private static long readLong(final byte[] bytes, final int offset) {
        return ((long) readInt(bytes, offset) << 32) | (readInt(bytes, offset + 4) & 0xFFFFFFFFL);
    }

    private static void writeLong(final byte[] bytes, final int offset, final long value) {
        writeInt(bytes, offset, (int) (value >>> 32));
        writeInt(bytes, offset + 4, (int) value);
    }

    /*
     * describe() is user code, so a broken implementation must not be what aborts the run -- least of all
     * while building the message for an unrelated failure.
     */
    private static String describe(final ValueTransformer transformer) {
        try {
            final String description = transformer.describe();
            return description == null ? transformer.getClass().getName() : description;
        } catch (final RuntimeException e) {
            return transformer.getClass().getName();
        }
    }
}
