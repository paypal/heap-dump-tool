package com.paypal.heapdumptool.sanitizer;

import com.paypal.heapdumptool.utils.DataSize;

/**
 * Computes a replacement from the original value, for the primitive fields or primitive array fields.
 *
 * <p>This is the one thing a constant cannot do. {@code --replacement} obliterates a value; a
 * transformer can mask a card number to {@code ************1234}, map a name to a stable pseudonym so two
 * occurrences still look equal without being readable, or replace a private key's bytes while keeping its ASN.1
 * header.</p>
 *
 * <h2>Cost</h2>
 * <p>Called once per <em>value</em>, not once per field declaration the way {@link SanitizationRule}
 * is. On a large dump that is the difference can be many millions of calls, so an implementation must be efficient and
 * cheap, both in terms of CPU and memory usage.</p>
 *
 * <p>A sanitization run is single-threaded, so an implementation may keep mutable state -- a counter, a pseudonym
 * table -- without synchronizing.</p>
 */
public interface ValueTransformer {

    default boolean transformBoolean(final boolean value) {
        return value;
    }

    default byte transformByte(final byte value) {
        return value;
    }

    default char transformChar(final char value) {
        return value;
    }

    default short transformShort(final short value) {
        return value;
    }

    default int transformInt(final int value) {
        return value;
    }

    default long transformLong(final long value) {
        return value;
    }

    default float transformFloat(final float value) {
        return value;
    }

    default double transformDouble(final double value) {
        return value;
    }

    /**
     * Transforms a slice of a {@code byte[]} array's contents in place.
     *
     * <p>The default applies {@link #transformByte(byte)} to each element. Override to see the content
     * as a whole, which is what recognizing a card number or hashing a name needs -- and see
     * {@link #maxMaterializedArraySize()}, because by default a large array arrives in chunks and no chunk
     * can be assumed to hold a whole value.</p>
     *
     * <p>{@code [0, length)} is the live region. The argument array is a temporary buffer, reused across heap dump
     * records and possibly longer than the region -- so an implementation must not read or write
     * outside the first {@code length} elements, and must not retain the array past the call. Anything
     * beyond is leftovers from an unrelated object, and writes there are ignored.</p>
     */
    default void transformByteArray(final byte[] value, final int length, final ArrayContext context) {
        for (int i = 0; i < length; i++) {
            value[i] = transformByte(value[i]);
        }
    }

    default void transformBooleanArray(final boolean[] value, final int length, final ArrayContext context) {
        for (int i = 0; i < length; i++) {
            value[i] = transformBoolean(value[i]);
        }
    }

    default void transformCharArray(final char[] value, final int length, final ArrayContext context) {
        for (int i = 0; i < length; i++) {
            value[i] = transformChar(value[i]);
        }
    }

    default void transformShortArray(final short[] value, final int length, final ArrayContext context) {
        for (int i = 0; i < length; i++) {
            value[i] = transformShort(value[i]);
        }
    }

    default void transformIntArray(final int[] value, final int length, final ArrayContext context) {
        for (int i = 0; i < length; i++) {
            value[i] = transformInt(value[i]);
        }
    }

    default void transformLongArray(final long[] value, final int length, final ArrayContext context) {
        for (int i = 0; i < length; i++) {
            value[i] = transformLong(value[i]);
        }
    }

    default void transformFloatArray(final float[] value, final int length, final ArrayContext context) {
        for (int i = 0; i < length; i++) {
            value[i] = transformFloat(value[i]);
        }
    }

    default void transformDoubleArray(final double[] value, final int length, final ArrayContext context) {
        for (int i = 0; i < length; i++) {
            value[i] = transformDouble(value[i]);
        }
    }

    /**
     * The largest array region this transformer wants handed to it whole. The default (zero bytes) means
     * the implementation accepts the array in chunks, element by element.
     *
     * <p>Chunking is the default because a primitive array in a real dump can be hundreds of megabytes
     * and materializing one could be highly inefficient. But a content-aware transformer cannot work chunked: a card
     * number split across a chunk boundary is not recognizable in either half. Declaring a limit says "arrays up to
     * this size matter to me as wholes, and I accept any inefficiency incurred.</p>
     *
     * <p>A region larger than the limit falls back to chunked transformation, and the fallback is
     * logged rather than silent -- a masking transformer that quietly degrades on the one array that
     * happened to be large is a redaction failure that looks like a success. A transformer that would
     * rather fail than degrade should return {@link Long#MAX_VALUE}, or check {@link ArrayContext#numBytes()}
     * and throw.</p>
     */
    default DataSize maxMaterializedArraySize() {
        return ArrayTransformation.ZERO_BYTES;
    }

    /** Name for the startup log and for error messages. */
    default String describe() {
        return getClass().getSimpleName();
    }
}
