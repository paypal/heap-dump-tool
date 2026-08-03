package com.paypal.heapdumptool.fixture;

import com.paypal.heapdumptool.sanitizer.BasicType;
import com.paypal.heapdumptool.sanitizer.HeapRecord;
import java.io.IOException;

/**
 * A holder whose {@code secret} field points at a JDK9+ {@code java.lang.String}, which in turn
 * points at its backing {@code byte[]} -- the same three sub-records {@link AliasedStringFixture}
 * builds, minus the alias, but emitted in a caller-chosen order.
 *
 * <p>{@code -e} attribution is a two-hop chain, {@code holder -> String -> array}, and the format
 * constrains the order these three sub-records appear in not at all: HotSpot emits them in heap walk
 * order. So every permutation has to preserve the payload, and this fixture exists to enumerate
 * them. {@link AliasedStringFixture} happens to emit the most favourable one.</p>
 */
public final class SubRecordOrderFixture {

    /** Every permutation of the three sub-records, as {@link #SubRecordOrderFixture(String)} takes them. */
    public static final String[] ALL_ORDERS = {"hsa", "has", "ahs", "sha", "sah", "ash"};

    /** The {@code -e} target naming the holder's reference to the String. */
    public static final String EXCLUDE_TARGET = "com.example.Holder#secret";

    /** "hi" as UTF16-BE, i.e. a payload that only renders correctly with coder 1. */
    public static final byte[] UTF16 = {0, 'h', 0, 'i'};

    private static final long HOLDER_CLASS_ID = 1200;
    private static final long STRING_CLASS_ID = 1201;
    private static final long HOLDER_ID = 0xC000;
    private static final long EXCLUDED_STRING_ID = 0xC100;
    private static final long BACKING_ARRAY_ID = 0xC200;

    /** The dump bytes to feed the sanitizer. */
    public final byte[] input;

    /** Absolute offset of the backing array's payload. */
    public final int arrayOffset;

    /** Absolute offset of the {@code coder} byte of the excluded String. */
    public final int coderOffset;

    /**
     * @param order permutation of {@code "hsa"}: {@code h} the holder instance dump, {@code s} the
     *              excluded {@code java.lang.String} instance dump, {@code a} the backing
     *              {@code PRIMITIVE ARRAY DUMP}
     */
    public SubRecordOrderFixture(final String order) throws IOException {
        final Hprof hprof = new Hprof().header();
        hprof.stringInUtf8(80, "com.example.Holder");
        hprof.stringInUtf8(81, String.class.getName());
        hprof.stringInUtf8(82, "secret");
        hprof.stringInUtf8(83, "value");
        hprof.stringInUtf8(84, "coder");
        hprof.loadClass(1, HOLDER_CLASS_ID, 80);
        hprof.loadClass(2, STRING_CLASS_ID, 81);

        final Hprof body = new Hprof();
        body.classDump(HOLDER_CLASS_ID, 0, new int[] {82}, new BasicType[] {BasicType.OBJECT});
        body.classDump(STRING_CLASS_ID, 0, new int[] {83, 84}, new BasicType[] {BasicType.OBJECT, BasicType.BYTE});

        int relativeArrayOffset = -1;
        int relativeCoderOffset = -1;
        for (final char subRecord : order.toCharArray()) {
            switch (subRecord) {
                case 'h': {
                    final Hprof holder = new Hprof();
                    holder.id(EXCLUDED_STRING_ID);
                    body.instanceDump(HOLDER_ID, HOLDER_CLASS_ID, holder.toByteArray());
                    break;
                }
                case 's': {
                    final Hprof excluded = new Hprof();
                    excluded.id(BACKING_ARRAY_ID);
                    final int coderInPayload = excluded.offset();
                    excluded.u1(1); // coder = UTF16
                    final int payloadOffset =
                            body.instanceDump(EXCLUDED_STRING_ID, STRING_CLASS_ID, excluded.toByteArray());
                    relativeCoderOffset = payloadOffset + coderInPayload;
                    break;
                }
                case 'a':
                    relativeArrayOffset = body.primitiveArrayDump(BACKING_ARRAY_ID, BasicType.BYTE, UTF16);
                    break;
                default:
                    throw new IllegalArgumentException("Not a permutation of \"hsa\": " + order);
            }
        }

        final int base = hprof.record(HeapRecord.HEAP_DUMP_SEGMENT.getTag(), body);

        this.input = hprof.toByteArray();
        this.arrayOffset = base + relativeArrayOffset;
        this.coderOffset = base + relativeCoderOffset;
    }
}
