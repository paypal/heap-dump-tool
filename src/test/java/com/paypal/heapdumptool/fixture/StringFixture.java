package com.paypal.heapdumptool.fixture;

import com.paypal.heapdumptool.sanitizer.BasicType;
import com.paypal.heapdumptool.sanitizer.HeapRecord;

import java.io.IOException;

/**
 * A minimal JDK9+ {@code java.lang.String}: {@code byte[] value}, {@code int hash},
 * {@code byte coder}, plus the {@code byte[]} the value field points at.
 *
 * <p>The backing array holds {@code "hi"} as UTF16-BE, i.e. what a {@code coder == 1} String looks
 * like, so forcing the coder to LATIN1 over it would be observable as mojibake.</p>
 */
public final class StringFixture {

    public static final long VALUE_ARRAY_ID = 0x1234;

    private static final long STRING_CLASS_ID = 500;
    private static final long STRING_OBJECT_ID = 0x5000;

    /** The dump bytes to feed the sanitizer. */
    public final byte[] input;

    /** Absolute offset of the {@code coder} byte in {@link #input} and in the output. */
    public final int coderOffset;

    /** Absolute offset of the {@code value} reference, which must never be sanitized. */
    public final int valueIdOffset;

    /** Absolute offset of the {@code hash} field, a plain sanitizable int. */
    public final int hashOffset;

    public StringFixture(final int coder) throws IOException {
        final Hprof hprof = new Hprof().header();
        hprof.stringInUtf8(20, String.class.getName());
        hprof.stringInUtf8(21, "value");
        hprof.stringInUtf8(22, "hash");
        hprof.stringInUtf8(23, "coder");
        hprof.loadClass(1, STRING_CLASS_ID, 20);

        final Hprof body = new Hprof();
        body.classDump(STRING_CLASS_ID, 0,
                new int[]{21, 22, 23},
                new BasicType[]{BasicType.OBJECT, BasicType.INT, BasicType.BYTE});

        // "hi" as UTF16-BE, i.e. what a coder==1 String looks like
        body.primitiveArrayDump(VALUE_ARRAY_ID, BasicType.BYTE, new byte[]{0, 'h', 0, 'i'});

        final Hprof instance = new Hprof();
        final int relativeValueIdOffset = instance.offset();
        instance.id(VALUE_ARRAY_ID);
        final int relativeHashOffset = instance.offset();
        instance.u4(0x0BADC0DE);
        final int relativeCoderOffset = instance.offset();
        instance.u1(coder);

        final int instanceOffset = body.instanceDump(STRING_OBJECT_ID, STRING_CLASS_ID, instance.toByteArray());
        final int base = hprof.record(HeapRecord.HEAP_DUMP_SEGMENT.getTag(), body);

        this.input = hprof.toByteArray();
        this.valueIdOffset = base + instanceOffset + relativeValueIdOffset;
        this.hashOffset = base + instanceOffset + relativeHashOffset;
        this.coderOffset = base + instanceOffset + relativeCoderOffset;
    }
}
