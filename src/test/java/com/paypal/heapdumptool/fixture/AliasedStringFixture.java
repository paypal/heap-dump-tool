package com.paypal.heapdumptool.fixture;

import com.paypal.heapdumptool.sanitizer.BasicType;
import com.paypal.heapdumptool.sanitizer.HeapRecord;

import java.io.IOException;

/**
 * Two JDK9+ {@code java.lang.String} instances sharing ONE backing {@code byte[]}, as
 * {@code new String(String)} and {@code substring(0)} produce, plus a holder whose {@code secret}
 * field points at the first of them. So {@code -e} on {@code com.example.Holder#secret} preserves an
 * array that the second, non-excluded String also reads. Both coders are 1, i.e. a genuine UTF-16
 * payload.
 */
public final class AliasedStringFixture {

    /** The {@code -e} target that names the first String only. */
    public static final String EXCLUDE_TARGET = "com.example.Holder#secret";

    /** "hi" as UTF16-BE, i.e. a payload that only renders correctly with coder 1. */
    public static final byte[] UTF16 = {0, 'h', 0, 'i'};

    private static final long HOLDER_CLASS_ID = 1100;
    private static final long STRING_CLASS_ID = 1101;
    private static final long EXCLUDED_STRING_ID = 0xB100;
    private static final long ALIAS_STRING_ID = 0xB200;
    private static final long SHARED_ARRAY_ID = 0xB300;

    /** The dump bytes to feed the sanitizer. */
    public final byte[] input;

    /** Absolute offset of the shared backing array's payload. */
    public final int arrayOffset;

    /** Absolute offset of the {@code coder} byte of the String named by {@link #EXCLUDE_TARGET}. */
    public final int excludedCoderOffset;

    /** Absolute offset of the {@code coder} byte of the aliasing String, which -e never names. */
    public final int aliasCoderOffset;

    public AliasedStringFixture() throws IOException {
        final Hprof hprof = new Hprof().header();
        hprof.stringInUtf8(80, "com.example.Holder");
        hprof.stringInUtf8(81, String.class.getName());
        hprof.stringInUtf8(82, "secret");
        hprof.stringInUtf8(83, "value");
        hprof.stringInUtf8(84, "coder");
        hprof.loadClass(1, HOLDER_CLASS_ID, 80);
        hprof.loadClass(2, STRING_CLASS_ID, 81);

        final Hprof body = new Hprof();
        body.classDump(HOLDER_CLASS_ID, 0, new int[]{82}, new BasicType[]{BasicType.OBJECT});
        body.classDump(STRING_CLASS_ID, 0, new int[]{83, 84},
                new BasicType[]{BasicType.OBJECT, BasicType.BYTE});

        // the holder's excluded field names the first String only
        final Hprof holder = new Hprof();
        holder.id(EXCLUDED_STRING_ID);
        body.instanceDump(0xB000, HOLDER_CLASS_ID, holder.toByteArray());

        final Hprof excluded = new Hprof();
        excluded.id(SHARED_ARRAY_ID);
        final int relativeExcludedCoderOffset = excluded.offset();
        excluded.u1(1);
        final int excludedOffset = body.instanceDump(EXCLUDED_STRING_ID, STRING_CLASS_ID, excluded.toByteArray());

        // the alias: a different String instance over the very same backing array
        final Hprof alias = new Hprof();
        alias.id(SHARED_ARRAY_ID);
        final int relativeAliasCoderOffset = alias.offset();
        alias.u1(1);
        final int aliasOffset = body.instanceDump(ALIAS_STRING_ID, STRING_CLASS_ID, alias.toByteArray());

        final int relativeArrayOffset = body.primitiveArrayDump(SHARED_ARRAY_ID, BasicType.BYTE, UTF16);
        final int base = hprof.record(HeapRecord.HEAP_DUMP_SEGMENT.getTag(), body);

        this.input = hprof.toByteArray();
        this.arrayOffset = base + relativeArrayOffset;
        this.excludedCoderOffset = base + excludedOffset + relativeExcludedCoderOffset;
        this.aliasCoderOffset = base + aliasOffset + relativeAliasCoderOffset;
    }
}
