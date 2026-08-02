package com.paypal.heapdumptool.fixture;

import com.paypal.heapdumptool.sanitizer.BasicType;
import com.paypal.heapdumptool.sanitizer.HeapRecord;

import java.io.IOException;
import java.util.Arrays;
import java.util.EnumMap;
import java.util.Map;

import static com.paypal.heapdumptool.fixture.Hprof.ID_SIZE;

/**
 * One instance with exactly one field of each of the 8 primitive types, plus one primitive array
 * dump of each of the 8 types. Every payload byte is {@link #UNSANITIZED_BYTE}, which differs from
 * every type's default replacement, so "sanitized" and "preserved" are distinguishable byte for
 * byte.
 */
public final class AllPrimitivesFixture {

    /**
     * The 8 sanitizable primitive types. {@link BasicType#OBJECT} is deliberately absent: object
     * references are never sanitizable.
     */
    public static final BasicType[] ALL_PRIMITIVES = {
            BasicType.BYTE, BasicType.BOOLEAN, BasicType.CHAR, BasicType.SHORT,
            BasicType.INT, BasicType.FLOAT, BasicType.LONG, BasicType.DOUBLE
    };

    /**
     * Fill byte for every payload here. Chosen to differ from every byte of every type's default
     * replacement (0x00 and 0x2A), so a preserved region and a sanitized region can never be
     * confused.
     */
    public static final int UNSANITIZED_BYTE = 0x5A;

    /** Element count of every primitive array in this fixture. */
    public static final int ARRAY_LENGTH = 4;

    private static final long CLASS_ID = 900;
    private static final long INSTANCE_ID = 0x9000;
    private static final long FIRST_ARRAY_ID = 0x9100;

    /** The dump bytes to feed the sanitizer. */
    public final byte[] input;

    private final Map<BasicType, Integer> fieldOffsets = new EnumMap<>(BasicType.class);
    private final Map<BasicType, Integer> arrayOffsets = new EnumMap<>(BasicType.class);

    public AllPrimitivesFixture() throws IOException {
        final Hprof hprof = new Hprof().header();
        hprof.stringInUtf8(90, "com.example.AllPrimitives");

        final int[] fieldNameStringIds = new int[ALL_PRIMITIVES.length];
        for (int i = 0; i < ALL_PRIMITIVES.length; i++) {
            fieldNameStringIds[i] = 91 + i;
            hprof.stringInUtf8(fieldNameStringIds[i], "field" + ALL_PRIMITIVES[i].name());
        }
        hprof.loadClass(1, CLASS_ID, 90);

        final Hprof body = new Hprof();
        body.classDump(CLASS_ID, 0, fieldNameStringIds, ALL_PRIMITIVES);

        final Hprof instance = new Hprof();
        final Map<BasicType, Integer> relativeFieldOffsets = new EnumMap<>(BasicType.class);
        for (final BasicType type : ALL_PRIMITIVES) {
            relativeFieldOffsets.put(type, instance.offset());
            instance.fill(UNSANITIZED_BYTE, type.getValueSize(ID_SIZE));
        }
        final int instanceOffset = body.instanceDump(INSTANCE_ID, CLASS_ID, instance.toByteArray());

        final Map<BasicType, Integer> relativeArrayOffsets = new EnumMap<>(BasicType.class);
        for (int i = 0; i < ALL_PRIMITIVES.length; i++) {
            final BasicType type = ALL_PRIMITIVES[i];
            final byte[] data = new byte[ARRAY_LENGTH * type.getValueSize(ID_SIZE)];
            Arrays.fill(data, (byte) UNSANITIZED_BYTE);
            relativeArrayOffsets.put(type, body.primitiveArrayDump(FIRST_ARRAY_ID + i, type, data));
        }

        final int base = hprof.record(HeapRecord.HEAP_DUMP_SEGMENT.getTag(), body);
        this.input = hprof.toByteArray();

        for (final BasicType type : ALL_PRIMITIVES) {
            fieldOffsets.put(type, base + instanceOffset + relativeFieldOffsets.get(type));
            arrayOffsets.put(type, base + relativeArrayOffsets.get(type));
        }
    }

    /** Absolute offset of the given type's non-array field. */
    public int fieldOffset(final BasicType type) {
        return fieldOffsets.get(type);
    }

    /** Absolute offset of the given type's primitive array payload. */
    public int arrayOffset(final BasicType type) {
        return arrayOffsets.get(type);
    }
}
