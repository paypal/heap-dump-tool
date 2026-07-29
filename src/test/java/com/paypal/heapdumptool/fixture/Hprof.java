package com.paypal.heapdumptool.fixture;

import com.paypal.heapdumptool.sanitizer.BasicType;
import com.paypal.heapdumptool.sanitizer.HeapRecord;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;

import static java.nio.charset.StandardCharsets.US_ASCII;

/**
 * Builds hprof bytes for tests that need a synthetic heap dump rather than a real one.
 *
 * <p>Also used for record and sub-record bodies, where {@link #offset()} is relative to the start
 * of that body. The write methods return the offset of the payload they wrote wherever a test needs
 * to assert on specific output bytes: sanitization never changes the length of a region --
 * {@code skipInput(n)} is always followed by writing exactly {@code n} bytes -- so an offset
 * recorded while building the input is also valid in the output.</p>
 */
public final class Hprof {

    /** Identifier width of every dump this class builds, i.e. a 64-bit dump. */
    public static final int ID_SIZE = 8;

    // heap dump sub-record tags
    public static final int CLASS_DUMP = 0x20;
    public static final int INSTANCE_DUMP = 0x21;
    public static final int OBJECT_ARRAY_DUMP = 0x22;
    public static final int PRIMITIVE_ARRAY_DUMP = 0x23;

    private final ByteArrayOutputStream buffer = new ByteArrayOutputStream();
    private final DataOutputStream out = new DataOutputStream(buffer);

    public int offset() {
        return out.size();
    }

    public byte[] toByteArray() throws IOException {
        out.flush();
        return buffer.toByteArray();
    }

    public Hprof header() throws IOException {
        out.write("JAVA PROFILE 1.0.2".getBytes(US_ASCII));
        out.write(0);
        out.writeInt(ID_SIZE);
        out.writeInt(0); // timestamp high word
        out.writeInt(0); // timestamp low word
        return this;
    }

    public void u1(final int value) throws IOException {
        out.writeByte(value);
    }

    public void u2(final int value) throws IOException {
        out.writeShort(value);
    }

    public void u4(final long value) throws IOException {
        out.writeInt((int) value);
    }

    public void id(final long value) throws IOException {
        out.writeLong(value);
    }

    public void fill(final int value, final int count) throws IOException {
        for (int i = 0; i < count; i++) {
            out.writeByte(value);
        }
    }

    /**
     * Writes a top level {@code tag / time / length / body} record and returns the absolute
     * offset at which the body starts.
     */
    public int record(final int tag, final Hprof body) throws IOException {
        final byte[] bytes = body.toByteArray();
        u1(tag);
        u4(0); // time
        u4(bytes.length);
        final int base = offset();
        out.write(bytes);
        return base;
    }

    public void stringInUtf8(final long stringId, final String value) throws IOException {
        final Hprof body = new Hprof();
        body.id(stringId);
        body.out.write(value.getBytes(US_ASCII));
        record(HeapRecord.STRING_IN_UTF8.getTag(), body);
    }

    public void loadClass(final int serial, final long classObjectId, final long nameStringId) throws IOException {
        final Hprof body = new Hprof();
        body.u4(serial);
        body.id(classObjectId);
        body.u4(0); // stack trace serial
        body.id(nameStringId);
        record(HeapRecord.LOAD_CLASS.getTag(), body);
    }

    public void classDump(final long classObjectId,
                          final long superClassObjectId,
                          final int[] fieldNameStringIds,
                          final BasicType[] fieldTypes) throws IOException {
        u1(CLASS_DUMP);
        id(classObjectId);
        u4(0); // stack trace serial
        id(superClassObjectId);
        id(0); // class loader
        id(0); // signers
        id(0); // protection domain
        id(0); // reserved
        id(0); // reserved
        u4(0); // instance size
        u2(0); // constant pool records
        u2(0); // static fields
        u2(fieldNameStringIds.length);
        for (int i = 0; i < fieldNameStringIds.length; i++) {
            id(fieldNameStringIds[i]);
            u1(fieldTypes[i].getU1Code());
        }
    }

    /**
     * Writes an instance dump sub-record and returns the offset of the first payload byte,
     * relative to the start of this builder.
     */
    public int instanceDump(final long objectId, final long classObjectId, final byte[] payload) throws IOException {
        u1(INSTANCE_DUMP);
        id(objectId);
        u4(0); // stack trace serial
        id(classObjectId);
        u4(payload.length);
        final int payloadOffset = offset();
        out.write(payload);
        return payloadOffset;
    }

    /**
     * Writes a primitive array dump sub-record and returns the offset of the first element
     * byte, relative to the start of this builder.
     */
    public int primitiveArrayDump(final long objectId, final BasicType elementType, final byte[] data) throws IOException {
        u1(PRIMITIVE_ARRAY_DUMP);
        id(objectId);
        u4(0); // stack trace serial
        u4(data.length / elementType.getValueSize(ID_SIZE));
        u1(elementType.getU1Code());
        final int dataOffset = offset();
        out.write(data);
        return dataOffset;
    }

    /**
     * Writes an object array dump sub-record -- array object id, u4 stack trace serial, u4 number
     * of elements, ID array class id, then one ID per element -- and returns the offset of the
     * first element, relative to the start of this builder.
     */
    public int objectArrayDump(final long arrayObjectId, final long arrayClassId, final long... elementIds)
            throws IOException {
        u1(OBJECT_ARRAY_DUMP);
        id(arrayObjectId);
        u4(0); // stack trace serial
        u4(elementIds.length);
        id(arrayClassId);
        final int elementsOffset = offset();
        for (final long elementId : elementIds) {
            id(elementId);
        }
        return elementsOffset;
    }
}
