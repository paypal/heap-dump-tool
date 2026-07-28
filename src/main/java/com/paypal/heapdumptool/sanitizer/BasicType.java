package com.paypal.heapdumptool.sanitizer;

import java.util.Optional;

public enum BasicType {
    OBJECT(2),
    BOOLEAN(4),
    CHAR(5),
    FLOAT(6),
    DOUBLE(7),
    BYTE(8),
    SHORT(9),
    INT(10),
    LONG(11);

    /*
     * u1Code -> type, indexed directly by the code. findByU1Code is called several times for every
     * field of every instance dump, which is the hottest path in the tool: streaming values() there
     * allocated a stream, a lambda capture and an Optional per call, tens of millions of times on a
     * large dump. Codes are a small dense range (2..11), so a plain array indexed by code is both
     * allocation-free and branch-free.
     */
    private static final BasicType[] BY_U1_CODE = newByU1CodeTable();

    private final int u1Code;

    public static int findValueSize(final int u1Code, final int idSize) {
        final BasicType basicType = byU1Code(u1Code);
        if (basicType == null) {
            throw new IllegalArgumentException("Unknown basic type code: " + u1Code);
        }
        return basicType.getValueSize(idSize);
    }

    public static Optional<BasicType> findByU1Code(final int u1Code) {
        return Optional.ofNullable(byU1Code(u1Code));
    }

    /**
     * The type with the given code, or null if the code is not a basic type. Unlike
     * {@link #findByU1Code(int)} this allocates nothing, so it is what the streaming path uses.
     */
    static BasicType byU1Code(final int u1Code) {
        if (u1Code < 0 || u1Code >= BY_U1_CODE.length) {
            return null;
        }
        return BY_U1_CODE[u1Code];
    }

    private static BasicType[] newByU1CodeTable() {
        int maxCode = 0;
        for (final BasicType type : values()) {
            maxCode = Math.max(maxCode, type.u1Code);
        }
        final BasicType[] table = new BasicType[maxCode + 1];
        for (final BasicType type : values()) {
            table[type.u1Code] = type;
        }
        return table;
    }

    BasicType(final int u1Code) {
        this.u1Code = u1Code;
    }

    public int getU1Code() {
        return u1Code;
    }

    public int getValueSize(final int idSize) {
        switch (this) {
            case OBJECT:
                return idSize;
            case BOOLEAN:
                return 1;
            case CHAR:
                return 2;
            case FLOAT:
                return 4;
            case DOUBLE:
                return 8;
            case BYTE:
                return 1;
            case SHORT:
                return 2;
            case INT:
                return 4;
            case LONG:
                return 8;
            default:
                throw new IllegalArgumentException("Unknown basic type: " + this);
        }
    }

}
