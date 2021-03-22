package com.paypal.heapdumptool.sanitizer;

import java.util.Optional;
import java.util.stream.Stream;

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

    private final int u1Code;

    public static int findValueSize(final int u1Code, final int idSize) {
        final BasicType basicType = findByU1Code(u1Code).orElseThrow(() -> new IllegalArgumentException("Unknown basic type code: " + u1Code));
        return basicType.getValueSize(idSize);
    }

    public static Optional<BasicType> findByU1Code(final int u1Code) {
        return Stream.of(BasicType.values())
                     .filter(basicType -> basicType.u1Code == u1Code)
                     .findFirst();
    }

    private BasicType(final int u1Code) {
        this.u1Code = u1Code;
    }

    public int getU1Code() {
        return u1Code;
    }

    private int getValueSize(final int idSize) {
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
