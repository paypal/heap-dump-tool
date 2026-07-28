package com.paypal.heapdumptool.sanitizer;

import org.apache.commons.lang3.StringUtils;

import java.nio.ByteBuffer;

/**
 * Parses a user-supplied replacement value into bytes of a specific {@link BasicType}.
 *
 * <p>Value grammar, uniform across all primitive types:</p>
 * <ul>
 *   <li>a decimal number is that numeric value: {@code 42}, {@code -1}, {@code 0.5}</li>
 *   <li>a single character, bare or single-quoted, is that character's code point:
 *       {@code '*'} and {@code *} both mean 42</li>
 *   <li>{@code true} / {@code false} are accepted for {@link BasicType#BOOLEAN} only</li>
 * </ul>
 *
 * <p>A bare digit is a number ({@code 4} is 4); the quoted form is the character
 * ({@code '4'} is 52).</p>
 */
public final class PrimitiveReplacement {

    private static final int ID_SIZE_UNUSED = 8;

    public static byte[] defaultFor(final BasicType type) {
        return encode(type, defaultValueText(type));
    }

    public static String defaultValueText(final BasicType type) {
        switch (type) {
            case BYTE:
                return "42";
            case CHAR:
                return "'*'";
            case SHORT:
            case INT:
            case LONG:
                return "0";
            case FLOAT:
            case DOUBLE:
                return "0.0";
            case BOOLEAN:
                return "false";
            default:
                throw new IllegalArgumentException("No replacement for " + type);
        }
    }

    public static byte[] encode(final BasicType type, final String value) {
        if (type == BasicType.OBJECT) {
            throw new IllegalArgumentException("Cannot sanitize OBJECT references");
        }
        if (StringUtils.isEmpty(value)) {
            throw new IllegalArgumentException("Empty replacement value for " + lowerName(type));
        }

        final int width = type.getValueSize(ID_SIZE_UNUSED);
        final ByteBuffer buffer = ByteBuffer.allocate(width);

        switch (type) {
            case BOOLEAN:
                buffer.put((byte) (parseBoolean(value) ? 1 : 0));
                break;
            case FLOAT:
                buffer.putFloat((float) parseDecimal(type, value));
                break;
            case DOUBLE:
                buffer.putDouble(parseDecimal(type, value));
                break;
            case CHAR:
                buffer.putChar((char) parseIntegral(type, value, Character.MIN_VALUE, Character.MAX_VALUE));
                break;
            case BYTE:
                buffer.put((byte) parseIntegral(type, value, Byte.MIN_VALUE, Byte.MAX_VALUE));
                break;
            case SHORT:
                buffer.putShort((short) parseIntegral(type, value, Short.MIN_VALUE, Short.MAX_VALUE));
                break;
            case INT:
                buffer.putInt((int) parseIntegral(type, value, Integer.MIN_VALUE, Integer.MAX_VALUE));
                break;
            case LONG:
                buffer.putLong(parseIntegral(type, value, Long.MIN_VALUE, Long.MAX_VALUE));
                break;
            default:
                throw new IllegalArgumentException("Unknown basic type: " + type);
        }

        return buffer.array();
    }

    private static boolean parseBoolean(final String value) {
        if ("true".equalsIgnoreCase(value)) {
            return true;
        }
        if ("false".equalsIgnoreCase(value)) {
            return false;
        }
        final Character character = asCharacterLiteral(value);
        if (character != null) {
            return character != 0;
        }
        // Accept any whole number: nonzero means true, zero means false.
        try {
            return Long.parseLong(value) != 0;
        } catch (final NumberFormatException e) {
            throw new IllegalArgumentException("Invalid boolean replacement value: " + value
                    + ". Expected true, false, a number, or a single character such as '*'");
        }
    }

    private static long parseIntegral(final BasicType type,
                                      final String value,
                                      final long min,
                                      final long max) {
        final long parsed = parseNumber(type, value);
        if (parsed < min || parsed > max) {
            throw new IllegalArgumentException("Replacement value " + value + " is out of range for "
                    + lowerName(type) + ". Expected " + min + ".." + max);
        }
        return parsed;
    }

    private static long parseNumber(final BasicType type, final String value) {
        final Character character = asCharacterLiteral(value);
        if (character != null) {
            return character;
        }
        try {
            return Long.parseLong(value);
        } catch (final NumberFormatException e) {
            throw new IllegalArgumentException("Invalid " + lowerName(type) + " replacement value: " + value
                    + ". Expected a whole number or a single character such as '*'");
        }
    }

    private static double parseDecimal(final BasicType type, final String value) {
        final Character character = asCharacterLiteral(value);
        if (character != null) {
            return character;
        }
        try {
            return Double.parseDouble(value);
        } catch (final NumberFormatException e) {
            throw new IllegalArgumentException("Invalid " + lowerName(type) + " replacement value: " + value
                    + ". Expected a number or a single character such as '*'");
        }
    }

    /**
     * Returns the character a value denotes, or null if the value is not a character literal.
     * Accepts a single-quoted character ('*') or a lone non-digit character (*).
     */
    private static Character asCharacterLiteral(final String value) {
        if (value.length() == 3 && value.charAt(0) == '\'' && value.charAt(2) == '\'') {
            return value.charAt(1);
        }
        if (value.length() == 1 && !Character.isDigit(value.charAt(0))) {
            return value.charAt(0);
        }
        return null;
    }

    private static String lowerName(final BasicType type) {
        return type.name().toLowerCase();
    }

    private PrimitiveReplacement() {
        throw new AssertionError();
    }
}
