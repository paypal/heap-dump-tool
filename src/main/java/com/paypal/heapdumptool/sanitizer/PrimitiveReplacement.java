package com.paypal.heapdumptool.sanitizer;

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.text.StringEscapeUtils;

import java.nio.ByteBuffer;

/**
 * Parses a user-supplied replacement value into bytes of a specific {@link BasicType}.
 *
 * <p>Value grammar:</p>
 * <ul>
 *   <li>a decimal number is that numeric value, for every type: {@code 42}, {@code -1}, {@code 0.5}</li>
 *   <li>{@link BasicType#CHAR} also accepts a character literal -- a lone non-digit character
 *       ({@code *} is code point 42, {@code a} is 97) or a backslash escape ({@code \0} is 0,
 *       {@code \98} is 98 ({@code b}), {@code \t} is 9). The numeric types do not: they take a number
 *       only.</li>
 *   <li>{@code true} / {@code false} are accepted for {@link BasicType#BOOLEAN} only</li>
 * </ul>
 *
 * <p>For char, a bare digit is a number ({@code 4} is code point 4); to mean the character, escape
 * its code point ({@code \52} is {@code '4'}). A char value of more than one character is rejected,
 * so the quoted form {@code '*'} is a usage error rather than a synonym for {@code *}.</p>
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
                return "*";
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

    /**
     * Normalizes a value for the flags that apply one replacement to every type
     * ({@code --replacement=all=<value>}, the deprecated {@code -t}): a character literal becomes
     * its decimal code point, so the numeric types accept it as a number while
     * {@link BasicType#CHAR} still reads that number as a code point. Any other value is returned
     * unchanged. Per-type entries in the replacement list (e.g. {@code int=42}) do not call this,
     * so a character literal remains a char-only form for them.
     */
    public static String toCodePointIfCharLiteral(final String value) {
        if (StringUtils.isEmpty(value)) {
            return value;
        }
        final Character character = asCharacterLiteral(value);
        return character == null ? value : Integer.toString(character);
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
                buffer.putChar((char) parseChar(value));
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
        // Accept any whole number: nonzero means true, zero means false.
        try {
            return Long.parseLong(value) != 0;
        } catch (final NumberFormatException e) {
            throw new IllegalArgumentException("Invalid boolean replacement value: " + value
                    + ". Expected true, false, or a number");
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
        try {
            return Long.parseLong(value);
        } catch (final NumberFormatException e) {
            throw new IllegalArgumentException("Invalid " + lowerName(type) + " replacement value: " + value
                    + ". Expected a whole number");
        }
    }

    /**
     * The code point a {@link BasicType#CHAR} replacement denotes. Unlike the numeric types, char
     * accepts a character literal ({@code *}, {@code \0}, {@code \98}) as well as a bare number.
     */
    private static int parseChar(final String value) {
        final Character character = asCharacterLiteral(value);
        if (character != null) {
            return character;
        }
        final long parsed = parseNumber(BasicType.CHAR, value);
        if (parsed < Character.MIN_VALUE || parsed > Character.MAX_VALUE) {
            throw new IllegalArgumentException("Replacement value " + value + " is out of range for char. Expected "
                    + (int) Character.MIN_VALUE + ".." + (int) Character.MAX_VALUE);
        }
        return (int) parsed;
    }

    private static double parseDecimal(final BasicType type, final String value) {
        try {
            return Double.parseDouble(value);
        } catch (final NumberFormatException e) {
            throw new IllegalArgumentException("Invalid " + lowerName(type) + " replacement value: " + value
                    + ". Expected a number");
        }
    }

    /**
     * Returns the character a value denotes, or null if the value is not a character literal.
     * Accepts a lone non-digit character ({@code *}) or a backslash escape ({@code \0}, {@code \98},
     * {@code \t}).
     *
     * @throws IllegalArgumentException if the value starts with a backslash but denotes no single character
     */
    private static Character asCharacterLiteral(final String value) {
        if (value.charAt(0) == '\\') {
            return unescapeToSingleChar(value);
        }
        if (value.length() == 1 && !Character.isDigit(value.charAt(0))) {
            return value.charAt(0);
        }
        return null;
    }

    /**
     * Resolves a backslash escape to the single character it denotes.
     *
     * <p>{@code \} followed only by digits is that decimal code point, so {@code \0} is NUL and
     * {@code \98} is {@code 'b'}. This deliberately overrides Java's octal escape reading of the
     * same text -- decimal is consistent with the unescaped forms of this grammar, which are
     * decimal throughout. Every other escape is Java's: {@code \t}, {@code \n}, {@code \\} and
     * the unicode form.</p>
     */
    private static Character unescapeToSingleChar(final String value) {
        final String body = value.substring(1);
        if (!body.isEmpty() && StringUtils.isNumeric(body)) {
            final int codePoint = parseCodePoint(value, body);
            return (char) codePoint;
        }

        final String unescaped = StringEscapeUtils.unescapeJava(value);
        if (unescaped == null || unescaped.length() != 1) {
            throw new IllegalArgumentException("Invalid escape sequence: " + value
                    + ". Expected a single character, such as \\0, \\98 or \\t");
        }
        return unescaped.charAt(0);
    }

    private static int parseCodePoint(final String value, final String digits) {
        final int codePoint;
        try {
            codePoint = Integer.parseInt(digits);
        } catch (final NumberFormatException e) {
            throw new IllegalArgumentException("Character code out of range: " + value
                    + ". Expected " + (int) Character.MIN_VALUE + ".." + (int) Character.MAX_VALUE);
        }
        if (codePoint > Character.MAX_VALUE) {
            throw new IllegalArgumentException("Character code out of range: " + value
                    + ". Expected " + (int) Character.MIN_VALUE + ".." + (int) Character.MAX_VALUE);
        }
        return codePoint;
    }

    private static String lowerName(final BasicType type) {
        return type.name().toLowerCase();
    }

    private PrimitiveReplacement() {
        throw new AssertionError();
    }
}
