package com.paypal.heapdumptool.sanitizer;

import org.apache.commons.lang3.StringUtils;

import java.util.ArrayList;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;

/**
 * Parses a {@code --replacement} spec into an ordered list of replacement-value mutations.
 *
 * <p>Grammar: comma-separated {@code <type>=<value>} entries applied left to right, where
 * {@code <type>} is a primitive type name with an optional trailing {@code s}, or {@code all}. The
 * {@code <value>} grammar belongs to {@link PrimitiveReplacement} and is unchanged by this class.</p>
 *
 * <p>{@code all=<value>} normalizes a character literal to its code point first, so every numeric
 * type accepts it: {@code all=*} gives {@code byte=42}, {@code int=42}, {@code char='*'}. A
 * per-type entry deliberately does not, which keeps a character literal a {@code char}-only form --
 * {@code int=*} is a usage error, not code point 42.</p>
 */
final class ReplacementSpec {

    private static final String ALL = "all";

    private static final String EXPECTED = "Expected <type>=<value> entries separated by ',',"
            + " where <type> is 'all' or one of " + SelectorNames.typeNames()
            + " (a trailing 's' is optional)";

    /**
     * Parses {@code value} and applies every entry, in order, to {@code builder}.
     *
     * @throws IllegalArgumentException if the spec is malformed or a value is invalid for its type.
     *                                  Parsing and encoding complete before the first mutation is
     *                                  applied, so a rejected spec leaves the builder untouched.
     */
    static void applyTo(final String value, final SanitizationPolicy.Builder builder) {
        for (final Entry entry : parse(value)) {
            entry.applyTo(builder);
        }
    }

    /**
     * Parses and discards, so a flag value can be rejected at parse time rather than at use time.
     *
     * @throws IllegalArgumentException if the spec is malformed
     */
    static void validate(final String value) {
        parse(value);
    }

    private static List<Entry> parse(final String value) {
        if (StringUtils.isBlank(value)) {
            throw new IllegalArgumentException("--replacement value is empty. " + EXPECTED);
        }

        final List<Entry> entries = new ArrayList<>();
        for (final String text : value.split(",", -1)) {
            entries.add(parseEntry(text));
        }
        return entries;
    }

    private static Entry parseEntry(final String text) {
        final String trimmed = StringUtils.trimToEmpty(text);
        if (trimmed.isEmpty()) {
            throw new IllegalArgumentException("--replacement has an empty entry. " + EXPECTED);
        }

        final int equals = trimmed.indexOf('=');
        if (equals < 0) {
            throw new IllegalArgumentException("--replacement entry '" + trimmed
                    + "' has no '='. " + EXPECTED);
        }

        final String typeText = StringUtils.trimToEmpty(trimmed.substring(0, equals));
        final String valueText = StringUtils.trimToEmpty(trimmed.substring(equals + 1));
        if (typeText.isEmpty()) {
            throw new IllegalArgumentException("--replacement entry '" + trimmed
                    + "' has an empty type. " + EXPECTED);
        }
        if (valueText.isEmpty()) {
            throw new IllegalArgumentException("--replacement entry '" + trimmed
                    + "' has an empty value. " + EXPECTED);
        }

        final String typeToken = SelectorNames.normalize(typeText);
        if (ALL.equals(typeToken) && !typeText.trim().toLowerCase().endsWith("s")) {
            return newAllEntry(valueText);
        }
        return newTypeEntry(typeText, typeToken, valueText);
    }

    /**
     * Encodes eagerly, for every type, so an invalid value is a parse-time error rather than a
     * surprise at apply time.
     */
    private static Entry newAllEntry(final String valueText) {
        final String normalized = PrimitiveReplacement.toCodePointIfCharLiteral(valueText);
        final Map<BasicType, byte[]> encoded = new EnumMap<>(BasicType.class);
        for (final BasicType type : SanitizationPolicy.PRIMITIVES) {
            encoded.put(type, PrimitiveReplacement.encode(type, normalized));
        }
        return new Entry(encoded);
    }

    private static Entry newTypeEntry(final String typeText,
                                      final String typeToken,
                                      final String valueText) {
        if (SelectorNames.isObject(typeToken)) {
            throw new IllegalArgumentException("--replacement cannot set 'object': overwriting"
                    + " object ids would corrupt the heap dump. Valid types are "
                    + SelectorNames.typeNames());
        }
        final BasicType type = SelectorNames.findType(typeToken);
        if (type == null) {
            throw new IllegalArgumentException("Unknown --replacement type: " + typeText + ". "
                    + EXPECTED);
        }

        final Map<BasicType, byte[]> encoded = new EnumMap<>(BasicType.class);
        encoded.put(type, PrimitiveReplacement.encode(type, valueText));
        return new Entry(encoded);
    }

    /**
     * One parsed entry, with its value already encoded per type.
     */
    private static class Entry {
        private final Map<BasicType, byte[]> encoded;

        Entry(final Map<BasicType, byte[]> encoded) {
            this.encoded = encoded;
        }

        void applyTo(final SanitizationPolicy.Builder builder) {
            for (final Map.Entry<BasicType, byte[]> replacement : encoded.entrySet()) {
                builder.setReplacement(replacement.getKey(), replacement.getValue());
            }
        }
    }

    private ReplacementSpec() {
        throw new AssertionError();
    }
}
