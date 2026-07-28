package com.paypal.heapdumptool.sanitizer;

import org.apache.commons.text.StringEscapeUtils;
import picocli.CommandLine.Option;

import java.util.ArrayList;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;

/**
 * Sanitization scope and replacement-value options, shared by the sanitize and capture commands.
 *
 * <p>Every option is declared as a <em>setter method</em> rather than a field. picocli invokes
 * annotated setters in exact command-line order, which is what makes
 * {@code --sanitize-all=false --sanitize-ints=true} differ from the reverse. Field injection
 * carries no ordering information.</p>
 *
 * <p>For the same reason no option declares a picocli {@code defaultValue}: picocli applies
 * defaults <em>after</em> matched options, so a default would overwrite whatever the user typed.
 * Defaults are seeded in {@link #resolve()} instead.</p>
 *
 * <h2>Why scope flags use {@code arity = "0..1"}</h2>
 * <p>The 17 scope flags ({@code --sanitize-ints}, etc.) use {@code arity = "0..1"} so that a bare
 * flag without a value, e.g. {@code --sanitize-ints}, is interpreted as {@code true}. With
 * {@code arity = "1"} the bare form would require an explicit value and raise a
 * {@code MissingParameter} error. For typical positional arguments (file paths like
 * {@code in.hprof out.hprof}) there is no conflict: picocli only consumes the next token as the
 * option value if that token converts to a boolean, which ordinary file paths do not. The narrow
 * caveat is a file literally named {@code true} or {@code false}: picocli would consume it as the
 * option value instead of treating it as a positional argument. Such file names are extremely
 * unusual in practice.</p>
 */
public class SanitizeOptions {

    private static final String BOOL = "<true|false>";

    private final List<Directive> directives = new ArrayList<>();

    // ---------- non-array field scope ----------

    @Option(names = "--sanitize-bytes", arity = "0..1", paramLabel = BOOL,
            description = "Sanitize byte fields. Default: true, via --sanitize-all")
    void sanitizeBytes(final boolean enabled) {
        addField(BasicType.BYTE, enabled);
    }

    @Option(names = "--sanitize-shorts", arity = "0..1", paramLabel = BOOL,
            description = "Sanitize short fields. Default: true, via --sanitize-all")
    void sanitizeShorts(final boolean enabled) {
        addField(BasicType.SHORT, enabled);
    }

    @Option(names = "--sanitize-ints", arity = "0..1", paramLabel = BOOL,
            description = "Sanitize int fields. Default: true, via --sanitize-all")
    void sanitizeInts(final boolean enabled) {
        addField(BasicType.INT, enabled);
    }

    @Option(names = "--sanitize-longs", arity = "0..1", paramLabel = BOOL,
            description = "Sanitize long fields. Default: true, via --sanitize-all")
    void sanitizeLongs(final boolean enabled) {
        addField(BasicType.LONG, enabled);
    }

    @Option(names = "--sanitize-chars", arity = "0..1", paramLabel = BOOL,
            description = "Sanitize char fields. Default: true, via --sanitize-all")
    void sanitizeChars(final boolean enabled) {
        addField(BasicType.CHAR, enabled);
    }

    @Option(names = "--sanitize-floats", arity = "0..1", paramLabel = BOOL,
            description = "Sanitize float fields. Default: true, via --sanitize-all")
    void sanitizeFloats(final boolean enabled) {
        addField(BasicType.FLOAT, enabled);
    }

    @Option(names = "--sanitize-doubles", arity = "0..1", paramLabel = BOOL,
            description = "Sanitize double fields. Default: true, via --sanitize-all")
    void sanitizeDoubles(final boolean enabled) {
        addField(BasicType.DOUBLE, enabled);
    }

    @Option(names = "--sanitize-booleans", arity = "0..1", paramLabel = BOOL,
            description = "Sanitize boolean fields. Default: true, via --sanitize-all")
    void sanitizeBooleans(final boolean enabled) {
        addField(BasicType.BOOLEAN, enabled);
    }

    // ---------- array scope ----------

    @Option(names = "--sanitize-byte-arrays", arity = "0..1", paramLabel = BOOL,
            description = "Sanitize byte[] contents. Default: true, via --sanitize-all")
    void sanitizeByteArrays(final boolean enabled) {
        addArray(BasicType.BYTE, enabled);
    }

    @Option(names = "--sanitize-short-arrays", arity = "0..1", paramLabel = BOOL,
            description = "Sanitize short[] contents. Default: true, via --sanitize-all")
    void sanitizeShortArrays(final boolean enabled) {
        addArray(BasicType.SHORT, enabled);
    }

    @Option(names = "--sanitize-int-arrays", arity = "0..1", paramLabel = BOOL,
            description = "Sanitize int[] contents. Default: true, via --sanitize-all")
    void sanitizeIntArrays(final boolean enabled) {
        addArray(BasicType.INT, enabled);
    }

    @Option(names = "--sanitize-long-arrays", arity = "0..1", paramLabel = BOOL,
            description = "Sanitize long[] contents. Default: true, via --sanitize-all")
    void sanitizeLongArrays(final boolean enabled) {
        addArray(BasicType.LONG, enabled);
    }

    @Option(names = "--sanitize-char-arrays", arity = "0..1", paramLabel = BOOL,
            description = "Sanitize char[] contents. Default: true, via --sanitize-all")
    void sanitizeCharArrays(final boolean enabled) {
        addArray(BasicType.CHAR, enabled);
    }

    @Option(names = "--sanitize-float-arrays", arity = "0..1", paramLabel = BOOL,
            description = "Sanitize float[] contents. Default: true, via --sanitize-all")
    void sanitizeFloatArrays(final boolean enabled) {
        addArray(BasicType.FLOAT, enabled);
    }

    @Option(names = "--sanitize-double-arrays", arity = "0..1", paramLabel = BOOL,
            description = "Sanitize double[] contents. Default: true, via --sanitize-all")
    void sanitizeDoubleArrays(final boolean enabled) {
        addArray(BasicType.DOUBLE, enabled);
    }

    @Option(names = "--sanitize-boolean-arrays", arity = "0..1", paramLabel = BOOL,
            description = "Sanitize boolean[] contents. Default: true, via --sanitize-all")
    void sanitizeBooleanArrays(final boolean enabled) {
        addArray(BasicType.BOOLEAN, enabled);
    }

    @Option(names = "--sanitize-all", arity = "0..1", paramLabel = BOOL,
            description = "Sanitize all primitive fields and arrays. Object references are never "
                    + "sanitized. Default: true")
    void sanitizeAll(final boolean enabled) {
        directives.add(new Directive(builder -> builder.setAll(enabled)));
    }

    // ---------- replacement values ----------

    @Option(names = "--sanitize-byte-replacement", paramLabel = "<value>",
            description = "Value to replace byte data with. Default: 42")
    void byteReplacement(final String value) {
        addReplacement(BasicType.BYTE, value);
    }

    @Option(names = "--sanitize-short-replacement", paramLabel = "<value>",
            description = "Value to replace short data with. Default: 0")
    void shortReplacement(final String value) {
        addReplacement(BasicType.SHORT, value);
    }

    @Option(names = "--sanitize-int-replacement", paramLabel = "<value>",
            description = "Value to replace int data with. Default: 0")
    void intReplacement(final String value) {
        addReplacement(BasicType.INT, value);
    }

    @Option(names = "--sanitize-long-replacement", paramLabel = "<value>",
            description = "Value to replace long data with. Default: 0")
    void longReplacement(final String value) {
        addReplacement(BasicType.LONG, value);
    }

    @Option(names = "--sanitize-char-replacement", paramLabel = "<value>",
            description = "Value to replace char data with. Default: '*'")
    void charReplacement(final String value) {
        addReplacement(BasicType.CHAR, value);
    }

    @Option(names = "--sanitize-float-replacement", paramLabel = "<value>",
            description = "Value to replace float data with. Default: 0.0")
    void floatReplacement(final String value) {
        addReplacement(BasicType.FLOAT, value);
    }

    @Option(names = "--sanitize-double-replacement", paramLabel = "<value>",
            description = "Value to replace double data with. Default: 0.0")
    void doubleReplacement(final String value) {
        addReplacement(BasicType.DOUBLE, value);
    }

    @Option(names = "--sanitize-boolean-replacement", paramLabel = "<value>",
            description = "Value to replace boolean data with. Default: false")
    void booleanReplacement(final String value) {
        addReplacement(BasicType.BOOLEAN, value);
    }

    @Option(names = "--sanitize-all-replacement", paramLabel = "<value>",
            description = "Value to replace all primitive data with, converted per type. "
                    + "A number, or a single character such as '*'")
    void allReplacement(final String value) {
        // Encode eagerly so picocli converts any IllegalArgumentException to a ParameterException.
        final Map<BasicType, byte[]> encoded = new EnumMap<>(BasicType.class);
        for (final BasicType type : SanitizationPolicy.PRIMITIVES) {
            encoded.put(type, PrimitiveReplacement.encode(type, value));
        }
        directives.add(new Directive(builder -> {
            for (final BasicType type : SanitizationPolicy.PRIMITIVES) {
                builder.setReplacement(type, encoded.get(type));
            }
        }));
    }

    // ---------- deprecated flag entry points, called from SanitizeOrCaptureCommandBase ----------

    void recordLegacyByteCharArraysOnly(final boolean byteCharArraysOnly) {
        directives.add(new Directive(builder -> {
            builder.addWarning("--sanitize-byte-char-arrays-only is deprecated. Use "
                    + (byteCharArraysOnly
                    ? "--sanitize-all=false --sanitize-byte-arrays=true --sanitize-char-arrays=true"
                    : "--sanitize-all=true"));
            if (byteCharArraysOnly) {
                builder.setAll(false)
                        .setArray(BasicType.BYTE, true)
                        .setArray(BasicType.CHAR, true);
            } else {
                builder.setAll(true);
            }
        }));
    }

    void recordLegacyText(final String text) {
        // e.g. unescape user-supplied \\0 (2 chars) to \0 (1 char)
        final String unescaped = StringEscapeUtils.unescapeJava(text);
        if (unescaped == null || unescaped.length() != 1 || unescaped.charAt(0) > 0x7F) {
            throw new IllegalArgumentException("--text supports only a single ASCII character."
                    + " Use --sanitize-all-replacement instead. Got: " + text);
        }
        final char replacement = unescaped.charAt(0);
        // Use the quoted-character form so that a digit is re-parsed as the character's code point,
        // not as a number. E.g. --text=0 must produce byte 0x30 ('0'), not byte 0x00.
        final String quotedReplacement = "'" + replacement + "'";
        directives.add(new Directive(builder -> {
            builder.addWarning("--text is deprecated. Use --sanitize-all-replacement instead");
            builder.setAllReplacements(quotedReplacement);
        }));
    }

    void recordLegacyTextCharset(final String charset) {
        directives.add(new Directive(builder -> builder.addWarning(
                "--text-charset is deprecated and ignored. Replacement values are now typed per"
                        + " primitive, so no charset is involved. Got: " + charset)));
    }

    // ---------- resolution ----------

    /**
     * Replays every recorded flag, in command-line order, over the default baseline.
     */
    public SanitizationPolicy resolve() {
        final SanitizationPolicy.Builder builder = SanitizationPolicy.builder()
                .setAll(true);

        for (final Directive directive : directives) {
            directive.applyTo(builder);
        }
        return builder.build();
    }

    public void copyFrom(final SanitizeOptions other) {
        if (other == this) {
            // clear() below would empty the very list being copied from, silently discarding
            // every recorded flag
            return;
        }
        directives.clear();
        directives.addAll(other.directives);
    }

    private void addField(final BasicType type, final boolean enabled) {
        directives.add(new Directive(builder -> builder.setField(type, enabled)));
    }

    private void addArray(final BasicType type, final boolean enabled) {
        directives.add(new Directive(builder -> builder.setArray(type, enabled)));
    }

    private void addReplacement(final BasicType type, final String value) {
        final byte[] bytes = PrimitiveReplacement.encode(type, value);
        directives.add(new Directive(builder -> builder.setReplacement(type, bytes)));
    }

    /**
     * One recorded flag, deferred until {@link #resolve()} so ordering is preserved.
     */
    private static class Directive {
        private final PolicyMutation mutation;

        Directive(final PolicyMutation mutation) {
            this.mutation = mutation;
        }

        void applyTo(final SanitizationPolicy.Builder builder) {
            mutation.applyTo(builder);
        }
    }

    private interface PolicyMutation {
        void applyTo(SanitizationPolicy.Builder builder);
    }
}
