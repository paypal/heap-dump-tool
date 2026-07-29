package com.paypal.heapdumptool.sanitizer;

import java.util.ArrayList;
import java.util.Collections;
import java.util.EnumMap;
import java.util.EnumSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.apache.commons.lang3.builder.ToStringBuilder.reflectionToString;
import static org.apache.commons.lang3.builder.ToStringStyle.MULTI_LINE_STYLE;

/**
 * The resolved outcome of all sanitization flags: which types are sanitized, and with what bytes.
 *
 * <p>Immutable. Built by {@link SanitizeOptions#resolve()}, which replays the
 * command-line flags in order over a default baseline.</p>
 */
public class SanitizationPolicy {

    static final Set<BasicType> PRIMITIVES = EnumSet.of(
            BasicType.BOOLEAN,
            BasicType.CHAR,
            BasicType.FLOAT,
            BasicType.DOUBLE,
            BasicType.BYTE,
            BasicType.SHORT,
            BasicType.INT,
            BasicType.LONG
    );

    private final Map<BasicType, Boolean> sanitizeField;
    private final Map<BasicType, Boolean> sanitizeArray;
    private final Map<BasicType, Replacement> replacement;
    private final List<String> warnings;

    public static Builder builder() {
        return new Builder();
    }

    private SanitizationPolicy(final Builder builder) {
        this.sanitizeField = new EnumMap<>(builder.sanitizeField);
        this.sanitizeArray = new EnumMap<>(builder.sanitizeArray);
        this.warnings = Collections.unmodifiableList(new ArrayList<>(builder.warnings));

        // Tile each replacement once, here, rather than per sanitized region. The policy is
        // immutable and resolved once per run, so the tiled buffers can be shared by every region
        // of their type. See Replacement.
        this.replacement = new EnumMap<>(BasicType.class);
        for (final Map.Entry<BasicType, byte[]> entry : builder.replacement.entrySet()) {
            this.replacement.put(entry.getKey(), new Replacement(entry.getValue()));
        }
    }

    public boolean sanitizeField(final BasicType type) {
        return Boolean.TRUE.equals(sanitizeField.get(type));
    }

    public boolean sanitizeArray(final BasicType type) {
        return Boolean.TRUE.equals(sanitizeArray.get(type));
    }

    /**
     * Whether any non-array primitive field is sanitized. Drives whether per-class
     * field layouts must be tracked while streaming.
     */
    public boolean isAnyFieldSanitized() {
        for (final BasicType type : PRIMITIVES) {
            if (sanitizeField(type)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Replacement bytes for the given type, big-endian, exactly the type's width.
     */
    public byte[] replacement(final BasicType type) {
        return replacementOf(type).getBytes();
    }

    /**
     * The given type's replacement with its pre-tiled buffer. Allocation-free, unlike
     * {@link #replacement(BasicType)}, so this is what the streaming path uses.
     */
    Replacement replacementOf(final BasicType type) {
        final Replacement value = replacement.get(type);
        if (value == null) {
            throw new IllegalArgumentException("No replacement for " + type);
        }
        return value;
    }

    public List<String> getWarnings() {
        return warnings;
    }

    @Override
    public String toString() {
        return reflectionToString(this, MULTI_LINE_STYLE);
    }

    public static class Builder {

        private final Map<BasicType, Boolean> sanitizeField = new EnumMap<>(BasicType.class);
        private final Map<BasicType, Boolean> sanitizeArray = new EnumMap<>(BasicType.class);
        private final Map<BasicType, byte[]> replacement = new EnumMap<>(BasicType.class);

        // LinkedHashSet: deduplicate while preserving first-seen order. See addWarning.
        private final Set<String> warnings = new LinkedHashSet<>();

        private Builder() {
            for (final BasicType type : PRIMITIVES) {
                sanitizeField.put(type, false);
                sanitizeArray.put(type, false);
                replacement.put(type, PrimitiveReplacement.defaultFor(type));
            }
        }

        public Builder setField(final BasicType type, final boolean enabled) {
            if (type == BasicType.OBJECT) {
                throw new IllegalArgumentException("Cannot sanitize OBJECT references: overwriting object ids corrupts the heap dump");
            }
            sanitizeField.put(type, enabled);
            return this;
        }

        public Builder setArray(final BasicType type, final boolean enabled) {
            if (type == BasicType.OBJECT) {
                throw new IllegalArgumentException("Cannot sanitize OBJECT references: overwriting object ids corrupts the heap dump");
            }
            sanitizeArray.put(type, enabled);
            return this;
        }

        /**
         * Sets every primitive field and array at once. Never affects
         * {@link BasicType#OBJECT} -- overwriting object ids corrupts the dump.
         */
        public Builder setAll(final boolean enabled) {
            for (final BasicType type : PRIMITIVES) {
                setField(type, enabled);
                setArray(type, enabled);
            }
            return this;
        }

        public Builder setReplacement(final BasicType type, final byte[] bytes) {
            replacement.put(type, bytes.clone());
            return this;
        }

        /**
         * Applies one user-supplied value to every primitive type, converted per type. A character
         * literal is normalized to its code point so the numeric types accept it, since a character
         * literal is otherwise a char-only form. See
         * {@link PrimitiveReplacement#toCodePointIfCharLiteral(String)}.
         */
        public Builder setAllReplacements(final String value) {
            final String normalized = PrimitiveReplacement.toCodePointIfCharLiteral(value);
            for (final BasicType type : PRIMITIVES) {
                setReplacement(type, PrimitiveReplacement.encode(type, normalized));
            }
            return this;
        }

        /**
         * Records a warning, ignoring an exact duplicate of one already recorded.
         *
         * <p>Deduplication is deliberate rather than defensive. A deprecated flag can only warn
         * once per invocation -- picocli raises {@code OverwrittenOptionException} if the same
         * option is passed twice -- so an identical warning can only arise from the same flag
         * being recorded more than once. That happens on every real run: {@code Application.main}
         * parses the same {@code CommandLine} twice, once via
         * {@code PrivilegeEscalator.escalatePrivilegesIfNeeded} and once via
         * {@code CommandLine.execute}, and picocli reuses the same user object, so every option
         * setter -- and hence every recorded directive -- fires twice. Replaying an idempotent
         * directive sequence twice leaves the scope and replacement values unchanged, but appended
         * warnings would otherwise accumulate and be logged twice.</p>
         */
        public Builder addWarning(final String warning) {
            warnings.add(warning);
            return this;
        }

        public SanitizationPolicy build() {
            return new SanitizationPolicy(this);
        }
    }
}
