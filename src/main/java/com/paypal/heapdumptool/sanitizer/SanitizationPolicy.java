package com.paypal.heapdumptool.sanitizer;

import java.util.ArrayList;
import java.util.Collections;
import java.util.EnumMap;
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

    private final Map<BasicType, Boolean> sanitizeField;
    private final Map<BasicType, Boolean> sanitizeArray;
    private final Map<BasicType, byte[]> replacement;
    private final List<String> warnings;

    public static Builder builder() {
        return new Builder();
    }

    private SanitizationPolicy(final Builder builder) {
        this.sanitizeField = new EnumMap<>(builder.sanitizeField);
        this.sanitizeArray = new EnumMap<>(builder.sanitizeArray);
        this.replacement = new EnumMap<>(builder.replacement);
        this.warnings = Collections.unmodifiableList(new ArrayList<>(builder.warnings));
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
        final byte[] bytes = replacement.get(type);
        if (bytes == null) {
            throw new IllegalArgumentException("No replacement for " + type);
        }
        return bytes.clone();
    }

    public List<String> getWarnings() {
        return warnings;
    }

    @Override
    public String toString() {
        return reflectionToString(this, MULTI_LINE_STYLE);
    }

    static final BasicType[] PRIMITIVES = {
            BasicType.BOOLEAN,
            BasicType.CHAR,
            BasicType.FLOAT,
            BasicType.DOUBLE,
            BasicType.BYTE,
            BasicType.SHORT,
            BasicType.INT,
            BasicType.LONG
    };

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
         * Applies one user-supplied value to every primitive type, converted per type.
         */
        public Builder setAllReplacements(final String value) {
            for (final BasicType type : PRIMITIVES) {
                setReplacement(type, PrimitiveReplacement.encode(type, value));
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
