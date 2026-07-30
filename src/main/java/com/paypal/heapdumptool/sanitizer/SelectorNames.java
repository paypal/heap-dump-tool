package com.paypal.heapdumptool.sanitizer;

import org.apache.commons.lang3.StringUtils;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * The vocabulary shared by {@code --target} and {@code --replacement}: the primitive type names,
 * and the rule that makes a trailing {@code s} optional so {@code bytes} and {@code byte} are one
 * word.
 *
 * <p>Normalization is deliberately per token rather than per whole selector. {@code --target}
 * splits {@code bytes-arrays} into its two components and normalizes each, which is what admits the
 * mixed forms ({@code bytes-array}) from one rule instead of an alias table.</p>
 */
final class SelectorNames {

    private static final Map<String, BasicType> TYPES_BY_NAME = newTypesByName();

    private static final String TYPE_NAMES = String.join(", ", sortedTypeNames());

    static final String OBJECT = "object";

    /**
     * Trims, lowercases and drops at most one trailing {@code s}. A bare {@code "s"} is left alone:
     * stripping it would produce the empty string, which is not a name.
     */
    static String normalize(final String token) {
        final String trimmed = StringUtils.trimToEmpty(token).toLowerCase();
        if (trimmed.length() > 1 && trimmed.endsWith("s")) {
            return trimmed.substring(0, trimmed.length() - 1);
        }
        return trimmed;
    }

    /**
     * The type an already-{@link #normalize(String) normalized} token names, or null if it names no
     * primitive type. {@code object} yields null like any other non-primitive; use
     * {@link #isObject(String)} to tell the two apart, since the two flags word that error
     * differently.
     */
    static BasicType findType(final String normalizedToken) {
        return TYPES_BY_NAME.get(normalizedToken);
    }

    static boolean isObject(final String normalizedToken) {
        return OBJECT.equals(normalizedToken);
    }

    /**
     * The valid type names, comma-separated and sorted, for error messages.
     */
    static String typeNames() {
        return TYPE_NAMES;
    }

    private static Map<String, BasicType> newTypesByName() {
        final Map<String, BasicType> map = new HashMap<>();
        for (final BasicType type : SanitizationPolicy.PRIMITIVES) {
            map.put(type.name().toLowerCase(), type);
        }
        return Collections.unmodifiableMap(map);
    }

    private static List<String> sortedTypeNames() {
        final List<String> names = new ArrayList<>(newTypesByName().keySet());
        Collections.sort(names);
        return names;
    }

    private SelectorNames() {
        throw new AssertionError();
    }
}
