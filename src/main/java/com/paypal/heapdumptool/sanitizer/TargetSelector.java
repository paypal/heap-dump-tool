package com.paypal.heapdumptool.sanitizer;

import org.apache.commons.lang3.StringUtils;

import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;

/**
 * Parses a {@code --target} selector list into an ordered list of scope mutations.
 *
 * <p>Grammar: comma-separated entries, applied left to right over a base of {@code none}. An entry
 * may be prefixed {@code -} to subtract. An entry is one of:</p>
 *
 * <pre>
 *   all | none                   every primitive field and array | nothing
 *   &lt;type&gt;                       that type's field AND array
 *   &lt;type&gt;-field | &lt;type&gt;-array  one half of that type
 *   field | array                that half of every type
 * </pre>
 *
 * <p>A trailing {@code s} is optional on each component, so {@code byte-arrays} and
 * {@code bytes-array} both parse. See {@link SelectorNames}.</p>
 *
 * <p>"Field" means a field of primitive type, such as {@code int count}. An array-typed field like
 * {@code byte[] data} holds an object reference and is never sanitized by a field selector; what
 * {@code byte-array} selects is the contents of the array object it refers to. The two halves
 * therefore partition the sanitizable data instead of overlapping.</p>
 *
 * <p>{@code all} and {@code none} are ordinary entries rather than special leading syntax: they are
 * legal in any position and mean the same thing there. Their usual appearance first is just the
 * visible consequence of the base being {@code none}, so {@code all,-int} and {@code none,all,-int}
 * are the same policy.</p>
 *
 * <p>A subtraction may not lead the list. {@code -int} would be a silent no-op -- base {@code none}
 * minus {@code int} is still nothing -- so it is rejected with a message pointing at
 * {@code all,-int}.</p>
 */
final class TargetSelector {

    private static final String ALL = "all";
    private static final String NONE = "none";
    private static final String FIELD = "field";
    private static final String ARRAY = "array";

    private static final String VALID_SELECTORS = "all, none, field, array, <type>, <type>-field,"
            + " <type>-array, where <type> is one of " + SelectorNames.typeNames()
            + " (a trailing 's' is optional)";

    /**
     * Parses {@code value} and applies every entry, in order, to {@code builder}.
     *
     * @throws IllegalArgumentException if the list is malformed. Parsing completes before the first
     *                                  mutation is applied, so a rejected list leaves the builder
     *                                  untouched.
     */
    static void applyTo(final String value, final SanitizationPolicy.Builder builder) {
        for (final Step step : parse(value)) {
            step.applyTo(builder);
        }
    }

    /**
     * Parses and discards, so a flag value can be rejected at parse time rather than at use time.
     *
     * @throws IllegalArgumentException if the list is malformed
     */
    static void validate(final String value) {
        parse(value);
    }

    private static List<Step> parse(final String value) {
        if (StringUtils.isBlank(value)) {
            throw new IllegalArgumentException("--target value is empty. Expected " + VALID_SELECTORS);
        }

        final List<Step> steps = new ArrayList<>();
        final String[] entries = value.split(",", -1);
        for (int i = 0; i < entries.length; i++) {
            steps.add(parseEntry(entries[i], i == 0));
        }
        return steps;
    }

    private static Step parseEntry(final String entry, final boolean first) {
        final String trimmed = StringUtils.trimToEmpty(entry);
        if (trimmed.isEmpty()) {
            throw new IllegalArgumentException("--target has an empty selector. Expected "
                    + VALID_SELECTORS);
        }

        final boolean subtract = trimmed.charAt(0) == '-';
        final String body = subtract ? StringUtils.trimToEmpty(trimmed.substring(1)) : trimmed;
        if (body.isEmpty()) {
            throw new IllegalArgumentException("--target has an empty selector after '-'. Expected "
                    + VALID_SELECTORS);
        }
        if (subtract && first) {
            throw new IllegalArgumentException("--target=" + trimmed + " cannot start the list:"
                    + " nothing is selected yet, so subtracting has no effect. Write 'all," + trimmed
                    + "' to mean everything except " + body);
        }

        return newStep(body, subtract);
    }

    private static Step newStep(final String body, final boolean subtract) {
        final boolean enabled = !subtract;

        final int dash = body.lastIndexOf('-');
        if (dash > 0) {
            final String typeToken = SelectorNames.normalize(body.substring(0, dash));
            final String kindToken = SelectorNames.normalize(body.substring(dash + 1));
            if (FIELD.equals(kindToken) || ARRAY.equals(kindToken)) {
                return new Step(typesOf(body, typeToken), ARRAY.equals(kindToken), FIELD.equals(kindToken), enabled);
            }
            throw unknownSelector(body);
        }

        final String token = SelectorNames.normalize(body);
        if (isReset(ALL, body, token) || isReset(NONE, body, token)) {
            // all and none reset the scope rather than contributing members to it, so subtracting
            // one is meaningless: '-all' is a confusing spelling of 'none', and '-none' reads as
            // "everything except nothing" but would clear everything.
            if (subtract) {
                throw new IllegalArgumentException("--target selector '" + token
                        + "' cannot be subtracted: it sets the whole scope rather than naming"
                        + " members of it. Write 'none' to clear, or subtract a type such as"
                        + " '-int'");
            }
            return new Step(allTypes(), true, true, ALL.equals(token));
        }
        if (FIELD.equals(token)) {
            return new Step(allTypes(), false, true, enabled);
        }
        if (ARRAY.equals(token)) {
            return new Step(allTypes(), true, false, enabled);
        }
        return new Step(typesOf(body, token), true, true, enabled);
    }

    /**
     * Whether the token is {@code all} or {@code none} as written. Both are singular-only, so
     * {@code alls} must not normalize into them.
     */
    private static boolean isReset(final String keyword, final String body, final String token) {
        return keyword.equals(token)
                && !StringUtils.trimToEmpty(body).toLowerCase().endsWith("s");
    }

    private static Set<BasicType> typesOf(final String body, final String normalizedToken) {
        if (SelectorNames.isObject(normalizedToken)) {
            throw new IllegalArgumentException("--target cannot select 'object': overwriting object"
                    + " ids would corrupt the heap dump. Valid types are "
                    + SelectorNames.typeNames());
        }
        final BasicType type = SelectorNames.findType(normalizedToken);
        if (type == null) {
            throw unknownSelector(body);
        }
        return EnumSet.of(type);
    }

    private static Set<BasicType> allTypes() {
        return EnumSet.copyOf(SanitizationPolicy.PRIMITIVES);
    }

    private static IllegalArgumentException unknownSelector(final String body) {
        return new IllegalArgumentException("Unknown --target selector: " + body + ". Expected "
                + VALID_SELECTORS);
    }

    /**
     * One parsed entry: which types, which halves, and whether to enable or clear them.
     */
    private static class Step {
        private final Set<BasicType> types;
        private final boolean arrays;
        private final boolean fields;
        private final boolean enabled;

        Step(final Set<BasicType> types, final boolean arrays, final boolean fields, final boolean enabled) {
            this.types = types;
            this.arrays = arrays;
            this.fields = fields;
            this.enabled = enabled;
        }

        void applyTo(final SanitizationPolicy.Builder builder) {
            for (final BasicType type : types) {
                if (fields) {
                    builder.setField(type, enabled);
                }
                if (arrays) {
                    builder.setArray(type, enabled);
                }
            }
        }
    }

    private TargetSelector() {
        throw new AssertionError();
    }
}
