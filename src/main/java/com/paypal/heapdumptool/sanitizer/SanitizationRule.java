package com.paypal.heapdumptool.sanitizer;

/**
 * A programmatic decision about what a sanitize run should overwrite.
 *
 * <p>Register with {@code command.getSanitizeOptions().addRule(rule)}. Rules are consulted in
 * registration order and the first non-{@code UNDECIDED} verdict wins; if every rule abstains, the
 * {@code --target} and {@code --replacement} flags decide exactly as they do without any rule.</p>
 *
 * <p>Both methods are consulted once per <em>field declaration</em> and once per <em>array</em>, never
 * once per value, so a verdict must depend only on the context it is handed. That is what makes the
 * cost proportional to the number of classes in the dump rather than to the number of values in it,
 * and it is why this interface decides <em>whether</em> to sanitize rather than <em>what value</em> to
 * write. See {@code docs/proposals/01-sanitization-rule-spi.md} for the reasoning.</p>
 *
 * <p>A rule that throws aborts the run. Sanitization must not treat an error as "leave the data
 * alone", since that silently emits the very bytes the user asked to remove.</p>
 *
 * <p>Implementations must be thread-confined only in the sense that one run uses one instance; the
 * two passes of a run share it, and each pass asks the same questions in the same order.</p>
 */
public interface SanitizationRule {

    /** A non-array primitive field, static or instance. */
    default Decision decideField(final FieldContext context) {
        return Decision.undecided();
    }

    /** The contents of a primitive array. */
    default Decision decideArray(final ArrayContext context) {
        return Decision.undecided();
    }

    /** A name for the startup log and the zero-match warning. */
    default String describe() {
        return getClass().getSimpleName();
    }
}
