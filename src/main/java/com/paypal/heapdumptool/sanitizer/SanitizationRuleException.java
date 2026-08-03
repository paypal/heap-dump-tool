package com.paypal.heapdumptool.sanitizer;

/**
 * A registered {@link SanitizationRule} threw, or returned a verdict that cannot be applied.
 *
 * <p>Unchecked, and never caught by the streaming path: a rule failure aborts the run. The
 * alternative -- treating it as "no verdict" and falling back to {@code --target} -- would let a
 * broken rule silently emit data the user asked to have removed, which is the one outcome a redaction
 * tool must not produce quietly.</p>
 */
public class SanitizationRuleException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public SanitizationRuleException(final String message) {
        super(message);
    }

    public SanitizationRuleException(final String message, final Throwable cause) {
        super(message, cause);
    }
}
