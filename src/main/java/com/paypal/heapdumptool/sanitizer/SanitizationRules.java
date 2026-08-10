package com.paypal.heapdumptool.sanitizer;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * The resolved chain of {@link SanitizationRule}s, and the only place they are invoked from.
 *
 * <p>Centralizing dispatch here keeps three cross-cutting concerns out of the streaming path: a rule
 * that throws aborts the run rather than silently falling back to preserving, a returned replacement
 * is checked against the type's width before it can reach the tiling code, and a rule that matched
 * nothing is remembered so the run can warn about it. All three exist because a redaction tool's
 * failure mode must not be "emit the data".</p>
 *
 * <p>{@link #isEmpty()} is the fast path every default run takes: with no rules registered the
 * streaming code never reaches any of this.</p>
 */
public final class SanitizationRules {

    private static final SanitizationRules EMPTY = new SanitizationRules(Collections.<SanitizationRule>emptyList());

    private final List<SanitizationRule> rules;

    /*
     * Parallel to rules: whether each has ever returned a verdict. A rule that never matches is
     * almost always a typo in a class or field name, and without this the run looks like a clean
     * success while having done nothing the user asked for.
     */
    private final boolean[] matched;

    static SanitizationRules empty() {
        return EMPTY;
    }

    SanitizationRules(final List<SanitizationRule> rules) {
        this.rules = Collections.unmodifiableList(new ArrayList<>(rules));
        this.matched = new boolean[rules.size()];
    }

    public boolean isEmpty() {
        return rules.isEmpty();
    }

    int size() {
        return rules.size();
    }

    /**
     * The first non-{@code UNDECIDED} verdict for this field, or {@link Decision#undecided()} if every
     * rule abstains.
     */
    Decision decideField(final FieldContext context) {
        for (int i = 0; i < rules.size(); i++) {
            final SanitizationRule rule = rules.get(i);
            final Decision decision = invokeField(rule, context);
            if (decision != null && !decision.isUndecided()) {
                validateWidth(rule, decision, context.type(), describeField(context));
                matched[i] = true;
                return decision;
            }
        }
        return Decision.undecided();
    }

    /**
     * The first non-{@code UNDECIDED} verdict for this array, or {@link Decision#undecided()} if every
     * rule abstains.
     */
    Decision decideArray(final ArrayContext context) {
        for (int i = 0; i < rules.size(); i++) {
            final SanitizationRule rule = rules.get(i);
            final Decision decision = invokeArray(rule, context);
            if (decision != null && !decision.isUndecided()) {
                validateWidth(rule, decision, context.elementType(), context.elementType() + "[]");
                matched[i] = true;
                return decision;
            }
        }
        return Decision.undecided();
    }

    /**
     * Names the rules that never returned a verdict, for a warning at the end of the run. Meaningful
     * only once the whole dump has been read.
     */
    List<String> describeUnmatchedRules() {
        final List<String> unmatched = new ArrayList<>();
        for (int i = 0; i < rules.size(); i++) {
            if (!matched[i]) {
                unmatched.add(describe(rules.get(i)));
            }
        }
        return unmatched;
    }

    /**
     * The registered rules by name, for the startup log. Unlike {@code --target} and
     * {@code --replacement} this does not round-trip as a flag value, so the caller has to present it
     * as what it is: a list of names, not a reproducible command line.
     */
    public List<String> describeRules() {
        final List<String> names = new ArrayList<>(rules.size());
        for (final SanitizationRule rule : rules) {
            names.add(describe(rule));
        }
        return names;
    }

    /*
     * A rule's own exception is wrapped rather than propagated bare so the message names the rule and
     * the field. Otherwise the stack trace points into the streaming path and says nothing about which
     * of several registered rules failed.
     */
    private Decision invokeField(final SanitizationRule rule, final FieldContext context) {
        try {
            return rule.decideField(context);
        } catch (final RuntimeException e) {
            throw new SanitizationRuleException(
                    "Rule " + describe(rule) + " failed deciding field " + describeField(context), e);
        }
    }

    private Decision invokeArray(final SanitizationRule rule, final ArrayContext context) {
        try {
            return rule.decideArray(context);
        } catch (final RuntimeException e) {
            throw new SanitizationRuleException(
                    "Rule " + describe(rule) + " failed deciding " + context.elementType() + "[" + context.numElements()
                            + "]",
                    e);
        }
    }

    /*
     * Checked here rather than in Decision because the width depends on the type the decision is being
     * applied to, which the factory method does not know. Wrong-width replacement bytes would either
     * mis-tile the region or change its length, so this cannot be left to the write path.
     */
    private void validateWidth(
            final SanitizationRule rule, final Decision decision, final BasicType type, final String what) {
        final byte[] replacement = decision.getReplacement();
        if (replacement == null) {
            return;
        }
        // idSize is irrelevant: OBJECT is rejected below, and every other width is id-independent
        final int expected = type.getValueSize(Long.BYTES);
        if (replacement.length != expected) {
            throw new SanitizationRuleException("Rule " + describe(rule) + " returned a " + replacement.length
                    + "-byte replacement for " + what + ", which is " + expected + " bytes."
                    + " A replacement must be exactly the type's width, or the region's length would change");
        }
        if (type == BasicType.OBJECT) {
            throw new SanitizationRuleException("Rule " + describe(rule) + " tried to sanitize " + what
                    + ": overwriting object ids corrupts the heap dump");
        }
    }

    private static String describeField(final FieldContext context) {
        return context.declaringClassName() + "#" + context.fieldName();
    }

    /*
     * describe() is user code, so a broken implementation must not be what aborts the run -- least of
     * all while building the message for an unrelated failure.
     */
    private static String describe(final SanitizationRule rule) {
        try {
            final String description = rule.describe();
            return description == null ? rule.getClass().getName() : description;
        } catch (final RuntimeException e) {
            return rule.getClass().getName();
        }
    }

    @Override
    public String toString() {
        return String.join(",", describeRules());
    }
}
