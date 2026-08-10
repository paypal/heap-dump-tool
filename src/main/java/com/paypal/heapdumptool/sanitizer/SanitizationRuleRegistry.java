package com.paypal.heapdumptool.sanitizer;

import java.util.ArrayList;
import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Set;

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
public final class SanitizationRuleRegistry {

    private static final SanitizationRuleRegistry EMPTY = new SanitizationRuleRegistry(Collections.emptyList());

    private final List<SanitizationRule> rules;

    /*
     * Parallel to rules: whether each has ever returned a verdict. A rule that never matches is
     * almost always a typo in a class or field name, and without this the run looks like a clean
     * success while having done nothing the user asked for.
     */
    private final boolean[] matched;

    /*
     * The distinct transformers this chain has actually routed to, for the end-of-run log. Recorded here
     * rather than logged at startup because a transformer is not registered: it arrives on a Decision, so
     * which ones a run uses is not knowable until the run has made its decisions.
     *
     * Identity semantics by default, which is what is wanted: two equal-looking transformers from
     * different rules are two things the log should name. Descriptions are built at the end, not here --
     * decideArray runs once per array record, and describe() is user code that may allocate.
     *
     * Capped because a rule is free to return a fresh instance per record -- Decision.transformWith(v ->
     * ...) inside decideArray is the obvious way to write one -- and an uncapped set of those would grow
     * with the dump. Past the cap the log says so rather than pretending the list is complete.
     */
    private static final int MAX_TRACKED_TRANSFORMERS = 32;

    private final Set<ValueTransformer> routedTransformers = Collections.newSetFromMap(new IdentityHashMap<>());

    private boolean moreTransformersThanTracked;

    static SanitizationRuleRegistry empty() {
        return EMPTY;
    }

    SanitizationRuleRegistry(final List<SanitizationRule> rules) {
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
                recordTransformer(decision);
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
                recordTransformer(decision);
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

    /*
     * A field's verdict is memoized on Field, so a transformer routed at a field is seen once per
     * declaration; an array's cannot be, so this runs per array record. Hence the containment check
     * before the add: IdentityHashMap.add on a present key is already cheap, and the cap keeps the set
     * from growing when a rule mints a transformer per record.
     */
    private void recordTransformer(final Decision decision) {
        final ValueTransformer transformer = decision.getTransformer();
        if (transformer == null || routedTransformers.contains(transformer)) {
            return;
        }
        if (routedTransformers.size() >= MAX_TRACKED_TRANSFORMERS) {
            moreTransformersThanTracked = true;
            return;
        }
        routedTransformers.add(transformer);
    }

    /**
     * Names the transformers this run actually routed values to, for a line at the end of the run.
     * Meaningful only once the dump has been read, since a transformer arrives on a {@link Decision}
     * rather than being registered up front. Empty on a run that transformed nothing.
     *
     * <p>The last entry reads {@code ...} if more distinct transformers ran than were tracked.</p>
     */
    public List<String> describeRoutedTransformers() {
        final List<String> names = new ArrayList<>(routedTransformers.size());
        for (final ValueTransformer transformer : routedTransformers) {
            names.add(describe(transformer));
        }
        /*
         * Sorted so the line is stable across runs: the set is identity-hashed, so its iteration order
         * varies with the addresses the JVM happened to hand out.
         */
        Collections.sort(names);
        if (moreTransformersThanTracked) {
            names.add("... (more than " + MAX_TRACKED_TRANSFORMERS + " distinct transformers ran)");
        }
        return names;
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
        /*
         * A transformer is rejected on OBJECT for the same reason a constant is, and for a stronger one:
         * ValueTransformer has no transformObject method at all, so there is nothing to call. Caught here
         * rather than ignored so a rule that routes a transformer at a reference field is told, instead
         * of appearing to work while the ids pipe through untouched.
         */
        if (decision.isTransform() && type == BasicType.OBJECT) {
            throw new SanitizationRuleException("Rule " + describe(rule) + " routed transformer "
                    + decision.describeTransformer() + " at " + what
                    + ", which holds object ids: transforming one corrupts the heap dump");
        }

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

    private static String describe(final ValueTransformer transformer) {
        try {
            final String description = transformer.describe();
            return description == null ? transformer.getClass().getName() : description;
        } catch (final RuntimeException e) {
            return transformer.getClass().getName();
        }
    }

    @Override
    public String toString() {
        return String.join(",", describeRules());
    }
}
