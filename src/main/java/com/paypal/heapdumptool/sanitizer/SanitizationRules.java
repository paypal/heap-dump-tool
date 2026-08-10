package com.paypal.heapdumptool.sanitizer;

import com.paypal.heapdumptool.utils.AbstractInvocationHandler;
import com.paypal.heapdumptool.utils.DefaultMethodInvoker;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.function.Function;
import java.util.function.Predicate;

import static java.util.Objects.requireNonNull;

/**
 * Static factory methods for building a {@link SanitizationRule} from a single lambda, for the
 * common case where a rule decides only fields or only arrays.
 *
 * <p>Each factory returns a {@link java.lang.reflect.Proxy} over {@link SanitizationRule}:
 *
 * <ul>
 *   <li>The targeted decision method ({@code decideField} or {@code decideArray}) delegates to the
 *       provided lambda. The other decision method keeps its default body, so a {@code fieldRule}
 *       abstains on every array and a {@code arrayRule} abstains on every field.</li>
 *   <li>{@code describe()} returns the supplied description, or {@code "fieldRule"} /
 *       {@code "arrayRule"} when none is given.</li>
 *   <li>Every other method keeps its {@code default} interface body.</li>
 * </ul>
 *
 * <p>The returned rule behaves like any other {@link SanitizationRule} -- a lambda that throws
 * aborts the run, wrapped in {@link SanitizationRuleException} by the dispatch chain, and a rule
 * that never returns a verdict is reported as unmatched at the end of the run.
 */
public final class SanitizationRules {

    private SanitizationRules() {
        throw new AssertionError();
    }

    /**
     * A rule that decides primitive fields only: {@code decideArray()} returns
     * {@link Decision#undecided()}.
     */
    public static SanitizationRule fieldRule(final Function<FieldContext, Decision> rule) {
        return fieldRule("fieldRule", rule);
    }

    public static SanitizationRule fieldRule(final String desc, final Function<FieldContext, Decision> rule) {
        return newProxy(new FieldRuleHandler(defaultDesc(desc, "fieldRule"), requireNonNull(rule, "rule")));
    }

    /**
     * A rule that preserves the primitive fields the predicate accepts and abstains on everything
     * else: {@code decideField()} returns {@link Decision#preserve()} when {@code predicate.test(field)}
     * is true, otherwise {@link Decision#undecided()}. {@code decideArray()} always returns
     * {@link Decision#undecided()}.
     *
     * <p>This is the preserve-only special case of {@link #fieldRule(String, Function)}: a rule
     * that only ever hands back {@code PRESERVE} or {@code UNDECIDED} can be written as a boolean
     * predicate instead of a {@link Decision}-returning lambda.</p>
     */
    public static SanitizationRule preserveFieldRule(final Predicate<FieldContext> predicate) {
        return preserveFieldRule("preserveFieldRule", predicate);
    }

    public static SanitizationRule preserveFieldRule(final String desc, final Predicate<FieldContext> predicate) {
        requireNonNull(predicate, "predicate");
        return fieldRule(
                defaultDesc(desc, "preserveFieldRule"),
                field -> predicate.test(field) ? Decision.preserve() : Decision.undecided());
    }

    /**
     * A rule that decides primitive arrays only: {@code decideField()} returns
     * {@link Decision#undecided()}.
     */
    public static SanitizationRule arrayRule(final Function<ArrayContext, Decision> rule) {
        return arrayRule("arrayRule", rule);
    }

    public static SanitizationRule arrayRule(final String desc, final Function<ArrayContext, Decision> rule) {
        return newProxy(new ArrayRuleHandler(defaultDesc(desc, "arrayRule"), requireNonNull(rule, "rule")));
    }

    private static SanitizationRule newProxy(final AbstractInvocationHandler handler) {
        return (SanitizationRule) Proxy.newProxyInstance(
                SanitizationRule.class.getClassLoader(), new Class<?>[] {SanitizationRule.class}, handler);
    }

    private static String defaultDesc(final String desc, final String defaultDesc) {
        return desc == null ? defaultDesc : desc;
    }

    private static boolean is(final Method method, final String name, final int paramCount) {
        return method.getName().equals(name) && method.getParameterCount() == paramCount;
    }

    /** The {@code decideField} half of a {@link #fieldRule}: every other method keeps its default body. */
    private static final class FieldRuleHandler extends AbstractInvocationHandler {

        private final String desc;
        private final Function<FieldContext, Decision> rule;

        FieldRuleHandler(final String desc, final Function<FieldContext, Decision> rule) {
            this.desc = desc;
            this.rule = rule;
        }

        @Override
        protected Object handleInvocation(final Object proxy, final Method method, final Object[] args)
                throws Throwable {
            if (is(method, "decideField", 1)) {
                return rule.apply((FieldContext) args[0]);
            }
            if (is(method, "describe", 0)) {
                return desc;
            }
            if (method.getDeclaringClass().isInterface() && method.isDefault()) {
                return DefaultMethodInvoker.invoke(proxy, method, args);
            }
            throw new UnsupportedOperationException("fieldRule proxy: unexpected method " + method);
        }
    }

    /** The {@code decideArray} half of an {@link #arrayRule}: every other method keeps its default body. */
    private static final class ArrayRuleHandler extends AbstractInvocationHandler {

        private final String desc;
        private final Function<ArrayContext, Decision> rule;

        ArrayRuleHandler(final String desc, final Function<ArrayContext, Decision> rule) {
            this.desc = desc;
            this.rule = rule;
        }

        @Override
        protected Object handleInvocation(final Object proxy, final Method method, final Object[] args)
                throws Throwable {
            if (is(method, "decideArray", 1)) {
                return rule.apply((ArrayContext) args[0]);
            }
            if (is(method, "describe", 0)) {
                return desc;
            }
            if (method.getDeclaringClass().isInterface() && method.isDefault()) {
                return DefaultMethodInvoker.invoke(proxy, method, args);
            }
            throw new UnsupportedOperationException("arrayRule proxy: unexpected method " + method);
        }
    }
}
