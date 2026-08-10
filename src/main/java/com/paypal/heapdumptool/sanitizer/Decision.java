package com.paypal.heapdumptool.sanitizer;

import java.util.Arrays;

/**
 * A {@link SanitizationRule}'s verdict on one field or array: overwrite it, keep it, or abstain.
 *
 * <p>Three-valued rather than boolean so that rules compose. {@link #undecided()} is the default, so
 * adding a rule never silently changes anything it did not mean to match, and {@code --target} /
 * {@code --replacement} stay the baseline rather than something every rule has to restate.</p>
 *
 * <p>A decision chooses <em>whether</em> to sanitize and optionally <em>which constant</em> to write.
 * It never chooses how many bytes: {@link #sanitizeWith(byte[])} is validated against the type's
 * width when the rule is resolved, which is what keeps the tool's length-preservation invariant
 * intact by construction. See {@link Replacement}.</p>
 */
public final class Decision {

    private static final Decision SANITIZE = new Decision(Kind.SANITIZE, null);
    private static final Decision PRESERVE = new Decision(Kind.PRESERVE, null);
    private static final Decision UNDECIDED = new Decision(Kind.UNDECIDED, null);

    enum Kind {
        SANITIZE,
        PRESERVE,
        TRANSFORM,
        UNDECIDED
    }

    private final Kind kind;
    private final byte[] replacement;

    /*
     * Non-null only for Kind.TRANSFORM. Kept on the decision rather than registered globally because
     * that is the whole cost argument of the transformed path: it runs exactly where a rule put it, and
     * a run with no TRANSFORM verdict never decodes a value.
     */
    private final ValueTransformer transformer;

    /*
     * The custom replacement, pre-tiled for the write path. Built on first use rather than in the
     * factory method, and cached here rather than per region: a rule may return a decision per array
     * record, and tiling an 8 KB buffer for each of those would allocate more than the constant-fill
     * path it is replacing. A field's decision is memoized on Field, so that case tiles once per
     * declaration regardless.
     */
    private Replacement tiled;

    private Decision(final Kind kind, final byte[] replacement) {
        this(kind, replacement, null);
    }

    private Decision(final Kind kind, final byte[] replacement, final ValueTransformer transformer) {
        this.kind = kind;
        this.replacement = replacement;
        this.transformer = transformer;
    }

    /** Overwrite this region with the replacement {@code --replacement} resolved for its type. */
    public static Decision sanitize() {
        return SANITIZE;
    }

    /**
     * Overwrite this region with these bytes, big-endian, instead of the type's configured
     * replacement. Must be exactly the type's width; checked when the rule chain is resolved.
     */
    public static Decision sanitizeWith(final byte[] replacement) {
        if (replacement == null || replacement.length == 0) {
            throw new IllegalArgumentException("Replacement bytes must be non-empty");
        }
        return new Decision(Kind.SANITIZE, replacement.clone());
    }

    /** Copy this region through untouched, whatever {@code --target} says. */
    public static Decision preserve() {
        return PRESERVE;
    }

    /**
     * Overwrite this region with what the transformer computes from its current value, rather than with
     * a constant.
     *
     * <p>This is the expensive verdict, and the only one that reads the original bytes: see
     * {@link ValueTransformer} for the cost. It is worth it exactly where the original value carries
     * something the analysis still needs -- the last four digits, the fact that two names are equal, the
     * order of magnitude -- and a constant would destroy it.</p>
     */
    public static Decision transformWith(final ValueTransformer transformer) {
        if (transformer == null) {
            throw new IllegalArgumentException("Transformer must not be null");
        }
        return new Decision(Kind.TRANSFORM, null, transformer);
    }

    /** Defer to the next rule, and then to {@code --target}. */
    public static Decision undecided() {
        return UNDECIDED;
    }

    Kind getKind() {
        return kind;
    }

    boolean isUndecided() {
        return kind == Kind.UNDECIDED;
    }

    boolean isSanitize() {
        return kind == Kind.SANITIZE;
    }

    boolean isTransform() {
        return kind == Kind.TRANSFORM;
    }

    /** The transformer to run over this region, or null unless this is a {@code TRANSFORM} verdict. */
    ValueTransformer getTransformer() {
        return transformer;
    }

    /** The custom replacement bytes, or null to use the type's configured replacement. */
    byte[] getReplacement() {
        return replacement;
    }

    /**
     * This decision's custom replacement, tiled, or null if it has none and the type's configured
     * replacement should be used instead.
     *
     * <p>Not synchronized. Both passes of a run are sequential and a race would at worst build two
     * identical buffers, so the lock would cost more on the streaming path than it could save.</p>
     */
    Replacement tiledReplacement() {
        if (replacement == null) {
            return null;
        }
        if (tiled == null) {
            tiled = new Replacement(replacement);
        }
        return tiled;
    }

    @Override
    public String toString() {
        if (transformer != null) {
            return kind + "(" + describeTransformer() + ")";
        }
        if (replacement == null) {
            return kind.name();
        }
        return kind + "(" + Arrays.toString(replacement) + ")";
    }

    /*
     * describe() is user code, so a broken implementation must not be what aborts the run -- least of
     * all while building the message for an unrelated failure. Same reasoning as SanitizationRuleRegistry.
     */
    String describeTransformer() {
        if (transformer == null) {
            return "none";
        }
        try {
            final String description = transformer.describe();
            return description == null ? transformer.getClass().getName() : description;
        } catch (final RuntimeException e) {
            return transformer.getClass().getName();
        }
    }
}
