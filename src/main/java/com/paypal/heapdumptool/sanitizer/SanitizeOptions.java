package com.paypal.heapdumptool.sanitizer;

import java.util.ArrayList;
import java.util.List;
import org.apache.commons.text.StringEscapeUtils;
import picocli.CommandLine.Option;

/**
 * Sanitization scope and replacement-value options, shared by the sanitize and capture commands.
 *
 * <p>Every option is declared as a <em>setter method</em> rather than a field. picocli invokes
 * annotated setters in exact command-line order, which is what makes
 * {@code -s=true --target=all} differ from the reverse. Field injection
 * carries no ordering information.</p>
 *
 * <p>For the same reason no option declares a picocli {@code defaultValue}: picocli applies
 * defaults <em>after</em> matched options, so a default would overwrite whatever the user typed.
 * Defaults are seeded in {@link #resolve()} instead.</p>
 *
 * <h2>Why the two flags are single-occurrence</h2>
 * <p>Each flag takes its whole list in one value, and a second occurrence of the same flag on one
 * command line is a picocli {@code OverwrittenOptionException}. That is deliberate. Declaring them
 * as {@code List<String>} with {@code split = ","} would allow repeats, but picocli re-invokes such
 * a setter with the entire accumulated list on each occurrence -- {@code [all]}, then
 * {@code [all, -int]} -- so the earlier entries would be recorded twice and the resolved policy
 * would depend on how the user split their list across occurrences. Ordering within a single value
 * is what {@link TargetSelector} resolves; ordering against the deprecated flags is what the
 * {@link Directive} list below resolves.</p>
 *
 * <p>Note that two separate {@code parseArgs} calls on the same {@code CommandLine} do not trip the
 * single-occurrence rule, which matters because {@code Application.main} parses the same command
 * object twice. Each setter simply fires again and appends its directive again; replaying an
 * idempotent directive sequence is harmless. See {@code SanitizationPolicy.Builder#addWarning}.</p>
 */
public class SanitizeOptions {

    private final List<Directive> directives = new ArrayList<>();

    /*
     * Kept out of the directive list on purpose. A directive is replayed on every resolve() and the
     * list is appended to on every picocli parse, which is harmless for idempotent scope mutations but
     * would duplicate rules -- and a duplicated rule is consulted twice, so a chain's "first verdict
     * wins" ordering would depend on how many times the command was parsed. Registration is by
     * identity instead: adding the same rule twice records it once.
     */
    private final List<SanitizationRule> rules = new ArrayList<>();

    // ---------- scope and replacement values ----------

    // Prose rather than an aligned two-column table: picocli re-wraps each description line to the
    // terminal width and indents the continuation, which splits a column layout mid-row. Verified
    // against picocli 4.7.5.
    @Option(
            names = "--target",
            paramLabel = "<selectors>",
            order = OptionOrder.TARGET,
            description = {
                "What to sanitize: a comma-separated list applied left to right. Default: all",
                "Selectors: all, none, <type>, <type>-fields, <type>-arrays, fields, arrays."
                        + " <type> alone means type's primitive fields and array fields;"
                        + " 'fields' or 'arrays' means type's primitive fields or array fields only",
                "Prefix an entry with '-' to deselect it, e.g. --target=all,-ints",
                "<type> is byte, short, int, long, char, float, double or boolean"
            })
    void target(final String value) {
        // Validate eagerly so picocli converts an IllegalArgumentException into a
        // ParameterException, and a bad value fails with usage help rather than mid-stream.
        TargetSelector.validate(value);
        directives.add(new Directive(builder -> {
            // Target selectors apply over a base of "none", so first clear everything
            builder.setAll(false);
            TargetSelector.applyTo(value, builder);
        }));
    }

    @Option(
            names = "--replacement",
            paramLabel = "<type>=<value>",
            order = OptionOrder.REPLACEMENT,
            description = {
                "Replacement values for sanitization: comma-separated <type>=<value> entries"
                        + " applied left to right.",
                // the same constant the resolved policy reports, so help and log cannot drift
                "Defaults: " + SanitizationPolicy.DEFAULT_REPLACEMENTS
            })
    void replacement(final String value) {
        ReplacementSpec.validate(value);
        directives.add(new Directive(builder -> ReplacementSpec.applyTo(value, builder)));
    }

    // ---------- deprecated flag entry points, called from SanitizeOrCaptureCommandBase ----------

    void recordLegacyByteCharArraysOnly(final boolean byteCharArraysOnly) {
        directives.add(new Directive(builder -> {
            builder.addWarning("--sanitize-byte-char-arrays-only is deprecated. Use "
                    + (byteCharArraysOnly ? "--target=byte-arrays,char-arrays" : "--target=all"));
            if (byteCharArraysOnly) {
                builder.setAll(false).setArray(BasicType.BYTE, true).setArray(BasicType.CHAR, true);
            } else {
                builder.setAll(true);
            }
        }));
    }

    void recordLegacyText(final String text) {
        // e.g. unescape user-supplied \\0 (2 chars) to \0 (1 char)
        final String unescaped = StringEscapeUtils.unescapeJava(text);
        if (unescaped == null || unescaped.length() != 1 || unescaped.charAt(0) > 0x7F) {
            throw new IllegalArgumentException("--text supports only a single ASCII character."
                    + " Use --replacement=all=<value> instead. Got: " + text);
        }
        // Use the escaped code point so that a digit is re-parsed as the character's code point,
        // not as a number. E.g. --text=0 must produce byte 0x30 ('0'), not byte 0x00.
        final String escapedReplacement = "\\" + (int) unescaped.charAt(0);
        directives.add(new Directive(builder -> {
            builder.addWarning("--text is deprecated. Use --replacement=all=<value> instead");
            builder.setAllReplacements(escapedReplacement);
        }));
    }

    void recordLegacyTextCharset(final String charset) {
        directives.add(new Directive(builder ->
                builder.addWarning("--text-charset is deprecated and ignored. Replacement values are now typed per"
                        + " primitive, so no charset is involved. Got: " + charset)));
    }

    void recordLegacyTarInput(final boolean tarInput) {
        directives.add(new Directive(builder ->
                builder.addWarning("--tar-input is deprecated and ignored. A tar or zip input is detected from its"
                        + " contents and unwrapped either way. Got: " + tarInput)));
    }

    void recordLegacyZipOutput() {
        directives.add(new Directive(builder -> builder.addWarning(
                "--zip-output is deprecated. Name the output file <outputFile>.zip instead, which also"
                        + " makes the output's format evident from its name")));
    }

    // ---------- programmatic rules ----------

    /**
     * Registers a rule that decides, per field declaration and per array, what this run overwrites.
     *
     * <p>Rules are consulted in registration order and the first non-{@code UNDECIDED} verdict wins;
     * where every rule abstains, {@code --target} and {@code --replacement} decide as usual. Adding
     * the same instance more than once has no further effect.</p>
     *
     * @see SanitizationRule
     */
    public SanitizeOptions addRule(final SanitizationRule rule) {
        if (rule == null) {
            throw new IllegalArgumentException("Rule must not be null");
        }
        // reference equality: two distinct instances of one rule class are two rules, but the same
        // instance re-registered by a second picocli parse or a copyFrom is not
        for (final SanitizationRule existing : rules) {
            if (existing == rule) {
                return this;
            }
        }
        rules.add(rule);
        return this;
    }

    // ---------- resolution ----------

    /**
     * Replays every recorded flag, in command-line order, over the default baseline.
     */
    public SanitizationPolicy resolve() {
        final SanitizationPolicy.Builder builder = SanitizationPolicy.builder().setAll(true);

        for (final Directive directive : directives) {
            directive.applyTo(builder);
        }
        return builder.build();
    }

    /**
     * The registered rules as one immutable chain.
     *
     * <p>Resolved separately from {@link #resolve()} and not held by {@link SanitizationPolicy},
     * because the chain is stateful -- it records which rules have matched, for the end-of-run warning
     * -- while the policy is a value that gets rebuilt on every call. One chain per run is what makes
     * the memoized verdict on {@link Field} and the zero-match warning both correct.</p>
     */
    public SanitizationRules resolveRules() {
        return rules.isEmpty() ? SanitizationRules.empty() : new SanitizationRules(rules);
    }

    public void copyFrom(final SanitizeOptions other) {
        if (other == this) {
            // clear() below would empty the very list being copied from, silently discarding
            // every recorded flag
            return;
        }
        directives.clear();
        directives.addAll(other.directives);
        rules.clear();
        rules.addAll(other.rules);
    }

    /**
     * One recorded flag, deferred until {@link #resolve()} so ordering is preserved.
     */
    private static class Directive {
        private final PolicyMutation mutation;

        Directive(final PolicyMutation mutation) {
            this.mutation = mutation;
        }

        void applyTo(final SanitizationPolicy.Builder builder) {
            mutation.applyTo(builder);
        }
    }

    private interface PolicyMutation {
        void applyTo(SanitizationPolicy.Builder builder);
    }
}
