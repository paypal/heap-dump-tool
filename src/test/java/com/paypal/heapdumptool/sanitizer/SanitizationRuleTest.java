package com.paypal.heapdumptool.sanitizer;

import com.paypal.heapdumptool.fixture.Hprof;
import com.paypal.heapdumptool.sanitizer.internal.hprof.HeapRecord;
import com.paypal.heapdumptool.sanitizer.internal.policy.SanitizationRuleRegistry;
import com.paypal.heapdumptool.utils.DataSize;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import picocli.CommandLine;

import static com.paypal.heapdumptool.fixture.Hprof.ID_SIZE;
import static java.util.Arrays.asList;
import static org.apache.commons.lang3.ArrayUtils.EMPTY_STRING_ARRAY;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Byte-exact tests for the {@link SanitizationRule} decision SPI.
 *
 * <p>Uses the same synthetic-fixture approach as {@link HeapDumpSanitizerSyntheticTest}: sanitization
 * never changes the length of a region, so an offset recorded while building the input is also valid
 * in the output.</p>
 */
class SanitizationRuleTest {

    private static final String ACCOUNT_CLASS_NAME = "com.mycorp.Account";
    private static final String CONFIG_CLASS_NAME = "com.mycorp.Config";

    private static final long ACCOUNT_CLASS_ID = 2100;
    private static final long CONFIG_CLASS_ID = 2300;
    private static final long ACCOUNT_OBJECT_ID = 0xA000;
    private static final long ARRAY_OBJECT_ID = 0xA100;

    /** The chain the most recent run used, for tests that assert on which rules matched. */
    private SanitizationRuleRegistry lastRunRules;

    /** A three-int-field class, so a rule can single out one field and leave its neighbours. */
    private static final class AccountFixture {

        final byte[] input;
        final int ssnOffset;
        final int balanceOffset;
        final int accountIdOffset;

        AccountFixture() throws IOException {
            final Hprof hprof = new Hprof().header();
            hprof.stringInUtf8(60, ACCOUNT_CLASS_NAME);
            hprof.stringInUtf8(61, "ssn");
            hprof.stringInUtf8(62, "balance");
            hprof.stringInUtf8(63, "accountId");
            hprof.loadClass(1, ACCOUNT_CLASS_ID, 60);

            final Hprof body = new Hprof();
            body.classDump(ACCOUNT_CLASS_ID, 0, new int[] {61, 62, 63}, new BasicType[] {
                BasicType.INT, BasicType.INT, BasicType.INT
            });

            final Hprof instance = new Hprof();
            final int relativeSsn = instance.offset();
            instance.u4(0x11111111);
            final int relativeBalance = instance.offset();
            instance.u4(0x22222222);
            final int relativeAccountId = instance.offset();
            instance.u4(0x33333333);
            final int instanceOffset = body.instanceDump(ACCOUNT_OBJECT_ID, ACCOUNT_CLASS_ID, instance.toByteArray());

            final int base = hprof.record(HeapRecord.HEAP_DUMP_SEGMENT.getTag(), body);

            this.input = hprof.toByteArray();
            this.ssnOffset = base + instanceOffset + relativeSsn;
            this.balanceOffset = base + instanceOffset + relativeBalance;
            this.accountIdOffset = base + instanceOffset + relativeAccountId;
        }
    }

    /** Sanitizes only the named fields of one class, abstaining on everything else. */
    private static final class NamedFieldRule implements SanitizationRule {

        private final String className;
        private final List<String> names;

        /** Names fields of {@link #ACCOUNT_CLASS_NAME}, the fixture most tests use. */
        NamedFieldRule(final String... names) {
            this(ACCOUNT_CLASS_NAME, asList(names));
        }

        static NamedFieldRule of(final String className, final String... names) {
            return new NamedFieldRule(className, asList(names));
        }

        private NamedFieldRule(final String className, final List<String> names) {
            this.className = className;
            this.names = names;
        }

        @Override
        public Decision decideField(final FieldContext context) {
            if (className.equals(context.declaringClassName()) && names.contains(context.fieldName())) {
                return Decision.sanitize();
            }
            return Decision.undecided();
        }

        @Override
        public String describe() {
            return "NamedFieldRule" + names;
        }
    }

    // ---------------------------------------------------------------------------------------------
    // Field decisions
    // ---------------------------------------------------------------------------------------------

    @Test
    @DisplayName(
            "testRuleSanitizesOnlyNamedFieldUnderTargetNone. --target=none plus a rule touches only the named field")
    void testRuleSanitizesOnlyNamedFieldUnderTargetNone() throws Exception {
        final AccountFixture fixture = new AccountFixture();

        final byte[] output = sanitize(fixture.input, new NamedFieldRule("ssn"), "--target=none");

        assertThat(region(output, fixture.ssnOffset, Integer.BYTES))
                .as("the rule named ssn, so it is overwritten with int's replacement")
                .containsExactly(0, 0, 0, 0);
        assertThat(region(output, fixture.balanceOffset, Integer.BYTES))
                .as("--target=none and no rule verdict, so balance survives")
                .containsExactly(0x22, 0x22, 0x22, 0x22);
        assertThat(region(output, fixture.accountIdOffset, Integer.BYTES))
                .as("--target=none and no rule verdict, so accountId survives")
                .containsExactly(0x33, 0x33, 0x33, 0x33);
    }

    @Test
    @DisplayName("testPreserveOverridesTargetAll. A PRESERVE verdict beats --target=all for that field only")
    void testPreserveOverridesTargetAll() throws Exception {
        final AccountFixture fixture = new AccountFixture();

        final SanitizationRule preserveBalance = new SanitizationRule() {
            @Override
            public Decision decideField(final FieldContext context) {
                return "balance".equals(context.fieldName()) ? Decision.preserve() : Decision.undecided();
            }
        };

        final byte[] output = sanitize(fixture.input, preserveBalance, "--target=all");

        assertThat(region(output, fixture.balanceOffset, Integer.BYTES))
                .as("the rule preserved balance despite --target=all")
                .containsExactly(0x22, 0x22, 0x22, 0x22);
        assertThat(region(output, fixture.ssnOffset, Integer.BYTES))
                .as("neighbouring fields still follow --target=all")
                .containsExactly(0, 0, 0, 0);
        assertThat(region(output, fixture.accountIdOffset, Integer.BYTES))
                .as("neighbouring fields still follow --target=all")
                .containsExactly(0, 0, 0, 0);
    }

    @Test
    @DisplayName("testSanitizeWithCustomReplacement. sanitizeWith writes the rule's own bytes")
    void testSanitizeWithCustomReplacement() throws Exception {
        final AccountFixture fixture = new AccountFixture();

        final SanitizationRule rule = new SanitizationRule() {
            @Override
            public Decision decideField(final FieldContext context) {
                return "ssn".equals(context.fieldName())
                        ? Decision.sanitizeWith(new byte[] {(byte) 0xDE, (byte) 0xAD, (byte) 0xBE, (byte) 0xEF})
                        : Decision.undecided();
            }
        };

        final byte[] output = sanitize(fixture.input, rule, "--target=none");

        assertThat(region(output, fixture.ssnOffset, Integer.BYTES))
                .as("the rule's own replacement, not --replacement's value for int")
                .containsExactly(0xDE, 0xAD, 0xBE, 0xEF);
    }

    @Test
    @DisplayName("testFirstNonUndecidedVerdictWins. Rules are consulted in registration order")
    void testFirstNonUndecidedVerdictWins() throws Exception {
        final AccountFixture fixture = new AccountFixture();

        final SanitizationRule preserve = new SanitizationRule() {
            @Override
            public Decision decideField(final FieldContext context) {
                return "ssn".equals(context.fieldName()) ? Decision.preserve() : Decision.undecided();
            }
        };

        final SanitizeCommand command = command("--target=all");
        command.getSanitizeOptions().addRule(preserve);
        command.getSanitizeOptions().addRule(new NamedFieldRule("ssn"));

        final byte[] output = sanitize(fixture.input, command);

        assertThat(region(output, fixture.ssnOffset, Integer.BYTES))
                .as("the earlier rule preserved ssn, so the later sanitizing rule is never asked")
                .containsExactly(0x11, 0x11, 0x11, 0x11);
    }

    @Test
    @DisplayName("testDeclaringClassNameIsVisibleToRules. A rule can key on the declaring class")
    void testDeclaringClassNameIsVisibleToRules() throws Exception {
        final AccountFixture fixture = new AccountFixture();

        final List<String> seen = new ArrayList<>();
        final SanitizationRule recorder = new SanitizationRule() {
            @Override
            public Decision decideField(final FieldContext context) {
                seen.add(context.declaringClassName() + "#" + context.fieldName() + ":" + context.type()
                        + (context.isStatic() ? ":static" : ""));
                return Decision.undecided();
            }
        };

        sanitize(fixture.input, recorder, "--target=none");

        assertThat(seen)
                .as("every declared field is offered exactly once, with its declaring class")
                .containsExactly(
                        "com.mycorp.Account#ssn:INT",
                        "com.mycorp.Account#balance:INT",
                        "com.mycorp.Account#accountId:INT");
    }

    // ---------------------------------------------------------------------------------------------
    // Array decisions
    // ---------------------------------------------------------------------------------------------

    @Test
    @DisplayName("testArrayRuleSeesElementTypeAndLength. decideArray can preserve one array type under --target=all")
    void testArrayRuleSeesElementTypeAndLength() throws Exception {
        final Hprof body = new Hprof();
        final int dataOffset = body.primitiveArrayDump(ARRAY_OBJECT_ID, BasicType.BYTE, new byte[] {1, 2, 3, 4});

        final Hprof input = new Hprof().header();
        final int base = input.record(HeapRecord.HEAP_DUMP_SEGMENT.getTag(), body);

        final List<String> seen = new ArrayList<>();
        final SanitizationRule rule = new SanitizationRule() {
            @Override
            public Decision decideArray(final ArrayContext context) {
                seen.add(context.elementType() + "[" + context.numElements() + "]=" + context.numBytes());
                return Decision.preserve();
            }
        };

        final byte[] output = sanitize(input.toByteArray(), rule, "--target=all");

        assertThat(seen).containsExactly("BYTE[4]=4");
        assertThat(region(output, base + dataOffset, 4))
                .as("the rule preserved this array despite --target=all")
                .containsExactly(1, 2, 3, 4);
    }

    @Test
    @DisplayName("testArrayRuleCustomReplacementIsTiled. A rule replacement tiles across a multi-element array")
    void testArrayRuleCustomReplacementIsTiled() throws Exception {
        final int numElements = 3;
        final Hprof body = new Hprof();
        final int dataOffset =
                body.primitiveArrayDump(ARRAY_OBJECT_ID, BasicType.SHORT, new byte[numElements * Short.BYTES]);

        final Hprof input = new Hprof().header();
        final int base = input.record(HeapRecord.HEAP_DUMP_SEGMENT.getTag(), body);

        final SanitizationRule rule = new SanitizationRule() {
            @Override
            public Decision decideArray(final ArrayContext context) {
                return Decision.sanitizeWith(new byte[] {(byte) 0xAB, (byte) 0xCD});
            }
        };

        final byte[] output = sanitize(input.toByteArray(), rule, "--target=none");

        assertThat(region(output, base + dataOffset, numElements * Short.BYTES))
                .as("the two-byte replacement repeats once per element, staying aligned")
                .containsExactly(0xAB, 0xCD, 0xAB, 0xCD, 0xAB, 0xCD);
    }

    // ---------------------------------------------------------------------------------------------
    // Failing closed
    // ---------------------------------------------------------------------------------------------

    @Test
    @DisplayName("testThrowingRuleAbortsTheRun. A rule that throws must not fall back to preserving")
    void testThrowingRuleAbortsTheRun() throws Exception {
        final AccountFixture fixture = new AccountFixture();

        final SanitizationRule broken = new SanitizationRule() {
            @Override
            public Decision decideField(final FieldContext context) {
                throw new IllegalStateException("boom");
            }

            @Override
            public String describe() {
                return "BrokenRule";
            }
        };

        assertThatThrownBy(() -> sanitize(fixture.input, broken, "--target=none"))
                .isInstanceOf(SanitizationRuleException.class)
                .hasMessageContaining("BrokenRule")
                .hasMessageContaining("com.mycorp.Account#ssn")
                .hasRootCauseMessage("boom");
    }

    @Test
    @DisplayName("testWrongWidthReplacementIsRejected. A replacement that is not the type's width would change lengths")
    void testWrongWidthReplacementIsRejected() throws Exception {
        final AccountFixture fixture = new AccountFixture();

        final SanitizationRule rule = new SanitizationRule() {
            @Override
            public Decision decideField(final FieldContext context) {
                // one byte for a four-byte int field
                return Decision.sanitizeWith(new byte[] {42});
            }
        };

        assertThatThrownBy(() -> sanitize(fixture.input, rule, "--target=none"))
                .isInstanceOf(SanitizationRuleException.class)
                .hasMessageContaining("1-byte replacement")
                .hasMessageContaining("4 bytes");
    }

    @Test
    @DisplayName("testUnmatchedRuleIsReported. A rule that matched nothing is almost always a typo")
    void testUnmatchedRuleIsReported() throws Exception {
        final AccountFixture fixture = new AccountFixture();

        final SanitizationRule matching = new NamedFieldRule("ssn");
        final SanitizationRule typo = new NamedFieldRule("ssnn");

        final SanitizeCommand command = command("--target=none");
        command.getSanitizeOptions().addRule(matching);
        command.getSanitizeOptions().addRule(typo);

        sanitize(fixture.input, command);

        assertThat(lastRunRules.describeUnmatchedRules())
                .as("only the rule that never returned a verdict is reported")
                .containsExactly("NamedFieldRule[ssnn]");
    }

    @Test
    @DisplayName("testObjectFieldCannotBeSanitizedByARule. Overwriting object ids corrupts the dump")
    void testObjectFieldCannotBeSanitizedByARule() throws Exception {
        final long holderClassId = 2200;
        final Hprof hprof = new Hprof().header();
        hprof.stringInUtf8(70, "com.example.Holder");
        hprof.stringInUtf8(71, "ref");
        hprof.loadClass(1, holderClassId, 70);

        final Hprof body = new Hprof();
        body.classDump(holderClassId, 0, new int[] {71}, new BasicType[] {BasicType.OBJECT});
        final Hprof instance = new Hprof();
        instance.id(0x1234);
        body.instanceDump(0xB000, holderClassId, instance.toByteArray());
        hprof.record(HeapRecord.HEAP_DUMP_SEGMENT.getTag(), body);

        final SanitizationRule rule = new SanitizationRule() {
            @Override
            public Decision decideField(final FieldContext context) {
                return Decision.sanitizeWith(new byte[ID_SIZE]);
            }
        };

        assertThatThrownBy(() -> sanitize(hprof.toByteArray(), rule, "--target=none"))
                .isInstanceOf(SanitizationRuleException.class)
                .hasMessageContaining("corrupts the heap dump");
    }

    // ---------------------------------------------------------------------------------------------
    // Static fields, and the two-pass run that is the default
    // ---------------------------------------------------------------------------------------------

    @Test
    @DisplayName("testStaticFieldRuleOnSinglePassRun. A rule can name a static field")
    void testStaticFieldRuleOnSinglePassRun() throws Exception {
        final StaticFixture fixture = new StaticFixture();

        final byte[] output =
                sanitize(fixture.input, NamedFieldRule.of(CONFIG_CLASS_NAME, "secretKey"), "--target=none");

        assertThat(region(output, fixture.secretKeyOffset, Integer.BYTES))
                .as("the named static field is overwritten")
                .containsExactly(0, 0, 0, 0);
        assertThat(region(output, fixture.versionOffset, Integer.BYTES))
                .as("the static field no rule named survives --target=none")
                .containsExactly(0x77, 0x77, 0x77, 0x77);
    }

    /*
     * The two-pass shape is the DEFAULT one, not an edge case: -e defaults to a non-empty list, so any
     * real run makes a metadata pass first. The passes share one HeapDumpSanitizer, and the metadata pass
     * is what decides which STRING_IN_UTF8 records the writing pass keeps -- so a name the metadata pass
     * fails to register as needed is simply absent by the time a rule is asked about it.
     */
    @Test
    @DisplayName("testStaticFieldRuleSurvivesTheMetadataPass. A static field name must outlive the metadata pass")
    void testStaticFieldRuleSurvivesTheMetadataPass() throws Exception {
        final StaticFixture fixture = new StaticFixture();

        final byte[] output =
                sanitizeTwoPasses(fixture.input, NamedFieldRule.of(CONFIG_CLASS_NAME, "secretKey"), "--target=none");

        assertThat(region(output, fixture.secretKeyOffset, Integer.BYTES))
                .as("the writing pass still resolves the static field's name, so the rule matches")
                .containsExactly(0, 0, 0, 0);
        assertThat(region(output, fixture.versionOffset, Integer.BYTES))
                .as("the static field no rule named survives --target=none")
                .containsExactly(0x77, 0x77, 0x77, 0x77);
    }

    @Test
    @DisplayName("testInstanceFieldRuleSurvivesTheMetadataPass. An instance field name must outlive the metadata pass")
    void testInstanceFieldRuleSurvivesTheMetadataPass() throws Exception {
        final AccountFixture fixture = new AccountFixture();

        final byte[] output = sanitizeTwoPasses(fixture.input, new NamedFieldRule("ssn"), "--target=none");

        assertThat(region(output, fixture.ssnOffset, Integer.BYTES))
                .as("the writing pass still resolves the instance field's name, so the rule matches")
                .containsExactly(0, 0, 0, 0);
        assertThat(region(output, fixture.balanceOffset, Integer.BYTES)).containsExactly(0x22, 0x22, 0x22, 0x22);
    }

    @Test
    @DisplayName("testMetadataPassNeverWrites. The metadata pass must leave the decision to the writing pass")
    void testMetadataPassNeverWrites() throws Exception {
        final AccountFixture fixture = new AccountFixture();

        final SanitizeCommand command = command("--target=none");
        command.getSanitizeOptions().addRule(new NamedFieldRule("ssn"));

        final HeapDumpSanitizer sanitizer = new HeapDumpSanitizer();
        sanitizer.setPreprocessingOnly(true);
        final byte[] discarded = run(sanitizer, fixture.input, command, true);

        assertThat(discarded).as("a read-only pipe writes nothing at all").isEmpty();
    }

    /*
     * A rule that matched only during the metadata pass must still count as matched: the chain is shared
     * across passes precisely so the end-of-run warning does not accuse a rule that did fire.
     */
    @Test
    @DisplayName("testMatchTrackingSpansBothPasses. Match state must survive the pass hand-off")
    void testMatchTrackingSpansBothPasses() throws Exception {
        final AccountFixture fixture = new AccountFixture();

        final SanitizeCommand command = command("--target=none");
        command.getSanitizeOptions().addRule(new NamedFieldRule("ssn"));

        sanitizeTwoPasses(fixture.input, command);

        assertThat(lastRunRules.describeUnmatchedRules())
                .as("the rule fired, so nothing is reported as unmatched")
                .isEmpty();
    }

    /** A class with two static int fields, so a rule can single one out. */
    private static final class StaticFixture {

        final byte[] input;
        final int secretKeyOffset;
        final int versionOffset;

        StaticFixture() throws IOException {
            final Hprof hprof = new Hprof().header();
            hprof.stringInUtf8(80, CONFIG_CLASS_NAME);
            hprof.stringInUtf8(81, "secretKey");
            hprof.stringInUtf8(82, "version");
            hprof.loadClass(1, CONFIG_CLASS_ID, 80);

            final Hprof body = new Hprof();
            final Hprof.StaticField[] statics = {
                new Hprof.StaticField(81, BasicType.INT, new byte[] {0x66, 0x66, 0x66, 0x66}),
                new Hprof.StaticField(82, BasicType.INT, new byte[] {0x77, 0x77, 0x77, 0x77}),
            };
            final int firstStaticOffset =
                    body.classDumpWithStatics(CONFIG_CLASS_ID, 0, statics, new int[0], new BasicType[0]);

            final int base = hprof.record(HeapRecord.HEAP_DUMP_SEGMENT.getTag(), body);

            this.input = hprof.toByteArray();
            this.secretKeyOffset = base + firstStaticOffset;
            // name id, u1 type and the 4-byte value of secretKey sit between the two values
            this.versionOffset = this.secretKeyOffset + Integer.BYTES + ID_SIZE + 1;
        }
    }

    // ---------------------------------------------------------------------------------------------
    // Registration
    // ---------------------------------------------------------------------------------------------

    @Test
    @DisplayName("testReRegisteringTheSameRuleIsIdempotent. picocli parses the same command twice per process")
    void testReRegisteringTheSameRuleIsIdempotent() {
        final SanitizationRule rule = new NamedFieldRule("ssn");
        final SanitizeOptions options = new SanitizeOptions();

        options.addRule(rule);
        options.addRule(rule);

        assertThat(options.resolveRules().size())
                .as("the same instance registered twice is one rule, or chain order would vary by parse count")
                .isEqualTo(1);
    }

    @Test
    @DisplayName("testCopyFromForwardsRules. The capture path copies its command from another")
    void testCopyFromForwardsRules() {
        final SanitizeCommand source = new SanitizeCommand();
        source.getSanitizeOptions().addRule(new NamedFieldRule("ssn"));

        final SanitizeCommand target = new SanitizeCommand();
        target.copyFrom(source);

        assertThat(target.getSanitizationRules().describeRules()).containsExactly("NamedFieldRule[ssn]");
    }

    @Test
    @DisplayName("testNoRulesMeansNoBehaviourChange. A default run resolves an empty chain")
    void testNoRulesMeansNoBehaviourChange() {
        assertThat(new SanitizeOptions().resolveRules().isEmpty()).isTrue();
    }

    // ---------------------------------------------------------------------------------------------

    private static SanitizeCommand command(final String... options) {
        final SanitizeCommand command = new SanitizeCommand();
        final List<String> argv = new ArrayList<>(asList(options));
        argv.add("in.hprof");
        argv.add("out.hprof");
        new CommandLine(command)
                .registerConverter(DataSize.class, DataSize::parse)
                .parseArgs(argv.toArray(EMPTY_STRING_ARRAY));
        return command;
    }

    private byte[] sanitize(final byte[] input, final SanitizationRule rule, final String... options)
            throws IOException {
        final SanitizeCommand command = command(options);
        command.getSanitizeOptions().addRule(rule);
        return sanitize(input, command);
    }

    private byte[] sanitize(final byte[] input, final SanitizeCommand command) throws IOException {
        return run(new HeapDumpSanitizer(), input, command, false);
    }

    private byte[] sanitizeTwoPasses(final byte[] input, final SanitizationRule rule, final String... options)
            throws IOException {
        final SanitizeCommand command = command(options);
        command.getSanitizeOptions().addRule(rule);
        return sanitizeTwoPasses(input, command);
    }

    /*
     * A metadata pass then a writing pass on ONE sanitizer, which is what SanitizeCommandProcessor does
     * whenever -e is non-empty or -f is true -- i.e. by default. Shape matters here: the two passes share
     * the string map, the class layouts and the rule chain.
     */
    private byte[] sanitizeTwoPasses(final byte[] input, final SanitizeCommand command) throws IOException {
        final HeapDumpSanitizer sanitizer = new HeapDumpSanitizer();
        sanitizer.setPreprocessingOnly(true);
        try {
            run(sanitizer, input, command, true);
        } finally {
            sanitizer.setPreprocessingOnly(false);
        }
        return run(sanitizer, input, command, false);
    }

    private byte[] run(
            final HeapDumpSanitizer sanitizer,
            final byte[] input,
            final SanitizeCommand command,
            final boolean readOnly)
            throws IOException {
        final ByteArrayOutputStream outputBytes = new ByteArrayOutputStream();
        sanitizer.setInputStream(new ByteArrayInputStream(input));
        sanitizer.setOutputStream(readOnly ? null : outputBytes);
        sanitizer.setProgressMonitor(numBytesProcessed -> {
            // no op
        });
        sanitizer.setSanitizeCommand(command);
        sanitizer.sanitize();
        /*
         * Kept so a test can ask which rules matched. command.getSanitizationRules() builds a fresh
         * chain per call and match state lives on the chain, so only the instance the run actually used
         * can answer that.
         */
        lastRunRules = sanitizer.getSanitizationRules();

        final byte[] output = outputBytes.toByteArray();
        if (!readOnly) {
            assertThat(output.length)
                    .as("sanitization must preserve the length of the dump")
                    .isEqualTo(input.length);
        }
        return output;
    }

    private int[] region(final byte[] bytes, final int offset, final int length) {
        final int[] unsigned = new int[length];
        for (int i = 0; i < length; i++) {
            unsigned[i] = bytes[offset + i] & 0xFF;
        }
        return unsigned;
    }
}
