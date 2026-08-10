package com.paypal.heapdumptool.sanitizer;

import com.paypal.heapdumptool.fixture.Hprof;
import com.paypal.heapdumptool.testutil.ConstructorTester;
import com.paypal.heapdumptool.utils.DataSize;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import picocli.CommandLine;

import static java.util.Arrays.asList;
import static org.apache.commons.lang3.ArrayUtils.EMPTY_STRING_ARRAY;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Tests for {@link SanitizationRules}, the static factory that builds a {@link SanitizationRule}
 * from a single lambda. The interesting behavior is what the returned proxy does with the methods
 * that are <em>not</em> the targeted one: they must keep their default interface bodies rather than
 * throw, so a {@code fieldRule} genuinely abstains on arrays and vice versa.
 */
class SanitizationRulesTest {

    private static final String ACCOUNT_CLASS_NAME = "com.mycorp.Account";

    private static final long ACCOUNT_CLASS_ID = 2100;
    private static final long ACCOUNT_OBJECT_ID = 0xA000;
    private static final long ARRAY_OBJECT_ID = 0xA100;

    @Test
    @DisplayName("testFactoryIsUninstantiable. A static factory has no public constructor")
    void testFactoryIsUninstantiable() throws Exception {
        ConstructorTester.test(SanitizationRules.class);
    }

    // ---------------------------------------------------------------------------------------------
    // The returned proxy
    // ---------------------------------------------------------------------------------------------

    @Test
    @DisplayName("testFieldRuleDelegatesTheFieldDecision. decideField reaches the lambda")
    void testFieldRuleDelegatesTheFieldDecision() {
        final List<String> seen = new ArrayList<>();
        final SanitizationRule rule = SanitizationRules.fieldRule(field -> {
            seen.add(field.declaringClassName() + "#" + field.fieldName());
            return Decision.sanitize();
        });

        final FieldContext context = new Field("ssn", BasicType.INT, ACCOUNT_CLASS_NAME, false);
        assertThat(rule.decideField(context)).isEqualTo(Decision.sanitize());
        assertThat(seen).containsExactly(ACCOUNT_CLASS_NAME + "#ssn");
    }

    @Test
    @DisplayName("testFieldRuleAbstainsOnArrays. decideArray keeps its default undecided body")
    void testFieldRuleAbstainsOnArrays() {
        final SanitizationRule rule = SanitizationRules.fieldRule(field -> Decision.sanitize());

        assertThat(rule.decideArray(new PrimitiveArrayContext(ARRAY_OBJECT_ID, BasicType.BYTE, 4, 4)))
                .as("the default body of decideArray, not a throw")
                .isEqualTo(Decision.undecided());
    }

    @Test
    @DisplayName("testArrayRuleDelegatesTheArrayDecision. decideArray reaches the lambda")
    void testArrayRuleDelegatesTheArrayDecision() {
        final AtomicInteger seen = new AtomicInteger();
        final SanitizationRule rule = SanitizationRules.arrayRule(array -> {
            seen.incrementAndGet();
            return Decision.preserve();
        });

        assertThat(rule.decideArray(new PrimitiveArrayContext(ARRAY_OBJECT_ID, BasicType.BYTE, 4, 4)))
                .isEqualTo(Decision.preserve());
        assertThat(seen.get()).isEqualTo(1);
    }

    @Test
    @DisplayName("testArrayRuleAbstainsOnFields. decideField keeps its default undecided body")
    void testArrayRuleAbstainsOnFields() {
        final SanitizationRule rule = SanitizationRules.arrayRule(array -> Decision.preserve());

        assertThat(rule.decideField(new Field("ssn", BasicType.INT, ACCOUNT_CLASS_NAME, false)))
                .as("the default body of decideField, not a throw")
                .isEqualTo(Decision.undecided());
    }

    @Test
    @DisplayName("testDescribeDefaultsToTheFactoryName. No desc means fieldRule or arrayRule")
    void testDescribeDefaultsToTheFactoryName() {
        assertThat(SanitizationRules.fieldRule(field -> Decision.undecided()).describe())
                .isEqualTo("fieldRule");
        assertThat(SanitizationRules.arrayRule(array -> Decision.undecided()).describe())
                .isEqualTo("arrayRule");
        assertThat(SanitizationRules.preserveFieldRule(field -> true).describe())
                .isEqualTo("preserveFieldRule");
    }

    @Test
    @DisplayName("testDescribeHonoursTheDescArgument. A custom description round-trips")
    void testDescribeHonoursTheDescArgument() {
        assertThat(SanitizationRules.fieldRule("FindsAccount", field -> Decision.undecided())
                        .describe())
                .isEqualTo("FindsAccount");
        assertThat(SanitizationRules.arrayRule("FindsArrays", array -> Decision.undecided())
                        .describe())
                .isEqualTo("FindsArrays");
        assertThat(SanitizationRules.preserveFieldRule("KeepsToken", field -> true)
                        .describe())
                .isEqualTo("KeepsToken");
    }

    @Test
    @DisplayName("testPreserveFieldRulePreservesMatchesOnly. A predicate that matches one field")
    void testPreserveFieldRulePreservesMatchesOnly() {
        final SanitizationRule rule = SanitizationRules.preserveFieldRule(field -> "ssn".equals(field.fieldName()));

        assertThat(rule.decideField(new Field("ssn", BasicType.INT, ACCOUNT_CLASS_NAME, false)))
                .isEqualTo(Decision.preserve());
        assertThat(rule.decideField(new Field("balance", BasicType.INT, ACCOUNT_CLASS_NAME, false)))
                .isEqualTo(Decision.undecided());
    }

    @Test
    @DisplayName("testPreserveFieldRuleAbstainsOnArrays. decideArray keeps its default undecided body")
    void testPreserveFieldRuleAbstainsOnArrays() {
        final SanitizationRule rule = SanitizationRules.preserveFieldRule(field -> true);

        assertThat(rule.decideArray(new PrimitiveArrayContext(ARRAY_OBJECT_ID, BasicType.BYTE, 4, 4)))
                .as("the default body of decideArray, not a throw")
                .isEqualTo(Decision.undecided());
    }

    @Test
    @DisplayName("testProxyBehavesLikeAnObject. equals, hashCode and toString are sane on a proxy")
    void testProxyBehavesLikeAnObject() {
        final SanitizationRule rule = SanitizationRules.fieldRule(field -> Decision.undecided());
        final SanitizationRule twin = SanitizationRules.fieldRule(field -> Decision.undecided());

        assertThat(rule.equals(rule)).isTrue();
        assertThat(rule.equals(twin)).isFalse();
        assertThat(rule.equals(null)).isFalse();
        assertThat(rule.equals("not a rule")).isFalse();
        assertThat(rule.hashCode()).isEqualTo(rule.hashCode());
        assertThat(rule.toString()).isNotEmpty();
    }

    @Test
    @DisplayName("testNullLambdaIsRejected. A rule must do something")
    @SuppressWarnings("all")
    void testNullLambdaIsRejected() {
        assertThatThrownBy(() -> SanitizationRules.fieldRule(null)).isInstanceOf(NullPointerException.class);
        assertThatThrownBy(() -> SanitizationRules.arrayRule(null)).isInstanceOf(NullPointerException.class);
        assertThatThrownBy(() -> SanitizationRules.preserveFieldRule(null)).isInstanceOf(NullPointerException.class);
    }

    // ---------------------------------------------------------------------------------------------
    // Integration through a real run
    // ---------------------------------------------------------------------------------------------

    @Test
    @DisplayName("testFieldRuleSanitizesOnlyTheNamedField. --target=none plus a fieldRule")
    void testFieldRuleSanitizesOnlyTheNamedField() throws Exception {
        final AccountFixture fixture = new AccountFixture();

        final SanitizationRule rule = SanitizationRules.fieldRule(
                field -> "ssn".equals(field.fieldName()) ? Decision.sanitize() : Decision.undecided());

        final byte[] output = sanitize(fixture.input, rule, "--target=none");

        assertThat(region(output, fixture.ssnOffset, Integer.BYTES))
                .as("the lambda named ssn, so it is overwritten")
                .containsExactly(0, 0, 0, 0);
        assertThat(region(output, fixture.balanceOffset, Integer.BYTES))
                .as("the lambda abstained on balance, so it survives")
                .containsExactly(0x22, 0x22, 0x22, 0x22);
    }

    @Test
    @DisplayName("testFieldRulePreservesUnderTargetAll. A PRESERVE verdict from a lambda beats --target=all")
    void testFieldRulePreservesUnderTargetAll() throws Exception {
        final AccountFixture fixture = new AccountFixture();

        final SanitizationRule rule = SanitizationRules.fieldRule(
                field -> "balance".equals(field.fieldName()) ? Decision.preserve() : Decision.undecided());

        final byte[] output = sanitize(fixture.input, rule, "--target=all");

        assertThat(region(output, fixture.balanceOffset, Integer.BYTES))
                .as("the lambda preserved balance")
                .containsExactly(0x22, 0x22, 0x22, 0x22);
        assertThat(region(output, fixture.ssnOffset, Integer.BYTES))
                .as("the untouched neighbour follows --target=all")
                .containsExactly(0, 0, 0, 0);
    }

    @Test
    @DisplayName("testPreserveFieldRuleKeepsTheNamedFieldUnderTargetAll. Predicate-based preserve beats --target=all")
    void testPreserveFieldRuleKeepsTheNamedFieldUnderTargetAll() throws Exception {
        final AccountFixture fixture = new AccountFixture();

        final SanitizationRule rule = SanitizationRules.preserveFieldRule(field -> "balance".equals(field.fieldName()));

        final byte[] output = sanitize(fixture.input, rule, "--target=all");

        assertThat(region(output, fixture.balanceOffset, Integer.BYTES))
                .as("the predicate preserved balance")
                .containsExactly(0x22, 0x22, 0x22, 0x22);
        assertThat(region(output, fixture.ssnOffset, Integer.BYTES))
                .as("the untouched neighbour follows --target=all")
                .containsExactly(0, 0, 0, 0);
    }

    @Test
    @DisplayName("testArrayRulePreservesAnArray. An arrayRule can preserve one array type under --target=all")
    void testArrayRulePreservesAnArray() throws Exception {
        final Hprof body = new Hprof();
        final int dataOffset = body.primitiveArrayDump(ARRAY_OBJECT_ID, BasicType.BYTE, new byte[] {1, 2, 3, 4});

        final Hprof input = new Hprof().header();
        final int base = input.record(HeapRecord.HEAP_DUMP_SEGMENT.getTag(), body);

        final SanitizationRule rule = SanitizationRules.arrayRule(array -> Decision.preserve());

        final byte[] output = sanitize(input.toByteArray(), rule, "--target=all");

        assertThat(region(output, base + dataOffset, 4))
                .as("the arrayRule preserved this array despite --target=all")
                .containsExactly(1, 2, 3, 4);
    }

    @Test
    @DisplayName("testThrowingLambdaAbortsTheRun. A rule that throws must not fall back to preserving")
    void testThrowingLambdaAbortsTheRun() throws Exception {
        final AccountFixture fixture = new AccountFixture();

        final SanitizationRule broken = SanitizationRules.fieldRule("BrokenRule", field -> {
            throw new IllegalStateException("boom");
        });

        assertThatThrownBy(() -> sanitize(fixture.input, broken, "--target=none"))
                .isInstanceOf(SanitizationRuleException.class)
                .hasMessageContaining("BrokenRule")
                .hasRootCauseMessage("boom");
    }

    // ---------------------------------------------------------------------------------------------

    private static final class AccountFixture {

        final byte[] input;
        final int ssnOffset;
        final int balanceOffset;

        AccountFixture() throws IOException {
            final Hprof hprof = new Hprof().header();
            hprof.stringInUtf8(60, ACCOUNT_CLASS_NAME);
            hprof.stringInUtf8(61, "ssn");
            hprof.stringInUtf8(62, "balance");
            hprof.loadClass(1, ACCOUNT_CLASS_ID, 60);

            final Hprof body = new Hprof();
            body.classDump(ACCOUNT_CLASS_ID, 0, new int[] {61, 62}, new BasicType[] {BasicType.INT, BasicType.INT});

            final Hprof instance = new Hprof();
            final int relativeSsn = instance.offset();
            instance.u4(0x11111111);
            final int relativeBalance = instance.offset();
            instance.u4(0x22222222);
            final int instanceOffset = body.instanceDump(ACCOUNT_OBJECT_ID, ACCOUNT_CLASS_ID, instance.toByteArray());

            final int base = hprof.record(HeapRecord.HEAP_DUMP_SEGMENT.getTag(), body);

            this.input = hprof.toByteArray();
            this.ssnOffset = base + instanceOffset + relativeSsn;
            this.balanceOffset = base + instanceOffset + relativeBalance;
        }
    }

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
        final ByteArrayOutputStream outputBytes = new ByteArrayOutputStream();
        final HeapDumpSanitizer sanitizer = new HeapDumpSanitizer();
        sanitizer.setInputStream(new ByteArrayInputStream(input));
        sanitizer.setOutputStream(outputBytes);
        sanitizer.setProgressMonitor(numBytesProcessed -> {
            // no op
        });
        sanitizer.setSanitizeCommand(command);
        sanitizer.sanitize();

        final byte[] output = outputBytes.toByteArray();
        assertThat(output.length)
                .as("sanitization must preserve the length of the dump")
                .isEqualTo(input.length);
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
