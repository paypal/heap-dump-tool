package com.paypal.heapdumptool.sanitizer;

import org.junit.jupiter.api.Test;
import org.meanbean.test.BeanVerifier;
import picocli.CommandLine;

import static com.paypal.heapdumptool.sanitizer.DataSize.ofMegabytes;
import static java.util.Collections.singletonList;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

public class SanitizeCommandTest {

    @Test
    public void testBean() {
        BeanVerifier.forClass(SanitizeCommand.class)
                    .withSettings(settings -> settings.addOverridePropertyFactory(SanitizeCommand::getBufferSize, () -> ofMegabytes(5)))
                    .withSettings(settings -> settings.addIgnoredPropertyName("excludeStringFields"))
                    .withSettings(settings -> settings.addIgnoredPropertyName("sanitizeOptions"))
                    .withSettings(settings -> settings.addIgnoredPropertyName("sanitizationPolicy"))
                    .verifyGettersAndSetters();
    }

    @Test
    public void testSanitizationPolicyFromCommandLine() {
        final SanitizeCommand command = parse("--target=byte-arrays",
                                              "in.hprof", "out.hprof");

        final SanitizationPolicy policy = command.getSanitizationPolicy();
        assertThat(policy.sanitizeArray(BasicType.BYTE)).isTrue();
        assertThat(policy.sanitizeArray(BasicType.INT)).isFalse();
        assertThat(policy.isAnyFieldSanitized()).isFalse();
    }

    @Test
    public void testLegacyFlagOnRealCommandWarns() {
        final SanitizeCommand command = parse("-s=true", "in.hprof", "out.hprof");

        assertThat(command.getSanitizationPolicy().getWarnings()).hasSize(1);
        assertThat(command.getSanitizationPolicy().sanitizeArray(BasicType.CHAR)).isTrue();
    }

    @Test
    public void testLegacyAndNewFlagsInterleaveOnRealCommand() {
        final SanitizationPolicy policy = parse("-s=true", "--target=byte-arrays,char-arrays,int-arrays",
                                                "in.hprof", "out.hprof").getSanitizationPolicy();
        assertThat(policy.sanitizeArray(BasicType.INT)).isTrue();
        assertThat(policy.sanitizeArray(BasicType.BYTE)).isTrue();

        // reverse order: the legacy flag comes last and wipes the int-array opt-in
        final SanitizationPolicy reversed = parse("--target=int-arrays", "-s=true",
                                                 "in.hprof", "out.hprof").getSanitizationPolicy();
        assertThat(reversed.sanitizeArray(BasicType.INT)).isFalse();
    }

    @Test
    public void testNoFlagsSanitizesEverythingByDefault() {
        final SanitizationPolicy policy = parse("in.hprof", "out.hprof").getSanitizationPolicy();
        for (final BasicType type : SanitizationPolicy.PRIMITIVES) {
            assertThat(policy.sanitizeField(type)).as("field " + type).isTrue();
            assertThat(policy.sanitizeArray(type)).as("array " + type).isTrue();
        }
        assertThat(policy.getWarnings()).isEmpty();
    }

    /**
     * The deprecated -T is parsed, warned about, and otherwise has no effect.
     */
    @Test
    public void testLegacyTextCharsetOnRealCommandWarns() {
        final SanitizationPolicy policy = parse("-T=UTF-8", "in.hprof", "out.hprof")
                .getSanitizationPolicy();
        assertThat(policy.getWarnings()).hasSize(1);
        assertThat(policy.getWarnings().get(0)).contains("--text-charset");
        assertThat(policy.replacement(BasicType.BYTE)).containsExactly(42);
    }

    @Test
    public void testLegacyTextOnRealCommandWarns() {
        final SanitizationPolicy policy = parse("-t=*", "in.hprof", "out.hprof")
                .getSanitizationPolicy();
        assertThat(policy.getWarnings()).hasSize(1);
        assertThat(policy.getWarnings().get(0)).contains("--text");
        assertThat(policy.replacement(BasicType.BYTE)).containsExactly('*');
        // BYTE alone cannot prove -t was applied: 42 == '*' is already the default. SHORT and
        // FLOAT discriminate -- their defaults are all-zero.
        assertThat(policy.replacement(BasicType.SHORT)).containsExactly(0, 42);
        assertThat(policy.replacement(BasicType.FLOAT)).containsExactly(0x42, 0x28, 0, 0);
    }

    /**
     * {@code Application.main} parses the same CommandLine twice: once inside
     * {@code PrivilegeEscalator.escalatePrivilegesIfNeeded} and again inside
     * {@code CommandLine.execute}. picocli reuses the same user object, so every option setter
     * fires twice and the recorded directives -- including their warnings -- are appended twice.
     * The resolved policy must still carry exactly one warning per distinct deprecated flag.
     */
    @Test
    public void testDoubleParseWarnsOncePerDeprecatedFlag() {
        final SanitizeCommand command = new SanitizeCommand();
        final CommandLine commandLine = new CommandLine(command)
                .registerConverter(DataSize.class, DataSize::parse);

        final String[] args = {"-T=UTF-8", "-s=true", "in.hprof", "out.hprof"};
        commandLine.parseArgs(args);
        commandLine.parseArgs(args);

        final SanitizationPolicy policy = command.getSanitizationPolicy();
        assertThat(policy.getWarnings()).hasSize(2);
        assertThat(policy.getWarnings().get(0)).contains("--text-charset");
        assertThat(policy.getWarnings().get(1)).contains("--sanitize-byte-char-arrays-only");

        // the scope outcome is order-preserving and unaffected by the replay
        assertThat(policy.sanitizeArray(BasicType.BYTE)).isTrue();
        assertThat(policy.sanitizeArray(BasicType.CHAR)).isTrue();
        assertThat(policy.sanitizeArray(BasicType.INT)).isFalse();
    }

    /**
     * The single-flag case from the finding: {@code sanitize -s=true} parsed twice must warn once.
     */
    @Test
    public void testDoubleParseSingleLegacyFlagWarnsOnce() {
        final SanitizeCommand command = new SanitizeCommand();
        final CommandLine commandLine = new CommandLine(command)
                .registerConverter(DataSize.class, DataSize::parse);

        commandLine.parseArgs("-s=true", "in.hprof", "out.hprof");
        commandLine.parseArgs("-s=true", "in.hprof", "out.hprof");

        assertThat(command.getSanitizationPolicy().getWarnings()).hasSize(1);
    }

    /**
     * The policy must not be memoized: reading it before a second parse of the same command
     * object must not freeze the result. {@code Application.main} parses twice, so a stale memo
     * is a live hazard rather than a theoretical one.
     */
    @Test
    public void testPolicyIsRecomputedAfterReparse() {
        final SanitizeCommand command = new SanitizeCommand();
        final CommandLine commandLine = new CommandLine(command)
                .registerConverter(DataSize.class, DataSize::parse);

        commandLine.parseArgs("--target=none", "in.hprof", "out.hprof");
        assertThat(command.getSanitizationPolicy().isAnyFieldSanitized()).isFalse();

        commandLine.parseArgs("--target=all", "in.hprof", "out.hprof");
        assertThat(command.getSanitizationPolicy().isAnyFieldSanitized()).isTrue();
    }

    /**
     * SanitizeOrCaptureCommandBase.copyFrom delegates to SanitizeOptions.copyFrom, which clears
     * the target before copying. Copying a command onto itself must not wipe its own flags.
     */
    @Test
    public void testCopyFromSelfPreservesEverything() {
        final SanitizeCommand command = parse("--target=char-arrays",
                                              "-T=UTF-8", "in.hprof", "out.hprof");

        command.copyFrom(command);

        final SanitizationPolicy policy = command.getSanitizationPolicy();
        assertThat(policy.sanitizeArray(BasicType.CHAR)).isTrue();
        assertThat(policy.sanitizeArray(BasicType.BYTE)).isFalse();
        assertThat(policy.isAnyFieldSanitized()).isFalse();
        assertThat(policy.getWarnings()).hasSize(1);
    }

    /**
     * getExcludeStringFields() is memoized because HeapDumpSanitizer asks per record. The memo must
     * still reflect a later setter -- picocli itself calls the setter after the command is built.
     */
    @Test
    public void testExcludeStringFieldsMemoIsInvalidatedBySetter() {
        final SanitizeCommand command = parse("in.hprof", "out.hprof");
        assertThat(command.getExcludeStringFields())
                .containsExactly("java.lang.Thread#name", "java.lang.ThreadGroup#name");
        assertThat(command.isExactClassWithExcludeStringField("java.lang.Thread")).isTrue();

        command.setExcludeStringFields(singletonList("com.example.Foo#bar"));

        assertThat(command.getExcludeStringFields()).containsExactly("com.example.Foo#bar");
        assertThat(command.getExcludeStringFields("com.example.Foo")).containsExactly("bar");
        assertThat(command.isExactClassWithExcludeStringField("java.lang.Thread")).isFalse();
    }

    /**
     * capture hands its options to a sanitize command via copyFrom, which is the other writer of
     * excludeStringFields. A memo read before the copy must not survive it.
     */
    @Test
    public void testExcludeStringFieldsMemoIsInvalidatedByCopyFrom() {
        final SanitizeCommand target = parse("in.hprof", "out.hprof");
        assertThat(target.getExcludeStringFields()).hasSize(2);

        final SanitizeCommand source = parse("-e=com.example.Foo#bar", "in.hprof", "out.hprof");
        target.copyFrom(source);

        assertThat(target.getExcludeStringFields()).containsExactly("com.example.Foo#bar");
        assertThat(target.isExactClassWithExcludeStringField("com.example.Foo")).isTrue();
        assertThat(target.isExactClassWithExcludeStringField("java.lang.Thread")).isFalse();
    }

    /**
     * The memoized list is handed to the streaming path on every record, so a caller must not be able
     * to mutate the copy every later record will see.
     */
    @Test
    public void testExcludeStringFieldsMemoIsUnmodifiable() {
        final SanitizeCommand command = parse("in.hprof", "out.hprof");

        assertThatThrownBy(() -> command.getExcludeStringFields().add("com.example.Foo#bar"))
                .isInstanceOf(UnsupportedOperationException.class);
    }

    /**
     * Mirrors {@code Application.newCommandLine}, which registers the DataSize converter.
     */
    private SanitizeCommand parse(final String... args) {
        final SanitizeCommand command = new SanitizeCommand();
        new CommandLine(command)
                .registerConverter(DataSize.class, DataSize::parse)
                .parseArgs(args);
        return command;
    }

}
