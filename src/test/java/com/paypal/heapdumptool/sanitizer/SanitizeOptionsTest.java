package com.paypal.heapdumptool.sanitizer;

import org.junit.jupiter.api.Test;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Mixin;
import picocli.CommandLine.Option;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class SanitizeOptionsTest {

    /**
     * Mirrors how SanitizeOrCaptureCommandBase declares these: the mixin carries the new
     * options, the enclosing command carries the deprecated ones. Declaring them the same way
     * here is what proves legacy and new flags interleave by position.
     */
    @Command(name = "test")
    private static class TestCommand {
        @Mixin
        private final SanitizeOptions options = new SanitizeOptions();

        @Option(names = {"-s", "--sanitize-byte-char-arrays-only"}, arity = "1",
                paramLabel = "<true|false>", description = "Deprecated")
        void legacyByteCharArraysOnly(final boolean value) {
            options.recordLegacyByteCharArraysOnly(value);
        }

        @Option(names = {"-t", "--text"}, paramLabel = "<text>", description = "Deprecated")
        void legacyText(final String value) {
            options.recordLegacyText(value);
        }

        @Option(names = {"-T", "--text-charset"}, paramLabel = "<charset>", description = "Deprecated")
        void legacyTextCharset(final String value) {
            options.recordLegacyTextCharset(value);
        }
    }

    private SanitizationPolicy parse(final String... args) {
        final TestCommand command = new TestCommand();
        new CommandLine(command).parseArgs(args);
        return command.options.resolve();
    }

    @Test
    void testDefaultSanitizesEverything() {
        final SanitizationPolicy policy = parse();
        for (final BasicType type : SanitizationPolicy.PRIMITIVES) {
            assertThat(policy.sanitizeField(type)).as("field " + type).isTrue();
            assertThat(policy.sanitizeArray(type)).as("array " + type).isTrue();
        }
        assertThat(policy.sanitizeField(BasicType.OBJECT)).isFalse();
        assertThat(policy.sanitizeArray(BasicType.OBJECT)).isFalse();
    }

    @Test
    void testTargetNoneSanitizesNothing() {
        final SanitizationPolicy policy = parse("--target=none");
        for (final BasicType type : SanitizationPolicy.PRIMITIVES) {
            assertThat(policy.sanitizeField(type)).as("field " + type).isFalse();
            assertThat(policy.sanitizeArray(type)).as("array " + type).isFalse();
        }
        assertThat(policy.isAnyFieldSanitized()).isFalse();
    }

    @Test
    void testTargetSubtraction() {
        final SanitizationPolicy policy = parse("--target=all,-short-fields");
        assertThat(policy.sanitizeField(BasicType.SHORT)).isFalse();
        assertThat(policy.sanitizeArray(BasicType.SHORT)).isTrue();
        assertThat(policy.sanitizeField(BasicType.INT)).isTrue();
    }

    @Test
    void testTargetImplicitNoneBase() {
        final SanitizationPolicy policy = parse("--target=byte-arrays,char-arrays");
        assertThat(policy.sanitizeArray(BasicType.BYTE)).isTrue();
        assertThat(policy.sanitizeArray(BasicType.CHAR)).isTrue();
        assertThat(policy.sanitizeArray(BasicType.INT)).isFalse();
        assertThat(policy.isAnyFieldSanitized()).isFalse();
    }

    /**
     * One --target value must produce exactly the policy the equivalent old flag sequence did.
     * This is the migration contract for the pre-1.4.0 scope.
     */
    @Test
    void testTargetReplacesTheOldTwoFlagSequences() {
        final SanitizationPolicy policy = parse("--target=int-fields");
        assertThat(policy.sanitizeField(BasicType.INT)).isTrue();
        assertThat(policy.sanitizeArray(BasicType.INT)).isFalse();
        for (final BasicType type : SanitizationPolicy.PRIMITIVES) {
            if (type != BasicType.INT) {
                assertThat(policy.sanitizeField(type)).as("field " + type).isFalse();
            }
            assertThat(policy.sanitizeArray(type)).as("array " + type).isFalse();
        }
    }

    @Test
    void testBadTargetIsParameterException() {
        assertThatThrownBy(() -> parse("--target=bogus"))
                .isInstanceOf(CommandLine.ParameterException.class)
                .hasMessageContaining("bogus");

        assertThatThrownBy(() -> parse("--target=-int"))
                .isInstanceOf(CommandLine.ParameterException.class)
                .hasMessageContaining("cannot start");
    }

    /**
     * --target takes the whole selector list in one value, so a second occurrence is an error
     * rather than an accumulation. See the class comment on SanitizeOptions.
     */
    @Test
    void testRepeatedTargetIsRejected() {
        assertThatThrownBy(() -> parse("--target=all", "--target=-int"))
                .isInstanceOf(CommandLine.OverwrittenOptionException.class);
    }

    @Test
    void testReplacementFlag() {
        final SanitizationPolicy policy = parse("--replacement=int=7,byte=122");
        assertThat(policy.replacement(BasicType.INT)).containsExactly(0, 0, 0, 7);
        assertThat(policy.replacement(BasicType.BYTE)).containsExactly('z');
        assertThat(policy.replacement(BasicType.SHORT)).containsExactly(0, 0);
    }

    @Test
    void testReplacementAllThenSpecific() {
        final SanitizationPolicy policy = parse("--replacement=all=*,int=0");
        assertThat(policy.replacement(BasicType.BYTE)).containsExactly(42);
        assertThat(policy.replacement(BasicType.INT)).containsExactly(0, 0, 0, 0);
    }

    @Test
    void testBadReplacementIsParameterException() {
        assertThatThrownBy(() -> parse("--replacement=byte=300"))
                .isInstanceOf(CommandLine.ParameterException.class)
                .hasMessageContaining("out of range");

        assertThatThrownBy(() -> parse("--replacement=bogus=1"))
                .isInstanceOf(CommandLine.ParameterException.class);

        assertThatThrownBy(() -> parse("--replacement=int=*"))
                .isInstanceOf(CommandLine.ParameterException.class);
    }

    @Test
    void testRepeatedReplacementIsRejected() {
        assertThatThrownBy(() -> parse("--replacement=all=0", "--replacement=int=7"))
                .isInstanceOf(CommandLine.OverwrittenOptionException.class);
    }

    /**
     * --target and --replacement are independent axes: setting a value does not change scope, and
     * narrowing scope does not change values.
     */
    @Test
    void testTargetAndReplacementAreIndependent() {
        final SanitizationPolicy policy = parse("--target=int-arrays", "--replacement=int=7");
        assertThat(policy.sanitizeArray(BasicType.INT)).isTrue();
        assertThat(policy.sanitizeField(BasicType.INT)).isFalse();
        assertThat(policy.replacement(BasicType.INT)).containsExactly(0, 0, 0, 7);
        // a type out of scope still has its replacement recorded, it is just never written
        assertThat(policy.replacement(BasicType.BYTE)).containsExactly(42);
    }

    @Test
    void testLegacyByteCharArraysOnlyTrue() {
        final SanitizationPolicy policy = parse("--sanitize-byte-char-arrays-only=true");

        assertThat(policy.sanitizeArray(BasicType.BYTE)).isTrue();
        assertThat(policy.sanitizeArray(BasicType.CHAR)).isTrue();
        assertThat(policy.sanitizeArray(BasicType.INT)).isFalse();
        assertThat(policy.isAnyFieldSanitized()).isFalse();
        assertThat(policy.getWarnings()).hasSize(1);
        assertThat(policy.getWarnings().get(0)).contains("--sanitize-byte-char-arrays-only");
    }

    @Test
    void testLegacyByteCharArraysOnlyFalse() {
        // --target=none first, so the assertions below cannot be satisfied by the default
        // all-on baseline: the legacy flag must actively turn everything back on.
        final SanitizationPolicy policy = parse("--target=none",
                                                "--sanitize-byte-char-arrays-only=false");
        assertThat(policy.isAnyFieldSanitized()).isTrue();
        for (final BasicType type : SanitizationPolicy.PRIMITIVES) {
            assertThat(policy.sanitizeField(type)).as("field " + type).isTrue();
            assertThat(policy.sanitizeArray(type)).as("array " + type).isTrue();
        }
        assertThat(policy.getWarnings()).hasSize(1);
    }

    @Test
    void testLegacyTextMapsToAllReplacement() {
        final SanitizationPolicy policy = parse("--text=*");
        assertThat(policy.replacement(BasicType.BYTE)).containsExactly(42);
        assertThat(policy.replacement(BasicType.CHAR)).containsExactly(0x00, 0x2A);
        assertThat(policy.getWarnings()).hasSize(1);
        assertThat(policy.getWarnings().get(0)).contains("--text");
    }

    @Test
    void testLegacyTextRejectsMultipleCharacters() {
        assertThatThrownBy(() -> parse("--text=REDACTED"))
                .isInstanceOf(CommandLine.ParameterException.class)
                .hasMessageContaining("single ASCII character");
    }

    @Test
    void testLegacyTextRejectsNonAscii() {
        assertThatThrownBy(() -> parse("--text=é"))
                .isInstanceOf(CommandLine.ParameterException.class)
                .hasMessageContaining("single ASCII character");
    }

    @Test
    void testLegacyTextAcceptsEscapedNull() {
        final SanitizationPolicy policy = parse("--text=\\0");
        assertThat(policy.replacement(BasicType.BYTE)).containsExactly(0);
    }

    @Test
    void testLegacyTextCharsetWarnsAndIsIgnored() {
        final SanitizationPolicy policy = parse("--text-charset=UTF-8");
        assertThat(policy.getWarnings()).hasSize(1);
        assertThat(policy.getWarnings().get(0)).contains("--text-charset");
        // ignored: byte replacement keeps its default
        assertThat(policy.replacement(BasicType.BYTE)).containsExactly(42);
    }

    @Test
    void testLegacyAndNewFlagsInterleaveByPosition() {
        // legacy narrows to byte/char arrays, then the new flag re-adds int arrays
        final SanitizationPolicy policy = parse("--sanitize-byte-char-arrays-only=true",
                                                "--target=int-arrays");
        assertThat(policy.sanitizeArray(BasicType.BYTE)).isFalse();
        assertThat(policy.sanitizeArray(BasicType.INT)).isTrue();

        // reverse order: legacy comes last and wipes the int-array opt-in
        final SanitizationPolicy reversed = parse("--target=int-arrays",
                                                  "--sanitize-byte-char-arrays-only=true");
        assertThat(reversed.sanitizeArray(BasicType.INT)).isFalse();
        assertThat(reversed.sanitizeArray(BasicType.BYTE)).isTrue();
    }

    @Test
    void testLegacyTextDigitIsCharNotNumber() {
        // --text=0 must produce byte 0x30 ('0'=48), not 0x00
        final SanitizationPolicy policy0 = parse("--text=0");
        assertThat(policy0.replacement(BasicType.BYTE)).containsExactly(48);

        // --text=7 must produce byte 0x37 ('7'=55), not throw
        final SanitizationPolicy policy7 = parse("--text=7");
        assertThat(policy7.replacement(BasicType.BYTE)).containsExactly(55);

        // --text=z still works
        final SanitizationPolicy policyZ = parse("--text=z");
        assertThat(policyZ.replacement(BasicType.BYTE)).containsExactly(122);
    }


    @Test
    void testCopyFromPreservesDirectiveOrder() {
        final TestCommand source = new TestCommand();
        new CommandLine(source).parseArgs("--target=long-arrays");

        final SanitizeOptions target = new SanitizeOptions();
        target.copyFrom(source.options);
        final SanitizationPolicy policy = target.resolve();

        assertThat(policy.sanitizeArray(BasicType.LONG)).isTrue();
        assertThat(policy.sanitizeArray(BasicType.BYTE)).isFalse();
    }

    /**
     * copyFrom clears the target's directives before copying. When source and target are the same
     * object those are the same list, so without a self-copy guard every directive is silently
     * discarded.
     */
    @Test
    void testCopyFromSelfIsANoOp() {
        final TestCommand command = new TestCommand();
        new CommandLine(command).parseArgs("--target=long-arrays",
                                          "--replacement=int=7",
                                          "--text-charset=UTF-8");

        final SanitizationPolicy before = command.options.resolve();

        command.options.copyFrom(command.options);

        final SanitizationPolicy after = command.options.resolve();
        assertThat(after.sanitizeArray(BasicType.LONG)).isTrue();
        assertThat(after.sanitizeArray(BasicType.BYTE)).isFalse();
        assertThat(after.isAnyFieldSanitized()).isFalse();
        assertThat(after.replacement(BasicType.INT)).containsExactly(0, 0, 0, 7);
        assertThat(after.getWarnings()).isEqualTo(before.getWarnings());
        assertThat(after.getWarnings()).hasSize(1);
    }
}
