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
    void testAllThenSpecificOptOut() {
        final SanitizationPolicy policy = parse("--sanitize-all=true", "--sanitize-shorts=false");
        assertThat(policy.sanitizeField(BasicType.SHORT)).isFalse();
        assertThat(policy.sanitizeField(BasicType.INT)).isTrue();
        assertThat(policy.sanitizeArray(BasicType.SHORT)).isTrue();
    }

    @Test
    void testSpecificThenAllIsOverwritten() {
        // literal left-to-right: --sanitize-all comes last and wins
        final SanitizationPolicy policy = parse("--sanitize-shorts=false", "--sanitize-all=true");
        assertThat(policy.sanitizeField(BasicType.SHORT)).isTrue();
    }

    @Test
    void testAllFalseThenOptIn() {
        final SanitizationPolicy policy = parse("--sanitize-all=false", "--sanitize-byte-arrays=true");
        assertThat(policy.sanitizeArray(BasicType.BYTE)).isTrue();
        assertThat(policy.sanitizeArray(BasicType.CHAR)).isFalse();
        assertThat(policy.sanitizeField(BasicType.BYTE)).isFalse();
        assertThat(policy.isAnyFieldSanitized()).isFalse();
    }

    @Test
    void testFlagWithoutValueMeansTrue() {
        final SanitizationPolicy policy = parse("--sanitize-all=false", "--sanitize-ints");
        assertThat(policy.sanitizeField(BasicType.INT)).isTrue();
    }

    @Test
    void testEveryScopeFlagIsWired() {
        final String[] fieldFlags = {
                "--sanitize-bytes", "--sanitize-shorts", "--sanitize-ints", "--sanitize-longs",
                "--sanitize-chars", "--sanitize-floats", "--sanitize-doubles", "--sanitize-booleans"
        };
        final BasicType[] types = {
                BasicType.BYTE, BasicType.SHORT, BasicType.INT, BasicType.LONG,
                BasicType.CHAR, BasicType.FLOAT, BasicType.DOUBLE, BasicType.BOOLEAN
        };

        for (int i = 0; i < fieldFlags.length; i++) {
            final SanitizationPolicy policy = parse("--sanitize-all=false", fieldFlags[i] + "=true");
            assertThat(policy.sanitizeField(types[i])).as(fieldFlags[i]).isTrue();
            assertThat(policy.sanitizeArray(types[i])).as(fieldFlags[i] + " array untouched").isFalse();
        }
    }

    @Test
    void testEveryArrayScopeFlagIsWired() {
        final String[] arrayFlags = {
                "--sanitize-byte-arrays", "--sanitize-short-arrays", "--sanitize-int-arrays",
                "--sanitize-long-arrays", "--sanitize-char-arrays", "--sanitize-float-arrays",
                "--sanitize-double-arrays", "--sanitize-boolean-arrays"
        };
        final BasicType[] types = {
                BasicType.BYTE, BasicType.SHORT, BasicType.INT, BasicType.LONG,
                BasicType.CHAR, BasicType.FLOAT, BasicType.DOUBLE, BasicType.BOOLEAN
        };

        for (int i = 0; i < arrayFlags.length; i++) {
            final SanitizationPolicy policy = parse("--sanitize-all=false", arrayFlags[i] + "=true");
            assertThat(policy.sanitizeArray(types[i])).as(arrayFlags[i]).isTrue();
            assertThat(policy.sanitizeField(types[i])).as(arrayFlags[i] + " field untouched").isFalse();
        }
    }

    @Test
    void testReplacementFlags() {
        final SanitizationPolicy policy = parse("--sanitize-int-replacement=7",
                                                "--sanitize-byte-replacement='z'");
        assertThat(policy.replacement(BasicType.INT)).containsExactly(0, 0, 0, 7);
        assertThat(policy.replacement(BasicType.BYTE)).containsExactly('z');
        assertThat(policy.replacement(BasicType.SHORT)).containsExactly(0, 0);
    }

    @Test
    void testAllReplacementThenSpecific() {
        final SanitizationPolicy policy = parse("--sanitize-all-replacement='*'",
                                                "--sanitize-int-replacement=0");
        assertThat(policy.replacement(BasicType.BYTE)).containsExactly(42);
        assertThat(policy.replacement(BasicType.INT)).containsExactly(0, 0, 0, 0);
    }

    @Test
    void testInvalidReplacementIsRejected() {
        assertThatThrownBy(() -> parse("--sanitize-byte-replacement=300"))
                .isInstanceOf(CommandLine.ParameterException.class)
                .hasMessageContaining("out of range");
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
        // --sanitize-all=false first, so the assertions below cannot be satisfied by the default
        // all-on baseline: the legacy flag must actively turn everything back on.
        final SanitizationPolicy policy = parse("--sanitize-all=false",
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
                                                "--sanitize-int-arrays=true");
        assertThat(policy.sanitizeArray(BasicType.BYTE)).isTrue();
        assertThat(policy.sanitizeArray(BasicType.INT)).isTrue();

        // reverse order: legacy comes last and wipes the int-array opt-in
        final SanitizationPolicy reversed = parse("--sanitize-int-arrays=true",
                                                  "--sanitize-byte-char-arrays-only=true");
        assertThat(reversed.sanitizeArray(BasicType.INT)).isFalse();
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
    void testAllReplacementBadValueIsParameterException() {
        assertThatThrownBy(() -> parse("--sanitize-all-replacement=bogus"))
                .isInstanceOf(CommandLine.ParameterException.class);
    }

    @Test
    void testAllReplacementNumber() {
        final SanitizationPolicy policy = parse("--sanitize-all-replacement=42");
        assertThat(policy.replacement(BasicType.BYTE)).containsExactly(42);
        assertThat(policy.replacement(BasicType.SHORT)).containsExactly(0, 42);
        assertThat(policy.replacement(BasicType.INT)).containsExactly(0, 0, 0, 42);
        assertThat(policy.replacement(BasicType.LONG)).containsExactly(0, 0, 0, 0, 0, 0, 0, 42);
        // char 42 = 0x002A
        assertThat(policy.replacement(BasicType.CHAR)).containsExactly(0x00, 0x2A);
        // float 42.0f
        assertThat(policy.replacement(BasicType.FLOAT)).containsExactly(0x42, 0x28, 0x00, 0x00);
        // double 42.0
        assertThat(policy.replacement(BasicType.DOUBLE))
                .containsExactly(0x40, 0x45, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00);
        // boolean: 42 != 0 -> true -> 1
        assertThat(policy.replacement(BasicType.BOOLEAN)).containsExactly(1);
    }

    @Test
    void testCopyFromPreservesDirectiveOrder() {
        final TestCommand source = new TestCommand();
        new CommandLine(source).parseArgs("--sanitize-all=false", "--sanitize-long-arrays=true");

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
        new CommandLine(command).parseArgs("--sanitize-all=false",
                                          "--sanitize-long-arrays=true",
                                          "--sanitize-int-replacement=7",
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
