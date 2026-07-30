package com.paypal.heapdumptool.sanitizer;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class ReplacementSpecTest {

    private static SanitizationPolicy parse(final String value) {
        final SanitizationPolicy.Builder builder = SanitizationPolicy.builder();
        ReplacementSpec.applyTo(value, builder);
        return builder.build();
    }

    @Test
    void testSingleTypeEntry() {
        final SanitizationPolicy policy = parse("int=7");
        assertThat(policy.replacement(BasicType.INT)).containsExactly(0, 0, 0, 7);
        // other types keep their defaults
        assertThat(policy.replacement(BasicType.BYTE)).containsExactly(42);
        assertThat(policy.replacement(BasicType.SHORT)).containsExactly(0, 0);
    }

    @Test
    void testMultipleEntries() {
        final SanitizationPolicy policy = parse("int=7,byte=122");
        assertThat(policy.replacement(BasicType.INT)).containsExactly(0, 0, 0, 7);
        assertThat(policy.replacement(BasicType.BYTE)).containsExactly('z');
    }

    @Test
    void testPluralTypeNames() {
        final SanitizationPolicy policy = parse("ints=7");
        assertThat(policy.replacement(BasicType.INT)).containsExactly(0, 0, 0, 7);
    }

    @Test
    void testCaseInsensitiveTypeNames() {
        final SanitizationPolicy policy = parse("INT=7");
        assertThat(policy.replacement(BasicType.INT)).containsExactly(0, 0, 0, 7);
    }

    @Test
    void testWhitespaceAroundEntriesIsIgnored() {
        final SanitizationPolicy policy = parse(" int = 7 , byte = 122 ");
        assertThat(policy.replacement(BasicType.INT)).containsExactly(0, 0, 0, 7);
        assertThat(policy.replacement(BasicType.BYTE)).containsExactly('z');
    }

    @Test
    void testAllSetsEveryType() {
        final SanitizationPolicy policy = parse("all=0");
        assertThat(policy.replacement(BasicType.BYTE)).containsExactly(0);
        assertThat(policy.replacement(BasicType.CHAR)).containsExactly(0, 0);
        assertThat(policy.replacement(BasicType.INT)).containsExactly(0, 0, 0, 0);
        assertThat(policy.replacement(BasicType.BOOLEAN)).containsExactly(0);
    }

    @Test
    void testAllThenSpecificOverrides() {
        final SanitizationPolicy policy = parse("all=0,int=7");
        assertThat(policy.replacement(BasicType.BYTE)).containsExactly(0);
        assertThat(policy.replacement(BasicType.INT)).containsExactly(0, 0, 0, 7);
    }

    @Test
    void testSpecificThenAllIsOverwritten() {
        final SanitizationPolicy policy = parse("int=7,all=0");
        assertThat(policy.replacement(BasicType.INT)).containsExactly(0, 0, 0, 0);
    }

    /**
     * all=* means "the same character everywhere", so it is normalized to its code point and every
     * numeric type accepts it. Similar behavior to the deprecated --text flag.
     */
    @Test
    void testAllAcceptsACharacterLiteral() {
        final SanitizationPolicy policy = parse("all=*");
        assertThat(policy.replacement(BasicType.BYTE)).containsExactly(42);
        assertThat(policy.replacement(BasicType.CHAR)).containsExactly(0x00, 0x2A);
        assertThat(policy.replacement(BasicType.INT)).containsExactly(0, 0, 0, 42);
        assertThat(policy.replacement(BasicType.BOOLEAN)).containsExactly(1);
    }

    @Test
    void testAllAcceptsAnEscape() {
        final SanitizationPolicy policy = parse("all=\\0");
        assertThat(policy.replacement(BasicType.CHAR)).containsExactly(0, 0);
        assertThat(policy.replacement(BasicType.BYTE)).containsExactly(0);
        assertThat(policy.replacement(BasicType.BOOLEAN)).containsExactly(0);
    }

    @Test
    void testCharAcceptsACharacterLiteral() {
        assertThat(parse("char=*").replacement(BasicType.CHAR)).containsExactly(0x00, 0x2A);
        assertThat(parse("char=a").replacement(BasicType.CHAR)).containsExactly(0x00, 0x61);
        assertThat(parse("char=\\98").replacement(BasicType.CHAR)).containsExactly(0x00, 0x62);
    }

    /**
     * A character literal stays a char-only form for the numeric per-type entries: int=* is a usage
     * error, not code point 42. Locked in by commit d8059f0.
     */
    @Test
    void testNumericTypesRejectACharacterLiteral() {
        assertThatThrownBy(() -> parse("int=*"))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> parse("byte=*"))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void testOutOfRangeValueIsRejected() {
        assertThatThrownBy(() -> parse("byte=300"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("out of range");
    }

    @Test
    void testMissingEqualsIsRejected() {
        assertThatThrownBy(() -> parse("int"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("<type>=<value>");
    }

    @Test
    void testEmptyTypeIsRejected() {
        assertThatThrownBy(() -> parse("=7"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("empty");
    }

    @Test
    void testEmptyValueIsRejected() {
        assertThatThrownBy(() -> parse("int="))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("empty");
    }

    @Test
    void testEmptyEntryIsRejected() {
        assertThatThrownBy(() -> parse("int=7,,byte=0"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("empty");
    }

    @Test
    void testEmptySpecIsRejected() {
        assertThatThrownBy(() -> parse(""))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("empty");
        assertThatThrownBy(() -> parse("   "))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("empty");
    }

    @Test
    void testUnknownTypeIsRejected() {
        assertThatThrownBy(() -> parse("bogus=7"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("bogus");
    }

    @Test
    void testObjectTypeIsRejectedWithItsOwnMessage() {
        assertThatThrownBy(() -> parse("object=7"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("object")
                .hasMessageContaining("corrupt");
    }

    /**
     * A value containing '=' is a usage error rather than being silently split, so a typo cannot
     * become a surprising value.
     */
    @Test
    void testExtraEqualsIsRejected() {
        assertThatThrownBy(() -> parse("int=7=8"))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void testInvalidSpecLeavesBuilderUntouched() {
        final SanitizationPolicy.Builder builder = SanitizationPolicy.builder();
        assertThatThrownBy(() -> ReplacementSpec.applyTo("int=7,bogus=1", builder))
                .isInstanceOf(IllegalArgumentException.class);
        // int keeps its default rather than the rejected spec's 7
        assertThat(builder.build().replacement(BasicType.INT)).containsExactly(0, 0, 0, 0);
    }

    @Test
    void testValidateAcceptsAndRejectsWithoutABuilder() {
        ReplacementSpec.validate("all=0,int=7");
        assertThatThrownBy(() -> ReplacementSpec.validate("int=*"))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
