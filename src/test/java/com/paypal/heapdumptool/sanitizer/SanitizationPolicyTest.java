package com.paypal.heapdumptool.sanitizer;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class SanitizationPolicyTest {

    @Test
    void testEverythingOffByDefault() {
        final SanitizationPolicy policy = SanitizationPolicy.builder().build();
        for (final BasicType type : BasicType.values()) {
            assertThat(policy.sanitizeField(type)).as("field " + type).isFalse();
            assertThat(policy.sanitizeArray(type)).as("array " + type).isFalse();
        }
        assertThat(policy.isAnyFieldSanitized()).isFalse();
        assertThat(policy.getWarnings()).isEmpty();
    }

    @Test
    void testSetAllCoversPrimitivesButNotObject() {
        final SanitizationPolicy policy = SanitizationPolicy.builder()
                .setAll(true)
                .build();

        assertThat(policy.sanitizeField(BasicType.OBJECT)).isFalse();
        assertThat(policy.sanitizeArray(BasicType.OBJECT)).isFalse();

        assertThat(policy.sanitizeField(BasicType.BYTE)).isTrue();
        assertThat(policy.sanitizeField(BasicType.BOOLEAN)).isTrue();
        assertThat(policy.sanitizeArray(BasicType.DOUBLE)).isTrue();
        assertThat(policy.isAnyFieldSanitized()).isTrue();
    }

    @Test
    void testFieldAndArrayAreIndependent() {
        final SanitizationPolicy policy = SanitizationPolicy.builder()
                .setArray(BasicType.BYTE, true)
                .build();

        assertThat(policy.sanitizeArray(BasicType.BYTE)).isTrue();
        assertThat(policy.sanitizeField(BasicType.BYTE)).isFalse();
        assertThat(policy.isAnyFieldSanitized()).isFalse();
    }

    @Test
    void testDefaultReplacements() {
        final SanitizationPolicy policy = SanitizationPolicy.builder().build();
        assertThat(policy.replacement(BasicType.BYTE)).containsExactly(42);
        assertThat(policy.replacement(BasicType.CHAR)).containsExactly(0x00, 0x2A);
        assertThat(policy.replacement(BasicType.INT)).containsExactly(0, 0, 0, 0);
        assertThat(policy.replacement(BasicType.SHORT)).containsExactly(0, 0);
        assertThat(policy.replacement(BasicType.LONG)).containsExactly(0, 0, 0, 0, 0, 0, 0, 0);
        assertThat(policy.replacement(BasicType.FLOAT)).containsExactly(0, 0, 0, 0);
        assertThat(policy.replacement(BasicType.DOUBLE)).containsExactly(0, 0, 0, 0, 0, 0, 0, 0);
        assertThat(policy.replacement(BasicType.BOOLEAN)).containsExactly(0);
    }

    @Test
    void testSetReplacementOverridesOneType() {
        final SanitizationPolicy policy = SanitizationPolicy.builder()
                .setReplacement(BasicType.INT, PrimitiveReplacement.encode(BasicType.INT, "7"))
                .build();

        assertThat(policy.replacement(BasicType.INT)).containsExactly(0, 0, 0, 7);
        assertThat(policy.replacement(BasicType.BYTE)).containsExactly(42);
    }

    @Test
    void testSetAllReplacementsFansOutAcrossTypes() {
        final SanitizationPolicy policy = SanitizationPolicy.builder()
                .setAllReplacements("\\42")
                .build();

        assertThat(policy.replacement(BasicType.BYTE)).containsExactly(42);
        assertThat(policy.replacement(BasicType.CHAR)).containsExactly(0x00, 0x2A);
        assertThat(policy.replacement(BasicType.SHORT)).containsExactly(0x00, 0x2A);
        assertThat(policy.replacement(BasicType.INT)).containsExactly(0, 0, 0, 42);
        assertThat(policy.replacement(BasicType.FLOAT)).containsExactly(0x42, 0x28, 0x00, 0x00);
        assertThat(policy.replacement(BasicType.BOOLEAN)).containsExactly(1);
    }

    @Test
    void testWarningsAccumulateInOrder() {
        final SanitizationPolicy policy = SanitizationPolicy.builder()
                .addWarning("first")
                .addWarning("second")
                .build();

        assertThat(policy.getWarnings()).containsExactly("first", "second");
    }

    /**
     * A deprecated flag can warn at most once per invocation (picocli raises
     * OverwrittenOptionException on a repeated option), so a repeated identical warning can only
     * come from the same flag being replayed -- e.g. by the double parse that
     * {@code Application.main} performs. Deduplicate, keeping first-seen order.
     */
    @Test
    void testDuplicateWarningsAreDeduplicatedKeepingFirstSeenOrder() {
        final SanitizationPolicy policy = SanitizationPolicy.builder()
                .addWarning("first")
                .addWarning("second")
                .addWarning("first")
                .addWarning("second")
                .addWarning("third")
                .build();

        assertThat(policy.getWarnings()).containsExactly("first", "second", "third");
    }

    @Test
    void testDeduplicatedWarningsAreStillUnmodifiable() {
        final SanitizationPolicy policy = SanitizationPolicy.builder()
                .addWarning("w")
                .addWarning("w")
                .build();

        assertThat(policy.getWarnings()).containsExactly("w");
        assertThatThrownBy(() -> policy.getWarnings().add("x"))
                .isInstanceOf(UnsupportedOperationException.class);
    }

    @Test
    void testWarningsAreUnmodifiable() {
        final SanitizationPolicy policy = SanitizationPolicy.builder().addWarning("w").build();
        assertThatThrownBy(() -> policy.getWarnings().add("x"))
                .isInstanceOf(UnsupportedOperationException.class);
    }

    @Test
    void testReplacementIsDefensivelyCopied() {
        final SanitizationPolicy policy = SanitizationPolicy.builder().build();
        final byte[] first = policy.replacement(BasicType.BYTE);
        first[0] = 99;
        assertThat(policy.replacement(BasicType.BYTE)).containsExactly(42);
    }

    @Test
    void testObjectReplacementRejected() {
        assertThatThrownBy(() -> SanitizationPolicy.builder().build().replacement(BasicType.OBJECT))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("OBJECT");
    }

    @Test
    void testSetReplacementCopiesTheCallersArray() {
        final byte[] mine = new byte[]{7};
        final SanitizationPolicy policy = SanitizationPolicy.builder()
                .setReplacement(BasicType.BYTE, mine)
                .build();

        mine[0] = 99;
        assertThat(policy.replacement(BasicType.BYTE)).containsExactly(7);
    }

    @Test
    void testBuilderReuseIsIsolated() {
        final SanitizationPolicy.Builder builder = SanitizationPolicy.builder()
                .setField(BasicType.BYTE, true)
                .setReplacement(BasicType.INT, new byte[]{0, 0, 0, 5});

        final SanitizationPolicy first = builder.build();

        // mutate the builder after first build
        builder.setField(BasicType.BYTE, false);
        builder.setReplacement(BasicType.INT, new byte[]{0, 0, 0, 9});

        final SanitizationPolicy second = builder.build();

        // first policy must not be affected by subsequent builder mutations
        assertThat(first.sanitizeField(BasicType.BYTE)).isTrue();
        assertThat(first.replacement(BasicType.INT)).containsExactly(0, 0, 0, 5);

        // second policy reflects the mutations
        assertThat(second.sanitizeField(BasicType.BYTE)).isFalse();
        assertThat(second.replacement(BasicType.INT)).containsExactly(0, 0, 0, 9);
    }

    @Test
    void testSetFieldAndSetArrayRejectObject() {
        assertThatThrownBy(() -> SanitizationPolicy.builder().setField(BasicType.OBJECT, true))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("OBJECT");

        assertThatThrownBy(() -> SanitizationPolicy.builder().setArray(BasicType.OBJECT, true))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("OBJECT");
    }
}
