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

    /**
     * The tiled buffer is shared by every sanitized region of its type, so nothing reachable from
     * the policy may alias it. replacement() returning the live buffer would let one caller's
     * mutation corrupt every later write.
     */
    @Test
    void testTiledBufferIsNotReachableThroughReplacement() {
        final SanitizationPolicy policy = SanitizationPolicy.builder().build();
        final byte[] buffer = policy.replacementOf(BasicType.BYTE).getTiledBuffer();

        policy.replacement(BasicType.BYTE)[0] = 99;

        assertThat(buffer[0]).isEqualTo((byte) 42);
        assertThat(buffer[buffer.length - 1]).isEqualTo((byte) 42);
    }

    @Test
    void testEachTypeGetsItsOwnTiledBuffer() {
        final SanitizationPolicy policy = SanitizationPolicy.builder()
                .setReplacement(BasicType.BYTE, new byte[]{7})
                .setReplacement(BasicType.SHORT, new byte[]{0, 9})
                .build();

        assertThat(policy.replacementOf(BasicType.BYTE).getTiledBuffer())
                .isNotSameAs(policy.replacementOf(BasicType.SHORT).getTiledBuffer());
        assertThat(policy.replacementOf(BasicType.BYTE).getTiledBuffer()[0]).isEqualTo((byte) 7);
        assertThat(policy.replacementOf(BasicType.SHORT).getTiledBuffer()[1]).isEqualTo((byte) 9);
    }

    /**
     * The point of pre-tiling: the same buffer instance serves every region of a type, so repeated
     * queries must not allocate a fresh one.
     */
    @Test
    void testTiledBufferIsReusedAcrossQueries() {
        final SanitizationPolicy policy = SanitizationPolicy.builder().build();

        assertThat(policy.replacementOf(BasicType.INT).getTiledBuffer())
                .isSameAs(policy.replacementOf(BasicType.INT).getTiledBuffer());
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
    void testDescribeTargets() {
        assertThat(SanitizationPolicy.builder().build().describeTargets())
                .isEqualTo("none");
        assertThat(SanitizationPolicy.builder().setAll(true).build().describeTargets())
                .isEqualTo("all");
        assertThat(SanitizationPolicy.builder()
                           .setArray(BasicType.BYTE, true)
                           .setArray(BasicType.CHAR, true)
                           .build()
                           .describeTargets())
                .isEqualTo("char-arrays,byte-arrays");
        assertThat(SanitizationPolicy.builder()
                           .setField(BasicType.INT, true)
                           .setArray(BasicType.INT, true)
                           .setField(BasicType.LONG, true)
                           .build()
                           .describeTargets())
                .isEqualTo("int,long-fields");
    }

    /**
     * Every type selected but one half missing is not 'all': the shorthand may only stand in for a
     * scope it exactly equals.
     */
    @Test
    void testDescribeTargetsIsAllOnlyWhenEveryHalfIsSelected() {
        assertThat(SanitizationPolicy.builder()
                           .setAll(true)
                           .setField(BasicType.BOOLEAN, false)
                           .build()
                           .describeTargets())
                .isEqualTo("boolean-arrays,char,float,double,byte,short,int,long");
    }

    @Test
    void testDescribeReplacementsListsEveryType() {
        assertThat(SanitizationPolicy.builder()
                           .setAllReplacements("0")
                           .setReplacement(BasicType.INT, PrimitiveReplacement.encode(BasicType.INT, "7"))
                           .build()
                           .describeReplacements())
                .isEqualTo("boolean=false,char=\\0,float=0.0,double=0.0,byte=0,short=0,int=7,long=0");
    }

    /**
     * The default run is the common one, so its line says what {@code --replacement}'s help says the
     * default is, rather than the eight-entry expansion that means the same thing.
     */
    @Test
    void testDescribeReplacementsShortensUntouchedDefaults() {
        assertThat(SanitizationPolicy.builder().build().describeReplacements())
                .isEqualTo("all=0,byte=42,char=*,boolean=false");
    }

    /**
     * Resolved bytes decide it, not whether a flag was passed: a flag that restates a default has
     * changed nothing, and the line should say so.
     */
    @Test
    void testDescribeReplacementsShortensDefaultsRestatedByFlag() {
        final SanitizationPolicy.Builder builder = SanitizationPolicy.builder();
        ReplacementSpec.applyTo("byte=42,char=*", builder);

        assertThat(builder.build().describeReplacements())
                .isEqualTo("all=0,byte=42,char=*,boolean=false");
    }

    /**
     * One altered type drops the shorthand for the full list, which is what makes the changed value
     * legible beside the untouched ones.
     */
    @Test
    void testDescribeReplacementsListsEveryTypeOnceOneDiffers() {
        assertThat(SanitizationPolicy.builder()
                           .setReplacement(BasicType.BYTE, PrimitiveReplacement.encode(BasicType.BYTE, "7"))
                           .build()
                           .describeReplacements())
                .isEqualTo("boolean=false,char=*,float=0.0,double=0.0,byte=7,short=0,int=0,long=0");
    }

    /**
     * The shorthand is advertised as pasteable too, so it must parse back to the very bytes it stands
     * for -- {@code all=0} zeroing every type, then three entries overriding.
     */
    @Test
    void testDefaultShorthandParsesBackToTheDefaults() {
        final SanitizationPolicy.Builder builder = SanitizationPolicy.builder()
                .setAllReplacements("9");
        ReplacementSpec.applyTo(SanitizationPolicy.DEFAULT_REPLACEMENTS, builder);
        final SanitizationPolicy reparsed = builder.build();

        for (final BasicType type : SanitizationPolicy.PRIMITIVES) {
            assertThat(reparsed.replacement(type))
                    .as("replacement " + type)
                    .isEqualTo(PrimitiveReplacement.defaultFor(type));
        }
        assertThat(reparsed.describeReplacements()).isEqualTo(SanitizationPolicy.DEFAULT_REPLACEMENTS);
    }

    /**
     * Both descriptions are advertised as pasteable, so they must parse back to the same policy.
     */
    @Test
    void testDescriptionsRoundTripThroughTheParsers() {
        final SanitizationPolicy original = SanitizationPolicy.builder()
                .setArray(BasicType.BYTE, true)
                .setField(BasicType.LONG, true)
                .setAllReplacements("*")
                .setReplacement(BasicType.INT, PrimitiveReplacement.encode(BasicType.INT, "-1"))
                .build();

        final SanitizationPolicy.Builder builder = SanitizationPolicy.builder();
        TargetSelector.applyTo(original.describeTargets(), builder);
        ReplacementSpec.applyTo(original.describeReplacements(), builder);
        final SanitizationPolicy reparsed = builder.build();

        assertThat(reparsed.describeTargets()).isEqualTo(original.describeTargets());
        assertThat(reparsed.describeReplacements()).isEqualTo(original.describeReplacements());
        for (final BasicType type : SanitizationPolicy.PRIMITIVES) {
            assertThat(reparsed.sanitizeField(type)).as("field " + type).isEqualTo(original.sanitizeField(type));
            assertThat(reparsed.sanitizeArray(type)).as("array " + type).isEqualTo(original.sanitizeArray(type));
            assertThat(reparsed.replacement(type)).as("replacement " + type).isEqualTo(original.replacement(type));
        }
    }

    /**
     * 'none' and 'all' are the two descriptions that are not a selector list, so check they parse
     * back too -- 'none' especially, since TargetSelector rejects a leading subtraction.
     */
    @Test
    void testNoneAndAllDescriptionsAreParseable() {
        TargetSelector.validate(SanitizationPolicy.builder().build().describeTargets());
        TargetSelector.validate(SanitizationPolicy.builder().setAll(true).build().describeTargets());
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
