package com.paypal.heapdumptool.sanitizer;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class TargetSelectorTest {

    private static SanitizationPolicy parse(final String value) {
        final SanitizationPolicy.Builder builder = SanitizationPolicy.builder();
        TargetSelector.applyTo(value, builder);
        return builder.build();
    }

    private static void assertNothingSanitized(final SanitizationPolicy policy) {
        for (final BasicType type : SanitizationPolicy.PRIMITIVES) {
            assertThat(policy.sanitizeField(type)).as("field " + type).isFalse();
            assertThat(policy.sanitizeArray(type)).as("array " + type).isFalse();
        }
    }

    private static void assertEverythingSanitized(final SanitizationPolicy policy) {
        for (final BasicType type : SanitizationPolicy.PRIMITIVES) {
            assertThat(policy.sanitizeField(type)).as("field " + type).isTrue();
            assertThat(policy.sanitizeArray(type)).as("array " + type).isTrue();
        }
    }

    @Test
    void testAllSelectsEverything() {
        assertEverythingSanitized(parse("all"));
    }

    @Test
    void testNoneSelectsNothing() {
        assertNothingSanitized(parse("none"));
    }

    @Test
    void testObjectIsNeverSanitized() {
        final SanitizationPolicy policy = parse("all");
        assertThat(policy.sanitizeField(BasicType.OBJECT)).isFalse();
        assertThat(policy.sanitizeArray(BasicType.OBJECT)).isFalse();
    }

    /**
     * A bare type name means both halves: the field AND the array of that type.
     */
    @Test
    void testBareTypeSelectsFieldAndArray() {
        final SanitizationPolicy policy = parse("int");
        assertThat(policy.sanitizeField(BasicType.INT)).isTrue();
        assertThat(policy.sanitizeArray(BasicType.INT)).isTrue();
        assertThat(policy.sanitizeField(BasicType.LONG)).isFalse();
        assertThat(policy.sanitizeArray(BasicType.LONG)).isFalse();
    }

    @Test
    void testTypeFieldSelectsOnlyTheField() {
        final SanitizationPolicy policy = parse("int-field");
        assertThat(policy.sanitizeField(BasicType.INT)).isTrue();
        assertThat(policy.sanitizeArray(BasicType.INT)).isFalse();
    }

    @Test
    void testTypeArraySelectsOnlyTheArray() {
        final SanitizationPolicy policy = parse("int-array");
        assertThat(policy.sanitizeArray(BasicType.INT)).isTrue();
        assertThat(policy.sanitizeField(BasicType.INT)).isFalse();
    }

    @Test
    void testBareFieldSelectsEveryTypesFields() {
        final SanitizationPolicy policy = parse("field");
        for (final BasicType type : SanitizationPolicy.PRIMITIVES) {
            assertThat(policy.sanitizeField(type)).as("field " + type).isTrue();
            assertThat(policy.sanitizeArray(type)).as("array " + type).isFalse();
        }
    }

    @Test
    void testBareArraySelectsEveryTypesArrays() {
        final SanitizationPolicy policy = parse("array");
        for (final BasicType type : SanitizationPolicy.PRIMITIVES) {
            assertThat(policy.sanitizeArray(type)).as("array " + type).isTrue();
            assertThat(policy.sanitizeField(type)).as("field " + type).isFalse();
        }
    }

    /**
     * Every canonical selector has singular and plural spellings, per component. One rule, so
     * bytes-array is admitted too.
     */
    @Test
    void testPluralAndMixedSpellingsAreEquivalent() {
        final String[] equivalentToIntArray = {
                "int-array", "int-arrays", "ints-array", "ints-arrays"
        };
        for (final String spelling : equivalentToIntArray) {
            final SanitizationPolicy policy = parse(spelling);
            assertThat(policy.sanitizeArray(BasicType.INT)).as(spelling).isTrue();
            assertThat(policy.sanitizeField(BasicType.INT)).as(spelling).isFalse();
        }

        final String[] equivalentToIntField = {
                "int-field", "int-fields", "ints-field", "ints-fields"
        };
        for (final String spelling : equivalentToIntField) {
            final SanitizationPolicy policy = parse(spelling);
            assertThat(policy.sanitizeField(BasicType.INT)).as(spelling).isTrue();
            assertThat(policy.sanitizeArray(BasicType.INT)).as(spelling).isFalse();
        }

        assertThat(parse("ints").sanitizeField(BasicType.INT)).isTrue();
        assertThat(parse("ints").sanitizeArray(BasicType.INT)).isTrue();
    }

    @Test
    void testEverySelectorIsWiredForEveryType() {
        for (final BasicType type : SanitizationPolicy.PRIMITIVES) {
            final String name = type.name().toLowerCase();

            final SanitizationPolicy fieldOnly = parse(name + "-field");
            assertThat(fieldOnly.sanitizeField(type)).as(name + "-field").isTrue();
            assertThat(fieldOnly.sanitizeArray(type)).as(name + "-field array").isFalse();

            final SanitizationPolicy arrayOnly = parse(name + "-array");
            assertThat(arrayOnly.sanitizeArray(type)).as(name + "-array").isTrue();
            assertThat(arrayOnly.sanitizeField(type)).as(name + "-array field").isFalse();

            final SanitizationPolicy both = parse(name);
            assertThat(both.sanitizeField(type)).as(name + " field").isTrue();
            assertThat(both.sanitizeArray(type)).as(name + " array").isTrue();
        }
    }

    @Test
    void testCaseInsensitive() {
        final SanitizationPolicy policy = parse("ALL,-Int-Arrays");
        assertThat(policy.sanitizeArray(BasicType.INT)).isFalse();
        assertThat(policy.sanitizeField(BasicType.INT)).isTrue();
    }

    @Test
    void testWhitespaceAroundEntriesIsIgnored() {
        final SanitizationPolicy policy = parse(" all , -int-arrays ");
        assertThat(policy.sanitizeArray(BasicType.INT)).isFalse();
        assertThat(policy.sanitizeField(BasicType.INT)).isTrue();
    }

    @Test
    void testSubtraction() {
        final SanitizationPolicy policy = parse("all,-int,-long");
        assertThat(policy.sanitizeField(BasicType.INT)).isFalse();
        assertThat(policy.sanitizeArray(BasicType.INT)).isFalse();
        assertThat(policy.sanitizeField(BasicType.LONG)).isFalse();
        assertThat(policy.sanitizeArray(BasicType.LONG)).isFalse();
        assertThat(policy.sanitizeField(BasicType.SHORT)).isTrue();
        assertThat(policy.sanitizeArray(BasicType.SHORT)).isTrue();
    }

    @Test
    void testSubtractingOneHalfKeepsTheOther() {
        final SanitizationPolicy policy = parse("all,-char-array");
        assertThat(policy.sanitizeArray(BasicType.CHAR)).isFalse();
        assertThat(policy.sanitizeField(BasicType.CHAR)).isTrue();
    }

    /**
     * The base is none, so an additive list needs no explicit base. This is the pre-1.4.0 scope.
     */
    @Test
    void testImplicitNoneBase() {
        final SanitizationPolicy policy = parse("byte-arrays,char-arrays");
        assertThat(policy.sanitizeArray(BasicType.BYTE)).isTrue();
        assertThat(policy.sanitizeArray(BasicType.CHAR)).isTrue();
        assertThat(policy.sanitizeArray(BasicType.INT)).isFalse();
        assertThat(policy.isAnyFieldSanitized()).isFalse();
    }

    @Test
    void testExplicitNoneBaseIsTheSame() {
        final SanitizationPolicy implicit = parse("byte-arrays,char-arrays");
        final SanitizationPolicy explicit = parse("none,byte-arrays,char-arrays");
        assertThat(explicit.sanitizeArray(BasicType.BYTE))
                .isEqualTo(implicit.sanitizeArray(BasicType.BYTE)).isTrue();
        assertThat(explicit.sanitizeArray(BasicType.INT))
                .isEqualTo(implicit.sanitizeArray(BasicType.INT)).isFalse();
        assertThat(explicit.isAnyFieldSanitized()).isEqualTo(implicit.isAnyFieldSanitized()).isFalse();
    }

    /**
     * all and none are ordinary entries, not special leading syntax, so they mean the same thing in
     * any position. Redundant, not an error.
     */
    @Test
    void testAllAndNoneAreLegalInAnyPosition() {
        assertEverythingSanitized(parse("int,all"));
        assertNothingSanitized(parse("all,none"));
        assertEverythingSanitized(parse("none,all"));
    }

    @Test
    void testEntriesApplyLeftToRight() {
        // subtract then re-add
        final SanitizationPolicy readded = parse("all,-char,char-array");
        assertThat(readded.sanitizeArray(BasicType.CHAR)).isTrue();
        assertThat(readded.sanitizeField(BasicType.CHAR)).isFalse();

        // add then subtract: the reverse order gives the opposite result
        final SanitizationPolicy removed = parse("all,char-array,-char");
        assertThat(removed.sanitizeArray(BasicType.CHAR)).isFalse();
        assertThat(removed.sanitizeField(BasicType.CHAR)).isFalse();
    }

    /**
     * all and none reset the scope rather than contributing members to it, so subtracting one is
     * meaningless: "-all" is a confusing way to write "none", and "-none" would read as "everything
     * except nothing" while the naive implementation clears everything instead. Rejected outright.
     */
    @Test
    void testSubtractingAllOrNoneIsRejected() {
        assertThatThrownBy(() -> parse("all,-all"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("cannot be subtracted");

        assertThatThrownBy(() -> parse("all,-none"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("cannot be subtracted");
    }

    @Test
    void testLeadingSubtractionIsRejected() {
        assertThatThrownBy(() -> parse("-int"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("cannot start")
                .hasMessageContaining("all,-int");
    }

    /**
     * all and none are singular-only, so the trailing-s rule must not turn 'alls' into 'all'.
     */
    @Test
    void testPluralizedAllAndNoneAreRejected() {
        assertThatThrownBy(() -> parse("alls"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("alls");

        assertThatThrownBy(() -> parse("nones"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("nones");
    }

    @Test
    void testUnknownSelectorIsRejected() {
        assertThatThrownBy(() -> parse("bogus"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("bogus");

        assertThatThrownBy(() -> parse("all,-bogus-array"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("bogus");

        assertThatThrownBy(() -> parse("int-bogus"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("int-bogus");
    }

    @Test
    void testObjectSelectorIsRejectedWithItsOwnMessage() {
        assertThatThrownBy(() -> parse("object"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("object")
                .hasMessageContaining("corrupt");

        assertThatThrownBy(() -> parse("object-array"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("object");
    }

    @Test
    void testEmptyValueIsRejected() {
        assertThatThrownBy(() -> parse(""))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("empty");

        assertThatThrownBy(() -> parse("   "))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("empty");
    }

    @Test
    void testEmptyEntryIsRejected() {
        assertThatThrownBy(() -> parse("all,,int"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("empty");

        assertThatThrownBy(() -> parse("all,"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("empty");
    }

    @Test
    void testBareDashIsRejected() {
        assertThatThrownBy(() -> parse("all,-"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("empty");
    }

    /**
     * A malformed list must not partially mutate the builder: parsing completes before the first
     * mutation is applied.
     */
    @Test
    void testInvalidListLeavesBuilderUntouched() {
        final SanitizationPolicy.Builder builder = SanitizationPolicy.builder();
        assertThatThrownBy(() -> TargetSelector.applyTo("all,bogus", builder))
                .isInstanceOf(IllegalArgumentException.class);
        assertNothingSanitized(builder.build());
    }

    @Test
    void testValidateAcceptsAndRejectsWithoutABuilder() {
        TargetSelector.validate("all,-int");
        assertThatThrownBy(() -> TargetSelector.validate("bogus"))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
