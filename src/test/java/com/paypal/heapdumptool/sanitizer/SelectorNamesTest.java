package com.paypal.heapdumptool.sanitizer;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class SelectorNamesTest {

    @Test
    void testNormalizeDropsOneTrailingS() {
        assertThat(SelectorNames.normalize("byte")).isEqualTo("byte");
        assertThat(SelectorNames.normalize("bytes")).isEqualTo("byte");
        assertThat(SelectorNames.normalize("array")).isEqualTo("array");
        assertThat(SelectorNames.normalize("arrays")).isEqualTo("array");
    }

    @Test
    void testNormalizeIsCaseInsensitiveAndTrims() {
        assertThat(SelectorNames.normalize("  Bytes ")).isEqualTo("byte");
        assertThat(SelectorNames.normalize("INT")).isEqualTo("int");
    }

    @Test
    void testNormalizeBlankIsEmpty() {
        assertThat(SelectorNames.normalize("")).isEmpty();
        assertThat(SelectorNames.normalize("   ")).isEmpty();
        assertThat(SelectorNames.normalize(null)).isEmpty();
    }

    /**
     * "s" must not normalize to "", and a name that legitimately ends in s after one strip must
     * not be stripped twice.
     */
    @Test
    void testNormalizeStripsAtMostOneS() {
        assertThat(SelectorNames.normalize("s")).isEqualTo("s");
        assertThat(SelectorNames.normalize("ss")).isEqualTo("s");
    }

    @Test
    void testFindTypeCoversEveryPrimitive() {
        assertThat(SelectorNames.findType("byte")).isEqualTo(BasicType.BYTE);
        assertThat(SelectorNames.findType("short")).isEqualTo(BasicType.SHORT);
        assertThat(SelectorNames.findType("int")).isEqualTo(BasicType.INT);
        assertThat(SelectorNames.findType("long")).isEqualTo(BasicType.LONG);
        assertThat(SelectorNames.findType("char")).isEqualTo(BasicType.CHAR);
        assertThat(SelectorNames.findType("float")).isEqualTo(BasicType.FLOAT);
        assertThat(SelectorNames.findType("double")).isEqualTo(BasicType.DOUBLE);
        assertThat(SelectorNames.findType("boolean")).isEqualTo(BasicType.BOOLEAN);
    }

    @Test
    void testFindTypeRejectsObjectAndUnknown() {
        assertThat(SelectorNames.findType("object")).isNull();
        assertThat(SelectorNames.findType("bogus")).isNull();
        assertThat(SelectorNames.findType("")).isNull();
    }

    @Test
    void testIsObject() {
        assertThat(SelectorNames.isObject("object")).isTrue();
        assertThat(SelectorNames.isObject("int")).isFalse();
    }

    /**
     * Every primitive in the canonical set must have a name, or a parser could reject a type the
     * policy supports. Sorted and comma-separated so error messages are stable.
     */
    @Test
    void testTypeNamesListsEveryPrimitiveSorted() {
        assertThat(SelectorNames.typeNames())
                .isEqualTo("boolean, byte, char, double, float, int, long, short");

        for (final BasicType type : SanitizationPolicy.PRIMITIVES) {
            assertThat(SelectorNames.typeNames())
                    .as("name for " + type)
                    .contains(type.name().toLowerCase());
        }
    }
}
