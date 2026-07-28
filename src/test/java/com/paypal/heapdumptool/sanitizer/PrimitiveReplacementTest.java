package com.paypal.heapdumptool.sanitizer;

import org.junit.jupiter.api.Test;

import static com.paypal.heapdumptool.sanitizer.PrimitiveReplacement.defaultFor;
import static com.paypal.heapdumptool.sanitizer.PrimitiveReplacement.defaultValueText;
import static com.paypal.heapdumptool.sanitizer.PrimitiveReplacement.encode;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class PrimitiveReplacementTest {

    @Test
    void testDefaults() {
        assertThat(defaultFor(BasicType.BYTE)).containsExactly(42);
        assertThat(defaultFor(BasicType.CHAR)).containsExactly(0x00, 0x2A);
        assertThat(defaultFor(BasicType.SHORT)).containsExactly(0, 0);
        assertThat(defaultFor(BasicType.INT)).containsExactly(0, 0, 0, 0);
        assertThat(defaultFor(BasicType.LONG)).containsExactly(0, 0, 0, 0, 0, 0, 0, 0);
        assertThat(defaultFor(BasicType.FLOAT)).containsExactly(0, 0, 0, 0);
        assertThat(defaultFor(BasicType.DOUBLE)).containsExactly(0, 0, 0, 0, 0, 0, 0, 0);
        assertThat(defaultFor(BasicType.BOOLEAN)).containsExactly(0);
    }

    @Test
    void testDefaultValueText() {
        assertThat(defaultValueText(BasicType.BYTE)).isEqualTo("42");
        assertThat(defaultValueText(BasicType.CHAR)).isEqualTo("'*'");
        assertThat(defaultValueText(BasicType.INT)).isEqualTo("0");
        assertThat(defaultValueText(BasicType.DOUBLE)).isEqualTo("0.0");
        assertThat(defaultValueText(BasicType.BOOLEAN)).isEqualTo("false");
    }

    @Test
    void testEncodeNumbers() {
        assertThat(encode(BasicType.BYTE, "42")).containsExactly(42);
        assertThat(encode(BasicType.BYTE, "-1")).containsExactly(0xFF);
        assertThat(encode(BasicType.SHORT, "0")).containsExactly(0, 0);
        assertThat(encode(BasicType.SHORT, "4660")).containsExactly(0x12, 0x34);
        assertThat(encode(BasicType.INT, "1")).containsExactly(0, 0, 0, 1);
        assertThat(encode(BasicType.LONG, "1")).containsExactly(0, 0, 0, 0, 0, 0, 0, 1);
    }

    @Test
    void testEncodeChars() {
        // quoted character -> code point
        assertThat(encode(BasicType.CHAR, "'*'")).containsExactly(0x00, 0x2A);
        // bare single character -> code point
        assertThat(encode(BasicType.CHAR, "*")).containsExactly(0x00, 0x2A);
        // byte accepts a character too
        assertThat(encode(BasicType.BYTE, "'*'")).containsExactly(42);
    }

    @Test
    void testBareDigitIsNumberQuotedDigitIsChar() {
        assertThat(encode(BasicType.BYTE, "4")).containsExactly(4);
        assertThat(encode(BasicType.BYTE, "'4'")).containsExactly(52);
    }

    @Test
    void testEncodeFloatingPoint() {
        assertThat(encode(BasicType.FLOAT, "0.0")).containsExactly(0, 0, 0, 0);
        assertThat(encode(BasicType.FLOAT, "42.0")).containsExactly(0x42, 0x28, 0x00, 0x00);
        assertThat(encode(BasicType.DOUBLE, "42.0"))
                .containsExactly(0x40, 0x45, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00);
    }

    @Test
    void testEncodeBoolean() {
        assertThat(encode(BasicType.BOOLEAN, "false")).containsExactly(0);
        assertThat(encode(BasicType.BOOLEAN, "true")).containsExactly(1);
        assertThat(encode(BasicType.BOOLEAN, "0")).containsExactly(0);
        assertThat(encode(BasicType.BOOLEAN, "1")).containsExactly(1);
    }

    @Test
    void testOutOfRangeRejected() {
        assertThatThrownBy(() -> encode(BasicType.BYTE, "300"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("out of range for byte");

        assertThatThrownBy(() -> encode(BasicType.SHORT, "70000"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("out of range for short");
    }

    @Test
    void testBooleanAcceptsAnyNumber() {
        // nonzero -> true
        assertThat(encode(BasicType.BOOLEAN, "7")).containsExactly(1);
        assertThat(encode(BasicType.BOOLEAN, "42")).containsExactly(1);
        // zero -> false (already covered by testEncodeBoolean but added here for clarity)
        assertThat(encode(BasicType.BOOLEAN, "0")).containsExactly(0);
    }

    @Test
    void testBooleanRejectsMalformed() {
        assertThatThrownBy(() -> encode(BasicType.BOOLEAN, "bogus"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("boolean");
    }

    @Test
    void testMalformedRejected() {
        assertThatThrownBy(() -> encode(BasicType.INT, "abc"))
                .isInstanceOf(IllegalArgumentException.class);

        assertThatThrownBy(() -> encode(BasicType.INT, ""))
                .isInstanceOf(IllegalArgumentException.class);

        assertThatThrownBy(() -> encode(BasicType.INT, "1.5"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("int");
    }

    @Test
    void testObjectTypeRejected() {
        assertThatThrownBy(() -> encode(BasicType.OBJECT, "0"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("OBJECT");
    }

    @Test
    void testConstructorIsPrivate() throws Exception {
        com.paypal.heapdumptool.fixture.ConstructorTester.test(PrimitiveReplacement.class);
    }
}
