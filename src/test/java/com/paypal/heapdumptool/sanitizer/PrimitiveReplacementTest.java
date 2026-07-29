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
        assertThat(defaultValueText(BasicType.CHAR)).isEqualTo("*");
        assertThat(defaultValueText(BasicType.SHORT)).isEqualTo("0");
        assertThat(defaultValueText(BasicType.INT)).isEqualTo("0");
        assertThat(defaultValueText(BasicType.LONG)).isEqualTo("0");
        assertThat(defaultValueText(BasicType.FLOAT)).isEqualTo("0.0");
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
        // bare single character -> code point, for char only
        assertThat(encode(BasicType.CHAR, "*")).containsExactly(0x00, 0x2A);
        assertThat(encode(BasicType.CHAR, "a")).containsExactly(0x00, 0x61);
        assertThat(encode(BasicType.CHAR, "b")).containsExactly(0x00, 0x62);
    }

    @Test
    void testNonCharTypesRejectCharacterLiterals() {
        // a character literal is a char-only form; the numeric types take a number only
        assertThatThrownBy(() -> encode(BasicType.BYTE, "*"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("byte");
        assertThatThrownBy(() -> encode(BasicType.SHORT, "a"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("short");
        assertThatThrownBy(() -> encode(BasicType.INT, "\\98"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("int");
        assertThatThrownBy(() -> encode(BasicType.LONG, "\\0"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("long");
        assertThatThrownBy(() -> encode(BasicType.FLOAT, "*"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("float");
        assertThatThrownBy(() -> encode(BasicType.DOUBLE, "\\98"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("double");
        assertThatThrownBy(() -> encode(BasicType.BOOLEAN, "*"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("boolean");
    }

    @Test
    void testEncodeEscapedChars() {
        // \0 is NUL, not the number 0 -- and for char the two agree, so a discriminating escape too
        assertThat(encode(BasicType.CHAR, "\\0")).containsExactly(0x00, 0x00);
        // a backslash followed by digits is a DECIMAL code point: \98 is 'b', not octal 8
        assertThat(encode(BasicType.CHAR, "\\98")).containsExactly(0x00, 0x62);
        assertThat(encode(BasicType.CHAR, "\\42")).containsExactly(0x00, 0x2A);
        // Java's named escapes still work
        assertThat(encode(BasicType.CHAR, "\\t")).containsExactly(0x00, 0x09);
        assertThat(encode(BasicType.CHAR, "\\n")).containsExactly(0x00, 0x0A);
        assertThat(encode(BasicType.CHAR, "\\\\")).containsExactly(0x00, 0x5C);
        // and the unicode form
        assertThat(encode(BasicType.CHAR, "\\u002A")).containsExactly(0x00, 0x2A);
    }

    @Test
    void testCharAcceptsBareNumber() {
        // char takes a plain number as a code point, as well as a character literal
        assertThat(encode(BasicType.CHAR, "98")).containsExactly(0x00, 0x62);
        assertThat(encode(BasicType.CHAR, "0")).containsExactly(0x00, 0x00);
        // out of the char range is rejected
        assertThatThrownBy(() -> encode(BasicType.CHAR, "70000"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("out of range for char");
    }

    @Test
    void testBareDigitIsNumber() {
        assertThat(encode(BasicType.BYTE, "4")).containsExactly(4);
        assertThat(encode(BasicType.CHAR, "4")).containsExactly(0x00, 0x04);
        // to mean the character '4' rather than code point 4, escape its code point (char only)
        assertThat(encode(BasicType.CHAR, "\\52")).containsExactly(0x00, 0x34);
    }

    @Test
    void testQuotedFormRejected() {
        // the old grammar accepted '*' as a synonym for *; a 3-character string is now an error
        assertThatThrownBy(() -> encode(BasicType.CHAR, "'*'"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("char");

        assertThatThrownBy(() -> encode(BasicType.BYTE, "'*'"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("byte");

        assertThatThrownBy(() -> encode(BasicType.BOOLEAN, "'*'"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("boolean");
    }

    @Test
    void testMultiCharacterRejected() {
        assertThatThrownBy(() -> encode(BasicType.CHAR, "ab"))
                .isInstanceOf(IllegalArgumentException.class);

        assertThatThrownBy(() -> encode(BasicType.CHAR, "abc"))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void testMalformedEscapeRejected() {
        // a lone backslash denotes no character
        assertThatThrownBy(() -> encode(BasicType.CHAR, "\\"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Invalid escape sequence");

        // an escape that unescapes to more than one character
        assertThatThrownBy(() -> encode(BasicType.CHAR, "\\-1"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Invalid escape sequence");

        // beyond the char range
        assertThatThrownBy(() -> encode(BasicType.CHAR, "\\65536"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Character code out of range");

        assertThatThrownBy(() -> encode(BasicType.CHAR, "\\99999999999999999999"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Character code out of range");
    }

    @Test
    void testEscapeRejectedForNonCharType() {
        // escapes are a char-only form now; byte takes a number only
        assertThatThrownBy(() -> encode(BasicType.BYTE, "\\200"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("byte");
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
