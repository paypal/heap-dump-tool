package com.paypal.heapdumptool.sanitizer;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

public class BasicTypeTest {

    @ParameterizedTest
    @EnumSource(BasicType.class)
    public void testFindValueSize(final BasicType basicType) {
        assertThat(BasicType.findValueSize(basicType.getU1Code(), 8))
                .isGreaterThan(0);
    }

    @Test
    public void testUnknownU1Tag() {
        assertThatIllegalArgumentException()
                .isThrownBy(() -> BasicType.findValueSize(0, 0))
                .withMessage("Unknown basic type code: 0");
    }
}
