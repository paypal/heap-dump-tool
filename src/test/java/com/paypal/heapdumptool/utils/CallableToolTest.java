package com.paypal.heapdumptool.utils;

import com.paypal.heapdumptool.fixture.ConstructorTester;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

import static com.paypal.heapdumptool.utils.CallableTool.callQuietlyWithDefault;
import static java.util.Objects.requireNonNull;
import static org.assertj.core.api.Assertions.assertThat;

public class CallableToolTest {

    @TestFactory
    public DynamicTest[] callQuietlyWithDefaultTests() {
        return new DynamicTest[] {

                DynamicTest.dynamicTest("Happy Path", () -> {

                    final int result = callQuietlyWithDefault(5, () -> 1);
                    assertThat(result).isEqualTo(1);
                }),

                DynamicTest.dynamicTest("Unhappy Path", () -> {

                    final int result = callQuietlyWithDefault(5, () -> requireNonNull(null));
                    assertThat(result).isEqualTo(5);
                }),
        };
    }

    @Test
    public void testConstructor() throws Exception {
        ConstructorTester.test(CallableTool.class);
    }
}
