package com.paypal.heapdumptool.fixture;

import java.lang.reflect.Constructor;

import static org.assertj.core.api.Assertions.assertThatCode;

public class ConstructorTester {

    public static void test(final Class<?> clazz) throws Exception {
        final Constructor<?> constructor = clazz.getDeclaredConstructor();
        constructor.setAccessible(true);
        assertThatCode(constructor::newInstance).hasRootCauseInstanceOf(AssertionError.class);
    }

    private ConstructorTester() {
        throw new AssertionError();
    }
}
