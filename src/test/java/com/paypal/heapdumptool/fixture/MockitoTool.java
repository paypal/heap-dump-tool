package com.paypal.heapdumptool.fixture;

import org.mockito.MockedConstruction;
import org.mockito.stubbing.Answer;

import java.util.concurrent.Callable;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

public class MockitoTool {

    /**
     * For more conveniently mocking generic parametrized types without eliciting compiler warnings
     */
    @SuppressWarnings("unchecked")
    public static <T> T genericMock(final Class<?> clazz) {
        return (T) mock(clazz);
    }

    public static <T> Answer<T> voidAnswer() {
        return voidAnswer(() -> null);
    }

    public static <T> Answer<T> voidAnswer(final Callable<?> callable) {
        return invocation -> {
            callable.call();
            return null;
        };
    }

    public static <T> T firstInstance(final MockedConstruction<T> mocked) {
        assertThat(mocked.constructed()).hasSizeGreaterThan(1);
        return mocked.constructed().get(1);
    }

    private MockitoTool() {
        throw new AssertionError();
    }
}
