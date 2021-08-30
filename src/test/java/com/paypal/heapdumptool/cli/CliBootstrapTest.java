package com.paypal.heapdumptool.cli;

import com.paypal.heapdumptool.fixture.ConstructorTester;
import org.apache.commons.lang3.reflect.ConstructorUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;

import java.lang.reflect.InvocationTargetException;

import static com.paypal.heapdumptool.fixture.MockitoTool.genericMock;
import static org.apache.commons.lang3.reflect.ConstructorUtils.invokeConstructor;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowable;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

public class CliBootstrapTest {

    private final CliCommand command = mock(CliCommand.class);

    private final CliCommandProcessor processor = genericMock(CliCommandProcessor.class);

    @BeforeEach
    public void beforeEach() {
        doReturn(processor.getClass())
                .when(command)
                .getProcessorClass();
    }

    @Test
    public void testRunCommand() throws Exception {
        try (final MockedStatic<ConstructorUtils> mocked = mockStatic(ConstructorUtils.class)) {
            mocked.when(() -> invokeConstructor(processor.getClass(), command))
                    .thenReturn(processor);

            CliBootstrap.runCommand(command);

            verify(processor).process();
        }
    }

    @Test
    public void testRunCommandInvocationTargetException() throws Exception {
        try (final MockedStatic<ConstructorUtils> mocked = mockStatic(ConstructorUtils.class)) {
            mocked.when(() -> invokeConstructor(processor.getClass(), command))
                    .thenThrow(new InvocationTargetException(new IllegalStateException()));

            verifyExceptionThrown();
        }
    }

    @Test
    public void testRunCommandException() throws Exception {
        try (final MockedStatic<ConstructorUtils> mocked = mockStatic(ConstructorUtils.class)) {
            mocked.when(() -> invokeConstructor(processor.getClass(), command))
                    .thenThrow(new IllegalStateException());

            final Throwable throwable = catchThrowable(() -> CliBootstrap.runCommand(command));
            assertThat(throwable).isInstanceOf(IllegalStateException.class);

            verify(processor, never()).process();
        }
    }

    private void verifyExceptionThrown() throws Exception {
        final Throwable throwable = catchThrowable(() -> CliBootstrap.runCommand(command));
        assertThat(throwable).isInstanceOf(IllegalStateException.class);

        verify(processor, never()).process();
    }


    @Test
    public void testConstructor() throws Exception {
        ConstructorTester.test(CliBootstrap.class);
    }
}
