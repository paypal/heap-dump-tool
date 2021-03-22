package com.paypal.heapdumptool.cli;

import com.paypal.heapdumptool.fixture.ConstructorTester;
import org.apache.commons.lang3.reflect.ConstructorUtils;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;

import static com.paypal.heapdumptool.fixture.MockitoTool.genericMock;
import static org.apache.commons.lang3.reflect.ConstructorUtils.invokeConstructor;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.verify;

public class CliBootstrapTest {

    @Test
    public void testRunCommand() throws Exception {

        final CliCommand command = mock(CliCommand.class);
        final CliCommandProcessor processor = genericMock(CliCommandProcessor.class);
        doReturn(processor.getClass())
                .when(command)
                .getProcessorClass();

        try (final MockedStatic<ConstructorUtils> mocked = mockStatic(ConstructorUtils.class)) {
            mocked.when(() -> invokeConstructor(processor.getClass(), command))
                  .thenReturn(processor);

            CliBootstrap.runCommand(command);

            verify(processor).process();
        }
    }

    @Test
    public void testConstructor() throws Exception {
        ConstructorTester.test(CliBootstrap.class);
    }
}
