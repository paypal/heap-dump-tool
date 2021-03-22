package com.paypal.heapdumptool.cli;

import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doCallRealMethod;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;

public class CliCommandTest {

    @Test
    public void testCall() throws Exception {
        final CliCommand command = mock(CliCommand.class);
        doCallRealMethod()
                .when(command)
                .call();

        try (final MockedStatic<CliBootstrap> mocked = mockStatic(CliBootstrap.class)) {
            command.call();

            mocked.verify(() -> CliBootstrap.runCommand(any()));
        }

    }
}
