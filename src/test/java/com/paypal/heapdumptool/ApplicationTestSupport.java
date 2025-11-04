package com.paypal.heapdumptool;

import com.paypal.heapdumptool.capture.PrivilegeEscalator;
import org.apache.commons.lang3.mutable.MutableInt;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.MockedStatic;
import picocli.CommandLine;
import picocli.CommandLine.ParseResult;

import static com.paypal.heapdumptool.capture.PrivilegeEscalator.Escalation.PRIVILEGED_ALREADY;
import static com.paypal.heapdumptool.fixture.MockitoTool.voidAnswer;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mockStatic;

public class ApplicationTestSupport {

    public static int runApplication(final String... args) throws Exception {
        final ArgumentCaptor<Integer> captor = ArgumentCaptor.forClass(int.class);

        try (final MockedStatic<Application> applicationMock = mockStatic(Application.class)) {

            applicationMock.when(() -> Application.systemExit(anyInt()))
                           .thenAnswer(voidAnswer());

            applicationMock.when(() -> Application.main(args))
                           .thenCallRealMethod();

            applicationMock.when(Application::newCommandLine)
                           .thenCallRealMethod();

            Application.main(args);

            applicationMock.verify(() -> Application.systemExit(captor.capture()));
        }

        return captor.getValue();
    }

    public static int runApplicationPrivileged(final String... args) throws Exception {

        final CommandLine commandLine = Application.newCommandLine();

        try (final MockedStatic<PrivilegeEscalator> escalatorMock = mockStatic(PrivilegeEscalator.class)) {

            escalatorMock.when(() -> PrivilegeEscalator.escalatePrivilegesIfNeeded(eq(commandLine), any()))
                         .thenReturn(PRIVILEGED_ALREADY);

            return runApplication(args);
        }
    }

    private ApplicationTestSupport() {
        throw new AssertionError();
    }
}
