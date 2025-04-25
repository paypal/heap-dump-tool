package com.paypal.heapdumptool;

import com.paypal.heapdumptool.capture.PrivilegeEscalator;
import org.apache.commons.lang3.mutable.MutableInt;
import org.mockito.MockedStatic;

import static com.paypal.heapdumptool.capture.PrivilegeEscalator.Escalation.PRIVILEGED_ALREADY;
import static com.paypal.heapdumptool.fixture.MockitoTool.voidAnswer;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.Mockito.mockStatic;

public class ApplicationTestSupport {

    public static int runApplication(final String... args) throws Exception {
        final MutableInt exitCode = new MutableInt();

        try (final MockedStatic<Application> applicationMock = mockStatic(Application.class)) {

            applicationMock.when(() -> Application.systemExit(anyInt()))
                           .thenAnswer(voidAnswer());

            applicationMock.when(() -> Application.main(args))
                           .thenCallRealMethod();

            applicationMock.when(() -> Application.run(args, Application.VersionProvider.versionResource))
                           .thenCallRealMethod();

            Application.main(args);
        }

        return exitCode.getValue();
    }

    public static int runApplicationPrivileged(final String... args) throws Exception {

        try (final MockedStatic<PrivilegeEscalator> escalatorMock = mockStatic(PrivilegeEscalator.class)) {

            escalatorMock.when(() -> PrivilegeEscalator.escalatePrivilegesIfNeeded(any()))
                         .thenReturn(PRIVILEGED_ALREADY);

            return runApplication(args);
        }
    }

    private ApplicationTestSupport() {
        throw new AssertionError();
    }
}
