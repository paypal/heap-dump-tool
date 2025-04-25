package com.paypal.heapdumptool;

import com.paypal.heapdumptool.Application.VersionProvider;
import com.paypal.heapdumptool.capture.PrivilegeEscalator;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.MockedStatic;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;

import static com.paypal.heapdumptool.ApplicationTestSupport.runApplication;
import static com.paypal.heapdumptool.ApplicationTestSupport.runApplicationPrivileged;
import static com.paypal.heapdumptool.capture.PrivilegeEscalator.escalatePrivilegesIfNeeded;
import static com.paypal.heapdumptool.capture.PrivilegeEscalator.Escalation.ESCALATED;
import static com.paypal.heapdumptool.fixture.ResourceTool.contentOf;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mockStatic;

@ExtendWith(OutputCaptureExtension.class)
public class ApplicationTest {

    @Test
    public void testVersionProvider() throws Exception {
        final String[] version = new VersionProvider().getVersion();
        assertThat(version[0]).contains("heap-dump-tool");
    }

    @Test
    public void testMainHelp(final CapturedOutput output) throws Exception {
        final int exitCode = runApplicationPrivileged("help");
        assertThat(exitCode).isEqualTo(0);

        final String expectedOutput = contentOf(getClass(), "help.txt");
        assertThat(output.getOut()).isEqualTo(expectedOutput);
    }

    @Test
    public void testPrivilegeEscalated(final CapturedOutput output) throws Exception {
        try (final MockedStatic<PrivilegeEscalator> mocked = mockStatic(PrivilegeEscalator.class)) {
            mocked.when(() -> escalatePrivilegesIfNeeded("help"))
                  .thenReturn(ESCALATED);

            final int exitCode = runApplication("help");
            assertThat(exitCode).isEqualTo(0);

            assertThat(output.getOut()).isEmpty();
        }
    }
}
