package com.paypal.heapdumptool;

import com.paypal.heapdumptool.capture.PrivilegeEscalator;
import org.apache.commons.lang3.ArrayUtils;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.mockito.MockedConstruction;
import org.mockito.MockedConstruction.Context;
import org.mockito.MockedStatic;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import picocli.CommandLine;

import java.util.Objects;

import static com.paypal.heapdumptool.ApplicationTestSupport.runApplication;
import static com.paypal.heapdumptool.ApplicationTestSupport.runApplicationPrivileged;
import static com.paypal.heapdumptool.capture.PrivilegeEscalator.Escalation.REQUIRED_AND_PROMPTED;
import static com.paypal.heapdumptool.capture.PrivilegeEscalator.escalatePrivilegesIfNeeded;
import static com.paypal.heapdumptool.fixture.ResourceTool.contentOf;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mockConstruction;
import static org.mockito.Mockito.mockStatic;

@ExtendWith(OutputCaptureExtension.class)
public class ApplicationTest {

    @Test
    public void testVersionProvider() throws Exception {
        final String[] version = new Application().getVersion();
        assertThat(version[0]).contains("heap-dump-tool");
    }

    @Test
    public void testMainHelp(final CapturedOutput output) throws Exception {
        final int exitCode = runApplicationPrivileged("help");
        assertThat(exitCode).isEqualTo(0);

        final String expectedOutput = contentOf(getClass(), "help.txt");
        assertThat(output.getOut()).isEqualTo(expectedOutput);
    }

    @ParameterizedTest
    @CsvSource(delimiter = '|', value = {
            "--bogus-option                   | Unknown option: '--bogus-option'",
            "-b nonsense                      | Invalid value for option '--buffer-size'",
            "--sanitize-byte-replacement=300  | is out of range for byte",
            "--s-a                            | '--s-a' is not unique",
    })
    public void testUsageErrorPrintsUsageMessage(final String badArg,
                                                 final String expectedMessage,
                                                 final CapturedOutput output) throws Exception {
        final String[] args = ArrayUtils.addAll(new String[]{"sanitize"},
                                                ArrayUtils.addAll(badArg.trim().split(" "), "in.hprof", "out.hprof"));

        final int exitCode = runApplication(args);

        assertThat(exitCode).isEqualTo(CommandLine.ExitCode.USAGE);
        assertThat(output.getErr())
                .contains(expectedMessage)
                .contains("Usage: heap-dump-tool sanitize [OPTIONS] <inputFile> <outputFile>")
                .doesNotContain("\tat com.paypal.heapdumptool"); // no stack trace
    }

    @Test
    public void testPrivilegeEscalated(final CapturedOutput output) throws Exception {
        final CommandLine commandLine = Application.newCommandLine();
        try (final MockedStatic<PrivilegeEscalator> mocked = mockStatic(PrivilegeEscalator.class)) {
            mocked.when(() -> escalatePrivilegesIfNeeded(eq(commandLine), eq("capture")))
                  .thenReturn(REQUIRED_AND_PROMPTED);

            try (final MockedConstruction<CommandLine> mockedCmd = mockConstruction(CommandLine.class, this::prepare)) {
                Objects.requireNonNull(mockedCmd);
                final int exitCode = runApplication("capture", "my-container");
                assertThat(exitCode).isEqualTo(0);
            }

            assertThat(output.getOut()).isEmpty();
        }
    }

    private void prepare(final CommandLine mock, final Context context) {
        doReturn(0).when(mock).execute(any());
    }
}
