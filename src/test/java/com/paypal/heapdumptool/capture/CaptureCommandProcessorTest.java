package com.paypal.heapdumptool.capture;

import com.paypal.heapdumptool.fixture.ResourceTool;
import com.paypal.heapdumptool.sanitizer.SanitizeCommandProcessor;
import com.paypal.heapdumptool.utils.ProcessTool;
import com.paypal.heapdumptool.utils.ProcessTool.ProcessResult;
import org.apache.commons.io.input.NullInputStream;
import org.apache.commons.io.output.NullOutputStream;
import org.apache.commons.lang3.ArrayUtils;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Instant;
import java.util.stream.Stream;

import static java.time.temporal.ChronoUnit.SECONDS;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.Answers.CALLS_REAL_METHODS;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.withSettings;

public class CaptureCommandProcessorTest {

    private final Instant now = Instant.parse("2020-09-18T23:33:17.764866Z");
    private final Path outputFile = Paths.get("my-app-2020-09-18T23-33-17.764866Z.hprof.zip");

    private final MockedStatic<ProcessTool> processToolMock = mockStatic(ProcessTool.class);
    private final MockedStatic<Instant> instantMock = mockStatic(Instant.class, withSettings().defaultAnswer(CALLS_REAL_METHODS));
    private final MockedStatic<SanitizeCommandProcessor> sanitizerMock = mockStatic(SanitizeCommandProcessor.class);
    private final MockedStatic<PrivilegeEscalator> privilegeEscalatorMock = mockStatic(PrivilegeEscalator.class);

    @BeforeEach
    @AfterEach
    public void cleanUpTempFile() throws IOException {
        Files.deleteIfExists(outputFile);
    }

    @AfterEach
    public void afterEach() {
        Stream.of(processToolMock, instantMock, sanitizerMock, privilegeEscalatorMock)
              .forEach(MockedStatic::close);
    }

    @Test
    public void testProcessInContainer() throws Exception {
        freezeTime();
        expectIsInDockerContainer(true);
        expectedProcessInvocations(true);
        expectSanitize();

        final CaptureCommand command = new CaptureCommand();
        command.setContainerName("my-app");

        final CaptureCommandProcessor processor = new CaptureCommandProcessor(command);
        processor.process();

        assertThat(outputFile).exists();
        processToolMock.verify(() -> ProcessTool.run("nsenter1", "docker", "ps", "--filter", "name=my-app"));
    }

    @Test
    public void testProcessOnHost() throws Exception {
        expectIsInDockerContainer(false);

        processToolMock.when(() -> ProcessTool.run("docker", "ps", "--filter", "name=my-app"))
                       .thenReturn(resultWith("docker-ps-none.txt"));

        final CaptureCommand command = new CaptureCommand();
        command.setContainerName("my-app");

        final CaptureCommandProcessor processor = new CaptureCommandProcessor(command);
        assertThatIllegalArgumentException()
                .isThrownBy(processor::process)
                .withMessageContaining("Cannot find container");

        processToolMock.verify(() -> ProcessTool.run("docker", "ps", "--filter", "name=my-app"));
    }

    private void expectIsInDockerContainer(final boolean value) {
        privilegeEscalatorMock.when(PrivilegeEscalator::isInDockerContainer)
                              .thenReturn(value);
    }

    private void expectSanitize() throws Exception {
        final SanitizeCommandProcessor processor = mock(SanitizeCommandProcessor.class);

        doNothing().when(processor).process();

        sanitizerMock.when(() -> SanitizeCommandProcessor.newInstance(any(), any()))
                     .thenAnswer(invocation -> {
                         final CaptureStreamFactory streamFactory = invocation.getArgument(1, CaptureStreamFactory.class);
                         streamFactory.newOutputStream(); // create now
                         return processor;
                     });
    }

    private void freezeTime() {
        instantMock.when(Instant::now)
                   .thenReturn(now);

        instantMock.when(() -> now.truncatedTo(SECONDS))
                   .thenReturn(now);
    }

    private void expectedProcessInvocations(final boolean inContainer) throws IOException {
        final CmdFunction cmd = args -> inContainer ? prefixWithNsenter1(args) : args;

        processToolMock.when(() -> ProcessTool.run(cmd.maybeWithNsenter1("docker", "ps", "--filter", "name=my-app")))
                       .thenReturn(resultWith("docker-ps.txt"));

        processToolMock.when(() -> ProcessTool.run(cmd.maybeWithNsenter1("docker", "exec", "my-app", "jps")))
                       .thenReturn(resultWith("docker-exec-jps.txt"));

        processToolMock.when(() -> ProcessTool.run(cmd.maybeWithNsenter1("docker", "exec", "my-app", "jcmd", "55", "Thread.print", "-l")))
                       .thenReturn(resultWith("docker-exec-jcmd-gc-heap-dump.txt"));

        final String tmpFile = "/tmp/my-app-2020-09-18T23-33-17.764866Z.hprof";
        processToolMock.when(() -> ProcessTool.run(cmd.maybeWithNsenter1("docker", "exec", "my-app", "jcmd", "55", "GC.heap_dump", tmpFile)))
                       .thenReturn(resultWith("docker-exec-jcmd-gc-heap-dump.txt"));

        final ProcessBuilder processBuilder = dockerCpProcess();
        processToolMock.when(() -> ProcessTool.processBuilder(cmd.maybeWithNsenter1("docker", "cp", "my-app:" + tmpFile, "-")))
                       .thenReturn(processBuilder);
    }

    @FunctionalInterface
    private static interface CmdFunction {
        String[] maybeWithNsenter1(String... args);
    }

    private String[] prefixWithNsenter1(final String[] args) {
        return ArrayUtils.addFirst(args, "nsenter1");
    }

    private ProcessBuilder dockerCpProcess() throws IOException {
        final ProcessBuilder processBuilder = mock(ProcessBuilder.class);
        final Process process = mock(Process.class);

        final InputStream nullInputStream = new NullInputStream();

        doReturn(process).when(processBuilder).start();
        doReturn(nullInputStream).when(process).getInputStream();
        doReturn(nullInputStream).when(process).getErrorStream();
        doReturn(NullOutputStream.INSTANCE).when(process).getOutputStream();

        return processBuilder;
    }

    private ProcessResult resultWith(final String stdoutResource) throws IOException {
        return new ProcessResult(0, resourceContent(stdoutResource), "");
    }

    private String resourceContent(final String name) throws IOException {
        return ResourceTool.contentOf(getClass(), name);
    }
}
