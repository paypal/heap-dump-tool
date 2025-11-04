package com.paypal.heapdumptool.capture;

import com.google.common.io.Closer;
import com.paypal.heapdumptool.Application;
import com.paypal.heapdumptool.capture.PrivilegeEscalator.Escalation;
import com.paypal.heapdumptool.fixture.ConstructorTester;
import com.paypal.heapdumptool.fixture.ResourceTool;
import com.paypal.heapdumptool.sanitizer.DataSize;
import org.apache.commons.lang3.RuntimeEnvironment;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.MockedStatic;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import picocli.CommandLine;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import static com.paypal.heapdumptool.capture.PrivilegeEscalator.escalatePrivilegesIfNeeded;
import static com.paypal.heapdumptool.capture.PrivilegeEscalator.Escalation.REQUIRED_AND_PROMPTED;
import static com.paypal.heapdumptool.capture.PrivilegeEscalator.Escalation.PRIVILEGED_ALREADY;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.mockito.Mockito.mockStatic;

@ExtendWith(OutputCaptureExtension.class)
public class PrivilegeEscalatorTest {

    @TempDir
    Path tempDir;

    private final Closer closer = Closer.create();

    @BeforeEach
    @AfterEach
    public void tearDown() throws IOException {
        closer.close();
    }

    @Test
    public void testNotInDockerContainer() throws Exception {
        expectInDockerContainer(false);

        assertThat(escalate("capture", "b a r"))
                .isEqualTo(PRIVILEGED_ALREADY);
    }

    @Test
    public void testInDockerContainerPrivilegedAlready() throws Exception {
        expectInDockerContainer(true);

        final Path cgroupPath = Paths.get(copyCgroup("docker-cgroup.txt"));
        final Path replacementPath = Paths.get("/bin/echo");
        final MockedStatic<Paths> mocked = createStaticMock(Paths.class);
        expectCgroup(mocked, cgroupPath);
        expectNsenter1(mocked, replacementPath);

        assertThat(escalate("capture", "b a r"))
                .isEqualTo(PRIVILEGED_ALREADY);
    }

    @Test
    public void testInDockerContainerNotPrivilegedAlready(final CapturedOutput output) throws Exception {
        expectInDockerContainer(true);

        final Path cgroupPath = Paths.get(copyCgroup("docker-cgroup.txt"));
        final MockedStatic<Paths> mocked = createStaticMock(Paths.class);
        expectCgroup(mocked, cgroupPath);

        assertThat(escalate("capture", "b a r"))
                .isEqualTo(REQUIRED_AND_PROMPTED);

        assertThat(output).contains("If you see this comment while running the tool");
    }

    @Test
    public void testCustomDockerRegistryOneArg(final CapturedOutput output) throws Exception {
        expectInDockerContainer(true);

        final Path cgroupPath = Paths.get(copyCgroup("docker-cgroup.txt"));
        final MockedStatic<Paths> mocked = createStaticMock(Paths.class);
        expectCgroup(mocked, cgroupPath);

        assertThat(escalate("--docker-registry=my-custom-registry.example.com"))
                .isEqualTo(REQUIRED_AND_PROMPTED);
        assertThat(output.getOut())
                .contains("FQ_IMAGE=\"${FORCED_DOCKER_REGISTRY:-my-custom-registry.example.com}/heapdumptool/heapdumptool\"\n");
    }

    @Test
    public void testCustomDockerRegistryTwoArg(final CapturedOutput output) throws Exception {
        expectInDockerContainer(true);

        final Path cgroupPath = Paths.get(copyCgroup("docker-cgroup.txt"));
        final MockedStatic<Paths> mocked = createStaticMock(Paths.class);
        expectCgroup(mocked, cgroupPath);

        assertThat(escalate("--docker-registry", "my-custom-registry.example.com", "capture", "b a r"))
                .isEqualTo(REQUIRED_AND_PROMPTED);
        assertThat(output.getOut())
                .contains("FQ_IMAGE=\"${FORCED_DOCKER_REGISTRY:-my-custom-registry.example.com}/heapdumptool/heapdumptool\"\n");
    }

    @Test
    public void testCustomDockerRegistryInvalidArg() throws Exception {
        final boolean value = true;
        expectInDockerContainer(value);

        final Path cgroupPath = Paths.get(copyCgroup("docker-cgroup.txt"));
        final MockedStatic<Paths> mocked = createStaticMock(Paths.class);
        expectCgroup(mocked, cgroupPath);

        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> escalate("--docker-registry"))
                .withMessage("Cannot find argument value for --docker-registry");
    }

    @Test
    public void testConstructor() throws Exception {
        ConstructorTester.test(PrivilegeEscalator.class);
    }

    private static Escalation escalate(final String... args) throws Exception {
        final CommandLine commandLine = newCommandLine();
        return escalatePrivilegesIfNeeded(commandLine, args);
    }

    static CommandLine newCommandLine() {
        final CommandLine commandLine = new CommandLine(new Application());
        commandLine.setUsageHelpWidth(120);
        commandLine.registerConverter(DataSize.class, DataSize::parse);
        commandLine.setAbbreviatedOptionsAllowed(true);
        return commandLine;
    }

    private void expectInDockerContainer(final boolean value) {
        final MockedStatic<RuntimeEnvironment> env = createStaticMock(RuntimeEnvironment.class);
        env.when(RuntimeEnvironment::inContainer).thenReturn(value);
    }

    private <T> MockedStatic<T> createStaticMock(final Class<T> clazz) {
        final MockedStatic<T> mocked = mockStatic(clazz);
        closer.register(mocked::close);
        return mocked;
    }

    private void expectNsenter1(final MockedStatic<Paths> mocked, final Path replacement) {
        mocked.when(() -> Paths.get("nsenter1"))
              .thenReturn(replacement);
    }

    private void expectCgroup(final MockedStatic<Paths> mocked, final Path replacement) {
        mocked.when(() -> Paths.get("/proc/1/cgroup"))
              .thenReturn(replacement);
    }

    private String copyCgroup(final String name) throws IOException {
        final Path file = copyResourceToFile(name);
        return file.toAbsolutePath().toString();
    }

    private Path copyResourceToFile(final String name) throws IOException {
        final String content = resourceContent(name);

        final Path file = tempDir.resolve(name);
        Files.write(file, content.getBytes(UTF_8));
        return file;
    }

    private String resourceContent(final String name) throws IOException {
        return ResourceTool.contentOf(getClass(), name);
    }
}
