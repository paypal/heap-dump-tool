package com.paypal.heapdumptool.capture;

import com.paypal.heapdumptool.cli.CliCommandProcessor;
import com.paypal.heapdumptool.sanitizer.SanitizeCommand;
import com.paypal.heapdumptool.sanitizer.SanitizeCommandProcessor;
import com.paypal.heapdumptool.utils.InternalLogger;
import com.paypal.heapdumptool.utils.ProcessTool;
import com.paypal.heapdumptool.utils.ProcessTool.ProcessResult;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.Validate;
import org.apache.commons.lang3.function.Failable;
import org.apache.commons.text.StringSubstitutor;

import java.io.Closeable;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.PosixFilePermission;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import static com.paypal.heapdumptool.utils.DateTimeTool.getFriendlyDuration;
import static com.paypal.heapdumptool.utils.ProcessTool.processBuilder;
import static java.nio.charset.StandardCharsets.UTF_8;
import static java.time.Instant.now;
import static org.apache.commons.lang3.StringUtils.substringAfterLast;
import static org.apache.commons.lang3.StringUtils.substringBefore;

public class CaptureCommandProcessor implements CliCommandProcessor {

    private static final String DOCKER = "docker";

    private static final InternalLogger LOGGER = InternalLogger.getLogger(CaptureCommandProcessor.class);

    private final CaptureCommand command;

    private final boolean isInContainer;

    public CaptureCommandProcessor(final CaptureCommand command) {
        this.command = command;
        this.isInContainer = PrivilegeEscalator.isInDockerContainer();
    }

    @Override
    public void process() throws Exception {
        final Instant now = now();
        LOGGER.info("Capturing sanitized heap dump. container={}", command.getContainerName());

        validateContainerRunning();

        final long pid = findPidInAppContainer();

        final Path heapDumpFileInAppContainer = createPlainHeapDumpInAppContainer(pid);
        final String threadDump = captureThreadDump(pid);
        final Path heapDumpFileOnHost = FileUtils.getTempDirectory()
                .toPath()
                .resolve(heapDumpFileInAppContainer.getFileName().toString());
        final Path output;
        try {
            copyFileOutOfAppContainer(heapDumpFileInAppContainer, heapDumpFileOnHost);
            output = sanitizeHeapDump(heapDumpFileOnHost, threadDump);
        } finally {
            Files.deleteIfExists(heapDumpFileOnHost);
            deletePlainHeapDumpInAppContainer(heapDumpFileOnHost);
        }

        LOGGER.info("Captured sanitized heap dump in {}. Output: {}", getFriendlyDuration(now), output);
    }

    private String captureThreadDump(final long pid) throws Exception {
        // jcmd PID Thread.print
        final List<Object> cmd = new ArrayList<>(command.getThreadCmd());
        addIfNotEmpty(command.getThreadOptions(), cmd);
        final Object[] cmdArray = cmd.stream()
                .map(arg -> "PID".equals(arg) ? pid : arg)
                .toArray();
        final ProcessResult result = execInAppContainer(cmdArray);
        return result.stdout;
    }

    private Path sanitizeHeapDump(final Path inputFile, final String threadDump) throws Exception {
        final String destFile = inputFile.getFileName().toAbsolutePath() // re-eval filename in current cwd
                + ".zip";
        final Path destFilePath = Paths.get(destFile);

        final SanitizeCommand sanitizeCommand = new SanitizeCommand();
        sanitizeCommand.copyFrom(this.command);
        sanitizeCommand.setInputFile(inputFile);
        sanitizeCommand.setOutputFile(destFilePath);
        sanitizeCommand.setZipOutput(true);

        try (final CaptureStreamFactory captureStreamFactory = new CaptureStreamFactory(sanitizeCommand)) {
            final SanitizeCommandProcessor processor = SanitizeCommandProcessor.newInstance(sanitizeCommand, captureStreamFactory);
            processor.process();

            writeThreadDump(threadDump, inputFile, captureStreamFactory);
        }

        updateFilePermissions(destFilePath);
        return destFilePath;
    }

    private void writeThreadDump(final String threadDump, final Path filePath, final CaptureStreamFactory captureStreamFactory) throws Exception {
        final ZipOutputStream zipStream = (ZipOutputStream) captureStreamFactory.getNativeOutputStream();

        final String fileName = filePath.getFileName()
                .toString()
                .replace(".hprof", ".threads.txt");
        Validate.validState(fileName.endsWith(".threads.txt"));

        zipStream.putNextEntry(new ZipEntry(fileName));
        IOUtils.write(threadDump, zipStream, UTF_8);
    }

    private void updateFilePermissions(final Path destFilePath) throws Exception {
        Files.setPosixFilePermissions(destFilePath, globalReadWritePermissions());

        final String hostUser = System.getProperty("hdt.HOST_USER", System.getenv("HOST_USER"));
        if (hostUser != null) {
            invokePrivilegedProcess("chown", hostUser + ":" + hostUser, destFilePath.toString());
        }
    }

    private Set<PosixFilePermission> globalReadWritePermissions() {
        return Stream.of(PosixFilePermission.values())
                .filter(permission -> !permission.name().contains("EXECUTE"))
                .collect(Collectors.toSet());
    }

    private void copyFileOutOfAppContainer(
            final Path heapDumpFileInContainer,
            final Path heapDumpFileOnHost) throws IOException, InterruptedException {
        final String src = command.getContainerName() + ":" + heapDumpFileInContainer;
        final String[] args = array(DOCKER, "cp", src, heapDumpFileOnHost.toString());
        logProcessArgs(args);

        final String[] cmd = nsenterIfNeeded(args);
        final Process process = processBuilder(cmd).start();
        closeQuietly(process.getOutputStream());
        closeQuietly(process.getErrorStream());
        final int exitCode = process.waitFor();
        Validate.isTrue(exitCode == 0, "exitCode=" + exitCode);
    }

    private void deletePlainHeapDumpInAppContainer(final Path filePath) throws Exception {
        execInAppContainer("rm", filePath);
    }

    private long findPidInAppContainer() {
        if (command.getPid() != null) {
            return command.getPid();
        }

        final ProcessResult result = Failable.call(() -> execInAppContainer("jps"));
        final Stream<String> javaProcesses = result.stdoutLines()
                .stream()
                .map(String::trim)
                .filter(StringUtils::isNotEmpty)
                .filter(line -> !substringAfterLast(line, " ").equals("Jps"));

        final long[] pids = javaProcesses.map(line -> substringBefore(line, " "))
                .mapToLong(Long::parseLong)
                .toArray();

        Validate.validState(pids.length == 1, "Cannot find unique Java process. Passing in --pid=PID." +
                " container=%s found=%s", command.getContainerName(), Arrays.toString(pids));
        return pids[0];
    }

    private Path createPlainHeapDumpInAppContainer(final long pid) throws Exception {
        final Path filePath = newHeapDumpFilePath();

        // jcmd PID GC.heap_dump FILE_PATH
        final List<Object> cmd = new ArrayList<>(command.getHeapCmd());
        addIfNotEmpty(command.getHeapOptions(), cmd);
        final Object[] cmdArray = cmd.stream()
                .map(arg -> "PID".equals(arg) ? pid : arg)
                .map(arg -> "FILE_PATH".equals(arg) ? filePath : arg)
                .toArray();
        final ProcessResult result = execInAppContainer(cmdArray);
        Validate.validState(result.stdout.contains("Heap dump file created"),
                "Cannot create heap dump. container=%s pid=%s"
                        + "\nstdout=%s"
                        + "\nstderr=%s",
                command.getContainerName(),
                pid,
                result.stdout,
                result.stderr);

        return filePath;
    }

    private static void addIfNotEmpty(final List<String> src, final List<Object> dest) {
        src.stream()
                .filter(StringUtils::isNotEmpty)
                .forEach(dest::add);
    }

    private Path newHeapDumpFilePath() {
        final Map<String, String> props = new HashMap<>();
        props.put("containerName", command.getContainerName());
        props.put("timestamp", Instant.now().toString().replace(":", "-"));

        final String fileName = StringSubstitutor.replace("${containerName}-${timestamp}.hprof", props);
        return Paths.get("/tmp/", fileName);
    }

    private void validateContainerRunning() throws Exception {
        final ProcessResult result = invokePrivilegedProcess(DOCKER, "ps", "--filter", "name=" + command.getContainerName());
        result.stdoutLines()
                .stream()
                .skip(1)
                .map(String::trim)
                .filter(StringUtils::isNotEmpty)
                .filter(line -> {
                    final String actualContainerName = substringAfterLast(line, " ");
                    return actualContainerName.equals(command.getContainerName());
                })
                .findFirst()
                .orElseThrow(() -> new IllegalArgumentException("Cannot find container. name=" + command.getContainerName()));
    }

    private ProcessResult execInAppContainer(final Object... args) throws Exception {
        final String[] stringArgs = Stream.of(args)
                .map(String::valueOf)
                .toArray(String[]::new);

        final String[] cmd = concat(array(DOCKER, "exec", command.getContainerName()),
                stringArgs);
        return invokePrivilegedProcess(cmd);
    }

    private String[] nsenterIfNeeded(final String... args) {
        if (!isInContainer) {
            return args;
        }
        return concat("nsenter1", args);
    }

    private ProcessResult invokePrivilegedProcess(final String... args) throws Exception {
        logProcessArgs(args);
        final String[] cmd = nsenterIfNeeded(args);
        return ProcessTool.run(cmd);
    }

    private void logProcessArgs(final String... cmd) {
        LOGGER.info("Running: {}", String.join(" ", cmd));
    }

    private static <T> T[] concat(final T element, final T[] array) {
        return ArrayUtils.addFirst(array, element);
    }

    private static <T> T[] concat(final T[] element, final T[] array) {
        return ArrayUtils.addAll(element, array);
    }

    private static String[] array(final String... elements) {
        return elements;
    }

    private static void closeQuietly(final Closeable closeable) {
        IOUtils.closeQuietly(closeable);
    }
}
