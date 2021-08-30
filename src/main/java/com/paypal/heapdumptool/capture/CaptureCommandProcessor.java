package com.paypal.heapdumptool.capture;

import com.paypal.heapdumptool.cli.CliCommandProcessor;
import com.paypal.heapdumptool.sanitizer.SanitizeCommand;
import com.paypal.heapdumptool.sanitizer.SanitizeCommandProcessor;
import com.paypal.heapdumptool.utils.ProcessTool;
import com.paypal.heapdumptool.utils.ProcessTool.ProcessResult;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.Validate;
import org.apache.commons.lang3.function.Failable;
import org.apache.commons.text.StringSubstitutor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.Closeable;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.PosixFilePermission;
import java.time.Instant;
import java.util.Arrays;
import java.util.HashMap;
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

    private static final Logger LOGGER = LoggerFactory.getLogger(CaptureCommandProcessor.class);

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

        final Path inputHeapDumpFile = createPlainHeapDumpInAppContainer(pid);
        final String threadDump = captureThreadDump(pid);
        final Path output;
        try (final InputStream inputStream = createCopyStreamOutOfAppContainer(inputHeapDumpFile)) {
            output = sanitizeHeapDump(inputHeapDumpFile, inputStream, threadDump);
        } finally {
            deletePlainHeapDumpInAppContainer(inputHeapDumpFile);
        }

        LOGGER.info("Captured sanitized heap dump in {}. Output: {}", getFriendlyDuration(now), output);
    }

    private String captureThreadDump(final long pid) throws Exception {
        final ProcessResult result = execInAppContainer("jcmd", pid, "Thread.print", "-l");
        return result.stdout;
    }

    private Path sanitizeHeapDump(final Path filePath, final InputStream inputStream, final String threadDump) throws Exception {
        final String destFile = filePath.getFileName().toAbsolutePath() // re-eval filename in current cwd
                + ".zip";
        final Path destFilePath = Paths.get(destFile);

        final SanitizeCommand sanitizeCommand = new SanitizeCommand();
        sanitizeCommand.setInputFile(filePath); // not used. for display only
        sanitizeCommand.setOutputFile(destFilePath);
        sanitizeCommand.setBufferSize(command.getBufferSize());
        sanitizeCommand.setTarInput(true);
        sanitizeCommand.setZipOutput(true);

        try (final CaptureStreamFactory captureStreamFactory = new CaptureStreamFactory(sanitizeCommand, inputStream)) {

            final SanitizeCommandProcessor processor = SanitizeCommandProcessor.newInstance(sanitizeCommand, captureStreamFactory);
            processor.process();

            writeThreadDump(threadDump, filePath, captureStreamFactory);
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

    private InputStream createCopyStreamOutOfAppContainer(final Path filePath) throws IOException {
        final String src = command.getContainerName() + ":" + filePath;
        final String[] args = array(DOCKER, "cp", src, "-");
        logProcessArgs(args);

        final String[] cmd = nsenterIfNeeded(args);
        final Process process = processBuilder(cmd).start();
        closeQuietly(process.getOutputStream());
        closeQuietly(process.getErrorStream());

        return new FilterInputStream(process.getInputStream()) {

            @Override
            public void close() throws IOException {
                super.close();
                process.destroy();
            }
        };
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

        Validate.validState(pids.length == 1, "Cannot find unique Java process. container=%s found=%s", command.getContainerName(), Arrays.toString(pids));
        return pids[0];
    }

    private Path createPlainHeapDumpInAppContainer(final long pid) throws Exception {
        final Path filePath = newHeapDumpFilePath();

        final ProcessResult result = execInAppContainer("jcmd", pid, "GC.heap_dump", filePath);
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
        if (LOGGER.isInfoEnabled()) {
            LOGGER.info("Running: {}", String.join(" ", cmd));
        }
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

    @SuppressWarnings("deprecation")
    private static void closeQuietly(final Closeable closeable) {
        IOUtils.closeQuietly(closeable);
    }
}
