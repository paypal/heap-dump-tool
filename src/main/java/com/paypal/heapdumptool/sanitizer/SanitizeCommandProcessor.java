package com.paypal.heapdumptool.sanitizer;

import com.paypal.heapdumptool.cli.CliCommandProcessor;
import com.paypal.heapdumptool.utils.InternalLogger;
import org.apache.commons.lang3.Validate;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.time.Instant;

import static com.paypal.heapdumptool.utils.DateTimeTool.getFriendlyDuration;
import static com.paypal.heapdumptool.utils.ProgressMonitor.numBytesProcessedMonitor;

public class SanitizeCommandProcessor implements CliCommandProcessor {

    private static final InternalLogger LOGGER = InternalLogger.getLogger(SanitizeCommandProcessor.class);

    private final SanitizeCommand command;

    private final SanitizeStreamFactory streamFactory;

    // for mocking
    public static SanitizeCommandProcessor newInstance(final SanitizeCommand command, final SanitizeStreamFactory streamFactory) {
        return new SanitizeCommandProcessor(command, streamFactory);
    }

    public SanitizeCommandProcessor(final SanitizeCommand command) {
        this(command, new SanitizeStreamFactory(command));
    }

    public SanitizeCommandProcessor(final SanitizeCommand command, final SanitizeStreamFactory streamFactory) {
        Validate.isTrue(command.getBufferSize().toBytes() >= 0, "Invalid buffer size");

        this.command = command;
        this.streamFactory = streamFactory;
    }

    @Override
    public void process() throws Exception {
        if (streamFactory.isStdinInput() && !command.getExcludeStringFields().isEmpty()) {
            throw new IllegalArgumentException("stdin input and excludeStringFields cannot be both set to true simultaneously");
        }
        final SanitizationPolicy policy = command.getSanitizationPolicy();
        for (final String warning : policy.getWarnings()) {
            LOGGER.info("WARNING: {}", warning);
        }
        logSanitizationPolicy(policy);

        final Instant now = Instant.now();

        final HeapDumpSanitizer sanitizer = applyPreprocessing();
        LOGGER.info("Starting heap dump sanitization ...");
        LOGGER.info("Input File: {}", command.getInputFile());
        LOGGER.info("Output File: {}", command.getOutputFile());

        try (final InputStream inputStream = streamFactory.newInputStream();
             final OutputStream outputStream = streamFactory.newOutputStream()) {

            sanitize(sanitizer, inputStream, outputStream);
        }
        LOGGER.info("Finished heap dump sanitization in {}", getFriendlyDuration(now));
    }

    /**
     * Logs what this run will sanitize and what it will write over it, in the flag syntax that
     * produced it. The deprecated flags, and the order they were combined in, make the resolved
     * policy hard to predict from the command line alone, so the log records the outcome. Both lines
     * are valid flag values: pasting them back reproduces the run.
     *
     * <p>Logged before the preprocessing pass rather than beside the input and output files, because
     * preprocessing reads the whole dump and takes minutes on a large one. Whoever is watching
     * should see what the run is about to do before that wait, not after it.</p>
     */
    private static void logSanitizationPolicy(final SanitizationPolicy policy) {
        LOGGER.info("Sanitization targets: --target={}", policy.describeTargets());
        LOGGER.info("Replacement values: --replacement={}", policy.describeReplacements());
    }

    private HeapDumpSanitizer applyPreprocessing() throws IOException {
        final HeapDumpSanitizer sanitizerPrototype = new HeapDumpSanitizer();
        if (command.getExcludeStringFields().isEmpty() && !command.isForceMatchStringCoder()) {
            return sanitizerPrototype;
        }

        LOGGER.info("Pre-processing ...");
        LOGGER.info("    String fields to exclude from sanitization: {}", String.join(",", command.getExcludeStringFields()));
        LOGGER.info("    Force match String.coder: {}", command.isForceMatchStringCoder());
        LOGGER.info("Input File: {}", command.getInputFile());

        sanitizerPrototype.setPreprocessingOnly(true);
        try (final InputStream inputStream = streamFactory.newInputStream()) {
            sanitize(sanitizerPrototype, inputStream, null);
        } finally {
            sanitizerPrototype.setPreprocessingOnly(false);
        }

        return sanitizerPrototype;
    }

    private void sanitize(final HeapDumpSanitizer sanitizer,
                          final InputStream inputStream,
                          final OutputStream outputStream) throws IOException {
        sanitizer.setInputStream(inputStream);
        sanitizer.setOutputStream(outputStream);
        sanitizer.setProgressMonitor(numBytesProcessedMonitor(command.getBufferSize(), LOGGER));
        sanitizer.setSanitizeCommand(command);

        sanitizer.sanitize();
    }

}
