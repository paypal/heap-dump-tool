package com.paypal.heapdumptool.sanitizer;

import com.paypal.heapdumptool.cli.CliCommandProcessor;
import com.paypal.heapdumptool.utils.InternalLogger;
import org.apache.commons.io.output.NullOutputStream;
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
        if (command.isSanitizeArraysOnly() && command.isSanitizeByteCharArraysOnly()) {
            throw new IllegalArgumentException("sanitizeArraysOnly and sanitizeByteCharArraysOnly cannot be both set to true simultaneously");
        }
        if (streamFactory.isStdinInput() && !command.getExcludeStringFields().isEmpty()) {
            throw new IllegalArgumentException("stdin input and excludeStringFields cannot be both set to true simultaneously");
        }
        Validate.notEmpty(command.getSanitizationText());

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

    private HeapDumpSanitizer applyPreprocessing() throws IOException {
        final HeapDumpSanitizer sanitizerPrototype = new HeapDumpSanitizer();
        if (command.getExcludeStringFields().isEmpty() && !command.isForceMatchStringCoder()) {
            return sanitizerPrototype;
        }

        LOGGER.info("Pre-processing ...");
        LOGGER.info("    String fields to exclude from sanitization: {}", String.join(",", command.getExcludeStringFields()));
        LOGGER.info("    Force match String.coder: {}", command.isForceMatchStringCoder());
        LOGGER.info("Input File: {}", command.getInputFile());

        try (final InputStream inputStream = streamFactory.newInputStream();
             final OutputStream outputStream = NullOutputStream.INSTANCE) {

            sanitize(sanitizerPrototype, inputStream, outputStream);
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
