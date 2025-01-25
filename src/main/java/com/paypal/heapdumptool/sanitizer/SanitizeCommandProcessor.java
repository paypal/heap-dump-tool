package com.paypal.heapdumptool.sanitizer;

import com.paypal.heapdumptool.cli.CliCommandProcessor;
import com.paypal.heapdumptool.utils.InternalLogger;
import org.apache.commons.lang3.Validate;

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
        LOGGER.info("Starting heap dump sanitization");
        LOGGER.info("Input File: {}", command.getInputFile());
        LOGGER.info("Output File: {}", command.getOutputFile());

        final Instant now = Instant.now();
        try (final InputStream inputStream = streamFactory.newInputStream();
             final OutputStream outputStream = streamFactory.newOutputStream()) {

            final HeapDumpSanitizer sanitizer = new HeapDumpSanitizer();
            sanitizer.setInputStream(inputStream);
            sanitizer.setOutputStream(outputStream);
            sanitizer.setProgressMonitor(numBytesProcessedMonitor(command.getBufferSize(), LOGGER));
            sanitizer.setSanitizationText(command.getSanitizationText());
            sanitizer.setSanitizeByteCharArraysOnly(command.isSanitizeByteCharArraysOnly());
            sanitizer.setSanitizeArraysOnly(command.isSanitizeArraysOnly());

            sanitizer.sanitize();
        }
        LOGGER.info("Finished heap dump sanitization in {}", getFriendlyDuration(now));
    }

}
