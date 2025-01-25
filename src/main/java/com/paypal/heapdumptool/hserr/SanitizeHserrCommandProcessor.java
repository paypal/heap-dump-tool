package com.paypal.heapdumptool.hserr;

import com.paypal.heapdumptool.cli.CliCommandProcessor;
import com.paypal.heapdumptool.sanitizer.SanitizeCommand;
import com.paypal.heapdumptool.sanitizer.SanitizeStreamFactory;
import com.paypal.heapdumptool.utils.InternalLogger;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;

import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

import static com.paypal.heapdumptool.utils.DateTimeTool.getFriendlyDuration;

public class SanitizeHserrCommandProcessor implements CliCommandProcessor {

    private static final InternalLogger LOGGER = InternalLogger.getLogger(SanitizeHserrCommandProcessor.class);

    private final SanitizeHserrCommand command;

    private final SanitizeStreamFactory streamFactory;

    public SanitizeHserrCommandProcessor(final SanitizeHserrCommand command) {
        this(command, new SanitizeStreamFactory(asSanitizeCommand(command)));
    }

    public SanitizeHserrCommandProcessor(final SanitizeHserrCommand command, final SanitizeStreamFactory streamFactory) {
        this.command = command;
        this.streamFactory = streamFactory;
    }

    @Override
    public void process() throws Exception {

        LOGGER.info("Starting hs_err sanitization");
        LOGGER.info("Input File: {}", command.getInputFile());
        LOGGER.info("Output File: {}", command.getOutputFile());

        final Instant now = Instant.now();
        try (final InputStream inputStream = streamFactory.newInputStream();
                final OutputStream outputStream = streamFactory.newOutputStream()) {

            final List<String> lines = IOUtils.readLines(inputStream, StandardCharsets.UTF_8);
            final List<String> sanitizedLines = sanitize(lines);

            IOUtils.writeLines(sanitizedLines, System.lineSeparator(), outputStream, StandardCharsets.UTF_8);
        }
        LOGGER.info("Finished hs_err sanitization in {}", getFriendlyDuration(now));
    }

    private List<String> sanitize(final List<String> lines) {
        boolean inEnvVarSection = false;
        final List<String> sanitizedLines = new ArrayList<>();
        for (final String line : lines) {
            String newLine = line;

            if (line.startsWith("Environment Variables:")) {
                inEnvVarSection = true;

            } else if (inEnvVarSection) {
                if (line.isEmpty()) {
                    inEnvVarSection = false;
                } else {
                    final String key = StringUtils.substringBefore(line, "=");
                    newLine = key + "=****";
                }
            }
            
            sanitizedLines.add(newLine);
        }
        return sanitizedLines;
    }

    private static SanitizeCommand asSanitizeCommand(final SanitizeHserrCommand command) {
        final SanitizeCommand sanitizeCommand = new SanitizeCommand();
        sanitizeCommand.setInputFile(command.getInputFile());
        sanitizeCommand.setOutputFile(command.getOutputFile());
        return sanitizeCommand;
    }
}
