package com.paypal.heapdumptool.sanitizer;

import com.paypal.heapdumptool.cli.CliCommandProcessor;
import com.paypal.heapdumptool.sanitizer.internal.policy.SanitizationRuleRegistry;
import com.paypal.heapdumptool.utils.InternalLogger;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.time.Instant;
import java.util.List;
import org.apache.commons.lang3.Validate;

import static com.paypal.heapdumptool.utils.DateTimeTool.getFriendlyDuration;
import static com.paypal.heapdumptool.utils.ProgressMonitor.numBytesProcessedMonitor;

public class SanitizeCommandProcessor implements CliCommandProcessor {

    private static final InternalLogger LOGGER = InternalLogger.getLogger(SanitizeCommandProcessor.class);

    private final SanitizeCommand command;

    private final SanitizeStreamFactory streamFactory;

    // for mocking
    public static SanitizeCommandProcessor newInstance(
            final SanitizeCommand command, final SanitizeStreamFactory streamFactory) {
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
            throw new IllegalArgumentException(
                    "stdin input and excludeStringFields cannot be both set to true simultaneously");
        }

        LOGGER.info("Input File: {}", command.getInputFile());
        LOGGER.info("Output File: {}", command.getOutputFile());
        final SanitizationPolicy policy = command.getSanitizationPolicy();
        for (final String warning : policy.getWarnings()) {
            LOGGER.info("WARNING: {}", warning);
        }
        logSanitizationPolicy(policy);
        logSanitizationRules(command.getSanitizationRules());

        final Instant now = Instant.now();
        final HeapDumpSanitizer sanitizer = applyPreprocessing();
        LOGGER.info("Starting heap dump sanitization ...");

        try (final InputStream inputStream = streamFactory.newInputStream();
                final OutputStream outputStream = streamFactory.newOutputStream()) {

            sanitize(sanitizer, inputStream, outputStream);
        }
        logRoutedTransformers(sanitizer.getSanitizationRules());
        warnAboutUnmatchedRules(sanitizer.getSanitizationRules());
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

    /**
     * Names the registered {@link SanitizationRule}s, if any.
     *
     * <p>Deliberately not written as a flag value, unlike the two lines above. Those round-trip --
     * pasting them back reproduces the run -- and a rule cannot, since it is user code. Printing a
     * rule list in flag syntax would suggest the log is a complete record of the run when it is
     * not.</p>
     */
    private static void logSanitizationRules(final SanitizationRuleRegistry rules) {
        // null-tolerant for the same reason HeapDumpSanitizer.sanitize() is: a stub command answers null
        if (rules == null || rules.isEmpty()) {
            return;
        }
        LOGGER.info(
                "Programmatic rules, applied in order before --target: {}", String.join(", ", rules.describeRules()));
    }

    /**
     * Names the {@link ValueTransformer}s this run computed replacements with, if any.
     *
     * <p>After the run, not before it, unlike the rule list: a transformer is not registered anywhere.
     * It arrives on a {@link Decision}, so which ones a run uses is not knowable until its rules have
     * been asked. A run whose rules only sanitize logs nothing here.</p>
     *
     * <p>Worth logging at all because a transformed field is the one case where the output is neither
     * the original value nor a constant from {@code --replacement}. Nothing else in the log would say
     * that user code decided what those bytes are.</p>
     */
    private static void logRoutedTransformers(final SanitizationRuleRegistry rules) {
        if (rules == null) {
            return;
        }
        final List<String> transformers = rules.describeRoutedTransformers();
        if (transformers.isEmpty()) {
            return;
        }
        LOGGER.info("Values computed by transformers, not by --replacement: {}", String.join(", ", transformers));
    }

    /**
     * Warns about rules that never returned a verdict, which is almost always a typo in a class or
     * field name. Without this, such a run reports a clean success while having done nothing the rule
     * was added for.
     *
     * <p>Logged after the run rather than raised as an error: by the time this is known the output is
     * already written, and a rule can also legitimately match nothing in one dump of many.</p>
     */
    private static void warnAboutUnmatchedRules(final SanitizationRuleRegistry rules) {
        if (rules == null) {
            return;
        }
        for (final String rule : rules.describeUnmatchedRules()) {
            LOGGER.info(
                    "WARNING: rule {} matched nothing in this dump. Check the class and field names it looks for",
                    rule);
        }
    }

    private HeapDumpSanitizer applyPreprocessing() throws IOException {
        final HeapDumpSanitizer sanitizerPrototype = new HeapDumpSanitizer();
        if (command.getExcludeStringFields().isEmpty() && !command.isForceMatchStringCoder()) {
            return sanitizerPrototype;
        }

        LOGGER.info(""); // empty line
        LOGGER.info("Pre-processing ...");
        LOGGER.info(
                "    String fields to exclude from sanitization: {}",
                String.join(",", command.getExcludeStringFields()));
        LOGGER.info("    Force match JEP-254 String.coder: {}", command.isForceMatchStringCoder());

        final Instant preprocessingStart = Instant.now();

        sanitizerPrototype.setPreprocessingOnly(true);
        try (final InputStream inputStream = streamFactory.newInputStream()) {
            sanitize(sanitizerPrototype, inputStream, null);
        } finally {
            sanitizerPrototype.setPreprocessingOnly(false);
        }
        LOGGER.info("Finished pre-processing in {}", getFriendlyDuration(preprocessingStart));
        LOGGER.info(""); // empty line

        return sanitizerPrototype;
    }

    private void sanitize(
            final HeapDumpSanitizer sanitizer, final InputStream inputStream, final OutputStream outputStream)
            throws IOException {
        sanitizer.setInputStream(inputStream);
        sanitizer.setOutputStream(outputStream);
        sanitizer.setProgressMonitor(numBytesProcessedMonitor(streamFactory.getInputSizeBytes(), LOGGER));
        sanitizer.setSanitizeCommand(command);

        sanitizer.sanitize();
    }
}
