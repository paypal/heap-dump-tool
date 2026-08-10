package com.paypal.heapdumptool.sanitizer;

import com.paypal.heapdumptool.utils.DataSize;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;
import picocli.CommandLine;

import static java.util.Objects.requireNonNull;

/**
 * Fluent entry point for running a sanitization without constructing a {@link SanitizeCommand} by
 * hand. Start from {@link HeapDumpSanitizer#create(Path, Path)}.
 *
 * <pre>{@code
 * HeapDumpSanitizer.create(input, output)
 *     .target("all")               // optional
 *     .replacement("char=*")       // optional
 *     .addRule(SanitizationRules.fieldRule(field -> ...))  // optional
 *     .sanitize();
 * }</pre>
 *
 * <p>Internally the builder creates the {@link SanitizeCommand} the way the CLI does: the input
 * and output paths are parsed as the command's positional parameters through picocli, so the
 * annotated defaults ({@code -e}, {@code -f}, {@code -b}) apply exactly as for a bare
 * {@code sanitize <input> <output>} run. The run then delegates to
 * {@link SanitizeCommandProcessor}, so it logs and behaves exactly like the CLI --
 * including the two-pass preprocessing when {@code -e} or {@code -f} call for it. {@link #target}
 * and {@link #replacement} are recorded in call order, same as the command line.</p>
 */
public final class HeapDumpSanitizerBuilder {

    private final SanitizeCommand command;

    /*
     * Applied immediately before process(), in registration order, once the builder's own settings are
     * already on the command. Only configure() reaches this list; the builder's settings are recorded
     * onto the command eagerly, so a customizer always sees them.
     */
    private final List<Consumer<SanitizeCommand>> customizers = new ArrayList<>();

    private HeapDumpSanitizerBuilder(final Path inputFile, final Path outputFile) {
        this.command = new SanitizeCommand();
        // Parse through picocli exactly like the CLI would, so the annotated defaults (the -e/-f/-b
        // defaultValues) and the positional input/output parameters are filled in one place.
        new CommandLine(command)
                .registerConverter(DataSize.class, DataSize::parse)
                .parseArgs(
                        requireNonNull(inputFile, "inputFile").toString(),
                        requireNonNull(outputFile, "outputFile").toString());
    }

    /**
     * A builder over two files. The output format follows the output file name, exactly as on the
     * command line: a {@code .zip}, {@code .tar}, {@code .gz} or {@code .tgz} output is wrapped
     * accordingly, and an archive or gzip input is unwrapped as it is read.
     */
    public static HeapDumpSanitizerBuilder create(final Path inputFile, final Path outputFile) {
        return new HeapDumpSanitizerBuilder(inputFile, outputFile);
    }

    /** Equivalent to {@code --target=<value>}. Applied in call order, same as the CLI. */
    public HeapDumpSanitizerBuilder target(final String value) {
        command.getSanitizeOptions().target(value);
        return this;
    }

    /** Equivalent to {@code --replacement=<value>}. Applied in call order, same as the CLI. */
    public HeapDumpSanitizerBuilder replacement(final String value) {
        command.getSanitizeOptions().replacement(value);
        return this;
    }

    /** Registers a programmatic rule. Same semantics as {@code SanitizeOptions.addRule()}. */
    public HeapDumpSanitizerBuilder addRule(final SanitizationRule rule) {
        command.getSanitizeOptions().addRule(rule);
        return this;
    }

    /**
     * Escape hatch for options not covered by the builder methods. Called after the builder's own
     * settings have been applied to the command, so the customizer may inspect or override them.
     */
    public HeapDumpSanitizerBuilder configure(final Consumer<SanitizeCommand> commandCustomizer) {
        customizers.add(requireNonNull(commandCustomizer, "commandCustomizer"));
        return this;
    }

    /** Runs the sanitization. Delegates to {@link SanitizeCommandProcessor}. */
    public void sanitize() throws Exception {
        for (final Consumer<SanitizeCommand> customizer : customizers) {
            customizer.accept(command);
        }
        new SanitizeCommandProcessor(command).process();
    }
}
