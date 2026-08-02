package com.paypal.heapdumptool.sanitizer;

import com.paypal.heapdumptool.cli.CliCommand;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;

import java.nio.file.Path;

// sortOptions = false: options are listed in the @Option(order = ...) sequence rather than
// alphabetically, so what to sanitize comes before how, and the deprecated flags sink to the bottom.
// Order values are shared with SanitizeOrCaptureCommandBase and the SanitizeOptions mixin.
@Command(name = "sanitize", description = "Sanitize a heap dump by replacing primitive field and array contents",
        abbreviateSynopsis = true, sortOptions = false)
public class SanitizeCommand extends SanitizeOrCaptureCommandBase implements CliCommand {

    // to allow field injection from picocli, these variables can't be final

    @Parameters(index = "0", description = {
            "Input heap dump. File or stdin",
            ".zip, .tar, .tar.gz, .tgz, .gz files also supported"
    })
    private Path inputFile;

    @Parameters(index = "1", description = {
            "Output heap dump .hprof file",
            ".zip, .tar, .tar.gz, .tgz, .gz files also supported"
    })
    private Path outputFile;

    private boolean zipOutput;

    @Option(names = {"-z", "--zip-output"},
            order = OptionOrder.LEGACY_ZIP_OUTPUT,
            description = "Deprecated. Name the output file <outputFile>.zip instead")
    void setLegacyZipOutput(final boolean zipOutput) {
        this.zipOutput = zipOutput;
        getSanitizeOptions().recordLegacyZipOutput();
    }

    @Override
    public Class<SanitizeCommandProcessor> getProcessorClass() {
        return SanitizeCommandProcessor.class;
    }

    public Path getInputFile() {
        return inputFile;
    }

    public void setInputFile(final Path inputFile) {
        this.inputFile = inputFile;
    }

    public Path getOutputFile() {
        return outputFile;
    }

    public void setOutputFile(final Path outputFile) {
        this.outputFile = outputFile;
    }

    public boolean isZipOutput() {
        return zipOutput;
    }

    public void setZipOutput(final boolean zipOutput) {
        this.zipOutput = zipOutput;
    }
}
