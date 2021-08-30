package com.paypal.heapdumptool.hserr;

import com.paypal.heapdumptool.cli.CliCommand;
import picocli.CommandLine.Command;
import picocli.CommandLine.Parameters;

import java.nio.file.Path;

import static org.apache.commons.lang3.builder.ToStringBuilder.reflectionToString;
import static org.apache.commons.lang3.builder.ToStringStyle.MULTI_LINE_STYLE;

@Command(name = "sanitize-hserr", description = "Sanitize fatal error log by censoring environment variable values", abbreviateSynopsis = true)
public class SanitizeHserrCommand implements CliCommand {

    // to allow field injection from picocli, these variables can't be final

    @Parameters(index = "0", description = "Input hs_err_pid* fatal error log. File or stdin")
    private Path inputFile;

    @Parameters(index = "1", description = "Output hs_err_pid* fatal error log. File, stdout, or stderr")
    private Path outputFile;

    @Override
    public Class<SanitizeHserrCommandProcessor> getProcessorClass() {
        return SanitizeHserrCommandProcessor.class;
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

    @Override
    public String toString() {
        return reflectionToString(this, MULTI_LINE_STYLE);
    }

}
