package com.paypal.heapdumptool.sanitizer;

import com.paypal.heapdumptool.cli.CliCommand;
import org.apache.commons.text.StringEscapeUtils;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;

import java.nio.file.Path;

import static com.paypal.heapdumptool.sanitizer.DataSize.ofMegabytes;
import static org.apache.commons.lang3.builder.ToStringBuilder.reflectionToString;
import static org.apache.commons.lang3.builder.ToStringStyle.MULTI_LINE_STYLE;
import static picocli.CommandLine.Help.Visibility.ALWAYS;

@Command(name = "sanitize", description = "Sanitize a heap dump by replacing byte and char array contents", abbreviateSynopsis = true)
public class SanitizeCommand implements CliCommand {

    static final String DOCKER_REGISTRY_OPTION = "--docker-registry";
    
    // to allow field injection from picocli, these variables can't be final

    @Option(names = { "-d", DOCKER_REGISTRY_OPTION }, description = "docker registry hostname for bootstrapping heap-dump-tool docker image")
    private String dockerRegistry;
    
    @Parameters(index = "0", description = "Input heap dump .hprof. File or stdin")
    private Path inputFile;

    @Option(names = {"-a", "--tar-input"}, description = "Treat input as tar archive")
    private boolean tarInput;

    @Parameters(index = "1", description = "Output heap dump .hprof. File, stdout, or stderr")
    private Path outputFile;

    @Option(names = {"-z", "--zip-output"}, description = "Write zipped output", showDefaultValue = ALWAYS)
    private boolean zipOutput;

    @Option(names = {"-t", "--text"}, description = "Sanitization text to replace with", defaultValue = "\\0", showDefaultValue = ALWAYS)
    private String sanitizationText = "\\0";

    @Option(names = {"-f", "--force-string-coder-match"},
            description = "Force strings coder values to match sanitizationText.coder value",
            defaultValue = "true", showDefaultValue = ALWAYS)
    // Suppose sanitizationText=*. If the coder value is not forced to match, the heap dump analyze tools like Eclipse
    // MAT might display escaped "\\u2A" (where 2A is ascii value) for Strings with coder==1. By forcing the coder value to
    // match, all strings would be displayed as "*"
    private boolean forceMatchStringCoder;

    @Option(names = {"-s", "--sanitize-byte-char-arrays-only"}, description = "Sanitize byte/char arrays only", defaultValue = "true", showDefaultValue = ALWAYS)
    private boolean sanitizeByteCharArraysOnly = true;

    @Option(names = {"--sanitize-arrays-only"}, description = "Sanitize arrays only", defaultValue = "false", showDefaultValue = ALWAYS)
    private boolean sanitizeArraysOnly;

    @Option(names = {"-b", "--buffer-size"}, description = "Buffer size for reading and writing", defaultValue = "100MB", showDefaultValue = ALWAYS)
    private DataSize bufferSize = ofMegabytes(100);

    @Override
    public Class<SanitizeCommandProcessor> getProcessorClass() {
        return SanitizeCommandProcessor.class;
    }

    public DataSize getBufferSize() {
        return bufferSize;
    }

    public void setBufferSize(final DataSize bufferSize) {
        this.bufferSize = bufferSize;
    }

    public boolean isSanitizeByteCharArraysOnly() {
        return sanitizeByteCharArraysOnly;
    }

    public void setSanitizeByteCharArraysOnly(final boolean sanitizeByteCharArraysOnly) {
        this.sanitizeByteCharArraysOnly = sanitizeByteCharArraysOnly;
    }

    public boolean isSanitizeArraysOnly() {
        return sanitizeArraysOnly;
    }

    public void setSanitizeArraysOnly(final boolean sanitizeArraysOnly) {
        this.sanitizeArraysOnly = sanitizeArraysOnly;
    }

    public Path getInputFile() {
        return inputFile;
    }

    public void setInputFile(final Path inputFile) {
        this.inputFile = inputFile;
    }

    public boolean isTarInput() {
        return tarInput;
    }

    public void setTarInput(final boolean tarInput) {
        this.tarInput = tarInput;
    }

    public Path getOutputFile() {
        return outputFile;
    }

    public void setOutputFile(final Path outputFile) {
        this.outputFile = outputFile;
    }

    public String getSanitizationText() {
        return StringEscapeUtils.unescapeJava(sanitizationText);
    }

    public void setSanitizationText(final String sanitizationText) {
        // e.g. unescape user-supplied \\0 string (2 chars) to \0 string (1 char)
        this.sanitizationText = StringEscapeUtils.unescapeJava(sanitizationText);
    }

    public boolean isForceMatchStringCoder() {
        return forceMatchStringCoder;
    }

    public void setForceMatchStringCoder(final boolean forceMatchStringCoder) {
        this.forceMatchStringCoder = forceMatchStringCoder;
    }

    public boolean isZipOutput() {
        return zipOutput;
    }

    public void setZipOutput(final boolean zipOutput) {
        this.zipOutput = zipOutput;
    }

    @Override
    public String toString() {
        return reflectionToString(this, MULTI_LINE_STYLE);
    }

}
