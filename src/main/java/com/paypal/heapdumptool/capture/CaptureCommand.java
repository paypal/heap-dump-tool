package com.paypal.heapdumptool.capture;

import com.paypal.heapdumptool.cli.CliCommand;
import com.paypal.heapdumptool.sanitizer.DataSize;
import org.apache.commons.text.StringEscapeUtils;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;

import static com.paypal.heapdumptool.sanitizer.DataSize.ofMegabytes;
import static org.apache.commons.lang3.builder.ToStringBuilder.reflectionToString;
import static org.apache.commons.lang3.builder.ToStringStyle.MULTI_LINE_STYLE;
import static picocli.CommandLine.Help.Visibility.ALWAYS;

@Command(name = "capture",
        description = {
                "Capture sanitized heap dump of a containerized app",
                "Plain thread dump is also captured"
        },
        abbreviateSynopsis = true)
public class CaptureCommand implements CliCommand {

    static final String DOCKER_REGISTRY_OPTION = "--docker-registry";
    
    // to allow field injection from picocli, these variables can't be final

    @Parameters(index = "0", description = "Container name")
    private String containerName;

    @Option(names = { "-p", "--pid" }, description = "Pid within the container, if there are multiple Java processes")
    private Long pid;

    @Option(names = { "-d", DOCKER_REGISTRY_OPTION }, description = "docker registry hostname for bootstrapping heap-dump-tool docker image")
    private String dockerRegistry;
    
    @Option(names = { "-z", "--zip-output" }, description = "Write zipped output", defaultValue = "true", showDefaultValue = ALWAYS)
    private boolean zipOutput = true;

    @Option(names = { "-t", "--text" }, description = "Sanitization text to replace with", defaultValue = "\\0", showDefaultValue = ALWAYS)
    private String sanitizationText = "\\0";

    @Option(names = { "-s", "--sanitize-byte-char-arrays-only" }, description = "Sanitize byte/char arrays only", defaultValue = "true", showDefaultValue = ALWAYS)
    private boolean sanitizeByteCharArraysOnly = true;

    @Option(names = { "-b", "--buffer-size" }, description = "Buffer size for reading and writing", defaultValue = "100MB", showDefaultValue = ALWAYS)
    private DataSize bufferSize = ofMegabytes(100);

    @Override
    public Class<CaptureCommandProcessor> getProcessorClass() {
        return CaptureCommandProcessor.class;
    }

    public DataSize getBufferSize() {
        return bufferSize;
    }

    public void setBufferSize(final DataSize bufferSize) {
        this.bufferSize = bufferSize;
    }

    public String getContainerName() {
        return containerName;
    }

    public void setContainerName(final String containerName) {
        this.containerName = containerName;
    }

    public Long getPid() {
        return pid;
    }

    public void setPid(final Long pid) {
        this.pid = pid;
    }

    public boolean isZipOutput() {
        return zipOutput;
    }

    public void setZipOutput(final boolean zipOutput) {
        this.zipOutput = zipOutput;
    }

    public boolean isSanitizeByteCharArraysOnly() {
        return sanitizeByteCharArraysOnly;
    }

    public void setSanitizeByteCharArraysOnly(final boolean sanitizeByteCharArraysOnly) {
        this.sanitizeByteCharArraysOnly = sanitizeByteCharArraysOnly;
    }

    public String getSanitizationText() {
        return StringEscapeUtils.unescapeJava(sanitizationText);
    }

    public void setSanitizationText(final String sanitizationText) {
        // e.g. unescape user-supplied \\0 string (2 chars) to \0 string (1 char)
        this.sanitizationText = StringEscapeUtils.unescapeJava(sanitizationText);
    }

    @Override
    public String toString() {
        return reflectionToString(this, MULTI_LINE_STYLE);
    }

}
