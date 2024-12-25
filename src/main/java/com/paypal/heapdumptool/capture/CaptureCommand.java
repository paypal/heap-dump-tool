package com.paypal.heapdumptool.capture;

import com.paypal.heapdumptool.cli.CliCommand;
import com.paypal.heapdumptool.sanitizer.DataSize;
import org.apache.commons.text.StringEscapeUtils;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

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

    @Option(names = { "-z", "--zip-output" }, description = "Write zipped output", defaultValue = "true", showDefaultValue = ALWAYS)
    private boolean zipOutput = true;

    @Option(names = { "-t", "--text" }, description = "Sanitization text to replace with", defaultValue = "\\0", showDefaultValue = ALWAYS)
    private String sanitizationText = "\\0";

    @Option(names = { "-s", "--sanitize-byte-char-arrays-only" }, description = "Sanitize byte/char arrays only", defaultValue = "true", showDefaultValue = ALWAYS)
    private boolean sanitizeByteCharArraysOnly = true;

    @Option(names = { "-b", "--buffer-size" }, description = "Buffer size for reading and writing", defaultValue = "100MB", showDefaultValue = ALWAYS)
    private DataSize bufferSize = ofMegabytes(100);

    @Option(names = { "--heap-cmd" }, description = "Command to capture heap dump", defaultValue = "jcmd PID GC.heap_dump FILE_PATH", showDefaultValue = ALWAYS)
    // e.g. set --heap-cmd "jcmd PID GC.heap_dump -all FILE_PATH" to pass -all flag to jcmd heap dump
    private List<String> heapCmd = new ArrayList<>(Arrays.asList("jcmd PID GC.heap_dump FILE_PATH"));

    @Option(names = { "--heap-options" }, description = "Options to heap dump command", defaultValue = "", showDefaultValue = ALWAYS)
    // e.g. set --heap-options -all to pass -all flag to jcmd heap dump
    private List<String> heapOptions = new ArrayList<>();

    @Option(names = { "--thread-cmd" }, description = "Command to capture thread dump", defaultValue = "jcmd PID Thread.print -l", showDefaultValue = ALWAYS)
    // e.g. set --thread-cmd "jcmd 1 Thread.dump_to_file -format=json -" to thread dump in json format
    private List<String> threadCmd = new ArrayList<>(Arrays.asList("jcmd PID Thread.print -l"));

    @Option(names = { "--thread-option" }, description = "Options to thread dump command", defaultValue = "", showDefaultValue = ALWAYS)
    private List<String> threadOptions = new ArrayList<>();

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

    public List<String> getHeapCmd() {
        return splitBySpace(heapCmd);
    }

    public void setHeapCmd(final List<String> heapCmd) {
        this.heapCmd = heapCmd;
    }

    public List<String> getHeapOptions() {
        return heapOptions;
    }

    public void setHeapOptions(final List<String> heapOptions) {
        this.heapOptions = heapOptions;
    }

    public List<String> getThreadCmd() {
        return splitBySpace(threadCmd);
    }

    public void setThreadCmd(final List<String> threadCmd) {
        this.threadCmd = threadCmd;
    }

    private static List<String> splitBySpace(final List<String> in) {
        final List<String> out = new ArrayList<>();
        for (final String token : in) {
            out.addAll(Arrays.asList(token.split("\\s+")));
        }
        return out;
    }

    public List<String> getThreadOptions() {
        return threadOptions;
    }

    public void setThreadOptions(final List<String> threadOptions) {
        this.threadOptions = threadOptions;
    }

    @Override
    public String toString() {
        return reflectionToString(this, MULTI_LINE_STYLE);
    }

}
