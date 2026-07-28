package com.paypal.heapdumptool.sanitizer;

import com.paypal.heapdumptool.cli.CliCommand;
import org.apache.commons.lang3.StringUtils;
import picocli.CommandLine.Mixin;
import picocli.CommandLine.Option;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;

import static com.paypal.heapdumptool.sanitizer.DataSize.ofMegabytes;
import static org.apache.commons.lang3.builder.ToStringBuilder.reflectionToString;
import static org.apache.commons.lang3.builder.ToStringStyle.MULTI_LINE_STYLE;
import static picocli.CommandLine.Help.Visibility.ALWAYS;

public abstract class SanitizeOrCaptureCommandBase implements CliCommand {

    static final String DOCKER_REGISTRY_OPTION = "--docker-registry";

    // to allow field injection from picocli, these variables can't be final

    @Option(names = {"-d", DOCKER_REGISTRY_OPTION}, description = "docker registry hostname for bootstrapping heap-dump-tool docker image")
    private String dockerRegistry;

    @Option(names = {"-a", "--tar-input"}, description = "Treat input as tar archive", arity = "1")
    private boolean tarInput;

    @Option(names = {"-e", "--exclude-string-fields"},
            description = "String fields to exclude from sanitization. Value in com.example.MyClass#fieldName format",
            defaultValue = "java.lang.Thread#name,java.lang.ThreadGroup#name",
            showDefaultValue = ALWAYS)
    private List<String> excludeStringFields;

    @Option(names = {"-f", "--force-string-coder-match"},
            description = "Force strings coder field to LATIN1 (0) when their backing byte[] is sanitized, so analysis tools render them correctly",
            defaultValue = "true",
            arity = "1",
            showDefaultValue = ALWAYS)
    // Suppose sanitizationText=*. If the coder value is not forced to match, the heap dump analyze tools like Eclipse
    // MAT might display escaped "\\u2A" (where 2A is ascii value) for Strings with coder==1. By forcing the coder value to
    // match, all strings would be displayed as "*"
    private boolean forceMatchStringCoder;

    @Mixin
    private SanitizeOptions sanitizeOptions = new SanitizeOptions();

    private StringFieldMap excludeStringFieldMap;

    @Option(names = {"-b", "--buffer-size"}, description = "Buffer size for reading and writing", defaultValue = "100MB", showDefaultValue = ALWAYS)
    private DataSize bufferSize = ofMegabytes(100);

    @Option(names = {"-s", "--sanitize-byte-char-arrays-only"},
            arity = "1",
            paramLabel = "<true|false>",
            description = "Deprecated. Use --sanitize-all, --sanitize-byte-arrays, and "
                    + "--sanitize-char-arrays instead")
    void setLegacySanitizeByteCharArraysOnly(final boolean byteCharArraysOnly) {
        sanitizeOptions.recordLegacyByteCharArraysOnly(byteCharArraysOnly);
    }

    @Option(names = {"-t", "--text"},
            paramLabel = "<text>",
            description = "Deprecated. Use --sanitize-all-replacement instead. "
                    + "Supports a single ASCII character only")
    void setLegacySanitizationText(final String text) {
        sanitizeOptions.recordLegacyText(text);
    }

    @Option(names = {"-T", "--text-charset"},
            paramLabel = "<charset>",
            description = "Deprecated and ignored. Replacement values are now typed per primitive")
    void setLegacySanitizationTextCharset(final String charset) {
        // deliberately not stored: the value is ignored, only warned about
        sanitizeOptions.recordLegacyTextCharset(charset);
    }

    public SanitizeOptions getSanitizeOptions() {
        return sanitizeOptions;
    }

    /**
     * Resolves the recorded flags on every call rather than memoizing. picocli parses the same
     * command object more than once per process ({@code PrivilegeEscalator} parses, then
     * {@code CommandLine.execute} parses again), and {@code copyFrom} can replace the recorded
     * directives afterwards, so a cached policy goes stale. {@code resolve()} is idempotent and
     * cheap, and it is called a handful of times per process.
     */
    public SanitizationPolicy getSanitizationPolicy() {
        return sanitizeOptions.resolve();
    }

    public void copyFrom(final SanitizeOrCaptureCommandBase other) {
        this.dockerRegistry = other.dockerRegistry;
        this.bufferSize = other.bufferSize;
        this.forceMatchStringCoder = other.forceMatchStringCoder;
        this.excludeStringFields = other.excludeStringFields;
        this.tarInput = other.tarInput;
        this.sanitizeOptions.copyFrom(other.sanitizeOptions);
    }

    public DataSize getBufferSize() {
        return bufferSize;
    }

    public void setBufferSize(final DataSize bufferSize) {
        this.bufferSize = bufferSize;
    }

    public boolean isTarInput() {
        return tarInput;
    }

    public void setTarInput(final boolean tarInput) {
        this.tarInput = tarInput;
    }

    public boolean isForceMatchStringCoder() {
        return forceMatchStringCoder;
    }

    public void setForceMatchStringCoder(final boolean forceMatchStringCoder) {
        this.forceMatchStringCoder = forceMatchStringCoder;
    }

    public List<String> getExcludeStringFields() {
        final List<String> list = excludeStringFields == null ? Collections.emptyList() : excludeStringFields;
        return list.stream()
                .map(StringUtils::trimToNull)
                .filter(Objects::nonNull)
                .filter(field -> field.contains("#"))
                .map(field -> field.split(","))
                .flatMap(Arrays::stream)
                .collect(Collectors.toList());
    }

    public void setExcludeStringFields(final List<String> list) {
        this.excludeStringFields = list;
    }

    private StringFieldMap getExcludeStringFieldMap() {
        if (excludeStringFieldMap != null) {
            return excludeStringFieldMap;
        }
        excludeStringFieldMap = new StringFieldMap();
        getExcludeStringFields().forEach(excludeStringFieldMap::add);
        return excludeStringFieldMap;
    }

    public boolean isExactClassWithExcludeStringField(final String className) {
        return getExcludeStringFieldMap().map.containsKey(className);
    }

    public List<String> getExcludeStringFields(final String className) {
        return getExcludeStringFieldMap().map.getOrDefault(className, Collections.emptyList());
    }

    @Override
    public String toString() {
        return reflectionToString(this, MULTI_LINE_STYLE);
    }

    private static class StringFieldMap {
        private final Map<String, List<String>> map = new HashMap<>();

        public void add(final String field) {
            final String className = StringUtils.substringBefore(field, "#");
            map.computeIfAbsent(className, key -> new ArrayList<>());
            map.get(className).add(StringUtils.substringAfter(field, "#"));
        }

        @Override
        public String toString() {
            return reflectionToString(this, MULTI_LINE_STYLE);
        }

    }
}
