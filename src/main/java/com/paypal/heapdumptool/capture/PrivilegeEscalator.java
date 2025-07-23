package com.paypal.heapdumptool.capture;

import com.paypal.heapdumptool.utils.ProcessTool;
import com.paypal.heapdumptool.utils.ProcessTool.ProcessResult;
import org.apache.commons.lang3.RuntimeEnvironment;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.text.StringSubstitutor;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.Callable;
import java.util.stream.Stream;

import static com.paypal.heapdumptool.capture.CaptureCommand.DOCKER_REGISTRY_OPTION;
import static com.paypal.heapdumptool.capture.CaptureCommand.SKIP_DOCKER_PULL;
import static com.paypal.heapdumptool.capture.PrivilegeEscalator.Escalation.ESCALATED;
import static com.paypal.heapdumptool.capture.PrivilegeEscalator.Escalation.PRIVILEGED_ALREADY;
import static com.paypal.heapdumptool.utils.CallableTool.callQuietlyWithDefault;
import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.stream.Collectors.joining;
import static org.apache.commons.io.IOUtils.resourceToString;

/**
 * Makes it possible to run docker inside docker. Prints a "docker run" command which the user can execute so that the container
 * has the right flags (--privileged and --pid) set.
 */
public class PrivilegeEscalator {

    public static final String DEFAULT_REGISTRY = System.getProperty("hdt.default-registry", "index.docker.io");
    public static final String IMAGE_NAME = System.getProperty("hdt.image-name", "heapdumptool/heapdumptool");
    private static final String DOCKER = "docker";

    public static Escalation escalatePrivilegesIfNeeded(final String... args) throws Exception {
        if (!isInDockerContainer() || isLikelyPrivileged()) {
            return PRIVILEGED_ALREADY;
        }

        final String shellTemplate = resourceToString("/privilege-escalate.sh.tmpl", UTF_8);
        final Map<String, String> templateParams = buildTemplateParams(args);

        final String shellCode = StringSubstitutor.replace(shellTemplate, templateParams, "__", "__");
        println(shellCode);
        return ESCALATED;
    }

    public enum Escalation {
        ESCALATED,
        PRIVILEGED_ALREADY
    }

    public static boolean isInDockerContainer() {
        return RuntimeEnvironment.inContainer();
    }

    // yes, print directly to stdout (bypassing SysOutOverSLF4J or other logger decorations)
    static void println(final String str) {
        System.out.println(str);
    }

    private static boolean isLikelyPrivileged() {
        final Callable<Boolean> canRunDockerInsideDocker = () -> {
            final Path nsenter1 = Paths.get("nsenter1");
            final ProcessResult result = ProcessTool.run(nsenter1.toString(), DOCKER);
            return result.exitCode == 0;
        };
        return callQuietlyWithDefault(false, canRunDockerInsideDocker);
    }

    private static Map<String, String> buildTemplateParams(final String... args) {
        final String quotedArgs = Stream.of(args)
                                        .map(PrivilegeEscalator::quoteIfNeeded)
                                        .collect(joining(" "));

        final Optional<String> forcedDockerRegistry = findForcedDockerRegistry(args);
        final String defaultRegistry = forcedDockerRegistry.orElse(DEFAULT_REGISTRY);

        final String dockerRegistryEnvName = forcedDockerRegistry.isPresent()
                ? "FORCED_DOCKER_REGISTRY"
                : "DOCKER_REGISTRY";

        final boolean skipDockerPull = Arrays.asList(args).contains(SKIP_DOCKER_PULL);

        final Map<String, String> params = new HashMap<>();
        params.put("IMAGE_NAME", IMAGE_NAME);
        params.put("ARGS", quotedArgs);
        params.put("DEFAULT_REGISTRY", defaultRegistry);
        params.put("DOCKER_REGISTRY_ENV_NAME", dockerRegistryEnvName);
        params.put("SKIP_DOCKER_PULL", Boolean.toString(skipDockerPull));

        return params;
    }

    private static Optional<String> findForcedDockerRegistry(final String... args) {
        String forcedDockerRegistry = null;
        for (int i = 0; i < args.length; i++) {
            final String arg = args[i];

            if (arg.startsWith(DOCKER_REGISTRY_OPTION)) {
                if (arg.contains("=")) {
                    forcedDockerRegistry = StringUtils.substringAfterLast(arg, "=");
                    break;
                }

                if (i < args.length - 1) {
                    forcedDockerRegistry = args[i + 1];
                    break;
                }

                throw new IllegalArgumentException("Cannot find argument value for " + DOCKER_REGISTRY_OPTION);
            }
        }
        return Optional.ofNullable(forcedDockerRegistry);
    }

    private static String quoteIfNeeded(final String str) {
        return str.contains(" ")
                ? "\"" + str + "\""
                : str;
    }

    private PrivilegeEscalator() {
        throw new AssertionError();
    }
}
