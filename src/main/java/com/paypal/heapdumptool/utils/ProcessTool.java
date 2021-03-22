package com.paypal.heapdumptool.utils;

import org.apache.commons.io.IOUtils;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.Future;

import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Collections.unmodifiableList;
import static java.util.concurrent.CompletableFuture.supplyAsync;

/**
 * Convenience tool for running os processes
 */
public class ProcessTool {

    // for mocking
    public static ProcessBuilder processBuilder(final String... cmd) {
        return new ProcessBuilder(cmd);
    }

    public static ProcessResult run(final String... cmd) throws Exception {
        final Process process = processBuilder(cmd).start();
        try {
            process.getOutputStream().close();

            final InputStream stderrStream = process.getErrorStream();
            final InputStream stdoutStream = process.getInputStream();

            final Future<String> stderrFuture = supplyAsync(() -> readStream(stderrStream));
            final Future<String> stdoutFuture = supplyAsync(() -> readStream(stdoutStream));

            final int exitCode = process.waitFor();
            return new ProcessResult(exitCode, stdoutFuture.get(), stderrFuture.get());
        } finally {
            process.destroy();
        }
    }

    static String readStream(final InputStream stream) {
        try {
            return IOUtils.toString(stream, UTF_8);
        } catch (final IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private ProcessTool() {
        throw new AssertionError();
    }

    public static class ProcessResult {

        public final int exitCode;
        public final String stdout;
        public final String stderr;

        public ProcessResult(final int exitCode, final String stdout, final String stderr) {
            this.exitCode = exitCode;
            this.stdout = stdout;
            this.stderr = stderr;
        }

        public List<String> stdoutLines() {
            return unmodifiableList(Arrays.asList(stdout.split("\n")));
        }
    }

}
