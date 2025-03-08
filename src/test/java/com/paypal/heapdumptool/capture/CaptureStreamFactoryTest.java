package com.paypal.heapdumptool.capture;

import com.paypal.heapdumptool.sanitizer.SanitizeCommand;
import org.apache.commons.io.IOUtils;
import org.apache.commons.io.output.CloseShieldOutputStream;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.Closeable;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Collection;
import java.util.concurrent.LinkedBlockingQueue;

import static com.paypal.heapdumptool.sanitizer.DataSize.ofBytes;
import static org.assertj.core.api.Assertions.assertThat;

class CaptureStreamFactoryTest {

    @TempDir
    Path tempDir;

    private final Collection<Closeable> closeables = new LinkedBlockingQueue<>();

    @AfterEach
    void afterEach() {
        closeables.forEach(IOUtils::closeQuietly);
    }

    @Test
    void testOutputStream() throws IOException {
        final CaptureStreamFactory streamFactory = newStreamFactory();
        assertThat(streamFactory.newOutputStream())
                .isInstanceOf(CloseShieldOutputStream.class);
        assertThat(streamFactory.getNativeOutputStream())
                .isInstanceOf(nioOutputStreamType());
    }

    private Class<?> nioOutputStreamType() throws IOException {
        final OutputStream nioOutputStream = Files.newOutputStream(tempDir.resolve("baz"));
        closeables.add(nioOutputStream);
        return nioOutputStream.getClass();
    }

    private CaptureStreamFactory newStreamFactory() {
        final SanitizeCommand command = new SanitizeCommand();
        command.setInputFile(tempDir.resolve("foo"));
        command.setOutputFile(tempDir.resolve("bar"));
        command.setBufferSize(ofBytes(0));

        final CaptureStreamFactory captureStreamFactory = new CaptureStreamFactory(command);
        closeables.add(captureStreamFactory);
        return captureStreamFactory;
    }
}
