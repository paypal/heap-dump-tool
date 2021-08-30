package com.paypal.heapdumptool.capture;

import com.paypal.heapdumptool.sanitizer.SanitizeCommand;
import com.paypal.heapdumptool.sanitizer.SanitizeStreamFactory;
import org.apache.commons.io.output.CloseShieldOutputStream;

import java.io.Closeable;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Path;
import java.util.concurrent.atomic.AtomicReference;

import static java.util.Objects.requireNonNull;
import static org.apache.commons.compress.utils.IOUtils.closeQuietly;

public class CaptureStreamFactory extends SanitizeStreamFactory implements Closeable {

    private final AtomicReference<InputStream> inputStreamRef;
    private final AtomicReference<OutputStream> outputStreamRef;

    public CaptureStreamFactory(final SanitizeCommand command, final InputStream inputStream) {
        super(command);
        this.inputStreamRef = new AtomicReference<>(inputStream);
        this.outputStreamRef = new AtomicReference<>();
    }

    @Override
    protected InputStream newInputStream(final Path ignored) {
        return requireNonNull(inputStreamRef.getAndSet(null));
    }

    @Override
    public OutputStream newOutputStream() throws IOException {
        final OutputStream stream = super.newOutputStream();
        outputStreamRef.compareAndSet(null, stream);
        return CloseShieldOutputStream.wrap(stream);
    }

    public OutputStream getNativeOutputStream() {
        return outputStreamRef.get();
    }

    @Override
    public void close() {
        closeQuietly(getNativeOutputStream());
    }

}
