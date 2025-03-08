package com.paypal.heapdumptool.capture;

import com.paypal.heapdumptool.sanitizer.SanitizeCommand;
import com.paypal.heapdumptool.sanitizer.SanitizeStreamFactory;
import org.apache.commons.io.output.CloseShieldOutputStream;

import java.io.Closeable;
import java.io.IOException;
import java.io.OutputStream;
import java.util.concurrent.atomic.AtomicReference;

import static org.apache.commons.io.IOUtils.closeQuietly;

public class CaptureStreamFactory extends SanitizeStreamFactory implements Closeable {

    private final AtomicReference<OutputStream> outputStreamRef;

    public CaptureStreamFactory(final SanitizeCommand command) {
        super(command);
        this.outputStreamRef = new AtomicReference<>();
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
