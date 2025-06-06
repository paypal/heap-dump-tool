package com.paypal.heapdumptool.utils;

import com.paypal.heapdumptool.sanitizer.DataSize;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.input.BoundedInputStream;
import org.apache.commons.io.output.CountingOutputStream;
import org.apache.commons.lang3.mutable.MutableLong;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UncheckedIOException;
import java.util.function.Consumer;

@FunctionalInterface
public interface ProgressMonitor extends Consumer<Long> {

    /**
     * Create a new {@link ProgressMonitor} that logs a message for each stepSize processed
     */
    static ProgressMonitor numBytesProcessedMonitor(final DataSize stepSize, final InternalLogger logger) {
        final long stepSizeBytes = stepSize.toBytes();
        final MutableLong steps = new MutableLong();

        return numBytesProcessed -> {
            final long currentSteps = numBytesProcessed / stepSizeBytes;
            if (currentSteps != steps.longValue()) {
                steps.setValue(currentSteps);
                logger.info("Processed {}", FileUtils.byteCountToDisplaySize(numBytesProcessed));
            }
        };
    }

    /**
     * Create a OutputStream monitored by this
     */
    default OutputStream monitoredOutputStream(final OutputStream output) {
        final ProgressMonitor monitor = this;
        return new CountingOutputStream(output) {

            @Override
            protected void beforeWrite(final int n) {
                super.beforeWrite(n);
                monitor.accept(getByteCount());
            }
        };
    }

    /**
     * Create a OutputStream monitored by this
     */
    @SuppressWarnings("deprecation")
    default InputStream monitoredInputStream(final InputStream input) {
        final ProgressMonitor monitor = this;
        return new BoundedInputStream(input) {

            @Override
            public void afterRead(final int n) {
                try {
                    super.afterRead(n);
                } catch (final IOException e) {
                    throw new UncheckedIOException(e);
                }
                monitor.accept(getCount());
            }
        };
    }

}
