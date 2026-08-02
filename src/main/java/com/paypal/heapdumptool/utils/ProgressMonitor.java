package com.paypal.heapdumptool.utils;

import org.apache.commons.io.output.CountingOutputStream;

import java.io.OutputStream;
import java.time.Clock;
import java.time.Duration;
import java.util.function.LongConsumer;

/**
 * Extends {@link LongConsumer} rather than {@code Consumer<Long>}: the monitored streams call this on
 * every single write, and boxing each count into a {@code Long} made it one of the largest allocation
 * sites in a profiled run. {@code LongConsumer.accept(long)} takes the count as a primitive.
 */
@FunctionalInterface
public interface ProgressMonitor extends LongConsumer {

    Duration DEFAULT_LOG_INTERVAL = Duration.ofSeconds(5);

    long UNKNOWN_TOTAL = -1;

    /**
     * Create a new {@link ProgressMonitor} that logs progress every {@link #DEFAULT_LOG_INTERVAL}.
     *
     * @param totalBytes the size of the input, for the ratio and the ETA, or {@link #UNKNOWN_TOTAL}
     *                   when it is not knowable
     */
    static ProgressMonitor numBytesProcessedMonitor(final long totalBytes, final InternalLogger logger) {
        return numBytesProcessedMonitor(totalBytes, DEFAULT_LOG_INTERVAL, Clock.systemUTC(), logger);
    }

    /**
     * As {@link #numBytesProcessedMonitor(long, InternalLogger)}, with the interval and the clock
     * injected so a test need not wait out real time.
     */
    static ProgressMonitor numBytesProcessedMonitor(final long totalBytes,
                                                    final Duration logInterval,
                                                    final Clock clock,
                                                    final InternalLogger logger) {
        return new NumBytesProcessedMonitor(totalBytes, logInterval, clock, logger);
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

}
