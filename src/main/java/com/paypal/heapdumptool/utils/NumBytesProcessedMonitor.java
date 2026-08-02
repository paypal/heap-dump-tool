package com.paypal.heapdumptool.utils;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;

import static com.paypal.heapdumptool.utils.DateTimeTool.getFriendlyDuration;

/**
 * Logs how far along the run is, on a time interval: {@code Processed 2.30 GB / 4.66 GB (ETA 1m20s)}.
 *
 * <p>Each figure is shown in the largest unit it is not a fraction of, so the two sides of the ratio may
 * differ: {@code Processed 512.00 MB / 4.00 GB}.</p>
 *
 * <p>The total is not always knowable -- a dump piped in on stdin has no size -- in which case only the
 * processed count is logged, with no ratio and no ETA.</p>
 */
class NumBytesProcessedMonitor implements ProgressMonitor {

    /*
     * How many times the clock is read per log interval. The gate below exists because accept() is called
     * on every single write of the run -- tens of millions of times on a large dump -- and asking the
     * clock that often costs measurable time, plus an Instant per reading, for an answer that cannot have
     * changed. Reading it a handful of times per interval is enough to notice the interval elapsing while
     * leaving all but a few of those millions of calls a single long compare.
     *
     * Ten, so a log line lands within about a tenth of an interval of when it is due, at ten readings per
     * interval rather than one per write.
     */
    private static final int CLOCK_CHECKS_PER_INTERVAL = 10;

    /*
     * The step to use before there is a rate to derive one from: a thousandth of the input, and at most a
     * megabyte. Deliberately finer than the tuned step, because it only has to last until the first clock
     * reading -- too fine costs a few extra readings at the very start, too coarse delays the first log
     * line on a small or slow input, which is the case the gate must not silence.
     *
     * A dump arriving on stdin has no size to take a thousandth of, so it gets the cap. That is no
     * hardship: a dump is not small, whatever it arrives on.
     */
    private static final int INITIAL_CLOCK_CHECKS_PER_RUN = 1000;
    private static final long MAX_INITIAL_CLOCK_CHECK_INTERVAL_BYTES = 1024 * 1024;

    private final long totalBytes;
    private final Duration logInterval;
    private final Clock clock;
    private final InternalLogger logger;
    private final Instant startTime;

    /*
     * Bytes of progress between consecutive readings of the clock, re-derived from the observed rate at
     * every reading: whatever the run's throughput turns out to be, the next reading is due a tenth of an
     * interval's worth of bytes from now. A fixed step cannot do that -- scaled off the total it ties the
     * reading count to the size of the dump instead of to its duration, which is what the interval is
     * measured in, and it has no answer at all for an input whose size is unknown.
     */
    private long clockCheckIntervalBytes;

    private long nextClockCheckBytes;
    private Instant nextLogTime;

    NumBytesProcessedMonitor(final long totalBytes,
                             final Duration logInterval,
                             final Clock clock,
                             final InternalLogger logger) {
        this.totalBytes = totalBytes;
        this.logInterval = logInterval;
        this.clock = clock;
        this.logger = logger;
        this.startTime = clock.instant();

        this.clockCheckIntervalBytes = totalBytes > 0
                                       ? Math.max(1, Math.min(MAX_INITIAL_CLOCK_CHECK_INTERVAL_BYTES,
                                                              totalBytes / INITIAL_CLOCK_CHECKS_PER_RUN))
                                       : MAX_INITIAL_CLOCK_CHECK_INTERVAL_BYTES;
        this.nextClockCheckBytes = clockCheckIntervalBytes;
        this.nextLogTime = startTime.plus(logInterval);
    }

    @Override
    public void accept(final long numBytesProcessed) {
        if (numBytesProcessed < nextClockCheckBytes) {
            return;
        }
        final Instant now = clock.instant();

        retuneClockCheckInterval(numBytesProcessed, now);
        nextClockCheckBytes = numBytesProcessed + clockCheckIntervalBytes;

        if (now.isBefore(nextLogTime)) {
            return;
        }
        /*
         * From now rather than from the previous deadline: a run whose writes pause for a while should
         * not then log several times in a row catching up on intervals nothing happened in.
         */
        nextLogTime = now.plus(logInterval);

        logger.info("Processed {}", describeProgress(numBytesProcessed, now));
    }

    /*
     * Sets the step to the bytes this run gets through in a tenth of an interval, from the average rate so
     * far -- the same rate the ETA extrapolates from, and stable for the same reason: both passes stream
     * the file start to finish.
     *
     * A slow run therefore reads the clock no more often than a fast one, and the millions of accept()
     * calls in between stay a single long compare. A run that then slows down overshoots by at most the
     * step it had at the old rate, which is a fraction of an interval, and the next reading corrects it.
     */
    private void retuneClockCheckInterval(final long numBytesProcessed, final Instant now) {
        final long elapsedMillis = Duration.between(startTime, now).toMillis();
        if (elapsedMillis <= 0) {
            // no rate yet, or a wall clock stepped backwards: keep the step until a later reading has one
            return;
        }
        final long bytesPerInterval = numBytesProcessed * logInterval.toMillis() / elapsedMillis;

        // at least one byte, so the gate cannot stop letting readings through and stall the logging
        clockCheckIntervalBytes = Math.max(1, bytesPerInterval / CLOCK_CHECKS_PER_INTERVAL);
    }

    private String describeProgress(final long numBytesProcessed, final Instant now) {
        if (totalBytes <= 0) {
            return FileTool.displaySize(numBytesProcessed);
        }
        return FileTool.displaySize(numBytesProcessed)
                + " / " + FileTool.displaySize(totalBytes)
                + " (ETA " + describeEta(numBytesProcessed, now) + ")";
    }

    /*
     * Extrapolates from the average rate so far. Deliberately not a windowed rate: the two passes each
     * stream the file start to finish, so the average is stable, whereas a recent-window estimate swings
     * with whatever record type happens to be under the cursor.
     */
    private String describeEta(final long numBytesProcessed, final Instant now) {
        /*
         * Positive: this is only reached once now has passed a deadline of startTime plus one interval.
         * Which is also what a wall clock stepped backwards by an adjustment does here -- not a negative
         * elapsed time, just no progress line until the clock has caught back up to that deadline.
         */
        final Duration elapsed = Duration.between(startTime, now);

        /*
         * Clamped at zero because the total can be an over- or under-estimate: with --tar-input it is the
         * size of the archive, of which the dump inside is all but a few hundred bytes of header.
         */
        final long remainingBytes = Math.max(0, totalBytes - numBytesProcessed);

        /*
         * elapsed * remaining / processed, in that order, would overflow in nanoseconds on any sizeable
         * dump; Duration does the arithmetic in BigDecimal, so it neither overflows nor loses the
         * precision a double would. The divisor is at least 1: accept() only reaches here past a
         * clock-check threshold of at least one byte.
         */
        final Duration remainingTime = elapsed.multipliedBy(remainingBytes)
                                              .dividedBy(numBytesProcessed);

        return getFriendlyDuration(remainingTime);
    }
}
