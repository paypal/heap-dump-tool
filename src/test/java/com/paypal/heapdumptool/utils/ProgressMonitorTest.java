package com.paypal.heapdumptool.utils;

import org.apache.commons.io.IOUtils;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;

import static com.paypal.heapdumptool.utils.ProgressMonitor.UNKNOWN_TOTAL;
import static com.paypal.heapdumptool.utils.ProgressMonitor.numBytesProcessedMonitor;
import static java.nio.charset.StandardCharsets.UTF_8;
import static java.time.ZoneOffset.UTC;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.withinPercentage;
import static org.mockito.Mockito.*;

@ExtendWith(OutputCaptureExtension.class)
public class ProgressMonitorTest {

    private static final InternalLogger LOGGER = InternalLogger.getLogger(ProgressMonitorTest.class);

    private static final Duration INTERVAL = Duration.ofSeconds(5);

    private static final long GB = 1024L * 1024 * 1024;

    private Instant now = Instant.EPOCH;

    /**
     * Readings taken, which is what the byte gate in accept() exists to keep down.
     */
    private int clockReads;

    /**
     * A clock the test advances by hand, so a 5s log interval costs no wall time.
     */
    private final Clock clock = new Clock() {

        @Override
        public Instant instant() {
            clockReads++;
            return now;
        }

        @Override
        public ZoneId getZone() {
            return UTC;
        }

        @Override
        public Clock withZone(final ZoneId zone) {
            return this;
        }
    };

    private void advanceSeconds(final long seconds) {
        now = now.plusSeconds(seconds);
    }

    @Test
    @DisplayName("testLogsOnTheTimeInterval. progress is logged per interval elapsed, not per byte step")
    public void testLogsOnTheTimeInterval(final CapturedOutput output) {
        final ProgressMonitor monitor = numBytesProcessedMonitor(100 * GB, INTERVAL, clock, LOGGER);

        // any number of bytes inside the interval logs nothing
        monitor.accept(10 * GB);
        monitor.accept(20 * GB);
        assertThat(output).isEmpty();

        advanceSeconds(5);
        monitor.accept(30 * GB);
        assertThat(output).hasLineCount(1);

        // and having just logged, it goes quiet again until the next interval
        monitor.accept(40 * GB);
        assertThat(output).hasLineCount(1);

        advanceSeconds(5);
        monitor.accept(50 * GB);
        assertThat(output).hasLineCount(2);
    }

    /**
     * The step between clock readings is re-derived from the observed rate, so how often the clock is read
     * follows the interval rather than the size of the input: a run is written in a fixed number of
     * readings per interval however fast it goes, and one twice as fast reads it no more often.
     *
     * <p>Simulated here by feeding the same 10s of run at two rates. A step fixed as a fraction of the
     * total, which is what this replaced, would read the clock the same number of times in both -- tying
     * the count to a size when the thing being measured is a duration.</p>
     */
    @Test
    @DisplayName("testClockReadsFollowTheIntervalNotTheInputSize. rate doubles, readings do not")
    public void testClockReadsFollowTheIntervalNotTheInputSize() {
        final int readsAtOneRate = countClockReadsOverTenSeconds(GB);
        final int readsAtDoubleRate = countClockReadsOverTenSeconds(2 * GB);

        // 10s at 10 readings per 5s interval, plus the readings before the first rate is known
        assertThat(readsAtOneRate).isBetween(20, 40);
        assertThat(readsAtDoubleRate).isCloseTo(readsAtOneRate, withinPercentage(25));
    }

    /**
     * Drives 10s of a run that gets through {@code bytesPerSecond} a second, in writes small enough that
     * the gate, not the write size, decides when the clock is read.
     */
    private int countClockReadsOverTenSeconds(final long bytesPerSecond) {
        clockReads = 0;
        now = Instant.EPOCH;

        final long writeSize = bytesPerSecond / 1000;
        final ProgressMonitor monitor = numBytesProcessedMonitor(100 * GB, INTERVAL, clock, LOGGER);
        for (int millis = 1; millis <= 10_000; millis++) {
            now = Instant.EPOCH.plusMillis(millis);
            monitor.accept(writeSize * millis);
        }
        return clockReads;
    }

    @Test
    @DisplayName("testLogsProcessedOfTotalWithEta. the ratio and the ETA, to 2 decimals")
    public void testLogsProcessedOfTotalWithEta(final CapturedOutput output) {
        final ProgressMonitor monitor = numBytesProcessedMonitor(100 * GB, INTERVAL, clock, LOGGER);

        // 25 GB in 10s, so the remaining 75 GB should take 30s
        advanceSeconds(10);
        monitor.accept(25 * GB);

        assertThat(output).contains("Processed 25.00 GB / 100.00 GB (ETA 30s)");
    }

    /**
     * Each side of the ratio is scaled on its own, so a value under 1 GB reads as MB instead of as a
     * fraction of a GB. The two units therefore differ whenever the run is early on a large dump.
     */
    @Test
    @DisplayName("testUnderOneUnitStepsDownToTheSmallerUnit. 512 MB of a 4 GB total is MB, not 0.50 GB")
    public void testUnderOneUnitStepsDownToTheSmallerUnit(final CapturedOutput output) {
        final ProgressMonitor monitor = numBytesProcessedMonitor(4 * GB, INTERVAL, clock, LOGGER);

        advanceSeconds(5);
        monitor.accept(512 * 1024 * 1024);

        assertThat(output).contains("Processed 512.00 MB / 4.00 GB (ETA ");
    }

    @Test
    @DisplayName("testUnitsScaleWithMagnitude. MB/GB/TB chosen per figure")
    public void testUnitsScaleWithMagnitude(final CapturedOutput output) {
        final ProgressMonitor mb = numBytesProcessedMonitor(500 * 1024 * 1024, INTERVAL, clock, LOGGER);
        advanceSeconds(5);
        mb.accept(250 * 1024 * 1024);
        assertThat(output).contains("Processed 250.00 MB / 500.00 MB");

        final ProgressMonitor tb = numBytesProcessedMonitor(3 * 1024 * GB, INTERVAL, clock, LOGGER);
        advanceSeconds(5);
        tb.accept(1024 * GB + 512 * GB);
        assertThat(output).contains("Processed 1.50 TB / 3.00 TB");
    }

    /**
     * The same step-down at the bottom of the scale, where "bytes" has no fractional form at all.
     */
    @Test
    @DisplayName("testSmallFiguresStepDownToKilobytesAndBytes. a tiny input is not 0.00 MB")
    public void testSmallFiguresStepDownToKilobytesAndBytes(final CapturedOutput output) {
        final ProgressMonitor monitor = numBytesProcessedMonitor(64 * 1024, INTERVAL, clock, LOGGER);

        advanceSeconds(5);
        monitor.accept(900);

        assertThat(output).contains("Processed 900 bytes / 64.00 KB");
    }

    @Test
    @DisplayName("testUnknownTotalLogsProcessedOnly. no size means no ratio and no ETA, not a wrong one")
    public void testUnknownTotalLogsProcessedOnly(final CapturedOutput output) {
        final ProgressMonitor monitor = numBytesProcessedMonitor(UNKNOWN_TOTAL, INTERVAL, clock, LOGGER);

        advanceSeconds(5);
        monitor.accept(2 * GB + 512 * 1024 * 1024);

        assertThat(output)
                .contains("Processed 2.50 GB")
                .doesNotContain("ETA")
                .doesNotContain(" / ");
    }

    /**
     * The tar total is the archive's size, slightly larger than the dump inside, so the last stretch of
     * the run reports more processed than the total. It must not produce a negative ETA.
     */
    @Test
    @DisplayName("testProcessedPastTheTotalReportsNoTimeLeft. an over-estimated total cannot go negative")
    public void testProcessedPastTheTotalReportsNoTimeLeft(final CapturedOutput output) {
        final ProgressMonitor monitor = numBytesProcessedMonitor(GB, INTERVAL, clock, LOGGER);

        advanceSeconds(5);
        monitor.accept(GB + 4096);

        assertThat(output).contains("(ETA 0s)");
    }

    /**
     * The byte gate that keeps accept() off the clock also means a zero-byte reading never reaches the
     * log, so the ETA always has a rate to extrapolate from. Pinned here because describeEta divides by
     * the processed count.
     */
    @Test
    @DisplayName("testNoProgressLogsNothing. a reading of zero bytes cannot reach the ETA calculation")
    public void testNoProgressLogsNothing(final CapturedOutput output) {
        final ProgressMonitor monitor = numBytesProcessedMonitor(GB, INTERVAL, clock, LOGGER);

        advanceSeconds(60);
        monitor.accept(0);

        assertThat(output).isEmpty();
    }

    @Test
    public void testMonitoredOutputStream() throws IOException {

        final ProgressMonitor monitor = mock(ProgressMonitor.class);

        final OutputStream outputStream = new ByteArrayOutputStream();
        doCallRealMethod().when(monitor).monitoredOutputStream(outputStream);

        final OutputStream monitoredOutputStream = monitor.monitoredOutputStream(outputStream);
        IOUtils.write("world", monitoredOutputStream, UTF_8);

        verify(monitor).accept((long) "world".length());
    }
}
