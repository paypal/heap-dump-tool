package com.paypal.heapdumptool.utils;

import java.time.Duration;
import java.time.Instant;

import static java.time.temporal.ChronoUnit.SECONDS;
import static java.util.Locale.ENGLISH;

public class DateTimeTool {

    public static String getFriendlyDuration(final Instant start) {
        final Instant startSeconds = start.truncatedTo(SECONDS);
        final Instant endSeconds = Instant.now().truncatedTo(SECONDS);

        return getFriendlyDuration(Duration.between(startSeconds, endSeconds));
    }

    /**
     * Renders a duration the way ISO-8601 writes it, less the {@code PT} prefix and in lower case:
     * {@code 1m5s}, {@code 45s}, {@code 2h3m4s}.
     */
    public static String getFriendlyDuration(final Duration duration) {
        final Duration truncatedDuration = Duration.ofSeconds(duration.getSeconds());
        return truncatedDuration.toString()
                       .substring(2)
                       .toLowerCase(ENGLISH);
    }

    private DateTimeTool() {
        throw new AssertionError();
    }
}
