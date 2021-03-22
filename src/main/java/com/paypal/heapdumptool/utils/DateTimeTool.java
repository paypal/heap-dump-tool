package com.paypal.heapdumptool.utils;

import java.time.Duration;
import java.time.Instant;

import static java.time.temporal.ChronoUnit.SECONDS;
import static java.util.Locale.ENGLISH;

public class DateTimeTool {

    public static String getFriendlyDuration(final Instant start) {
        final Instant startSeconds = start.truncatedTo(SECONDS);
        final Instant endSeconds = Instant.now().truncatedTo(SECONDS);

        final Duration duration = Duration.between(startSeconds, endSeconds);
        return duration.toString()
                       .substring(2)
                       .toLowerCase(ENGLISH);
    }

    private DateTimeTool() {
        throw new AssertionError();
    }
}
