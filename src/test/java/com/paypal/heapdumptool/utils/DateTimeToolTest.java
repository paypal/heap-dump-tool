package com.paypal.heapdumptool.utils;

import org.junit.jupiter.api.Test;

import java.time.Instant;

import static com.paypal.heapdumptool.utils.DateTimeTool.getFriendlyDuration;
import static org.assertj.core.api.Assertions.assertThat;

public class DateTimeToolTest {

    @Test
    public void testFriendlyDuration() {
        final Instant start = Instant.now().minusSeconds(65);

        assertThat(getFriendlyDuration(start))
                .satisfiesAnyOf(display -> assertThat(display).isEqualTo("1m5s"),
                                display -> assertThat(display).isEqualTo("1m6s"));
    }

}
