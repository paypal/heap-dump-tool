package com.paypal.heapdumptool.sanitizer.example;

import java.lang.management.ManagementFactory;
import java.time.Instant;
import java.time.temporal.ChronoUnit;

// for manual testing.
// jcmd 186633 GC.heap_dump /tmp/heap.hprof
// java -jar heap-dump-tool.jar sanitize /tmp/heap.hprof /tmp/sanitize.hprof --sanitize-byte-char-arrays-only=false
// verify 0 primitive values
// verify non-null object refs
public class SimpleClass {

    private static final Long simpleStaticLong = System.currentTimeMillis();
    private final Long simpleInstanceLong = simpleStaticLong + 1;
    private final int simpleInstanceInt = (int) (long) simpleInstanceLong;

    private final Inner inner = new Inner();

    private static class Inner {
        private static final Long staticLong = System.currentTimeMillis();
        private final Long instanceLong = staticLong + 1;
        private final int instanceInt = (int) (long) instanceLong;
    }

    public static void main(final String... args) throws InterruptedException {
        final SimpleClass simpleClass = new SimpleClass();
        final String pid = ManagementFactory.getRuntimeMXBean().getName();
        while (!Thread.currentThread().isInterrupted()) {
            System.out.println("Running at " + Instant.now().truncatedTo(ChronoUnit.SECONDS) + " " + pid);

            if (simpleClass.simpleInstanceLong > 0) {
                Thread.sleep(1_000);
            }
        }
    }
}
