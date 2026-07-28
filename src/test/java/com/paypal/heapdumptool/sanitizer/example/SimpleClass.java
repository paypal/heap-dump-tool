package com.paypal.heapdumptool.sanitizer.example;

import java.lang.management.ManagementFactory;
import java.lang.management.RuntimeMXBean;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;

// for manual testing.
// java -jar heap-dump-tool.jar sanitize /tmp/heap.hprof /tmp/sanitize.hprof --sanitize-byte-char-arrays-only=false
// verify 0 primitive values
// verify non-null object refs
@SuppressWarnings("unused")
public class SimpleClass {

    private static final Long simpleStaticLong = System.currentTimeMillis();
    private final Long simpleInstanceLong = simpleStaticLong + 1;
    private final int simpleInstanceInt = (int) (long) simpleInstanceLong;
    private final boolean trueBoolean = true;
    private final boolean falseBoolean = false;
    private final byte[] byteArray = new byte[]{1, 2, 3};
    private final char[] charArray = new char[]{'a', 'b', 'c'};
    private final String asciiString = new String(charArray);
    private final String utf8String = new String(charArray) + "\uD83D\uDE00";

    @SuppressWarnings("all")
    private final int[] largeIntArray = new int[1024];

    {
        Arrays.fill(largeIntArray, 123);
    }

    private final Inner inner = new Inner();

    private static class Inner {
        private static final Long staticLong = System.currentTimeMillis();
        private final Long instanceLong = staticLong + 1;
        private final int instanceInt = (int) (long) instanceLong;
    }

    public static void main(final String... args) throws Exception {
        final SimpleClass simpleClass = new SimpleClass();
        final RuntimeMXBean runtime = ManagementFactory.getRuntimeMXBean();
        final String pid = runtime.getName().replaceAll("@.+", "");
        final String javaVersion = runtime.getSpecVersion();

        System.out.println("Created SimpleClass: " + simpleClass);
        System.out.println("Java version: " + javaVersion);
        System.out.println("Running at " + Instant.now().truncatedTo(ChronoUnit.SECONDS) + " " + pid);

        final Path heapDumpFile = Paths.get("/tmp/heap-dump-tool/heap-" + javaVersion + ".hprof");
        Files.createDirectories(heapDumpFile.getParent());
        Files.deleteIfExists(heapDumpFile);
        System.out.println("Creating heap dump file: " + heapDumpFile);
        Runtime.getRuntime().exec(new String[]{"jcmd", pid, "GC.heap_dump", heapDumpFile.toString()})
                .waitFor();
        System.out.println("OK");
    }
}
