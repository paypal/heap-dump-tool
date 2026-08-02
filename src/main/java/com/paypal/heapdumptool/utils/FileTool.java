package com.paypal.heapdumptool.utils;

import org.apache.commons.io.FileUtils;

public class FileTool {

    /**
     * Human-readable size formatted to 2 decimal places in the largest fitting unit
     * (e.g. "4.87 GB", "858.34 MB"). Raw bytes below 1 KB are shown as a whole count,
     * since fractional bytes are meaningless.
     */
    public static String displaySize(final long bytes) {
        if (bytes >= FileUtils.ONE_TB) {
            return String.format("%.2f TB", (double) bytes / FileUtils.ONE_TB);
        }
        if (bytes >= FileUtils.ONE_GB) {
            return String.format("%.2f GB", (double) bytes / FileUtils.ONE_GB);
        }
        if (bytes >= FileUtils.ONE_MB) {
            return String.format("%.2f MB", (double) bytes / FileUtils.ONE_MB);
        }
        if (bytes >= FileUtils.ONE_KB) {
            return String.format("%.2f KB", (double) bytes / FileUtils.ONE_KB);
        }
        return bytes + " bytes";
    }
}
