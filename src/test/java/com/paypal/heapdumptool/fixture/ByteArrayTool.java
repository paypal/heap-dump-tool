package com.paypal.heapdumptool.fixture;

import com.paypal.heapdumptool.sanitizer.DataSize;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public class ByteArrayTool {

    public static int countOfSequence(final byte[] big, final byte[] small) {
        int count = 0;
        for (int i = 0; i < big.length; i++) {
            if (startsWith(big, i, small)) {
                count++;
                i = i + small.length - 2;
            }
        }
        return count;
    }

    public static boolean startsWith(final byte[] big, final int bigIndex, final byte[] small) {
        int count = 0;
        for (int i = bigIndex, j = 0; i < big.length && j < small.length; i++, j++) {
            if (big[i] == small[j]) {
                count++;
            }
        }
        return count == small.length;
    }

    public static byte[] lengthen(final byte[] input, final DataSize wantedDataSize) {
        return Arrays.copyOf(input, (int) wantedDataSize.toBytes());
    }

    public static String lengthen(final String input, final DataSize wantedDataSize) {
        final byte[] currentBytes = input.getBytes(StandardCharsets.UTF_8);
        final byte[] newBytes = lengthen(currentBytes, wantedDataSize);
        return new String(newBytes, StandardCharsets.UTF_8);
    }

    public static byte[] nCopiesLongToBytes(final long value, final int count) {
        final ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES * count);
        for (int i = 0; i < count; i++) {
            buffer.putLong(value);
        }
        return buffer.array();
    }

    private ByteArrayTool() {
        throw new AssertionError();
    }
}
