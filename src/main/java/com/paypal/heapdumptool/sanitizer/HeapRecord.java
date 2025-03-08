package com.paypal.heapdumptool.sanitizer;

import java.util.Arrays;
import java.util.Map;
import java.util.Objects;
import java.util.function.Function;
import java.util.stream.Collectors;

public enum HeapRecord {

    STRING_IN_UTF8(0x01),
    LOAD_CLASS(0x02),
    UNLOAD_CLASS(0x03),
    STACK_FRAME(0x04),
    STACK_TRACE(0x05),
    ALLOC_SITES(0x06),
    HEAP_SUMMARY(0x07),
    START_THREAD(0x0A),
    END_THREAD(0x0B),
    HEAP_DUMP(0x0C),
    HEAP_DUMP_SEGMENT(0x1C),
    HEAP_DUMP_END(0x2C),
    CPU_SAMPLES(0x0D),
    CONTROL_SETTINGS(0x0E),
    ;

    private final int tag;

    private static final Map<Integer, HeapRecord> tagToHeapRecord = Arrays.stream(HeapRecord.values())
            .collect(Collectors.toMap(HeapRecord::getTag, Function.identity()));

    HeapRecord(final int tag) {
        this.tag = tag;
    }

    public int getTag() {
        return tag;
    }

    public static HeapRecord findByTag(final int tag) {
        final HeapRecord heapRecord = tagToHeapRecord.get(tag);
        Objects.requireNonNull(heapRecord);
        return heapRecord;
    }
}
