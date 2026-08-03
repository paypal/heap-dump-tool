/*
 * Copyright 2014-2025 Real Logic Limited.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.paypal.heapdumptool.utils;

import java.util.Arrays;

/**
 * An open-addressing with linear probing hash map specialised for primitive key and value pairs.
 *
 * <p>Vendored from Agrona (org.agrona.collections.Long2LongHashMap, Apache-2.0, copyright above)
 * rather than taken as a dependency: this tool ships as a fat jar and needs exactly one class from
 * that library. Reduced to the operations
 * {@link com.paypal.heapdumptool.sanitizer.HeapDumpSanitizer} uses, with Agrona's own annotations
 * and iterator/entry-set machinery removed, and reformatted to this project's style by spotless; the
 * hashing, probing and resize logic are unmodified.</p>
 *
 * <p>Chosen over a hand-rolled equivalent on measurement. Against the 3.66 mil real String-to-array
 * edges of the 1.2 GB sample dump it retains 128 MB, where a two-array-plus-occupancy-array version
 * retains 136 MB and a {@code HashMap<Long, Long>} retains 316 MB, all three at the same table
 * capacity and the primitive two within noise of each other on lookup throughput. The single
 * interleaved key/value array is what buys the 8 MB: a reserved {@code missingValue} encodes an empty
 * slot, so no separate occupancy array is needed.</p>
 */
public class Long2LongHashMap {
    static final int MIN_CAPACITY = 8;

    private final float loadFactor;
    private final long missingValue;
    private int resizeThreshold;
    private int size = 0;

    private long[] entries;

    /**
     * Create a map instance with a specified {@code missingValue} and default sizing.
     *
     * @param missingValue for the map that represents null.
     */
    public Long2LongHashMap(final long missingValue) {
        this(MIN_CAPACITY, Hashing.DEFAULT_LOAD_FACTOR, missingValue);
    }

    /**
     * Create a map instance with specified parameters.
     *
     * @param initialCapacity for the map to override {@link #MIN_CAPACITY}
     * @param loadFactor      for the map to override {@link Hashing#DEFAULT_LOAD_FACTOR}.
     * @param missingValue    for the map that represents null.
     */
    public Long2LongHashMap(final int initialCapacity, final float loadFactor, final long missingValue) {
        validateLoadFactor(loadFactor);

        this.loadFactor = loadFactor;
        this.missingValue = missingValue;

        capacity(findNextPositivePowerOfTwo(Math.max(MIN_CAPACITY, initialCapacity)));
    }

    static int findNextPositivePowerOfTwo(final int value) {
        return 1 << (Integer.SIZE - Integer.numberOfLeadingZeros(value - 1));
    }

    /**
     * Validate that a load factor is in the range of 0.1 to 0.9.
     * <p>
     * Load factors in the range 0.5 - 0.7 are recommended for open-addressing with linear probing.
     *
     * @param loadFactor to be validated.
     */
    public static void validateLoadFactor(final float loadFactor) {
        if (loadFactor < 0.1f || loadFactor > 0.9f) {
            throw new IllegalArgumentException("load factor must be in the range of 0.1 to 0.9: " + loadFactor);
        }
    }

    /**
     * Get the total capacity for the map to which the load factor will be a fraction of.
     *
     * @return the total capacity for the map.
     */
    public int capacity() {
        return entries.length >> 1;
    }

    /**
     * The number of key value pairs in the map.
     *
     * @return the number of key value pairs in the map.
     */
    public int size() {
        return size;
    }

    /**
     * Whether the map holds no entries.
     *
     * @return true if the map holds no entries.
     */
    public boolean isEmpty() {
        return 0 == size;
    }

    /**
     * Get a value using provided key avoiding boxing.
     *
     * @param key lookup key.
     * @return value associated with the key, or the reserved missing value if the key is absent.
     */
    public long get(final long key) {
        final long missingValue = this.missingValue;
        final long[] entries = this.entries;
        final int mask = entries.length - 1;
        int index = Hashing.evenHash(key, mask);

        long value;
        while (missingValue != (value = entries[index + 1])) {
            if (key == entries[index]) {
                break;
            }

            index = next(index, mask);
        }

        return value;
    }

    /**
     * Put a key value pair in the map.
     *
     * @param key   lookup key
     * @param value new value, must not be the reserved missing value
     * @return previous value associated with the key, or the reserved missing value if none found
     * @throws IllegalArgumentException if value is the reserved missing value
     */
    public long put(final long key, final long value) {
        final long missingValue = this.missingValue;
        if (missingValue == value) {
            throw new IllegalArgumentException("cannot accept missingValue");
        }

        final long[] entries = this.entries;
        final int mask = entries.length - 1;
        int index = Hashing.evenHash(key, mask);

        long oldValue;
        while (missingValue != (oldValue = entries[index + 1])) {
            if (key == entries[index]) {
                break;
            }

            index = next(index, mask);
        }

        if (missingValue == oldValue) {
            ++size;
            entries[index] = key;
        }

        entries[index + 1] = value;

        increaseCapacity();

        return oldValue;
    }

    private void increaseCapacity() {
        if (size > resizeThreshold) {
            // entries.length = 2 * capacity
            final int newCapacity = entries.length;
            rehash(newCapacity);
        }
    }

    private void rehash(final int newCapacity) {
        final long missingValue = this.missingValue;
        final long[] oldEntries = entries;
        final int length = oldEntries.length;

        capacity(newCapacity);

        final long[] newEntries = entries;
        final int mask = newEntries.length - 1;

        for (int valueIndex = 1; valueIndex < length; valueIndex += 2) {
            final long value = oldEntries[valueIndex];
            if (missingValue != value) {
                final long key = oldEntries[valueIndex - 1];
                int newKeyIndex = Hashing.evenHash(key, mask);

                while (missingValue != newEntries[newKeyIndex + 1]) {
                    newKeyIndex = next(newKeyIndex, mask);
                }

                newEntries[newKeyIndex] = key;
                newEntries[newKeyIndex + 1] = value;
            }
        }
    }

    /**
     * Long primitive specialised containsKey.
     *
     * @param key the key to check.
     * @return true if the map contains key as a key, false otherwise.
     */
    public boolean containsKey(final long key) {
        return missingValue != get(key);
    }

    private static int next(final int index, final int mask) {
        return (index + 2) & mask;
    }

    private void capacity(final int newCapacity) {
        final int entriesLength = newCapacity * 2;
        if (entriesLength < 0) {
            throw new IllegalStateException("max capacity reached at size=" + size);
        }

        resizeThreshold = (int) (newCapacity * loadFactor);
        entries = new long[entriesLength];
        Arrays.fill(entries, missingValue);
    }
}
