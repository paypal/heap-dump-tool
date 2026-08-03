package com.paypal.heapdumptool.utils;

import java.util.HashMap;
import java.util.Map;
import java.util.Random;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Covers the behavior {@link com.paypal.heapdumptool.sanitizer.HeapDumpSanitizer} relies on from the
 * vendored map, rather than re-testing Agrona's own class wholesale: that the reserved
 * {@code missingValue} is distinguishable from every id a dump can contain, that 0 works as an
 * ordinary key and value, and that heap-address-shaped keys neither collide pathologically nor get
 * lost across a rehash.
 */
class Long2LongHashMapTest {

    /**
     * The same sentinel the sanitizer uses. Object ids are addresses and {@code Pipe.pipeId()}
     * rejects anything negative, so no real id can collide with it.
     */
    private static final long MISSING = Long.MIN_VALUE;

    @Test
    @DisplayName("testPutAndGet. a stored value comes back and an absent key reads as missing")
    void testPutAndGet() {
        final Long2LongHashMap map = new Long2LongHashMap(MISSING);

        map.put(42, 4242);

        assertThat(map.get(42)).isEqualTo(4242);
        assertThat(map.containsKey(42)).isTrue();
        assertThat(map.get(43)).isEqualTo(MISSING);
        assertThat(map.containsKey(43)).isFalse();
        assertThat(map.size()).isEqualTo(1);
    }

    /**
     * 0 is a real heap dump object id, meaning null, so it has to work as both a key and a value
     * while still being distinguishable from absence. This is why the sentinel is not 0.
     */
    @Test
    @DisplayName("testZeroIsAnOrdinaryKeyAndValue. zero must not read as missing")
    void testZeroIsAnOrdinaryKeyAndValue() {
        final Long2LongHashMap map = new Long2LongHashMap(MISSING);

        assertThat(map.containsKey(0)).as("nothing stored yet").isFalse();

        map.put(0, 0);

        assertThat(map.containsKey(0)).isTrue();
        assertThat(map.get(0)).isZero();
        assertThat(map.size()).isEqualTo(1);
    }

    /**
     * The one constraint the sentinel imposes on callers. Nothing in the sanitizer can hit it -- a
     * value is always an id read through {@code pipeId()}, which rejects negatives -- but a future
     * caller that picked a reachable sentinel would fail loudly here rather than silently lose the
     * entry.
     */
    @Test
    @DisplayName("testStoringTheMissingValueIsRejected. the reserved value may not be stored")
    void testStoringTheMissingValueIsRejected() {
        final Long2LongHashMap map = new Long2LongHashMap(MISSING);

        assertThatThrownBy(() -> map.put(1, MISSING))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("missingValue");
    }

    @Test
    @DisplayName("testPutOverwritesWithoutGrowingSize. re-putting a key replaces the value")
    void testPutOverwritesWithoutGrowingSize() {
        final Long2LongHashMap map = new Long2LongHashMap(MISSING);

        map.put(7, 1);
        map.put(7, 2);

        assertThat(map.get(7)).isEqualTo(2);
        assertThat(map.size()).isEqualTo(1);
    }

    /**
     * Well past several growth steps, and against a {@link HashMap} rather than against the values
     * put in, so a rehash that drops or duplicates an entry shows up as a size mismatch too.
     */
    @Test
    @DisplayName("testManyEntriesSurviveRehashing. growth preserves every entry")
    void testManyEntriesSurviveRehashing() {
        final Long2LongHashMap map = new Long2LongHashMap(MISSING);
        final Map<Long, Long> expected = new HashMap<>();
        final Random random = new Random(20260803);

        for (int i = 0; i < 50_000; i++) {
            // a small key space relative to the count, so overwrites are exercised as well
            final long key = random.nextInt(30_000);
            final long value = random.nextInt(Integer.MAX_VALUE);
            map.put(key, value);
            expected.put(key, value);
        }

        assertThat(map.size()).isEqualTo(expected.size());
        for (final Map.Entry<Long, Long> entry : expected.entrySet()) {
            assertThat(map.get((long) entry.getKey()))
                    .as("key " + entry.getKey())
                    .isEqualTo(entry.getValue());
        }
    }

    /**
     * The real key shape: object ids are allocation addresses, so they are tightly clustered and
     * 8-aligned, leaving the low bits always zero. Masked into a power-of-two table without mixing
     * they would collide in swathes. Measured on the 1.2 GB sample dump, the 3.66 mil real ids
     * average 1.39 probes per insert, so a regression in the hash would show up as this test slowing
     * sharply rather than failing.
     */
    @Test
    @DisplayName("testAlignedClusteredKeys. object-address-shaped keys must not degenerate")
    void testAlignedClusteredKeys() {
        final Long2LongHashMap map = new Long2LongHashMap(MISSING);
        final long base = 0x00007F0012340000L;

        for (int i = 0; i < 20_000; i++) {
            map.put(base + (i * 8L), i);
        }

        assertThat(map.size()).isEqualTo(20_000);
        for (int i = 0; i < 20_000; i++) {
            assertThat(map.get(base + (i * 8L))).isEqualTo(i);
        }
        assertThat(map.containsKey(base + (20_000 * 8L))).isFalse();
    }

    @Test
    @DisplayName("testEmptyMap. a fresh map holds nothing and still answers lookups")
    void testEmptyMap() {
        final Long2LongHashMap map = new Long2LongHashMap(MISSING);

        assertThat(map.size()).isZero();
        assertThat(map.isEmpty()).isTrue();
        assertThat(map.containsKey(1)).isFalse();
        assertThat(map.get(1)).isEqualTo(MISSING);
    }
}
