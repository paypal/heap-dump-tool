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

/**
 * Hashing functions for applying to integers.
 *
 * <p>Vendored from Agrona (org.agrona.collections.Hashing, Apache-2.0, copyright above) alongside
 * {@link Long2LongHashMap}, which is its only caller here. Reduced to the functions that map needs
 * and reformatted to this project's style by spotless; the hash mixing itself is unmodified.</p>
 */
public final class Hashing {
    /**
     * Default load factor to be used in open-addressing hashed data structures.
     */
    public static final float DEFAULT_LOAD_FACTOR = 0.65f;

    private Hashing() {}

    /**
     * Generate a hash for a long value.
     *
     * @param value to be hashed.
     * @return the hashed value.
     */
    public static int hash(final long value) {
        long x = value;

        x = (x ^ (x >>> 30)) * 0xbf58476d1ce4e5b9L;
        x = (x ^ (x >>> 27)) * 0x94d049bb133111ebL;
        x = x ^ (x >>> 31);

        return (int) x ^ (int) (x >>> 32);
    }

    /**
     * Generate an even hash for a long value and apply mask to get a remainder that will be even.
     *
     * @param value to be hashed.
     * @param mask  mask to be applied that must be a power of 2 - 1.
     * @return the hash of the value which is always even.
     */
    public static int evenHash(final long value, final int mask) {
        final int hash = hash(value);
        final int evenHash = (hash << 1) - (hash << 8);

        return evenHash & mask;
    }
}
