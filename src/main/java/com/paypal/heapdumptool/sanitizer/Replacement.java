package com.paypal.heapdumptool.sanitizer;

import java.util.Arrays;

/**
 * One primitive type's replacement bytes, pre-tiled into a reusable buffer.
 *
 * <p>Built once per {@link SanitizationPolicy}, then shared by every sanitized region of that
 * type. {@link #getTiledBuffer()} exposes the buffer directly rather than a copy, so callers must
 * treat it as read-only; {@link #getBytes()} returns a defensive copy for callers outside the
 * streaming path.</p>
 *
 * <h2>Why a whole number of tiles</h2>
 * <p>Tiling is always exactly aligned: a non-array field's size is its type's width, and a
 * primitive array's region is {@code numElements * elementSize}. So a region's length is always a
 * whole multiple of the replacement's length. Holding a whole number of tiles preserves that
 * property under chunking: any prefix of the buffer whose length is a multiple of the
 * replacement's length is itself correctly tiled, so writing the region in buffer-sized chunks
 * cannot shift the alignment.</p>
 *
 * <p>The buffer is at least one tile, so a region shorter than {@link #TILED_BUFFER_SIZE} is still
 * fully covered by repeated whole-buffer writes.</p>
 */
public class Replacement {

    /**
     * Upper bound on the tiled buffer. Rounded down to a whole number of tiles, so the buffer is
     * at most this and at least one tile. 8 KB is large enough that a big primitive array is
     * written in few chunks, and small enough that holding one per primitive type costs 64 KB.
     */
    static final int TILED_BUFFER_SIZE = 8192;

    private final byte[] bytes;
    private final byte[] tiledBuffer;

    Replacement(final byte[] bytes) {
        this.bytes = bytes.clone();
        this.tiledBuffer = newTiledBuffer(this.bytes);
    }

    /**
     * The replacement value itself, big-endian, exactly the type's width.
     */
    public byte[] getBytes() {
        return bytes.clone();
    }

    /**
     * The replacement tiled across a reusable buffer. Read-only: callers must not modify it.
     * Its length is always a whole multiple of {@link #getLength()}.
     */
    byte[] getTiledBuffer() {
        return tiledBuffer;
    }

    /**
     * Width of one replacement value in bytes.
     */
    public int getLength() {
        return bytes.length;
    }

    private static byte[] newTiledBuffer(final byte[] replacement) {
        final int numTiles = Math.max(1, TILED_BUFFER_SIZE / replacement.length);
        final byte[] buffer = new byte[numTiles * replacement.length];

        if (replacement.length == 1) {
            Arrays.fill(buffer, replacement[0]);
        } else {
            for (int offset = 0; offset < buffer.length; offset += replacement.length) {
                System.arraycopy(replacement, 0, buffer, offset, replacement.length);
            }
        }
        return buffer;
    }
}
