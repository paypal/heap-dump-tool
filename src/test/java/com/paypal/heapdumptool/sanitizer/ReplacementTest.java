package com.paypal.heapdumptool.sanitizer;

import org.junit.jupiter.api.Test;

import java.util.Arrays;

import static com.paypal.heapdumptool.sanitizer.Replacement.TILED_BUFFER_SIZE;
import static org.assertj.core.api.Assertions.assertThat;

class ReplacementTest {

    @Test
    void testSingleByteBufferIsFilled() {
        final byte[] buffer = new Replacement(new byte[]{42}).getTiledBuffer();

        assertThat(buffer).hasSize(TILED_BUFFER_SIZE);
        for (final byte b : buffer) {
            assertThat(b).isEqualTo((byte) 42);
        }
    }

    /**
     * The tiled buffer is written to the output in chunks, so every tile boundary in it must carry
     * the replacement in the right byte order. Checking only the first tile would pass even if the
     * rest of the buffer were zeros.
     */
    @Test
    void testEveryTileCarriesTheReplacement() {
        final byte[] replacement = {0x12, 0x34, 0x56, 0x78};
        final byte[] buffer = new Replacement(replacement).getTiledBuffer();

        assertThat(buffer).hasSize(TILED_BUFFER_SIZE);
        for (int offset = 0; offset < buffer.length; offset += replacement.length) {
            assertThat(Arrays.copyOfRange(buffer, offset, offset + replacement.length))
                    .as("tile at " + offset)
                    .containsExactly(0x12, 0x34, 0x56, 0x78);
        }
    }

    /**
     * A region is always a whole multiple of the replacement's width, and the writer chunks the
     * region by the buffer's length. If the buffer held a partial tile, a chunked write would shift
     * the alignment and every value after the first chunk would be garbled.
     */
    @Test
    void testBufferHoldsAWholeNumberOfTiles() {
        // 3 divides neither 8192 nor any power of two, so a naive size would leave a partial tile
        for (final int width : new int[]{1, 2, 3, 4, 5, 7, 8, 8192, 8193, 20000}) {
            final byte[] buffer = new Replacement(new byte[width]).getTiledBuffer();
            assertThat(buffer.length % width).as("width " + width).isZero();
            assertThat(buffer.length).as("width " + width).isPositive();
        }
    }

    /**
     * A replacement wider than the buffer cap still needs at least one whole tile, or a region of
     * that type could never be filled.
     */
    @Test
    void testOversizeReplacementGetsOneWholeTile() {
        final int width = TILED_BUFFER_SIZE + 1;
        final byte[] buffer = new Replacement(new byte[width]).getTiledBuffer();

        assertThat(buffer).hasSize(width);
    }

    @Test
    void testBufferNeverExceedsTheCapUnlessOneTileDoes() {
        for (final int width : new int[]{1, 2, 3, 4, 5, 7, 8, 1000}) {
            final byte[] buffer = new Replacement(new byte[width]).getTiledBuffer();
            assertThat(buffer.length).as("width " + width).isLessThanOrEqualTo(TILED_BUFFER_SIZE);
        }
    }

    @Test
    void testBytesAndLength() {
        final Replacement replacement = new Replacement(new byte[]{0x00, 0x2A});

        assertThat(replacement.getBytes()).containsExactly(0x00, 0x2A);
        assertThat(replacement.getLength()).isEqualTo(2);
    }

    @Test
    void testConstructorCopiesTheCallersArray() {
        final byte[] mine = {7};
        final Replacement replacement = new Replacement(mine);

        mine[0] = 99;

        assertThat(replacement.getBytes()).containsExactly(7);
        assertThat(replacement.getTiledBuffer()[0]).isEqualTo((byte) 7);
    }

    /**
     * getBytes() is the copying accessor: the tiled buffer is shared with every sanitized region of
     * its type, so a caller that could mutate the replacement through getBytes() would corrupt
     * later writes.
     */
    @Test
    void testGetBytesIsDefensivelyCopied() {
        final Replacement replacement = new Replacement(new byte[]{7});

        replacement.getBytes()[0] = 99;

        assertThat(replacement.getBytes()).containsExactly(7);
        assertThat(replacement.getTiledBuffer()[0]).isEqualTo((byte) 7);
    }
}
