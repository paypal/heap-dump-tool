package com.paypal.heapdumptool.sanitizer;

import org.apache.commons.compress.compressors.gzip.GzipCompressorInputStream;
import org.apache.commons.compress.compressors.gzip.GzipCompressorOutputStream;
import org.apache.commons.compress.compressors.gzip.GzipParameters;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.Strings;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * A compression wrapper around a stream, outside whatever archive is inside it.
 *
 * <p>Separate from {@link ArchiveFormat} because the two are independent: a {@code .tar.gz} is gzip
 * around a tar, and gzip around a bare dump is equally valid. So this decides only whether the bytes
 * are compressed, and the archive format is decided afterwards, from the decompressed bytes -- which
 * is also why a {@code .tgz} needs nothing said about tar here.</p>
 *
 * <p>Gzip is a stream format with no index or entry table: it declares no length up front and cannot
 * be read backwards. So a gzipped input's dump length is only knowable from the archive inside it,
 * and a gzipped output is written straight through.</p>
 */
enum CompressionFormat {

    /**
     * Not compressed: the bytes are the archive, or the dump.
     */
    NONE,

    GZIP;

    /**
     * Bytes to sniff before deciding: gzip's magic is the first two.
     */
    static final int SIGNATURE_LENGTH = 2;

    /**
     * The format the given leading bytes indicate, or {@link #NONE} if they match no compression.
     */
    static CompressionFormat detect(final byte[] signature, final int length) {
        if (GzipCompressorInputStream.matches(signature, length)) {
            return GZIP;
        }
        return NONE;
    }

    /**
     * The compression of the given file, from its leading bytes.
     *
     * <p>A file too short to carry a signature, or missing entirely, is {@link #NONE} -- as in
     * {@link ArchiveFormat#ofInputFile}, a file that cannot be opened is the sanitizer's error to
     * report from the stream it fails to read.</p>
     */
    static CompressionFormat ofInputFile(final Path inputFile) {
        final byte[] signature = new byte[SIGNATURE_LENGTH];
        try (final InputStream stream = Files.newInputStream(inputFile)) {
            return detect(signature, IOUtils.read(stream, signature));
        } catch (final IOException e) {
            return NONE;
        }
    }

    /**
     * The compression to write for the given output file, by extension: {@code .gz} or {@code .tgz}
     * is gzip, anything else uncompressed.
     *
     * <p>{@code .tgz} is the same thing as {@code .tar.gz}, so what it asks for is gzip here and a tar
     * from {@link ArchiveFormat#ofOutputFile}.</p>
     */
    static CompressionFormat ofOutputFile(final Path outputFile) {
        final String name = outputFile.getFileName().toString();
        if (Strings.CI.endsWith(name, ".gz") || Strings.CI.endsWith(name, ".tgz")) {
            return GZIP;
        }
        return NONE;
    }

    /**
     * Returns {@code stream} with this compression decoded, or {@code stream} itself for
     * {@link #NONE}.
     */
    InputStream decompress(final InputStream stream) throws IOException {
        if (this == NONE) {
            return stream;
        }
        return GzipCompressorInputStream.builder()
                .setInputStream(stream)
                .setDecompressConcatenated(true)
                .get();
    }

    /**
     * Returns {@code stream} wrapped so that what is written to it is compressed, or {@code stream}
     * itself for {@link #NONE}.
     *
     * @param fileName the name to record in the gzip header, which is what {@code gunzip} restores the
     *                 decompressed file as
     */
    OutputStream compress(final OutputStream stream, final String fileName) throws IOException {
        if (this == NONE) {
            return stream;
        }
        final GzipParameters parameters = new GzipParameters();
        parameters.setFileName(fileName);
        return new GzipCompressorOutputStream(stream, parameters);
    }

    /**
     * The extension this compression adds to a file name, or an empty string for {@link #NONE}.
     */
    String extension() {
        return this == GZIP ? ".gz" : "";
    }

    /**
     * How this format names itself in a log line or an error message.
     */
    String displayName() {
        return name().toLowerCase();
    }
}
