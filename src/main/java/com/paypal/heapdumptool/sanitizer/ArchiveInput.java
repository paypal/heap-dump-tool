package com.paypal.heapdumptool.sanitizer;

import com.paypal.heapdumptool.utils.InternalLogger;
import org.apache.commons.compress.archivers.tar.TarArchiveEntry;
import org.apache.commons.compress.archivers.tar.TarArchiveInputStream;
import org.apache.commons.compress.archivers.zip.ZipArchiveEntry;
import org.apache.commons.compress.archivers.zip.ZipArchiveInputStream;
import org.apache.commons.compress.archivers.zip.ZipFile;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.Strings;

import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.PushbackInputStream;
import java.nio.file.Path;
import java.util.Enumeration;

import static com.paypal.heapdumptool.utils.ProgressMonitor.UNKNOWN_TOTAL;

/**
 * A heap dump taken from a stream that may or may not be wrapped in an archive, compressed, or both.
 *
 * <p>Given a tar or a zip, reads past the framing so that {@link #getStream()} is positioned at the
 * first byte of the dump itself; given gzip, decompresses on the way. Nothing is extracted to disk:
 * the dump is read out of the archive as the sanitizer consumes it.</p>
 *
 * <p>Compression is the outer layer and comes off first, since a {@code .tar.gz} looks like no archive
 * at all until it is decompressed. The two are independent -- gzip around a bare dump is as valid as
 * gzip around a tar -- so they are detected as two steps rather than as one combined format.</p>
 *
 * <p>What was found is reported through {@link #getFormat()} and {@link #getEntryName()} rather than
 * logged here. A run opens its input once per pass, so logging from this class would say the same thing
 * twice; the caller knows which pass it is on and logs accordingly.</p>
 */
final class ArchiveInput {

    private static final InternalLogger LOGGER = InternalLogger.getLogger(ArchiveInput.class);

    private final ArchiveFormat format;

    private final CompressionFormat compression;

    private final InputStream stream;

    private final long dumpSizeBytes;

    private final String entryName;

    private ArchiveInput(final ArchiveFormat format,
                         final CompressionFormat compression,
                         final InputStream stream,
                         final long dumpSizeBytes,
                         final String entryName) {
        this.format = format;
        this.compression = compression;
        this.stream = stream;
        this.dumpSizeBytes = dumpSizeBytes;
        this.entryName = entryName;
    }

    /**
     * Sniffs {@code inputStream} itself and returns it positioned at the dump, undoing any gzip and
     * unwrapping a tar or zip around it.
     *
     * <p>For a stream that can only be read once -- stdin, where {@code kubectl cp} delivers a tar
     * with no name to go by. The bytes examined are pushed back before anything else sees the stream,
     * so a plain dump is handed on whole.</p>
     *
     * @throws IOException if an archive holds no heap dump this tool can read
     */
    static ArchiveInput sniffing(final InputStream inputStream) throws IOException {
        final PushbackInputStream stream = new PushbackInputStream(inputStream, ArchiveFormat.SIGNATURE_LENGTH);

        final byte[] signature = new byte[ArchiveFormat.SIGNATURE_LENGTH];
        // IOUtils.read, not InputStream.read: one read() of a pipe returns whatever has arrived so
        // far, which for a signature spanning several packets can be a few bytes
        final int length = IOUtils.read(stream, signature);
        stream.unread(signature, 0, length);

        /*
         * One read serves both, gzip's magic being the first 2 bytes of the same 512. An uncompressed
         * stream is then already sniffed and needs nothing further; a compressed one has to be looked at
         * again, since what says whether there is an archive is the decompressed bytes.
         */
        final CompressionFormat compression = CompressionFormat.detect(signature, length);
        if (compression == CompressionFormat.NONE) {
            return of(ArchiveFormat.detect(signature, length), compression, stream);
        }
        return sniffingArchive(compression, stream);
    }

    /**
     * As {@link #sniffing(InputStream)} for a file, which can be opened again as needed.
     *
     * <p>An uncompressed file has its format established by a sniffing read of its own, done here, and
     * keeps the pushback wrapper off a plain dump -- which is then read through exactly the stream the
     * caller opened. Worth the separate sniff: the sanitizer reads a dump's records a byte at a time,
     * tens of millions of times, and every layer in between is a virtual call per byte.</p>
     *
     * <p>A compressed file cannot be sniffed that way, since what has to be examined is the
     * decompressed bytes, and cannot be read backwards to a zip's central directory either. So it goes
     * the same way as stdin, and is subject to the same limits.</p>
     *
     * @param stream an open stream over {@code inputFile}, used unless a zip is read by path instead
     */
    static ArchiveInput ofFile(final Path inputFile, final InputStream stream) throws IOException {
        final CompressionFormat compression = CompressionFormat.ofInputFile(inputFile);
        if (compression != CompressionFormat.NONE) {
            return sniffingArchive(compression, stream);
        }

        final ArchiveFormat format = ArchiveFormat.ofInputFile(inputFile);
        if (format == ArchiveFormat.NONE) {
            return new ArchiveInput(format, compression, stream, UNKNOWN_TOTAL, null);
        }
        if (format == ArchiveFormat.TAR) {
            return openTarEntry(compression, stream);
        }
        /*
         * By path, not through the stream already open on it, so that the entry's length comes from
         * the central directory -- see openZipFileEntry. That stream is then surplus, and closing it
         * here is this method's job: on the path it is used, the caller closes it, and the caller
         * cannot tell the two apart.
         */
        stream.close();
        return openZipFileEntry(inputFile);
    }

    /*
     * The archive inside the stream, which is looked for in the decompressed bytes -- a .tar.gz looks
     * like neither a tar nor a zip until the gzip comes off. Sniffed forwards and pushed back, since a
     * decompressed stream can no more be reopened for a second look than a pipe can.
     */
    private static ArchiveInput sniffingArchive(final CompressionFormat compression,
                                                final InputStream inputStream) throws IOException {
        final InputStream decompressed = compression.decompress(inputStream);
        final PushbackInputStream stream = new PushbackInputStream(decompressed, ArchiveFormat.SIGNATURE_LENGTH);

        final byte[] signature = new byte[ArchiveFormat.SIGNATURE_LENGTH];
        // IOUtils.read, not InputStream.read: one read() of a pipe returns whatever has arrived so
        // far, which for a signature spanning several packets can be a few bytes
        final int length = IOUtils.read(stream, signature);
        stream.unread(signature, 0, length);

        return of(ArchiveFormat.detect(signature, length), compression, stream);
    }

    /**
     * As {@link #ofFile} for a stream that can only be read forwards, whose formats are already known.
     */
    private static ArchiveInput of(final ArchiveFormat format,
                                   final CompressionFormat compression,
                                   final InputStream stream) throws IOException {
        if (format == ArchiveFormat.NONE) {
            return new ArchiveInput(format, compression, stream, UNKNOWN_TOTAL, null);
        }
        if (format == ArchiveFormat.TAR) {
            return openTarEntry(compression, stream);
        }
        return openZipStreamEntry(compression, stream);
    }

    /*
     * The first entry, whatever it is called. A tar from `kubectl cp` holds the dump alone, under
     * whatever path it had in the container, so there is no name to select on -- unlike a zip, which
     * this tool itself writes with a thread dump beside the heap dump.
     */
    private static ArchiveInput openTarEntry(final CompressionFormat compression,
                                             final InputStream stream) throws IOException {
        final TarArchiveInputStream tarStream = new TarArchiveInputStream(stream);
        final TarArchiveEntry entry = tarStream.getNextEntry();
        if (entry == null) {
            throw new IOException("No entries in the tar input");
        }
        return new ArchiveInput(ArchiveFormat.TAR, compression, tarStream,
                                sizeOrUnknown(entry.getSize()), entry.getName());
    }

    /**
     * The dump entry of a zip <em>file</em>, read by way of the central directory at the end of it.
     *
     * <p>Which is what makes a {@code .zip} input into a {@code .tar} output possible. A zip states
     * an entry's length twice: in the local header, before the data, and again in the central
     * directory at the end of the file. A zip written streaming -- as this tool writes its own, having
     * no more idea of the sanitized length up front than the local header does -- can only fill in the
     * central directory copy, and leaves the local header's empty. So reading the central directory
     * gets a length for every zip a seekable file can hold, and a tar entry cannot be written without
     * one.</p>
     */
    private static ArchiveInput openZipFileEntry(final Path inputFile) throws IOException {
        final ZipFile zipFile = ZipFile.builder().setPath(inputFile).get();
        try {
            final ZipArchiveEntry entry = findDumpEntry(zipFile);
            /*
             * The entry stream does not own the ZipFile, so it has to be closed alongside it: the
             * caller closes the stream it is given and knows nothing of what is behind it.
             */
            final InputStream entryStream = closingBoth(zipFile.getInputStream(entry), zipFile);
            return new ArchiveInput(ArchiveFormat.ZIP, CompressionFormat.NONE, entryStream,
                                    sizeOrUnknown(entry.getSize()), entry.getName());
        } catch (final IOException | RuntimeException e) {
            zipFile.close();
            throw e;
        }
    }

    /*
     * Selected by name, because a zip written by `capture` holds a .threads.txt entry as well, and
     * ordering within a zip is not guaranteed to put the dump first.
     */
    private static ZipArchiveEntry findDumpEntry(final ZipFile zipFile) throws IOException {
        final Enumeration<ZipArchiveEntry> entries = zipFile.getEntries();
        while (entries.hasMoreElements()) {
            final ZipArchiveEntry entry = entries.nextElement();
            if (!isDumpEntry(entry)) {
                continue;
            }
            if (!zipFile.canReadEntryData(entry)) {
                throw unreadableEntry(entry);
            }
            return entry;
        }
        throw noDumpEntry();
    }

    /*
     * As openZipFileEntry, for a zip that can only be read forwards -- one arriving on stdin, whose
     * central directory is a thousand entries and several gigabytes further on than the dump this is
     * here to start reading. Such a zip's declared length is whatever its local headers carry, which
     * for a streamed zip is nothing.
     */
    private static ArchiveInput openZipStreamEntry(final CompressionFormat compression,
                                                   final InputStream stream) throws IOException {
        final ZipArchiveInputStream zipStream = new ZipArchiveInputStream(stream);

        ZipArchiveEntry entry;
        while ((entry = zipStream.getNextEntry()) != null) {
            if (!isDumpEntry(entry)) {
                continue;
            }
            if (!zipStream.canReadEntryData(entry)) {
                throw unreadableEntry(entry);
            }
            return new ArchiveInput(ArchiveFormat.ZIP, compression, zipStream,
                                    sizeOrUnknown(entry.getSize()), entry.getName());
        }
        throw noDumpEntry();
    }

    private static boolean isDumpEntry(final ZipArchiveEntry entry) {
        if (entry.isDirectory() || !Strings.CI.endsWith(entry.getName(), ArchiveFormat.HPROF_SUFFIX)) {
            LOGGER.debug("Skipping zip entry: {}", entry.getName());
            return false;
        }
        return true;
    }

    private static IOException unreadableEntry(final ZipArchiveEntry entry) {
        return new IOException("Cannot read zip entry, which may use an unsupported compression"
                                       + " method or be encrypted: " + entry.getName());
    }

    private static IOException noDumpEntry() {
        return new IOException("No *" + ArchiveFormat.HPROF_SUFFIX + " entry in the zip input");
    }

    /*
     * A stream that closes the archive it was opened from as well as itself.
     */
    private static InputStream closingBoth(final InputStream entryStream, final ZipFile zipFile) {
        return new FilterInputStream(entryStream) {
            @Override
            public void close() throws IOException {
                try {
                    super.close();
                } finally {
                    zipFile.close();
                }
            }
        };
    }

    /*
     * An entry size is only present if the archive declares one. A zip written streaming -- the
     * sizes go in a trailer after the data, so the local header carries none -- reports -1, which is
     * a missing size rather than a real one and must not be shown as a total.
     */
    private static long sizeOrUnknown(final long entrySize) {
        return entrySize >= 0 ? entrySize : UNKNOWN_TOTAL;
    }

    ArchiveFormat getFormat() {
        return format;
    }

    /**
     * The compression the dump was read through, or {@link CompressionFormat#NONE} if the input was
     * not compressed.
     */
    CompressionFormat getCompression() {
        return compression;
    }

    /**
     * The name of the archive entry the dump is being read from, or {@code null} if there is no
     * archive.
     */
    String getEntryName() {
        return entryName;
    }

    /**
     * The stream, positioned at the first byte of the dump.
     */
    InputStream getStream() {
        return stream;
    }

    /**
     * The dump's length in bytes as the archive declares it, or {@link
     * com.paypal.heapdumptool.utils.ProgressMonitor#UNKNOWN_TOTAL} when there is no archive to
     * declare one, or it does not.
     */
    long getDumpSizeBytes() {
        return dumpSizeBytes;
    }
}
