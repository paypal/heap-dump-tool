package com.paypal.heapdumptool.sanitizer;

import org.apache.commons.compress.archivers.tar.TarArchiveEntry;
import org.apache.commons.compress.archivers.tar.TarArchiveOutputStream;

import java.io.IOException;
import java.io.OutputStream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import static com.paypal.heapdumptool.utils.ProgressMonitor.UNKNOWN_TOTAL;

/**
 * Wraps the output stream in the archive the output file name asks for.
 *
 * <p>Nothing is staged on disk: the sanitized dump is compressed as it is written, so a run needs no
 * room for a second copy of the dump.</p>
 *
 * <p>What is written is reported by the caller rather than logged here, as on the input side -- see
 * {@link ArchiveInput}. Only the caller can tell an archive that was written from one that was asked
 * for and refused.</p>
 */
final class ArchiveOutput {

    private ArchiveOutput() {
        throw new AssertionError();
    }

    /**
     * Returns {@code output} wrapped in {@code format}, with the dump entry already open, or
     * {@code output} itself when the format is {@link ArchiveFormat#NONE}.
     *
     * @param entryName     the name for the dump entry inside the archive
     * @param dumpSizeBytes the length the dump will have, needed by {@link ArchiveFormat#TAR}, or
     *                      {@link com.paypal.heapdumptool.utils.ProgressMonitor#UNKNOWN_TOTAL}
     */
    static OutputStream wrap(final OutputStream output,
                             final ArchiveFormat format,
                             final String entryName,
                             final long dumpSizeBytes) throws IOException {
        switch (format) {
            case TAR:
                return newTarStream(output, entryName, dumpSizeBytes);
            case ZIP:
                return newZipStream(output, entryName);
            default:
                return output;
        }
    }

    private static OutputStream newZipStream(final OutputStream output, final String entryName) throws IOException {
        final ZipOutputStream zipStream = new ZipOutputStream(output);
        zipStream.putNextEntry(new ZipEntry(entryName));
        return zipStream;
    }

    /*
     * A tar entry header carries the entry's length, and it is written before the data, so the length
     * has to be known up front -- commons-compress rejects both a write past the declared size and an
     * entry closed short of it. The dump's length is knowable because sanitization is
     * length-preserving: every field and array is overwritten in place, never resized. So the output
     * entry is exactly as long as the input dump.
     *
     * That leaves tar output unavailable when the input's length is not knowable, which is a stdin
     * input that is not itself an archive. Zip has no such constraint -- it writes the sizes in a
     * trailer after the data -- so that is what the error suggests.
     */
    private static OutputStream newTarStream(final OutputStream output,
                                             final String entryName,
                                             final long dumpSizeBytes) throws IOException {
        if (dumpSizeBytes == UNKNOWN_TOTAL) {
            throw new IllegalArgumentException("Cannot write tar output for an input of unknown length,"
                                                       + " because a tar entry declares its length before"
                                                       + " its data. Use a .zip output file, or a plain"
                                                       + " .hprof one, optionally .gz -- neither a zip nor"
                                                       + " gzip needs the length up front");
        }

        final TarArchiveOutputStream tarStream = new EntryClosingTarOutputStream(output);
        /*
         * POSIX (pax) headers for anything the 1979 header fields cannot hold: a size above 8 GB --
         * a real possibility for a heap dump -- or a path above 100 bytes. The default mode throws on
         * both. GNU format would also do, but pax is the POSIX.1-2001 standard and is what modern tar
         * implementations write.
         */
        tarStream.setLongFileMode(TarArchiveOutputStream.LONGFILE_POSIX);
        tarStream.setBigNumberMode(TarArchiveOutputStream.BIGNUMBER_POSIX);

        final TarArchiveEntry entry = new TarArchiveEntry(entryName);
        entry.setSize(dumpSizeBytes);
        tarStream.putArchiveEntry(entry);
        return tarStream;
    }

    /**
     * Closes the open entry as part of closing the stream.
     *
     * <p>A tar entry has to be closed explicitly -- it is what pads the data out to a record
     * boundary -- and {@code TarArchiveOutputStream.close()} refuses to finish an archive with an
     * entry still open. Callers here close the stream and no more: the writing pass hands its output
     * to a try-with-resources that knows nothing of archives, and {@code CaptureStreamFactory} shields
     * the stream from that close to append a thread dump, then closes it itself later.</p>
     */
    private static final class EntryClosingTarOutputStream extends TarArchiveOutputStream {

        private boolean entryClosed;

        EntryClosingTarOutputStream(final OutputStream output) {
            super(output);
        }

        @Override
        public void close() throws IOException {
            // guarded, because close() is idempotent by contract while closeArchiveEntry() is not
            if (!entryClosed) {
                entryClosed = true;
                closeArchiveEntry();
            }
            super.close();
        }
    }
}
