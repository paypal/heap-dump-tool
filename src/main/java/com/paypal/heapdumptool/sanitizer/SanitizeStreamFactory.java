package com.paypal.heapdumptool.sanitizer;

import com.paypal.heapdumptool.utils.DataSize;
import com.paypal.heapdumptool.utils.FileTool;
import com.paypal.heapdumptool.utils.InternalLogger;
import com.paypal.heapdumptool.utils.ProgressMonitor;
import org.apache.commons.io.input.BufferedFileChannelInputStream;
import org.apache.commons.lang3.Strings;
import org.apache.commons.lang3.Validate;

import java.io.BufferedOutputStream;
import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;

import static com.paypal.heapdumptool.utils.ProgressMonitor.UNKNOWN_TOTAL;
import static java.lang.Math.toIntExact;

/**
 * Creates i/o streams for input/output files
 *
 * <p>Both sides handle archives and gzip. An input that turns out to be a tar, a zip, or gzipped is
 * unwrapped as it is read, and an output file named {@code .tar}, {@code .zip}, {@code .gz} or
 * {@code .tgz} is written that way -- in neither case by way of a temporary file.</p>
 */
public class SanitizeStreamFactory {

    private static final InternalLogger LOGGER = InternalLogger.getLogger(SanitizeStreamFactory.class);

    private final SanitizeCommand command;

    /*
     * Both established by the last newInputStream() call, and held rather than computed on demand
     * because establishing them means sniffing the stream, which a stdin input allows only once.
     *
     * Two figures rather than one because they tolerate different things. A tar entry header states
     * its length before the data, and commons-compress rejects a write that runs past it or an entry
     * closed short of it, so exactDumpSizeBytes must be the dump's length or nothing at all. The
     * progress total is only ever divided into a percentage and an ETA, so an approximation -- the
     * archive's size, a little over the dump's -- reads fine and the ETA clamps the overshoot.
     */
    private long exactDumpSizeBytes = UNKNOWN_TOTAL;

    private long progressTotalBytes = UNKNOWN_TOTAL;

    private boolean archiveInputLogged;

    public SanitizeStreamFactory(final SanitizeCommand command) {
        this.command = validate(command);
    }

    /**
     * Opens the input, positioned at the first byte of the heap dump: past the framing if the input
     * is an archive, at the start of the file or pipe if it is not.
     *
     * <p>Called once per pass, so a file input is sniffed and unwrapped again on the second pass.
     * That is what makes the metadata pass and the writing pass independent, and it costs a second
     * read of a few hundred header bytes.</p>
     */
    public InputStream newInputStream() throws IOException {
        final ArchiveInput archiveInput = openArchiveInput();

        logArchiveInputOnce(archiveInput);
        this.exactDumpSizeBytes = resolveExactDumpSizeBytes(archiveInput);
        this.progressTotalBytes = resolveProgressTotalBytes(archiveInput);
        return archiveInput.getStream();
    }

    /*
     * Once per run, not once per pass. The input is opened again for the writing pass, which would
     * otherwise announce the same archive and the same entry a second time -- and the second time reads
     * as though a different file were being picked up, rather than the same one being reread.
     */
    private void logArchiveInputOnce(final ArchiveInput archiveInput) {
        final boolean plain = archiveInput.getFormat() == ArchiveFormat.NONE
                && archiveInput.getCompression() == CompressionFormat.NONE;
        if (plain || archiveInputLogged) {
            return;
        }
        archiveInputLogged = true;
        LOGGER.info("Reading {} input: {} - {}", describeInputFormat(archiveInput), getInputFileName(),
                    describeDumpSize(archiveInput));
        if (archiveInput.getEntryName() != null) {
            LOGGER.info("    Entry: {}", archiveInput.getEntryName());
        }
    }

    /*
     * As describeOutputFormat, for what was found in the input: tar.gz for a gzipped tar, gzip alone
     * for a gzipped bare dump.
     */
    private static String describeInputFormat(final ArchiveInput archiveInput) {
        if (archiveInput.getFormat() == ArchiveFormat.NONE) {
            return archiveInput.getCompression().displayName();
        }
        return archiveInput.getFormat().displayName() + archiveInput.getCompression().extension();
    }

    /*
     * The dump's length as the archive declares it. A streamed zip declares none, and gzip never does.
     */
    private static String describeDumpSize(final ArchiveInput archiveInput) {
        final long dumpSizeBytes = archiveInput.getDumpSizeBytes();
        return dumpSizeBytes == UNKNOWN_TOTAL ? "size not declared" : FileTool.displaySize(dumpSizeBytes);
    }

    /*
     * An uncompressed file is sniffed by a read of its own, so that a plain dump -- the common case --
     * is then read through the stream newInputStream(Path) opened and nothing more. stdin cannot be
     * re-read, so there the signature has to come out of the stream itself and be pushed back.
     */
    private ArchiveInput openArchiveInput() throws IOException {
        final Path inputFile = command.getInputFile();
        if (isStdinInput()) {
            return ArchiveInput.sniffing(newInputStream(inputFile));
        }
        return ArchiveInput.ofFile(inputFile, newInputStream(inputFile));
    }

    /**
     * Opens the output, wrapped in whatever the output file name asks for: an archive, gzip, or both.
     *
     * <p>Gzip goes outside the archive, so that {@code .tar.gz} is a compressed tar and not a tar of
     * compressed data -- the same order {@code tar czf} writes.</p>
     */
    public OutputStream newOutputStream() throws IOException {
        final Path outputFile = command.getOutputFile();
        // the logging wrapper is innermost, so its close() runs once everything above has flushed and
        // finished and the file's size on disk is final
        final OutputStream fileOutput = loggingWhenWritten(Files.newOutputStream(outputFile));
        final OutputStream output = getBufferSize() == 0
                                    ? fileOutput
                                    : new BufferedOutputStream(fileOutput, getBufferSize());

        final ArchiveFormat format = getOutputFormat();
        final CompressionFormat compression = getOutputCompression();
        if (format == ArchiveFormat.NONE && compression == CompressionFormat.NONE) {
            return output;
        }

        /*
         * The name recorded in the gzip header is the file as it will be once decompressed -- what
         * `gunzip` restores it as -- so it is the output name with the .gz taken off, and for a .tgz
         * the .tar that shorthand stands for.
         */
        final String decompressedName = ArchiveFormat.withoutCompressionExtension(getOutputFileName());
        final OutputStream compressed = compression.compress(output, decompressedName);
        if (format == ArchiveFormat.NONE) {
            logWritingOutput();
            return compressed;
        }
        final String entryName = format.entryName(decompressedName);
        final OutputStream archive = ArchiveOutput.wrap(compressed, format, entryName, exactDumpSizeBytes);

        // after the wrap, so that a tar refused for want of a length is not announced as being written
        logWritingOutput();
        return archive;
    }

    /*
     * What is about to be written, in the same shape as the line reporting it written. The size here is
     * the dump's own length, which only a tar states up front -- a zip and a gzip both commit to
     * nothing until the data is through them.
     */
    private void logWritingOutput() {
        final String size = getOutputFormat() == ArchiveFormat.TAR && exactDumpSizeBytes != UNKNOWN_TOTAL
                            ? FileTool.displaySize(exactDumpSizeBytes)
                            : "size not yet known";
        LOGGER.info("Writing {} output: {} - {}", describeOutputFormat(), getOutputFileName(), size);
    }

    /*
     * Reported once the file is closed and its size is final, which for a zip or a gzip is the first
     * point the size is knowable at all.
     */
    private OutputStream loggingWhenWritten(final OutputStream fileOutput) {
        if (getOutputFormat() == ArchiveFormat.NONE && getOutputCompression() == CompressionFormat.NONE) {
            return fileOutput;
        }
        return new FilterOutputStream(fileOutput) {

            private boolean logged;

            @Override
            public void write(final byte[] bytes, final int offset, final int length) throws IOException {
                // FilterOutputStream's own version forwards a byte at a time, which for a heap dump is
                // hundreds of millions of virtual calls
                out.write(bytes, offset, length);
            }

            @Override
            public void close() throws IOException {
                super.close();
                if (!logged) { // close() is idempotent by contract, so the line must not repeat
                    logged = true;
                    LOGGER.info("Wrote {} output: {} - {}", describeOutputFormat(), getOutputFileName(),
                                FileTool.displaySize(outputFileSizeOrZero()));
                }
            }
        };
    }

    private long outputFileSizeOrZero() {
        try {
            return Files.size(command.getOutputFile());
        } catch (final IOException e) {
            // the file has just been written and closed; a log line is not worth failing the run over
            return 0;
        }
    }

    /*
     * How the layers name themselves together: a tar inside gzip is "tar.gz", as the file name has it.
     */
    private String describeOutputFormat() {
        final ArchiveFormat format = getOutputFormat();
        if (format == ArchiveFormat.NONE) {
            return getOutputCompression().displayName();
        }
        return format.displayName() + getOutputCompression().extension();
    }

    /**
     * The archive to write, from the output file's extension, or {@link ArchiveFormat#NONE} for a
     * plain dump.
     *
     * <p>{@code --zip-output} forces a zip whatever the extension says, for as long as the flag
     * exists.</p>
     */
    ArchiveFormat getOutputFormat() {
        if (command.isZipOutput()) {
            return ArchiveFormat.ZIP;
        }
        return ArchiveFormat.ofOutputFile(command.getOutputFile());
    }

    /**
     * The compression to write, from the output file's extension, or {@link CompressionFormat#NONE}
     * for an uncompressed one.
     *
     * <p>{@code --zip-output} names the archive, not the compression, so a {@code .gz} output is still
     * gzipped under it -- a zip inside gzip, which is what both flags together literally ask for.</p>
     */
    CompressionFormat getOutputCompression() {
        return CompressionFormat.ofOutputFile(command.getOutputFile());
    }

    protected InputStream newInputStream(final Path inputFile) throws IOException {
        if (isStdinInput()) {
            return System.in;
        }
        if (getBufferSize() == 0) {
            return Files.newInputStream(inputFile);
        }
        return BufferedFileChannelInputStream.builder()
                                      .setPath(inputFile)
                                      .setBufferSize(getBufferSize())
                                      .get();
    }

    public boolean isStdinInput() {
        final String name = command.getInputFile().getFileName().toString();
        return Strings.CS.equalsAny(name, "-", "stdin", "0");
    }

    /**
     * Valid only after {@link #newInputStream()}, which determines whether the input is an archive:
     * an archive declares its entry's length, so a dump in one has a total even on stdin.
     */
    public long getInputSizeBytes() {
        return progressTotalBytes;
    }

    /*
     * The dump's exact length, for a tar entry header: the archive's declared entry length if the
     * input is an archive, otherwise the input file's own size, since a plain dump is the whole file.
     * A stdin input that is not an archive has none, and neither does an archive that declares none.
     */
    private long resolveExactDumpSizeBytes(final ArchiveInput archiveInput) {
        if (archiveInput.getFormat() != ArchiveFormat.NONE) {
            return archiveInput.getDumpSizeBytes();
        }
        return fileSizeOrUnknown(archiveInput);
    }

    /*
     * Prefers the archive's declared entry length, which measures the same bytes progress counts. The
     * file size is what remains: exact for a plain dump, and for an archive that declares no length an
     * over-estimate that still gives a usable ratio -- the framing is a few hundred bytes of a tar,
     * and a zip's compressed size understates the dump but at least bounds it.
     */
    private long resolveProgressTotalBytes(final ArchiveInput archiveInput) {
        return exactDumpSizeBytes != UNKNOWN_TOTAL ? exactDumpSizeBytes : fileSizeOrUnknown(archiveInput);
    }

    /*
     * The input file's length, which stands for the dump's only when the file is the dump.
     *
     * Nothing at all for a compressed input: the file's length then measures compressed bytes, several
     * times smaller than what will be read out of it. As a tar entry length that would declare an entry
     * far shorter than the dump written into it, which commons-compress rejects part way through -- and
     * as a progress total it would read as several hundred percent. gzip does record the decompressed
     * length in its trailer, but as 32 bits, which a heap dump routinely exceeds.
     */
    private long fileSizeOrUnknown(final ArchiveInput archiveInput) {
        if (isStdinInput() || archiveInput.getCompression() != CompressionFormat.NONE) {
            return UNKNOWN_TOTAL;
        }
        try {
            return Files.size(command.getInputFile());
        } catch (final IOException e) {
            // progress reporting is not worth failing a run over; the size is simply not shown
            return UNKNOWN_TOTAL;
        }
    }

    private static SanitizeCommand validate(final SanitizeCommand command) {
        final Path outputFile = command.getOutputFile();

        Validate.isTrue(!command.getInputFile().equals(outputFile), "input and output files cannot be the same");
        return command;
    }

    private String getOutputFileName() {
        final Path outputFile = command.getOutputFile();
        return outputFile.getFileName().toString();
    }

    /*
     * "stdin" for a pipe, rather than the "-" or "0" that named it, which on a line already full of
     * dashes reads as punctuation.
     */
    private String getInputFileName() {
        return isStdinInput() ? "stdin" : command.getInputFile().getFileName().toString();
    }

    private int getBufferSize() {
        final DataSize bufferSize = command.getBufferSize();
        return toIntExact(bufferSize.toBytes());
    }

}
