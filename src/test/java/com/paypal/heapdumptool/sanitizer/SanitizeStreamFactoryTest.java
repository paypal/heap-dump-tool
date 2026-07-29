package com.paypal.heapdumptool.sanitizer;

import com.paypal.heapdumptool.testutil.ResourceTool;
import org.apache.commons.compress.archivers.tar.TarArchiveInputStream;
import org.apache.commons.compress.archivers.tar.TarArchiveOutputStream;
import org.apache.commons.compress.archivers.zip.ZipArchiveInputStream;
import org.apache.commons.compress.compressors.gzip.GzipCompressorInputStream;
import org.apache.commons.compress.compressors.gzip.GzipCompressorOutputStream;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;

import org.apache.commons.io.input.BufferedFileChannelInputStream;

import java.io.BufferedOutputStream;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.concurrent.Callable;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import static com.paypal.heapdumptool.utils.DataSize.ofBytes;
import static com.paypal.heapdumptool.utils.ProgressMonitor.UNKNOWN_TOTAL;
import static java.nio.file.StandardOpenOption.TRUNCATE_EXISTING;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@ExtendWith(OutputCaptureExtension.class)
public class SanitizeStreamFactoryTest {

    @TempDir
    Path tempDir;

    private SanitizeStreamFactory streamFactory;

    /**
     * A dump piped in plain comes through byte for byte. The signature has to be read off the pipe to
     * know it is not an archive -- stdin cannot be reopened for a second look -- so what this pins is
     * that those bytes are handed back rather than consumed.
     */
    @Test
    public void testStdinInputStream() throws IOException {
        // longer than the signature, so a lost pushback would truncate rather than empty the stream
        final String dump = StringUtils.repeat("not an archive. ", 100);

        final InputStream stream = withStdin(dump, () -> {
            final SanitizeCommand cmd = newCommand();
            cmd.setInputFile(Paths.get("-"));
            cmd.setBufferSize(ofBytes(0));

            streamFactory = new SanitizeStreamFactory(cmd);
            return streamFactory.newInputStream();
        });

        assertThat(IOUtils.toString(stream, StandardCharsets.UTF_8)).isEqualTo(dump);
        assertThat(streamFactory.getInputSizeBytes())
                .as("a pipe has no length, so there is no total to report")
                .isEqualTo(UNKNOWN_TOTAL);
    }

    /**
     * The case the detection is for: {@code kubectl cp} delivers a tar on stdin, which has no name to
     * go by and cannot be rewound.
     */
    @Test
    public void testStdinTarInputIsDetected() throws IOException {
        final byte[] tarBytes = ResourceTool.bytesOf(getClass(), "sample.tar");

        final InputStream stream = withStdin(tarBytes, () -> {
            final SanitizeCommand cmd = newCommand();
            cmd.setInputFile(Paths.get("-"));
            cmd.setBufferSize(ofBytes(0));

            streamFactory = new SanitizeStreamFactory(cmd);
            return streamFactory.newInputStream();
        });

        assertThat(stream).isInstanceOf(TarArchiveInputStream.class);
        assertThat(streamFactory.getInputSizeBytes())
                .as("the tar declares its entry's length, so even a pipe has a total")
                .isEqualTo(12);
    }

    /**
     * A plain dump is handed back as exactly the stream that was opened for it, with no unwrapping
     * layer in between. The sanitizer reads a dump a field at a time, so a wrapper here would be a
     * virtual call on every one of tens of millions of reads.
     */
    @Test
    public void testBufferedInputStream() throws IOException {
        final Path inputFile = Files.createTempFile(tempDir, getClass().getSimpleName(), ".hprof");
        FileUtils.write(inputFile.toFile(), "test data", StandardCharsets.UTF_8);
        final SanitizeCommand cmd = newCommand();
        cmd.setInputFile(inputFile);

        streamFactory = new SanitizeStreamFactory(cmd);
        assertThat(streamFactory.newInputStream())
                .isInstanceOf(BufferedFileChannelInputStream.class);
    }

    @Test
    public void testBufferedOutputStream() throws IOException {
        final SanitizeCommand cmd = newCommand();
        cmd.setOutputFile(tempDir.resolve("testBufferedOutputStream"));

        streamFactory = new SanitizeStreamFactory(cmd);
        assertThat(streamFactory.newOutputStream())
                .isInstanceOf(BufferedOutputStream.class);
    }

    @Test
    public void testFileInputStream() throws IOException {
        final Path inputFile = Files.createTempFile(tempDir, getClass().getSimpleName(), ".hprof");
        final SanitizeCommand cmd = newCommand();
        cmd.setInputFile(inputFile);
        cmd.setBufferSize(ofBytes(0));

        streamFactory = new SanitizeStreamFactory(cmd);
        assertThat(streamFactory.newInputStream())
                .isNotInstanceOf(BufferedFileChannelInputStream.class);
    }

    @Test
    public void testFileOutputStream() throws IOException {
        final Path file = Files.createTempFile(tempDir, getClass().getSimpleName(), ".hprof");
        final SanitizeCommand cmd = newCommand();
        cmd.setInputFile(Paths.get("foo"));
        cmd.setOutputFile(file);
        cmd.setBufferSize(ofBytes(0));

        streamFactory = new SanitizeStreamFactory(cmd);
        assertThat(streamFactory.newOutputStream())
                .isNotInstanceOf(BufferedOutputStream.class);
    }

    /**
     * A tar is recognized from its contents, not its name: the fixture is called {@code .hprof} and
     * no flag says otherwise.
     */
    @Test
    public void testTarInputIsDetectedFromContent() throws IOException {
        final Path inputFile = Files.createTempFile(tempDir, getClass().getSimpleName(), ".hprof");
        writeTar(inputFile);

        final SanitizeCommand cmd = newCommand();
        cmd.setInputFile(inputFile);
        cmd.setBufferSize(ofBytes(0));

        streamFactory = new SanitizeStreamFactory(cmd);
        assertThat(streamFactory.newInputStream())
                .isInstanceOf(TarArchiveInputStream.class);
    }

    /**
     * The dump is read from the entry, so the total for the progress line is the entry's declared
     * length rather than the archive's -- 12 bytes of content inside a 2 KB tar.
     */
    @Test
    public void testTarInputSizeIsTheEntrySizeNotTheArchiveSize() throws IOException {
        final Path inputFile = Files.createTempFile(tempDir, getClass().getSimpleName(), ".hprof");
        writeTar(inputFile);

        final SanitizeCommand cmd = newCommand();
        cmd.setInputFile(inputFile);
        cmd.setBufferSize(ofBytes(0));

        streamFactory = new SanitizeStreamFactory(cmd);
        streamFactory.newInputStream();

        assertThat(streamFactory.getInputSizeBytes()).isEqualTo(12);
        assertThat(Files.size(inputFile)).isGreaterThan(12);
    }

    /**
     * A zip is recognized from its contents, not its name, and the dump is read out of the entry
     * rather than the file: what comes back is the entry's 10 bytes, not the zip's.
     */
    @Test
    public void testZipInputIsDetectedFromContent() throws IOException {
        final Path inputFile = Files.createTempFile(tempDir, getClass().getSimpleName(), ".hprof");
        writeZip(inputFile, "dump.hprof");

        final SanitizeCommand cmd = newCommand();
        cmd.setInputFile(inputFile);
        cmd.setBufferSize(ofBytes(0));

        streamFactory = new SanitizeStreamFactory(cmd);
        assertThat(IOUtils.toString(streamFactory.newInputStream(), StandardCharsets.UTF_8))
                .isEqualTo("dump.hprof");
    }

    /**
     * A zip states an entry's length in the local header and again in the central directory, and one
     * written streaming -- as this tool writes its own -- fills in only the latter. A zip file is read
     * through the central directory so that the length is there regardless, which is what lets a
     * {@code .zip} input be written back out as a {@code .tar}.
     */
    @Test
    public void testZipInputSizeComesFromTheCentralDirectory() throws IOException {
        final Path inputFile = Files.createTempFile(tempDir, getClass().getSimpleName(), ".hprof");
        writeZip(inputFile, "dump.hprof");

        // written streaming, so the local header carries no length to be had
        try (final ZipArchiveInputStream zipStream = new ZipArchiveInputStream(Files.newInputStream(inputFile))) {
            assertThat(zipStream.getNextEntry().getSize()).isEqualTo(UNKNOWN_TOTAL);
        }

        final SanitizeCommand cmd = newCommand();
        cmd.setInputFile(inputFile);
        cmd.setOutputFile(tempDir.resolve("out.tar"));
        cmd.setBufferSize(ofBytes(0));

        streamFactory = new SanitizeStreamFactory(cmd);
        streamFactory.newInputStream();

        assertThat(streamFactory.getInputSizeBytes()).isEqualTo("dump.hprof".length());
        assertThat(streamFactory.newOutputStream())
                .as("a tar entry declares its length, so the zip's length is what permits this")
                .isInstanceOf(TarArchiveOutputStream.class);
    }

    /**
     * A zip written by {@code capture} holds a {@code .threads.txt} beside the dump, and nothing
     * guarantees the dump comes first, so the entry is chosen by name.
     */
    @Test
    public void testZipInputSkipsNonHprofEntries() throws IOException {
        final Path inputFile = Files.createTempFile(tempDir, getClass().getSimpleName(), ".hprof");
        writeZip(inputFile, "notes.txt", "dump.threads.txt", "dump.hprof");

        final SanitizeCommand cmd = newCommand();
        cmd.setInputFile(inputFile);
        cmd.setBufferSize(ofBytes(0));

        streamFactory = new SanitizeStreamFactory(cmd);
        final InputStream stream = streamFactory.newInputStream();

        assertThat(IOUtils.toString(stream, StandardCharsets.UTF_8)).isEqualTo("dump.hprof");
    }

    /**
     * A zip on stdin cannot be read backwards to its central directory, so a streamed zip's dump has
     * no knowable length -- the one case where the refusal to write a tar is the right answer.
     */
    @Test
    public void testStdinZipInputHasNoKnowableSize() throws IOException {
        final Path zipFile = Files.createTempFile(tempDir, getClass().getSimpleName(), ".zip");
        writeZip(zipFile, "dump.hprof");

        final InputStream stream = withStdin(Files.readAllBytes(zipFile), () -> {
            final SanitizeCommand cmd = newCommand();
            cmd.setInputFile(Paths.get("-"));
            cmd.setBufferSize(ofBytes(0));

            streamFactory = new SanitizeStreamFactory(cmd);
            return streamFactory.newInputStream();
        });

        assertThat(IOUtils.toString(stream, StandardCharsets.UTF_8)).isEqualTo("dump.hprof");
        assertThat(streamFactory.getInputSizeBytes()).isEqualTo(UNKNOWN_TOTAL);
    }

    /**
     * A run opens its input once per pass, so what was found in it is announced by the run rather than
     * by the opening: two passes over the same zip are one archive being reread, and saying so twice
     * reads as a second file having been picked up.
     */
    @Test
    public void testArchiveInputIsAnnouncedOncePerRunNotOncePerPass(final CapturedOutput output) throws IOException {
        final Path inputFile = Files.createTempFile(tempDir, getClass().getSimpleName(), ".hprof");
        writeZip(inputFile, "dump.hprof");

        final SanitizeCommand cmd = newCommand();
        cmd.setInputFile(inputFile);
        cmd.setBufferSize(ofBytes(0));

        streamFactory = new SanitizeStreamFactory(cmd);
        streamFactory.newInputStream().close();
        streamFactory.newInputStream().close();

        assertThat(StringUtils.countMatches(output.toString(), "Reading zip input")).isEqualTo(1);
        assertThat(StringUtils.countMatches(output.toString(), "Entry: dump.hprof")).isEqualTo(1);
    }

    /**
     * There is nothing to announce for a plain dump, which is the common case.
     */
    @Test
    public void testPlainInputIsNotAnnouncedAsAnArchive(final CapturedOutput output) throws IOException {
        final Path inputFile = Files.createTempFile(tempDir, getClass().getSimpleName(), ".hprof");
        Files.write(inputFile, "not an archive".getBytes(StandardCharsets.UTF_8));

        final SanitizeCommand cmd = newCommand();
        cmd.setInputFile(inputFile);
        cmd.setBufferSize(ofBytes(0));

        streamFactory = new SanitizeStreamFactory(cmd);
        streamFactory.newInputStream().close();

        assertThat(output.toString()).doesNotContain("archive");
    }

    @Test
    public void testZipInputWithNoHprofEntryFails() throws IOException {
        final Path inputFile = Files.createTempFile(tempDir, getClass().getSimpleName(), ".hprof");
        writeZip(inputFile, "notes.txt", "dump.threads.txt");

        final SanitizeCommand cmd = newCommand();
        cmd.setInputFile(inputFile);
        cmd.setBufferSize(ofBytes(0));

        streamFactory = new SanitizeStreamFactory(cmd);
        assertThatThrownBy(() -> streamFactory.newInputStream())
                .isInstanceOf(IOException.class)
                .hasMessageContaining("No *.hprof entry in the zip input");
    }

    @Test
    public void testZipOutputFromFileExtension() throws IOException {
        final Path outputFile = Files.createTempFile(tempDir, getClass().getSimpleName(), ".zip");

        final SanitizeCommand cmd = newCommand();
        cmd.setInputFile(Paths.get("foo"));
        cmd.setOutputFile(outputFile);
        cmd.setBufferSize(ofBytes(0));

        streamFactory = new SanitizeStreamFactory(cmd);
        assertThat(streamFactory.newOutputStream())
                .isInstanceOf(ZipOutputStream.class);
    }

    /**
     * The deprecated flag still forces a zip, whatever the output file is called.
     */
    @Test
    public void testZipOutputFlagOverridesExtension() throws IOException {
        final Path outputFile = Files.createTempFile(tempDir, getClass().getSimpleName(), ".hprof");

        final SanitizeCommand cmd = newCommand();
        cmd.setInputFile(Paths.get("foo"));
        cmd.setOutputFile(outputFile);
        cmd.setBufferSize(ofBytes(0));
        cmd.setZipOutput(true);

        streamFactory = new SanitizeStreamFactory(cmd);
        assertThat(streamFactory.newOutputStream())
                .isInstanceOf(ZipOutputStream.class);
    }

    @Test
    public void testTarOutputFromFileExtension() throws IOException {
        final Path inputFile = Files.createTempFile(tempDir, getClass().getSimpleName(), ".hprof");
        FileUtils.write(inputFile.toFile(), "test data", StandardCharsets.UTF_8);

        final SanitizeCommand cmd = newCommand();
        cmd.setInputFile(inputFile);
        cmd.setOutputFile(tempDir.resolve("out.tar"));
        cmd.setBufferSize(ofBytes(0));

        streamFactory = new SanitizeStreamFactory(cmd);
        streamFactory.newInputStream(); // establishes the dump's length, which a tar entry declares
        assertThat(streamFactory.newOutputStream())
                .isInstanceOf(TarArchiveOutputStream.class);
    }

    /**
     * A tar states the entry's length in the header it has just written, so the log says what that is.
     * A zip commits to nothing up front, so there is nothing to state.
     */
    @Test
    public void testTarOutputAnnouncesTheDeclaredEntryLength(final CapturedOutput output) throws IOException {
        final Path inputFile = Files.createTempFile(tempDir, getClass().getSimpleName(), ".hprof");
        FileUtils.write(inputFile.toFile(), "test data", StandardCharsets.UTF_8);

        final SanitizeCommand cmd = newCommand();
        cmd.setInputFile(inputFile);
        cmd.setOutputFile(tempDir.resolve("out.tar"));
        cmd.setBufferSize(ofBytes(0));

        streamFactory = new SanitizeStreamFactory(cmd);
        streamFactory.newInputStream();
        streamFactory.newOutputStream();

        assertThat(output.toString()).contains("Writing tar output: out.tar - 9 bytes");
    }

    /**
     * A tar entry states its length ahead of the data, so an input with no knowable length cannot be
     * written as one. Refused up front rather than part way through writing an archive.
     */
    @Test
    public void testTarOutputOfUnknownLengthInputFails() throws IOException {
        final SanitizeCommand cmd = newCommand();
        cmd.setInputFile(Paths.get("-"));
        cmd.setOutputFile(tempDir.resolve("out.tar"));
        cmd.setBufferSize(ofBytes(0));

        streamFactory = new SanitizeStreamFactory(cmd);
        assertThatIllegalArgumentException()
                .isThrownBy(() -> streamFactory.newOutputStream())
                .withMessageContaining("Cannot write tar output for an input of unknown length");
    }

    /**
     * An output file named neither {@code .tar} nor {@code .zip} is a plain dump, so nothing wraps it.
     */
    @Test
    public void testPlainOutputForOtherExtensions() throws IOException {
        final SanitizeCommand cmd = newCommand();
        cmd.setInputFile(Paths.get("foo"));
        cmd.setOutputFile(tempDir.resolve("out.hprof"));
        cmd.setBufferSize(ofBytes(0));

        streamFactory = new SanitizeStreamFactory(cmd);
        assertThat(streamFactory.newOutputStream())
                .isNotInstanceOf(ZipOutputStream.class)
                .isNotInstanceOf(TarArchiveOutputStream.class);
    }

    /**
     * The output archive is announced alongside the input one, and by the same class, so that a run's
     * log reads as the run rather than as whichever class happened to open a stream.
     */
    @Test
    public void testArchiveOutputIsAnnounced(final CapturedOutput output) throws IOException {
        final SanitizeCommand cmd = newCommand();
        cmd.setInputFile(Paths.get("foo"));
        cmd.setOutputFile(tempDir.resolve("out.zip"));
        cmd.setBufferSize(ofBytes(0));

        streamFactory = new SanitizeStreamFactory(cmd);
        streamFactory.newOutputStream();

        assertThat(output.toString()).contains("Writing zip output: out.zip - size not yet known");
    }

    /**
     * Announced only once it is actually being written. A tar refused for want of a length must not
     * have been claimed as written a line earlier.
     */
    @Test
    public void testRefusedTarOutputIsNotAnnounced(final CapturedOutput output) {
        final SanitizeCommand cmd = newCommand();
        cmd.setInputFile(Paths.get("-"));
        cmd.setOutputFile(tempDir.resolve("out.tar"));
        cmd.setBufferSize(ofBytes(0));

        streamFactory = new SanitizeStreamFactory(cmd);
        assertThatIllegalArgumentException().isThrownBy(() -> streamFactory.newOutputStream());

        assertThat(output.toString()).doesNotContain("Writing");
    }

    /**
     * Nothing to announce for a plain dump, as on the input side.
     */
    @Test
    public void testPlainOutputIsNotAnnouncedAsAnArchive(final CapturedOutput output) throws IOException {
        final SanitizeCommand cmd = newCommand();
        cmd.setInputFile(Paths.get("foo"));
        cmd.setOutputFile(tempDir.resolve("out.hprof"));
        cmd.setBufferSize(ofBytes(0));

        streamFactory = new SanitizeStreamFactory(cmd);
        streamFactory.newOutputStream();

        assertThat(output.toString()).doesNotContain("Writing");
    }

    /**
     * A {@code .tar.gz} is gzip around a tar, so both layers come off and what is read is the dump
     * inside the entry. Detected from content, so the fixture's {@code .hprof} name says nothing.
     */
    @Test
    public void testGzippedTarInputIsUnwrappedThroughBothLayers() throws IOException {
        final Path inputFile = Files.createTempFile(tempDir, getClass().getSimpleName(), ".hprof");
        writeGzip(inputFile, ResourceTool.bytesOf(getClass(), "sample.tar"));

        final SanitizeCommand cmd = newCommand();
        cmd.setInputFile(inputFile);
        cmd.setBufferSize(ofBytes(0));

        streamFactory = new SanitizeStreamFactory(cmd);
        final InputStream stream = streamFactory.newInputStream();

        assertThat(stream).isInstanceOf(TarArchiveInputStream.class);
        assertThat(streamFactory.getInputSizeBytes())
                .as("the tar entry declares its length, which gzip around it does not obscure")
                .isEqualTo(12);
    }

    /**
     * Gzip around a bare dump: nothing to unwrap past the decompression, and what comes out is the
     * dump's own bytes.
     */
    @Test
    public void testGzippedPlainInputIsDecompressed() throws IOException {
        final Path inputFile = Files.createTempFile(tempDir, getClass().getSimpleName(), ".hprof");
        final String dump = StringUtils.repeat("not an archive. ", 100);
        writeGzip(inputFile, dump.getBytes(StandardCharsets.UTF_8));

        final SanitizeCommand cmd = newCommand();
        cmd.setInputFile(inputFile);
        cmd.setBufferSize(ofBytes(0));

        streamFactory = new SanitizeStreamFactory(cmd);
        final InputStream stream = streamFactory.newInputStream();

        assertThat(IOUtils.toString(stream, StandardCharsets.UTF_8)).isEqualTo(dump);
    }

    /**
     * The file's own length measures compressed bytes, several times short of what will be read out of
     * it, so it must not stand for the dump's -- as a progress total it would read as several hundred
     * percent, and as a tar entry length it would declare an entry shorter than its own contents.
     */
    @Test
    public void testGzippedPlainInputHasNoKnowableSize() throws IOException {
        final Path inputFile = Files.createTempFile(tempDir, getClass().getSimpleName(), ".hprof");
        writeGzip(inputFile, StringUtils.repeat("compresses well. ", 1000).getBytes(StandardCharsets.UTF_8));

        final SanitizeCommand cmd = newCommand();
        cmd.setInputFile(inputFile);
        cmd.setOutputFile(tempDir.resolve("out.tar"));
        cmd.setBufferSize(ofBytes(0));

        streamFactory = new SanitizeStreamFactory(cmd);
        streamFactory.newInputStream();

        assertThat(Files.size(inputFile)).isLessThan(17000); // it did compress, so the file size lies
        assertThat(streamFactory.getInputSizeBytes()).isEqualTo(UNKNOWN_TOTAL);
        assertThatIllegalArgumentException()
                .as("no length to declare, so a tar entry cannot be written")
                .isThrownBy(() -> streamFactory.newOutputStream());
    }

    /**
     * A gzipped tar on stdin, which is {@code kubectl cp} piped through {@code gzip}: no name to go by
     * and no rewinding, so both layers are found by sniffing.
     */
    @Test
    public void testStdinGzippedTarInputIsDetected(final CapturedOutput output) throws IOException {
        final Path gzFile = Files.createTempFile(tempDir, getClass().getSimpleName(), ".tar.gz");
        writeGzip(gzFile, ResourceTool.bytesOf(getClass(), "sample.tar"));

        final InputStream stream = withStdin(Files.readAllBytes(gzFile), () -> {
            final SanitizeCommand cmd = newCommand();
            cmd.setInputFile(Paths.get("-"));
            cmd.setBufferSize(ofBytes(0));

            streamFactory = new SanitizeStreamFactory(cmd);
            return streamFactory.newInputStream();
        });

        assertThat(stream).isInstanceOf(TarArchiveInputStream.class);
        assertThat(streamFactory.getInputSizeBytes()).isEqualTo(12);
        assertThat(output.toString())
                .as("a pipe is called stdin, not the '-' that named it")
                .contains("Reading tar.gz input: stdin - 12 bytes");
    }

    /**
     * {@code gzip} and {@code cat} both produce multi-member files, and stopping at the first member's
     * end would truncate the dump without saying so.
     */
    @Test
    public void testConcatenatedGzipMembersAreAllRead() throws IOException {
        final Path inputFile = Files.createTempFile(tempDir, getClass().getSimpleName(), ".hprof");
        try (final OutputStream stream = Files.newOutputStream(inputFile)) {
            for (final String part : new String[]{"first half. ", "second half."}) {
                final GzipCompressorOutputStream member = new GzipCompressorOutputStream(stream);
                member.write(part.getBytes(StandardCharsets.UTF_8));
                member.finish(); // not close(), which would close the file under the next member
            }
        }

        final SanitizeCommand cmd = newCommand();
        cmd.setInputFile(inputFile);
        cmd.setBufferSize(ofBytes(0));

        streamFactory = new SanitizeStreamFactory(cmd);
        assertThat(IOUtils.toString(streamFactory.newInputStream(), StandardCharsets.UTF_8))
                .isEqualTo("first half. second half.");
    }

    /**
     * {@code .tar.gz} asks for both layers, in that order: gzip outside, tar inside, as {@code tar czf}
     * writes it. So what lands on disk is readable by {@code tar tzf} and by this tool alike.
     */
    @Test
    public void testGzippedTarOutputIsGzipAroundTar() throws IOException {
        final Path inputFile = Files.createTempFile(tempDir, getClass().getSimpleName(), ".hprof");
        FileUtils.write(inputFile.toFile(), "test data", StandardCharsets.UTF_8);
        final Path outputFile = tempDir.resolve("out.tar.gz");

        final SanitizeCommand cmd = newCommand();
        cmd.setInputFile(inputFile);
        cmd.setOutputFile(outputFile);
        cmd.setBufferSize(ofBytes(0));

        streamFactory = new SanitizeStreamFactory(cmd);
        streamFactory.newInputStream(); // establishes the dump's length, which a tar entry declares
        try (final OutputStream stream = streamFactory.newOutputStream()) {
            stream.write("test data".getBytes(StandardCharsets.UTF_8));
        }

        try (final TarArchiveInputStream tarStream = new TarArchiveInputStream(
                new GzipCompressorInputStream(Files.newInputStream(outputFile)))) {
            assertThat(tarStream.getNextEntry().getName()).isEqualTo("out.hprof");
            assertThat(IOUtils.toString(tarStream, StandardCharsets.UTF_8)).isEqualTo("test data");
        }
    }

    /**
     * {@code .tgz} is {@code .tar.gz} written short, so it means the same two layers and the entry
     * inside is named as though the long form had been used.
     */
    @Test
    public void testTgzOutputMeansTheSameAsTarGz() throws IOException {
        final Path inputFile = Files.createTempFile(tempDir, getClass().getSimpleName(), ".hprof");
        FileUtils.write(inputFile.toFile(), "test data", StandardCharsets.UTF_8);
        final Path outputFile = tempDir.resolve("out.tgz");

        final SanitizeCommand cmd = newCommand();
        cmd.setInputFile(inputFile);
        cmd.setOutputFile(outputFile);
        cmd.setBufferSize(ofBytes(0));

        streamFactory = new SanitizeStreamFactory(cmd);
        streamFactory.newInputStream();
        try (final OutputStream stream = streamFactory.newOutputStream()) {
            stream.write("test data".getBytes(StandardCharsets.UTF_8));
        }

        try (final TarArchiveInputStream tarStream = new TarArchiveInputStream(
                new GzipCompressorInputStream(Files.newInputStream(outputFile)))) {
            assertThat(tarStream.getNextEntry().getName()).isEqualTo("out.hprof");
        }
    }

    /**
     * A {@code .gz} with no archive extension under it is a gzipped bare dump -- no tar, no zip, so no
     * entry and no length needed.
     */
    @Test
    public void testGzippedPlainOutputHasNoArchiveAroundIt() throws IOException {
        final Path outputFile = tempDir.resolve("out.hprof.gz");

        final SanitizeCommand cmd = newCommand();
        cmd.setInputFile(Paths.get("-"));
        cmd.setOutputFile(outputFile);
        cmd.setBufferSize(ofBytes(0));

        streamFactory = new SanitizeStreamFactory(cmd);
        try (final OutputStream stream = streamFactory.newOutputStream()) {
            stream.write("test data".getBytes(StandardCharsets.UTF_8));
        }

        try (final InputStream stream = new GzipCompressorInputStream(Files.newInputStream(outputFile))) {
            assertThat(IOUtils.toString(stream, StandardCharsets.UTF_8)).isEqualTo("test data");
        }
    }

    /**
     * Written by this tool, read back by it: the round trip is what a user piping between two runs
     * depends on.
     */
    @Test
    public void testGzippedTarOutputReadsBackAsInput() throws IOException {
        final Path inputFile = Files.createTempFile(tempDir, getClass().getSimpleName(), ".hprof");
        FileUtils.write(inputFile.toFile(), "test data", StandardCharsets.UTF_8);
        final Path archive = tempDir.resolve("round.tar.gz");

        final SanitizeCommand writeCmd = newCommand();
        writeCmd.setInputFile(inputFile);
        writeCmd.setOutputFile(archive);
        writeCmd.setBufferSize(ofBytes(0));

        final SanitizeStreamFactory writer = new SanitizeStreamFactory(writeCmd);
        writer.newInputStream();
        try (final OutputStream stream = writer.newOutputStream()) {
            stream.write("test data".getBytes(StandardCharsets.UTF_8));
        }

        final SanitizeCommand readCmd = newCommand();
        readCmd.setInputFile(archive);
        readCmd.setBufferSize(ofBytes(0));

        streamFactory = new SanitizeStreamFactory(readCmd);
        assertThat(IOUtils.toString(streamFactory.newInputStream(), StandardCharsets.UTF_8))
                .isEqualTo("test data");
        assertThat(streamFactory.getInputSizeBytes()).isEqualTo("test data".length());
    }

    /**
     * The compressed size is only knowable once the file is closed, so it is reported then rather than
     * guessed at up front -- and the two lines name the layers the same way.
     */
    @Test
    public void testGzippedOutputSizeIsReportedOnceWritten(final CapturedOutput output) throws IOException {
        final Path inputFile = Files.createTempFile(tempDir, getClass().getSimpleName(), ".hprof");
        FileUtils.write(inputFile.toFile(), "test data", StandardCharsets.UTF_8);

        final SanitizeCommand cmd = newCommand();
        cmd.setInputFile(inputFile);
        cmd.setOutputFile(tempDir.resolve("out.tar.gz"));
        cmd.setBufferSize(ofBytes(0));

        streamFactory = new SanitizeStreamFactory(cmd);
        streamFactory.newInputStream();
        final OutputStream stream = streamFactory.newOutputStream();

        assertThat(output.toString())
                .as("the dump's length is known up front, being what the tar entry declares")
                .contains("Writing tar.gz output: out.tar.gz - 9 bytes");
        assertThat(output.toString())
                .as("nothing is on disk yet, so nothing is claimed written")
                .doesNotContain("Wrote");

        stream.write("test data".getBytes(StandardCharsets.UTF_8));
        stream.close();

        assertThat(output.toString()).containsPattern("Wrote tar.gz output: out\\.tar\\.gz - \\d+ bytes");
    }

    /**
     * Reported once, however many times the stream is closed -- {@code close()} is idempotent by
     * contract, and {@code CaptureStreamFactory} does close its output a second time.
     */
    @Test
    public void testWroteOutputIsReportedOnce(final CapturedOutput output) throws IOException {
        final SanitizeCommand cmd = newCommand();
        cmd.setInputFile(Paths.get("-"));
        cmd.setOutputFile(tempDir.resolve("out.zip"));
        cmd.setBufferSize(ofBytes(0));

        streamFactory = new SanitizeStreamFactory(cmd);
        final OutputStream stream = streamFactory.newOutputStream();
        stream.write("test data".getBytes(StandardCharsets.UTF_8));
        stream.close();
        stream.close();

        assertThat(StringUtils.countMatches(output.toString(), "Wrote zip output")).isEqualTo(1);
    }

    /**
     * A plain dump is not an archive and not compressed, so neither line has anything to report.
     */
    @Test
    public void testPlainOutputIsNotReportedAsWritten(final CapturedOutput output) throws IOException {
        final SanitizeCommand cmd = newCommand();
        cmd.setInputFile(Paths.get("-"));
        cmd.setOutputFile(tempDir.resolve("out.hprof"));
        cmd.setBufferSize(ofBytes(0));

        streamFactory = new SanitizeStreamFactory(cmd);
        streamFactory.newOutputStream().close();

        assertThat(output.toString()).doesNotContain("Wrote");
    }

    @Test
    public void testSameInputOutput() {
        final SanitizeCommand cmd = newCommand();
        cmd.setInputFile(Paths.get("foo"));
        cmd.setOutputFile(Paths.get("foo"));

        assertThatIllegalArgumentException()
                .isThrownBy(() -> new SanitizeStreamFactory(cmd));
    }

    private void writeTar(final Path destPath) throws IOException {
        final byte[] srcBytes = ResourceTool.bytesOf(getClass(), "sample.tar");
        Files.write(destPath, srcBytes, TRUNCATE_EXISTING);
    }

    /**
     * Writes {@code content} gzipped, as {@code gzip} would.
     */
    private void writeGzip(final Path destPath, final byte[] content) throws IOException {
        try (final OutputStream stream = new GzipCompressorOutputStream(Files.newOutputStream(destPath))) {
            stream.write(content);
        }
    }

    /**
     * Writes a zip holding one entry per name, each containing its own name as its content, so a test
     * can tell which entry it was handed.
     */
    private void writeZip(final Path destPath, final String... entryNames) throws IOException {
        try (final ZipOutputStream zipStream = new ZipOutputStream(Files.newOutputStream(destPath))) {
            for (final String entryName : entryNames) {
                zipStream.putNextEntry(new ZipEntry(entryName));
                zipStream.write(entryName.getBytes(StandardCharsets.UTF_8));
            }
        }
    }

    /**
     * Runs {@code action} with {@code System.in} replaced by {@code content}, restoring it afterwards.
     * The real {@code System.in} under a test runner is an empty or idle stream, and detection reads
     * from it.
     */
    private <T> T withStdin(final String content, final Callable<T> action) throws IOException {
        return withStdin(content.getBytes(StandardCharsets.UTF_8), action);
    }

    private <T> T withStdin(final byte[] content, final Callable<T> action) throws IOException {
        final InputStream originalStdin = System.in;
        System.setIn(new ByteArrayInputStream(content));
        try {
            return action.call();
        } catch (final IOException e) {
            throw e;
        } catch (final Exception e) {
            throw new IllegalStateException(e);
        } finally {
            System.setIn(originalStdin);
        }
    }

    private SanitizeCommand newCommand() {
        final SanitizeCommand cmd = new SanitizeCommand();
        cmd.setInputFile(Paths.get("input.txt"));
        cmd.setOutputFile(Paths.get("output.txt"));
        return cmd;
    }
}
