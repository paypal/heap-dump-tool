package com.paypal.heapdumptool.sanitizer;

import org.apache.commons.compress.archivers.tar.TarArchiveInputStream;
import org.apache.commons.compress.archivers.zip.ZipArchiveInputStream;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.Strings;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * The archive formats a heap dump may arrive in or be written to.
 *
 * <p>Input is decided by {@linkplain #detect(InputStream) sniffing the bytes} rather than by the file
 * name, because the input can be a pipe with no name at all -- {@code kubectl cp} yields a tar on
 * stdin -- and because a name is only a claim about the contents. Output is decided by
 * {@linkplain #ofOutputFile(Path) the file extension}, since there are no bytes to sniff yet and the
 * extension is the only statement of intent available.</p>
 */
enum ArchiveFormat {

    /**
     * Not an archive: the dump is the stream.
     */
    NONE,

    TAR,

    ZIP;

    /**
     * Bytes to sniff before deciding. Both signatures live in the first entry header, well inside
     * this, but a tar's magic sits at offset 257 and {@link TarArchiveInputStream#matches} demands a
     * full record, so it takes the whole 512.
     */
    static final int SIGNATURE_LENGTH = 512;

    /**
     * What a heap dump is called: the extension an entry is selected by on the way in, and given on
     * the way out.
     */
    static final String HPROF_SUFFIX = ".hprof";

    /**
     * The format the given leading bytes indicate, or {@link #NONE} if they match no archive.
     *
     * @param signature the first bytes of the stream
     * @param length    how many of them were actually read, which may be short of the array on a
     *                  stream smaller than {@link #SIGNATURE_LENGTH}
     */
    static ArchiveFormat detect(final byte[] signature, final int length) {
        /*
         * Ordered zip first only for speed: a zip signature is 4 bytes at offset 0, a tar's is a
         * checksum over a 512-byte record. The two cannot both match -- a tar's first 4 bytes are
         * part of a file name -- so the order does not affect the answer.
         */
        if (ZipArchiveInputStream.matches(signature, length)) {
            return ZIP;
        }
        if (TarArchiveInputStream.matches(signature, length)) {
            return TAR;
        }
        return NONE;
    }

    /**
     * The format of the given file, from its leading bytes.
     *
     * <p>A file short of a signature, or missing entirely, is {@link #NONE}: whatever it is, it is
     * not an archive, and a file that cannot be opened at all is the sanitizer's error to report from
     * the stream it fails to read, in its own terms.</p>
     */
    static ArchiveFormat ofInputFile(final Path inputFile) {
        final byte[] signature = new byte[SIGNATURE_LENGTH];
        try (final InputStream stream = Files.newInputStream(inputFile)) {
            return detect(signature, IOUtils.read(stream, signature));
        } catch (final IOException e) {
            return NONE;
        }
    }

    /**
     * The format to write for the given output file, by extension: {@code .tar} is a tar,
     * {@code .zip} a zip, anything else the bare dump.
     *
     * <p>Read underneath any compression extension, which is the outer layer: {@code .tar.gz} is a
     * tar, and so is {@code .tgz}, that being the same name shortened. A {@code .gz} with nothing
     * under it -- {@code dump.hprof.gz} -- is a compressed bare dump.</p>
     *
     * <p>Matched case-insensitively, since the extension is a user-typed file name rather than
     * anything the format specifies.</p>
     */
    static ArchiveFormat ofOutputFile(final Path outputFile) {
        final String name = withoutCompressionExtension(outputFile.getFileName().toString());
        if (Strings.CI.endsWith(name, ".tar")) {
            return TAR;
        }
        if (Strings.CI.endsWith(name, ".zip")) {
            return ZIP;
        }
        return NONE;
    }

    /*
     * The name with the compression extension taken off, so the archive extension underneath can be
     * read: dump.tar.gz is a tar, and dump.tgz is the same name written short.
     */
    static String withoutCompressionExtension(final String fileName) {
        if (Strings.CI.endsWith(fileName, ".tgz")) {
            return Strings.CI.removeEnd(fileName, ".tgz") + ".tar";
        }
        return Strings.CI.removeEnd(fileName, ".gz");
    }

    /**
     * The name for the dump entry inside an archive named {@code archiveFileName}: the archive's own
     * name with the archive extension removed, so {@code dump.hprof.zip} holds {@code dump.hprof}.
     *
     * <p>The entry always ends in {@code .hprof}, since what is in it is a heap dump and the analysis
     * tools go by the extension. So {@code dump.tar} holds {@code dump.hprof} rather than a
     * extensionless {@code dump}, and an archive named nothing but its extension falls back to
     * {@code heapdump.hprof} rather than leaving the entry unnamed.</p>
     */
    String entryName(final String archiveFileName) {
        if (this == NONE) {
            throw new IllegalStateException("not an archive");
        }
        final String extension = this == TAR ? ".tar" : ".zip";
        final String name = Strings.CI.removeEnd(archiveFileName, extension);
        if (name.isEmpty()) {
            return "heapdump" + HPROF_SUFFIX;
        }
        return Strings.CI.endsWith(name, HPROF_SUFFIX) ? name : name + HPROF_SUFFIX;
    }

    /**
     * How this format names itself in a log line or an error message.
     */
    String displayName() {
        return name().toLowerCase();
    }
}
