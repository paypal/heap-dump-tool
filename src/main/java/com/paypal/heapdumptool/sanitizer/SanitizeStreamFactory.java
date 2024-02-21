package com.paypal.heapdumptool.sanitizer;

import org.apache.commons.compress.archivers.tar.TarArchiveInputStream;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.Validate;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import static java.lang.Math.toIntExact;

/**
 * Creates i/o streams for input/output files
 */
public class SanitizeStreamFactory {

    private final SanitizeCommand command;

    public SanitizeStreamFactory(final SanitizeCommand command) {
        this.command = validate(command);
    }

    public InputStream newInputStream() throws IOException {
        final Path inputFile = command.getInputFile();
        final InputStream inputStream = getBufferSize() == 0
                                        ? newInputStream(inputFile)
                                        : new BufferedInputStream(newInputStream(inputFile), getBufferSize());

        if (command.isTarInput()) {
            final TarArchiveInputStream tarStream = new TarArchiveInputStream(inputStream);
            Validate.notNull(tarStream.getNextEntry(), "no tar entries");
            return tarStream;
        }
        return inputStream;
    }

    public OutputStream newOutputStream() throws IOException {
        final Path outputFile = command.getOutputFile();
        final OutputStream output = getBufferSize() == 0
                                    ? Files.newOutputStream(outputFile)
                                    : new BufferedOutputStream(Files.newOutputStream(outputFile), getBufferSize());

        if (command.isZipOutput()) {
            final ZipOutputStream zipStream = new ZipOutputStream(output);
            final String name = getOutputFileName();
            final String entryName = StringUtils.removeEnd(name, ".zip");
            zipStream.putNextEntry(new ZipEntry(entryName));
            return zipStream;
        }
        return output;
    }

    protected InputStream newInputStream(final Path inputFile) throws IOException {
        final String name = inputFile.getFileName().toString();
        return StringUtils.equalsAny(name, "-", "stdin", "0")
               ? System.in
               : Files.newInputStream(inputFile);
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

    private int getBufferSize() {
        final DataSize bufferSize = command.getBufferSize();
        return toIntExact(bufferSize.toBytes());
    }

}
