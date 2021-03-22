package com.paypal.heapdumptool.sanitizer;

import com.paypal.heapdumptool.utils.ProgressMonitor;
import org.apache.commons.io.IOUtils;
import org.apache.commons.io.input.BoundedInputStream;
import org.apache.commons.lang3.Validate;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * For piping or copying data from input to output streams.
 * Along the way, different data can be written by calling {@link #copyFrom(InputStream, long)} or {@link #writeU1(int)} methods.
 */
public class Pipe {

    private final DataInputStream input;
    private final DataOutputStream output;
    private Integer idSize;

    public Pipe(final InputStream input, final OutputStream output, final ProgressMonitor numBytesWrittenMonitor) {
        this.input = new DataInputStream(input);
        this.output = new DataOutputStream(numBytesWrittenMonitor.monitoredOutputStream(output));
    }

    private Pipe(final DataInputStream input, final DataOutputStream output, final Integer idSize) {
        this.input = input;
        this.output = output;
        this.idSize = idSize;
    }

    /**
     * Creates a copy of this pipe where only up to give count of bytes can read from input stream
     */
    public Pipe newInputBoundedPipe(final long inputCount) {
        final DataInputStream boundedInput = new DataInputStream(new BoundedInputStream(input, inputCount));
        return new Pipe(boundedInput, output, idSize);
    }

    public int getIdSize() {
        return idSize;
    }

    public void setIdSize(final int idSize) {
        Validate.isTrue(idSize == 4 || idSize == 8, "Unknown id size: %s", idSize);
        this.idSize = idSize;
    }

    public int readU1() throws IOException {
        return input.read();
    }

    public void writeU1(final int u1) throws IOException {
        output.write(u1);
    }

    public void copyFrom(final InputStream inputStream, final long count) throws IOException {
        IOUtils.copyLarge(inputStream, output, 0, count);
    }

    public int pipeU1() throws IOException {
        final int u1 = input.read();
        output.write(u1);
        return u1;
    }

    public int pipeU1IfPossible() throws IOException {
        final int u1 = input.read();
        if (u1 != -1) {
            output.write(u1);
        }
        return u1;
    }

    public int pipeU2() throws IOException {
        final int u2 = input.readShort();
        output.writeShort(u2);
        return u2;
    }

    public long pipeU4() throws IOException {
        final int u4 = input.readInt();
        output.writeInt(u4);
        return Integer.toUnsignedLong(u4);
    }

    public long pipeId() throws IOException {
        if (idSize == 4) {
            return pipeU4();
        } else {
            final long value = input.readLong();
            output.writeLong(value);
            Validate.isTrue(value >= 0, "Small unsigned long expected");
            return value;
        }
    }

    public void pipe(final long count) throws IOException {
        IOUtils.copyLarge(input, output, 0, count);
    }

    public void skipInput(final long count) throws IOException {
        IOUtils.skipFully(input, count);
    }

    public String pipeNullTerminatedString() throws IOException {
        int byteValue = Integer.MAX_VALUE;
        final StringBuilder sb = new StringBuilder();
        while (byteValue > 0) {
            byteValue = input.read();
            if (byteValue >= 0) {
                output.write(byteValue);
                sb.append((char) byteValue);
            }
        }
        return sb.toString();
    }
}
