package com.paypal.heapdumptool.sanitizer;

import com.paypal.heapdumptool.utils.ProgressMonitor;
import org.apache.commons.io.IOUtils;
import org.apache.commons.io.input.BoundedInputStream;
import org.apache.commons.lang3.Validate;

import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;

/**
 * For piping or copying data from input to output streams.
 * Along the way, different data can be written by calling {@link #copyFrom(InputStream, long)} or {@link #writeU1(int)} methods.
 */
public class Pipe {

    private static final int COPY_BUFFER_SIZE = 8192;

    private final DataInputStream input;
    private final DataOutputStream output;

    /*
     * One scratch buffer for every copy this pipe and its bounded children perform. Not an allocation
     * saving: the IOUtils.copyLarge overload without a buffer reuses a ThreadLocal scratch array, so
     * it allocates nothing either. It does Arrays.fill it to zero on every call, though, and pipe() is
     * called at least once per record of the dump, so passing our own buffer skips an 8 KB zero-fill
     * per record. Worth a few percent of wall clock, nothing measurable in allocation.
     *
     * Safe to share: copying is strictly sequential -- a copy never runs while another is in progress
     * -- and a bounded child pipe reads the same underlying input as its parent.
     */
    private final byte[] copyBuffer;

    private Integer idSize;

    public Pipe(final InputStream input, final OutputStream output, final ProgressMonitor numBytesWrittenMonitor) {
        this.input = new DataInputStream(input);
        this.output = new DataOutputStream(numBytesWrittenMonitor.monitoredOutputStream(output));
        this.copyBuffer = new byte[COPY_BUFFER_SIZE];
    }

    private Pipe(final DataInputStream input, final DataOutputStream output, final Integer idSize, final byte[] copyBuffer) {
        this.input = input;
        this.output = output;
        this.idSize = idSize;
        this.copyBuffer = copyBuffer;
    }

    /**
     * Creates a copy of this pipe where only up to give count of bytes can read from input stream
     */
    @SuppressWarnings("deprecation")
    public Pipe newInputBoundedPipe(final long inputCount) {
        final DataInputStream boundedInput = new DataInputStream(new BoundedInputStream(input, inputCount));
        return new Pipe(boundedInput, output, idSize, copyBuffer);
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

    public byte[] read(final long numBytes) throws IOException {
        final ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        IOUtils.copyLarge(input, byteArrayOutputStream, 0, numBytes);
        return byteArrayOutputStream.toByteArray();
    }

    public void writeU1(final int u1) throws IOException {
        output.write(u1);
    }

    public void write(final byte[] bytes) throws IOException {
        IOUtils.write(bytes, output);
    }

    public void write(final byte[] bytes, final int offset, final int length) throws IOException {
        output.write(bytes, offset, length);
    }

    public void copyFrom(final InputStream inputStream, final long count) throws IOException {
        IOUtils.copyLarge(inputStream, output, 0, count, copyBuffer);
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
        IOUtils.copyLarge(input, output, 0, count, copyBuffer);
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

    public String pipeString(final long numBytes) throws IOException {
        final byte[] bytes = read(numBytes);
        write(bytes);
        return new String(bytes, StandardCharsets.UTF_8);
    }
}
