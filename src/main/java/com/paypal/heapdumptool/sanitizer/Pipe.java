package com.paypal.heapdumptool.sanitizer;

import com.paypal.heapdumptool.utils.ProgressMonitor;
import org.apache.commons.io.IOUtils;
import org.apache.commons.io.input.BoundedInputStream;
import org.apache.commons.lang3.Validate;
import org.apache.commons.lang3.mutable.MutableLong;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;

/**
 * For piping or copying data from input to output streams.
 * Along the way, different data can be written by calling {@link #copyFrom(InputStream, long)} or {@link #writeU1(int)} methods.
 *
 * <p>A pipe from {@link #readOnlyPipe(InputStream, ProgressMonitor)} has no output: it parses the
 * input identically but writes nothing and seeks over bulk regions.</p>
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

    /*
     * Non-null only in read-only mode, where the output stream that normally reports progress is
     * absent. Shared with bounded children so a segment's child adds to the parent's total.
     */
    private final MutableLong bytesConsumed;

    private final ProgressMonitor monitor;

    private boolean skipSupported = true;

    private Integer idSize;

    public Pipe(final InputStream input, final OutputStream output, final ProgressMonitor numBytesWrittenMonitor) {
        this.input = new DataInputStream(input);
        this.output = new DataOutputStream(numBytesWrittenMonitor.monitoredOutputStream(output));
        this.monitor = numBytesWrittenMonitor;
        this.copyBuffer = new byte[COPY_BUFFER_SIZE];
        this.bytesConsumed = null;
    }

    /**
     * Creates a pipe that reads but never writes, for the metadata-collection pass whose output is
     * discarded. Every write method is a no-op and {@link #pipe(long)} seeks instead of copying.
     *
     * <p>Progress cannot come from the output stream here, so this pipe reports the bytes it has
     * <em>consumed</em> to the monitor instead. The counter is shared with bounded children, the same
     * way {@link #copyBuffer} is, so one record's child contributes to a single running total.</p>
     */
    public static Pipe readOnlyPipe(final InputStream input, final ProgressMonitor numBytesConsumedMonitor) {
        return new Pipe(new DataInputStream(input), null, null, new byte[COPY_BUFFER_SIZE],
                        numBytesConsumedMonitor, new MutableLong());
    }

    private Pipe(final DataInputStream input,
                 final DataOutputStream output,
                 final Integer idSize,
                 final byte[] copyBuffer,
                 final ProgressMonitor monitor,
                 final MutableLong bytesConsumed) {
        this.input = input;
        this.output = output;
        this.idSize = idSize;
        this.copyBuffer = copyBuffer;
        this.monitor = monitor;
        this.bytesConsumed = bytesConsumed;
    }

    /**
     * Creates a copy of this pipe where only up to give count of bytes can read from input stream
     */
    @SuppressWarnings("deprecation")
    public Pipe newInputBoundedPipe(final long inputCount) {
        final DataInputStream boundedInput = new DataInputStream(new BoundedInputStream(input, inputCount));
        return new Pipe(boundedInput, output, idSize, copyBuffer, monitor, bytesConsumed);
    }

    public int getIdSize() {
        return idSize;
    }

    public void setIdSize(final int idSize) {
        Validate.isTrue(idSize == 4 || idSize == 8, "Unknown id size: %s", idSize);
        this.idSize = idSize;
    }

    private boolean isReadOnly() {
        return output == null;
    }

    public int readU1() throws IOException {
        return input.read();
    }

    public void writeU1(final int u1) throws IOException {
        if (isReadOnly()) {
            return;
        }
        output.write(u1);
    }

    public void write(final byte[] bytes) throws IOException {
        if (isReadOnly()) {
            return;
        }
        IOUtils.write(bytes, output);
    }

    public void write(final byte[] bytes, final int offset, final int length) throws IOException {
        if (isReadOnly()) {
            return;
        }
        output.write(bytes, offset, length);
    }

    public void copyFrom(final InputStream inputStream, final long count) throws IOException {
        if (isReadOnly()) {
            return;
        }
        IOUtils.copyLarge(inputStream, output, 0, count, copyBuffer);
    }

    public int pipeU1() throws IOException {
        final int u1 = input.read();
        if (!isReadOnly()) {
            output.write(u1);
        }
        return u1;
    }

    public int pipeU1IfPossible() throws IOException {
        final int u1 = input.read();
        if (u1 != -1 && !isReadOnly()) {
            output.write(u1);
        }
        return u1;
    }

    public int pipeU2() throws IOException {
        final int u2 = input.readShort();
        if (!isReadOnly()) {
            output.writeShort(u2);
        }
        return u2;
    }

    public long pipeU4() throws IOException {
        final int u4 = input.readInt();
        if (!isReadOnly()) {
            output.writeInt(u4);
        }
        return Integer.toUnsignedLong(u4);
    }

    public long pipeId() throws IOException {
        if (idSize == 4) {
            return pipeU4();
        }
        final long value = input.readLong();
        if (!isReadOnly()) {
            output.writeLong(value);
        }
        Validate.isTrue(value >= 0, "Small unsigned long expected");
        return value;
    }

    public void pipe(final long count) throws IOException {
        if (isReadOnly()) {
            seekInput(count);
            return;
        }
        IOUtils.copyLarge(input, output, 0, count, copyBuffer);
    }

    /*
     * Advances the input without materializing its bytes, which is the whole point of the read-only
     * pass: BufferedFileChannelInputStream.skip consumes what is buffered and then repositions the
     * FileChannel, so a multi-megabyte region costs nothing.
     *
     * Deliberately not IOUtils.skipFully, which documents that it uses read() rather than delegating
     * to skip() -- it would touch every byte and save nothing.
     *
     * Stopping short at EOF is not an error: the writing path is a copyLarge that also stops at EOF,
     * so both modes agree on a truncated final record.
     */
    private void seekInput(final long count) throws IOException {
        long remaining = count;
        while (remaining > 0) {
            final long skipped = trySkip(remaining);
            if (skipped > 0) {
                remaining -= skipped;
                continue;
            }
            // skip() returned 0 or is unsupported: fall back to reading, which also detects EOF
            final int read = input.read(copyBuffer, 0, (int) Math.min(remaining, copyBuffer.length));
            if (read < 0) {
                break;
            }
            remaining -= read;
        }
        recordBytesConsumed(count - remaining);
    }

    private long trySkip(final long count) throws IOException {
        if (!skipSupported) {
            return 0;
        }
        try {
            return input.skip(count);
        } catch (final IOException e) {
            skipSupported = false;
            return 0;
        }
    }

    private void recordBytesConsumed(final long count) {
        if (bytesConsumed == null) {
            return;
        }
        bytesConsumed.add(count);
        monitor.accept(bytesConsumed.longValue());
    }

    public void skipInput(final long count) throws IOException {
        IOUtils.skipFully(input, count);
        recordBytesConsumed(count);
    }

    public String pipeNullTerminatedString() throws IOException {
        int byteValue = Integer.MAX_VALUE;
        final StringBuilder sb = new StringBuilder();
        while (byteValue > 0) {
            byteValue = input.read();
            if (byteValue >= 0) {
                if (!isReadOnly()) {
                    output.write(byteValue);
                }
                sb.append((char) byteValue);
            }
        }
        return sb.toString();
    }

    /**
     * Transfers exactly {@code numBytes} from input to output, decoding nothing.
     *
     * <p>Differs from {@link #pipe(long)} in demanding the bytes be there: a heap dump that ends
     * mid-record is corrupt, so a record whose declared length overruns the file is an
     * {@link java.io.EOFException} rather than a short read.</p>
     */
    public void pipeExactly(final long numBytes) throws IOException {
        pipeExactly(numBytes, false, (byte) 0, (byte) 0);
        // no String is built: see the note on borrowing copyBuffer
    }

    /**
     * As {@link #pipeExactly(long)}, but additionally returns the bytes decoded as UTF-8 with every
     * {@code match} replaced by {@code replacement}. What is written through is unaffected -- the
     * substitution applies only to the value handed back.
     *
     * <p>Saves a whole copy of the string versus decoding and then calling {@code String.replace},
     * which allocates a second String for every value containing the character. Here the bytes are
     * edited in the read buffer, before the single decode.</p>
     *
     * <p>Both characters must be ASCII, which is what makes the byte-level edit equivalent to the
     * character-level one: every byte of a multi-byte UTF-8 sequence has its high bit set, so a byte
     * below 0x80 can only be that character standing alone, never part of something larger.</p>
     */
    public String pipeStringReplacing(final long numBytes, final char match, final char replacement) throws IOException {
        Validate.isTrue(match < 0x80 && replacement < 0x80, "ASCII expected: %s, %s", match, replacement);
        return pipeExactly(numBytes, true, (byte) match, (byte) replacement);
    }

    /*
     * Reads into copyBuffer rather than a per-call array. STRING_IN_UTF8 is the most numerous record
     * type in a dump -- roughly 1.4 mil of them totaling some 90 MB on a 1.2 GB sample -- so an
     * exact-sized array per record is millions of allocations for bytes that never outlive the call.
     * Virtually all of those records fit in the 8 KB buffer; a longer one (the format caps a record at
     * 64 KB) gets its own array, because growing the shared buffer to suit the rare case would also
     * change the chunk size of every pipe() copy.
     *
     * Borrowing is safe for the same reason sharing it across copies is: transfers are strictly
     * sequential, so nothing else is mid-copy, and the buffer never escapes -- callers get a String or
     * nothing.
     */
    private String pipeExactly(final long numBytes,
                               final boolean wantString,
                               final byte match,
                               final byte replacement) throws IOException {
        final int length = Math.toIntExact(numBytes);
        final byte[] bytes = length <= copyBuffer.length ? copyBuffer : new byte[length];

        input.readFully(bytes, 0, length);
        recordBytesConsumed(length);
        // before any substitution: what goes downstream is the record exactly as it was read
        write(bytes, 0, length);

        if (!wantString) {
            return null;
        }
        for (int i = 0; i < length; i++) {
            if (bytes[i] == match) {
                bytes[i] = replacement;
            }
        }
        return new String(bytes, 0, length, StandardCharsets.UTF_8);
    }
}
