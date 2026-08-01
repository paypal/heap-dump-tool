package com.paypal.heapdumptool.sanitizer;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;
import java.util.concurrent.atomic.AtomicLong;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

public class PipeTest {

    private final String data = "hello world\0more-stuff-here";

    private final ByteArrayInputStream inputBytes = byteStreamOf(data);

    private final ByteArrayOutputStream outputBytes = new ByteArrayOutputStream();

    private final AtomicLong monitor = new AtomicLong();

    private final Pipe pipe = new Pipe(inputBytes, outputBytes, monitor::set);

    @Test
    public void testIdSizeSetGet() {
        pipe.setIdSize(4);
        assertThat(pipe.getIdSize())
                .isEqualTo(4);

        pipe.setIdSize(8);
        assertThat(pipe.getIdSize())
                .isEqualTo(8);
    }

    @Test
    @DisplayName("testIdSizeNullDefault. check that NPE is thrown")
    public void testIdSizeNullDefault() {
        assertThatThrownBy(pipe::getIdSize)
                .isInstanceOf(NullPointerException.class);
    }

    @Test
    public void testIdSize4Or8() {
        assertThatThrownBy(() -> pipe.setIdSize(10))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("Unknown id size: 10");
    }

    @Test
    public void testReadU1() throws IOException {
        assertThat(pipe.readU1())
                .isEqualTo('h');

        pipe.skipInput(data.length() - 1);
        verifyEoF();

        assertThat(outputBytes.toByteArray())
                .hasSize(0);
    }

    @Test
    public void testWriteU1() throws IOException {
        pipe.writeU1('z');
        assertThat(outputString())
                .isEqualTo("z");

        verifyInputStreamUnchanged();
    }

    @Test
    public void testPipeByLength() throws IOException {
        pipe.pipe(data.length());
        verifyEoF();
        assertThat(outputString())
                .isEqualTo(data);
    }

    @Test
    public void testPipeId4() throws IOException {
        pipe.setIdSize(4);
        pipe.pipeId();

        assertThat(outputString())
                .isEqualTo("hell")
                .hasSize(4);
    }

    @Test
    public void testPipeId8() throws IOException {
        pipe.setIdSize(8);
        pipe.pipeId();

        assertThat(outputString())
                .isEqualTo("hello wo")
                .hasSize(8);
    }

    @Test
    public void testCopyFrom() throws IOException {
        final String newData = "byte stream data";
        pipe.copyFrom(byteStreamOf(newData), newData.length());

        verifyInputStreamUnchanged();

        assertThat(outputString())
                .isEqualTo(newData);
    }

    @Test
    public void testPipeU1() throws IOException {
        final int u1 = pipe.pipeU1();
        assertThat(u1)
                .isEqualTo('h');

        assertThat(outputString())
                .isEqualTo("h");
        assertThat(inputBytes.read())
                .isEqualTo('e');
    }

    @Test
    public void testPipeU1IfPossible() throws IOException {
        final int u1 = pipe.pipeU1IfPossible();
        assertThat(u1)
                .isEqualTo('h');

        assertThat(outputString())
                .isEqualTo("h");
        assertThat(inputBytes.read())
                .isEqualTo('e');
    }

    @Test
    @DisplayName("pipe u1 on exhausted input")
    public void testPipeU1IfPossibleNot() throws IOException {
        pipe.pipe(100);
        final int u1 = pipe.pipeU1IfPossible();
        assertThat(u1)
                .isEqualTo(-1);

        assertThat(outputString())
                .isEqualTo(data);
    }

    @Test
    public void testPipeU2() throws IOException {
        pipe.pipeU2();
        assertThat(inputBytes.read())
                .isEqualTo('l');
        assertThat(outputString())
                .isEqualTo("he");
    }

    @Test
    public void testPipeNullTerminatedString() throws IOException {
        assertThat(pipe.pipeNullTerminatedString())
                .isEqualTo("hello world\0")
                .isEqualTo(outputString());
    }

    @Test
    public void testNewInputBoundedPipe() throws IOException {
        pipe.pipeU1();

        final Pipe boundedPipe = pipe.newInputBoundedPipe(4);
        assertThat(boundedPipe.pipeNullTerminatedString())
                .isEqualTo("ello");

        assertThat(outputString())
                .isEqualTo("hello");

        assertThat(pipe.pipeNullTerminatedString())
                .isEqualTo(" world\0");
        assertThat(outputString())
                .isEqualTo("hello world\0");
    }

    /**
     * One scratch buffer is shared by a pipe, its bounded children, and every copy any of them makes.
     * A payload several buffers long, interleaved across parent and child, would surface any stale or
     * partially-overwritten buffer content as garbled or truncated output.
     */
    @Test
    @DisplayName("testCopiesLongerThanTheSharedBufferAreExact. interleaved multi-buffer copies must not corrupt each other")
    public void testCopiesLongerThanTheSharedBufferAreExact() throws IOException {
        final byte[] payload = new byte[3 * 8192 + 17];
        for (int i = 0; i < payload.length; i++) {
            payload[i] = (byte) (i % 251);
        }

        final ByteArrayOutputStream output = new ByteArrayOutputStream();
        final Pipe parent = new Pipe(new ByteArrayInputStream(payload), output, new AtomicLong()::set);

        final int firstChunk = 8192 + 3;
        parent.pipe(firstChunk);

        final int childChunk = 2 * 8192 + 5;
        final Pipe child = parent.newInputBoundedPipe(childChunk);
        child.pipe(childChunk);

        // a copyFrom on the parent, between two pipes, also shares the buffer
        final byte[] injected = new byte[8192 + 1];
        Arrays.fill(injected, (byte) 0x5A);
        parent.copyFrom(new ByteArrayInputStream(injected), injected.length);

        parent.pipe(payload.length - firstChunk - childChunk);

        final byte[] expected = new byte[payload.length + injected.length];
        System.arraycopy(payload, 0, expected, 0, firstChunk + childChunk);
        System.arraycopy(injected, 0, expected, firstChunk + childChunk, injected.length);
        System.arraycopy(payload, firstChunk + childChunk,
                expected, firstChunk + childChunk + injected.length,
                payload.length - firstChunk - childChunk);

        assertThat(output.toByteArray()).containsExactly(expected);
    }

    @Test
    public void testProgressMonitor() throws IOException {
        pipe.pipeU1();
        assertThat(monitor)
                .hasValue(1);

        pipe.pipe(100);
        assertThat(monitor)
                .hasValue(data.length());
    }

    @Test
    @DisplayName("testReadOnlyPipeReadsTheSameValues. read-only mode must parse identically to a writing pipe")
    public void testReadOnlyPipeReadsTheSameValues() throws IOException {
        final Pipe readOnly = Pipe.readOnlyPipe(byteStreamOf(data), new AtomicLong()::set);
        readOnly.setIdSize(4);

        assertThat(readOnly.pipeU1()).isEqualTo('h');
        assertThat(readOnly.pipeU2()).isEqualTo(pipeU2Of("el"));
        assertThat(readOnly.pipeId()).isEqualTo(pipeId4Of("lo w"));
        assertThat(readOnly.pipeNullTerminatedString()).isEqualTo("orld\0");
    }

    @Test
    @DisplayName("testReadOnlyPipeWritesNothing. every write method is a no-op with no output attached")
    public void testReadOnlyPipeWritesNothing() throws IOException {
        final Pipe readOnly = Pipe.readOnlyPipe(byteStreamOf(data), new AtomicLong()::set);

        // none of these may throw, and there is no output to observe
        readOnly.writeU1('z');
        readOnly.write(bytesOf("abc"));
        readOnly.write(bytesOf("abc"), 0, 3);
        readOnly.copyFrom(byteStreamOf("injected"), "injected".length());

        // the input is still positioned at the start: writes must not consume input
        assertThat(readOnly.readU1()).isEqualTo('h');
    }

    @Test
    @DisplayName("testReadOnlyBoundedChildIsAlsoReadOnly. the mode propagates to bounded children")
    public void testReadOnlyBoundedChildIsAlsoReadOnly() throws IOException {
        final Pipe readOnly = Pipe.readOnlyPipe(byteStreamOf(data), new AtomicLong()::set);
        readOnly.pipeU1();

        final Pipe child = readOnly.newInputBoundedPipe(4);
        child.writeU1('z');
        assertThat(child.pipeNullTerminatedString()).isEqualTo("ello");

        // parent continues where the child stopped
        assertThat(readOnly.pipeNullTerminatedString()).isEqualTo(" world\0");
    }

    @Test
    @DisplayName("testReadOnlyPipeAdvancesInputExactly. a seek must consume exactly count bytes")
    public void testReadOnlyPipeAdvancesInputExactly() throws IOException {
        final Pipe readOnly = Pipe.readOnlyPipe(byteStreamOf(data), new AtomicLong()::set);

        readOnly.pipe(6);
        assertThat(readOnly.readU1()).isEqualTo('w');
    }

    @Test
    @DisplayName("testReadOnlyBoundedChildCannotSeekPastItsBound. a child seek must not steal parent bytes")
    public void testReadOnlyBoundedChildCannotSeekPastItsBound() throws IOException {
        final Pipe readOnly = Pipe.readOnlyPipe(byteStreamOf(data), new AtomicLong()::set);

        final Pipe child = readOnly.newInputBoundedPipe(5);
        child.pipe(100);
        assertThat(child.readU1()).isEqualTo(-1);

        // the parent's next byte is the 6th, so the child consumed exactly 5
        assertThat(readOnly.readU1()).isEqualTo(' ');
    }

    @Test
    @DisplayName("testReadOnlyPipeFallsBackWhenSkipThrows. a non-seekable stream must still read correctly")
    public void testReadOnlyPipeFallsBackWhenSkipThrows() throws IOException {
        final InputStream unseekable = new FilterInputStream(byteStreamOf(data)) {
            @Override
            public long skip(final long n) throws IOException {
                throw new IOException("Illegal seek");
            }
        };
        final Pipe readOnly = Pipe.readOnlyPipe(unseekable, new AtomicLong()::set);

        readOnly.pipe(6);
        assertThat(readOnly.readU1()).isEqualTo('w');
    }

    @Test
    @DisplayName("testReadOnlyPipeFallsBackWhenSkipReturnsZero. skip returning 0 short of EOF must not spin")
    public void testReadOnlyPipeFallsBackWhenSkipReturnsZero() throws IOException {
        final InputStream lazySkip = new FilterInputStream(byteStreamOf(data)) {
            @Override
            public long skip(final long n) {
                return 0;
            }
        };
        final Pipe readOnly = Pipe.readOnlyPipe(lazySkip, new AtomicLong()::set);

        readOnly.pipe(6);
        assertThat(readOnly.readU1()).isEqualTo('w');
    }

    /**
     * The read-only pass exists to seek over the regions it does not inspect, so it has to actually
     * call skip(). The tests around this one all assert on the bytes that come out, which a pass that
     * read every byte through read() satisfies just as well -- so none of them can tell a working seek
     * from a dead one, and the optimisation can be switched off without a red test. This one asserts on
     * the call itself.
     */
    @Test
    @DisplayName("testReadOnlyPipeSeeksRatherThanReading. the seek must be used, not merely be correct")
    public void testReadOnlyPipeSeeksRatherThanReading() throws IOException {
        final AtomicLong skipCalls = new AtomicLong();
        final AtomicLong readCalls = new AtomicLong();
        final InputStream counting = new FilterInputStream(byteStreamOf(data)) {
            @Override
            public long skip(final long n) throws IOException {
                skipCalls.incrementAndGet();
                return super.skip(n);
            }

            @Override
            public int read(final byte[] b, final int off, final int len) throws IOException {
                readCalls.incrementAndGet();
                return super.read(b, off, len);
            }
        };
        final Pipe readOnly = Pipe.readOnlyPipe(counting, new AtomicLong()::set);

        readOnly.pipe(6);

        assertThat(skipCalls).hasValue(1);
        assertThat(readCalls)
                .as("a seekable stream must not be walked through read()")
                .hasValue(0);
        assertThat(readOnly.readU1()).isEqualTo('w');
    }

    /**
     * The fallback is sticky: a stream whose skip() throws keeps throwing, and pipe() is called at
     * least once per record, so retrying the seek per record would turn one failure into millions of
     * exception constructions.
     */
    @Test
    @DisplayName("testSkipIsNotRetriedAfterItThrows. one failed seek must not be re-attempted per record")
    public void testSkipIsNotRetriedAfterItThrows() throws IOException {
        final AtomicLong skipCalls = new AtomicLong();
        final InputStream unseekable = new FilterInputStream(byteStreamOf(data)) {
            @Override
            public long skip(final long n) throws IOException {
                skipCalls.incrementAndGet();
                throw new IOException("Illegal seek");
            }
        };
        final Pipe readOnly = Pipe.readOnlyPipe(unseekable, new AtomicLong()::set);

        readOnly.pipe(6);
        readOnly.pipe(5);

        assertThat(skipCalls)
                .as("the first throw settles it; later records go straight to read()")
                .hasValue(1);
        assertThat(readOnly.readU1()).isEqualTo('\0');
    }

    @Test
    @DisplayName("testReadOnlyPipeAtEofStopsShort. seeking past EOF must stop, matching copyLarge")
    public void testReadOnlyPipeAtEofStopsShort() throws IOException {
        final Pipe readOnly = Pipe.readOnlyPipe(byteStreamOf(data), new AtomicLong()::set);

        readOnly.pipe(data.length() + 100);
        assertThat(readOnly.readU1()).isEqualTo(-1);
    }

    @Test
    @DisplayName("testReadOnlyProgressMonitorCountsConsumedBytes. progress must survive having no output")
    public void testReadOnlyProgressMonitorCountsConsumedBytes() throws IOException {
        final AtomicLong consumed = new AtomicLong();
        final Pipe readOnly = Pipe.readOnlyPipe(byteStreamOf(data), consumed::set);

        readOnly.pipe(6);
        assertThat(consumed).hasValue(6);

        final Pipe child = readOnly.newInputBoundedPipe(5);
        child.pipe(5);
        assertThat(consumed)
                .as("a bounded child contributes to the parent's running total")
                .hasValue(11);
    }

    @Test
    @DisplayName("testPipeStringReplacingReadsExactlyNumBytes. must not read past the length it was given")
    public void testPipeStringReplacingReadsExactlyNumBytes() throws IOException {
        assertThat(pipe.pipeStringReplacing(5, '/', '.'))
                .isEqualTo("hello");

        assertThat(outputString())
                .as("the bytes are written through unchanged")
                .isEqualTo("hello");

        assertThat(inputBytes.read())
                .as("the input is left positioned right after the string")
                .isEqualTo(' ');
    }

    @Test
    @DisplayName("testPipeExactlyTransfersWithoutDecoding. the no-String path must move the same bytes")
    public void testPipeExactlyTransfersWithoutDecoding() throws IOException {
        pipe.pipeExactly(5);

        assertThat(outputString())
                .isEqualTo("hello");
        assertThat(inputBytes.read())
                .isEqualTo(' ');
    }

    /**
     * The substitution rewrites the read buffer in place, so it has to happen strictly after the write.
     * Otherwise the sanitized dump would carry class names with dots where the format requires slashes.
     */
    @Test
    @DisplayName("testPipeStringReplacingDoesNotAlterOutput. only the returned value is converted")
    public void testPipeStringReplacingDoesNotAlterOutput() throws IOException {
        final String path = "java/lang/String";
        final Pipe slashes = new Pipe(byteStreamOf(path), outputBytes, monitor::set);

        assertThat(slashes.pipeStringReplacing(path.length(), '/', '.'))
                .isEqualTo("java.lang.String");
        assertThat(outputString())
                .as("the dump keeps the slashes it declared")
                .isEqualTo(path);
    }

    /**
     * copyBuffer is 8 KB and is reused across records, so both sides of that boundary must decode
     * exactly, and a reused buffer must not leak the previous record's tail into a shorter one.
     */
    @Test
    @DisplayName("testPipeStringReplacingHandlesRecordsLongerThanTheBuffer. over 8 KB takes its own array")
    public void testPipeStringReplacingHandlesRecordsLongerThanTheBuffer() throws IOException {
        final StringBuilder longString = new StringBuilder();
        for (int i = 0; longString.length() < 3 * 8192; i++) {
            longString.append("com/example/Type").append(i).append('/');
        }
        final String first = longString.toString();
        final String second = "a/b";

        final ByteArrayOutputStream output = new ByteArrayOutputStream();
        final Pipe bufferPipe = new Pipe(byteStreamOf(first + second), output, new AtomicLong()::set);

        assertThat(bufferPipe.pipeStringReplacing(first.length(), '/', '.'))
                .isEqualTo(first.replace('/', '.'));
        assertThat(bufferPipe.pipeStringReplacing(second.length(), '/', '.'))
                .as("a short record after a long one must not pick up leftover bytes")
                .isEqualTo("a.b");

        assertThat(output.toString("UTF-8")).isEqualTo(first + second);
    }

    /**
     * The in-place byte substitution is only equivalent to String.replace because a byte below 0x80
     * cannot be part of a multi-byte UTF-8 sequence. A non-ASCII payload must survive it untouched.
     */
    @Test
    @DisplayName("testPipeStringReplacingLeavesMultiByteCharactersIntact. byte-level edit must be UTF-8 safe")
    public void testPipeStringReplacingLeavesMultiByteCharactersIntact() throws IOException {
        final String unicode = "a/é中😀/b";
        final byte[] bytes = bytesOf(unicode);

        final ByteArrayOutputStream output = new ByteArrayOutputStream();
        final Pipe pipe = new Pipe(new ByteArrayInputStream(bytes), output, new AtomicLong()::set);

        assertThat(pipe.pipeStringReplacing(bytes.length, '/', '.'))
                .isEqualTo("a.é中😀.b");
        assertThat(output.toByteArray()).containsExactly(bytes);
    }

    @Test
    @DisplayName("testPipeStringReplacingRejectsNonAscii. a non-ASCII match cannot be done byte-wise")
    public void testPipeStringReplacingRejectsNonAscii() {
        assertThatThrownBy(() -> pipe.pipeStringReplacing(3, 'é', '.'))
                .isInstanceOf(IllegalArgumentException.class);

        assertThatThrownBy(() -> pipe.pipeStringReplacing(3, '/', 'é'))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    @DisplayName("testPipeExactlyOnTruncatedRecordThrows. a dump ending mid-string is corrupt, not a short string")
    public void testPipeExactlyOnTruncatedRecordThrows() {
        assertThatThrownBy(() -> pipe.pipeExactly(data.length() + 10))
                .isInstanceOf(EOFException.class);

        assertThatThrownBy(() -> new Pipe(byteStreamOf(data), outputBytes, monitor::set)
                .pipeStringReplacing(data.length() + 10, '/', '.'))
                .isInstanceOf(EOFException.class);
    }

    @Test
    @DisplayName("testReadOnlyPipeStringWritesNothing. read-only mode still decodes but emits nothing")
    public void testReadOnlyPipeStringWritesNothing() throws IOException {
        final AtomicLong consumed = new AtomicLong();
        final Pipe readOnly = Pipe.readOnlyPipe(byteStreamOf(data), consumed::set);

        assertThat(readOnly.pipeStringReplacing(5, '/', '.'))
                .isEqualTo("hello");
        assertThat(consumed)
                .as("string bytes count toward progress, since there is no output to count")
                .hasValue(5);

        readOnly.pipeExactly(6);
        assertThat(consumed)
                .as("the no-String path reports progress too")
                .hasValue(11);
    }

    private void verifyEoF() throws IOException {
        assertThat(pipe.readU1())
                .isEqualTo(-1);
    }

    private void verifyInputStreamUnchanged() {
        assertThat(inputBytes.read())
                .isEqualTo('h');
    }

    private String outputString() throws IOException {
        return outputBytes.toString("UTF-8");
    }

    private ByteArrayInputStream byteStreamOf(final String str) {
        return new ByteArrayInputStream(bytesOf(str));
    }

    private byte[] bytesOf(final String str) {
        return str.getBytes(UTF_8);
    }

    private int pipeU2Of(final String twoChars) {
        return (short) ((twoChars.charAt(0) << 8) | twoChars.charAt(1));
    }

    private long pipeId4Of(final String fourChars) {
        long value = 0;
        for (int i = 0; i < 4; i++) {
            value = (value << 8) | fourChars.charAt(i);
        }
        return value;
    }
}
