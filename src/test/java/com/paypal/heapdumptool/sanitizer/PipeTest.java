package com.paypal.heapdumptool.sanitizer;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
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

    @Test
    public void testProgressMonitor() throws IOException {
        pipe.pipeU1();
        assertThat(monitor)
                .hasValue(1);

        pipe.pipe(100);
        assertThat(monitor)
                .hasValue(data.length());
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
}
