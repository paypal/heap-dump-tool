package com.paypal.heapdumptool.utils;

import com.paypal.heapdumptool.fixture.ConstructorTester;
import com.paypal.heapdumptool.utils.ProcessTool.ProcessResult;
import org.apache.commons.io.input.BrokenInputStream;
import org.junit.jupiter.api.Test;

import java.io.UncheckedIOException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;

public class ProcessToolTest {

    @Test
    public void testRun() throws Exception {
        final ProcessResult result = ProcessTool.run("ls", "-l");
        assertThat(result.exitCode).isEqualTo(0);
        assertThat(result.stdout).isNotEmpty();
        assertThat(result.stderr).isEmpty();
        assertThat(result.stdoutLines()).isNotEmpty();
    }

    @Test
    public void testBrokenInputStream() {
        assertThatCode(() -> ProcessTool.readStream(new BrokenInputStream()))
                .isInstanceOf(UncheckedIOException.class);
    }

    @Test
    public void testConstructor() throws Exception {
        ConstructorTester.test(ProcessTool.class);
    }
}
