package com.paypal.heapdumptool.utils;

import org.apache.commons.io.IOUtils;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import static com.paypal.heapdumptool.sanitizer.DataSize.ofBytes;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.doCallRealMethod;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

@ExtendWith(OutputCaptureExtension.class)
public class ProgressMonitorTest {

    private static final Logger LOGGER = LoggerFactory.getLogger(ProgressMonitorTest.class);

    @Test
    public void testNumBytesWrittenMonitor(final CapturedOutput output) {

        final ProgressMonitor numBytesWrittenMonitor = ProgressMonitor.numBytesProcessedMonitor(ofBytes(5), LOGGER);
        numBytesWrittenMonitor.accept(4L);

        assertThat(output)
                .isEmpty();

        numBytesWrittenMonitor.accept(5L);
        assertThat(output)
                .hasLineCount(1)
                .contains("Processed 5 bytes");

        numBytesWrittenMonitor.accept(6L);
        assertThat(output)
                .hasLineCount(1)
                .contains("Processed 5 bytes");

        numBytesWrittenMonitor.accept(11L);
        assertThat(output)
                .hasLineCount(2)
                .contains("Processed 5 bytes")
                .contains("Processed 11 bytes");
    }

    @Test
    public void testMonitoredInputStream() throws IOException {

        final ProgressMonitor monitor = mock(ProgressMonitor.class);

        final InputStream inputStream = new ByteArrayInputStream("hello".getBytes(UTF_8));
        doCallRealMethod().when(monitor).monitoredInputStream(inputStream);

        final InputStream monitoredInputStream = monitor.monitoredInputStream(inputStream);
        IOUtils.toByteArray(monitoredInputStream);

        verify(monitor, times(2)).accept((long) "hello".length());
    }

    @Test
    public void testMonitoredOutputStream() throws IOException {

        final ProgressMonitor monitor = mock(ProgressMonitor.class);

        final OutputStream outputStream = new ByteArrayOutputStream();
        doCallRealMethod().when(monitor).monitoredOutputStream(outputStream);

        final OutputStream monitoredOutputStream = monitor.monitoredOutputStream(outputStream);
        IOUtils.write("world", monitoredOutputStream, UTF_8);

        verify(monitor).accept((long) "world".length());
    }
}
