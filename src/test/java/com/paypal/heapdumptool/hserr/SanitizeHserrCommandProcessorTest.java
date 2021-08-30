package com.paypal.heapdumptool.hserr;

import com.paypal.heapdumptool.fixture.ResourceTool;
import com.paypal.heapdumptool.sanitizer.SanitizeStreamFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.file.Paths;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;

public class SanitizeHserrCommandProcessorTest {

    private final SanitizeHserrCommand command = new SanitizeHserrCommand();

    private final SanitizeStreamFactory streamFactory = mock(SanitizeStreamFactory.class);

    private final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

    private SanitizeHserrCommandProcessor processor;

    @BeforeEach
    public void beforeEach() throws IOException {
        final String input = ResourceTool.contentOf(SanitizeHserrCommandProcessorTest.class, "hs_err_pid123.txt");
        doReturn(new ByteArrayInputStream(input.getBytes(UTF_8)))
                .when(streamFactory)
                .newInputStream();

        doReturn(outputStream).when(streamFactory).newOutputStream();

        command.setInputFile(Paths.get("input"));
        command.setOutputFile(Paths.get("output"));
        processor = new SanitizeHserrCommandProcessor(command, streamFactory);
    }

    @Test
    public void testProcess() throws Exception {
        processor.process();
        
        final String output = outputStream.toString(UTF_8.name());
        assertThat(output)
                .contains("#  SIGSEGV (0xb) at pc=0x00007fab2dfe7a6d, pid=32369, tid=32375")
                .doesNotContain("LANG=en_US.UTF-8")
                .contains("LANG=****");
    }
}
