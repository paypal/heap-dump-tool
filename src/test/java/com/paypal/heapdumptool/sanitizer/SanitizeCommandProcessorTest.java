package com.paypal.heapdumptool.sanitizer;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.MockedConstruction;

import java.io.IOException;
import java.nio.file.Paths;
import java.util.Collections;

import static com.paypal.heapdumptool.sanitizer.DataSize.ofBytes;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockConstruction;
import static org.mockito.Mockito.verify;

class SanitizeCommandProcessorTest {

    private final HeapDumpSanitizer sanitizer = mock(HeapDumpSanitizer.class);

    private final SanitizeStreamFactory streamFactory = mock(SanitizeStreamFactory.class);

    private final SanitizeCommand command = new SanitizeCommand();

    @BeforeEach
    void beforeEach() throws IOException {
        doNothing().when(sanitizer).sanitize();
        doReturn(null).when(streamFactory).newInputStream();
        doReturn(null).when(streamFactory).newOutputStream();

        command.setInputFile(Paths.get("input"));
        command.setOutputFile(Paths.get("output"));
        command.setExcludeStringFields(Collections.singletonList("none#none"));
    }

    @Test
    void testBufferSizeValidation() {
        command.setBufferSize(ofBytes(-1));

        assertThatThrownBy(() -> new SanitizeCommandProcessor(command))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("Invalid buffer size");
    }

    @Test
    void testProcess() throws Exception {
        final SanitizeCommandProcessor processor = new SanitizeCommandProcessor(command, streamFactory);

        try (final MockedConstruction<HeapDumpSanitizer> mocked = mockConstruction(HeapDumpSanitizer.class, this::prepare)) {
            processor.process();
            for (final HeapDumpSanitizer sanitizer : mocked.constructed()) {
                verify(sanitizer, atLeastOnce()).sanitize();
            }
        }
    }

    private void prepare(final HeapDumpSanitizer mock, final MockedConstruction.Context context) throws Throwable {
        doNothing().when(mock).sanitize();
    }

}
