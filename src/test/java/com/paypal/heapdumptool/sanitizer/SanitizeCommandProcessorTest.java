package com.paypal.heapdumptool.sanitizer;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.MockedConstruction;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;

import java.io.IOException;
import java.nio.file.Paths;
import java.util.Collections;
import java.util.List;

import static com.paypal.heapdumptool.sanitizer.DataSize.ofBytes;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockConstruction;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

@ExtendWith(OutputCaptureExtension.class)
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

    /**
     * The resolved policy is logged on startup, in the flag syntax that would reproduce it. Here the
     * default scope, so the pair reads as --target=all with the default fills.
     */
    @Test
    void testSanitizationPolicyIsLogged(final CapturedOutput output) throws Exception {
        final SanitizeCommandProcessor processor = new SanitizeCommandProcessor(command, streamFactory);

        try (final MockedConstruction<HeapDumpSanitizer> mocked = mockConstruction(HeapDumpSanitizer.class, this::prepare)) {
            processor.process();
        }

        assertThat(output.getAll())
                .contains("Sanitization targets: --target=all")
                .contains("Replacement values: --replacement="
                                  + "boolean=false,char=*,float=0.0,double=0.0,byte=42,short=0,int=0,long=0");
    }

    @Test
    void testNarrowedSanitizationPolicyIsLogged(final CapturedOutput output) throws Exception {
        command.getSanitizeOptions().target("byte-arrays,char-arrays");
        command.getSanitizeOptions().replacement("all=0");
        final SanitizeCommandProcessor processor = new SanitizeCommandProcessor(command, streamFactory);

        try (final MockedConstruction<HeapDumpSanitizer> mocked = mockConstruction(HeapDumpSanitizer.class, this::prepare)) {
            processor.process();
        }

        assertThat(output.getAll())
                .contains("Sanitization targets: --target=char-arrays,byte-arrays")
                .contains("Replacement values: --replacement="
                                  + "boolean=false,char=\\0,float=0.0,double=0.0,byte=0,short=0,int=0,long=0");
    }

    private void prepare(final HeapDumpSanitizer mock, final MockedConstruction.Context context) throws Throwable {
        doNothing().when(mock).sanitize();
    }

    @Test
    @DisplayName("testPreprocessingOpensNoOutputStream. the metadata pass must not open an output")
    void testPreprocessingOpensNoOutputStream() throws Exception {
        final SanitizeCommandProcessor processor = new SanitizeCommandProcessor(command, streamFactory);

        try (final MockedConstruction<HeapDumpSanitizer> mocked = mockConstruction(HeapDumpSanitizer.class, this::prepare)) {
            processor.process();

            final List<HeapDumpSanitizer> constructed = mocked.constructed();
            assertThat(constructed).hasSize(1);
            verify(constructed.get(0)).setPreprocessingOnly(true);
            verify(constructed.get(0)).setPreprocessingOnly(false);
        }

        // one output stream for the writing pass only, not two
        verify(streamFactory, times(1)).newOutputStream();
        verify(streamFactory, times(2)).newInputStream();
    }

}
