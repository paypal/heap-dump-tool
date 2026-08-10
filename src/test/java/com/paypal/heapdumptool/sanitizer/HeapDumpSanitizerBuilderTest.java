package com.paypal.heapdumptool.sanitizer;

import com.paypal.heapdumptool.fixture.Hprof;
import com.paypal.heapdumptool.sanitizer.internal.hprof.HeapRecord;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static com.paypal.heapdumptool.utils.DataSize.ofMegabytes;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for {@link HeapDumpSanitizerBuilder} and the {@code HeapDumpSanitizer.create(...)} entry
 * points. These run a real sanitization end to end -- the builder delegates to
 * {@link SanitizeCommandProcessor}, so the interesting behavior is that the whole pipeline runs from
 * the fluent surface alone, with no {@code SanitizeCommand} in the caller's hands.
 */
class HeapDumpSanitizerBuilderTest {

    private static final String ACCOUNT_CLASS_NAME = "com.mycorp.Account";

    private static final long ACCOUNT_CLASS_ID = 2100;
    private static final long ACCOUNT_OBJECT_ID = 0xA000;

    @TempDir
    Path tempDir;

    private int ssnOffset;
    private int balanceOffset;

    @Test
    @DisplayName("testPathBuilderSanitizes. A file-to-file run from the fluent surface alone")
    void testPathBuilderSanitizes() throws Exception {
        final byte[] input = fixtureBytes();
        final Path inputFile = tempDir.resolve("in.hprof");
        final Path outputFile = tempDir.resolve("out.hprof");
        Files.write(inputFile, input);

        HeapDumpSanitizer.create(inputFile, outputFile)
                .target("none")
                .addRule(SanitizationRules.fieldRule(
                        field -> "ssn".equals(field.fieldName()) ? Decision.sanitize() : Decision.undecided()))
                .sanitize();

        final byte[] output = Files.readAllBytes(outputFile);
        assertThat(output.length)
                .as("sanitization preserves the length of the dump")
                .isEqualTo(input.length);
        assertThat(region(output, ssnOffset, Integer.BYTES))
                .as("the rule named ssn, so it is overwritten")
                .containsExactly(0, 0, 0, 0);
        assertThat(region(output, balanceOffset, Integer.BYTES))
                .as("--target=none and no verdict on balance, so it survives")
                .containsExactly(0x22, 0x22, 0x22, 0x22);
    }

    @Test
    @DisplayName("testTargetAppliesInCallOrder. The builder records target() like the CLI")
    void testTargetAppliesInCallOrder() throws Exception {
        final byte[] input = fixtureBytes();
        final Path inputFile = tempDir.resolve("in.hprof");
        final Path outputFile = tempDir.resolve("out.hprof");
        Files.write(inputFile, input);

        final AtomicReference<SanitizationPolicy> seen = new AtomicReference<>();
        HeapDumpSanitizer.create(inputFile, outputFile)
                .target("none")
                .target("int-fields")
                .configure(command -> seen.set(command.getSanitizationPolicy()))
                .sanitize();

        assertThat(seen.get().sanitizeField(BasicType.INT))
                .as("the later target() re-selected int fields over the earlier none")
                .isTrue();
        assertThat(seen.get().sanitizeField(BasicType.LONG))
                .as("int-fields alone selects nothing else")
                .isFalse();
    }

    @Test
    @DisplayName("testConfigureSeesTheFullyPopulatedCommand. The escape hatch can inspect what the builder set up")
    void testConfigureSeesTheFullyPopulatedCommand() throws Exception {
        final byte[] input = fixtureBytes();
        final Path inputFile = tempDir.resolve("in.hprof");
        final Path outputFile = tempDir.resolve("out.hprof");
        Files.write(inputFile, input);

        final AtomicReference<SanitizeCommand> seen = new AtomicReference<>();
        HeapDumpSanitizer.create(inputFile, outputFile)
                .target("none")
                .addRule(SanitizationRules.fieldRule(field -> Decision.undecided()))
                .configure(seen::set)
                .sanitize();

        assertThat(seen.get().getInputFile()).isEqualTo(inputFile);
        assertThat(seen.get().getOutputFile()).isEqualTo(outputFile);
        assertThat(seen.get().getBufferSize())
                .as("picocli applied the annotated -b default to the builder's command")
                .isEqualTo(ofMegabytes(8));
        assertThat(seen.get().isForceMatchStringCoder())
                .as("picocli applied the annotated -f default to the builder's command")
                .isTrue();
        assertThat(seen.get().getExcludeStringFields())
                .as("picocli applied the annotated -e default to the builder's command")
                .containsExactly("java.lang.Thread#name", "java.lang.ThreadGroup#name");
        assertThat(seen.get().getSanitizationRules().size())
                .as("the builder's rule is on the command when the customizer runs")
                .isEqualTo(1);
        assertThat(seen.get().getSanitizationPolicy().isAnyFieldSanitized())
                .as("target(\"none\") was recorded")
                .isFalse();
    }

    // ---------------------------------------------------------------------------------------------

    private byte[] fixtureBytes() throws IOException {
        final Hprof hprof = new Hprof().header();
        hprof.stringInUtf8(60, ACCOUNT_CLASS_NAME);
        hprof.stringInUtf8(61, "ssn");
        hprof.stringInUtf8(62, "balance");
        hprof.loadClass(1, ACCOUNT_CLASS_ID, 60);

        final Hprof body = new Hprof();
        body.classDump(ACCOUNT_CLASS_ID, 0, new int[] {61, 62}, new BasicType[] {BasicType.INT, BasicType.INT});

        final Hprof instance = new Hprof();
        final int relativeSsn = instance.offset();
        instance.u4(0x11111111);
        final int relativeBalance = instance.offset();
        instance.u4(0x22222222);
        final int instanceOffset = body.instanceDump(ACCOUNT_OBJECT_ID, ACCOUNT_CLASS_ID, instance.toByteArray());

        final int base = hprof.record(HeapRecord.HEAP_DUMP_SEGMENT.getTag(), body);

        ssnOffset = base + instanceOffset + relativeSsn;
        balanceOffset = base + instanceOffset + relativeBalance;
        return hprof.toByteArray();
    }

    private int[] region(final byte[] bytes, final int offset, final int length) {
        final int[] unsigned = new int[length];
        for (int i = 0; i < length; i++) {
            unsigned[i] = bytes[offset + i] & 0xFF;
        }
        return unsigned;
    }
}
