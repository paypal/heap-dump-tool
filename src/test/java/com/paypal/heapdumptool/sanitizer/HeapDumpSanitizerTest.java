package com.paypal.heapdumptool.sanitizer;

import com.paypal.heapdumptool.fixture.HeapDumper;
import com.paypal.heapdumptool.fixture.ResourceTool;
import com.paypal.heapdumptool.sanitizer.example.ClassWithManyInstanceFields;
import com.paypal.heapdumptool.sanitizer.example.ClassWithManyStaticFields;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.MethodOrderer.Random;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInfo;
import org.junit.jupiter.api.TestMethodOrder;
import org.junit.jupiter.api.io.TempDir;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

import static com.paypal.heapdumptool.ApplicationTestSupport.runApplicationPrivileged;
import static com.paypal.heapdumptool.fixture.ByteArrayTool.countOfSequence;
import static com.paypal.heapdumptool.fixture.ByteArrayTool.lengthen;
import static com.paypal.heapdumptool.fixture.ByteArrayTool.nCopiesLongToBytes;
import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Arrays.asList;
import static org.apache.commons.io.FileUtils.byteCountToDisplaySize;
import static org.apache.commons.lang3.ArrayUtils.EMPTY_STRING_ARRAY;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;

@TestMethodOrder(Random.class)
public class HeapDumpSanitizerTest {

    private static final Logger LOGGER = LoggerFactory.getLogger(HeapDumpSanitizerTest.class);

    @TempDir
    static Path tempDir;

    // "his-secret-value" with each letter incremented by 1
    private final String hisSecretValue = "ijt.tfdsfu.wbmvf";
    private final String herSecretValue = "ifs.tfdsfu.wbmvf";
    private final String itsSecretValue = "jut.tfdsfu.wbmvf";

    // "his-classified-value" with each letter incremented by 1
    private final String hisClassifiedValue = "ijt.dmbttjgjfe.wbmvf";
    private final String herClassifiedValue = "ifs.dmbttjgjfe.wbmvf";
    private final String itsClassifiedValue = "jut.dmbttjgjfe.wbmvf";

    @BeforeEach
    public void beforeEach(final TestInfo info) {
        LOGGER.info("Test - {}:", info.getDisplayName());
    }

    @BeforeEach
    @AfterEach
    public void clearLoadedHeapDumpInfo() {
        System.gc();
    }

    @Test
    @DisplayName("testSecretsAreInHeapDump. Verify that heap dump normally contains sensitive data")
    public void testSecretsAreInHeapDump() throws Exception {

        // keep as byte array in mem
        byte[] actualHisSecretValue = adjustLettersToByteArray(hisSecretValue);

        // keep as char array in mem
        String actualHerSecretValue = new String(actualHisSecretValue, UTF_8).replace("his", "her");

        // interned
        lengthenAndInternItsValue(actualHisSecretValue);

        actualHisSecretValue = lengthen(actualHisSecretValue, DataSize.ofMegabytes(1));
        actualHerSecretValue = lengthen(actualHerSecretValue, DataSize.ofMegabytes(1));

        final byte[] heapDump = loadHeapDump();

        final byte[] expectedHisSecretValueBytes = adjustLettersToByteArray(hisSecretValue);
        final byte[] expectedHerSecretValueBytes = adjustLettersToByteArray(herSecretValue);
        final byte[] expectedItsSecretValueBytes = adjustLettersToByteArray(itsSecretValue);

        assertThat(heapDump)
                .overridingErrorMessage("sequences do not match") // normal error message would be long and not helpful at all
                .containsSequence(expectedHisSecretValueBytes)
                .containsSequence(expectedHerSecretValueBytes)
                .containsSequence(expectedItsSecretValueBytes);
    }

    @Test
    @DisplayName("testConfidentialsNotInHeapDump. Verify that sanitized heap dump does not contains sensitive data")
    public void testConfidentialsNotInHeapDump() throws Exception {

        byte[] actualHisConfidentialValue = ResourceTool.bytesOf(getClass(), "classifieds.txt");
        String actualHerConfidentialValue = new String(actualHisConfidentialValue, UTF_8).replace("his", "her");
        lengthenAndInternItsValue(actualHisConfidentialValue);

        actualHisConfidentialValue = lengthen(actualHisConfidentialValue, DataSize.ofMegabytes(1));
        actualHerConfidentialValue = lengthen(actualHerConfidentialValue, DataSize.ofMegabytes(1));

        final byte[] heapDump = loadSanitizedHeapDump();

        final byte[] expectedHisClassifiedValueBytes = adjustLettersToByteArray(hisClassifiedValue);
        final byte[] expectedHerClassifiedValueBytes = adjustLettersToByteArray(herClassifiedValue);
        final byte[] expectedItsClassifiedValueBytes = adjustLettersToByteArray(itsClassifiedValue);

        verifyDoesNotContainsSequence(heapDump, expectedHisClassifiedValueBytes);
        verifyDoesNotContainsSequence(heapDump, expectedHerClassifiedValueBytes);
        verifyDoesNotContainsSequence(heapDump, expectedItsClassifiedValueBytes);
    }

    @Test
    @DisplayName("testSanitizeFieldsOfNonArrayPrimitiveType. Verify that fields of non-array primitive type can be sanitized")
    public void testSanitizeFieldsOfNonArrayPrimitiveType() throws Exception {
        final Object instance = new ClassWithManyInstanceFields();
        final Object staticFields = new ClassWithManyStaticFields();
        assertThat(instance).isNotNull();
        assertThat(staticFields).isNotNull();

        byte[] sanitizedHeapDump = loadSanitizedHeapDump("--sanitize-byte-char-arrays-only=false");
        verifyDoesNotContainsSequence(sanitizedHeapDump, nCopiesLongToBytes(deadcow(), 100));
        assertThat(countOfSequence(sanitizedHeapDump, nCopiesLongToBytes(cafegirl(), 1)))
                .isLessThan(1000);

        sanitizedHeapDump = null;
        clearLoadedHeapDumpInfo();

        final byte[] clearHeapDump = loadSanitizedHeapDump("--sanitize-byte-char-arrays-only=true");
        assertThat(clearHeapDump)
                .overridingErrorMessage("sequences do not match") // normal error message would be long and not helpful at all
                .containsSequence(nCopiesLongToBytes(deadcow(), 500));

        assertThat(countOfSequence(clearHeapDump, nCopiesLongToBytes(cafegirl(), 1)))
                .isGreaterThan(500);
    }

    // 0xDEADBEEF
    private long deadcow() {
        return 0xDEADBEEE + Long.parseLong("1");
    }

    // 0xCAFEBABE
    private long cafegirl() {
        return 0XCAFEBABD + Long.parseLong("1");
    }

    private void verifyDoesNotContainsSequence(final byte[] big, final byte[] small) {
        final String corrId = System.currentTimeMillis() + "";
        assertThatCode(() -> {
            assertThat(big)
                    .withFailMessage(corrId).containsSequence(small);
        }).withFailMessage("does in fact contains sequence")
          .hasMessageContaining(corrId);
    }

    private void lengthenAndInternItsValue(final byte[] value) {
        String itsValue = new String(value, UTF_8).replace("his", "its");
        itsValue = lengthen(itsValue, DataSize.ofMegabytes(1));
        itsValue.intern();
    }

    private byte[] adjustLettersToByteArray(final String str) {
        return adjustLetters(str, -1)
                .getBytes(UTF_8);
    }

    private String adjustLetters(final String str, final int adjustment) {
        return str.chars()
                  .map(chr -> chr + adjustment)
                  .mapToObj(chr -> String.valueOf((char) chr))
                  .collect(Collectors.joining(""));
    }

    private Path triggerHeapDump() throws Exception {
        final Path heapDumpPath = newTempFilePath();

        LOGGER.info("Heap dumping to {}", heapDumpPath);
        HeapDumper.dumpHeap(heapDumpPath);

        return heapDumpPath;
    }

    private byte[] loadHeapDump() throws Exception {
        return loadHeapDump(triggerHeapDump());
    }

    private byte[] loadHeapDump(final Path heapDumpPath) throws IOException {
        final long size = Files.size(heapDumpPath);
        LOGGER.info("Loading heap dump. size={} name={}", byteCountToDisplaySize(size), heapDumpPath.getFileName());
        return Files.readAllBytes(heapDumpPath);
    }

    private byte[] loadSanitizedHeapDump(final String... options) throws Exception {
        final Path heapDump = triggerHeapDump();
        final Path sanitizedHeapDumpPath = newTempFilePath();

        final List<String> cmd = new ArrayList<>();
        cmd.add("sanitize");
        cmd.addAll(asList(options));
        cmd.add(heapDump.toString());
        cmd.add(sanitizedHeapDumpPath.toString());

        runApplicationPrivileged(cmd.toArray(EMPTY_STRING_ARRAY));
        return loadHeapDump(sanitizedHeapDumpPath);
    }

    private Path newTempFilePath() throws IOException {
        final Path path = Files.createTempFile(tempDir, getClass().getSimpleName(), ".hprof");
        Files.delete(path);
        return path;
    }
}
