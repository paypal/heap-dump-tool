package com.paypal.heapdumptool.sanitizer;

import com.paypal.heapdumptool.fixture.HeapDumper;
import com.paypal.heapdumptool.fixture.ResourceTool;
import com.paypal.heapdumptool.sanitizer.example.ClassWithManyInstanceFields;
import com.paypal.heapdumptool.sanitizer.example.ClassWithManyStaticFields;
import org.apache.commons.lang3.StringUtils;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.MethodOrderer.Random;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInfo;
import org.junit.jupiter.api.TestMethodOrder;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ThreadLocalRandom;
import java.util.stream.Collectors;

import static com.paypal.heapdumptool.ApplicationTestSupport.runApplicationPrivileged;
import static com.paypal.heapdumptool.fixture.ByteArrayTool.countOfSequence;
import static com.paypal.heapdumptool.fixture.ByteArrayTool.lengthen;
import static com.paypal.heapdumptool.fixture.ByteArrayTool.nCopiesLongToBytes;
import static java.nio.ByteOrder.BIG_ENDIAN;
import static java.nio.charset.StandardCharsets.UTF_16BE;
import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Arrays.asList;
import static org.apache.commons.io.FileUtils.byteCountToDisplaySize;
import static org.apache.commons.lang3.ArrayUtils.EMPTY_BYTE_ARRAY;
import static org.apache.commons.lang3.ArrayUtils.EMPTY_STRING_ARRAY;
import static org.apache.commons.lang3.JavaVersion.JAVA_1_8;
import static org.apache.commons.lang3.SystemUtils.isJavaVersionAtMost;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;

@TestMethodOrder(Random.class)
class HeapDumpSanitizerTest {

    private static final Logger LOGGER = LoggerFactory.getLogger(HeapDumpSanitizerTest.class);

    @TempDir
    static Path tempDir2;
    static Path tempDir;

    static {
        try {
            tempDir = Files.createTempDirectory("");
        } catch (final IOException e) {
            throw new RuntimeException(e);
        }
    }

    private final SecretArrays secretArrays = new SecretArrays();

    @BeforeEach
    void beforeEach(final TestInfo info) {
        LOGGER.info("Test - {}:", info.getDisplayName());
    }

    @BeforeEach
    @AfterEach
    void clearLoadedHeapDumpInfo() {
        System.gc();
    }

    private void unused(final Object... o) {
        //no op
    }

    @Test
    @DisplayName("testSecretsAreInHeapDump. Verify that heap dump normally contains sensitive data")
    void testSecretsAreInHeapDump() throws Exception {
        // "his-secret-value" with each letter incremented by 1
        final String hisSecretValue = "ijt.tfdsfu.wbmvf";
        final String herSecretValue = "ifs.tfdsfu.wbmvf";
        final String itsSecretValue = "jut.tfdsfu.wbmvf";

        // keep as byte array in mem
        byte[] actualHisSecretValue = adjustLettersToByteArray(hisSecretValue);

        // keep as char array in mem
        String actualHerSecretValue = new String(actualHisSecretValue, UTF_8).replace("his", "her");

        // interned
        lengthenAndInternItsValue(actualHisSecretValue);

        actualHisSecretValue = lengthen(actualHisSecretValue, DataSize.ofMegabytes(1));
        actualHerSecretValue = lengthen(actualHerSecretValue, DataSize.ofMegabytes(1));
        unused(actualHisSecretValue, actualHerSecretValue);

        final byte[] heapDump = loadHeapDump();

        final byte[] expectedHisSecretValueBytes = adjustLettersToByteArray(hisSecretValue);
        final byte[] expectedHerSecretValueBytes = adjustLettersToByteArray(herSecretValue);
        final byte[] expectedItsSecretValueBytes = adjustLettersToByteArray(itsSecretValue);

        assertThat(heapDump)
                .overridingErrorMessage("sequences do not match") // normal error message would be long and not helpful at all
                .containsSequence(expectedHisSecretValueBytes)
                .containsSequence(expectedHerSecretValueBytes)
                .containsSequence(expectedItsSecretValueBytes)
                .containsSequence(secretArrays.getByteArraySequence())
                .containsSequence(secretArrays.getCharArraySequence())
                .containsSequence(secretArrays.getShortArraySequence())
                .containsSequence(secretArrays.getIntArraySequence())
                .containsSequence(secretArrays.getLongArraySequence())
                .containsSequence(secretArrays.getFloatArraySequence())
                .containsSequence(secretArrays.getDoubleArraySequence())
                .containsSequence(secretArrays.getBooleanArraySequence());
    }

    @ParameterizedTest
    @CsvSource(value = {"--force-string-coder-match=true", "--force-string-coder-match=false"})
    @DisplayName("testConfidentialsNotInHeapDump. Verify that sanitized heap dump does not contains sensitive data")
    void testConfidentialsNotInHeapDump(final String cliArg) throws Exception {
        // "his-classified-value" with each letter incremented by 1
        final String hisClassifiedValue = "ijt.dmbttjgjfe.wbmvf";
        final String herClassifiedValue = "ifs.dmbttjgjfe.wbmvf";
        final String itsClassifiedValue = "jut.dmbttjgjfe.wbmvf";

        byte[] actualHisConfidentialValue = ResourceTool.bytesOf(getClass(), "classifieds.txt");
        String actualHerConfidentialValue = new String(actualHisConfidentialValue, UTF_8).replace("his", "her");
        lengthenAndInternItsValue(actualHisConfidentialValue);

        actualHisConfidentialValue = lengthen(actualHisConfidentialValue, DataSize.ofMegabytes(1));
        actualHerConfidentialValue = lengthen(actualHerConfidentialValue, DataSize.ofMegabytes(1));
        unused(actualHisConfidentialValue, actualHerConfidentialValue);

        final byte[] heapDump = loadSanitizedHeapDump(cliArg);

        final byte[] expectedHisClassifiedValueBytes = adjustLettersToByteArray(hisClassifiedValue);
        final byte[] expectedHerClassifiedValueBytes = adjustLettersToByteArray(herClassifiedValue);
        final byte[] expectedItsClassifiedValueBytes = adjustLettersToByteArray(itsClassifiedValue);

        verifyDoesNotContainsSequence(heapDump, expectedHisClassifiedValueBytes);
        verifyDoesNotContainsSequence(heapDump, expectedHerClassifiedValueBytes);
        verifyDoesNotContainsSequence(heapDump, expectedItsClassifiedValueBytes);

        verifyDoesNotContainsSequence(heapDump, secretArrays.getByteArraySequence());
        verifyDoesNotContainsSequence(heapDump, secretArrays.getCharArraySequence());

        // by default only byte and char arrays are sanitized
        assertThat(heapDump)
                .overridingErrorMessage("sequences do not match") // normal error message would be long and not helpful at all
                .containsSequence(secretArrays.getShortArraySequence())
                .containsSequence(secretArrays.getIntArraySequence())
                .containsSequence(secretArrays.getLongArraySequence())
                .containsSequence(secretArrays.getFloatArraySequence())
                .containsSequence(secretArrays.getDoubleArraySequence())
                .containsSequence(secretArrays.getBooleanArraySequence());
    }

    @Test
    @DisplayName("testSanitizeFieldsOfNonArrayPrimitiveType. Verify that fields of non-array primitive type can be sanitized")
    void testSanitizeFieldsOfNonArrayPrimitiveType() throws Exception {
        final Object instance = new ClassWithManyInstanceFields();
        final Object staticFields = new ClassWithManyStaticFields();
        assertThat(instance).isNotNull();
        assertThat(staticFields).isNotNull();

        byte[] sanitizedHeapDump = loadSanitizedHeapDump("--sanitize-byte-char-arrays-only=false");
        verifyDoesNotContainsSequence(sanitizedHeapDump, nCopiesLongToBytes(deadcow(), 100));
        assertThat(countOfSequence(sanitizedHeapDump, nCopiesLongToBytes(cafegirl(), 1)))
                .isLessThan(1000);

        sanitizedHeapDump = EMPTY_BYTE_ARRAY;
        unused(new Object[]{sanitizedHeapDump});
        clearLoadedHeapDumpInfo();

        {
            final byte[] clearHeapDump = loadSanitizedHeapDump("--sanitize-byte-char-arrays-only=true");
            assertThat(clearHeapDump)
                    .overridingErrorMessage("sequences do not match") // normal error message would be long and not helpful at all
                    .containsSequence(nCopiesLongToBytes(deadcow(), 500));

            assertThat(countOfSequence(clearHeapDump, nCopiesLongToBytes(cafegirl(), 1)))
                    .isGreaterThan(500);
        }

        {
            final byte[] clearHeapDump = loadSanitizedHeapDump("--sanitize-byte-char-arrays-only=false", "--sanitize-arrays-only=true");
            assertThat(clearHeapDump)
                    .overridingErrorMessage("sequences do not match") // normal error message would be long and not helpful at all
                    .containsSequence(nCopiesLongToBytes(deadcow(), 500));

            assertThat(countOfSequence(clearHeapDump, nCopiesLongToBytes(cafegirl(), 1)))
                    .isGreaterThan(500);
        }
    }

    @Test
    void testSanitizeArraysOnly() throws Exception {
        final byte[] heapDump = loadSanitizedHeapDump("--sanitize-byte-char-arrays-only=false", "--sanitize-arrays-only=true");
        verifyDoesNotContainsSequence(heapDump, secretArrays.getByteArraySequence());
        verifyDoesNotContainsSequence(heapDump, secretArrays.getCharArraySequence());
        verifyDoesNotContainsSequence(heapDump, secretArrays.getShortArraySequence());
        verifyDoesNotContainsSequence(heapDump, secretArrays.getIntArraySequence());
        verifyDoesNotContainsSequence(heapDump, secretArrays.getLongArraySequence());
        verifyDoesNotContainsSequence(heapDump, secretArrays.getFloatArraySequence());
        verifyDoesNotContainsSequence(heapDump, secretArrays.getDoubleArraySequence());
        verifyDoesNotContainsSequence(heapDump, secretArrays.getBooleanArraySequence());
    }

    @Test
    void testThreadNameExcludedFromSanitization() throws Exception {
        // "xN-classified-value" with each letter incremented by 1
        final String x2ClassifiedValue = "y3.dmbttjgjfe.wbmvf";
        final String x5ClassifiedValue = "y6.dmbttjgjfe.wbmvf";
        final ThreadGroup threadGroup = new ThreadGroup(adjustLetters(x5ClassifiedValue));
        final Thread thread = new Thread(threadGroup, (Runnable) null);
        thread.setDaemon(true);
        thread.setName(adjustLetters(x2ClassifiedValue));

        final Charset charset = isJavaVersionAtMost(JAVA_1_8) ? UTF_16BE : UTF_8;
        final byte[] sanitizedHeapDump = loadSanitizedHeapDump();
        assertThat(sanitizedHeapDump)
                .withFailMessage("threadGroupName " + threadGroup.getName())
                .containsSequence(butLast(threadGroup.getName()).getBytes(charset))
                .withFailMessage("threadName " + thread.getName())
                .containsSequence(butLast(thread.getName()).getBytes(charset));
    }

    private String butLast(final String input) {
        return StringUtils.substring(input, 0, input.length() - 2);
    }

    @Test
    void testThreadNameIncludedInSanitization() throws Exception {
        // "xN-classified-value" with each letter incremented by 1
        final String x7ClassifiedValue = "y8.dmbttjgjfe.wbmvf";
        final String x11ClassifiedValue = "y12.dmbttjgjfe.wbmvf";
        final ThreadGroup threadGroup = new ThreadGroup(adjustLetters(x7ClassifiedValue));
        final Thread thread = new Thread(threadGroup, (Runnable) null);
        thread.setDaemon(true);
        thread.setName(adjustLetters(x11ClassifiedValue));

        final byte[] sanitizedHeapDump = loadSanitizedHeapDump("--exclude-string-fields=none#none");
        verifyDoesNotContainsSequence(sanitizedHeapDump, threadGroup.getName().getBytes(UTF_8));
        verifyDoesNotContainsSequence(sanitizedHeapDump, thread.getName().getBytes(UTF_8));
    }

    // 0xDEADBEEF
    private long deadcow() {
        return 0xDEADBEEE + Integer.parseInt("1");
    }

    // 0xCAFEBABE
    private long cafegirl() {
        return 0xCAFEBABD + Integer.parseInt("1");
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
        unused(itsValue.intern());
    }

    private byte[] adjustLettersToByteArray(final String str) {
        return adjustLetters(str).getBytes(UTF_8);
    }

    private String adjustLetters(final String str) {
        return str.chars()
                .map(chr -> chr - 1)
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

    private static class SecretArrays {
        private static final int LENGTH = 512;

        private final byte[] byteArray = new byte[LENGTH];
        private final char[] charArray = new char[LENGTH];
        private final short[] shortArray = new short[LENGTH];
        private final int[] intArray = new int[LENGTH];
        private final long[] longArray = new long[LENGTH];
        private final float[] floatArray = new float[LENGTH];
        private final double[] doubleArray = new double[LENGTH];
        private final boolean[] booleanArray = new boolean[LENGTH];

        {
            final ThreadLocalRandom random = ThreadLocalRandom.current();
            for (int i = 0; i < LENGTH; i++) {
                byteArray[i] = (byte) random.nextInt();
                charArray[i] = (char) random.nextInt();
                shortArray[i] = (short) random.nextInt();
                intArray[i] = random.nextInt();
                longArray[i] = random.nextLong();
                floatArray[i] = random.nextFloat();
                doubleArray[i] = random.nextDouble();
                booleanArray[i] = random.nextBoolean();
            }
        }

        public byte[] getByteArraySequence() {
            return byteArray;
        }

        public byte[] getCharArraySequence() {
            final ByteBuffer buffer = ByteBuffer.allocate(Character.BYTES * LENGTH);
            buffer.order(BIG_ENDIAN);
            for (int i = 0; i < LENGTH; i++) {
                buffer.putChar(i * Character.BYTES, charArray[i]);
            }
            return buffer.array();
        }

        public byte[] getShortArraySequence() {
            final ByteBuffer buffer = ByteBuffer.allocate(Short.BYTES * LENGTH);
            buffer.order(BIG_ENDIAN);
            for (int i = 0; i < LENGTH; i++) {
                buffer.putShort(i * Short.BYTES, shortArray[i]);
            }
            return buffer.array();
        }

        public byte[] getIntArraySequence() {
            final ByteBuffer buffer = ByteBuffer.allocate(Integer.BYTES * LENGTH);
            buffer.order(BIG_ENDIAN);
            for (int i = 0; i < LENGTH; i++) {
                buffer.putInt(i * Integer.BYTES, intArray[i]);
            }
            return buffer.array();
        }

        public byte[] getLongArraySequence() {
            final ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES * LENGTH);
            buffer.order(BIG_ENDIAN);
            for (int i = 0; i < LENGTH; i++) {
                buffer.putLong(i * Long.BYTES, longArray[i]);
            }
            return buffer.array();
        }

        public byte[] getFloatArraySequence() {
            final ByteBuffer buffer = ByteBuffer.allocate(Float.BYTES * LENGTH);
            buffer.order(BIG_ENDIAN);
            for (int i = 0; i < LENGTH; i++) {
                buffer.putFloat(i * Float.BYTES, floatArray[i]);
            }
            return buffer.array();
        }

        public byte[] getDoubleArraySequence() {
            final ByteBuffer buffer = ByteBuffer.allocate(Double.BYTES * LENGTH);
            buffer.order(BIG_ENDIAN);
            for (int i = 0; i < LENGTH; i++) {
                buffer.putDouble(i * Double.BYTES, doubleArray[i]);
            }
            return buffer.array();
        }

        public byte[] getBooleanArraySequence() {
            final ByteBuffer buffer = ByteBuffer.allocate(LENGTH);
            buffer.order(BIG_ENDIAN);
            for (int i = 0; i < LENGTH; i++) {
                buffer.put(i, booleanArray[i] ? (byte) 1 : (byte) 0);
            }
            return buffer.array();
        }
    }
}
