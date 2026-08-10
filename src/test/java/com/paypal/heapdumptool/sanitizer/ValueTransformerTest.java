package com.paypal.heapdumptool.sanitizer;

import com.paypal.heapdumptool.fixture.Hprof;
import com.paypal.heapdumptool.utils.DataSize;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import picocli.CommandLine;

import static java.util.Arrays.*;
import static java.util.Arrays.asList;
import static org.apache.commons.lang3.ArrayUtils.EMPTY_STRING_ARRAY;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Byte-exact tests for {@link ValueTransformer}, the computed-replacement half of the SPI.
 *
 * <p>Same synthetic-fixture approach as {@link SanitizationRuleTest}: a transformed region keeps its
 * length, so an offset recorded while building the input is also valid in the output. That invariant is
 * what most of these tests are really checking -- a transformer decodes and re-encodes values, which is
 * the one path in the tool where a width could be got wrong.</p>
 */
@ExtendWith(OutputCaptureExtension.class)
class ValueTransformerTest {

    private static final String ACCOUNT_CLASS_NAME = "com.mycorp.Account";

    private static final long ACCOUNT_CLASS_ID = 2100;
    private static final long ACCOUNT_OBJECT_ID = 0xA000;
    private static final long ARRAY_OBJECT_ID = 0xA100;

    /** The chain the most recent run used, for tests that assert on what it logged about transformers. */
    private SanitizationRuleRegistry lastRunRules;

    /**
     * A class with one field of each transformable type, so a single fixture can prove every arm of the
     * scalar switch reads and writes exactly the type's width.
     *
     * <p>The OBJECT field last is deliberate: a transformer must not be reachable for it, and having it
     * in the layout means a wrong width anywhere earlier mis-slots it and shows up as a corrupted id.</p>
     */
    private static final class AllTypesFixture {

        static final int NUM_FIELDS = 9;

        final byte[] input;

        /** Field offsets in declaration order, parallel to {@link #TYPES}. */
        final int[] offsets = new int[NUM_FIELDS];

        static final String[] NAMES = {
            "flag", "b", "c", "s", "i", "l", "f", "d", "ref",
        };

        static final BasicType[] TYPES = {
            BasicType.BOOLEAN,
            BasicType.BYTE,
            BasicType.CHAR,
            BasicType.SHORT,
            BasicType.INT,
            BasicType.LONG,
            BasicType.FLOAT,
            BasicType.DOUBLE,
            BasicType.OBJECT,
        };

        AllTypesFixture() throws IOException {
            final Hprof hprof = new Hprof().header();
            hprof.stringInUtf8(60, ACCOUNT_CLASS_NAME);
            final int[] nameIds = new int[NUM_FIELDS];
            for (int i = 0; i < NUM_FIELDS; i++) {
                nameIds[i] = 61 + i;
                hprof.stringInUtf8(nameIds[i], NAMES[i]);
            }
            hprof.loadClass(1, ACCOUNT_CLASS_ID, 60);

            final Hprof body = new Hprof();
            body.classDump(ACCOUNT_CLASS_ID, 0, nameIds, TYPES);

            final Hprof instance = new Hprof();
            final int[] relative = new int[NUM_FIELDS];

            relative[0] = instance.offset();
            instance.u1(1); // flag = true
            relative[1] = instance.offset();
            instance.u1(0x07); // b = 7
            relative[2] = instance.offset();
            instance.u2('A'); // c
            relative[3] = instance.offset();
            instance.u2(0x0102); // s
            relative[4] = instance.offset();
            instance.u4(0x11111111); // i
            relative[5] = instance.offset();
            instance.id(0x2222222233333333L); // l -- id() writes 8 bytes, which is long's width
            relative[6] = instance.offset();
            instance.u4(Float.floatToRawIntBits(1.5f) & 0xFFFFFFFFL);
            relative[7] = instance.offset();
            instance.id(Double.doubleToRawLongBits(2.5d));
            relative[8] = instance.offset();
            instance.id(0xBEEF); // ref

            final int instanceOffset = body.instanceDump(ACCOUNT_OBJECT_ID, ACCOUNT_CLASS_ID, instance.toByteArray());
            final int base = hprof.record(HeapRecord.HEAP_DUMP_SEGMENT.getTag(), body);

            this.input = hprof.toByteArray();
            for (int i = 0; i < NUM_FIELDS; i++) {
                this.offsets[i] = base + instanceOffset + relative[i];
            }
        }

        int offsetOf(@SuppressWarnings("all") final String name) {
            return offsets[asList(NAMES).indexOf(name)];
        }
    }

    /** Routes a transformer at the named fields of {@link #ACCOUNT_CLASS_NAME}, abstaining elsewhere. */
    private static final class TransformFieldRule implements SanitizationRule {

        private final ValueTransformer transformer;
        private final List<String> names;

        TransformFieldRule(final ValueTransformer transformer, final String... names) {
            this.transformer = transformer;
            this.names = asList(names);
        }

        @Override
        public Decision decideField(final FieldContext context) {
            if (ACCOUNT_CLASS_NAME.equals(context.declaringClassName()) && names.contains(context.fieldName())) {
                return Decision.transformWith(transformer);
            }
            return Decision.undecided();
        }

        @Override
        public String describe() {
            return "TransformFieldRule" + names;
        }
    }

    /** Routes a transformer at every primitive array, abstaining on fields. */
    private static final class TransformArrayRule implements SanitizationRule {

        private final ValueTransformer transformer;

        TransformArrayRule(final ValueTransformer transformer) {
            this.transformer = transformer;
        }

        @Override
        public Decision decideArray(final ArrayContext context) {
            return Decision.transformWith(transformer);
        }

        @Override
        public String describe() {
            return "TransformArrayRule";
        }
    }

    // ---------------------------------------------------------------------------------------------
    // Scalar fields
    // ---------------------------------------------------------------------------------------------

    @Test
    @DisplayName("testTransformedFieldLeavesNeighboursByteIdentical. A transformer touches only the field it was"
            + " routed at")
    void testTransformedFieldLeavesNeighboursByteIdentical() throws Exception {
        final AllTypesFixture fixture = new AllTypesFixture();

        // the int field only, and to a value that shares no byte with the original
        final ValueTransformer transformer = new ValueTransformer() {
            @Override
            public int transformInt(final int value) {
                return 0x44556677;
            }
        };

        final byte[] output = sanitize(fixture.input, new TransformFieldRule(transformer, "i"), "--target=none");

        assertThat(region(output, fixture.offsetOf("i"), Integer.BYTES))
                .as("the transformed field holds what the transformer returned, big-endian")
                .containsExactly(0x44, 0x55, 0x66, 0x77);

        assertThat(output)
                .as("every other byte of the dump is untouched, so nothing was mis-sliced")
                .isEqualTo(
                        withRegionReplaced(fixture.input, fixture.offsetOf("i"), new byte[] {0x44, 0x55, 0x66, 0x77}));
    }

    @Test
    @DisplayName("testEveryScalarTypeRoundTripsUnchanged. An identity transformer on all 8 types rewrites no byte")
    void testEveryScalarTypeRoundTripsUnchanged() throws Exception {
        final AllTypesFixture fixture = new AllTypesFixture();

        /*
         * The default methods are identities, so an empty implementation routed at every transformable
         * field must reproduce the dump exactly. This is the width test: any arm reading or writing the
         * wrong number of bytes desynchronizes the walk and corrupts what follows -- including the OBJECT
         * field the fixture puts last.
         */
        final ValueTransformer identity = new ValueTransformer() {};

        final byte[] output = sanitize(
                fixture.input,
                new TransformFieldRule(identity, "flag", "b", "c", "s", "i", "l", "f", "d"),
                "--target=none");

        assertThat(output).isEqualTo(fixture.input);
    }

    @Test
    @DisplayName("testTransformerSeesTheOriginalValueOfEachType. Each arm decodes the value the fixture wrote")
    void testTransformerSeesTheOriginalValueOfEachType() throws Exception {
        final AllTypesFixture fixture = new AllTypesFixture();
        final List<String> seen = new ArrayList<>();

        final ValueTransformer recorder = new ValueTransformer() {
            @Override
            public boolean transformBoolean(final boolean value) {
                seen.add("boolean=" + value);
                return value;
            }

            @Override
            public byte transformByte(final byte value) {
                seen.add("byte=" + value);
                return value;
            }

            @Override
            public char transformChar(final char value) {
                seen.add("char=" + value);
                return value;
            }

            @Override
            public short transformShort(final short value) {
                seen.add("short=" + value);
                return value;
            }

            @Override
            public int transformInt(final int value) {
                seen.add("int=" + Integer.toHexString(value));
                return value;
            }

            @Override
            public long transformLong(final long value) {
                seen.add("long=" + Long.toHexString(value));
                return value;
            }

            @Override
            public float transformFloat(final float value) {
                seen.add("float=" + value);
                return value;
            }

            @Override
            public double transformDouble(final double value) {
                seen.add("double=" + value);
                return value;
            }
        };

        sanitize(
                fixture.input,
                new TransformFieldRule(recorder, "flag", "b", "c", "s", "i", "l", "f", "d"),
                "--target=none");

        assertThat(seen)
                .as("decoded in declaration order, each as its own type")
                .containsExactly(
                        "boolean=true",
                        "byte=7",
                        "char=A",
                        "short=258",
                        "int=11111111",
                        "long=2222222233333333",
                        "float=1.5",
                        "double=2.5");
    }

    @Test
    @DisplayName("testSignallingNaNSurvivesAnIdentityTransform. Raw bits, so a preserved NaN is not canonicalized")
    void testSignallingNaNSurvivesAnIdentityTransform() throws Exception {
        /*
         * floatToIntBits collapses every NaN to one canonical NaN. An identity transformer over that
         * would rewrite the bytes of a signalling NaN -- a value the tool was told to keep -- so the
         * float and double arms use the raw conversions. Same reason -0.0 is here: it must not become 0.0.
         */
        final int signallingNaNBits = 0x7FA00000;
        final long signallingNaNDoubleBits = 0x7FF4000000000000L;

        final FloatDoubleFixture fixture =
                new FloatDoubleFixture(signallingNaNBits, signallingNaNDoubleBits, -0.0f, -0.0d);

        final byte[] output = sanitize(
                fixture.input,
                new TransformFieldRule(new ValueTransformer() {}, "f1", "d1", "f2", "d2"),
                "--target=none");

        assertThat(output)
                .as("an identity transform is a genuine no-op, even for NaN payloads and negative zero")
                .isEqualTo(fixture.input);
    }

    /** Two float and two double fields, written from explicit raw bit patterns. */
    private static final class FloatDoubleFixture {

        final byte[] input;

        FloatDoubleFixture(final int f1Bits, final long d1Bits, final float f2, final double d2) throws IOException {
            final Hprof hprof = new Hprof().header();
            hprof.stringInUtf8(60, ACCOUNT_CLASS_NAME);
            hprof.stringInUtf8(61, "f1");
            hprof.stringInUtf8(62, "d1");
            hprof.stringInUtf8(63, "f2");
            hprof.stringInUtf8(64, "d2");
            hprof.loadClass(1, ACCOUNT_CLASS_ID, 60);

            final Hprof body = new Hprof();
            body.classDump(ACCOUNT_CLASS_ID, 0, new int[] {61, 62, 63, 64}, new BasicType[] {
                BasicType.FLOAT, BasicType.DOUBLE, BasicType.FLOAT, BasicType.DOUBLE
            });

            final Hprof instance = new Hprof();
            instance.u4(f1Bits & 0xFFFFFFFFL);
            instance.id(d1Bits);
            instance.u4(Float.floatToRawIntBits(f2) & 0xFFFFFFFFL);
            instance.id(Double.doubleToRawLongBits(d2));

            body.instanceDump(ACCOUNT_OBJECT_ID, ACCOUNT_CLASS_ID, instance.toByteArray());
            hprof.record(HeapRecord.HEAP_DUMP_SEGMENT.getTag(), body);
            this.input = hprof.toByteArray();
        }
    }

    @Test
    @DisplayName("testTransformerIsInvokedExactlyOncePerValueAcrossTwoPasses. The metadata pass never transforms")
    void testTransformerIsInvokedExactlyOncePerValueAcrossTwoPasses() throws Exception {
        final AllTypesFixture fixture = new AllTypesFixture();
        final AtomicInteger calls = new AtomicInteger();

        /*
         * A transformer may keep state -- a counter, a pseudonym table -- so being invoked once per pass
         * would double every count. The metadata pass runs with sanitizationEnabled false, which is what
         * keeps this at one; the assertion is here because that is a property of the SPI, not an
         * implementation detail callers should have to know.
         */
        final ValueTransformer counting = new ValueTransformer() {
            @Override
            public int transformInt(final int value) {
                return calls.incrementAndGet();
            }
        };

        sanitizeTwoPasses(fixture.input, new TransformFieldRule(counting, "i"), "--target=none");

        assertThat(calls.get()).isEqualTo(1);
    }

    @Test
    @DisplayName("testStaticFieldCanBeTransformed. A static field's value is transformed like an instance field's")
    void testStaticFieldCanBeTransformed() throws Exception {
        final Hprof hprof = new Hprof().header();
        hprof.stringInUtf8(60, ACCOUNT_CLASS_NAME);
        hprof.stringInUtf8(61, "counter");
        hprof.loadClass(1, ACCOUNT_CLASS_ID, 60);

        final Hprof body = new Hprof();
        final int relativeStatic = body.classDumpWithStatics(
                ACCOUNT_CLASS_ID,
                0,
                new Hprof.StaticField[] {new Hprof.StaticField(61, BasicType.INT, new byte[] {0x11, 0x22, 0x33, 0x44})},
                new int[0],
                new BasicType[0]);
        final int base = hprof.record(HeapRecord.HEAP_DUMP_SEGMENT.getTag(), body);

        final ValueTransformer negate = new ValueTransformer() {
            @Override
            public int transformInt(final int value) {
                return ~value;
            }
        };

        final byte[] output = sanitize(hprof.toByteArray(), new TransformFieldRule(negate, "counter"), "--target=none");

        assertThat(region(output, base + relativeStatic, Integer.BYTES))
                .as("the static value went through the transformer")
                .containsExactly(0xEE, 0xDD, 0xCC, 0xBB);
    }

    // ---------------------------------------------------------------------------------------------
    // Arrays
    // ---------------------------------------------------------------------------------------------

    @Test
    @DisplayName("testArrayIsTransformedElementWiseByDefault. The default array method applies the scalar one")
    void testArrayIsTransformedElementWiseByDefault() throws Exception {
        final ArrayFixture fixture = new ArrayFixture(BasicType.INT, new byte[] {
            0, 0, 0, 1, //
            0, 0, 0, 2, //
            0, 0, 0, 3,
        });

        final ValueTransformer doubling = new ValueTransformer() {
            @Override
            public int transformInt(final int value) {
                return value * 2;
            }
        };

        final byte[] output = sanitize(fixture.input, new TransformArrayRule(doubling), "--target=none");

        assertThat(region(output, fixture.dataOffset, 12))
                .as("each element decoded, doubled and re-encoded in place")
                .containsExactly(0, 0, 0, 2, 0, 0, 0, 4, 0, 0, 0, 6);
    }

    @Test
    @DisplayName("testArrayLongerThanOneChunkIsFullyTransformed. Chunking covers every element exactly once")
    void testArrayLongerThanOneChunkIsFullyTransformed() throws Exception {
        /*
         * Deliberately not a multiple of the 8 KB chunk: the last chunk is partial, which is where an
         * off-by-one in the loop shows up. Elements are longs so the region spans several chunks without
         * the fixture having to be enormous.
         */
        final int numElements = 3000;
        final byte[] data = new byte[numElements * Long.BYTES];
        for (int i = 0; i < numElements; i++) {
            writeLong(data, i * Long.BYTES, i);
        }
        final ArrayFixture fixture = new ArrayFixture(BasicType.LONG, data);

        final AtomicInteger calls = new AtomicInteger();
        final ValueTransformer increment = new ValueTransformer() {
            @Override
            public long transformLong(final long value) {
                calls.incrementAndGet();
                return value + 1;
            }
        };

        final byte[] output = sanitize(fixture.input, new TransformArrayRule(increment), "--target=none");

        assertThat(calls.get())
                .as("once per element, no element skipped and none seen twice")
                .isEqualTo(numElements);
        for (int i = 0; i < numElements; i++) {
            final long actual = readLong(output, fixture.dataOffset + i * Long.BYTES);
            assertThat(actual).as("element %s", i).isEqualTo(i + 1);
        }
    }

    @Test
    @DisplayName("testWholeArrayModeSeesTheWholeRegion. An opted-in transformer gets the array, not a chunk")
    void testWholeArrayModeSeesTheWholeRegion() throws Exception {
        final byte[] secret = "4111111111111234".getBytes(StandardCharsets.UTF_8);
        final ArrayFixture fixture = new ArrayFixture(BasicType.BYTE, secret);

        /*
         * The point of whole-array mode: recognizing content that spans elements. A masking transformer
         * cannot do this chunked, so the region must arrive in one call. The transformer honors the
         * length -- the array may be longer than the region, since the buffer is engine scratch -- and
         * decodes only [0, length).
         */
        final List<String> seen = new ArrayList<>();
        final ValueTransformer masking = new ValueTransformer() {
            private final DataSize dataSize = DataSize.ofBytes(1024);

            @Override
            public void transformByteArray(final byte[] value, final int length, final ArrayContext context) {
                seen.add(new String(value, 0, length, StandardCharsets.UTF_8));
                for (int i = 0; i < length - 4; i++) {
                    value[i] = '*';
                }
            }

            @Override
            public DataSize maxMaterializedArraySize() {
                return dataSize;
            }
        };

        final byte[] output = sanitize(fixture.input, new TransformArrayRule(masking), "--target=none");

        assertThat(seen)
                .as("the whole region arrives in one call, exactly once")
                .containsExactly("4111111111111234");
        assertThat(new String(output, fixture.dataOffset, secret.length, StandardCharsets.UTF_8))
                .as("masked except the last four, which a constant replacement could not have preserved")
                .isEqualTo("************1234");
    }

    @Test
    @DisplayName("testReusedBufferLongerThanTheRegion. An over-long scratch buffer does not leak into the region")
    void testReusedBufferLongerThanTheRegion() throws Exception {
        /*
         * Two arrays in one dump, the second shorter than the first. The scratch buffer is grown, never
         * shrunk, so the second array is handed over in a buffer still long enough for the first. The
         * transformer honors the length, so the leftover tail never shows up in what it decodes.
         */
        final Hprof body = new Hprof();
        final int firstOffset = body.primitiveArrayDump(
                ARRAY_OBJECT_ID, BasicType.BYTE, "AAAAAAAAAAAA".getBytes(StandardCharsets.UTF_8));
        final int secondOffset =
                body.primitiveArrayDump(ARRAY_OBJECT_ID + 1, BasicType.BYTE, "BBBB".getBytes(StandardCharsets.UTF_8));

        final Hprof hprof = new Hprof().header();
        final int base = hprof.record(HeapRecord.HEAP_DUMP_SEGMENT.getTag(), body);

        final List<String> seen = new ArrayList<>();
        final ValueTransformer wholeReader = new ValueTransformer() {
            private final DataSize dataSize = DataSize.ofBytes(1024);

            @Override
            public void transformByteArray(final byte[] value, final int length, final ArrayContext context) {
                seen.add(new String(value, 0, length, StandardCharsets.UTF_8));
            }

            @Override
            public DataSize maxMaterializedArraySize() {
                return dataSize;
            }
        };

        final byte[] output = sanitize(hprof.toByteArray(), new TransformArrayRule(wholeReader), "--target=none");

        assertThat(seen).containsExactly("AAAAAAAAAAAA", "BBBB");
        assertThat(region(output, base + firstOffset, 12)).containsOnly('A');
        assertThat(region(output, base + secondOffset, 4)).containsOnly('B');
    }

    @Test
    @DisplayName("testOversizedArrayFallsBackToChunkedAndSaysSo. The degradation is logged, not silent")
    void testOversizedArrayFallsBackToChunkedAndSaysSo(final CapturedOutput logOutput) throws Exception {
        final int numElements = 4000;
        final ArrayFixture fixture = new ArrayFixture(BasicType.BYTE, new byte[numElements]);

        /*
         * A transformer that asked to see arrays whole, on an array too big for the limit it named. It
         * still runs -- chunked -- because refusing would abort a redaction that is mostly working. But a
         * masking transformer that quietly degrades on the one array that happened to be large is a
         * redaction failure that reports success, so the run has to say so.
         */
        final ValueTransformer wholeOnly = new ValueTransformer() {
            private final DataSize dataSize = DataSize.ofBytes(64);

            @Override
            public void transformByteArray(final byte[] value, final int length, final ArrayContext context) {
                for (int i = 0; i < length; i++) {
                    value[i] = '*';
                }
            }

            @Override
            public DataSize maxMaterializedArraySize() {
                return dataSize;
            }

            @Override
            public String describe() {
                return "WholeOnlyMasker";
            }
        };

        final byte[] output = sanitize(fixture.input, new TransformArrayRule(wholeOnly), "--target=none");

        assertThat(logOutput.getAll())
                .as("names the transformer, the limit and the array that exceeded it")
                .contains("WholeOnlyMasker")
                .contains("64")
                .contains("BYTE[4000]");
        assertThat(region(output, fixture.dataOffset, numElements))
                .as("still fully transformed, just not in one piece")
                .containsOnly('*');
    }

    @Test
    @DisplayName("testWritingOutsideTheLiveRegionIsNotEmitted. Only the live region reaches the output")
    void testWritingOutsideTheLiveRegionIsNotEmitted() throws Exception {
        final int numElements = 3000; // spans several chunks, so a chunk buffer runs past the region
        final ArrayFixture fixture = new ArrayFixture(BasicType.BYTE, new byte[numElements]);

        /*
         * The buffer handed over is engine scratch and may be longer than the live region. A transformer
         * that ignores the bounds and scribbles over the whole array is misusing the SPI, but the failure
         * mode must be its own writes being dropped -- not a dump whose records disagree with their
         * lengths.
         */
        final ValueTransformer outOfBounds = new ValueTransformer() {
            @Override
            public void transformByteArray(final byte[] value, final int length, final ArrayContext context) {
                fill(value, (byte) 0xFF);
            }
        };

        final byte[] output = sanitize(fixture.input, new TransformArrayRule(outOfBounds), "--target=none");

        assertThat(output.length)
                .as("length is preserved regardless of what the transformer wrote")
                .isEqualTo(fixture.input.length);
        assertThat(region(output, fixture.dataOffset, numElements)).containsOnly(0xFF);
        assertThat(output)
                .as("the record after the array is untouched, so no scratch leaked into it")
                .isEqualTo(withRegionReplaced(fixture.input, fixture.dataOffset, filled(numElements, (byte) 0xFF)));
    }

    @Test
    @DisplayName("testLatin1AndUtf16BackingArraysGoThroughTheSameTransformer. A masking transformer handles both")
    void testLatin1AndUtf16BackingArraysGoThroughTheSameTransformer() throws Exception {
        /*
         * On JDK 9+ a String's backing byte[] is LATIN1 (one byte per char) or UTF-16 (two, little-endian
         * code units). Both are byte[] as far as the dump is concerned, so both reach the same
         * transformer, and it sees the encoding difference rather than being shielded from it. Worth
         * pinning: a transformer that assumes LATIN1 silently mangles the other, and the tool cannot tell
         * it which it has -- only the owning String's coder field says, and that is a different record.
         */
        final byte[] latin1 = "abc".getBytes(StandardCharsets.ISO_8859_1);
        final byte[] utf16 = "abc".getBytes(StandardCharsets.UTF_16LE);

        final Hprof body = new Hprof();
        final int latin1Offset = body.primitiveArrayDump(ARRAY_OBJECT_ID, BasicType.BYTE, latin1);
        final int utf16Offset = body.primitiveArrayDump(ARRAY_OBJECT_ID + 1, BasicType.BYTE, utf16);

        final Hprof hprof = new Hprof().header();
        final int base = hprof.record(HeapRecord.HEAP_DUMP_SEGMENT.getTag(), body);

        final List<Integer> lengths = new ArrayList<>();
        final ValueTransformer uppercasing = new ValueTransformer() {
            private final DataSize dataSize = DataSize.ofBytes(1024);

            @Override
            public void transformByteArray(final byte[] value, final int length, final ArrayContext context) {
                lengths.add(length);
                for (int i = 0; i < length; i++) {
                    // ASCII-range bytes only, which is exactly what both encodings agree on
                    if (value[i] >= 'a' && value[i] <= 'z') {
                        value[i] = (byte) (value[i] - 32);
                    }
                }
            }

            @Override
            public DataSize maxMaterializedArraySize() {
                return dataSize;
            }
        };

        final byte[] output = sanitize(hprof.toByteArray(), new TransformArrayRule(uppercasing), "--target=none");

        assertThat(lengths).as("three bytes LATIN1, six bytes UTF-16").containsExactly(3, 6);
        assertThat(new String(output, base + latin1Offset, latin1.length, StandardCharsets.ISO_8859_1))
                .isEqualTo("ABC");
        assertThat(new String(output, base + utf16Offset, utf16.length, StandardCharsets.UTF_16LE))
                .as("the zero high bytes are untouched, so the UTF-16 array is still valid")
                .isEqualTo("ABC");
    }

    @Test
    @DisplayName("testExcludeStringFieldsWinsOverATransformer. -e preserves an array a rule would transform")
    void testExcludeStringFieldsWinsOverATransformer() throws Exception {
        /*
         * A user who both excludes a field and routes a transformer at its backing array is contradicting
         * themselves. Preserving is the safe reading, and it is the same precedence a SANITIZE verdict
         * gets -- the transformed path must not have found a way around it.
         */
        final byte[] payload = "secret".getBytes(StandardCharsets.UTF_8);
        final StringFixture fixture = new StringFixture(payload);

        final ValueTransformer clobbering = new ValueTransformer() {
            @Override
            public byte transformByte(final byte value) {
                return '#';
            }
        };

        final byte[] output = sanitize(
                fixture.input,
                new TransformArrayRule(clobbering),
                "--target=all",
                "--exclude-string-fields=" + ACCOUNT_CLASS_NAME + "#name");

        assertThat(new String(output, fixture.dataOffset, payload.length, StandardCharsets.UTF_8))
                .as("-e preserved this array, so the transformer never reached it")
                .isEqualTo("secret");
    }

    /**
     * An {@code Account} with a String {@code name} field, the String instance it points to, and that
     * String's backing byte[] -- the shape {@code --exclude-string-fields} walks.
     */
    private static final class StringFixture {

        final byte[] input;
        final int dataOffset;

        StringFixture(final byte[] payload) throws IOException {
            final long stringClassId = 3000;
            final long stringObjectId = 0xB000;
            final long arrayId = 0xB100;

            final Hprof hprof = new Hprof().header();
            hprof.stringInUtf8(60, ACCOUNT_CLASS_NAME);
            hprof.stringInUtf8(61, "name");
            hprof.stringInUtf8(70, "java.lang.String");
            hprof.stringInUtf8(71, "value");
            hprof.stringInUtf8(72, "coder");
            hprof.loadClass(1, ACCOUNT_CLASS_ID, 60);
            hprof.loadClass(2, stringClassId, 70);

            final Hprof body = new Hprof();
            body.classDump(ACCOUNT_CLASS_ID, 0, new int[] {61}, new BasicType[] {BasicType.OBJECT});
            body.classDump(stringClassId, 0, new int[] {71, 72}, new BasicType[] {BasicType.OBJECT, BasicType.BYTE});

            final Hprof account = new Hprof();
            account.id(stringObjectId);
            body.instanceDump(ACCOUNT_OBJECT_ID, ACCOUNT_CLASS_ID, account.toByteArray());

            final Hprof string = new Hprof();
            string.id(arrayId);
            string.u1(0); // coder = LATIN1
            body.instanceDump(stringObjectId, stringClassId, string.toByteArray());

            final int relativeData = body.primitiveArrayDump(arrayId, BasicType.BYTE, payload);
            final int base = hprof.record(HeapRecord.HEAP_DUMP_SEGMENT.getTag(), body);

            this.input = hprof.toByteArray();
            this.dataOffset = base + relativeData;
        }
    }

    // ---------------------------------------------------------------------------------------------
    // Failing closed
    // ---------------------------------------------------------------------------------------------

    @Test
    @DisplayName("testTransformerRoutedAtAnObjectFieldIsRejected. Overwriting an id corrupts the dump")
    void testTransformerRoutedAtAnObjectFieldIsRejected() throws Exception {
        final AllTypesFixture fixture = new AllTypesFixture();

        assertThatThrownBy(() -> sanitize(
                        fixture.input, new TransformFieldRule(new ValueTransformer() {}, "ref"), "--target=none"))
                .isInstanceOf(SanitizationRuleException.class)
                .hasMessageContaining("ref")
                .hasMessageContaining("object ids");
    }

    @Test
    @DisplayName("testThrowingTransformerAbortsTheRun. A transformer that throws must not fall back to preserving")
    void testThrowingTransformerAbortsTheRun() throws Exception {
        final AllTypesFixture fixture = new AllTypesFixture();

        final ValueTransformer broken = new ValueTransformer() {
            @Override
            public int transformInt(final int value) {
                throw new IllegalStateException("boom");
            }

            @Override
            public String describe() {
                return "BrokenTransformer";
            }
        };

        assertThatThrownBy(() -> sanitize(fixture.input, new TransformFieldRule(broken, "i"), "--target=none"))
                .as("naming the transformer and the field, since the stack trace points into the streaming path")
                .isInstanceOf(SanitizationRuleException.class)
                .hasMessageContaining("BrokenTransformer")
                .hasMessageContaining("i")
                .hasRootCauseMessage("boom");
    }

    @Test
    @DisplayName("testThrowingTransformerOnAnArrayAbortsTheRun. Same failing-closed rule for the array path")
    void testThrowingTransformerOnAnArrayAbortsTheRun() throws Exception {
        final ArrayFixture fixture = new ArrayFixture(BasicType.INT, new byte[] {0, 0, 0, 1});

        final ValueTransformer broken = new ValueTransformer() {
            @Override
            public void transformIntArray(final int[] value, final int length, final ArrayContext context) {
                throw new IllegalStateException("boom");
            }

            @Override
            public String describe() {
                return "BrokenArrayTransformer";
            }
        };

        assertThatThrownBy(() -> sanitize(fixture.input, new TransformArrayRule(broken), "--target=none"))
                .isInstanceOf(SanitizationRuleException.class)
                .hasMessageContaining("BrokenArrayTransformer")
                .hasMessageContaining("INT[1]")
                .hasRootCauseMessage("boom");
    }

    @Test
    @DisplayName("testThrowingWholeArrayLimitAbortsTheRun. A broken limit is not read as zero")
    void testThrowingWholeArrayLimitAbortsTheRun() throws Exception {
        final ArrayFixture fixture = new ArrayFixture(BasicType.INT, new byte[] {0, 0, 0, 1});

        final ValueTransformer broken = new ValueTransformer() {
            @Override
            public DataSize maxMaterializedArraySize() {
                throw new IllegalStateException("boom");
            }

            @Override
            public String describe() {
                return "BrokenLimit";
            }
        };

        assertThatThrownBy(() -> sanitize(fixture.input, new TransformArrayRule(broken), "--target=none"))
                .isInstanceOf(SanitizationRuleException.class)
                .hasMessageContaining("BrokenLimit")
                .hasMessageContaining("maxMaterializedArraySize");
    }

    @Test
    @DisplayName("testNullTransformerIsRejectedAtTheDecision. Caught where the caller can see it")
    @SuppressWarnings("all")
    void testNullTransformerIsRejected() {
        assertThatThrownBy(() -> Decision.transformWith(null)).isInstanceOf(IllegalArgumentException.class);
    }

    // ---------------------------------------------------------------------------------------------
    // Reporting
    // ---------------------------------------------------------------------------------------------

    @Test
    @DisplayName("testRoutedTransformersAreReported. A run names the transformers that computed values")
    void testRoutedTransformersAreReported() throws Exception {
        final AllTypesFixture fixture = new AllTypesFixture();

        final ValueTransformer named = new ValueTransformer() {
            @Override
            public String describe() {
                return "MyMasker";
            }
        };

        sanitize(fixture.input, new TransformFieldRule(named, "i"), "--target=none");

        assertThat(lastRunRules.describeRoutedTransformers())
                .as("a transformer is not registered anywhere, so this is only knowable after the run")
                .containsExactly("MyMasker");
    }

    @Test
    @DisplayName("testARunThatTransformsNothingReportsNoTransformers. Sanitizing rules add no line")
    void testARunThatTransformsNothingReportsNoTransformers() throws Exception {
        final AllTypesFixture fixture = new AllTypesFixture();

        final SanitizationRule sanitizing = new SanitizationRule() {
            @Override
            public Decision decideField(final FieldContext context) {
                return "i".equals(context.fieldName()) ? Decision.sanitize() : Decision.undecided();
            }
        };

        sanitize(fixture.input, sanitizing, "--target=none");

        assertThat(lastRunRules.describeRoutedTransformers()).isEmpty();
    }

    @Test
    @DisplayName("testABrokenDescribeDoesNotAbortTheRun. describe() is user code on a reporting path")
    void testABrokenDescribeDoesNotAbortTheRun() throws Exception {
        final AllTypesFixture fixture = new AllTypesFixture();

        final ValueTransformer brokenDescribe = new ValueTransformer() {
            @Override
            public String describe() {
                throw new IllegalStateException("boom");
            }
        };

        sanitize(fixture.input, new TransformFieldRule(brokenDescribe, "i"), "--target=none");

        assertThat(lastRunRules.describeRoutedTransformers())
                .as("falls back to the class name rather than failing a run that already succeeded")
                .hasSize(1);
    }

    // ---------------------------------------------------------------------------------------------

    /** One primitive array of the given type, alone in a heap dump segment. */
    private static final class ArrayFixture {

        final byte[] input;
        final int dataOffset;

        ArrayFixture(final BasicType elementType, final byte[] data) throws IOException {
            final Hprof body = new Hprof();
            final int relativeData = body.primitiveArrayDump(ARRAY_OBJECT_ID, elementType, data);

            final Hprof hprof = new Hprof().header();
            final int base = hprof.record(HeapRecord.HEAP_DUMP_SEGMENT.getTag(), body);

            this.input = hprof.toByteArray();
            this.dataOffset = base + relativeData;
        }
    }

    private static SanitizeCommand command(final String... options) {
        final SanitizeCommand command = new SanitizeCommand();
        final List<String> argv = new ArrayList<>(asList(options));
        argv.add("in.hprof");
        argv.add("out.hprof");
        new CommandLine(command)
                .registerConverter(DataSize.class, DataSize::parse)
                .parseArgs(argv.toArray(EMPTY_STRING_ARRAY));
        return command;
    }

    private byte[] sanitize(final byte[] input, final SanitizationRule rule, final String... options)
            throws IOException {
        final SanitizeCommand command = command(options);
        command.getSanitizeOptions().addRule(rule);
        return run(new HeapDumpSanitizer(), input, command, false);
    }

    /*
     * A metadata pass then a writing pass on ONE sanitizer, which is what SanitizeCommandProcessor does
     * whenever -e is non-empty or -f is true -- i.e. by default.
     */
    private void sanitizeTwoPasses(
            final byte[] input, final SanitizationRule rule, @SuppressWarnings("all") final String... options)
            throws IOException {
        final SanitizeCommand command = command(options);
        command.getSanitizeOptions().addRule(rule);

        final HeapDumpSanitizer sanitizer = new HeapDumpSanitizer();
        sanitizer.setPreprocessingOnly(true);
        try {
            run(sanitizer, input, command, true);
        } finally {
            sanitizer.setPreprocessingOnly(false);
        }
        run(sanitizer, input, command, false);
    }

    private byte[] run(
            final HeapDumpSanitizer sanitizer,
            final byte[] input,
            final SanitizeCommand command,
            final boolean readOnly)
            throws IOException {
        final ByteArrayOutputStream outputBytes = new ByteArrayOutputStream();
        sanitizer.setInputStream(new ByteArrayInputStream(input));
        sanitizer.setOutputStream(readOnly ? null : outputBytes);
        sanitizer.setProgressMonitor(numBytesProcessed -> {
            // no op
        });
        sanitizer.setSanitizeCommand(command);
        sanitizer.sanitize();
        lastRunRules = sanitizer.getSanitizationRules();

        final byte[] output = outputBytes.toByteArray();
        if (!readOnly) {
            assertThat(output.length)
                    .as("transformation must preserve the length of the dump")
                    .isEqualTo(input.length);
        }
        return output;
    }

    private static int[] region(final byte[] bytes, final int offset, final int length) {
        final int[] unsigned = new int[length];
        for (int i = 0; i < length; i++) {
            unsigned[i] = bytes[offset + i] & 0xFF;
        }
        return unsigned;
    }

    /** The input with one region overwritten, for asserting that nothing else changed. */
    private static byte[] withRegionReplaced(final byte[] input, final int offset, final byte[] replacement) {
        final byte[] expected = input.clone();
        System.arraycopy(replacement, 0, expected, offset, replacement.length);
        return expected;
    }

    private static byte[] filled(@SuppressWarnings("all") final int length, @SuppressWarnings("all") final byte value) {
        final byte[] bytes = new byte[length];
        fill(bytes, value);
        return bytes;
    }

    private static void writeLong(final byte[] bytes, final int offset, final long value) {
        for (int i = 0; i < Long.BYTES; i++) {
            bytes[offset + i] = (byte) (value >>> (8 * (Long.BYTES - 1 - i)));
        }
    }

    private static long readLong(final byte[] bytes, final int offset) {
        long value = 0;
        for (int i = 0; i < Long.BYTES; i++) {
            value = (value << 8) | (bytes[offset + i] & 0xFF);
        }
        return value;
    }
}
