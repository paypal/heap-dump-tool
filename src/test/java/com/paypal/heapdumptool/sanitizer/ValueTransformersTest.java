package com.paypal.heapdumptool.sanitizer;

import com.paypal.heapdumptool.fixture.Hprof;
import com.paypal.heapdumptool.testutil.ConstructorTester;
import com.paypal.heapdumptool.utils.DataSize;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import picocli.CommandLine;

import static java.util.Arrays.asList;
import static org.apache.commons.lang3.ArrayUtils.EMPTY_STRING_ARRAY;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Tests for {@link ValueTransformers}, the static factory that builds a {@link ValueTransformer}
 * from lambdas. Like {@link SanitizationRulesTest}, the point is what the returned proxy does with
 * the methods that are <em>not</em> the targeted one: a {@code intTransformer} must leave every
 * other type identity, and a {@code combine} must fan every method out to its components in order.
 */
@ExtendWith(OutputCaptureExtension.class)
class ValueTransformersTest {

    private static final String ACCOUNT_CLASS_NAME = "com.mycorp.Account";

    private static final long ACCOUNT_CLASS_ID = 2100;
    private static final long ACCOUNT_OBJECT_ID = 0xA000;
    private static final long ARRAY_OBJECT_ID = 0xA100;

    @Test
    @DisplayName("testFactoryIsUninstantiable. A static factory has no public constructor")
    void testFactoryIsUninstantiable() throws Exception {
        ConstructorTester.test(ValueTransformers.class);
    }

    // ---------------------------------------------------------------------------------------------
    // Scalar transformers
    // ---------------------------------------------------------------------------------------------

    @Test
    @DisplayName("testIntTransformerChangesOnlyItsOwnType. A scalar lambda leaves every other type identity")
    void testIntTransformerChangesOnlyItsOwnType() throws Exception {
        final AllTypesFixture fixture = new AllTypesFixture();

        final ValueTransformer intMask = ValueTransformers.intTransformer(value -> 0x44556677);

        final byte[] output = sanitize(fixture.input, new TransformFieldRule(intMask, "i"), "--target=none");

        assertThat(region(output, fixture.offsetOf("i"), Integer.BYTES))
                .as("the int lambda's result, big-endian")
                .containsExactly(0x44, 0x55, 0x66, 0x77);
        assertThat(output)
                .as("every other byte of the dump is untouched, so no other type was routed through the lambda")
                .isEqualTo(
                        withRegionReplaced(fixture.input, fixture.offsetOf("i"), new byte[] {0x44, 0x55, 0x66, 0x77}));
    }

    @Test
    @DisplayName("testEveryScalarFactoryHasAnIdentityElsewhere. Non-targeted transforms keep their default bodies")
    void testEveryScalarFactoryHasAnIdentityElsewhere() throws Exception {
        final AllTypesFixture fixture = new AllTypesFixture();

        final byte[] output = sanitize(
                fixture.input,
                new TransformFieldRule(
                        ValueTransformers.booleanTransformer(value -> value),
                        "flag",
                        "b",
                        "c",
                        "s",
                        "i",
                        "l",
                        "f",
                        "d"),
                "--target=none");

        /*
         * A booleanTransformer routed at every transformable field reproduces the dump exactly: the
         * boolean lambda is identity and the other seven arms run their default bodies. That is the
         * width test -- any arm reading or writing the wrong width desynchronizes the walk.
         */
        assertThat(output).isEqualTo(fixture.input);
    }

    @Test
    @DisplayName("testScalarFactoriesDescribeThemselves. Default descriptions name the factory method")
    void testScalarFactoriesDescribeThemselves() {
        assertThat(ValueTransformers.booleanTransformer(value -> value).describe())
                .isEqualTo("booleanTransformer");
        assertThat(ValueTransformers.byteTransformer(value -> value).describe()).isEqualTo("byteTransformer");
        assertThat(ValueTransformers.charTransformer(value -> value).describe()).isEqualTo("charTransformer");
        assertThat(ValueTransformers.shortTransformer(value -> value).describe())
                .isEqualTo("shortTransformer");
        assertThat(ValueTransformers.intTransformer(value -> value).describe()).isEqualTo("intTransformer");
        assertThat(ValueTransformers.longTransformer(value -> value).describe()).isEqualTo("longTransformer");
        assertThat(ValueTransformers.floatTransformer(value -> value).describe())
                .isEqualTo("floatTransformer");
        assertThat(ValueTransformers.doubleTransformer(value -> value).describe())
                .isEqualTo("doubleTransformer");
    }

    @Test
    @DisplayName("testCustomDescWinsOverTheFactoryName. A supplied description round-trips")
    void testCustomDescWinsOverTheFactoryName() {
        assertThat(ValueTransformers.intTransformer("CardMasker", value -> value)
                        .describe())
                .isEqualTo("CardMasker");
    }

    @Test
    @DisplayName("testScalarTransformerReportsNoWholeArrayLimit. maxMaterializedArraySize defaults to zero")
    void testScalarTransformerReportsNoWholeArrayLimit() {
        assertThat(ValueTransformers.intTransformer(value -> value)
                        .maxMaterializedArraySize()
                        .toBytes())
                .isZero();
    }

    @Test
    @DisplayName("testNullLambdaIsRejected. A transformer must do something")
    @SuppressWarnings("all")
    void testNullLambdaIsRejected() {
        assertThatThrownBy(() -> ValueTransformers.intTransformer(null)).isInstanceOf(NullPointerException.class);
    }

    // ---------------------------------------------------------------------------------------------
    // Byte-array transformer
    // ---------------------------------------------------------------------------------------------

    @Test
    @DisplayName("testByteArrayTransformerSeesTheWholeRegion. A content-aware lambda gets the array, not a chunk")
    void testByteArrayTransformerSeesTheWholeRegion() throws Exception {
        final byte[] secret = "4111111111111234".getBytes(StandardCharsets.UTF_8);
        final ArrayFixture fixture = new ArrayFixture(BasicType.BYTE, secret);

        final List<String> seen = new ArrayList<>();
        final ValueTransformer masking =
                ValueTransformers.byteArrayTransformer(DataSize.ofBytes(1024), (value, length, context) -> {
                    seen.add(new String(value, 0, length, StandardCharsets.UTF_8));
                    for (int i = 0; i < length - 4; i++) {
                        value[i] = '*';
                    }
                });

        final byte[] output = sanitize(fixture.input, new TransformArrayRule(masking), "--target=none");

        assertThat(seen)
                .as("the whole region arrives in one call, exactly once")
                .containsExactly("4111111111111234");
        assertThat(new String(output, fixture.dataOffset, secret.length, StandardCharsets.UTF_8))
                .as("masked except the last four, which a constant replacement could not have preserved")
                .isEqualTo("************1234");
    }

    @Test
    @DisplayName("testByteArrayTransformerDeclaresItsLimit. maxMaterializedArraySize round-trips")
    void testByteArrayTransformerDeclaresItsLimit() {
        assertThat(ValueTransformers.byteArrayTransformer(DataSize.ofBytes(1024), (value, length, context) -> {})
                        .maxMaterializedArraySize())
                .isEqualTo(DataSize.ofBytes(1024));
        assertThat(ValueTransformers.byteArrayTransformer(DataSize.ofBytes(1024), (value, length, context) -> {})
                        .describe())
                .isEqualTo("byteArrayTransformer");
    }

    @Test
    @DisplayName("testOversizedArrayFallsBackToChunkedAndSaysSo. The degradation is logged, not silent")
    void testOversizedArrayFallsBackToChunkedAndSaysSo(final CapturedOutput logOutput) throws Exception {
        final int numElements = 4000;
        final ArrayFixture fixture = new ArrayFixture(BasicType.BYTE, new byte[numElements]);

        final ValueTransformer masker = ValueTransformers.byteArrayTransformer(
                "WholeOnlyMasker", DataSize.ofBytes(64), (value, length, context) -> {
                    for (int i = 0; i < length; i++) {
                        value[i] = '*';
                    }
                });

        final byte[] output = sanitize(fixture.input, new TransformArrayRule(masker), "--target=none");

        assertThat(logOutput.getAll())
                .as("names the transformer, the limit and the array that exceeded it")
                .contains("WholeOnlyMasker")
                .contains("64")
                .contains("BYTE[4000]");
        assertThat(region(output, fixture.dataOffset, numElements))
                .as("still fully transformed, just not in one piece")
                .containsOnly('*');
    }

    // ---------------------------------------------------------------------------------------------
    // Whole-array transformers for the other primitive types
    // ---------------------------------------------------------------------------------------------

    @Test
    @DisplayName("testArrayFactoriesDescribeThemselves. Default descriptions name each factory method")
    void testArrayFactoriesDescribeThemselves() {
        assertThat(ValueTransformers.booleanArrayTransformer(DataSize.ofBytes(1), (value, length, context) -> {})
                        .describe())
                .isEqualTo("booleanArrayTransformer");
        assertThat(ValueTransformers.charArrayTransformer(DataSize.ofBytes(1), (value, length, context) -> {})
                        .describe())
                .isEqualTo("charArrayTransformer");
        assertThat(ValueTransformers.shortArrayTransformer(DataSize.ofBytes(1), (value, length, context) -> {})
                        .describe())
                .isEqualTo("shortArrayTransformer");
        assertThat(ValueTransformers.intArrayTransformer(DataSize.ofBytes(1), (value, length, context) -> {})
                        .describe())
                .isEqualTo("intArrayTransformer");
        assertThat(ValueTransformers.longArrayTransformer(DataSize.ofBytes(1), (value, length, context) -> {})
                        .describe())
                .isEqualTo("longArrayTransformer");
        assertThat(ValueTransformers.floatArrayTransformer(DataSize.ofBytes(1), (value, length, context) -> {})
                        .describe())
                .isEqualTo("floatArrayTransformer");
        assertThat(ValueTransformers.doubleArrayTransformer(DataSize.ofBytes(1), (value, length, context) -> {})
                        .describe())
                .isEqualTo("doubleArrayTransformer");
    }

    @Test
    @DisplayName("testArrayTransformersDeclareTheirLimit. maxMaterializedArraySize round-trips per factory")
    void testArrayTransformersDeclareTheirLimit() {
        assertThat(ValueTransformers.intArrayTransformer(DataSize.ofBytes(2048), (value, length, context) -> {})
                        .maxMaterializedArraySize())
                .isEqualTo(DataSize.ofBytes(2048));
        assertThat(ValueTransformers.doubleArrayTransformer(DataSize.ofBytes(2048), (value, length, context) -> {})
                        .maxMaterializedArraySize())
                .isEqualTo(DataSize.ofBytes(2048));
    }

    @Test
    @DisplayName("testIntArrayTransformerSeesTheWholeRegion. A content-aware int[] lambda gets the materialized array")
    void testIntArrayTransformerSeesTheWholeRegion() throws Exception {
        final ByteBuffer ints = ByteBuffer.allocate(Integer.BYTES * 4);
        ints.putInt(1).putInt(2).putInt(3).putInt(4);
        final ArrayFixture fixture = new ArrayFixture(BasicType.INT, ints.array());

        final List<String> seen = new ArrayList<>();
        final ValueTransformer masker =
                ValueTransformers.intArrayTransformer(DataSize.ofBytes(1024), (value, length, context) -> {
                    seen.add(length + ":" + Arrays.toString(value));
                    for (int i = 0; i < length; i++) {
                        value[i] = 0;
                    }
                });

        final byte[] output = sanitize(fixture.input, new TransformArrayRule(masker), "--target=none");

        assertThat(seen)
                .as("the whole int[] region arrives in one call, exactly once, as element values")
                .containsExactly("4:[1, 2, 3, 4]");
        assertThat(region(output, fixture.dataOffset, Integer.BYTES * 4))
                .as("the consumer's writes went back into the dump as big-endian ints")
                .containsOnly(0);
    }

    @Test
    @DisplayName("testArrayTransformerLeavesOtherArrayTypesAlone. Only the targeted array method is intercepted")
    void testArrayTransformerLeavesOtherArrayTypesAlone() throws Exception {
        final byte[] payload = {1, 2, 3, 4};
        final ArrayFixture fixture = new ArrayFixture(BasicType.BYTE, payload);

        final ValueTransformer intMasker =
                ValueTransformers.intArrayTransformer(DataSize.ofBytes(1024), (value, length, context) -> {
                    throw new AssertionError("an int[] consumer must not see a byte[] array");
                });

        final byte[] output = sanitize(fixture.input, new TransformArrayRule(intMasker), "--target=none");

        assertThat(region(output, fixture.dataOffset, 4))
                .as("transformByteArray kept its default per-element identity body")
                .containsExactly(1, 2, 3, 4);
    }

    // ---------------------------------------------------------------------------------------------
    // combine
    // ---------------------------------------------------------------------------------------------

    @Test
    @DisplayName("testCombinePipesScalarValuesInOrder. Each transformer's output feeds the next")
    void testCombinePipesScalarValuesInOrder() {
        final ValueTransformer combined = ValueTransformers.combine(asList(
                ValueTransformers.intTransformer(value -> value + 1),
                ValueTransformers.intTransformer(value -> value * 2)));

        assertThat(combined.transformInt(1)).as("t2(t1(value)): (1 + 1) * 2").isEqualTo(4);
    }

    @Test
    @DisplayName("testCombineLeavesNonCombinedTypesIdentity. A combined transformer does not invent transforms")
    void testCombineLeavesNonCombinedTypesIdentity() {
        final ValueTransformer combined = ValueTransformers.combine(asList(
                ValueTransformers.intTransformer(value -> value + 1),
                ValueTransformers.intTransformer(value -> value * 2)));

        assertThat(combined.transformLong(5L))
                .as("no component touched transformLong, so the default identity runs")
                .isEqualTo(5L);
    }

    @Test
    @DisplayName("testCombineChainsArrayConsumersOverTheSameSlice. Both consumers see the same region")
    void testCombineChainsArrayConsumersOverTheSameSlice() {
        final AtomicInteger calls = new AtomicInteger();
        final ValueTransformer combined = ValueTransformers.combine(asList(
                ValueTransformers.byteArrayTransformer(DataSize.ofBytes(1024), (value, length, context) -> {
                    calls.incrementAndGet();
                    for (int i = 0; i < length; i++) {
                        value[i] = (byte) (value[i] + 1);
                    }
                }),
                ValueTransformers.byteArrayTransformer(DataSize.ofBytes(1024), (value, length, context) -> {
                    calls.incrementAndGet();
                    for (int i = 0; i < length; i++) {
                        value[i] = (byte) (value[i] + 1);
                    }
                })));

        final byte[] region = {1, 2, 3};
        combined.transformByteArray(region, 3, new PrimitiveArrayContext(ARRAY_OBJECT_ID, BasicType.BYTE, 3, 3));

        assertThat(calls.get())
                .as("once per component, both over the same slice")
                .isEqualTo(2);
        assertThat(region)
                .as("each element went through both consumers in order: 1 -> 2 -> 3, etc.")
                .containsExactly(3, 4, 5);
    }

    @Test
    @DisplayName("testCombineConcatenatesDescriptions. Each component names itself, in order")
    void testCombineConcatenatesDescriptions() {
        final List<ValueTransformer> components = asList(
                ValueTransformers.intTransformer("First", value -> value),
                ValueTransformers.intTransformer("Second", value -> value));

        assertThat(ValueTransformers.combine(components).describe())
                .as("component descriptions joined with ', '")
                .isEqualTo("First, Second");
        assertThat(ValueTransformers.combine("Mask", components).describe())
                .as("the desc argument prefixes the list")
                .isEqualTo("Mask, First, Second");
    }

    @Test
    @DisplayName("testCombineRejectsDisagreeingWholeArrayLimits. A name-checking transformer cannot be chunked")
    void testCombineRejectsDisagreeingWholeArrayLimits() {
        assertThatThrownBy(() -> ValueTransformers.combine(asList(
                        ValueTransformers.byteArrayTransformer(DataSize.ofBytes(1024), (value, length, context) -> {}),
                        ValueTransformers.intTransformer(value -> value))))
                .as("naming the conflicting values")
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("1024B")
                .hasMessageContaining("0B");
    }

    @Test
    @DisplayName("testCombineRejectsAnEmptyList. There must be something to combine")
    @SuppressWarnings("all")
    void testCombineRejectsAnEmptyList() {
        assertThatThrownBy(() -> ValueTransformers.combine(new ArrayList<>()))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> ValueTransformers.combine(null)).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    @DisplayName("testCombinedLimitEqualsTheComponents'. A combined transformer reports what its parts agreed on")
    void testCombinedLimitEqualsTheComponents() {
        final ValueTransformer combined = ValueTransformers.combine(asList(
                ValueTransformers.intTransformer(value -> value), ValueTransformers.intTransformer(value -> value)));

        assertThat(combined.maxMaterializedArraySize().toBytes()).isZero();
    }

    // ---------------------------------------------------------------------------------------------
    // Proxy behaviour
    // ---------------------------------------------------------------------------------------------

    @Test
    @DisplayName("testProxyBehavesLikeAnObject. equals, hashCode and toString are sane on a proxy")
    void testProxyBehavesLikeAnObject() {
        final ValueTransformer transformer = ValueTransformers.intTransformer(value -> value);
        final ValueTransformer twin = ValueTransformers.intTransformer(value -> value);

        assertThat(transformer.equals(transformer)).isTrue();
        assertThat(transformer.equals(twin)).isFalse();
        assertThat(transformer.equals(null)).isFalse();
        assertThat(transformer.hashCode()).isEqualTo(transformer.hashCode());
        assertThat(transformer.toString()).isNotEmpty();
    }

    // ---------------------------------------------------------------------------------------------
    // Fixtures and harness
    // ---------------------------------------------------------------------------------------------

    /**
     * A class with one field of each transformable type, so a single fixture can prove every arm of
     * the scalar switch reads and writes exactly the type's width. The OBJECT field last is
     * deliberate: a wrong width anywhere earlier mis-slots it and shows up as a corrupted id.
     */
    private static final class AllTypesFixture {

        static final int NUM_FIELDS = 9;

        final byte[] input;
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
            instance.u1(1);
            relative[1] = instance.offset();
            instance.u1(0x07);
            relative[2] = instance.offset();
            instance.u2('A');
            relative[3] = instance.offset();
            instance.u2(0x0102);
            relative[4] = instance.offset();
            instance.u4(0x11111111);
            relative[5] = instance.offset();
            instance.id(0x2222222233333333L);
            relative[6] = instance.offset();
            instance.u4(Float.floatToRawIntBits(1.5f) & 0xFFFFFFFFL);
            relative[7] = instance.offset();
            instance.id(Double.doubleToRawLongBits(2.5d));
            relative[8] = instance.offset();
            instance.id(0xBEEF);

            final int instanceOffset = body.instanceDump(ACCOUNT_OBJECT_ID, ACCOUNT_CLASS_ID, instance.toByteArray());
            final int base = hprof.record(HeapRecord.HEAP_DUMP_SEGMENT.getTag(), body);

            this.input = hprof.toByteArray();
            for (int i = 0; i < NUM_FIELDS; i++) {
                this.offsets[i] = base + instanceOffset + relative[i];
            }
        }

        int offsetOf(final String name) {
            return offsets[asList(NAMES).indexOf(name)];
        }
    }

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
        final ByteArrayOutputStream outputBytes = new ByteArrayOutputStream();
        final HeapDumpSanitizer sanitizer = new HeapDumpSanitizer();
        sanitizer.setInputStream(new ByteArrayInputStream(input));
        sanitizer.setOutputStream(outputBytes);
        sanitizer.setProgressMonitor(numBytesProcessed -> {
            // no op
        });
        sanitizer.setSanitizeCommand(command);
        sanitizer.sanitize();

        final byte[] output = outputBytes.toByteArray();
        assertThat(output.length)
                .as("transformation must preserve the length of the dump")
                .isEqualTo(input.length);
        return output;
    }

    private int[] region(final byte[] bytes, final int offset, final int length) {
        final int[] unsigned = new int[length];
        for (int i = 0; i < length; i++) {
            unsigned[i] = bytes[offset + i] & 0xFF;
        }
        return unsigned;
    }

    private static byte[] withRegionReplaced(final byte[] input, final int offset, final byte[] replacement) {
        final byte[] expected = input.clone();
        System.arraycopy(replacement, 0, expected, offset, replacement.length);
        return expected;
    }
}
