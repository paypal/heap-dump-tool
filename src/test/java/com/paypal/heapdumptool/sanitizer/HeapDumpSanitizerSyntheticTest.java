package com.paypal.heapdumptool.sanitizer;

import com.paypal.heapdumptool.fixture.AliasedStringFixture;
import com.paypal.heapdumptool.fixture.AllPrimitivesFixture;
import com.paypal.heapdumptool.fixture.Hprof;
import com.paypal.heapdumptool.fixture.StringFixture;
import com.paypal.heapdumptool.utils.DataSize;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import picocli.CommandLine;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static com.paypal.heapdumptool.fixture.AllPrimitivesFixture.ALL_PRIMITIVES;
import static com.paypal.heapdumptool.fixture.AllPrimitivesFixture.ARRAY_LENGTH;
import static com.paypal.heapdumptool.fixture.AllPrimitivesFixture.UNSANITIZED_BYTE;
import static com.paypal.heapdumptool.fixture.Hprof.ID_SIZE;
import static java.nio.charset.StandardCharsets.US_ASCII;
import static java.util.Arrays.asList;
import static org.apache.commons.lang3.ArrayUtils.EMPTY_STRING_ARRAY;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;

/**
 * Byte-exact tests over synthetic in-memory hprof fixtures.
 *
 * <p>Unlike {@link HeapDumpSanitizerTest}, nothing here dumps a real heap: every fixture is a
 * handful of bytes built by {@link Hprof}, so the whole class runs in milliseconds and each
 * assertion can name the exact output byte it cares about. Sanitization never changes the length of
 * a region -- {@code skipInput(n)} is always followed by writing exactly {@code n} bytes -- so an
 * offset recorded while building the input is also valid in the output.</p>
 */
class HeapDumpSanitizerSyntheticTest {

    // ---------------------------------------------------------------------------------------------
    // Finding 1: a replacement whose big-endian encoding contains 0xFF
    // ---------------------------------------------------------------------------------------------

    @Test
    @DisplayName("testByteReplacementOfMinusOne. 0xFF is a legal replacement byte, not an end-of-stream marker")
    void testByteReplacementOfMinusOne() throws Exception {
        final Hprof body = new Hprof();
        final int dataOffset = body.primitiveArrayDump(0x1000, BasicType.BYTE, new byte[]{1, 2, 3, 4});

        final Hprof input = new Hprof().header();
        final int base = input.record(HeapRecord.HEAP_DUMP_SEGMENT.getTag(), body);

        final byte[] output = sanitize(input.toByteArray(), "--replacement=byte=-1");

        assertThat(region(output, base + dataOffset, 4))
                .containsExactly(0xFF, 0xFF, 0xFF, 0xFF);
    }

    @Test
    @DisplayName("testLongReplacementOfMinusOne. An all-0xFF long replacement is tiled, not rejected")
    void testLongReplacementOfMinusOne() throws Exception {
        final Hprof body = new Hprof();
        final int dataOffset = body.primitiveArrayDump(0x1000, BasicType.LONG, new byte[3 * Long.BYTES]);

        final Hprof input = new Hprof().header();
        final int base = input.record(HeapRecord.HEAP_DUMP_SEGMENT.getTag(), body);

        final byte[] output = sanitize(input.toByteArray(), "--replacement=long=-1");

        final int[] expected = new int[3 * Long.BYTES];
        Arrays.fill(expected, 0xFF);
        assertThat(region(output, base + dataOffset, expected.length))
                .containsExactly(expected);
    }

    @Test
    @DisplayName("testTilingStaysAlignedAcrossManyBufferWrites. A region far larger than one internal buffer stays tile-aligned")
    void testTilingStaysAlignedAcrossManyBufferWrites() throws Exception {
        final int numElements = 5000;
        final Hprof body = new Hprof();
        final int dataOffset = body.primitiveArrayDump(0x1000, BasicType.SHORT, new byte[numElements * Short.BYTES]);

        final Hprof input = new Hprof().header();
        final int base = input.record(HeapRecord.HEAP_DUMP_SEGMENT.getTag(), body);

        // -2 encodes as 0xFFFE: contains 0xFF, and is asymmetric so a misalignment by one byte shows
        final byte[] output = sanitize(input.toByteArray(), "--replacement=short=-2");

        final int[] expected = new int[numElements * Short.BYTES];
        for (int i = 0; i < numElements; i++) {
            expected[i * Short.BYTES] = 0xFF;
            expected[i * Short.BYTES + 1] = 0xFE;
        }
        assertThat(region(output, base + dataOffset, expected.length))
                .containsExactly(expected);
    }

    // ---------------------------------------------------------------------------------------------
    // Findings 2 and 3: String.coder
    // ---------------------------------------------------------------------------------------------

    @Test
    @DisplayName("testCoderPipedThroughWhenForceMatchDisabled. -f=false must not touch String.coder")
    void testCoderPipedThroughWhenForceMatchDisabled() throws Exception {
        final StringFixture fixture = new StringFixture(1);

        final byte[] output = sanitize(fixture.input, "--force-string-coder-match=false");

        assertThat(output[fixture.coderOffset])
                .as("String.coder must be piped through unchanged when -f=false")
                .isEqualTo((byte) 1);
        assertThat(region(output, fixture.valueIdOffset, ID_SIZE))
                .as("object references are never sanitized")
                .containsExactly(0, 0, 0, 0, 0, 0, 0x12, 0x34);
        assertThat(region(output, fixture.hashOffset, Integer.BYTES))
                .as("exempting coder must not exempt String's other primitive fields")
                .containsExactly(0, 0, 0, 0);
    }

    @Test
    @DisplayName("testCoderForcedToLatin1WhenByteArraysAreSanitized. -f=true plus a replaced byte[] means coder 0")
    void testCoderForcedToLatin1WhenByteArraysAreSanitized() throws Exception {
        final StringFixture fixture = new StringFixture(1);

        final byte[] output = sanitize(fixture.input, "--force-string-coder-match=true");

        assertThat(output[fixture.coderOffset])
                .as("the backing byte[] is replaced with single-byte values, so LATIN1")
                .isEqualTo((byte) 0);
        assertThat(region(output, fixture.hashOffset, Integer.BYTES))
                .as("exempting coder must not exempt String's other primitive fields")
                .containsExactly(0, 0, 0, 0);
    }

    @Test
    @DisplayName("testCoderPipedThroughWhenByteArraysArePreserved. -f=true must not force coder 0 over a surviving UTF16 array")
    void testCoderPipedThroughWhenByteArraysArePreserved() throws Exception {
        final StringFixture fixture = new StringFixture(1);

        final byte[] output = sanitize(fixture.input,
                "--force-string-coder-match=true", "--target=all,-byte-arrays");

        assertThat(output[fixture.coderOffset])
                .as("the original UTF16 payload survives, so forcing LATIN1 would produce mojibake")
                .isEqualTo((byte) 1);
    }

    @Test
    @DisplayName("testCoderPipedThroughUnderSanitizeAllFalse. --target=none leaves String.coder alone")
    void testCoderPipedThroughUnderSanitizeAllFalse() throws Exception {
        final StringFixture fixture = new StringFixture(1);

        final byte[] output = sanitize(fixture.input,
                "--force-string-coder-match=true", "--target=none");

        assertThat(output[fixture.coderOffset]).isEqualTo((byte) 1);
    }

    @Test
    @DisplayName("testCoderPipedThroughWhenTheStringIsExcluded. An -e preserved UTF16 array must keep its coder")
    void testCoderPipedThroughWhenTheStringIsExcluded() throws Exception {
        final long holderClassId = 700;
        final long stringClassId = 701;
        final long stringObjectId = 0x7100;
        final long valueArrayId = 0x7200;
        // "hi" as UTF16-BE, i.e. a genuine coder==1 payload
        final byte[] utf16 = {0, 'h', 0, 'i'};

        final Hprof input = new Hprof().header();
        input.stringInUtf8(40, "com.example.Holder");
        input.stringInUtf8(41, String.class.getName());
        input.stringInUtf8(42, "secret");
        input.stringInUtf8(43, "value");
        input.stringInUtf8(44, "hash");
        input.stringInUtf8(45, "coder");
        input.loadClass(1, holderClassId, 40);
        input.loadClass(2, stringClassId, 41);

        final Hprof body = new Hprof();
        body.classDump(holderClassId, 0, new int[]{42}, new BasicType[]{BasicType.OBJECT});
        body.classDump(stringClassId, 0, new int[]{43, 44, 45},
                new BasicType[]{BasicType.OBJECT, BasicType.INT, BasicType.BYTE});

        // the holder's excluded field points at the String, which marks its backing array as preserved
        final Hprof holder = new Hprof();
        holder.id(stringObjectId);
        body.instanceDump(0x7000, holderClassId, holder.toByteArray());

        final Hprof string = new Hprof();
        string.id(valueArrayId);
        string.u4(0x0BADC0DE);
        final int relativeCoderOffset = string.offset();
        string.u1(1);
        final int instanceOffset = body.instanceDump(stringObjectId, stringClassId, string.toByteArray());

        final int dataOffset = body.primitiveArrayDump(valueArrayId, BasicType.BYTE, utf16);
        final int base = input.record(HeapRecord.HEAP_DUMP_SEGMENT.getTag(), body);

        // -f defaults to true and byte arrays are sanitized by default, but -e preserves THIS array
        final byte[] output = sanitize(input.toByteArray(),
                "--force-string-coder-match=true",
                "--exclude-string-fields=" + AliasedStringFixture.EXCLUDE_TARGET);

        assertThat(region(output, base + dataOffset, utf16.length))
                .as("the -e excluded backing array must be preserved")
                .containsExactly(0, 'h', 0, 'i');
        assertThat(output[base + instanceOffset + relativeCoderOffset])
                .as("forcing LATIN1 over a surviving UTF16 array is mojibake at double length")
                .isEqualTo((byte) 1);
    }

    // ---------------------------------------------------------------------------------------------
    // -e / -f independence
    // ---------------------------------------------------------------------------------------------

    /**
     * {@code -e} selects which fields to preserve and {@code -f} controls how {@code String.coder}
     * is rewritten. They are logically independent, so {@code -f=false} must not silently disable
     * {@code -e}. The step they used to share is the instance-id -> backing-array-id bridge: only
     * the String field walk learns which {@code byte[]} an excluded String points at, and that walk
     * used to be reachable only when {@code -f=true}. Without the bridge the excluded array is
     * sanitized like any other and the value the user asked to keep is destroyed.
     */
    @Test
    @DisplayName("testExcludedStringSurvivesWhenForceMatchDisabled. -e must be honored under -f=false")
    void testExcludedStringSurvivesWhenForceMatchDisabled() throws Exception {
        final AliasedStringFixture fixture = new AliasedStringFixture();

        final byte[] output = sanitize(fixture.input,
                "--force-string-coder-match=false",
                "--exclude-string-fields=" + AliasedStringFixture.EXCLUDE_TARGET);

        assertThat(region(output, fixture.arrayOffset, AliasedStringFixture.UTF16.length))
                .as("the -e excluded backing array must be preserved regardless of -f")
                .containsExactly(0, 'h', 0, 'i');
        assertThat(output[fixture.excludedCoderOffset])
                .as("-f=false must still pipe String.coder through unchanged")
                .isEqualTo((byte) 1);
    }

    /**
     * The array-scoped half of the same split. {@code -e} preservation is keyed by the backing
     * array's id, but the coder decision used to be keyed by the String instance's id. On JDK 9+
     * two Strings can share one backing {@code byte[]} -- {@code new String(String)},
     * {@code substring(0)} and other zero-copy paths all alias it -- so a non-excluded String can
     * sit over an array that was preserved on another String's behalf. Forcing its coder to LATIN1
     * then reinterprets each surviving UTF-16 code unit as two characters: mojibake at double
     * length, in a String whose bytes were in fact preserved.
     */
    @Test
    @DisplayName("testAliasedBackingArrayKeepsItsCoder. A non-excluded String aliasing a preserved array keeps coder 1")
    void testAliasedBackingArrayKeepsItsCoder() throws Exception {
        final AliasedStringFixture fixture = new AliasedStringFixture();

        final byte[] output = sanitize(fixture.input,
                "--force-string-coder-match=true",
                "--exclude-string-fields=" + AliasedStringFixture.EXCLUDE_TARGET);

        assertThat(region(output, fixture.arrayOffset, AliasedStringFixture.UTF16.length))
                .as("the -e excluded backing array must be preserved")
                .containsExactly(0, 'h', 0, 'i');
        assertThat(output[fixture.excludedCoderOffset])
                .as("the excluded String's own coder must survive")
                .isEqualTo((byte) 1);
        assertThat(output[fixture.aliasCoderOffset])
                .as("the aliasing String shares the surviving UTF16 array, so LATIN1 would be mojibake")
                .isEqualTo((byte) 1);
    }

    /**
     * {@code -e} names String-typed fields, but the declared type was never checked: the exclusion
     * arm always consumed one object id for the field while the ledger subtracted the field's real
     * width. Point {@code -e} at a 1-byte field and the walk over-reads by 7, every following field
     * is mis-sliced, the sub-record boundary is lost, and the run aborts on a garbage tag leaving a
     * truncated output file.
     */
    @Test
    @DisplayName("testExcludeOnANonReferenceFieldKeepsTheStreamAligned. -e on a primitive field must not over-read")
    void testExcludeOnANonReferenceFieldKeepsTheStreamAligned() throws Exception {
        final long classId = 1000;
        final byte[] trailing = {0x5A, 0x5A, 0x5A, 0x5A};

        final Hprof input = new Hprof().header();
        input.stringInUtf8(70, "com.example.Prim");
        input.stringInUtf8(71, "marker");
        input.stringInUtf8(72, "payload");
        input.loadClass(1, classId, 70);

        final Hprof body = new Hprof();
        // marker is a 1-byte field, payload an 8-byte one: an id-width read of marker eats 7 bytes
        // of payload, so a drifted cursor shows up in both regions
        body.classDump(classId, 0, new int[]{71, 72},
                new BasicType[]{BasicType.BYTE, BasicType.LONG});

        final Hprof instance = new Hprof();
        final int relativeMarkerOffset = instance.offset();
        instance.fill(UNSANITIZED_BYTE, 1);
        final int relativePayloadOffset = instance.offset();
        instance.fill(UNSANITIZED_BYTE, Long.BYTES);
        final int instanceOffset = body.instanceDump(0xA000, classId, instance.toByteArray());

        // a sub-record AFTER the instance: if the boundary is lost, this is what gets eaten
        final int trailingOffset = body.primitiveArrayDump(0xA100, BasicType.BYTE, trailing);
        final int base = input.record(HeapRecord.HEAP_DUMP_SEGMENT.getTag(), body);

        // byte FIELDS in scope, byte ARRAYS out of scope, so each region below has a distinct
        // expected value and a drifted cursor cannot coincidentally satisfy them
        final byte[][] output = new byte[1][];
        assertThatCode(() -> output[0] = sanitize(input.toByteArray(),
                "--target=byte-fields",
                "--exclude-string-fields=com.example.Prim#marker"))
                .as("a non-reference -e target must not desynchronize the stream")
                .doesNotThrowAnyException();

        assertThat(region(output[0], base + instanceOffset + relativeMarkerOffset, 1))
                .as("a non-reference -e target is not a String value, so it is sanitized normally")
                .containsExactly(0x2A);
        assertThat(region(output[0], base + instanceOffset + relativePayloadOffset, Long.BYTES))
                .as("the long field is out of scope and must be piped through intact")
                .containsExactly(unsanitized(Long.BYTES));
        assertThat(region(output[0], base + trailingOffset, trailing.length))
                .as("the following sub-record must still be parsed at its own boundary")
                .containsExactly(unsanitized(trailing.length));
    }

    // ---------------------------------------------------------------------------------------------
    // Finding 4: field-layout lookup
    // ---------------------------------------------------------------------------------------------

    @Test
    @DisplayName("testUnknownClassLayoutIsPipedThrough. A LOAD_CLASS with no CLASS DUMP must not crash or guess a layout")
    void testUnknownClassLayoutIsPipedThrough() throws Exception {
        assertUnknownLayoutIsPipedThrough("com.example.NoClassDump");
    }

    /**
     * The String path is the one where the missing-layout guard is load-bearing: a non-String class
     * with no layout happens to survive by accident, because its field walk yields an empty stream
     * and the body is piped verbatim. {@code copyStringsInstanceFields} instead dereferences the
     * layout directly, so without the guard this throws.
     */
    @Test
    @DisplayName("testUnknownLayoutForStringIsPipedThrough. java.lang.String with no CLASS DUMP must not crash under -f=true")
    void testUnknownLayoutForStringIsPipedThrough() throws Exception {
        assertUnknownLayoutIsPipedThrough(String.class.getName());
    }

    private void assertUnknownLayoutIsPipedThrough(final String className) throws Exception {
        final long classObjectId = 300;
        final byte[] payload = {0, 0, 0, 0, 0, 0, 0x0B, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};

        final Hprof input = new Hprof().header();
        input.stringInUtf8(10, className);
        input.loadClass(1, classObjectId, 10);

        final Hprof body = new Hprof();
        final int payloadOffset = body.instanceDump(0x2000, classObjectId, payload);
        final int base = input.record(HeapRecord.HEAP_DUMP_SEGMENT.getTag(), body);

        final byte[][] output = new byte[1][];
        assertThatCode(() -> output[0] = sanitize(input.toByteArray(), "--force-string-coder-match=true"))
                .doesNotThrowAnyException();

        assertThat(Arrays.copyOfRange(output[0], base + payloadOffset, base + payloadOffset + payload.length))
                .as("an unknown layout must be piped through, never guessed")
                .containsExactly(payload);
    }

    // ---------------------------------------------------------------------------------------------
    // Hierarchy field order
    // ---------------------------------------------------------------------------------------------

    @Test
    @DisplayName("testSubclassFieldsPrecedeSuperclassFieldsInTheInstanceBody. Hierarchy walk order must be subclass first")
    void testSubclassFieldsPrecedeSuperclassFieldsInTheInstanceBody() throws Exception {
        final long superClassId = 800;
        final long subClassId = 801;

        final Hprof input = new Hprof().header();
        input.stringInUtf8(50, "com.example.OrderBase");
        input.stringInUtf8(51, "com.example.OrderDerived");
        input.stringInUtf8(52, "inheritedLong");
        input.stringInUtf8(53, "declaredRef");
        input.loadClass(1, superClassId, 50);
        input.loadClass(2, subClassId, 51);

        final Hprof body = new Hprof();
        body.classDump(superClassId, 0, new int[]{52}, new BasicType[]{BasicType.LONG});
        body.classDump(subClassId, superClassId, new int[]{53}, new BasicType[]{BasicType.OBJECT});

        /*
         * HPROF lays out subclass fields first: slot 0 is OrderDerived.declaredRef (an OBJECT id,
         * never overwritten) and slot 1 is OrderBase.inheritedLong (wiped to the long replacement,
         * 0 by default). Swapping the walk order swaps both outcomes, which is why both slots carry
         * distinctive non-zero bytes.
         */
        final Hprof instance = new Hprof();
        instance.id(0xCAFEBABEL);
        instance.id(0x0BADC0DE0BADC0DEL);
        final byte[] payload = instance.toByteArray();

        final int payloadOffset = body.instanceDump(0x8000, subClassId, payload);
        final int base = input.record(HeapRecord.HEAP_DUMP_SEGMENT.getTag(), body);

        final byte[] output = sanitize(input.toByteArray());

        assertThat(region(output, base + payloadOffset, Long.BYTES))
                .as("slot 0 is the subclass OBJECT reference and must be preserved")
                .containsExactly(0, 0, 0, 0, 0xCA, 0xFE, 0xBA, 0xBE);
        assertThat(region(output, base + payloadOffset + Long.BYTES, Long.BYTES))
                .as("slot 1 is the superclass long and must be wiped")
                .containsExactly(0, 0, 0, 0, 0, 0, 0, 0);
    }

    /**
     * The hierarchy walk is deliberately not memoized per class object id. A CLASS DUMP for the
     * superclass can appear after an instance of the subclass, so the first instance sees a shorter
     * chain than later ones; caching that first answer would leave every later instance's inherited
     * fields unsanitized and desynchronize the reader.
     */
    @Test
    @DisplayName("testSuperClassDumpSeenAfterAnInstanceStillAppliesToLaterInstances. A late CLASS DUMP must not be masked by an earlier walk")
    void testSuperClassDumpSeenAfterAnInstanceStillAppliesToLaterInstances() throws Exception {
        final long superClassId = 900;
        final long subClassId = 901;

        final Hprof input = new Hprof().header();
        input.stringInUtf8(60, "com.example.LateBase");
        input.stringInUtf8(61, "com.example.LateDerived");
        input.stringInUtf8(62, "inheritedLong");
        input.stringInUtf8(63, "declaredLong");
        input.loadClass(1, superClassId, 60);
        input.loadClass(2, subClassId, 61);

        final Hprof body = new Hprof();
        // only the subclass layout is known at this point
        body.classDump(subClassId, superClassId, new int[]{63}, new BasicType[]{BasicType.LONG});

        final Hprof early = new Hprof();
        early.id(0x1111111111111111L); // declaredLong, wiped
        final int earlyOffset = body.instanceDump(0x9000, subClassId, early.toByteArray());

        // the superclass layout arrives only now, between the two instances
        body.classDump(superClassId, 0, new int[]{62}, new BasicType[]{BasicType.LONG});

        final Hprof late = new Hprof();
        late.id(0x2222222222222222L); // declaredLong
        late.id(0x3333333333333333L); // inheritedLong, only reachable via the late superclass layout
        final int lateOffset = body.instanceDump(0x9001, subClassId, late.toByteArray());

        final int base = input.record(HeapRecord.HEAP_DUMP_SEGMENT.getTag(), body);

        final byte[] output = sanitize(input.toByteArray());

        assertThat(region(output, base + earlyOffset, Long.BYTES))
                .as("the early instance's own field is still wiped")
                .containsExactly(0, 0, 0, 0, 0, 0, 0, 0);
        assertThat(region(output, base + lateOffset, Long.BYTES))
                .as("the later instance's declared field is wiped")
                .containsExactly(0, 0, 0, 0, 0, 0, 0, 0);
        assertThat(region(output, base + lateOffset + Long.BYTES, Long.BYTES))
                .as("the inherited field must be wiped too: the hierarchy is re-walked, not cached")
                .containsExactly(0, 0, 0, 0, 0, 0, 0, 0);
    }

    @Test
    @DisplayName("testDuplicateClassNamesDoNotShareALayout. Two classes with the same name must keep their own field layouts")
    void testDuplicateClassNamesDoNotShareALayout() throws Exception {
        final Hprof input = new Hprof().header();
        input.stringInUtf8(10, "com.example.Dup");
        input.stringInUtf8(11, "longField");
        input.stringInUtf8(12, "ref");
        input.loadClass(1, 100, 10);
        input.loadClass(2, 200, 10);

        final Hprof body = new Hprof();
        body.classDump(100, 0, new int[]{11}, new BasicType[]{BasicType.LONG});
        body.classDump(200, 0, new int[]{12}, new BasicType[]{BasicType.OBJECT});

        // an object reference: mis-slotting it as the LONG field of the other class would zero it
        final byte[] payload = {0, 0, 0, 0, (byte) 0xCA, (byte) 0xFE, (byte) 0xBA, (byte) 0xBE};
        final int payloadOffset = body.instanceDump(0x3000, 200, payload);
        final int base = input.record(HeapRecord.HEAP_DUMP_SEGMENT.getTag(), body);

        final byte[] output = sanitize(input.toByteArray());

        assertThat(Arrays.copyOfRange(output, base + payloadOffset, base + payloadOffset + payload.length))
                .as("the OBJECT field of the second class must survive")
                .containsExactly(payload);
    }

    @Test
    @DisplayName("testExcludeStringFieldIsInheritedThroughTheClassHierarchy. A superclass exclusion still applies to a subclass instance")
    void testExcludeStringFieldIsInheritedThroughTheClassHierarchy() throws Exception {
        final long superClassId = 600;
        final long subClassId = 601;
        final long stringClassId = 602;
        final long secretObjectId = 0x6100;
        final long secretArrayId = 0x6200;
        final byte[] secret = "keep-me".getBytes(US_ASCII);

        final Hprof input = new Hprof().header();
        input.stringInUtf8(30, "com.example.Base");
        input.stringInUtf8(31, "com.example.Derived");
        input.stringInUtf8(32, String.class.getName());
        input.stringInUtf8(33, "secret");
        input.stringInUtf8(34, "value");
        input.stringInUtf8(35, "coder");
        input.loadClass(1, superClassId, 30);
        input.loadClass(2, subClassId, 31);
        input.loadClass(3, stringClassId, 32);

        final Hprof body = new Hprof();
        // Base declares the excluded String field; Derived declares nothing and inherits it
        body.classDump(superClassId, 0, new int[]{33}, new BasicType[]{BasicType.OBJECT});
        body.classDump(subClassId, superClassId, new int[]{}, new BasicType[]{});
        body.classDump(stringClassId, 0, new int[]{34, 35},
                new BasicType[]{BasicType.OBJECT, BasicType.BYTE});

        // a Derived instance whose inherited secret field points at the String
        final Hprof derived = new Hprof();
        derived.id(secretObjectId);
        body.instanceDump(0x6000, subClassId, derived.toByteArray());

        // the String instance: value -> the backing byte[], coder 0
        final Hprof string = new Hprof();
        string.id(secretArrayId);
        string.u1(0);
        body.instanceDump(secretObjectId, stringClassId, string.toByteArray());

        final int dataOffset = body.primitiveArrayDump(secretArrayId, BasicType.BYTE, secret);
        final int base = input.record(HeapRecord.HEAP_DUMP_SEGMENT.getTag(), body);

        final byte[] output = sanitize(input.toByteArray(),
                "--exclude-string-fields=com.example.Base#secret");

        assertThat(Arrays.copyOfRange(output, base + dataOffset, base + dataOffset + secret.length))
                .as("an exclusion declared on the superclass must reach the subclass instance")
                .containsExactly(secret);
    }

    // ---------------------------------------------------------------------------------------------
    // Per-type scope flags: fast mirrors of the end-to-end tests in HeapDumpSanitizerTest
    // ---------------------------------------------------------------------------------------------

    @Test
    @DisplayName("testDefaultSanitizesEveryPrimitiveFieldAndArray. No scope flag means all 8 fields and all 8 arrays")
    void testDefaultSanitizesEveryPrimitiveFieldAndArray() throws Exception {
        final AllPrimitivesFixture fixture = new AllPrimitivesFixture();

        final byte[] output = sanitize(fixture.input);

        for (final BasicType type : ALL_PRIMITIVES) {
            assertFieldSanitized(output, fixture, type);
            assertArraySanitized(output, fixture, type);
        }
    }

    @Test
    @DisplayName("testSanitizeAllFalsePreservesEveryFieldAndArray. --target=none sanitizes nothing")
    void testSanitizeAllFalsePreservesEveryFieldAndArray() throws Exception {
        final AllPrimitivesFixture fixture = new AllPrimitivesFixture();

        final byte[] output = sanitize(fixture.input, "--target=none");

        for (final BasicType type : ALL_PRIMITIVES) {
            assertFieldPreserved(output, fixture, type);
            assertArrayPreserved(output, fixture, type);
        }
    }

    @Test
    @DisplayName("testEachArrayFlagAffectsOnlyItsOwnArrayType. --target=X-arrays wipes X[] and nothing else")
    void testEachArrayFlagAffectsOnlyItsOwnArrayType() throws Exception {
        for (final BasicType selected : ALL_PRIMITIVES) {
            final AllPrimitivesFixture fixture = new AllPrimitivesFixture();

            final byte[] output = sanitize(fixture.input,
                    arrayTarget(selected));

            for (final BasicType type : ALL_PRIMITIVES) {
                if (type == selected) {
                    assertArraySanitized(output, fixture, type);
                } else {
                    assertArrayPreserved(output, fixture, type);
                }
                // an array flag never touches non-array fields
                assertFieldPreserved(output, fixture, type);
            }
        }
    }

    @Test
    @DisplayName("testEachFieldFlagAffectsOnlyItsOwnFieldType. --target=X-fields wipes X fields and nothing else")
    void testEachFieldFlagAffectsOnlyItsOwnFieldType() throws Exception {
        for (final BasicType selected : ALL_PRIMITIVES) {
            final AllPrimitivesFixture fixture = new AllPrimitivesFixture();

            final byte[] output = sanitize(fixture.input,
                    fieldTarget(selected));

            for (final BasicType type : ALL_PRIMITIVES) {
                if (type == selected) {
                    assertFieldSanitized(output, fixture, type);
                } else {
                    assertFieldPreserved(output, fixture, type);
                }
                // a field flag never touches array contents
                assertArrayPreserved(output, fixture, type);
            }
        }
    }

    /**
     * The FIELD flag and the ARRAY flag of one type are independent: opting int fields out must
     * leave {@code int[]} contents in scope. Mirrors
     * {@code testPerTypeFieldOptOutIsHonored} end to end.
     */
    @Test
    @DisplayName("testFieldOptOutLeavesTheSameTypesArrayInScope. --target=all,-int-fields keeps int arrays only")
    void testFieldOptOutLeavesTheSameTypesArrayInScope() throws Exception {
        final AllPrimitivesFixture fixture = new AllPrimitivesFixture();

        final byte[] output = sanitize(fixture.input, "--target=all,-int-fields");

        assertFieldPreserved(output, fixture, BasicType.INT);
        assertArraySanitized(output, fixture, BasicType.INT);

        for (final BasicType type : ALL_PRIMITIVES) {
            if (type != BasicType.INT) {
                assertFieldSanitized(output, fixture, type);
            }
            assertArraySanitized(output, fixture, type);
        }
    }

    @Test
    @DisplayName("testOrderMattersAllAfterSpecific. all last in --target overwrites an earlier opt-out")
    void testOrderMattersAllAfterSpecific() throws Exception {
        final AllPrimitivesFixture fixture = new AllPrimitivesFixture();

        final byte[] output = sanitize(fixture.input,
                "--target=int-arrays,all");

        assertArraySanitized(output, fixture, BasicType.INT);
    }

    @Test
    @DisplayName("testOrderMattersSpecificAfterAll. A later per-type flag in --target overrides all")
    void testOrderMattersSpecificAfterAll() throws Exception {
        final AllPrimitivesFixture fixture = new AllPrimitivesFixture();

        final byte[] output = sanitize(fixture.input,
                "--target=all,-int-arrays");

        assertArrayPreserved(output, fixture, BasicType.INT);
        // every other array type is still in scope
        assertArraySanitized(output, fixture, BasicType.SHORT);
        assertArraySanitized(output, fixture, BasicType.LONG);
    }

    /**
     * The legacy migration contract: {@code -s=true} means exactly
     * {@code --target=byte-arrays,char-arrays}, so
     * byte[] and char[] are wiped WHILE the other six array types and every non-array field
     * survive. Mirrors {@code testLegacyByteCharArraysOnlyStillWorks} end to end.
     */
    @Test
    @DisplayName("testLegacyByteCharArraysOnlyScopesToThoseTwoArrays. -s=true wipes byte[] and char[] only")
    void testLegacyByteCharArraysOnlyScopesToThoseTwoArrays() throws Exception {
        final AllPrimitivesFixture fixture = new AllPrimitivesFixture();

        final byte[] output = sanitize(fixture.input, "-s=true");

        assertArraySanitized(output, fixture, BasicType.BYTE);
        assertArraySanitized(output, fixture, BasicType.CHAR);

        for (final BasicType type : ALL_PRIMITIVES) {
            if (type != BasicType.BYTE && type != BasicType.CHAR) {
                assertArrayPreserved(output, fixture, type);
            }
            assertFieldPreserved(output, fixture, type);
        }
    }

    @Test
    @DisplayName("testLegacyByteCharArraysOnlyFalseSanitizesEverything. -s=false means --target=all")
    void testLegacyByteCharArraysOnlyFalseSanitizesEverything() throws Exception {
        final AllPrimitivesFixture fixture = new AllPrimitivesFixture();

        // The leading --target=none is what makes this test discriminate: all-16-sanitized is
        // the DEFAULT baseline, so "-s=false" alone would pass even if it were a complete no-op.
        // Turning everything off first means -s=false has to turn everything back on, in order.
        final byte[] output = sanitize(fixture.input, "--target=none", "-s=false");

        for (final BasicType type : ALL_PRIMITIVES) {
            assertFieldSanitized(output, fixture, type);
            assertArraySanitized(output, fixture, type);
        }
    }

    @Test
    @DisplayName("testIntArrayReplacementValueIsTiled. --replacement=int=<value> fills int[] with that value")
    void testIntArrayReplacementValueIsTiled() throws Exception {
        final AllPrimitivesFixture fixture = new AllPrimitivesFixture();

        // 0x11223344: all four bytes differ from each other and from every default replacement byte,
        // so this pins WHICH type's replacement was tiled. A value like 0x2A2A2A2A cannot: it is
        // byte-identical to four copies of the byte default, so fetching replacement(BYTE) instead of
        // replacement(INT) would go undetected.
        final byte[] output = sanitize(fixture.input,
                "--target=int-arrays",
                "--replacement=int=" + 0x11223344);

        final int[] expected = new int[ARRAY_LENGTH * Integer.BYTES];
        for (int i = 0; i < expected.length; i += Integer.BYTES) {
            expected[i] = 0x11;
            expected[i + 1] = 0x22;
            expected[i + 2] = 0x33;
            expected[i + 3] = 0x44;
        }
        assertThat(region(output, fixture.arrayOffset(BasicType.INT), expected.length))
                .as("int[] must be tiled with the requested replacement")
                .containsExactly(expected);

        // the int FIELD is out of scope, so the replacement value must not appear there
        assertFieldPreserved(output, fixture, BasicType.INT);
    }

    @Test
    @DisplayName("testDefaultReplacementValuePerType. Each type's default replacement bytes are as documented")
    void testDefaultReplacementValuePerType() throws Exception {
        final AllPrimitivesFixture fixture = new AllPrimitivesFixture();

        final byte[] output = sanitize(fixture.input);

        // byte=42 (0x2A), char='*' (0x002A), everything else zero-valued
        assertThat(region(output, fixture.arrayOffset(BasicType.BYTE), 4))
                .containsExactly(0x2A, 0x2A, 0x2A, 0x2A);
        assertThat(region(output, fixture.arrayOffset(BasicType.CHAR), 8))
                .containsExactly(0x00, 0x2A, 0x00, 0x2A, 0x00, 0x2A, 0x00, 0x2A);
        assertThat(region(output, fixture.arrayOffset(BasicType.SHORT), 8))
                .containsExactly(0, 0, 0, 0, 0, 0, 0, 0);
        assertThat(region(output, fixture.arrayOffset(BasicType.BOOLEAN), 4))
                .containsExactly(0, 0, 0, 0);
    }

    // ---------------------------------------------------------------------------------------------
    // helpers
    // ---------------------------------------------------------------------------------------------

    private static String fieldTarget(final BasicType type) {
        return "--target=" + type.name().toLowerCase() + "-fields";
    }

    private static String arrayTarget(final BasicType type) {
        return "--target=" + type.name().toLowerCase() + "-arrays";
    }

    /**
     * The documented default replacement bytes, spelled out rather than read back from
     * {@link PrimitiveReplacement}, so a change to the defaults is a test failure.
     */
    private static int[] defaultReplacementTile(final BasicType type) {
        switch (type) {
            case BYTE:
                return new int[]{42};
            case BOOLEAN:
                return new int[]{0};
            case CHAR:
                return new int[]{0x00, 0x2A};
            case SHORT:
                return new int[]{0, 0};
            case INT:
            case FLOAT:
                return new int[]{0, 0, 0, 0};
            case LONG:
            case DOUBLE:
                return new int[]{0, 0, 0, 0, 0, 0, 0, 0};
            default:
                throw new IllegalArgumentException("" + type);
        }
    }

    private static int[] tile(final BasicType type, final int numElements) {
        final int[] unit = defaultReplacementTile(type);
        final int[] expected = new int[unit.length * numElements];
        for (int i = 0; i < numElements; i++) {
            System.arraycopy(unit, 0, expected, i * unit.length, unit.length);
        }
        return expected;
    }

    private static int[] unsanitized(final int numBytes) {
        final int[] expected = new int[numBytes];
        Arrays.fill(expected, UNSANITIZED_BYTE);
        return expected;
    }

    private void assertFieldSanitized(final byte[] output,
                                      final AllPrimitivesFixture fixture,
                                      final BasicType type) {
        final int width = type.getValueSize(ID_SIZE);
        assertThat(region(output, fixture.fieldOffset(type), width))
                .as("field of type " + type + " must be sanitized")
                .containsExactly(tile(type, 1));
    }

    private void assertFieldPreserved(final byte[] output,
                                      final AllPrimitivesFixture fixture,
                                      final BasicType type) {
        final int width = type.getValueSize(ID_SIZE);
        assertThat(region(output, fixture.fieldOffset(type), width))
                .as("field of type " + type + " must be preserved")
                .containsExactly(unsanitized(width));
    }

    private void assertArraySanitized(final byte[] output,
                                      final AllPrimitivesFixture fixture,
                                      final BasicType type) {
        final int[] expected = tile(type, ARRAY_LENGTH);
        assertThat(region(output, fixture.arrayOffset(type), expected.length))
                .as("array of type " + type + " must be sanitized")
                .containsExactly(expected);
    }

    private void assertArrayPreserved(final byte[] output,
                                      final AllPrimitivesFixture fixture,
                                      final BasicType type) {
        final int numBytes = ARRAY_LENGTH * type.getValueSize(ID_SIZE);
        assertThat(region(output, fixture.arrayOffset(type), numBytes))
                .as("array of type " + type + " must be preserved")
                .containsExactly(unsanitized(numBytes));
    }

    @Test
    @DisplayName("testPreprocessingOnlyProducesNoOutput. the metadata pass must consume the dump and write nothing")
    void testPreprocessingOnlyProducesNoOutput() throws IOException {
        final AllPrimitivesFixture fixture = new AllPrimitivesFixture();
        final ByteArrayOutputStream outputBytes = new ByteArrayOutputStream();

        final SanitizeCommand command = new SanitizeCommand();
        new CommandLine(command)
                .registerConverter(DataSize.class, DataSize::parse)
                .parseArgs("in.hprof", "out.hprof");

        final HeapDumpSanitizer sanitizer = new HeapDumpSanitizer();
        sanitizer.setPreprocessingOnly(true);
        sanitizer.setInputStream(new ByteArrayInputStream(fixture.input));
        sanitizer.setOutputStream(outputBytes);
        sanitizer.setProgressMonitor(numBytesProcessed -> {
            // no op
        });
        sanitizer.setSanitizeCommand(command);

        assertThatCode(sanitizer::sanitize).doesNotThrowAnyException();
        assertThat(outputBytes.size())
                .as("the metadata pass writes nothing, even when handed an output stream")
                .isZero();
    }

    /**
     * The writing pass keeps only the strings the metadata pass read back, so a class name that pass
     * needs must survive the pruning. The -f coder rewrite is the sharpest case: it fires only for
     * instances whose class name equals java.lang.String, a comparison made during the writing pass, so
     * losing that one string silently turns the rewrite off and leaves a coder inconsistent with the
     * byte[] beside it -- unreadable strings in MAT, not a failed run.
     *
     * <p>Drives both passes over a single sanitizer the way SanitizeCommandProcessor does, because the
     * pruning happens between them, and pads the dump with strings nothing reads so the pruning has
     * something to remove.</p>
     */
    @Test
    @DisplayName("testStringsNeededByTheWritingPassSurvivePreprocessing. pruning must not drop a class name -f needs")
    void testStringsNeededByTheWritingPassSurvivePreprocessing() throws IOException {
        final long stringClassId = 900;
        final long stringObjectId = 0x9100;
        final long valueArrayId = 0x9200;

        final Hprof input = new Hprof().header();
        input.stringInUtf8(20, String.class.getName());
        input.stringInUtf8(21, "value");
        input.stringInUtf8(22, "coder");
        // strings nothing ever reads back: these are what the pruning is meant to drop
        for (int i = 0; i < 50; i++) {
            input.stringInUtf8(100 + i, "unreferenced-heap-string-" + i);
        }
        input.loadClass(1, stringClassId, 20);

        final Hprof body = new Hprof();
        body.classDump(stringClassId, 0, new int[]{21, 22},
                new BasicType[]{BasicType.OBJECT, BasicType.BYTE});
        // "hi" as UTF16-BE, i.e. a genuine coder==1 payload
        body.primitiveArrayDump(valueArrayId, BasicType.BYTE, new byte[]{0, 'h', 0, 'i'});

        final Hprof instance = new Hprof();
        instance.id(valueArrayId);
        final int relativeCoderOffset = instance.offset();
        instance.u1(1);
        final int instanceOffset = body.instanceDump(stringObjectId, stringClassId, instance.toByteArray());
        final int base = input.record(HeapRecord.HEAP_DUMP_SEGMENT.getTag(), body);
        final byte[] inputBytes = input.toByteArray();

        final SanitizeCommand command = new SanitizeCommand();
        new CommandLine(command)
                .registerConverter(DataSize.class, DataSize::parse)
                .parseArgs("--force-string-coder-match=true", "in.hprof", "out.hprof");

        // one sanitizer across both passes, as SanitizeCommandProcessor does
        final HeapDumpSanitizer sanitizer = new HeapDumpSanitizer();
        sanitizer.setProgressMonitor(numBytesProcessed -> {
            // no op
        });
        sanitizer.setSanitizeCommand(command);

        sanitizer.setPreprocessingOnly(true);
        sanitizer.setInputStream(new ByteArrayInputStream(inputBytes));
        sanitizer.sanitize();
        sanitizer.setPreprocessingOnly(false);

        final ByteArrayOutputStream outputBytes = new ByteArrayOutputStream();
        sanitizer.setInputStream(new ByteArrayInputStream(inputBytes));
        sanitizer.setOutputStream(outputBytes);
        sanitizer.sanitize();

        final byte[] output = outputBytes.toByteArray();
        assertThat(output.length).isEqualTo(inputBytes.length);
        assertThat(output[base + instanceOffset + relativeCoderOffset])
                .as("java.lang.String survived pruning, so -f still recognized this instance and forced LATIN1")
                .isEqualTo((byte) 0);
    }

    @Test
    @DisplayName("testObjectArrayElementsArePreserved. object references are never sanitized")
    void testObjectArrayElementsArePreserved() throws IOException {
        final long[] elementIds = {0x1111L, 0x2222L, 0x3333L, 0x4444L};

        final Hprof hprof = new Hprof().header();
        final Hprof body = new Hprof();
        final int relativeOffset = body.objectArrayDump(0x7000L, 0x7100L, elementIds);
        final int base = hprof.record(HeapRecord.HEAP_DUMP_SEGMENT.getTag(), body);
        final byte[] input = hprof.toByteArray();

        final byte[] output = sanitize(input);

        final ByteBuffer elements = ByteBuffer.wrap(output, base + relativeOffset, elementIds.length * ID_SIZE);
        for (final long elementId : elementIds) {
            assertThat(elements.getLong())
                    .as("object array elements must survive sanitization byte for byte")
                    .isEqualTo(elementId);
        }
    }

    private byte[] sanitize(final byte[] input, final String... options) throws IOException {
        final SanitizeCommand command = new SanitizeCommand();
        final List<String> argv = new ArrayList<>(asList(options));
        argv.add("in.hprof");
        argv.add("out.hprof");
        new CommandLine(command)
                .registerConverter(DataSize.class, DataSize::parse)
                .parseArgs(argv.toArray(EMPTY_STRING_ARRAY));

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
                .as("sanitization must preserve the length of the dump")
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

}
