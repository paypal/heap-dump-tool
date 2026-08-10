package com.paypal.heapdumptool.sanitizer;

import com.paypal.heapdumptool.sanitizer.internal.hprof.ArrayTransformation;
import com.paypal.heapdumptool.sanitizer.internal.hprof.ClassObject;
import com.paypal.heapdumptool.sanitizer.internal.hprof.Field;
import com.paypal.heapdumptool.sanitizer.internal.hprof.HeapRecord;
import com.paypal.heapdumptool.sanitizer.internal.hprof.Pipe;
import com.paypal.heapdumptool.sanitizer.internal.hprof.PrimitiveArrayContext;
import com.paypal.heapdumptool.sanitizer.internal.policy.Replacement;
import com.paypal.heapdumptool.sanitizer.internal.policy.SanitizationRuleRegistry;
import com.paypal.heapdumptool.utils.InternalLogger;
import com.paypal.heapdumptool.utils.Long2LongHashMap;
import com.paypal.heapdumptool.utils.ProgressMonitor;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static com.paypal.heapdumptool.sanitizer.internal.hprof.HeapRecord.HEAP_DUMP;
import static com.paypal.heapdumptool.sanitizer.internal.hprof.HeapRecord.HEAP_DUMP_SEGMENT;
import static com.paypal.heapdumptool.sanitizer.internal.hprof.HeapRecord.LOAD_CLASS;
import static com.paypal.heapdumptool.sanitizer.internal.hprof.HeapRecord.STRING_IN_UTF8;
import static org.apache.commons.lang3.BooleanUtils.isFalse;

/**
 * Heavily based on: <br>
 *
 * <a href="https://html-preview.github.io/?url=https://github.com/openjdk/jdk8/blob/master/jdk/src/share/demo/jvmti/hprof/manual.html">
 * Heap Dump Binary Format Spec
 * </a> (highly recommended to make sense of the code in any meaningful way)
 * <br>
 *
 * <a href="https://github.com/openjdk/jdk/blob/a2bbf933d96dc4a911ac4b429519937d8dd83200/src/hotspot/share/services/heapDumper.cpp">
 * JDK heapDumper.cpp
 * </a>
 * <br>
 *
 * <a href="https://github.com/AdoptOpenJDK/jheappo">
 * JHeappo
 * </a> (clean modern code)
 * <br>
 *
 * <a href="https://github.com/apache/netbeans/tree/f2611e358c181935500ea4d9d9142fb850504a72/profiler/lib.profiler/src/org/netbeans/lib/profiler/heap">
 * NetBeans/VisualVM HeapDump code (old but reference)
 * </a>
 */
public class HeapDumpSanitizer {

    private static final String STRING_CODER_FIELD = "coder";
    private static final String STRING_VALUE_FIELD = "value";

    /**
     * Fluent entry point for running a sanitization without constructing a {@link SanitizeCommand}
     * by hand. See {@link HeapDumpSanitizerBuilder}.
     */
    public static HeapDumpSanitizerBuilder create(final Path inputFile, final Path outputFile) {
        return HeapDumpSanitizerBuilder.create(inputFile, outputFile);
    }

    /*
     * The "no such entry" marker for stringObjectIdToValueArrayIdMap. Object ids
     * are addresses, so the sign bit is never set on any id a dump can contain.
     * pipeId() rejects anything above 2^63 outright.
     */
    private static final long NO_VALUE_ARRAY_ID = Long.MIN_VALUE;

    private static final InternalLogger LOGGER = InternalLogger.getLogger(HeapDumpSanitizer.class);

    private InputStream inputStream;
    private OutputStream outputStream;
    private ProgressMonitor progressMonitor;
    private SanitizeCommand sanitizeCommand;

    /*
     * Debugging switch to disable sanitization. Useful for verifying that the tool is able to correctly parse and
     * create valid heap dump files.
     */
    private boolean sanitizationEnabled = isFalse(Boolean.getBoolean("disable-sanitization"));

    /*
     * True for the metadata-collection pass, whose output is discarded.
     */
    private boolean preprocessingOnly;

    /*
     * Resolved once per sanitize() run, not per query. SanitizeCommand.getSanitizationPolicy()
     * deliberately re-resolves the recorded flags on every call (a memo goes stale because picocli
     * parses the same command object more than once), so it allocates. The scope questions below are
     * asked once per field of every instance dump, which is as hot as this code gets.
     */
    private SanitizationPolicy sanitizationPolicy;

    /*
     * The programmatic rule chain, empty on a default run. Resolved once per instance rather than once
     * per sanitize() call: the chain records which rules have matched, and both passes share this
     * object, so re-resolving between passes would lose the metadata pass's matches and warn about
     * rules that did fire. Empty is the common case and short-circuits before any of this costs
     * anything -- see hasRules.
     */
    private SanitizationRuleRegistry sanitizationRules = SanitizationRuleRegistry.empty();

    /*
     * Hoisted out of the field and array decisions for the same reason sanitizationPolicy is: these are
     * asked once per field of every instance dump. A boolean read beats a List.isEmpty() through two
     * levels of indirection on that path.
     */
    private boolean hasRules;

    /*
     * The transformed-array engine, null until a TRANSFORM verdict on an array actually needs it -- not
     * merely until rules are registered, since a rule chain that only sanitizes never decodes an element.
     * One per sanitizer rather than per record: it holds the decode scratch buffers, and reallocating
     * those per array is precisely what it exists to avoid.
     */
    private ArrayTransformation arrayTransformation;

    /*
     * Also resolved once per run, for the same reason: getExcludeStringFields() is memoized but the
     * emptiness question is asked once per instance dump and once per class dump.
     */
    private boolean hasExcludeStringFields;

    private final Map<Long, String> stringIdToStringMap = new HashMap<>();
    private final Map<Long, Long> classObjectIdToStringIdMap = new HashMap<>();

    /*
     * The string ids this run actually reads back, recorded during the metadata pass and consulted by
     * the writing pass.
     *
     * stringIdToStringMap is queried for exactly two things -- class names (getClassName) and instance
     * field names (class dumps) -- but STRING_IN_UTF8 records carry every string in the heap, so on a
     * 1.2 GB dump it stored around 1.4 mil entries of which only about 100k were ever looked up. The
     * other ~90% are heap object contents that nothing queries, retaining a few hundred MB for the
     * length of the run.
     *
     * The ids cannot be known on a single pass: STRING_IN_UTF8 records precede the LOAD_CLASS and class
     * dump records that reference them. They can be known on the second, because both passes share one
     * instance -- so the metadata pass notes every id it queries, and the writing pass keeps only
     * those. Null until a metadata pass has finished, meaning "keep everything", which is what a
     * single-pass run and the metadata pass itself both need.
     */
    private Set<Long> neededStringIds;
    private Set<Long> queriedStringIds;

    /*
     * Field layouts, keyed by class object id rather than class name. Class names are not unique in a
     * heap dump -- the same name loaded by two class loaders yields two distinct classes with
     * distinct layouts -- and sharing one layout between them mis-slots every field after the first
     * divergence: OBJECT references get classified as primitives and overwritten, and the widths
     * disagree so the reader runs off the end of the record. Class object ids are unique by
     * construction.
     */
    private final Map<Long, ClassObject> classObjectIdToClassObjectMap = new HashMap<>();
    private final Set<Long> excludeStringObjectIds = new HashSet<>();
    private final Set<Long> excludeStringValueArrayObjectIds = new HashSet<>();

    /*
     * Every String instance's own id -> the id of the byte[] its value field points at, recorded by
     * the metadata pass and resolved against excludeStringObjectIds when that pass ends.
     *
     * -e attribution is a two-hop chain, holder -> String -> array, and the two hops are found in
     * separate sub-records whose order the format does not constrain: HotSpot emits them in heap walk
     * order. Recording each hop only when the previous one was already known made a pass advance the
     * chain by at most one hop, so correctness rested on the emission order AND on the pass count
     * happening to equal the chain length. It did not hold: with the array emitted before both the
     * String and the holder, the array was read before either hop was available in EITHER pass, so
     * the payload -e was asked to keep was overwritten -- silently, exit code 0. Recording the second
     * hop unconditionally and resolving it after the pass has seen every record makes the writing
     * pass start from a complete set instead of building one as it goes, so no order can defeat it.
     *
     * The cost is one entry per String instance, since the -e set is not complete until the pass
     * ends. Measured on the 1.2 GB dump the comments above use as a benchmark that is 3.66 mil
     * entries, where a HashMap<Long, Long> retains 316 MB against this map's 128 MB -- the boxed
     * keys, boxed values and per-entry nodes are most of it. Hence a primitive map, and hence one
     * with an interleaved key/value array rather than parallel arrays plus an occupancy array, which
     * measured 8 MB worse at the same speed.
     *
     * Populated only when -e names something, so an -f-only run pays nothing, and dropped as soon as
     * it is resolved, so the writing pass never carries it.
     */
    private Long2LongHashMap stringObjectIdToValueArrayIdMap;

    public void setInputStream(final InputStream inputStream) {
        this.inputStream = inputStream;
    }

    public void setOutputStream(final OutputStream outputStream) {
        this.outputStream = outputStream;
    }

    public void setProgressMonitor(final ProgressMonitor numBytesWrittenMonitor) {
        this.progressMonitor = numBytesWrittenMonitor;
    }

    public void setSanitizeCommand(final SanitizeCommand sanitizeCommand) {
        this.sanitizeCommand = sanitizeCommand;
    }

    /**
     * The rule chain this instance used, for the end-of-run zero-match warning. Empty until
     * {@link #sanitize()} has resolved it.
     */
    public SanitizationRuleRegistry getSanitizationRules() {
        return sanitizationRules;
    }

    public void setPreprocessingOnly(final boolean preprocessingOnly) {
        this.preprocessingOnly = preprocessingOnly;
        this.sanitizationEnabled = !preprocessingOnly && isFalse(Boolean.getBoolean("disable-sanitization"));
        if (preprocessingOnly) {
            /*
             * Entering the metadata pass: start recording which string ids get read back, and keep
             * every string for the duration, since the set is not known until this pass ends.
             */
            queriedStringIds = new HashSet<>();
            neededStringIds = null;
            stringObjectIdToValueArrayIdMap = new Long2LongHashMap(NO_VALUE_ARRAY_ID);
        } else if (queriedStringIds != null) {
            resolveExcludeStringValueArrayIds();

            /*
             * Leaving it: the recorded ids are the only ones the writing pass can read back, because
             * both passes see the same records in the same order and ask the same questions of them.
             * Dropping the recorder also stops the writing pass from growing a set nothing consults.
             */
            neededStringIds = queriedStringIds;
            queriedStringIds = null;

            /*
             * Both passes share this map, so the entries the metadata pass already stored have to go
             * too -- gating the writing pass's puts alone would leave all of them resident. The
             * writing pass repopulates what it keeps from the same records, in the same order.
             */
            final int storedBefore = stringIdToStringMap.size();
            stringIdToStringMap.keySet().retainAll(neededStringIds);
            LOGGER.debug(
                    "Retained {} of {} strings for the sanitization pass", stringIdToStringMap.size(), storedBefore);
        }
    }

    /**
     * Walks the second hop of {@code -e} attribution for every excluded String the metadata pass
     * found, now that it has seen every record and both hops are complete. See
     * {@link #stringObjectIdToValueArrayIdMap} for why this cannot be done inline.
     *
     * <p>An excluded id with no recorded edge is normal and silently skipped: {@code -e} can name a
     * field holding null, or one whose target is not a {@code java.lang.String} at all.</p>
     */
    private void resolveExcludeStringValueArrayIds() {
        if (stringObjectIdToValueArrayIdMap == null) {
            return;
        }

        for (final Long excludedStringObjectId : excludeStringObjectIds) {
            final long valueArrayId = stringObjectIdToValueArrayIdMap.get(excludedStringObjectId);
            if (valueArrayId != NO_VALUE_ARRAY_ID) {
                excludeStringValueArrayObjectIds.add(valueArrayId);
            }
        }
        LOGGER.debug(
                "Resolved {} of {} excluded strings to a backing array, from {} recorded value edges",
                excludeStringValueArrayObjectIds.size(),
                excludeStringObjectIds.size(),
                stringObjectIdToValueArrayIdMap.size());

        // resolved, so the per-String-instance memory goes back before the writing pass starts
        stringObjectIdToValueArrayIdMap = null;
    }

    public void sanitize() throws IOException {
        sanitizationPolicy = sanitizeCommand.getSanitizationPolicy();
        hasExcludeStringFields = !sanitizeCommand.getExcludeStringFields().isEmpty();

        /*
         * Resolved once, on the first pass, and then kept: the chain accumulates which rules matched,
         * so replacing it on the second pass would discard the metadata pass's matches and make the
         * zero-match warning report rules that did fire.
         */
        if (sanitizationRules.isEmpty()) {
            /*
             * Null-coalesced rather than assigned straight through: a stub or mock SanitizeCommand
             * answers null here, and letting that replace the empty chain turns every later
             * isEmpty() into an NPE -- on the no-rules path, which is the default one.
             */
            final SanitizationRuleRegistry resolved = sanitizeCommand.getSanitizationRules();
            sanitizationRules = resolved == null ? SanitizationRuleRegistry.empty() : resolved;
            hasRules = !sanitizationRules.isEmpty();
        }

        final Pipe pipe = preprocessingOnly
                ? Pipe.readOnlyPipe(inputStream, progressMonitor)
                : new Pipe(inputStream, outputStream, progressMonitor);

        /*
         * The basic fields in the binary output are u1 (1 byte), u2 (2 byte), u4 (4 byte), and u8 (8 byte).
         *
         * The binary output begins with the information:
         * [u1]* An initial NULL terminated series of bytes representing the format name and version
         * u4 size of identifiers. Identifiers are used to represent UTF8 strings, objects, stack traces, etc.
         * u4 high word of number of milliseconds since 0:00 GMT, 1/1/70
         * u4 low word of number of milliseconds since 0:00 GMT, 1/1/70
         */
        final String version = pipe.pipeNullTerminatedString().trim();
        LOGGER.debug("Heap Dump Version: {}", version);

        pipe.setIdSize((int) pipe.pipeU4());
        LOGGER.debug("Id Size: {}", pipe.getIdSize());
        pipe.pipe(8);

        /*
         * Followed by a sequence of records that look like:
         * u1		TAG: denoting the type of the record
         * u4		TIME: number of microseconds since the time stamp in the header
         * u4		LENGTH: number of bytes that follow this u4 field and belong to this record
         * [u1]*	BODY: as many bytes as specified in the above u4 field
         */

        while (true) {
            final int tag = pipe.pipeU1IfPossible();
            if (tag == -1) {
                break;
            }
            final HeapRecord heapRecord = HeapRecord.findByTag(tag);

            pipe.pipeU4(); // timestamp
            final long length = pipe.pipeU4();
            LOGGER.debug("Tag: {}", tag);
            LOGGER.debug("Length: {}", length);

            if (heapRecord == HEAP_DUMP || heapRecord == HEAP_DUMP_SEGMENT) {
                final Pipe heapPipe = pipe.newInputBoundedPipe(length);
                copyHeapDumpRecord(heapPipe);

            } else if (heapRecord == STRING_IN_UTF8) {
                copyStringInUtf8Record(pipe, length);

            } else if (heapRecord == LOAD_CLASS) {
                copyLoadClassRecord(pipe);

            } else {
                pipe.pipe(length);
            }
        }
    }

    private void copyLoadClassRecord(final Pipe pipe) throws IOException {
        pipe.pipeU4(); // class serial number
        final long classObjectId = pipe.pipeId(); // class object ID
        pipe.pipeU4(); // stack trace serial number
        final long id = pipe.pipeId(); // class name string ID
        if (shouldTrackClassMetadata() || isStringClass(classObjectId)) {
            classObjectIdToStringIdMap.put(classObjectId, id);
        }
    }

    private boolean isStringClass(final long classObjectId) {
        return getClassName(classObjectId).equals(String.class.getName());
    }

    /*
     * STRING IN UTF8  0x01
     *
     * ID     string id
     * [u1]*  UTF8 bytes, for the rest of the record (no trailing NUL)
     *
     * The body length is the record length less the leading id, and the pipe now reads exactly that many
     * bytes. Previously the body was read through a per-record bounded child pipe, which is where the
     * correct length lived: the length argument was the whole record length, over-long by idSize, and
     * only the child's bound stopped it from reading into the next record. Passing the true length makes
     * the bound redundant, which drops three allocations (child Pipe, DataInputStream,
     * BoundedInputStream) from the most numerous record type in a dump.
     */
    private void copyStringInUtf8Record(final Pipe pipe, final long length) throws IOException {
        final long id = pipe.pipeId();
        final long bodyLength = length - pipe.getIdSize();

        /*
         * Decided before reading, so a record nothing will store is never decoded. The map keeps only
         * about 100k of some 1.4 mil records on a 1.2 GB dump, so the other ~90% were being turned into
         * a String -- and, for the half of them containing a slash, a second String -- to be dropped.
         */
        if (isNeededStringId(id) && (shouldTrackClassMetadata() || sanitizeCommand.isForceMatchStringCoder())) {
            stringIdToStringMap.put(id, pipe.pipeStringReplacing(bodyLength, '/', '.'));
        } else {
            pipe.pipeExactly(bodyLength);
        }
    }

    /*
     * The body of a HEAP DUMP or HEAP DUMP SEGMENT record: a series of sub-records, each with its own
     * u1 tag and its own layout.
     *
     * ROOT UNKNOWN         0xFF  ID object id
     * ROOT JNI GLOBAL      0x01  ID object id; ID JNI global ref id
     * ROOT JNI LOCAL       0x02  ID object id; u4 thread serial; u4 frame number (-1 for empty)
     * ROOT JAVA FRAME      0x03  ID object id; u4 thread serial; u4 frame number (-1 for empty)
     * ROOT NATIVE STACK    0x04  ID object id; u4 thread serial
     * ROOT STICKY CLASS    0x05  ID object id
     * ROOT THREAD BLOCK    0x06  ID object id; u4 thread serial
     * ROOT MONITOR USED    0x07  ID object id
     * ROOT THREAD OBJECT   0x08  ID thread object id; u4 thread serial; u4 stack trace serial
     * CLASS DUMP           0x20  ID class object id; ...
     * INSTANCE DUMP        0x21  ID object id; ...
     * OBJECT ARRAY DUMP    0x22  ID array object id; ...
     * PRIMITIVE ARRAY DUMP 0x23  ID array object id; ...
     *
     * Only the last four DUMP types hold the field values and array elements this tool sanitizes.
     *
     * An unknown tag throws instead of being skipped over. A sub-record's size is only knowable from
     * its layout, so there is no length to skip by: a tag this switch does not know means the rest of
     * the body can no longer be located, and carrying on would write a corrupt dump.
     */
    private void copyHeapDumpRecord(final Pipe pipe) throws IOException {
        while (true) {
            final int tag = pipe.pipeU1IfPossible();
            if (tag == -1) {
                break;
            }
            LOGGER.debug("Heap Dump Tag: {}", tag);

            final long id = pipe.pipeId();
            switch (tag) {
                case 0xFF: // ROOT UNKNOWN
                    break;

                case 0x01: // ROOT JNI GLOBAL
                    pipe.pipeId(); // JNI global ref id
                    break;

                case 0x02: // ROOT JNI LOCAL
                case 0x03: // ROOT JAVA FRAME
                    pipe.pipe(4 + 4); // thread serial, frame number
                    break;

                case 0x04: // ROOT NATIVE STACK
                    pipe.pipeU4(); // thread serial
                    break;

                case 0x05: // ROOT STICKY CLASS
                    break;

                case 0x06: // ROOT THREAD BLOCK
                    pipe.pipeU4(); // thread serial
                    break;

                case 0x07: // ROOT MONITOR USED
                    break;

                case 0x08: // ROOT THREAD OBJECT
                    pipe.pipe(4 + 4); // thread serial, stack trace serial
                    break;

                case 0x20: // CLASS DUMP
                    copyHeapDumpClassDump(pipe, id);
                    break;

                case 0x21: // INSTANCE DUMP
                    copyHeapDumpInstanceDump(pipe, id);
                    break;

                case 0x22: // OBJECT ARRAY DUMP
                    // the array object id is not needed: elements are references, never sanitized
                    copyHeapDumpObjectArrayDump(pipe);
                    break;

                case 0x23: // PRIMITIVE ARRAY DUMP
                    copyHeapDumpPrimitiveArrayDump(pipe, id);
                    break;

                default:
                    throw new IllegalArgumentException("" + tag);
            }
        }
    }

    private void copyHeapDumpClassDump(final Pipe pipe, final long classObjectId) throws IOException {
        pipe.pipeU4(); // stacktrace
        final long superClassObjectId = pipe.pipeId();
        pipe.pipeId(); // class loader object id
        pipe.pipeId(); // signers object id
        pipe.pipeId(); // protection domain
        pipe.pipeId(); // reserved
        pipe.pipeId(); // reserved
        pipe.pipeU4(); // instance size

        final int numConstantPoolRecords = pipe.pipeU2();
        for (int i = 0; i < numConstantPoolRecords; i++) {
            pipe.pipeU2();
            final int entryType = pipe.pipeU1();
            pipeBasicType(pipe, entryType);
        }

        /*
         * Resolved once for the whole record rather than per field. Only rules can ask for it -- the
         * flags decide by type alone -- so a default run does not pay for the lookup or for keeping the
         * class-name string alive.
         */
        final String declaringClassName = hasRules ? getClassName(classObjectId) : "";

        final int numStaticFields = pipe.pipeU2();
        for (int i = 0; i < numStaticFields; i++) {
            final long fieldNameStringId = pipe.pipeId();
            final int entryType = pipe.pipeU1();
            pipeStaticField(pipe, fieldNameStringId, entryType, declaringClassName);
        }

        final ClassObject classObject = new ClassObject(classObjectId, superClassObjectId);
        if (shouldTrackClassMetadata() || isStringClass(classObjectId)) {
            classObjectIdToClassObjectMap.putIfAbsent(classObjectId, classObject);
        }
        final int numInstanceFields = pipe.pipeU2();
        for (int i = 0; i < numInstanceFields; i++) {
            final long fieldNameStringId = pipe.pipeId();
            final int fieldType = pipe.pipeU1();
            recordStringIdQuery(fieldNameStringId);
            final String fieldName = stringIdToStringMap.getOrDefault(fieldNameStringId, "");
            final BasicType basicType = requireBasicType(fieldType);
            classObject.fields.add(new Field(fieldName, basicType, declaringClassName, false));
        }
    }

    /**
     * The type for a code that has already been validated as a basic type, e.g. by a preceding
     * {@link BasicType#findValueSize(int, int)} or scope check.
     */
    private static BasicType requireBasicType(final int u1Code) {
        final BasicType basicType = BasicType.byU1Code(u1Code);
        if (basicType == null) {
            throw new IllegalStateException("Unknown basic type code: " + u1Code);
        }
        return basicType;
    }

    /*
     * Rules force this on. Any rule that names a class or field needs the layout to have been recorded,
     * and a rule chain's targets are opaque from here -- there is no way to ask "does this rule care
     * about this class?" without consulting it, which is what needs the layout in the first place.
     */
    private boolean shouldTrackClassMetadata() {
        return !sanitizeCommand.getExcludeStringFields().isEmpty()
                || sanitizationPolicy.isAnyFieldSanitized()
                || hasRules;
    }

    private boolean isAssignableClassWithExcludeStringField(final long classObjectId) {
        for (ClassObject c = classHierarchyStart(classObjectId); c != null; c = superClassOf(c)) {
            if (sanitizeCommand.isExactClassWithExcludeStringField(getClassName(c.id))) {
                return true;
            }
        }
        return false;
    }

    /*
     * A static field's name id used to be discarded, since the flags decide by type alone. It is
     * resolved to a name here only when a rule chain is registered and could ask for it.
     *
     * Unlike an instance field there is no per-declaration object to memoize on: static values live in
     * the class dump itself, are read exactly once per class per pass, and are never revisited. So the
     * chain is consulted per static field -- at most twice per declaration over a whole run, which is
     * the same order as the instance-field case, not the per-value case the SPI exists to avoid.
     */
    private void pipeStaticField(
            final Pipe pipe, final long fieldNameStringId, final int entryType, final String declaringClassName)
            throws IOException {
        final int valueSize = BasicType.findValueSize(entryType, pipe.getIdSize());
        final BasicType basicType = requireBasicType(entryType);

        if (hasRules) {
            /*
             * Recorded in both passes, unlike the name lookup below it. The metadata pass is what decides
             * which strings the writing pass keeps, and sanitizationEnabled is false for the whole of that
             * pass -- so recording it under that gate never happened at all, and the writing pass dropped
             * every static field name before a rule could be asked about one. Since -e defaults to a
             * non-empty list, that two-pass shape is the default one.
             */
            recordStringIdQuery(fieldNameStringId);

            if (sanitizationEnabled) {
                final String fieldName = stringIdToStringMap.getOrDefault(fieldNameStringId, "");
                final Field field = new Field(fieldName, basicType, declaringClassName, true);
                pipeDeclaredField(pipe, field, valueSize);
                return;
            }
        }

        if (shouldSanitizeField(entryType)) {
            applySanitization(pipe, basicType, valueSize);
        } else {
            pipe.pipe(valueSize);
        }
    }

    private void pipeBasicType(final Pipe pipe, final int entryType) throws IOException {
        final int valueSize = BasicType.findValueSize(entryType, pipe.getIdSize());
        pipe.pipe(valueSize);
    }

    /*
     *
     * INSTANCE DUMP    0x21
     *
     * ID  object ID
     * u4  stack trace serial number
     * ID  class object ID
     * u4  number of bytes that follow
     * [value]*  instance field values (this class, followed by super class, etc)
     */
    private void copyHeapDumpInstanceDump(final Pipe pipe, final long objectId) throws IOException {
        pipe.pipeU4();
        final long classObjectId = pipe.pipeId();
        final long numBytes = pipe.pipeU4();
        final String className = getClassName(classObjectId);

        if (classObjectIdToClassObjectMap.get(classObjectId) == null) {
            /*
             * No CLASS DUMP was seen for this class, so its field layout is unknown. A LOAD_CLASS
             * record without a matching CLASS DUMP does occur in real dumps. Walking fields needs an
             * exact layout: guessing one mis-slots every field, which overwrites OBJECT references
             * and desynchronizes the reader from the record boundary. Pipe the body through instead.
             */
            pipe.pipe(numBytes);

        } else if ((sanitizeCommand.isForceMatchStringCoder() || hasExcludeStringFields)
                && className.equals(String.class.getName())) {
            /*
             * Not gated on -f alone. -e selects fields to preserve and -f controls how coder is
             * rewritten, so they must stay independent -- but only this walk reads String.value,
             * which is the sole bridge from an excluded String's instance id to its backing array
             * id. Gating the walk on -f let -f=false silently disable -e: the bridge never ran,
             * excludeStringValueArrayObjectIds stayed empty, and every excluded String's payload
             * was replaced anyway. pipeStringCoder keeps -f's own observable behavior.
             */
            copyStringsInstanceFields(pipe, classObjectId, objectId, numBytes);

        } else if (isAssignableClassWithExcludeStringField(classObjectId)
                || sanitizationPolicy.isAnyFieldSanitized()
                // a rule can sanitize a field --target left out, so --target=none plus a rule still
                // has to walk the layout rather than pipe the body through
                || hasRules) {
            copyInstanceAndSanitizeSomeFields(pipe, classObjectId, numBytes);

        } else {
            // nothing to sanitize in the instance dump; arrays are handled in the array dump section
            pipe.pipe(numBytes);
        }
    }

    /*
     * java.lang.String gets its own field walk because String.coder is never a generic BYTE field.
     * On JDK 9+, coder selects how the backing byte[] is decoded (LATIN1=0, UTF16=1); every other
     * value is illegal and breaks string rendering for the whole dump in MAT and JVisualVM. So the
     * only two things that may be written are the original value and, when the backing array is
     * genuinely being replaced with single-byte values, 0.
     *
     * On JDK 8 String has no coder field at all, and the loop simply never matches it.
     */
    private void copyStringsInstanceFields(
            final Pipe pipe, final long classObjectId, final long objectId, long numBytes) throws IOException {
        // never null: copyHeapDumpInstanceDump checks the layout before choosing this branch
        final ClassObject classObject = classObjectIdToClassObjectMap.get(classObjectId);

        /*
         * This String's backing array id, once the value field has been read. Tracked so the coder
         * decision can be made from the ARRAY's preservation state rather than this instance's id:
         * two Strings can share one backing byte[] (new String(String), substring(0) and the other
         * zero-copy paths all alias it), so a String that is not itself named by -e can still sit
         * over an array that -e preserved on another String's behalf.
         */
        long valueArrayObjectId = -1;
        boolean sawValueField = false;

        for (final Field field : classObject.fields) {
            final int fieldSize = field.type.getValueSize(pipe.getIdSize());

            if (field.type == BasicType.BYTE && STRING_CODER_FIELD.equals(field.name)) {
                /*
                 * An unread value field means the layout puts coder first, so the backing array is
                 * not yet known. Treat it as preserved: piping a coder through is the conservative
                 * error (at worst a replaced payload renders as escapes rather than '*'), whereas
                 * forcing 0 over a surviving UTF-16 array corrupts a value -e was asked to keep.
                 */
                final boolean backingArrayPreserved =
                        !sawValueField || excludeStringValueArrayObjectIds.contains(valueArrayObjectId);
                pipeStringCoder(pipe, backingArrayPreserved);

            } else if (field.type == BasicType.OBJECT && STRING_VALUE_FIELD.equals(field.name)) {
                final long id = pipe.pipeId();
                valueArrayObjectId = id;
                sawValueField = true;
                recordStringValueEdge(objectId, id);
                if (excludeStringObjectIds.contains(objectId)) {
                    /*
                     * Kept alongside the edge recording above, which is what actually makes -e order
                     * independent. This inline hop is all a SINGLE pass has: there is no end-of-pass
                     * resolution point, so a one-pass run still resolves the chain exactly as far as
                     * it used to -- which is to say, when the records happen to arrive in a
                     * favourable order. SanitizeCommandProcessor always runs two passes when -e is
                     * set, so nothing in production depends on that.
                     */
                    excludeStringValueArrayObjectIds.add(id);
                }

            } else {
                pipeDeclaredField(pipe, field, fieldSize);
            }

            numBytes -= fieldSize;
        }

        pipe.pipe(numBytes);
    }

    /**
     * Notes which {@code byte[]} this String instance reads, i.e. the second hop of {@code -e}
     * attribution. Recorded for every String rather than only excluded ones, because the {@code -e}
     * set is not complete until the metadata pass ends -- see
     * {@link #stringObjectIdToValueArrayIdMap}.
     *
     * <p>Only the metadata pass records. In a single-pass run the map is null, and the writing pass
     * already has the resolved set, so neither one grows a structure nothing consults.</p>
     *
     * <p>An excluded String whose value field appears in more than one instance dump for the same
     * object id cannot happen: an object id is dumped once. Overwriting on a repeat would be no worse
     * than the previous inline behavior in any case, since both keep the last edge seen.</p>
     */
    private void recordStringValueEdge(final long stringObjectId, final long valueArrayObjectId) {
        if (stringObjectIdToValueArrayIdMap != null && hasExcludeStringFields) {
            stringObjectIdToValueArrayIdMap.put(stringObjectId, valueArrayObjectId);
        }
    }

    /*
     * Forces the coder to LATIN1 if and only if the backing byte[] this String reads is actually
     * being overwritten with a single-byte replacement, which every byte[] replacement is. Then any
     * surviving coder==1 would claim the replaced bytes are UTF-16 code units and render as garbage,
     * so 0 is the truthful value. That is:
     *
     *     --force-string-coder-match=true
     *  && byte arrays are in scope (not excluded by --target)
     *  && the backing array is not preserved by --exclude-string-fields
     *
     * The last condition is keyed by the BACKING ARRAY, not by this String's own object id, because
     * the two are not interchangeable: on JDK 9+ several String instances can share one backing
     * byte[] -- new String(String), substring(0) and the other zero-copy paths all alias it -- so a
     * String that -e never named can still read an array that -e preserved on another String's
     * behalf. Keying on the instance id forced 0 over such a surviving UTF-16 array, reinterpreting
     * each code unit as two LATIN1 characters: mojibake at double length, in a String whose bytes
     * were in fact preserved. Array preservation is decided in shouldApplyArraySanitization from the
     * same excludeStringValueArrayObjectIds set, so the two answers now agree by construction.
     *
     * In every other case the original coder is piped through unchanged.
     */
    private void pipeStringCoder(final Pipe pipe, final boolean backingArrayPreserved) throws IOException {
        final boolean forceLatin1 = sanitizeCommand.isForceMatchStringCoder()
                && sanitizationPolicy.sanitizeArray(BasicType.BYTE)
                && !backingArrayPreserved;
        if (forceLatin1) {
            pipe.readU1();
            pipe.writeU1(0);
        } else {
            pipe.pipeU1();
        }
    }

    /*
     * The class object a hierarchy walk starts from, or null if no CLASS DUMP was seen for the id.
     * Walk on with superClassOf. Each walk visits the class then its ancestors, which is the order
     * HPROF lays instance fields in.
     *
     * Iterating the chain in place rather than collecting it: the walk runs up to three times per
     * instance dump, and the previous Stream.concat-per-level version was one of the largest
     * allocation sites in a profiled run -- each level added a concatenated stream, a spliterator and
     * a lambda capture. Collecting into a list per walk is cheaper but still allocates per instance;
     * in place allocates nothing at all.
     *
     * Deliberately not memoized per class object id: a CLASS DUMP can appear after instances of the
     * class it describes, so a hierarchy captured from an earlier instance can be shorter than the
     * truth.
     */
    private ClassObject classHierarchyStart(final long classObjectId) {
        return classObjectIdToClassObjectMap.get(classObjectId);
    }

    private ClassObject superClassOf(final ClassObject classObject) {
        return classObjectIdToClassObjectMap.get(classObject.superClassObjectId);
    }

    /*
     * Returns the empty list without allocating in the common case: -e names a handful of classes, so
     * almost no instance dump in a real heap contributes anything here.
     */
    private Collection<String> getExcludeStringFieldsInClassHierarchy(final long classObjectId) {
        List<String> fields = null;
        for (ClassObject c = classHierarchyStart(classObjectId); c != null; c = superClassOf(c)) {
            final List<String> classFields = sanitizeCommand.getExcludeStringFields(getClassName(c.id));
            if (!classFields.isEmpty()) {
                if (fields == null) {
                    fields = new ArrayList<>(classFields);
                } else {
                    fields.addAll(classFields);
                }
            }
        }
        return fields == null ? Collections.<String>emptyList() : fields;
    }

    private void copyInstanceAndSanitizeSomeFields(final Pipe pipe, final long classObjectId, final long numBytes)
            throws IOException {
        final Collection<String> excludeStringFields = getExcludeStringFieldsInClassHierarchy(classObjectId);
        // reached for java.lang.String only when -f=false AND -e names nothing, i.e. when there is
        // no coder to force and no exclusion to bridge; copyStringsInstanceFields handles the rest
        final boolean isStringClass = isStringClass(classObjectId);
        long numBytesRemaining = numBytes;
        for (ClassObject c = classHierarchyStart(classObjectId); c != null; c = superClassOf(c)) {
            for (final Field field : c.fields) {
                final int fieldSize = field.type.getValueSize(pipe.getIdSize());

                if (field.type == BasicType.OBJECT && excludeStringFields.contains(field.name)) {
                    /*
                     * Only a reference field can name a String whose payload is preserved, and the
                     * type check is what keeps the walk aligned. pipeId() always reads getIdSize()
                     * bytes while the ledger below subtracts the field's real width, so taking this
                     * arm for a narrower field -- -e=java.lang.String#coder, or any byte/int/char
                     * field -- over-read the difference, mis-sliced every following field, lost the
                     * sub-record boundary and aborted the run on a garbage tag, leaving a truncated
                     * output. A non-reference -e target is treated like any other field instead.
                     */
                    final long id = pipe.pipeId();
                    excludeStringObjectIds.add(id);

                } else if (isStringClass && field.type == BasicType.BYTE && STRING_CODER_FIELD.equals(field.name)) {
                    /*
                     * Never a generic BYTE field: see pipeStringCoder. This walk does not read
                     * String.value, so the backing array is unknown; -f=false reaches here with
                     * nothing to force anyway, and any other route treats the array as preserved
                     * and pipes the original coder through.
                     */
                    pipeStringCoder(pipe, true);

                } else {
                    pipeDeclaredField(pipe, field, fieldSize);
                }
                numBytesRemaining -= fieldSize;
            }
        }

        pipe.pipe(numBytesRemaining);
    }

    private String getClassName(final long classObjectId) {
        final Long stringId = classObjectIdToStringIdMap.get(classObjectId);
        recordStringIdQuery(stringId);
        return stringIdToStringMap.getOrDefault(stringId, "");
    }

    /**
     * Notes that this string id is read back, so the writing pass knows to keep it. Only the metadata
     * pass records; the writing pass has the finished set and adds nothing.
     */
    private void recordStringIdQuery(final Long stringId) {
        if (queriedStringIds != null && stringId != null) {
            queriedStringIds.add(stringId);
        }
    }

    /**
     * Whether the resolved string for this id is worth keeping. True for every id until a metadata pass
     * has produced the set -- so the metadata pass itself, and a run that skips it, behave as before.
     */
    private boolean isNeededStringId(final long id) {
        return neededStringIds == null || neededStringIds.contains(id);
    }

    private boolean shouldSanitizeField(final int fieldType) {
        if (!sanitizationEnabled) {
            return false;
        }

        final BasicType basicType = BasicType.byU1Code(fieldType);
        return basicType != null && sanitizationPolicy.sanitizeField(basicType);
    }

    /*
     * Pipes one declared field, letting the rule chain override --target for it.
     *
     * The rule chain is consulted through Field.resolvedDecision, which asks it once per declaration
     * and then reuses the verdict for every instance of the class. With no rules registered -- the
     * default -- this is one boolean test more than the old path, and the decision object is never
     * touched.
     *
     * Returns nothing and always advances the pipe by exactly fieldSize, whichever branch is taken.
     * That is the invariant the whole file rests on, and keeping it in one place is the point of
     * routing every walk through here: a rule chooses whether to overwrite and with what, never how
     * many bytes.
     */
    private void pipeDeclaredField(final Pipe pipe, final Field field, final int fieldSize) throws IOException {
        if (hasRules && sanitizationEnabled) {
            final Decision decision = field.resolvedDecision(sanitizationRules);
            if (!decision.isUndecided()) {
                if (decision.isSanitize()) {
                    applySanitization(pipe, field.type, fieldSize, decision.tiledReplacement());
                } else if (decision.isTransform()) {
                    applyTransformation(pipe, field, decision.getTransformer());
                } else {
                    pipe.pipe(fieldSize);
                }
                return;
            }
        }

        if (shouldSanitizeField(field.type.getU1Code())) {
            applySanitization(pipe, field.type, fieldSize);
        } else {
            pipe.pipe(fieldSize);
        }
    }

    /*
     * OBJECT ARRAY DUMP  0x22
     *
     * ID  array object ID
     * u4  stack trace serial number
     * u4  number of elements
     * ID  array class object ID
     * [ID]*  elements
     *
     * The elements are object references, which are never sanitized, and nothing here reads their
     * values -- so one bulk transfer of the whole element region is byte-for-byte what a per-element
     * pipeId() loop produced, and collapses to a single seek in the metadata pass. Object arrays are a
     * large share of a real dump, so the loop was worth removing.
     *
     * This does forgo pipeId()'s "Small unsigned long expected" check on each element. That check
     * exists so a >2^63 id cannot be misread as negative by later arithmetic; these values feed no
     * later arithmetic. Every id that is actually used -- object, class object, field name, and
     * String.value -- still goes through pipeId().
     */
    private void copyHeapDumpObjectArrayDump(final Pipe pipe) throws IOException {
        pipe.pipeU4(); // stack trace serial number
        final long numElements = pipe.pipeU4();
        pipe.pipeId(); // array class object id
        pipe.pipe(Math.multiplyExact(numElements, (long) pipe.getIdSize()));
    }

    /*
     * PRIMITIVE ARRAY DUMP	 * 	0x23
     * 	ID	array object ID
     * 	u4	stack trace serial number
     * 	u4	number of elements
     * 	u1	element type (See Basic Type)
     * 	[u1]*	elements (packed array)
     */
    private void copyHeapDumpPrimitiveArrayDump(final Pipe pipe, final long objectId) throws IOException {
        pipe.pipeU4();
        final long numElements = pipe.pipeU4();

        final int elementType = pipe.pipeU1();
        final long elementSize = BasicType.findValueSize(elementType, pipe.getIdSize());

        final long numBytes = Math.multiplyExact(numElements, elementSize);

        /*
         * A rule's verdict cannot be memoized the way a field's is -- there is no per-declaration object
         * to hang it on and the answer may differ per array -- so the chain is consulted once per array
         * record. That is the same cost class as the excludeStringValueArrayObjectIds lookup below, and
         * still one call per record rather than per element.
         *
         * -e wins over a rule: excludeStringValueArrayObjectIds is checked first, inside
         * shouldApplyArraySanitization. A user who both excludes a field and registers a rule that would
         * overwrite its backing array is contradicting themselves, and preserving is the safe reading.
         */
        if (hasRules && sanitizationEnabled && !excludeStringValueArrayObjectIds.contains(objectId)) {
            final BasicType basicType = BasicType.byU1Code(elementType);
            if (basicType != null) {
                // the same context object the rule saw is handed to the transformer, so a transformer can
                // read the array's type and length without the rule having to close over them
                final ArrayContext context = new PrimitiveArrayContext(objectId, basicType, numElements, numBytes);
                final Decision decision = sanitizationRules.decideArray(context);
                if (!decision.isUndecided()) {
                    if (decision.isSanitize()) {
                        applySanitization(pipe, basicType, numBytes, decision.tiledReplacement());
                    } else if (decision.isTransform()) {
                        arrayTransformation()
                                .apply(pipe, basicType, numElements, numBytes, context, decision.getTransformer());
                    } else {
                        pipe.pipe(numBytes);
                    }
                    return;
                }
            }
        }

        if (shouldApplyArraySanitization(objectId, elementType)) {
            final BasicType basicType = requireBasicType(elementType);
            applySanitization(pipe, basicType, numBytes);
        } else {
            pipe.pipe(numBytes);
        }
    }

    /*
     * Not synchronized, and not lazily allocated for thread safety's sake: a run is single-threaded, and
     * both passes are sequential. Lazy only so a run that never transforms an array holds no buffers.
     */
    private ArrayTransformation arrayTransformation() {
        if (arrayTransformation == null) {
            arrayTransformation = new ArrayTransformation();
        }
        return arrayTransformation;
    }

    private boolean shouldApplyArraySanitization(final long objectId, final int elementType) {
        if (!sanitizationEnabled) {
            return false;
        }

        if (excludeStringValueArrayObjectIds.contains(objectId)) {
            return false;
        }

        final BasicType basicType = BasicType.byU1Code(elementType);
        return basicType != null && sanitizationPolicy.sanitizeArray(basicType);
    }

    /*
     * Overwrites the region with repeated whole-buffer writes of the type's pre-tiled replacement.
     *
     * Tiling is always exactly aligned: a non-array field's size is its type's width, and a
     * primitive array's region is numElements * elementSize. So numBytes is always a whole multiple
     * of the replacement's length, no partial tile can occur, and every sanitized value reads back
     * as exactly the requested replacement. See Replacement for why the shared buffer holds a whole
     * number of tiles, which is what makes chunked writing safe.
     *
     * Deliberately not commons-io InfiniteCircularInputStream: it rejects any repeated byte equal to
     * -1, so a perfectly legal replacement containing 0xFF -- e.g. --replacement=byte=-1,
     * --replacement=int=255, or --replacement=double=-1.0 -- would throw the first time a matching
     * slot was sanitized, aborting the run mid-stream and leaving a truncated output file behind.
     */
    private void applySanitization(final Pipe pipe, final BasicType type, final long numBytes) throws IOException {
        applySanitization(pipe, type, numBytes, null);
    }

    /*
     * As above, with an optional replacement from a rule's decision in place of the type's configured
     * one. A rule-supplied replacement is validated to be exactly the type's width when the decision is
     * made (SanitizationRuleRegistry.validateWidth), so the tiling argument above holds for it unchanged:
     * numBytes is still a whole multiple of the replacement length.
     */
    private void applySanitization(
            final Pipe pipe, final BasicType type, final long numBytes, final Replacement override) throws IOException {
        pipe.skipInput(numBytes);
        final Replacement replacement = override == null ? sanitizationPolicy.replacementOf(type) : override;
        final byte[] tiledBuffer = replacement.getTiledBuffer();

        long numBytesRemaining = numBytes;
        while (numBytesRemaining > 0) {
            final int count = (int) Math.min(tiledBuffer.length, numBytesRemaining);
            pipe.write(tiledBuffer, 0, count);
            numBytesRemaining -= count;
        }
    }

    /*
     * The second write path: read one value, hand it to user code, write what comes back.
     *
     * The structural opposite of applySanitization, which never decodes anything. Length preservation
     * comes from the type system rather than from arithmetic -- each read of n bytes is paired with a
     * write of exactly n, and a transformer returns the same type it was given, so there is no width for
     * it to get wrong.
     *
     * Only reached with sanitizationEnabled, i.e. never during the metadata pass. That matters beyond
     * the wasted work: a transformer may keep state (a counter, a pseudonym table), and invoking it once
     * per value per pass would double every count.
     *
     * BOOLEAN is a u1 in the format, where the JVM writes 0 or 1. A transformer sees the decoded
     * boolean, and what is written back is 0 or 1 -- so a dump whose boolean byte was some other value
     * is normalized by transforming it. Nothing reads booleans as anything but zero/non-zero, and the
     * alternative is handing user code a byte it cannot interpret as the type it asked for.
     */
    private void applyTransformation(final Pipe pipe, final Field field, final ValueTransformer transformer)
            throws IOException {
        try {
            switch (field.type) {
                case BOOLEAN:
                    pipe.writeU1(transformer.transformBoolean(pipe.readU1() != 0) ? 1 : 0);
                    break;

                case BYTE:
                    pipe.writeU1(transformer.transformByte((byte) pipe.readU1()));
                    break;

                case CHAR:
                    pipe.writeU2(transformer.transformChar((char) pipe.readU2()));
                    break;

                case SHORT:
                    pipe.writeU2(transformer.transformShort((short) pipe.readU2()));
                    break;

                case INT:
                    pipe.writeU4(transformer.transformInt(pipe.readU4()));
                    break;

                case LONG:
                    pipe.writeU8(transformer.transformLong(pipe.readU8()));
                    break;

                    /*
                     * Raw bits both ways. floatToIntBits collapses every NaN to one canonical NaN, so a
                     * transformer that returns its argument unchanged would still rewrite the bytes of a
                     * signalling NaN -- a value the tool was told to preserve, silently altered. Raw makes
                     * "return value" a genuine no-op for every input.
                     */
                case FLOAT:
                    pipe.writeU4(
                            Float.floatToRawIntBits(transformer.transformFloat(Float.intBitsToFloat(pipe.readU4()))));
                    break;

                case DOUBLE:
                    pipe.writeU8(Double.doubleToRawLongBits(
                            transformer.transformDouble(Double.longBitsToDouble(pipe.readU8()))));
                    break;

                default:
                    // OBJECT is rejected when the decision is made; nothing else exists
                    throw new SanitizationRuleException("Cannot transform " + field.type + " field "
                            + field.declaringClassName() + "#" + field.name);
            }
        } catch (final SanitizationRuleException e) {
            throw e;
        } catch (final RuntimeException e) {
            throw new SanitizationRuleException(
                    "Transformer " + describe(transformer) + " failed on field " + field.declaringClassName() + "#"
                            + field.name,
                    e);
        }
    }

    /*
     * describe() is user code, so a broken implementation must not be what aborts the run -- least of all
     * while building the message for an unrelated failure.
     */
    private static String describe(final ValueTransformer transformer) {
        try {
            final String description = transformer.describe();
            return description == null ? transformer.getClass().getName() : description;
        } catch (final RuntimeException e) {
            return transformer.getClass().getName();
        }
    }
}
