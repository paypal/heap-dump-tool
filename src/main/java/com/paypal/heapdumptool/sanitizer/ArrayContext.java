package com.paypal.heapdumptool.sanitizer;

/**
 * The primitive array a {@link SanitizationRule} is being asked about.
 *
 * <p>Consulted once per {@code PRIMITIVE_ARRAY_DUMP} rather than per element. A verdict cannot be
 * memoized the way a field's can, since it may depend on the array itself, so rules that only decide
 * fields are skipped here entirely.</p>
 */
public interface ArrayContext {

    /**
     * The array object's id in the heap dump.
     *
     * <p>In chunked mode, the same {@code ArrayContext} and the same {@code objectId()} is
     * passed to ValueTransformer when processing every chunk of one array, in order.
     */
    long objectId();

    BasicType elementType();

    long numElements();

    /** Total size of the element region, i.e. {@link #numElements()} times the element width. */
    long numBytes();
}
