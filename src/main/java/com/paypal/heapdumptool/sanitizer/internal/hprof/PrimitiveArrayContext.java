package com.paypal.heapdumptool.sanitizer.internal.hprof;

import com.paypal.heapdumptool.sanitizer.ArrayContext;
import com.paypal.heapdumptool.sanitizer.BasicType;

/*
 * Allocated per array record, not per element, and only when a rule chain is registered. A default
 * run never constructs one.
 */
public final class PrimitiveArrayContext implements ArrayContext {

    private final long objectId;
    private final BasicType elementType;
    private final long numElements;
    private final long numBytes;

    public PrimitiveArrayContext(
            final long objectId, final BasicType elementType, final long numElements, final long numBytes) {
        this.objectId = objectId;
        this.elementType = elementType;
        this.numElements = numElements;
        this.numBytes = numBytes;
    }

    @Override
    public long objectId() {
        return objectId;
    }

    @Override
    public BasicType elementType() {
        return elementType;
    }

    @Override
    public long numElements() {
        return numElements;
    }

    @Override
    public long numBytes() {
        return numBytes;
    }
}
