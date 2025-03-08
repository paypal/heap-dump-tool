package com.paypal.heapdumptool.sanitizer;

import java.util.ArrayList;
import java.util.List;

import static org.apache.commons.lang3.builder.ToStringBuilder.reflectionToString;
import static org.apache.commons.lang3.builder.ToStringStyle.MULTI_LINE_STYLE;

public class ClassObject {

    public final long id;
    public final long superClassObjectId;
    public final List<Field> fields = new ArrayList<>();

    public ClassObject(final long id, final long superClassObjectId) {
        this.id = id;
        this.superClassObjectId = superClassObjectId;
    }

    @Override
    public String toString() {
        return reflectionToString(this, MULTI_LINE_STYLE);
    }
}
