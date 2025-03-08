package com.paypal.heapdumptool.sanitizer;

import static org.apache.commons.lang3.builder.ToStringBuilder.reflectionToString;
import static org.apache.commons.lang3.builder.ToStringStyle.MULTI_LINE_STYLE;

public class Field {

    public final String name;
    public final BasicType type;

    public Field(final String name, final BasicType type) {
        this.name = name;
        this.type = type;
    }

    @Override
    public String toString() {
        return reflectionToString(this, MULTI_LINE_STYLE);
    }
}
