package com.paypal.heapdumptool.sanitizer;

public class Field {

    private final String fieldName;
    private final BasicType fieldType;

    public Field(final String fieldName, final BasicType fieldType) {
        this.fieldName = fieldName;
        this.fieldType = fieldType;
    }

    public String getFieldName() {
        return fieldName;
    }

    public BasicType getFieldType() {
        return fieldType;
    }

    @Override
    public String toString() {
        return "Field{" +
                "fieldName='" + fieldName + '\'' +
                ", fieldType=" + fieldType +
                '}';
    }
}
