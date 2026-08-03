package com.paypal.heapdumptool.sanitizer;

/**
 * The field a {@link SanitizationRule} is being asked about.
 *
 * <p>Everything here is fixed for the life of a class layout, which is what lets a verdict be
 * resolved once per field declaration and reused for every instance of the class. Deliberately absent
 * is the <em>instance's</em> class: a verdict that varied by instance class could not be memoized per
 * field and would reintroduce a map lookup on the hottest path in the tool.</p>
 */
public interface FieldContext {

    /** The class that declares this field, not the class of the instance being read. */
    String declaringClassName();

    String fieldName();

    BasicType type();

    boolean isStatic();
}
