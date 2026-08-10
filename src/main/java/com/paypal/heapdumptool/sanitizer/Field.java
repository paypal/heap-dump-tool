package com.paypal.heapdumptool.sanitizer;

import static org.apache.commons.lang3.builder.ToStringBuilder.reflectionToString;
import static org.apache.commons.lang3.builder.ToStringStyle.MULTI_LINE_STYLE;

/**
 * One field declaration from a class dump.
 *
 * <p>Also serves as its own {@link FieldContext}: everything a rule is allowed to decide from is fixed
 * for the life of the declaration, so handing the rule this object avoids allocating a context per
 * field of every instance dump -- the hottest path in the tool.</p>
 */
public class Field implements FieldContext {

    public final String name;
    public final BasicType type;

    private final String declaringClassName;
    private final boolean isStatic;

    /*
     * The rule chain's verdict for this declaration, computed on first use and reused for every
     * instance of the class. Null means "not yet asked", which is distinct from Decision.undecided()
     * meaning "asked, and every rule abstained" -- without that distinction a field no rule matches
     * would re-consult the whole chain for every instance.
     *
     * Safe to memoize because a verdict depends only on the fields of this object, all final, and
     * because both passes of a run share one ClassObject map and so one Field per declaration.
     */
    private Decision resolved;

    public Field(final String name, final BasicType type) {
        this(name, type, "", false);
    }

    public Field(final String name, final BasicType type, final String declaringClassName, final boolean isStatic) {
        this.name = name;
        this.type = type;
        this.declaringClassName = declaringClassName;
        this.isStatic = isStatic;
    }

    @Override
    public String declaringClassName() {
        return declaringClassName;
    }

    @Override
    public String fieldName() {
        return name;
    }

    @Override
    public BasicType type() {
        return type;
    }

    @Override
    public boolean isStatic() {
        return isStatic;
    }

    /**
     * This declaration's verdict, asking the rule chain only the first time.
     */
    Decision resolvedDecision(final SanitizationRuleRegistry rules) {
        if (resolved == null) {
            resolved = rules.decideField(this);
        }
        return resolved;
    }

    @Override
    public String toString() {
        return reflectionToString(this, MULTI_LINE_STYLE);
    }
}
