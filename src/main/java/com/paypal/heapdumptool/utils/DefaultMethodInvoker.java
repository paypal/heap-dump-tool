package com.paypal.heapdumptool.utils;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.MethodHandles;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;

/**
 * Invokes a {@code default} interface method on a {@link java.lang.reflect.Proxy}, which
 * {@link com.paypal.heapdumptool.utils.AbstractInvocationHandler} does not do on its own.
 *
 * <p>{@code java.lang.reflect.Proxy} gained first-class support for this only in JDK 16, as the
 * static {@code InvocationHandler.invokeDefault(Object, Method, Object...)}. This class detects
 * that method once at class load and dispatches through a cached {@link MethodHandle} when it
 * exists. On JDK 9-15 it falls back to {@code MethodHandles.privateLookupIn}, and on JDK 8 -- which
 * the project still compiles for -- to the private {@code Lookup(Class, int)} constructor, accessed
 * reflectively, which yields the full-access lookup that {@code unreflectSpecial} requires on JDK 8
 * ({@code lookup().in(declaring)} only produces package access there, so {@code unreflectSpecial}
 * rejects it with {@code "private access required"}). The older paths are also resolved reflectively
 * at class load, so nothing here references an API newer than the JDK 8 this project builds with.
 *
 * <p>Only ever called with methods whose declaring class is an interface and which have a default
 * body, by the handlers in {@code SanitizationRules} and {@code ValueTransformers}.
 */
public final class DefaultMethodInvoker {

    private static final Object[] NO_ARGS = {};

    /** JDK 16+, null on older JDKs. */
    private static final MethodHandle INVOKE_DEFAULT;

    /** JDK 9-15, null on JDK 8. */
    private static final Method PRIVATE_LOOKUP_IN;

    /** JDK 8 only: the private {@code Lookup(Class, int)} constructor, null when unavailable. */
    private static final Constructor<MethodHandles.Lookup> LOOKUP_CTOR;

    static {
        MethodHandle invokeDefault = null;
        Method privateLookupIn = null;
        try {
            invokeDefault = MethodHandles.lookup()
                    .unreflect(InvocationHandler.class.getMethod(
                            "invokeDefault", Object.class, Method.class, Object[].class));
        } catch (final ReflectiveOperationException e) {
            // JDK 8-15: the method does not exist
        }
        if (invokeDefault == null) {
            try {
                privateLookupIn =
                        MethodHandles.class.getMethod("privateLookupIn", Class.class, MethodHandles.Lookup.class);
            } catch (final ReflectiveOperationException e) {
                // JDK 8: the method does not exist
            }
        }
        Constructor<MethodHandles.Lookup> lookupCtor = null;
        if (invokeDefault == null && privateLookupIn == null) {
            try {
                lookupCtor = MethodHandles.Lookup.class.getDeclaredConstructor(Class.class, int.class);
                lookupCtor.setAccessible(true);
            } catch (final ReflectiveOperationException e) {
                // Some JDK 8 builds restrict this; invoke() falls back to lookup().in(declaring)
            }
        }
        INVOKE_DEFAULT = invokeDefault;
        PRIVATE_LOOKUP_IN = privateLookupIn;
        LOOKUP_CTOR = lookupCtor;
    }

    private DefaultMethodInvoker() {}

    public static Object invoke(final Object proxy, final Method method, final Object[] args) throws Throwable {
        final Object[] invocationArgs = args == null ? NO_ARGS : args;

        if (INVOKE_DEFAULT != null) {
            return INVOKE_DEFAULT.invoke(proxy, method, invocationArgs);
        }

        if (PRIVATE_LOOKUP_IN != null) {
            final MethodHandles.Lookup lookup = (MethodHandles.Lookup)
                    PRIVATE_LOOKUP_IN.invoke(null, method.getDeclaringClass(), MethodHandles.lookup());
            return invokeDefaultMethod(proxy, method, invocationArgs, lookup);
        }

        final MethodHandles.Lookup lookup;
        if (LOOKUP_CTOR != null) {
            try {
                lookup = LOOKUP_CTOR.newInstance(method.getDeclaringClass(), FULL_ACCESS_MODES);
            } catch (final ReflectiveOperationException e) {
                throw new IllegalStateException(e);
            }
        } else {
            lookup = MethodHandles.lookup().in(method.getDeclaringClass());
        }
        return invokeDefaultMethod(proxy, method, invocationArgs, lookup);
    }

    /** {@code PUBLIC | PRIVATE | PROTECTED | PACKAGE}. */
    private static final int FULL_ACCESS_MODES = MethodHandles.Lookup.PUBLIC
            | MethodHandles.Lookup.PRIVATE
            | MethodHandles.Lookup.PROTECTED
            | MethodHandles.Lookup.PACKAGE;

    private static Object invokeDefaultMethod(
            final Object proxy, final Method method, final Object[] args, final MethodHandles.Lookup lookup)
            throws Throwable {
        return lookup.unreflectSpecial(method, method.getDeclaringClass())
                .bindTo(proxy)
                .invokeWithArguments(args);
    }
}
