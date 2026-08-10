package com.paypal.heapdumptool.utils;

import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Verifies that {@link DefaultMethodInvoker} dispatches to {@code default} interface method bodies on
 * whatever JDK the tests happen to run on. The implementation has three arms -- JDK 16+
 * {@code InvocationHandler.invokeDefault}, the JDK 9-15 {@code privateLookupIn} path, and the JDK 8
 * recipe -- and this test is what keeps the other two alive after each is written.
 */
class DefaultMethodInvokerTest {

    @FunctionalInterface
    private interface HasDefaults {

        default int defaultValue() {
            return 42;
        }

        default int addOne(final int value) {
            return value + 1;
        }

        default int doubleAbstract() {
            return abstractMethod() * 2;
        }

        int abstractMethod();
    }

    /** Routes every default method to its interface body; a proxy's abstract method is not expected. */
    private static class DispatchToDefaultsHandler extends AbstractInvocationHandler {

        @Override
        protected Object handleInvocation(final Object proxy, final Method method, final Object[] args)
                throws Throwable {
            if (method.getDeclaringClass().isInterface() && method.isDefault()) {
                return DefaultMethodInvoker.invoke(proxy, method, args);
            }
            throw new UnsupportedOperationException("unexpected method " + method);
        }
    }

    @Test
    @DisplayName("testDefaultMethodBodyRunsOnTheProxy. The default implementation executes, on any JDK")
    void testDefaultMethodBodyRunsOnTheProxy() {
        final HasDefaults proxy = newProxy();

        assertThat(proxy.defaultValue())
                .as("the interface's default body, not a throw from the handler")
                .isEqualTo(42);
    }

    @Test
    @DisplayName("testArgumentsReachTheDefaultBody. Primitive arguments are boxed and unboxed correctly")
    void testArgumentsReachTheDefaultBody() {
        final HasDefaults proxy = newProxy();

        assertThat(proxy.addOne(41)).isEqualTo(42);
    }

    @Test
    @DisplayName("testDefaultBodyCanCallAbstractMethods. The default body runs as though on a real instance")
    void testDefaultBodyCanCallAbstractMethods() {
        /*
         * This is the harder case a plain Method.invoke cannot handle: a default body that calls
         * another method of the interface must dispatch back into the proxy, exactly as on a real
         * instance.
         */
        final HasDefaults proxy = (HasDefaults) Proxy.newProxyInstance(
                getClass().getClassLoader(), new Class<?>[] {HasDefaults.class}, new DispatchToDefaultsHandler() {
                    @Override
                    protected Object handleInvocation(final Object proxy, final Method method, final Object[] args)
                            throws Throwable {
                        if ("abstractMethod".equals(method.getName())) {
                            return 7;
                        }
                        return super.handleInvocation(proxy, method, args);
                    }
                });

        assertThat(proxy.doubleAbstract())
                .as("the default body's call to the abstract method dispatched back into the proxy: 7 * 2")
                .isEqualTo(14);
        assertThat(proxy.defaultValue()).isEqualTo(42);
    }

    private static HasDefaults newProxy() {
        return (HasDefaults) Proxy.newProxyInstance(
                DefaultMethodInvokerTest.class.getClassLoader(),
                new Class<?>[] {HasDefaults.class},
                new DispatchToDefaultsHandler());
    }
}
