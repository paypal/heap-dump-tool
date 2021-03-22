package com.paypal.heapdumptool.utils;

import java.util.concurrent.Callable;

public class CallableTool {

    public static <T> T callQuietlyWithDefault(final T defaultValue, final Callable<T> callable) {
        try {
            return callable.call();
        } catch (final Exception ignore) {
            return defaultValue;
        }
    }

    private CallableTool() {
        throw new AssertionError();
    }
}
