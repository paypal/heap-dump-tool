package com.paypal.heapdumptool.fixture;

import javax.management.MBeanServer;

import java.lang.management.ManagementFactory;
import java.lang.reflect.Method;
import java.nio.file.Path;

public class HeapDumper {

    private static final String CLASS_NAME = "com.sun.management.HotSpotDiagnosticMXBean";

    private static final String HOTSPOT_BEAN_NAME = "com.sun.management:type=HotSpotDiagnostic";

    public static void dumpHeap(final Path path) throws Exception {
        dumpHeap(path, false);
    }

    public static void dumpHeap(final Path path, final boolean live) throws Exception {
        final Class<?> clazz = Class.forName(CLASS_NAME);
        final Object mxBean = getHotSpotMxBean(clazz);
        final Method method = clazz.getMethod("dumpHeap", String.class, boolean.class);
        method.invoke(mxBean, path.toString(), live);
    }

    private static <T> T getHotSpotMxBean(final Class<T> clazz) throws Exception {
        final MBeanServer server = ManagementFactory.getPlatformMBeanServer();
        return ManagementFactory.newPlatformMXBeanProxy(server, HOTSPOT_BEAN_NAME, clazz);
    }

    private HeapDumper() {
        throw new AssertionError();
    }
}
