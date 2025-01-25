package com.paypal.heapdumptool.utils;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.spi.SLF4JServiceProvider;

import java.io.PrintStream;
import java.time.OffsetDateTime;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.ServiceLoader;

// class to make slf4j impl work when heap-dump-tool is used as a library or when used as an app without slf4j impl
public class InternalLogger {

    private static final int DEBUG_INT = 10;

    private static final int INFO_INT = 20;

    private static final boolean hasSlf4jImpl = hasSelf4jImpl();

    private static final int level = Integer.getInteger("heap-dump-tool.logLevel", INFO_INT);

    private static final DateTimeFormatter dateTimeFormatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss,SSS");

    private final PrintStream out = System.out;

    private final String clazz;

    private Logger logger;

    public InternalLogger(final Class<?> clazz) {
        this.clazz = clazz.getSimpleName();
    }

    private static boolean hasSelf4jImpl() {
        final ClassLoader classLoader = Thread.currentThread().getContextClassLoader() != null
                ? Thread.currentThread().getContextClassLoader()
                : InternalLogger.class.getClassLoader();
        final String explicitlySpecified = System.getProperty("slf4j.provider");
        if (explicitlySpecified != null && !explicitlySpecified.isEmpty()) {
            return true;
        }
        final ServiceLoader<SLF4JServiceProvider> loader = ServiceLoader.load(SLF4JServiceProvider.class, classLoader);
        return loader.iterator().hasNext();
    }

    public static InternalLogger getLogger(final Class<?> clazz) {
        return new InternalLogger(clazz);
    }

    private synchronized Logger getLogger() {
        if (logger == null) {
            logger = LoggerFactory.getLogger(clazz);
        }
        return logger;
    }

    public void info(final String format, final Object... arguments) {
        if (hasSlf4jImpl) {
            getLogger().info(format, arguments);
        } else if (level <= INFO_INT) {
            final String message = getMessage(format, arguments);
            out.printf("%s INFO  %s - %s%n", getTimestamp(), clazz, message);
        }
    }

    public void debug(final String format, final Object... arguments) {
        if (hasSlf4jImpl) {
            getLogger().debug(format, arguments);
        } else if (level <= DEBUG_INT) {
            final String message = getMessage(format, arguments);
            out.printf("%s DEBUG %s - %s%n", getTimestamp(), clazz, message);
        }
    }

    private static String getMessage(final String format, final Object[] arguments) {
        final String newFormat = format.replace("{}", "%s");
        return String.format(newFormat, arguments);
    }

    private static String getTimestamp() {
        return dateTimeFormatter.format(OffsetDateTime.now().truncatedTo(ChronoUnit.MILLIS));
    }
}
