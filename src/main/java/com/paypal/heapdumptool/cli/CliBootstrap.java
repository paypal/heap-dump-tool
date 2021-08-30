package com.paypal.heapdumptool.cli;

import com.paypal.heapdumptool.Application.VersionProvider;
import org.apache.commons.lang3.exception.ExceptionUtils;

import java.lang.reflect.InvocationTargetException;

import static org.apache.commons.lang3.reflect.ConstructorUtils.invokeConstructor;

public class CliBootstrap {

    public static <T extends CliCommand> boolean runCommand(final T command) throws Exception {

        VersionProvider.printVersion();

        final Class<? extends CliCommandProcessor> clazz = command.getProcessorClass();
        try {
            final CliCommandProcessor processor = invokeConstructor(clazz, command);

            processor.process();
        } catch (final InvocationTargetException e) {
            if (e.getCause() != null) {
                ExceptionUtils.rethrow(e.getCause());
            }
            throw e;
        }

        return true;
    }

    private CliBootstrap() {
        throw new AssertionError();
    }
}
