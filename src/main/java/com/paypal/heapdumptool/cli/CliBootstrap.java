package com.paypal.heapdumptool.cli;

import com.paypal.heapdumptool.Application.VersionProvider;

import static org.apache.commons.lang3.reflect.ConstructorUtils.invokeConstructor;

public class CliBootstrap {

    public static <T extends CliCommand> boolean runCommand(final T command) throws Exception {

        VersionProvider.printVersion();

        final Class<? extends CliCommandProcessor> clazz = command.getProcessorClass();
        final CliCommandProcessor processor = invokeConstructor(clazz, command);

        processor.process();

        return true;
    }

    private CliBootstrap() {
        throw new AssertionError();
    }
}
