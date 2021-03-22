package com.paypal.heapdumptool.cli;

import java.util.concurrent.Callable;

public interface CliCommand extends Callable<Boolean> {

    @Override
    default Boolean call() throws Exception {
        return CliBootstrap.runCommand(this);
    }

    Class<? extends CliCommandProcessor> getProcessorClass();

}
