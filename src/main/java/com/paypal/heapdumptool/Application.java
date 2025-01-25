package com.paypal.heapdumptool;

import com.paypal.heapdumptool.Application.VersionProvider;
import com.paypal.heapdumptool.capture.CaptureCommand;
import com.paypal.heapdumptool.capture.PrivilegeEscalator.Escalation;
import com.paypal.heapdumptool.hserr.SanitizeHserrCommand;
import com.paypal.heapdumptool.sanitizer.DataSize;
import com.paypal.heapdumptool.sanitizer.SanitizeCommand;
import com.paypal.heapdumptool.utils.InternalLogger;
import org.apache.commons.text.StringSubstitutor;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.HelpCommand;
import picocli.CommandLine.IVersionProvider;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.Properties;

import static com.paypal.heapdumptool.Application.APP_ID;
import static com.paypal.heapdumptool.capture.PrivilegeEscalator.Escalation.ESCALATED;
import static com.paypal.heapdumptool.capture.PrivilegeEscalator.escalatePrivilegesIfNeeded;
import static org.apache.commons.io.IOUtils.resourceToByteArray;

@Command(name = APP_ID,
        description = "Tool primarily for capturing or sanitizing heap dumps",
        mixinStandardHelpOptions = true,
        versionProvider = VersionProvider.class,
        subcommands = {
                CaptureCommand.class,
                SanitizeCommand.class,
                SanitizeHserrCommand.class,
                HelpCommand.class,
        }
)
public class Application {

    public static final String APP_ID = "heap-dump-tool";

    // Stay with "String[] args". vararg "String... args" causes weird failure with mockito in Java 11
    public static void main(final String[] args) throws Exception {
        final Escalation escalation = escalatePrivilegesIfNeeded(args);
        if (escalation == ESCALATED) {
            return;
        }

        final CommandLine commandLine = new CommandLine(new Application());
        commandLine.setUsageHelpWidth(120);
        commandLine.registerConverter(DataSize.class, DataSize::parse);
        commandLine.setAbbreviatedOptionsAllowed(true);

        final int exitCode = commandLine.execute(args);
        systemExit(exitCode);
    }

    // for mocking
    static void systemExit(final int exitCode) {
        System.exit(exitCode);
    }

    public static class VersionProvider implements IVersionProvider {

        public static void printVersion() throws IOException {
            final String[] versionInfo = new VersionProvider().getVersion();
            InternalLogger.getLogger(Application.class).info(versionInfo[0]);
        }

        @Override
        public String[] getVersion() throws IOException {
            final byte[] bytes = resourceToByteArray("/git-heap-dump-tool.properties");
            final Properties gitProperties = new Properties();
            gitProperties.load(new ByteArrayInputStream(bytes));
            gitProperties.put("appId", APP_ID);

            final String versionInfo = StringSubstitutor.replace(
                    "${appId} (${git.build.version} ${git.commit.id.abbrev}, ${git.commit.time})",
                    gitProperties);
            return new String[]{versionInfo};
        }

    }

}
