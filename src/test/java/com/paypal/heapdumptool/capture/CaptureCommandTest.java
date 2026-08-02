package com.paypal.heapdumptool.capture;

import com.paypal.heapdumptool.sanitizer.BasicType;
import com.paypal.heapdumptool.utils.DataSize;
import com.paypal.heapdumptool.sanitizer.SanitizationPolicy;
import com.paypal.heapdumptool.sanitizer.SanitizeCommand;
import org.junit.jupiter.api.Test;
import org.meanbean.test.BeanVerifier;
import picocli.CommandLine;

import static org.assertj.core.api.Assertions.assertThat;

public class CaptureCommandTest {

    @Test
    public void testBean() {
        BeanVerifier.forClass(CaptureCommand.class)
                    .withSettings(settings -> settings.addOverridePropertyFactory(CaptureCommand::getBufferSize, () -> DataSize.ofMegabytes(5)))
                    .withSettings(settings -> settings.addIgnoredPropertyName("excludeStringFields"))
                    .withSettings(settings -> settings.addIgnoredPropertyName("sanitizeOptions"))
                    .withSettings(settings -> settings.addIgnoredPropertyName("sanitizationPolicy"))
                    .verifyGettersAndSetters();
    }

    /**
     * capture hands its options to a SanitizeCommand via copyFrom. Directive order, and hence
     * the outcome of interleaved flags, must survive the hand-off.
     */
    @Test
    public void testCopyFromPreservesFlagOrder() {
        final CaptureCommand captureCommand = new CaptureCommand();
        new CommandLine(captureCommand)
                .registerConverter(DataSize.class, DataSize::parse)
                .parseArgs("-s=true", "--target=byte-arrays,char-arrays,int-arrays", "my-container");

        final SanitizeCommand sanitizeCommand = new SanitizeCommand();
        sanitizeCommand.copyFrom(captureCommand);

        final SanitizationPolicy policy = sanitizeCommand.getSanitizationPolicy();
        assertThat(policy.sanitizeArray(BasicType.INT)).isTrue();
        assertThat(policy.sanitizeArray(BasicType.BYTE)).isTrue();
        assertThat(policy.isAnyFieldSanitized()).isFalse();
        assertThat(policy.getWarnings()).hasSize(1);
    }

    /**
     * getSanitizationPolicy resolves on every call, so a policy read before copyFrom must not
     * shadow the directives copied in afterwards.
     */
    @Test
    public void testPolicyReadBeforeCopyFromDoesNotGoStale() {
        final CaptureCommand captureCommand = new CaptureCommand();
        new CommandLine(captureCommand)
                .registerConverter(DataSize.class, DataSize::parse)
                .parseArgs("--target=none", "my-container");

        final SanitizeCommand sanitizeCommand = new SanitizeCommand();
        assertThat(sanitizeCommand.getSanitizationPolicy().isAnyFieldSanitized()).isTrue();

        sanitizeCommand.copyFrom(captureCommand);
        assertThat(sanitizeCommand.getSanitizationPolicy().isAnyFieldSanitized()).isFalse();
    }

}
