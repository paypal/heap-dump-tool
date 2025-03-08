package com.paypal.heapdumptool.sanitizer;

import org.junit.jupiter.api.Test;
import org.meanbean.test.BeanVerifier;

import static com.paypal.heapdumptool.sanitizer.DataSize.ofMegabytes;
import static org.assertj.core.api.Assertions.assertThat;

public class SanitizeCommandTest {

    @Test
    public void testBean() {
        BeanVerifier.forClass(SanitizeCommand.class)
                    .withSettings(settings -> settings.addOverridePropertyFactory(SanitizeCommand::getBufferSize, () -> ofMegabytes(5)))
                    .withSettings(settings -> settings.addIgnoredPropertyName("excludeStringFields"))
                    .verifyGettersAndSetters();
    }

    @Test
    public void testSanitizationText() {
        assertThat(escapedSanitizationText("\\0"))
                .isEqualTo("\0");
        assertThat(escapedSanitizationText("\0"))
                .isEqualTo("\0");

        assertThat(escapedSanitizationText("foobar"))
                .isEqualTo("foobar");
    }

    private String escapedSanitizationText(final String sanitizationText) {
        final SanitizeCommand cmd = new SanitizeCommand();
        cmd.setSanitizationText(sanitizationText);
        return cmd.getSanitizationText();
    }

}
