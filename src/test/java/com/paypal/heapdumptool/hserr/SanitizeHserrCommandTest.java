package com.paypal.heapdumptool.hserr;

import org.junit.jupiter.api.Test;
import org.meanbean.test.BeanVerifier;

import static org.assertj.core.api.Assertions.assertThat;

public class SanitizeHserrCommandTest {
    
    @Test
    public void testBean() {
        BeanVerifier.forClass(SanitizeHserrCommand.class)
                    .verifyGettersAndSetters()
                    .verifyToString();
        
        assertThat(new SanitizeHserrCommand().getProcessorClass())
                .isEqualTo(SanitizeHserrCommandProcessor.class);
    }
    
}

