package com.armorauth.autoconfigure;

import com.armorauth.FrameworkEndpointHandlerMapping;
import org.springframework.context.annotation.Bean;

public class FrameworkEndpointConfiguration {

    @Bean
    public FrameworkEndpointHandlerMapping frameworkEndpointHandlerMapping() {
        return new FrameworkEndpointHandlerMapping();
    }

}
