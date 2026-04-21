/*
 * Copyright (c) 2023-present ArmorAuth. All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.armorauth.federation.config;

import com.armorauth.config.ArmorAuthSecurityCustomizer;
import com.armorauth.federation.FederatedLoginOrchestrator;
import com.armorauth.federation.provider.ExtendedOAuth2ClientPropertiesMapper;
import com.armorauth.federation.provider.FederatedOAuth2ProviderRegistry;
import com.armorauth.federation.configurer.OAuth2FederatedLoginServerConfigurer;
import com.armorauth.federation.security.FederatedAuthenticationSuccessHandler;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.security.oauth2.client.autoconfigure.OAuth2ClientProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.oauth2.client.JdbcOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.savedrequest.RequestCache;

import java.util.Collections;
import java.util.Map;

@Configuration(proxyBeanMethods = false)
@EnableConfigurationProperties(OAuth2ClientProperties.class)
public class FederationConfiguration {

    @Bean
    @Primary
    public FederatedAuthenticationSuccessHandler federatedAuthenticationSuccessHandler(
            RequestCache requestCache,
            FederatedLoginOrchestrator federatedLoginOrchestrator) {
        FederatedAuthenticationSuccessHandler successHandler =
                new FederatedAuthenticationSuccessHandler("/", requestCache);
        successHandler.setFederatedLoginOrchestrator(federatedLoginOrchestrator);
        return successHandler;
    }

    @Bean
    public ClientRegistrationRepository clientRegistrationRepository(
            @Autowired(required = false) OAuth2ClientProperties properties,
            FederatedOAuth2ProviderRegistry providerRegistry) {
        if (properties == null || properties.getRegistration().isEmpty()) {
            return new InMemoryClientRegistrationRepository(Collections.emptyList());
        }
        ExtendedOAuth2ClientPropertiesMapper propertiesMapper =
                new ExtendedOAuth2ClientPropertiesMapper(properties, providerRegistry);
        Map<String, ClientRegistration> clientRegistrations = propertiesMapper.asClientRegistrations();
        return new InMemoryClientRegistrationRepository(clientRegistrations);
    }

    @Bean
    public OAuth2AuthorizedClientService authorizedClientService(
            JdbcTemplate jdbcTemplate,
            ClientRegistrationRepository clientRegistrationRepository) {
        return new JdbcOAuth2AuthorizedClientService(jdbcTemplate, clientRegistrationRepository);
    }

    @Bean
    public ArmorAuthSecurityCustomizer federationSecurityCustomizer(FederationProperties federationProperties) {
        return http -> {
            if (!federationProperties.isEnabled()) {
                return;
            }
            http.with(new OAuth2FederatedLoginServerConfigurer(), federatedLogin ->
                    federatedLogin.federatedAuthorization(federatedAuthorization ->
                            federatedAuthorization.loginPageUrl("/login")));
        };
    }

}
