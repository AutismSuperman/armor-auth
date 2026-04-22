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
package com.armorauth.federation.provider.common;

import com.armorauth.federation.provider.FederatedOAuth2Provider;
import com.armorauth.federation.provider.FederatedOAuth2ProviderRegistry;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.client.registration.ClientRegistration;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class CommonFederatedOAuth2ProviderConfigurationTest {

    private final CommonFederatedOAuth2ProviderConfiguration configuration =
            new CommonFederatedOAuth2ProviderConfiguration();

    private final FederatedOAuth2ProviderRegistry providerRegistry = new FederatedOAuth2ProviderRegistry(
            List.of(
                    configuration.microsoftFederatedOAuth2Provider(),
                    configuration.gitlabFederatedOAuth2Provider(),
                    configuration.discordFederatedOAuth2Provider(),
                    configuration.slackFederatedOAuth2Provider(),
                    configuration.linkedinFederatedOAuth2Provider(),
                    configuration.appleFederatedOAuth2Provider(),
                    configuration.weiboFederatedOAuth2Provider(),
                    configuration.baiduFederatedOAuth2Provider(),
                    configuration.oschinaFederatedOAuth2Provider()
            )
    );

    @Test
    void shouldRegisterCommonFederatedProviders() {
        assertThat(providerRegistry.findProvider("microsoft")).isPresent();
        assertThat(providerRegistry.findProvider("gitlab")).isPresent();
        assertThat(providerRegistry.findProvider("discord")).isPresent();
        assertThat(providerRegistry.findProvider("slack")).isPresent();
        assertThat(providerRegistry.findProvider("linkedin")).isPresent();
        assertThat(providerRegistry.findProvider("apple")).isPresent();
        assertThat(providerRegistry.findProvider("weibo")).isPresent();
        assertThat(providerRegistry.findProvider("baidu")).isPresent();
        assertThat(providerRegistry.findProvider("oschina")).isPresent();
    }

    @Test
    void shouldBuildCommonClientRegistrationMetadata() {
        List<String> providerIds = List.of(
                "microsoft",
                "gitlab",
                "discord",
                "slack",
                "linkedin",
                "apple",
                "weibo",
                "baidu",
                "oschina"
        );
        for (String providerId : providerIds) {
            ClientRegistration registration = providerRegistry.findProvider(providerId)
                    .orElseThrow()
                    .getBuilder(providerId)
                    .clientId("client-id")
                    .clientSecret("client-secret")
                    .build();
            assertThat(registration.getRegistrationId()).isEqualTo(providerId);
        }

        FederatedOAuth2Provider microsoft = providerRegistry.findProvider("microsoft").orElseThrow();
        ClientRegistration registration = microsoft.getBuilder("microsoft")
                .clientId("client-id")
                .clientSecret("client-secret")
                .build();
        assertThat(registration.getClientName()).isEqualTo("Microsoft");
        assertThat(registration.getProviderDetails().getAuthorizationUri())
                .isEqualTo("https://login.microsoftonline.com/common/oauth2/v2.0/authorize");
        assertThat(registration.getProviderDetails().getUserInfoEndpoint().getUserNameAttributeName())
                .isEqualTo("sub");
    }

    @Test
    void shouldUseQueryParameterUserServiceForDomesticProviders() {
        assertThat(providerRegistry.findProvider("weibo").orElseThrow().getOAuth2UserService())
                .isInstanceOf(QueryParameterOAuth2UserService.class);
        assertThat(providerRegistry.findProvider("baidu").orElseThrow().getOAuth2UserService())
                .isInstanceOf(QueryParameterOAuth2UserService.class);
        assertThat(providerRegistry.findProvider("oschina").orElseThrow().getOAuth2UserService())
                .isInstanceOf(QueryParameterOAuth2UserService.class);
    }

}
