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
package com.armorauth.federat;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.web.WebAttributes;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class DelegatingOAuth2AuthorizationRequestResolverTest {

    @Test
    void shouldStoreConfirmModeIntoSession() {
        FederatedSessionContextRepository sessionContextRepository = new FederatedSessionContextRepository();
        DelegatingOAuth2AuthorizationRequestResolver resolver = new DelegatingOAuth2AuthorizationRequestResolver(
                new InMemoryClientRegistrationRepository(clientRegistration()),
                "/oauth2/authorization",
                sessionContextRepository
        );
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/oauth2/authorization/gitee");
        request.addParameter("mode", "confirm");
        request.setServletPath("/oauth2/authorization/gitee");
        request.setScheme("http");
        request.setServerName("armorauth-server");
        request.setServerPort(9000);

        OAuth2AuthorizationRequest authorizationRequest = resolver.resolve(request);

        assertThat(authorizationRequest).isNotNull();
        FederatedAuthorizationContext context = sessionContextRepository.loadAuthorizationContext(request).orElseThrow();
        assertThat(context.registrationId()).isEqualTo("gitee");
        assertThat(context.mode()).isEqualTo(FederatedLoginMode.CONFIRM);
    }

    @Test
    void shouldDefaultMissingModeToAuto() {
        FederatedSessionContextRepository sessionContextRepository = new FederatedSessionContextRepository();
        DelegatingOAuth2AuthorizationRequestResolver resolver = new DelegatingOAuth2AuthorizationRequestResolver(
                new InMemoryClientRegistrationRepository(clientRegistration()),
                "/oauth2/authorization",
                sessionContextRepository
        );
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/oauth2/authorization/gitee");
        request.setServletPath("/oauth2/authorization/gitee");
        request.setScheme("http");
        request.setServerName("armorauth-server");
        request.setServerPort(9000);

        resolver.resolve(request);

        FederatedAuthorizationContext context = sessionContextRepository.loadAuthorizationContext(request).orElseThrow();
        assertThat(context.mode()).isEqualTo(FederatedLoginMode.AUTO);
    }

    @Test
    void shouldRejectInvalidMode() {
        FederatedSessionContextRepository sessionContextRepository = new FederatedSessionContextRepository();
        DelegatingOAuth2AuthorizationRequestResolver resolver = new DelegatingOAuth2AuthorizationRequestResolver(
                new InMemoryClientRegistrationRepository(clientRegistration()),
                "/oauth2/authorization",
                sessionContextRepository
        );
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/oauth2/authorization/gitee");
        request.addParameter("mode", "unexpected");
        request.setServletPath("/oauth2/authorization/gitee");
        request.setScheme("http");
        request.setServerName("armorauth-server");
        request.setServerPort(9000);

        assertThatThrownBy(() -> resolver.resolve(request))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("联合登录模式");
        assertThat(request.getSession(false)).isNotNull();
        assertThat(request.getSession(false).getAttribute(WebAttributes.AUTHENTICATION_EXCEPTION))
                .isInstanceOf(BadCredentialsException.class);
    }

    private ClientRegistration clientRegistration() {
        return ClientRegistration.withRegistrationId("gitee")
                .clientId("client-id")
                .clientSecret("client-secret")
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
                .authorizationUri("https://example.com/oauth/authorize")
                .tokenUri("https://example.com/oauth/token")
                .userInfoUri("https://example.com/userinfo")
                .userNameAttributeName("id")
                .scope("user:info")
                .clientName("Gitee")
                .build();
    }
}
