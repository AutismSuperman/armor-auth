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
package com.armorauth.federation;

import com.armorauth.federation.provider.FederatedOAuth2ProviderRegistry;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestRedirectFilter;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.web.WebAttributes;
import org.springframework.util.Assert;

public class DelegatingOAuth2AuthorizationRequestResolver implements OAuth2AuthorizationRequestResolver {

    private final DefaultOAuth2AuthorizationRequestResolver delegate;

    private final FederatedSessionContextRepository sessionContextRepository;

    private final FederatedLoginMode defaultLoginMode;

    private final FederatedOAuth2ProviderRegistry providerRegistry;

    public DelegatingOAuth2AuthorizationRequestResolver(
            ClientRegistrationRepository clientRegistrationRepository,
            String authorizationRequestBaseUri,
            FederatedSessionContextRepository sessionContextRepository,
            FederatedLoginMode defaultLoginMode,
            FederatedOAuth2ProviderRegistry providerRegistry) {
        Assert.notNull(clientRegistrationRepository, "clientRegistrationRepository cannot be null");
        Assert.notNull(sessionContextRepository, "sessionContextRepository cannot be null");
        Assert.notNull(providerRegistry, "providerRegistry cannot be null");
        String baseUri = authorizationRequestBaseUri != null
                ? authorizationRequestBaseUri
                : OAuth2AuthorizationRequestRedirectFilter.DEFAULT_AUTHORIZATION_REQUEST_BASE_URI;
        this.sessionContextRepository = sessionContextRepository;
        this.defaultLoginMode = defaultLoginMode != null ? defaultLoginMode : FederatedLoginMode.AUTO;
        this.providerRegistry = providerRegistry;
        this.delegate = new DefaultOAuth2AuthorizationRequestResolver(clientRegistrationRepository, baseUri);
        this.delegate.setAuthorizationRequestCustomizer(this::authorizationRequestCustomizer);
    }

    @Override
    public OAuth2AuthorizationRequest resolve(HttpServletRequest request) {
        return rememberAuthorizationContext(request, this.delegate.resolve(request));
    }

    @Override
    public OAuth2AuthorizationRequest resolve(HttpServletRequest request, String clientRegistrationId) {
        return rememberAuthorizationContext(request, this.delegate.resolve(request, clientRegistrationId));
    }

    void authorizationRequestCustomizer(OAuth2AuthorizationRequest.Builder builder) {
        builder.attributes(attributes -> {
            String registrationId = (String) attributes.get(OAuth2ParameterNames.REGISTRATION_ID);
            this.providerRegistry.findProvider(registrationId)
                    .map(provider -> provider.getAuthorizationRequestConverter())
                    .filter(converter -> converter != null)
                    .ifPresent(converter -> converter.convert(builder));
        });
    }

    private OAuth2AuthorizationRequest rememberAuthorizationContext(
            HttpServletRequest request,
            OAuth2AuthorizationRequest authorizationRequest) {
        if (authorizationRequest == null) {
            return null;
        }
        try {
            FederatedLoginMode mode =
                    FederatedLoginMode.resolveForAuthorization(request.getParameter("mode"), this.defaultLoginMode);
            String registrationId = authorizationRequest.getAttribute(OAuth2ParameterNames.REGISTRATION_ID);
            this.sessionContextRepository.saveAuthorizationContext(
                    request,
                    new FederatedAuthorizationContext(
                            registrationId,
                            mode,
                            request.getRequestURI() + (request.getQueryString() != null ? "?" + request.getQueryString() : ""),
                            System.currentTimeMillis()
                    )
            );
            this.sessionContextRepository.clearPendingContext(request);
            return authorizationRequest;
        } catch (IllegalArgumentException ex) {
            this.sessionContextRepository.clearAll(request);
            request.getSession(true)
                    .setAttribute(WebAttributes.AUTHENTICATION_EXCEPTION, new BadCredentialsException(ex.getMessage(), ex));
            throw ex;
        }
    }

}
