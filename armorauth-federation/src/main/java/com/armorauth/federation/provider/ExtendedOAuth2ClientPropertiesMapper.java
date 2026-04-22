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
package com.armorauth.federation.provider;

import org.springframework.boot.security.oauth2.client.autoconfigure.OAuth2ClientProperties;
import org.springframework.boot.security.oauth2.client.autoconfigure.OAuth2ClientProperties.Provider;
import org.springframework.security.config.oauth2.client.CommonOAuth2Provider;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrations;
import org.springframework.security.oauth2.core.AuthenticationMethod;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.util.StringUtils;

import java.util.LinkedHashMap;
import java.util.Map;

public final class ExtendedOAuth2ClientPropertiesMapper {

    private final OAuth2ClientProperties properties;

    private final FederatedOAuth2ProviderRegistry providerRegistry;

    public ExtendedOAuth2ClientPropertiesMapper(
            OAuth2ClientProperties properties,
            FederatedOAuth2ProviderRegistry providerRegistry) {
        this.properties = properties;
        this.providerRegistry = providerRegistry;
    }

    public Map<String, ClientRegistration> asClientRegistrations() {
        Map<String, ClientRegistration> clientRegistrations = new LinkedHashMap<>();
        this.properties.getRegistration().forEach((key, value) ->
                clientRegistrations.put(key, getClientRegistration(key, value, this.properties.getProvider())));
        return clientRegistrations;
    }

    private ClientRegistration getClientRegistration(
            String registrationId,
            OAuth2ClientProperties.Registration properties,
            Map<String, Provider> providers) {
        ClientRegistration.Builder builder = getBuilderFromIssuerIfPossible(registrationId, properties.getProvider(), providers);
        if (builder == null) {
            builder = getBuilder(registrationId, properties.getProvider(), providers);
        }
        if (properties.getClientId() != null) {
            builder.clientId(properties.getClientId());
        }
        if (properties.getClientSecret() != null) {
            builder.clientSecret(properties.getClientSecret());
        }
        if (properties.getClientAuthenticationMethod() != null) {
            builder.clientAuthenticationMethod(new ClientAuthenticationMethod(properties.getClientAuthenticationMethod()));
        }
        if (properties.getAuthorizationGrantType() != null) {
            builder.authorizationGrantType(new AuthorizationGrantType(properties.getAuthorizationGrantType()));
        }
        if (properties.getRedirectUri() != null) {
            builder.redirectUri(properties.getRedirectUri());
        }
        if (properties.getScope() != null) {
            builder.scope(StringUtils.toStringArray(properties.getScope()));
        }
        if (properties.getClientName() != null) {
            builder.clientName(properties.getClientName());
        }
        return builder.build();
    }

    private static ClientRegistration.Builder getBuilderFromIssuerIfPossible(
            String registrationId,
            String configuredProviderId,
            Map<String, Provider> providers) {
        String providerId = configuredProviderId != null ? configuredProviderId : registrationId;
        if (!providers.containsKey(providerId)) {
            return null;
        }
        Provider provider = providers.get(providerId);
        if (!StringUtils.hasText(provider.getIssuerUri())) {
            return null;
        }
        ClientRegistration.Builder builder = ClientRegistrations
                .fromIssuerLocation(provider.getIssuerUri())
                .registrationId(registrationId);
        return applyProviderOverrides(builder, provider);
    }

    private ClientRegistration.Builder getBuilder(
            String registrationId,
            String configuredProviderId,
            Map<String, Provider> providers) {
        String providerId = configuredProviderId != null ? configuredProviderId : registrationId;
        ClientRegistration.Builder builder = this.providerRegistry.findProvider(providerId)
                .map(provider -> provider.getBuilder(registrationId))
                .orElseGet(() -> {
                    CommonOAuth2Provider commonProvider = getCommonOAuth2Provider(providerId);
                    if (commonProvider != null) {
                        return commonProvider.getBuilder(registrationId);
                    }
                    if (providers.containsKey(providerId)) {
                        return ClientRegistration.withRegistrationId(registrationId);
                    }
                    throw new IllegalStateException(getErrorMessage(configuredProviderId, registrationId));
                });
        if (providers.containsKey(providerId)) {
            return applyProviderOverrides(builder, providers.get(providerId));
        }
        return builder;
    }

    private static ClientRegistration.Builder applyProviderOverrides(
            ClientRegistration.Builder builder,
            Provider provider) {
        if (provider.getAuthorizationUri() != null) {
            builder.authorizationUri(provider.getAuthorizationUri());
        }
        if (provider.getTokenUri() != null) {
            builder.tokenUri(provider.getTokenUri());
        }
        if (provider.getUserInfoUri() != null) {
            builder.userInfoUri(provider.getUserInfoUri());
        }
        if (provider.getUserInfoAuthenticationMethod() != null) {
            builder.userInfoAuthenticationMethod(new AuthenticationMethod(provider.getUserInfoAuthenticationMethod()));
        }
        if (provider.getJwkSetUri() != null) {
            builder.jwkSetUri(provider.getJwkSetUri());
        }
        if (provider.getUserNameAttribute() != null) {
            builder.userNameAttributeName(provider.getUserNameAttribute());
        }
        return builder;
    }

    private static CommonOAuth2Provider getCommonOAuth2Provider(String providerId) {
        for (CommonOAuth2Provider provider : CommonOAuth2Provider.values()) {
            if (provider.name().equalsIgnoreCase(providerId)) {
                return provider;
            }
        }
        return null;
    }

    private static String getErrorMessage(String configuredProviderId, String registrationId) {
        return configuredProviderId != null
                ? "Unknown provider ID '" + configuredProviderId + "'"
                : "Provider ID must be specified for client registration '" + registrationId + "'";
    }

}
