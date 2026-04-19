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

import org.springframework.boot.convert.ApplicationConversionService;
import org.springframework.boot.security.oauth2.client.autoconfigure.OAuth2ClientProperties;
import org.springframework.boot.security.oauth2.client.autoconfigure.OAuth2ClientProperties.Provider;
import org.springframework.core.convert.ConversionException;
import org.springframework.security.config.oauth2.client.CommonOAuth2Provider;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistration.Builder;
import org.springframework.security.oauth2.client.registration.ClientRegistrations;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthenticationMethod;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.util.StringUtils;

import java.util.HashMap;
import java.util.Map;

/**
 * Maps {@link OAuth2ClientProperties} to {@link ClientRegistration ClientRegistrations}.
 * Extended Spring Boot OAuth2 client properties mapper.
 *
 * @author AutismSuperman
 * @see InMemoryClientRegistrationRepository
 */
public final class ExtendedOAuth2ClientPropertiesMapper {

    private final OAuth2ClientProperties properties;

    public ExtendedOAuth2ClientPropertiesMapper(OAuth2ClientProperties properties) {
        this.properties = properties;
    }

    public Map<String, ClientRegistration> asClientRegistrations() {
        Map<String, ClientRegistration> clientRegistrations = new HashMap<>();
        this.properties.getRegistration().forEach((key, value) ->
                clientRegistrations.put(key, getClientRegistration(key, value, this.properties.getProvider())));
        return clientRegistrations;
    }

    private static ClientRegistration getClientRegistration(
            String registrationId,
            OAuth2ClientProperties.Registration properties,
            Map<String, Provider> providers) {
        Builder builder = getBuilderFromIssuerIfPossible(registrationId, properties.getProvider(), providers);
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

    private static Builder getBuilderFromIssuerIfPossible(
            String registrationId,
            String configuredProviderId,
            Map<String, Provider> providers) {
        String providerId = (configuredProviderId != null) ? configuredProviderId : registrationId;
        if (providers.containsKey(providerId)) {
            Provider provider = providers.get(providerId);
            String issuer = provider.getIssuerUri();
            if (issuer != null) {
                Builder builder = ClientRegistrations.fromIssuerLocation(issuer).registrationId(registrationId);
                return getBuilder(builder, provider);
            }
        }
        return null;
    }

    private static Builder getBuilder(
            String registrationId,
            String configuredProviderId,
            Map<String, Provider> providers) {
        String providerId = (configuredProviderId != null) ? configuredProviderId : registrationId;
        ExtendedOAuth2ClientProvider extendedProvider = getExtendedOAuth2Provider(providerId);
        CommonOAuth2Provider commonProvider = getCommonOAuth2Provider(providerId);
        if ((extendedProvider == null && commonProvider == null) && !providers.containsKey(providerId)) {
            throw new IllegalStateException(getErrorMessage(configuredProviderId, registrationId));
        }
        Builder builder;
        if (extendedProvider != null && extendedProvider.getBuilder(registrationId) != null) {
            builder = extendedProvider.getBuilder(registrationId);
        } else if (commonProvider != null && commonProvider.getBuilder(registrationId) != null) {
            builder = commonProvider.getBuilder(registrationId);
        } else {
            builder = ClientRegistration.withRegistrationId(registrationId);
        }
        if (providers.containsKey(providerId)) {
            return getBuilder(builder, providers.get(providerId));
        }
        return builder;
    }

    private static String getErrorMessage(String configuredProviderId, String registrationId) {
        return ((configuredProviderId != null) ? "Unknown provider ID '" + configuredProviderId + "'"
                : "Provider ID must be specified for client registration '" + registrationId + "'");
    }

    private static Builder getBuilder(Builder builder, Provider provider) {
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

    private static ExtendedOAuth2ClientProvider getExtendedOAuth2Provider(String providerId) {
        try {
            return ApplicationConversionService.getSharedInstance().convert(providerId, ExtendedOAuth2ClientProvider.class);
        } catch (ConversionException ex) {
            return null;
        }
    }

    private static CommonOAuth2Provider getCommonOAuth2Provider(String providerId) {
        try {
            return ApplicationConversionService.getSharedInstance().convert(providerId, CommonOAuth2Provider.class);
        } catch (ConversionException ex) {
            return null;
        }
    }

}
