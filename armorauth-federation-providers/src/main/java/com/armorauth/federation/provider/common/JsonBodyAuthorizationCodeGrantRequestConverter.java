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

import com.armorauth.federation.provider.ExtendedOAuth2ClientProvider;
import com.armorauth.federation.provider.converter.OAuth2AuthorizationCodeGrantRequestConverter;
import org.springframework.http.MediaType;
import org.springframework.http.RequestEntity;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationExchange;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;

import java.util.LinkedHashMap;
import java.util.Map;

public class JsonBodyAuthorizationCodeGrantRequestConverter implements OAuth2AuthorizationCodeGrantRequestConverter {

    private final ExtendedOAuth2ClientProvider provider;

    private final String clientIdName;

    private final String clientSecretName;

    private final String grantTypeName;

    public JsonBodyAuthorizationCodeGrantRequestConverter(
            ExtendedOAuth2ClientProvider provider,
            String clientIdName,
            String clientSecretName,
            String grantTypeName) {
        this.provider = provider;
        this.clientIdName = clientIdName;
        this.clientSecretName = clientSecretName;
        this.grantTypeName = grantTypeName;
    }

    @Override
    public RequestEntity<?> convert(OAuth2AuthorizationCodeGrantRequest request) {
        ClientRegistration clientRegistration = request.getClientRegistration();
        OAuth2AuthorizationExchange authorizationExchange = request.getAuthorizationExchange();
        Map<String, Object> body = new LinkedHashMap<>();
        body.put(this.clientIdName, clientRegistration.getClientId());
        body.put(this.clientSecretName, clientRegistration.getClientSecret());
        body.put(OAuth2ParameterNames.CODE, authorizationExchange.getAuthorizationResponse().getCode());
        body.put(this.grantTypeName, request.getGrantType().getValue());
        return RequestEntity.post(clientRegistration.getProviderDetails().getTokenUri())
                .contentType(MediaType.APPLICATION_JSON)
                .accept(MediaType.APPLICATION_JSON)
                .body(body);
    }

    @Override
    public boolean supports(String registrationId) {
        return ExtendedOAuth2ClientProvider.matchNameLowerCase(this.provider, registrationId);
    }

}
