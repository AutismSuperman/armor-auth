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
package com.armorauth.federation.provider.alipay;

import com.armorauth.federation.provider.ExtendedOAuth2ClientProvider;
import com.armorauth.federation.provider.converter.OAuth2AuthorizationCodeGrantRequestConverter;
import org.springframework.http.RequestEntity;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationExchange;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.URI;
import java.util.Map;

public class AlipayAuthorizationCodeGrantRequestConverter implements OAuth2AuthorizationCodeGrantRequestConverter {

    @Override
    public RequestEntity<?> convert(OAuth2AuthorizationCodeGrantRequest request) {
        ClientRegistration clientRegistration = request.getClientRegistration();
        OAuth2AuthorizationExchange authorizationExchange = request.getAuthorizationExchange();
        Map<String, String> parameters = AlipaySupport.gatewayParameters(
                clientRegistration,
                "alipay.system.oauth.token"
        );
        parameters.put(OAuth2ParameterNames.GRANT_TYPE, request.getGrantType().getValue());
        parameters.put(OAuth2ParameterNames.CODE, authorizationExchange.getAuthorizationResponse().getCode());
        URI uri = UriComponentsBuilder.fromUriString(clientRegistration.getProviderDetails().getTokenUri())
                .queryParams(CollectionUtils.toMultiValueMap(AlipaySupport.sign(parameters, clientRegistration)))
                .build()
                .encode()
                .toUri();
        return RequestEntity.get(uri).build();
    }

    @Override
    public boolean supports(String registrationId) {
        return ExtendedOAuth2ClientProvider.matchNameLowerCase(ExtendedOAuth2ClientProvider.ALIPAY, registrationId);
    }

}
