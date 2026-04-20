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
package com.armorauth.federat.gitee;

import com.armorauth.federat.ExtendedOAuth2ClientProvider;
import com.armorauth.federat.converter.OAuth2AuthorizationCodeGrantRequestConverter;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.RequestEntity;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationExchange;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import java.net.URI;
import java.util.Collections;

public class GiteeOAuth2AuthorizationCodeGrantRequestConverter implements OAuth2AuthorizationCodeGrantRequestConverter {

    @Override
    public RequestEntity<?> convert(OAuth2AuthorizationCodeGrantRequest request) {
        ClientRegistration clientRegistration = request.getClientRegistration();
        OAuth2AuthorizationExchange authorizationExchange = request.getAuthorizationExchange();

        MultiValueMap<String, String> formParameters = new LinkedMultiValueMap<>();
        formParameters.add(OAuth2ParameterNames.GRANT_TYPE, request.getGrantType().getValue());
        formParameters.add(OAuth2ParameterNames.CODE, authorizationExchange.getAuthorizationResponse().getCode());
        formParameters.add(OAuth2ParameterNames.REDIRECT_URI, authorizationExchange.getAuthorizationRequest().getRedirectUri());
        formParameters.add(OAuth2ParameterNames.CLIENT_ID, clientRegistration.getClientId());
        if (ClientAuthenticationMethod.CLIENT_SECRET_POST.equals(clientRegistration.getClientAuthenticationMethod())) {
            formParameters.add(OAuth2ParameterNames.CLIENT_SECRET, clientRegistration.getClientSecret());
        }

        HttpHeaders headers = new HttpHeaders();
        headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        URI tokenUri = URI.create(clientRegistration.getProviderDetails().getTokenUri());
        return RequestEntity.post(tokenUri).headers(headers).body(formParameters);
    }

    @Override
    public boolean supports(String registrationId) {
        return ExtendedOAuth2ClientProvider.matchNameLowerCase(ExtendedOAuth2ClientProvider.GITEE, registrationId);
    }

}
