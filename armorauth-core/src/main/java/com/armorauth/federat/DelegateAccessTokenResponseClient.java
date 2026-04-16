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

import com.armorauth.federat.converter.OAuth2AccessTokenRestTemplate;
import com.armorauth.federat.converter.OAuth2AuthorizationCodeGrantRequestConverter;
import com.armorauth.federat.qq.QqAccessTokenRestTemplate;
import com.armorauth.federat.qq.QqOAuth2AuthorizationCodeGrantRequestConverter;
import com.armorauth.federat.wechat.WechatAccessTokenRestTemplate;
import com.armorauth.federat.wechat.WechatAuthorizationCodeGrantRequestConverter;
import org.springframework.http.RequestEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.endpoint.RestClientAuthorizationCodeTokenResponseClient;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.web.client.RestTemplate;

import java.util.ArrayList;
import java.util.List;

public class DelegateAccessTokenResponseClient
        implements OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> {

    private final RestClientAuthorizationCodeTokenResponseClient delegate =
            new RestClientAuthorizationCodeTokenResponseClient();

    private final List<OAuth2AccessTokenRestTemplate> restTemplates = new ArrayList<>();

    private final List<OAuth2AuthorizationCodeGrantRequestConverter> requestConverters = new ArrayList<>();

    public DelegateAccessTokenResponseClient() {
        this.restTemplates.add(new WechatAccessTokenRestTemplate());
        this.restTemplates.add(new QqAccessTokenRestTemplate());
        this.requestConverters.add(new WechatAuthorizationCodeGrantRequestConverter());
        this.requestConverters.add(new QqOAuth2AuthorizationCodeGrantRequestConverter());
    }

    @Override
    public OAuth2AccessTokenResponse getTokenResponse(OAuth2AuthorizationCodeGrantRequest authorizationGrantRequest) {
        String registrationId = authorizationGrantRequest.getClientRegistration().getRegistrationId();
        for (OAuth2AuthorizationCodeGrantRequestConverter requestConverter : this.requestConverters) {
            if (requestConverter.supports(registrationId)) {
                return executeCustomTokenRequest(authorizationGrantRequest, requestConverter);
            }
        }
        return delegate.getTokenResponse(authorizationGrantRequest);
    }

    public void addAccessTokenRestTemplate(OAuth2AccessTokenRestTemplate restTemplate) {
        this.restTemplates.add(restTemplate);
    }

    private OAuth2AccessTokenResponse executeCustomTokenRequest(
            OAuth2AuthorizationCodeGrantRequest authorizationGrantRequest,
            OAuth2AuthorizationCodeGrantRequestConverter requestConverter) {
        RequestEntity<?> requestEntity = requestConverter.convert(authorizationGrantRequest);
        RestTemplate restTemplate = this.restTemplates.stream()
                .filter(candidate -> candidate.supports(
                        authorizationGrantRequest.getClientRegistration().getRegistrationId()))
                .findFirst()
                .map(candidate -> candidate.getRestTemplate(authorizationGrantRequest))
                .orElseThrow(() -> new OAuth2AuthenticationException(new OAuth2Error(
                        OAuth2ErrorCodes.SERVER_ERROR,
                        "No token client is available for "
                                + authorizationGrantRequest.getClientRegistration().getRegistrationId(),
                        null
                )));
        ResponseEntity<OAuth2AccessTokenResponse> response =
                restTemplate.exchange(requestEntity, OAuth2AccessTokenResponse.class);
        OAuth2AccessTokenResponse body = response.getBody();
        if (body == null) {
            throw new OAuth2AuthenticationException(new OAuth2Error(
                    OAuth2ErrorCodes.SERVER_ERROR,
                    "Access token response body is empty",
                    null
            ));
        }
        return body;
    }

}
