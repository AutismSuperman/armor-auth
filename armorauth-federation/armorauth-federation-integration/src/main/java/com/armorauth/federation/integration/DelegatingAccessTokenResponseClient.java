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
package com.armorauth.federation.integration;

import com.armorauth.federation.core.endpoint.FederatedOAuth2AccessTokenRestTemplate;
import org.springframework.security.oauth2.client.endpoint.DefaultAuthorizationCodeTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequestEntityConverter;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.util.Assert;

import java.util.ArrayList;
import java.util.List;

public class DelegatingAccessTokenResponseClient implements OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> {

    private final DefaultAuthorizationCodeTokenResponseClient delegate = new DefaultAuthorizationCodeTokenResponseClient();

    private final List<FederatedOAuth2AccessTokenRestTemplate> accessTokenRestTemplates;

    public DelegatingAccessTokenResponseClient() {
        this.accessTokenRestTemplates = new ArrayList<>();
    }


    public DelegatingAccessTokenResponseClient(List<FederatedOAuth2AccessTokenRestTemplate> accessTokenRestTemplates) {
        Assert.notNull(accessTokenRestTemplates, "oAuth2AccessTokenRestTemplates cannot be null");
        this.accessTokenRestTemplates = accessTokenRestTemplates;
    }

    @Override
    public OAuth2AccessTokenResponse getTokenResponse(OAuth2AuthorizationCodeGrantRequest authorizationGrantRequest) {
        String registrationId = authorizationGrantRequest.getClientRegistration().getRegistrationId();
        FederatedOAuth2AccessTokenRestTemplate federatedOAuth2AccessTokenRestTemplate = accessTokenRestTemplates.stream()
                .filter(f -> f.supports(registrationId))
                .findFirst()
                .orElse(null);
        if (federatedOAuth2AccessTokenRestTemplate != null) {
            delegate.setRestOperations(federatedOAuth2AccessTokenRestTemplate.getRestTemplate(authorizationGrantRequest));
            delegate.setRequestEntityConverter(federatedOAuth2AccessTokenRestTemplate);
        }
        return delegate.getTokenResponse(authorizationGrantRequest);
    }

    public void addAccessTokenRestTemplate(FederatedOAuth2AccessTokenRestTemplate accessTokenRestTemplate) {
        accessTokenRestTemplates.add(accessTokenRestTemplate);
    }

    public void addAccessTokenRestTemplates(List<FederatedOAuth2AccessTokenRestTemplate> accessTokenRestTemplates) {
        this.accessTokenRestTemplates.addAll(accessTokenRestTemplates);
    }


}
