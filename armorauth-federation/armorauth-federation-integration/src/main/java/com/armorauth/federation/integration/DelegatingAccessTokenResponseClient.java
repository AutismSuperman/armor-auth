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
import com.armorauth.federation.core.endpoint.FederatedOAuth2AuthorizationCodeGrantRequestConverter;
import org.springframework.security.oauth2.client.endpoint.DefaultAuthorizationCodeTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.util.Assert;

import java.util.ArrayList;
import java.util.List;

public class DelegatingAccessTokenResponseClient implements OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> {

    private final DefaultAuthorizationCodeTokenResponseClient delegate = new DefaultAuthorizationCodeTokenResponseClient();

    private final List<FederatedOAuth2AccessTokenRestTemplate> oAuth2AccessTokenRestTemplates;

    private final List<FederatedOAuth2AuthorizationCodeGrantRequestConverter> authorizationCodeGrantRequestConverters;

    public DelegatingAccessTokenResponseClient() {
        this.oAuth2AccessTokenRestTemplates = new ArrayList<>();
        this.authorizationCodeGrantRequestConverters = new ArrayList<>();
        this.delegate.setRequestEntityConverter(
                new DelegatingAuthorizationCodeGrantRequestConverter(authorizationCodeGrantRequestConverters)
        );
    }


    public DelegatingAccessTokenResponseClient(
            List<FederatedOAuth2AccessTokenRestTemplate> restTemplates,
            List<FederatedOAuth2AuthorizationCodeGrantRequestConverter> authorizationCodeGrantRequestConverters
    ) {
        Assert.notNull(restTemplates, "restTemplates cannot be null");
        Assert.notNull(authorizationCodeGrantRequestConverters, "authorizationCodeGrantRequestConverters cannot be null");
        this.oAuth2AccessTokenRestTemplates = restTemplates;
        this.authorizationCodeGrantRequestConverters = authorizationCodeGrantRequestConverters;
        DelegatingAuthorizationCodeGrantRequestConverter delegatingAuthorizationCodeGrantRequestConverter =
                new DelegatingAuthorizationCodeGrantRequestConverter(authorizationCodeGrantRequestConverters);
        this.delegate.setRequestEntityConverter(delegatingAuthorizationCodeGrantRequestConverter);
    }

    @Override
    public OAuth2AccessTokenResponse getTokenResponse(OAuth2AuthorizationCodeGrantRequest authorizationGrantRequest) {
        String registrationId = authorizationGrantRequest.getClientRegistration().getRegistrationId();
        oAuth2AccessTokenRestTemplates.stream()
                .filter(f -> f.supports(registrationId))
                .findFirst()
                .ifPresent(accessTokenRestTemplate ->
                        delegate.setRestOperations(accessTokenRestTemplate.getRestTemplate(authorizationGrantRequest))
                );
        return delegate.getTokenResponse(authorizationGrantRequest);
    }

    public void addAccessTokenRestTemplate(FederatedOAuth2AccessTokenRestTemplate restTemplate) {
        oAuth2AccessTokenRestTemplates.add(restTemplate);
    }

    public void addAccessTokenRestTemplates(List<FederatedOAuth2AccessTokenRestTemplate> oAuth2AccessTokenRestTemplates) {
        this.oAuth2AccessTokenRestTemplates.addAll(oAuth2AccessTokenRestTemplates);
    }

    public void addAuthorizationCodeGrantRequestConverter(FederatedOAuth2AuthorizationCodeGrantRequestConverter auth2AuthorizationCodeGrantRequestConverter) {
        this.authorizationCodeGrantRequestConverters.add(auth2AuthorizationCodeGrantRequestConverter);
    }

    public void addAuthorizationCodeGrantRequestConverters(List<FederatedOAuth2AuthorizationCodeGrantRequestConverter> authorizationCodeGrantRequestConverters) {
        this.authorizationCodeGrantRequestConverters.addAll(authorizationCodeGrantRequestConverters);
    }

}
