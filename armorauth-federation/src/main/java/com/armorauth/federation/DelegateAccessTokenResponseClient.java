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

import com.armorauth.federation.provider.FederatedOAuth2Provider;
import com.armorauth.federation.provider.FederatedOAuth2ProviderRegistry;
import com.armorauth.federation.provider.converter.OAuth2AccessTokenRestTemplate;
import com.armorauth.federation.provider.converter.OAuth2AuthorizationCodeGrantRequestConverter;
import org.springframework.http.RequestEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.endpoint.RestClientAuthorizationCodeTokenResponseClient;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestTemplate;

public class DelegateAccessTokenResponseClient
        implements OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> {

    private final RestClientAuthorizationCodeTokenResponseClient delegate =
            new RestClientAuthorizationCodeTokenResponseClient();

    private final FederatedOAuth2ProviderRegistry providerRegistry;

    public DelegateAccessTokenResponseClient(FederatedOAuth2ProviderRegistry providerRegistry) {
        this.providerRegistry = providerRegistry;
        this.delegate.setRestClient(RestClient.builder()
                .requestFactory(new SimpleClientHttpRequestFactory())
                .build());
    }

    @Override
    public OAuth2AccessTokenResponse getTokenResponse(OAuth2AuthorizationCodeGrantRequest authorizationGrantRequest) {
        String registrationId = authorizationGrantRequest.getClientRegistration().getRegistrationId();
        return this.providerRegistry.findProvider(registrationId)
                .filter(provider -> provider.getAuthorizationCodeGrantRequestConverter() != null)
                .map(provider -> executeCustomTokenRequest(authorizationGrantRequest, provider))
                .map(response -> validateAccessTokenResponse(response, registrationId))
                .orElseGet(() -> validateAccessTokenResponse(this.delegate.getTokenResponse(authorizationGrantRequest), registrationId));
    }

    private OAuth2AccessTokenResponse executeCustomTokenRequest(
            OAuth2AuthorizationCodeGrantRequest authorizationGrantRequest,
            FederatedOAuth2Provider provider) {
        OAuth2AuthorizationCodeGrantRequestConverter requestConverter = provider.getAuthorizationCodeGrantRequestConverter();
        OAuth2AccessTokenRestTemplate restTemplateProvider = provider.getAccessTokenRestTemplate();
        if (restTemplateProvider == null) {
            throw new OAuth2AuthenticationException(new OAuth2Error(
                    OAuth2ErrorCodes.SERVER_ERROR,
                    "No token client is available for " + provider.getProviderId(),
                    null
            ));
        }
        RequestEntity<?> requestEntity = requestConverter.convert(authorizationGrantRequest);
        RestTemplate restTemplate = restTemplateProvider.getRestTemplate(authorizationGrantRequest);
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

    private OAuth2AccessTokenResponse validateAccessTokenResponse(
            OAuth2AccessTokenResponse response,
            String registrationId) {
        if (response == null || response.getAccessToken() == null) {
            throw new OAuth2AuthenticationException(new OAuth2Error(
                    OAuth2ErrorCodes.SERVER_ERROR,
                    "Access token is missing in token response for " + registrationId,
                    null
            ));
        }
        return response;
    }

}
