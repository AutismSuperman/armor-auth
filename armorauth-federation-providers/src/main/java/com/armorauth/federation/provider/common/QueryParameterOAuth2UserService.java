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

import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpMethod;
import org.springframework.http.RequestEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.http.OAuth2ErrorResponseErrorHandler;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2UserAuthority;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.web.client.RestOperations;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.URI;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

public class QueryParameterOAuth2UserService implements OAuth2UserService<OAuth2UserRequest, OAuth2User> {

    private static final ParameterizedTypeReference<Map<String, Object>> PARAMETERIZED_RESPONSE_TYPE =
            new ParameterizedTypeReference<>() {
            };

    private final Map<String, String> additionalParameters;

    private RestOperations restOperations;

    public QueryParameterOAuth2UserService() {
        this(Map.of());
    }

    public QueryParameterOAuth2UserService(Map<String, String> additionalParameters) {
        this.additionalParameters = new LinkedHashMap<>(additionalParameters);
        RestTemplate restTemplate = new RestTemplate();
        restTemplate.setErrorHandler(new OAuth2ErrorResponseErrorHandler());
        this.restOperations = restTemplate;
    }

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        Assert.notNull(userRequest, "userRequest cannot be null");
        String userInfoUri = userRequest.getClientRegistration().getProviderDetails().getUserInfoEndpoint().getUri();
        if (!StringUtils.hasText(userInfoUri)) {
            throw oauth2Exception("missing_user_info_uri", "Missing required UserInfo Uri.");
        }
        String userNameAttributeName = userRequest.getClientRegistration()
                .getProviderDetails()
                .getUserInfoEndpoint()
                .getUserNameAttributeName();
        if (!StringUtils.hasText(userNameAttributeName)) {
            throw oauth2Exception("missing_user_name_attribute", "Missing required user name attribute.");
        }

        URI uri = buildUserInfoUri(userInfoUri, userRequest);
        RequestEntity<Void> request = new RequestEntity<>(HttpMethod.GET, uri);
        ResponseEntity<Map<String, Object>> response =
                this.restOperations.exchange(request, PARAMETERIZED_RESPONSE_TYPE);
        Map<String, Object> attributes = response.getBody();
        if (attributes == null || !attributes.containsKey(userNameAttributeName)) {
            throw oauth2Exception(
                    OAuth2ErrorCodes.INVALID_REQUEST,
                    "UserInfo response is missing attribute '" + userNameAttributeName + "'."
            );
        }

        Set<GrantedAuthority> authorities = new LinkedHashSet<>();
        authorities.add(new OAuth2UserAuthority(attributes));
        OAuth2AccessToken token = userRequest.getAccessToken();
        for (String authority : token.getScopes()) {
            authorities.add(new SimpleGrantedAuthority("SCOPE_" + authority));
        }
        return new DefaultOAuth2User(authorities, attributes, userNameAttributeName);
    }

    public final void setRestOperations(RestOperations restOperations) {
        Assert.notNull(restOperations, "restOperations cannot be null");
        this.restOperations = restOperations;
    }

    private URI buildUserInfoUri(String userInfoUri, OAuth2UserRequest userRequest) {
        UriComponentsBuilder builder = UriComponentsBuilder.fromUriString(userInfoUri)
                .queryParam("access_token", userRequest.getAccessToken().getTokenValue());
        this.additionalParameters.forEach((queryName, sourceName) -> {
            Object value = userRequest.getAdditionalParameters().get(sourceName);
            if (value != null) {
                builder.queryParam(queryName, value);
            }
        });
        return builder.build().encode().toUri();
    }

    private OAuth2AuthenticationException oauth2Exception(String code, String description) {
        OAuth2Error oauth2Error = new OAuth2Error(code, description, null);
        return new OAuth2AuthenticationException(oauth2Error, oauth2Error.toString());
    }

}
