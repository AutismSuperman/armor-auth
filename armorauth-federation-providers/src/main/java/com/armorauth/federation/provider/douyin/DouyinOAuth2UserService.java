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
package com.armorauth.federation.provider.douyin;

import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpMethod;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.http.OAuth2ErrorResponseErrorHandler;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
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

public class DouyinOAuth2UserService implements OAuth2UserService<OAuth2UserRequest, OAuth2User> {

    private static final ParameterizedTypeReference<Map<String, Object>> RESPONSE_TYPE =
            new ParameterizedTypeReference<>() {
            };

    private final RestOperations restOperations;

    public DouyinOAuth2UserService() {
        RestTemplate restTemplate = new RestTemplate();
        restTemplate.setErrorHandler(new OAuth2ErrorResponseErrorHandler());
        this.restOperations = restTemplate;
    }

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        Assert.notNull(userRequest, "userRequest cannot be null");
        String userInfoUri = userRequest.getClientRegistration().getProviderDetails().getUserInfoEndpoint().getUri();
        String userNameAttributeName = userRequest.getClientRegistration()
                .getProviderDetails()
                .getUserInfoEndpoint()
                .getUserNameAttributeName();
        Object openId = userRequest.getAdditionalParameters().get(userNameAttributeName);
        if (!StringUtils.hasText(userInfoUri) || openId == null) {
            throw oauth2Exception("missing_douyin_userinfo_parameter", "Missing Douyin user info parameter.");
        }
        URI uri = UriComponentsBuilder.fromUriString(userInfoUri)
                .queryParam(OAuth2ParameterNames.ACCESS_TOKEN, userRequest.getAccessToken().getTokenValue())
                .queryParam(userNameAttributeName, openId)
                .build()
                .encode()
                .toUri();
        Map<String, Object> response = this.restOperations.exchange(uri, HttpMethod.GET, null, RESPONSE_TYPE).getBody();
        Map<String, Object> attributes = extractData(response);
        if (!attributes.containsKey(userNameAttributeName)) {
            attributes.put(userNameAttributeName, openId);
        }

        Set<GrantedAuthority> authorities = new LinkedHashSet<>();
        authorities.add(new OAuth2UserAuthority(attributes));
        for (String authority : userRequest.getAccessToken().getScopes()) {
            authorities.add(new SimpleGrantedAuthority("SCOPE_" + authority));
        }
        return new DefaultOAuth2User(authorities, attributes, userNameAttributeName);
    }

    private Map<String, Object> extractData(Map<String, Object> response) {
        if (response == null) {
            return new LinkedHashMap<>();
        }
        Object data = response.get("data");
        if (data instanceof Map<?, ?> dataMap) {
            Map<String, Object> attributes = new LinkedHashMap<>();
            dataMap.forEach((key, value) -> {
                if (key != null) {
                    attributes.put(String.valueOf(key), value);
                }
            });
            return attributes;
        }
        return new LinkedHashMap<>(response);
    }

    private OAuth2AuthenticationException oauth2Exception(String code, String description) {
        OAuth2Error oauth2Error = new OAuth2Error(code, description, null);
        return new OAuth2AuthenticationException(oauth2Error, oauth2Error.toString());
    }

}
