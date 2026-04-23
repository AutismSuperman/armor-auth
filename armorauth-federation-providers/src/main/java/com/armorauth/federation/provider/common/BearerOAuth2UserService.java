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
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.RequestEntity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.http.OAuth2ErrorResponseErrorHandler;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2UserAuthority;
import org.springframework.web.client.RestOperations;
import org.springframework.web.client.RestTemplate;

import java.net.URI;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

public class BearerOAuth2UserService implements OAuth2UserService<OAuth2UserRequest, OAuth2User> {

    private static final ParameterizedTypeReference<Map<String, Object>> RESPONSE_TYPE =
            new ParameterizedTypeReference<>() {
            };

    private final String dataKey;

    private final RestOperations restOperations;

    public BearerOAuth2UserService(String dataKey) {
        this.dataKey = dataKey;
        RestTemplate restTemplate = new RestTemplate();
        restTemplate.setErrorHandler(new OAuth2ErrorResponseErrorHandler());
        this.restOperations = restTemplate;
    }

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(userRequest.getAccessToken().getTokenValue());
        RequestEntity<Void> request = new RequestEntity<>(
                headers,
                HttpMethod.GET,
                URI.create(userRequest.getClientRegistration().getProviderDetails().getUserInfoEndpoint().getUri())
        );
        Map<String, Object> response = this.restOperations.exchange(request, RESPONSE_TYPE).getBody();
        Map<String, Object> attributes = extractAttributes(response);
        String userNameAttributeName = userRequest.getClientRegistration()
                .getProviderDetails()
                .getUserInfoEndpoint()
                .getUserNameAttributeName();
        if (!attributes.containsKey(userNameAttributeName)) {
            throw oauth2Exception("missing_user_name_attribute", "UserInfo response is missing " + userNameAttributeName);
        }

        Set<GrantedAuthority> authorities = new LinkedHashSet<>();
        authorities.add(new OAuth2UserAuthority(attributes));
        for (String authority : userRequest.getAccessToken().getScopes()) {
            authorities.add(new SimpleGrantedAuthority("SCOPE_" + authority));
        }
        return new DefaultOAuth2User(authorities, attributes, userNameAttributeName);
    }

    private Map<String, Object> extractAttributes(Map<String, Object> response) {
        if (response == null) {
            return new LinkedHashMap<>();
        }
        if (this.dataKey == null) {
            return new LinkedHashMap<>(response);
        }
        Object data = response.get(this.dataKey);
        if (!(data instanceof Map<?, ?> dataMap)) {
            return new LinkedHashMap<>(response);
        }
        Map<String, Object> attributes = new LinkedHashMap<>();
        dataMap.forEach((key, value) -> {
            if (key != null) {
                attributes.put(String.valueOf(key), value);
            }
        });
        return attributes;
    }

    private OAuth2AuthenticationException oauth2Exception(String code, String description) {
        OAuth2Error oauth2Error = new OAuth2Error(code, description, null);
        return new OAuth2AuthenticationException(oauth2Error, oauth2Error.toString());
    }

}
