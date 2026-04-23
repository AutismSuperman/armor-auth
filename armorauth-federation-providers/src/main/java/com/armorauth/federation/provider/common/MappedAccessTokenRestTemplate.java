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
import com.armorauth.federation.provider.converter.OAuth2AccessTokenRestTemplate;
import org.springframework.http.MediaType;
import org.springframework.http.converter.FormHttpMessageConverter;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.http.OAuth2ErrorResponseErrorHandler;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.endpoint.DefaultMapOAuth2AccessTokenResponseConverter;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.http.converter.OAuth2AccessTokenResponseHttpMessageConverter;
import org.springframework.web.client.RestTemplate;

import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;

public class MappedAccessTokenRestTemplate implements OAuth2AccessTokenRestTemplate {

    private final ExtendedOAuth2ClientProvider provider;

    private final String dataKey;

    private final String accessTokenKey;

    private final String refreshTokenKey;

    private final String expiresInKey;

    public MappedAccessTokenRestTemplate(
            ExtendedOAuth2ClientProvider provider,
            String dataKey,
            String accessTokenKey,
            String refreshTokenKey,
            String expiresInKey) {
        this.provider = provider;
        this.dataKey = dataKey;
        this.accessTokenKey = accessTokenKey;
        this.refreshTokenKey = refreshTokenKey;
        this.expiresInKey = expiresInKey;
    }

    @Override
    public RestTemplate getRestTemplate(OAuth2AuthorizationCodeGrantRequest authorizationGrantRequest) {
        OAuth2AccessTokenResponseHttpMessageConverter tokenResponseHttpMessageConverter =
                new OAuth2AccessTokenResponseHttpMessageConverter();
        tokenResponseHttpMessageConverter.setSupportedMediaTypes(Arrays.asList(
                MediaType.APPLICATION_JSON,
                MediaType.TEXT_HTML,
                MediaType.TEXT_PLAIN,
                new MediaType("application", "*+json"))
        );
        tokenResponseHttpMessageConverter.setAccessTokenResponseConverter(responseParameters -> {
            Map<String, Object> tokenParameters = extractTokenParameters(responseParameters);
            putIfPresent(tokenParameters, OAuth2ParameterNames.ACCESS_TOKEN, tokenParameters.get(this.accessTokenKey));
            putIfPresent(tokenParameters, OAuth2ParameterNames.REFRESH_TOKEN, tokenParameters.get(this.refreshTokenKey));
            putIfPresent(tokenParameters, OAuth2ParameterNames.EXPIRES_IN, tokenParameters.get(this.expiresInKey));
            tokenParameters.put(OAuth2ParameterNames.TOKEN_TYPE, OAuth2AccessToken.TokenType.BEARER.getValue());
            return new DefaultMapOAuth2AccessTokenResponseConverter().convert(tokenParameters);
        });
        RestTemplate restTemplate = new RestTemplate(Arrays.asList(
                new FormHttpMessageConverter(),
                tokenResponseHttpMessageConverter,
                new MappingJackson2HttpMessageConverter()
        ));
        restTemplate.setErrorHandler(new OAuth2ErrorResponseErrorHandler());
        return restTemplate;
    }

    @Override
    public boolean supports(String registrationId) {
        return ExtendedOAuth2ClientProvider.matchNameLowerCase(this.provider, registrationId);
    }

    private Map<String, Object> extractTokenParameters(Map<String, Object> responseParameters) {
        if (this.dataKey == null) {
            return new LinkedHashMap<>(responseParameters);
        }
        Object data = responseParameters.get(this.dataKey);
        if (!(data instanceof Map<?, ?> dataMap)) {
            return new LinkedHashMap<>(responseParameters);
        }
        Map<String, Object> tokenParameters = new LinkedHashMap<>();
        dataMap.forEach((key, value) -> {
            if (key != null) {
                tokenParameters.put(String.valueOf(key), value);
            }
        });
        return tokenParameters;
    }

    private void putIfPresent(Map<String, Object> tokenParameters, String key, Object value) {
        if (value != null) {
            tokenParameters.put(key, value);
        }
    }

}
