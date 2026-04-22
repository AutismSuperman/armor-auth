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
import com.armorauth.federation.provider.converter.OAuth2AccessTokenRestTemplate;
import org.springframework.http.MediaType;
import org.springframework.http.converter.FormHttpMessageConverter;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.http.OAuth2ErrorResponseErrorHandler;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.endpoint.DefaultMapOAuth2AccessTokenResponseConverter;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.http.converter.OAuth2AccessTokenResponseHttpMessageConverter;
import org.springframework.web.client.RestTemplate;

import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;

public class AlipayAccessTokenRestTemplate implements OAuth2AccessTokenRestTemplate {

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
            tokenParameters.put(OAuth2ParameterNames.TOKEN_TYPE, OAuth2AccessToken.TokenType.BEARER.getValue());
            if (tokenParameters.containsKey("expires_in")) {
                tokenParameters.put(OAuth2ParameterNames.EXPIRES_IN, tokenParameters.get("expires_in"));
            }
            return new DefaultMapOAuth2AccessTokenResponseConverter().convert(tokenParameters);
        });
        RestTemplate restTemplate = new RestTemplate(Arrays.asList(
                new FormHttpMessageConverter(),
                tokenResponseHttpMessageConverter
        ));
        restTemplate.setErrorHandler(new OAuth2ErrorResponseErrorHandler());
        return restTemplate;
    }

    @Override
    public boolean supports(String registrationId) {
        return ExtendedOAuth2ClientProvider.matchNameLowerCase(ExtendedOAuth2ClientProvider.ALIPAY, registrationId);
    }

    private Map<String, Object> extractTokenParameters(Map<String, Object> responseParameters) {
        Object response = responseParameters.get("alipay_system_oauth_token_response");
        if (!(response instanceof Map<?, ?> responseMap)) {
            return new LinkedHashMap<>(responseParameters);
        }
        Map<String, Object> tokenParameters = new LinkedHashMap<>();
        responseMap.forEach((key, value) -> {
            if (key != null) {
                tokenParameters.put(String.valueOf(key), value);
            }
        });
        return tokenParameters;
    }

}
