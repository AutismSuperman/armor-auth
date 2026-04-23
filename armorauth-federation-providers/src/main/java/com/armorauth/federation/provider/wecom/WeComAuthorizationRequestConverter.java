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
package com.armorauth.federation.provider.wecom;

import com.armorauth.federation.provider.ExtendedOAuth2ClientProvider;
import com.armorauth.federation.provider.converter.OAuth2AuthorizationRequestConverter;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;

import java.util.LinkedHashMap;

public class WeComAuthorizationRequestConverter implements OAuth2AuthorizationRequestConverter {

    @Override
    public void convert(OAuth2AuthorizationRequest.Builder builder) {
        builder.parameters(parameters -> {
            LinkedHashMap<String, Object> convertedParameters = new LinkedHashMap<>();
            parameters.forEach((key, value) -> {
                if (OAuth2ParameterNames.CLIENT_ID.equals(key)) {
                    convertedParameters.put("appid", value);
                } else {
                    convertedParameters.put(key, value);
                }
            });
            parameters.clear();
            parameters.putAll(convertedParameters);
            builder.authorizationRequestUri(uriBuilder -> uriBuilder.fragment("wechat_redirect").build());
        });
    }

    @Override
    public boolean supports(String registrationId) {
        return ExtendedOAuth2ClientProvider.matchNameLowerCase(ExtendedOAuth2ClientProvider.WECOM, registrationId);
    }

}
