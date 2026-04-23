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
package com.armorauth.federation.provider.feishu;

import com.armorauth.federation.provider.ExtendedOAuth2ClientProvider;
import com.armorauth.federation.provider.FederatedOAuth2Provider;
import com.armorauth.federation.provider.common.BearerOAuth2UserService;
import com.armorauth.federation.provider.common.JsonBodyAuthorizationCodeGrantRequestConverter;
import com.armorauth.federation.provider.common.MappedAccessTokenRestTemplate;
import com.armorauth.federation.provider.converter.OAuth2AccessTokenRestTemplate;
import com.armorauth.federation.provider.converter.OAuth2AuthorizationCodeGrantRequestConverter;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Component;

@Component
public class FeishuFederatedOAuth2Provider implements FederatedOAuth2Provider {

    @Override
    public String getProviderId() {
        return "feishu";
    }

    @Override
    public ClientRegistration.Builder getBuilder(String registrationId) {
        return ExtendedOAuth2ClientProvider.FEISHU.getBuilder(registrationId);
    }

    @Override
    public OAuth2AuthorizationCodeGrantRequestConverter getAuthorizationCodeGrantRequestConverter() {
        return new JsonBodyAuthorizationCodeGrantRequestConverter(
                ExtendedOAuth2ClientProvider.FEISHU,
                "client_id",
                "client_secret",
                "grant_type"
        );
    }

    @Override
    public OAuth2AccessTokenRestTemplate getAccessTokenRestTemplate() {
        return new MappedAccessTokenRestTemplate(
                ExtendedOAuth2ClientProvider.FEISHU,
                "data",
                "access_token",
                "refresh_token",
                "expires_in"
        );
    }

    @Override
    public OAuth2UserService<OAuth2UserRequest, OAuth2User> getOAuth2UserService() {
        return new BearerOAuth2UserService("data");
    }

}
