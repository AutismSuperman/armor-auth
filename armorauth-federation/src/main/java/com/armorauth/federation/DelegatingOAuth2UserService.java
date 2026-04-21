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

import com.armorauth.federation.provider.FederatedOAuth2ProviderRegistry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;

public class DelegatingOAuth2UserService implements OAuth2UserService<OAuth2UserRequest, OAuth2User> {

    private static final Logger log = LoggerFactory.getLogger(DelegatingOAuth2UserService.class);

    private final OAuth2UserService<OAuth2UserRequest, OAuth2User> defaultOAuth2UserService =
            new DefaultOAuth2UserService();

    private final FederatedOAuth2ProviderRegistry providerRegistry;

    public DelegatingOAuth2UserService(FederatedOAuth2ProviderRegistry providerRegistry) {
        this.providerRegistry = providerRegistry;
    }

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        String registrationId = userRequest.getClientRegistration().getRegistrationId();
        OAuth2UserService<OAuth2UserRequest, OAuth2User> delegate = this.providerRegistry.findProvider(registrationId)
                .map(provider -> provider.getOAuth2UserService())
                .filter(userService -> userService != null)
                .orElse(this.defaultOAuth2UserService);
        log.info(
                "Loading federated user info for registrationId={} with service={}",
                registrationId,
                delegate.getClass().getSimpleName()
        );
        OAuth2User user = delegate.loadUser(userRequest);
        log.info("Loaded federated user info for registrationId={} principalName={}", registrationId, user.getName());
        return user;
    }

}
