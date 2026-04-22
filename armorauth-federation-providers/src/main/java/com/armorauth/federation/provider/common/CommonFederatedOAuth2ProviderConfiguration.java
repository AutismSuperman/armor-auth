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
import com.armorauth.federation.provider.FederatedOAuth2Provider;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.Map;

@Configuration(proxyBeanMethods = false)
public class CommonFederatedOAuth2ProviderConfiguration {

    @Bean
    public FederatedOAuth2Provider microsoftFederatedOAuth2Provider() {
        return provider("microsoft", ExtendedOAuth2ClientProvider.MICROSOFT);
    }

    @Bean
    public FederatedOAuth2Provider gitlabFederatedOAuth2Provider() {
        return provider("gitlab", ExtendedOAuth2ClientProvider.GITLAB);
    }

    @Bean
    public FederatedOAuth2Provider discordFederatedOAuth2Provider() {
        return provider("discord", ExtendedOAuth2ClientProvider.DISCORD);
    }

    @Bean
    public FederatedOAuth2Provider slackFederatedOAuth2Provider() {
        return provider("slack", ExtendedOAuth2ClientProvider.SLACK);
    }

    @Bean
    public FederatedOAuth2Provider linkedinFederatedOAuth2Provider() {
        return provider("linkedin", ExtendedOAuth2ClientProvider.LINKEDIN);
    }

    @Bean
    public FederatedOAuth2Provider appleFederatedOAuth2Provider() {
        return provider("apple", ExtendedOAuth2ClientProvider.APPLE);
    }

    @Bean
    public FederatedOAuth2Provider weiboFederatedOAuth2Provider() {
        return provider(
                "weibo",
                ExtendedOAuth2ClientProvider.WEIBO,
                new QueryParameterOAuth2UserService(Map.of("uid", "uid"))
        );
    }

    @Bean
    public FederatedOAuth2Provider baiduFederatedOAuth2Provider() {
        return provider(
                "baidu",
                ExtendedOAuth2ClientProvider.BAIDU,
                new QueryParameterOAuth2UserService()
        );
    }

    @Bean
    public FederatedOAuth2Provider oschinaFederatedOAuth2Provider() {
        return provider(
                "oschina",
                ExtendedOAuth2ClientProvider.OSCHINA,
                new QueryParameterOAuth2UserService()
        );
    }

    private static FederatedOAuth2Provider provider(
            String providerId,
            ExtendedOAuth2ClientProvider clientProvider) {
        return new EnumFederatedOAuth2Provider(providerId, clientProvider);
    }

    private static FederatedOAuth2Provider provider(
            String providerId,
            ExtendedOAuth2ClientProvider clientProvider,
            QueryParameterOAuth2UserService userService) {
        return new EnumFederatedOAuth2Provider(providerId, clientProvider, userService);
    }

}
