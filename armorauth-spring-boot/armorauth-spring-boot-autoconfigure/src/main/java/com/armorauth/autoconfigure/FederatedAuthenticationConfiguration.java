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
package com.armorauth.autoconfigure;


import com.armorauth.federation.core.ExtendedOAuth2ClientPropertiesMapper;
import com.armorauth.federation.core.ExtendedOAuth2ClientProvider;
import com.armorauth.federation.core.endpoint.OAuth2AccessTokenRestTemplateConverter;
import com.armorauth.federation.core.endpoint.OAuth2AuthorizationCodeGrantRequestConverter;
import com.armorauth.federation.core.web.converter.OAuth2AuthorizationRequestTransformer;
import com.armorauth.federation.gitee.user.GiteeOAuth2UserService;
import com.armorauth.federation.integration.DelegatingAccessTokenResponseClient;
import com.armorauth.federation.integration.DelegatingAuthorizationRequestResolver;
import com.armorauth.federation.integration.DelegatingOAuth2UserService;
import com.armorauth.federation.integration.web.FederatedAuthenticationEntryPoint;
import com.armorauth.federation.integration.web.configurers.FederatedOAuth2LoginConfigurer;
import com.armorauth.federation.qq.endpoint.QqAccessTokenRestTemplateConverter;
import com.armorauth.federation.qq.endpoint.QqAuthorizationCodeGrantRequestConverter;
import com.armorauth.federation.wechat.endpoint.WechatAccessTokenRestTemplateConverter;
import com.armorauth.federation.wechat.endpoint.WechatAuthorizationCodeGrantRequestConverter;
import com.armorauth.federation.wechat.web.converter.WechatAuthorizationRequestTransformer;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.oauth2.client.OAuth2ClientProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.client.JdbcOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.RequestMatcher;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static com.armorauth.federation.core.ExtendedOAuth2ClientProvider.*;

@Configuration(proxyBeanMethods = false)
public class FederatedAuthenticationConfiguration {

    private static final String CUSTOM_LOGIN_PAGE = "/login";


    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE + 1)
    public SecurityFilterChain federatedSecurityFilterChain(HttpSecurity http,
                                                            ClientRegistrationRepository clientRegistrationRepository
    ) throws Exception {

        FederatedOAuth2LoginConfigurer federatedOAuth2LoginConfigurer = new FederatedOAuth2LoginConfigurer();
        RequestMatcher endpointsMatcher = federatedOAuth2LoginConfigurer.getEndpointsMatcher();
        http.securityMatcher(endpointsMatcher);
        http.apply(federatedOAuth2LoginConfigurer);
        FederatedAuthenticationEntryPoint authenticationEntryPoint =
                new FederatedAuthenticationEntryPoint(CUSTOM_LOGIN_PAGE, clientRegistrationRepository);
        http.exceptionHandling(exceptionHandling ->
                exceptionHandling
                        .authenticationEntryPoint(authenticationEntryPoint)
        );
        //OAuth 授权地址转换 OAuth2AuthorizationRequestTransformer
        List<OAuth2AuthorizationRequestTransformer> authorizationRequestConverters = new ArrayList<>();
        authorizationRequestConverters.add(new WechatAuthorizationRequestTransformer());
        DelegatingAuthorizationRequestResolver delegatingAuthorizationRequestResolver =
                new DelegatingAuthorizationRequestResolver(clientRegistrationRepository, authorizationRequestConverters);
        //OAuth 请求AccessToken的RestTemplate转换 OAuth2AccessTokenRestTemplateConverter
        List<OAuth2AccessTokenRestTemplateConverter> restTemplates = new ArrayList<>();
        List<OAuth2AuthorizationCodeGrantRequestConverter> authorizationCodeGrantRequestConverters = new ArrayList<>();
        restTemplates.add(new WechatAccessTokenRestTemplateConverter());
        authorizationCodeGrantRequestConverters.add(new WechatAuthorizationCodeGrantRequestConverter());
        restTemplates.add(new QqAccessTokenRestTemplateConverter());
        authorizationCodeGrantRequestConverters.add(new QqAuthorizationCodeGrantRequestConverter());
        DelegatingAccessTokenResponseClient accessTokenResponseClient = new DelegatingAccessTokenResponseClient(
                restTemplates,
                authorizationCodeGrantRequestConverters
        );
        //OAuth2LoginConfigurer
        http.getConfigurer(FederatedOAuth2LoginConfigurer.class)
                .loginPage(CUSTOM_LOGIN_PAGE)
                .authorizationEndpoint(authorizationEndpoint -> authorizationEndpoint
                        .authorizationRequestResolver(delegatingAuthorizationRequestResolver)
                )
                .tokenEndpoint(tokenEndpoint -> tokenEndpoint
                        .accessTokenResponseClient(accessTokenResponseClient)
                )
                .userInfoEndpoint(userInfoEndpoint -> userInfoEndpoint
                        .addUserService(ExtendedOAuth2ClientProvider.getNameLowerCase(GITEE), new GiteeOAuth2UserService())
                        .addUserService(ExtendedOAuth2ClientProvider.getNameLowerCase(QQ), new GiteeOAuth2UserService())
                        .addUserService(ExtendedOAuth2ClientProvider.getNameLowerCase(WECHAT), new GiteeOAuth2UserService())
                        .userService(new DelegatingOAuth2UserService())
                        .bindUserPage("/bind")
                )
        ;
        return http.build();
    }


    @Bean
    public ClientRegistrationRepository clientRegistrationRepository(@Autowired(required = false) OAuth2ClientProperties properties) {
        InMemoryClientRegistrationRepository clientRegistrations;
        ExtendedOAuth2ClientPropertiesMapper extendedOAuth2ClientPropertiesMapper = new ExtendedOAuth2ClientPropertiesMapper(properties);
        Map<String, ClientRegistration> extendedClientRegistrations = extendedOAuth2ClientPropertiesMapper.asClientRegistrations();
        clientRegistrations = new InMemoryClientRegistrationRepository(extendedClientRegistrations);
        return clientRegistrations;
    }

    @Bean
    public OAuth2AuthorizedClientService authorizedClientService(
            JdbcTemplate jdbcTemplate,
            ClientRegistrationRepository clientRegistrationRepository) {
        return new JdbcOAuth2AuthorizedClientService(jdbcTemplate, clientRegistrationRepository);
    }


}
