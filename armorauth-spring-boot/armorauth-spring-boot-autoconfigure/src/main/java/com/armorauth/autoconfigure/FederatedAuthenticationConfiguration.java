package com.armorauth.autoconfigure;


import com.armorauth.federation.core.ExtendedOAuth2ClientPropertiesMapper;
import com.armorauth.federation.core.ExtendedOAuth2ClientProvider;
import com.armorauth.federation.core.endpoint.OAuth2AccessTokenRestTemplateConverter;
import com.armorauth.federation.core.endpoint.OAuth2AuthorizationCodeGrantRequestConverter;
import com.armorauth.federation.core.web.converter.OAuth2AuthorizationRequestConverter;
import com.armorauth.federation.gitee.user.GiteeOAuth2UserService;
import com.armorauth.federation.integration.DelegatingAccessTokenResponseClient;
import com.armorauth.federation.integration.DelegatingAuthorizationRequestResolver;
import com.armorauth.federation.integration.DelegatingOAuth2UserService;
import com.armorauth.federation.integration.web.FederatedAuthenticationEntryPoint;
import com.armorauth.federation.integration.web.configurers.FederatedLoginConfigurer;
import com.armorauth.federation.qq.endpoint.QqAccessTokenRestTemplateConverter;
import com.armorauth.federation.qq.endpoint.QqAuthorizationCodeGrantRequestConverter;
import com.armorauth.federation.wechat.endpoint.WechatAccessTokenRestTemplateConverter;
import com.armorauth.federation.wechat.endpoint.WechatAuthorizationCodeGrantRequestConverter;
import com.armorauth.federation.wechat.web.converter.WechatAuthorizationRequestConverter;
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
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.RequestMatcher;

import java.util.ArrayList;
import java.util.HashMap;
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

        FederatedLoginConfigurer federatedLoginConfigurer = new FederatedLoginConfigurer();
        RequestMatcher endpointsMatcher = federatedLoginConfigurer.getEndpointsMatcher();
        http.securityMatcher(endpointsMatcher);
        http.apply(federatedLoginConfigurer);
        FederatedAuthenticationEntryPoint authenticationEntryPoint =
                new FederatedAuthenticationEntryPoint(CUSTOM_LOGIN_PAGE, clientRegistrationRepository);
        http.exceptionHandling(exceptionHandling ->
                exceptionHandling
                        .authenticationEntryPoint(authenticationEntryPoint)
        );
        //OAuth 授权地址转换 OAuth2AuthorizationRequestConverter
        List<OAuth2AuthorizationRequestConverter> authorizationRequestConverters = new ArrayList<>();
        authorizationRequestConverters.add(new WechatAuthorizationRequestConverter());
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
        //OAuth 查询用户信息 UserService
        Map<String, OAuth2UserService<OAuth2UserRequest, OAuth2User>> userServices = new HashMap<>();
        userServices.put(ExtendedOAuth2ClientProvider.getNameLowerCase(GITEE), new GiteeOAuth2UserService());
        userServices.put(ExtendedOAuth2ClientProvider.getNameLowerCase(QQ), new GiteeOAuth2UserService());
        userServices.put(ExtendedOAuth2ClientProvider.getNameLowerCase(WECHAT), new GiteeOAuth2UserService());
        DelegatingOAuth2UserService delegatingOAuth2UserService = new DelegatingOAuth2UserService(userServices);
        //OAuth2LoginConfigurer
        http.getConfigurer(FederatedLoginConfigurer.class)
                .loginPage(CUSTOM_LOGIN_PAGE)
                .authorizationEndpoint(authorizationEndpoint -> authorizationEndpoint
                        .authorizationRequestResolver(delegatingAuthorizationRequestResolver)
                )
                .tokenEndpoint(tokenEndpoint -> tokenEndpoint
                        .accessTokenResponseClient(accessTokenResponseClient)
                )
                .userInfoEndpoint(userInfoEndpoint -> userInfoEndpoint
                        .userService(delegatingOAuth2UserService)
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
