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
package com.armorauth.config;

import com.armorauth.configurers.OAuth2FederatedLoginServerConfigurer;
import com.armorauth.configurers.web.OAuth2UserLoginFilterSecurityConfigurer;
import com.armorauth.data.repository.UserInfoRepository;
import com.armorauth.details.DelegateUserDetailsService;
import com.armorauth.federat.ExtendedOAuth2ClientPropertiesMapper;
import com.armorauth.federat.FederatedLoginOrchestrator;
import com.armorauth.security.FederatedAuthenticationSuccessHandler;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.security.oauth2.client.autoconfigure.OAuth2ClientProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.JdbcOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.session.HttpSessionEventPublisher;

import java.util.Collections;
import java.util.Map;

@EnableWebSecurity
@EnableConfigurationProperties(OAuth2ClientProperties.class)
@Configuration(proxyBeanMethods = false)
public class DefaultSecurityConfig {

    private static final String CUSTOM_LOGIN_PAGE = "/login";

    private static final String REMEMBER_ME_COOKIE_NAME = "armorauth-remember-me";

    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE + 1)
    SecurityFilterChain defaultSecurityFilterChain(
            HttpSecurity http,
            DelegateUserDetailsService delegateUserDetailsService,
            FederatedAuthenticationSuccessHandler federatedAuthenticationSuccessHandler,
            SecurityContextRepository securityContextRepository,
            @Value("${armorauth.federation.enabled:true}") boolean federationEnabled) throws Exception {
        SimpleUrlAuthenticationFailureHandler authenticationFailureHandler =
                new SimpleUrlAuthenticationFailureHandler(CUSTOM_LOGIN_PAGE + "?error");

        http.authorizeHttpRequests(authorizeRequests -> authorizeRequests
                        .requestMatchers("/login/captcha/send").permitAll()
                        .requestMatchers("/federated/confirm").permitAll()
                        .requestMatchers("/federated/confirm/create").permitAll()
                        .requestMatchers("/federated/confirm/bind").permitAll()
                        .anyRequest().authenticated()
                )
                .csrf(AbstractHttpConfigurer::disable)
                .logout(logout -> logout.logoutSuccessUrl(CUSTOM_LOGIN_PAGE + "?logout"))
                .securityContext(securityContext -> securityContext.securityContextRepository(securityContextRepository))
                .userDetailsService(delegateUserDetailsService);

        http.with(new OAuth2UserLoginFilterSecurityConfigurer(), oauth2UserLogin ->
                oauth2UserLogin
                        .formLogin(formLogin -> formLogin
                                .loginPage(CUSTOM_LOGIN_PAGE).permitAll()
                                .successHandler(federatedAuthenticationSuccessHandler)
                                .failureHandler(authenticationFailureHandler)
                        )
                        .captchaLogin(captchaLogin -> captchaLogin
                                .captchaVerifyService(this::verifyCaptchaMock)
                                .userDetailsService(delegateUserDetailsService)
                                .successHandler(federatedAuthenticationSuccessHandler)
                                .failureHandler(authenticationFailureHandler)
                        )
                        .rememberMe(rememberMe -> rememberMe
                                .rememberMeCookieName(REMEMBER_ME_COOKIE_NAME)
                                .userDetailsService(delegateUserDetailsService)
                        )
        );

        if (federationEnabled) {
            http.with(new OAuth2FederatedLoginServerConfigurer(), federatedLogin ->
                    federatedLogin.federatedAuthorization(federatedAuthorization ->
                            federatedAuthorization.loginPageUrl(CUSTOM_LOGIN_PAGE)
                    )
            );
        }

        return http.build();
    }

    private boolean verifyCaptchaMock(String account, String captcha) {
        return "1234".equals(captcha);
    }

    @Bean
    public DelegateUserDetailsService delegateUserDetailsService(UserInfoRepository userInfoRepository) {
        return new DelegateUserDetailsService(userInfoRepository);
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    @Bean
    public ObjectMapper objectMapper() {
        return new ObjectMapper().registerModule(new JavaTimeModule());
    }

    @Bean
    public RequestCache requestCache() {
        return new HttpSessionRequestCache();
    }

    @Bean
    public SecurityContextRepository securityContextRepository() {
        return new HttpSessionSecurityContextRepository();
    }

    @Bean
    public FederatedAuthenticationSuccessHandler federatedAuthenticationSuccessHandler(
            RequestCache requestCache,
            FederatedLoginOrchestrator federatedLoginOrchestrator) {
        FederatedAuthenticationSuccessHandler successHandler =
                new FederatedAuthenticationSuccessHandler("/", requestCache);
        successHandler.setFederatedLoginOrchestrator(federatedLoginOrchestrator);
        return successHandler;
    }

    @Bean
    public ClientRegistrationRepository clientRegistrationRepository(@Autowired(required = false) OAuth2ClientProperties properties) {
        if (properties == null || properties.getRegistration().isEmpty()) {
            return new InMemoryClientRegistrationRepository(Collections.emptyList());
        }
        ExtendedOAuth2ClientPropertiesMapper extendedOAuth2ClientPropertiesMapper =
                new ExtendedOAuth2ClientPropertiesMapper(properties);
        Map<String, ClientRegistration> extendedClientRegistrations =
                extendedOAuth2ClientPropertiesMapper.asClientRegistrations();
        return new InMemoryClientRegistrationRepository(extendedClientRegistrations);
    }

    @Bean
    public OAuth2AuthorizedClientService authorizedClientService(
            JdbcTemplate jdbcTemplate,
            ClientRegistrationRepository clientRegistrationRepository) {
        return new JdbcOAuth2AuthorizedClientService(jdbcTemplate, clientRegistrationRepository);
    }

    @Bean
    public SessionRegistry sessionRegistry() {
        return new SessionRegistryImpl();
    }

    @Bean
    public HttpSessionEventPublisher httpSessionEventPublisher() {
        return new HttpSessionEventPublisher();
    }

    @Bean
    WebSecurityCustomizer webSecurityCustomizer() {
        return web -> web.ignoring()
                .requestMatchers("/error")
                .requestMatchers("/favicon.ico")
                .requestMatchers("/favicon.svg")
                .requestMatchers("/static/**")
                .requestMatchers("/resources/**")
                .requestMatchers("/assets/**")
                .requestMatchers("/brand/**")
                .requestMatchers("/oauth/**")
                .requestMatchers("/webjars/**")
                .requestMatchers("/h2-console/**")
                .requestMatchers("/actuator/health")
                .requestMatchers("/system/monitor");
    }

}
