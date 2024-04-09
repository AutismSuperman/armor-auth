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

import com.armorauth.core.configurers.web.OAuth2UserLoginFilterSecurityConfigurer;
import com.armorauth.core.constant.ConfigBeanNameConstants;
import com.armorauth.core.details.DelegateUserDetailsService;
import com.armorauth.core.security.FailureAuthenticationEntryPoint;
import com.armorauth.core.security.FederatedAuthenticationSuccessHandler;
import com.armorauth.data.repository.UserInfoRepository;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationEntryPointFailureHandler;

@Configuration(proxyBeanMethods = false)
public class AuthenticationConfiguration {

    private static final String CUSTOM_LOGIN_PAGE = "/login";

    private static final String REMEMBER_ME_COOKIE_NAME = "armorauth-remember-me";


    @Bean(name = ConfigBeanNameConstants.DEFAULT_SECURITY_FILTER_CHAIN)
    @Order(Ordered.HIGHEST_PRECEDENCE + 2)
    public SecurityFilterChain defaultSecurityFilterChain(
            HttpSecurity http,
            DelegateUserDetailsService delegateUserDetailsService) throws Exception {
        AuthenticationEntryPointFailureHandler authenticationFailureHandler =
                new AuthenticationEntryPointFailureHandler(new FailureAuthenticationEntryPoint());
        FederatedAuthenticationSuccessHandler federatedAuthenticationSuccessHandler =
                new FederatedAuthenticationSuccessHandler();
        http.authorizeHttpRequests(authorizeRequests -> authorizeRequests
                        .anyRequest().authenticated()
                )
                .csrf(AbstractHttpConfigurer::disable)
                .userDetailsService(delegateUserDetailsService);
        // OAuth2UserLoginFilterSecurityConfigurer Customizer
        http.apply(new OAuth2UserLoginFilterSecurityConfigurer())
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
                );
        return http.build();
    }

    private boolean verifyCaptchaMock(String account, String captcha) {
        return captcha.equals("1234");
    }

    //*********************************************UserDetailsService*********************************************//


    @Bean
    public DelegateUserDetailsService delegateUserDetailsService(UserInfoRepository userInfoRepository) {
        return new DelegateUserDetailsService(userInfoRepository);
    }


}
