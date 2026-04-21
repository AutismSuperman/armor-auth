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
package com.armorauth.federation.security;

import com.armorauth.federation.FederatedLoginOrchestrator;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.util.Assert;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.function.Consumer;

/**
 * An {@link AuthenticationSuccessHandler} for capturing the {@link OidcUser} or
 * {@link OAuth2User} for Federated Account Linking or JIT Account Provisioning.
 *
 * @author Steve Riesenberg
 * @since 0.2.3
 */
public final class FederatedAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

    private static final String DEFAULT_TARGET_URL = "/";

    private final SavedRequestAwareAuthenticationSuccessHandler delegateAuthenticationSuccessHandler =
            new SavedRequestAwareAuthenticationSuccessHandler();

    private AuthenticationSuccessHandler authenticationSuccessHandler = this.delegateAuthenticationSuccessHandler;

    private Consumer<OAuth2User> oauth2UserHandler = (user) -> {
    };

    private Consumer<OidcUser> oidcUserHandler = (user) -> {
    };

    private FederatedLoginOrchestrator federatedLoginOrchestrator;

    public FederatedAuthenticationSuccessHandler() {
        this(DEFAULT_TARGET_URL, new HttpSessionRequestCache());
    }

    public FederatedAuthenticationSuccessHandler(String redirect, RequestCache requestCache) {
        Assert.notNull(requestCache, "requestCache must not be null");
        this.delegateAuthenticationSuccessHandler.setDefaultTargetUrl(redirect);
        this.delegateAuthenticationSuccessHandler.setRequestCache(requestCache);
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {
        Object principal = authentication.getPrincipal();
        if (principal instanceof OidcUser oidcUser) {
            this.oidcUserHandler.accept(oidcUser);
        } else if (principal instanceof OAuth2User oauth2User) {
            this.oauth2UserHandler.accept(oauth2User);
        }
        if (principal instanceof OAuth2User && this.federatedLoginOrchestrator != null
                && this.federatedLoginOrchestrator.handleSuccess(request, response, authentication)) {
            return;
        }
        this.authenticationSuccessHandler.onAuthenticationSuccess(request, response, authentication);
    }

    public void setOAuth2UserHandler(Consumer<OAuth2User> oauth2UserHandler) {
        this.oauth2UserHandler = oauth2UserHandler;
    }

    public void setOidcUserHandler(Consumer<OidcUser> oidcUserHandler) {
        this.oidcUserHandler = oidcUserHandler;
    }

    public void setAuthenticationSuccessHandler(AuthenticationSuccessHandler authenticationSuccessHandler) {
        Assert.notNull(authenticationSuccessHandler, "authenticationSuccessHandler cannot be null");
        this.authenticationSuccessHandler = authenticationSuccessHandler;
    }

    public void setRequestCache(RequestCache requestCache) {
        this.delegateAuthenticationSuccessHandler.setRequestCache(requestCache);
    }

    public void setFederatedLoginOrchestrator(FederatedLoginOrchestrator federatedLoginOrchestrator) {
        this.federatedLoginOrchestrator = federatedLoginOrchestrator;
    }

}
