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
package com.armorauth.federation.integration.web;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.core.log.LogMessage;
import org.springframework.http.HttpStatus;
import org.springframework.security.oauth2.client.ClientAuthorizationRequiredException;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.*;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.util.ThrowableAnalyzer;
import org.springframework.util.Assert;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * OAuth2AuthorizationRequestRedirectFilter 增强，提供定制化的功能
 *
 * @see OAuth2AuthorizationRequestRedirectFilter
 */
public class FederatedOAuth2AuthorizationRequestRedirectFilter extends OncePerRequestFilter {


    public static final String DEFAULT_AUTHORIZATION_REQUEST_BASE_URI = "/federated/authorization";

    private final ThrowableAnalyzer throwableAnalyzer = new DefaultThrowableAnalyzer();

    private RedirectStrategy authorizationRedirectStrategy = new DefaultRedirectStrategy();

    private OAuth2AuthorizationRequestResolver authorizationRequestResolver;

    private AuthorizationRequestRepository<OAuth2AuthorizationRequest> authorizationRequestRepository = new HttpSessionOAuth2AuthorizationRequestRepository();

    private RequestCache requestCache = new HttpSessionRequestCache();


    public FederatedOAuth2AuthorizationRequestRedirectFilter(ClientRegistrationRepository clientRegistrationRepository) {
        this(clientRegistrationRepository, DEFAULT_AUTHORIZATION_REQUEST_BASE_URI);
    }


    public FederatedOAuth2AuthorizationRequestRedirectFilter(ClientRegistrationRepository clientRegistrationRepository,
                                                             String authorizationRequestBaseUri) {
        Assert.notNull(clientRegistrationRepository, "clientRegistrationRepository cannot be null");
        Assert.hasText(authorizationRequestBaseUri, "authorizationRequestBaseUri cannot be empty");
        // Default AuthorizationRequestResolver may result in loss of functionality
        this.authorizationRequestResolver = new DefaultOAuth2AuthorizationRequestResolver(clientRegistrationRepository,
                authorizationRequestBaseUri);
    }


    public FederatedOAuth2AuthorizationRequestRedirectFilter(OAuth2AuthorizationRequestResolver authorizationRequestResolver) {
        Assert.notNull(authorizationRequestResolver, "authorizationRequestResolver cannot be null");
        this.authorizationRequestResolver = authorizationRequestResolver;
    }


    public void setAuthorizationRedirectStrategy(RedirectStrategy authorizationRedirectStrategy) {
        Assert.notNull(authorizationRedirectStrategy, "authorizationRedirectStrategy cannot be null");
        this.authorizationRedirectStrategy = authorizationRedirectStrategy;
    }


    public final void setAuthorizationRequestRepository(
            AuthorizationRequestRepository<OAuth2AuthorizationRequest> authorizationRequestRepository) {
        Assert.notNull(authorizationRequestRepository, "authorizationRequestRepository cannot be null");
        this.authorizationRequestRepository = authorizationRequestRepository;
    }


    public final void setRequestCache(RequestCache requestCache) {
        Assert.notNull(requestCache, "requestCache cannot be null");
        this.requestCache = requestCache;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        try {
            OAuth2AuthorizationRequest authorizationRequest = this.authorizationRequestResolver.resolve(request);
            if (authorizationRequest != null) {
                this.sendRedirectForAuthorization(request, response, authorizationRequest);
                return;
            }
        } catch (Exception ex) {
            this.unsuccessfulRedirectForAuthorization(request, response, ex);
            return;
        }
        try {
            filterChain.doFilter(request, response);
        } catch (IOException ex) {
            throw ex;
        } catch (Exception ex) {
            // Check to see if we need to handle ClientAuthorizationRequiredException
            Throwable[] causeChain = this.throwableAnalyzer.determineCauseChain(ex);
            ClientAuthorizationRequiredException authzEx = (ClientAuthorizationRequiredException) this.throwableAnalyzer
                    .getFirstThrowableOfType(ClientAuthorizationRequiredException.class, causeChain);
            if (authzEx != null) {
                try {
                    OAuth2AuthorizationRequest authorizationRequest = this.authorizationRequestResolver.resolve(request,
                            authzEx.getClientRegistrationId());
                    if (authorizationRequest == null) {
                        throw authzEx;
                    }
                    this.requestCache.saveRequest(request, response);
                    this.sendRedirectForAuthorization(request, response, authorizationRequest);
                } catch (Exception failed) {
                    this.unsuccessfulRedirectForAuthorization(request, response, failed);
                }
                return;
            }
            if (ex instanceof ServletException) {
                throw (ServletException) ex;
            }
            throw (RuntimeException) ex;
        }
    }

    private void sendRedirectForAuthorization(HttpServletRequest request, HttpServletResponse response,
                                              OAuth2AuthorizationRequest authorizationRequest) throws IOException {
        if (AuthorizationGrantType.AUTHORIZATION_CODE.equals(authorizationRequest.getGrantType())) {
            this.authorizationRequestRepository.saveAuthorizationRequest(authorizationRequest, request, response);
        }
        this.authorizationRedirectStrategy.sendRedirect(request, response,
                authorizationRequest.getAuthorizationRequestUri());
    }

    private void unsuccessfulRedirectForAuthorization(HttpServletRequest request, HttpServletResponse response,
                                                      Exception ex) throws IOException {
        LogMessage message = LogMessage.format("Authorization Request failed: %s", ex);
        // no tuned separately from other errors, but if we ever wanted to this is the place
        this.logger.error(message, ex);
        response.sendError(HttpStatus.INTERNAL_SERVER_ERROR.value(),
                HttpStatus.INTERNAL_SERVER_ERROR.getReasonPhrase());
    }

    private static final class DefaultThrowableAnalyzer extends ThrowableAnalyzer {

        @Override
        protected void initExtractorMap() {
            super.initExtractorMap();
            registerExtractor(ServletException.class, (throwable) -> {
                ThrowableAnalyzer.verifyThrowableHierarchy(throwable, ServletException.class);
                return ((ServletException) throwable).getRootCause();
            });
        }

    }

}
