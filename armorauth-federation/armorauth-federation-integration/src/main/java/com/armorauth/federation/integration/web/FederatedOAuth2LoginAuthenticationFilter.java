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

import com.armorauth.federation.integration.authentication.bind.FederatedBindUserCheckToken;
import com.armorauth.federation.integration.authentication.FederatedOAuth2LoginAuthenticationToken;
import com.armorauth.federation.integration.endpoint.BindUserRequest;
import com.armorauth.federation.integration.endpoint.BindUserRequestRepository;
import com.armorauth.federation.integration.endpoint.HttpSessionBindUserRequestRepository;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.authentication.OAuth2LoginAuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.*;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationExchange;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.UrlUtils;
import org.springframework.util.Assert;
import org.springframework.util.MultiValueMap;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;

/**
 * @see OAuth2LoginAuthenticationFilter
 */
public class FederatedOAuth2LoginAuthenticationFilter extends AbstractAuthenticationProcessingFilter {


    public static final String DEFAULT_FILTER_PROCESSES_URI = "/login/federated/oauth2/code/*";

    private static final String AUTHORIZATION_REQUEST_NOT_FOUND_ERROR_CODE = "authorization_request_not_found";

    private static final String CLIENT_REGISTRATION_NOT_FOUND_ERROR_CODE = "client_registration_not_found";

    private final RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

    private ClientRegistrationRepository clientRegistrationRepository;

    private OAuth2AuthorizedClientRepository authorizedClientRepository;

    private AuthorizationRequestRepository<OAuth2AuthorizationRequest> authorizationRequestRepository = new HttpSessionOAuth2AuthorizationRequestRepository();

    private BindUserRequestRepository<BindUserRequest> bindUserRequestRepository = new HttpSessionBindUserRequestRepository();

    private Converter<FederatedOAuth2LoginAuthenticationToken, OAuth2AuthenticationToken> authenticationResultConverter = this::createAuthenticationResult;

    private String bindUserPage;


    public FederatedOAuth2LoginAuthenticationFilter(ClientRegistrationRepository clientRegistrationRepository,
                                                    OAuth2AuthorizedClientService authorizedClientService) {
        this(clientRegistrationRepository, authorizedClientService, DEFAULT_FILTER_PROCESSES_URI);
    }


    public FederatedOAuth2LoginAuthenticationFilter(ClientRegistrationRepository clientRegistrationRepository,
                                                    OAuth2AuthorizedClientService authorizedClientService, String filterProcessesUrl) {
        this(clientRegistrationRepository,
                new AuthenticatedPrincipalOAuth2AuthorizedClientRepository(authorizedClientService),
                filterProcessesUrl);
    }


    public FederatedOAuth2LoginAuthenticationFilter(ClientRegistrationRepository clientRegistrationRepository,
                                                    OAuth2AuthorizedClientRepository authorizedClientRepository, String filterProcessesUrl) {
        super(filterProcessesUrl);
        Assert.notNull(clientRegistrationRepository, "clientRegistrationRepository cannot be null");
        Assert.notNull(authorizedClientRepository, "authorizedClientRepository cannot be null");
        this.clientRegistrationRepository = clientRegistrationRepository;
        this.authorizedClientRepository = authorizedClientRepository;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException, IOException, ServletException {
        MultiValueMap<String, String> params = OAuth2AuthorizationResponseUtils.toMultiMap(request.getParameterMap());
        if (!OAuth2AuthorizationResponseUtils.isAuthorizationResponse(params)) {
            OAuth2Error oauth2Error = new OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST);
            throw new OAuth2AuthenticationException(oauth2Error, oauth2Error.toString());
        }
        // Remove Authorization Request
        OAuth2AuthorizationRequest authorizationRequest = this.authorizationRequestRepository
                .removeAuthorizationRequest(request, response);
        if (authorizationRequest == null) {
            OAuth2Error oauth2Error = new OAuth2Error(AUTHORIZATION_REQUEST_NOT_FOUND_ERROR_CODE);
            throw new OAuth2AuthenticationException(oauth2Error, oauth2Error.toString());
        }
        // Get  Authorization Request Registration
        String registrationId = authorizationRequest.getAttribute(OAuth2ParameterNames.REGISTRATION_ID);
        ClientRegistration clientRegistration = this.clientRegistrationRepository.findByRegistrationId(registrationId);
        if (clientRegistration == null) {
            OAuth2Error oauth2Error = new OAuth2Error(CLIENT_REGISTRATION_NOT_FOUND_ERROR_CODE,
                    "Client Registration not found with Id: " + registrationId, null);
            throw new OAuth2AuthenticationException(oauth2Error, oauth2Error.toString());
        }
        // @formatter:off
        String redirectUri = UriComponentsBuilder.fromHttpUrl(UrlUtils.buildFullRequestUrl(request))
                .replaceQuery(null)
                .build()
                .toUriString();
        // @formatter:on
        // Authenticate FederatedOAuth2LoginAuthenticationToken
        OAuth2AuthorizationResponse authorizationResponse = OAuth2AuthorizationResponseUtils.convert(params, redirectUri);
        Object authenticationDetails = this.authenticationDetailsSource.buildDetails(request);
        FederatedOAuth2LoginAuthenticationToken authenticationRequest = new FederatedOAuth2LoginAuthenticationToken(clientRegistration,
                new OAuth2AuthorizationExchange(authorizationRequest, authorizationResponse));
        authenticationRequest.setDetails(authenticationDetails);
        FederatedOAuth2LoginAuthenticationToken federatedOAuth2LoginAuthenticationToken =
                (FederatedOAuth2LoginAuthenticationToken) this.getAuthenticationManager().authenticate(authenticationRequest);
        //Convert OAuth2AuthenticationToken
        OAuth2AuthenticationToken oauth2Authentication = this.authenticationResultConverter
                .convert(federatedOAuth2LoginAuthenticationToken);
        Assert.notNull(oauth2Authentication, "authentication result cannot be null");
        oauth2Authentication.setDetails(authenticationDetails);
        //Check BindUser
        FederatedBindUserCheckToken checkBindUserRequest = new FederatedBindUserCheckToken(
                oauth2Authentication.getPrincipal(),
                federatedOAuth2LoginAuthenticationToken.getClientRegistration()
        );
        BindUserRequest bindUserRequest =
                new BindUserRequest(federatedOAuth2LoginAuthenticationToken.getPrincipal(),
                        federatedOAuth2LoginAuthenticationToken.getClientRegistration().getRegistrationId(),
                        federatedOAuth2LoginAuthenticationToken
                                .getClientRegistration()
                                .getProviderDetails()
                                .getUserInfoEndpoint()
                                .getUserNameAttributeName()
                );
        bindUserRequestRepository.saveBindUserRequest(bindUserRequest, request, response);
        FederatedBindUserCheckToken checkBindUserResult =
                (FederatedBindUserCheckToken) this.getAuthenticationManager().authenticate(checkBindUserRequest);
        // if not authenticated, send redirect to bind user page
        if (!checkBindUserResult.isAuthenticated()) {
            //send redirect to bind user page
            sendRedirectForBindUser(request, response);
        }
        //AuthorizedClientRepository saveAuthorizedClient
        OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(
                federatedOAuth2LoginAuthenticationToken.getClientRegistration(),
                oauth2Authentication.getName(),
                federatedOAuth2LoginAuthenticationToken.getAccessToken(),
                federatedOAuth2LoginAuthenticationToken.getRefreshToken()
        );
        this.authorizedClientRepository.saveAuthorizedClient(authorizedClient, oauth2Authentication, request, response);
        return oauth2Authentication;
    }


    public void setBindUserPage(String bindUserPage) {
        this.bindUserPage = bindUserPage;
    }

    private void sendRedirectForBindUser(HttpServletRequest request, HttpServletResponse response) throws IOException {
        this.redirectStrategy.sendRedirect(request, response, bindUserPage);
    }

    /**
     * Sets the repository for stored {@link OAuth2AuthorizationRequest}'s.
     *
     * @param authorizationRequestRepository the repository for stored
     *                                       {@link OAuth2AuthorizationRequest}'s
     */
    public final void setAuthorizationRequestRepository(
            AuthorizationRequestRepository<OAuth2AuthorizationRequest> authorizationRequestRepository) {
        Assert.notNull(authorizationRequestRepository, "authorizationRequestRepository cannot be null");
        this.authorizationRequestRepository = authorizationRequestRepository;
    }

    public void setFederatedBindUserRequestRepository(
            BindUserRequestRepository<BindUserRequest> bindUserRequestRepository) {
        Assert.notNull(bindUserRequestRepository, "federatedBindUserRequestRepository cannot be null");
        this.bindUserRequestRepository = bindUserRequestRepository;
    }

    /**
     * Sets the converter responsible for converting from
     * {@link OAuth2LoginAuthenticationToken} to {@link OAuth2AuthenticationToken}
     * authentication result.
     *
     * @param authenticationResultConverter the converter for
     *                                      {@link OAuth2AuthenticationToken}'s
     * @since 5.6
     */
    public final void setAuthenticationResultConverter(
            Converter<FederatedOAuth2LoginAuthenticationToken, OAuth2AuthenticationToken> authenticationResultConverter) {
        Assert.notNull(authenticationResultConverter, "authenticationResultConverter cannot be null");
        this.authenticationResultConverter = authenticationResultConverter;
    }

    private OAuth2AuthenticationToken createAuthenticationResult(FederatedOAuth2LoginAuthenticationToken authenticationResult) {
        return new OAuth2AuthenticationToken(authenticationResult.getPrincipal(), authenticationResult.getAuthorities(),
                authenticationResult.getClientRegistration().getRegistrationId());
    }


}
