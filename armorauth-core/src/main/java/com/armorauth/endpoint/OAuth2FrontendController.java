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
package com.armorauth.endpoint;

import com.armorauth.data.entity.OAuth2Scope;
import com.armorauth.data.repository.OAuth2ScopeRepository;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.springframework.aot.hint.annotation.RegisterReflectionForBinding;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.CurrentSecurityContext;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsent;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.web.WebAttributes;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.security.Principal;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

@Controller
public class OAuth2FrontendController {

    private final RegisteredClientRepository registeredClientRepository;

    private final ClientRegistrationRepository clientRegistrationRepository;

    private final OAuth2AuthorizationConsentService authorizationConsentService;

    private final OAuth2ScopeRepository oAuth2ScopeRepository;

    private final AuthorizationServerSettings authorizationServerSettings;

    public OAuth2FrontendController(RegisteredClientRepository registeredClientRepository,
                                    ClientRegistrationRepository clientRegistrationRepository,
                                    OAuth2AuthorizationConsentService authorizationConsentService,
                                    OAuth2ScopeRepository oAuth2ScopeRepository,
                                    AuthorizationServerSettings authorizationServerSettings) {
        this.registeredClientRepository = registeredClientRepository;
        this.clientRegistrationRepository = clientRegistrationRepository;
        this.authorizationConsentService = authorizationConsentService;
        this.oAuth2ScopeRepository = oAuth2ScopeRepository;
        this.authorizationServerSettings = authorizationServerSettings;
    }

    @GetMapping(path = "/", produces = MediaType.TEXT_HTML_VALUE)
    @RegisterReflectionForBinding(String.class)
    public String index(@CurrentSecurityContext(expression = "authentication") Authentication authentication,
                        Model model) {
        if (authentication == null || authentication instanceof AnonymousAuthenticationToken) {
            return "redirect:/login";
        }
        model.addAttribute("userName", authentication.getName());
        return "home";
    }

    @GetMapping(path = "/login", produces = MediaType.TEXT_HTML_VALUE)
    @RegisterReflectionForBinding(String.class)
    public String login(@CurrentSecurityContext(expression = "authentication") Authentication authentication,
                        HttpServletRequest request,
                        Model model,
                        @RequestParam(name = "error", required = false) String error,
                        @RequestParam(name = "logout", required = false) String logout) {
        if (authentication != null && !(authentication instanceof AnonymousAuthenticationToken)) {
            return "redirect:/";
        }

        model.addAttribute("federatedProviders", getFederatedProviders());
        model.addAttribute("loggedOut", logout != null);

        if (error != null) {
            String errorMessage = "用户名、密码或验证码不正确。";
            HttpSession session = request.getSession(false);
            if (session != null) {
                Object authenticationException = session.getAttribute(WebAttributes.AUTHENTICATION_EXCEPTION);
                if (authenticationException instanceof Exception exception && StringUtils.hasText(exception.getMessage())) {
                    errorMessage = exception.getMessage();
                }
                session.removeAttribute(WebAttributes.AUTHENTICATION_EXCEPTION);
            }
            model.addAttribute("errorMessage", errorMessage);
        }

        return "login";
    }

    @GetMapping(path = "/consent", produces = MediaType.TEXT_HTML_VALUE)
    @RegisterReflectionForBinding(String.class)
    public String consent(Principal principal, Model model,
                          @RequestParam(OAuth2ParameterNames.CLIENT_ID) String clientId,
                          @RequestParam(OAuth2ParameterNames.SCOPE) String scope,
                          @RequestParam(OAuth2ParameterNames.STATE) String state,
                          @RequestParam(name = OAuth2ParameterNames.USER_CODE, required = false) String userCode) {
        RegisteredClient registeredClient = this.registeredClientRepository.findByClientId(clientId);
        assert registeredClient != null;
        String id = registeredClient.getId();
        OAuth2AuthorizationConsent currentAuthorizationConsent =
                this.authorizationConsentService.findById(id, principal.getName());
        Set<String> authorizedScopes = currentAuthorizationConsent != null
                ? currentAuthorizationConsent.getScopes()
                : Collections.emptySet();
        Set<OAuth2Scope> scopesToApproves = new HashSet<>();
        Set<OAuth2Scope> previouslyApprovedScopesSet = new HashSet<>();
        String[] scopes = StringUtils.delimitedListToStringArray(scope, " ");
        List<OAuth2Scope> oAuth2Scopes =
                oAuth2ScopeRepository.findAllByClientIdAndScopeIn(clientId, Arrays.asList(scopes));

        oAuth2Scopes.forEach(oAuth2Scope -> {
            if (authorizedScopes.contains(oAuth2Scope.getScope())) {
                previouslyApprovedScopesSet.add(oAuth2Scope);
            } else {
                scopesToApproves.add(oAuth2Scope);
            }
        });

        model.addAttribute("userCode", userCode);
        model.addAttribute("requestUri", StringUtils.hasText(userCode)
                ? authorizationServerSettings.getDeviceVerificationEndpoint()
                : authorizationServerSettings.getAuthorizationEndpoint());
        model.addAttribute("clientId", clientId);
        model.addAttribute("clientName", registeredClient.getClientName());
        model.addAttribute("state", state);
        model.addAttribute("scopes", scopesToApproves);
        model.addAttribute("previouslyApprovedScopes", previouslyApprovedScopesSet);
        model.addAttribute("principalName", principal.getName());
        return "consent";
    }

    private List<ClientRegistration> getFederatedProviders() {
        if (this.clientRegistrationRepository instanceof Iterable<?> registrations) {
            List<ClientRegistration> providers = new ArrayList<>();
            for (Object registration : registrations) {
                if (registration instanceof ClientRegistration clientRegistration) {
                    providers.add(clientRegistration);
                }
            }
            return providers;
        }
        return Collections.emptyList();
    }

}
