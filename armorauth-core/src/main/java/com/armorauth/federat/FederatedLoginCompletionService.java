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
package com.armorauth.federat;

import com.armorauth.data.entity.UserInfo;
import com.armorauth.details.DelegateUserDetailsService;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.stereotype.Service;

import java.io.IOException;

@Service
public class FederatedLoginCompletionService {

    private final DelegateUserDetailsService delegateUserDetailsService;

    private final SecurityContextRepository securityContextRepository;

    private final SavedRequestAwareAuthenticationSuccessHandler successHandler;

    public FederatedLoginCompletionService(DelegateUserDetailsService delegateUserDetailsService,
                                           RequestCache requestCache,
                                           SecurityContextRepository securityContextRepository) {
        this.delegateUserDetailsService = delegateUserDetailsService;
        this.securityContextRepository = securityContextRepository;
        this.successHandler = new SavedRequestAwareAuthenticationSuccessHandler();
        this.successHandler.setDefaultTargetUrl("/");
        this.successHandler.setRequestCache(requestCache);
    }

    public void complete(HttpServletRequest request, HttpServletResponse response, UserInfo userInfo)
            throws IOException, ServletException {
        UserDetails userDetails = this.delegateUserDetailsService.loadUserByUsername(userInfo.getUsername());
        Authentication authentication =
                UsernamePasswordAuthenticationToken.authenticated(userDetails, null, userDetails.getAuthorities());
        if (authentication instanceof AbstractAuthenticationToken authenticationToken) {
            authenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
        }
        SecurityContext context = SecurityContextHolder.createEmptyContext();
        context.setAuthentication(authentication);
        SecurityContextHolder.setContext(context);
        this.securityContextRepository.saveContext(context, request, response);
        this.successHandler.onAuthenticationSuccess(request, response, authentication);
    }

    public void clearAuthentication(HttpServletRequest request, HttpServletResponse response) {
        SecurityContextHolder.clearContext();
        SecurityContext emptyContext = SecurityContextHolder.createEmptyContext();
        this.securityContextRepository.saveContext(emptyContext, request, response);
    }
}
