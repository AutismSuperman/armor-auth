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

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.util.Optional;

@Component
public class FederatedSessionContextRepository {

    public static final Duration PENDING_CONTEXT_TTL = Duration.ofMinutes(10);

    private static final String AUTHORIZATION_CONTEXT_ATTR =
            FederatedSessionContextRepository.class.getName() + ".AUTHORIZATION_CONTEXT";

    private static final String PENDING_CONTEXT_ATTR =
            FederatedSessionContextRepository.class.getName() + ".PENDING_CONTEXT";

    public void saveAuthorizationContext(HttpServletRequest request, FederatedAuthorizationContext context) {
        request.getSession(true).setAttribute(AUTHORIZATION_CONTEXT_ATTR, context);
    }

    public Optional<FederatedAuthorizationContext> loadAuthorizationContext(HttpServletRequest request) {
        return loadContext(request, AUTHORIZATION_CONTEXT_ATTR, FederatedAuthorizationContext.class);
    }

    public void clearAuthorizationContext(HttpServletRequest request) {
        clearContext(request, AUTHORIZATION_CONTEXT_ATTR);
    }

    public void savePendingContext(HttpServletRequest request, PendingFederatedContext context) {
        request.getSession(true).setAttribute(PENDING_CONTEXT_ATTR, context);
    }

    public Optional<PendingFederatedContext> loadPendingContext(HttpServletRequest request) {
        return loadContext(request, PENDING_CONTEXT_ATTR, PendingFederatedContext.class);
    }

    public void clearPendingContext(HttpServletRequest request) {
        clearContext(request, PENDING_CONTEXT_ATTR);
    }

    public void clearAll(HttpServletRequest request) {
        clearAuthorizationContext(request);
        clearPendingContext(request);
    }

    private <T> Optional<T> loadContext(HttpServletRequest request, String attributeName, Class<T> targetType) {
        HttpSession session = request.getSession(false);
        if (session == null) {
            return Optional.empty();
        }
        Object context = session.getAttribute(attributeName);
        if (targetType.isInstance(context)) {
            return Optional.of(targetType.cast(context));
        }
        return Optional.empty();
    }

    private void clearContext(HttpServletRequest request, String attributeName) {
        HttpSession session = request.getSession(false);
        if (session != null) {
            session.removeAttribute(attributeName);
        }
    }
}
