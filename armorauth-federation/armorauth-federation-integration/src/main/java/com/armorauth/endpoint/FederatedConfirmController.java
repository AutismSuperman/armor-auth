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

import com.armorauth.data.entity.UserInfo;
import com.armorauth.federat.FederatedAccountService;
import com.armorauth.federat.FederatedLoginCompletionService;
import com.armorauth.federat.FederatedSessionContextRepository;
import com.armorauth.federat.PendingFederatedContext;
import com.armorauth.federat.UserFederatedBindingService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.web.WebAttributes;
import org.springframework.stereotype.Controller;
import org.springframework.ui.ExtendedModelMap;
import org.springframework.ui.Model;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.View;
import org.springframework.web.servlet.ViewResolver;

import java.util.List;
import java.util.Locale;

@Controller
public class FederatedConfirmController {

    private static final int MIN_PASSWORD_LENGTH = 6;

    private final FederatedSessionContextRepository federatedSessionContextRepository;

    private final FederatedAccountService federatedAccountService;

    private final UserFederatedBindingService userFederatedBindingService;

    private final FederatedLoginCompletionService federatedLoginCompletionService;

    private final List<ViewResolver> viewResolvers;

    public FederatedConfirmController(FederatedSessionContextRepository federatedSessionContextRepository,
                                      FederatedAccountService federatedAccountService,
                                      UserFederatedBindingService userFederatedBindingService,
                                      FederatedLoginCompletionService federatedLoginCompletionService,
                                      List<ViewResolver> viewResolvers) {
        this.federatedSessionContextRepository = federatedSessionContextRepository;
        this.federatedAccountService = federatedAccountService;
        this.userFederatedBindingService = userFederatedBindingService;
        this.federatedLoginCompletionService = federatedLoginCompletionService;
        this.viewResolvers = viewResolvers;
    }

    @GetMapping(path = "/federated/confirm", produces = MediaType.TEXT_HTML_VALUE)
    public String confirmPage(HttpServletRequest request,
                              Model model,
                              @RequestParam(name = "tab", required = false, defaultValue = "create") String tab) {
        PendingFederatedContext pendingContext = loadPendingContext(request);
        if (pendingContext == null) {
            return redirectToLoginError(request, "联合登录确认信息不存在或已过期，请重新发起授权。");
        }
        populateModel(model, pendingContext, pendingContext.suggestedUsername(), "", normalizeTab(tab), null);
        return "federated-confirm";
    }

    @PostMapping(path = "/federated/confirm/create", produces = MediaType.TEXT_HTML_VALUE)
    public void confirmCreate(HttpServletRequest request,
                              HttpServletResponse response,
                              @RequestParam("username") String username,
                              @RequestParam("password") String password,
                              @RequestParam("confirmPassword") String confirmPassword) throws Exception {
        PendingFederatedContext pendingContext = loadPendingContext(request);
        if (pendingContext == null) {
            response.sendRedirect(request.getContextPath() + "/login?error");
            return;
        }
        String normalizedUsername = username == null ? "" : username.trim();
        String validationMessage = validateCreateForm(normalizedUsername, password, confirmPassword);
        if (validationMessage != null) {
            renderConfirmView(request, response, pendingContext, normalizedUsername, "", "create", validationMessage);
            return;
        }
        try {
            String now = this.federatedAccountService.currentTimestamp();
            UserInfo userInfo = this.federatedAccountService.createLocalUser(
                    normalizedUsername,
                    password,
                    StringUtils.hasText(pendingContext.displayName()) ? pendingContext.displayName() : normalizedUsername,
                    now
            );
            this.userFederatedBindingService.createOrUpdateBinding(userInfo, pendingContext.toProfile(), now);
            this.federatedSessionContextRepository.clearAll(request);
            this.federatedLoginCompletionService.complete(request, response, userInfo);
        } catch (IllegalArgumentException | IllegalStateException ex) {
            renderConfirmView(request, response, pendingContext, normalizedUsername, "", "create", ex.getMessage());
        }
    }

    @PostMapping(path = "/federated/confirm/bind", produces = MediaType.TEXT_HTML_VALUE)
    public void confirmBind(HttpServletRequest request,
                            HttpServletResponse response,
                            @RequestParam("username") String username,
                            @RequestParam("password") String password) throws Exception {
        PendingFederatedContext pendingContext = loadPendingContext(request);
        if (pendingContext == null) {
            response.sendRedirect(request.getContextPath() + "/login?error");
            return;
        }
        String normalizedUsername = username == null ? "" : username.trim();
        if (!StringUtils.hasText(normalizedUsername) || !StringUtils.hasText(password)) {
            renderConfirmView(request, response, pendingContext, pendingContext.suggestedUsername(), normalizedUsername,
                    "bind", "请输入已有本地账号的用户名和密码。");
            return;
        }
        UserInfo userInfo = this.federatedAccountService.authenticateLocalUser(normalizedUsername, password)
                .orElse(null);
        if (userInfo == null) {
            renderConfirmView(request, response, pendingContext, pendingContext.suggestedUsername(), normalizedUsername,
                    "bind", "本地账号认证失败，请检查用户名或密码。");
            return;
        }
        try {
            String now = this.federatedAccountService.currentTimestamp();
            this.userFederatedBindingService.createOrUpdateBinding(userInfo, pendingContext.toProfile(), now);
            this.federatedSessionContextRepository.clearAll(request);
            this.federatedLoginCompletionService.complete(request, response, userInfo);
        } catch (IllegalStateException ex) {
            renderConfirmView(request, response, pendingContext, pendingContext.suggestedUsername(), normalizedUsername,
                    "bind", ex.getMessage());
        }
    }

    private PendingFederatedContext loadPendingContext(HttpServletRequest request) {
        PendingFederatedContext pendingContext = this.federatedSessionContextRepository.loadPendingContext(request)
                .orElse(null);
        if (pendingContext == null) {
            rememberError(request, "联合登录确认信息不存在或已过期，请重新发起授权。");
            return null;
        }
        if (!pendingContext.isComplete() || pendingContext.isExpired(FederatedSessionContextRepository.PENDING_CONTEXT_TTL)) {
            this.federatedSessionContextRepository.clearAll(request);
            rememberError(request, "联合登录确认信息不存在或已过期，请重新发起授权。");
            return null;
        }
        return pendingContext;
    }

    private String validateCreateForm(String username, String password, String confirmPassword) {
        if (!StringUtils.hasText(username)) {
            return "请输入本地账号用户名。";
        }
        if (this.federatedAccountService.findByUsername(username).isPresent()) {
            return "用户名已存在，请更换后重试。";
        }
        if (!StringUtils.hasText(password)) {
            return "请输入本地账号密码。";
        }
        if (password.length() < MIN_PASSWORD_LENGTH) {
            return "密码长度至少需要 6 位。";
        }
        if (!password.equals(confirmPassword)) {
            return "两次输入的密码不一致。";
        }
        return null;
    }

    private void renderConfirmView(HttpServletRequest request,
                                   HttpServletResponse response,
                                   PendingFederatedContext pendingContext,
                                   String createUsername,
                                   String bindUsername,
                                   String selectedTab,
                                   String errorMessage) throws Exception {
        ExtendedModelMap model = new ExtendedModelMap();
        populateModel(model, pendingContext, createUsername, bindUsername, selectedTab, errorMessage);
        resolveView().render(model, request, response);
    }

    private View resolveView() throws Exception {
        for (ViewResolver viewResolver : this.viewResolvers) {
            View view = viewResolver.resolveViewName("federated-confirm", Locale.getDefault());
            if (view != null) {
                return view;
            }
        }
        throw new IllegalStateException("无法解析联合登录确认页视图。");
    }

    private void populateModel(Model model,
                               PendingFederatedContext pendingContext,
                               String createUsername,
                               String bindUsername,
                               String selectedTab,
                               String errorMessage) {
        model.addAttribute("pending", pendingContext);
        model.addAttribute("createUsername", StringUtils.hasText(createUsername)
                ? createUsername
                : pendingContext.suggestedUsername());
        model.addAttribute("bindUsername", bindUsername);
        model.addAttribute("selectedTab", normalizeTab(selectedTab));
        model.addAttribute("providerUserIdSummary", maskProviderUserId(pendingContext.providerUserId()));
        if (StringUtils.hasText(errorMessage)) {
            model.addAttribute("errorMessage", errorMessage);
        }
    }

    private String normalizeTab(String tab) {
        return "bind".equalsIgnoreCase(tab) ? "bind" : "create";
    }

    private String maskProviderUserId(String providerUserId) {
        if (!StringUtils.hasText(providerUserId)) {
            return "未知";
        }
        if (providerUserId.length() <= 8) {
            return providerUserId;
        }
        return providerUserId.substring(0, 4) + "..." + providerUserId.substring(providerUserId.length() - 4);
    }

    private String redirectToLoginError(HttpServletRequest request, String message) {
        this.federatedSessionContextRepository.clearAll(request);
        rememberError(request, message);
        return "redirect:/login?error";
    }

    private void rememberError(HttpServletRequest request, String message) {
        request.getSession(true).setAttribute(WebAttributes.AUTHENTICATION_EXCEPTION, new BadCredentialsException(message));
    }
}
