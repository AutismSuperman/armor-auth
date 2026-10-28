<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>欢迎登录 - ArmorAuth</title>
    <link rel="icon" type="image/svg+xml" href="/favicon.svg">
    <link rel="shortcut icon" href="/favicon.svg">
    <link rel="stylesheet" href="/assets/armorauth-ui.css?v=2026102801">
    <script src="/assets/provider-icons.js?v=2026052501"></script>
</head>
<body class="authing-login-page identity-page google-login-page" data-page-title-key="page.login.title">
<div class="page-shell">
    <main class="login-product-shell">
        <!-- Left Brand & Feature Showcase (Authing Cloud & Google Style) -->
        <section class="login-visual-panel" data-visual="login">
            <div class="login-brand">
                <div class="brand-logo-wrap">
                    <img class="login-brand-mark" src="/brand/icon.svg" alt="ArmorAuth logo">
                </div>
                <div class="brand-text-wrap">
                    <strong>ArmorAuth</strong>
                    <small>企业级统一身份与访问管理平台</small>
                </div>
            </div>

            <div class="login-visual-copy">
                <span class="login-kicker">安全连接 · 全域统一</span>
                <h1>让每一次登录<br>安全且值得信赖</h1>
                <p>集中处理企业单点登录 (SSO)、多因素安全凭据认证 (MFA)、无密码 Passkey 与全域联合身份源接入。</p>
            </div>

            <div class="identity-feature-list" aria-label="核心能力">
                <div class="feature-item">
                    <div class="feature-icon">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path></svg>
                    </div>
                    <div class="feature-content">
                        <strong>企业级安全防护</strong>
                        <small>OAuth 2.1 / OIDC / PKCE / DPoP 安全基线</small>
                    </div>
                </div>
                <div class="feature-item">
                    <div class="feature-icon">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect><path d="M7 11V7a5 5 0 0 1 10 0v4"></path></svg>
                    </div>
                    <div class="feature-content">
                        <strong>无密码与多因素验证</strong>
                        <small>Passkey FIDO2 凭据与动态 TOTP 保护</small>
                    </div>
                </div>
                <div class="feature-item">
                    <div class="feature-icon">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><line x1="2" y1="12" x2="22" y2="12"></line><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"></path></svg>
                    </div>
                    <div class="feature-content">
                        <strong>全生态身份源互联</strong>
                        <small>SAML 2.0 / LDAP / 企业微信 / 飞书 / GitHub</small>
                    </div>
                </div>
            </div>

            <div class="login-tenant-badge">
                <span class="tenant-dot"></span>
                <span>当前环境: <strong>默认用户池 · Default Pool</strong></span>
            </div>
        </section>

        <!-- Right Authentication Card (Authing Guard & Google Sign-In) -->
        <section class="login-card-panel">
            <div class="login-card">
                <div class="login-card-toolbar">
                    <div class="login-card-logo">
                        <img src="/brand/icon.svg" alt="ArmorAuth logo">
                        <span>ArmorAuth</span>
                    </div>
                    <div class="top-actions">
                        <button class="locale-toggle" type="button" data-locale-toggle title="切换语言">
                            <span data-locale-text>EN</span>
                        </button>
                        <button class="theme-toggle" type="button" data-theme-toggle title="切换主题">
                            <span class="theme-toggle-icon" data-theme-icon>
                                <svg class="icon-sun" viewBox="0 0 24 24">
                                    <circle cx="12" cy="12" r="5"></circle>
                                    <line x1="12" y1="1" x2="12" y2="3"></line>
                                    <line x1="12" y1="21" x2="12" y2="23"></line>
                                    <line x1="4.22" y1="4.22" x2="5.64" y2="5.64"></line>
                                    <line x1="18.36" y1="18.36" x2="19.78" y2="19.78"></line>
                                    <line x1="1" y1="12" x2="3" y2="12"></line>
                                    <line x1="21" y1="12" x2="23" y2="12"></line>
                                    <line x1="4.22" y1="19.78" x2="5.64" y2="18.36"></line>
                                    <line x1="18.36" y1="5.64" x2="19.78" y2="4.22"></line>
                                </svg>
                                <svg class="icon-moon" viewBox="0 0 24 24">
                                    <path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"></path>
                                </svg>
                            </span>
                            <span data-theme-text>深色</span>
                        </button>
                    </div>
                </div>

                <div class="login-card-title">
                    <span class="login-card-kicker">Welcome</span>
                    <h1>欢迎登录</h1>
                    <p>请选择一种认证方式以继续访问</p>
                </div>

                <#if errorMessage??>
                    <div class="notice error is-dismissible" role="alert" data-page-notice data-page-error data-dismiss-after="5000">
                        <svg class="notice-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="8" x2="12" y2="12"></line><line x1="12" y1="16" x2="12.01" y2="16"></line></svg>
                        <span class="notice-message">${errorMessage}</span>
                        <button class="notice-close" type="button" aria-label="关闭提示" data-notice-close>
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" aria-hidden="true">
                                <line x1="18" y1="6" x2="6" y2="18"></line>
                                <line x1="6" y1="6" x2="18" y2="18"></line>
                            </svg>
                        </button>
                    </div>
                </#if>
                <#if loggedOut?? && loggedOut>
                    <div class="notice success is-dismissible" role="status" data-page-notice data-dismiss-after="5000">
                        <svg class="notice-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path><polyline points="22 4 12 14.01 9 11.01"></polyline></svg>
                        <span class="notice-message">您已安全退出当前会话。</span>
                        <button class="notice-close" type="button" aria-label="关闭提示" data-notice-close>
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" aria-hidden="true">
                                <line x1="18" y1="6" x2="6" y2="18"></line>
                                <line x1="6" y1="6" x2="18" y2="18"></line>
                            </svg>
                        </button>
                    </div>
                </#if>

                <div class="login-methods" data-tab-group>
                    <#assign activeLoginTab = selectedLoginTab!'password'>
                    <div class="switcher" aria-label="登录模式">
                        <button type="button" class="<#if activeLoginTab == 'password'>is-active</#if>" data-tab-target="password-login">账号密码</button>
                        <#if graphicCaptcha?? && graphicCaptcha>
                            <button type="button" class="<#if activeLoginTab == 'graphic'>is-active</#if>" data-tab-target="graphic-login">图形验证码</button>
                        </#if>
                        <#if smsCaptcha?? && smsCaptcha>
                            <button type="button" class="<#if activeLoginTab == 'sms'>is-active</#if>" data-tab-target="sms-login">短信验证码</button>
                        </#if>
                    </div>

                    <!-- Password Login -->
                    <form id="password-login" class="auth-form" action="/login" method="post" <#if activeLoginTab != 'password'>hidden</#if> data-tab-panel>
                        <div class="field-group field-with-affix">
                            <label for="username">邮箱或用户名</label>
                            <div class="field-input-box">
                                <span class="field-affix field-affix-icon">
                                    <svg class="input-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"></path><circle cx="12" cy="7" r="4"></circle></svg>
                                </span>
                                <input id="username" name="username" type="text" autocomplete="username" placeholder="请输入邮箱或用户名" required>
                            </div>
                        </div>
                        <div class="field-group field-with-affix">
                            <label for="password">密码</label>
                            <div class="field-input-box has-suffix">
                                <span class="field-affix field-affix-icon">
                                    <svg class="input-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect><path d="M7 11V7a5 5 0 0 1 10 0v4"></path></svg>
                                </span>
                                <input id="password" name="password" type="password" autocomplete="current-password" placeholder="请输入密码" required>
                                <button class="field-affix-btn" type="button" data-password-toggle title="显示/隐藏密码" aria-label="显示/隐藏密码">
                                    <svg class="eye-open" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path><circle cx="12" cy="12" r="3"></circle></svg>
                                    <svg class="eye-closed" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"></path><line x1="1" y1="1" x2="23" y2="23"></line></svg>
                                </button>
                            </div>
                        </div>
                        <div class="form-meta-row">
                            <label class="checkbox-row" for="remember-me-password">
                                <input id="remember-me-password" name="remember-me" type="checkbox" value="true">
                                <span>记住我</span>
                            </label>
                            <span class="form-meta-note">安全受控会话</span>
                        </div>
                        <div class="action-row action-row-stacked">
                            <button class="button primary" type="submit">登 录</button>
                            <button class="button secondary passkey-btn" type="button" data-passkey-login>
                                <svg class="btn-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="3"></circle><path d="M12 1v6M12 17v6M4.22 4.22l4.24 4.24M15.54 15.54l4.24 4.24M1 12h6M17 12h6M4.22 19.78l4.24-4.24M15.54 8.46l4.24-4.24"></path></svg>
                                使用 Passkey 免密登录
                            </button>
                        </div>
                    </form>

                    <!-- Graphic Captcha Login -->
                    <#if graphicCaptcha?? && graphicCaptcha>
                    <form id="graphic-login" class="auth-form" action="/login/captcha" method="post" <#if activeLoginTab != 'graphic'>hidden</#if> data-tab-panel>
                        <div class="field-group field-with-affix">
                            <label for="graphic-account">手机号或账号</label>
                            <div class="field-input-box">
                                <span class="field-affix field-affix-icon">
                                    <svg class="input-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="5" y="2" width="14" height="20" rx="2" ry="2"></rect><line x1="12" y1="18" x2="12.01" y2="18"></line></svg>
                                </span>
                                <input id="graphic-account" name="account" type="text" autocomplete="tel" placeholder="请输入手机号或账号" required>
                            </div>
                        </div>
                        <input type="hidden" name="captchaId" id="graphic-captchaId" value="">
                        <div class="field-group field-with-affix">
                            <label for="graphic-captcha">图形验证码</label>
                            <div class="captcha-image-row">
                                <div class="field-input-box">
                                    <span class="field-affix field-affix-icon">
                                        <svg class="input-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path></svg>
                                    </span>
                                    <input id="graphic-captcha" name="captcha" type="text" autocomplete="one-time-code" placeholder="输入 4 位验证码" maxlength="4" required>
                                </div>
                                <button class="captcha-image-button" type="button" title="点击刷新验证码" data-captcha-trigger>
                                    <img id="graphicCaptchaImage" class="captcha-image" src="/login/captcha/image" alt="验证码" data-captcha-refresh>
                                </button>
                            </div>
                        </div>
                        <div class="form-meta-row">
                            <label class="checkbox-row" for="remember-me-graphic">
                                <input id="remember-me-graphic" name="remember-me" type="checkbox" value="true">
                                <span>记住我</span>
                            </label>
                            <span class="form-meta-note">图片人机校验</span>
                        </div>
                        <div class="action-row action-row-stacked">
                            <button class="button primary" type="submit">验证并登录</button>
                        </div>
                    </form>
                    </#if>

                    <!-- SMS Captcha Login -->
                    <#if smsCaptcha?? && smsCaptcha>
                    <form id="sms-login" class="auth-form" action="/login/captcha" method="post" <#if activeLoginTab != 'sms'>hidden</#if> data-tab-panel>
                        <div class="notice success" hidden data-captcha-feedback></div>
                        <div class="field-group field-with-affix">
                            <label for="sms-account">手机号</label>
                            <div class="field-input-box">
                                <span class="field-affix field-affix-icon">
                                    <svg class="input-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="5" y="2" width="14" height="20" rx="2" ry="2"></rect><line x1="12" y1="18" x2="12.01" y2="18"></line></svg>
                                </span>
                                <input id="sms-account" name="account" type="text" autocomplete="tel" placeholder="请输入手机号" required>
                            </div>
                        </div>
                        <div class="field-group field-inline field-with-affix">
                            <label for="sms-captcha">短信验证码</label>
                            <div class="sms-input-row">
                                <div class="field-input-box sms-field-box">
                                    <span class="field-affix field-affix-icon">
                                        <svg class="input-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"></path></svg>
                                    </span>
                                    <input id="sms-captcha" name="captcha" type="text" autocomplete="one-time-code" placeholder="输入短信验证码" required>
                                </div>
                                <button class="button secondary inline-button sms-send-btn" type="button" data-captcha-send>获取验证码</button>
                            </div>
                        </div>
                        <div class="form-meta-row">
                            <label class="checkbox-row" for="remember-me-sms">
                                <input id="remember-me-sms" name="remember-me" type="checkbox" value="true">
                                <span>记住我</span>
                            </label>
                            <span class="form-meta-note">一次性短信密钥</span>
                        </div>
                        <div class="action-row action-row-stacked">
                            <button class="button primary" type="submit">验证并登录</button>
                        </div>
                    </form>
                    </#if>
                </div>

                <!-- Federated Social Providers -->
                <#if federatedProviders?has_content>
                    <div class="login-provider-section">
                        <div class="login-divider"><span>或使用以下方式快捷登录</span></div>
                        <#if federatedProviders?size gt 8>
                            <input class="provider-more-check" type="checkbox" id="provider-more-toggle">
                        </#if>
                        <div class="provider-list" data-provider-list>
                            <#list federatedProviders as provider>
                                <#assign providerId = provider.registrationId?lower_case>
                                <#assign providerIcon = (provider.iconKey!providerId)?lower_case>
                                <#assign providerIconUrl = provider.iconUrl!''>
                                <a class="provider-link provider-${providerId} provider-icon-${providerIcon}" href="${provider.authorizationUrl}?mode=${selectedFederatedMode}" aria-label="使用 ${provider.clientName!provider.registrationId} 登录" title="${provider.clientName!provider.registrationId}" <#if provider_index gte 8>data-provider-extra</#if>>
                                    <span class="provider-icon" data-provider-icon="${providerIcon}" aria-hidden="true">
                                        <#if providerIconUrl?has_content>
                                            <img class="provider-custom-image" src="${providerIconUrl}" alt="">
                                        <#else>
                                            <svg class="provider-symbol provider-brand-symbol" focusable="false">
                                                <use href="#provider-icon-${providerIcon}"></use>
                                            </svg>
                                            <span class="provider-fallback">${provider.iconText!'ID'}</span>
                                        </#if>
                                    </span>
                                    <span class="provider-tooltip" role="tooltip">${provider.clientName!provider.registrationId}</span>
                                </a>
                            </#list>
                        </div>
                        <#if federatedProviders?size gt 8>
                            <label class="provider-more" for="provider-more-toggle">
                                <span class="provider-more-open">展开更多登录方式</span>
                                <span class="provider-more-close">收起登录方式</span>
                            </label>
                        </#if>
                    </div>
                </#if>
                <p class="login-card-foot">受 ArmorAuth 安全架构保护 · 敏感凭据端到端加密</p>
            </div>
        </section>
    </main>
    <footer class="page-footer login-page-footer">
        <div class="page-footer-brand">
            <strong>ArmorAuth</strong>
            <span>企业统一身份与访问控制平台</span>
        </div>
        <div class="page-footer-nav" aria-label="页面信息">
            <span>简体中文</span>
            <span>安全合规</span>
            <span>隐私保护</span>
        </div>
    </footer>
</div>
<script src="/assets/armorauth-ui.js?v=2026102801"></script>
<script>
(() => {
    const passkeyButton = document.querySelector('[data-passkey-login]');
    const usernameInput = document.querySelector('#username');
    if (!passkeyButton || !window.PublicKeyCredential) {
        return;
    }

    const decodeBase64Url = (value) => {
        const base64 = String(value || '').replace(/-/g, '+').replace(/_/g, '/');
        const padded = base64 + '='.repeat((4 - base64.length % 4) % 4);
        const binary = atob(padded);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i += 1) {
            bytes[i] = binary.charCodeAt(i);
        }
        return bytes.buffer;
    };

    const encodeBase64Url = (buffer) => {
        if (!buffer) {
            return null;
        }
        const bytes = new Uint8Array(buffer);
        let binary = '';
        for (let i = 0; i < bytes.length; i += 1) {
            binary += String.fromCharCode(bytes[i]);
        }
        return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
    };

    const postJson = async (url, body) => {
        const response = await fetch(url, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(body || {})
        });
        const payload = await response.json();
        if (!response.ok || payload.code !== 200) {
            throw new Error(payload.message || window.ArmorAuthI18n?.t('passkey.loginFailed') || 'Passkey 登录失败');
        }
        return payload.data;
    };

    passkeyButton.addEventListener('click', async () => {
        try {
            passkeyButton.disabled = true;
            passkeyButton.classList.add('is-loading');
            const username = usernameInput && usernameInput.value ? usernameInput.value.trim() : '';
            const options = await postJson('/login/passkey/options', username ? {username} : {});
            const publicKey = {
                challenge: decodeBase64Url(options.challenge),
                rpId: options.rpId,
                timeout: options.timeoutMillis,
                userVerification: options.userVerification || 'preferred'
            };
            if (options.allowCredentials && options.allowCredentials.length) {
                publicKey.allowCredentials = options.allowCredentials.map((credential) => ({
                    type: credential.type || 'public-key',
                    id: decodeBase64Url(credential.id),
                    transports: credential.transports || undefined
                }));
            }

            const credential = await navigator.credentials.get({publicKey});
            const result = await postJson('/login/passkey/finish', {
                credentialId: credential.id,
                clientDataJSON: encodeBase64Url(credential.response.clientDataJSON),
                authenticatorData: encodeBase64Url(credential.response.authenticatorData),
                signature: encodeBase64Url(credential.response.signature),
                userHandle: encodeBase64Url(credential.response.userHandle)
            });
            window.location.assign(result.redirectUrl || '/');
        } catch (error) {
            window.location.assign('/login?error');
        } finally {
            passkeyButton.disabled = false;
            passkeyButton.classList.remove('is-loading');
        }
    });
})();
</script>
</body>
</html>
