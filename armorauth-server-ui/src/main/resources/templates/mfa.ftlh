<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>二次验证 - ArmorAuth</title>
    <link rel="icon" type="image/svg+xml" href="/favicon.svg">
    <link rel="shortcut icon" href="/favicon.svg">
    <link rel="stylesheet" href="/assets/armorauth-ui.css?v=2026102801">
</head>
<body class="authing-login-page identity-page google-login-page auth-flow-page mfa-flow-page" data-page-title-key="page.mfa.title">
<div class="page-shell">
    <main class="mfa-card-shell">
        <section class="mfa-card">
            <!-- Toolbar -->
            <div class="mfa-card-toolbar">
                <div class="mfa-brand">
                    <img class="mfa-logo-mark" src="/brand/icon.svg" alt="ArmorAuth logo">
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

            <!-- MFA Header (Google 2-Step Verification Style) -->
            <div class="mfa-header">
                <div class="security-shield-icon">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path><circle cx="12" cy="11" r="2.5"></circle><line x1="12" y1="13.5" x2="12" y2="16"></line></svg>
                </div>
                <h1 class="mfa-title">两步安全验证</h1>
                <p class="mfa-subtitle">为了保障您的账号安全，请输入身份验证器 (Authenticator) 生成的 6 位动态验证码</p>
                <div class="mfa-account-badge">
                    <span class="account-dot"></span>
                    <span>验证账号: <strong>${principal!'-'}</strong></span>
                </div>
            </div>

            <#if errorMessage??>
                <div class="notice error">
                    <svg class="notice-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="8" x2="12" y2="12"></line><line x1="12" y1="16" x2="12.01" y2="16"></line></svg>
                    <span class="notice-message">${errorMessage}</span>
                </div>
            </#if>

            <form class="auth-form mfa-form" action="/login/mfa" method="post">
                <input type="hidden" name="principal" value="${principal!}">
                <div class="field-group mfa-code-group">
                    <label for="mfaCode">动态验证码</label>
                    <div class="mfa-input-wrap">
                        <input id="mfaCode" name="mfaCode" type="text"
                               autocomplete="one-time-code"
                               inputmode="numeric"
                               pattern="[0-9]{6}"
                               maxlength="6"
                               placeholder="000000"
                               class="mfa-otp-input"
                               autofocus required>
                    </div>
                </div>
                <div class="action-row action-row-stacked">
                    <button class="button primary mfa-verify-btn" type="submit">验 证</button>
                </div>
            </form>

            <div class="login-divider"><span>或使用无密码凭证</span></div>
            <div id="passkeyNotice" class="notice error" style="display:none"></div>
            <div class="action-row action-row-stacked">
                <button id="passkeyButton" class="button secondary passkey-mfa-btn" type="button">
                    <svg class="btn-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="3"></circle><path d="M12 1v6M12 17v6M4.22 4.22l4.24 4.24M15.54 15.54l4.24 4.24M1 12h6M17 12h6M4.22 19.78l4.24-4.24M15.54 8.46l4.24-4.24"></path></svg>
                    使用绑定的 Passkey 安全密钥验证
                </button>
            </div>

            <div class="mfa-footer-links">
                <a class="mfa-back-link" href="/login">返回重新登录</a>
                <span class="mfa-recovery-tip">如果无法使用验证器，请联系租户管理员重置 MFA</span>
            </div>
        </section>
    </main>
    <footer class="page-footer">
        <div class="page-footer-brand">
            <strong>ArmorAuth</strong>
            <span>企业统一身份与多因素凭据保护平台</span>
        </div>
        <div class="page-footer-nav" aria-label="页面信息">
            <span>FIDO2 / WebAuthn</span>
            <span>TOTP 动态令牌</span>
            <span>会话防御</span>
        </div>
    </footer>
</div>
<script src="/assets/armorauth-ui.js?v=2026102801"></script>
<script>
    const passkeyButton = document.getElementById('passkeyButton');
    const passkeyNotice = document.getElementById('passkeyNotice');

    function showPasskeyError(message) {
        passkeyNotice.textContent = message || window.ArmorAuthI18n?.t('passkey.verifyFailed') || 'Passkey 验证失败';
        passkeyNotice.style.display = 'block';
    }

    function base64urlToBuffer(value) {
        const base64 = value.replace(/-/g, '+').replace(/_/g, '/')
            .padEnd(Math.ceil(value.length / 4) * 4, '=');
        const binary = atob(base64);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) {
            bytes[i] = binary.charCodeAt(i);
        }
        return bytes.buffer;
    }

    function bufferToBase64url(buffer) {
        const bytes = new Uint8Array(buffer);
        let binary = '';
        for (let i = 0; i < bytes.byteLength; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
    }

    async function postJson(url, body) {
        const response = await fetch(url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: body ? JSON.stringify(body) : undefined
        });
        const payload = await response.json();
        if (!response.ok || payload.code !== 200) {
            throw new Error(payload.message || window.ArmorAuthI18n?.t('passkey.requestFailed') || '请求失败');
        }
        return payload.data;
    }

    passkeyButton?.addEventListener('click', async () => {
        passkeyNotice.style.display = 'none';
        passkeyButton.disabled = true;
        passkeyButton.classList.add('is-loading');
        try {
            if (!window.PublicKeyCredential || !navigator.credentials?.get) {
                throw new Error(window.ArmorAuthI18n?.t('passkey.unsupported') || '当前浏览器不支持 Passkey');
            }
            const options = await postJson('/login/passkey/assertion/options');
            const publicKey = {
                challenge: base64urlToBuffer(options.challenge),
                rpId: options.rpId,
                timeout: options.timeoutMillis || 60000,
                userVerification: options.userVerification || 'preferred',
                allowCredentials: (options.allowCredentials || []).map(item => ({
                    type: item.type || 'public-key',
                    id: base64urlToBuffer(item.id),
                    transports: item.transports || undefined
                }))
            };
            const credential = await navigator.credentials.get({ publicKey });
            if (!credential) {
                throw new Error(window.ArmorAuthI18n?.t('passkey.notSelected') || '未选择 Passkey');
            }
            const result = await postJson('/login/passkey/assertion/finish', {
                credentialId: bufferToBase64url(credential.rawId),
                authenticatorData: bufferToBase64url(credential.response.authenticatorData),
                clientDataJSON: bufferToBase64url(credential.response.clientDataJSON),
                signature: bufferToBase64url(credential.response.signature),
                userHandle: credential.response.userHandle
                    ? bufferToBase64url(credential.response.userHandle)
                    : null
            });
            window.location.href = result.redirectUrl || '/';
        } catch (error) {
            showPasskeyError(error.message);
        } finally {
            passkeyButton.disabled = false;
            passkeyButton.classList.remove('is-loading');
        }
    });
</script>
</body>
</html>
