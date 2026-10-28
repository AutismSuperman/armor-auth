<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>账号确认 - ArmorAuth</title>
    <link rel="icon" type="image/svg+xml" href="/favicon.svg">
    <link rel="shortcut icon" href="/favicon.svg">
    <link rel="stylesheet" href="/assets/armorauth-ui.css?v=2026102801">
</head>
<body class="authing-login-page identity-page google-login-page auth-flow-page federated-flow-page" data-page-title-key="page.federatedConfirm.title">
<div class="page-shell">
    <main class="federated-card-shell">
        <section class="federated-card">
            <div class="federated-card-toolbar">
                <div class="federated-brand">
                    <img class="federated-logo-mark" src="/brand/icon.svg" alt="ArmorAuth logo">
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

            <div class="federated-header">
                <div class="federated-connect-visual">
                    <div class="fed-node fed-node-external">
                        <#if pending.avatarUrl()?? && pending.avatarUrl()?has_content>
                            <img class="fed-avatar" src="${pending.avatarUrl()}" alt="${pending.registrationId()}">
                        <#else>
                            <span class="fed-avatar-placeholder">${(pending.registrationId()!'E')?substring(0, 1)?upper_case}</span>
                        </#if>
                        <span class="fed-node-label">${pending.registrationId()}</span>
                    </div>
                    <div class="fed-link-line">
                        <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2"><polyline points="13 17 18 12 13 7"></polyline><polyline points="6 17 11 12 6 7"></polyline></svg>
                    </div>
                    <div class="fed-node fed-node-local">
                        <img class="fed-avatar" src="/brand/icon.svg" alt="ArmorAuth">
                        <span class="fed-node-label">ArmorAuth</span>
                    </div>
                </div>

                <h1 class="federated-title">第三方身份确认</h1>
                <p class="federated-subtitle">您正在使用 <strong>${pending.registrationId()}</strong> 登录，请选择将该外部身份关联至本地账号：</p>
                <div class="fed-account-badge">
                    <span>外部用户: <strong>${pending.displayName()!pending.providerUsername()!'未提供'}</strong> (${providerUserIdSummary})</span>
                </div>
            </div>

            <#if errorMessage??>
                <div class="notice error">
                    <svg class="notice-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="8" x2="12" y2="12"></line><line x1="12" y1="16" x2="12.01" y2="16"></line></svg>
                    <span class="notice-message">${errorMessage}</span>
                </div>
            </#if>

            <div class="login-methods" data-tab-group>
                <div class="switcher" aria-label="确认方式">
                    <button type="button" class="<#if selectedTab == 'create'>is-active</#if>" data-tab-target="create-account">快速创建新账号</button>
                    <button type="button" class="<#if selectedTab == 'bind'>is-active</#if>" data-tab-target="bind-account">绑定已有本地账号</button>
                </div>

                <!-- Create Form -->
                <form id="create-account" class="auth-form" action="/federated/confirm/create" method="post" <#if selectedTab != 'create'>hidden</#if> data-tab-panel>
                    <div class="field-group field-with-affix">
                        <label for="create-username">用户名</label>
                        <div class="field-input-box">
                            <span class="field-affix field-affix-icon">
                                <svg class="input-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"></path><circle cx="12" cy="7" r="4"></circle></svg>
                            </span>
                            <input id="create-username" name="username" type="text" autocomplete="username" value="${createUsername!pending.suggestedUsername()}" placeholder="请输入本地用户名" required>
                        </div>
                    </div>
                    <div class="field-group field-with-affix">
                        <label for="create-password">密码</label>
                        <div class="field-input-box">
                            <span class="field-affix field-affix-icon">
                                <svg class="input-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect><path d="M7 11V7a5 5 0 0 1 10 0v4"></path></svg>
                            </span>
                            <input id="create-password" name="password" type="password" autocomplete="new-password" placeholder="请输入至少 6 位密码" required>
                        </div>
                    </div>
                    <div class="field-group field-with-affix">
                        <label for="confirm-password">确认密码</label>
                        <div class="field-input-box">
                            <span class="field-affix field-affix-icon">
                                <svg class="input-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect><path d="M7 11V7a5 5 0 0 1 10 0v4"></path></svg>
                            </span>
                            <input id="confirm-password" name="confirmPassword" type="password" autocomplete="new-password" placeholder="请再次输入密码" required>
                        </div>
                    </div>
                    <div class="action-row action-row-between">
                        <a class="button secondary" href="/federated/confirm/cancel">取消</a>
                        <button class="button primary" type="submit">创建并完成登录</button>
                    </div>
                </form>

                <!-- Bind Form -->
                <form id="bind-account" class="auth-form" action="/federated/confirm/bind" method="post" <#if selectedTab != 'bind'>hidden</#if> data-tab-panel>
                    <div class="field-group field-with-affix">
                        <label for="bind-username">已有用户名</label>
                        <div class="field-input-box">
                            <span class="field-affix field-affix-icon">
                                <svg class="input-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"></path><circle cx="12" cy="7" r="4"></circle></svg>
                            </span>
                            <input id="bind-username" name="username" type="text" autocomplete="username" value="${bindUsername!''}" placeholder="请输入已有本地用户名" required>
                        </div>
                    </div>
                    <div class="field-group field-with-affix">
                        <label for="bind-password">已有账号密码</label>
                        <div class="field-input-box">
                            <span class="field-affix field-affix-icon">
                                <svg class="input-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect><path d="M7 11V7a5 5 0 0 1 10 0v4"></path></svg>
                            </span>
                            <input id="bind-password" name="password" type="password" autocomplete="current-password" placeholder="请输入已有账号密码" required>
                        </div>
                    </div>
                    <div class="action-row action-row-between">
                        <a class="button secondary" href="/federated/confirm/cancel">取消</a>
                        <button class="button primary" type="submit">验证并绑定登录</button>
                    </div>
                </form>
            </div>

            <p class="login-card-foot">完成首次确认绑定后，今后可使用该第三方账号一键单点登录。</p>
        </section>
    </main>
    <footer class="page-footer">
        <div class="page-footer-brand">
            <strong>ArmorAuth</strong>
            <span>联合身份与多源互联</span>
        </div>
        <div class="page-footer-nav" aria-label="页面信息">
            <span>第三方身份映射</span>
            <span>自动绑定</span>
            <span>账号安全</span>
        </div>
    </footer>
</div>
<script src="/assets/armorauth-ui.js?v=2026102801"></script>
</body>
</html>
