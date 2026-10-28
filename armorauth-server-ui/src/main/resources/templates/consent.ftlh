<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>授权确认 - ArmorAuth</title>
    <link rel="icon" type="image/svg+xml" href="/favicon.svg">
    <link rel="shortcut icon" href="/favicon.svg">
    <link rel="stylesheet" href="/assets/armorauth-ui.css?v=2026102801">
</head>
<body class="authing-login-page identity-page google-login-page auth-flow-page consent-flow-page" data-page-title-key="page.consent.title">
<div class="page-shell">
    <main class="consent-card-shell">
        <section class="consent-card">
            <!-- Header Toolbar -->
            <div class="consent-card-toolbar">
                <div class="consent-brand">
                    <img class="consent-logo-mark" src="/brand/icon.svg" alt="ArmorAuth logo">
                    <span class="consent-brand-name">ArmorAuth</span>
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

            <!-- Target App & User Account Card -->
            <div class="consent-header">
                <div class="app-avatar-box">
                    <span class="app-avatar-initial">${(clientName!'A')?substring(0, 1)?upper_case}</span>
                </div>
                <h1 class="consent-title">${clientName}</h1>
                <p class="consent-subtitle">正在申请访问您的 ArmorAuth 账号信息</p>

                <!-- Current User Account Pill (Google Style) -->
                <div class="consent-account-chip">
                    <span class="account-avatar-dot">${(principalName!'U')?substring(0, 1)?upper_case}</span>
                    <span class="account-name">${principalName}</span>
                    <span class="account-check-badge" title="当前登录身份">
                        <svg viewBox="0 0 24 24" width="12" height="12" fill="none" stroke="currentColor" stroke-width="3"><polyline points="20 6 9 17 4 12"></polyline></svg>
                    </span>
                </div>
            </div>

            <form id="consent-form" class="auth-form consent-form" action="${requestUri}" method="post">
                <input type="hidden" name="client_id" value="${clientId}">
                <input type="hidden" name="state" value="${state}">
                <#if userCode?? && userCode?has_content>
                    <input type="hidden" name="user_code" value="${userCode}">
                </#if>

                <div class="consent-section-title">
                    <span>此应用申请获得以下权限：</span>
                </div>

                <div class="scope-list">
                    <#if scopes?has_content>
                        <#list scopes as scope>
                            <label class="scope-item">
                                <div class="scope-checkbox-wrap">
                                    <input type="checkbox" name="scope" value="${scope.scope}" checked>
                                    <span class="custom-checkbox"></span>
                                </div>
                                <div class="scope-copy">
                                    <strong>${scope.scope}</strong>
                                    <p>${scope.description!scope.scope}</p>
                                </div>
                            </label>
                        </#list>
                    <#else>
                        <div class="notice success">
                            <span class="notice-message">当前请求的权限此前已经过授权，本次只需确认继续。</span>
                        </div>
                    </#if>
                </div>

                <#if previouslyApprovedScopes?has_content>
                    <div class="previously-approved-section">
                        <div class="previously-approved-header">
                            <span class="eyebrow">已获得权限</span>
                            <small>（以下权限在之前的授权中已生效）</small>
                        </div>
                        <div class="scope-list scope-list-readonly">
                            <#list previouslyApprovedScopes as scope>
                                <div class="scope-item scope-item-readonly">
                                    <span class="scope-readonly-check">
                                        <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"></polyline></svg>
                                    </span>
                                    <div class="scope-copy">
                                        <strong>${scope.scope}</strong>
                                        <p>${scope.description!scope.scope}</p>
                                    </div>
                                </div>
                            </#list>
                        </div>
                    </div>
                </#if>

                <div class="consent-trust-note">
                    <svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="16" x2="12" y2="12"></line><line x1="12" y1="8" x2="12.01" y2="8"></line></svg>
                    <span>授权后，该应用可根据上述权限访问您的信息。您可以随时在个人账号安全中心撤销已授权的应用。</span>
                </div>

                <div class="action-row action-row-between consent-actions">
                    <button class="button secondary consent-btn-deny" type="button" id="deny-button">拒绝授权</button>
                    <button class="button primary consent-btn-allow" type="submit">同意并继续</button>
                </div>
            </form>

            <div class="consent-meta-footer">
                <span>客户端 ID: <code>${clientId}</code></span>
            </div>
        </section>
    </main>
    <footer class="page-footer">
        <div class="page-footer-brand">
            <strong>ArmorAuth</strong>
            <span>统一身份与授权控制平台</span>
        </div>
        <div class="page-footer-nav" aria-label="页面信息">
            <span>授权透明</span>
            <span>细粒度权限控制</span>
            <span>隐私可撤销</span>
        </div>
    </footer>
</div>
<script src="/assets/armorauth-ui.js?v=2026102801"></script>
<script>
    document.getElementById('deny-button').addEventListener('click', () => {
        document.querySelectorAll('#consent-form input[name="scope"]').forEach((input) => {
            input.checked = false;
        });
        document.getElementById('consent-form').submit();
    });
</script>
</body>
</html>
