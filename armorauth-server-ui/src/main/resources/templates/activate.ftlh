<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>连接设备 - ArmorAuth</title>
    <link rel="icon" type="image/svg+xml" href="/favicon.svg">
    <link rel="shortcut icon" href="/favicon.svg">
    <link rel="stylesheet" href="/assets/armorauth-ui.css?v=2026102801">
</head>
<body class="authing-login-page identity-page google-login-page auth-flow-page device-flow-page" data-page-title-key="page.activate.title">
<div class="page-shell">
    <main class="device-card-shell">
        <section class="device-card">
            <div class="device-card-toolbar">
                <div class="device-brand">
                    <img class="device-logo-mark" src="/brand/icon.svg" alt="ArmorAuth logo">
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

            <!-- Device Flow Header (Google Style) -->
            <div class="device-header">
                <div class="device-flow-icon">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="3" width="20" height="14" rx="2" ry="2"></rect><line x1="8" y1="21" x2="16" y2="21"></line><line x1="12" y1="17" x2="12" y2="21"></line></svg>
                </div>
                <h1 class="device-title">连接并激活设备</h1>
                <p class="device-subtitle">请在下方输入您在智能设备、CLI 或电视屏幕上看到的 8 位用户激活码</p>
            </div>

            <form class="auth-form device-form" action="${deviceVerificationEndpoint}" method="post">
                <div class="field-group activation-code-field">
                    <label for="user_code">用户激活码 (User Code)</label>
                    <div class="field-input-box device-input-box">
                        <span class="field-affix field-affix-icon">
                            <svg class="input-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect><path d="M7 11V7a5 5 0 0 1 10 0v4"></path></svg>
                        </span>
                        <input id="user_code" name="user_code" type="text"
                               placeholder="ABCD-EFGH"
                               class="device-code-input"
                               autofocus required>
                    </div>
                    <small class="device-hint">格式如：ABCD-EFGH（不区分大小写）</small>
                </div>
                <div class="action-row action-row-between device-actions">
                    <a class="button secondary" href="/login">返回登录</a>
                    <button class="button primary" type="submit">继续验证设备</button>
                </div>
            </form>

            <div class="device-meta-note">
                <svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="16" x2="12" y2="12"></line><line x1="12" y1="8" x2="12.01" y2="8"></line></svg>
                <span>请确认设备代码与屏幕完全一致，以防止非授权连接。</span>
            </div>
        </section>
    </main>
    <footer class="page-footer">
        <div class="page-footer-brand">
            <strong>ArmorAuth</strong>
            <span>OAuth 2.0 Device Authorization Grant</span>
        </div>
        <div class="page-footer-nav" aria-label="页面信息">
            <span>安全设备互联</span>
            <span>CLI 快速授权</span>
            <span>会话保护</span>
        </div>
    </footer>
</div>
<script src="/assets/armorauth-ui.js?v=2026102801"></script>
</body>
</html>
