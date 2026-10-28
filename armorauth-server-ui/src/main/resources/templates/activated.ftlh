<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>设备已连接 - ArmorAuth</title>
    <link rel="icon" type="image/svg+xml" href="/favicon.svg">
    <link rel="shortcut icon" href="/favicon.svg">
    <link rel="stylesheet" href="/assets/armorauth-ui.css?v=2026102801">
</head>
<body class="authing-login-page identity-page google-login-page auth-flow-page device-flow-page" data-page-title-key="page.activated.title">
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

            <!-- Success Header -->
            <div class="device-header">
                <div class="device-success-icon">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path><polyline points="22 4 12 14.01 9 11.01"></polyline></svg>
                </div>
                <h1 class="device-title">设备已连接成功</h1>
                <p class="device-subtitle">设备端已获得授权并继续登录，您可以安全关闭当前浏览器窗口</p>
            </div>

            <div class="notice success">
                <svg class="notice-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path><polyline points="22 4 12 14.01 9 11.01"></polyline></svg>
                <span class="notice-message">本次授权已实时生效。如果设备屏幕未自动跳转，请在设备端按任意键或刷新。</span>
            </div>

            <div class="action-row action-row-stacked">
                <a class="button primary" href="/">进入个人账号中心</a>
                <a class="button secondary" href="/login">返回登录页面</a>
            </div>
        </section>
    </main>
    <footer class="page-footer">
        <div class="page-footer-brand">
            <strong>ArmorAuth</strong>
            <span>OAuth 2.0 Device Flow</span>
        </div>
        <div class="page-footer-nav" aria-label="页面信息">
            <span>授权成功</span>
            <span>会话就绪</span>
            <span>安全连接</span>
        </div>
    </footer>
</div>
<script src="/assets/armorauth-ui.js?v=2026102801"></script>
</body>
</html>
