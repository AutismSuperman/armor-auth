<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>控制台 - ArmorAuth</title>
    <link rel="icon" type="image/svg+xml" href="/favicon.svg">
    <link rel="shortcut icon" href="/favicon.svg">
    <link rel="stylesheet" href="/assets/armorauth-ui.css?v=2026102801">
</head>
<body class="authing-login-page identity-page google-account-page" data-page-title-key="page.home.title">
<div class="page-shell">
    <main class="login-product-shell is-wide account-shell">
        <!-- Sidebar Navigation (Google Account / Authing Console Style) -->
        <section class="login-visual-panel account-sidebar-panel" data-visual="home">
            <div class="login-brand">
                <div class="brand-logo-wrap">
                    <img class="login-brand-mark" src="/brand/icon.svg" alt="ArmorAuth logo">
                </div>
                <div class="brand-text-wrap">
                    <strong>ArmorAuth 账号</strong>
                    <small>个人安全中心</small>
                </div>
            </div>

            <div class="login-visual-copy">
                <span class="login-kicker">用户中心</span>
                <h1>欢迎回来</h1>
                <p>集中查看与管理个人资料、两步验证、授权应用与活动会话。</p>
            </div>

            <div class="identity-menu account-nav-menu" aria-label="账号服务">
                <button class="identity-menu-item is-active" type="button" data-account-section-target="home">
                    <span class="identity-menu-icon">
                        <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"></path></svg>
                    </span>
                    <span>
                        <strong>首页概览</strong>
                        <small>安全评分与快捷入口</small>
                    </span>
                </button>
                <button class="identity-menu-item" type="button" data-account-section-target="profile">
                    <span class="identity-menu-icon">
                        <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"></path><circle cx="12" cy="7" r="4"></circle></svg>
                    </span>
                    <span>
                        <strong>个人信息</strong>
                        <small>昵称与联系方式验证</small>
                    </span>
                </button>
                <button class="identity-menu-item" type="button" data-account-section-target="security">
                    <span class="identity-menu-icon">
                        <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect><path d="M7 11V7a5 5 0 0 1 10 0v4"></path></svg>
                    </span>
                    <span>
                        <strong>安全性与 MFA</strong>
                        <small>二次验证 / Authenticator</small>
                    </span>
                </button>
                <button class="identity-menu-item" type="button" data-account-section-target="apps">
                    <span class="identity-menu-icon">
                        <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="7" height="7"></rect><rect x="14" y="3" width="7" height="7"></rect><rect x="14" y="14" width="7" height="7"></rect><rect x="3" y="14" width="7" height="7"></rect></svg>
                    </span>
                    <span>
                        <strong>已授权应用</strong>
                        <small>OAuth2 / OIDC 客户端</small>
                    </span>
                </button>
                <button class="identity-menu-item" type="button" data-account-section-target="privacy">
                    <span class="identity-menu-icon">
                        <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path></svg>
                    </span>
                    <span>
                        <strong>数据与隐私</strong>
                        <small>活动日志与审计</small>
                    </span>
                </button>
            </div>

            <div class="account-side-actions">
                <a class="account-side-link" href="/login">返回登录页面</a>
                <form action="/logout" method="post" style="display:inline-block;width:100%;">
                    <button class="button secondary button-compact account-logout-btn" type="submit">安全退出当前账号</button>
                </form>
            </div>
        </section>

        <!-- Main Account Content Panel -->
        <section class="login-card-panel account-content-panel">
            <div class="login-card account-card">
                <div class="login-card-toolbar">
                    <div class="login-card-logo">
                        <img src="/brand/icon.svg" alt="ArmorAuth logo">
                        <span>个人账号中心</span>
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

                <!-- Account Hero (Google Account Header Style) -->
                <div class="account-profile-hero">
                    <div class="account-profile-avatar">
                        <span>${(userName!'A')?substring(0, 1)?upper_case}</span>
                    </div>
                    <div class="account-hero-copy">
                        <h1 data-i18n-template="home.welcome" data-i18n-value-name="${userName}">欢迎，${userName}</h1>
                        <p>管理您的个人资料、密码凭据与授权应用</p>
                    </div>
                    <div class="account-chip-row" aria-label="账号快捷入口">
                        <button type="button" data-account-section-target="profile">个人资料</button>
                        <button type="button" data-account-section-target="security">MFA 安全</button>
                        <button type="button" data-account-section-target="apps">授权应用</button>
                        <button type="button" data-account-section-target="privacy">登录审计</button>
                    </div>
                </div>

                <div class="account-center" data-account-center>
                    <!-- Tab 1: Home Overview -->
                    <section class="account-section is-active" data-account-section="home">
                        <div class="account-summary-grid">
                            <button class="account-summary-card" type="button" data-account-section-target="profile">
                                <div class="summary-card-head">
                                    <div class="summary-icon icon-profile">
                                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"></path><circle cx="12" cy="7" r="4"></circle></svg>
                                    </div>
                                    <strong>个人资料</strong>
                                </div>
                                <span class="summary-desc" data-overview-profile>加载资料状态...</span>
                            </button>
                            <button class="account-summary-card" type="button" data-account-section-target="security">
                                <div class="summary-card-head">
                                    <div class="summary-icon icon-security">
                                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect><path d="M7 11V7a5 5 0 0 1 10 0v4"></path></svg>
                                    </div>
                                    <strong>账号安全与 MFA</strong>
                                </div>
                                <span class="summary-desc" data-overview-security>正在检查 MFA 状态...</span>
                            </button>
                            <button class="account-summary-card" type="button" data-account-section-target="apps">
                                <div class="summary-card-head">
                                    <div class="summary-icon icon-apps">
                                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="7" height="7"></rect><rect x="14" y="3" width="7" height="7"></rect><rect x="14" y="14" width="7" height="7"></rect><rect x="3" y="14" width="7" height="7"></rect></svg>
                                    </div>
                                    <strong>授权应用</strong>
                                </div>
                                <span class="summary-desc">查看已授权访问的 OAuth2 / OIDC 应用。</span>
                            </button>
                            <button class="account-summary-card" type="button" data-account-section-target="privacy">
                                <div class="summary-card-head">
                                    <div class="summary-icon icon-privacy">
                                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path></svg>
                                    </div>
                                    <strong>活动与会话</strong>
                                </div>
                                <span class="summary-desc">查看最近登录设备与安全操作审计。</span>
                            </button>
                        </div>
                    </section>

                    <!-- Tab 2: Profile -->
                    <section class="account-section" data-account-section="profile" hidden>
                        <div class="account-section-head">
                            <div>
                                <strong>个人资料与联系方式</strong>
                                <span>维护您的公开显示名称、邮箱和手机号，并完成安全校验。</span>
                            </div>
                            <span class="account-security-badge is-muted" data-profile-status>未加载</span>
                        </div>

                        <form class="account-profile-form" data-profile-form>
                            <div class="profile-card profile-card-basic">
                                <div class="profile-card-head">
                                    <div>
                                        <strong>基础资料</strong>
                                        <span>这些信息将用于系统内与已授权应用的用户识别。</span>
                                    </div>
                                    <button class="button secondary button-compact" type="button" data-profile-refresh>刷新</button>
                                </div>
                                <div class="profile-field-grid">
                                    <div class="field-group">
                                        <label for="profile-display-name">显示名称</label>
                                        <input id="profile-display-name" type="text" autocomplete="name"
                                               data-profile-field="displayName" placeholder="请输入显示名称">
                                    </div>
                                    <div class="field-group">
                                        <label for="profile-about">个人备注</label>
                                        <textarea id="profile-about" rows="3" data-profile-field="profile"
                                                  placeholder="记录您的个性签名或组织备注"></textarea>
                                    </div>
                                </div>
                                <div class="profile-form-actions">
                                    <button class="button primary button-compact" type="submit">保存基本资料</button>
                                </div>
                            </div>

                            <div class="profile-card">
                                <div class="profile-card-head">
                                    <div>
                                        <strong>联系方式验证</strong>
                                        <span>绑定的邮箱或手机号可用于二次验证及密码找回。</span>
                                    </div>
                                </div>

                                <div class="contact-verify-card" data-contact-card="email">
                                    <div class="contact-verify-main">
                                        <span class="contact-verify-icon">
                                            <svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="2"><path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"></path><polyline points="22,6 12,13 2,6"></polyline></svg>
                                        </span>
                                        <div>
                                            <strong>电子邮箱</strong>
                                            <span data-contact-summary="email">填写并保存后可发送验证码完成验证。</span>
                                        </div>
                                    </div>
                                    <span class="account-security-badge is-muted" data-contact-status="email">未验证</span>
                                    <div class="field-group contact-value-field">
                                        <label for="profile-email">邮箱地址</label>
                                        <input id="profile-email" type="email" autocomplete="email"
                                               data-profile-field="email" placeholder="example@armorauth.com">
                                    </div>
                                    <div class="contact-verify-actions">
                                        <button class="button secondary button-compact" type="button" data-send-contact-code="email">
                                            发送验证码
                                        </button>
                                        <div class="contact-code-row" data-contact-code-row="email" hidden>
                                            <input type="text" inputmode="numeric" maxlength="8" placeholder="输入邮箱验证码"
                                                   data-contact-code="email">
                                            <button class="button primary button-compact" type="button" data-verify-contact="email">
                                                确认验证
                                            </button>
                                        </div>
                                    </div>
                                    <small data-contact-message="email"></small>
                                </div>

                                <div class="contact-verify-card" data-contact-card="phone">
                                    <div class="contact-verify-main">
                                        <span class="contact-verify-icon">
                                            <svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="2"><rect x="5" y="2" width="14" height="20" rx="2" ry="2"></rect><line x1="12" y1="18" x2="12.01" y2="18"></line></svg>
                                        </span>
                                        <div>
                                            <strong>手机号码</strong>
                                            <span data-contact-summary="phone">填写并保存后可发送短信验证码完成验证。</span>
                                        </div>
                                    </div>
                                    <span class="account-security-badge is-muted" data-contact-status="phone">未验证</span>
                                    <div class="field-group contact-value-field">
                                        <label for="profile-phone">手机号码</label>
                                        <input id="profile-phone" type="tel" autocomplete="tel"
                                               data-profile-field="phone" placeholder="请输入 11 位手机号码">
                                    </div>
                                    <div class="contact-verify-actions">
                                        <button class="button secondary button-compact" type="button" data-send-contact-code="phone">
                                            发送验证码
                                        </button>
                                        <div class="contact-code-row" data-contact-code-row="phone" hidden>
                                            <input type="text" inputmode="numeric" maxlength="8" placeholder="输入短信验证码"
                                                   data-contact-code="phone">
                                            <button class="button primary button-compact" type="button" data-verify-contact="phone">
                                                确认验证
                                            </button>
                                        </div>
                                    </div>
                                    <small data-contact-message="phone"></small>
                                </div>
                            </div>
                        </form>
                    </section>

                    <!-- Tab 3: Security & MFA -->
                    <section class="account-section" data-account-section="security" hidden>
                        <div class="account-security-panel" data-account-security>
                            <div class="account-security-head">
                                <div>
                                    <strong>多因素认证与凭证安全</strong>
                                    <span data-mfa-summary>正在检查 MFA 保护策略...</span>
                                </div>
                                <span class="account-security-badge is-muted" data-mfa-status>检查中</span>
                            </div>

                            <div class="security-toggle-row">
                                <div class="security-toggle-info">
                                    <strong>登录二次安全验证 (2FA / MFA)</strong>
                                    <small>启用后，在输入密码后必须通过 Authenticator 动态码验证身份。</small>
                                </div>
                                <button class="security-switch" type="button" aria-label="切换登录二次验证"
                                        aria-pressed="false" data-mfa-toggle disabled>
                                    <span></span>
                                </button>
                            </div>

                            <div class="factor-list" data-factor-list>
                                <div class="factor-empty">正在加载绑定的验证方式...</div>
                            </div>

                            <div class="security-actions-inline">
                                <button class="button primary button-compact" type="button" data-totp-setup>
                                    添加 Authenticator
                                </button>
                                <button class="button secondary button-compact" type="button" data-factor-refresh>
                                    刷新状态
                                </button>
                            </div>

                            <div class="totp-setup-panel" data-totp-panel hidden>
                                <div class="totp-setup-head">
                                    <strong>绑定 Google Authenticator / Microsoft Authenticator</strong>
                                    <span>打开手机身份验证器应用扫描下方二维码，或手动输入密钥，然后输入 6 位验证码完成激活。</span>
                                </div>
                                <div class="totp-setup-grid">
                                    <div class="totp-qr-card">
                                        <img src="" alt="Authenticator 二维码" data-totp-qr hidden>
                                        <span data-totp-qr-empty>正在生成安全令牌二维码...</span>
                                    </div>
                                    <div class="totp-manual-fields">
                                        <a class="button secondary button-compact totp-open-link" href="#" data-totp-open hidden>
                                            在 Authenticator 中直接打开
                                        </a>
                                        <div class="copy-field">
                                            <label>Secret 密钥</label>
                                            <code data-totp-secret>-</code>
                                            <button type="button" data-copy-field="secret">复制</button>
                                        </div>
                                        <div class="copy-field">
                                            <label>otpauth URI</label>
                                            <code data-totp-uri>-</code>
                                            <button type="button" data-copy-field="uri">复制</button>
                                        </div>
                                    </div>
                                </div>
                                <div class="field-group compact-field">
                                    <label for="totp-code">输入 6 位动态验证码</label>
                                    <input id="totp-code" type="text" inputmode="numeric" maxlength="8"
                                           autocomplete="one-time-code" placeholder="例如：123456" data-totp-code>
                                </div>
                                <div class="security-actions-inline">
                                    <button class="button primary button-compact" type="button" data-totp-verify>
                                        验证并正式启用
                                    </button>
                                    <button class="button secondary button-compact" type="button" data-totp-cancel>
                                        取消配置
                                    </button>
                                </div>
                                <div class="recovery-code-panel" data-recovery-panel hidden>
                                    <strong>安全应急恢复码</strong>
                                    <span>请妥善离线保存这些恢复码。当您的手机丢失或无法使用 Authenticator 时可用于紧急登录。</span>
                                    <div class="recovery-code-grid" data-recovery-codes></div>
                                </div>
                            </div>
                        </div>
                    </section>

                    <!-- Tab 4: Apps -->
                    <section class="account-section" data-account-section="apps" hidden>
                        <div class="account-section-head">
                            <div>
                                <strong>已授权访问的第三方应用</strong>
                                <span>这些应用获得了访问您 ArmorAuth 账号部分资源的授权。您可以随时撤销访问权限。</span>
                            </div>
                        </div>
                        <div class="factor-empty">当前账号尚未对任何第三方应用发放外部授权访问。</div>
                    </section>

                    <!-- Tab 5: Privacy -->
                    <section class="account-section" data-account-section="privacy" hidden>
                        <div class="account-section-head">
                            <div>
                                <strong>登录活动与安全审计</strong>
                                <span>记录当前会话、登录历史与安全凭据变动记录。</span>
                            </div>
                        </div>
                        <div class="factor-empty">安全审计日志实时记录中。如需查看完整审计事件，请访问管理员控制台。</div>
                    </section>
                </div>
            </div>
        </section>
    </main>
    <footer class="page-footer">
        <div class="page-footer-brand">
            <strong>ArmorAuth</strong>
            <span>统一身份与访问控制平台</span>
        </div>
        <div class="page-footer-nav" aria-label="页面信息">
            <span>安全中心</span>
            <span>凭据隔离</span>
            <span>合规防护</span>
        </div>
    </footer>
</div>
<script src="/assets/armorauth-ui.js?v=2026102801"></script>
</body>
</html>
