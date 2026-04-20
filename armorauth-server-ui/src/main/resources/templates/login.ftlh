<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>欢迎登录 - ArmorAuth</title>
    <link rel="stylesheet" href="/assets/armorauth-ui.css">
</head>
<body>
<div class="page-shell">
    <main class="panel-frame">
        <section class="visual-panel">
            <div class="brand-row">
                <div class="brand-chip">
                    <span class="brand-mark">A</span>
                    <span class="brand-copy">
                        <strong>ArmorAuth</strong>
                        <span>账号与授权中心</span>
                    </span>
                </div>
                <div class="top-actions">
                    <span class="status-pill">在线服务</span>
                    <button class="theme-toggle" type="button" data-theme-toggle>
                        <span class="theme-toggle-icon" data-theme-icon>☼</span>
                        <span data-theme-text>浅色</span>
                    </button>
                </div>
            </div>

            <div class="hero-copy">
                <span class="eyebrow">统一入口</span>
                <h1>安全、统一、清晰的身份入口。</h1>
                <p>在一个界面完成登录、授权确认与设备激活。</p>
            </div>

            <div class="hero-stage" aria-hidden="true">
                <div class="dashboard-illus">
                    <div class="dashboard-layer top"></div>
                    <div class="dashboard-layer main"></div>
                    <div class="dashboard-layer side"></div>
                </div>
            </div>

            <div class="metric-grid">
                <div class="metric-card">
                    <span>登录方式</span>
                    <strong>支持密码与验证码登录</strong>
                </div>
                <div class="metric-card">
                    <span>覆盖场景</span>
                    <strong>统一覆盖授权、设备与联邦流程</strong>
                </div>
                <div class="metric-card">
                    <span>产品体验</span>
                    <strong>保持一致的认证体验</strong>
                </div>
            </div>
        </section>
        <section class="content-panel">
            <div class="content-column">
                <div class="section-title">
                    <span class="eyebrow">账号登录</span>
                    <h1>欢迎登录</h1>
                    <p>登录后即可继续访问你的账号与服务。</p>
                </div>

                <#if errorMessage??>
                    <div class="notice error">${errorMessage}</div>
                </#if>
                <#if loggedOut?? && loggedOut>
                    <div class="notice success">您已成功退出当前会话。</div>
                </#if>

                <div data-tab-group>
                    <div class="switcher" aria-label="登录模式">
                        <button type="button" class="is-active" data-tab-target="password-login">账号密码</button>
                        <button type="button" data-tab-target="captcha-login">短信验证码</button>
                    </div>

                    <form id="password-login" class="auth-form" action="/login" method="post" data-tab-panel>
                        <div class="field-group">
                            <label for="username">用户名</label>
                            <input id="username" name="username" type="text" autocomplete="username" placeholder="请输入用户名" value="admin">
                        </div>
                        <div class="field-group">
                            <label for="password">密码</label>
                            <input id="password" name="password" type="password" autocomplete="current-password" placeholder="请输入密码" value="123456">
                        </div>
                        <label class="checkbox-row" for="remember-me-password">
                            <input id="remember-me-password" name="remember-me" type="checkbox" value="true">
                            <span>记住我</span>
                        </label>
                        <div class="action-row">
                            <button class="button primary" type="submit">登录</button>
                        </div>
                    </form>

                    <form id="captcha-login" class="auth-form" action="/login/captcha" method="post" hidden data-tab-panel>
                        <div class="notice success" hidden data-captcha-feedback></div>
                        <div class="field-group">
                            <label for="account">手机号</label>
                            <input id="account" name="account" type="text" autocomplete="tel" placeholder="请输入手机号" value="13103777777">
                        </div>
                        <div class="field-group field-inline">
                            <label for="captcha">验证码</label>
                            <input id="captcha" name="captcha" type="text" autocomplete="one-time-code" placeholder="请输入验证码" value="1234">
                            <button class="button secondary inline-button" type="button" data-captcha-send>获取验证码</button>
                        </div>
                        <label class="checkbox-row" for="remember-me-captcha">
                            <input id="remember-me-captcha" name="remember-me" type="checkbox" value="true">
                            <span>记住我</span>
                        </label>
                        <div class="action-row">
                            <button class="button primary" type="submit">验证并登录</button>
                        </div>
                    </form>
                </div>
            </div>

            <#if federatedProviders?has_content>
                <div class="content-column">
                    <div class="section-title">
                        <span class="eyebrow">快捷登录</span>
                        <p>使用你常用的平台快速进入。</p>
                    </div>
                    <div class="switcher" aria-label="联合登录策略">
                        <a class="<#if selectedFederatedMode == 'auto'>is-active</#if>" href="/login?mode=auto">自动注册</a>
                        <a class="<#if selectedFederatedMode == 'confirm'>is-active</#if>" href="/login?mode=confirm">中间页确认</a>
                    </div>
                    <p class="page-note">当前方式：<#if selectedFederatedMode == 'confirm'>首次登录需要确认账号<#else>首次登录将自动完成接入</#if>。</p>
                    <div class="provider-list">
                        <#list federatedProviders as provider>
                            <a class="provider-link provider-${provider.registrationId?lower_case} provider-default" href="/oauth2/authorization/${provider.registrationId}?mode=${selectedFederatedMode!'auto'}" aria-label="使用 ${provider.clientName!provider.registrationId} 登录">
                                <span class="provider-icon" aria-hidden="true"></span>
                                <span class="provider-label">${provider.clientName!provider.registrationId}</span>
                            </a>
                        </#list>
                    </div>
                </div>
            </#if>

            <p class="footer-copy">ArmorAuth 统一身份平台</p>
        </section>
    </main>
</div>
<script src="/assets/armorauth-ui.js"></script>
</body>
</html>
