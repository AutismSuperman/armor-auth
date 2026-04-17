<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>ArmorAuth 登录</title>
    <link rel="stylesheet" href="/assets/armorauth-ui.css">
</head>
<body>
<div class="page-shell">
    <main class="auth-card">
        <section class="auth-aside">
            <div class="brand-chip">
                <span class="brand-dot"></span>
                <span>ArmorAuth Identity Hub</span>
            </div>
            <div class="aside-copy">
                <h1>统一登录入口，回到服务端模板流。</h1>
                <p>当前页面已经从 Node/Vite 壳子切回 Spring MVC + FreeMarker。登录、授权、设备激活都由服务端直接渲染。</p>
            </div>
            <div class="aside-points">
                <div class="aside-point">
                    <strong>密码登录</strong>
                    <p>标准表单提交流程，认证成功后按 Spring Security 默认保存请求跳转。</p>
                </div>
                <div class="aside-point">
                    <strong>验证码登录</strong>
                    <p>保留原有验证码入口，不再返回前端专用 JSON 响应。</p>
                </div>
            </div>
        </section>
        <section class="auth-main">
            <div class="content-column">
                <div class="section-title">
                    <span class="eyebrow">Sign In</span>
                    <h1>登录 ArmorAuth</h1>
                    <p>继续访问授权中心、设备验证和联邦登录入口。</p>
                </div>

                <#if errorMessage??>
                    <div class="notice error">${errorMessage}</div>
                </#if>
                <#if loggedOut?? && loggedOut>
                    <div class="notice success">您已成功退出当前会话。</div>
                </#if>

                <div class="switcher" aria-label="登录模式">
                    <button type="button" class="is-active" data-target="password-login">账号密码</button>
                    <button type="button" data-target="captcha-login">短信验证码</button>
                </div>

                <form id="password-login" class="auth-form" action="/login" method="post">
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

                <form id="captcha-login" class="auth-form" action="/login/captcha" method="post" hidden>
                    <div class="field-group">
                        <label for="account">手机号</label>
                        <input id="account" name="account" type="text" autocomplete="tel" placeholder="请输入手机号" value="13103777777">
                    </div>
                    <div class="field-group">
                        <label for="captcha">验证码</label>
                        <input id="captcha" name="captcha" type="text" autocomplete="one-time-code" placeholder="请输入验证码" value="1234">
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

            <#if federatedProviders?has_content>
                <div class="content-column">
                    <div class="section-title">
                        <span class="eyebrow">Federated</span>
                        <p>第三方登录支持两种首次登录策略，默认自动注册，也可以切到中间页确认后再完成 OAuth 成功。</p>
                    </div>
                    <div class="switcher" aria-label="联合登录策略">
                        <a class="<#if selectedFederatedMode == 'auto'>is-active</#if>" href="/login?mode=auto">自动注册</a>
                        <a class="<#if selectedFederatedMode == 'confirm'>is-active</#if>" href="/login?mode=confirm">中间页确认</a>
                    </div>
                    <p class="page-note">当前策略：<#if selectedFederatedMode == 'confirm'>拿到第三方资料后先进入确认页<#else>首次登录自动创建本地账号并建立绑定</#if>。</p>
                    <div class="provider-list">
                        <#list federatedProviders as provider>
                            <a class="provider-link" href="/oauth2/authorization/${provider.registrationId}?mode=${selectedFederatedMode!'auto'}">
                                ${provider.clientName!provider.registrationId}
                            </a>
                        </#list>
                    </div>
                </div>
            </#if>

            <p class="footer-copy">Spring Boot 4 + Spring Security 7 + FreeMarker</p>
        </section>
    </main>
</div>
<script>
    const switcherButtons = document.querySelectorAll('.switcher button');
    const forms = document.querySelectorAll('.auth-form');
    switcherButtons.forEach((button) => {
        button.addEventListener('click', () => {
            switcherButtons.forEach((item) => item.classList.remove('is-active'));
            forms.forEach((form) => {
                form.hidden = form.id !== button.dataset.target;
            });
            button.classList.add('is-active');
        });
    });
</script>
</body>
</html>
