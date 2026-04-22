<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>欢迎登录 - ArmorAuth</title>
    <link rel="icon" type="image/svg+xml" href="/favicon.svg">
    <link rel="shortcut icon" href="/favicon.svg">
    <link rel="stylesheet" href="/assets/armorauth-ui.css">
    <script src="/assets/iconfont.js"></script>
</head>
<body>
<div class="page-shell">
    <main class="panel-frame">
        <section class="visual-panel">
            <div class="brand-row">
                <div class="brand-chip brand-chip-logo">
                    <img class="brand-logo" src="/brand/icon.svg" alt="ArmorAuth logo">
                    <span class="brand-copy">
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
                <h1>统一身份认证</h1>
                <p>在一个界面完成登录、授权确认与设备激活。</p>
            </div>

            <div class="hero-stage" aria-hidden="true">
                <div class="showcase-panel">
                    <div class="showcase-logo-shell">
                        <img class="showcase-logo" src="/brand/logo.svg" alt="ArmorAuth logo">
                    </div>
                    <div class="showcase-orbit">
                        <div class="showcase-node showcase-node-top">统一登录</div>
                        <div class="showcase-node showcase-node-left">授权确认</div>
                        <div class="showcase-node showcase-node-right">设备激活</div>
                    </div>
                </div>
            </div>

            <div class="signal-board" aria-label="平台能力">
                <div class="signal-line">
                    <span class="signal-tag">多方式登录</span>
                    <strong>账号密码与短信验证码统一接入</strong>
                </div>
                <div class="signal-line">
                    <span class="signal-tag">流程统一</span>
                    <strong>登录、授权、设备激活保持同一套界面语言</strong>
                </div>
                <div class="signal-line">
                    <span class="signal-tag">品牌一致</span>
                    <strong>认证入口与平台身份体系保持清晰且连续</strong>
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
                        <div class="action-row action-row-stacked">
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
                        <div class="action-row action-row-stacked">
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
                    <div class="provider-list">
                        <#list federatedProviders as provider>
                            <#assign providerId = provider.registrationId?lower_case>
                            <a class="provider-link provider-${providerId}" href="/oauth2/authorization/${provider.registrationId}?mode=${selectedFederatedMode}" aria-label="使用 ${provider.clientName!provider.registrationId} 登录">
                                <span class="provider-icon" aria-hidden="true">
                                    <#if providerId == 'gitee'>
                                        <svg class="provider-symbol" viewBox="0 0 1024 1024" focusable="false">
                                            <use href="#icon-gitee"></use>
                                        </svg>
                                    <#elseif providerId == 'qq'>
                                        <svg class="provider-symbol" viewBox="0 0 1024 1024" focusable="false">
                                            <use href="#icon-QQ1"></use>
                                        </svg>
                                    <#elseif providerId == 'wechat' || providerId == 'weixin'>
                                        <svg class="provider-symbol" viewBox="0 0 1024 1024" focusable="false">
                                            <use href="#icon-weixin"></use>
                                        </svg>
                                    <#elseif providerId == 'github'>
                                        <svg class="provider-symbol" viewBox="0 0 1049 1024" focusable="false">
                                            <use href="#icon-GitHub"></use>
                                        </svg>
                                    <#elseif providerId == 'google'>
                                        <span class="provider-mark provider-mark-google">G</span>
                                    <#elseif providerId == 'facebook'>
                                        <span class="provider-mark provider-mark-facebook">f</span>
                                    <#elseif providerId == 'microsoft'>
                                        <span class="provider-mark provider-mark-microsoft">
                                            <span></span><span></span><span></span><span></span>
                                        </span>
                                    <#elseif providerId == 'gitlab'>
                                        <span class="provider-mark provider-mark-gitlab">GL</span>
                                    <#elseif providerId == 'discord'>
                                        <span class="provider-mark provider-mark-discord">D</span>
                                    <#elseif providerId == 'slack'>
                                        <span class="provider-mark provider-mark-slack">S</span>
                                    <#elseif providerId == 'linkedin'>
                                        <span class="provider-mark provider-mark-linkedin">in</span>
                                    <#elseif providerId == 'apple'>
                                        <span class="provider-mark provider-mark-apple">A</span>
                                    <#elseif providerId == 'weibo'>
                                        <span class="provider-mark provider-mark-weibo">WB</span>
                                    <#elseif providerId == 'baidu'>
                                        <span class="provider-mark provider-mark-baidu">du</span>
                                    <#elseif providerId == 'oschina'>
                                        <span class="provider-mark provider-mark-oschina">OS</span>
                                    <#elseif providerId == 'douyin'>
                                        <span class="provider-mark provider-mark-douyin">dy</span>
                                    <#elseif providerId == 'alipay'>
                                        <span class="provider-mark provider-mark-alipay">支</span>
                                    <#else>
                                        <span class="provider-fallback">${providerId?upper_case?substring(0, 2)}</span>
                                    </#if>
                                </span>
                                <span class="provider-label">${provider.clientName!provider.registrationId}</span>
                            </a>
                        </#list>
                    </div>
                </div>
            </#if>

            <p class="footer-copy">ArmorAuth 统一身份平台</p>
        </section>
    </main>
    <footer class="page-footer">
        <div class="page-footer-brand">
            <strong>ArmorAuth</strong>
            <span>统一身份与授权平台</span>
        </div>
        <div class="page-footer-nav" aria-label="页面信息">
            <span>简体中文</span>
            <span>安全登录</span>
            <span>隐私保护</span>
        </div>
    </footer>
</div>
<script src="/assets/armorauth-ui.js"></script>
</body>
</html>
