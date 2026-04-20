<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>账号确认 - ArmorAuth</title>
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
                        <span>第三方账号确认</span>
                    </span>
                </div>
                <div class="top-actions">
                    <span class="status-pill">第三方登录</span>
                    <button class="theme-toggle" type="button" data-theme-toggle>
                        <span class="theme-toggle-icon" data-theme-icon>☼</span>
                        <span data-theme-text>浅色</span>
                    </button>
                </div>
            </div>

            <div class="hero-copy">
                <span class="eyebrow">账号确认</span>
                <h1>确认第三方账号对应的本地身份。</h1>
                <p>确认后即可继续进入账号服务。</p>
            </div>

            <div class="summary-grid">
                <div class="summary-item">
                    <span>登录来源</span>
                    <strong>${pending.registrationId}</strong>
                </div>
                <div class="summary-item">
                    <span>第三方昵称</span>
                    <strong>${pending.displayName!pending.providerUsername!'未提供'}</strong>
                </div>
                <div class="summary-item">
                    <span>第三方标识</span>
                    <strong>${providerUserIdSummary}</strong>
                </div>
            </div>
            <#if pending.avatarUrl?? && pending.avatarUrl?has_content>
                <div class="avatar-card">
                    <img src="${pending.avatarUrl}" alt="第三方头像">
                </div>
            </#if>
        </section>
        <section class="content-panel">
            <div class="content-column">
                <div class="section-title">
                    <span class="eyebrow">本地账号</span>
                    <h1>确认账号</h1>
                    <p>创建新账号，或绑定到已有账号后继续。</p>
                </div>

                <#if errorMessage??>
                    <div class="notice error">${errorMessage}</div>
                </#if>

                <div class="meta-block">完成一次确认后，后续可直接使用该第三方账号登录。</div>

                <div data-tab-group>
                    <div class="switcher" aria-label="确认方式">
                        <button type="button" class="<#if selectedTab == 'create'>is-active</#if>" data-tab-target="create-account">创建新账号</button>
                        <button type="button" class="<#if selectedTab == 'bind'>is-active</#if>" data-tab-target="bind-account">绑定已有账号</button>
                    </div>

                    <form id="create-account" class="auth-form" action="/federated/confirm/create" method="post" <#if selectedTab != 'create'>hidden</#if> data-tab-panel>
                        <div class="field-group">
                            <label for="create-username">用户名</label>
                            <input id="create-username" name="username" type="text" autocomplete="username" value="${createUsername!pending.suggestedUsername}" placeholder="请输入本地用户名">
                        </div>
                        <div class="field-group">
                            <label for="create-password">密码</label>
                            <input id="create-password" name="password" type="password" autocomplete="new-password" placeholder="请输入至少 6 位密码">
                        </div>
                        <div class="field-group">
                            <label for="confirm-password">确认密码</label>
                            <input id="confirm-password" name="confirmPassword" type="password" autocomplete="new-password" placeholder="请再次输入密码">
                        </div>
                        <div class="action-row">
                            <button class="button primary" type="submit">创建并完成登录</button>
                            <a class="button secondary" href="/login?mode=confirm">返回登录页</a>
                        </div>
                    </form>

                    <form id="bind-account" class="auth-form" action="/federated/confirm/bind" method="post" <#if selectedTab != 'bind'>hidden</#if> data-tab-panel>
                        <div class="field-group">
                            <label for="bind-username">已有用户名</label>
                            <input id="bind-username" name="username" type="text" autocomplete="username" value="${bindUsername!''}" placeholder="请输入已有本地用户名">
                        </div>
                        <div class="field-group">
                            <label for="bind-password">密码</label>
                            <input id="bind-password" name="password" type="password" autocomplete="current-password" placeholder="请输入已有账号密码">
                        </div>
                        <div class="action-row">
                            <button class="button primary" type="submit">绑定并完成登录</button>
                            <a class="button secondary" href="/login?mode=confirm">返回登录页</a>
                        </div>
                    </form>
                </div>
            </div>

            <p class="footer-copy">ArmorAuth 第三方接入</p>
        </section>
    </main>
</div>
<script src="/assets/armorauth-ui.js"></script>
</body>
</html>
