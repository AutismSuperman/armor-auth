<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>联合登录确认</title>
    <link rel="stylesheet" href="/assets/armorauth-ui.css">
</head>
<body>
<div class="page-shell">
    <main class="auth-card">
        <section class="auth-aside">
            <div class="brand-chip">
                <span class="brand-dot"></span>
                <span>ArmorAuth Federated Bridge</span>
            </div>
            <div class="aside-copy">
                <h1>第三方资料已拿到，还差本地账号确认。</h1>
                <p>当前还不算 OAuth 成功。只有完成“创建新账号”或“绑定已有账号”之一，才会写入本地会话并继续原始跳转。</p>
            </div>
            <div class="summary-stack">
                <div class="summary-item">
                    <span>Provider</span>
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
        <section class="auth-main">
            <div class="section-title">
                <span class="eyebrow">Federated Confirm</span>
                <h1>确认本地账号归属</h1>
                <p>创建新账号会写入 `user_info` 和绑定表；绑定已有账号只写入第三方绑定关系。</p>
            </div>

            <#if errorMessage??>
                <div class="notice error">${errorMessage}</div>
            </#if>

            <div class="meta-block">
                绑定键固定为 `${pending.registrationId}` + `${providerUserIdSummary}`，后续再次使用同一第三方账号登录时会直接命中本地账号，不再进入此页。
            </div>

            <div class="switcher" aria-label="确认方式">
                <button type="button" class="<#if selectedTab == 'create'>is-active</#if>" data-target="create-account">创建新账号</button>
                <button type="button" class="<#if selectedTab == 'bind'>is-active</#if>" data-target="bind-account">绑定已有账号</button>
            </div>

            <form id="create-account" class="auth-form" action="/federated/confirm/create" method="post" <#if selectedTab != 'create'>hidden</#if>>
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

            <form id="bind-account" class="auth-form" action="/federated/confirm/bind" method="post" <#if selectedTab != 'bind'>hidden</#if>>
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

            <p class="footer-copy">完成后仍沿用 Spring Security SavedRequest 跳转逻辑。</p>
        </section>
    </main>
</div>
<script>
    const confirmTabs = document.querySelectorAll('.switcher button[data-target]');
    const confirmForms = document.querySelectorAll('#create-account, #bind-account');
    confirmTabs.forEach((button) => {
        button.addEventListener('click', () => {
            confirmTabs.forEach((item) => item.classList.remove('is-active'));
            confirmForms.forEach((form) => {
                form.hidden = form.id !== button.dataset.target;
            });
            button.classList.add('is-active');
        });
    });
</script>
</body>
</html>
