<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>ArmorAuth 授权确认</title>
    <link rel="stylesheet" href="/assets/armorauth-ui.css">
</head>
<body>
<div class="page-shell">
    <main class="center-card">
        <div class="section-title">
            <span class="eyebrow">Authorization</span>
            <h1>${clientName} 正在请求访问你的账号</h1>
            <p>当前登录账号为 ${principalName}。请确认要授予的权限范围。</p>
        </div>

        <div class="meta-block">
            <strong>客户端标识：</strong> ${clientId}
            <br>
            <strong>提交地址：</strong> ${requestUri}
            <#if userCode?? && userCode?has_content>
                <br>
                <strong>设备码：</strong> ${userCode}
            </#if>
        </div>

        <form id="consent-form" class="auth-form" action="${requestUri}" method="post">
            <input type="hidden" name="client_id" value="${clientId}">
            <input type="hidden" name="state" value="${state}">
            <#if userCode?? && userCode?has_content>
                <input type="hidden" name="user_code" value="${userCode}">
            </#if>

            <div class="scope-list">
                <#if scopes?has_content>
                    <#list scopes as scope>
                        <label class="scope-item">
                            <input type="checkbox" name="scope" value="${scope.scope}" checked>
                            <span>
                                <strong>${scope.scope}</strong>
                                <p>${scope.description!scope.scope}</p>
                            </span>
                        </label>
                    </#list>
                <#else>
                    <div class="notice success">当前请求的权限已经全部授权过，本次只需确认继续。</div>
                </#if>
            </div>

            <#if previouslyApprovedScopes?has_content>
                <div class="section-title">
                    <span class="eyebrow">Existing</span>
                    <p>以下权限已在之前的会话中授权过。</p>
                </div>
                <div class="scope-list">
                    <#list previouslyApprovedScopes as scope>
                        <div class="scope-item">
                            <input type="checkbox" checked disabled>
                            <span>
                                <strong>${scope.scope}</strong>
                                <p>${scope.description!scope.scope}</p>
                            </span>
                        </div>
                    </#list>
                </div>
            </#if>

            <div class="action-row">
                <button class="button primary" type="submit">同意并继续</button>
                <button class="button secondary" type="button" id="deny-button">拒绝授权</button>
            </div>
        </form>
    </main>
</div>
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
