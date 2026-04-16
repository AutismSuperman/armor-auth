<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>ArmorAuth 设备激活</title>
    <link rel="stylesheet" href="/assets/armorauth-ui.css">
</head>
<body>
<div class="page-shell">
    <main class="center-card">
        <div class="section-title">
            <span class="eyebrow">Device Flow</span>
            <h1>输入设备激活码</h1>
            <p>在电视、CLI 或 IoT 设备上获取到的激活码，输入后即可继续完成授权确认。</p>
        </div>

        <div class="meta-block">
            当前验证端点：${deviceVerificationEndpoint}
        </div>

        <form class="auth-form" action="${deviceVerificationEndpoint}" method="post">
            <div class="field-group">
                <label for="user_code">激活码</label>
                <input id="user_code" name="user_code" type="text" placeholder="例如：ABCD-EFGH" autofocus required>
            </div>
            <div class="action-row">
                <button class="button primary" type="submit">继续验证</button>
                <a class="button secondary" href="/login">返回登录</a>
            </div>
        </form>
    </main>
</div>
</body>
</html>
