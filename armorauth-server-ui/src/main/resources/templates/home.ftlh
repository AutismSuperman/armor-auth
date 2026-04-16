<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>ArmorAuth 首页</title>
    <link rel="stylesheet" href="/assets/armorauth-ui.css">
</head>
<body>
<div class="page-shell">
    <main class="center-card">
        <div class="toolbar">
            <div class="brand-chip">
                <span class="brand-dot"></span>
                <span>ArmorAuth</span>
            </div>
            <form action="/logout" method="post">
                <button class="button secondary" type="submit">退出登录</button>
            </form>
        </div>

        <div class="hero-grid">
            <div class="section-title">
                <span class="eyebrow">Dashboard</span>
                <h1>你好，${userName}</h1>
                <p>当前实例已经切回服务端 FreeMarker 模板，作为统一授权入口的中间页使用。</p>
            </div>

            <div class="meta-block">
                <strong>你可以从这里继续：</strong>
                <br>
                1. 发起新的 OAuth2/OIDC 授权请求
                <br>
                2. 处理设备码登录激活
                <br>
                3. 通过联邦登录回到上游系统
            </div>

            <p class="muted">如果这是一个登录后的跳转中间页，后续可以继续按业务需要扩展为账号中心或授权概览页。</p>
        </div>
    </main>
</div>
</body>
</html>
