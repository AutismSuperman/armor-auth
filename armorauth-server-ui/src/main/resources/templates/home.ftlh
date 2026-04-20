<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>控制台 - ArmorAuth</title>
    <link rel="stylesheet" href="/assets/armorauth-ui.css">
</head>
<body>
<div class="page-shell">
    <main class="center-stack">
        <section class="surface-card">
            <div class="surface-inner">
                <div class="toolbar">
                    <div class="brand-chip">
                        <span class="brand-mark">A</span>
                        <span class="brand-copy">
                            <strong>ArmorAuth</strong>
                            <span>控制台</span>
                        </span>
                    </div>
                    <div class="top-actions">
                        <button class="theme-toggle" type="button" data-theme-toggle>
                            <span class="theme-toggle-icon" data-theme-icon>☼</span>
                            <span data-theme-text>浅色</span>
                        </button>
                        <form action="/logout" method="post">
                            <button class="button secondary" type="submit">退出登录</button>
                        </form>
                    </div>
                </div>

                <div class="hero-grid">
                    <div class="section-title">
                        <span class="eyebrow">首页</span>
                        <h1>欢迎，${userName}</h1>
                        <p>你的账号服务已就绪。</p>
                    </div>

                    <div class="meta-strip">
                        <strong>快捷入口</strong>
                        <br>
                        1. 发起新的授权请求
                        <br>
                        2. 处理设备激活
                        <br>
                        3. 进入联邦登录流程
                    </div>
                </div>
            </div>
        </section>
    </main>
</div>
<script src="/assets/armorauth-ui.js"></script>
</body>
</html>
