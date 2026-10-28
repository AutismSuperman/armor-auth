export default [
    {
        path: '/main/home',
        name: 'Home',
        component: () => import('../views/main/Home.vue'),
        meta: { title: '概览' }
    },
    {
        path: '/main/applications',
        name: 'Applications',
        component: () => import('../views/main/Application.vue'),
        meta: { title: '自建与集成应用' }
    },
    {
        path: '/main/scopes',
        name: 'Scopes',
        component: () => import('../views/main/Scopes.vue'),
        meta: { title: 'Scope 权限定义' }
    },
    {
        path: '/main/loginPolicies',
        name: 'LoginPolicies',
        component: () => import('../views/main/LoginPolicies.vue'),
        meta: { title: '登录与 MFA 策略' }
    },
    {
        path: '/main/secretProtection',
        name: 'SecretProtection',
        component: () => import('../views/main/SecretProtection.vue'),
        meta: { title: 'Client Secret 保护' }
    },
    {
        path: '/main/jwkKeys',
        name: 'JwkKeys',
        component: () => import('../views/main/JwkKeys.vue'),
        meta: { title: 'JWK 签名密钥轮转' }
    },
    {
        path: '/main/sessions',
        name: 'Sessions',
        component: () => import('../views/main/Sessions.vue'),
        meta: { title: '在线会话管理' }
    },
    {
        path: '/main/monitor',
        name: 'Monitor',
        component: () => import('../views/main/Monitor.vue'),
        meta: { title: 'Token 签发监控' }
    },
    {
        path: '/main/users',
        name: 'Users',
        component: () => import('../views/main/Users.vue'),
        meta: { title: '用户目录' }
    },
    {
        path: '/main/organizations',
        name: 'Organizations',
        component: () => import('../views/main/Organizations.vue'),
        meta: { title: '组织架构' }
    },
    {
        path: '/main/tenants',
        name: 'Tenants',
        component: () => import('../views/main/Tenants.vue'),
        meta: { title: '租户与用户池' }
    },
    {
        path: '/main/identityProviders',
        name: 'IdentityProviders',
        component: () => import('../views/main/IdentityProviders.vue'),
        meta: { title: '身份源连接器' }
    },
    {
        path: '/main/federatedBindings',
        name: 'FederatedBindings',
        component: () => import('../views/main/FederatedBindings.vue'),
        meta: { title: '外部账号映射绑定' }
    },
    {
        path: '/main/audit',
        name: 'Audit',
        component: () => import('../views/main/Audit.vue'),
        meta: { title: '安全审计日志' }
    },
    {
        path: '/main/webhooks',
        name: 'Webhooks',
        component: () => import('../views/main/Webhooks.vue'),
        meta: { title: 'Webhook 事件' }
    },
    {
        path: '/main/settings',
        name: 'Settings',
        component: () => import('../views/main/Settings.vue'),
        meta: { title: '系统设置' }
    }
]
