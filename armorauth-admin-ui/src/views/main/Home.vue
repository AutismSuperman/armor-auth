<template>
  <div class="home-page">
    <!-- Hero Banner (Authing Identity Cloud Style) -->
    <div class="welcome-banner">
      <div class="welcome-content">
        <div class="banner-pill">
          <span class="pill-badge">Enterprise Edition</span>
          <span>ArmorAuth 统一身份与访问控制平台</span>
        </div>
        <h2>构建现代化的企业级身份与单点登录中枢</h2>
        <p>提供基于 OAuth 2.1 / OIDC 的托管认证页、Passkey 生物认证、SAML 2.0 企业 SSO 与多租户安全管理</p>
        <div class="banner-actions">
          <a-button type="primary" size="large" class="hero-btn" @click="$router.push('/main/applications')">
            <template #icon><PlusOutlined /></template>
            创建单点登录应用
          </a-button>
          <a-button ghost size="large" class="hero-btn-ghost" @click="$router.push('/main/identityProviders')">
            <template #icon><CloudOutlined /></template>
            连接身份源
          </a-button>
          <a-button type="link" class="hero-link" href="http://localhost:9000/login" target="_blank">
            体验托管登录页 <ArrowRightOutlined />
          </a-button>
        </div>
      </div>
      <div class="welcome-art">
        <div class="art-shield-card">
          <SafetyCertificateOutlined class="shield-big-icon" />
          <div class="shield-text">
            <strong>零信任安全接入</strong>
            <span>OAuth 2.1 + DPoP + WebAuthn</span>
          </div>
        </div>
      </div>
    </div>

    <!-- Stats Grid (Authing Cloud Metrics) -->
    <div class="stats-grid">
      <div class="stat-card" v-for="stat in statsCards" :key="stat.key" @click="$router.push(stat.path)">
        <div class="stat-icon" :style="{ background: stat.bg }">
          <component :is="stat.icon" />
        </div>
        <div class="stat-info">
          <div class="stat-top">
            <span class="stat-label">{{ stat.label }}</span>
            <a-tag :color="stat.tagColor" size="small">{{ stat.tag }}</a-tag>
          </div>
          <div class="stat-value">{{ stat.value }}</div>
          <div class="stat-hint">{{ stat.hint }}</div>
        </div>
      </div>
    </div>

    <!-- Onboarding Guide / 4-Step Checklist -->
    <div class="dashboard-section">
      <div class="section-header">
        <div class="section-title-wrap">
          <h3>快速接入单点登录</h3>
          <span class="section-subtitle">4 个步骤完成应用与企业身份体系的快速集成</span>
        </div>
      </div>
      <div class="onboarding-grid">
        <div
          v-for="step in onboardingSteps"
          :key="step.step"
          class="step-card"
          @click="$router.push(step.path)">
          <div class="step-num">{{ step.step }}</div>
          <div class="step-body">
            <h4 class="step-title">{{ step.title }}</h4>
            <p class="step-desc">{{ step.desc }}</p>
            <div class="step-action">
              <span>{{ step.actionText }}</span>
              <ArrowRightOutlined />
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- Protocol & Security Capabilities -->
    <div class="dashboard-section">
      <div class="section-header">
        <div class="section-title-wrap">
          <h3>企业级安全与协议能力</h3>
          <span class="section-subtitle">符合国际标准与现代身份前沿安全规范</span>
        </div>
      </div>
      <div class="feature-matrix">
        <div v-for="feature in securityFeatures" :key="feature.title" class="feature-item">
          <div class="feature-icon-box" :style="{ color: feature.color }">
            <component :is="feature.icon" />
          </div>
          <div class="feature-text">
            <h4>{{ feature.title }}</h4>
            <p>{{ feature.desc }}</p>
          </div>
        </div>
      </div>
    </div>

    <!-- Quick Navigation -->
    <div class="dashboard-section">
      <div class="section-header">
        <div class="section-title-wrap">
          <h3>管理控制台导航</h3>
          <span class="section-subtitle">快速进入各项身份池管理、策略配置与审计模块</span>
        </div>
      </div>
      <div class="nav-grid">
        <div class="nav-card" v-for="item in routers" :key="item.title" @click="$router.push(item.path)">
          <div class="nav-icon" :style="{ background: item.color }">
            <component :is="item.icon" />
          </div>
          <div class="nav-info">
            <span class="nav-title">{{ item.title }}</span>
            <span class="nav-desc">{{ item.desc }}</span>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { reactive, onMounted, h } from 'vue'
import {
  AppstoreOutlined,
  UserOutlined,
  TeamOutlined,
  CloudOutlined,
  FileTextOutlined,
  BarChartOutlined,
  SafetyOutlined,
  KeyOutlined,
  PlusOutlined,
  ArrowRightOutlined,
  SafetyCertificateOutlined,
  LockOutlined,
  ThunderboltOutlined,
  CheckCircleOutlined
} from '@ant-design/icons-vue'
import { getApplications, getUsers, getOrganizations, getIdentityProviders } from '../../api'

const stats = reactive({ applications: 0, providers: 0, users: 0, orgs: 0 })

const statsCards = reactive([
  {
    key: 'apps',
    label: '集成应用',
    value: 0,
    tag: 'OAuth 2.1',
    tagColor: 'blue',
    hint: '自建与第三方客户端',
    path: '/main/applications',
    icon: () => h(AppstoreOutlined),
    bg: 'linear-gradient(135deg, #2152ff, #437dff)'
  },
  {
    key: 'idps',
    label: '身份源连接',
    value: 0,
    tag: '多协议互通',
    tagColor: 'purple',
    hint: 'SAML / 微信 / Google',
    path: '/main/identityProviders',
    icon: () => h(CloudOutlined),
    bg: 'linear-gradient(135deg, #7c3aed, #a78bfa)'
  },
  {
    key: 'users',
    label: '认证用户',
    value: 0,
    tag: '目录账户',
    tagColor: 'green',
    hint: '多租户用户数据池',
    path: '/main/users',
    icon: () => h(UserOutlined),
    bg: 'linear-gradient(135deg, #10b981, #34d399)'
  },
  {
    key: 'orgs',
    label: '组织机构',
    value: 0,
    tag: '部门架构',
    tagColor: 'orange',
    hint: '企业部门与层级关联',
    path: '/main/organizations',
    icon: () => h(TeamOutlined),
    bg: 'linear-gradient(135deg, #f59e0b, #fbbf24)'
  }
])

const onboardingSteps = [
  {
    step: '01',
    title: '创建单点登录应用',
    desc: '注册 SPA、移动端、标准 Web 或 M2M 客户端，配置授权类型与回调 URI。',
    actionText: '去创建应用',
    path: '/main/applications'
  },
  {
    step: '02',
    title: '连接企业或社交身份源',
    desc: '一键接入 Google、GitHub、微信、飞书扫码或企业 SAML 2.0 / LDAP 目录。',
    actionText: '连接身份源',
    path: '/main/identityProviders'
  },
  {
    step: '03',
    title: '配置多因素与安全策略',
    desc: '开启基于 TOTP / Passkey 的 MFA 强制验证，抵御撞库与网络钓鱼。',
    actionText: '配置安全策略',
    path: '/main/loginPolicies'
  },
  {
    step: '04',
    title: '体验托管统一登录页',
    desc: '访问标准认证授权端点，测试多身份源聚合登录与 OIDC 令牌下发。',
    actionText: '查看应用列表',
    path: '/main/applications'
  }
]

const securityFeatures = [
  {
    title: 'OAuth 2.1 & OIDC 核心协议',
    desc: '遵循 RFC 6749 / 8252 最新安全规范，强制 PKCE 授权码模式，淘汰隐式流。',
    color: '#2152ff',
    icon: SafetyCertificateOutlined
  },
  {
    title: 'Passkey / WebAuthn 生物认证',
    desc: '支持 Touch ID、Face ID 及 Windows Hello 无密码安全硬件凭据认证。',
    color: '#10b981',
    icon: LockOutlined
  },
  {
    title: 'RFC 9449 DPoP 证明凭据',
    desc: '应用层非对称公私钥绑定 Access Token，杜绝令牌被黑客窃取及重放。',
    color: '#8b5cf6',
    icon: ThunderboltOutlined
  },
  {
    title: 'SAML 2.0 & LDAP 目录同步',
    desc: '零代码直连 Okta、Azure AD、OneLogin 及 Windows AD，支持属性自动映射。',
    color: '#f59e0b',
    icon: CheckCircleOutlined
  }
]

const routers = [
  { title: '应用管理', desc: '管理 OAuth 2.1 客户端', icon: AppstoreOutlined, path: '/main/applications', color: '#2152ff' },
  { title: '用户管理', desc: '用户增删改查与状态', icon: UserOutlined, path: '/main/users', color: '#10b981' },
  { title: '组织管理', desc: '企业组织架构与成员', icon: TeamOutlined, path: '/main/organizations', color: '#f59e0b' },
  { title: '身份源管理', desc: '企业 SSO 与社交登录', icon: CloudOutlined, path: '/main/identityProviders', color: '#8b5cf6' },
  { title: '安全策略', desc: 'MFA 验证与登录规则', icon: SafetyOutlined, path: '/main/loginPolicies', color: '#ef4444' },
  { title: '审计日志', desc: '敏感操作追踪与审计', icon: FileTextOutlined, path: '/main/audit', color: '#6366f1' },
  { title: '监控管理', desc: 'Token 签发与调用度量', icon: BarChartOutlined, path: '/main/monitor', color: '#0ea5e9' },
  { title: '密钥管理', desc: 'JWK 密钥轮换与 Secret', icon: KeyOutlined, path: '/main/jwkKeys', color: '#ec4899' }
]

onMounted(async () => {
  try {
    const [appRes, userRes, orgRes, idpRes] = await Promise.allSettled([
      getApplications(0, 1),
      getUsers(0, 1),
      getOrganizations(0, 1),
      getIdentityProviders(0, 1)
    ])
    stats.applications = appRes.status === 'fulfilled' ? (appRes.value.data?.totalElements || 0) : 0
    stats.users = userRes.status === 'fulfilled' ? (userRes.value.data?.totalElements || 0) : 0
    stats.orgs = orgRes.status === 'fulfilled' ? (orgRes.value.data?.totalElements || 0) : 0
    stats.providers = idpRes.status === 'fulfilled' ? (idpRes.value.data?.totalElements || 0) : 0

    statsCards[0].value = stats.applications
    statsCards[1].value = stats.providers
    statsCards[2].value = stats.users
    statsCards[3].value = stats.orgs
  } catch (e) { /* ignore */ }
})
</script>

<style scoped lang="scss">
.home-page {
  max-width: 1600px;
  width: 100%;
  margin: 0 auto;
  padding: 24px;
}

// ── Hero Welcome Banner ──
.welcome-banner {
  background: linear-gradient(135deg, #0f172a 0%, #1e293b 60%, #172554 100%);
  border-radius: 16px;
  padding: 36px 40px;
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 24px;
  box-shadow: 0 10px 25px -5px rgba(15, 23, 42, 0.3);
  position: relative;
  overflow: hidden;
  border: 1px solid rgba(255, 255, 255, 0.08);

  &::before {
    content: '';
    position: absolute;
    top: -50%;
    right: -20%;
    width: 600px;
    height: 600px;
    border-radius: 50%;
    background: radial-gradient(circle, rgba(33, 82, 255, 0.18) 0%, transparent 70%);
    pointer-events: none;
  }
}

.welcome-content {
  position: relative;
  z-index: 2;
  max-width: 720px;

  h2 {
    font-size: 26px;
    font-weight: 700;
    color: #ffffff;
    margin: 12px 0 8px;
    letter-spacing: -0.02em;
  }

  p {
    color: #94a3b8;
    font-size: 14.5px;
    line-height: 1.6;
    margin: 0 0 24px;
  }
}

.banner-pill {
  display: inline-flex;
  align-items: center;
  gap: 8px;
  background: rgba(255, 255, 255, 0.08);
  border: 1px solid rgba(255, 255, 255, 0.14);
  padding: 4px 12px;
  border-radius: 20px;
  font-size: 12px;
  color: #e2e8f0;
}

.pill-badge {
  background: #2152ff;
  color: #fff;
  font-weight: 700;
  font-size: 10.5px;
  padding: 2px 7px;
  border-radius: 10px;
  text-transform: uppercase;
}

.banner-actions {
  display: flex;
  align-items: center;
  gap: 14px;
  flex-wrap: wrap;
}

.hero-btn {
  background: #2152ff !important;
  border-color: #2152ff !important;
  font-weight: 600;
  height: 40px;
  padding: 0 20px;
  box-shadow: 0 4px 14px rgba(33, 82, 255, 0.4) !important;

  &:hover {
    background: #1b45db !important;
  }
}

.hero-btn-ghost {
  color: #ffffff !important;
  border-color: rgba(255, 255, 255, 0.25) !important;
  height: 40px;
  padding: 0 20px;

  &:hover {
    border-color: #ffffff !important;
    background: rgba(255, 255, 255, 0.08) !important;
  }
}

.hero-link {
  color: #60a5fa !important;
  font-size: 14px;
  display: inline-flex;
  align-items: center;
  gap: 6px;

  &:hover {
    color: #93c5fd !important;
  }
}

.welcome-art {
  position: relative;
  z-index: 2;
  flex-shrink: 0;
}

.art-shield-card {
  background: rgba(255, 255, 255, 0.06);
  border: 1px solid rgba(255, 255, 255, 0.12);
  border-radius: 14px;
  padding: 20px 24px;
  display: flex;
  align-items: center;
  gap: 16px;
  backdrop-filter: blur(8px);
}

.shield-big-icon {
  font-size: 38px;
  color: #3b82f6;
}

.shield-text {
  display: flex;
  flex-direction: column;
  gap: 3px;

  strong {
    color: #fff;
    font-size: 15px;
  }

  span {
    color: #94a3b8;
    font-size: 12px;
  }
}

// ── Stats Grid ──
.stats-grid {
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: 16px;
  margin-bottom: 28px;
}

.stat-card {
  background: #ffffff;
  border-radius: 12px;
  padding: 20px;
  display: flex;
  align-items: center;
  gap: 16px;
  box-shadow: var(--aa-shadow-sm);
  border: 1px solid var(--aa-border);
  cursor: pointer;
  transition: all 0.2s cubic-bezier(0.4, 0, 0.2, 1);

  &:hover {
    box-shadow: var(--aa-shadow-md);
    transform: translateY(-2px);
    border-color: #cbd5e1;
  }
}

.stat-icon {
  width: 48px;
  height: 48px;
  border-radius: 12px;
  display: flex;
  align-items: center;
  justify-content: center;
  flex-shrink: 0;
  box-shadow: 0 4px 10px rgba(0, 0, 0, 0.08);

  :deep(.anticon) {
    font-size: 22px;
    color: #ffffff;
  }
}

.stat-info {
  flex: 1;
  min-width: 0;
}

.stat-top {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.stat-label {
  font-size: 13px;
  color: var(--aa-text-secondary);
  font-weight: 500;
}

.stat-value {
  font-size: 28px;
  font-weight: 800;
  color: var(--aa-text-primary);
  line-height: 1.2;
  margin: 4px 0 2px;
  font-family: var(--aa-font-mono);
}

.stat-hint {
  font-size: 11.5px;
  color: var(--aa-text-muted);
}

// ── Dashboard Sections ──
.dashboard-section {
  margin-bottom: 28px;
}

.section-header {
  margin-bottom: 16px;
}

.section-title-wrap {
  h3 {
    font-size: 16px;
    font-weight: 700;
    color: var(--aa-text-primary);
    margin: 0;
    display: flex;
    align-items: center;
    gap: 8px;

    &::before {
      content: '';
      width: 4px;
      height: 16px;
      background: var(--aa-primary);
      border-radius: 2px;
    }
  }

  .section-subtitle {
    display: block;
    font-size: 12.5px;
    color: var(--aa-text-secondary);
    margin-top: 4px;
    margin-left: 12px;
  }
}

// ── Onboarding 4 Steps Grid ──
.onboarding-grid {
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: 16px;
}

.step-card {
  background: #ffffff;
  border-radius: 12px;
  padding: 20px;
  border: 1px solid var(--aa-border);
  box-shadow: var(--aa-shadow-sm);
  display: flex;
  flex-direction: column;
  justify-content: space-between;
  cursor: pointer;
  transition: all 0.2s cubic-bezier(0.4, 0, 0.2, 1);

  &:hover {
    transform: translateY(-2px);
    box-shadow: var(--aa-shadow-md);
    border-color: var(--aa-primary);

    .step-action {
      color: var(--aa-primary);
      gap: 8px;
    }
  }
}

.step-num {
  font-size: 24px;
  font-weight: 800;
  color: #cbd5e1;
  font-family: var(--aa-font-mono);
  margin-bottom: 8px;
}

.step-title {
  font-size: 14.5px;
  font-weight: 600;
  color: var(--aa-text-primary);
  margin: 0 0 6px;
}

.step-desc {
  font-size: 12.5px;
  color: var(--aa-text-secondary);
  line-height: 1.5;
  margin: 0 0 16px;
  min-height: 38px;
}

.step-action {
  display: flex;
  align-items: center;
  gap: 4px;
  font-size: 12.5px;
  font-weight: 600;
  color: var(--aa-text-secondary);
  transition: all 0.2s;
}

// ── Feature Matrix ──
.feature-matrix {
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: 16px;
}

.feature-item {
  background: #ffffff;
  border-radius: 12px;
  padding: 20px;
  border: 1px solid var(--aa-border);
  box-shadow: var(--aa-shadow-sm);
  display: flex;
  align-items: flex-start;
  gap: 14px;
}

.feature-icon-box {
  width: 40px;
  height: 40px;
  border-radius: 10px;
  background: #f8fafc;
  border: 1px solid var(--aa-border-light);
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 20px;
  flex-shrink: 0;
}

.feature-text {
  h4 {
    font-size: 14px;
    font-weight: 600;
    color: var(--aa-text-primary);
    margin: 0 0 4px;
  }

  p {
    font-size: 12px;
    color: var(--aa-text-secondary);
    line-height: 1.5;
    margin: 0;
  }
}

// ── Nav Grid ──
.nav-grid {
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: 14px;
}

.nav-card {
  background: #ffffff;
  border-radius: 12px;
  padding: 18px;
  display: flex;
  align-items: center;
  gap: 14px;
  cursor: pointer;
  border: 1px solid var(--aa-border);
  box-shadow: var(--aa-shadow-sm);
  transition: all 0.2s;

  &:hover {
    box-shadow: var(--aa-shadow-md);
    transform: translateY(-2px);
    border-color: var(--aa-primary);
  }
}

.nav-icon {
  width: 40px;
  height: 40px;
  border-radius: 10px;
  display: flex;
  align-items: center;
  justify-content: center;
  flex-shrink: 0;

  :deep(.anticon) {
    font-size: 19px;
    color: #ffffff;
  }
}

.nav-info {
  display: flex;
  flex-direction: column;
  gap: 2px;
  min-width: 0;
}

.nav-title {
  font-size: 14px;
  font-weight: 600;
  color: var(--aa-text-primary);
}

.nav-desc {
  font-size: 12px;
  color: var(--aa-text-muted);
}

@media (max-width: 1200px) {
  .stats-grid,
  .onboarding-grid,
  .feature-matrix {
    grid-template-columns: repeat(2, 1fr);
  }

  .nav-grid {
    grid-template-columns: repeat(2, 1fr);
  }
}

@media (max-width: 768px) {
  .welcome-banner {
    flex-direction: column;
    align-items: flex-start;
    gap: 20px;
    padding: 24px;
  }

  .welcome-art {
    display: none;
  }

  .stats-grid,
  .onboarding-grid,
  .feature-matrix,
  .nav-grid {
    grid-template-columns: 1fr;
  }
}
</style>