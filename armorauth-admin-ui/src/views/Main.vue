<template>
  <a-layout class="main-layout">
    <!-- Sidebar (Authing Dark Slate Theme) -->
    <a-layout-sider
      v-model:collapsed="collapsed"
      :trigger="null"
      collapsible
      class="aa-sidebar"
      :width="240"
      :collapsed-width="68"
    >
      <div class="aa-sidebar-logo" @click="$router.push('/main/home')">
        <div class="aa-logo-icon">
          <img src="/brand/logo-mark.svg" alt="ArmorAuth logo">
        </div>
        <transition name="fade">
          <div v-if="!collapsed" class="aa-logo-brand">
            <span class="aa-logo-text">ArmorAuth</span>
            <span class="aa-logo-sub">身份云控制台</span>
          </div>
        </transition>
      </div>

      <div class="aa-sidebar-menu">
        <a-menu
          v-model:selectedKeys="selectedKeys"
          v-model:openKeys="openKeys"
          mode="inline"
          theme="dark"
          :inline-collapsed="collapsed"
          @click="menuClick"
        >
          <a-menu-item key="/main/home">
            <template #icon><HomeOutlined /></template>
            <span>概览</span>
          </a-menu-item>

          <a-sub-menu key="app-management">
            <template #icon><AppstoreOutlined /></template>
            <template #title>单点登录应用</template>
            <a-menu-item key="/main/applications">自建与集成应用</a-menu-item>
            <a-menu-item key="/main/scopes">Scope 权限定义</a-menu-item>
          </a-sub-menu>

          <a-sub-menu key="user-management">
            <template #icon><UserOutlined /></template>
            <template #title>用户与组织</template>
            <a-menu-item key="/main/users">用户目录</a-menu-item>
            <a-menu-item key="/main/organizations">组织架构</a-menu-item>
            <a-menu-item key="/main/tenants">租户与用户池</a-menu-item>
          </a-sub-menu>

          <a-sub-menu key="security">
            <template #icon><SafetyOutlined /></template>
            <template #title>安全风控</template>
            <a-menu-item key="/main/loginPolicies">登录与 MFA 策略</a-menu-item>
            <a-menu-item key="/main/sessions">在线会话管理</a-menu-item>
            <a-menu-item key="/main/secretProtection">Client Secret 保护</a-menu-item>
            <a-menu-item key="/main/jwkKeys">JWK 签名密钥轮转</a-menu-item>
          </a-sub-menu>

          <a-sub-menu key="identity">
            <template #icon><GlobalOutlined /></template>
            <template #title>连接身份源</template>
            <a-menu-item key="/main/identityProviders">身份源连接器</a-menu-item>
            <a-menu-item key="/main/federatedBindings">外部账号映射绑定</a-menu-item>
          </a-sub-menu>

          <a-sub-menu key="monitoring">
            <template #icon><DashboardOutlined /></template>
            <template #title>审计与监控</template>
            <a-menu-item key="/main/monitor">Token 签发监控</a-menu-item>
            <a-menu-item key="/main/audit">安全审计日志</a-menu-item>
          </a-sub-menu>

          <a-menu-item key="/main/webhooks">
            <template #icon><ApiOutlined /></template>
            <span>Webhook 事件</span>
          </a-menu-item>

          <a-menu-item key="/main/settings">
            <template #icon><SettingOutlined /></template>
            <span>系统设置</span>
          </a-menu-item>
        </a-menu>
      </div>

      <div class="aa-sidebar-footer" v-if="!collapsed">
        <div class="aa-version-badge">
          <span>ArmorAuth v1.0.0</span>
          <a-tag color="blue">Enterprise</a-tag>
        </div>
      </div>
    </a-layout-sider>

    <!-- Main Content -->
    <a-layout class="aa-main-area">
      <!-- Top Header (Authing Console Style) -->
      <div class="aa-header">
        <div class="aa-header-left">
          <span class="aa-collapse-trigger" @click="collapsed = !collapsed" :title="collapsed ? '展开菜单' : '折叠菜单'">
            <MenuUnfoldOutlined v-if="collapsed" />
            <MenuFoldOutlined v-else />
          </span>

          <!-- Authing-style Tenant / User Pool Switcher -->
          <a-dropdown :trigger="['click']">
            <div class="aa-tenant-switcher" title="点击切换租户与用户池">
              <div class="tenant-badge-icon">
                <AppstoreOutlined />
              </div>
              <div class="tenant-meta">
                <span class="tenant-name">默认用户池</span>
                <span class="tenant-code">tenant-default</span>
              </div>
              <a-tag color="blue" class="tenant-env-tag">开发/测试</a-tag>
              <DownOutlined class="tenant-arrow" />
            </div>
            <template #overlay>
              <a-menu class="aa-tenant-menu">
                <a-menu-item-group title="可用用户池与租户空间">
                  <a-menu-item key="default">
                    <div class="tenant-option-row">
                      <div>
                        <strong>默认用户池 (Default Pool)</strong>
                        <div class="tenant-option-id">ID: tenant-default</div>
                      </div>
                      <a-tag color="green">当前连接</a-tag>
                    </div>
                  </a-menu-item>
                </a-menu-item-group>
                <a-menu-divider />
                <a-menu-item key="manage" @click="router.push('/main/tenants')">
                  <SettingOutlined /> 管理全部租户与用户池
                </a-menu-item>
              </a-menu>
            </template>
          </a-dropdown>

          <a-breadcrumb class="aa-breadcrumb">
            <a-breadcrumb-item>控制台</a-breadcrumb-item>
            <a-breadcrumb-item>{{ currentPageTitle }}</a-breadcrumb-item>
          </a-breadcrumb>
        </div>

        <div class="aa-header-right">
          <!-- Global Quick Command Palette Trigger (Cmd+K / Ctrl+K) -->
          <div class="aa-header-search-wrap" @click="openCommandPalette">
            <SearchOutlined class="search-lead-icon" />
            <span class="search-text-placeholder">搜索应用、用户、策略...</span>
            <span class="search-kbd-wrap">
              <kbd class="search-kbd">{{ isMac ? '⌘' : 'Ctrl' }}</kbd>
              <kbd class="search-kbd">K</kbd>
            </span>
          </div>

          <div class="aa-header-divider"></div>

          <a-tooltip title="开发者文档与 API 参考">
            <a-button type="text" class="aa-header-btn" href="/swagger-ui.html" target="_blank">
              <template #icon><BookOutlined /></template>
            </a-button>
          </a-tooltip>

          <a-tooltip title="刷新当前页面">
            <a-button type="text" class="aa-header-btn" @click="refreshPage">
              <template #icon><ReloadOutlined /></template>
            </a-button>
          </a-tooltip>

          <a-dropdown>
            <div class="aa-user-info">
              <a-avatar :size="32" class="aa-avatar">
                {{ avatarLetter }}
              </a-avatar>
              <div class="aa-user-meta">
                <span class="aa-username">{{ adminUser.displayName || adminUser.username || '管理员' }}</span>
                <small class="aa-role-label">超级管理员</small>
              </div>
              <DownOutlined style="font-size: 10px; color: #9ca3af" />
            </div>
            <template #overlay>
              <a-menu>
                <a-menu-item key="profile" disabled>
                  <strong>{{ adminUser.username || '未识别账号' }}</strong>
                </a-menu-item>
                <a-menu-divider />
                <a-menu-item key="validate" @click="refreshSession">
                  <template #icon><ReloadOutlined /></template>
                  校验登录状态
                </a-menu-item>
                <a-menu-item key="settings" @click="router.push('/main/settings')">
                  <template #icon><SettingOutlined /></template>
                  账号安全与权限
                </a-menu-item>
                <a-menu-divider />
                <a-menu-item key="logout" @click="handleLogout">
                  <template #icon><LogoutOutlined /></template>
                  退出登录
                </a-menu-item>
              </a-menu>
            </template>
          </a-dropdown>
        </div>
      </div>

      <!-- Content Area with Ambient Depth -->
      <a-layout-content class="aa-content">
        <router-view :key="routeKey" />
      </a-layout-content>
    </a-layout>

    <!-- Global Command Palette Modal (Cmd+K / Ctrl+K) -->
    <a-modal
      v-model:open="commandPaletteOpen"
      :footer="null"
      :closable="false"
      width="580px"
      class="command-palette-modal"
      @cancel="closeCommandPalette"
    >
      <div class="palette-box">
        <div class="palette-input-line">
          <SearchOutlined class="palette-search-icon" />
          <input
            ref="paletteInputRef"
            v-model="paletteQuery"
            type="text"
            placeholder="搜索控制台功能、快速直达页面..."
            class="palette-native-input"
            @keydown.down.prevent="navigateResults(1)"
            @keydown.up.prevent="navigateResults(-1)"
            @keydown.enter="executeActiveItem"
            @keydown.esc="closeCommandPalette"
          />
          <span class="palette-esc-badge" @click="closeCommandPalette">ESC</span>
        </div>

        <div class="palette-results-list">
          <template v-if="filteredNavItems.length">
            <div
              v-for="(item, index) in filteredNavItems"
              :key="item.path"
              class="palette-item"
              :class="{ 'is-active': activeIndex === index }"
              @mouseenter="activeIndex = index"
              @click="selectNavItem(item)"
            >
              <div class="palette-item-icon">
                <component :is="item.icon" />
              </div>
              <div class="palette-item-meta">
                <div class="palette-item-title-row">
                  <span class="palette-item-title">{{ item.title }}</span>
                  <span class="palette-item-group">{{ item.group }}</span>
                </div>
                <div class="palette-item-desc">{{ item.desc }}</div>
              </div>
              <span class="palette-item-enter">↵</span>
            </div>
          </template>
          <div v-else class="palette-empty">
            <span>未找到与 "{{ paletteQuery }}" 相关的功能入口</span>
          </div>
        </div>

        <div class="palette-footer">
          <span class="palette-hint">使用 <kbd>↑</kbd> <kbd>↓</kbd> 切换选项，<kbd>↵</kbd> 回车跳转，<kbd>ESC</kbd> 退出</span>
        </div>
      </div>
    </a-modal>
  </a-layout>
</template>

<script setup>
import { ref, computed, watch, onMounted, onBeforeUnmount, nextTick } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { message } from 'ant-design-vue'
import {
  HomeOutlined, AppstoreOutlined, UserOutlined, SafetyOutlined,
  GlobalOutlined, DashboardOutlined, ApiOutlined, SettingOutlined,
  MenuFoldOutlined, MenuUnfoldOutlined, ReloadOutlined,
  LogoutOutlined, DownOutlined, SearchOutlined, BookOutlined
} from '@ant-design/icons-vue'
import { clearAdminAuth, getAdminUser, validateAdminSession } from '../api'

const route = useRoute()
const router = useRouter()

const collapsed = ref(false)
const selectedKeys = ref(['/main/home'])
const openKeys = ref([])
const routeKey = ref(0)
const adminUser = ref(getAdminUser())
let lastForbiddenToastAt = 0

// Command Palette State
const commandPaletteOpen = ref(false)
const paletteQuery = ref('')
const activeIndex = ref(0)
const paletteInputRef = ref(null)

const isMac = typeof navigator !== 'undefined' && /Mac|iPod|iPhone|iPad/.test(navigator.userAgent)

const submenuMap = {
  '/main/applications': 'app-management',
  '/main/scopes': 'app-management',
  '/main/users': 'user-management',
  '/main/organizations': 'user-management',
  '/main/tenants': 'user-management',
  '/main/loginPolicies': 'security',
  '/main/sessions': 'security',
  '/main/secretProtection': 'security',
  '/main/jwkKeys': 'security',
  '/main/identityProviders': 'identity',
  '/main/federatedBindings': 'identity',
  '/main/monitor': 'monitoring',
  '/main/audit': 'monitoring'
}

const pageTitleMap = {
  '/main/home': '概览',
  '/main/applications': '自建与集成应用',
  '/main/scopes': 'Scope 权限定义',
  '/main/users': '用户目录',
  '/main/organizations': '组织架构',
  '/main/tenants': '租户与用户池',
  '/main/loginPolicies': '登录与 MFA 策略',
  '/main/sessions': '在线会话管理',
  '/main/secretProtection': 'Client Secret 保护',
  '/main/jwkKeys': 'JWK 签名密钥轮转',
  '/main/identityProviders': '身份源连接器',
  '/main/federatedBindings': '外部账号映射绑定',
  '/main/monitor': 'Token 签发监控',
  '/main/audit': '安全审计日志',
  '/main/webhooks': 'Webhook 事件',
  '/main/settings': '系统设置'
}

const allNavItems = [
  { path: '/main/home', title: '控制台概览', group: '首页总览', desc: '全域应用统计、用户基数与系统运行状态看板', icon: HomeOutlined },
  { path: '/main/applications', title: '自建与集成应用', group: '单点登录应用', desc: 'OAuth 2.1 / OIDC 客户端管理、PKCE、DPoP 安全基线', icon: AppstoreOutlined },
  { path: '/main/scopes', title: 'Scope 权限定义', group: '单点登录应用', desc: '定义 OIDC 作用域与 API 资源访问授权边界', icon: AppstoreOutlined },
  { path: '/main/users', title: '用户目录', group: '用户与组织', desc: '企业账号资产、角色赋予、Profile 扩展及密码重置', icon: UserOutlined },
  { path: '/main/organizations', title: '组织架构', group: '用户与组织', desc: '部门层级树、组织成员编排与组织角色权限', icon: UserOutlined },
  { path: '/main/tenants', title: '租户与用户池', group: '用户与组织', desc: '多租户数据空间隔离、用户池管理与品牌个性化', icon: UserOutlined },
  { path: '/main/loginPolicies', title: '登录与 MFA 策略', group: '安全风控', desc: '应用全员强制 MFA、特定高权限角色二次认证规则', icon: SafetyOutlined },
  { path: '/main/sessions', title: '在线会话管理', group: '安全风控', desc: '全域活跃会话在线探测、终端类型与一键强制下线', icon: SafetyOutlined },
  { path: '/main/secretProtection', title: 'Client Secret 保护', group: '安全风控', desc: '敏感客户端凭证掩码保护与轮换历史', icon: SafetyOutlined },
  { path: '/main/jwkKeys', title: 'JWK 签名密钥轮转', group: '安全风控', desc: 'RS256 / ES256 签名私钥轮转与公开端点同步', icon: SafetyOutlined },
  { path: '/main/identityProviders', title: '身份源连接器', group: '连接身份源', desc: 'SAML 2.0 / LDAP / 企业微信 / 飞书 / GitHub 连接', icon: GlobalOutlined },
  { path: '/main/federatedBindings', title: '外部账号映射绑定', group: '连接身份源', desc: '第三方平台身份与本地用户映射关系管理', icon: GlobalOutlined },
  { path: '/main/monitor', title: 'Token 签发监控', group: '审计与监控', desc: '令牌签发吞吐量、认证耗时及异常失败监控', icon: DashboardOutlined },
  { path: '/main/audit', title: '安全审计日志', group: '审计与监控', desc: '全生命周期关键安全事件操作轨迹追踪与回溯', icon: DashboardOutlined },
  { path: '/main/webhooks', title: 'Webhook 事件', group: '系统扩展', desc: '订阅全域身份安全事件并向业务端点推送消息', icon: ApiOutlined },
  { path: '/main/settings', title: '系统设置', group: '系统配置', desc: '管理员安全密码、权限配置与系统偏好', icon: SettingOutlined }
]

const filteredNavItems = computed(() => {
  if (!paletteQuery.value) {
    return allNavItems
  }
  const q = paletteQuery.value.toLowerCase().trim()
  return allNavItems.filter(item =>
    item.title.toLowerCase().includes(q) ||
    item.group.toLowerCase().includes(q) ||
    item.desc.toLowerCase().includes(q) ||
    item.path.toLowerCase().includes(q)
  )
})

const currentPageTitle = computed(() => pageTitleMap[route.path] || '概览')

const avatarLetter = computed(() => {
  return (adminUser.value.displayName || adminUser.value.username || 'A').charAt(0).toUpperCase()
})

const openCommandPalette = () => {
  paletteQuery.value = ''
  activeIndex.value = 0
  commandPaletteOpen.value = true
  nextTick(() => {
    if (paletteInputRef.value) {
      paletteInputRef.value.focus()
    }
  })
}

const closeCommandPalette = () => {
  commandPaletteOpen.value = false
}

const navigateResults = (direction) => {
  const max = filteredNavItems.value.length
  if (max === 0) return
  activeIndex.value = (activeIndex.value + direction + max) % max
}

const executeActiveItem = () => {
  const item = filteredNavItems.value[activeIndex.value]
  if (item) {
    selectNavItem(item)
  }
}

const selectNavItem = (item) => {
  closeCommandPalette()
  router.push(item.path)
}

const handleGlobalKeydown = (e) => {
  if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
    e.preventDefault()
    if (commandPaletteOpen.value) {
      closeCommandPalette()
    } else {
      openCommandPalette()
    }
  }
}

watch(
  () => route.path,
  (path) => {
    selectedKeys.value = [path]
    const parent = submenuMap[path]
    if (parent && !openKeys.value.includes(parent)) {
      openKeys.value = [...openKeys.value, parent]
    }
  },
  { immediate: true }
)

const menuClick = (data) => {
  if (data.key !== route.path) {
    router.push(data.key)
  }
}

const refreshPage = () => {
  routeKey.value++
}

const refreshSession = async () => {
  try {
    adminUser.value = await validateAdminSession()
    message.success('登录状态校验成功')
  } catch (e) {
    message.error(e.message || '登录校验失败')
    router.replace({ path: '/login', query: { redirect: route.fullPath } })
  }
}

const handleAuthExpired = (event) => {
  adminUser.value = getAdminUser()
  message.warning(event.detail?.message || '登录已过期，请重新登录')
  if (route.path !== '/login') {
    router.replace({ path: '/login', query: { redirect: route.fullPath } })
  }
}

const handleForbidden = (event) => {
  const now = Date.now()
  if (now - lastForbiddenToastAt < 1500) return
  lastForbiddenToastAt = now
  message.warning(event.detail?.message || '当前账号没有此操作权限')
}

const handleLogout = () => {
  clearAdminAuth()
  adminUser.value = getAdminUser()
  router.replace('/login')
}

onMounted(() => {
  adminUser.value = getAdminUser()
  window.addEventListener('armorauth:auth-expired', handleAuthExpired)
  window.addEventListener('armorauth:forbidden', handleForbidden)
  window.addEventListener('keydown', handleGlobalKeydown)
})

onBeforeUnmount(() => {
  window.removeEventListener('armorauth:auth-expired', handleAuthExpired)
  window.removeEventListener('armorauth:forbidden', handleForbidden)
  window.removeEventListener('keydown', handleGlobalKeydown)
})
</script>

<style scoped lang="scss">
.main-layout {
  width: 100%;
  height: 100vh;
  display: flex;
  overflow: hidden;
}

.aa-sidebar {
  background: var(--aa-sidebar-bg) !important;
  height: 100vh;
  overflow: hidden;
  display: flex;
  flex-direction: column;
  box-shadow: 2px 0 16px rgba(0, 0, 0, 0.16);
  z-index: 10;

  :deep(.ant-layout-sider-children) {
    display: flex;
    flex-direction: column;
    height: 100%;
  }
}

.aa-sidebar-logo {
  height: 64px;
  display: flex;
  align-items: center;
  padding: 0 18px;
  gap: 12px;
  cursor: pointer;
  border-bottom: 1px solid rgba(255, 255, 255, 0.08);
  flex-shrink: 0;
  transition: all 0.2s ease;

  :deep(.ant-layout-sider-collapsed) & {
    padding: 0;
    justify-content: center;
  }
}

.aa-logo-icon {
  width: 36px;
  height: 36px;
  background: #ffffff;
  border-radius: 10px;
  display: flex;
  align-items: center;
  justify-content: center;
  flex-shrink: 0;
  box-shadow: 0 2px 8px rgba(0, 0, 0, 0.25);

  img {
    width: 25px;
    height: 25px;
    display: block;
  }
}

.aa-logo-brand {
  display: flex;
  flex-direction: column;
  line-height: 1.2;
}

.aa-logo-text {
  font-size: 16.5px;
  font-weight: 700;
  color: #ffffff;
  letter-spacing: -0.02em;
}

.aa-logo-sub {
  font-size: 11px;
  color: rgba(255, 255, 255, 0.5);
  margin-top: 2px;
}

.aa-sidebar-menu {
  flex: 1;
  overflow-y: auto;
  overflow-x: hidden;
  padding: 12px 0;

  &::-webkit-scrollbar {
    width: 4px;
  }
  &::-webkit-scrollbar-thumb {
    background: rgba(255, 255, 255, 0.12);
    border-radius: 2px;
  }
}

:deep(.ant-menu-dark) {
  background: transparent;

  .ant-menu-item {
    margin: 2px 10px;
    border-radius: 8px;
    height: 38px;
    line-height: 38px;
    font-size: 13.5px;
    color: rgba(255, 255, 255, 0.72);
    transition: all 0.2s ease;

    &:hover {
      color: #ffffff;
      background: rgba(255, 255, 255, 0.08);
    }

    &-selected {
      color: #ffffff !important;
      background: var(--aa-primary) !important;
      box-shadow: 0 2px 10px rgba(33, 82, 255, 0.4);
      font-weight: 600;
    }
  }

  .ant-menu-submenu {
    margin: 2px 10px;
    border-radius: 8px;

    .ant-menu-submenu-title {
      height: 38px;
      line-height: 38px;
      border-radius: 8px;
      font-size: 13.5px;
      color: rgba(255, 255, 255, 0.72);

      &:hover {
        color: #ffffff;
        background: rgba(255, 255, 255, 0.08);
      }
    }

    &-open > .ant-menu-submenu-title {
      color: rgba(255, 255, 255, 0.95);
      font-weight: 600;
    }
  }

  .ant-menu-sub {
    background: rgba(0, 0, 0, 0.18) !important;
    border-radius: 8px;
    margin: 4px 0;
  }
}

.aa-sidebar-footer {
  padding: 14px 18px;
  border-top: 1px solid rgba(255, 255, 255, 0.08);
  flex-shrink: 0;
}

.aa-version-badge {
  display: flex;
  align-items: center;
  justify-content: space-between;
  font-size: 11.5px;
  color: rgba(255, 255, 255, 0.5);
}

.aa-main-area {
  flex: 1;
  display: flex;
  flex-direction: column;
  overflow: hidden;
  background: var(--aa-bg);
}

.aa-header {
  height: 64px;
  background: rgba(255, 255, 255, 0.94);
  backdrop-filter: blur(12px);
  -webkit-backdrop-filter: blur(12px);
  border-bottom: 1px solid var(--aa-border);
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 0 28px;
  flex-shrink: 0;
  box-shadow: 0 1px 2px rgba(15, 23, 42, 0.04);
  z-index: 5;
}

.aa-header-left {
  display: flex;
  align-items: center;
  gap: 16px;
}

.aa-collapse-trigger {
  display: flex;
  align-items: center;
  justify-content: center;
  width: 34px;
  height: 34px;
  border-radius: 8px;
  cursor: pointer;
  color: var(--aa-text-secondary);
  transition: all 0.2s;

  &:hover {
    background: var(--aa-bg-light);
    color: var(--aa-text-primary);
  }
}

/* Authing-style Tenant Switcher */
.aa-tenant-switcher {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 5px 12px;
  border-radius: 8px;
  background: #f8fafc;
  border: 1px solid var(--aa-border);
  cursor: pointer;
  transition: all 0.2s ease;

  &:hover {
    border-color: var(--aa-primary);
    background: #ffffff;
    box-shadow: 0 2px 6px rgba(15, 23, 42, 0.06);
  }
}

.tenant-badge-icon {
  width: 24px;
  height: 24px;
  border-radius: 6px;
  background: var(--aa-primary-light);
  color: var(--aa-primary);
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 13px;
}

.tenant-meta {
  display: flex;
  flex-direction: column;
  line-height: 1.15;
}

.tenant-name {
  font-size: 12.5px;
  font-weight: 600;
  color: var(--aa-text-primary);
}

.tenant-code {
  font-size: 11px;
  color: var(--aa-text-muted);
}

.tenant-env-tag {
  font-size: 11px !important;
  line-height: 18px !important;
  padding: 0 6px !important;
  margin: 0 !important;
}

.tenant-arrow {
  font-size: 10px;
  color: var(--aa-text-muted);
}

.tenant-option-row {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 16px;
  min-width: 240px;
  padding: 4px 0;
}

.tenant-option-id {
  font-size: 11.5px;
  color: #94a3b8;
  font-family: var(--aa-font-mono);
}

.aa-breadcrumb {
  font-size: 13.5px;
  border-left: 1px solid var(--aa-border);
  padding-left: 16px;

  :deep(.ant-breadcrumb-link) {
    color: var(--aa-text-secondary);
  }

  :deep(.ant-breadcrumb-link:last-child) {
    color: var(--aa-text-primary);
    font-weight: 600;
  }
}

.aa-header-right {
  display: flex;
  align-items: center;
  gap: 10px;
}

/* ── Modern Command Palette Search Bar (No Truncation) ── */
.aa-header-search-wrap {
  width: 280px;
  height: 36px;
  background: #f1f5f9;
  border: 1px solid transparent;
  border-radius: 8px;
  padding: 0 10px;
  display: flex;
  align-items: center;
  gap: 8px;
  cursor: pointer;
  transition: all 0.25s cubic-bezier(0.4, 0, 0.2, 1);

  &:hover {
    background: #ffffff;
    border-color: var(--aa-border);
    box-shadow: 0 1px 4px rgba(15, 23, 42, 0.05);

    .search-lead-icon {
      color: var(--aa-primary);
    }
  }
}

.search-lead-icon {
  font-size: 14px;
  color: var(--aa-text-muted);
  transition: color 0.2s;
}

.search-text-placeholder {
  flex: 1;
  font-size: 12.5px;
  color: #64748b;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}

.search-kbd-wrap {
  display: flex;
  align-items: center;
  gap: 3px;
}

.search-kbd {
  font-family: var(--aa-font-mono);
  font-size: 10.5px;
  background: #ffffff;
  color: #475569;
  border: 1px solid #cbd5e1;
  border-radius: 4px;
  padding: 1px 5px;
  box-shadow: 0 1px 1px rgba(0, 0, 0, 0.05);
  line-height: 1.2;
}

.aa-header-divider {
  width: 1px;
  height: 20px;
  background: var(--aa-border);
  margin: 0 4px;
}

.aa-header-btn {
  width: 34px;
  height: 34px;
  border-radius: 8px;
  color: var(--aa-text-secondary);
  display: flex;
  align-items: center;
  justify-content: center;

  &:hover {
    background: var(--aa-bg-light);
    color: var(--aa-primary);
  }
}

.aa-user-info {
  display: flex;
  align-items: center;
  gap: 9px;
  padding: 4px 10px;
  border-radius: 8px;
  cursor: pointer;
  transition: background 0.2s;

  &:hover {
    background: var(--aa-bg-light);
  }
}

.aa-avatar {
  background: linear-gradient(135deg, var(--aa-primary) 0%, #6366f1 100%);
  color: #fff;
  font-weight: 700;
  font-size: 13.5px;
}

.aa-user-meta {
  display: flex;
  flex-direction: column;
  line-height: 1.15;
}

.aa-username {
  font-size: 13px;
  font-weight: 600;
  color: var(--aa-text-primary);
}

.aa-role-label {
  font-size: 10.5px;
  color: var(--aa-text-muted);
}

/* ── Content Area with Ambient Depth ── */
.aa-content {
  flex: 1;
  overflow-y: auto;
  padding: 28px 36px 48px;
  background:
    radial-gradient(1200px circle at 50% 0%, rgba(33, 82, 255, 0.035) 0%, transparent 60%),
    #f6f8fb;
  position: relative;
}

/* ── Command Palette Modal Styles ── */
:deep(.command-palette-modal) {
  .ant-modal-content {
    padding: 0 !important;
    border-radius: 16px !important;
    overflow: hidden;
    background: #ffffff;
    box-shadow: 0 25px 60px -15px rgba(15, 23, 42, 0.25) !important;
    border: 1px solid var(--aa-border);
  }
}

.palette-box {
  display: flex;
  flex-direction: column;
}

.palette-input-line {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 16px 20px;
  border-bottom: 1px solid var(--aa-border);
}

.palette-search-icon {
  font-size: 18px;
  color: var(--aa-primary);
}

.palette-native-input {
  flex: 1;
  border: none;
  outline: none;
  font-size: 15px;
  color: var(--aa-text-primary);
  background: transparent;

  &::placeholder {
    color: var(--aa-text-muted);
  }
}

.palette-esc-badge {
  font-size: 11px;
  font-weight: 600;
  color: var(--aa-text-muted);
  background: #f1f5f9;
  border: 1px solid #cbd5e1;
  border-radius: 4px;
  padding: 2px 6px;
  cursor: pointer;

  &:hover {
    color: var(--aa-text-primary);
  }
}

.palette-results-list {
  max-height: 380px;
  overflow-y: auto;
  padding: 8px 10px;
}

.palette-item {
  display: flex;
  align-items: center;
  gap: 14px;
  padding: 10px 14px;
  border-radius: 10px;
  cursor: pointer;
  transition: all 0.15s ease;

  &:hover,
  &.is-active {
    background: #eff4ff;

    .palette-item-icon {
      background: var(--aa-primary);
      color: #ffffff;
    }

    .palette-item-title {
      color: var(--aa-primary);
    }

    .palette-item-enter {
      opacity: 1;
    }
  }
}

.palette-item-icon {
  width: 32px;
  height: 32px;
  border-radius: 8px;
  background: #f1f5f9;
  color: var(--aa-text-secondary);
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 15px;
  flex-shrink: 0;
  transition: all 0.2s ease;
}

.palette-item-meta {
  flex: 1;
  min-width: 0;
}

.palette-item-title-row {
  display: flex;
  align-items: center;
  gap: 8px;
}

.palette-item-title {
  font-size: 13.5px;
  font-weight: 600;
  color: var(--aa-text-primary);
}

.palette-item-group {
  font-size: 11px;
  color: var(--aa-text-muted);
  background: rgba(0, 0, 0, 0.04);
  padding: 1px 6px;
  border-radius: 4px;
}

.palette-item-desc {
  font-size: 12px;
  color: var(--aa-text-muted);
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
  margin-top: 2px;
}

.palette-item-enter {
  font-size: 14px;
  color: var(--aa-primary);
  opacity: 0;
  transition: opacity 0.2s;
  padding-right: 4px;
}

.palette-empty {
  padding: 40px 20px;
  text-align: center;
  color: var(--aa-text-muted);
  font-size: 13px;
}

.palette-footer {
  padding: 10px 20px;
  border-top: 1px solid var(--aa-border-light);
  background: #f8fafc;
  display: flex;
  align-items: center;
  justify-content: flex-end;
}

.palette-hint {
  font-size: 11.5px;
  color: var(--aa-text-muted);

  kbd {
    background: #ffffff;
    border: 1px solid #cbd5e1;
    border-radius: 3px;
    padding: 1px 4px;
    font-size: 10px;
    margin: 0 2px;
  }
}

.fade-enter-active,
.fade-leave-active {
  transition: opacity 0.2s;
}
.fade-enter-from,
.fade-leave-to {
  opacity: 0;
}
</style>
