<template>
  <div class="login-page">
    <!-- Pure Atmospheric Aurora Canvas (No Text Clutter) -->
    <div class="login-bg-canvas">
      <div class="aurora-beam beam-top"></div>
      <div class="aurora-beam beam-center"></div>
      <div class="aurora-beam beam-bottom"></div>
      <div class="aurora-beam beam-accent"></div>
      <div class="micro-dust-grid"></div>

      <!-- Minimal Geometric Precision Rings (Hairline Precision, Zero Text) -->
      <svg class="geo-rings" viewBox="0 0 800 800" fill="none" xmlns="http://www.w3.org/2000/svg">
        <circle cx="400" cy="400" r="230" stroke="rgba(33, 82, 255, 0.12)" stroke-width="1" stroke-dasharray="3 6" />
        <circle cx="400" cy="400" r="330" stroke="rgba(99, 102, 241, 0.08)" stroke-width="1" />
        <circle cx="400" cy="400" r="410" stroke="rgba(255, 255, 255, 0.04)" stroke-width="0.8" stroke-dasharray="4 8" />
      </svg>
    </div>

    <!-- Minimalist Glassmorphic Card (Sharp, Modern & Focused) -->
    <div class="login-card">
      <div class="card-glass-rim"></div>

      <div class="login-header">
        <div class="login-logo-box">
          <img src="/brand/logo-mark.svg" alt="ArmorAuth logo">
        </div>
        <h1 class="brand-title">ArmorAuth</h1>
        <span class="brand-sub">Console</span>
      </div>

      <a-form :model="form" layout="vertical" @finish="handleLogin" class="login-form">
        <a-form-item name="username" :rules="[{ required: true, message: '请输入账号或邮箱' }]">
          <label class="compact-label">账号</label>
          <a-input v-model:value="form.username" size="large" placeholder="用户名 / 邮箱" autofocus>
            <template #prefix><UserOutlined class="input-icon" /></template>
          </a-input>
        </a-form-item>

        <a-form-item name="password" :rules="[{ required: true, message: '请输入密码' }]">
          <label class="compact-label">密码</label>
          <a-input-password v-model:value="form.password" size="large" placeholder="密码" @keyup.enter="handleLogin">
            <template #prefix><LockOutlined class="input-icon" /></template>
          </a-input-password>
        </a-form-item>

        <a-form-item class="form-action-item">
          <a-button type="primary" html-type="submit" size="large" block :loading="loading" class="login-btn">
            进入控制台
          </a-button>
        </a-form-item>
      </a-form>

      <div class="login-footer">
        <span class="footer-meta">ArmorAuth · Enterprise IAM</span>
      </div>
    </div>
  </div>
</template>

<script setup>
import { reactive, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { message } from 'ant-design-vue'
import { UserOutlined, LockOutlined } from '@ant-design/icons-vue'
import { loginAdmin } from '../api'

const router = useRouter()
const route = useRoute()
const loading = ref(false)
const form = reactive({ username: '', password: '' })

const handleLogin = async () => {
  if (loading.value) return
  loading.value = true
  try {
    const adminUser = await loginAdmin(form.username, form.password)
    message.success(`欢迎登录，${adminUser.displayName || adminUser.username}`)
    const redirect = typeof route.query.redirect === 'string' && route.query.redirect.startsWith('/main')
      ? route.query.redirect
      : '/main/home'
    router.replace(redirect)
  } catch (e) {
    message.error(e.message || '登录失败，请检查账号密码')
  } finally {
    loading.value = false
  }
}
</script>

<style scoped lang="scss">
.login-page {
  width: 100%;
  height: 100vh;
  display: flex;
  justify-content: center;
  align-items: center;
  background: #040711;
  position: relative;
  overflow: hidden;
  padding: 24px;
}

/* ── Deep Space Aurora Canvas ── */
.login-bg-canvas {
  position: absolute;
  inset: 0;
  pointer-events: none;
  overflow: hidden;
}

.aurora-beam {
  position: absolute;
  border-radius: 50%;
  filter: blur(120px);
  will-change: transform;
}

.beam-top {
  width: 600px;
  height: 400px;
  background: radial-gradient(ellipse at center, rgba(33, 82, 255, 0.28) 0%, rgba(33, 82, 255, 0) 70%);
  top: -160px;
  left: 50%;
  transform: translateX(-50%);
}

.beam-center {
  width: 480px;
  height: 480px;
  background: radial-gradient(circle, rgba(33, 82, 255, 0.16) 0%, rgba(33, 82, 255, 0) 70%);
  top: 50%;
  left: 50%;
  transform: translate(-50%, -50%);
}

.beam-bottom {
  width: 550px;
  height: 400px;
  background: radial-gradient(circle, rgba(99, 102, 241, 0.18) 0%, rgba(99, 102, 241, 0) 70%);
  bottom: -150px;
  left: 30%;
}

.beam-accent {
  width: 320px;
  height: 320px;
  background: radial-gradient(circle, rgba(6, 182, 212, 0.14) 0%, rgba(6, 182, 212, 0) 70%);
  top: 30%;
  right: 18%;
}

.geo-rings {
  position: absolute;
  top: 50%;
  left: 50%;
  transform: translate(-50%, -50%);
  width: 800px;
  height: 800px;
}

.micro-dust-grid {
  position: absolute;
  inset: 0;
  background-image: radial-gradient(rgba(255, 255, 255, 0.12) 1px, transparent 1px);
  background-size: 28px 28px;
  mask-image: radial-gradient(ellipse 70% 60% at 50% 50%, black 20%, transparent 80%);
  -webkit-mask-image: radial-gradient(ellipse 70% 60% at 50% 50%, black 20%, transparent 80%);
}

/* ── Minimalist Frosted Glass Card ── */
.login-card {
  width: 100%;
  max-width: 380px;
  background: rgba(9, 14, 28, 0.78);
  backdrop-filter: blur(28px);
  -webkit-backdrop-filter: blur(28px);
  border: 1px solid rgba(255, 255, 255, 0.1);
  border-radius: 20px;
  padding: 36px 32px 28px;
  box-shadow:
    0 25px 50px -12px rgba(0, 0, 0, 0.75),
    0 0 40px rgba(33, 82, 255, 0.12);
  position: relative;
  z-index: 2;
}

.card-glass-rim {
  position: absolute;
  top: 0;
  left: 24px;
  right: 24px;
  height: 1px;
  background: linear-gradient(90deg, transparent, rgba(255, 255, 255, 0.22), transparent);
}

.login-header {
  text-align: center;
  display: flex;
  flex-direction: column;
  align-items: center;
  margin-bottom: 26px;
}

.login-logo-box {
  width: 48px;
  height: 48px;
  border-radius: 13px;
  background: linear-gradient(135deg, #ffffff 0%, #f1f5f9 100%);
  display: flex;
  align-items: center;
  justify-content: center;
  margin-bottom: 12px;
  box-shadow: 0 4px 16px rgba(0, 0, 0, 0.4), 0 0 0 1px rgba(255, 255, 255, 0.2);

  img {
    width: 30px;
    height: 30px;
    display: block;
  }
}

.brand-title {
  font-size: 21px;
  font-weight: 700;
  color: #ffffff;
  margin: 0;
  letter-spacing: -0.02em;
}

.brand-sub {
  font-size: 11px;
  font-weight: 600;
  letter-spacing: 0.12em;
  text-transform: uppercase;
  color: #64748b;
  margin-top: 3px;
}

.compact-label {
  display: block;
  font-size: 12.5px;
  font-weight: 500;
  color: #94a3b8;
  margin-bottom: 6px;
}

.input-icon {
  color: #64748b;
  font-size: 14px;
  transition: color 0.2s ease;
}

/* ── Clean Dark Glass Inputs (Zero Clutter, Zero Double Border) ── */
.login-form {
  :deep(.ant-input-affix-wrapper) {
    background: rgba(255, 255, 255, 0.05) !important;
    border: 1px solid rgba(255, 255, 255, 0.12) !important;
    border-radius: 10px !important;
    height: 44px !important;
    padding: 0 12px !important;
    transition: all 0.2s ease !important;

    &:hover {
      background: rgba(255, 255, 255, 0.07) !important;
      border-color: rgba(255, 255, 255, 0.25) !important;

      .input-icon {
        color: #cbd5e1;
      }
    }

    &:focus,
    &.ant-input-affix-wrapper-focused {
      background: rgba(255, 255, 255, 0.08) !important;
      border-color: #2152ff !important;
      box-shadow: 0 0 0 3px rgba(33, 82, 255, 0.25) !important;

      .input-icon {
        color: #2152ff;
      }
    }

    .ant-input {
      background: transparent !important;
      color: #ffffff !important;
      border: none !important;
      box-shadow: none !important;
      font-size: 13.5px !important;
      padding-left: 6px !important;

      &::placeholder {
        color: #64748b !important;
        opacity: 1 !important;
      }
    }

    .ant-input-password-icon {
      color: #64748b !important;
      font-size: 14px;
      transition: color 0.2s ease;

      &:hover {
        color: #ffffff !important;
      }
    }
  }

  :deep(.ant-form-item) {
    margin-bottom: 18px;
  }
}

.form-action-item {
  margin-top: 6px;
  margin-bottom: 0 !important;
}

.login-btn {
  height: 44px;
  font-size: 14.5px;
  font-weight: 600;
  border-radius: 10px !important;
  background: linear-gradient(135deg, #2152ff 0%, #1742e6 100%) !important;
  border: none !important;
  box-shadow: 0 4px 14px rgba(33, 82, 255, 0.4) !important;
  letter-spacing: 0.04em;

  &:hover {
    background: linear-gradient(135deg, #1b45db 0%, #1539bf 100%) !important;
    transform: translateY(-1px);
    box-shadow: 0 6px 18px rgba(33, 82, 255, 0.5) !important;
  }

  &:active {
    transform: translateY(0);
  }
}

.login-footer {
  margin-top: 22px;
  text-align: center;
  border-top: 1px solid rgba(255, 255, 255, 0.06);
  padding-top: 14px;
}

.footer-meta {
  font-size: 11.5px;
  color: #475569;
  letter-spacing: 0.02em;
}
</style>
