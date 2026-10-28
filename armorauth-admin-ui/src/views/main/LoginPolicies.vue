<template>
  <div class="page-container">
    <div class="page-header">
      <div>
        <h2>登录与 MFA 策略</h2>
        <div class="page-subtitle">配置各应用的认证安全基线、强制多因素认证 (MFA) 与角色策略准入规则</div>
      </div>
      <a-space>
        <a-button @click="fetchData">
          <template #icon><ReloadOutlined /></template>
          刷新
        </a-button>
      </a-space>
    </div>

    <div class="toolbar">
      <a-input-search
        v-model:value="searchKeyword"
        allow-clear
        placeholder="搜索应用名称或 Client ID..."
        style="max-width: 360px"
      />
    </div>

    <a-table
      :dataSource="filteredPolicies"
      :columns="columns"
      :loading="loading"
      :pagination="pagination"
      :scroll="{ x: 1240 }"
      row-key="id"
      size="middle"
      @change="handleTableChange">
      <template #bodyCell="{ column, record }">
        <template v-if="column.key === 'clientName'">
          <div class="app-name-cell">
            <div class="app-avatar-box">
              <span>{{ (record.clientName || 'A').charAt(0).toUpperCase() }}</span>
            </div>
            <div class="app-name-meta">
              <span class="app-main-name" :title="record.clientName">{{ record.clientName }}</span>
              <span class="app-sub-info">OAuth 2.1 / OIDC</span>
            </div>
          </div>
        </template>

        <template v-if="column.key === 'clientId'">
          <div class="client-id-cell">
            <code class="client-id-chip" :title="record.clientId">{{ formatClientId(record.clientId) }}</code>
            <a-tooltip title="复制完整 Client ID">
              <a-button type="text" size="small" class="copy-btn" @click.stop="copyToClipboard(record.clientId)">
                <template #icon><CopyOutlined /></template>
              </a-button>
            </a-tooltip>
          </div>
        </template>

        <template v-if="column.key === 'mfaRequired'">
          <div class="mfa-switch-cell">
            <a-switch
              :checked="record.mfaRequired"
              :loading="updatingId === record.id"
              @change="checked => toggleMfa(record, checked)" />
            <span class="mfa-switch-status" :class="record.mfaRequired ? 'status-active' : 'status-inactive'">
              {{ record.mfaRequired ? '全员开启' : '未开启' }}
            </span>
          </div>
        </template>

        <template v-if="column.key === 'roleMfaRequired'">
          <div class="role-tags-wrap">
            <a-tag v-for="role in (record.roleMfaRequired || []).slice(0, 2)" :key="role" color="orange" class="role-tag">
              {{ roleNameMap[role] || role }}
            </a-tag>
            <a-tooltip v-if="(record.roleMfaRequired || []).length > 2" :title="(record.roleMfaRequired || []).slice(2).map(r => roleNameMap[r] || r).join(', ')">
              <a-tag color="default" class="role-tag-more">+{{ (record.roleMfaRequired || []).length - 2 }}</a-tag>
            </a-tooltip>
            <span v-if="!record.roleMfaRequired?.length" class="text-muted">-</span>
          </div>
        </template>

        <template v-if="column.key === 'enforcement'">
          <div class="enforcement-tags-wrap">
            <a-tag v-if="record.mfaRequired" color="red">全员强制</a-tag>
            <a-tag v-if="record.roleMfaRequired?.length" color="gold">角色命中</a-tag>
            <span v-if="!record.mfaRequired && !record.roleMfaRequired?.length" class="text-muted">免二次验证</span>
          </div>
        </template>

        <template v-if="column.key === 'updatedAt'">
          <span class="time-cell">{{ formatTime(record.updatedAt) }}</span>
        </template>

        <template v-if="column.key === 'action'">
          <a-button type="primary" ghost size="small" @click="showPolicyEditor(record)">
            <template #icon><SettingOutlined /></template>
            配置策略
          </a-button>
        </template>
      </template>
    </a-table>

    <!-- Authing-Style Policy Configuration Modal -->
    <a-modal
      v-model:open="editorVisible"
      title="应用登录与 MFA 策略配置"
      width="640px"
      :confirmLoading="saving"
      :bodyStyle="{ maxHeight: 'calc(80vh - 120px)', overflowY: 'auto' }"
      okText="保存策略"
      cancelText="取消"
      @ok="savePolicy">
      <div class="policy-modal-body">
        <!-- Application Header Card -->
        <div class="modal-app-card">
          <div class="modal-app-avatar">
            <span>{{ (editingRecord?.clientName || 'A').charAt(0).toUpperCase() }}</span>
          </div>
          <div class="modal-app-info">
            <div class="modal-app-title">{{ editingRecord?.clientName }}</div>
            <div class="modal-app-id">
              <span class="label">Client ID:</span>
              <code>{{ editingRecord?.clientId }}</code>
              <a-tooltip title="复制 Client ID">
                <a-button type="text" size="small" class="copy-btn" @click="copyToClipboard(editingRecord?.clientId)">
                  <template #icon><CopyOutlined /></template>
                </a-button>
              </a-tooltip>
            </div>
          </div>
          <div class="modal-app-tag">
            <a-tag color="blue">OIDC Client</a-tag>
          </div>
        </div>

        <!-- Strategy Setting 1: Application-Wide MFA -->
        <div class="setting-item-box">
          <div class="setting-item-header">
            <div class="setting-item-meta">
              <div class="setting-title">应用全员强制二次验证 (MFA)</div>
              <div class="setting-desc">开启后，所有通过此应用完成账号密码登录的用户，均必须完成动态验证码 (TOTP / SMS / Passkey) 的二次验证。</div>
            </div>
            <div class="setting-item-toggle">
              <a-switch v-model:checked="editForm.mfaRequired" />
              <span class="toggle-hint-text" :class="editForm.mfaRequired ? 'text-primary' : 'text-muted'">
                {{ editForm.mfaRequired ? '已启用' : '已关闭' }}
              </span>
            </div>
          </div>
        </div>

        <!-- Strategy Setting 2: Role-Based MFA -->
        <div class="setting-item-box" :class="{ 'is-disabled-section': editForm.mfaRequired }">
          <div class="setting-item-meta">
            <div class="setting-title">指定角色强制二次验证</div>
            <div class="setting-desc">
              <template v-if="editForm.mfaRequired">
                <span class="text-info">已启用全员强制 MFA，当前应用下的所有角色登录均已受二次验证保护。</span>
              </template>
              <template v-else>
                当全员 MFA 未开启时，仅对命中以下特定高权限角色的用户强制触发二次验证。
              </template>
            </div>
          </div>
          <div class="setting-item-input" v-if="!editForm.mfaRequired">
            <a-select
              v-model:value="editForm.roleMfaRequired"
              mode="multiple"
              :options="roleSelectOptions"
              :max-tag-count="4"
              placeholder="选择需要强制二次验证的高权限角色..."
              style="width: 100%" />
          </div>
        </div>

        <!-- Authentication Flow Architecture Explanation -->
        <div class="policy-flow-guide">
          <div class="guide-header">
            <SafetyCertificateOutlined class="guide-icon" />
            <span>安全风控准入与流转机制</span>
          </div>
          <div class="guide-pipeline">
            <div class="pipe-step">
              <div class="step-num">1</div>
              <div class="step-label">密码 / 凭据验证</div>
            </div>
            <div class="pipe-arrow">➔</div>
            <div class="pipe-step">
              <div class="step-num">2</div>
              <div class="step-label">判定全员/角色策略</div>
            </div>
            <div class="pipe-arrow">➔</div>
            <div class="pipe-step">
              <div class="step-num">3</div>
              <div class="step-label">校验二次安全凭据</div>
            </div>
            <div class="pipe-arrow">➔</div>
            <div class="pipe-step">
              <div class="step-num">4</div>
              <div class="step-label">签发 OAuth 令牌</div>
            </div>
          </div>
          <div class="guide-footer-note">
            * 若目标用户尚未绑定二次凭据，系统将在第 3 步自动将用户重定向至安全激活流引导其完成凭据绑定。
          </div>
        </div>
      </div>
    </a-modal>
  </div>
</template>

<script setup>
import { computed, reactive, ref, onMounted } from 'vue'
import { message } from 'ant-design-vue'
import { ReloadOutlined, SettingOutlined, CopyOutlined, SafetyCertificateOutlined } from '@ant-design/icons-vue'
import dayjs from 'dayjs'
import { getLoginPolicies, updateLoginPolicy, getRoles } from '../../api'

const policies = ref([])
const roles = ref([])
const loading = ref(false)
const saving = ref(false)
const updatingId = ref('')
const editorVisible = ref(false)
const editingRecord = ref(null)
const searchKeyword = ref('')
const pagination = reactive({ current: 1, pageSize: 20, total: 0 })
const editForm = reactive({
  mfaRequired: false,
  roleMfaRequired: []
})

const columns = [
  { title: '应用名称', dataIndex: 'clientName', key: 'clientName', width: 220 },
  { title: 'Client ID', dataIndex: 'clientId', key: 'clientId', width: 200 },
  { title: '应用 MFA', key: 'mfaRequired', width: 140 },
  { title: '角色 MFA', key: 'roleMfaRequired', width: 220 },
  { title: '生效时机', key: 'enforcement', width: 160 },
  { title: '更新时间', key: 'updatedAt', width: 170 },
  { title: '操作', key: 'action', width: 120, fixed: 'right' }
]

const filteredPolicies = computed(() => {
  if (!searchKeyword.value) {
    return policies.value
  }
  const kw = searchKeyword.value.toLowerCase().trim()
  return policies.value.filter(p =>
    (p.clientName && p.clientName.toLowerCase().includes(kw)) ||
    (p.clientId && p.clientId.toLowerCase().includes(kw))
  )
})

const roleSelectOptions = computed(() => roles.value.map(role => ({
  value: role.roleCode,
  label: `${role.roleName || role.roleCode} (${role.roleCode})`
})))

const roleNameMap = computed(() => Object.fromEntries(
  roles.value.map(role => [role.roleCode, role.roleName || role.roleCode])
))

const formatClientId = (id) => {
  if (!id) return '-'
  if (id.length <= 16) return id
  return `${id.slice(0, 8)}...${id.slice(-6)}`
}

const copyToClipboard = async (text) => {
  if (!text) return
  try {
    await navigator.clipboard.writeText(text)
    message.success('已复制到剪贴板')
  } catch {
    message.info(text)
  }
}

const fetchRoles = async () => {
  try {
    const res = await getRoles()
    roles.value = Array.isArray(res.data) ? res.data : []
  } catch (e) {
    message.error('角色加载失败: ' + e.message)
  }
}

const fetchData = async () => {
  loading.value = true
  try {
    const res = await getLoginPolicies(pagination.current - 1, pagination.pageSize)
    policies.value = (res.data?.content || []).map(policy => ({
      ...policy,
      roleMfaRequired: policy.roleMfaRequired || []
    }))
    pagination.total = res.data?.totalElements || 0
  } catch (e) {
    message.error('加载失败: ' + e.message)
  } finally {
    loading.value = false
  }
}

const handleTableChange = (pag) => {
  pagination.current = pag.current
  pagination.pageSize = pag.pageSize
  fetchData()
}

const toggleMfa = async (record, checked) => {
  updatingId.value = record.id
  try {
    const res = await updateLoginPolicy(record.id, { mfaRequired: checked })
    Object.assign(record, {
      ...(res.data || {}),
      mfaRequired: res.data?.mfaRequired ?? checked,
      roleMfaRequired: res.data?.roleMfaRequired || record.roleMfaRequired || []
    })
    message.success(checked ? '已开启应用全员 MFA' : '已关闭应用全员 MFA')
  } catch (e) {
    message.error(e.message)
  } finally {
    updatingId.value = ''
  }
}

const showPolicyEditor = (record) => {
  editingRecord.value = record
  editForm.mfaRequired = !!record.mfaRequired
  editForm.roleMfaRequired = [...(record.roleMfaRequired || [])]
  editorVisible.value = true
}

const savePolicy = async () => {
  if (!editingRecord.value) {
    return
  }
  saving.value = true
  try {
    const res = await updateLoginPolicy(editingRecord.value.id, {
      mfaRequired: editForm.mfaRequired,
      roleMfaRequired: editForm.roleMfaRequired
    })
    Object.assign(editingRecord.value, {
      ...(res.data || {}),
      mfaRequired: editForm.mfaRequired,
      roleMfaRequired: res.data?.roleMfaRequired || editForm.roleMfaRequired || []
    })
    editorVisible.value = false
    message.success('登录与 MFA 策略已成功保存')
  } catch (e) {
    message.error(e.message)
  } finally {
    saving.value = false
  }
}

const formatTime = value => value ? dayjs(value).format('YYYY-MM-DD HH:mm:ss') : '-'

onMounted(() => {
  fetchRoles()
  fetchData()
})
</script>

<style scoped>
/* ── Table Cell Styles ── */
.app-name-cell {
  display: flex;
  align-items: center;
  gap: 12px;
}

.app-avatar-box {
  width: 34px;
  height: 34px;
  border-radius: 8px;
  background: linear-gradient(135deg, #eff4ff 0%, #dbeafe 100%);
  color: var(--aa-primary);
  font-weight: 700;
  font-size: 14px;
  display: flex;
  align-items: center;
  justify-content: center;
  flex-shrink: 0;
  border: 1px solid #bfdbfe;
}

.app-name-meta {
  display: flex;
  flex-direction: column;
  min-width: 0;
}

.app-main-name {
  font-weight: 600;
  color: var(--aa-text-primary);
  font-size: 13.5px;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}

.app-sub-info {
  font-size: 11.5px;
  color: var(--aa-text-muted);
}

.client-id-cell {
  display: flex;
  align-items: center;
  gap: 4px;
}

.client-id-chip {
  font-family: var(--aa-font-mono);
  font-size: 12px;
  background: #f1f5f9;
  color: #334155;
  padding: 2px 7px;
  border-radius: 4px;
  border: 1px solid #e2e8f0;
}

.copy-btn {
  color: var(--aa-text-muted);
  padding: 0 4px;
  height: 24px;

  &:hover {
    color: var(--aa-primary);
  }
}

.mfa-switch-cell {
  display: flex;
  align-items: center;
  gap: 8px;
}

.mfa-switch-status {
  font-size: 12.5px;
  font-weight: 500;

  &.status-active {
    color: var(--aa-primary);
  }

  &.status-inactive {
    color: var(--aa-text-muted);
  }
}

.role-tags-wrap {
  display: flex;
  flex-wrap: wrap;
  gap: 4px;
  align-items: center;
}

.role-tag {
  margin: 0;
  font-size: 12px;
}

.role-tag-more {
  margin: 0;
  cursor: pointer;
}

.enforcement-tags-wrap {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
  align-items: center;

  .ant-tag {
    margin: 0;
  }
}

.time-cell {
  color: var(--aa-text-secondary);
  font-size: 12.5px;
}

.text-muted {
  color: var(--aa-text-muted);
  font-size: 12px;
}

/* ── Modal Settings Styles ── */
.policy-modal-body {
  display: flex;
  flex-direction: column;
  gap: 18px;
  padding-top: 6px;
}

.modal-app-card {
  display: flex;
  align-items: center;
  gap: 14px;
  background: #f8fafc;
  border: 1px solid var(--aa-border);
  border-radius: var(--aa-radius);
  padding: 14px 16px;
}

.modal-app-avatar {
  width: 40px;
  height: 40px;
  border-radius: 10px;
  background: linear-gradient(135deg, #2152ff 0%, #4338ca 100%);
  color: #ffffff;
  font-weight: 700;
  font-size: 16px;
  display: flex;
  align-items: center;
  justify-content: center;
  flex-shrink: 0;
  box-shadow: 0 2px 6px rgba(33, 82, 255, 0.3);
}

.modal-app-info {
  flex: 1;
  min-width: 0;
}

.modal-app-title {
  font-size: 15px;
  font-weight: 700;
  color: var(--aa-text-primary);
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}

.modal-app-id {
  display: flex;
  align-items: center;
  gap: 6px;
  font-size: 12px;
  margin-top: 2px;

  .label {
    color: var(--aa-text-muted);
  }

  :is(code) {
    font-family: var(--aa-font-mono);
    color: var(--aa-text-secondary);
    background: #e2e8f0;
    padding: 1px 6px;
    border-radius: 4px;
  }
}

.setting-item-box {
  border: 1px solid var(--aa-border);
  border-radius: var(--aa-radius);
  padding: 16px;
  background: #ffffff;
  transition: all 0.2s ease;

  &.is-disabled-section {
    background: #f8fafc;
    border-color: #f1f5f9;
  }
}

.setting-item-header {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  gap: 16px;
}

.setting-item-meta {
  flex: 1;
}

.setting-title {
  font-size: 14px;
  font-weight: 600;
  color: var(--aa-text-primary);
  margin-bottom: 4px;
}

.setting-desc {
  font-size: 12.5px;
  color: var(--aa-text-secondary);
  line-height: 1.5;
}

.setting-item-toggle {
  display: flex;
  align-items: center;
  gap: 10px;
  flex-shrink: 0;
}

.toggle-hint-text {
  font-size: 12.5px;
  font-weight: 500;

  &.text-primary {
    color: var(--aa-primary);
  }

  &.text-muted {
    color: var(--aa-text-muted);
  }
}

.setting-item-input {
  margin-top: 14px;
}

.text-info {
  color: var(--aa-primary);
  font-weight: 500;
}

/* ── Safety Flow Guide ── */
.policy-flow-guide {
  background: #f8faff;
  border: 1px solid #dbeafe;
  border-radius: var(--aa-radius);
  padding: 14px 16px;
}

.guide-header {
  display: flex;
  align-items: center;
  gap: 8px;
  font-weight: 600;
  font-size: 13px;
  color: var(--aa-primary);
  margin-bottom: 12px;

  .guide-icon {
    font-size: 15px;
  }
}

.guide-pipeline {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 6px;
  margin-bottom: 10px;
}

.pipe-step {
  display: flex;
  flex-direction: column;
  align-items: center;
  text-align: center;
  gap: 6px;
  flex: 1;
}

.step-num {
  width: 22px;
  height: 22px;
  border-radius: 50%;
  background: var(--aa-primary);
  color: #ffffff;
  font-size: 11px;
  font-weight: 700;
  display: flex;
  align-items: center;
  justify-content: center;
}

.step-label {
  font-size: 11px;
  font-weight: 500;
  color: var(--aa-text-secondary);
  line-height: 1.3;
}

.pipe-arrow {
  color: #93c5fd;
  font-size: 12px;
  font-weight: bold;
}

.guide-footer-note {
  font-size: 11.5px;
  color: var(--aa-text-muted);
  line-height: 1.4;
  border-top: 1px dashed #bfdbfe;
  padding-top: 8px;
}
</style>
