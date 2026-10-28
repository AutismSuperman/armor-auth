<template>
  <div class="page-container">
    <div class="page-header">
      <div>
        <h2>身份源连接</h2>
        <div class="page-subtitle">连接社交登录与企业身份提供商，支持零代码配置与标准协议即插即用</div>
      </div>
      <div class="page-actions">
        <a-segmented
          v-model:value="activeSection"
          :options="[
            { label: '已配置连接 (' + providers.length + ')', value: 'connections' },
            { label: '连接器市场 (8)', value: 'catalog' }
          ]"
        />
        <a-radio-group v-if="activeSection === 'connections'" v-model:value="viewMode" button-style="solid">
          <a-radio-button value="card">
            <AppstoreOutlined /> 卡片
          </a-radio-button>
          <a-radio-button value="table">
            <BarsOutlined /> 表格
          </a-radio-button>
        </a-radio-group>
        <a-select
          v-if="activeSection === 'connections'"
          v-model:value="sourceFilter"
          :options="sourceOptions"
          class="source-filter"
          style="width: 150px"
          @change="handleSourceFilterChange" />
        <a-button type="primary" @click="showCreate">
          <template #icon><PlusOutlined /></template>
          添加自定义身份源
        </a-button>
      </div>
    </div>

    <!-- Section 1: Configured Connections -->
    <div v-if="activeSection === 'connections'">
      <!-- Card View -->
      <div v-if="viewMode === 'card'" class="idp-card-grid-container">
        <a-spin :spinning="loading">
          <div v-if="providers.length" class="idp-card-grid">
            <div v-for="record in providers" :key="record.id" class="idp-entity-card">
              <div class="idp-card-top">
                <div class="idp-avatar-box">
                  <img v-if="record.iconUrl" :src="record.iconUrl" alt="" class="idp-avatar-img" />
                  <component v-else :is="iconMeta(record.iconKey, record.providerType).icon" class="idp-avatar-icon" />
                </div>
                <div class="idp-card-main-info">
                  <div class="idp-title-line">
                    <h4 class="idp-card-title">{{ record.providerName }}</h4>
                    <a-tag :color="providerMeta(record.providerType).color">
                      {{ providerMeta(record.providerType).label }}
                    </a-tag>
                  </div>
                  <div class="idp-sub-id">
                    <span class="reg-label">ID:</span>
                    <code class="reg-code" :title="record.registrationId">{{ record.registrationId }}</code>
                    <a-tooltip title="复制 ID">
                      <a-button type="text" size="small" class="copy-icon-btn" @click.stop="copyToClipboard(record.registrationId)">
                        <CopyOutlined />
                      </a-button>
                    </a-tooltip>
                  </div>
                </div>
              </div>

              <div class="idp-card-meta">
                <div class="idp-meta-item">
                  <span class="meta-label">来源:</span>
                  <a-tag :color="sourceColor(record)">{{ sourceLabel(record) }}</a-tag>
                </div>
                <div class="idp-meta-item">
                  <span class="meta-label">策略:</span>
                  <a-tag color="geekblue">{{ record.linkingStrategy || 'AUTO_REGISTER' }}</a-tag>
                </div>
                <div v-if="record.providerType !== 'LDAP'" class="idp-meta-item">
                  <span class="meta-label">登录页:</span>
                  <a-switch
                    :checked="record.displayOnLogin !== false"
                    :loading="record.displayUpdating"
                    size="small"
                    @change="val => toggleLoginDisplay(record, val)"
                  />
                  <span class="status-pill-text" :class="record.displayOnLogin !== false ? 'is-enabled' : 'is-disabled'">
                    {{ record.displayOnLogin !== false ? '显示' : '隐藏' }}
                  </span>
                </div>
              </div>

              <div class="idp-card-footer">
                <div class="status-toggle-wrap">
                  <span class="status-label">状态:</span>
                  <a-tag v-if="isConfigProvider(record)" color="green">配置生效</a-tag>
                  <template v-else>
                    <a-switch
                      :checked="record.enabled"
                      size="small"
                      @change="val => toggleStatus(record, val)"
                    />
                    <span class="status-pill-text" :class="record.enabled ? 'is-enabled' : 'is-disabled'">
                      {{ record.enabled ? '已启用' : '已禁用' }}
                    </span>
                  </template>
                </div>
                <div class="idp-actions-wrap">
                  <a-button type="text" size="small" @click="handleTest(record, false)">
                    测试
                  </a-button>
                  <a-button type="text" size="small" @click="showConfig(record)">
                    配置
                  </a-button>
                  <a-button v-if="!isConfigProvider(record)" type="text" size="small" @click="showEdit(record)">
                    编辑
                  </a-button>
                  <a-dropdown :trigger="['click']">
                    <a-button type="text" size="small">更多</a-button>
                    <template #overlay>
                      <a-menu>
                        <a-menu-item key="probe" @click="handleTest(record, true)">
                          远程探测
                        </a-menu-item>
                        <template v-if="record.providerType === 'LDAP'">
                          <a-menu-item key="sync-dry" @click="handleLdapSync(record, true)">
                            同步预演
                          </a-menu-item>
                          <a-menu-item key="sync-exec" @click="handleLdapSync(record, false)">
                            立即同步
                          </a-menu-item>
                        </template>
                        <template v-if="!isConfigProvider(record)">
                          <a-menu-divider />
                          <a-menu-item key="delete" danger>
                            <a-popconfirm title="确认删除此身份源？" @confirm="handleDelete(record.id)">
                              <span style="color: #ff4d4f">删除身份源</span>
                            </a-popconfirm>
                          </a-menu-item>
                        </template>
                      </a-menu>
                    </template>
                  </a-dropdown>
                </div>
              </div>
            </div>
          </div>
          <div v-else-if="!loading" class="idp-empty-wrap">
            <a-empty description="暂未配置任何身份源，您可以从上方市场挑选常用连接器或自定义创建" />
            <a-button type="primary" style="margin-top: 16px" @click="activeSection = 'catalog'">
              浏览连接器市场
            </a-button>
          </div>
        </a-spin>
      </div>

      <!-- Table View -->
      <a-table
        v-else
        :dataSource="providers"
        :columns="columns"
        :loading="loading"
        :pagination="pagination"
        :scroll="{ x: 1400 }"
        @change="handleTableChange"
        row-key="id"
        size="middle">
        <template #bodyCell="{ column, record }">
          <template v-if="column.key === 'type'">
            <a-tag :color="providerMeta(record.providerType).color" class="provider-tag">
              <component :is="providerMeta(record.providerType).icon" />
              {{ providerMeta(record.providerType).label }}
            </a-tag>
          </template>
          <template v-if="column.key === 'source'">
            <a-tag :color="sourceColor(record)">
              {{ sourceLabel(record) }}
            </a-tag>
          </template>
          <template v-if="column.key === 'displayOnLogin'">
            <a-tag v-if="record.providerType === 'LDAP'">不适用</a-tag>
            <div v-else class="table-switch-wrap">
              <a-switch :checked="record.displayOnLogin !== false"
                        :loading="record.displayUpdating"
                        size="small"
                        @change="val => toggleLoginDisplay(record, val)" />
              <span class="status-pill-text" :class="record.displayOnLogin !== false ? 'is-enabled' : 'is-disabled'">
                {{ record.displayOnLogin !== false ? '显示' : '隐藏' }}
              </span>
            </div>
          </template>
          <template v-if="column.key === 'status'">
            <a-tag v-if="isConfigProvider(record)" color="green">配置生效</a-tag>
            <div v-else class="table-switch-wrap">
              <a-switch :checked="record.enabled" size="small" @change="val => toggleStatus(record, val)" />
              <span class="status-pill-text" :class="record.enabled ? 'is-enabled' : 'is-disabled'">
                {{ record.enabled ? '已启用' : '已禁用' }}
              </span>
            </div>
          </template>
          <template v-if="column.key === 'action'">
            <a-space size="small" v-if="!isConfigProvider(record)">
              <a @click="showConfig(record)">查看配置</a>
              <a @click="showEdit(record)">编辑</a>
              <a @click="handleTest(record, false)">测试</a>
              <a-dropdown :trigger="['click']">
                <a class="ant-dropdown-link" @click.prevent>
                  更多 <DownOutlined />
                </a>
                <template #overlay>
                  <a-menu>
                    <a-menu-item key="probe">
                      <a-popconfirm title="远程探测会访问外部 URL，确认执行？" @confirm="handleTest(record, true)">
                        <span>远程探测</span>
                      </a-popconfirm>
                    </a-menu-item>
                    <template v-if="record.providerType === 'LDAP'">
                      <a-menu-item key="sync-dry" @click="handleLdapSync(record, true)">
                        同步预演
                      </a-menu-item>
                      <a-menu-item key="sync-exec">
                        <a-popconfirm title="确认同步 LDAP 用户？" @confirm="handleLdapSync(record, false)">
                          <span>立即同步</span>
                        </a-popconfirm>
                      </a-menu-item>
                    </template>
                    <a-menu-divider />
                    <a-menu-item key="delete" danger>
                      <a-popconfirm title="确认删除此身份源？" @confirm="handleDelete(record.id)">
                        <span style="color: #ff4d4f">删除身份源</span>
                      </a-popconfirm>
                    </a-menu-item>
                  </a-menu>
                </template>
              </a-dropdown>
            </a-space>
            <a-space v-else>
              <a @click="showConfig(record)">查看配置</a>
              <a-typography-text type="secondary">配置文件只读</a-typography-text>
            </a-space>
          </template>
        </template>
      </a-table>
    </div>

    <!-- Section 2: Catalog Market (Authing Style IdP Marketplace) -->
    <div v-else class="idp-catalog-section">
      <div class="catalog-filters">
        <a-radio-group v-model:value="catalogCategoryFilter" button-style="solid">
          <a-radio-button value="all">全部连接器 (8)</a-radio-button>
          <a-radio-button value="social">社交与个人登录 (5)</a-radio-button>
          <a-radio-button value="enterprise">企业级身份源 SSO (3)</a-radio-button>
        </a-radio-group>
        <span class="catalog-count-tip">点击任意连接器卡片一键配置预填</span>
      </div>

      <div class="idp-catalog-grid">
        <div
          v-for="item in filteredCatalog"
          :key="item.key"
          class="catalog-card"
          @click="handleConnectFromCatalog(item)">
          <div class="catalog-card-header">
            <div class="catalog-icon-wrapper" :style="{ color: item.color }">
              <component :is="iconMeta(item.iconKey, item.type).icon" />
            </div>
            <div class="catalog-title-box">
              <h4 class="catalog-title">{{ item.name }}</h4>
              <a-tag :color="item.category === 'social' ? 'blue' : 'purple'">
                {{ item.type }}
              </a-tag>
            </div>
          </div>
          <p class="catalog-desc">{{ item.desc }}</p>
          <div class="catalog-card-footer">
            <span class="catalog-category-tag">{{ item.category === 'social' ? '社交身份' : '企业目录/SSO' }}</span>
            <a-button type="primary" size="small" ghost>
              + 连接
            </a-button>
          </div>
        </div>
      </div>
    </div>

    <a-modal v-model:open="modalVisible" :title="isEdit ? '编辑身份源' : '添加身份源'"
             @ok="handleSubmit" :confirmLoading="submitting" width="780px"
             :bodyStyle="{ maxHeight: 'calc(80vh - 120px)', overflowY: 'auto', paddingRight: '12px' }">
      <a-form :model="form" layout="vertical">
        <a-form-item label="提供商类型" required>
          <div class="provider-type-grid" :class="{ disabled: isEdit }">
            <button
              v-for="type in providerTypeOptions"
              :key="type.value"
              type="button"
              class="provider-type-option"
              :class="{ active: form.providerType === type.value }"
              :disabled="isEdit"
              @click="selectProviderType(type.value)">
              <component :is="type.icon" class="provider-type-icon" />
              <span>{{ type.label }}</span>
              <small>{{ type.description }}</small>
            </button>
          </div>
        </a-form-item>
        <a-row :gutter="16">
          <a-col :span="12">
            <a-form-item label="提供商名称" required>
              <a-input v-model:value="form.providerName" placeholder="如 企业SSO" />
            </a-form-item>
          </a-col>
          <a-col :span="12">
            <a-form-item label="Registration ID" required>
              <a-input v-model:value="form.registrationId" :disabled="isEdit" placeholder="唯一标识，如 enterprise-oidc" />
            </a-form-item>
          </a-col>
        </a-row>
        <a-row v-if="form.providerType !== 'LDAP'" :gutter="16">
          <a-col :span="12">
            <a-form-item label="登录页展示" class="idp-display-form-item">
              <div class="idp-display-control">
                <a-switch v-model:checked="form.displayOnLogin" />
                <span class="status-pill-text" :class="form.displayOnLogin !== false ? 'is-enabled' : 'is-disabled'">
                  {{ form.displayOnLogin !== false ? '显示' : '隐藏' }}
                </span>
                <span class="hint-text">关闭后不会出现在 server 登录页，已配置的授权入口仍保留。</span>
              </div>
            </a-form-item>
          </a-col>
          <a-col :span="12">
            <a-form-item label="显示顺序">
              <a-input-number v-model:value="form.displayOrder" :min="0" style="width: 100%" />
            </a-form-item>
          </a-col>
        </a-row>
        <template v-if="form.providerType === 'SAML'">
          <a-row :gutter="16">
            <a-col :span="12">
              <a-form-item label="IdP Entity ID">
                <a-input v-model:value="form.samlEntityId" placeholder="https://idp.example.com/entity-id" />
              </a-form-item>
            </a-col>
            <a-col :span="12">
              <a-form-item label="Metadata URL">
                <a-input v-model:value="form.samlMetadataUrl" placeholder="https://idp.example.com/metadata" />
              </a-form-item>
            </a-col>
          </a-row>
          <a-row :gutter="16">
            <a-col :span="12">
              <a-form-item label="SSO URL">
                <a-input v-model:value="form.samlSsoUrl" placeholder="https://idp.example.com/sso" />
              </a-form-item>
            </a-col>
            <a-col :span="12">
              <a-form-item label="SLO URL">
                <a-input v-model:value="form.samlSloUrl" placeholder="https://idp.example.com/logout" />
              </a-form-item>
            </a-col>
          </a-row>
          <a-form-item label="X.509 Certificate">
            <a-textarea v-model:value="form.samlX509Certificate" :rows="4" placeholder="-----BEGIN CERTIFICATE-----" />
          </a-form-item>
          <a-row :gutter="16">
            <a-col :span="12">
              <a-form-item label="SP Entity ID">
                <a-input v-model:value="form.samlSpEntityId" placeholder="https://auth.example.com/saml/sp" />
              </a-form-item>
            </a-col>
            <a-col :span="12">
              <a-form-item label="ACS URL">
                <a-input v-model:value="form.samlAcsUrl" placeholder="https://auth.example.com/login/saml2/sso/{registrationId}" />
              </a-form-item>
            </a-col>
          </a-row>
          <a-form-item label="NameID Format">
            <a-input v-model:value="form.samlNameIdFormat" placeholder="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress" />
          </a-form-item>
        </template>
        <template v-else-if="form.providerType === 'LDAP'">
          <a-row :gutter="16">
            <a-col :span="12">
              <a-form-item label="LDAP URL" required>
                <a-input v-model:value="form.ldapUrl" placeholder="ldap://ad.example.com:389" />
              </a-form-item>
            </a-col>
            <a-col :span="12">
              <a-form-item label="Base DN" required>
                <a-input v-model:value="form.ldapBaseDn" placeholder="dc=example,dc=com" />
              </a-form-item>
            </a-col>
          </a-row>
          <a-row :gutter="16">
            <a-col :span="12">
              <a-form-item label="Bind DN">
                <a-input v-model:value="form.ldapBindDn" placeholder="cn=reader,dc=example,dc=com" />
              </a-form-item>
            </a-col>
            <a-col :span="12">
              <a-form-item label="Bind Password">
                <a-input-password v-model:value="form.ldapBindPassword" />
              </a-form-item>
            </a-col>
          </a-row>
          <a-row :gutter="16">
            <a-col :span="12">
              <a-form-item label="User Search Base">
                <a-input v-model:value="form.ldapUserSearchBase" placeholder="ou=users" />
              </a-form-item>
            </a-col>
            <a-col :span="12">
              <a-form-item label="User Search Filter">
                <a-input v-model:value="form.ldapUserSearchFilter" placeholder="(objectClass=person)" />
              </a-form-item>
            </a-col>
          </a-row>
          <a-row :gutter="16">
            <a-col :span="12">
              <a-form-item label="Username Attribute">
                <a-input v-model:value="form.ldapUsernameAttribute" placeholder="uid / sAMAccountName" />
              </a-form-item>
            </a-col>
            <a-col :span="12">
              <a-form-item label="Email Attribute">
                <a-input v-model:value="form.ldapEmailAttribute" placeholder="mail" />
              </a-form-item>
            </a-col>
          </a-row>
          <a-row :gutter="16">
            <a-col :span="12">
              <a-form-item label="Phone Attribute">
                <a-input v-model:value="form.ldapPhoneAttribute" placeholder="telephoneNumber" />
              </a-form-item>
            </a-col>
            <a-col :span="12">
              <a-form-item label="Display Name Attribute">
                <a-input v-model:value="form.ldapDisplayNameAttribute" placeholder="displayName" />
              </a-form-item>
            </a-col>
          </a-row>
          <a-row :gutter="16">
            <a-col :span="12">
              <a-form-item label="Group Attribute">
                <a-input v-model:value="form.ldapGroupAttribute" placeholder="memberOf" />
              </a-form-item>
            </a-col>
            <a-col :span="12">
              <a-form-item label="Page Size">
                <a-input-number v-model:value="form.ldapPageSize" :min="1" :max="1000" style="width: 100%" />
              </a-form-item>
            </a-col>
          </a-row>
          <a-space>
            <a-checkbox v-model:checked="form.ldapUseSsl">LDAPS</a-checkbox>
            <a-checkbox v-model:checked="form.ldapStartTls">StartTLS</a-checkbox>
          </a-space>
        </template>
        <template v-else>
          <a-row :gutter="16">
            <a-col :span="12">
              <a-form-item label="Client ID" required>
                <a-input v-model:value="form.clientId" />
              </a-form-item>
            </a-col>
            <a-col :span="12">
              <a-form-item label="Client Secret">
                <a-input-password v-model:value="form.clientSecret" />
              </a-form-item>
            </a-col>
          </a-row>
          <a-row :gutter="16">
            <a-col :span="12">
              <a-form-item label="Authorization URI">
                <a-input v-model:value="form.authorizationUri" placeholder="https://..." />
              </a-form-item>
            </a-col>
            <a-col :span="12">
              <a-form-item label="Token URI">
                <a-input v-model:value="form.tokenUri" placeholder="https://..." />
              </a-form-item>
            </a-col>
          </a-row>
          <a-row :gutter="16">
            <a-col :span="12">
              <a-form-item label="UserInfo URI">
                <a-input v-model:value="form.userinfoUri" placeholder="https://..." />
              </a-form-item>
            </a-col>
            <a-col :span="12">
              <a-form-item label="JWK Set URI">
                <a-input v-model:value="form.jwkSetUri" placeholder="https://.../jwks" />
              </a-form-item>
            </a-col>
          </a-row>
          <a-form-item label="Scopes">
            <a-input v-model:value="form.scopes" placeholder="逗号分隔，如 openid,profile,email" />
          </a-form-item>
        </template>
        <a-row :gutter="16">
          <a-col :span="12">
            <a-form-item label="链接策略">
              <a-select v-model:value="form.linkingStrategy" placeholder="选择策略">
                <a-select-option value="AUTO_REGISTER">自动注册</a-select-option>
                <a-select-option value="CONFIRM">确认页</a-select-option>
                <a-select-option value="EMAIL_MATCH">邮箱匹配</a-select-option>
                <a-select-option value="NONE">禁止自动注册</a-select-option>
              </a-select>
            </a-form-item>
          </a-col>
        </a-row>
        <a-form-item label="属性映射 JSON">
          <a-textarea v-model:value="form.attributeMapping" :rows="3"
                      placeholder='{"email":"email","displayName":"name"}' />
        </a-form-item>
        <a-collapse
          v-if="form.providerType !== 'LDAP'"
          v-model:activeKey="iconPanelActiveKeys"
          ghost
          class="idp-icon-collapse">
          <a-collapse-panel key="login-icon" header="登录页图标">
            <div class="idp-icon-summary">
              <div class="idp-icon-current">
                <span v-if="form.iconUrl" class="provider-uploaded-tag">
                  <img :src="form.iconUrl" alt="" />
                  自定义上传
                </span>
                <a-tag v-else :color="iconMeta(form.iconKey, form.providerType).color" class="provider-tag">
                  <component :is="iconMeta(form.iconKey, form.providerType).icon" />
                  {{ iconMeta(form.iconKey, form.providerType).label }}
                </a-tag>
                <span>{{ iconMode === 'auto' ? '自动' : '自定义' }}</span>
              </div>
              <a-segmented
                v-model:value="iconMode"
                :options="iconModeOptions"
                @change="handleIconModeChange" />
            </div>
            <div v-if="iconMode === 'library'" class="idp-icon-grid">
              <button
                v-for="option in iconOptions"
                :key="option.value"
                type="button"
                class="idp-icon-option"
                :class="{ active: form.iconKey === option.value && !form.iconUrl }"
                @click="selectIcon(option.value)">
                <component :is="option.icon" />
                <span>{{ option.label }}</span>
              </button>
            </div>
            <div v-else-if="iconMode === 'upload'" class="idp-icon-upload-panel">
              <a-upload
                :show-upload-list="false"
                :before-upload="beforeIconUpload"
                accept="image/svg+xml,image/png,image/jpeg,image/webp">
                <a-button>
                  <template #icon><UploadOutlined /></template>
                  上传图标
                </a-button>
              </a-upload>
              <div v-if="form.iconUrl" class="idp-icon-upload-preview">
                <img :src="form.iconUrl" alt="" />
                <a-button type="link" size="small" @click="clearUploadedIcon">移除</a-button>
              </div>
              <a-typography-text type="secondary">支持 SVG、PNG、JPG、WebP，建议 200KB 内。</a-typography-text>
            </div>
          </a-collapse-panel>
        </a-collapse>
      </a-form>
    </a-modal>

    <a-modal v-model:open="configVisible" title="查看身份源配置" :footer="null" width="840px"
             :bodyStyle="{ maxHeight: 'calc(80vh - 120px)', overflowY: 'auto' }">
      <template v-if="configRecord">
        <div class="config-view-header">
          <div>
            <div class="config-view-title">{{ configRecord.providerName }}</div>
            <div class="config-view-subtitle">{{ configRecord.registrationId }}</div>
          </div>
          <a-space>
            <a-tag :color="sourceColor(configRecord)">{{ sourceLabel(configRecord) }}</a-tag>
            <a-tag :color="configRecord.readOnly ? 'orange' : 'green'">
              {{ configRecord.readOnly ? '只读' : '可编辑' }}
            </a-tag>
          </a-space>
        </div>

        <a-descriptions bordered size="small" :column="2" class="config-descriptions">
          <a-descriptions-item label="提供商类型">
            <a-tag :color="providerMeta(configRecord.providerType).color" class="provider-tag">
              <component :is="providerMeta(configRecord.providerType).icon" />
              {{ providerMeta(configRecord.providerType).label }}
            </a-tag>
          </a-descriptions-item>
          <a-descriptions-item label="登录页入口">
            <span v-if="configRecord.providerType === 'LDAP'">不适用</span>
            <span v-else class="idp-login-entry-cell">
              <a-tag :color="configRecord.displayOnLogin !== false ? 'green' : 'default'">
                {{ configRecord.displayOnLogin !== false ? '显示' : '隐藏' }}
              </a-tag>
              <span v-if="configRecord.iconUrl" class="provider-uploaded-tag">
                <img :src="configRecord.iconUrl" alt="" />
                自定义上传
              </span>
              <a-tag v-else :color="iconMeta(configRecord.iconKey, configRecord.providerType).color" class="provider-tag">
                <component :is="iconMeta(configRecord.iconKey, configRecord.providerType).icon" />
                {{ iconMeta(configRecord.iconKey, configRecord.providerType).label }}
              </a-tag>
            </span>
          </a-descriptions-item>
          <a-descriptions-item label="Client ID">
            <span class="config-value">{{ displayText(configRecord.clientId) }}</span>
          </a-descriptions-item>
          <a-descriptions-item label="状态">
            {{ isConfigProvider(configRecord) ? '配置生效' : (configRecord.enabled ? '启用' : '禁用') }}
          </a-descriptions-item>
          <a-descriptions-item label="链接策略">{{ displayText(configRecord.linkingStrategy) }}</a-descriptions-item>
          <a-descriptions-item label="顺序">{{ displayText(configRecord.displayOrder) }}</a-descriptions-item>
          <a-descriptions-item label="更新时间">{{ displayText(configRecord.updatedAt) }}</a-descriptions-item>
        </a-descriptions>

        <template v-if="configRecord.providerType !== 'SAML' && configRecord.providerType !== 'LDAP'">
          <a-divider orientation="left">OAuth / OIDC</a-divider>
          <a-descriptions bordered size="small" :column="1" class="config-descriptions">
            <a-descriptions-item label="回调地址">
              <span class="config-value">{{ displayText(configRecord.redirectUri) }}</span>
            </a-descriptions-item>
            <a-descriptions-item label="授权类型">
              <span class="config-value">{{ displayText(configRecord.authorizationGrantType) }}</span>
            </a-descriptions-item>
            <a-descriptions-item label="客户端认证">
              <span class="config-value">{{ displayText(configRecord.clientAuthenticationMethod) }}</span>
            </a-descriptions-item>
            <a-descriptions-item label="用户 ID 映射">
              <span class="config-value">{{ displayText(configRecord.userNameAttributeName) }}</span>
            </a-descriptions-item>
            <a-descriptions-item label="Authorization URI">
              <span class="config-value">{{ displayText(configRecord.authorizationUri) }}</span>
            </a-descriptions-item>
            <a-descriptions-item label="Token URI">
              <span class="config-value">{{ displayText(configRecord.tokenUri) }}</span>
            </a-descriptions-item>
            <a-descriptions-item label="UserInfo URI">
              <span class="config-value">{{ displayText(configRecord.userinfoUri) }}</span>
            </a-descriptions-item>
            <a-descriptions-item label="JWK Set URI">
              <span class="config-value">{{ displayText(configRecord.jwkSetUri) }}</span>
            </a-descriptions-item>
            <a-descriptions-item label="Scopes">
              <span class="config-value">{{ displayText(configRecord.scopes) }}</span>
            </a-descriptions-item>
          </a-descriptions>
        </template>

        <template v-if="configRecord.providerType === 'SAML'">
          <a-divider orientation="left">SAML</a-divider>
          <a-descriptions bordered size="small" :column="1" class="config-descriptions">
            <a-descriptions-item label="IdP Entity ID">
              <span class="config-value">{{ displayText(configRecord.samlEntityId) }}</span>
            </a-descriptions-item>
            <a-descriptions-item label="Metadata URL">
              <span class="config-value">{{ displayText(configRecord.samlMetadataUrl) }}</span>
            </a-descriptions-item>
            <a-descriptions-item label="SSO URL">
              <span class="config-value">{{ displayText(configRecord.samlSsoUrl) }}</span>
            </a-descriptions-item>
            <a-descriptions-item label="SLO URL">
              <span class="config-value">{{ displayText(configRecord.samlSloUrl) }}</span>
            </a-descriptions-item>
            <a-descriptions-item label="SP Entity ID">
              <span class="config-value">{{ displayText(configRecord.samlSpEntityId) }}</span>
            </a-descriptions-item>
            <a-descriptions-item label="ACS URL">
              <span class="config-value">{{ displayText(configRecord.samlAcsUrl) }}</span>
            </a-descriptions-item>
            <a-descriptions-item label="NameID Format">
              <span class="config-value">{{ displayText(configRecord.samlNameIdFormat) }}</span>
            </a-descriptions-item>
            <a-descriptions-item label="X.509 Certificate">
              <pre class="config-pre">{{ displayText(configRecord.samlX509Certificate) }}</pre>
            </a-descriptions-item>
          </a-descriptions>
        </template>

        <template v-if="configRecord.providerType === 'LDAP'">
          <a-divider orientation="left">LDAP / AD</a-divider>
          <a-descriptions bordered size="small" :column="2" class="config-descriptions">
            <a-descriptions-item label="LDAP URL">
              <span class="config-value">{{ displayText(configRecord.ldapUrl) }}</span>
            </a-descriptions-item>
            <a-descriptions-item label="Base DN">
              <span class="config-value">{{ displayText(configRecord.ldapBaseDn) }}</span>
            </a-descriptions-item>
            <a-descriptions-item label="Bind DN">
              <span class="config-value">{{ displayText(configRecord.ldapBindDn) }}</span>
            </a-descriptions-item>
            <a-descriptions-item label="Bind Password">
              {{ configRecord.ldapBindPasswordConfigured ? '已配置' : '未配置' }}
            </a-descriptions-item>
            <a-descriptions-item label="User Search Base">
              <span class="config-value">{{ displayText(configRecord.ldapUserSearchBase) }}</span>
            </a-descriptions-item>
            <a-descriptions-item label="User Search Filter">
              <span class="config-value">{{ displayText(configRecord.ldapUserSearchFilter) }}</span>
            </a-descriptions-item>
            <a-descriptions-item label="Username Attribute">
              <span class="config-value">{{ displayText(configRecord.ldapUsernameAttribute) }}</span>
            </a-descriptions-item>
            <a-descriptions-item label="Email Attribute">
              <span class="config-value">{{ displayText(configRecord.ldapEmailAttribute) }}</span>
            </a-descriptions-item>
            <a-descriptions-item label="Phone Attribute">
              <span class="config-value">{{ displayText(configRecord.ldapPhoneAttribute) }}</span>
            </a-descriptions-item>
            <a-descriptions-item label="Display Name Attribute">
              <span class="config-value">{{ displayText(configRecord.ldapDisplayNameAttribute) }}</span>
            </a-descriptions-item>
            <a-descriptions-item label="Group Attribute">
              <span class="config-value">{{ displayText(configRecord.ldapGroupAttribute) }}</span>
            </a-descriptions-item>
            <a-descriptions-item label="Page Size">{{ displayText(configRecord.ldapPageSize) }}</a-descriptions-item>
            <a-descriptions-item label="LDAPS">{{ configRecord.ldapUseSsl ? '是' : '否' }}</a-descriptions-item>
            <a-descriptions-item label="StartTLS">{{ configRecord.ldapStartTls ? '是' : '否' }}</a-descriptions-item>
          </a-descriptions>
        </template>

        <a-divider orientation="left">属性映射</a-divider>
        <pre class="config-pre">{{ displayText(configRecord.attributeMapping) }}</pre>
        <div style="margin-top: 20px; text-align: right;">
          <a-button type="primary" @click="configVisible = false">关闭</a-button>
        </div>
      </template>
    </a-modal>

    <a-modal v-model:open="testVisible" title="身份源测试结果" :footer="null" width="640px"
             :bodyStyle="{ maxHeight: 'calc(80vh - 120px)', overflowY: 'auto' }">
      <a-alert :type="testResult.success ? 'success' : 'error'"
               :message="testResult.message || (testResult.success ? '配置检查通过' : '配置检查失败')"
               show-icon style="margin-bottom: 16px" />
      <a-descriptions bordered size="small" :column="1">
        <a-descriptions-item v-for="item in checkItems" :key="item.key" :label="item.key">
          <a-tag :color="checkColor(item.value)">{{ checkLabel(item.value) }}</a-tag>
        </a-descriptions-item>
      </a-descriptions>
      <div style="margin-top: 20px; text-align: right;">
        <a-button type="primary" @click="testVisible = false">关闭</a-button>
      </div>
    </a-modal>

    <a-modal v-model:open="syncVisible" title="LDAP/AD 同步结果" :footer="null" width="640px"
             :bodyStyle="{ maxHeight: 'calc(80vh - 120px)', overflowY: 'auto' }">
      <a-alert :type="syncResult.failed ? 'warning' : 'success'"
               :message="syncResult.message || '同步完成'"
               show-icon style="margin-bottom: 16px" />
      <a-descriptions bordered size="small" :column="2">
        <a-descriptions-item label="模式">{{ syncResult.dryRun ? '预演' : '执行' }}</a-descriptions-item>
        <a-descriptions-item label="扫描">{{ syncResult.scanned ?? 0 }}</a-descriptions-item>
        <a-descriptions-item label="待创建">{{ syncResult.wouldCreate ?? 0 }}</a-descriptions-item>
        <a-descriptions-item label="待更新">{{ syncResult.wouldUpdate ?? 0 }}</a-descriptions-item>
        <a-descriptions-item label="已创建">{{ syncResult.created ?? 0 }}</a-descriptions-item>
        <a-descriptions-item label="已更新">{{ syncResult.updated ?? 0 }}</a-descriptions-item>
        <a-descriptions-item label="跳过">{{ syncResult.skipped ?? 0 }}</a-descriptions-item>
        <a-descriptions-item label="失败">{{ syncResult.failed ?? 0 }}</a-descriptions-item>
      </a-descriptions>
      <div style="margin-top: 20px; text-align: right;">
        <a-button type="primary" @click="syncVisible = false">关闭</a-button>
      </div>
    </a-modal>
  </div>
</template>

<script setup>
import { ref, reactive, onMounted, computed } from 'vue'
import { message } from 'ant-design-vue'
import {
  AlipayCircleOutlined,
  ApartmentOutlined,
  ApiOutlined,
  BankOutlined,
  CloudServerOutlined,
  CodeOutlined,
  DingdingOutlined,
  QqOutlined,
  SafetyCertificateOutlined,
  TeamOutlined,
  WechatOutlined,
  PlusOutlined,
  UploadOutlined,
  AppstoreOutlined,
  BarsOutlined,
  CopyOutlined,
  DownOutlined
} from '@ant-design/icons-vue'
import {
  getIdentityProviders,
  createIdentityProvider,
  updateIdentityProvider,
  deleteIdentityProvider,
  updateIdpStatus,
  updateIdpLoginDisplay,
  testIdentityProvider,
  syncIdentityProviderUsers
} from '../../api'

const copyToClipboard = (text) => {
  if (navigator.clipboard) {
    navigator.clipboard.writeText(text)
    message.success('已复制到剪贴板')
  }
}

const providers = ref([])
const loading = ref(false)
const modalVisible = ref(false)
const submitting = ref(false)
const isEdit = ref(false)
const editId = ref(null)
const configVisible = ref(false)
const configRecord = ref(null)
const testVisible = ref(false)
const testResult = ref({ success: false, message: '', checks: {} })
const syncVisible = ref(false)
const syncResult = ref({})
const sourceFilter = ref('ALL')
const iconMode = ref('auto')
const iconPanelActiveKeys = ref([])
const pagination = reactive({
  current: 1,
  pageSize: 50,
  total: 0,
  showSizeChanger: true,
  pageSizeOptions: ['20', '50', '100'],
  showTotal: total => `共 ${total} 个身份源`
})

const sourceOptions = [
  { label: '全部来源', value: 'ALL' },
  { label: '配置文件提供', value: 'CONFIG_FILE' },
  { label: '管理端配置', value: 'DATABASE' }
]

const iconModeOptions = [
  { label: '自动', value: 'auto' },
  { label: '图标库', value: 'library' },
  { label: '上传图片', value: 'upload' }
]

const activeSection = ref('connections')
const viewMode = ref('card')
const catalogCategoryFilter = ref('all')

const idpCatalog = [
  {
    key: 'google',
    name: 'Google',
    type: 'OIDC',
    category: 'social',
    desc: 'Google 账号全球快捷单点登录，基于 OpenID Connect 1.0 标准协议',
    iconKey: 'google',
    color: '#ea4335',
    preset: {
      providerName: 'Google',
      providerType: 'OIDC',
      registrationId: 'google',
      authorizationUri: 'https://accounts.google.com/o/oauth2/v2/auth',
      tokenUri: 'https://oauth2.googleapis.com/token',
      userinfoUri: 'https://openidconnect.googleapis.com/v1/userinfo',
      jwkSetUri: 'https://www.googleapis.com/oauth2/v3/certs',
      scopes: 'openid,profile,email',
      iconKey: 'google'
    }
  },
  {
    key: 'github',
    name: 'GitHub',
    type: 'CUSTOM',
    category: 'social',
    desc: '面向开发者的 GitHub 账号 OAuth 2.0 授权一键登录',
    iconKey: 'github',
    color: '#24292f',
    preset: {
      providerName: 'GitHub',
      providerType: 'CUSTOM',
      registrationId: 'github',
      authorizationUri: 'https://github.com/login/oauth/authorize',
      tokenUri: 'https://github.com/login/oauth/access_token',
      userinfoUri: 'https://api.github.com/user',
      scopes: 'read:user,user:email',
      iconKey: 'github'
    }
  },
  {
    key: 'wechat',
    name: '微信扫码',
    type: 'CUSTOM',
    category: 'social',
    desc: '微信开放平台网站应用微信扫码登录与公众号免密',
    iconKey: 'wechat',
    color: '#07c160',
    preset: {
      providerName: '微信扫码登录',
      providerType: 'CUSTOM',
      registrationId: 'wechat',
      authorizationUri: 'https://open.weixin.qq.com/connect/qrconnect',
      tokenUri: 'https://api.weixin.qq.com/sns/oauth2/access_token',
      userinfoUri: 'https://api.weixin.qq.com/sns/userinfo',
      scopes: 'snsapi_login',
      iconKey: 'wechat'
    }
  },
  {
    key: 'feishu',
    name: '飞书',
    type: 'CUSTOM',
    category: 'social',
    desc: '飞书企业办公平台扫码登录与组织人员免密协同',
    iconKey: 'feishu',
    color: '#00d6b9',
    preset: {
      providerName: '飞书',
      providerType: 'CUSTOM',
      registrationId: 'feishu',
      authorizationUri: 'https://passport.feishu.cn/suite/pas/oauth/authorize',
      tokenUri: 'https://passport.feishu.cn/suite/pas/oauth/token',
      userinfoUri: 'https://passport.feishu.cn/suite/pas/oauth/userinfo',
      scopes: 'contact:user.base:readonly',
      iconKey: 'feishu'
    }
  },
  {
    key: 'dingtalk',
    name: '钉钉',
    type: 'CUSTOM',
    category: 'social',
    desc: '钉钉企业组织工作台扫码与第三方免密授权登录',
    iconKey: 'dingtalk',
    color: '#007fff',
    preset: {
      providerName: '钉钉',
      providerType: 'CUSTOM',
      registrationId: 'dingtalk',
      authorizationUri: 'https://login.dingtalk.com/oauth2/auth',
      tokenUri: 'https://api.dingtalk.com/v1.0/oauth2/userAccessToken',
      userinfoUri: 'https://api.dingtalk.com/v1.0/contact/users/me',
      scopes: 'openid,corpid',
      iconKey: 'dingtalk'
    }
  },
  {
    key: 'saml',
    name: '企业 SAML 2.0',
    type: 'SAML',
    category: 'enterprise',
    desc: '集成 Okta、Azure AD、OneLogin 等企业级 SAML 2.0 单点登录',
    iconKey: 'saml',
    color: '#7c3aed',
    preset: {
      providerName: '企业 SAML SSO',
      providerType: 'SAML',
      registrationId: 'saml-sso',
      iconKey: 'saml'
    }
  },
  {
    key: 'ldap',
    name: 'LDAP / Active Directory',
    type: 'LDAP',
    category: 'enterprise',
    desc: '连接 Windows AD 或 OpenLDAP 企业员工目录，支持属性映射与批量同步',
    iconKey: 'custom',
    color: '#059669',
    preset: {
      providerName: '企业 LDAP 目录',
      providerType: 'LDAP',
      registrationId: 'enterprise-ldap',
      ldapUrl: 'ldap://ad.example.com:389',
      ldapBaseDn: 'dc=example,dc=com',
      ldapUserSearchBase: 'ou=users',
      ldapUserSearchFilter: '(objectClass=person)',
      ldapUsernameAttribute: 'sAMAccountName',
      ldapEmailAttribute: 'mail'
    }
  },
  {
    key: 'oidc',
    name: '标准 OIDC 连接器',
    type: 'OIDC',
    category: 'enterprise',
    desc: '连接任意兼容 OpenID Connect 1.0 标准的企业身份源或 IdP 服务',
    iconKey: 'oidc',
    color: '#2563eb',
    preset: {
      providerName: '标准 OIDC',
      providerType: 'OIDC',
      registrationId: 'custom-oidc',
      scopes: 'openid,profile,email',
      iconKey: 'oidc'
    }
  }
]

const filteredCatalog = computed(() => {
  if (catalogCategoryFilter.value === 'all') return idpCatalog
  return idpCatalog.filter(item => item.category === catalogCategoryFilter.value)
})

const handleConnectFromCatalog = (item) => {
  resetForm()
  Object.assign(form, item.preset)
  if (item.preset.iconKey) {
    iconMode.value = 'library'
  }
  isEdit.value = false
  editId.value = null
  modalVisible.value = true
}

const providerTypeOptions = [
  { value: 'CUSTOM', label: 'Custom', description: '自定义 OAuth2', icon: ApiOutlined, color: 'default' },
  { value: 'OIDC', label: 'OIDC', description: '标准协议', icon: CloudServerOutlined, color: 'blue' },
  { value: 'SAML', label: 'SAML', description: '企业 SSO', icon: SafetyCertificateOutlined, color: 'purple' },
  { value: 'LDAP', label: 'LDAP / AD', description: '目录服务', icon: ApartmentOutlined, color: 'green' }
]

const providerTypes = [
  { value: 'OIDC', label: 'OIDC', description: '标准协议', icon: CloudServerOutlined, color: 'blue' },
  { value: 'SAML', label: 'SAML', description: '企业 SSO', icon: SafetyCertificateOutlined, color: 'purple' },
  { value: 'LDAP', label: 'LDAP / AD', description: '目录服务', icon: ApartmentOutlined, color: 'green' },
  { value: 'WECHAT', label: '微信', description: '开放平台', icon: WechatOutlined, color: 'green' },
  { value: 'WECOM', label: '企业微信', description: '企业身份', icon: BankOutlined, color: 'cyan' },
  { value: 'DINGTALK', label: '钉钉', description: '组织登录', icon: DingdingOutlined, color: 'blue' },
  { value: 'FEISHU', label: '飞书', description: '协作账号', icon: TeamOutlined, color: 'geekblue' },
  { value: 'ALIPAY', label: '支付宝', description: '开放能力', icon: AlipayCircleOutlined, color: 'gold' },
  { value: 'QQ', label: 'QQ', description: '社交登录', icon: QqOutlined, color: 'blue' },
  { value: 'GITEE', label: 'Gitee', description: '代码平台', icon: CodeOutlined, color: 'red' },
  { value: 'CUSTOM', label: 'Custom', description: '自定义 OAuth2', icon: ApiOutlined, color: 'default' }
]

const providerMetaMap = Object.fromEntries(providerTypes.map(type => [type.value, type]))
const providerMeta = (type) => providerMetaMap[type] || providerMetaMap.CUSTOM
const defaultIconKey = (type) => (type || 'CUSTOM').toLowerCase().replace(/_/g, '-')
const normalizeIconKey = (key) => (key || '').toString().trim().toLowerCase().replace(/_/g, '-')
const iconOptions = [
  { value: 'custom', label: 'Custom', icon: ApiOutlined, color: 'default' },
  { value: 'oidc', label: 'OIDC', icon: CloudServerOutlined, color: 'blue' },
  { value: 'saml', label: 'SSO', icon: SafetyCertificateOutlined, color: 'purple' },
  { value: 'wechat', label: '微信', icon: WechatOutlined, color: 'green' },
  { value: 'wecom', label: '企业微信', icon: BankOutlined, color: 'cyan' },
  { value: 'dingtalk', label: '钉钉', icon: DingdingOutlined, color: 'blue' },
  { value: 'feishu', label: '飞书', icon: TeamOutlined, color: 'geekblue' },
  { value: 'alipay', label: '支付宝', icon: AlipayCircleOutlined, color: 'gold' },
  { value: 'qq', label: 'QQ', icon: QqOutlined, color: 'blue' },
  { value: 'gitee', label: 'Gitee', icon: CodeOutlined, color: 'red' },
  { value: 'github', label: 'GitHub', icon: CodeOutlined, color: 'default' },
  { value: 'google', label: 'Google', icon: CloudServerOutlined, color: 'blue' },
  { value: 'facebook', label: 'Facebook', icon: CloudServerOutlined, color: 'blue' },
  { value: 'microsoft', label: 'Microsoft', icon: BankOutlined, color: 'blue' },
  { value: 'gitlab', label: 'GitLab', icon: CodeOutlined, color: 'orange' },
  { value: 'discord', label: 'Discord', icon: TeamOutlined, color: 'geekblue' },
  { value: 'slack', label: 'Slack', icon: TeamOutlined, color: 'purple' },
  { value: 'linkedin', label: 'LinkedIn', icon: TeamOutlined, color: 'blue' },
  { value: 'apple', label: 'Apple', icon: CloudServerOutlined, color: 'default' },
  { value: 'weibo', label: '微博', icon: TeamOutlined, color: 'red' },
  { value: 'baidu', label: '百度', icon: CloudServerOutlined, color: 'blue' },
  { value: 'douyin', label: '抖音', icon: TeamOutlined, color: 'default' },
  { value: 'oschina', label: 'OSChina', icon: CodeOutlined, color: 'green' }
]
const iconMetaMap = Object.fromEntries(iconOptions.map(option => [option.value, option]))
const iconMeta = (key, providerType) =>
  iconMetaMap[normalizeIconKey(key)] || iconMetaMap[defaultIconKey(providerType)] || iconMetaMap.custom

const form = reactive({
  providerName: '', providerType: 'CUSTOM', registrationId: '', clientId: '', clientSecret: '',
  authorizationUri: '', tokenUri: '', userinfoUri: '', jwkSetUri: '', scopes: '',
  samlEntityId: '', samlSsoUrl: '', samlSloUrl: '', samlX509Certificate: '',
  samlMetadataUrl: '', samlSpEntityId: '', samlAcsUrl: '', samlNameIdFormat: '',
  ldapUrl: '', ldapBaseDn: '', ldapBindDn: '', ldapBindPassword: '',
  ldapUserSearchBase: '', ldapUserSearchFilter: '(objectClass=person)',
  ldapUsernameAttribute: 'uid', ldapEmailAttribute: 'mail', ldapPhoneAttribute: 'telephoneNumber',
  ldapDisplayNameAttribute: 'displayName', ldapGroupAttribute: 'memberOf',
  ldapUseSsl: false, ldapStartTls: false, ldapPageSize: 200,
  iconKey: '', iconUrl: '', displayOnLogin: true,
  attributeMapping: '', linkingStrategy: 'AUTO_REGISTER', displayOrder: 0
})

const columns = [
  { title: '名称', dataIndex: 'providerName', key: 'name', width: 150 },
  { title: '类型', key: 'type', width: 130 },
  { title: '来源', key: 'source', width: 120 },
  { title: 'Registration ID', dataIndex: 'registrationId', key: 'regId', width: 180 },
  { title: 'Client ID', dataIndex: 'clientId', key: 'clientId', width: 260, ellipsis: true },
  { title: '链接策略', dataIndex: 'linkingStrategy', key: 'strategy', width: 120 },
  { title: '顺序', dataIndex: 'displayOrder', key: 'order', width: 80 },
  { title: '登录页', key: 'displayOnLogin', width: 120 },
  { title: '状态', key: 'status', width: 100 },
  { title: '操作', key: 'action', width: 220, fixed: 'right' }
]

const checkItems = computed(() =>
  Object.entries(testResult.value.checks || {}).map(([key, value]) => ({ key, value }))
)

const checkColor = (value) => {
  if (value === true || value === 'ok' || value === 'optional' || value === 'skipped'
    || value === 'manual' || value === 'metadata_url') return 'green'
  if (value === 'pending') return 'gold'
  if (typeof value === 'number' && value < 500) return 'green'
  return 'red'
}

const checkLabel = (value) => {
  if (value === true) return 'ok'
  if (value === false) return 'failed'
  return String(value)
}

const fetchData = async () => {
  loading.value = true
  try {
    const res = await getIdentityProviders(pagination.current - 1, pagination.pageSize, sourceFilter.value)
    providers.value = res.data?.content || []
    pagination.total = res.data?.totalElements || 0
  } catch (e) { message.error('加载失败') }
  finally { loading.value = false }
}

const handleTableChange = (pag) => {
  pagination.current = pag.current
  pagination.pageSize = pag.pageSize
  fetchData()
}

const handleSourceFilterChange = () => {
  pagination.current = 1
  fetchData()
}

const isConfigProvider = (record) => record?.source === 'CONFIG_FILE' || record?.readOnly === true
const sourceLabel = (record) => isConfigProvider(record) ? '配置文件提供' : '管理端配置'
const sourceColor = (record) => isConfigProvider(record) ? 'blue' : 'default'
const displayText = (value) => {
  if (value === null || value === undefined || value === '') return '未配置'
  return String(value)
}

const showConfig = (record) => {
  configRecord.value = record
  configVisible.value = true
}

const resetForm = () => {
  form.providerName = ''; form.providerType = 'CUSTOM'; form.registrationId = ''
  form.clientId = ''; form.clientSecret = ''; form.authorizationUri = ''
  form.tokenUri = ''; form.userinfoUri = ''; form.jwkSetUri = ''; form.scopes = ''
  form.samlEntityId = ''; form.samlSsoUrl = ''; form.samlSloUrl = ''; form.samlX509Certificate = ''
  form.samlMetadataUrl = ''; form.samlSpEntityId = ''; form.samlAcsUrl = ''; form.samlNameIdFormat = ''
  form.ldapUrl = ''; form.ldapBaseDn = ''; form.ldapBindDn = ''; form.ldapBindPassword = ''
  form.ldapUserSearchBase = ''; form.ldapUserSearchFilter = '(objectClass=person)'
  form.ldapUsernameAttribute = 'uid'; form.ldapEmailAttribute = 'mail'
  form.ldapPhoneAttribute = 'telephoneNumber'; form.ldapDisplayNameAttribute = 'displayName'
  form.ldapGroupAttribute = 'memberOf'; form.ldapUseSsl = false; form.ldapStartTls = false; form.ldapPageSize = 200
  form.iconKey = ''; form.iconUrl = ''; form.displayOnLogin = true
  form.attributeMapping = ''; form.linkingStrategy = 'AUTO_REGISTER'; form.displayOrder = 0
  iconMode.value = 'auto'
  iconPanelActiveKeys.value = []
  editId.value = null
}

const selectProviderType = (type) => {
  if (isEdit.value) return
  form.providerType = type
  form.iconKey = ''
  form.iconUrl = ''
  iconMode.value = 'auto'
  form.displayOnLogin = type !== 'LDAP'
  if (!form.scopes && !['SAML', 'LDAP'].includes(type)) {
    form.scopes = 'openid,profile,email'
  }
  if (['SAML', 'LDAP'].includes(type)) {
    form.scopes = ''
  }
  if (!form.registrationId) {
    form.registrationId = type.toLowerCase().replace(/_/g, '-')
  }
}

const handleIconModeChange = (mode) => {
  if (mode === 'auto') {
    form.iconKey = ''
    form.iconUrl = ''
    return
  }
  if (mode === 'library') {
    form.iconUrl = ''
    if (!form.iconKey) {
      form.iconKey = defaultIconKey(form.providerType)
    }
    return
  }
  if (mode === 'upload' && !form.iconUrl) {
    form.iconKey = 'custom'
  }
}

const selectIcon = (iconKey) => {
  form.iconKey = iconKey
  form.iconUrl = ''
  iconMode.value = 'library'
}

const beforeIconUpload = (file) => {
  const accepted = ['image/svg+xml', 'image/png', 'image/jpeg', 'image/webp']
  const typeAccepted = accepted.includes(file.type) || /\.(svg|png|jpe?g|webp)$/i.test(file.name || '')
  if (!typeAccepted) {
    message.error('请上传 SVG、PNG、JPG 或 WebP 图标')
    return false
  }
  if (file.size > 200 * 1024) {
    message.error('图标不能超过 200KB')
    return false
  }
  const reader = new FileReader()
  reader.onload = event => {
    form.iconUrl = event.target?.result || ''
    form.iconKey = 'custom'
    iconMode.value = 'upload'
  }
  reader.readAsDataURL(file)
  return false
}

const clearUploadedIcon = () => {
  form.iconUrl = ''
  form.iconKey = ''
  iconMode.value = 'auto'
}

const showCreate = () => { isEdit.value = false; resetForm(); modalVisible.value = true }

const showEdit = (record) => {
  isEdit.value = true; editId.value = record.id
  const normalizedIconKey = normalizeIconKey(record.iconKey)
  const providerDefaultIconKey = defaultIconKey(record.providerType)
  Object.assign(form, {
    providerName: record.providerName, providerType: record.providerType,
    registrationId: record.registrationId, clientId: record.clientId,
    clientSecret: '', authorizationUri: record.authorizationUri || '',
    tokenUri: record.tokenUri || '', userinfoUri: record.userinfoUri || '',
    jwkSetUri: record.jwkSetUri || '', scopes: record.scopes || '',
    samlEntityId: record.samlEntityId || '', samlSsoUrl: record.samlSsoUrl || '',
    samlSloUrl: record.samlSloUrl || '', samlX509Certificate: record.samlX509Certificate || '',
    samlMetadataUrl: record.samlMetadataUrl || '', samlSpEntityId: record.samlSpEntityId || '',
    samlAcsUrl: record.samlAcsUrl || '', samlNameIdFormat: record.samlNameIdFormat || '',
    ldapUrl: record.ldapUrl || '', ldapBaseDn: record.ldapBaseDn || '',
    ldapBindDn: record.ldapBindDn || '', ldapBindPassword: '',
    ldapUserSearchBase: record.ldapUserSearchBase || '',
    ldapUserSearchFilter: record.ldapUserSearchFilter || '(objectClass=person)',
    ldapUsernameAttribute: record.ldapUsernameAttribute || 'uid',
    ldapEmailAttribute: record.ldapEmailAttribute || 'mail',
    ldapPhoneAttribute: record.ldapPhoneAttribute || 'telephoneNumber',
    ldapDisplayNameAttribute: record.ldapDisplayNameAttribute || 'displayName',
    ldapGroupAttribute: record.ldapGroupAttribute || 'memberOf',
    ldapUseSsl: !!record.ldapUseSsl,
    ldapStartTls: !!record.ldapStartTls,
    ldapPageSize: record.ldapPageSize || 200,
    iconKey: normalizedIconKey && normalizedIconKey !== providerDefaultIconKey ? normalizedIconKey : '',
    iconUrl: record.iconUrl || '',
    displayOnLogin: record.displayOnLogin !== false,
    attributeMapping: record.attributeMapping || '',
    linkingStrategy: record.linkingStrategy || 'AUTO_REGISTER',
    displayOrder: record.displayOrder || 0
  })
  iconMode.value = form.iconUrl ? 'upload' : (form.iconKey ? 'library' : 'auto')
  iconPanelActiveKeys.value = []
  modalVisible.value = true
}

const handleSubmit = async () => {
  submitting.value = true
  try {
    if (isEdit.value) {
      await updateIdentityProvider(editId.value, form)
      message.success('更新成功')
    } else {
      await createIdentityProvider(form)
      message.success('创建成功')
    }
    modalVisible.value = false; fetchData()
  } catch (e) { message.error(e.message) }
  finally { submitting.value = false }
}

const handleDelete = async (id) => {
  try { await deleteIdentityProvider(id); message.success('删除成功'); fetchData() }
  catch (e) { message.error(e.message) }
}

const toggleStatus = async (record, enabled) => {
  try { await updateIdpStatus(record.id, enabled); record.enabled = enabled; message.success(enabled ? '已启用' : '已禁用') }
  catch (e) { message.error(e.message) }
}

const toggleLoginDisplay = async (record, displayOnLogin) => {
  const previous = record.displayOnLogin !== false
  record.displayOnLogin = displayOnLogin
  record.displayUpdating = true
  try {
    const res = await updateIdpLoginDisplay(record.id, displayOnLogin)
    Object.assign(record, res.data || { displayOnLogin })
    message.success(displayOnLogin ? '已显示在登录页' : '已从登录页隐藏')
  } catch (e) {
    record.displayOnLogin = previous
    message.error(e.message)
  } finally {
    record.displayUpdating = false
  }
}

const handleTest = async (record, probeRemote) => {
  try {
    const res = await testIdentityProvider(record.id, probeRemote)
    testResult.value = res.data || { success: false, message: '无返回结果', checks: {} }
    testVisible.value = true
  } catch (e) {
    message.error(e.message)
  }
}

const handleLdapSync = async (record, dryRun) => {
  try {
    const res = await syncIdentityProviderUsers(record.id, { dryRun, maxResults: 200 })
    syncResult.value = res.data || {}
    syncVisible.value = true
  } catch (e) {
    message.error(e.message)
  }
}

onMounted(fetchData)
</script>

<style scoped>
.page-container {
  padding: 24px;
  max-width: 1600px;
  margin: 0 auto;
  width: 100%;
}

.page-header {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  margin-bottom: 24px;
}

.page-subtitle {
  color: var(--aa-text-secondary);
  font-size: 13px;
  margin-top: 4px;
}

.idp-card-grid-container {
  margin-top: 16px;
}

.idp-card-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(360px, 1fr));
  gap: 20px;
}

.idp-entity-card {
  background: #ffffff;
  border: 1px solid var(--aa-border);
  border-radius: 12px;
  padding: 20px;
  display: flex;
  flex-direction: column;
  justify-content: space-between;
  transition: all 0.2s cubic-bezier(0.4, 0, 0.2, 1);
  box-shadow: var(--aa-shadow-sm);
}

.idp-entity-card:hover {
  transform: translateY(-2px);
  box-shadow: var(--aa-shadow-md);
  border-color: #cbd5e1;
}

.idp-card-top {
  display: flex;
  gap: 14px;
  align-items: flex-start;
  margin-bottom: 12px;
}

.idp-avatar-box {
  width: 44px;
  height: 44px;
  border-radius: 10px;
  background: #f1f5f9;
  display: flex;
  align-items: center;
  justify-content: center;
  flex-shrink: 0;
  border: 1px solid var(--aa-border);
}

.idp-avatar-icon {
  font-size: 22px;
  color: var(--aa-primary);
}

.idp-avatar-img {
  width: 28px;
  height: 28px;
  object-fit: contain;
}

.idp-card-main-info {
  flex: 1;
  min-width: 0;
}

.idp-title-line {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 8px;
  margin-bottom: 4px;
}

.idp-card-title {
  margin: 0;
  font-size: 15px;
  font-weight: 600;
  color: var(--aa-text-primary);
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}

.idp-sub-id {
  display: flex;
  align-items: center;
  gap: 6px;
  font-size: 12px;
  color: var(--aa-text-muted);
}

.reg-label {
  font-size: 11px;
  text-transform: uppercase;
  font-weight: 600;
  color: var(--aa-text-secondary);
}

.reg-code {
  font-family: var(--aa-font-mono);
  font-size: 12px;
  background: #f1f5f9;
  padding: 1px 6px;
  border-radius: 4px;
  color: #334155;
  max-width: 140px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.copy-inline {
  margin: 0 !important;
  display: inline-flex;
  align-items: center;
}

.idp-card-meta {
  display: flex;
  flex-wrap: wrap;
  gap: 12px;
  margin: 12px 0 16px;
  padding: 10px 12px;
  background: #f8fafc;
  border-radius: 8px;
  border: 1px solid var(--aa-border-light);
}

.idp-meta-item {
  display: flex;
  align-items: center;
  gap: 6px;
  font-size: 12px;
}

.meta-label {
  color: var(--aa-text-secondary);
  font-size: 12px;
}

.idp-card-footer {
  display: flex;
  justify-content: space-between;
  align-items: center;
  border-top: 1px solid var(--aa-border-light);
  padding-top: 14px;
  margin-top: auto;
}

.status-toggle-wrap {
  display: flex;
  align-items: center;
  gap: 8px;
}

.table-switch-wrap {
  display: flex;
  align-items: center;
  gap: 8px;
}

.status-pill-text {
  font-size: 12px;
  font-weight: 500;

  &.is-enabled {
    color: var(--aa-primary);
  }

  &.is-disabled {
    color: var(--aa-text-muted);
  }
}

.status-label {
  font-size: 12px;
  color: var(--aa-text-secondary);
}

.idp-actions-wrap {
  display: flex;
  align-items: center;
  gap: 2px;
}

.idp-empty-wrap {
  padding: 60px 0;
  background: #ffffff;
  border-radius: 12px;
  border: 1px dashed var(--aa-border);
  text-align: center;
}

/* IdP Catalog Market */
.idp-catalog-section {
  margin-top: 16px;
}

.catalog-filters {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 20px;
}

.catalog-count-tip {
  font-size: 13px;
  color: var(--aa-text-secondary);
}

.idp-catalog-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
  gap: 18px;
}

.catalog-card {
  background: #ffffff;
  border: 1px solid var(--aa-border);
  border-radius: 12px;
  padding: 20px;
  display: flex;
  flex-direction: column;
  justify-content: space-between;
  cursor: pointer;
  transition: all 0.2s cubic-bezier(0.4, 0, 0.2, 1);
  box-shadow: var(--aa-shadow-sm);
}

.catalog-card:hover {
  transform: translateY(-2px);
  border-color: var(--aa-primary);
  box-shadow: 0 10px 24px rgba(33, 82, 255, 0.12);
}

.catalog-card-header {
  display: flex;
  gap: 14px;
  align-items: center;
  margin-bottom: 12px;
}

.catalog-icon-wrapper {
  width: 44px;
  height: 44px;
  border-radius: 10px;
  background: #f8fafc;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 24px;
  border: 1px solid var(--aa-border-light);
  flex-shrink: 0;
}

.catalog-title-box {
  flex: 1;
  min-width: 0;
  display: flex;
  align-items: center;
  justify-content: space-between;
}

.catalog-title {
  margin: 0;
  font-size: 15px;
  font-weight: 600;
  color: var(--aa-text-primary);
}

.catalog-desc {
  color: var(--aa-text-secondary);
  font-size: 13px;
  line-height: 1.5;
  margin: 0 0 16px 0;
  min-height: 40px;
}

.catalog-card-footer {
  display: flex;
  justify-content: space-between;
  align-items: center;
  border-top: 1px solid var(--aa-border-light);
  padding-top: 12px;
}

.catalog-category-tag {
  font-size: 12px;
  color: var(--aa-text-muted);
}

.provider-tag {
  display: inline-flex;
  align-items: center;
  gap: 5px;
}

.page-actions {
  display: flex;
  align-items: center;
  gap: 12px;
}

.source-filter {
  width: 150px;
}

.provider-uploaded-tag {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  min-height: 24px;
  padding: 1px 8px;
  color: var(--aa-text-primary);
  font-size: 12px;
  line-height: 20px;
  background: var(--aa-page-bg);
  border: 1px solid var(--aa-border);
  border-radius: 12px;
}

.provider-uploaded-tag img {
  width: 16px;
  height: 16px;
  object-fit: contain;
  display: block;
}

.idp-login-entry-cell {
  display: inline-flex;
  align-items: center;
  flex-wrap: wrap;
  gap: 6px;
}

.provider-type-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(100px, 1fr));
  gap: 10px;
  max-width: 100%;
}

.provider-type-option {
  display: grid;
  min-height: 80px;
  padding: 8px;
  border: 1px solid var(--aa-border);
  border-radius: 8px;
  background: var(--aa-card-bg);
  color: var(--aa-text-primary);
  cursor: pointer;
  gap: 2px;
  justify-items: start;
  text-align: left;
  transition: border-color .2s ease, box-shadow .2s ease, transform .2s ease;
}

.provider-type-option:hover:not(:disabled),
.provider-type-option.active {
  border-color: var(--aa-primary);
  box-shadow: 0 8px 20px rgba(15, 23, 42, .08);
  transform: translateY(-1px);
}

.provider-type-option:disabled {
  cursor: not-allowed;
  opacity: .72;
}

.provider-type-icon {
  color: var(--aa-primary);
  font-size: 20px;
}

.provider-type-option span {
  font-weight: 600;
  line-height: 1.2;
}

.provider-type-option small {
  color: var(--aa-text-secondary);
  font-size: 12px;
  line-height: 1.2;
}

.idp-icon-collapse {
  margin-top: -4px;
  margin-bottom: 16px;
  border: 1px solid var(--aa-border);
  border-radius: 8px;
}

.idp-icon-summary {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  margin-bottom: 12px;
}

.idp-icon-current {
  display: inline-flex;
  align-items: center;
  flex-wrap: wrap;
  gap: 8px;
  min-width: 0;
}

.idp-icon-current > span:last-child {
  color: var(--aa-text-secondary);
  font-size: 12px;
  line-height: 1.4;
}

.idp-icon-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(85px, 1fr));
  gap: 8px;
}

.idp-icon-option {
  min-height: 38px;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: 6px;
  padding: 4px 8px;
  border: 1px solid var(--aa-border);
  border-radius: 6px;
  background: var(--aa-card-bg);
  color: var(--aa-text-primary);
  cursor: pointer;
  font-size: 13px;
  transition: border-color .2s ease, background .2s ease, color .2s ease, transform .2s ease;
}

.idp-icon-option:hover,
.idp-icon-option.active {
  border-color: var(--aa-primary);
  background: rgba(47, 107, 255, .08);
  color: var(--aa-primary);
  transform: translateY(-1px);
}

.idp-icon-option span {
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  font-weight: 600;
}

.idp-icon-upload-panel {
  display: flex;
  flex-direction: column;
  align-items: flex-start;
  gap: 10px;
  min-height: 112px;
  padding: 12px;
  background: var(--aa-page-bg);
  border: 1px dashed var(--aa-border);
  border-radius: 8px;
}

.idp-icon-upload-preview {
  display: inline-flex;
  align-items: center;
  gap: 10px;
  min-height: 40px;
}

.idp-icon-upload-preview img {
  width: 40px;
  height: 40px;
  padding: 6px;
  object-fit: contain;
  background: var(--aa-card-bg);
  border: 1px solid var(--aa-border);
  border-radius: 8px;
}

.idp-display-control {
  display: flex;
  flex-direction: column;
  align-items: flex-start;
  gap: 8px;
}

.idp-display-control span:last-child {
  color: var(--aa-text-secondary);
  font-size: 12px;
  line-height: 1.5;
}

.config-view-header {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 16px;
  margin-bottom: 18px;
}

.config-view-title {
  color: var(--aa-text-primary);
  font-size: 18px;
  font-weight: 700;
  line-height: 1.3;
}

.config-view-subtitle {
  margin-top: 4px;
  color: var(--aa-text-secondary);
  font-family: Consolas, Monaco, monospace;
  font-size: 13px;
  line-height: 1.4;
  word-break: break-all;
}

.config-descriptions {
  margin-bottom: 4px;
}

.config-value {
  font-family: Consolas, Monaco, monospace;
  word-break: break-all;
}

.config-pre {
  min-height: 34px;
  max-height: 220px;
  margin: 0;
  padding: 10px 12px;
  overflow: auto;
  color: var(--aa-text-primary);
  font-family: Consolas, Monaco, monospace;
  font-size: 12px;
  line-height: 1.6;
  white-space: pre-wrap;
  word-break: break-all;
  background: var(--aa-page-bg);
  border: 1px solid var(--aa-border);
  border-radius: 6px;
}

@media (max-width: 720px) {
  .page-actions {
    width: 100%;
    justify-content: space-between;
    flex-wrap: wrap;
  }

  .source-filter {
    flex: 1 1 150px;
  }

  .provider-type-grid {
    grid-template-columns: repeat(3, 1fr);
  }

  .idp-icon-grid {
    grid-template-columns: repeat(3, 1fr);
  }

  .idp-icon-summary {
    align-items: flex-start;
    flex-direction: column;
  }

  .config-view-header {
    flex-direction: column;
  }
}
</style>

<style>
.idp-display-form-item .ant-form-item-control-input-content {
  width: auto !important;
  flex: none;
}
</style>
