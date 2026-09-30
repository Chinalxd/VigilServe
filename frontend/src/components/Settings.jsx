import { useState, useEffect } from 'react'
import { authHeaders } from '../services/auth'
import { usePerm } from '../services/permissions'
import { formatDateTime, localDate, parseServerTime } from '../utils/format'
import { loadPasswordHint, invalidatePasswordHint, FALLBACK_HINT } from '../services/passwordRules'
import RoleManagement from './RoleManagement'
import './Settings.css'
import Icon from './AppIcon'

const API = '/api'
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/

/**
 * 「运行参数」页只显示真正属于运行参数的项。
 * 安全策略（security.*）在「安全设置」页、告警阈值（*_threshold_*）在「告警配置」页，
 * roles_default_seeded 是内部标记，不在本页展示。
 * （原先还有 meshcentral_* 三项，2026-09-23 随 MeshCentral 集成整体下线已移除。）
 */
const RUNTIME_CONFIG_KEYS = [
  'collect_interval',
  'agent_collect_interval',
  'service_check_interval',
  'snmp_collect_interval',
  'chart_refresh_interval',
  'alert_check_interval',
  'frontend_poll_interval',
  'data_retention_days',
  'alert_log_retention_days',
  'operation_log_retention_days',
]

const toLocalInput = (v) => {
  if (!v) return ''
  const d = parseServerTime(v)
  return !d ? '' : localDate(d)
}

// 系统设置里的每个页签对应一个系统权限操作项，颗粒度到「页签」
// 「安全设置」排在「角色管理」前面
const TAB_ORDER = ['security', 'roles', 'users', 'email', 'config', 'alert']

// 安全策略项的中文说明（键 -> 标签 / 单位 / 提示），顺序 = 页面上的分组顺序
const SECURITY_FIELDS = [
  { group: '登录失败', items: [
    { key: 'login_max_attempts', label: '允许连续失败次数', unit: '次', min: 0, max: 99, hint: '0 = 不限制' },
    { key: 'login_lock_minutes', label: '超限后锁定时长', unit: '分钟', min: 0, max: 1440, hint: '0 = 不锁定（只计数）' },
  ] },
  { group: '登录超时', items: [
    { key: 'session_idle_minutes', label: '空闲自动登出', unit: '分钟', min: 0, max: 1440, hint: '0 = 不限制' },
    { key: 'session_max_hours', label: '会话最长时长', unit: '小时', min: 0, max: 720, hint: '0 = 不限制' },
  ] },
  { group: '密码规则', items: [
    { key: 'pwd_min_length', label: '最小长度', unit: '位', min: 4, max: 64, hint: '' },
    { key: 'pwd_require_upper', label: '必须含大写字母', type: 'bool', hint: '' },
    { key: 'pwd_require_lower', label: '必须含小写字母', type: 'bool', hint: '' },
    { key: 'pwd_require_digit', label: '必须含数字', type: 'bool', hint: '' },
    { key: 'pwd_require_symbol', label: '必须含特殊字符', type: 'bool', hint: '' },
  ] },
  { group: '密码有效期', items: [
    { key: 'pwd_max_age_days', label: '密码有效期', unit: '天', min: 0, max: 3650, hint: '0 = 永不过期；到期后登录需先改密码' },
  ] },
  { group: '首次登录', items: [
    { key: 'force_reset_first_login', label: '强制修改密码', type: 'bool', hint: '开启后，账号第一次登录必须先改密码' },
  ] },
]

// 数字项「空值」不能当 0 处理（2026-09-23 现场）。
// 这些安全策略项里 `0` 普遍意味着**关闭该项保护**（锁定时长 / 空闲登出 / 会话时长 /
// 用户清空输入框想重输、顺手点了保存，就会把该项**静默改成 0**。
// 界面上看不出任何异常（P1-7 刻意让"已锁定"与"口令错误"返回同样的提示）。
// 所以：空值一律**保留空值**（不转 0），并由这里算出"哪些项还空着"，
const SECURITY_NUM_FIELDS = SECURITY_FIELDS
  .flatMap((g) => g.items)
  .filter((it) => it.type !== 'bool')

const isBlankNum = (v) =>
  v === '' || v === null || v === undefined || (typeof v === 'number' && !Number.isFinite(v))

const blankSecurityFields = (policy) =>
  SECURITY_NUM_FIELDS.filter((it) => isBlankNum(policy?.[it.key]))

export default function Settings({ isAdmin = false }) {
  const { can } = usePerm()
  const tabOps = {
    security: can('sys', 'settings', 'edit', 'security_manage'),
    roles: can('sys', 'settings', 'edit', 'roles_manage'),
    users: can('sys', 'settings', 'edit', 'users_manage'),
    email: can('sys', 'settings', 'edit', 'email_config'),
    config: can('sys', 'settings', 'edit', 'period_config'),
    alert: can('sys', 'settings', 'edit', 'alert_config'),
  }
  const firstTab = TAB_ORDER.find((t) => tabOps[t])
  const [tab, setTab] = useState(firstTab || (isAdmin ? 'users' : 'config'))
  const [users, setUsers] = useState([])
  const [config, setConfig] = useState({})
  const [loading, setLoading] = useState(true)

  const [newUser, setNewUser] = useState({ username: '', full_name: '', password: '', email: '', role: 'viewer', valid_until: '' })
  const [userError, setUserError] = useState('')
  const [showAddUser, setShowAddUser] = useState(false)
  const [editingUser, setEditingUser] = useState(null)
  const [editForm, setEditForm] = useState({ username: '', full_name: '', password: '', email: '', role: 'viewer', status: 'active', valid_until: '' })
  const [showPwd, setShowPwd] = useState(false)
  const [deleteConfirmUser, setDeleteConfirmUser] = useState(null)
  const [roles, setRoles] = useState([])

  // ── 口令规则提示（新增/重置用户密码时显示在输入框下方）──
  // 规则文案来自后端（同一份 policy 喂给校验与提示），见 services/passwordRules.js
  const [pwdHint, setPwdHint] = useState(FALLBACK_HINT)

  // ── 安全设置 ──────────────────────────────────────────────
  const [secPolicy, setSecPolicy] = useState(null)
  const [secSaving, setSecSaving] = useState(false)
  const [secMsg, setSecMsg] = useState('')
  // ── 服务端证书（CA 指纹 / SAN / 到期），Agent 首次信任时人工核对用 ──
  const [tlsInfo, setTlsInfo] = useState(null)

  const loadTlsInfo = async () => {
    try {
      const res = await fetch(`${API}/tls/status`, { headers })
      if (res.ok) setTlsInfo(await res.json())
    } catch { setTlsInfo(null) }
  }

  const loadSecurity = async () => {
    try {
      const res = await fetch(`${API}/security/policy`, { headers })
      if (res.ok) {
        const data = await res.json()
        setSecPolicy(data.policy || {})
      }
    } catch { setSecPolicy(null) }
  }

  const saveSecurity = async () => {
    // 兜底：任何一个数字项空着都不保存。绝不能让空值被当成 0 写进库
    // —— 0 在这些项上就是"关闭该保护"，静默关掉比报错危险得多。
    const blanks = blankSecurityFields(secPolicy)
    if (blanks.length) {
      setSecMsg(`有 ${blanks.length} 项没填：${blanks.map((b) => b.label).join('、')}。`
        + '要关闭某项请显式填 0，不要留空。')
      return
    }
    setSecSaving(true)
    setSecMsg('')
    try {
      const res = await fetch(`${API}/security/policy`, {
        method: 'PUT', headers: { ...headers, 'Content-Type': 'application/json' },
        body: JSON.stringify(secPolicy || {}),
      })
      if (!res.ok) { const e = await res.json(); throw new Error(e.detail || '保存失败') }
      setSecMsg('保存成功')
      loadSecurity()
      // 规则可能刚被改过：清掉缓存并重新取，否则"新增用户"那边还显示旧规则
      invalidatePasswordHint()
      loadPasswordHint().then((h) => { if (h) setPwdHint(h) })
    } catch (e) { setSecMsg(e.message) }
    setSecSaving(false)
    setTimeout(() => setSecMsg(''), 3000)
  }

  const loadRoles = async () => {
    // 后端按 roles_manage 权限点鉴权，无权限返回 403，这里静默置空即可
    try {
      const res = await fetch(`${API}/roles/`, { headers })
      if (res.ok) {
        const data = await res.json()
        setRoles(Array.isArray(data) ? data : [])
      }
    } catch { setRoles([]) }
  }

  const roleName = (code) => {
    const r = roles.find((x) => x.code === code)
    return r ? r.name : code
  }

  const closeAddUser = () => {
    setShowAddUser(false)
    setNewUser({ username: '', full_name: '', password: '', email: '', role: 'viewer', valid_until: '' })
    setUserError('')
  }

  const [configForm, setConfigForm] = useState({})
  const [configSub, setConfigSub] = useState('runtime')

  const [configSaving, setConfigSaving] = useState(false)
  const [configMsg, setConfigMsg] = useState('')

  const [emailCfg, setEmailCfg] = useState({ smtp_host: '', smtp_port: '465', smtp_user: '', smtp_pass: '', from_addr: '' })
  const [emailSaving, setEmailSaving] = useState(false)
  const [emailMsg, setEmailMsg] = useState('')

  const headers = authHeaders()

  const loadUsers = async () => {
    if (!isAdmin) { setUsers([]); return }
    try {
      const res = await fetch(`${API}/auth/users`, { headers })
      if (res.ok) {
        const data = await res.json()
        setUsers(Array.isArray(data) ? data : [])
      }
    } catch { setUsers([]) }
  }

  const loadConfig = async () => {
    try {
      const res = await fetch(`${API}/config/`, { headers })
      if (res.ok) {
        const data = await res.json()
        setConfig(data && typeof data === 'object' ? data : {})
        const form = {}
        Object.entries(data || {}).forEach(([k, v]) => { form[k] = v.value })
        setConfigForm(form)
      }
    } catch {}
  }

  const loadEmailCfg = async () => {
    try {
      const res = await fetch(`${API}/config/email`, { headers })
      if (res.ok) {
        const data = await res.json()
        if (data && typeof data === 'object') setEmailCfg(d => ({ ...d, ...data }))
      }
    } catch {}
  }

  useEffect(() => {
    setLoading(true)
    Promise.all([loadUsers(), loadConfig(), loadEmailCfg(), loadRoles(), loadSecurity(), loadTlsInfo()]).finally(() => setLoading(false))
    loadPasswordHint().then((h) => { if (h) setPwdHint(h) })
  }, [])

  const validateUser = (data, isEdit = false) => {
    if (!data.full_name || !data.full_name.trim()) return '用户姓名为必填项'
    if (!data.username || !data.username.trim()) return '登录名为必填项'
    if (!isEdit && (!data.password || !data.password.trim())) return '密码为必填项'
    if (data.email && !EMAIL_RE.test(data.email)) return '邮箱格式错误'
    return ''
  }

  const addUser = async () => {
    setUserError('')
    const err = validateUser(newUser)
    if (err) { setUserError(err); return }
    try {
      const res = await fetch(`${API}/auth/users`, {
        method: 'POST', headers: { ...headers, 'Content-Type': 'application/json' },
        body: JSON.stringify(newUser),
      })
      if (!res.ok) { const e = await res.json(); throw new Error(e.detail || '创建失败') }
      closeAddUser()
      loadUsers()
    } catch (e) { setUserError(e.message) }
  }

  const deleteUser = async (id) => {
    await fetch(`${API}/auth/users/${id}`, { method: 'DELETE', headers })
    setDeleteConfirmUser(null)
    loadUsers()
  }

  const openDeleteConfirm = (u) => setDeleteConfirmUser(u)
  const closeDeleteConfirm = () => setDeleteConfirmUser(null)

  const closeEditUser = () => {
    setEditingUser(null)
    setShowPwd(false)
    setEditForm({ username: '', full_name: '', password: '', email: '', role: 'viewer', status: 'active', valid_until: '' })
    setUserError('')
  }

  const saveUserEdit = async (id) => {
    setUserError('')
    const err = validateUser(editForm, true)
    if (err) { setUserError(err); return }
    const payload = { ...editForm }
    if (!payload.password || !payload.password.trim()) {
      delete payload.password
    }
    const res = await fetch(`${API}/auth/users/${id}`, {
      method: 'PUT', headers: { ...headers, 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    })
    if (!res.ok) {
      const e = await res.json().catch(() => ({}))
      setUserError(e.detail || '保存失败')
      return
    }
    closeEditUser()
    loadUsers()
  }

  const openEdit = (u) => {
    loadRoles()
    setEditingUser(u.id)
    setShowPwd(false)
    setEditForm({ username: u.username, full_name: u.full_name || '', password: '', email: u.email || '', role: u.role, status: u.status, valid_until: u.valid_until ? toLocalInput(u.valid_until) : '' })
  }

  const saveConfig = async () => {
    setConfigSaving(true)
    setConfigMsg('')
    try {
      const res = await fetch(`${API}/config/`, {
        method: 'PUT', headers: { ...headers, 'Content-Type': 'application/json' },
        body: JSON.stringify(configForm),
      })
      if (!res.ok) { const e = await res.json(); throw new Error(e.detail || '保存失败') }
      setConfigMsg('保存成功')
      loadConfig()
    } catch (e) { setConfigMsg(e.message) }
    setConfigSaving(false)
    setTimeout(() => setConfigMsg(''), 3000)
  }

  const saveEmailCfg = async () => {
    setEmailSaving(true)
    setEmailMsg('')
    try {
      const res = await fetch(`${API}/config/email`, {
        method: 'PUT', headers: { ...headers, 'Content-Type': 'application/json' },
        body: JSON.stringify(emailCfg),
      })
      if (!res.ok) { const e = await res.json(); throw new Error(e.detail || '保存失败') }
      setEmailMsg('保存成功')
    } catch (e) { setEmailMsg(e.message) }
    setEmailSaving(false)
    setTimeout(() => setEmailMsg(''), 3000)
  }

  const handleTestMail = async () => {
    setEmailSaving(true)
    setEmailMsg('')
    try {
      const res = await fetch(`${API}/config/email/test`, {
        method: 'POST', headers: { ...headers, 'Content-Type': 'application/json' },
      })
      if (!res.ok) { const e = await res.json(); throw new Error(e.detail || '发送失败') }
      const data = await res.json()
      setEmailMsg(data.message || '发送成功')
    } catch (e) { setEmailMsg(e.message) }
    setEmailSaving(false)
    setTimeout(() => setEmailMsg(''), 5000)
  }

  const intervalOptions = ['10', '15', '30', '60', '120', '300', '600']
  const thresholdOptions = ['50', '60', '70', '75', '80', '85', '90', '95', '98']
  const retentionOptions = ['30', '60', '90', '180']

  const alertConfigKeys = [
    'cpu_threshold_warning',
    'cpu_threshold_critical',
    'memory_threshold_warning',
    'memory_threshold_critical',
    'disk_threshold_warning',
    'disk_threshold_critical',
  ]

  if (loading) return <div className="page-loading">加载中...</div>

  return (
    <div className="settings-page">
      <div className="settings-tabs">
        {tabOps.security && (
          <button className={`stab pill ${tab === 'security' ? 'active' : ''}`} onClick={() => setTab('security')}>安全设置</button>
        )}
        {tabOps.roles && (
          <button className={`stab pill ${tab === 'roles' ? 'active' : ''}`} onClick={() => setTab('roles')}>角色管理</button>
        )}
        {tabOps.users && (
          <button className={`stab pill ${tab === 'users' ? 'active' : ''}`} onClick={() => setTab('users')}>用户管理</button>
        )}
        {tabOps.email && (
          <button className={`stab pill ${tab === 'email' ? 'active' : ''}`} onClick={() => setTab('email')}>邮件配置</button>
        )}
        {tabOps.config && (
          <button className={`stab pill ${tab === 'config' ? 'active' : ''}`} onClick={() => setTab('config')}>运行参数</button>
        )}
        {tabOps.alert && (
          <button className={`stab pill ${tab === 'alert' ? 'active' : ''}`} onClick={() => setTab('alert')}>告警配置</button>
        )}
      </div>

      {!firstTab && (
        <div className="no-access-page">
          <div className="no-access-icon"><Icon kind="ui-lock" size={32} /></div>
          <div className="no-access-text">当前角色没有系统设置里任何页面的操作权限</div>
        </div>
      )}

      {tab === 'security' && tabOps.security && (
        <div className="settings-panel">
          <div className="settings-panel-body">
          <div className="settings-section-header">
            <h3>安全策略</h3>
          </div>
          {secMsg && <div className="form-error" style={{ marginBottom: '10px' }}>{secMsg}</div>}
          {!secPolicy ? (
            <div className="page-loading">加载中...</div>
          ) : (
            <div className="sec-groups">
              {SECURITY_FIELDS.map((grp) => (
                <div className="sec-group" key={grp.group}>
                  <div className="sec-group-title">{grp.group}</div>
                  {grp.items.map((it) => (
                    <div className="sec-row" key={it.key}>
                      <span className="sec-label">{it.label}</span>
                      {it.type === 'bool' ? (
                        <label className="sec-switch">
                          <input type="checkbox" checked={!!secPolicy[it.key]}
                            onChange={(e) => setSecPolicy({ ...secPolicy, [it.key]: e.target.checked ? 1 : 0 })} />
                          <span>{secPolicy[it.key] ? '开启' : '关闭'}</span>
                        </label>
                      ) : (
                        <span className="sec-input">
                          {/* 别写 Number(e.target.value)：Number('') === 0，
 清空输入框想重输时会被静默存成 0 = 关闭该保护。
 空值保留空值，由上面的 blankSecurityFields 拦住保存。 */}
                          <input className={`form-input sec-num${isBlankNum(secPolicy[it.key]) ? ' sec-num-blank' : ''}`}
                            type="number" min={it.min} max={it.max}
                            value={secPolicy[it.key] ?? ''}
                            onChange={(e) => {
                              const raw = e.target.value
                              setSecPolicy({ ...secPolicy, [it.key]: raw === '' ? '' : Number(raw) })
                            }} />
                          <em className="sec-unit">{it.unit}</em>
                        </span>
                      )}
                      {isBlankNum(secPolicy[it.key]) && it.type !== 'bool' ? (
                        <span className="sec-hint sec-hint-blank">
                          不能留空{it.hint ? `（${it.hint}）` : ''}
                        </span>
                      ) : (it.hint && <span className="sec-hint">{it.hint}</span>)}
                    </div>
                  ))}
                </div>
              ))}
            </div>
          )}

          {/* 服务端证书：CA 指纹是 Agent 首次「信任服务端证书」时**人工核对**的依据。
 为什么要放在这里：每台服务端都在首次启动时自签一把本地 CA，Agent 安装包
 里预置的那把只对"打包那台机器"有效，换台机器部署就必然校验失败。所以
 Agent 侧改成从服务端取 CA 并让操作员核对指纹 —— 而核对的前提是这里
 能看见同一串指纹，否则那个确认框就是走过场。 */}
          <div className="settings-section-header" style={{ marginTop: 18 }}>
            <h3>服务端证书</h3>
          </div>
          {!tlsInfo ? (
            <div className="page-loading">加载中...</div>
          ) : (
            <div className="sec-groups">
              <div className="sec-group">
                <div className="sec-group-title">本地 CA（Agent 首次连接时要核对它）</div>
                <div className="sec-fp-label">SHA-256 指纹</div>
                <div className="sec-fp">{tlsInfo.ca_fingerprint || '—'}</div>
                <div className="sec-row">
                  <span className="sec-label">有效期至</span>
                  <span className="sec-value">
                    {tlsInfo.ca_not_after ? formatDateTime(tlsInfo.ca_not_after) : '—'}
                  </span>
                </div>
              </div>
              <div className="sec-group">
                <div className="sec-group-title">服务器证书</div>
                <div className="sec-row">
                  <span className="sec-label">包含地址（SAN）</span>
                  <span className="sec-value">{(tlsInfo.sans || []).join('、') || '—'}</span>
                </div>
                <div className="sec-row">
                  <span className="sec-label">有效期至</span>
                  <span className="sec-value">
                    {tlsInfo.not_after ? formatDateTime(tlsInfo.not_after) : '—'}
                  </span>
                </div>
              </div>
              <p className="sec-hint" style={{ margin: '0 0 4px' }}>
                Agent 首次连接本服务端时会显示它收到的 CA 指纹，请与上面这串逐段核对，一致再点「信任服务端证书」。
              </p>
            </div>
          )}
          </div>
          <div className="settings-panel-foot">
            <button className="btn-submit"
              disabled={secSaving || !secPolicy || blankSecurityFields(secPolicy).length > 0}
              onClick={saveSecurity}>
              {secSaving ? '保存中…' : '保存'}
            </button>
          </div>
        </div>
      )}

      {tab === 'roles' && tabOps.roles && <RoleManagement isAdmin={isAdmin} onRolesChanged={loadRoles} />}

      {tab === 'users' && tabOps.users && (
        <div className="settings-panel">
          <div className="settings-section-header">
            <h3>用户列表</h3>
            <button className="btn-add-user" onClick={() => { loadRoles(); setShowAddUser(true) }}>添加用户</button>
          </div>
          <div className="settings-panel-body">
          <table className="settings-table settings-table-fixed">
            <thead><tr>
              <th className="col-id">ID</th><th className="col-fullname">用户姓名</th><th className="col-user">登录名</th>
              <th className="col-mail">邮箱</th><th className="col-role">角色</th><th className="col-status">状态</th>
              <th className="col-time">有效期</th><th className="col-time">创建时间</th><th className="col-ops">操作</th>
            </tr></thead>
            <tbody>
              {users.map((u) => (
                <tr key={u.id}>
                  <td className="col-id">{u.id}</td>
                  <td className="col-fullname">{u.full_name || '—'}</td>
                  <td className="col-user">{u.username}</td>
                  <td className="col-mail">{u.email || '—'}</td>
                  <td className="col-role"><span className={`role-badge role-${u.role}`}>{u.role_name || roleName(u.role)}</span></td>
                  <td className="col-status"><span className={`status-badge status-${u.status}`}>{u.status === 'active' ? '正常' : '禁用'}</span></td>
                  <td className="col-time">{u.valid_until ? formatDateTime(u.valid_until) : '长期有效'}</td>
                  <td className="col-ops actions">
                    <button className="btn-sm btn-primary" onClick={() => openEdit(u)}>编辑</button>
                    {/* 判据用 id===1（与后端 delete/update 的默认管理员判据一致）：
 登录名可改之后，用名字判断会在改名后漏掉保护。 */}
                    {u.id !== 1 && (
                      <button className="btn-sm btn-danger" onClick={() => openDeleteConfirm(u)}>删除</button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          </div>

          <div className="settings-panel-foot">
            <span className="settings-count">共 {users.length} 个用户</span>
          </div>

          {showAddUser && (
            <div className="settings-modal-overlay" onClick={closeAddUser}>
              <div className="settings-modal" onClick={(e) => e.stopPropagation()}>
                <div className="settings-modal-header">
                  <h4>添加用户</h4>
                  <button className="settings-modal-close" onClick={closeAddUser} title="关闭">×</button>
                </div>
                <div className="settings-modal-body">
                  {userError && <div className="form-error" style={{ marginBottom: '12px' }}>{userError}</div>}
                  <div className="settings-form-group">
                    <label className="settings-form-label">用户姓名 <span className="required">*</span></label>
                    <input className="form-input" value={newUser.full_name} onChange={(e) => setNewUser({ ...newUser, full_name: e.target.value })}
                      placeholder="用户姓名" autoComplete="off" spellCheck="false" />
                  </div>
                  <div className="settings-form-group">
                    <label className="settings-form-label">登录名 <span className="required">*</span></label>
                    <input className="form-input" value={newUser.username} onChange={(e) => setNewUser({ ...newUser, username: e.target.value })}
                      placeholder="登录名" autoComplete="off" spellCheck="false" />
                  </div>
                  <div className="settings-form-group">
                    <label className="settings-form-label">密码 <span className="required">*</span></label>
                    <input className="form-input" type="password" value={newUser.password} onChange={(e) => setNewUser({ ...newUser, password: e.target.value })}
                      placeholder="密码" autoComplete="new-password" spellCheck="false" />
                    {pwdHint && <p className="pwd-rule-hint">密码规则：{pwdHint}</p>}
                  </div>
                  <div className="settings-form-group">
                    <label className="settings-form-label">邮箱</label>
                    <input className="form-input" value={newUser.email} onChange={(e) => setNewUser({ ...newUser, email: e.target.value })}
                      placeholder="邮箱（选填）" autoComplete="off" spellCheck="false" />
                  </div>
                  <div className="settings-form-group">
                    <label className="settings-form-label">角色 <span className="required">*</span></label>
                    <select className="form-input" value={newUser.role} onChange={(e) => setNewUser({ ...newUser, role: e.target.value })}>
                      {roles.map((r) => (
                        <option key={r.id} value={r.code}>{r.name}</option>
                      ))}
                    </select>
                  </div>
                  <div className="settings-form-group">
                    <label className="settings-form-label">账户有效期</label>
                    <div className="valid-until-cell">
                      <input className="form-input" type="date" value={newUser.valid_until || ''}
                        onChange={(e) => setNewUser({ ...newUser, valid_until: e.target.value })} />
                      <button type="button" className="btn-sm" onClick={() => setNewUser({ ...newUser, valid_until: '' })}
                        title="清空 = 长期有效">长期有效</button>
                    </div>
                    <span className="sec-hint">留空 = 长期有效；到期后该账号无法登录</span>
                  </div>
                </div>
                <div className="settings-modal-footer">
                  <button className="btn-cancel" onClick={closeAddUser}>取消</button>
                  <button className="btn-submit" onClick={addUser}>添加</button>
                </div>
              </div>
            </div>
          )}

          {editingUser && (
            <div className="settings-modal-overlay" onClick={closeEditUser}>
              <div className="settings-modal" onClick={(e) => e.stopPropagation()}>
                <div className="settings-modal-header">
                  <h4>编辑用户</h4>
                  <button className="settings-modal-close" onClick={closeEditUser} title="关闭">×</button>
                </div>
                <div className="settings-modal-body">
                  {userError && <div className="form-error" style={{ marginBottom: '12px' }}>{userError}</div>}
                  <div className="settings-form-group">
                    <label className="settings-form-label">用户姓名 <span className="required">*</span></label>
                    <input className="form-input" value={editForm.full_name} onChange={(e) => setEditForm({ ...editForm, full_name: e.target.value })}
                      placeholder="用户姓名" autoComplete="off" spellCheck="false" />
                  </div>
                  <div className="settings-form-group">
                    <label className="settings-form-label">登录名 <span className="required">*</span></label>
                    <input className="form-input" value={editForm.username}
                      onChange={(e) => setEditForm({ ...editForm, username: e.target.value })}
                      placeholder="登录名" autoComplete="off" spellCheck="false" />
                  </div>
                  <div className="settings-form-group">
                    <label className="settings-form-label">密码</label>
                    <div className="pwd-cell">
                      <input className="form-input" type={showPwd ? 'text' : 'password'} value={editForm.password}
                        onChange={(e) => setEditForm({ ...editForm, password: e.target.value })}
                        placeholder="留空表示不修改" autoComplete="new-password" spellCheck="false" />
                      <span className="pwd-toggle" onClick={() => setShowPwd(!showPwd)} title={showPwd ? '隐藏密码' : '显示密码'}>
                        {showPwd ? <Icon kind="ui-eye-off" size={13} /> : <Icon kind="ui-eye" size={13} />}
                      </span>
                    </div>
                    {pwdHint && <p className="pwd-rule-hint">密码规则：{pwdHint}</p>}
                  </div>
                  <div className="settings-form-group">
                    <label className="settings-form-label">邮箱</label>
                    <input className="form-input" value={editForm.email} onChange={(e) => setEditForm({ ...editForm, email: e.target.value })}
                      placeholder="邮箱（选填）" autoComplete="off" spellCheck="false" />
                  </div>
                  <div className="settings-form-group">
                    <label className="settings-form-label">角色 <span className="required">*</span></label>
                    {/* 系统默认用户（id===1，与后端 delete/update 的判据一致）的管理员
 角色不可改。判据必须用"被编辑的那条记录的 id"，不能用 editForm.username
 —— 登录名现在可改，边改边判断会让锁失效。 */}
                    <select className="form-input" value={editForm.role} disabled={editingUser === 1}
                      onChange={(e) => setEditForm({ ...editForm, role: e.target.value })}>
                      {roles.map((r) => (
                        <option key={r.id} value={r.code}>{r.name}</option>
                      ))}
                    </select>
                  </div>
                  <div className="settings-form-group">
                    <label className="settings-form-label">状态 <span className="required">*</span></label>
                    <select className="form-input" value={editForm.status} disabled={editingUser === 1}
                      onChange={(e) => setEditForm({ ...editForm, status: e.target.value })}>
                      <option value="active">正常</option>
                      <option value="disabled">禁用</option>
                    </select>
                  </div>
                  <div className="settings-form-group">
                    <label className="settings-form-label">账户有效期</label>
                    <div className="valid-until-cell">
                      <input className="form-input" type="date" value={editForm.valid_until || ''}
                        onChange={(e) => setEditForm({ ...editForm, valid_until: e.target.value })} />
                      <button type="button" className="btn-sm" onClick={() => setEditForm({ ...editForm, valid_until: '' })}
                        title="清空 = 长期有效">长期有效</button>
                    </div>
                    <span className="sec-hint">留空 = 长期有效（admin 默认长期有效）；到期后该账号无法登录</span>
                  </div>
                </div>
                <div className="settings-modal-footer">
                  <button className="btn-cancel" onClick={closeEditUser}>取消</button>
                  <button className="btn-submit" onClick={() => saveUserEdit(editingUser)}>保存</button>
                </div>
              </div>
            </div>
          )}

          {deleteConfirmUser && (
            <div className="settings-modal-overlay" onClick={closeDeleteConfirm}>
              <div className="settings-modal" onClick={(e) => e.stopPropagation()}>
                <div className="settings-modal-header">
                  <h4>确认删除</h4>
                  <button className="settings-modal-close" onClick={closeDeleteConfirm} title="关闭">×</button>
                </div>
                <div className="settings-modal-body">
                  <p style={{ margin: 0, fontSize: 14, color: '#333' }}>
                    确定要删除用户 <strong>{deleteConfirmUser.full_name || deleteConfirmUser.username}</strong>（登录名：{deleteConfirmUser.username}）吗？
                    <br /><span style={{ color: '#dc3545', fontSize: 13 }}>删除后不可恢复。</span>
                  </p>
                </div>
                <div className="settings-modal-footer">
                  <button className="btn-cancel" onClick={closeDeleteConfirm}>取消</button>
                  <button className="btn-sm btn-danger" onClick={() => deleteUser(deleteConfirmUser.id)}>删除</button>
                </div>
              </div>
            </div>
          )}
        </div>
      )}

      {tab === 'config' && tabOps.config && (
        <div className="settings-panel">
          {/* 二级页签：原来「运行参数」「设备准入」是两块带标题的列表，改成两个页签 */}
          <div className="settings-tabs settings-tabs-sub">
            <button className={`stab ${configSub === 'runtime' ? 'active' : ''}`} onClick={() => setConfigSub('runtime')}>运行参数</button>
            <button className={`stab ${configSub === 'access' ? 'active' : ''}`} onClick={() => setConfigSub('access')}>设备准入</button>
          </div>
          <div className="settings-panel-body">
          {configSub === 'runtime' && (
          <table className="settings-table">
            <thead><tr><th>配置项</th><th>当前值</th><th>修改</th><th>说明</th></tr></thead>
            <tbody>
              {RUNTIME_CONFIG_KEYS
                .filter((key) => config[key])
                .map((key) => {
                  const info = config[key]
                  return (
                    <tr key={key}>
                      <td>{key.replace(/_/g, ' ')}</td>
                      <td>
                        {key.includes('retention')
                          ? `${info.value} 天`
                          : `${info.value}${info.description.includes('%') ? '%' : ' 秒'}`}
                      </td>
                      <td>
                        <select className="form-input-sm" value={configForm[key] || info.value}
                          onChange={(e) => setConfigForm({ ...configForm, [key]: e.target.value })}>
                          {(info.description.includes('%') ? thresholdOptions
                            : key.includes('retention') ? retentionOptions
                            : intervalOptions).map((v) => (
                              <option key={v} value={v}>
                                {key.includes('retention') ? `${v} 天` : `${v}${info.description.includes('%') ? '%' : 's'}`}
                              </option>
                            ))}
                        </select>
                      </td>
                      <td>{info.description}</td>
                    </tr>
                  )
                })}
            </tbody>
          </table>
          )}

          {configSub === 'access' && (
          <>
          <table className="settings-table">
            <thead><tr><th>配置项</th><th>当前值</th><th>修改</th><th>说明</th></tr></thead>
            <tbody>
              <tr>
                <td>auto approve</td>
                <td>
                  <span className={config.auto_approve?.value === '1' ? 'settings-badge warn' : 'settings-badge'}>
                    {config.auto_approve?.value === '1' ? '自动批准' : '需人工审批'}
                  </span>
                </td>
                <td>
                  <select className="form-input-sm"
                    value={configForm.auto_approve || config.auto_approve?.value || '0'}
                    onChange={(e) => setConfigForm({ ...configForm, auto_approve: e.target.value })}>
                    <option value="0">0 — 需人工核对配对码</option>
                    <option value="1">1 — 直接发证</option>
                  </select>
                </td>
                <td>{config.auto_approve?.description}</td>
              </tr>
              <tr>
                <td>cert reclaim days</td>
                <td>
                  {config.cert_reclaim_days?.value === '0'
                    ? '已关闭'
                    : `${config.cert_reclaim_days?.value} 天`}
                </td>
                <td>
                  <select className="form-input-sm"
                    value={configForm.cert_reclaim_days || config.cert_reclaim_days?.value || '90'}
                    onChange={(e) => setConfigForm({ ...configForm, cert_reclaim_days: e.target.value })}>
                    <option value="0">0 — 关闭自动回收</option>
                    {['30', '60', '90', '180', '365'].map((v) => (
                      <option key={v} value={v}>{v} 天</option>
                    ))}
                  </select>
                </td>
                <td>{config.cert_reclaim_days?.description}</td>
              </tr>
            </tbody>
          </table>
          {(configForm.auto_approve ?? config.auto_approve?.value) === '1' && (
            <p className="settings-inline-warn">
              <Icon kind="ui-warning" size={13} /> 置 1 后，任何能连到本服务端的机器都会直接拿到证书、不再需要人工核对配对码。
              只在受控内网临时开启，用完请关回 0。被吊销过的设备不会因此自动恢复。
            </p>
          )}
          </>
          )}
          </div>
          <div className="settings-panel-foot" style={{ justifyContent: 'space-between' }}>
            <span className="settings-count">
              共 {configSub === 'runtime'
                ? RUNTIME_CONFIG_KEYS.filter((key) => config[key]).length
                : 2} 项
            </span>
            <div>
              {configMsg && <span style={{ marginRight: 12, fontSize: 13, color: configMsg.includes('成功') ? '#06d6a0' : '#dc3545' }}>{configMsg}</span>}
              <button className="btn-submit" onClick={saveConfig} disabled={configSaving}>
                {configSaving ? '保存中…' : '保存配置'}
              </button>
            </div>
          </div>
        </div>
      )}

      {tab === 'email' && tabOps.email && (
        <div className="settings-panel">
          <div className="settings-panel-body">
          <h3>邮件配置</h3>
          <p style={{ fontSize: 13, color: '#495057', marginBottom: 16 }}>配置 SMTP 服务器信息后，系统可在产生告警时向指定邮箱发送通知。</p>
          <div className="email-config-form">
            <div className="form-group">
              <label className="form-label">SMTP 服务器地址</label>
              <input className="form-input" value={emailCfg.smtp_host} onChange={(e) => setEmailCfg({ ...emailCfg, smtp_host: e.target.value })}
                placeholder="smtp.example.com" />
            </div>
            <div className="form-row">
              <div className="form-group flex-1">
                <label className="form-label">端口号</label>
                <input className="form-input" value={emailCfg.smtp_port} onChange={(e) => setEmailCfg({ ...emailCfg, smtp_port: e.target.value })}
                  placeholder="465" />
              </div>
              <div className="form-group flex-1">
                <label className="form-label">加密方式</label>
                <select className="form-select" value={emailCfg.encryption || 'ssl'} onChange={(e) => setEmailCfg({ ...emailCfg, encryption: e.target.value })}>
                  <option value="ssl">SSL</option>
                  <option value="tls">TLS / STARTTLS</option>
                  <option value="none">无</option>
                </select>
              </div>
            </div>
            <div className="form-group">
              <label className="form-label">发件人邮箱地址</label>
              <input className="form-input" value={emailCfg.from_addr} onChange={(e) => setEmailCfg({ ...emailCfg, from_addr: e.target.value })}
                placeholder="alert@example.com" />
            </div>
            <div className="form-row">
              <div className="form-group flex-1">
                <label className="form-label">SMTP 用户名</label>
                <input className="form-input" value={emailCfg.smtp_user} onChange={(e) => setEmailCfg({ ...emailCfg, smtp_user: e.target.value })}
                  placeholder="用户名" autoComplete="off" />
              </div>
              <div className="form-group flex-1">
                <label className="form-label">SMTP 密码</label>
                <input className="form-input" type="password" value={emailCfg.smtp_pass} onChange={(e) => setEmailCfg({ ...emailCfg, smtp_pass: e.target.value })}
                  placeholder="密码" autoComplete="new-password" />
              </div>
            </div>
          <p style={{ fontSize: 12, color: '#6c757d', marginTop: 4, marginBottom: 0 }}>
            收件人将自动使用"用户管理"中所有已填写邮箱的用户地址。
          </p>
          </div>
          <div style={{ textAlign: 'right', marginTop: 16 }}>
            {emailMsg && <span style={{ marginRight: 12, fontSize: 13, color: emailMsg.includes('成功') ? '#06d6a0' : '#dc3545' }}>{emailMsg}</span>}
            <button className="btn-cancel" onClick={handleTestMail} disabled={emailSaving} style={{ marginRight: 8 }}>
              {emailSaving ? '发送中…' : '发送测试'}
            </button>
            <button className="btn-submit" onClick={saveEmailCfg} disabled={emailSaving}>
              {emailSaving ? '保存中…' : '保存配置'}
            </button>
          </div>
          </div>
        </div>
      )}

      {tab === 'alert' && tabOps.alert && (
        <div className="settings-panel">
          <h3>告警配置</h3>
          <div className="settings-panel-body">
          <table className="settings-table">
            <thead><tr><th>配置项</th><th>当前值</th><th>修改</th><th>说明</th></tr></thead>
            <tbody>
              {Object.entries(config)
                .filter(([key]) => alertConfigKeys.includes(key))
                .map(([key, info]) => (
                  <tr key={key}>
                    <td>{key.replace(/_/g, ' ')}</td>
                    <td>{info.value}%</td>
                    <td>
                      <select className="form-input-sm" value={configForm[key] || info.value}
                        onChange={(e) => setConfigForm({ ...configForm, [key]: e.target.value })}>
                        {thresholdOptions.map((v) => (
                          <option key={v} value={v}>{v}%</option>
                        ))}
                      </select>
                    </td>
                    <td>{info.description}</td>
                  </tr>
                ))}
            </tbody>
          </table>
          </div>
          <div className="settings-panel-foot" style={{ justifyContent: 'space-between' }}>
            <span className="settings-count">共 {Object.keys(config).filter((key) => alertConfigKeys.includes(key)).length} 项</span>
            <div>
              {configMsg && <span style={{ marginRight: 12, fontSize: 13, color: configMsg.includes('成功') ? '#06d6a0' : '#dc3545' }}>{configMsg}</span>}
              <button className="btn-submit" onClick={saveConfig} disabled={configSaving}>
                {configSaving ? '保存中…' : '保存配置'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}