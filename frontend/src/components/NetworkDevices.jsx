/* 方案 B：设备管理 →「网络设备」页签
 *
 * 网络设备（交换机 / 路由器 / 防火墙 / 存储）装不上 Agent，接入方式跟主机完全不同：
 * 主机 = 装 Agent → 上报注册 → 管理员审批
 * 设备 = 管理员填 IP + SNMPv3 凭据 → 服务端试连 → 通了才入库
 *
 * 所以这里是独立的一套列表 + 新增弹窗，但仍然落在 servers 表里（device_kind=network），
 * 仪表盘 / 告警 / 分组 / 审计全部复用主机那套，不另起炉灶。 */
import { useCallback, useEffect, useState } from 'react'
import { parseServerTime } from '../utils/format'
import {
  fetchNetworkDevices,
  probeNetworkDevice,
  createNetworkDevice,
  connectNetworkDevice,
  disconnectNetworkDevice,
  deleteServer,
  fetchServerDetail,
  updateServer,
  testNetworkCli,
} from '../services/api'
import { usePerm } from '../services/permissions'
import { showToast } from '../utils/toast'
import Icon from './AppIcon'
import './NetworkDevices.css'

const CATEGORY_LABELS = {
  switch: '交换机',
  router: '路由器',
  firewall: '防火墙',
  ap: '无线 AP',
  storage: '存储 / NAS',
  server: '服务器',
  other: '其他设备',
}

const SECURITY_LEVELS = [
  { value: 'authPriv', label: 'authPriv（鉴权 + 加密）' },
  { value: 'authNoPriv', label: 'authNoPriv（只鉴权）' },
  { value: 'noAuthNoPriv', label: 'noAuthNoPriv（都不做，不建议）' },
]

const AUTH_PROTOS = ['SHA', 'SHA224', 'SHA256', 'SHA384', 'SHA512', 'MD5']

// 两个都放在下拉里会让人以为是强度不同的两种算法。这里只留 AES128；库里已经存进去的
const PRIV_PROTOS = ['AES128', 'AES192', 'AES256', 'DES', '3DES']

function normPrivProto(v) {
  const s = String(v || '').toUpperCase()
  return s === 'AES' ? 'AES128' : (s || 'AES128')
}

/* UDP 端口的即时提示：只做提醒，不拦保存 —— 有些环境确实改过端口。
 * 返回 '' 表示没问题（标准 161）。 */
function snmpPortHint(port) {
  const n = Number(port)
  if (!n || n < 1 || n > 65535) return '需在 1 ~ 65535 之间'
  if (n === 161) return ''
  // 162 是最容易填错的一个：它是服务端**接收** trap 的端口，不是查询端口
  if (n === 162) return '162 是 trap 接收端口，采集填它会连不上（标准是 161）'
  return '标准是 161，改过请确认与设备端一致'
}

/** UDP 端口输入框 —— 新增 / 编辑两个弹窗共用，顺便把上面的提示带上 */
function SnmpPortField({ value, onChange }) {
  const hint = snmpPortHint(value)
  return (
    <label className="nd-field">
      <span className="nd-label">
        UDP 端口{hint ? <span className="nd-hint nd-hint-warn">{hint}</span> : null}
      </span>
      <input
        className="nd-input"
        type="number"
        value={value}
        onChange={(e) => onChange(e.target.value)}
      />
    </label>
  )
}

const CLI_PROTOCOLS = [
  { value: 'ssh', label: 'SSH' },
  { value: 'telnet', label: 'Telnet（明文，仅在设备只支持它时用）' },
]

// WEB 管理入口（详情页「WEB管理」页签）：设备自带界面的协议与端口
const WEB_PROTOCOLS = [
  { value: 'https', label: 'HTTPS（设备多为自签名证书，由服务端代接受）' },
  { value: 'http', label: 'HTTP' },
]

const CATEGORY_OPTIONS = [
  { value: '', label: '（保持自动识别结果）' },
  { value: 'switch', label: '交换机' },
  { value: 'router', label: '路由器' },
  { value: 'firewall', label: '防火墙' },
  { value: 'ap', label: '无线 AP' },
  { value: 'storage', label: '存储 / NAS' },
  { value: 'server', label: '服务器' },
  { value: 'other', label: '其他设备' },
]

const MASK = '******'

const EMPTY_SNMP = {
  snmp_port: 161,
  snmp_username: '',
  snmp_security_level: 'authPriv',
  snmp_auth_proto: 'SHA',
  snmp_priv_proto: 'AES128',
  snmp_context: '',
  snmp_auth_password: '',
  snmp_priv_password: '',
}

const EMPTY_WEB = {
  web_protocol: 'https',
  web_port: 443,
}

function fmtMinute(iso) {
  if (!iso) return '-'
  const d = parseServerTime(iso)
  if (Number.isNaN(d.getTime())) return '-'
  const p = (n) => String(n).padStart(2, '0')
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`
}

function fmtUptime(sec) {
  const s = Number(sec) || 0
  if (s <= 0) return '—'
  const d = Math.floor(s / 86400)
  const h = Math.floor((s % 86400) / 3600)
  const m = Math.floor((s % 3600) / 60)
  const parts = []
  if (d) parts.push(`${d} 天`)
  if (h || d) parts.push(`${h} 小时`)
  parts.push(`${m} 分钟`)
  return parts.join(' ')
}

/** 状态语义：断开是管理员主动停采集，离线是采不到 —— 两件事得分开显示 */
function StatusCell({ device }) {
  if (device.status === 'disconnected') {
    return <span className="nd-pill nd-pill-off" title="管理员已断开采集，不再纳入监控">已断开</span>
  }
  if (device.is_online) {
    return <span className="nd-pill nd-pill-on">在线</span>
  }
  return (
    <span
      className="nd-pill nd-pill-err"
      title={device.last_collect_error ? `最近一次采集失败：${device.last_collect_error}` : '超过采集周期未返回数据'}
    >
      离线
    </span>
  )
}

function AddDeviceModal({ visible, onClose, onCreated }) {
  const [form, setForm] = useState({ name: '', ip_address: '', description: '', ...EMPTY_SNMP, ...EMPTY_WEB })
  const [busy, setBusy] = useState('')
  const [result, setResult] = useState(null)
  const [showAuthPwd, setShowAuthPwd] = useState(false)
  const [showPrivPwd, setShowPrivPwd] = useState(false)

  useEffect(() => {
    if (visible) {
      setForm({ name: '', ip_address: '', description: '', ...EMPTY_SNMP, ...EMPTY_WEB })
      setResult(null)
      setBusy('')
      // 重新打开时收回明文 —— 上一次看的明文不该留在屏上
      setShowAuthPwd(false)
      setShowPrivPwd(false)
    }
  }, [visible])

  if (!visible) return null

  const setField = (k, v) => {
    setForm((prev) => ({ ...prev, [k]: v }))
    // 改了凭据就把上一次的测试结果作废 —— 它已经不能代表当前填的值了
    if (k.startsWith('snmp_') || k === 'ip_address') setResult(null)
  }

  const needAuth = form.snmp_security_level !== 'noAuthNoPriv'
  const needPriv = form.snmp_security_level === 'authPriv'

  const onTest = async () => {
    if (!form.ip_address.trim()) return showToast('请先填写设备 IP', 'error')
    setBusy('test')
    setResult(null)
    try {
      const res = await probeNetworkDevice({
        ip_address: form.ip_address.trim(),
        snmp: {
          snmp_port: Number(form.snmp_port) || 161,
          snmp_username: form.snmp_username,
          snmp_security_level: form.snmp_security_level,
          snmp_auth_proto: form.snmp_auth_proto,
          snmp_priv_proto: form.snmp_priv_proto,
          snmp_context: form.snmp_context,
          snmp_auth_password: form.snmp_auth_password,
          snmp_priv_password: form.snmp_priv_password,
        },
      })
      setResult(res)
      if (res.ok) {
        showToast(`连接成功：${res.sys_name || res.category_label || '设备'}`, 'success')
      } else {
        showToast(`连接失败：${res.error || '未知错误'}`, 'error')
      }
    } catch (e) {
      showToast(e.message || '测试连接失败', 'error')
    } finally {
      setBusy('')
    }
  }

  const onSave = async () => {
    if (!form.ip_address.trim()) return showToast('请填写设备 IP', 'error')
    if (!form.snmp_username.trim()) return showToast('请填写 SNMPv3 用户名', 'error')
    const _webPort = Number(form.web_port) || 443
    if (!(_webPort >= 1 && _webPort <= 65535)) return showToast('WEB 管理端口需在 1 ~ 65535 之间', 'error')
    setBusy('save')
    try {
      const res = await createNetworkDevice({
        ip_address: form.ip_address.trim(),
        name: form.name.trim(),
        description: form.description.trim(),
        snmp: {
          snmp_port: Number(form.snmp_port) || 161,
          snmp_username: form.snmp_username,
          snmp_security_level: form.snmp_security_level,
          snmp_auth_proto: form.snmp_auth_proto,
          snmp_priv_proto: form.snmp_priv_proto,
          snmp_context: form.snmp_context,
          snmp_auth_password: form.snmp_auth_password,
          snmp_priv_password: form.snmp_priv_password,
        },
        // WEB 管理入口：地址固定是设备 IP，这里只落协议和端口
        web: {
          web_protocol: form.web_protocol,
          web_port: Number(form.web_port) || 443,
        },
      })
      showToast(`已新增设备「${res.name}」，识别为 ${CATEGORY_LABELS[res.device_category] || '其他设备'}`, 'success')
      onCreated && onCreated()
      onClose()
    } catch (e) {
      showToast(e.message || '新增设备失败', 'error')
    } finally {
      setBusy('')
    }
  }

  return (
    // 点遮罩不关窗：表单里填的是一堆凭据，误点一下把十分钟敲的东西丢了比
    // 多点一次「取消/×」代价大得多。关闭只走右上 × 和底部按钮。
    <div className="nd-modal-mask">
      <div className="nd-modal">
        <header className="nd-modal-head">
          <span className="nd-modal-title">新增网络设备</span>
          <button className="nd-modal-close" onClick={onClose} title="关闭">×</button>
        </header>

        <div className="nd-modal-body">
          <div className="nd-form">
            <label className="nd-field">
              <span className="nd-label">设备 IP <b>*</b></span>
              <input
                className="nd-input"
                value={form.ip_address}
                placeholder="如 192.168.1.1"
                onChange={(e) => setField('ip_address', e.target.value)}
              />
            </label>

            <label className="nd-field">
              <span className="nd-label">设备名称<span className="nd-hint">留空自动生成</span></span>
              <input
                className="nd-input"
                value={form.name}
                placeholder="如 办公区接入交换机"
                onChange={(e) => setField('name', e.target.value)}
              />
            </label>

            {/* 备注（2026-09-22 补上）：以前「新增设备」压根没有备注输入框
 （form 和提交里一直有 description 字段，但 UI 缺这一行），
 建好之后想写备注只能再去编辑。现在与「编辑设备」一致 —— 多行文本。 */}
            <label className="nd-field nd-field-wide">
              <span className="nd-label">备注</span>
              <textarea
                className="nd-input nd-textarea"
                value={form.description}
                placeholder="如 三楼办公区接入"
                rows={3}
                onChange={(e) => setField('description', e.target.value)}
              />
            </label>

            <label className="nd-field">
              <span className="nd-label">SNMPv3 用户名 <b>*</b></span>
              <input
                className="nd-input"
                value={form.snmp_username}
                placeholder="如 snmpuser"
                onChange={(e) => setField('snmp_username', e.target.value)}
              />
            </label>

            <label className="nd-field">
              <span className="nd-label">安全级别</span>
              <select
                className="nd-input"
                value={form.snmp_security_level}
                onChange={(e) => setField('snmp_security_level', e.target.value)}
              >
                {SECURITY_LEVELS.map((s) => <option key={s.value} value={s.value}>{s.label}</option>)}
              </select>
            </label>

            <label className="nd-field">
              <span className="nd-label">鉴权协议</span>
              <select
                className="nd-input"
                value={form.snmp_auth_proto}
                disabled={!needAuth}
                onChange={(e) => setField('snmp_auth_proto', e.target.value)}
              >
                {AUTH_PROTOS.map((p) => <option key={p} value={p}>{p}</option>)}
              </select>
            </label>

            <label className="nd-field">
              <span className="nd-label">鉴权口令</span>
              <span className="nd-pwd-wrap">
                <input
                  className="nd-input"
                  type={showAuthPwd ? 'text' : 'password'}
                  autoComplete="new-password"
                  value={form.snmp_auth_password}
                  disabled={!needAuth}
                  onChange={(e) => setField('snmp_auth_password', e.target.value)}
                />
                {/* 两个口令框都包在 `<label>` 里 —— 点按钮会连带触发 label 的默认行为
 （把焦点转给输入框）。这里 preventDefault 掐掉，让"点眼睛"只做显隐。 */}
                <button
                  type="button"
                  className="nd-pwd-toggle"
                  disabled={!needAuth}
                  onClick={(e) => { e.preventDefault(); setShowAuthPwd((v) => !v) }}
                  title={showAuthPwd ? '隐藏明文' : '显示明文'}
                  aria-label={showAuthPwd ? '隐藏鉴权口令明文' : '显示鉴权口令明文'}
                >
                  {showAuthPwd ? <Icon kind="ui-eye-off" size={15} /> : <Icon kind="ui-eye" size={15} />}
                </button>
              </span>
            </label>

            <label className="nd-field">
              <span className="nd-label">加密协议</span>
              <select
                className="nd-input"
                value={form.snmp_priv_proto}
                disabled={!needPriv}
                onChange={(e) => setField('snmp_priv_proto', e.target.value)}
              >
                {PRIV_PROTOS.map((p) => <option key={p} value={p}>{p}</option>)}
              </select>
            </label>

            <label className="nd-field">
              <span className="nd-label">加密口令</span>
              <span className="nd-pwd-wrap">
                <input
                  className="nd-input"
                  type={showPrivPwd ? 'text' : 'password'}
                  autoComplete="new-password"
                  value={form.snmp_priv_password}
                  disabled={!needPriv}
                  onChange={(e) => setField('snmp_priv_password', e.target.value)}
                />
                <button
                  type="button"
                  className="nd-pwd-toggle"
                  disabled={!needPriv}
                  onClick={(e) => { e.preventDefault(); setShowPrivPwd((v) => !v) }}
                  title={showPrivPwd ? '隐藏明文' : '显示明文'}
                  aria-label={showPrivPwd ? '隐藏加密口令明文' : '显示加密口令明文'}
                >
                  {showPrivPwd ? <Icon kind="ui-eye-off" size={15} /> : <Icon kind="ui-eye" size={15} />}
                </button>
              </span>
            </label>

            <SnmpPortField
              value={form.snmp_port}
              onChange={(v) => setField('snmp_port', v)}
            />

            <label className="nd-field">
              <span className="nd-label">上下文名<span className="nd-hint">多数留空</span></span>
              <input
                className="nd-input"
                value={form.snmp_context}
                placeholder="Cisco 的 vlan-&lt;id&gt; / VRF 填这里"
                onChange={(e) => setField('snmp_context', e.target.value)}
              />
            </label>

            <label className="nd-field">
              <span className="nd-label">WEB 管理协议<span className="nd-hint">详情页「WEB管理」页签用</span></span>
              <select
                className="nd-input"
                value={form.web_protocol}
                onChange={(e) => setField('web_protocol', e.target.value)}
              >
                {WEB_PROTOCOLS.map((p) => <option key={p.value} value={p.value}>{p.label}</option>)}
              </select>
            </label>

            <label className="nd-field">
              <span className="nd-label">WEB 管理端口<span className="nd-hint">地址用设备 IP</span></span>
              <input
                className="nd-input"
                type="number"
                value={form.web_port}
                onChange={(e) => setField('web_port', e.target.value)}
              />
            </label>
          </div>

          {result && (
            <div className={`nd-probe ${result.ok ? 'ok' : 'fail'}`}>
              {result.ok ? (
                <>
                  <div className="nd-probe-title">
                    连接成功 —— 识别为
                    <b> {result.vendor ? `${result.vendor} ` : ''}{result.category_label || '其他设备'}</b>
                    {result.model ? <span className="nd-probe-model">{result.model}</span> : null}
                  </div>
                  <table className="nd-kv">
                    <tbody>
                      <tr><th>设备名</th><td>{result.sys_name || '—'}</td></tr>
                      <tr><th>位置</th><td>{result.sys_location || '—'}</td></tr>
                      <tr><th>运行时长</th><td>{fmtUptime(result.uptime)}</td></tr>
                      <tr><th>端口数</th><td>{result.interface_count}</td></tr>
                      <tr>
                        <th>CPU / 内存</th>
                        <td>
                          {result.cpu_percent == null ? '设备未提供' : `${result.cpu_percent}%`}
                          {' / '}
                          {result.memory_percent == null ? '设备未提供' : `${result.memory_percent}%`}
                        </td>
                      </tr>
                      <tr><th>设备描述</th><td className="nd-mono">{result.sys_descr || '—'}</td></tr>
                    </tbody>
                  </table>
                </>
              ) : (
                <div className="nd-probe-title">
                  连接失败：<span className="nd-mono">{result.error || '未知错误'}</span>
                  {/* 这段"常见原因"**只在设备根本没响应时才成立**。设备已经明确
 回了错（用户名不存在 / 鉴权失败 / 设备回了 errorStatus…）时
 还挂着它，等于把人往网络方向带 —— 2026-09-30 现场就是这么被
 带偏的（真正的原因在设备回的状态码里，却去查了防火墙）。
 归属由后端的 error_kind 判定，界面不猜文案：
 见 services/snmp_collector.py 的 error_kind()。 */}
                  {result.error_kind === 'no-response' && (
                    <div className="nd-probe-hint">
                      常见原因：IP 不通 / UDP 161 被防火墙或设备 ACL 挡了 / 设备没开 SNMP /
                      源 IP 被设备的登录限流临时锁了。少数设备在凭据不符时也会静默丢包，
                      可以再对照设备侧的 SNMP 配置核一遍用户名与协议。
                    </div>
                  )}
                </div>
              )}
            </div>
          )}

        </div>

        <footer className="nd-modal-foot">
          <button className="nd-btn" onClick={onTest} disabled={!!busy}>
            {busy === 'test' ? '测试中…' : '测试连接'}
          </button>
          <span className="nd-spacer" />
          <button className="nd-btn" onClick={onClose} disabled={!!busy}>取消</button>
          <button className="nd-btn nd-btn-primary" onClick={onSave} disabled={!!busy}>
            {busy === 'save' ? '保存中…' : '保存'}
          </button>
        </footer>
      </div>
    </div>
  )
}

/** 编辑设备：连接信息（SNMPv3 采集凭据 + 命令行凭据）都在这里维护。
 *
 * 「网络」页签删掉之后，这是唯一能改 SNMP 凭据的地方 —— 详情页只负责展示设备
 * 长什么样、跑得怎么样，不再夹带配置。
 *
 * 2026-09-22 起**导出**给设备详情页复用：详情页头部那个编辑图标点开的就是它
 *（`ServerDetail.jsx` 里网络设备走这条，主机走 `ServerFormModal`）。
 * 它自己不依赖列表页数据 —— 内部按 `device.id` 重新 `fetchServerDetail`。
 */
export function EditDeviceModal({ device, onClose, onSaved }) {
  const [form, setForm] = useState(null)
  const [busy, setBusy] = useState('')
  const [probe, setProbe] = useState(null)
  const [cliProbe, setCliProbe] = useState(null)

  useEffect(() => {
    let alive = true
    setBusy('')
    setProbe(null)
    setCliProbe(null)
    ;(async () => {
      try {
        const d = await fetchServerDetail(device.id)
        if (!alive) return
        const snmp = d.snmp || {}
        const cli = d.cli || {}
        const web = d.web || {}
        setForm({
          name: d.name || '',
          ip_address: d.ip_address || '',
          description: d.description || '',
          device_vendor: d.device_vendor || '',
          device_model: d.device_model || '',
          device_category: d.device_category || '',
          snmp_port: snmp.port || 161,
          snmp_username: snmp.username || '',
          snmp_security_level: snmp.security_level || 'authPriv',
          snmp_auth_proto: snmp.auth_proto || 'SHA',
          snmp_priv_proto: normPrivProto(snmp.priv_proto),
          snmp_context: snmp.context || '',
          snmp_auth_password: '',
          snmp_priv_password: '',
          has_auth_password: !!snmp.has_auth_password,
          has_priv_password: !!snmp.has_priv_password,
          cli_protocol: cli.protocol || 'ssh',
          cli_port: cli.port || 22,
          cli_username: cli.username || '',
          cli_password: '',
          cli_enable_password: '',
          has_cli_password: !!cli.has_password,
          has_cli_enable_password: !!cli.has_enable_password,
          web_protocol: web.protocol || 'https',
          web_port: web.port || 443,
          // WEB 管理账号口令自动填充：回显的口令一律是掩码，编辑框先空着（留空 = 不修改）
          web_auto_login: !!web.auto_login,
          web_username: web.username || '',
          web_password: '',
          has_web_password: !!web.has_password,
          // 厂商认不出来就不提供自动填充（后端只给认得的厂商做适配器）
          web_auto_login_supported: web.auto_login_supported !== false,
        })
      } catch (e) {
        showToast(e.message || '读取设备配置失败', 'error')
        onClose()
      }
    })()
    return () => { alive = false }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [device.id])

  if (!form) {
    return (
      <div className="nd-modal-mask">
        <div className="nd-modal"><div className="nd-modal-body nd-modal-loading">读取设备配置…</div></div>
      </div>
    )
  }

  const setField = (k, v) => {
    setForm((prev) => ({ ...prev, [k]: v }))
    // 改了凭据就把上一次的测试结果作废 —— 它已经不能代表当前填的值了
    if (k.startsWith('snmp_') || k === 'ip_address') setProbe(null)
    if (k.startsWith('cli_') || k === 'ip_address') setCliProbe(null)
  }

  const needAuth = form.snmp_security_level !== 'noAuthNoPriv'
  const needPriv = form.snmp_security_level === 'authPriv'

  const onTestSnmp = async () => {
    setBusy('snmp')
    setProbe(null)
    try {
      const res = await probeNetworkDevice({
        // 带上 server_id：这条探测记录才能挂到该设备的「事件日志」上
        server_id: device.id,
        ip_address: form.ip_address.trim(),
        snmp: {
          snmp_port: Number(form.snmp_port) || 161,
          snmp_username: form.snmp_username,
          snmp_security_level: form.snmp_security_level,
          snmp_auth_proto: form.snmp_auth_proto,
          snmp_priv_proto: form.snmp_priv_proto,
          snmp_context: form.snmp_context,
          // 没改就留空：后端拿不到新口令，会自动回退到库里已存的那份
          snmp_auth_password: form.snmp_auth_password,
          snmp_priv_password: form.snmp_priv_password,
        },
      })
      setProbe(res)
      showToast(res.ok ? `采集连接成功：${res.sys_name || res.category_label || '设备'}` : `采集连接失败：${res.error || '未知错误'}`,
        res.ok ? 'success' : 'error')
    } catch (e) {
      showToast(e.message || '测试连接失败', 'error')
    } finally {
      setBusy('')
    }
  }

  const onTestCli = async () => {
    if (!form.cli_username.trim()) return showToast('请先填写命令行登录用户名', 'error')
    setBusy('cli')
    setCliProbe(null)
    try {
      const res = await testNetworkCli(device.id, {
        ip_address: form.ip_address.trim(),
        cli_protocol: form.cli_protocol,
        cli_port: Number(form.cli_port) || 22,
        cli_username: form.cli_username,
        cli_password: form.cli_password,
        cli_enable_password: form.cli_enable_password,
      })
      setCliProbe(res)
      showToast(res.ok ? `命令行连接成功：${res.target || ''}` : `命令行连接失败：${res.error || '未知错误'}`,
        res.ok ? 'success' : 'error')
    } catch (e) {
      showToast(e.message || '测试命令行连接失败', 'error')
    } finally {
      setBusy('')
    }
  }

  const onSave = async () => {
    if (!form.ip_address.trim()) return showToast('请填写设备 IP', 'error')
    if (!form.snmp_username.trim()) return showToast('请填写 SNMPv3 用户名', 'error')
    const _webPort = Number(form.web_port) || 443
    if (!(_webPort >= 1 && _webPort <= 65535)) return showToast('WEB 管理端口需在 1 ~ 65535 之间', 'error')
    setBusy('save')
    try {
      const payload = {
        name: form.name.trim(),
        ip_address: form.ip_address.trim(),
        description: form.description.trim(),
        device_vendor: form.device_vendor.trim(),
        device_model: form.device_model.trim(),
        snmp_port: Number(form.snmp_port) || 161,
        snmp_username: form.snmp_username,
        snmp_security_level: form.snmp_security_level,
        snmp_auth_proto: form.snmp_auth_proto,
        snmp_priv_proto: form.snmp_priv_proto,
        snmp_context: form.snmp_context,
        cli_protocol: form.cli_protocol,
        cli_port: Number(form.cli_port) || 22,
        cli_username: form.cli_username,
        web_protocol: form.web_protocol,
        web_port: Number(form.web_port) || 443,
        web_auto_login: form.web_auto_login ? 1 : 0,
        web_username: form.web_username.trim(),
      }
      // 设备类型留空 = 保持自动识别结果，不要把它写成 ''
      if (form.device_category) payload.device_category = form.device_category
      if (form.snmp_auth_password) payload.snmp_auth_password = form.snmp_auth_password
      if (form.snmp_priv_password) payload.snmp_priv_password = form.snmp_priv_password
      if (form.cli_password) payload.cli_password = form.cli_password
      if (form.cli_enable_password) payload.cli_enable_password = form.cli_enable_password
      if (form.web_password) payload.web_password = form.web_password

      await updateServer(device.id, payload)
      showToast('已保存设备连接信息', 'success')
      onSaved && onSaved()
      onClose()
    } catch (e) {
      showToast(e.message || '保存失败', 'error')
    } finally {
      setBusy('')
    }
  }

  return (
    // 同上：编辑弹窗字段更多，点遮罩更不能关
    <div className="nd-modal-mask">
      <div className="nd-modal nd-modal-wide">
        <header className="nd-modal-head">
          <span className="nd-modal-title">编辑设备 — {device.name}</span>
          <button className="nd-modal-close" onClick={onClose} title="关闭">×</button>
        </header>

        <div className="nd-modal-body">
          <div className="nd-subhead">基本信息</div>
          <div className="nd-form">
            <label className="nd-field">
              <span className="nd-label">设备 IP <b>*</b></span>
              <input className="nd-input" value={form.ip_address}
                onChange={(e) => setField('ip_address', e.target.value)} />
            </label>
            <label className="nd-field">
              <span className="nd-label">设备名称 <b>*</b></span>
              <input className="nd-input" value={form.name}
                onChange={(e) => setField('name', e.target.value)} />
            </label>
            {/* 备注改成多行文本（2026-09-22）：设备备注常常要写几行
 （安装位置 / 上行口 / 联系人 / 开通时间），单行输入框装不下也看不全 */}
            <label className="nd-field nd-field-wide">
              <span className="nd-label">备注</span>
              <textarea
                className="nd-input nd-textarea"
                value={form.description}
                placeholder="如 三楼办公区接入"
                rows={3}
                onChange={(e) => setField('description', e.target.value)}
              />
            </label>
            <label className="nd-field">
              <span className="nd-label">厂商</span>
              <input className="nd-input" value={form.device_vendor}
                onChange={(e) => setField('device_vendor', e.target.value)} />
            </label>
            <label className="nd-field">
              <span className="nd-label">型号</span>
              <input className="nd-input" value={form.device_model}
                onChange={(e) => setField('device_model', e.target.value)} />
            </label>
            <label className="nd-field">
              <span className="nd-label">设备类型</span>
              <select className="nd-input" value={form.device_category}
                onChange={(e) => setField('device_category', e.target.value)}>
                {CATEGORY_OPTIONS.map((c) => <option key={c.value} value={c.value}>{c.label}</option>)}
              </select>
            </label>
          </div>

          <div className="nd-subhead">
            SNMP 采集凭据
          </div>
          <div className="nd-form">
            <label className="nd-field">
              <span className="nd-label">SNMPv3 用户名 <b>*</b></span>
              <input className="nd-input" value={form.snmp_username}
                onChange={(e) => setField('snmp_username', e.target.value)} />
            </label>
            <label className="nd-field">
              <span className="nd-label">安全级别</span>
              <select className="nd-input" value={form.snmp_security_level}
                onChange={(e) => setField('snmp_security_level', e.target.value)}>
                {SECURITY_LEVELS.map((s) => <option key={s.value} value={s.value}>{s.label}</option>)}
              </select>
            </label>
            <label className="nd-field">
              <span className="nd-label">鉴权协议</span>
              <select className="nd-input" value={form.snmp_auth_proto} disabled={!needAuth}
                onChange={(e) => setField('snmp_auth_proto', e.target.value)}>
                {AUTH_PROTOS.map((p) => <option key={p} value={p}>{p}</option>)}
              </select>
            </label>
            <label className="nd-field">
              <span className="nd-label">
                鉴权口令{form.has_auth_password && <span className="nd-hint">已保存，留空则不修改</span>}
              </span>
              <input className="nd-input" type="password" autoComplete="new-password"
                value={form.snmp_auth_password} disabled={!needAuth}
                onChange={(e) => setField('snmp_auth_password', e.target.value)} />
            </label>
            <label className="nd-field">
              <span className="nd-label">加密协议</span>
              <select className="nd-input" value={form.snmp_priv_proto} disabled={!needPriv}
                onChange={(e) => setField('snmp_priv_proto', e.target.value)}>
                {PRIV_PROTOS.map((p) => <option key={p} value={p}>{p}</option>)}
              </select>
            </label>
            <label className="nd-field">
              <span className="nd-label">
                加密口令{form.has_priv_password && <span className="nd-hint">已保存，留空则不修改</span>}
              </span>
              <input className="nd-input" type="password" autoComplete="new-password"
                value={form.snmp_priv_password} disabled={!needPriv}
                onChange={(e) => setField('snmp_priv_password', e.target.value)} />
            </label>
            <SnmpPortField
              value={form.snmp_port}
              onChange={(v) => setField('snmp_port', v)}
            />
            <label className="nd-field">
              <span className="nd-label">上下文名<span className="nd-hint">多数留空</span></span>
              <input className="nd-input" value={form.snmp_context}
                placeholder="Cisco 的 vlan-&lt;id&gt; / VRF 填这里"
                onChange={(e) => setField('snmp_context', e.target.value)} />
            </label>
          </div>
          <div className="nd-inline-test">
            <button className="nd-btn" onClick={onTestSnmp} disabled={!!busy}>
              {busy === 'snmp' ? '测试中…' : '测试采集连接'}
            </button>
          </div>
          {probe && (
            <div className={`nd-probe ${probe.ok ? 'ok' : 'fail'}`}>
              {probe.ok ? (
                <div className="nd-probe-title">
                  采集连接成功 —— 识别为
                  <b> {probe.vendor ? `${probe.vendor} ` : ''}{probe.category_label || '其他设备'}</b>
                  {probe.model ? <span className="nd-probe-model">{probe.model}</span> : null}
                  <span className="nd-probe-model">{probe.interface_count} 个端口</span>
                </div>
              ) : (
                <div className="nd-probe-title">
                  采集连接失败：<span className="nd-mono">{probe.error || '未知错误'}</span>
                </div>
              )}
            </div>
          )}

          <div className="nd-subhead">
            命令行凭据（WEB终端）
          </div>
          <div className="nd-form">
            <label className="nd-field">
              <span className="nd-label">协议</span>
              <select className="nd-input" value={form.cli_protocol}
                onChange={(e) => setField('cli_protocol', e.target.value)}>
                {CLI_PROTOCOLS.map((p) => <option key={p.value} value={p.value}>{p.label}</option>)}
              </select>
            </label>
            <label className="nd-field">
              <span className="nd-label">端口</span>
              <input className="nd-input" type="number" value={form.cli_port}
                onChange={(e) => setField('cli_port', e.target.value)} />
            </label>
            <label className="nd-field">
              <span className="nd-label">登录用户名</span>
              <input className="nd-input" value={form.cli_username}
                placeholder="设备上的 SSH/Telnet 账号"
                onChange={(e) => setField('cli_username', e.target.value)} />
            </label>
            <label className="nd-field">
              <span className="nd-label">
                登录口令{form.has_cli_password && <span className="nd-hint">已保存，留空则不修改</span>}
              </span>
              <input className="nd-input" type="password" autoComplete="new-password"
                value={form.cli_password}
                onChange={(e) => setField('cli_password', e.target.value)} />
            </label>
            <label className="nd-field">
              <span className="nd-label">
                特权口令<span className="nd-hint">Cisco enable / 华为 super，多数留空</span>
              </span>
              <input className="nd-input" type="password" autoComplete="new-password"
                value={form.cli_enable_password}
                onChange={(e) => setField('cli_enable_password', e.target.value)} />
            </label>
          </div>
          <div className="nd-inline-test">
            <button className="nd-btn" onClick={onTestCli} disabled={!!busy}>
              {busy === 'cli' ? '测试中…' : '测试命令行连接'}
            </button>
          </div>
          {cliProbe && (
            <div className={`nd-probe ${cliProbe.ok ? 'ok' : 'fail'}`}>
              {cliProbe.ok ? (
                <>
                  <div className="nd-probe-title">命令行连接成功：<b>{cliProbe.target}</b></div>
                  {cliProbe.banner ? (
                    <pre className="nd-banner">{cliProbe.banner}</pre>
                  ) : null}
                </>
              ) : (
                <div className="nd-probe-title">
                  命令行连接失败：<span className="nd-mono">{cliProbe.error || '未知错误'}</span>
                  <div className="nd-probe-hint">
                    常见原因：设备没开 SSH/Telnet 服务、端口不对、用户名或口令不对、
                    服务端到设备的 TCP 23/22 被防火墙挡了。
                  </div>
                </div>
              )}
            </div>
          )}

          <div className="nd-subhead">
            WEB 管理入口
            <span className="nd-subhead-note">用于详情页「WEB管理」页签代理打开设备自带的管理界面</span>
          </div>
          <div className="nd-form">
            <label className="nd-field">
              <span className="nd-label">协议</span>
              <select className="nd-input" value={form.web_protocol}
                onChange={(e) => setField('web_protocol', e.target.value)}>
                {WEB_PROTOCOLS.map((p) => <option key={p.value} value={p.value}>{p.label}</option>)}
              </select>
            </label>
            <label className="nd-field">
              <span className="nd-label">端口</span>
              <input className="nd-input" type="number" value={form.web_port}
                onChange={(e) => setField('web_port', e.target.value)} />
            </label>
            <label className="nd-field">
              <span className="nd-label">管理地址</span>
              <input className="nd-input" value={form.ip_address} disabled />
            </label>
          </div>

          <div className="nd-subhead">
            自动填充账号口令
          </div>
          {!form.web_auto_login_supported && (
            <div className="nd-probe-hint" style={{ marginBottom: 8 }}>
              这台设备的厂商（{form.device_vendor || '未识别'}）暂不支持自动填充，可先在「资产信息」里把厂商改正。
            </div>
          )}
          <div className="nd-form">
            <label className="nd-field">
              <span className="nd-label">登录账号</span>
              <input className="nd-input"
                placeholder="设备 WEB 界面的用户名"
                autoComplete="off"
                disabled={!form.web_auto_login_supported}
                value={form.web_username}
                onChange={(e) => setField('web_username', e.target.value)} />
            </label>
            <label className="nd-field">
              <span className="nd-label">
                登录口令{form.has_web_password && <span className="nd-hint">已保存，留空则不修改</span>}
              </span>
              <input className="nd-input" type="password"
                placeholder={form.has_web_password ? '留空则沿用已保存的口令' : ''}
                autoComplete="new-password"
                disabled={!form.web_auto_login_supported}
                value={form.web_password}
                onChange={(e) => setField('web_password', e.target.value)} />
            </label>
            <label className="nd-field nd-field-switch">
              <input type="checkbox"
                disabled={!form.web_auto_login_supported}
                checked={form.web_auto_login}
                onChange={(e) => setField('web_auto_login', e.target.checked)} />
              <span>打开「WEB管理」时自动填写账号口令</span>
            </label>
          </div>
          {/* 2026-09-22：这里原本还有一段 WEB 自动填充的长说明（勾选后出现），
 用户要求删掉 —— 开关下面只剩「打开「WEB管理」时自动填写账号口令」这一句，
 行为没变，仍是只填不提交。 */}
        </div>

        <footer className="nd-modal-foot">
          <span className="nd-spacer" />
          <button className="nd-btn" onClick={onClose} disabled={busy === 'save'}>取消</button>
          <button className="nd-btn nd-btn-primary" onClick={onSave} disabled={!!busy}>
            {busy === 'save' ? '保存中…' : '保存'}
          </button>
        </footer>
      </div>
    </div>
  )
}

export default function NetworkDevicesTab({ onServersChanged }) {
  const { can } = usePerm()
  const canView = can('sys', 'network_devices', 'view')
  const canAdd = can('sys', 'network_devices', 'edit', 'add')
  const canEdit = can('sys', 'network_devices', 'edit', 'edit')
  const canConnect = can('sys', 'network_devices', 'edit', 'connect')
  const canCollect = can('sys', 'network_devices', 'edit', 'collect')
  const canDelete = can('sys', 'network_devices', 'edit', 'delete')

  const [devices, setDevices] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [filter, setFilter] = useState('all')
  const [showAdd, setShowAdd] = useState(false)
  const [editTarget, setEditTarget] = useState(null)
  const [busyId, setBusyId] = useState(0)

  const load = useCallback(async () => {
    setLoading(true)
    setError('')
    try {
      setDevices(await fetchNetworkDevices())
    } catch (e) {
      setError(e.message || '加载失败')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { if (canView) load() }, [canView, load])

  const list = devices.filter((d) => {
    if (filter === 'connected') return d.status !== 'disconnected'
    if (filter === 'disconnected') return d.status === 'disconnected'
    return true
  })

  const onConnect = async (d) => {
    setBusyId(d.id)
    try {
      const res = await connectNetworkDevice(d.id)
      showToast(res.ok ? `已连接「${d.name}」` : `已连接但采集失败：${res.error || '未知错误'}`,
        res.ok ? 'success' : 'error')
      load()
      onServersChanged && onServersChanged()
    } catch (e) {
      showToast(e.message || '连接失败', 'error')
    } finally {
      setBusyId(0)
    }
  }

  const onDisconnect = async (d) => {
    if (!window.confirm(
      `确定断开「${d.name}」？\n\n· 立即停止 SNMP 采集，并从侧边栏设备列表移除；\n` +
      '· 设备档案、凭据、分组与历史数据都保留，之后可再点「连接」恢复。'
    )) return
    setBusyId(d.id)
    try {
      await disconnectNetworkDevice(d.id)
      showToast(`已断开「${d.name}」`, 'success')
      load()
      onServersChanged && onServersChanged()
    } catch (e) {
      showToast(e.message || '断开失败', 'error')
    } finally {
      setBusyId(0)
    }
  }

  const onDelete = async (d) => {
    if (!window.confirm(
      `确定删除「${d.name}」？\n\n这会连同它的端口表、指标与设备档案一并删除，且不可恢复。\n` +
      '如果只是想暂时停采集，请用「断开」。'
    )) return
    setBusyId(d.id)
    try {
      await deleteServer(d.id)
      showToast(`已删除「${d.name}」`, 'success')
      load()
      onServersChanged && onServersChanged()
    } catch (e) {
      showToast(e.message || '删除失败', 'error')
    } finally {
      setBusyId(0)
    }
  }

  if (!canView) {
    return <div className="reg-empty">当前角色没有「网络设备」查看权限</div>
  }

  const filterBtn = (key, label) => (
    <button
      key={key}
      className={`reg-filter-btn ${filter === key ? 'active' : ''}`}
      onClick={() => setFilter(key)}
    >{label}</button>
  )

  return (
    <div className="reg-section">
      <div className="reg-section-header">
        <h3 className="reg-section-title">网络设备列表</h3>
        <div className="reg-header-actions">
          <div className="reg-filter-group">
            {filterBtn('all', '全部')}
            {filterBtn('connected', '已连接')}
            {filterBtn('disconnected', '已断开')}
          </div>
          {canAdd && (
            <button className="reg-btn-add" onClick={() => setShowAdd(true)}>新增设备</button>
          )}
          <button className="reg-refresh-btn" onClick={load} title="刷新列表">刷新</button>
        </div>
      </div>

      {error && <div className="agent-update-error">{error}</div>}

      {loading ? (
        <div className="reg-loading">加载中…</div>
      ) : list.length === 0 ? (
        <p className="reg-empty">
          暂无网络设备。点右上角「新增设备」，填 IP + SNMPv3 凭据即可接入（设备端无需安装任何软件）。
        </p>
      ) : (
        <div className="host-list-table-wrap">
          <table className="host-list-table">
            <thead>
              <tr>
                <th>设备名称</th>
                <th>IP 地址</th>
                <th>类型</th>
                <th>厂商 / 型号</th>
                <th>状态</th>
                <th>端口</th>
                <th>最后采集</th>
                <th>操作</th>
              </tr>
            </thead>
            <tbody>
              {list.map((d) => (
                <tr key={d.id}>
                  <td className="host-name">{d.name}</td>
                  <td>{d.ip_address}</td>
                  <td>{CATEGORY_LABELS[d.device_category] || '其他设备'}</td>
                  <td className="nd-vendor">
                    {[d.device_vendor, d.device_model].filter(Boolean).join(' ') || '—'}
                  </td>
                  <td><StatusCell device={d} /></td>
                  <td className="nd-num">{d.interface_count || 0}</td>
                  <td title={d.last_collect_error || ''}>{fmtMinute(d.last_collect_at)}</td>
                  <td className="host-actions">
                    {canEdit && (
                      <button
                        className="reg-btn-edit"
                        disabled={busyId === d.id}
                        onClick={() => setEditTarget(d)}
                        title="修改 IP / 名称 / SNMP 凭据 / 命令行凭据"
                      >编辑</button>
                    )}
                    {d.status === 'disconnected' ? (
                      canConnect && (
                        <button
                          className="reg-btn-add"
                          disabled={busyId === d.id}
                          onClick={() => onConnect(d)}
                        >连接</button>
                      )
                    ) : (
                      canConnect && (
                        <button
                          className="reg-btn-remove"
                          disabled={busyId === d.id}
                          onClick={() => onDisconnect(d)}
                        >断开</button>
                      )
                    )}
                    {canCollect && d.status !== 'disconnected' && (
                      <button
                        className="reg-btn-edit"
                        disabled={busyId === d.id}
                        onClick={() => onConnect(d)}
                        title="重新连接并立刻采集一次"
                      >立即采集</button>
                    )}
                    {canDelete && (
                      <button
                        className="reg-btn-remove"
                        disabled={busyId === d.id}
                        onClick={() => onDelete(d)}
                      >删除</button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <div className="reg-panel-foot">
        <span className="reg-count">共 {list.length} 台设备</span>
        <span className="nd-foot-note">
          在线判定 = 采集周期 × 2.5（当前 {devices[0] ? devices[0].collect_period_sec : 300} 秒一轮）
        </span>
      </div>

      {showAdd && (
        <AddDeviceModal
          visible={showAdd}
          onClose={() => setShowAdd(false)}
          onCreated={() => { load(); onServersChanged && onServersChanged() }}
        />
      )}

      {editTarget && (
        <EditDeviceModal
          device={editTarget}
          onClose={() => setEditTarget(null)}
          onSaved={() => { load(); onServersChanged && onServersChanged() }}
        />
      )}
    </div>
  )
}
