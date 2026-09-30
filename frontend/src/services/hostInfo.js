import { authHeaders } from './auth'
import { mockHostInfo, mockApplications, mockUpdates, mockEventLogs, mockStartup } from './hostInfoMock'

/**
 * 主机信息 / 应用管理 / 事件日志 数据层。
 *
 * USE_MOCK = false —— 后端（routes/host_info.py）+ Agent（host_info.py）已落地，
 * 走真实接口。需要离线演示时把下面的开关改回 true 即可切回 Mock。
 * 端点约定：
 *   GET  /api/servers/{id}/system-info      -> mockHostInfo() 的结构
 *   GET  /api/servers/{id}/applications     -> { items: [...] }  （含 scope/uninstallable/uninstall_cmd）
 *   GET  /api/servers/{id}/applications/updates -> { items: [...] }
 *   POST /api/servers/{id}/applications/uninstall  body: { ids: [...] } -> { ok, results: [...] }
 *   GET  /api/servers/{id}/event-logs?level=&limit= -> { items: [...] }  系统事件日志
 *   GET  /api/servers/{id}/startup                 -> { items: [...] }  系统启动项（含 id/enabled）
 *   POST /api/servers/{id}/startup/{item_id}/toggle  body: { enabled: bool } -> { ok, enabled }
 */
export const USE_MOCK = false

const API = '/api'

/**
 * 「系统应用」判定：只有**操作系统自带 / 运行时 / 驱动 / 补丁**才算系统应用。
 *
 * 之前只按注册表位置（HKLM → system）划分，导致 360压缩、Adobe Acrobat、RustDesk、
 * ToDesk、Node.js、WPS、酷狗音乐、多可档案这些第三方软件被错分到系统应用。
 * 规则（命中任一即系统应用）：
 *   1. Agent 已给出 is_system 时直接采信（Agent 能读到 SystemComponent 等标志）
 *   2. 补丁类：KB + 数字、Update for / 安全更新 / 累积更新 / Hotfix / Service Pack
 *   3. 微软运行时与系统组件：VC++ 可再发行组件、.NET、Windows Desktop Runtime、
 *      ASP.NET、Edge / Edge Update / WebView2、Update Health Tools、Windows 开头且
 *      属于系统组件（安装助手、电脑健康状况检查、SDK、Defender 等）
 *   4. 安装位置在系统目录（C:\Windows\...）
 *   5. 驱动/系统工具：名称含 Driver 且安装在 system32\spool\drivers 或 DriverStore
 *
 * 注意：Microsoft Office / Adobe / 各类第三方软件一律算**用户应用**。
 */
const SYS_PATTERNS = [
  /^kb\d+/i,
  /\b(hotfix|service pack)\b/i,
  /^(security update|update for|累积更新|安全更新)/i,
  /^microsoft (visual c\+\+|visual basic|visual studio)/i,
  /^microsoft (\.net|asp\.net)/i,
  /^microsoft windows desktop runtime/i,
  /^microsoft (edge|update health)/i,
  /^microsoft (silverlight|xna|sql server (?!\d)|web deploy)/i,
  /^windows (sdk|defender|malicious|malware)/i,
  /^windows (安装助手|电脑健康状况检查|更新)/i,
  /^windows (11|10)/i,
  /^windows driver package/i,
]

const SYS_LOC_PATTERNS = [
  /^[a-z]:\\windows\\/i,
  /\\windows\\system32\\spool\\drivers/i,
  /\\windows\\system32\\driverstore/i,
]

export function isSystemApp(app) {
  if (!app) return false
  if (typeof app.is_system === 'boolean') return app.is_system
  const name = String(app.name || '').trim()
  const loc = String(app.install_location || '').replace(/\//g, '\\')
  if (!name) return false
  if (SYS_PATTERNS.some((re) => re.test(name))) return true
  if (loc && SYS_LOC_PATTERNS.some((re) => re.test(loc))) return true
  if (/driver/i.test(name) && SYS_LOC_PATTERNS.some((re) => re.test(loc))) return true
  return false
}

async function getJson(url) {
  const res = await fetch(url, { headers: authHeaders() })
  if (!res.ok) {
    const e = await res.json().catch(() => ({}))
    throw new Error(e.detail || `请求失败 (${res.status})`)
  }
  return res.json()
}

async function postJson(url, body) {
  const res = await fetch(url, {
    method: 'POST',
    headers: { ...authHeaders(), 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })
  if (!res.ok) {
    const e = await res.json().catch(() => ({}))
    throw new Error(e.detail || `请求失败 (${res.status})`)
  }
  return res.json()
}

export async function fetchHostInfo(serverId, serverName) {
  if (USE_MOCK) return mockHostInfo(serverName)
  return getJson(`${API}/servers/${serverId}/system-info`)
}

export async function fetchApplications(serverId) {
  if (USE_MOCK) {
    const data = await mockApplications()
    return Array.isArray(data) ? data : []
  }
  const d = await getJson(`${API}/servers/${serverId}/applications`)
  return d.items || []
}

export async function fetchSystemUpdates(serverId) {
  if (USE_MOCK) {
    const data = await mockUpdates()
    return Array.isArray(data) ? data : []
  }
  const d = await getJson(`${API}/servers/${serverId}/applications/updates`)
  return d.items || []
}

/**
 * 按需采集（Pull）：点「刷新」时不再让 HTTP 请求干等一轮 WMI（应用列表能到几十秒），
 * 而是让服务端把采集丢进线程池，这里拿 task_id 轮询，采完再回来拉缓存。
 *
 * kind: system-info / applications / app-updates
 */
export async function triggerHostInfoRefresh(serverId, kind) {
  if (USE_MOCK) return { ok: true, task_id: null }
  return postJson(`${API}/servers/${serverId}/host-info/refresh?kind=${encodeURIComponent(kind)}`, {})
}

export async function waitHostInfoTask(serverId, taskId, opts = {}) {
  const { timeoutMs = 180000, intervalMs = 1500 } = opts
  if (!taskId) return
  const deadline = Date.now() + timeoutMs
  // eslint-disable-next-line no-constant-condition
  while (true) {
    const t = await getJson(`${API}/servers/${serverId}/host-info/task/${taskId}`)
    if (t.status === 'done') return
    if (t.status === 'error') throw new Error(t.error || '采集失败')
    if (Date.now() > deadline) throw new Error('采集超时，请稍后重试')
    await new Promise((r) => setTimeout(r, intervalMs))
  }
}

/** 依次触发多个采集项并等它们跑完（串行提交，别把 Agent 打爆）。 */
export async function refreshHostInfo(serverId, kinds) {
  if (USE_MOCK) return
  for (const kind of kinds) {
    const { task_id } = await triggerHostInfoRefresh(serverId, kind)
    await waitHostInfoTask(serverId, task_id)
  }
}

export async function uninstallApplications(serverId, ids) {
  if (USE_MOCK) {
    return { ok: true, results: ids.map((id) => ({ id, ok: true, message: '卸载指令已下发（模拟）' })) }
  }
  return postJson(`${API}/servers/${serverId}/applications/uninstall`, { ids })
}

export async function fetchStartupItems(serverId) {
  if (USE_MOCK) return mockStartup()
  const d = await getJson(`${API}/servers/${serverId}/startup`)
  return d.items || []
}

export async function toggleStartupItem(serverId, itemId, enabled) {
  if (USE_MOCK) return { ok: true, enabled }
  return postJson(`${API}/servers/${serverId}/startup/${encodeURIComponent(itemId)}/toggle`, { enabled })
}

export async function fetchHostEventLogs(serverId, params = {}) {
  if (USE_MOCK) {
    const items = await mockEventLogs()
    return items.filter((i) => !params.level || params.level === 'all' || i.level === params.level)
  }
  const qs = new URLSearchParams()
  Object.entries(params).forEach(([k, v]) => { if (v != null && v !== '') qs.append(k, v) })
  const d = await getJson(`${API}/servers/${serverId}/event-logs?${qs.toString()}`)
  return d.items || []
}
