import { authHeaders } from './auth';

const API_BASE = '/api';

function withAuth(headers = {}) {
  return { ...authHeaders(), ...headers };
}

export async function fetchDashboard() {
  const res = await fetch(`${API_BASE}/dashboard/`, { headers: withAuth() });
  if (!res.ok) throw new Error('Failed to fetch dashboard');
  return res.json();
}

export async function fetchUserPreferences() {
  const res = await fetch(`${API_BASE}/auth/preferences`, { headers: withAuth() });
  if (!res.ok) throw new Error('Failed to fetch preferences');
  return res.json();
}

export async function updateUserPreferences(preferences) {
  const res = await fetch(`${API_BASE}/auth/preferences`, {
    method: 'PUT',
    headers: { ...authHeaders(), 'Content-Type': 'application/json' },
    body: JSON.stringify(preferences),
  });
  if (!res.ok) throw new Error('Failed to update preferences');
  return res.json();
}

export async function fetchServers() {
  const res = await fetch(`${API_BASE}/servers/`, { headers: withAuth() });
  if (!res.ok) throw new Error('Failed to fetch servers');
  return res.json();
}

export async function fetchAllServers() {
  const res = await fetch(`${API_BASE}/servers/?include_pending=true`, { headers: withAuth() });
  if (!res.ok) throw new Error('Failed to fetch servers');
  return res.json();
}

export async function fetchServerDetail(id) {
  const res = await fetch(`${API_BASE}/servers/${id}`, { headers: withAuth() });
  if (!res.ok) throw new Error('Server not found');
  return res.json();
}

export async function fetchServerMetrics(id) {
  const res = await fetch(`${API_BASE}/servers/${id}/metrics`, { headers: withAuth() })
  if (!res.ok) throw new Error('Failed to fetch server metrics')
  return res.json()
}

export async function fetchServerServices(id) {
  const res = await fetch(`${API_BASE}/servers/${id}/services`, { headers: withAuth() })
  if (!res.ok) throw new Error('Failed to fetch server services')
  return res.json()
}

export async function fetchPendingServices(id) {
  const res = await fetch(`${API_BASE}/servers/${id}/pending-services`, { headers: withAuth() });
  if (!res.ok) throw new Error('Failed to fetch pending services');
  return res.json();
}

export async function fetchAgentCommands(id) {
  const res = await fetch(`${API_BASE}/servers/${id}/agent-commands`, { headers: withAuth() });
  if (!res.ok) throw new Error('Failed to fetch agent commands');
  return res.json();
}

export async function fetchAlertLogs(params = {}) {
  const qs = new URLSearchParams();
  Object.entries(params).forEach(([k, v]) => { if (v != null && v !== '') qs.append(k, v); });
  const res = await fetch(`${API_BASE}/logs/alerts?${qs.toString()}`, { headers: withAuth() });
  if (!res.ok) throw new Error('Failed to fetch alert logs');
  return res.json();
}

export async function fetchOperationLogs(params = {}) {
  const qs = new URLSearchParams();
  Object.entries(params).forEach(([k, v]) => { if (v != null && v !== '') qs.append(k, v); });
  const res = await fetch(`${API_BASE}/logs/operations?${qs.toString()}`, { headers: withAuth() });
  if (!res.ok) throw new Error('Failed to fetch operation logs');
  return res.json();
}

export async function fetchLogContext(type, id, params = {}) {
  const qs = new URLSearchParams();
  Object.entries(params).forEach(([k, v]) => { if (v != null && v !== '') qs.append(k, v); });
  const res = await fetch(`${API_BASE}/logs/${type}/${id}/context?${qs.toString()}`, { headers: withAuth() });
  if (!res.ok) throw new Error('Failed to fetch log context');
  return res.json();
}

export async function clearLogs(type, params = {}) {
  const qs = new URLSearchParams();
  Object.entries(params).forEach(([k, v]) => { if (v != null && v !== '') qs.append(k, v); });
  const res = await fetch(`${API_BASE}/logs/${type}/clear?${qs.toString()}`, {
    method: 'DELETE',
    headers: withAuth({ 'Content-Type': 'application/json' }),
    body: JSON.stringify(params),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || '清除失败');
  }
  return res.json();
}

export async function exportLogsExcel(type, params = {}) {
  const qs = new URLSearchParams();
  Object.entries(params).forEach(([k, v]) => { if (v != null && v !== '') qs.append(k, v); });
  const res = await fetch(`${API_BASE}/logs/${type}/export?${qs.toString()}`, { headers: withAuth() });
  if (!res.ok) throw new Error('导出失败');
  const blob = await res.blob();
  const disposition = res.headers.get('content-disposition') || ''
  const filenameStar = disposition.match(/filename\*=UTF-8''([^;]+)/)?.[1]
  const filename = filenameStar
    ? decodeURIComponent(filenameStar)
    : (disposition.match(/filename="?([^";]+)"?/)?.[1] || `${type}_logs.xlsx`)
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

export async function fetchMetricHistory(id, range = '1h', start = null, end = null) {
  let url = `${API_BASE}/metrics/${id}/history?range=${range}`;
  if (range === 'custom' && start && end) {
    url += `&start=${encodeURIComponent(start)}&end=${encodeURIComponent(end)}`;
  }
  const res = await fetch(url, { headers: withAuth() });
  if (!res.ok) throw new Error('Failed to fetch history');
  return res.json();
}

export async function createServer(data) {
  const res = await fetch(`${API_BASE}/servers/`, {
    method: 'POST',
    headers: withAuth({ 'Content-Type': 'application/json' }),
    body: JSON.stringify(data),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    const msg = typeof err.detail === 'string'
      ? err.detail
      : Array.isArray(err.detail)
        ? err.detail.map((d) => `${(d.loc || []).join('.')}: ${d.msg}`).join('; ')
        : '创建失败';
    throw new Error(msg);
  }
  return res.json();
}

export async function updateServer(id, data) {
  const res = await fetch(`${API_BASE}/servers/${id}`, {
    method: 'PUT',
    headers: withAuth({ 'Content-Type': 'application/json' }),
    body: JSON.stringify(data),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    const msg = typeof err.detail === 'string'
      ? err.detail
      : Array.isArray(err.detail)
        ? err.detail.map((d) => `${(d.loc || []).join('.')}: ${d.msg}`).join('; ')
        : '更新失败';
    throw new Error(msg);
  }
  return res.json();
}

export async function deleteServer(id) {
  const res = await fetch(`${API_BASE}/servers/${id}`, { method: 'DELETE', headers: withAuth() });
  if (!res.ok) {
    // 2026-09-22：后端删除有条件保护（在管 / Agent 在线），把拒绝原因带上来
    let msg = '删除失败';
    try {
      const d = await res.json();
      if (d && d.detail) msg = d.detail;
    } catch { }
    throw new Error(msg);
  }
  return res.json();
}

export async function updateServerStatus(id, data) {
  const res = await fetch(`${API_BASE}/servers/${id}/status`, {
    method: 'PUT',
    headers: withAuth({ 'Content-Type': 'application/json' }),
    body: JSON.stringify(data),
  })
  if (!res.ok) throw new Error('更新失败')
  return res.json()
}

export async function acknowledgeAlerts(serverId) {
  const res = await fetch(`${API_BASE}/servers/${serverId}/acknowledge-alerts`, { method: 'PUT', headers: withAuth() });
  return res.json();
}

// 吊销该主机的设备身份（已登记公钥作废）。重新接入须先「移出管理」再「加入管理」。
export async function revokeAgentCert(serverId) {
  const res = await fetch(`${API_BASE}/servers/${serverId}/revoke-cert`, {
    method: 'POST',
    headers: withAuth(),
  });
  if (!res.ok) throw new Error('吊销失败');
  return res.json();
}

// 2026-09-23 开源加固 ⑤：轮换该主机的静态 Agent token。
// 返回 { status, prev_valid_until, grace_seconds } —— 注意**不含**新 token：
// 新 token 只给那台 Agent 自己（它在下一次心跳里领取），不落进浏览器。
export async function rotateAgentToken(serverId) {
  const res = await fetch(`${API_BASE}/servers/${serverId}/rotate-agent-token`, {
    method: 'POST',
    headers: withAuth(),
  });
  if (!res.ok) {
    let msg = '轮换失败';
    try {
      const d = await res.json();
      if (d && d.detail) msg = d.detail;
    } catch (e) { }
    throw new Error(msg);
  }
  return res.json();
}

// 2026-09-23：重新登记该主机的 Agent 完整性基线。
// 用在"指纹变了但这变化是我们自己造成的"场合（同版本号重打包、Agent 侧修 bug 重发），
// 否则服务端会一直记「疑似被改造」告警。清掉基线后，下次心跳把当前指纹记为新基线。
export async function resetAgentBaseline(serverId) {
  const res = await fetch(`${API_BASE}/servers/${serverId}/reset-agent-baseline`, {
    method: 'POST',
    headers: withAuth(),
  });
  if (!res.ok) {
    let msg = '重新登记失败';
    try {
      const d = await res.json();
      if (d && d.detail) msg = d.detail;
    } catch (e) { }
    throw new Error(msg);
  }
  return res.json();
}

export async function bulkUpdateServerStatus(ids, status) {
  const res = await fetch(`${API_BASE}/servers/bulk-status`, {
    method: 'POST',
    headers: withAuth({ 'Content-Type': 'application/json' }),
    body: JSON.stringify({ ids, status }),
  });
  if (!res.ok) {
    let msg = '批量操作失败';
    try {
      const d = await res.json();
      msg = d.detail || msg;
    } catch (e) { }
    throw new Error(msg);
  }
  return res.json();
}

export async function powerControl(serverId, action) {
  const res = await fetch(`${API_BASE}/servers/${serverId}/power`, {
    method: 'POST',
    headers: withAuth({ 'Content-Type': 'application/json' }),
    body: JSON.stringify({ action }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || '操作失败');
  }
  return res.json();
}

export async function dismissAlert(serverId, alertId) {
  const res = await fetch(`${API_BASE}/servers/${serverId}/alerts/${alertId}`, { method: 'DELETE', headers: withAuth() });
  return res.json();
}

export async function addService(serverId, data) {
  const res = await fetch(`${API_BASE}/servers/${serverId}/services`, {
    method: 'POST',
    headers: withAuth({ 'Content-Type': 'application/json' }),
    body: JSON.stringify(data),
  });
  if (!res.ok) throw new Error('添加服务失败');
  return res.json();
}

export async function deleteService(serverId, serviceId) {
  const res = await fetch(`${API_BASE}/servers/${serverId}/services/${serviceId}`, { method: 'DELETE', headers: withAuth() });
  if (!res.ok) throw new Error('删除服务失败');
  return res.json();
}

export async function agentScan(serverId) {
  const res = await fetch(`${API_BASE}/agent/scan?server_id=${serverId}`, {
    method: 'POST',
    headers: withAuth({ 'Content-Type': 'application/json' }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}))
    throw new Error(err.detail || '扫描失败')
  }
  return res.json();
}

export async function updateService(serverId, serviceId, data) {
  const res = await fetch(`${API_BASE}/servers/${serverId}/services/${serviceId}`, {
    method: 'PUT',
    headers: withAuth({ 'Content-Type': 'application/json' }),
    body: JSON.stringify(data),
  });
  if (!res.ok) throw new Error('更新失败');
  return res.json();
}

function _errorMessage(err, fallback) {
  if (!err) return fallback;
  if (typeof err.detail === 'string') return err.detail;
  if (err.detail) return JSON.stringify(err.detail);
  if (typeof err === 'string') return err;
  return fallback;
}

export async function terminateService(serverId, serviceId, mode = 'graceful') {
  const res = await fetch(`${API_BASE}/servers/${serverId}/services/${serviceId}/terminate`, {
    method: 'POST',
    headers: withAuth({ 'Content-Type': 'application/json' }),
    body: JSON.stringify({ mode }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(_errorMessage(err, '终止进程失败'));
  }
  return res.json();
}

export async function checkServerServices(serverId) {
  const res = await fetch(`${API_BASE}/servers/${serverId}/check-services`, { method: 'POST', headers: withAuth() });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(_errorMessage(err, '服务检查失败'));
  }
  return res.json();
}

export async function triggerServerCollect(serverId) {
  const res = await fetch(`${API_BASE}/servers/${serverId}/trigger-collect`, { method: 'POST', headers: withAuth() });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(_errorMessage(err, '触发采集失败'));
  }
  return res.json();
}

export async function copyFiles(serverId, sources, target) {
  const res = await fetch(`${API_BASE}/servers/${serverId}/files/copy`, {
    method: 'POST',
    headers: withAuth({ 'Content-Type': 'application/json' }),
    body: JSON.stringify({ sources, target }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(_errorMessage(err, '复制失败'));
  }
  return res.json();
}

export async function deleteFiles(serverId, paths) {
  const res = await fetch(`${API_BASE}/servers/${serverId}/files/delete`, {
    method: 'POST',
    headers: withAuth({ 'Content-Type': 'application/json' }),
    body: JSON.stringify({ paths }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(_errorMessage(err, '删除失败'));
  }
  return res.json();
}

export async function createFolder(serverId, path) {
  const res = await fetch(`${API_BASE}/servers/${serverId}/files/mkdir`, {
    method: 'POST',
    headers: withAuth({ 'Content-Type': 'application/json' }),
    body: JSON.stringify({ path }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(_errorMessage(err, '创建文件夹失败'));
  }
  return res.json();
}

export async function renameFile(serverId, source, target) {
  const res = await fetch(`${API_BASE}/servers/${serverId}/files/rename`, {
    method: 'POST',
    headers: withAuth({ 'Content-Type': 'application/json' }),
    body: JSON.stringify({ source, target }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(_errorMessage(err, '重命名失败'));
  }
  return res.json();
}

export async function readTextFile(serverId, path) {
  const res = await fetch(
    `${API_BASE}/servers/${serverId}/files/read?path=${encodeURIComponent(path)}`,
    { headers: withAuth() },
  );
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(_errorMessage(err, '读取文件失败'));
  }
  return res.json();
}

export async function writeTextFile(serverId, path, content) {
  const res = await fetch(`${API_BASE}/servers/${serverId}/files/write`, {
    method: 'POST',
    headers: withAuth({ 'Content-Type': 'application/json' }),
    body: JSON.stringify({ path, content }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(_errorMessage(err, '保存文件失败'));
  }
  return res.json();
}

export async function createFile(serverId, path) {
  const res = await fetch(`${API_BASE}/servers/${serverId}/files/create`, {
    method: 'POST',
    headers: withAuth({ 'Content-Type': 'application/json' }),
    body: JSON.stringify({ path }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(_errorMessage(err, '新建文件失败'));
  }
  return res.json();
}

export async function zipFiles(serverId, paths, targetDir, zipName) {
  const res = await fetch(`${API_BASE}/servers/${serverId}/files/zip`, {
    method: 'POST',
    headers: withAuth({ 'Content-Type': 'application/json' }),
    body: JSON.stringify({ paths, target_dir: targetDir, zip_name: zipName || '' }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(_errorMessage(err, '压缩失败'));
  }
  return res.json();
}

export async function unzipFile(serverId, path) {
  const res = await fetch(`${API_BASE}/servers/${serverId}/files/unzip`, {
    method: 'POST',
    headers: withAuth({ 'Content-Type': 'application/json' }),
    body: JSON.stringify({ path }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(_errorMessage(err, '解压失败'));
  }
  return res.json();
}

export async function fetchAgentUpdateServers() {
  const res = await fetch(`${API_BASE}/agent-update/servers`, { headers: withAuth() });
  if (!res.ok) throw new Error('Failed to fetch agent update servers');
  return res.json();
}

export async function fetchAgentUpdatePackages() {
  const res = await fetch(`${API_BASE}/agent-update/packages`, { headers: withAuth() });
  if (!res.ok) throw new Error('Failed to fetch agent update packages');
  return res.json();
}

export async function createAgentUpdateTask(serverIds, packagePath) {
  const res = await fetch(`${API_BASE}/agent-update/tasks`, {
    method: 'POST',
    headers: withAuth({ 'Content-Type': 'application/json' }),
    body: JSON.stringify({ server_ids: serverIds, package_path: packagePath }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || '创建更新任务失败');
  }
  return res.json();
}

export async function fetchAgentUpdateTasks(limit = 100) {
  const res = await fetch(`${API_BASE}/agent-update/tasks?limit=${limit}`, { headers: withAuth() });
  if (!res.ok) throw new Error('Failed to fetch agent update tasks');
  return res.json();
}

export async function retryAgentUpdateTask(taskId) {
  const res = await fetch(`${API_BASE}/agent-update/tasks/${taskId}/retry`, {
    method: 'POST',
    headers: withAuth(),
  });
  if (!res.ok) throw new Error('Failed to retry task');
  return res.json();
}


async function _jsonOrThrow(res, fallback) {
  if (res.ok) return res.json();
  let msg = fallback;
  try {
    const d = await res.json();
    msg = (d && (d.detail || d.message)) || msg;
  } catch (e) { }
  throw new Error(typeof msg === 'string' ? msg : fallback);
}

export async function fetchNetworkInterfaces(serverId) {
  const res = await fetch(`${API_BASE}/servers/${serverId}/network-interfaces`, { headers: withAuth() });
  return _jsonOrThrow(res, '获取端口信息失败');
}

// 立即采集。不传 config = 用库里已存的凭据采并落库；
export async function collectSnmp(serverId, config = null) {
  const res = await fetch(`${API_BASE}/servers/${serverId}/snmp/collect`, {
    method: 'POST',
    headers: withAuth({ 'Content-Type': 'application/json' }),
    body: JSON.stringify(config || {}),
  });
  return _jsonOrThrow(res, 'SNMP 采集失败');
}

export async function updateSnmpConfig(serverId, data) {
  const res = await fetch(`${API_BASE}/servers/${serverId}`, {
    method: 'PUT',
    headers: withAuth({ 'Content-Type': 'application/json' }),
    body: JSON.stringify(data),
  });
  return _jsonOrThrow(res, '保存 SNMP 配置失败');
}

export async function fetchSshHostKey(serverId) {
  const res = await fetch(`${API_BASE}/servers/${serverId}/ssh-host-key`, { headers: withAuth() });
  return _jsonOrThrow(res, '获取 SSH 主机密钥失败');
}

// fingerprint 可省略（接受当前待确认的）；给了就必须与待确认值一致
export async function repinSshHostKey(serverId, fingerprint = '') {
  const res = await fetch(`${API_BASE}/servers/${serverId}/ssh-host-key/repin`, {
    method: 'POST',
    headers: withAuth({ 'Content-Type': 'application/json' }),
    body: JSON.stringify({ fingerprint }),
  });
  return _jsonOrThrow(res, '重新钉扎失败');
}

export async function unpinSshHostKey(serverId) {
  const res = await fetch(`${API_BASE}/servers/${serverId}/ssh-host-key`, {
    method: 'DELETE',
    headers: withAuth(),
  });
  return _jsonOrThrow(res, '清除钉扎失败');
}

// ── 方案 B：网络设备（交换机 / 路由器 / 防火墙）─────────────────────
// 装不上 Agent 的设备：服务端持 SNMPv3 凭据主动去问，被管设备上不装任何东西。

/** 网络设备列表（含"已断开"的，断开的设备不进侧边栏但档案还在） */
export async function fetchNetworkDevices() {
  const res = await fetch(
    `${API_BASE}/servers/?kind=network&include_pending=true&include_disconnected=true`,
    { headers: withAuth() }
  );
  if (!res.ok) throw new Error('获取网络设备失败');
  return res.json();
}

/** 测试连接（不落库）：拿表单里还没保存的凭据试一次，顺带返回识别结果 */
export async function probeNetworkDevice(payload) {
  const res = await fetch(`${API_BASE}/servers/network-devices/probe`, {
    method: 'POST',
    headers: withAuth({ 'Content-Type': 'application/json' }),
    body: JSON.stringify(payload),
  });
  return _jsonOrThrow(res, '测试连接失败');
}

export async function createNetworkDevice(payload) {
  const res = await fetch(`${API_BASE}/servers/network-devices`, {
    method: 'POST',
    headers: withAuth({ 'Content-Type': 'application/json' }),
    body: JSON.stringify(payload),
  });
  return _jsonOrThrow(res, '新增设备失败');
}

export async function connectNetworkDevice(serverId) {
  const res = await fetch(`${API_BASE}/servers/${serverId}/network/connect`, {
    method: 'POST',
    headers: withAuth(),
  });
  return _jsonOrThrow(res, '连接失败');
}

export async function disconnectNetworkDevice(serverId) {
  const res = await fetch(`${API_BASE}/servers/${serverId}/network/disconnect`, {
    method: 'POST',
    headers: withAuth(),
  });
  return _jsonOrThrow(res, '断开失败');
}

/** 网络设备日志：服务端记录的告警 + 审计（设备没有 Windows 事件日志可拉） */
export async function fetchNetworkDeviceLogs(serverId, limit = 300) {
  const res = await fetch(`${API_BASE}/servers/${serverId}/network/logs?limit=${limit}`, {
    headers: withAuth(),
  });
  return _jsonOrThrow(res, '获取设备日志失败');
}

// 2026-09-21：路线 A —— 立刻用只读 SSH 拉一次设备内部日志（display logbuffer / trapbuffer）。
// 不改设备任何配置；设备没配 CLI 登录凭据时后端会直接报错。
export async function collectDeviceLogs(serverId) {
  const res = await fetch(`${API_BASE}/servers/${serverId}/network/device-logs/collect`, {
    method: 'POST',
    headers: withAuth({ 'Content-Type': 'application/json' }),
    body: JSON.stringify({}),
  });
  return _jsonOrThrow(res, '拉取设备内部日志失败');
}

// 解除「采集熔断」：连续认证失败后采集器会自己停采，改好凭据后点这里恢复。
export async function resumeSnmpCollect(serverId) {
  const res = await fetch(`${API_BASE}/servers/${serverId}/snmp/resume`, {
    method: 'POST',
    headers: withAuth({ 'Content-Type': 'application/json' }),
    body: JSON.stringify({}),
  });
  return _jsonOrThrow(res, '恢复采集失败');
}

/**
 * 测试网络设备的命令行（SSH / Telnet）能不能登录。
 * 不传 payload = 用库里已存的凭据；传了就用表单里还没保存的值试。
 */
export async function testNetworkCli(serverId, payload = null) {
  const res = await fetch(`${API_BASE}/servers/${serverId}/network/cli/test`, {
    method: 'POST',
    headers: withAuth({ 'Content-Type': 'application/json' }),
    body: JSON.stringify(payload || {}),
  });
  return _jsonOrThrow(res, '测试命令行连接失败');
}

/**
 * 网络设备「WEB管理」页签的入口信息（协议 / 地址 / 端口 / 代理前缀）。
 * 后端会把 "打开过一次" 记进审计，所以每次点开页签都调一次。
 */
export async function fetchNetworkWebConfig(serverId) {
  const res = await fetch(`${API_BASE}/servers/${serverId}/web-config`, {
    headers: withAuth(),
  });
  return _jsonOrThrow(res, '读取 WEB 管理配置失败');
}
