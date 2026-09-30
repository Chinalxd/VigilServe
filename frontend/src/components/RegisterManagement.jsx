import { useState, useEffect, useRef } from 'react'
import {
  fetchAllServers,
  updateServerStatus,
  bulkUpdateServerStatus,
  deleteServer,
  revokeAgentCert,
  rotateAgentToken,
  resetAgentBaseline,
  fetchAgentUpdateServers,
  fetchAgentUpdatePackages,
  createAgentUpdateTask,
  fetchAgentUpdateTasks,
  retryAgentUpdateTask,
} from '../services/api'
import NetworkDevicesTab from './NetworkDevices'
import { usePerm } from '../services/permissions'
import { parseServerTime } from '../utils/format'
import './RegisterManagement.css'
import Icon from './AppIcon'

// 取服务端时间戳的毫秒数（用于比较/排序）。缺值给 -Infinity，排在升序最前。
// 同样必须走 parseServerTime —— 见 parseServerTime 的注释。
function _ts(v) {
  const d = parseServerTime(v)
  return d ? d.getTime() : -Infinity
}

function formatLastSeen(iso) {
  if (!iso) return '从未'
  const d = parseServerTime(iso)
  if (!d) return iso
  const now = new Date()
  const diffSec = Math.round((now - d) / 1000)
  if (diffSec < 60) return '刚刚'
  if (diffSec < 3600) return `${Math.floor(diffSec / 60)} 分钟前`
  if (diffSec < 86400) return `${Math.floor(diffSec / 3600)} 小时前`
  return `${Math.floor(diffSec / 86400)} 天前`
}

function formatMinute(iso) {
  if (!iso) return '-'
  const d = parseServerTime(iso)
  if (!d) return iso
  const pad = (n) => String(n).padStart(2, '0')
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}`
}

// 与后端 services/device_status.py 是同一条规则 —— 周期由后端按设备形态算好下发
// （Agent 主机看推送间隔，网络设备看 SNMP 采集间隔），前端不再各写一套硬编码阈值。
function isOnlineByHeartbeat(s) {
  const last = parseServerTime(s.last_seen)
  if (!last) return false
  const period = Number(s.collect_period_sec) || 60
  // 🚨 这里以前是 `new Date(s.last_seen)` —— 服务端时间是 naive UTC，被当成本地
  //   时间解析会凭空多出 8 小时差值，于是**所有主机恒被判为离线**，
  //   「离线时长」列一直显示成一个 8 小时前的时刻。必须走 parseServerTime。
  const diffMs = Date.now() - last.getTime()
  return diffMs < period * 2.5 * 1000
}

function HostsTab({ onServersChanged, onEditServer }) {
  const { can } = usePerm()
  // 注册管理三个动作：加入管理（审批通过）/ 移出管理（删除注册）/ 编辑主机
  const canApprove = can('sys', 'register', 'edit', 'approve')
  const canRemove = can('sys', 'register', 'edit', 'delete')
  const canEditServer = can('sys', 'register', 'edit', 'edit')
  const [allServers, setAllServers] = useState([])
  const [servers, setServers] = useState([])
  const [loading, setLoading] = useState(true)
  const [filter, setFilter] = useState('all')
  const [sort, setSort] = useState({ field: 'isManaged', direction: 'desc' })
  const [checked, setChecked] = useState(new Set())
  const [sub, setSub] = useState('list')
  const showAgentUpdate = can('sys', 'agent_update', 'view')
  // 权限被回收时站在已隐藏的页签上就没法回去了 —— 拉回列表
  useEffect(() => { if (!showAgentUpdate) setSub('list') }, [showAgentUpdate])

  const computeList = (raw, activeFilter, activeSort) => {
    const managedStatuses = new Set(['monitored', 'online', 'offline', 'warning', 'critical'])
    let list = raw
      .filter(s => s.protocol === 'agent')
      .map(s => {
        const isManaged = managedStatuses.has(s.status)
        const isOnline = isOnlineByHeartbeat(s)
        return { ...s, isManaged, isOnline }
      })
      // 2026-09-22：离线的待审核主机也要显示 —— Agent 卸载后它的注册条目
      // 就是「离线 registered」，不显示的话管理员既没法移出管理，也没法
      .filter(s => s.isManaged || s.status === 'registered')

    if (activeFilter === 'managed') {
      list = list.filter(s => s.isManaged)
    } else if (activeFilter === 'unmanaged') {
      list = list.filter(s => !s.isManaged)
    }

    list = list.sort((a, b) => {
      let cmp = 0
      switch (activeSort.field) {
        case 'name':
          cmp = (a.name || '').localeCompare(b.name || '')
          break
        case 'ip_address':
          cmp = (a.ip_address || '').localeCompare(b.ip_address || '')
          break
        case 'os_type':
          cmp = (a.os_type || '').localeCompare(b.os_type || '')
          break
        case 'status':
          cmp = (a.isOnline ? 1 : 0) - (b.isOnline ? 1 : 0)
          break
        case 'join_time':
          cmp = _ts(a.join_time) - _ts(b.join_time)
          break
        case 'online_time':
          cmp = _ts(a.online_time) - _ts(b.online_time)
          break
        case 'offline_time':
          cmp = _ts(a.offline_time || a.last_seen) - _ts(b.offline_time || b.last_seen)
          break
        case 'isManaged':
        default:
          cmp = (a.isManaged ? 1 : 0) - (b.isManaged ? 1 : 0)
          break
      }
      if (cmp === 0) cmp = a.id - b.id
      return activeSort.direction === 'asc' ? cmp : -cmp
    })

    return list
  }

  const load = async () => {
    setLoading(true)
    const all = await fetchAllServers()
    setAllServers(all)
    setServers(computeList(all, filter, sort))
    setLoading(false)
  }

  useEffect(() => { load() }, [])

  useEffect(() => {
    setServers(computeList(allServers, filter, sort))
    // 列表刷新后把已经不在列表里的勾选清掉，避免对看不见的主机做批量操作
    setChecked(prev => {
      const ids = new Set(computeList(allServers, filter, sort).map(s => s.id))
      const next = new Set([...prev].filter(id => ids.has(id)))
      return next.size === prev.size ? prev : next
    })
  }, [filter, sort, allServers])

  const toggleOne = (id) => {
    setChecked(prev => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  }

  const toggleAll = () => {
    if (checked.size === servers.length && servers.length > 0) setChecked(new Set())
    else setChecked(new Set(servers.map(s => s.id)))
  }

  const handleBulk = async (status) => {
    if (checked.size === 0) return
    const verb = status === 'monitored' ? '加入管理' : '移出管理'
    const picked = servers.filter(s => checked.has(s.id))
    // 未加入管理**且离线**的主机不能加入管理：此刻没有任何 Agent 在连服务端
    // （多半是已卸载，或配置 / 网络有问题）。加进去只会得到一条永远不上报
    // 数据的「已纳管」记录 —— 列表上看着绿，实际一台机器都没有。
    // 与行内按钮的禁用条件必须是同一条，否则批量就成了绕过单台限制的口子。
    if (status === 'monitored') {
      const blocked = picked.filter(s => !s.isManaged && !s.isOnline)
      if (blocked.length > 0) {
        window.alert(
          '以下主机未加入管理且 Agent 离线，暂不可加入管理：\n\n' +
          blocked.map(s => `${s.name}（Agent 离线，请先在该主机上启动 Agent 或检查网络）`).join('\n')
        )
        return
      }
    }
    const names = picked.map(s => s.name).join('、')
    const ok = window.confirm(
      `确定将以下 ${picked.length} 台主机${verb}？\n\n${names}`
    )
    if (!ok) return
    try {
      const res = await bulkUpdateServerStatus(Array.from(checked), status)
      setChecked(new Set())
      load()
      onServersChanged && onServersChanged()
      if (res && res.skipped) {
        window.alert(`${res.message}（${res.skipped} 台已是目标状态或不存在，已跳过）`)
      }
    } catch (e) {
      window.alert(`批量${verb}失败：${e.message || e}`)
    }
  }

  const handleAdd = async (server) => {
    await updateServerStatus(server.id, { status: 'monitored' })
    load()
    onServersChanged && onServersChanged()
  }

  // 2026-09-22：删除主机（不可逆）。仅对「已移出管理 + 离线」的主机开放 ——
  // 在线 Agent 删了会立刻重新注册回来；在管数据全挂在记录上，必须先移出管理。
  const handleBulkDelete = async () => {
    if (checked.size === 0) return
    const picked = servers.filter(s => checked.has(s.id))
    const blocked = picked.filter(s => s.isManaged || s.isOnline)
    if (blocked.length > 0) {
      const why = blocked.map(s =>
        `${s.name}（${s.isManaged ? '仍在管理中，请先移出管理' : 'Agent 仍在线，请先退出或卸载 Agent'}）`
      ).join('\n')
      window.alert(`以下主机暂不可删除：\n\n${why}`)
      return
    }
    const names = picked.map(s => s.name).join('、')
    const ok = window.confirm(
      `确定永久删除以下 ${picked.length} 台主机？\n\n${names}\n\n` +
      '删除不可恢复（含监控历史、服务、告警、设备身份）。'
    )
    if (!ok) return
    const failed = []
    for (const s of picked) {
      try {
        await deleteServer(s.id)
      } catch (e) {
        failed.push(`${s.name}：${e.message || e}`)
      }
    }
    setChecked(new Set())
    load()
    onServersChanged && onServersChanged()
    if (failed.length > 0) {
      window.alert(`部分主机删除失败：\n\n${failed.join('\n')}`)
    }
  }

  const handleRemove = async (server) => {
    await updateServerStatus(server.id, { status: 'registered' })
    load()
    onServersChanged && onServersChanged()
  }

  // 吊销设备身份。吊销后该机要重新接入，必须「移出管理」再「加入管理」，
  // 并重新核对配对码 —— 所以提示里写清楚这条路径。
  const handleRevoke = async (server) => {
    const ok = window.confirm(
      `确定吊销「${server.name}」的设备身份？\n\n` +
      '· 该设备的私钥签名将被拒绝，主机停止上报数据；\n' +
      '· 重新接入需先「移出管理」，再「加入管理」并核对新配对码。'
    )
    if (!ok) return
    try {
      await revokeAgentCert(server.id)
      load()
      onServersChanged && onServersChanged()
    } catch (e) {
      window.alert(`吊销失败：${e.message || e}`)
    }
  }

  // 开源加固 ⑤：轮换这台主机的静态 Agent token。
  // 适用情形：怀疑 agent_config.json 外流，或运维人员变动后需一次性作废旧凭据。
  // 轮换后旧 token 进入 24 小时倒计时，期间仍能上报 —— 这是留给那台 Agent 用
  // 下一次心跳把新 token 领走的窗口；24 小时后旧 token 彻底失效。
  const handleRotate = async (server) => {
    const ok = window.confirm(
      `确定轮换「${server.name}」的 Agent 凭据？\n\n` +
      '作用：更换该主机与服务端之间的共享密钥，使外流的旧凭据失效。\n\n' +
      '· 旧凭据 24 小时内仍被接受（供 Agent 自动领取新凭据），之后作废；\n' +
      '· 新凭据由该主机下次心跳自动领取，采集与远程管理不受影响；\n' +
      '· 如需旧凭据立即失效，请改用「吊销设备」。'
    )
    if (!ok) return
    try {
      await rotateAgentToken(server.id)
      load()
      onServersChanged && onServersChanged()
    } catch (e) {
      window.alert(`轮换失败：${e.message || e}`)
    }
  }

  // 🚨 这是个**信任动作，不是取证动作**：点下去等于宣布"这台机器现在跑的代码是官方的"。
  // 真怀疑被改造时千万别点 —— 那会把唯一的痕迹擦掉。所以确认框里保留这句警示。
  const handleResetBaseline = async (server) => {
    const ok = window.confirm(
      `确定重新登记「${server.name}」的 Agent 完整性基线？\n\n` +
      '用途：Agent 代码指纹与基线不一致时会告警「疑似被改造」；\n' +
      '自行重新打包、修复缺陷后重发同样会使指纹变化，此时可用本操作消除误报。\n\n' +
      '· 清除旧基线及「疑似被改造」告警；\n' +
      '· 下次心跳将当前代码记为新的官方基线。\n\n' +
      '⚠ 仅限确认为自行发布的版本时使用；\n' +
      '若怀疑该机被改造，请保留告警并排查。'
    )
    if (!ok) return
    try {
      await resetAgentBaseline(server.id)
      load()
      onServersChanged && onServersChanged()
    } catch (e) {
      window.alert(`重新登记失败：${e.message || e}`)
    }
  }

  const handleSort = (field) => {
    setSort(prev => ({
      field,
      direction: prev.field === field && prev.direction === 'asc' ? 'desc' : 'asc',
    }))
  }

  const sortIndicator = (field) => {
    if (sort.field !== field) return <span className="sort-indicator"><Icon kind="ui-sort" size={11} /></span>
    return <span className={`sort-indicator active ${sort.direction}`}><Icon kind={sort.direction === 'asc' ? 'ui-chevron-up' : 'ui-chevron-down'} size={11} /></span>
  }

  const SortHeader = ({ field, children }) => (
    <th className="sortable-header" onClick={() => handleSort(field)} title="点击排序">
      {children} {sortIndicator(field)}
    </th>
  )

  const filterBtn = (key, label) => (
    <button
      key={key}
      className={`reg-filter-btn ${filter === key ? 'active' : ''}`}
      onClick={() => setFilter(key)}
    >
      {label}
    </button>
  )

  if (loading) return <div className="reg-loading">加载中...</div>

  const tabBtn = (key, label) => (
    <button
      key={key}
      className={`reg-subtab ${sub === key ? 'active' : ''}`}
      onClick={() => setSub(key)}
    >
      {label}
    </button>
  )

  // 工具栏左边不再是标题，而是两个子页签 —— Agent 更新原来挂在顶级页签里，
  // 但它只作用于主机，和「网络设备」平级放着容易被读成「网络设备也在升级」。
  const header = (
    <div className="reg-section-header">
      <div className="reg-subtabs">
        {tabBtn('list', '主机列表')}
        {showAgentUpdate && tabBtn('agent-update', 'Agent 更新')}
      </div>
      {sub === 'list' && (
        <div className="reg-header-actions">
          <div className="reg-filter-group">
            {filterBtn('all', '全部')}
            {filterBtn('managed', '已加入')}
            {filterBtn('unmanaged', '未加入')}
          </div>
          {/* S4：批量操作。只有有审批权限的人看得见，且已选 0 台时按钮禁用 */}
          {canApprove && (
            <div className="reg-bulk-group">
              <button
                className="reg-btn-add"
                disabled={checked.size === 0}
                onClick={() => handleBulk('monitored')}
                title="批量加入管理"
              >批量加入{checked.size > 0 ? ` (${checked.size})` : ''}</button>
              <button
                className="reg-btn-remove"
                disabled={checked.size === 0}
                onClick={() => handleBulk('registered')}
                title="批量移出管理"
              >批量移出{checked.size > 0 ? ` (${checked.size})` : ''}</button>
              {/* 2026-09-22：删除主机 —— 只对「已移出管理 + 离线」的主机生效，
                  点了会逐台校验并说明不能删的原因。 */}
              {canRemove && (
                <button
                  className="reg-btn-remove"
                  disabled={checked.size === 0}
                  onClick={handleBulkDelete}
                  title="批量删除主机（仅限已移出管理且 Agent 已离线的主机）"
                >删除主机{checked.size > 0 ? ` (${checked.size})` : ''}</button>
              )}
            </div>
          )}
          <button className="reg-refresh-btn" onClick={load} title="刷新列表">刷新</button>
        </div>
      )}
    </div>
  )

  // 「Agent 更新」整块接管卡片体：它有自己的工具栏和表格，不复用主机列表那套
  if (sub === 'agent-update') {
    return (
      <div className="reg-section">
        {header}
        <AgentUpdateTab />
      </div>
    )
  }

  return (
    <div className="reg-section">
      {header}
      {servers.length === 0 ? (
        <p className="reg-empty">暂无主机</p>
      ) : (
        <div className="host-list-table-wrap">
          <table className="host-list-table">
            <thead>
              <tr>
                {canApprove && (
                  <th className="reg-check-col">
                    <input
                      type="checkbox"
                      checked={servers.length > 0 && checked.size === servers.length}
                      onChange={toggleAll}
                      title="全选 / 取消全选"
                    />
                  </th>
                )}
                <SortHeader field="name">主机名称</SortHeader>
                <SortHeader field="ip_address">IP 地址</SortHeader>
                <SortHeader field="os_type">系统</SortHeader>
                <SortHeader field="status">状态</SortHeader>
                <SortHeader field="join_time">加入时间</SortHeader>
                <SortHeader field="online_time">上线时间</SortHeader>
                <SortHeader field="offline_time">离线时间</SortHeader>
                <th>配对码</th>
                <th>操作</th>
              </tr>
            </thead>
            <tbody>
              {servers.map(s => (
                <tr key={s.id} className={s.isManaged ? 'managed' : 'unmanaged'}>
                  {canApprove && (
                    <td className="reg-check-col">
                      <input
                        type="checkbox"
                        checked={checked.has(s.id)}
                        onChange={() => toggleOne(s.id)}
                      />
                    </td>
                  )}
                  <td className="host-name">
                    {s.name}
                    {s.name_conflict && (
                      <span
                        className="reg-name-conflict"
                        title="主机名与已存在的另一条记录重复（来源 IP 不同）。可能是冒名顶替，也可能是这台机器重装后 IP 变了 —— 请核对后再「加入管理」。"
                      >名称重复</span>
                    )}
                  </td>
                  <td>{s.ip_address}</td>
                  <td>{s.os_type || '未知系统'}</td>
                  <td>
                    <span className={`reg-status-dot ${s.isOnline ? 'online' : 'offline'}`}>
                      {s.isOnline ? '在线' : '离线'}
                    </span>
                  </td>
                  <td title={s.join_time || ''}>{formatMinute(s.join_time)}</td>
                  <td title={s.online_time || ''}>{formatMinute(s.online_time)}</td>
                  <td title={s.isOnline ? '' : (s.offline_time || s.last_seen || '')}>
                    {s.isOnline ? '-' : formatMinute(s.offline_time || s.last_seen)}
                  </td>
                  <td className="reg-pairing">
                    {!s.isManaged && s.pairing_code ? (
                      <>
                        <span
                          className="reg-pairing-code"
                          title="请比对此配对码和agent端显示的配对码是否一致，确保接入正确主机。"
                        >{s.pairing_code}</span>
                        {s.key_fingerprint && (
                          <span
                            className="reg-key-fp"
                            title="设备公钥指纹（由 Agent 端私钥决定，复制配置目录也带不走）。怀疑被顶替时用它做精确核对。"
                          >{s.key_fingerprint.slice(0, 16)}</span>
                        )}
                      </>
                    ) : !s.isManaged ? (
                      <span className="reg-pairing-none" title="未上报配对码：可能是老版本 Agent，请按 IP / 主机名人工核对">—</span>
                    ) : (
                      <span className="reg-pairing-none" title="已加入管理，配对码作废">—</span>
                    )}
                  </td>
                  <td className="host-actions">
                    {s.isManaged ? (
                      <>
                        {canEditServer && (
                          <button className="reg-btn-edit" onClick={() => onEditServer && onEditServer(s)}>编辑主机</button>
                        )}
                        {canApprove && (
                          <button
                            className="reg-btn-rotate"
                            onClick={() => handleRotate(s)}
                            title="配置文件外流时更换共享密钥，旧凭据 24 小时后失效。"
                          >轮换凭据</button>
                        )}
                        {canApprove && (
                          <button
                            className="reg-btn-rebaseline"
                            onClick={() => handleResetBaseline(s)}
                            title="将当前 Agent 代码记为新的官方基线，消除「疑似被改造」误报。"
                          >重登记基线</button>
                        )}
                        {/* 1.1.51 方案 A：身份是「登记的公钥」，不再是证书。
                            issued / approved 是旧状态名，一并认，避免存量数据显示不出按钮。 */}
                        {canApprove && ['authorized', 'issued', 'approved'].includes(s.identity_state) && (
                          <button
                            className="reg-btn-revoke"
                            onClick={() => handleRevoke(s)}
                            title="吊销设备身份，需移出管理后重新加入并核对配对码。"
                          >吊销设备</button>
                        )}
                        {canRemove && (
                          <button className="reg-btn-remove" onClick={() => handleRemove(s)}>移出管理</button>
                        )}
                      </>
                    ) : (
                      canApprove && (
                        // 服务端立刻置离线），此刻把它加进管理只会得到一条永远
                        // 不上报数据的「已纳管」记录。重装并重新联网后自动恢复可用。
                        <button
                          className="reg-btn-add"
                          disabled={!s.isOnline}
                          title={s.isOnline
                            ? '加入管理'
                            : '该主机未加入管理且 Agent 离线，须先启动 Agent 使其上线后才能加入管理'}
                          onClick={() => handleAdd(s)}
                        >加入管理</button>
                      )
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* 底部状态栏：统计项数在左侧，全部项目一页显示、不翻页 */}
      <div className="reg-panel-foot">
        <span className="reg-count">共 {servers.length} 台主机</span>
      </div>
    </div>
  )
}

function AgentUpdateTab() {
  const { can } = usePerm()
  const canUpdate = can('sys', 'agent_update', 'edit', 'update')
  const canRetry = can('sys', 'agent_update', 'edit', 'retry')
  const [servers, setServers] = useState([])
  const [packages, setPackages] = useState([])
  const [selectedPackage, setSelectedPackage] = useState('')
  const [selectedServers, setSelectedServers] = useState(new Set())
  const [tasks, setTasks] = useState([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const pollRef = useRef(null)

  const load = async () => {
    setLoading(true)
    setError('')
    try {
      const [svrRes, pkgRes, taskRes] = await Promise.all([
        fetchAgentUpdateServers(),
        fetchAgentUpdatePackages(),
        fetchAgentUpdateTasks(50),
      ])
      setServers(svrRes || [])
      setPackages(pkgRes.packages || [])
      setTasks(taskRes || [])
      if (pkgRes.packages && pkgRes.packages.length > 0 && !selectedPackage) {
        setSelectedPackage(pkgRes.packages[0].path)
      }
    } catch (e) {
      setError(e.message)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    load()
    pollRef.current = setInterval(() => {
      fetchAgentUpdateTasks(50).then(setTasks).catch(() => {})
    }, 3000)
    return () => {
      if (pollRef.current) clearInterval(pollRef.current)
    }
  }, [])

  const toggleServer = (id) => {
    const next = new Set(selectedServers)
    if (next.has(id)) next.delete(id)
    else next.add(id)
    setSelectedServers(next)
  }

  const toggleAll = () => {
    if (selectedServers.size === servers.length && servers.length > 0) {
      setSelectedServers(new Set())
    } else {
      setSelectedServers(new Set(servers.map(s => s.id)))
    }
  }

  const handleUpdate = async () => {
    if (!selectedPackage) return setError('请选择安装包')
    if (selectedServers.size === 0) return setError('请至少选择一台主机')
    setError('')
    try {
      await createAgentUpdateTask(Array.from(selectedServers), selectedPackage)
      const tasks = await fetchAgentUpdateTasks(50)
      setTasks(tasks)
    } catch (e) {
      setError(e.message)
    }
  }

  const handleRetry = async (taskId) => {
    try {
      await retryAgentUpdateTask(taskId)
      const tasks = await fetchAgentUpdateTasks(50)
      setTasks(tasks)
    } catch (e) {
      setError(e.message)
    }
  }

  const statusClass = (status) => {
    if (status === 'success') return 'status-success'
    if (status === 'failed') return 'status-failed'
    if (status === 'running') return 'status-running'
    return 'status-pending'
  }

  const statusLabel = (status) => {
    if (status === 'success') return '成功'
    if (status === 'failed') return '失败'
    if (status === 'running') return '进行中'
    return '等待中'
  }

  const latestTaskByServer = {}
  for (const t of tasks) {
    const sid = t.server_id
    if (!sid) continue
    const prev = latestTaskByServer[sid]
    if (!prev || _ts(t.created_at) > _ts(prev.created_at)) {
      latestTaskByServer[sid] = t
    }
  }

  return (
    <div className="agent-update-tab">
      <div className="agent-update-toolbar">
        <div className="agent-update-field">
          <label>安装包</label>
          <select value={selectedPackage} onChange={(e) => setSelectedPackage(e.target.value)}>
            {packages.length === 0 && <option value="">暂无安装包</option>}
            {packages.map(p => (
              <option key={p.path} value={p.path}>
                {p.filename} (v{p.version}, {p.size_mb} MB)
              </option>
            ))}
          </select>
        </div>
        <button
          className="reg-btn-add"
          onClick={handleUpdate}
          disabled={!canUpdate || !selectedPackage || selectedServers.size === 0}
          title={canUpdate ? '' : '当前角色没有「一键更新」权限'}
        >
          一键更新
        </button>
        <button className="reg-refresh-btn" onClick={load}>刷新</button>
      </div>

      {error && <div className="agent-update-error">{error}</div>}

      <div className="agent-update-table-wrap">
        <table className="agent-update-table">
          <thead>
            <tr>
              <th className="check-cell">
                <input type="checkbox" checked={servers.length > 0 && selectedServers.size === servers.length} onChange={toggleAll} />
              </th>
              <th>主机名称</th>
              <th>IP 地址</th>
              <th>协议</th>
              <th>状态</th>
              <th>Agent 版本</th>
              <th>最后推送</th>
              <th>更新任务</th>
            </tr>
          </thead>
          <tbody>
            {servers.length === 0 ? (
              <tr><td colSpan={8} className="empty-cell">暂无已管理主机</td></tr>
            ) : servers.map(s => {
              const task = latestTaskByServer[s.id]
              return (
                <tr key={s.id}>
                  <td className="check-cell">
                    <input type="checkbox" checked={selectedServers.has(s.id)} onChange={() => toggleServer(s.id)} />
                  </td>
                  <td>{s.name}</td>
                  <td>{s.ip_address}</td>
                  <td>{s.protocol}</td>
                  <td>
                    <span className={`reg-status-dot ${s.status === 'online' || s.status === 'monitored' ? 'online' : 'offline'}`}>
                      {s.status === 'online' || s.status === 'monitored' ? '在线' : '离线'}
                    </span>
                  </td>
                  <td>{s.agent_version || '未知'}</td>
                  <td title={task?.created_at || ''}>{task ? formatMinute(task.created_at) : '-'}</td>
                  <td className="task-cell">
                    {task ? (
                      <div className="task-cell-inner">
                        <div className="task-cell-row">
                          <span className={`task-status-badge ${statusClass(task.status)}`}>
                            {statusLabel(task.status)}
                          </span>
                          <span className="task-stage" title={task.stage || ''}>{task.stage || '-'}</span>
                          {task.status === 'failed' && canRetry && (
                            <button className="task-retry-inline" onClick={() => handleRetry(task.id)}>重试</button>
                          )}
                        </div>
                        {task.error && (
                          <div className="task-cell-error" title={task.error}>{task.error}</div>
                        )}
                      </div>
                    ) : (
                      <span className="task-none">-</span>
                    )}
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>

      {/* 底部状态栏：统计项数在左侧，全部项目一页显示、不翻页 */}
      <div className="reg-panel-foot">
        <span className="reg-count">共 {servers.length} 台主机</span>
      </div>
    </div>
  )
}

export default function RegisterManagement({ onServersChanged, onEditServer }) {
  const { can } = usePerm()
  // 页签按角色「查看」权限显隐；至少有一个页签可见才会渲染本页（App 路由已保证）
  const tabs = [
    // 分组管理已迁回侧边栏「主机列表」，此处不再提供页签
    { key: 'hosts', label: '主机管理', show: can('sys', 'register', 'view') },
    // 方案 B：网络设备（装不上 Agent 的交换机 / 路由器 / 防火墙）单独一套接入流程
    { key: 'network-devices', label: '网络设备', show: can('sys', 'network_devices', 'view') },
    // Agent 更新不再占顶级页签 —— 收到「主机管理」卡片工具栏里，和主机列表并排
  ].filter((t) => t.show)
  const [activeTab, setActiveTab] = useState('hosts')
  // 权限加载完成前 tabs 可能为空；兜底取第一个可见页签
  const currentTab = tabs.some((t) => t.key === activeTab) ? activeTab : (tabs[0] && tabs[0].key)

  return (
    <div className="reg-management">
      <div className="log-tabs">
        {tabs.map((t) => (
          <button
            key={t.key}
            className={`log-tab ${currentTab === t.key ? 'active' : ''}`}
            onClick={() => setActiveTab(t.key)}
          >
            {t.label}
          </button>
        ))}
      </div>

      <div className="settings-panel">
        {currentTab === 'hosts' && (
          <HostsTab onServersChanged={onServersChanged} onEditServer={onEditServer} />
        )}
        {currentTab === 'network-devices' && (
          <NetworkDevicesTab onServersChanged={onServersChanged} />
        )}
      </div>
    </div>
  )
}
