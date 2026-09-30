/* 方案 B：网络设备「系统信息」页签 —— 设备系统及硬件信息
 *
 * 这里原来是「网络」页签（SNMP 凭据 + SSH 指纹）。按用户要求删掉那个页签之后：
 *   · SNMPv3 凭据 → 挪到「设备管理 - 网络设备」页的编辑弹窗里维护
 *   · 剩下的设备信息 / 端口表 / SSH 主机密钥 → 复用成网络设备的「系统信息」
 *
 * 所以现在这一屏三块，全是"设备长什么样"：
 *   1. 资产信息（厂商 / 型号 / 类型 / 采集周期 —— 新增时 SNMP 自动识别，可人工改）
 *   2. 设备信息（sysDescr / sysName / 位置 / 运行时长 / 上次采集）
 *   3. 端口列表（IF-MIB：状态 / 速率 / 流量 / 错包）
 *
 * 「SSH 主机密钥」卡片已按用户要求删除（2026-09-20）：它属于敏感凭据信息，
 * 不该出现在设备信息页。ssh_pinning 的后端能力与接口保留未动。
 */
import { useCallback, useEffect, useMemo, useState } from 'react'
import { parseServerTime } from '../utils/format'
import { fetchNetworkInterfaces } from '../services/api'
import { isVirtualIface } from '../utils/ifaces'
import './NetworkPanel.css'

function fmtBytes(n) {
  const v = Number(n) || 0
  const G = 1024 ** 3
  const M = 1024 ** 2
  const K = 1024
  if (v >= 1024 ** 4) return `${(v / 1024 ** 4).toFixed(2)} TB`
  if (v >= G) return `${(v / G).toFixed(2)} GB`
  if (v >= M) return `${(v / M).toFixed(2)} MB`
  if (v >= K) return `${(v / K).toFixed(1)} KB`
  return `${v} B`
}

/* 单端口速率（Mbps）。null = 这一轮还没算出速率（缺基线 / 刚重启 / 计数器回绕），
 * 显示"—"而不是 0 —— 0 会被读成"这口真的没在跑流量"。 */
function fmtRate(v) {
  if (v == null || Number.isNaN(Number(v))) return '—'
  const n = Number(v)
  if (n >= 1000) return `${(n / 1000).toFixed(2)} Gbps`
  return `${n < 1 ? n.toFixed(3) : n.toFixed(2)} Mbps`
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

function fmtTime(iso) {
  if (!iso) return '—'
  const d = parseServerTime(iso)
  if (Number.isNaN(d.getTime())) return '—'
  const p = (x) => String(x).padStart(2, '0')
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`
}

function StatusPill({ text }) {
  const t = String(text || '').toLowerCase()
  let cls = 'np-pill np-pill-unknown'
  let label = text || '未知'
  if (t === 'up') { cls = 'np-pill np-pill-up'; label = 'UP' }
  else if (t === 'down') { cls = 'np-pill np-pill-down'; label = 'DOWN' }
  else if (t === 'testing') { cls = 'np-pill np-pill-test'; label = '测试' }
  return <span className={cls}>{label}</span>
}

export default function NetworkPanel({ serverId, server, mode = 'info' }) {
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [data, setData] = useState(null)
  const [filter, setFilter] = useState('')
  const [showAll, setShowAll] = useState(false)

  const load = useCallback(async () => {
    setLoading(true)
    setError('')
    try {
      setData(await fetchNetworkInterfaces(serverId))
    } catch (e) {
      setError(e.message || '加载失败')
    } finally {
      setLoading(false)
    }
  }, [serverId])

  useEffect(() => { load() }, [load])

  // 这里原来有个「立即采集」按钮（onCollect → collectSnmp）。2026-09-21 按需求删掉：
  // 采集入口统一收到「设备管理 - 网络设备」列表里那一列，本页只读。

  const allIfaces = useMemo(() => (data && data.interfaces) || [], [data])
  const hiddenCount = useMemo(() => allIfaces.filter(isVirtualIface).length, [allIfaces])
  const shownTotal = showAll ? allIfaces.length : allIfaces.length - hiddenCount

  const ifaces = useMemo(() => {
    const base = showAll ? allIfaces : allIfaces.filter((i) => !isVirtualIface(i))
    const kw = filter.trim().toLowerCase()
    if (!kw) return base
    return base.filter((i) =>
      [i.if_name, i.if_descr, i.if_alias].join(' ').toLowerCase().includes(kw))
  }, [allIfaces, showAll, filter])

  const dev = (data && data.device) || {}
  const asset = (data && data.asset) || {}

  if (loading) return <div className="np-loading">正在加载设备信息…</div>
  if (error) return <div className="np-error">{error}</div>

  return (
    <div className="network-panel">
      <section className="np-panel">
        <header className="np-panel-head">
          <span className="np-panel-title">{mode === 'info' ? '设备系统信息' : '设备信息'}</span>
          <span className="np-spacer" />
          <input
            className="np-search"
            placeholder="过滤端口名 / 描述"
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
          />
          <button className="np-btn" onClick={load}>刷新</button>
        </header>

        <div className="np-panel-body">
          {/* 资产信息：新增设备时由 SNMP 自动识别，识别错了可在「设备管理 - 网络设备」里改 */}
          <div className="np-row">
            <div className="np-row-head"><span className="np-row-name">资产信息</span></div>
            <div className="np-row-body">
              <table className="np-kv">
                <tbody>
                  <tr>
                    <th>设备名称</th>
                    <td>{asset.name || server?.name || '—'}</td>
                  </tr>
                  <tr>
                    <th>管理 IP</th>
                    <td className="np-mono">{asset.ip_address || server?.ip_address || '—'}</td>
                  </tr>
                  <tr>
                    <th>厂商</th>
                    <td>{asset.device_vendor || '—'}</td>
                  </tr>
                  <tr>
                    <th>型号</th>
                    <td className="np-mono">{asset.device_model || '—'}</td>
                  </tr>
                  <tr>
                    <th>设备类型</th>
                    <td>{asset.device_category_label || '其他设备'}</td>
                  </tr>
                  <tr>
                    <th>采集周期</th>
                    <td>{asset.collect_period_sec ? `${asset.collect_period_sec} 秒` : '—'}</td>
                  </tr>
                  {asset.description ? (
                    <tr>
                      <th>备注</th>
                      <td>{asset.description}</td>
                    </tr>
                  ) : null}
                </tbody>
              </table>
            </div>
          </div>

          {!data || !data.snmp_enabled ? (
            <div className="np-empty-box">
              该设备未启用 SNMP 采集。请在「设备管理 - 网络设备」里点「连接」恢复采集。
            </div>
          ) : (
            <div className="np-row">
              <div className="np-row-head"><span className="np-row-name">系统信息（SNMP）</span></div>
              <div className="np-row-body">
                <table className="np-kv">
                  <tbody>
                    <tr>
                      <th>设备描述</th>
                      <td className="np-mono">{dev.sys_descr || '—'}</td>
                    </tr>
                    <tr>
                      <th>设备名</th>
                      <td>{dev.sys_name || '—'}</td>
                    </tr>
                    <tr>
                      <th>位置</th>
                      <td>{dev.sys_location || '—'}</td>
                    </tr>
                    <tr>
                      <th>运行时长</th>
                      <td>{fmtUptime(dev.uptime_seconds)}</td>
                    </tr>
                    <tr>
                      <th>上次采集</th>
                      <td>
                        {fmtTime(dev.last_attempt_at)}
                        {dev.ok === false && (
                          <span className="np-inline-err">
                            （失败 ×{dev.consecutive_failures || 0}：{dev.error}）
                          </span>
                        )}
                      </td>
                    </tr>
                  </tbody>
                </table>
              </div>
            </div>
          )}

          <div className="np-row">
            <div className="np-row-head">
              <span className="np-row-name">端口列表</span>
              <span className="np-row-sub">
                共 {ifaces.length} 个
                {(!showAll && hiddenCount > 0) ? ` · 已隐藏 ${hiddenCount} 个虚拟 / 管理口` : ''}
                {ifiltered(ifaces.length, shownTotal)}
              </span>
              <span className="np-spacer" />
              <label className="np-toggle">
                <input
                  type="checkbox"
                  checked={showAll}
                  onChange={(e) => setShowAll(e.target.checked)}
                />
                显示全部端口
              </label>
            </div>
            <div className="np-row-body np-row-body-flush">
              {ifaces.length === 0 ? (
                <div className="np-empty-box">
                  {allIfaces.length > 0
                    ? '当前没有可显示的端口：物理口为空，其余都是虚拟 / 管理口（已隐藏）。勾上方「显示全部端口」可查看。'
                    : (data && data.snmp_enabled)
                      // 本页的「立即采集」按钮已去掉，指个真能点的地方
                      ? '还没有采集到端口。到「设备管理 - 网络设备」列表里点这台设备的「立即采集」拉一次。'
                      : '未启用 SNMP 采集，无端口数据。'}
                </div>
              ) : (
                <div className="np-table-wrap">
                  <table className="np-table">
                    <thead>
                      <tr>
                        <th style={{ width: 56 }}>索引</th>
                        <th style={{ width: 180 }}>端口</th>
                        <th>描述 / 对端</th>
                        <th style={{ width: 70 }}>管理</th>
                        <th style={{ width: 70 }}>运行</th>
                        {/* 原来这列叫「速率」，加了"入向速率/出向速率"之后两个"速率"挨在一起
                            分不清：这里是接口带宽（ifHighSpeed），那边是实测流量速率。 */}
                        <th style={{ width: 90 }} title="接口协商带宽（ifHighSpeed）">端口带宽</th>
                        <th style={{ width: 100 }}>入向速率</th>
                        <th style={{ width: 100 }}>出向速率</th>
                        <th style={{ width: 110 }} title="设备启动以来的累计字节，不是速率">入向累计</th>
                        <th style={{ width: 110 }} title="设备启动以来的累计字节，不是速率">出向累计</th>
                        <th style={{ width: 80 }}>入错包</th>
                        <th style={{ width: 80 }}>出错包</th>
                      </tr>
                    </thead>
                    <tbody>
                      {ifaces.map((i) => (
                        <tr key={i.if_index}>
                          <td className="np-num">{i.if_index}</td>
                          <td className="np-mono" title={i.if_name}>{i.if_name || `if${i.if_index}`}</td>
                          <td title={i.if_alias || i.if_descr}>{i.if_alias || i.if_descr || '—'}</td>
                          <td><StatusPill text={i.admin_status} /></td>
                          <td><StatusPill text={i.oper_status} /></td>
                          <td className="np-num">{i.if_speed_mbps ? `${i.if_speed_mbps} Mbps` : '—'}</td>
                          {/* 速率列：库里没有基线时后端给 null，显示"—"而不是 0 Mbps
                              （0 会被读成"这口真的没流量"） */}
                          <td className="np-num">{fmtRate(i.in_rate_mbps)}</td>
                          <td className="np-num">{fmtRate(i.out_rate_mbps)}</td>
                          <td className="np-num">{fmtBytes(i.in_octets)}</td>
                          <td className="np-num">{fmtBytes(i.out_octets)}</td>
                          <td className={`np-num ${(i.in_errors || 0) > 0 ? 'np-num-warn' : ''}`}>{i.in_errors || 0}</td>
                          <td className={`np-num ${(i.out_errors || 0) > 0 ? 'np-num-warn' : ''}`}>{i.out_errors || 0}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          </div>
        </div>
      </section>
    </div>
  )
}

function ifiltered(shown, total) {
  return shown === total ? '' : `（已过滤，共 ${total} 个）`
}
