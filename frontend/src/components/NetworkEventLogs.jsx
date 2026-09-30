/* 方案 B：网络设备「事件日志」页签 —— 设备日志
 *
 * 主机那套事件日志是「服务端 → Agent → Windows 事件日志」，网络设备装不上 Agent，
 * 也没有 Windows 事件日志可拉。所以这里合并三条流：
 *
 * · 设备（device） —— 2026-09-21 起，走「路线 A：只读 SSH 轮询」从设备
 * 内部拉回来的运行日志（华为 logbuffer / trapbuffer）。只发 display 命令，
 * 不改设备配置。设备日志只活在内存里（环形缓冲，实测已被覆盖 2207 次、重启即丢），
 * 不主动拉就查不到。
 * · 告警（Alert） —— 采集失败、端口 DOWN、指标越线、SSH 主机密钥变更
 * · 审计（OperationLog）—— 新增 / 连接 / 断开 / 改凭据 / 命令行登录
 *
 * 这仍**不是** syslog。设备主动推日志给服务端（UDP 514 / 162）是另一条路，
 * 需要动设备配置并在服务端起监听，页面底部如实写了这一点，不假装已经支持。 */
import { useCallback, useEffect, useMemo, useState } from 'react'
import { parseServerTime } from '../utils/format'
import { collectDeviceLogs, fetchNetworkDeviceLogs, resumeSnmpCollect } from '../services/api'
import './NetworkEventLogs.css'

const SOURCE_LABELS = {
  device: '设备',
  alert: '告警',
  audit: '审计',
}

const LEVEL_LABELS = {
  info: '信息',
  warning: '警告',
  error: '错误',
  critical: '严重',
}

const PAGE_SIZES = [20, 50, 100, 200]

function fmtTime(iso) {
  if (!iso) return '—'
  const d = parseServerTime(iso)
  if (Number.isNaN(d.getTime())) return '—'
  const p = (x) => String(x).padStart(2, '0')
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`
}

export default function NetworkEventLogs({ serverId }) {
  const [items, setItems] = useState([])
  const [collect, setCollect] = useState(null)
  const [deviceLogs, setDeviceLogs] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [source, setSource] = useState('all')
  const [busy, setBusy] = useState('')
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(50)

  const load = useCallback(async () => {
    setLoading(true)
    setError('')
    try {
      const res = await fetchNetworkDeviceLogs(serverId, 300)
      setItems(res.items || [])
      setCollect(res.collect || null)
      setDeviceLogs(res.device_logs || null)
    } catch (e) {
      setError(e.message || '加载设备日志失败')
    } finally {
      setLoading(false)
    }
  }, [serverId])

  useEffect(() => { load() }, [load])

  const list = source === 'all' ? items : items.filter((i) => i.source === source)

  // 筛选条件 / 每页条数变化时回到第一页（和主机事件日志同样的处理）
  useEffect(() => { setPage(1) }, [source, pageSize])

  const total = list.length
  const totalPages = Math.max(1, Math.ceil(total / pageSize))
  const safePage = Math.min(Math.max(1, page), totalPages)
  const pageRows = useMemo(
    () => list.slice((safePage - 1) * pageSize, safePage * pageSize),
    [list, safePage, pageSize]
  )

  const filterBtn = (key, label) => (
    <button
      key={key}
      className={`reg-filter-btn ${source === key ? 'active' : ''}`}
      onClick={() => setSource(key)}
    >{label}</button>
  )

  // 没配 CLI 登录凭据的设备后端会直接报错，这里在按钮上先禁掉并给出原因，
  const onCollectDeviceLogs = async () => {
    setBusy('collect')
    setError('')
    try {
      const res = await collectDeviceLogs(serverId)
      await load()
      if (res && res.ok === false) setError(res.error || '拉取设备内部日志失败')
    } catch (e) {
      setError(e.message || '拉取设备内部日志失败')
    } finally {
      setBusy('')
    }
  }

  // 解除 SNMP 采集熔断（连续认证失败后采集器自己停的采）
  const onResume = async () => {
    setBusy('resume')
    setError('')
    try {
      await resumeSnmpCollect(serverId)
      await load()
    } catch (e) {
      setError(e.message || '恢复采集失败')
    } finally {
      setBusy('')
    }
  }

  // ndl-card（2026-09-21 加）：整页收进一张大卡片。
  // 而那两套样式是给"多块拼起来"的页面用的（各块自己带边框）。
  // 所以这里挂一个自己的根类，在 NetworkEventLogs.css 里把内层边框全部抹掉 ——
  // 不要直接改 .reg-*，那会连带把 Agent 更新 / 主机列表页面一起改掉。
  return (
    <div className="reg-section ndl-card">
      <div className="reg-section-header">
        {/* 2026-09-21：「上次采集」原先单独占卡片第二行，按需求上移到工具栏标题后面。
 用一个 .ndl-head-left 把标题和它包起来，右侧按钮组仍旧靠右排。
 这里显示的是**设备日志**那条链路的状态（deviceLogs），不是 SNMP 的
 collect —— 这个页签讲的是设备内部日志，摆 SNMP 的"成功，10 个端口"
 只会让人以为内部日志拉成功了。

 2026-09-21 再改：按需求**只留时间**，后面那串说明文案（「成功，新增 N 条」
 /「失败：…」/「不支持，…」）全部取消显示。
 状态本身没有丢 —— 「拉取设备日志」按钮的悬浮提示里写着原因，
 不支持时按钮还是灰的；采集失败也仍然会在点按钮后以红字报出来。 */}
        <div className="ndl-head-left">
          <h3 className="reg-section-title">设备日志</h3>
          {deviceLogs && deviceLogs.last_attempt_at && (
            <span className="ndl-collect">
              <span className="ndl-collect-k">上次采集</span>
              <span className="ndl-collect-v">{fmtTime(deviceLogs.last_attempt_at)}</span>
            </span>
          )}
        </div>
        <div className="reg-header-actions">
          <div className="reg-filter-group">
            {filterBtn('all', '全部')}
            {filterBtn('device', '设备')}
            {filterBtn('alert', '告警')}
            {filterBtn('audit', '审计')}
          </div>
          {/* SNMP 进入熔断时给一个"恢复采集"入口 —— 否则用户改对了凭据也等不到自动恢复 */}
          {collect && collect.paused && (
            <button
              className="reg-refresh-btn ndl-resume-btn"
              onClick={onResume}
              disabled={busy === 'resume'}
              title="采集器因连续认证失败已暂停，改好 SNMP 凭据后点这里恢复"
            >{busy === 'resume' ? '恢复中…' : '恢复采集'}</button>
          )}
          <button
            className="reg-refresh-btn"
            onClick={onCollectDeviceLogs}
            disabled={busy === 'collect' || (deviceLogs && deviceLogs.supported === false)}
            title={
              deviceLogs && deviceLogs.supported === false
                ? (deviceLogs.reason || '该设备不支持采集内部日志')
                : deviceLogs && deviceLogs.need_credentials
                  ? '还没配置该设备的命令行（CLI）登录用户名 / 口令，配好后才能拉设备内部日志'
                  : '只读 SSH 到设备拉一次内部日志（display logbuffer / trapbuffer），不改设备配置'
            }
          >{busy === 'collect' ? '拉取中…' : '拉取设备日志'}</button>
          <button className="reg-refresh-btn" onClick={load} title="刷新">刷新</button>
        </div>
      </div>

      {error && <div className="agent-update-error">{error}</div>}

      {/* 熔断 / 设备日志采集失败的横幅：不放进表格，否则一屏日志看下来根本注意不到 */}
      {collect && collect.paused && (
        <div className="ndl-alert-bar">
          采集已暂停至 {fmtTime(collect.paused_until)} —— 连续认证失败后采集器主动停采，
          避免继续把本机 IP 锁死。请核对设备上的 SNMPv3 用户名 / 鉴权协议 / 加密协议 / 口令，
          改好后点右上角「恢复采集」。
        </div>
      )}

      {loading ? (
        <div className="reg-loading">加载中…</div>
      ) : total === 0 ? (
        <p className="reg-empty">
          这台设备还没有任何记录。
          {deviceLogs && deviceLogs.supported === false
            ? `设备内部日志不支持采集：${deviceLogs.reason || '该设备没有可轮询的命令行日志'}。`
            : '点「拉取设备日志」从设备内部拉一次；新增 / 连接 / 采集失败也会在这里留痕。'}
        </p>
      ) : (
        <div className="host-list-table-wrap">
          <table className="host-list-table">
            <thead>
              <tr>
                <th style={{ width: 160 }}>时间</th>
                <th style={{ width: 70 }}>来源</th>
                <th style={{ width: 70 }}>级别</th>
                <th>说明</th>
                {/* 设备日志没有"操作人"（是设备自己产生的），这一列给它显示产生日志的模块 */}
                <th style={{ width: 120 }}>操作人 / 模块</th>
              </tr>
            </thead>
            <tbody>
              {pageRows.map((r) => (
                <tr key={`${r.source}-${r.id}`}>
                  <td
                    className="ndl-time"
                    title={r.source === 'device' && r.device_time
                      ? `设备本地时间：${r.device_time}` : ''}
                  >{fmtTime(r.timestamp)}</td>
                  <td>
                    <span className={`ndl-src ndl-src-${r.source}`}>
                      {SOURCE_LABELS[r.source] || r.source}
                    </span>
                  </td>
                  <td>
                    <span className={`ndl-level ndl-level-${r.level}`}>
                      {LEVEL_LABELS[r.level] || r.level || '信息'}
                    </span>
                  </td>
                  <td className="ndl-msg" title={r.message || r.title}>
                    {r.source === 'device' && r.action
                      ? <span className="ndl-mnemonic" title={r.level_name || ''}>{r.action}</span>
                      : null}
                    {r.title || r.message || '—'}
                  </td>
                  <td>{r.source === 'device' ? (r.category || '—') : (r.username || '系统')}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* 状态栏：条数 + 每页条数 + 翻页 —— 与「主机事件日志」(.el-pagination) 同一套样式。
 2026-09-21：按需求把原本跟在「共 N 条」后面的描述文字（设备日志上次采集 / 底部说明）
 全部删掉，「上次采集」已经上移到工具栏标题后面了。 */}
      <div className="reg-panel-foot ndl-foot">
        <span className="ndl-total-count">共 {total} 条</span>
        <div className="ndl-page-size">
          <select
            className="ndl-page-size-select"
            value={pageSize}
            onChange={(e) => setPageSize(Number(e.target.value))}
            title="每页条数"
          >
            {PAGE_SIZES.map((s) => <option key={s} value={s}>{s}条/页</option>)}
          </select>
        </div>
        <span className="ndl-page-info">第 {safePage} / {totalPages} 页</span>
        <div className="ndl-page-buttons">
          <button className="btn-sm" disabled={safePage <= 1} onClick={() => setPage(1)}>首页</button>
          <button className="btn-sm" disabled={safePage <= 1} onClick={() => setPage((p) => Math.max(1, p - 1))}>上一页</button>
          <button className="btn-sm" disabled={safePage >= totalPages} onClick={() => setPage((p) => Math.min(totalPages, p + 1))}>下一页</button>
          <button className="btn-sm" disabled={safePage >= totalPages} onClick={() => setPage(totalPages)}>末页</button>
        </div>
      </div>    </div>
  )
}
