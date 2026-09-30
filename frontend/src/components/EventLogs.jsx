import { useState, useEffect, useMemo, useCallback } from 'react'
import { fetchHostEventLogs, USE_MOCK } from '../services/hostInfo'
import './EventLogs.css'

const LOGS = [
  { key: 'all', label: 'ALL' },
  { key: 'System', label: 'System' },
  { key: 'Application', label: 'Application' },
  { key: 'Security', label: 'Security' },
  { key: 'Setup', label: 'Setup' },
]

const LEVELS = [
  { key: 'all', label: '全部' },
  { key: '严重', label: '严重' },
  { key: '错误', label: '错误' },
  { key: '警告', label: '警告' },
]

const PAGE_SIZES = [20, 50, 100, 200]

const FETCH_LIMIT = 500

/** 默认只采集最近 3 天的日志（Agent 侧在未传起止时间时也用这个窗口） */
const DEFAULT_RANGE_DAYS = 3

const _pad = (n) => String(n).padStart(2, '0')

function toLocalInput(d) {
  return `${d.getFullYear()}-${_pad(d.getMonth() + 1)}-${_pad(d.getDate())}T${_pad(d.getHours())}:${_pad(d.getMinutes())}`
}

function defaultRange() {
  const end = new Date()
  const start = new Date(end.getTime() - DEFAULT_RANGE_DAYS * 86400 * 1000)
  return { start: toLocalInput(start), end: toLocalInput(end) }
}

function levelClass(level) {
  if (level === '严重' || level === 'critical') return 'lv-critical'
  if (level === '错误' || level === 'error') return 'lv-error'
  if (level === '警告' || level === 'warning') return 'lv-warning'
  return 'lv-info'
}

/** 三个来源的级别写法不一致（中文 / 英文），归一化后才能用同一组按钮筛选 */
function normLevel(v) {
  const s = String(v ?? '').toLowerCase()
  if (s === '严重' || s === 'critical' || s === 'fatal') return '严重'
  if (s === '错误' || s === 'error') return '错误'
  if (s === '警告' || s === 'warning' || s === 'warn') return '警告'
  return '信息'
}

/**
 * 事件属于哪个日志：优先用 Agent 给的 log（英文原名），
 * 旧 Agent 只给中文 category 时按映射回推。
 */
function logOf(e) {
  if (e?.log) return String(e.log)
  const c = String(e?.category || '')
  if (c === '系统') return 'System'
  if (c === '应用程序') return 'Application'
  if (c === '安全') return 'Security'
  if (c === '安装' || /setup/i.test(c)) return 'Setup'
  return ''
}

export default function EventLogs({ serverId }) {
  const [log, setLog] = useState('all')
  const [level, setLevel] = useState('all')
  const [keyword, setKeyword] = useState('')
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(50)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  const [sysEvents, setSysEvents] = useState([])
  // 采集时间窗口：默认「近 3 天」，可改成任意自定义区间
  const [range, setRange] = useState(defaultRange)

  const load = useCallback(async () => {
    setLoading(true)
    setError('')
    try {
      const e = await fetchHostEventLogs(serverId, {
        level: 'all',
        limit: FETCH_LIMIT,
        start: range.start || '',
        end: range.end || '',
      }).catch(() => [])
      setSysEvents(e)
    } catch (err) {
      setError(err.message || '加载失败')
    } finally {
      setLoading(false)
    }
  }, [serverId, range])

  useEffect(() => { load() }, [load])

  const kw = keyword.trim().toLowerCase()

  const rows = useMemo(
    () => sysEvents
      .filter((i) => log === 'all' || logOf(i) === log)
      .filter((i) => [i.source, i.message, i.event_id, i.category].some((v) => String(v ?? '').toLowerCase().includes(kw)))
      .filter((i) => level === 'all' || normLevel(i.level) === level),
    [sysEvents, log, level, kw]
  )

  useEffect(() => { setPage(1) }, [log, level, kw, pageSize])

  const total = rows.length
  const totalPages = Math.max(1, Math.ceil(total / pageSize))
  const safePage = Math.min(Math.max(1, page), totalPages)
  const pageRows = rows.slice((safePage - 1) * pageSize, safePage * pageSize)

  // 列宽（2026-09-21 修）：表格改成 `table-layout: fixed` —— 见 EventLogs.css 的说明。
  // 左侧五列给死宽度并禁止换行；描述列截获剩下的宽度，长串（SQL Server 那些
  const columns = [
    { key: 'time', title: '时间', width: '160px', cls: 'el-nowrap' },
    { key: 'category', title: '日志', width: '80px', cls: 'el-nowrap' },
    { key: 'source', title: '来源', width: '200px', cls: 'el-break' },
    { key: 'event_id', title: '事件 ID', width: '80px', cls: 'el-nowrap' },
    { key: 'level', title: '级别', width: '70px', cls: 'el-nowrap', render: (r) => <span className={`el-tag ${levelClass(r.level)}`}>{r.level}</span> },
    { key: 'message', title: '描述', cls: 'el-msg' },
  ]

  return (
    <div className="event-logs">
      <div className="el-card">
        <div className="el-toolbar">
          <div className="el-tab-group">
            {LOGS.map((t) => (
              <button key={t.key} className={`el-tab-btn ${log === t.key ? 'active' : ''}`} onClick={() => setLog(t.key)}>
                {t.label}
              </button>
            ))}
          </div>

          <div className="el-filter-group">
            {LEVELS.map((l) => (
              <button key={l.key} className={`el-filter ${level === l.key ? 'active' : ''}`} onClick={() => setLevel(l.key)}>
                {l.label}
              </button>
            ))}
          </div>

          <input
            className="el-search"
            value={keyword}
            onChange={(e) => setKeyword(e.target.value)}
            placeholder="搜索来源 / 事件 ID / 描述"
          />

          <div className="el-range">
            <span className="el-range-label">时间</span>
            <input
              className="el-datetime"
              type="datetime-local"
              value={range.start}
              onChange={(e) => setRange((r) => ({ ...r, start: e.target.value }))}
              title="起始时间"
            />
            <span className="el-range-sep">至</span>
            <input
              className="el-datetime"
              type="datetime-local"
              value={range.end}
              onChange={(e) => setRange((r) => ({ ...r, end: e.target.value }))}
              title="结束时间"
            />
          </div>

          <button className="el-btn" onClick={load} disabled={loading}>
            {loading ? '刷新中…' : '刷新'}
          </button>
        </div>

        {USE_MOCK && <div className="el-mock-tip">系统事件为示例数据（前端先行），需由 Agent 采集 Windows 事件日志后接入。</div>}
        {error && <div className="el-error">{error}</div>}

        <div className="el-table-wrap">
          {loading ? (
            <div className="el-loading">加载中…</div>
          ) : (
            <table className="el-table">
              <thead>
                <tr>{columns.map((c) => <th key={c.key} style={c.width ? { width: c.width } : undefined}>{c.title}</th>)}</tr>
              </thead>
              <tbody>
                {pageRows.map((r, i) => (
                  <tr key={r.id ?? i}>
                    {columns.map((c) => <td key={c.key} className={c.cls}>{c.render ? c.render(r) : (r[c.key] ?? '—')}</td>)}
                  </tr>
                ))}
                {pageRows.length === 0 && (
                  <tr><td colSpan={columns.length} className="el-empty">暂无记录</td></tr>
                )}
              </tbody>
            </table>
          )}
        </div>

        {/* 状态栏：汇总条数 / 每页条数 / 翻页 —— 样式参考「日志管理」页面 */}
        <div className="el-pagination">
          <span className="el-total-count">共 {total} 条记录</span>
          <div className="el-page-size">
            <select
              className="el-page-size-select"
              value={pageSize}
              onChange={(e) => setPageSize(Number(e.target.value))}
              title="每页条数"
            >
              {PAGE_SIZES.map((s) => <option key={s} value={s}>{s}条/页</option>)}
            </select>
          </div>
          <span className="el-page-info">第 {safePage} / {totalPages} 页</span>
          <div className="el-page-buttons">
            <button className="btn-sm" disabled={safePage <= 1} onClick={() => setPage(1)}>首页</button>
            <button className="btn-sm" disabled={safePage <= 1} onClick={() => setPage((p) => Math.max(1, p - 1))}>上一页</button>
            <button className="btn-sm" disabled={safePage >= totalPages} onClick={() => setPage((p) => Math.min(totalPages, p + 1))}>下一页</button>
            <button className="btn-sm" disabled={safePage >= totalPages} onClick={() => setPage(totalPages)}>末页</button>
          </div>
        </div>
      </div>
    </div>
  )
}
