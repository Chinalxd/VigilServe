import { useState, useEffect, useCallback } from 'react'
import { fetchAlertLogs, fetchOperationLogs, fetchLogContext, exportLogsExcel, fetchServers, clearLogs } from '../services/api'
import { formatDateTime, localDateTime } from '../utils/format'
import DateTimeInput from './DateTimeInput'
import { usePerm } from '../services/permissions'
import './LogManagement.css'

const LEVEL_COLORS = {
  critical: '#d9534f',
  warning: '#f0ad4e',
  info: '#5cb85c',
  error: '#d9534f',
}

const CATEGORIES = ['login', 'user', 'server', 'config', 'alert', 'service', 'resource', 'terminal', 'agent', 'remote_desktop', 'system']
const CATEGORY_LABELS = {
  login: '登录',
  user: '用户',
  server: '主机',
  config: '配置',
  alert: '告警',
  service: '服务',
  resource: '资源管理',
  terminal: '终端',
  agent: 'Agent',
  remote_desktop: '远程桌面',
  system: '系统',
}
const LEVELS = ['info', 'warning', 'critical']
const LEVEL_LABELS = {
  info: '信息',
  warning: '警告',
  critical: '严重',
}

export default function LogManagement() {
  const { can } = usePerm()
  const canExport = can('sys', 'logs', 'edit', 'export')
  const canCleanup = can('sys', 'logs', 'edit', 'cleanup')
  const [tab, setTab] = useState('alerts')
  const [servers, setServers] = useState([])

  const now = new Date()
  const weekAgo = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000)
  const [filters, setFilters] = useState({
    start: localDateTime(weekAgo),
    end: localDateTime(now),
    keyword: '',
    regex: false,
    server_id: '',
    level: '',
    category: '',
    username: '',
  })

  const [data, setData] = useState({ total: 0, page: 1, page_size: 50, items: [] })
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(50)
  const [context, setContext] = useState(null)
  const [exporting, setExporting] = useState(false)
  const [clearing, setClearing] = useState(false)
  const [confirmClear, setConfirmClear] = useState(false)

  useEffect(() => {
    fetchServers().then(setServers).catch(() => {})
  }, [])

  const buildParams = useCallback(() => {
    const p = {
      start: new Date(filters.start).toISOString(),
      end: new Date(filters.end).toISOString(),
      keyword: filters.keyword || undefined,
      regex: filters.regex || undefined,
      page,
      page_size: pageSize,
    }
    if (tab === 'alerts') {
      if (filters.server_id) p.server_id = filters.server_id
      if (filters.level) p.level = filters.level
    } else {
      if (filters.category) p.category = filters.category
      if (filters.username) p.username = filters.username
    }
    return p
  }, [filters, page, pageSize, tab])

  const load = useCallback(async () => {
    setLoading(true)
    setError('')
    try {
      const params = buildParams()
      const res = tab === 'alerts' ? await fetchAlertLogs(params) : await fetchOperationLogs(params)
      setData(res)
    } catch (e) {
      setError(e.message || '加载失败')
    } finally {
      setLoading(false)
    }
  }, [buildParams, tab])

  useEffect(() => {
    setPage(1)
  }, [tab, filters.server_id, filters.level, filters.category, filters.username, filters.keyword, filters.regex, pageSize])

  useEffect(() => {
    const t = setTimeout(() => load(), 200)
    return () => clearTimeout(t)
  }, [load])

  const handleSearch = (e) => {
    e.preventDefault()
    setPage(1)
    load()
  }

  const handleReset = () => {
    setFilters({
      start: localDateTime(weekAgo),
      end: localDateTime(now),
      keyword: '',
      regex: false,
      server_id: '',
      level: '',
      category: '',
      username: '',
    })
    setPage(1)
  }

  const handleExport = async () => {
    setExporting(true)
    try {
      await exportLogsExcel(tab, buildParams())
    } catch (e) {
      setError(e.message || '导出失败')
    } finally {
      setExporting(false)
    }
  }

  const handleClear = async () => {
    setClearing(true)
    try {
      const params = buildParams()
      delete params.page
      delete params.page_size
      const res = await clearLogs(tab, params)
      setError('')
      setPage(1)
      load()
      window.alert(res.message || `已清除 ${res.deleted} 条日志`)
    } catch (e) {
      setError(e.message || '清除失败')
    } finally {
      setClearing(false)
      setConfirmClear(false)
    }
  }

  const openContext = async (item) => {
    try {
      const params = buildParams()
      delete params.page
      delete params.page_size
      const res = await fetchLogContext(tab, item.id, params)
      setContext({ ...res, type: tab })
    } catch (e) {
      setError(e.message || '加载上下文失败')
    }
  }

  const totalPages = Math.max(1, Math.ceil(data.total / pageSize))

  return (
    <div className="log-management">
      <div className="log-tabs">
        <button className={`log-tab ${tab === 'alerts' ? 'active' : ''}`} onClick={() => setTab('alerts')}>
          告警日志
        </button>
        <button className={`log-tab ${tab === 'operations' ? 'active' : ''}`} onClick={() => setTab('operations')}>
          操作日志
        </button>
      </div>

      <div className="log-card">
        <form className="log-filter-bar" onSubmit={handleSearch}>
          <div className="log-filter-group">
            <label>开始时间</label>
            <DateTimeInput
              value={filters.start}
              onChange={(iso) => setFilters({ ...filters, start: iso })}
            />
          </div>
          <div className="log-filter-group">
            <label>结束时间</label>
            <DateTimeInput
              value={filters.end}
              onChange={(iso) => setFilters({ ...filters, end: iso })}
            />
          </div>

          {tab === 'alerts' ? (
            <>
              <div className="log-filter-group">
                <label>主机</label>
                <select className="form-input-sm" value={filters.server_id} onChange={(e) => setFilters({ ...filters, server_id: e.target.value })}>
                  <option value="">全部主机</option>
                  {servers.map((s) => (
                    <option key={s.id} value={s.id}>{s.name} ({s.ip_address})</option>
                  ))}
                </select>
              </div>
            <div className="log-filter-group">
              <label>级别</label>
              <select className="form-input-sm" value={filters.level} onChange={(e) => setFilters({ ...filters, level: e.target.value })}>
                <option value="">全部级别</option>
                {LEVELS.map((l) => <option key={l} value={l}>{LEVEL_LABELS[l] || l}</option>)}
              </select>
            </div>
            </>
          ) : (
            <>
              <div className="log-filter-group">
                <label>分类</label>
                <select className="form-input-sm" value={filters.category} onChange={(e) => setFilters({ ...filters, category: e.target.value })}>
                  <option value="">全部分类</option>
                  {CATEGORIES.map((c) => <option key={c} value={c}>{CATEGORY_LABELS[c] || c}</option>)}
                </select>
              </div>
              <div className="log-filter-group">
                <label>用户</label>
                <input
                  type="text"
                  className="form-input-sm"
                  placeholder="用户姓名/登录名"
                  value={filters.username}
                  onChange={(e) => setFilters({ ...filters, username: e.target.value })}
                />
              </div>
            </>
          )}

          <div className="log-filter-group log-keyword">
            <label>关键词 / 正则</label>
            <div className="log-keyword-row">
              <input
                type="text"
                className="form-input-sm log-keyword-input"
                placeholder="输入后按回车查询"
                value={filters.keyword}
                onChange={(e) => setFilters({ ...filters, keyword: e.target.value })}
              />
              <label className="log-regex-label">
                <input
                  type="checkbox"
                  checked={filters.regex}
                  onChange={(e) => setFilters({ ...filters, regex: e.target.checked })}
                />
                正则
              </label>
            </div>
          </div>

          <div className="log-filter-actions">
            <button type="button" className="btn-cancel" onClick={handleReset}>重置</button>
            <button type="button" className="btn-cancel" onClick={load} disabled={loading}>
              {loading ? '刷新中…' : '刷新'}
            </button>
            {canExport && (
              <button type="button" className="btn-cancel" onClick={handleExport} disabled={exporting || loading}>
                {exporting ? '导出中…' : '导出 Excel'}
              </button>
            )}
            {canCleanup && (
              <button type="button" className="btn-danger" onClick={() => setConfirmClear(true)} disabled={clearing || loading}>
                {clearing ? '清除中…' : '清除日志'}
              </button>
            )}
          </div>
        </form>

        {error && <div className="log-error">{error}</div>}

        <div className="log-table-panel">
          {tab === 'alerts' ? (
          <table className="log-table">
            <thead>
              <tr>
                <th>时间</th>
                <th>主机</th>
                <th>级别</th>
                <th>类型</th>
                <th>标题</th>
                <th>消息</th>
                <th>状态</th>
                <th>操作</th>
              </tr>
            </thead>
            <tbody>
              {data.items.map((item) => (
                <tr key={item.id}>
                  <td>{formatDateTime(item.timestamp)}</td>
                  <td>{item.server_name || '—'}</td>
                  <td>
                    <span className="log-level-badge" style={{ background: LEVEL_COLORS[item.level] || '#777' }}>
                      {LEVEL_LABELS[item.level] || item.level}
                    </span>
                  </td>
                  <td>{item.metric_type || '—'}</td>
                  <td>{item.title}</td>
                  <td className="log-message">{item.message}</td>
                  <td>{item.acknowledged ? '已确认' : '未确认'}</td>
                  <td><button className="btn-sm" onClick={() => openContext(item)}>上下文</button></td>
                </tr>
              ))}
              {data.items.length === 0 && !loading && (
                <tr><td colSpan={8} className="log-empty">暂无告警日志</td></tr>
              )}
            </tbody>
          </table>
        ) : (
          <table className="log-table">
            <thead>
              <tr>
                <th>时间</th>
                <th>级别</th>
                <th>分类</th>
                <th>动作</th>
                <th>状态</th>
                <th>用户</th>
                <th>来源IP</th>
                <th>目标</th>
                <th>消息</th>
                <th>操作</th>
              </tr>
            </thead>
            <tbody>
              {data.items.map((item) => (
                <tr key={item.id}>
                  <td>{formatDateTime(item.timestamp)}</td>
                  <td>
                    <span className="log-level-badge" style={{ background: LEVEL_COLORS[item.level] || '#777' }}>
                      {LEVEL_LABELS[item.level] || item.level}
                    </span>
                  </td>
                  <td>{CATEGORY_LABELS[item.category] || item.category}</td>
                  <td>{item.action}</td>
                  <td>{item.status === 'success' ? '成功' : (item.status === 'failed' ? '失败' : (item.status || '—'))}</td>
                  <td>{item.full_name || item.username || '—'}</td>
                  <td>{item.ip_address || '—'}</td>
                  <td>{item.target_type ? `${item.target_type}:${item.target_id}` : '—'}</td>
                  <td className="log-message">{item.message}</td>
                  <td><button className="btn-sm" onClick={() => openContext(item)}>上下文</button></td>
                </tr>
              ))}
              {data.items.length === 0 && !loading && (
                <tr><td colSpan={10} className="log-empty">暂无操作日志</td></tr>
              )}
            </tbody>
          </table>
        )}
        {loading && <div className="log-loading">加载中…</div>}
      </div>

        <div className="log-pagination">
          <div className="log-total-count">共 {data.total} 条记录</div>
          <div className="log-page-size">
            <select className="log-page-size-select" value={pageSize} onChange={(e) => setPageSize(Number(e.target.value))} title="每页条数">
              {[20, 50, 100, 200].map((s) => <option key={s} value={s}>{s}条/页</option>)}
            </select>
          </div>
          <div className="log-page-info">第 {page} / {totalPages} 页</div>
          <div className="log-page-buttons">
            <button className="btn-sm" disabled={page <= 1} onClick={() => setPage(1)}>首页</button>
            <button className="btn-sm" disabled={page <= 1} onClick={() => setPage((p) => p - 1)}>上一页</button>
            <button className="btn-sm" disabled={page >= totalPages} onClick={() => setPage((p) => p + 1)}>下一页</button>
            <button className="btn-sm" disabled={page >= totalPages} onClick={() => setPage(totalPages)}>末页</button>
          </div>
        </div>
      </div>

      {context && (
        <div className="log-modal-overlay" onClick={() => setContext(null)}>
          <div className="log-modal" onClick={(e) => e.stopPropagation()}>
            <div className="log-modal-header">
              <h3>日志上下文</h3>
              <button className="log-modal-close" onClick={() => setContext(null)}>×</button>
            </div>
            <div className="log-modal-body">
              {context.before.length > 0 && (
                <>
                  <div className="log-context-label">上文</div>
                  {context.before.map((item) => (
                    <div key={item.id} className="log-context-item">
                      <span className="log-context-time">{formatDateTime(item.timestamp)}</span>
                      <span className="log-context-text">{item.title || item.message || item.action}</span>
                    </div>
                  ))}
                </>
              )}
              <div className="log-context-label current">当前记录</div>
              <div className="log-context-item current">
                <span className="log-context-time">{formatDateTime(context.record.timestamp)}</span>
                <span className="log-context-text">{context.record.title || context.record.message || context.record.action}</span>
              </div>
              {context.after.length > 0 && (
                <>
                  <div className="log-context-label">下文</div>
                  {context.after.map((item) => (
                    <div key={item.id} className="log-context-item">
                      <span className="log-context-time">{formatDateTime(item.timestamp)}</span>
                      <span className="log-context-text">{item.title || item.message || item.action}</span>
                    </div>
                  ))}
                </>
              )}
            </div>
          </div>
        </div>
      )}

      {confirmClear && (
        <div className="log-modal-overlay" onClick={() => setConfirmClear(false)}>
          <div className="log-modal log-modal-sm" onClick={(e) => e.stopPropagation()}>
            <div className="log-modal-header">
              <h3>确认清除日志</h3>
              <button className="log-modal-close" onClick={() => setConfirmClear(false)}>×</button>
            </div>
            <div className="log-modal-body">
              <p style={{ margin: '0 0 12px', lineHeight: 1.6 }}>
                即将按当前筛选条件清除<strong>{tab === 'alerts' ? '告警日志' : '操作日志'}</strong>。
              </p>
              <p style={{ margin: '0 0 16px', color: '#d9534f', fontSize: 13 }}>
                清除后不可恢复，建议先导出备份。最近 1 小时内的活跃日志会被自动保留，不会删除。
              </p>
              <div style={{ textAlign: 'right' }}>
                <button className="btn-cancel" onClick={() => setConfirmClear(false)} style={{ marginRight: 8 }}>取消</button>
                <button className="btn-danger" onClick={handleClear} disabled={clearing}>
                  {clearing ? '清除中…' : '确认清除'}
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
