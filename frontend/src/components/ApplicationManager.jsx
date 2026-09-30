import { useState, useEffect, useMemo, useCallback } from 'react'
import { usePerm } from '../services/permissions'
import {
  fetchApplications,
  fetchSystemUpdates,
  fetchStartupItems,
  uninstallApplications,
  toggleStartupItem,
  isSystemApp,
  refreshHostInfo,
  USE_MOCK,
} from '../services/hostInfo'
import './ApplicationManager.css'

const CATEGORIES = [
  { key: 'all', label: '全部应用' },
  { key: 'user', label: '用户应用' },
  { key: 'system', label: '系统应用' },
  { key: 'updates', label: '更新补丁' },
]

/** 启动项管理：顶部视图页签之一（与「应用管理」并列，不再放在工具栏按钮里） */
const STARTUP_KEY = 'startup'

function fmtSize(mb) {
  if (mb === null || mb === undefined) return '—'
  if (mb >= 1024) return `${(mb / 1024).toFixed(1)} GB`
  return `${mb} MB`
}

export default function ApplicationManager({ serverId }) {
  const { can } = usePerm()
  const canUninstall = can('host', 'apps', 'edit', 'uninstall')
  const canStartup = can('host', 'apps', 'edit', 'startup')

  const [apps, setApps] = useState([])
  const [updates, setUpdates] = useState([])
  const [startup, setStartup] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [category, setCategory] = useState('all')
  const [lastAppCat, setLastAppCat] = useState('all')
  const [keyword, setKeyword] = useState('')
  const [selected, setSelected] = useState(new Set())
  const [confirm, setConfirm] = useState(null)
  const [uninstalling, setUninstalling] = useState(false)
  const [toggleTarget, setToggleTarget] = useState(null)
  const [toggling, setToggling] = useState(false)
  const [result, setResult] = useState(null)
  const [refreshing, setRefreshing] = useState(false)

  // 注意：load 必须先声明 —— onRefresh 的依赖数组里要引用 load，
  // 依赖数组在渲染时就求值，声明顺序反了会直接 ReferenceError（TDZ）。
  const load = useCallback(async () => {
    setLoading(true)
    setError('')
    try {
      const [a, u, s] = await Promise.all([
        fetchApplications(serverId).catch(() => []),
        fetchSystemUpdates(serverId).catch(() => []),
        fetchStartupItems(serverId).catch(() => []),
      ])
      setApps(a)
      setUpdates(u)
      setStartup(s)
    } catch (e) {
      setError(e.message || '加载失败')
    } finally {
      setLoading(false)
    }
  }, [serverId])

  // 点「刷新」走服务端的异步采集队列：HTTP 不等 WMI 跑完，只轮询任务状态。
  // 应用列表一轮 WMI 能到几十秒，以前点一下刷新页面就卡住不动。
  const onRefresh = useCallback(async () => {
    setRefreshing(true)
    setError('')
    try {
      await refreshHostInfo(serverId, ['applications', 'app-updates'])
      await load()
    } catch (e) {
      setError(e.message || '刷新失败')
    } finally {
      setRefreshing(false)
    }
  }, [serverId, load])

  useEffect(() => { load() }, [load])

  const kw = keyword.trim().toLowerCase()

  const rows = useMemo(() => {
    if (category === STARTUP_KEY) {
      return startup
        .filter((s) => !kw || [s.name, s.command, s.location].some((v) => String(v || '').toLowerCase().includes(kw)))
        .map((s) => ({ ...s, _kind: 'startup' }))
    }
    if (category === 'updates') {
      return updates
        .filter((u) => !kw || String(u.title || '').toLowerCase().includes(kw) || String(u.kb || '').toLowerCase().includes(kw))
        .map((u) => ({ ...u, _kind: 'update' }))
    }
    return apps
      // 系统/用户分类不再按注册表位置（HKLM/HKCU）划分，改按「是否系统组件」判定，
      // 否则第三方软件（360、Adobe、RustDesk 等）会被错分进系统应用
      .filter((a) => {
        if (category === 'all') return true
        if (category === 'system') return isSystemApp(a)
        if (category === 'user') return !isSystemApp(a)
        return a.scope === category
      })
      .filter((a) => !kw || String(a.name || '').toLowerCase().includes(kw) || String(a.publisher || '').toLowerCase().includes(kw))
      .map((a) => ({ ...a, _kind: 'app' }))
  }, [apps, updates, startup, category, kw])

  const uninstallableSelected = useMemo(
    () => [...selected].filter((id) => {
      const r = rows.find((x) => String(x.id) === String(id))
      return r && r.uninstallable
    }),
    [selected, rows]
  )

  const switchCategory = (key) => {
    if (key !== STARTUP_KEY) setLastAppCat(key)
    setCategory(key)
    setSelected(new Set())
  }

  const switchView = (view) => switchCategory(view === 'startup' ? STARTUP_KEY : lastAppCat)

  const toggle = (id) => setSelected((prev) => {
    const next = new Set(prev)
    if (next.has(id)) next.delete(id)
    else next.add(id)
    return next
  })

  const toggleAll = () => {
    const uninstallable = rows.filter((r) => r.uninstallable).map((r) => r.id)
    if (uninstallable.length === 0) return
    const allSel = uninstallable.every((id) => selected.has(id))
    setSelected((prev) => {
      const next = new Set(prev)
      uninstallable.forEach((id) => (allSel ? next.delete(id) : next.add(id)))
      return next
    })
  }

  const askUninstall = (r) => setConfirm({ ids: [r.id], names: [r.name] })
  const askUninstallSelected = () => {
    if (uninstallableSelected.length === 0) return
    const names = uninstallableSelected.map((id) => rows.find((x) => String(x.id) === String(id))?.name).filter(Boolean)
    setConfirm({ ids: uninstallableSelected, names })
  }

  const doUninstall = async () => {
    const ids = confirm.ids
    setUninstalling(true)
    try {
      const res = await uninstallApplications(serverId, ids)
      // Agent 现在会等卸载程序跑完并复查注册表，逐项回报真实结果
      const items = ids.map((id) => {
        const row = [...apps, ...updates].find((x) => String(x.id) === String(id))
        const r = (res.results || []).find((x) => String(x.id) === String(id))
        return {
          name: row?.name || id,
          ok: r ? r.ok !== false : false,
          mode: r?.mode || 'none',
          message: r?.message || 'Agent 未返回该项结果',
        }
      })
      const okCount = items.filter((it) => it.ok).length
      const allOk = okCount === items.length
      setResult({
        ok: allOk,
        title: allOk ? '卸载完成'
          : (okCount > 0 ? `部分完成（成功 ${okCount} / 共 ${items.length}）` : '卸载未完成'),
        items,
      })
      setSelected(new Set())
      await load()
    } catch (e) {
      setResult({ ok: false, title: '卸载失败', items: [{ name: '卸载失败', message: e.message, ok: false }] })
    } finally {
      setUninstalling(false)
      setConfirm(null)
    }
  }

  const askToggle = (item) => setToggleTarget({ item, enabled: !item.enabled })

  const doToggle = async () => {
    const { item, enabled } = toggleTarget
    setToggling(true)
    try {
      const res = await toggleStartupItem(serverId, item.id, enabled)
      const next = res && typeof res.enabled === 'boolean' ? res.enabled : enabled
      setStartup((prev) => prev.map((s) => (String(s.id) === String(item.id) ? { ...s, enabled: next } : s)))
      setResult({
        ok: true,
        title: '启动项已更新',
        items: [{ name: item.name, message: next ? '已设为开机启动' : '已禁止开机启动' }],
      })
    } catch (e) {
      setResult({ ok: false, title: '启动项更新失败', items: [{ name: item.name, message: e.message }] })
    } finally {
      setToggling(false)
      setToggleTarget(null)
    }
  }

  if (loading) return <div className="am-loading">正在读取应用列表…</div>

  const isUpdates = category === 'updates'
  const isStartup = category === STARTUP_KEY
  const colSpan = isStartup ? 6 : (isUpdates ? 7 : 8)

  return (
    <div className="app-manager">
      <section className="am-panel">
        <div className="am-view-tabs">
          <button
            className={`am-view-tab ${!isStartup ? 'active' : ''}`}
            onClick={() => switchView('apps')}
          >
            应用管理
          </button>
          <button
            className={`am-view-tab ${isStartup ? 'active' : ''}`}
            onClick={() => switchView('startup')}
            disabled={!canStartup}
            title={canStartup ? '查看与管理本机启动项' : '当前角色没有管理启动项的权限'}
          >
            启动项管理
          </button>
        </div>

        <header className="am-panel-head">
          {!isStartup && (
            <div className="am-filter-group">
              {CATEGORIES.map((c) => (
                <button
                  key={c.key}
                  className={`am-filter ${category === c.key ? 'active' : ''}`}
                  onClick={() => switchCategory(c.key)}
                >
                  {c.label}
                </button>
              ))}
            </div>
          )}
          <span className="am-spacer" />
          <input
            className="am-search"
            value={keyword}
            onChange={(e) => setKeyword(e.target.value)}
            placeholder={isUpdates ? '搜索补丁标题 / KB 号' : (isStartup ? '搜索启动项 / 命令' : '搜索应用 / 发布者')}
          />
          <button className="am-btn" onClick={onRefresh} disabled={refreshing || loading}>
            {refreshing ? '采集中…' : '刷新'}
          </button>
          {!isStartup && (
            <button
              className="am-btn am-btn-danger"
              onClick={askUninstallSelected}
              disabled={!canUninstall || uninstallableSelected.length === 0}
              title={canUninstall ? `卸载选中的 ${uninstallableSelected.length} 个应用` : '当前角色没有卸载应用的权限'}
            >
              一键卸载{uninstallableSelected.length > 0 ? ` (${uninstallableSelected.length})` : ''}
            </button>
          )}
        </header>

        <div className="am-panel-body">
          {USE_MOCK && (
            <div className="am-mock-tip">当前为示例数据（前端先行），后端与 Agent 采集落地后自动切换为真实数据。</div>
          )}
          {error && <div className="am-error">{error}</div>}

          <div className="am-table-wrap">
            <table className="am-table">
              <thead>
                <tr>
                  {!isStartup && (
                    <th className="am-col-check">
                      <input
                        type="checkbox"
                        checked={rows.filter((r) => r.uninstallable).length > 0
                          && rows.filter((r) => r.uninstallable).every((r) => selected.has(r.id))}
                        onChange={toggleAll}
                        disabled={!canUninstall || rows.filter((r) => r.uninstallable).length === 0}
                        title="全选可卸载项"
                      />
                    </th>
                  )}
                  {isUpdates ? (
                    <>
                      <th className="am-col-kb">KB</th>
                      <th>标题</th>
                      <th className="am-col-cat">类别</th>
                      <th className="am-col-sev">级别</th>
                      <th className="am-col-date">安装时间</th>
                      <th className="am-col-ops">操作</th>
                    </>
                  ) : isStartup ? (
                    <>
                      <th>名称</th>
                      <th>命令</th>
                      <th className="am-col-loc">位置</th>
                      <th className="am-col-impact">影响</th>
                      <th className="am-col-state">状态</th>
                      <th className="am-col-ops">操作</th>
                    </>
                  ) : (
                    <>
                      <th>应用名称</th>
                      <th className="am-col-ver">版本</th>
                      <th className="am-col-pub">发布者</th>
                      <th className="am-col-date">安装日期</th>
                      <th className="am-col-size">大小</th>
                      <th className="am-col-path">安装位置</th>
                      <th className="am-col-ops">操作</th>
                    </>
                  )}
                </tr>
              </thead>
              <tbody>
                {rows.map((r) => (
                  <tr key={r.id}>
                    {isStartup ? (
                      <>
                        <td className="am-name" title={r.name}>{r.name}</td>
                        <td className="am-col-cmd" title={r.command}>{r.command || '—'}</td>
                        <td className="am-col-loc" title={r.location}>{r.location || '—'}</td>
                        <td className="am-col-impact">{r.impact || '—'}</td>
                        <td className="am-col-state">
                          {r.enabled
                            ? <span className="am-state am-state-on">已启动</span>
                            : <span className="am-state am-state-off">已禁用</span>}
                        </td>
                        <td className="am-col-ops">
                          <button
                            className={`am-btn-state ${r.enabled ? 'on' : 'off'}`}
                            onClick={() => askToggle(r)}
                            disabled={!canStartup}
                            title={canStartup
                              ? (r.enabled ? '点击禁止开机启动' : '点击设为开机启动')
                              : '当前角色没有修改启动项的权限'}
                          >
                            {/* 按钮是「动作」而不是「状态」：已启动 → 关闭，已禁用 → 启动 */}
                            {r.enabled ? '关闭' : '启动'}
                          </button>
                        </td>
                      </>
                    ) : (
                      <>
                        <td className="am-col-check">
                          <input
                            type="checkbox"
                            checked={selected.has(r.id)}
                            onChange={() => toggle(r.id)}
                            disabled={!r.uninstallable || !canUninstall}
                            title={r.uninstallable ? '' : '该应用不可卸载'}
                          />
                        </td>
                        {isUpdates ? (
                          <>
                            <td className="am-col-kb">{r.kb}</td>
                            <td className="am-name" title={r.title}>{r.title}</td>
                            <td className="am-col-cat">{r.category}</td>
                            <td className="am-col-sev">{r.severity}</td>
                            <td className="am-col-date">{r.installed_on}</td>
                            <td className="am-col-ops">
                              {r.uninstallable && canUninstall ? (
                                <button className="am-link-danger" onClick={() => askUninstall(r)}>卸载</button>
                              ) : <span className="am-na">不可卸载</span>}
                            </td>
                          </>
                        ) : (
                          <>
                            <td className="am-name" title={r.name}>{r.name}</td>
                            <td className="am-col-ver">{r.version || '—'}</td>
                            <td className="am-col-pub" title={r.publisher}>{r.publisher || '—'}</td>
                            <td className="am-col-date">{r.installed_on || '—'}</td>
                            <td className="am-col-size">{fmtSize(r.size_mb)}</td>
                            <td className="am-col-path" title={r.install_location}>{r.install_location || '—'}</td>
                            <td className="am-col-ops">
                              {!r.uninstallable ? (
                                <span className="am-na">不可卸载</span>
                              ) : canUninstall ? (
                                <button className="am-link-danger" onClick={() => askUninstall(r)}>卸载</button>
                              ) : (
                                <span className="am-na">无权限</span>
                              )}
                            </td>
                          </>
                        )}
                      </>
                    )}
                  </tr>
                ))}
                {rows.length === 0 && (
                  <tr>
                    <td colSpan={colSpan} className="am-empty">
                      {kw ? '没有匹配的记录' : (isStartup ? '暂无启动项' : (isUpdates ? '暂无更新补丁' : '暂无应用数据'))}
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>

        {/* 底部状态栏：统计项数在左侧，全部项目一页显示、不翻页 */}
        <footer className="am-panel-foot">
          <span className="am-count">共 {rows.length} 项</span>
        </footer>
      </section>

      {confirm && (
        <div className="am-modal-overlay" onClick={() => setConfirm(null)}>
          <div className="am-modal" onClick={(e) => e.stopPropagation()}>
            <div className="am-modal-head">确认卸载</div>
            <div className="am-modal-body">
              <p>确定要卸载以下 {confirm.names.length} 项吗？</p>
              <ul className="am-list">
                {confirm.names.map((n, i) => <li key={i}>{n}</li>)}
              </ul>
              <p className="am-warn">卸载由目标主机上的 Agent 执行，可能需要数分钟，期间请勿断电。</p>
            </div>
            <div className="am-modal-foot">
              <button className="am-btn" onClick={() => setConfirm(null)}>取消</button>
              <button className="am-btn am-btn-danger" onClick={doUninstall} disabled={uninstalling}>
                {uninstalling ? '卸载中…' : '确认卸载'}
              </button>
            </div>
          </div>
        </div>
      )}

      {toggleTarget && (
        <div className="am-modal-overlay" onClick={() => setToggleTarget(null)}>
          <div className="am-modal am-modal-sm" onClick={(e) => e.stopPropagation()}>
            <div className="am-modal-head">{toggleTarget.enabled ? '启用启动项' : '禁用启动项'}</div>
            <div className="am-modal-body">
              <p>
                确定要{toggleTarget.enabled ? '启用' : '禁用'}启动项
                <strong> {toggleTarget.item.name} </strong>吗？
              </p>
              <p className="am-warn">
                {toggleTarget.enabled ? '启用后该程序将随系统自动启动。' : '禁用后该程序不会随系统自动启动，不影响手动运行。'}
              </p>
            </div>
            <div className="am-modal-foot">
              <button className="am-btn" onClick={() => setToggleTarget(null)}>取消</button>
              <button className="am-btn am-btn-startup active" onClick={doToggle} disabled={toggling}>
                {toggling ? '处理中…' : '确定'}
              </button>
            </div>
          </div>
        </div>
      )}

      {result && (
        <div className="am-modal-overlay" onClick={() => setResult(null)}>
          <div className="am-modal" onClick={(e) => e.stopPropagation()}>
            <div className="am-modal-head">{result.title || (result.ok ? '卸载完成' : '卸载未完成')}</div>
            <div className="am-modal-body">
              <ul className="am-list">
                {result.items.map((it, i) => (
                  <li key={i} className={it.ok === false ? 'am-item-bad' : undefined}>
                    <strong>{it.name}</strong>：{it.message}
                  </li>
                ))}
              </ul>
            </div>
            <div className="am-modal-foot">
              <button className="am-btn" onClick={() => setResult(null)}>确定</button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
