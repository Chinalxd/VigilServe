import { NavLink, useLocation } from 'react-router-dom'
import { useState, useEffect, useMemo, useCallback, useRef } from 'react'
import { useAuth, authHeaders } from '../services/auth'
import { usePerm } from '../services/permissions'
import {
  fetchHostGroups,
  createHostGroup,
  updateHostGroup,
  deleteHostGroup,
  HOST_GROUPS_CHANGED,
} from '../services/hostGroups'
import './Sidebar.css'
import Icon, { deviceIconKind } from './AppIcon'

const STATUS_COLORS = {
  online: '#06d6a0',
  monitored: '#06d6a0',
  warning: '#ffd166',
  critical: '#ef476f',
  offline: '#6c757d',
  registered: '#adb5bd',
  unknown: '#adb5bd',
}

export default function Sidebar({ servers, loading, onConnect }) {
  const location = useLocation()
  const { user, logout, online } = useAuth()
  const { can } = usePerm()
  const [showUserMenu, setShowUserMenu] = useState(false)
  const [serverVersion, setServerVersion] = useState('')
  const [groups, setGroups] = useState([])
  const [groupsLoading, setGroupsLoading] = useState(true)
  const [collapsedGroups, setCollapsedGroups] = useState(() => new Set())
  // 宁可不显示，也不要显示一个过期的假版本号。
  useEffect(() => {
    if (!user) {
      setServerVersion('')
      return undefined
    }
    let alive = true
    fetch('/api/version', { headers: authHeaders() })
      .then((r) => (r.ok ? r.json() : null))
      .then((d) => {
        if (alive && d && d.version) setServerVersion(String(d.version))
      })
      .catch(() => {})
    return () => { alive = false }
  }, [user?.username])

  const [editingGroupId, setEditingGroupId] = useState(null)
  const [editingName, setEditingName] = useState('')
  const [activeMenuGroupId, setActiveMenuGroupId] = useState(null)
  const [draggedServerId, setDraggedServerId] = useState(null)
  const [dragOverId, setDragOverId] = useState(null)
  const [dragOverPosition, setDragOverPosition] = useState(null)
  const [dragOverGroupId, setDragOverGroupId] = useState(null)
  const renameInputRef = useRef(null)
  const groupMenuRef = useRef(null)

  // 分组的增/改/删需要「主机管理 - 分组管理」的编辑权限
  const canGroupEdit = can('sys', 'host_groups', 'edit')

  const loadGroups = useCallback(async () => {
    if (!user) {
      setGroups([])
      setGroupsLoading(false)
      return
    }
    try {
      setGroups(await fetchHostGroups())
    } catch {
      setGroups([])
    } finally {
      setGroupsLoading(false)
    }
  }, [user])

  useEffect(() => { loadGroups() }, [loadGroups])

  useEffect(() => {
    const handler = () => { loadGroups() }
    window.addEventListener(HOST_GROUPS_CHANGED, handler)
    return () => window.removeEventListener(HOST_GROUPS_CHANGED, handler)
  }, [loadGroups])

  useEffect(() => {
    if (editingGroupId && renameInputRef.current) {
      renameInputRef.current.focus()
      renameInputRef.current.select()
    }
  }, [editingGroupId])

  useEffect(() => {
    if (!activeMenuGroupId) return
    const handleClickOutside = (e) => {
      if (groupMenuRef.current && !groupMenuRef.current.contains(e.target)) {
        setActiveMenuGroupId(null)
      }
    }
    document.addEventListener('mousedown', handleClickOutside)
    return () => document.removeEventListener('mousedown', handleClickOutside)
  }, [activeMenuGroupId])

  const toggleGroup = (groupId) => {
    setCollapsedGroups((prev) => {
      const next = new Set(prev)
      if (next.has(groupId)) next.delete(groupId)
      else next.add(groupId)
      return next
    })
  }


  const handleAddGroup = async () => {
    if (!canGroupEdit) return
    let idx = 1
    let name = '新建分组'
    const existing = new Set(groups.map((g) => g.name))
    while (existing.has(name)) {
      idx += 1
      name = `新建分组 ${idx}`
    }
    try {
      const created = await createHostGroup(name)
      setCollapsedGroups((prev) => {
        const next = new Set(prev)
        next.delete(created.id)
        return next
      })
      setEditingGroupId(created.id)
      setEditingName(created.name)
    } catch (e) {
      window.alert(e.message || '新建分组失败')
    }
  }

  const handleRenameStart = (group) => {
    if (!canGroupEdit) return
    setEditingGroupId(group.id)
    setEditingName(group.name)
  }

  const handleRenameCommit = async (groupId) => {
    const name = editingName.trim()
    const current = groups.find((g) => g.id === groupId)
    setEditingGroupId(null)
    setEditingName('')
    if (!name || !current || name === current.name) return
    setGroups((prev) => prev.map((g) => (g.id === groupId ? { ...g, name } : g)))
    try {
      await updateHostGroup(groupId, { name })
    } catch (e) {
      window.alert(e.message || '重命名失败')
      loadGroups()
    }
  }

  const handleRenameKey = (e, groupId) => {
    if (e.key === 'Enter') handleRenameCommit(groupId)
    if (e.key === 'Escape') {
      setEditingGroupId(null)
      setEditingName('')
    }
  }

  const handleDeleteGroup = async (group) => {
    if (!canGroupEdit) return
    const count = (group.server_ids || []).length
    const tip = count
      ? `确定删除分组「${group.name}」？分组内 ${count} 台主机将回到设备列表（未分组）。`
      : `确定删除分组「${group.name}」？`
    if (!window.confirm(tip)) return
    try {
      await deleteHostGroup(group.id)
      // 组内主机由后端级联摘除，这里整体重载分组即可让它们出现在「未分组」
      loadGroups()
    } catch (e) {
      window.alert(e.message || '删除分组失败')
      loadGroups()
    }
  }


  const getDropPosition = (e) => {
    const rect = e.currentTarget.getBoundingClientRect()
    const mid = rect.top + rect.height / 2
    return e.clientY < mid ? 'before' : 'after'
  }

  /**
   * 移动主机：先从原分组摘掉，再插到目标分组的指定位置。
   * targetGroupId 为 null 表示拖回「未分组」。
   */
  const moveServer = async (serverId, targetGroupId, targetServerId, position) => {
    if (serverId === targetServerId) return
    const next = groups.map((g) => ({ ...g, server_ids: [...(g.server_ids || [])] }))
    const src = next.find((g) => g.server_ids.includes(serverId))
    if (src) src.server_ids = src.server_ids.filter((id) => id !== serverId)
    let tgt = null
    if (targetGroupId) {
      tgt = next.find((g) => g.id === targetGroupId)
      if (!tgt) return
      if (targetServerId && tgt.server_ids.includes(targetServerId)) {
        const idx = tgt.server_ids.indexOf(targetServerId)
        tgt.server_ids.splice(position === 'after' ? idx + 1 : idx, 0, serverId)
      } else {
        tgt.server_ids.push(serverId)
      }
    }
    setGroups(next)
    if (targetGroupId) {
      setCollapsedGroups((prev) => {
        const s = new Set(prev)
        s.delete(targetGroupId)
        return s
      })
    }
    try {
      if (src && (!tgt || tgt.id !== src.id)) {
        await updateHostGroup(src.id, { server_ids: src.server_ids })
      }
      if (tgt) await updateHostGroup(tgt.id, { server_ids: tgt.server_ids })
    } catch (e) {
      window.alert(e.message || '移动主机失败')
    } finally {
      loadGroups()
    }
  }

  const resetDragState = () => {
    setDraggedServerId(null)
    setDragOverId(null)
    setDragOverPosition(null)
    setDragOverGroupId(null)
  }

  const handleServerDragStart = (e, serverId) => {
    setDraggedServerId(serverId)
    e.dataTransfer.effectAllowed = 'move'
  }

  const handleServerDragOver = (e, serverId) => {
    e.preventDefault()
    e.stopPropagation()
    if (draggedServerId === serverId) {
      setDragOverId(null)
      setDragOverPosition(null)
      return
    }
    setDragOverId(serverId)
    setDragOverPosition(getDropPosition(e))
  }

  const handleServerDrop = (e, targetServerId, targetGroupId) => {
    e.preventDefault()
    e.stopPropagation()
    if (!draggedServerId || draggedServerId === targetServerId) {
      resetDragState()
      return
    }
    const position = dragOverId === targetServerId ? dragOverPosition : 'before'
    moveServer(draggedServerId, targetGroupId || null, targetServerId, position)
    resetDragState()
  }

  const handleGroupDragOver = (e, groupId) => {
    e.preventDefault()
    setDragOverGroupId(groupId)
    setDragOverId(null)
    setDragOverPosition(null)
  }

  const handleGroupDrop = (e, groupId) => {
    e.preventDefault()
    e.stopPropagation()
    if (!draggedServerId) {
      setDragOverGroupId(null)
      return
    }
    moveServer(draggedServerId, groupId, null, null)
    resetDragState()
  }


  // 按分组解析主机；分组内已移除/无权限的主机自动忽略
  const groupedRows = useMemo(() => {
    const byId = new Map(servers.map((s) => [s.id, s]))
    return groups.map((g) => {
      const members = (g.server_ids || []).map((id) => byId.get(id)).filter(Boolean)
      return { group: g, members }
    })
  }, [groups, servers])

  const ungroupedServers = useMemo(() => {
    const inGroup = new Set()
    groups.forEach((g) => (g.server_ids || []).forEach((id) => inGroup.add(id)))
    return servers.filter((s) => !inGroup.has(s.id))
  }, [groups, servers])

  // 系统页面（侧边栏菜单项）按角色的「查看」权限显隐
  const menu = {
    dashboard: can('sys', 'dashboard', 'view'),
    register:
      can('sys', 'register', 'view') ||
      can('sys', 'host_groups', 'view') ||
      can('sys', 'agent_update', 'view'),
    logs: can('sys', 'logs', 'view'),
    settings: can('sys', 'settings', 'view'),
  }
  const hasBottomNav = menu.register || menu.logs || menu.settings

  const renderServerItem = (s, groupId) => {
    const isDropBefore = dragOverId === s.id && dragOverPosition === 'before'
    const isDropAfter = dragOverId === s.id && dragOverPosition === 'after'
    return (
      <div
        key={s.id}
        className={`nav-item-wrapper ${isDropBefore ? 'drop-before' : ''} ${isDropAfter ? 'drop-after' : ''}`}
        draggable={canGroupEdit}
        onDragStart={(e) => handleServerDragStart(e, s.id)}
        onDragOver={(e) => handleServerDragOver(e, s.id)}
        onDragLeave={() => setDragOverId(null)}
        onDrop={(e) => handleServerDrop(e, s.id, groupId)}
        onDragEnd={resetDragState}
      >
        <NavLink
          to={`/server/${s.id}`}
          className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}
        >
          {/* 图标 2026-09-22 起是内置 SVG：主机按操作系统官方 logo、网络设备按设备类型，
              形状不同但同一套画风（详见 AppIcon.jsx）。原来是 emoji。 */}
          <span className="nav-icon"><Icon kind={deviceIconKind(s)} /></span>
          <div className="nav-server-info">
            <span className="nav-server-name">{s.name}</span>
          </div>
          <span
            className="status-dot"
            style={{ background: STATUS_COLORS[s.status] || '#adb5bd' }}
            title={s.status}
          />
        </NavLink>
      </div>
    )
  }

  return (
    <aside className="sidebar">
      <div className="sidebar-header">
        <div className="sidebar-logo">
          <img src="/logo.png" alt="" className="sidebar-logo-img" />
          <div className="logo-title">VigilServe</div>
        </div>
        {user && (
          // 点击弹出「退出登录」，光标移开整块区域（含下拉菜单本身）后自动收起
          <div
            className="sidebar-user"
            onClick={() => setShowUserMenu((v) => !v)}
            onMouseLeave={() => setShowUserMenu(false)}
          >
            <span className="sidebar-user-name">{user.full_name || user.username}</span>
            <span className="sidebar-user-role">{user.role_name || (user.role === 'admin' ? '管理员' : '普通用户')}</span>
            {/* 在线状态：同一账号只允许一处在线，被别处顶下线时这里转为「已离线」 */}
            <span
              className={`sidebar-user-status ${online ? 'on' : 'off'}`}
              title={online ? '当前会话在线' : '当前会话已离线'}
            >
              <i className="sidebar-status-dot" />
              {online ? '在线' : '已离线'}
            </span>
            <span className="sidebar-user-arrow"><Icon kind={showUserMenu ? 'ui-chevron-up' : 'ui-chevron-down'} size={10} /></span>
            {showUserMenu && (
              <div className="user-dropdown-menu">
                <div className="user-dropdown-item logout" onClick={(e) => { e.stopPropagation(); logout(); }}>退出登录</div>
              </div>
            )}
          </div>
        )}
      </div>

      <nav className="sidebar-nav">
        {menu.dashboard && (
          <>
            <div className="nav-section-label">总览</div>
            <NavLink
              to="/"
              end
              className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}
            >
              <span className="nav-icon"><Icon kind="nav-dashboard" /></span>
              <span>看板</span>
            </NavLink>
          </>
        )}

        <div className="nav-section-label">
          设备列表
          {(loading || groupsLoading) && <span className="loading-dot">...</span>}
          {!loading && !groupsLoading && <span className="server-count">{servers.length}</span>}
          {canGroupEdit && (
            <span className="group-add-icon" title="新建分组" onClick={handleAddGroup}>+</span>
          )}
        </div>

        {ungroupedServers.map((s) => renderServerItem(s, null))}

        {groupedRows.map(({ group, members }) => {
          const collapsed = collapsedGroups.has(group.id)
          return (
            <div
              key={group.id}
              className={`nav-group ${dragOverGroupId === group.id ? 'drag-over' : ''}`}
              onDragOver={(e) => handleGroupDragOver(e, group.id)}
              onDragLeave={() => setDragOverGroupId(null)}
              onDrop={(e) => handleGroupDrop(e, group.id)}
            >
              <div className="nav-group-header">
                <span
                  className="group-toggle"
                  onClick={() => toggleGroup(group.id)}
                  title={collapsed ? '展开' : '合并'}
                >
                  {collapsed ? <Icon kind="ui-chevron-right" size={10} /> : <Icon kind="ui-chevron-down" size={10} />}
                </span>
                {editingGroupId === group.id ? (
                  // autoFocus：新建分组时分组行是「后到」的（等后端返回才渲染），
                  // 点别处也不会 blur -> 会一直卡在改名框里。这里让 input 自己
                  <input
                    ref={renameInputRef}
                    className="group-rename-input"
                    value={editingName}
                    autoFocus
                    onFocus={(e) => e.target.select()}
                    onChange={(e) => setEditingName(e.target.value)}
                    onBlur={() => handleRenameCommit(group.id)}
                    onKeyDown={(e) => handleRenameKey(e, group.id)}
                  />
                ) : (
                  <span
                    className="group-name"
                    title={group.name}
                  >
                    {group.name}
                  </span>
                )}
                <span className="group-count">{members.length}</span>
                {canGroupEdit && (
                  <div
                    className="group-actions"
                    ref={activeMenuGroupId === group.id ? groupMenuRef : null}
                  >
                    <span
                      className="group-action-icon"
                      onClick={(e) => {
                        e.stopPropagation()
                        setActiveMenuGroupId(activeMenuGroupId === group.id ? null : group.id)
                      }}
                      title="分组操作"
                    >
                      <Icon kind="ui-more" size={12} />
                    </span>
                    {activeMenuGroupId === group.id && (
                      <div className="group-action-menu">
                        <div
                          className="group-action-item"
                          onClick={() => {
                            setActiveMenuGroupId(null)
                            handleRenameStart(group)
                          }}
                        >
                          重命名
                        </div>
                        <div
                          className="group-action-item group-action-danger"
                          onClick={() => {
                            setActiveMenuGroupId(null)
                            handleDeleteGroup(group)
                          }}
                        >
                          删除分组
                        </div>
                      </div>
                    )}
                  </div>
                )}
              </div>
              {!collapsed && (
                <div className="nav-group-servers">
                  {members.length === 0 ? (
                    <div className="group-empty">拖入主机进行分组</div>
                  ) : (
                    members.map((s) => renderServerItem(s, group.id))
                  )}
                </div>
              )}
            </div>
          )
        })}

      </nav>

      {hasBottomNav && <div className="sidebar-divider" />}

      {hasBottomNav && (
      <div className="sidebar-bottom-nav">
        {menu.register && (
          <NavLink to="/register" className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}>
            <span className="nav-icon"><Icon kind="nav-devices" /></span>
            <span>设备管理</span>
          </NavLink>
        )}

        {menu.logs && (
          <NavLink to="/logs" className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}>
            <span className="nav-icon"><Icon kind="nav-logs" /></span>
            <span>日志管理</span>
          </NavLink>
        )}

        {menu.settings && (
          <NavLink to="/settings" className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}>
            <span className="nav-icon"><Icon kind="nav-settings" /></span>
            <span>系统设置</span>
          </NavLink>
        )}
      </div>
      )}

      <div className="sidebar-footer">
        <div className="footer-divider" />
        <div className="footer-info">
          <span>{serverVersion ? `v${serverVersion}` : ''}</span>
        </div>
      </div>
    </aside>
  )
}
