import { Routes, Route, useNavigate, Navigate } from 'react-router-dom'
import { useState, useEffect, useCallback } from 'react'
import Layout from './components/Layout'
import Dashboard from './components/Dashboard'
import ServerDetail from './components/ServerDetail'
import ServerFormModal from './components/ServerFormModal'
import RegisterManagement from './components/RegisterManagement'
import RemoteDesktopStandalone from './components/RemoteDesktopStandalone'
import LogManagement from './components/LogManagement'
import ConfirmModal from './components/ConfirmModal'
import ForceChangePassword from './components/ForceChangePassword'
import ErrorBoundary from './components/ErrorBoundary'
import Settings from './components/Settings'
import LoginPage from './components/LoginPage'
import { AuthProvider, useAuth, authHeaders } from './services/auth'
import { PermissionsProvider, usePerm } from './services/permissions'
import { fetchServers, createServer, updateServer, updateServerStatus, deleteServer, fetchServerDetail } from './services/api'
import Icon from './components/AppIcon'

// 无权限占位：菜单/路由被角色权限挡住时显示，避免白屏
function NoAccess({ text = '当前角色没有该页面的查看权限' }) {
  return (
    <div className="no-access-page">
      <div className="no-access-icon"><Icon kind="ui-lock" size={32} /></div>
      <div className="no-access-text">{text}</div>
    </div>
  )
}

function AppContent() {
  const [servers, setServers] = useState([])
  const [loading, setLoading] = useState(true)
  const [modalVisible, setModalVisible] = useState(false)
  const [editingServer, setEditingServer] = useState(null)
  const [deleteConfirmId, setDeleteConfirmId] = useState(null)
  const [refreshSignal, setRefreshSignal] = useState(0)
  const navigate = useNavigate()
  const { user, isAdmin, loading: authLoading, checkSession } = useAuth()
  const { can, canManage, loading: permLoading } = usePerm()
  // 2026-09-23 开源加固 ②：账号带着 must_reset_password 时服务端已拒绝除改密外的
  // 一切请求，这里给出唯一出路（改密框不可关闭，改完重新拉会话清掉标记）。
  const mustResetPassword = Boolean(user?.must_reset_password)

  const loadServers = useCallback(async () => {
    try {
      const data = await fetchServers()
      setServers(data)
    } catch (e) {
      console.error(e)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { if (user) loadServers() }, [loadServers, user])

  useEffect(() => {
    if (!user) return
    let pollInterval = 10000

    fetch('/api/config/', { headers: authHeaders() })
      .then(r => r.json())
      .then(cfg => {
        if (cfg.frontend_poll_interval) {
          pollInterval = parseInt(cfg.frontend_poll_interval.value) * 1000 || 10000
        }
      })
      .catch(() => {})

    const interval = setInterval(async () => {
      try { await loadServers() } catch {}
    }, pollInterval)
    return () => clearInterval(interval)
  }, [loadServers, user])

  if (authLoading || permLoading) return <div style={{ padding: 40, textAlign: 'center' }}>加载中...</div>
  if (!user) return <LoginPage />

  // 严格白名单：只有角色「管理主机」列表里显式添加的主机才可见
  const visibleServers = servers.filter((s) => canManage(s.id))

  const canOpenRegister =
    can('sys', 'register', 'view') ||
    can('sys', 'host_groups', 'view') ||
    can('sys', 'agent_update', 'view')

  const handleConnect = () => {
    if (!can('sys', 'register', 'edit')) return
    setEditingServer(null)
    setModalVisible(true)
  }

  const handleEdit = async (server) => {
    if (!can('sys', 'register', 'edit', 'edit')) return
    try {
      const detail = await fetchServerDetail(server.id)
      setEditingServer(detail)
      setModalVisible(true)
    } catch (e) {
      console.error(e)
    }
  }

  const handleFormSubmit = async (data) => {
    if (editingServer) {
      await updateServer(editingServer.id, data)
    } else {
      const result = await createServer(data)
      navigate(`/server/${result.id}`)
    }
    await loadServers()
    setRefreshSignal((v) => v + 1)
  }

  const canDeleteServer = can('sys', 'register', 'edit', 'delete')

  const handleDelete = async (id) => {
    if (!canDeleteServer) return
    setDeleteConfirmId(id)
  }

  const confirmDelete = async () => {
    const id = deleteConfirmId
    if (!id) return
    const server = servers.find(s => s.id === id)
    if (server && server.protocol === 'agent') {
      await updateServerStatus(id, { status: 'registered' })
    } else {
      await deleteServer(id)
    }
    setDeleteConfirmId(null)
    navigate('/')
    loadServers()
  }

  return (
    <ErrorBoundary>
    <>
      <Routes>
        {/* 独立窗口：/rdp/<主机id>，由页签内嵌的远程桌面「全屏」按钮 window.open 出来。
            刻意放在带 Layout 的 "/" 之前，它不带侧边栏 / 顶栏。 */}
        <Route path="/rdp/:serverId" element={<RemoteDesktopStandalone />} />
        <Route
          path="/"
          element={<Layout servers={visibleServers} loading={loading} onConnect={handleConnect} />}
        >
          <Route index element={<Dashboard servers={visibleServers} isAdmin={isAdmin} />} />
          {servers.map((s) => (
            <Route
              key={s.id}
              path={`server/${s.id}`}
              element={
                <ServerDetail
                  serverId={s.id}
                  onEdit={() => handleEdit(s)}
                  onDelete={() => handleDelete(s.id)}
                  isAdmin={isAdmin}
                  refreshSignal={refreshSignal}
                />
              }
            />
          ))}
          {/* 直接访问未授权主机时给明确提示，而不是空白页 */}
          <Route path="server/:serverId" element={<NoAccess />} />
          <Route
            path="settings"
            element={can('sys', 'settings', 'view') ? <Settings isAdmin={isAdmin} /> : <NoAccess />}
          />
          <Route
            path="register"
            element={
              canOpenRegister ? (
                <RegisterManagement
                  onServersChanged={loadServers}
                  onEditServer={handleEdit}
                />
              ) : <NoAccess />
            }
          />
          <Route path="logs" element={can('sys', 'logs', 'view') ? <LogManagement /> : <NoAccess />} />
        </Route>
      </Routes>

      <ServerFormModal
        visible={modalVisible}
        onClose={() => setModalVisible(false)}
        onSubmit={handleFormSubmit}
        onDelete={editingServer ? () => handleDelete(editingServer.id) : null}
        initialData={editingServer}
      />

      <ConfirmModal
        visible={deleteConfirmId !== null}
        title="删除连接"
        message="确定要从监控列表移除该连接吗？如需再次添加请到设备管理添加。"
        danger
        onConfirm={confirmDelete}
        onCancel={() => setDeleteConfirmId(null)}
      />

      <ForceChangePassword
        visible={mustResetPassword}
        onDone={() => { checkSession() }}
      />
    </>
    </ErrorBoundary>
  )
}

function AppWithPerms() {
  const { user } = useAuth()
  return (
    <PermissionsProvider authenticated={Boolean(user)}>
      <AppContent />
    </PermissionsProvider>
  )
}

export default function App() {
  return (
    <AuthProvider>
      <AppWithPerms />
    </AuthProvider>
  )
}
