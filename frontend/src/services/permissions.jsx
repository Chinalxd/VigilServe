import { createContext, useContext, useState, useEffect, useCallback } from 'react'
import { authHeaders } from './auth'

/**
 * 权限上下文。
 *
 * 后端是唯一判据：登录后拉 /api/roles/me/scope，拿到角色权限表与可管理主机，
 * 前端只做「显示层」控制（菜单/页签/按钮），真正的拦截在后端接口。
 */
const API = '/api'

export const PermContext = createContext(null)

function lookup(perms, scope, page, action, op, opNoEdit) {
  if (!perms) return false
  const s = perms[scope]
  if (!s) return false
  const p = s[page]
  if (!p) return false
  if (op !== undefined && op !== null) {
    if (!Boolean(p.ops && p.ops[op])) return false
    // 后端标了 `needs_edit: false` 的只读操作（R-13 的「查看/下载文件」）不该被
    // 页面的「编辑」总开关连带关掉 —— 否则只读角色连下载按钮都看不到。
    // 规则由 `/api/roles/me/scope` 的 `op_no_edit` 下发，前后端必须同口径。
    const exempt = Boolean(opNoEdit && (opNoEdit[`${scope}/${page}`] || []).includes(op))
    return exempt ? true : Boolean(p.edit)
  }
  return Boolean(p[action])
}

export function PermissionsProvider({ children, authenticated }) {
  const [perms, setPerms] = useState(null)
  // R-13：后端下发的「免 edit 总开关」操作项清单，形如 {"host/resources": ["read"]}
  const [opNoEdit, setOpNoEdit] = useState({})
  const [serverIds, setServerIds] = useState(null)
  const [isAdmin, setIsAdmin] = useState(false)
  const [loading, setLoading] = useState(true)

  const load = useCallback(async () => {
    if (!authenticated) {
      setPerms(null)
      setServerIds(null)
      setIsAdmin(false)
      setLoading(false)
      return
    }
    try {
      const res = await fetch(`${API}/roles/me/scope`, { headers: authHeaders() })
      if (!res.ok) throw new Error('failed')
      const data = await res.json()
      if (!data.authenticated) {
        setPerms(null)
        setServerIds(null)
        setIsAdmin(false)
        return
      }
      setIsAdmin(Boolean(data.is_admin))
      setPerms(data.permissions || {})
      setOpNoEdit(data.op_no_edit || {})
      // server_ids 为空数组表示「未绑定任何主机」，语义等同全部，由后端处理
      setServerIds(Array.isArray(data.server_ids) ? data.server_ids : [])
    } catch {
      setPerms(null)
      setServerIds(null)
      setIsAdmin(false)
    } finally {
      setLoading(false)
    }
  }, [authenticated])

  useEffect(() => { load() }, [load])

  const can = useCallback((scope, page, action, op) => {
    if (isAdmin) return true
    return lookup(perms, scope, page, action, op, opNoEdit)
  }, [perms, isAdmin, opNoEdit])

  // 严格白名单：server_ids 为空数组 = 角色未绑定任何主机 = 看不到任何主机
  const canManage = useCallback((serverId) => {
    if (isAdmin) return true
    if (!serverIds) return false
    return serverIds.includes(Number(serverId))
  }, [serverIds, isAdmin])

  return (
    <PermContext.Provider value={{ perms, serverIds, isAdmin, loading, can, canManage, reload: load }}>
      {children}
    </PermContext.Provider>
  )
}

export function usePerm() {
  return useContext(PermContext) || {
    perms: null, serverIds: null, isAdmin: false, loading: false,
    can: () => false, canManage: () => false, reload: () => {},
  }
}
