import { authHeaders } from './auth'

/**
 * 全局主机分组（后端 host_groups 表）。
 * 由管理员在「主机管理 - 分组管理」维护，所有用户共享；
 * 侧边栏「主机列表」只展示分组及其中的主机。
 */
export const HOST_GROUPS_CHANGED = 'vigilserve:host-groups-changed'

export async function fetchHostGroups() {
  const res = await fetch('/api/host-groups/', { headers: authHeaders() })
  if (!res.ok) throw new Error('load host groups failed')
  const data = await res.json()
  return Array.isArray(data) ? data : []
}

export function notifyHostGroupsChanged() {
  window.dispatchEvent(new Event(HOST_GROUPS_CHANGED))
}

async function _json(res, fallback) {
  const data = await res.json().catch(() => ({}))
  if (!res.ok) throw new Error(data.detail || fallback)
  return data
}

export async function createHostGroup(name, serverIds = []) {
  const res = await fetch('/api/host-groups/', {
    method: 'POST',
    headers: { ...authHeaders(), 'Content-Type': 'application/json' },
    body: JSON.stringify({ name, server_ids: serverIds }),
  })
  const data = await _json(res, '新建分组失败')
  notifyHostGroupsChanged()
  return data
}

/** 重命名 / 整体重排成员（server_ids 传数组即覆盖该分组全部成员）。 */
export async function updateHostGroup(groupId, patch) {
  const res = await fetch(`/api/host-groups/${groupId}`, {
    method: 'PUT',
    headers: { ...authHeaders(), 'Content-Type': 'application/json' },
    body: JSON.stringify(patch),
  })
  const data = await _json(res, '保存分组失败')
  notifyHostGroupsChanged()
  return data
}

/** 删除分组（所有分组都可删；组内主机级联摘除，自动回到未分组）。 */
export async function deleteHostGroup(groupId) {
  const res = await fetch(`/api/host-groups/${groupId}`, {
    method: 'DELETE',
    headers: authHeaders(),
  })
  const data = await _json(res, '删除分组失败')
  notifyHostGroupsChanged()
  return data
}

/** 把主机从某个分组「移动」到另一个分组（源分组移除 + 目标分组加入）。 */
export async function moveHosts(groupId, serverIds, targetGroupId) {
  const res = await fetch(`/api/host-groups/${groupId}/move`, {
    method: 'POST',
    headers: { ...authHeaders(), 'Content-Type': 'application/json' },
    body: JSON.stringify({ server_ids: serverIds, target_group_id: targetGroupId }),
  })
  const data = await res.json().catch(() => ({}))
  if (!res.ok) throw new Error(data.detail || '移动失败')
  return data
}
