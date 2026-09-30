import { useState, useEffect } from 'react'
import { authHeaders } from '../services/auth'
import { usePerm } from '../services/permissions'
import { fetchAllServers } from '../services/api'
import { fetchHostGroups, notifyHostGroupsChanged, moveHosts } from '../services/hostGroups'
import './GroupManagement.css'

const API = '/api'

/**
 * 分组管理（全局共享）。
 * 分组保存在后端 host_groups / host_group_members，所有用户的侧边栏「主机列表」共用同一套分组。
 */
export default function GroupManagement({ onGroupsChanged }) {
  const { can } = usePerm()
  const [groups, setGroups] = useState([])
  const [servers, setServers] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  const [editing, setEditing] = useState(null)
  const [form, setForm] = useState({ name: '', description: '', server_ids: [] })
  const [saving, setSaving] = useState(false)
  const [deleteTarget, setDeleteTarget] = useState(null)
  const [addOpen, setAddOpen] = useState(false)
  const [addIds, setAddIds] = useState([])
  const [checked, setChecked] = useState([])
  const [moveOpen, setMoveOpen] = useState(false)
  const [moveTarget, setMoveTarget] = useState('')
  const [moving, setMoving] = useState(false)
  const [notice, setNotice] = useState('')

  const headers = authHeaders()
  // 「主机管理/分组管理」操作项：与页面按钮一一对应
  const canCreate = can('sys', 'host_groups', 'edit', 'create')
  const canEdit = can('sys', 'host_groups', 'edit', 'edit')
  const canDelete = can('sys', 'host_groups', 'edit', 'delete')

  const load = async () => {
    try {
      const [groupsData, sv] = await Promise.all([
        fetchHostGroups(),
        fetchAllServers().catch(() => []),
      ])
      setGroups(groupsData)
      setServers(Array.isArray(sv) ? sv : [])
      setError('')
    } catch (e) {
      setError(e.message || '加载失败')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { load() }, [])

  /** 分组变化后通知侧边栏重新拉取（侧边栏「主机列表」只展示分组）。 */
  const refreshSidebar = () => {
    notifyHostGroupsChanged()
    if (typeof onGroupsChanged === 'function') onGroupsChanged()
  }

  const serverName = (id) => {
    const s = servers.find((x) => x.id === id)
    return s ? (s.name || s.ip_address) : `#${id}`
  }

  const availableServers = servers.filter((s) => !form.server_ids.includes(s.id))

  const resetModalState = () => {
    setChecked([])
    setMoveOpen(false)
    setMoveTarget('')
    setNotice('')
  }

  const openCreate = () => {
    setError('')
    setEditing({ isNew: true })
    setForm({ name: '', description: '', server_ids: [] })
    resetModalState()
  }

  const openEdit = (g) => {
    setError('')
    setEditing({ isNew: false, id: g.id, name: g.name, isDefault: !!g.is_default })
    setForm({
      name: g.name,
      description: g.description || '',
      server_ids: [...(g.server_ids || [])],
    })
    resetModalState()
  }

  const closeModal = () => { setEditing(null); setError(''); resetModalState() }

  const save = async () => {
    setError('')
    const name = form.name.trim()
    if (!name) { setError('分组名称为必填项'); return }
    setSaving(true)
    try {
      const url = editing.isNew ? `${API}/host-groups/` : `${API}/host-groups/${editing.id}`
      const res = await fetch(url, {
        method: editing.isNew ? 'POST' : 'PUT',
        headers: { ...headers, 'Content-Type': 'application/json' },
        body: JSON.stringify({ name, description: form.description, server_ids: form.server_ids }),
      })
      if (!res.ok) {
        const e = await res.json().catch(() => ({}))
        throw new Error(e.detail || '保存失败')
      }
      closeModal()
      await load()
      refreshSidebar()
    } catch (e) {
      setError(e.message)
    } finally {
      setSaving(false)
    }
  }

  const remove = async (id) => {
    try {
      const res = await fetch(`${API}/host-groups/${id}`, { method: 'DELETE', headers })
      if (!res.ok) {
        const e = await res.json().catch(() => ({}))
        throw new Error(e.detail || '删除失败')
      }
      setDeleteTarget(null)
      await load()
      refreshSidebar()
    } catch (e) {
      setError(e.message)
      setDeleteTarget(null)
    }
  }

  const removeServer = (id) => {
    setForm((f) => ({ ...f, server_ids: f.server_ids.filter((x) => x !== id) }))
    setChecked((ids) => ids.filter((x) => x !== id))
  }

  const confirmAdd = () => {
    setForm((f) => ({
      ...f,
      server_ids: [...f.server_ids, ...addIds.filter((id) => !f.server_ids.includes(id))],
    }))
    setAddOpen(false)
  }

  const toggleChecked = (id) => {
    setChecked((ids) => (ids.includes(id) ? ids.filter((x) => x !== id) : [...ids, id]))
  }

  const allChecked = form.server_ids.length > 0 && checked.length === form.server_ids.length
  const toggleAllChecked = () => setChecked(allChecked ? [] : [...form.server_ids])

  const moveTargets = groups.filter((g) => !editing || g.id !== editing.id)

  const openMove = () => {
    setError('')
    setMoveTarget('')
    setMoveOpen(true)
  }

  const doMove = async () => {
    const targetId = Number(moveTarget)
    if (!targetId) { setError('请选择要移动到的分组'); return }
    setMoving(true)
    setError('')
    try {
      const res = await moveHosts(editing.id, checked, targetId)
      const target = groups.find((g) => g.id === targetId)
      // 移动立即落库：把已移动的主机从表单里的当前分组剔除
      const moved = [...checked]
      setForm((f) => ({ ...f, server_ids: f.server_ids.filter((id) => !moved.includes(id)) }))
      setChecked([])
      setMoveOpen(false)
      setNotice(res.message || `已移动到「${target ? target.name : targetId}」`)
      await load()
      refreshSidebar()
    } catch (e) {
      setError(e.message)
    } finally {
      setMoving(false)
    }
  }

  if (loading) return <div className="page-loading">加载中...</div>

  return (
    <div>
      <div className="group-toolbar">
        <span className="group-toolbar-title">
          分组列表
          <span className="group-toolbar-count">{groups.length}</span>
        </span>
        <button className="btn-add-user" onClick={openCreate} disabled={!canCreate}
          title={canCreate ? '' : '当前角色没有「创建分组」权限'}>
          创建分组
        </button>
      </div>

      {error && <div className="form-error" style={{ marginBottom: 12 }}>{error}</div>}

      <table className="settings-table settings-table-fixed">
        <thead>
          <tr>
            <th className="col-id">ID</th>
            <th>分组名称</th>
            <th>说明</th>
            <th className="col-num">主机数</th>
            <th>包含主机</th>
            <th className="col-ops">操作</th>
          </tr>
        </thead>
        <tbody>
          {groups.map((g) => (
            <tr key={g.id}>
              <td className="col-id">{g.id}</td>
              <td>
                {g.name}
              </td>
              <td>{g.description || '—'}</td>
              <td className="col-num">{g.server_ids ? g.server_ids.length : 0}</td>
              <td className="group-hosts-cell">
                {g.server_ids && g.server_ids.length > 0
                  ? g.server_ids.map(serverName).join('、')
                  : '—'}
              </td>
              <td className="col-ops actions">
                <button className="btn-sm btn-primary" onClick={() => openEdit(g)} disabled={!canEdit}
                  title={canEdit ? '' : '当前角色没有「编辑」权限'}>
                  编辑
                </button>
                <button className="btn-sm btn-danger" onClick={() => setDeleteTarget(g)}
                  disabled={!canDelete}
                  title={canDelete ? '' : '当前角色没有「删除」权限'}>
                  删除
                </button>
              </td>
            </tr>
          ))}
          {groups.length === 0 && (
            <tr>
              <td colSpan={6} className="group-empty-cell">暂无分组，点击右上角「创建分组」新建</td>
            </tr>
          )}
        </tbody>
      </table>

      {editing && (
        <div className="settings-modal-overlay" onClick={closeModal}>
          <div className="settings-modal group-modal" onClick={(e) => e.stopPropagation()}>
            <div className="settings-modal-header">
              <h4>{editing.isNew ? '创建分组' : '编辑分组'}</h4>
              <button className="settings-modal-close" onClick={closeModal} title="关闭">×</button>
            </div>
            <div className="settings-modal-body">
              {error && <div className="form-error" style={{ marginBottom: 12 }}>{error}</div>}

              <div className="settings-form-group">
                <label className="settings-form-label">分组名称 <span className="required">*</span></label>
                <input className="form-input" value={form.name}
                  onChange={(e) => setForm({ ...form, name: e.target.value })}
                  placeholder="如：生产环境" autoComplete="off" />
              </div>

              <div className="settings-form-group">
                <label className="settings-form-label">说明</label>
                <input className="form-input" value={form.description}
                  onChange={(e) => setForm({ ...form, description: e.target.value })}
                  placeholder="选填" autoComplete="off" />
              </div>

              <div className="settings-form-group">
                <div className="group-block-head">
                  <span className="settings-form-label" style={{ marginBottom: 0 }}>分组主机</span>
                  <div className="group-block-actions">
                    <button type="button" className="btn-sm btn-primary"
                      onClick={() => { setAddIds([]); setAddOpen(true) }}
                      disabled={availableServers.length === 0}>
                      添加主机
                    </button>
                    <button type="button" className="btn-sm btn-primary" onClick={openMove}
                      disabled={checked.length === 0 || editing.isNew}
                      title={editing.isNew ? '请先保存分组，再移动主机'
                        : (checked.length === 0 ? '请先勾选要移动的主机' : `移动选中的 ${checked.length} 台主机`)}>
                      移动到{checked.length > 0 ? ` (${checked.length})` : ''}
                    </button>
                  </div>
                </div>
                {notice && <div className="group-notice">{notice}</div>}
                <table className="group-server-table">
                  <thead>
                    <tr>
                      <th className="col-check">
                        <input type="checkbox" checked={allChecked} onChange={toggleAllChecked}
                          disabled={form.server_ids.length === 0} title="全选" />
                      </th>
                      <th>主机名称</th>
                      <th className="col-ip">IP 地址</th>
                      <th className="col-ops">操作</th>
                    </tr>
                  </thead>
                  <tbody>
                    {form.server_ids.length === 0 ? (
                      <tr>
                        <td colSpan={4} className="group-empty-cell">尚未添加主机</td>
                      </tr>
                    ) : form.server_ids.map((id) => {
                      const s = servers.find((x) => x.id === id)
                      return (
                        <tr key={id}>
                          <td className="col-check">
                            <input type="checkbox" checked={checked.includes(id)}
                              onChange={() => toggleChecked(id)} />
                          </td>
                          <td>{serverName(id)}</td>
                          <td className="col-ip">{s ? (s.ip_address || '') : ''}</td>
                          <td className="col-ops">
                            <button type="button" className="btn-sm btn-danger" onClick={() => removeServer(id)}>
                              移除
                            </button>
                          </td>
                        </tr>
                      )
                    })}
                  </tbody>
                </table>
              </div>
            </div>
            <div className="settings-modal-footer">
              <button className="btn-cancel" onClick={closeModal}>取消</button>
              <button className="btn-submit" onClick={save} disabled={saving}>
                {saving ? '保存中…' : '保存'}
              </button>
            </div>
          </div>
        </div>
      )}

      {deleteTarget && (
        <div className="settings-modal-overlay" onClick={() => setDeleteTarget(null)}>
          <div className="settings-modal" onClick={(e) => e.stopPropagation()}>
            <div className="settings-modal-header">
              <h4>确认删除</h4>
              <button className="settings-modal-close" onClick={() => setDeleteTarget(null)} title="关闭">×</button>
            </div>
            <div className="settings-modal-body">
              <p style={{ margin: 0, fontSize: 14, color: '#333' }}>
                确定要删除分组 <strong>{deleteTarget.name}</strong> 吗？
                {(deleteTarget.server_ids || []).length > 0 && (
                  <span style={{ color: '#c0392b', fontSize: 13 }}>
                    <br />分组内 {deleteTarget.server_ids.length} 台主机不会被删除，会自动回到设备列表（未分组）。
                  </span>
                )}
                {(deleteTarget.server_ids || []).length === 0 && (
                  <span style={{ color: '#6c757d', fontSize: 13 }}><br />该分组当前没有主机。</span>
                )}
              </p>
            </div>
            <div className="settings-modal-footer">
              <button className="btn-cancel" onClick={() => setDeleteTarget(null)}>取消</button>
              <button className="btn-sm btn-danger" onClick={() => remove(deleteTarget.id)}>删除</button>
            </div>
          </div>
        </div>
      )}

      {addOpen && (
        <div className="settings-modal-overlay" onClick={() => setAddOpen(false)}>
          <div className="settings-modal group-picker-modal" onClick={(e) => e.stopPropagation()}>
            <div className="settings-modal-header">
              <h4>添加主机</h4>
              <button className="settings-modal-close" onClick={() => setAddOpen(false)} title="关闭">×</button>
            </div>
            <div className="settings-modal-body">
              {availableServers.length === 0 ? (
                <p className="group-hint" style={{ margin: 0 }}>没有可添加的主机（已全部加入或暂无主机）</p>
              ) : (
                <div className="group-picker-list">
                  {availableServers.map((s) => (
                    <label key={s.id} className="group-check group-picker-item">
                      <input type="checkbox" checked={addIds.includes(s.id)}
                        onChange={() => setAddIds((ids) => (ids.includes(s.id) ? ids.filter((x) => x !== s.id) : [...ids, s.id]))} />
                      <span className="group-picker-name">{s.name || s.ip_address}</span>
                      <span className="group-picker-ip">{s.ip_address || ''}</span>
                    </label>
                  ))}
                </div>
              )}
            </div>
            <div className="settings-modal-footer">
              <button className="btn-cancel" onClick={() => setAddOpen(false)}>取消</button>
              <button className="btn-submit" onClick={confirmAdd} disabled={addIds.length === 0}>
                添加{addIds.length > 0 ? ` (${addIds.length})` : ''}
              </button>
            </div>
          </div>
        </div>
      )}

      {moveOpen && (
        <div className="settings-modal-overlay" onClick={() => setMoveOpen(false)}>
          <div className="settings-modal group-picker-modal" onClick={(e) => e.stopPropagation()}>
            <div className="settings-modal-header">
              <h4>移动到其他分组</h4>
              <button className="settings-modal-close" onClick={() => setMoveOpen(false)} title="关闭">×</button>
            </div>
            <div className="settings-modal-body">
              {error && <div className="form-error" style={{ marginBottom: 12 }}>{error}</div>}
              <p className="group-hint" style={{ marginTop: 0 }}>
                把「{editing ? editing.name : ''}」中勾选的 {checked.length} 台主机移动到：
              </p>
              {moveTargets.length === 0 ? (
                <p className="group-hint" style={{ margin: 0 }}>没有其他分组可移动，请先创建分组。</p>
              ) : (
                <div className="group-picker-list">
                  {moveTargets.map((g) => (
                    <label key={g.id} className="group-check group-picker-item">
                      <input type="radio" name="move-target" checked={String(moveTarget) === String(g.id)}
                        onChange={() => setMoveTarget(String(g.id))} />
                      <span className="group-picker-name">{g.name}</span>
                      <span className="group-picker-ip">{g.server_ids ? g.server_ids.length : 0} 台</span>
                    </label>
                  ))}
                </div>
              )}
            </div>
            <div className="settings-modal-footer">
              <button className="btn-cancel" onClick={() => setMoveOpen(false)}>取消</button>
              <button className="btn-submit" onClick={doMove} disabled={moving || !moveTarget}>
                {moving ? '移动中…' : '移动到该分组'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
