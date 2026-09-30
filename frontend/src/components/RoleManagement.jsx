import { useState, useEffect, Fragment } from 'react'
import { authHeaders } from '../services/auth'
import './RoleManagement.css'

const API = '/api'

function emptyPerms(scopes) {
  const out = {}
  scopes.forEach((sc) => {
    out[sc.code] = {}
    sc.pages.forEach((p) => {
      out[sc.code][p.code] = {
        view: false,
        edit: false,
        ops: p.ops.reduce((acc, o) => ({ ...acc, [o.code]: false }), {}),
      }
    })
  })
  return out
}

function mergePerms(scopes, saved) {
  const base = emptyPerms(scopes)
  if (!saved || typeof saved !== 'object') return base
  scopes.forEach((sc) => {
    const src = saved[sc.code]
    if (!src || typeof src !== 'object') return
    sc.pages.forEach((p) => {
      const e = src[p.code]
      if (!e || typeof e !== 'object') return
      base[sc.code][p.code].view = Boolean(e.view)
      base[sc.code][p.code].edit = Boolean(e.edit)
      p.ops.forEach((o) => {
        base[sc.code][p.code].ops[o.code] = Boolean(e.ops && e.ops[o.code])
      })
    })
  })
  return base
}

export default function RoleManagement({ isAdmin, onRolesChanged }) {
  const [roles, setRoles] = useState([])
  const [scopes, setScopes] = useState([])
  const [servers, setServers] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  const [editing, setEditing] = useState(null)
  const [form, setForm] = useState({ name: '', code: '', description: '', permissions: {}, server_ids: [] })
  const [deleteTarget, setDeleteTarget] = useState(null)
  const [saving, setSaving] = useState(false)
  const [pickerOpen, setPickerOpen] = useState(false)
  const [pickerIds, setPickerIds] = useState([])
  const [notice, setNotice] = useState('')
  const [modalTab, setModalTab] = useState('hosts')

  const headers = authHeaders()

  const loadAll = async () => {
    try {
      const [mr, ms, mv] = await Promise.all([
        fetch(`${API}/roles/manifest`, { headers }),
        fetch(`${API}/roles/`, { headers }),
        fetch(`${API}/servers/`, { headers }),
      ])
      if (mr.ok) {
        const d = await mr.json()
        setScopes(d.scopes || [])
      }
      if (ms.ok) {
        const d = await ms.json()
        setRoles(Array.isArray(d) ? d : [])
      }
      if (mv.ok) {
        const d = await mv.json()
        setServers(Array.isArray(d) ? d : [])
      }
    } catch (e) {
      setError(e.message || '加载失败')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { loadAll() }, [])

  const openCreate = () => {
    setError('')
    setEditing({ isNew: true })
    setForm({ name: '', code: '', description: '', permissions: emptyPerms(scopes), server_ids: [] })
    setModalTab('hosts')
  }

  const openEdit = (role) => {
    setError('')
    setEditing({ isNew: false, ...role })
    setForm({
      name: role.name,
      code: role.code,
      description: role.description || '',
      permissions: mergePerms(scopes, role.permissions),
      server_ids: role.server_ids || [],
    })
    setModalTab('hosts')
  }

  const closeModal = () => {
    setEditing(null)
    setError('')
  }

  const setPageFlag = (scope, page, key, value) => {
    setForm((f) => {
      const perms = { ...f.permissions }
      perms[scope] = { ...perms[scope] }
      perms[scope][page] = { ...perms[scope][page], [key]: value }
      if (key === 'edit' && !value) {
        perms[scope][page].ops = Object.keys(perms[scope][page].ops || {})
          .reduce((acc, k) => ({ ...acc, [k]: false }), {})
      }
      return { ...f, permissions: perms }
    })
  }

  const setOpFlag = (scope, page, op, value) => {
    setForm((f) => {
      const perms = { ...f.permissions }
      perms[scope] = { ...perms[scope] }
      perms[scope][page] = { ...perms[scope][page] }
      perms[scope][page].ops = { ...perms[scope][page].ops, [op]: value }
      if (value) perms[scope][page].edit = true
      return { ...f, permissions: perms }
    })
  }

  const toggleAllInScope = (scope, value) => {
    setForm((f) => {
      const perms = { ...f.permissions }
      const sc = scopes.find((s) => s.code === scope)
      perms[scope] = { ...perms[scope] }
      sc.pages.forEach((p) => {
        perms[scope][p.code] = {
          view: value,
          edit: value,
          ops: p.ops.reduce((acc, o) => ({ ...acc, [o.code]: value }), {}),
        }
      })
      return { ...f, permissions: perms }
    })
  }

  const removeServer = (id) => {
    setForm((f) => ({ ...f, server_ids: f.server_ids.filter((x) => x !== id) }))
  }

  const availableServers = servers.filter((s) => !form.server_ids.includes(s.id))

  const openPicker = () => {
    setPickerIds([])
    setPickerOpen(true)
  }

  const togglePicker = (id) => {
    setPickerIds((ids) => (ids.includes(id) ? ids.filter((x) => x !== id) : [...ids, id]))
  }

  const confirmPicker = () => {
    setForm((f) => ({
      ...f,
      server_ids: [...f.server_ids, ...pickerIds.filter((id) => !f.server_ids.includes(id))],
    }))
    setPickerOpen(false)
  }

  const save = async () => {
    setError('')
    if (!form.name.trim()) { setError('角色名称为必填项'); return }
    if (editing.isNew && !form.code.trim()) { setError('角色标识为必填项'); return }
    setSaving(true)
    try {
      const payload = {
        name: form.name.trim(),
        code: form.code.trim(),
        description: form.description,
        permissions: form.permissions,
        server_ids: form.server_ids,
      }
      const url = editing.isNew ? `${API}/roles/` : `${API}/roles/${editing.id}`
      const method = editing.isNew ? 'POST' : 'PUT'
      if (!editing.isNew) delete payload.code
      const res = await fetch(url, {
        method, headers: { ...headers, 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      })
      if (!res.ok) {
        const e = await res.json().catch(() => ({}))
        throw new Error(e.detail || '保存失败')
      }
      closeModal()
      loadAll()
      // 通知父级刷新角色列表（用户管理的角色下拉依赖这份数据）
      if (typeof onRolesChanged === 'function') onRolesChanged()
    } catch (e) {
      setError(e.message)
    } finally {
      setSaving(false)
    }
  }

  const remove = async (id) => {
    try {
      const res = await fetch(`${API}/roles/${id}`, { method: 'DELETE', headers })
      if (!res.ok) {
        const e = await res.json().catch(() => ({}))
        throw new Error(e.detail || '删除失败')
      }
      setDeleteTarget(null)
      loadAll()
      if (typeof onRolesChanged === 'function') onRolesChanged()
    } catch (e) {
      setError(e.message)
      setDeleteTarget(null)
    }
  }

  const serverName = (id) => {
    const s = servers.find((x) => x.id === id)
    return s ? (s.name || s.ip_address) : `#${id}`
  }

  const serverIp = (id) => {
    const s = servers.find((x) => x.id === id)
    return s ? (s.ip_address || '') : ''
  }

  const askDelete = (r) => {
    if ((r.user_count || 0) > 0) {
      setNotice('该角色已被用户引用，请解除引用后再删除')
      return
    }
    setDeleteTarget(r)
  }

  if (loading) return <div className="page-loading">加载中...</div>

  return (
    <div className="settings-panel">
      <div className="settings-section-header">
        <h3>角色列表</h3>
        <button className="btn-add-user" onClick={openCreate} disabled={!isAdmin}>添加角色</button>
      </div>

      <div className="settings-panel-body">
      {error && <div className="form-error" style={{ marginBottom: 12 }}>{error}</div>}

      <table className="settings-table settings-table-fixed">
        <thead>
          <tr>
            <th className="col-id">ID</th>
            <th>角色名称</th>
            <th>标识</th>
            <th>说明</th>
            <th>授权主机</th>
            <th className="col-status">类型</th>
            <th className="col-ops">操作</th>
          </tr>
        </thead>
        <tbody>
          {roles.map((r) => (
            <tr key={r.id}>
              <td className="col-id">{r.id}</td>
              <td>{r.name}</td>
              <td><code>{r.code}</code></td>
              <td>{r.description || '—'}</td>
              <td>
                {r.is_admin
                  ? '全部主机（系统管理员）'
                  : r.server_ids && r.server_ids.length > 0
                    ? r.server_ids.map(serverName).join('、')
                    : '无'}
              </td>
              <td className="col-status">
                <span className={`role-badge role-${r.is_admin ? 'admin' : 'custom'}`}>
                  {r.is_admin ? '系统管理员' : '自定义'}
                </span>
              </td>
              <td className="col-ops actions">
                <button
                  className="btn-sm btn-primary"
                  onClick={() => openEdit(r)}
                  disabled={!isAdmin || (r.builtin && r.is_admin)}
                  title={r.builtin && r.is_admin ? '系统管理员角色不可修改' : ''}
                >
                  编辑
                </button>
                <button
                  className="btn-sm btn-danger"
                  onClick={() => askDelete(r)}
                  disabled={!isAdmin || Boolean(r.builtin)}
                  title={r.builtin ? '内置角色不可删除' : (r.user_count ? '该角色已被用户引用' : '')}
                >
                  删除
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      </div>

      <div className="settings-panel-foot">
        <span className="settings-count">共 {roles.length} 个角色</span>
      </div>

      {editing && (
        <div className="settings-modal-overlay">
          <div className="settings-modal role-modal" onClick={(e) => e.stopPropagation()}>
            <div className="settings-modal-header">
              <h4>{editing.isNew ? '添加角色' : '编辑角色'}</h4>
              <button className="settings-modal-close" onClick={closeModal} title="关闭">×</button>
            </div>

            <div className="settings-modal-body">
              {error && <div className="form-error" style={{ marginBottom: 12 }}>{error}</div>}

              <div className="role-section">
                <div className="role-section-title">基本信息</div>
                <div className="role-form-grid">
                  <div className="settings-form-group">
                    <label className="settings-form-label">角色名称 <span className="required">*</span></label>
                    <input className="form-input" value={form.name}
                      onChange={(e) => setForm({ ...form, name: e.target.value })}
                      placeholder="如：运维主管" autoComplete="off" />
                  </div>

                  <div className="settings-form-group">
                    <label className="settings-form-label">角色标识 <span className="required">*</span></label>
                    <input className="form-input" value={form.code} disabled={!editing.isNew}
                      onChange={(e) => setForm({ ...form, code: e.target.value })}
                      placeholder="如：ops_lead（英文，创建后不可修改）" autoComplete="off" />
                  </div>

                  <div className="settings-form-group role-form-full">
                    <label className="settings-form-label">说明</label>
                    <input className="form-input" value={form.description}
                      onChange={(e) => setForm({ ...form, description: e.target.value })}
                      placeholder="选填" autoComplete="off" />
                  </div>
                </div>
              </div>

              <div className="role-modal-tabs">
                <button type="button"
                  className={`role-mtab ${modalTab === 'hosts' ? 'active' : ''}`}
                  onClick={() => setModalTab('hosts')}>授权主机</button>
                <button type="button"
                  className={`role-mtab ${modalTab === 'perms' ? 'active' : ''}`}
                  onClick={() => setModalTab('perms')}>权限配置</button>
              </div>

              {modalTab === 'hosts' && (
              <div className="role-section">
                <div className="role-scope role-host-card">
                  <div className="role-scope-head role-host-card-head">
                    <strong>授权主机</strong>
                    <button type="button" className="btn-sm btn-primary" onClick={openPicker}
                      disabled={availableServers.length === 0}>
                      添加主机
                    </button>
                  </div>
                  <table className="role-server-table">
                  <thead>
                    <tr>
                      <th>主机名称</th>
                      <th className="col-ip">IP 地址</th>
                      <th className="col-ops">操作</th>
                    </tr>
                  </thead>
                  <tbody>
                    {form.server_ids.length === 0 ? (
                      <tr>
                        <td colSpan={3} className="role-empty">尚未添加主机，该角色看不到任何主机</td>
                      </tr>
                    ) : form.server_ids.map((id) => (
                      <tr key={id}>
                        <td>{serverName(id)}</td>
                        <td className="col-ip">{serverIp(id)}</td>
                        <td className="col-ops">
                          <button type="button" className="btn-sm btn-danger" onClick={() => removeServer(id)}>
                            移除
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
                </div>
              </div>
              )}

              {modalTab === 'perms' && (
              <div className="role-section">
                <div className="role-perm-grid">
                  {scopes.map((sc) => (
                    <div key={sc.code} className="role-scope">
                      <div className="role-scope-head">
                        <strong>{sc.name}</strong>
                        <span className="role-scope-actions">
                          <button type="button" className="btn-sm" onClick={() => toggleAllInScope(sc.code, true)}>全选</button>
                          <button type="button" className="btn-sm" onClick={() => toggleAllInScope(sc.code, false)}>清空</button>
                        </span>
                      </div>
                      <table className="role-perm-table">
                        <thead>
                          <tr>
                            <th>页面 / 页签</th>
                            <th className="col-perm">查看</th>
                            <th className="col-perm">编辑</th>
                          </tr>
                        </thead>
                        <tbody>
                          {sc.pages.map((p) => {
                            const entry = form.permissions[sc.code]?.[p.code] || { view: false, edit: false, ops: {} }
                            return (
                              <Fragment key={p.code}>
                                <tr>
                                  <td>{p.name}</td>
                                  <td className="col-perm">
                                    <input type="checkbox" checked={entry.view}
                                      onChange={(e) => setPageFlag(sc.code, p.code, 'view', e.target.checked)} />
                                  </td>
                                  <td className="col-perm">
                                    <input type="checkbox" checked={entry.edit}
                                      onChange={(e) => setPageFlag(sc.code, p.code, 'edit', e.target.checked)} />
                                  </td>
                                </tr>
                                {p.ops.length > 0 && (
                                  <tr className="role-ops-row">
                                    <td colSpan={3}>
                                      <div className="role-ops">
                                        {p.ops.map((o) => (
                                          <label key={o.code} className="role-check">
                                            <input type="checkbox" checked={Boolean(entry.ops?.[o.code])}
                                              onChange={(e) => setOpFlag(sc.code, p.code, o.code, e.target.checked)} />
                                            <span>{o.name}</span>
                                          </label>
                                        ))}
                                      </div>
                                    </td>
                                  </tr>
                                )}
                              </Fragment>
                            )
                          })}
                        </tbody>
                      </table>
                    </div>
                  ))}
                </div>
              </div>
              )}
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
                确定要删除角色 <strong>{deleteTarget.name}</strong> 吗？
                <br /><span style={{ color: '#dc3545', fontSize: 13 }}>该角色下若仍有用户，需先调整这些用户的角色。</span>
              </p>
            </div>
            <div className="settings-modal-footer">
              <button className="btn-cancel" onClick={() => setDeleteTarget(null)}>取消</button>
              <button className="btn-sm btn-danger" onClick={() => remove(deleteTarget.id)}>删除</button>
            </div>
          </div>
        </div>
      )}

      {notice && (
        <div className="settings-modal-overlay" onClick={() => setNotice('')}>
          <div className="settings-modal role-notice-modal" onClick={(e) => e.stopPropagation()}>
            <div className="settings-modal-header">
              <h4>无法删除</h4>
              <button className="settings-modal-close" onClick={() => setNotice('')} title="关闭">×</button>
            </div>
            <div className="settings-modal-body">
              <p style={{ margin: 0, fontSize: 14, color: '#333' }}>{notice}</p>
            </div>
            <div className="settings-modal-footer">
              <button className="btn-submit" onClick={() => setNotice('')}>确定</button>
            </div>
          </div>
        </div>
      )}

      {pickerOpen && (
        <div className="settings-modal-overlay" onClick={() => setPickerOpen(false)}>
          <div className="settings-modal role-picker-modal" onClick={(e) => e.stopPropagation()}>
            <div className="settings-modal-header">
              <h4>添加主机</h4>
              <button className="settings-modal-close" onClick={() => setPickerOpen(false)} title="关闭">×</button>
            </div>
            <div className="settings-modal-body">
              {availableServers.length === 0 ? (
                <p className="role-hint" style={{ margin: 0 }}>没有可添加的主机（已全部加入或暂无主机）</p>
              ) : (
                <div className="role-picker-list">
                  {availableServers.map((s) => (
                    <label key={s.id} className="role-check role-picker-item">
                      <input type="checkbox" checked={pickerIds.includes(s.id)}
                        onChange={() => togglePicker(s.id)} />
                      <span className="role-picker-name">{s.name || s.ip_address}</span>
                      <span className="role-picker-ip">{s.ip_address || ''}</span>
                    </label>
                  ))}
                </div>
              )}
            </div>
            <div className="settings-modal-footer">
              <button className="btn-cancel" onClick={() => setPickerOpen(false)}>取消</button>
              <button className="btn-submit" onClick={confirmPicker} disabled={pickerIds.length === 0}>
                添加{pickerIds.length > 0 ? ` (${pickerIds.length})` : ''}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
