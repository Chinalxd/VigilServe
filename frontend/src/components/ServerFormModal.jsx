import { useState, useEffect } from 'react'
import './ServerFormModal.css'
import Icon from './AppIcon'

const PROTOCOL_OPTIONS = [
  { value: 'SSH', label: 'SSH (Linux/Unix)', defaultPort: 22 },
  { value: 'WinRM', label: 'WinRM (Windows)', defaultPort: 5985 },
  { value: 'Telnet', label: 'Telnet', defaultPort: 23 },
]

export default function ServerFormModal({ visible, onClose, onSubmit, onDelete, initialData }) {
  const isEdit = !!initialData
  const isAgent = initialData?.protocol === 'agent'

  const [form, setForm] = useState({
    name: '',
    ip_address: '',
    business_system: '',
    protocol: 'SSH',
    connection_port: 22,
    username: '',
    password: '',
    description: '',
  })
  const [submitting, setSubmitting] = useState(false)
  const [errors, setErrors] = useState({})
  const [showPassword, setShowPassword] = useState(true)

  useEffect(() => {
    if (initialData) {
      setForm({
        name: initialData.name || '',
        ip_address: initialData.ip_address || '',
        business_system: initialData.business_system || '',
        protocol: initialData.protocol || 'SSH',
        connection_port: initialData.connection_port || 22,
        username: initialData.username || '',
        password: initialData.password || '',
        description: initialData.description || '',
      })
    } else {
      setForm({
        name: '',
        ip_address: '',
        business_system: '',
        protocol: 'SSH',
        connection_port: 22,
        username: '',
        password: '',
        description: '',
      })
    }
    setErrors({})
    setShowPassword(false)
  }, [initialData, visible])

  if (!visible) return null

  const handleChange = (field, value) => {
    setForm((prev) => ({ ...prev, [field]: value }))
    if (errors[field]) setErrors((prev) => ({ ...prev, [field]: null }))
  }

  const handleProtocolChange = (proto) => {
    const option = PROTOCOL_OPTIONS.find((o) => o.value === proto)
    setForm((prev) => ({
      ...prev,
      protocol: proto,
      connection_port: option ? option.defaultPort : prev.connection_port,
    }))
  }

  const validate = () => {
    const errs = {}
    if (!form.name.trim()) errs.name = '请输入主机名称'
    if (!isAgent) {
      if (!form.ip_address.trim()) errs.ip_address = '请输入IP地址'
      if (!form.protocol) errs.protocol = '请选择连接协议'
      if (!form.connection_port || form.connection_port < 1) errs.connection_port = '请输入有效端口'
      if (!form.username.trim()) errs.username = '请输入登录用户名'
      if (!isEdit && !form.password.trim()) errs.password = '请输入登录密码'
    }
    setErrors(errs)
    return Object.keys(errs).length === 0
  }

  const handleSubmit = async () => {
    if (!validate()) return
    setSubmitting(true)
    try {
      await onSubmit({
        ...form,
        connection_port: parseInt(form.connection_port) || 22,
      })
      onClose()
    } catch (e) {
      setErrors({ submit: e.message || '操作失败，请重试' })
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <div className="modal-overlay" onClick={(e) => { }}>
      <div className="modal-container" onClick={(e) => e.stopPropagation()}>
        <div className="modal-header">
          <h2>{isEdit ? '编辑主机' : '连接新服务器'}</h2>
          <button className="modal-close" onClick={onClose}><Icon kind="ui-close" size={18} /></button>
        </div>

        <div className="modal-body">
          <div className="form-group">
            <label className="form-label required">主机名称</label>
            <input
              className={`form-input ${errors.name ? 'input-error' : ''}`}
              value={form.name}
              onChange={(e) => handleChange('name', e.target.value)}
              placeholder="例如：ERP生产服务器"
            />
            {errors.name && <span className="form-error">{errors.name}</span>}
          </div>

          {!isEdit && (
            <div className="form-group">
              <label className="form-label">业务系统</label>
              <input
                className="form-input"
                value={form.business_system}
                onChange={(e) => handleChange('business_system', e.target.value)}
                placeholder="例如：ERP系统、金蝶K/3、文件服务（自定义填写）"
              />
            </div>
          )}

          {!isAgent && (
          <>
          <div className="form-row">
            <div className="form-group flex-1">
              <label className="form-label required">IP 地址</label>
              <input
                className={`form-input ${errors.ip_address ? 'input-error' : ''}`}
                value={form.ip_address}
                onChange={(e) => handleChange('ip_address', e.target.value)}
                placeholder="192.168.1.100"
              />
              {errors.ip_address && <span className="form-error">{errors.ip_address}</span>}
            </div>
            <div className="form-group flex-1">
              <label className="form-label required">连接协议</label>
              <select
                className={`form-select ${errors.protocol ? 'input-error' : ''}`}
                value={form.protocol}
                onChange={(e) => handleProtocolChange(e.target.value)}
              >
                {PROTOCOL_OPTIONS.map((o) => (
                  <option key={o.value} value={o.value}>{o.label}</option>
                ))}
              </select>
            </div>
            <div className="form-group" style={{ width: '100px' }}>
              <label className="form-label required">端口</label>
              <input
                type="number"
                className={`form-input ${errors.connection_port ? 'input-error' : ''}`}
                value={form.connection_port}
                onChange={(e) => handleChange('connection_port', e.target.value)}
                min="1" max="65535"
              />
              {errors.connection_port && <span className="form-error">{errors.connection_port}</span>}
            </div>
          </div>

          <div className="form-row">
            <div className="form-group flex-1">
              <label className="form-label required">用户名</label>
              <input
                className={`form-input ${errors.username ? 'input-error' : ''}`}
                value={form.username}
                onChange={(e) => handleChange('username', e.target.value)}
                placeholder="root / administrator"
              />
              {errors.username && <span className="form-error">{errors.username}</span>}
            </div>
            <div className="form-group flex-1">
              <label className="form-label">{isEdit ? '密码' : '密码'}</label>
              <div className="password-wrap">
                <input
                  type={showPassword ? 'text' : 'password'}
                  className={`form-input ${errors.password ? 'input-error' : ''}`}
                  value={form.password}
                  onChange={(e) => handleChange('password', e.target.value)}
                  placeholder={isEdit ? '保持不变请留空' : '输入登录密码'}
                />
                <button
                  type="button"
                  className="btn-toggle-pwd"
                  onClick={() => setShowPassword(!showPassword)}
                  title={showPassword ? '隐藏密码' : '显示密码'}
                >
                  {showPassword ? <Icon kind="ui-eye-off" size={15} /> : <Icon kind="ui-eye" size={15} />}
                </button>
              </div>
              {errors.password && <span className="form-error">{errors.password}</span>}
            </div>
          </div>
          </>
          )}

          <div className="form-group">
            <label className="form-label">备注</label>
            <textarea
              className="form-textarea"
              value={form.description}
              onChange={(e) => handleChange('description', e.target.value)}
              placeholder="服务器用途、位置、负责人等备注信息..."
              rows={3}
            />
          </div>

          {errors.submit && <div className="submit-error">{errors.submit}</div>}
        </div>

        <div className="modal-footer">
          <div className="footer-right">
            <button className="btn-cancel" onClick={onClose} disabled={submitting}>取消</button>
            <button className="btn-submit" onClick={handleSubmit} disabled={submitting}>
              {submitting ? '处理中...' : isEdit ? '保存修改' : '连接服务器'}
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}