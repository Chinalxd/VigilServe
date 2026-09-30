import { useState } from 'react'
import { useAuth } from '../services/auth'
import './LoginPage.css'
import Icon from './AppIcon'

export default function LoginPage() {
  const { login, kickedInfo } = useAuth()
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [err, setErr] = useState('')
  const [loading, setLoading] = useState(false)
  const [showPwd, setShowPwd] = useState(false)

  // 同一账号在别处登录、本机被顶下线后的提示。只显示一句笼统说明，
  // **不显示账号名和登录 IP**（那属于账号行踪，不该暴露在登录页上）。
  const kickTip = kickedInfo || ''

  const handleSubmit = async (e) => {
    e?.preventDefault?.()
    setErr('')
    setLoading(true)
    try {
      await login(username.trim(), password)
    } catch (e) {
      setErr(e.message || '登录失败')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="login-bg">
      <form className="login-card" onSubmit={handleSubmit}>
        <div className="login-brand">
          <img src="/logo.png" alt="VigilServe" className="login-logo-img" />
          <h1>VigilServe</h1>
        </div>
        <div className="login-form">
          <label>登录名</label>
          <input
            className="form-input"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            placeholder="请输入登录名"
            autoFocus
          />
          <label>密码</label>
          <div className="pwd-input-wrap">
            <input
              className="form-input"
              type={showPwd ? 'text' : 'password'}
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="请输入密码"
            />
            <span className="pwd-toggle" onClick={() => setShowPwd(!showPwd)} title={showPwd ? '隐藏' : '显示'}>
              {showPwd ? <Icon kind="ui-eye-off" size={15} /> : <Icon kind="ui-eye" size={15} />}
            </span>
          </div>
          {err && <div className="form-error">{err}</div>}
          <button className="login-submit" disabled={loading || !username || !password}>
            {loading ? '登录中...' : '登录'}
          </button>
          {kickTip && (
            <div className="login-kick-tip" role="alert">
              <span className="login-kick-icon"><Icon kind="ui-warning" size={13} /></span>
              <span>{kickTip}</span>
            </div>
          )}
        </div>
        <div className="login-hint">
          {/* 2026-09-23 开源加固 ②：这里原来直接印「默认管理员账号：admin / admin123」。
 源码一旦公开，这就是一把现成的后台钥匙。初始口令已改为服务端首次启动时
 随机生成，只写进服务端 backend/data/initial_admin_password.txt，
 页面上不再给出任何提示（真忘了只能找管理员在用户管理里重置）。 */}
          忘记密码请联系系统管理员重置
        </div>
      </form>
    </div>
  )
}
