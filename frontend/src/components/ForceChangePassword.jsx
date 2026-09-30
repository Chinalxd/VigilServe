import { useState, useEffect } from 'react'
import { authHeaders } from '../services/auth'
import { loadPasswordHint, FALLBACK_HINT } from '../services/passwordRules'
import Icon from './AppIcon'
import './ForceChangePassword.css'

/**
 * 首次登录强制修改口令。
 *
 * 2026-09-23 开源加固 ②：服务端在 `get_current_user_full` 里已经对
 * `must_reset_password=1` 的账号截断除改密/登出外的全部请求（403）。
 * 这里负责给用户一条能走通的通路 —— 改之前系统里根本没有自助改密入口，
 * 而 seed 出来的 admin 就是唯一管理员，服务端一强制就会被彻底锁死。
 *
 * 刻意做成**不可关闭**：没有取消按钮、点遮罩不关、Esc 不关。
 * 否则"强制改密"又退化成"点一下就绕过去"。
 */
export default function ForceChangePassword({ visible, onDone }) {
  const [oldPwd, setOldPwd] = useState('')
  const [newPwd, setNewPwd] = useState('')
  const [confirmPwd, setConfirmPwd] = useState('')
  const [err, setErr] = useState('')
  const [saving, setSaving] = useState(false)
  // 口令规则提示：规则来自「系统设置 - 安全设置」，由后端拼好文案（见 services/passwordRules.js）
  const [pwdHint, setPwdHint] = useState(FALLBACK_HINT)

  useEffect(() => {
    let alive = true
    loadPasswordHint().then((h) => { if (alive && h) setPwdHint(h) })
    return () => { alive = false }
  }, [])

  if (!visible) return null

  const submit = async (e) => {
    e?.preventDefault?.()
    setErr('')
    if (!oldPwd || !newPwd) {
      setErr('请填写当前口令和新口令')
      return
    }
    if (newPwd !== confirmPwd) {
      setErr('两次输入的新口令不一致')
      return
    }
    if (newPwd === oldPwd) {
      setErr('新口令不能与当前口令相同')
      return
    }
    setSaving(true)
    try {
      const res = await fetch('/api/auth/change-password', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', ...authHeaders() },
        body: JSON.stringify({ old_password: oldPwd, new_password: newPwd }),
      })
      const data = await res.json().catch(() => ({}))
      if (!res.ok) {
        setErr(data.detail || '修改失败')
        return
      }
      onDone?.()
    } catch (e2) {
      setErr(e2.message || '网络错误，请重试')
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="fcp-overlay">
      <form className="fcp-modal" onSubmit={submit}>
        <h3 className="fcp-title">
          <span className="fcp-title-icon"><Icon kind="ui-warning" size={15} /></span>
          必须先修改登录口令
        </h3>
        <p className="fcp-desc">
          当前口令是系统生成的初始口令（或已到期）。在修改之前，除本窗口外的所有功能均不可用。
        </p>

        <label className="fcp-label">当前口令</label>
        <input
          className="form-input"
          type="password"
          value={oldPwd}
          onChange={(e) => setOldPwd(e.target.value)}
          placeholder="请输入当前口令"
          autoFocus
        />

        <label className="fcp-label">新口令</label>
        <input
          className="form-input"
          type="password"
          value={newPwd}
          onChange={(e) => setNewPwd(e.target.value)}
          placeholder="请输入新口令"
        />
        {pwdHint && <p className="pwd-rule-hint">密码规则：{pwdHint}</p>}

        <label className="fcp-label">确认新口令</label>
        <input
          className="form-input"
          type="password"
          value={confirmPwd}
          onChange={(e) => setConfirmPwd(e.target.value)}
          placeholder="请再次输入新口令"
        />

        {err && <div className="form-error">{err}</div>}

        <div className="fcp-buttons">
          <button className="fcp-btn primary" type="submit" disabled={saving}>
            {saving ? '提交中...' : '修改口令'}
          </button>
        </div>
      </form>
    </div>
  )
}
