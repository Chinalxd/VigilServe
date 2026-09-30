/* SSH 主机密钥卡片（原「网络」页签里的一块，页签删除后独立成组件）
 *
 * 网络设备「系统信息」页签复用它 —— 设备身份的一部分：服务端第一次 SSH 登录这台
 * 设备时把主机密钥钉下来，之后密钥变了就拒绝连接并告警，管理员确认后才转正。
 * 放在这里而不是「主机管理 - 网络设备」，是因为它属于"这台设备的身份现状"，
 * 跟凭据（那边维护）是两件事。
 */
import { useCallback, useEffect, useState } from 'react'
import { parseServerTime } from '../utils/format'
import { fetchSshHostKey, repinSshHostKey, unpinSshHostKey } from '../services/api'
import { usePerm } from '../services/permissions'
import { showToast } from '../utils/toast'
import './NetworkPanel.css'

function fmtTime(iso) {
  if (!iso) return '—'
  const d = parseServerTime(iso)
  if (Number.isNaN(d.getTime())) return '—'
  const p = (x) => String(x).padStart(2, '0')
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`
}

export default function SshHostKeyCard({ serverId }) {
  const { can } = usePerm()
  const canRepin = can('host', 'network', 'edit', 'repin')

  const [hostKey, setHostKey] = useState(null)
  const [hostKeyErr, setHostKeyErr] = useState('')
  const [busy, setBusy] = useState('')

  // SSH 主机密钥归「系统设置 - 注册管理」管，没那个权限的角色会拿到 403。
  // 这里不能静默吞掉 —— 否则页面显示"还没有钉扎记录"，管理员会以为设备没连过。
  const load = useCallback(async () => {
    try {
      setHostKey(await fetchSshHostKey(serverId))
      setHostKeyErr('')
    } catch (e) {
      setHostKeyErr(e.message || '读取失败')
    }
  }, [serverId])

  useEffect(() => { load() }, [load])

  const onRepin = async () => {
    setBusy('repin')
    try {
      await repinSshHostKey(serverId, (hostKey && hostKey.pending_fingerprint) || '')
      showToast('已确认为新密钥', 'success')
      await load()
    } catch (e) {
      showToast(e.message || '确认失败', 'error')
    } finally {
      setBusy('')
    }
  }

  const onUnpin = async () => {
    setBusy('unpin')
    try {
      await unpinSshHostKey(serverId)
      showToast('已清除钉扎记录，下次连接将重新走首连流程', 'success')
      await load()
    } catch (e) {
      showToast(e.message || '清除失败', 'error')
    } finally {
      setBusy('')
    }
  }

  const hk = hostKey || {}
  const hkStatus = hk.pinned ? hk.status : 'none'

  return (
    <section className="np-panel">
      <header className="np-panel-head">
        <span className="np-panel-title">SSH 主机密钥</span>
        <span className="np-spacer" />
        {canRepin && hkStatus === 'changed' && (
          <button className="np-btn np-btn-danger" onClick={onRepin} disabled={!!busy}>
            {busy === 'repin' ? '处理中…' : '确认为新密钥'}
          </button>
        )}
        {canRepin && hk.pinned && (
          <button className="np-btn" onClick={onUnpin} disabled={!!busy}>
            {busy === 'unpin' ? '处理中…' : '清除钉扎'}
          </button>
        )}
      </header>
      <div className="np-panel-body">
        {hostKeyErr ? (
          <div className="np-empty-box">
            无法读取 SSH 主机密钥：{hostKeyErr}（该项归「系统设置 - 注册管理」权限管）
          </div>
        ) : hkStatus === 'none' ? (
          <div className="np-empty-box">
            还没有钉扎记录。第一次通过「WEB终端」SSH 登录这台设备时会自动记录主机密钥
            （当前策略：{hk.policy === 'strict' ? '严格 —— 首连也需先在别处登记' : '首次连接自动信任（TOFU）'}）。
          </div>
        ) : (
          <>
            {hkStatus === 'changed' && (
              <div className="np-alert">
                <b>主机密钥已变更，连接已被拒绝。</b>
                可能是设备重装 / 换过密钥，也可能是中间人。确认这台设备确实是你预期的那台之后再点
                「确认为新密钥」；否则先查网络。
              </div>
            )}
            <table className="np-kv">
              <tbody>
                <tr>
                  <th>状态</th>
                  <td>
                    <span className={`np-pill ${hkStatus === 'changed' ? 'np-pill-down' : 'np-pill-up'}`}>
                      {hkStatus === 'changed' ? '待确认' : '已钉扎'}
                    </span>
                    <span className="np-inline-sub">
                      策略：{hk.policy === 'strict' ? '严格' : 'TOFU（首连自动信任）'}
                    </span>
                  </td>
                </tr>
                <tr>
                  <th>已钉扎指纹</th>
                  <td className="np-mono np-fp">{hk.fingerprint || '—'}</td>
                </tr>
                <tr>
                  <th>密钥类型</th>
                  <td>{hk.key_type || '—'}</td>
                </tr>
                <tr>
                  <th>主机 : 端口</th>
                  <td>{hk.hostname || '—'} : {hk.port || 22}</td>
                </tr>
                <tr>
                  <th>钉扎 / 最近校验</th>
                  <td>{fmtTime(hk.pinned_at)} / {fmtTime(hk.last_verified_at)}</td>
                </tr>
                {hk.pending_fingerprint ? (
                  <>
                    <tr>
                      <th>新观察到的指纹</th>
                      <td className="np-mono np-fp np-fp-new">{hk.pending_fingerprint}</td>
                    </tr>
                    <tr>
                      <th>首次发现</th>
                      <td>{fmtTime(hk.pending_first_seen)}</td>
                    </tr>
                  </>
                ) : null}
              </tbody>
            </table>
          </>
        )}
      </div>
    </section>
  )
}
