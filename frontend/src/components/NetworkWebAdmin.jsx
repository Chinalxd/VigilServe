/* 方案 B：网络设备「WEB管理」页签 —— 设备自带 Web 管理界面的反向代理外壳
 *
 * 页面本体不是我们写的：服务端把设备的界面搬到 /api/servers/{id}/web/ 底下，
 * 这里只负责把这个地址嵌进来。
 *
 * iframe 一定要 sandbox 且**不要** allow-same-origin：代理回来的页面和我们同源，
 * 给了 allow-same-origin 它就能读 parent.localStorage，把登录令牌整个端走
 * （设备被入侵时这是现成的跳板）。
 *
 * 代价是沙箱里浏览器**不保存任何 Cookie**，所以两件事由服务端兜：
 * * 帧内后续请求靠 URL 上的窄票据 `t=`（web-config 下发，30 分钟、绑定用户与设备）；
 * * 设备自己的会话 Cookie 由后端保管箱记着，替它带上去。
 * 前端这边只管把票据拼进 iframe 的地址。 */
import { useCallback, useEffect, useState } from 'react'
import { fetchNetworkWebConfig } from '../services/api'
import './NetworkWebAdmin.css'

const SANDBOX_BASE = 'allow-scripts allow-forms allow-modals allow-popups'
// 那时设备页面弹出的顶层窗口落在另一个源上，读不到主站的 localStorage，放行它
// 同源形态下不能给 —— 弹出的顶层窗口跟我们同 origin，设备页面（万一被入侵）可以
const SANDBOX_ESCAPE = ' allow-popups-to-escape-sandbox'

// 拼进 HTML 属性前转义：地址来自服务端配置，理论上可信，但拼字符串就该转义。
const escapeAttr = (s) => String(s)
  .replace(/&/g, '&amp;').replace(/"/g, '&quot;')
  .replace(/</g, '&lt;').replace(/>/g, '&gt;')

export default function NetworkWebAdmin({ serverId }) {
  const [cfg, setCfg] = useState(null)
  const [err, setErr] = useState('')
  const [nonce, setNonce] = useState(0)

  useEffect(() => {
    let alive = true
    setErr('')
    setCfg(null)
    ;(async () => {
      try {
        const data = await fetchNetworkWebConfig(serverId)
        if (alive) setCfg(data)
      } catch (e) {
        if (alive) setErr(e.message || '读取 WEB 管理配置失败')
      }
    })()
    return () => { alive = false }
  }, [serverId])

  // 服务端配置了「独立源代理」时（proxy_base_url 非空），帧地址走那个源：
  // 跨源之后设备页面读不到主站 localStorage，"新窗口打开"也不再是跳板。
  const proxyBase = cfg?.proxy_base_url || ''
  const prefix = cfg?.proxy_prefix || `/api/servers/${serverId}/web/`
  // 票据走**路径首段**：服务端下发的 <base> 也长这样，于是 webpack 分片、CSS 里的
  // 相对 url()、JS 里 fetch 的地址全都自动带上票据。写成 `?t=` 的话这些子资源带不上，
  const frameSrc = cfg?.ticket
    ? `${proxyBase}${prefix}${cfg.ticket}/?_=${nonce}`
    : ''
  const onReload = useCallback(() => setNonce((n) => n + 1), [])

  // 独立源形态才允许设备页面自己弹出「逃出沙箱」的窗口
  const sandbox = proxyBase ? SANDBOX_BASE + SANDBOX_ESCAPE : SANDBOX_BASE

  // 「新窗口打开」不能写成 `window.open(frameSrc)` —— 那会把设备页面直接放到
  // **顶层窗口**里，外面没有任何 sandbox 约束；同源形态下它跟主站同 origin，可以
  // 改成先开一个空白窗口，再往里写一张**同样带 sandbox 的 iframe**：设备页面无论
  // 怎么跳转都还困在沙箱里，而新窗口本身是我们自己写的静态 HTML，不含任何凭据。
  const onOpenWindow = useCallback(() => {
    if (!frameSrc) return
    const w = window.open('', `_network_web_${serverId}`)
    if (!w) return
    const doc = w.document
    doc.open()
    doc.write(
      '<!DOCTYPE html><html lang="zh-CN"><head><meta charset="utf-8">'
      + '<title>设备 WEB 管理</title><style>'
      + 'html,body{margin:0;height:100%;background:#f5f6f8}'
      + 'iframe{border:0;display:block;width:100%;height:100vh}'
      + '</style></head><body>'
      + `<iframe src="${escapeAttr(frameSrc)}" sandbox="${sandbox}" `
      + 'referrerpolicy="no-referrer"></iframe>'
      + '</body></html>'
    )
    doc.close()
  }, [frameSrc, serverId, sandbox])

  if (err) {
    return (
      <div className="nwa">
        <div className="nwa-empty">{err}</div>
      </div>
    )
  }

  if (!cfg) {
    return (
      <div className="nwa">
        <div className="nwa-empty">读取 WEB 管理配置…</div>
      </div>
    )
  }

  if (!cfg.enabled) {
    return (
      <div className="nwa">
        <div className="nwa-empty">
          这台设备没有可用的管理地址（设备 IP 为空），WEB 管理页打不开。
        </div>
      </div>
    )
  }

  if (!cfg.ticket) {
    return (
      <div className="nwa">
        <div className="nwa-empty">登录状态已失效，请重新登录后再打开。</div>
      </div>
    )
  }

  return (
    // 工具栏和网页窗口合并成一张大卡片（2026-09-21）：外层 .nwa 出边框，
    // 里面的工具条和 iframe 各自都不再画边框 —— 原来是两个带边框的盒子中间夹 8px 缝，
    <div className="nwa">
      {/* 工具条只留设备地址 + 两个按钮：
 「地址」这个前缀和后面的"页面由服务端代理…"说明都按需求去掉了 */}
      <div className="nwa-bar">
        <b className="nwa-addr" title="新增设备时填的网络信息，自动带到这里">
          {cfg.protocol}://{cfg.host}:{cfg.port}
        </b>
        <span className="nwa-spacer" />
        <button className="nd-btn" onClick={onOpenWindow} disabled={!frameSrc}>新窗口打开</button>
        <button className="nd-btn" onClick={onReload}>重新加载</button>
      </div>

      <iframe
        key={nonce}
        className="nwa-frame"
        title="设备 WEB 管理"
        src={frameSrc}
        sandbox={sandbox}
        referrerPolicy="no-referrer"
      />
    </div>
  )
}
