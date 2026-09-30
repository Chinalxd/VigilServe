import { useParams, useSearchParams } from 'react-router-dom'
import RemoteDesktop from './RemoteDesktop'
import './RemoteDesktop.css'

/**
 * 独立窗口形态的远程桌面（路由 /rdp/:serverId）
 *
 * 由页签内嵌那个远程桌面的「全屏」按钮 window.open 出来。
 *
 * 为什么走**独立路由**而不是把内嵌面板 portal 到新窗口：guac 画面、IME 输入槽、
 * 剪贴板桥接三样都是挂在 document / window 上的，跨文档搬运每一处都要单独补一份
 *（键盘要新建、输入槽要搬、Ctrl+V 桥接要在新 window 上再挂一次）。独立窗口有自己
 * 的 document，这些能力天然可用，RemoteDesktop 一行都不用改，只多一个 standalone 开关。
 *
 * 权限不做前端门禁：与页签内嵌保持一致 —— 没权限时「连接」按钮就是灰的并在 title
 * 里说明原因；WebSocket 通道后端还有一道 admission_check。
 */
export default function RemoteDesktopStandalone() {
  const { serverId } = useParams()
  const [params] = useSearchParams()
  const id = Number(serverId)

  if (!id || Number.isNaN(id)) {
    return <div className="rdp-window rdp-window-denied">远程桌面：主机编号无效</div>
  }

  return (
    <div className="rdp-window">
      <RemoteDesktop serverId={id} serverName={params.get('name') || ''} standalone />
    </div>
  )
}
