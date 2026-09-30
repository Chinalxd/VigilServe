// WebSocket 连接助手（安全加固阶段 3）
// 浏览器不允许给 WebSocket 设置自定义 Header，以前只能把登录令牌拼在 URL 上
// （`/ws/terminal/1?token=xxx`）。URL 会被写进访问日志、浏览器历史和 Referer，
// 子协议只在握手帧里出现，不进 URL、不进历史、不进 Referer。
export const WS_TOKEN_SUBPROTOCOL = 'vigitoken.'

export function wsUrl(path) {
  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
  return `${protocol}//${window.location.host}${path}`
}

// 带鉴权的 WebSocket。extraProtocols 用于 guacamole 等固定子协议的第三方库。
export function connectWS(path, token, extraProtocols = []) {
  const protocols = [...extraProtocols]
  if (token) protocols.push(WS_TOKEN_SUBPROTOCOL + token)
  return protocols.length
    ? new WebSocket(wsUrl(path), protocols)
    : new WebSocket(wsUrl(path))
}
