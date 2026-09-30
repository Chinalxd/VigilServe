import { useEffect, useRef, useState, useCallback } from 'react'
import { Terminal as Xterm } from 'xterm'
import { FitAddon } from 'xterm-addon-fit'
import 'xterm/css/xterm.css'
import { usePerm } from '../services/permissions'
import { connectWS } from '../services/ws'
import './Terminal.css'

/* @param {boolean} network 网络设备=true 时连 `/ws/network-terminal/{id}`：
 * 由**服务端直接 SSH / Telnet 到设备**（网络设备装不上 Agent，主机那条
 * 「服务端 → Agent → 本机 PTY」的路走不通）。命令窗口本身完全复用。 */
export default function WebTerminal({ serverId, network = false }) {
  const { can } = usePerm()
  const canConnect = can('host', 'terminal', 'edit', 'connect')
  const termRef = useRef(null)
  const xtermRef = useRef(null)
  const wsRef = useRef(null)
  const [connState, setConnState] = useState('idle')
  const connectCalled = useRef(false)
  const sizeRef = useRef({ cols: 80, rows: 24 })

  const disconnect = useCallback(() => {
    const ws = wsRef.current
    if (ws) {
      ws.onclose = null
      ws.onerror = null
      if (ws.readyState === WebSocket.OPEN || ws.readyState === WebSocket.CONNECTING) {
        ws.close()
      }
      wsRef.current = null
    }
    setConnState('idle')
  }, [])

  useEffect(() => {
    const el = termRef.current
    if (!el) return

    const term = new Xterm({
      fontSize: 14,
      fontFamily: 'Consolas, "Courier New", "Microsoft YaHei", "微软雅黑", "SimHei", monospace',
      cursorBlink: true,
      letterSpacing: 1,
      cols: 80,
      rows: 24,
      theme: {
        background: '#1e1e1e',
        foreground: '#d4d4d4',
        cursor: '#ffffff',
        selectionBackground: '#264f78',
      },
      allowProposedApi: true,
    })

    const fit = new FitAddon()
    term.loadAddon(fit)
    term.open(el)
    xtermRef.current = term

    el.addEventListener('click', () => term.focus())

    function resizeNow() {
      if (el.clientWidth < 50 || el.clientHeight < 50) return
      try { fit.fit() } catch { return }
      const { cols, rows } = term
      if (cols !== sizeRef.current.cols || rows !== sizeRef.current.rows) {
        sizeRef.current = { cols, rows }
        const ws = wsRef.current
        if (ws && ws.readyState === WebSocket.OPEN) {
          ws.send(JSON.stringify({ type: 'resize', cols, rows }))
        }
      }
    }

    let attempts = 0
    function ensureFit() {
      if (el.clientWidth < 50) { attempts++; if (attempts > 30) return; requestAnimationFrame(ensureFit); return }
      resizeNow()
    }
    requestAnimationFrame(ensureFit)

    const ro = new ResizeObserver(resizeNow)
    ro.observe(el)
    window.addEventListener('resize', resizeNow)

    return () => {
      window.removeEventListener('resize', resizeNow)
      ro.disconnect()
      disconnect()
      term.dispose()
    }
  }, [serverId, disconnect])

  const connect = useCallback(() => {
    const term = xtermRef.current
    if (!term || connectCalled.current) return
    connectCalled.current = true
    setConnState('connecting')

    const token = localStorage.getItem('token') || ''

    let ws = null
    let heartbeatTimer = null

    const decoder = new TextDecoder()
    const decoderOptions = { stream: true }

    // 令牌走子协议，不拼进 URL（安全加固阶段 3）
    ws = connectWS(network ? `/ws/network-terminal/${serverId}` : `/ws/terminal/${serverId}`, token)
    wsRef.current = ws
    ws.binaryType = 'arraybuffer'

    ws.onopen = () => {
      setConnState('connected')
      const { cols, rows } = sizeRef.current
      ws.send(JSON.stringify({ type: 'resize', cols, rows }))
      heartbeatTimer = setInterval(() => {
        if (ws && ws.readyState === WebSocket.OPEN) {
          ws.send(JSON.stringify({ type: 'ping' }))
        }
      }, 25000)
      term.focus()
    }

    ws.onmessage = (evt) => {
      if (typeof evt.data === 'string') {
        try {
          const msg = JSON.parse(evt.data)
          if (msg.type === 'pong' || msg.type === 'ping') return
        } catch {}
        return
      }
      if (evt.data instanceof ArrayBuffer) {
        const text = decoder.decode(evt.data, decoderOptions)
        if (text === '\x00') return
        term.write(text)
      }
    }

    ws.onclose = () => {
      clearInterval(heartbeatTimer)
      wsRef.current = null
      connectCalled.current = false
      setConnState('idle')
      term.writeln('\r\n\x1b[31m连接已关闭\x1b[0m')
    }

    ws.onerror = () => {
      connectCalled.current = false
      setConnState('idle')
      term.writeln('\r\n\x1b[31m连接失败\x1b[0m')
    }

    term.onData((data) => {
      if (!ws || ws.readyState !== WebSocket.OPEN) return
      ws.send(new TextEncoder().encode(data))
    })

    // 网络设备：先提示一句连的是什么，免得连上后一片黑不知道在等什么
    if (network) {
      term.writeln(`\x1b[36m正在由服务端 SSH/Telnet 登录设备…\x1b[0m`)
      term.writeln('\x1b[90m凭据在「设备管理 - 网络设备」里维护；登录后如需特权模式请自行输入 enable / super。\x1b[0m')
    }

    const el = termRef.current
    if (el) {
      el.addEventListener('contextmenu', (e) => {
        e.preventDefault()
        const sel = term.getSelection()
        const old = document.querySelector('.xterm-context-menu')
        if (old) old.remove()
        const menu = document.createElement('div')
        menu.className = 'xterm-context-menu'
        Object.assign(menu.style, {
          position: 'fixed', left: e.clientX + 'px', top: e.clientY + 'px',
          zIndex: '9999', background: '#333', border: '1px solid #555',
          borderRadius: '4px', padding: '4px 0', minWidth: '100px',
          boxShadow: '0 2px 8px rgba(0,0,0,0.5)',
        })
        function addItem(label, fn) {
          const item = document.createElement('div')
          item.textContent = label
          Object.assign(item.style, { padding: '6px 14px', cursor: 'pointer', color: '#d4d4d4', fontSize: '13px', userSelect: 'none' })
          if (!sel && label === '复制') { item.style.color = '#666'; item.style.cursor = 'default' }
          item.onmouseenter = () => { item.style.background = '#444' }
          item.onmouseleave = () => { item.style.background = 'transparent' }
          item.onclick = () => { menu.remove(); fn() }
          menu.appendChild(item)
        }
        addItem('复制', () => { if (!sel) return; navigator.clipboard?.writeText(sel).catch(() => {}) })
        addItem('粘贴', () => {
          navigator.clipboard?.readText().then(t => {
            if (!ws || ws.readyState !== WebSocket.OPEN) return
            const data = t.replace(/\r?\n/g, '\r\n')
            const encoder = new TextEncoder()
            const chunkSize = 8
            const delay = 5
            let i = 0
            function sendNext() {
              if (i >= data.length) return
              const end = Math.min(i + chunkSize, data.length)
              ws.send(encoder.encode(data.slice(i, end)))
              i = end
              setTimeout(sendNext, delay)
            }
            sendNext()
          }).catch(() => {})
        })
        document.body.appendChild(menu)
        const closer = (ev) => { if (!menu.contains(ev.target)) { menu.remove(); document.removeEventListener('mousedown', closer) } }
        setTimeout(() => document.addEventListener('mousedown', closer), 0)
      })
    }
  }, [serverId])

  return (
    <div className="web-terminal-wrapper">
      <div className="web-terminal-toolbar">
        <span className="rdp-spacer" />
        <button
          className={connState === 'connected' ? 'rdp-disconnect' : 'rdp-connect'}
          onClick={connState === 'connected' ? disconnect : connect}
          disabled={connState === 'connecting' || !canConnect}
          title={
            canConnect
              ? (connState === 'connected' ? '断开终端' : (network ? '登录设备命令行' : '连接终端'))
              : '当前角色没有WEB终端的连接权限'
          }
        >
          {connState === 'connected' ? '断开' : (connState === 'connecting' ? '连接中…' : (network ? '连接设备' : '连接终端'))}
        </button>
      </div>
      <div className="web-terminal" ref={termRef}>
        {connState !== 'connected' && (
          <div className="terminal-overlay">
            <div className="rdp-waiting">
              终端未连接
              <span>
                {canConnect
                  ? (network ? '点击右上角「连接设备」登录命令行' : '点击右上角「连接终端」开始')
                  : '当前角色没有WEB终端的连接权限'}
              </span>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
