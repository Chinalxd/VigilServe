import { useEffect, useRef, useState, useCallback } from 'react'
import Guacamole from '../vendor/guacamole-common.js'
import { usePerm } from '../services/permissions'
import './RemoteDesktop.css'
import Icon from './AppIcon'

const STATE_TEXT = { 0: '空闲', 1: '连接中', 2: '等待中', 3: '已连接', 4: '断开中', 5: '已断开' }

// 工具栏组合键（后端 services/rdp.COMBOS 白名单，名字必须对得上）
const COMBOS = [
  { name: 'taskmgr', label: '任务管理器', title: 'Ctrl+Shift+Esc' },
  { name: 'cad', label: 'Ctrl+Alt+Del', title: '安全桌面序列，部分场景不生效，可用任务管理器代替' },
  { name: 'altab', label: 'Alt+Tab', title: '切换窗口' },
  { name: 'win', label: '开始菜单', title: 'Win' },
  { name: 'winl', label: '锁定', title: 'Win+L' },
]

const QUALITY = [
  { key: 'low', label: '流畅' },
  { key: 'medium', label: '标准' },
  { key: 'high', label: '高清' },
]

// 边界（表现为关闭远程桌面后主机页「页面加载异常 a.current.disconnect is not a function」）。
// 补一个 no-op 版 disconnect：置空回调，让残留监听空转，不再向已断开的 client 发按键。
if (Guacamole.Keyboard && typeof Guacamole.Keyboard.prototype.disconnect !== 'function') {
  Guacamole.Keyboard.prototype.disconnect = function () {
    this.onkeydown = null
    this.onkeyup = null
  }
}

// IME 通道实际是现成的。但这两个事件**只有在页面里真存在一个拿到焦点的可编辑
// 元素时才会触发**：没有输入框时浏览器找不到组字目标，会退化成把拼音字母当普通
// keydown 往外发，于是远端收到的就是一串小写字母——这正是「切到中文却打不出
// 官方客户端的做法就是额外挂一个隐藏 textarea（Guacamole.InputSink）承接组字。
// 做成模块级单例：`InputSink` 构造时会在 document 上注册一个**无法撤销**的
let _imeSink = null
function getImeSink() {
  if (_imeSink) return _imeSink
  if (typeof Guacamole.InputSink === 'function') {
    _imeSink = new Guacamole.InputSink()
  } else {
    // 兜底：vendor 换版本后没有 InputSink 时自建等价物，避免静默失效
    const el = document.createElement('textarea')
    el.setAttribute('aria-hidden', 'true')
    el.tabIndex = -1
    el.style.cssText = 'position:fixed;left:0;bottom:0;width:1px;height:1px;margin:0;' +
      'padding:0;border:none;outline:none;resize:none;background:transparent;color:transparent'
    el.addEventListener('compositionend', (e) => { if (e.data) el.value = '' })
    el.addEventListener('input', (e) => { if (e.data && !e.isComposing) el.value = '' })
    _imeSink = {
      getElement: () => el,
      focus: () => window.setTimeout(() => el.focus(), 0),
    }
  }

  attachClipboardBridge(_imeSink.getElement())
  return _imeSink
}

// 焦点在这个输入框上时，Ctrl+C / Ctrl+V / Ctrl+X 会被浏览器当成**对这个输入框的
// 复制/剪切 -> 浏览器拿 textarea 的空选区去写剪贴板，会把刚从远端同步回来的
// 内容覆盖掉（「远端复制 -> 本机粘贴」这条链路就断了）；
// 复制/剪切：只拦默认行为，按键照常发到远端（远端内部复制粘贴不受影响）；
// 粘贴：**自己接管** —— 把本机剪贴板文本经 guac `clipboard` 指令同步到远端
// 顺序是关键，**不能直接放行原始 Ctrl+V**：keydown 会先到远端，远端立刻拿
// **旧**剪贴板粘一次，我们之后同步过去的内容只能等下一次粘贴才生效。
// 也不能对 keydown 调 preventDefault：那样浏览器连 `paste` 事件都不派发，
// 就拿不到本机剪贴板内容了。所以只用 stopPropagation 掐断传播，默认动作保留。
let _clipSend = null
let _pasteTimer = 0
let _pasteSwallow = false
let _remoteClip = ''

// 「远端内部复制粘贴」不能被这次改造带偏：Agent 是 1.5s 轮询才把远端剪贴板回传，
// 用户在远端 Ctrl+C 后立刻按 Ctrl+V，本机剪贴板很可能还是旧内容——这时把它写回
// 远端就会粘错。所以记住远端回声，内容一致就说明远端本来就有，直接按 Ctrl+V。
function noteRemoteClip(text) {
  _remoteClip = text
}

const KEYSYM_CTRL = 0xffe3
const KEYSYM_V = 0x76
const CLIPBOARD_MAX = 500000

function sendCtrlV() {
  const send = _clipSend
  if (!send) return
  send('key', KEYSYM_CTRL, 1)
  send('key', KEYSYM_V, 1)
  send('key', KEYSYM_V, 0)
  send('key', KEYSYM_CTRL, 0)
}

/** 用 Clipboard API 主动读本机剪贴板（不依赖焦点），读不到就返回 ''。 */
async function readLocalClipboard() {
  try {
    if (navigator.clipboard && navigator.clipboard.readText) {
      return (await navigator.clipboard.readText()) || ''
    }
  } catch {
    // 权限被拒 / 非安全上下文 / 文档没焦点：交给 paste 事件兜底
  }
  return ''
}

/** 先把文本同步到远端剪贴板，再补一次 Ctrl+V 让远端从它自己的剪贴板粘贴。 */
function pushClipboardThenPaste(text) {
  const send = _clipSend
  if (!send) return
  text = (text || '').slice(0, CLIPBOARD_MAX)
  if (text && text !== _remoteClip) {
    send('clipboard', '0', text)
    _remoteClip = text
    window.setTimeout(sendCtrlV, 150)
    return
  }
  // 空剪贴板、或本机剪贴板只是远端回声：远端本来就有，直接按 Ctrl+V
  sendCtrlV()
}

function writeLocalClipboard(text) {
  if (!text) return
  noteRemoteClip(text)
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(text).catch(() => legacyCopy(text))
    return
  }
  legacyCopy(text)
}

function legacyCopy(text) {
  try {
    const el = _imeSink && _imeSink.getElement && _imeSink.getElement()
    if (!el) return
    el.value = text
    el.focus()
    el.select()
    document.execCommand('copy')
    el.value = ''
  } catch {
  }
}

function attachClipboardBridge(sinkEl) {
  const block = (e) => e.preventDefault()
  sinkEl.addEventListener('copy', block)
  sinkEl.addEventListener('cut', block)

  const isEditable = (el) => !!el && (el.tagName === 'INPUT' ||
    el.tagName === 'TEXTAREA' || el.isContentEditable)

  const isPasteKey = (e) =>
    (e.ctrlKey || e.metaKey) && !e.shiftKey && !e.altKey &&
    (e.key || '').toLowerCase() === 'v'

  // 必须挂在 **window 的捕获阶段**。vendor 的 `Guacamole.Keyboard.listenTo()`
  const onKeyDown = (e) => {
    if (!_clipSend || !isPasteKey(e)) return
    // 焦点在**别的**输入框里（工具栏之类）说明用户想粘到本地输入框，别抢
    const ae = document.activeElement
    if (ae && ae !== sinkEl && isEditable(ae)) return

    // 扣下原始 Ctrl+V，等拿到本机剪贴板内容、同步到远端后再补发。
    // 只用 stopPropagation 掐断传播，不能 preventDefault —— 那样浏览器连 paste
    e.stopPropagation()
    _pasteSwallow = true

    // 焦点必须回到输入槽：点过画面/工具栏之后焦点可能已经跑到 canvas 或按钮上，
    // 浏览器就不会把剪贴板内容派发成 paste 事件（现象就是"粘贴没反应"）。
    // 这里同步抢回焦点，粘贴的默认动作才会落到 sink 上。
    if (document.activeElement !== sinkEl) {
      try { sinkEl.focus() } catch { }
    }

    if (_pasteTimer) clearTimeout(_pasteTimer)
    // 兜底：paste 没来（焦点没抢到 / 浏览器没派发）时直接调 Clipboard API 读
    _pasteTimer = window.setTimeout(async () => {
      _pasteTimer = 0
      pushClipboardThenPaste(await readLocalClipboard())
    }, 200)
  }

  const onKeyUp = (e) => {
    if (!_pasteSwallow) return
    const k = (e.key || '').toLowerCase()
    // 配对的 V / Ctrl 抬起也要扣掉，否则远端会收到没按下过的 keyup
    if (k === 'v' || k === 'control' || k === 'meta') {
      e.stopPropagation()
      if (k === 'control' || k === 'meta') _pasteSwallow = false
    }
  }

  window.addEventListener('keydown', onKeyDown, true)
  window.addEventListener('keyup', onKeyUp, true)

  sinkEl.addEventListener('paste', async (e) => {
    e.preventDefault()   // 别插进 textarea，否则 input -> 再逐字键入一遍
    e.stopPropagation()
    if (_pasteTimer) { clearTimeout(_pasteTimer); _pasteTimer = 0 }
    let text = ''
    try {
      text = (e.clipboardData && e.clipboardData.getData('text')) || ''
    } catch {
      text = ''
    }
    // clipboardData 存在但为空 => 剪贴板本来就是空的，别去触发浏览器的读权限提示
    if (!text && !e.clipboardData) text = await readLocalClipboard()
    pushClipboardThenPaste(text)
  })
}

function b64ToText(b64) {
  try {
    const bin = atob(b64)
    const bytes = Uint8Array.from(bin, (c) => c.charCodeAt(0))
    return new TextDecoder().decode(bytes)
  } catch {
    return ''
  }
}

/**
 * 内嵌远程桌面（全屏 overlay）
 * 画面由 VigilServe Agent 采集（WGC/mss）→ 后端 hub 以 Guacamole 协议下发，
 * 不使用 Windows RDP。tunnel 走 /api/rdp/tunnel/{server_id}，
 * JWT 通过 WebSocket 子协议 `vigitoken.<jwt>` 传递（不进 URL）。
 */
export default function RemoteDesktop({ serverId, serverName, onClose, standalone = false }) {
  const stageRef = useRef(null)
  const clientRef = useRef(null)
  const keyboardRef = useRef(null)
  const mouseRef = useRef(null)
  const displayRef = useRef(null)
  const tunnelRef = useRef(null)
  const modeRef = useRef('fit')
  const syncsRef = useRef([])
  const framesRef = useRef(0)
  const closingRef = useRef(false)
  const autoRef = useRef(0)
  const startRef = useRef(0)
  // 「快捷键」下拉菜单的宿主节点：判断「点在外面」要关菜单
  const comboWrapRef = useRef(null)

  const [state, setState] = useState(5)
  const [errText, setErrText] = useState('')
  const [resText, setResText] = useState('-')
  const [fps, setFps] = useState(0)
  const [frames, setFrames] = useState(0)
  const [mode, setModeState] = useState('fit')
  const [attempt, setAttempt] = useState(0)
  const [rtt, setRtt] = useState(0)
  const [elapsed, setElapsed] = useState(0)
  const [quality, setQuality] = useState('medium')
  // 「快捷键」下拉菜单展开态：5 个组合键收进菜单而不是各占一个按钮
  //（2026-09-22 —— 工具栏要跟 6 个状态指标挤同一行，宽度吃紧）
  const [comboOpen, setComboOpen] = useState(false)

  // 角色权限：连接/断开、画质调整、组合键三个操作分别受控
  const { can } = usePerm()
  const canConnect = can('host', 'rdp', 'edit', 'connect')

  // 连接开关：打开页签默认「断开」态，不自动推流；由头部「连接 / 断开」按钮触发
  const [active, setActive] = useState(false)
  const connected = state === 3
  const busy = state === 1 || state === 4

  // 独立窗口：默认页签内嵌显示；点「全屏」弹出一个**独立的浏览器窗口**
  //（默认铺满屏幕，但可移动、可调整大小 —— 缩小或移开后能同时操作别的窗口）。
  // 不再用原生 requestFullscreen：那会独占整块屏幕，别的窗口一个都点不到。
  const rootRef = useRef(null)
  const winRef = useRef(null)
  const [popped, setPopped] = useState(false)

  const refit = useCallback(() => {
    const display = displayRef.current
    const stage = stageRef.current
    if (!display || !stage) return
    const w = display.getWidth()
    const h = display.getHeight()
    if (!w || !h) return
    const s = modeRef.current === 'full'
      ? 1
      : Math.min((stage.clientWidth - 16) / w, (stage.clientHeight - 16) / h)
    display.scale(Math.max(s, 0.05))
    setResText(`${w}×${h} @${Math.round(display.getScale() * 100)}%`)
  }, [])

  const setMode = useCallback((m) => {
    modeRef.current = m
    setModeState(m)
    refit()
  }, [refit])

  // 独立窗口 = 把 /rdp/<id> 这条路由开成一个新窗口。之所以走独立路由、而不是把内嵌
  // 面板 portal 到新文档：guac 画面、IME 输入槽、剪贴板桥接全是挂在 document /
  // window 上的，跨文档搬运每一处都要单独补一份；独立窗口自己有一份 document，
  // 这些能力天然可用，键盘 / 中文输入法 / 粘贴一行都不用改。
  useEffect(() => {
    if (!popped) return
    // 用户在窗口右上角点了关闭：按钮状态要跟着回到「未弹出」，下次点击才能重新开
    const id = setInterval(() => {
      const w = winRef.current
      if (!w || w.closed) {
        clearInterval(id)
        winRef.current = null
        setPopped(false)
      }
    }, 600)
    return () => clearInterval(id)
  }, [popped])

  // 独立窗口里这一页就是为了看远程桌面，进来直接连（没权限就保持断开，按钮会说明原因）
  const autoStartedRef = useRef(false)
  useEffect(() => {
    if (!standalone || !canConnect || autoStartedRef.current) return
    autoStartedRef.current = true
    setActive(true)
  }, [standalone, canConnect])

  // 独立窗口的标题栏写清是哪台主机（任务栏 / Alt+Tab 里才认得出）
  useEffect(() => {
    if (!standalone) return
    document.title = `VigilServe 远程桌面 - ${serverName || '#' + serverId}`
  }, [standalone, serverName, serverId])

  // Esc 必须挂在 **window 的捕获阶段** 并 stopPropagation：Guacamole 的键盘监听
  // 挂在 document 捕获阶段且比我们注册得早，挂 document 拦不住它 —— 菜单开着按 Esc
  useEffect(() => {
    if (!comboOpen) return
    const onDown = (e) => {
      const w = comboWrapRef.current
      if (w && !w.contains(e.target)) setComboOpen(false)
    }
    const onKey = (e) => {
      if (e.key !== 'Escape') return
      e.stopPropagation()
      setComboOpen(false)
    }
    document.addEventListener('mousedown', onDown, true)
    window.addEventListener('keydown', onKey, true)
    return () => {
      document.removeEventListener('mousedown', onDown, true)
      window.removeEventListener('keydown', onKey, true)
    }
  }, [comboOpen])

  useEffect(() => {
    const stage = stageRef.current
    if (!stage) return
    // 默认断开态：不建立 tunnel / 不推流，只把状态标为「已断开」
    if (!active) {
      setState(5)
      setErrText('')
      setFps(0)
      setFrames(0)
      return
    }
    closingRef.current = false
    const token = localStorage.getItem('token') || ''

    const proto = window.location.protocol === 'https:' ? 'wss' : 'ws'
    // 安全加固阶段 3：JWT 不再拼进 URL（会落到访问日志/Referer），改由子协议携带。
    window.__VS_WS_EXTRA_PROTOCOLS = token ? ['vigitoken.' + token] : []
    const tunnel = new Guacamole.WebSocketTunnel(
      `${proto}://${window.location.host}/api/rdp/tunnel/${serverId}`
    )
    tunnelRef.current = tunnel
    const client = new Guacamole.Client(tunnel)
    clientRef.current = client
    const display = client.getDisplay()
    displayRef.current = display
    const displayEl = display.getElement()
    displayEl.className = 'rdp-guac-display'
    stage.appendChild(displayEl)

    // IME 输入槽：必须挂进 DOM 才有组字目标（fixed 定位，无任何视觉影响）
    const sink = getImeSink()
    const sinkEl = sink.getElement()
    stage.appendChild(sinkEl)
    // 剪贴板桥接要用当前 tunnel 发指令；sink 是单例，这里只换 sender 不重复挂监听
    const sendClip = (...args) => {
      try { tunnel.sendMessage(...args) } catch { }
    }
    _clipSend = sendClip
    window.__VS_CLIP_READY = true
    // 点画面 / 工具栏之后焦点会跑到 canvas 或按钮上，输入法随即失去组字目标
    const rootEl = rootRef.current
    const refocus = () => sink.focus()
    rootEl?.addEventListener('mousedown', refocus)

    const onResize = () => refit()
    display.onresize = onResize
    window.addEventListener('resize', onResize)

    client.onstatechange = (s) => {
      setState(s)
      if (s === 3) {
        startRef.current = Date.now()
        autoRef.current = 0
        // 连上就把焦点交给输入槽，否则第一次敲拼音时还没有组字目标
        sink.focus()
      }
      if (s === 5 && !closingRef.current && autoRef.current < 3) {
        autoRef.current += 1
        setTimeout(() => setAttempt((a) => a + 1), 2000)
      }
    }
    client.onerror = (status) => {
      console.error('[rdp] error', status.code, status.message)
      setErrText(status.message || `错误码 ${status.code}`)
      setState(5)
    }
    client.onsync = () => {
      framesRef.current += 1
      setFrames(framesRef.current)
      syncsRef.current.push(performance.now())
      if (syncsRef.current.length > 120) syncsRef.current.shift()
    }

    // 被控端剪贴板 -> 本机。Agent 每 1.5s 轮询远端剪贴板，变化时推 clipboard_push
    // 只要 **blob / end 两条也发全** 就会走到 onend（少一条就永远收不到）。
    client.onclipboard = (stream, mimetype) => {
      if (mimetype && mimetype !== 'text/plain') return
      let acc = ''
      stream.onblob = (b64) => { acc += b64ToText(b64) }
      stream.onend = () => {
        if (!acc) return
        writeLocalClipboard(acc)
      }
    }

    const mouse = new Guacamole.Mouse(displayEl)
    mouseRef.current = mouse
    mouse.onEach(['mousedown', 'mousemove', 'mouseup'], (e) => {
      client.sendMouseState(e.state, true)
    })

    // 键盘：绑定在 document 上，收尾必须 disconnect
    const keyboard = new Guacamole.Keyboard(document)
    keyboardRef.current = keyboard
    keyboard.onkeydown = (keysym) => client.sendKeyEvent(1, keysym)
    keyboard.onkeyup = (keysym) => client.sendKeyEvent(0, keysym)

    client.connect('')

    const statTimer = setInterval(() => {
      const now = performance.now()
      const cut = now - 1000
      const arr = syncsRef.current
      while (arr.length && arr[0] < cut) arr.shift()
      setFps(arr.length)
      if (startRef.current) setElapsed(Math.round((Date.now() - startRef.current) / 1000))
    }, 1000)

    // 会话 RTT 每 5 秒拉一次（「帧」「在线」两个状态项已按需求删除，
    const sessTimer = setInterval(async () => {
      try {
        const r = await fetch(`/api/rdp/session/${serverId}`, {
          headers: { Authorization: `Bearer ${token}` },
        })
        const d = await r.json()
        if (d && !d.error) {
          setRtt(d.rtt_ms || 0)
        }
      } catch { }
    }, 5000)

    return () => {
      clearInterval(statTimer)
      clearInterval(sessTimer)
      window.removeEventListener('resize', onResize)
      rootEl?.removeEventListener('mousedown', refocus)
      if (_pasteTimer) { clearTimeout(_pasteTimer); _pasteTimer = 0 }
      _pasteSwallow = false
      _clipSend = null
      window.__VS_CLIP_READY = false
      if (sinkEl.parentNode === stage) stage.removeChild(sinkEl)
      const kb = keyboardRef.current
      if (kb) {
        kb.onkeydown = null
        kb.onkeyup = null
        if (typeof kb.disconnect === 'function') kb.disconnect()
        keyboardRef.current = null
      }
      if (clientRef.current) {
        try { clientRef.current.disconnect() } catch { }
        clientRef.current = null
      }
      if (displayEl && displayEl.parentNode) displayEl.parentNode.removeChild(displayEl)
      displayRef.current = null
      tunnelRef.current = null
    }
  }, [serverId, attempt, active, refit])

  const sendRaw = useCallback((...args) => {
    const t = tunnelRef.current
    if (!t) return false
    try {
      t.sendMessage(...args)
      return true
    } catch (e) {
      console.warn('[rdp] sendMessage failed', e)
      return false
    }
  }, [])

  const sendCombo = (name) => sendRaw('combo', name)

  const applyQuality = async (key) => {
    setQuality(key)
    const token = localStorage.getItem('token') || ''
    try {
      const r = await fetch(`/api/rdp/settings/${serverId}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        body: JSON.stringify({ preset: key }),
      })
      await r.json()
    } catch {
    }
  }

  /* 弹出独立窗口：/rdp/<id> 开成一个新窗口。
 * 尺寸默认给到屏幕可用大小（观感等同全屏），但**不锁死** —— 用户能拖边框缩放、
 * 能拖动窗口，缩下去或移开后就能同时操作别的窗口。 */
  const openPopupWindow = () => {
    const w = winRef.current
    if (w && !w.closed) {
      w.focus()
      return
    }
    const s = window.screen
    const feats = [
      'popup=yes',
      `width=${s.availWidth}`,
      `height=${s.availHeight}`,
      'left=0',
      'top=0',
      'resizable=yes',
      'scrollbars=no',
      'toolbar=no',
      'menubar=no',
      'location=no',
      'status=no',
    ].join(',')
    const url = `/rdp/${serverId}?name=${encodeURIComponent(serverName || '')}`
    // 必须在用户手势的同一个 tick 里发起，否则会被当成脚本弹窗拦掉
    const nw = window.open(url, `vs_rdp_${serverId}`, feats)
    if (!nw) {
      setErrText('浏览器拦截了弹出窗口，请允许本站弹出窗口后重试')
      return
    }
    winRef.current = nw
    setPopped(true)
    nw.focus()

    // 画面已经搬到独立窗口了，页签里这路就没人看 —— 主动断开，别让同一台主机
    // closingRef 必须置 true：那是「主动断开」的标记，
    // 不置的话 onstatechange 会把它当成意外掉线，2 秒后自动重连最多 3 次。
    // 关掉独立窗口后想回页签里看，再点一次「连接」即可。
    if (active) {
      closingRef.current = true
      setActive(false)
    }
  }

  const handleToggle = useCallback(() => {
    if (connected) {
      // 主动断开：标记关闭，effect 清理后回到「已断开」态，不再自动重连
      closingRef.current = true
      setActive(false)
    } else if (!busy) {
      setActive(true)
    }
  }, [connected, busy])

  const stateLabel = STATE_TEXT[state] || String(state)
  const stateClass =
    state === 3 ? 'ok' : state === 4 || state === 5 || errText ? 'err' : 'warn'
  const mmss = `${String(Math.floor(elapsed / 60)).padStart(2, '0')}:${String(elapsed % 60).padStart(2, '0')}`

  return (
    <div
      className={`rdp-panel${standalone ? ' rdp-standalone' : ''}`}
      ref={rootRef}
      role="region"
      aria-label="远程桌面"
    >
      {/* 单行工具栏（2026-09-22 合并）：左边依次是品牌 / 主机名 / 状态指标，
 右边是全部操作按钮 + 连接开关。原先拆成两行（上行状态、下行按钮），
 状态被推到最右、按钮被挤到第二行；现在状态紧跟主机名（左移），
 按钮组整体靠右，两行并成一行。
 窄屏放不下时仍是 flex-wrap 换行，不出现横向滚动。 */}
      <header className="rdp-header">
        <span className="rdp-brand"><b>VigilServe</b> 远程桌面</span>
        <span className="rdp-target">{serverName || `#${serverId}`}</span>
        <span className="rdp-status">
          <span className="rdp-chip">
            状态 <b className={`rdp-state rdp-state-${stateClass}`}>{errText ? '错误' : stateLabel}</b>
          </span>
          <span className="rdp-chip">分辨率 <b>{resText}</b></span>
          <span className="rdp-chip">FPS <b>{fps}</b></span>
          <span className="rdp-chip">延迟 <b>{rtt}ms</b></span>
          <span className="rdp-chip">时长 <b>{mmss}</b></span>
          <span className="rdp-chip">协议 <b>Guacamole</b></span>
        </span>
        <span className="rdp-spacer" />
        <button
          className="rdp-btn"
          aria-pressed={mode === 'fit'}
          onClick={() => setMode('fit')}
        >适应窗口</button>
        <button
          className="rdp-btn"
          aria-pressed={mode === 'full'}
          onClick={() => setMode('full')}
        >1:1</button>
        {/* 独立窗口里本来就已经是独立窗口了，不用再给「全屏」 */}
        {!standalone && (
          <button
            className="rdp-btn"
            aria-pressed={popped}
            title={popped
              ? '独立窗口已打开，点击把它置顶'
              : '在独立窗口中打开（默认铺满屏幕，可移动、可调整大小）；页签内这一路会自动断开'}
            onClick={openPopupWindow}
          >全屏</button>
        )}
        {/* 「快捷键」下拉菜单（2026-09-22）：5 个组合键收进来，不再各占一个按钮 ——
 它们叠在一起要截获约 330px，是工具栏并成一行后最宽的一块。 */}
        <span className="rdp-combo" ref={comboWrapRef}>
          <button
            className="rdp-btn"
            aria-haspopup="menu"
            aria-expanded={comboOpen}
            title="常用组合键：任务管理器 / Ctrl+Alt+Del / Alt+Tab / 开始菜单 / 锁定"
            onClick={() => setComboOpen((v) => !v)}
          >快捷键<span className="rdp-caret"><Icon kind="ui-chevron-down" size={10} /></span></button>
          {comboOpen && (
            <span className="rdp-menu" role="menu">
              {COMBOS.map((c) => (
                <button
                  key={c.name}
                  className="rdp-menu-item"
                  role="menuitem"
                  title={c.title || c.label}
                  onClick={() => { setComboOpen(false); sendCombo(c.name) }}
                >{c.label}</button>
              ))}
            </span>
          )}
        </span>
        <span className="rdp-sep" />
        {QUALITY.map((q) => (
          <button
            key={q.key}
            className="rdp-btn"
            aria-pressed={quality === q.key}
            onClick={() => applyQuality(q.key)}
          >{q.label}</button>
        ))}
        <button
          className={connected ? 'rdp-disconnect' : 'rdp-connect'}
          onClick={handleToggle}
          disabled={busy || !canConnect}
          title={canConnect ? (connected ? '断开远程桌面' : '连接远程桌面') : '当前角色没有远程桌面的连接权限'}
        >{connected ? '断开' : (busy ? '连接中…' : '连接')}</button>
      </header>

      <div className="rdp-stage" ref={stageRef}>
        {!connected && !busy && !errText && (
          <div className="rdp-waiting">
            远程桌面未连接
            <span>点击右上角「连接」开始远程桌面</span>
          </div>
        )}
        {state === 3 && frames <= 1 && fps === 0 && !errText && (
          <div className="rdp-waiting">
            等待被控端画面…
            <span>
              长时间无画面 = 该主机的 Agent 未推流（旧版 Agent 不支持远程桌面，需升级）
            </span>
          </div>
        )}
        {errText && <div className="rdp-error">{errText}</div>}
      </div>

    </div>
  )
}
