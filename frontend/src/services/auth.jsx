import { createContext, useContext, useState, useEffect, useCallback, useRef } from 'react'

export const AuthContext = createContext(null)

const API = '/api'

/**
 * 会话复核周期。同一账号只允许一个在线：账号在第二台电脑登录后，
 * 第一台靠这个轮询发现自己的 token 已被顶掉，然后明确提示并退回登录页。
 */
const SESSION_POLL_MS = 20000

/**
 * 把「请求压根没送到后端」的异常翻译成能照着排查的话。
 *
 * fetch 只有在连接层就失败时才 reject（服务端毫无感知），浏览器给的是原生
 * TypeError("Failed to fetch") —— 没有状态码、没有响应体、没有任何服务端
 * 上下文。以前被 LoginPage 直接 `e.message` 印出来，用户只能看到一个英文串，
 * 既不知道连的是哪个地址，也不知道下一步该干嘛。
 *
 * 全新部署/换机部署后最常见的四种成因都写进文案里，并把实际请求的 URL 摆出来
 * ——「看着 8001 却连的是 8009」这类错，只有把地址写出来用户才会自己发现。
 */
function describeNetworkFailure(e) {
  const raw = String((e && e.message) || e || '')
  const target = `${location.protocol}//${location.host}${API}/auth/login`
  if (/abort/i.test(raw)) {
    return `登录请求被中断（${raw}）。通常是后端正在重启，稍等几秒再试一次。`
  }
  return [
    '连不上服务端：请求没能送到后端，这一步和账号密码无关。',
    `实际请求地址：${target}`,
    '请依次确认：① 后端已启动（托盘控制台看「服务状态」）；② 地址用的是 https:// 而不是 http://；'
      + '③ 自签证书已被本机信任（浏览器先在地址栏手动信任一次再回来登录）；'
      + '④ 公司代理或安全软件没有拦这个端口。',
    '仍不行请按 F12 → Network，重新点一次登录，看 login 这条的状态码与失败原因。',
  ].join('\n')
}

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null)
  const [loading, setLoading] = useState(true)
  // 侧边栏「在线状态」：服务端确认会话有效才算在线
  const [online, setOnline] = useState(false)
  const kickedRef = useRef(false)
  // 被顶下线时登录页要显示的提示文案。只存一句话，**不存账号名和登录 IP**
  const [kickedInfo, setKickedInfo] = useState(null)

  const checkSession = useCallback(async () => {
    try {
      const token = localStorage.getItem('token')
      if (!token) {
        setUser(null)
        setOnline(false)
        return
      }
      const res = await fetch(`${API}/auth/session`, {
        headers: { Authorization: `Bearer ${token}` },
      })
      const data = await res.json()
      if (data.authenticated) {
        setUser({
          username: data.username, full_name: data.full_name || '', role: data.role,
          role_id: data.role_id, role_name: data.role_name || '',
          is_admin: Boolean(data.is_admin), status: data.status,
          // 2026-09-23 开源加固 ②：服务端已据此拒绝除改密外的一切请求，
          // 前端也要据此弹"必须先改密"的框 —— 否则用户会看到一堆 403 却不知道为什么。
          must_reset_password: Boolean(data.must_reset_password),
        })
        setOnline(true)
      } else {
        localStorage.removeItem('token')
        setUser(null)
        setOnline(false)
        // 被其他设备顶下线：给出明确提示，而不是让用户觉得"莫名其妙掉线"
        if (data.reason === 'replaced' && !kickedRef.current) {
          kickedRef.current = true
          // 只在登录按钮下方显示文字提示（LoginPage 渲染），**不再弹右侧 toast**：
          // 两次提示重复，且 toast 会在几秒后消失、用户容易错过。
          setKickedInfo(data.message || '该账号已在其他设备登录，当前会话已下线')
        }
      }
    } catch (e) {
      // 网络抖动或后端重启时不要误判成掉线，保持当前状态
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { checkSession() }, [checkSession])

  // 仅依赖用户名：轮询刷新 user 对象不会反复重建定时器
  useEffect(() => {
    if (!user?.username) return undefined
    const timer = setInterval(checkSession, SESSION_POLL_MS)
    return () => clearInterval(timer)
  }, [user?.username, checkSession])

  const login = async (username, password) => {
    let res
    try {
      res = await fetch(`${API}/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password }),
      })
    } catch (e) {
      // 只有连接层失败才会到这里（后端没起来 / 证书没信任 / 端口不对 / 被代理拦）。
      // 有响应的错误都在下面按 res.ok 处理，服务端返回的 detail 更能说明问题。
      throw new Error(describeNetworkFailure(e))
    }
    if (!res.ok) {
      const err = await res.json().catch(() => ({}))
      throw new Error(err.detail || '登录失败')
    }
    const data = await res.json()
    // ⚠ 已知取舍（第二轮复查 R-6）：令牌存 localStorage，同源 JS 都能读到 ——
    // 一旦出现 XSS，会话就会被完整劫走，且服务端无法吊销。
    // 后台目前只发 Bearer 令牌、不下发 httpOnly Cookie，所以短期内没有更安全的
    // 存放位置；换 httpOnly + SameSite Cookie 要改整条鉴权链路（含 8009 独立源
    // 代理那一路），属于另一次改造。**在此期间靠两件事兜底**：
    //   ② 会话有时长上限（服务端「安全设置 - 登录超时」，默认 24h 绝对时长），
    localStorage.setItem('token', data.token)
    kickedRef.current = false
    setKickedInfo(null)
    setUser({
      username: data.username, full_name: data.full_name || '', role: data.role,
      role_id: data.role_id, role_name: data.role_name || '',
      is_admin: Boolean(data.is_admin), status: data.status,
      must_reset_password: Boolean(data.must_reset_password),
    })
    setOnline(true)
    return data
  }

  const logout = () => {
    const token = localStorage.getItem('token')
    // 2026-09-22 P1-3：退出前先通知服务端作废会话。
    // 这条会话仍然有效，token 一旦泄露，用户"退出"之后照样能用。
    // 这里刻意**不改成 async**：调用方（侧边栏/顶栏的 onClick）都是同步调用，
    // 改成 async 会改变返回约定；用 fire-and-forget 的 fetch 即可，
    // 请求失败也不影响本地退出（本地清了本地的，服务端那条最多等自然过期）。
    if (token) {
      fetch(`${API}/auth/logout`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${token}` },
        keepalive: true,
      }).catch(() => {})
    }
    localStorage.removeItem('token')
    setUser(null)
    setOnline(false)
    kickedRef.current = false
    // 主动退出不是"被顶下线"，登录页不该再显示那句提示
    setKickedInfo(null)
  }

  // 以服务端下发的 is_admin 为准（角色可自定义，不能再靠 role 字符串判断）
  const isAdmin = Boolean(user?.is_admin) || user?.role === 'admin'

  return (
    <AuthContext.Provider value={{ user, loading, login, logout, isAdmin, checkSession, online, kickedInfo }}>
      {children}
    </AuthContext.Provider>
  )
}

export function useAuth() {
  return useContext(AuthContext)
}

export function authHeaders() {
  const token = localStorage.getItem('token')
  return token ? { Authorization: `Bearer ${token}` } : {}
}
