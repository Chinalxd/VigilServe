import { authHeaders } from './auth'

/* 口令组成规则提示（「系统设置 - 安全设置 - 密码规则」是唯一真源）。
 *
 * 规则文案由后端拼（`services/security_policy.describe_password_rules`），前端只负责显示
 * —— 提示和实际拦截读的是同一份 policy，管理员改了规则提示立刻跟着变。前端写死一句
 * "至少 8 位含大小写数字"看着也能用，但规则一改提示就成假的：用户照着提示输还是过不去，
 * 比没有提示更糟。
 *
 * 统一走这里还顺带解决两件事：
 * 1. 请求只发一次（结果缓存在模块级），改密窗口 / 用户管理反复打开都不重复打接口；
 * 2. 接口不可用时退化到下面这句兜底文案，**不会**把提示显示成空白。 */

const FALLBACK_HINT = '长度至少 8 位，且必须包含大写字母、小写字母、数字'

let _cached = null
let _inflight = null

export async function loadPasswordHint() {
  if (_cached) return _cached
  if (_inflight) return _inflight
  _inflight = fetch('/api/security/password-rules', { headers: authHeaders() })
    .then((res) => (res.ok ? res.json() : null))
    .then((data) => {
      const hint = (data && data.hint) || ''
      _cached = hint || FALLBACK_HINT
      return _cached
    })
    .catch(() => FALLBACK_HINT)
    .finally(() => { _inflight = null })
  return _inflight
}

/** 管理员改了安全设置后要刷新缓存，否则界面还显示旧规则。 */
export function invalidatePasswordHint() {
  _cached = null
}

export { FALLBACK_HINT }
