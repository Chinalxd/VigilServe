/**
 * 🚨 服务端时间统一解析入口（2026-09-23）。
 *
 * 后端所有时间列都存 **naive UTC**（`datetime.now(timezone.utc).replace(tzinfo=None)`），
 * 序列化出来是 `"2026-09-23T11:58:10.233691"` —— **没有 Z、没有时区偏移**。
 * 而 JS 对"没有时区标记"的时间串是按**浏览器本地时间**解析的，再配
 * `getHours()` 这类本地时区 getter 取值，结果就比真实时间**慢整整一个时区**
 * （本机 UTC+8 → 慢 8 小时）。实测：
 *     new Date('2026-09-23T11:58:10')        → 11:58  ✗
 *     new Date('2026-09-23T11:58:10Z')       → 19:58  ✓
 *
 * 所以凡是**来自服务端**的时间戳，都必须先过这个函数：没有时区标记的一律补 `Z`
 * 按 UTC 解析。之后 `getHours()` 等本地 getter 才会给出正确的本地时间。
 *
 * ⚠ 别在组件里直接 `new Date(serverTs)` —— 那正是这个 bug 的来源。
 *   也别只改一处：所有页面必须走同一份口径，否则不同页面的时间会互相矛盾。
 *
 * @returns {Date|null} 解析失败返回 null
 */
export function parseServerTime(ts) {
  if (ts == null || ts === '') return null
  if (ts instanceof Date) return isNaN(ts.getTime()) ? null : ts
  if (typeof ts === 'number') {
    const dn = new Date(ts)
    return isNaN(dn.getTime()) ? null : dn
  }
  let s = String(ts).trim()
  if (!s) return null
  // 已经带时区标记（Z 或 ±HH:mm / ±HHmm）→ 按原样解析，不要画蛇添足
  const hasZone = /(?:Z|[+-]\d{2}:?\d{2})$/i.test(s)
  if (!hasZone) {
    s = s.replace(' ', 'T')
    if (!/\.\d+$/.test(s) && /T\d{2}:\d{2}$/.test(s)) s += ':00'
    if (!s.endsWith('Z')) s += 'Z'
  }
  const d = new Date(s)
  return isNaN(d.getTime()) ? null : d
}

/**
 * Format a timestamp to the project standard datetime string:
 * YYYY-MM-DD HH:mm:ss
 */
export function formatDateTime(ts) {
  if (!ts) return '--'
  const d = parseServerTime(ts)
  if (!d) return String(ts)
  const pad = (n) => String(n).padStart(2, '0')
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`
}

/**
 * Format a timestamp to a short datetime string (same standard).
 * Kept as an alias for consistency where components previously used
 * `formatDateTimeShort`.
 */
export function formatDateTimeShort(ts) {
  return formatDateTime(ts)
}

export function localDate(dt) {
  const pad = (n) => String(n).padStart(2, '0')
  return `${dt.getFullYear()}-${pad(dt.getMonth() + 1)}-${pad(dt.getDate())}`
}

export function localDateTime(dt) {
  const pad = (n) => String(n).padStart(2, '0')
  return `${dt.getFullYear()}-${pad(dt.getMonth() + 1)}-${pad(dt.getDate())}T${pad(dt.getHours())}:${pad(dt.getMinutes())}`
}

export function dateToStartISO(dateStr) {
  return new Date(`${dateStr}T00:00:00`).toISOString()
}

export function dateToEndISO(dateStr) {
  return new Date(`${dateStr}T23:59:59.999`).toISOString()
}
