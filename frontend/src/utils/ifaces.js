/* 端口表里"哪些口算虚拟 / 管理口"的判定 —— 端口表和「端口健康」卡片共用同一套规则，
 * 别在两个组件里各写一份（2026-09-21）。
 *
 * **只认 ifType 是不够的**：NAS 上那 6 个 docker 网桥的 ifType 是 6
 * （ethernetCsmacd），跟物理口 eth0 一模一样；华为的管理口 MEth0/0/1 同样是 6。
 * 所以"类型规则"和"名字规则"两套一起上，谁命中都算虚拟口。
 *
 * 类型（IF-MIB ifType）：
 * 1 other —— 华为的 NULL0 / Console9/0/0
 * 24 softwareLoopback —— lo / InLoopBack0
 * 53 propVirtual —— Vlanif
 * 131 tunnel —— sit0
 * 名字：lo / sit / docker / br- / veth / virbr / dummy / ifb / tunl / gre / ip6tnl /
 * MEth / Vlanif / InLoopBack / NULL / Console / Aux / Loopback / Vlan / Tunnel / BVI / NVI
 *
 * 聚合口（Eth-Trunk / Port-channel / Bridge-Aggregation）**不隐藏**：它们是真业务口，
 * 而且 ifType 通常是 161（ieee8023adLag），本来也进不了上面的集合。 */

const VIRTUAL_IF_TYPES = new Set(['1', '24', '53', '131'])

const VIRTUAL_IF_NAME_RE =
  /^(lo|sit|docker|br-|veth|virbr|dummy|ifb|tunl|gre|ip6tnl|nflog|nfqueue|meth|vlanif|inloopback|null|console|aux|loopback|vlan|tunnel|bvi|nvi)/i

export function isVirtualIface(i) {
  if (!i) return false
  if (VIRTUAL_IF_TYPES.has(String(i.if_type || '').trim())) return true
  return VIRTUAL_IF_NAME_RE.test(String(i.if_name || i.if_descr || '').trim())
}

/* 端口名：优先 if_name，没有就退回 if{index} —— 和端口表里的显示保持一致 */
export function ifaceName(i) {
  if (!i) return ''
  return i.if_name || `if${i.if_index}`
}

export function periodLabel(sec) {
  const p = Number(sec) || 0
  if (!p) return ''
  if (p % 3600 === 0) return `${p / 3600} 小时`
  if (p % 60 === 0) return `${p / 60} 分钟`
  return `${p} 秒`
}
