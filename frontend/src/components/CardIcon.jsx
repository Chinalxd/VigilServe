/* 「统计小卡片」左侧的图标（2026-09-21 抽成共享模块）
 *
 * 为什么抽出来：主机「设备状态」和网络设备「设备状态」是两套组件
 * （`ServerDetail.jsx` 的 `MetricCard` / `NetworkDeviceStatus.jsx` 的 `MetricBox`），
 * 但两边的小卡片长得应该一样 —— 网络设备那边先做了图标，主机那边要"加同一套"。
 * 如果各写一份样式，两边迟早会漂移（一边 22px 一边 26px、线宽一个 1.6 一个 1.8）。
 *
 * 2026-09-22：**图形本体已收编到 `AppIcon.jsx`（`card-*` 那 11 个）**，
 * 这里只剩三件事：用哪个图形、多大、什么灰。这样全站图标只有一份几何、一个外壳
 * （16 网格 / 描边 1.3 / currentColor），不会再出现"卡片图标自成一套"。
 *
 * 图标**不承载状态**：颜色一律同灰（见 `CardIcon.css`），状态仍由右侧数值的颜色表达。 */
import Icon from './AppIcon'
import './CardIcon.css'

/* 图标尺寸：两侧共用同一个值。
 2026-09-21 从 22 调到 28 —— 用户反馈"左侧图标加大些"。
 只改这一个常量，两个页面同步生效。 */
export const CARD_ICON_SIZE = 28

/* 允许的名字（= `AppIcon.jsx` 里 `card-*` 的后半段）。
 不认识的 key 返回 null（宁可不渲染，也别摆个兜底图形出去 —— 那是无声的错误）。 */
const CARD_ICON_NAMES = [
  'cpu', 'memory', 'in', 'out', 'port',
  'latency', 'temp', 'power', 'fan', 'storage', 'disk',
]

/* 渲染一张小卡片左侧的图标。
 *
 * @param name 取值见 `CARD_ICON_NAMES`
 * @param size 像素边长，默认 `CARD_ICON_SIZE`
 * @param className 页面自己的定位类（主机侧 `.mcard-icon` / 网络设备侧 `.nds-card-icon`），
 * 两者都只负责"摆在哪、什么颜色" */
export default function CardIcon({ name, size = CARD_ICON_SIZE, className = '' }) {
  if (!CARD_ICON_NAMES.includes(name)) return null
  return (
    <span
      className={['stat-card-icon', className].filter(Boolean).join(' ')}
      aria-hidden="true"
    >
      <Icon kind={`card-${name}`} size={size} />
    </span>
  )
}
