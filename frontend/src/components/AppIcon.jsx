/**
 * 全站图标（2026-09-22）：主机 + 网络设备 + 菜单 + 通用 UI 图标。
 *
 * 背景：原来各处用 emoji / 符号当图标（🪟 🖥️ 📊 📋 📜 ⚙️ 🔒 👤 👁️ 🙈 ⚠ ✅ ✕ ▲▼▶ ▾ ⋮ ⇅），
 * 三个硬伤：
 *   1. emoji 字形由**系统字体**决定，Win10 / Win11 / 不同浏览器里长得都不一样，
 *      同一个列表里还会混着彩色和灰白；
 *   2. 颜色不跟主题走（深色侧边栏上忽明忽暗，选中态不会跟着变亮，告警红/危险红也用不上）；
 *   3. 分辨不出东西：Windows Server 也是 🪟，NAS / 交换机 / 防火墙全是同一个 🖥️。
 *
 * 现在全部换成自绘图标，两条原则：
 *   A. **统一风格**：同一个外壳（16×16 / 描边 1.3 / 圆头圆角 / `currentColor`），
 *      尺寸、粗细、颜色只在一处写，改不了歪；
 *   B. **图案用各家官方 logo 的原形状**（Windows 斜切四格旗、Ubuntu 圆环三点、苹果…），
 *      Linux 没有官方 logo，用企鹅 Tux（公认的 Linux 吉祥物）；
 *      网络设备没有 logo，用行业通行画法（交换机=双向箭头、防火墙=砖墙…）；
 *      通用 UI 用最通行的形状（锁 / 人 / 眼 / 三角警告 / 对勾 / X / 尖角 / 竖三点）。
 *
 * 三组图形一个文件，但**颜色一律 currentColor** ——
 * 告警三角放在红色文字里就是红的，放在灰文字里就是灰的，不用给图标单独配色。
 *
 * 加图标三个动作：往 `ICON_BODIES` / `NAV_BODIES` / `UI_BODIES` 加一条
 * → 补 `ICON_LABELS` → 跑 `gen_device_icons_sheet.mjs` 重出图标表 + 基准 JSON。
 */

/**
 * 所有图形共用的画布外壳。少一个地方写分布就不会出现"某个图标比别的粗一点"。
 * size 直接给 width/height（viewBox 恒为 16，所以描边粗细会跟着等比放大，
 * 32px 的锁比 12px 的尖角粗一点是正常的，和主流图标集一致）。
 */
function IconFrame({ children, size = 16 }) {
  return (
    <svg
      className="device-icon"
      viewBox="0 0 16 16"
      width={size}
      height={size}
      fill="none"
      stroke="currentColor"
      strokeWidth="1.3"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      focusable="false"
    >
      {children}
    </svg>
  )
}

/**
 * Microsoft Windows 官方旗（微软的招牌四格）。
 * 关键点：四格不是正矩形 —— **左边矮、右边高**（斜切透视），
 * 左下角收上去、右下角落下来，这是 Windows logo 最好认的特征，
 * 画成四个正矩形就变成"九宫格"了。
 * 官方 logo 本身就是实心块面，所以这里 `fill` 实心、`stroke` 关掉。
 * s / dx / dy 用来在「服务器版」里缩放复用同一面旗。
 */
function WindowsFlag({ s = 1, dx = 0, dy = 0 }) {
  return (
    <g transform={`translate(${dx} ${dy}) scale(${s})`} fill="currentColor" stroke="none">
      <path d="M1.6 3.1 L7.4 2.2 L7.4 7.6 L1.6 7.6 Z" />
      <path d="M8.6 1.8 L14.4 1.8 L14.4 7.6 L8.6 7.6 Z" />
      <path d="M1.6 8.8 L7.4 8.8 L7.4 13.4 L1.6 12.5 Z" />
      <path d="M8.6 8.8 L14.4 8.8 L14.4 14.2 L8.6 13.3 Z" />
    </g>
  )
}

const ICON_BODIES = {
  'host-windows': <WindowsFlag />,

  // 服务器版 = 官方旗（放大到 62%）+ 下方一条 1U 机架（带电源灯和风栅）
  // 🚨 别把旗缩到机箱里：16px 下缩进机箱的那面旗就是 4 个灰点，等于没画。
  'host-windows-server': (
    <>
      <WindowsFlag s={0.62} dx={3.04} dy={0.58} />
      <rect x="2.2" y="10.4" width="11.6" height="3.4" rx="0.8" />
      <circle cx="3.6" cy="12.1" r="0.5" fill="currentColor" stroke="none" />
      <path d="M5.4 12.1h6.8" />
    </>
  ),

  // Ubuntu 官方「朋友之环」：一圈 + 环上三个实心点 + 三条向心的短辐条
  'host-ubuntu': (
    <>
      <circle cx="8" cy="8" r="4.6" />
      <g fill="currentColor" stroke="none">
        <circle cx="8" cy="3.4" r="1.1" />
        <circle cx="4.02" cy="10.3" r="1.1" />
        <circle cx="11.98" cy="10.3" r="1.1" />
      </g>
      <path d="M8 4.7v1.4M5.2 9.7l1.2-.7M10.8 9.7l-1.2-.7" />
    </>
  ),

  'host-macos': (
    <>
      <path d="M8.1 5.35c-.65-.95-1.5-1.45-2.4-1.45-1.6 0-2.85 1.45-2.85 3.6 0 2.75 1.65 5.35 3.25 5.35.6 0 1.05-.28 1.5-.62.3-.23.5-.35.75-.35s.45.12.75.35c.45.34.9.62 1.5.62 1.6 0 3.25-2.6 3.25-5.35 0-2.15-1.25-3.6-2.85-3.6-.9 0-1.75.5-2.4 1.45z" />
      <path d="M8.25 3.45c.1-.95.85-1.7 1.8-1.8.1.95-.85 1.9-1.8 1.8z" />
    </>
  ),

  // 其他 Linux / 国产发行版：企鹅 Tux（Linux 公认吉祥物；Linux 本身没有官方 logo）
  // 用 fill-rule="evenodd" 把两只眼睛掏空 —— 单色图里只有这样才看得出是企鹅不是黑团。
  'host-linux': (
    <>
      <path fill="currentColor" stroke="none" fillRule="evenodd" d="M8 1.9c1.8 0 3.1 1.4 3.1 3.2 0 .8.5 1.3 1.3 1.9 1 .8 1.6 1.9 1.6 3.1v1.1c0 .85-.55 1.4-1.35 1.4H3.35c-.8 0-1.35-.55-1.35-1.4v-1.1c0-1.2.6-2.3 1.6-3.1.8-.6 1.3-1.1 1.3-1.9C4.9 3.3 6.2 1.9 8 1.9zm-1.9 3.7a.72.72 0 1 0 0 1.44.72.72 0 0 0 0-1.44zm3.8 0a.72.72 0 1 0 0 1.44.72.72 0 0 0 0-1.44z" />
      <path d="M6.0 12.5l-.9 1.5h1.8l.35-.9M10.0 12.5l.9 1.5h-1.8l-.35-.9" />
    </>
  ),

  // 系统还没采集到 / 认不出来：中性显示器（不带任何 logo，免得误报成 Windows）
  'host-generic': (
    <>
      <rect x="1.7" y="2.7" width="12.6" height="8.6" rx="1.1" />
      <path d="M8 11.3v2.4M6.1 13.9h3.8" />
      <path d="M5.6 6.9h4.8" />
    </>
  ),

  'net-switch': (
    <>
      <rect x="1.6" y="4.9" width="12.8" height="6.2" rx="1.2" />
      <path d="M4.4 6.6h5.4M8.2 5.2l1.6 1.4-1.6 1.4" />
      <path d="M11.6 9.4H6.2M7.8 8l-1.6 1.4 1.6 1.4" />
    </>
  ),
  'net-router': (
    <>
      <rect x="1.6" y="9" width="12.8" height="4.6" rx="2.3" />
      <path d="M4.4 9V6.4M3.5 7.3l.9-.9.9.9" />
      <path d="M8 9V5.2M7.1 6.1L8 5.2l.9.9" />
      <path d="M11.6 9V6.4M10.7 7.3l.9-.9.9.9" />
    </>
  ),
  'net-firewall': (
    <>
      <rect x="1.8" y="3.2" width="12.4" height="9.6" rx="1" />
      <path d="M1.8 6.4h12.4M1.8 9.6h12.4" />
      <path d="M6 3.2v3.2M10 3.2v3.2" />
      <path d="M4 6.4v3.2M8 6.4v3.2M12 6.4v3.2" />
      <path d="M6 9.6v3.2M10 9.6v3.2" />
    </>
  ),
  'net-ap': (
    <>
      <rect x="5.4" y="10.6" width="5.2" height="3.2" rx="0.9" />
      <path d="M6.4 8.3a2.3 2.3 0 0 1 3.2 0" />
      <path d="M4.9 6.5a4.4 4.4 0 0 1 6.2 0" />
      <path d="M3.4 4.7a6.5 6.5 0 0 1 9.2 0" />
    </>
  ),
  'net-nas': (
    <>
      <rect x="3.2" y="1.9" width="9.6" height="12.2" rx="1.1" />
      <path d="M3.2 6h9.6M3.2 10.1h9.6" />
      <g fill="currentColor" stroke="none">
        <circle cx="5.2" cy="3.95" r="0.5" />
        <circle cx="5.2" cy="8.05" r="0.5" />
        <circle cx="5.2" cy="12.15" r="0.5" />
      </g>
      <path d="M7.4 3.95h3.2M7.4 8.05h3.2M7.4 12.15h3.2" />
    </>
  ),
  'net-server': (
    <>
      <rect x="1.8" y="5.8" width="12.4" height="6.4" rx="1" />
      <path d="M8.2 5.8v6.4M11.3 5.8v6.4" />
      <g fill="currentColor" stroke="none">
        <circle cx="4.1" cy="7.7" r="0.5" />
        <circle cx="4.1" cy="10.3" r="0.5" />
      </g>
      <path d="M5.9 7.7h1.3M5.9 10.3h1.3" />
    </>
  ),
  'net-generic': (
    <>
      <rect x="2.4" y="2.4" width="11.2" height="11.2" rx="2" />
      <path d="M6.4 6.6a1.6 1.6 0 1 1 2.2 1.5c-.45.17-.6.5-.6.95v.35" />
      <circle cx="8" cy="11.2" r="0.6" fill="currentColor" stroke="none" />
    </>
  ),
}

const NAV_BODIES = {
  'nav-dashboard': <path d="M2.4 13.2h11.2M4.8 13.2V8.6M8 13.2V5.6M11.2 13.2V3.2" />,
  'nav-devices': (
    <>
      <rect x="3.2" y="3.4" width="9.6" height="9.8" rx="1.1" />
      <rect x="6.2" y="2.0" width="3.6" height="2.2" rx="0.5" />
      <path d="M5.8 6.6h4.4M5.8 8.7h4.4M5.8 10.8h3.0" />
    </>
  ),
  'nav-logs': (
    <>
      <path d="M3.9 3.6a1 1 0 0 1 1-1h4.4l3.8 3.8v6.2a1 1 0 0 1-1 1H4.9a1 1 0 0 1-1-1z" />
      <path d="M9.3 2.6v3.2h3.2" />
      <path d="M6.2 8.6h3.6M6.2 10.8h3.6" />
    </>
  ),
  // 齿轮：8 齿，齿顶 R=6.6 / 齿根 r=5.2（坐标是算出来的，别手改小数点）
  'nav-settings': (
    <>
      <path d="M14.5 7.0 L14.6 8.0 L14.5 9.0 L13.0 9.4 L12.8 10.0 L12.5 10.5 L13.3 11.9 L12.7 12.7 L11.9 13.3 L10.5 12.5 L10.0 12.8 L9.4 13.0 L9.0 14.5 L8.0 14.6 L7.0 14.5 L6.6 13.0 L6.0 12.8 L5.5 12.5 L4.1 13.3 L3.3 12.7 L2.7 11.9 L3.5 10.5 L3.2 10.0 L3.0 9.4 L1.5 9.0 L1.4 8.0 L1.5 7.0 L3.0 6.6 L3.2 6.0 L3.5 5.5 L2.7 4.1 L3.3 3.3 L4.1 2.7 L5.5 3.5 L6.0 3.2 L6.6 3.0 L7.0 1.5 L8.0 1.4 L9.0 1.5 L9.4 3.0 L10.0 3.2 L10.5 3.5 L11.9 2.7 L12.7 3.3 L13.3 4.1 L12.5 5.5 L12.8 6.0 L13.0 6.6 L14.5 7.0 Z" />
      <circle cx="8" cy="8" r="2.2" />
    </>
  ),
}

/** 通用 UI 图标（原来散落各处的 🔒 👤 👁️ 🙈 ⚠ ✅ ✕ ▲▼▶ ▾ ⋮ ⇅） */
const UI_BODIES = {
  'ui-lock': (
    <>
      <rect x="3.2" y="7.2" width="9.6" height="6.6" rx="1.2" />
      <path d="M5.4 7.2V5.2a2.6 2.6 0 0 1 5.2 0v2" />
    </>
  ),
  'ui-user': (
    <>
      <circle cx="8" cy="5.6" r="2.6" />
      <path d="M2.8 13.6c0-2.7 2.3-4.6 5.2-4.6s5.2 1.9 5.2 4.6" />
    </>
  ),
  'ui-eye': (
    <>
      <path d="M1.6 8s2.6-4.2 6.4-4.2S14.4 8 14.4 8s-2.6 4.2-6.4 4.2S1.6 8 1.6 8z" />
      <circle cx="8" cy="8" r="1.9" />
    </>
  ),
  'ui-eye-off': (
    <>
      <path d="M1.6 8s2.6-4.2 6.4-4.2S14.4 8 14.4 8s-2.6 4.2-6.4 4.2S1.6 8 1.6 8z" />
      <circle cx="8" cy="8" r="1.9" />
      <path d="M2.6 2.6l10.8 10.8" />
    </>
  ),
  // 警告：三角 + 感叹号
  'ui-warning': (
    <>
      <path d="M8 2.4 15 14.2H1z" />
      <path d="M8 6.6v3.2" />
      <circle cx="8" cy="12.2" r="0.65" fill="currentColor" stroke="none" />
    </>
  ),
  'ui-check': <path d="M2.8 8.6 6.2 12l7-7.4" />,
  'ui-close': <path d="M3.6 3.6l8.8 8.8M12.4 3.6l-8.8 8.8" />,
  // 所以两者放一起时描边粗细和点的直径都是同一档。
  'ui-info': (
    <>
      <circle cx="8" cy="8" r="6.2" />
      <path d="M8 7.4v4.1" />
      <circle cx="8" cy="5" r="0.65" fill="currentColor" stroke="none" />
    </>
  ),
  'ui-chevron-up': <path d="M3.4 10.2 8 5.6l4.6 4.6" />,
  'ui-chevron-down': <path d="M3.4 5.8 8 10.4l4.6-4.6" />,
  'ui-chevron-right': <path d="M5.8 3.4 10.4 8l-4.6 4.6" />,
  'ui-sort': <path d="M8 13.4V2.6M5.4 5.2 8 2.6l2.6 2.6M5.4 10.8 8 13.4l2.6-2.6" />,
  'ui-more': (
    <g fill="currentColor" stroke="none">
      <circle cx="8" cy="3.6" r="0.9" />
      <circle cx="8" cy="8" r="0.9" />
      <circle cx="8" cy="12.4" r="0.9" />
    </g>
  ),

  // ── 文件 / 资源管理器（2026-09-22 从 ResourceManager.jsx 收编过来的 18 个）
  // 描边粗细换算后正好也是 ~1/12 尺寸（2/24 ≈ 1.3/16），所以**调用处的 size 不用改**。
  'ui-home': (
    <>
      <path d="M1.8 7.6 8 2.4l6.2 5.2" />
      <path d="M3.4 6.6v6.8h9.2V6.6" />
      <path d="M6.4 13.4v-3.2h3.2v3.2" />
    </>
  ),
  'ui-arrow-left': (
    <>
      <path d="M13.2 8H3" />
      <path d="M6.6 4.4 3 8l3.6 3.6" />
    </>
  ),
  // 刷新：两段弧 + 两个箭头端（feather refresh-cw 的坐标换算，别手改小数点）
  'ui-refresh': (
    <>
      <path d="M2 8a6 6 0 0 1 6-6 6.5 6.5 0 0 1 4.5 1.8L14 5.3" />
      <path d="M14 2v3.3h-3.3" />
      <path d="M14 8a6 6 0 0 1-6 6 6.5 6.5 0 0 1-4.5-1.8L2 10.7" />
      <path d="M5.3 10.7H2V14" />
    </>
  ),
  'ui-folder': (
    <path d="M14.7 12.7a1.3 1.3 0 0 1-1.3 1.3H2.7a1.3 1.3 0 0 1-1.3-1.3V3.3a1.3 1.3 0 0 1 1.3-1.3h3.3l1.3 2h6a1.3 1.3 0 0 1 1.3 1.3z" />
  ),
  'ui-folder-plus': (
    <>
      <path d="M14.7 12.7a1.3 1.3 0 0 1-1.3 1.3H2.7a1.3 1.3 0 0 1-1.3-1.3V3.3a1.3 1.3 0 0 1 1.3-1.3h3.3l1.3 2h6a1.3 1.3 0 0 1 1.3 1.3z" />
      <path d="M8 7.4v3.6M6.2 9.2h3.6" />
    </>
  ),
  'ui-file': (
    <>
      <path d="M8.7 1.3H4a1.3 1.3 0 0 0-1.3 1.3v10.7a1.3 1.3 0 0 0 1.3 1.3h8a1.3 1.3 0 0 0 1.3-1.3V6z" />
      <path d="M8.7 1.3v4.7h4.7" />
    </>
  ),
  'ui-file-plus': (
    <>
      <path d="M8.7 1.3H4a1.3 1.3 0 0 0-1.3 1.3v10.7a1.3 1.3 0 0 0 1.3 1.3h8a1.3 1.3 0 0 0 1.3-1.3V6z" />
      <path d="M8.7 1.3v4.7h4.7" />
      <path d="M8 12.7V8.7M6 10.7h4" />
    </>
  ),
  // 硬盘（资源管理器里按 36px 用）：机身 + 左侧风栅 + 右侧指示灯
  'ui-disk': (
    <>
      <rect x="1.3" y="4" width="13.4" height="9.3" rx="1.3" />
      <path d="M4 6.7v2.6" />
      <circle cx="11.3" cy="8" r="0.85" fill="currentColor" stroke="none" />
    </>
  ),
  'ui-upload': (
    <>
      <path d="M14 10v2.7a1.3 1.3 0 0 1-1.3 1.3H3.3A1.3 1.3 0 0 1 2 12.7V10" />
      <path d="M11.3 5.3 8 2l-3.3 3.3" />
      <path d="M8 2v8.7" />
    </>
  ),
  'ui-download': (
    <>
      <path d="M14 10v2.7a1.3 1.3 0 0 1-1.3 1.3H3.3A1.3 1.3 0 0 1 2 12.7V10" />
      <path d="M4.7 7.3 8 10.7l3.3-3.4" />
      <path d="M8 2v8.7" />
    </>
  ),
  'ui-copy': (
    <>
      <rect x="6" y="6" width="8.7" height="8.7" rx="1.3" />
      <path d="M3.3 10H2.7A1.3 1.3 0 0 1 1.3 8.7V2.7A1.3 1.3 0 0 1 2.7 1.3h6a1.3 1.3 0 0 1 1.3 1.3v.7" />
    </>
  ),
  'ui-paste': (
    <>
      <path d="M10.7 2.7h1.3a1.3 1.3 0 0 1 1.3 1.3v9.3a1.3 1.3 0 0 1-1.3 1.3H4a1.3 1.3 0 0 1-1.3-1.3V4A1.3 1.3 0 0 1 4 2.7h1.3" />
      <rect x="5.3" y="1.3" width="5.3" height="2.7" rx="0.7" />
    </>
  ),
  'ui-trash': (
    <>
      <path d="M2 4h12" />
      <path d="M12.7 4v9.3a1.3 1.3 0 0 1-1.3 1.3H4.7a1.3 1.3 0 0 1-1.3-1.3V4" />
      <path d="M5.4 4V2.7a1.3 1.3 0 0 1 1.3-1.4h2.6a1.3 1.3 0 0 1 1.3 1.4V4" />
      <path d="M6.7 7.3v4M9.3 7.3v4" />
    </>
  ),
  'ui-edit': <path d="M11.3 2a1.9 1.9 0 1 1 2.7 2.7L5 13.7 1.3 14.7l1-3.7z" />,
  'ui-zip': (
    <>
      <path d="M13.4 5.3v8a1.3 1.3 0 0 1-1.3 1.3H3.9a1.3 1.3 0 0 1-1.3-1.3v-8" />
      <rect x="1.3" y="2" width="13.4" height="3.3" rx="0.7" />
      <path d="M6.7 8.7h2.6" />
    </>
  ),
  'ui-unzip': (
    <>
      <path d="M14.7 12.7a1.3 1.3 0 0 1-1.3 1.3H2.7a1.3 1.3 0 0 1-1.3-1.3V3.3a1.3 1.3 0 0 1 1.3-1.3h3.3l1.3 2h6a1.3 1.3 0 0 1 1.3 1.3z" />
      <path d="M8 12.7V7.3" />
      <path d="M5.3 10.6 8 13.3l2.7-2.7" />
    </>
  ),
  'ui-save': (
    <>
      <path d="M12.7 14H3.3A1.3 1.3 0 0 1 2 12.7V3.3A1.3 1.3 0 0 1 3.3 2h7.3l3.3 3.3v7.3a1.3 1.3 0 0 1-1.3 1.3z" />
      <path d="M11.3 14V8.7H4.7V14" />
      <path d="M4.7 2v3.3H10" />
    </>
  ),
  // 转圈（处理中）：唯一的动效图标，动画写在图形里，跟着 IconFrame 一起缩放
  'ui-spinner': (
    <circle cx="8" cy="8" r="6.2" strokeDasharray="20">
      <animateTransform attributeName="transform" type="rotate"
        from="0 8 8" to="360 8 8" dur="1s" repeatCount="indefinite" />
    </circle>
  ),

  'ui-power': (
    <>
      <path d="M8 1.3v6.7" />
      <path d="M12.3 4.4a6 6 0 1 1-8.5 0" />
    </>
  ),
  // 日历（日期时间选择器）：外框 + 两个页眉挂耳 + 分隔线
  'ui-calendar': (
    <>
      <rect x="2" y="2.7" width="12" height="12" rx="1.3" />
      <path d="M5.3 1.3v2.7M10.7 1.3v2.7M2 6.7h12" />
    </>
  ),
}

/**
 * 统计小卡片左侧的图标（2026-09-22 从 `CardIcon.jsx` 收编；原 24 网格 / 描边 1.6 → 16 网格）。
 * 🚨 风扇那片叶子的旋转中心是 **8,8**（16 网格的中心），`CardIcon.css` 里的
 *    `transform-origin` 必须跟着写 8px 8px，否则会绕着 24 网格的中心甩出去。
 */
const CARD_BODIES = {
  'card-cpu': (
    <>
      <rect x="4.7" y="4.7" width="6.7" height="6.7" />
      <path d="M2.7 6.7h2M2.7 9.3h2M11.3 6.7h2M11.3 9.3h2M6.7 2.7v2M9.3 2.7v2M6.7 11.3v2M9.3 11.3v2" />
    </>
  ),
  'card-memory': (
    <>
      <rect x="2" y="4.7" width="12" height="6.7" />
      <path d="M4.7 11.3v2M8 11.3v2M11.3 11.3v2M4.7 7.3v1.3M7.3 7.3v1.3M10 7.3v1.3" />
    </>
  ),
  // 入站 = 向下落在基线上；出站 = 向上离开基线（两者只差箭头方向，特意做成一对）
  'card-in': (
    <>
      <path d="M8 2.7v7.3" />
      <path d="M5 7 8 10l3-3" />
      <path d="M2.7 12.7h10.7" />
    </>
  ),
  'card-out': (
    <>
      <path d="M8 10V2.7" />
      <path d="M5 5.7 8 2.7l3 3" />
      <path d="M2.7 12.7h10.7" />
    </>
  ),
  'card-port': (
    <>
      <rect x="2" y="5.3" width="12" height="5.3" />
      <path d="M4.7 8h.01M7.3 8h.01M10 8h.01" />
    </>
  ),
  'card-latency': <path d="M2 10h2.7l1.3-4 2 6.7 2-9.3 1.3 6.7h2.7" />,
  'card-temp': (
    <>
      <path d="M9.3 9.9V3.3a1.3 1.3 0 1 0-2.7 0v6.6a2.7 2.7 0 1 0 2.7 0Z" />
      <path d="M8 11.7v-4" />
    </>
  ),
  'card-power': (
    <>
      <path d="M6 2v4M10 2v4" />
      <path d="M4.7 6h6.7v2a3.3 3.3 0 0 1-6.7 0V6Z" />
      <path d="M8 11.3v2.7" />
    </>
  ),
  // 风扇：三片叶子整体转（转速固定，不代表真实转速 —— 真实转速写在副行）
  'card-fan': (
    <g className="stat-icon-fan">
      <ellipse cx="8" cy="4.7" rx="2.1" ry="3" />
      <ellipse cx="8" cy="4.7" rx="2.1" ry="3" transform="rotate(120 8 8)" />
      <ellipse cx="8" cy="4.7" rx="2.1" ry="3" transform="rotate(240 8 8)" />
      <circle cx="8" cy="8" r="1.2" />
    </g>
  ),
  'card-storage': (
    <>
      <ellipse cx="8" cy="4" rx="5.3" ry="2" />
      <path d="M2.7 4v8c0 1.1 2.4 2 5.3 2s5.3-.9 5.3-2V4" />
      <path d="M2.7 8c0 1.1 2.4 2 5.3 2s5.3-.9 5.3-2" />
    </>
  ),
  'card-disk': (
    <>
      <rect x="2" y="3.3" width="12" height="9.3" />
      <path d="M4.7 10h2.7" />
      <path d="M11.3 10h.01" />
    </>
  ),
}

/**
 * 状态标（原来详情页告警状态是**实心色块 + 白色符号**，两套画风）。
 * 按用户 2026-09-22 的拍板改成**描边图形 + 保留状态色**：颜色由外层容器的 `color` 给
 * （`info.color` 绿/黄/红），形状仍然两两可分（圆+勾 / 三角+叹号 / 圆+叉），
 * 所以颜色信息没丢，也不用给图标单独写死颜色。
 */
const STATUS_BODIES = {
  'status-ok': (
    <>
      <circle cx="8" cy="8" r="6.7" />
      <path d="M5.2 8.3 7.2 10.3l3.6-3.9" />
    </>
  ),
  // 警告沿用通用那个三角（形状本身就跟"圆"分得开，没必要再画一个）
  'status-warn': UI_BODIES['ui-warning'],
  'status-bad': (
    <>
      <circle cx="8" cy="8" r="6.7" />
      <path d="M5.7 5.7l4.6 4.6M10.3 5.7l-4.6 4.6" />
    </>
  ),
  'status-minus': (
    <>
      <circle cx="8" cy="8" r="6.7" />
      <path d="M5 8h6" />
    </>
  ),
}

/** 图标的中文名，只给图标表 / 调试用（界面上不显示，避免多出一层 tooltip）。 */
export const ICON_LABELS = {
  'host-windows': 'Windows 桌面版（微软官方旗）',
  'host-windows-server': 'Windows 服务器版',
  'host-ubuntu': 'Ubuntu（官方「朋友之环」）',
  'host-linux': '其他 Linux / 国产发行版（Tux）',
  'host-macos': 'macOS（官方苹果）',
  'host-generic': '主机（系统未识别）',
  'net-switch': '交换机',
  'net-router': '路由器',
  'net-firewall': '防火墙',
  'net-ap': '无线 AP',
  'net-nas': '存储 / NAS',
  'net-server': '机架服务器',
  'net-generic': '网络设备（类型未识别）',
  'nav-dashboard': '看板',
  'nav-devices': '设备管理',
  'nav-logs': '日志管理',
  'nav-settings': '系统设置',
  'ui-lock': '无权限（锁）',
  'ui-user': '用户',
  'ui-eye': '显示口令（睁眼）',
  'ui-eye-off': '隐藏口令（闭眼）',
  'ui-warning': '警告',
  'ui-check': '正常（对勾）',
  'ui-close': '关闭',
  'ui-info': '信息 / 提示',
  'ui-chevron-up': '向上 / 升序',
  'ui-chevron-down': '向下 / 降序 / 展开',
  'ui-chevron-right': '向右 / 折叠',
  'ui-sort': '未排序',
  'ui-more': '更多操作',
  'ui-home': '根目录',
  'ui-arrow-left': '返回上一级',
  'ui-refresh': '刷新',
  'ui-folder': '文件夹',
  'ui-folder-plus': '新建文件夹',
  'ui-file': '文件',
  'ui-file-plus': '新建文件',
  'ui-disk': '磁盘',
  'ui-upload': '上传',
  'ui-download': '下载',
  'ui-copy': '复制',
  'ui-paste': '粘贴',
  'ui-trash': '删除',
  'ui-edit': '编辑（铅笔）',
  'ui-zip': '压缩',
  'ui-unzip': '解压',
  'ui-save': '保存（软盘）',
  'ui-spinner': '处理中（转圈）',
  'ui-power': '电源（重启 / 关机）',
  'ui-calendar': '日历',
  'card-cpu': 'CPU',
  'card-memory': '内存',
  'card-in': '入站流量',
  'card-out': '出站流量',
  'card-port': '端口健康',
  'card-latency': '时延',
  'card-temp': '温度',
  'card-power': '电源',
  'card-fan': '风扇',
  'card-storage': '存储',
  'card-disk': '磁盘',
  'status-ok': '正常（描边圆 + 勾）',
  'status-warn': '警告（三角 + 叹号）',
  'status-bad': '严重（圆 + 叉）',
  'status-minus': '终止（圆 + 横杠）',
}

/**
 * os_type → 图标。os_type 是连上主机后由 Agent 上报的自由文本
 * （"Windows 11"、"Ubuntu 22.04.3 LTS"、"CentOS Linux 7"…），所以按关键词判断、一律小写比较。
 */
export function hostIconKind(osType) {
  const t = String(osType || '').toLowerCase()
  if (!t) return 'host-generic'
  if (t.includes('windows')) {
    return t.includes('server') ? 'host-windows-server' : 'host-windows'
  }
  if (t.includes('ubuntu')) return 'host-ubuntu'
  if (t.includes('mac') || t.includes('darwin')) return 'host-macos'
  // 其余 Linux 发行版统一画 Tux：红帽系 / 中标麒麟 / 统信 UOS / openEuler 都在这里
  if (
    t.includes('linux') || t.includes('centos') || t.includes('red hat') ||
    t.includes('redhat') || t.includes('rhel') || t.includes('rocky') ||
    t.includes('alma') || t.includes('oracle') || t.includes('fedora') ||
    t.includes('suse') || t.includes('debian') || t.includes('kali') ||
    t.includes('arch') || t.includes('kylin') || t.includes('麒麟') ||
    t.includes('uos') || t.includes('统信') || t.includes('openeuler')
  ) {
    return 'host-linux'
  }
  return 'host-generic'
}

/**
 * device_category → 图标。类别值由后端 SNMP 识别（services/device_profile.py）
 * 或管理员手选，库里是英文小写：switch / router / firewall / ap / storage / server / other。
 * 这里容错中文和大小写，免得以后后端换写法前端就全落到"未识别"。
 */
export function networkIconKind(category) {
  const c = String(category || '').toLowerCase()
  if (!c) return 'net-generic'
  if (c.includes('switch') || c.includes('交换')) return 'net-switch'
  if (c.includes('router') || c.includes('路由') || c.includes('gateway')) return 'net-router'
  if (c.includes('firewall') || c.includes('防火')) return 'net-firewall'
  if (c === 'ap' || c.includes('wireless') || c.includes('无线')) return 'net-ap'
  if (c.includes('storage') || c.includes('nas') || c.includes('存储')) return 'net-nas'
  if (c.includes('server') || c.includes('服务')) return 'net-server'
  return 'net-generic'
}

export function deviceIconKind(server) {
  if (!server) return 'host-generic'
  if ((server.device_kind || 'host') === 'network') {
    return networkIconKind(server.device_category)
  }
  return hostIconKind(server.os_type)
}

/**
 * 全站统一入口：`<Icon kind="host-windows" />` / `<Icon kind="ui-close" size={18} />`。
 * 三个分组查一遍，认不出来就退回"主机未识别"（而不是渲染个空白 svg —— 那是无声的 bug）。
 */
export function Icon({ kind, size = 16 }) {
  if (kind in NAV_BODIES) return <IconFrame size={size}>{NAV_BODIES[kind]}</IconFrame>
  if (kind in UI_BODIES) return <IconFrame size={size}>{UI_BODIES[kind]}</IconFrame>
  if (kind in CARD_BODIES) return <IconFrame size={size}>{CARD_BODIES[kind]}</IconFrame>
  if (kind in STATUS_BODIES) return <IconFrame size={size}>{STATUS_BODIES[kind]}</IconFrame>
  return (
    <IconFrame size={size}>{ICON_BODIES[kind] || ICON_BODIES['host-generic']}</IconFrame>
  )
}

export default Icon
