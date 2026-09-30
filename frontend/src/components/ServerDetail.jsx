import React, { useState, useEffect, useRef, useCallback } from 'react'
import {
  XAxis, YAxis, CartesianGrid, Tooltip,
  ResponsiveContainer, Area, AreaChart,
  LineChart, Line,
} from 'recharts'
import {
  fetchServerDetail,
  fetchServerMetrics,
  fetchServerServices,
  fetchPendingServices,
  fetchAgentCommands,
  fetchMetricHistory,
  terminateService,
  triggerServerCollect,
  updateServer,
  powerControl,
} from '../services/api'
import { showToast } from '../utils/toast'
import { authHeaders } from '../services/auth'
import { connectWS } from '../services/ws'
import { usePerm } from '../services/permissions'
import { formatDateTime, formatDateTimeShort, localDateTime, parseServerTime } from '../utils/format'
import DateTimeInput from './DateTimeInput'
import ServiceConfigModal, { applyServiceFilter } from './ServiceConfigModal'
import ResourceManager from './ResourceManager'
import WebTerminal from './Terminal'
import NetworkWebAdmin from './NetworkWebAdmin'
import RemoteDesktop from './RemoteDesktop'
import HostInfo from './HostInfo'
import ApplicationManager from './ApplicationManager'
import EventLogs from './EventLogs'
import NetworkPanel from './NetworkPanel'
import NetworkDeviceStatus from './NetworkDeviceStatus'
import NetworkEventLogs from './NetworkEventLogs'
import ServerFormModal from './ServerFormModal'
// 网络设备的编辑弹窗：定义在 NetworkDevices.jsx（2026-09-22 起导出），详情页头部的
// 编辑图标直接复用同一个弹窗，避免 SNMP 凭据表单在两处各维护一份。
import { EditDeviceModal } from './NetworkDevices'
// 小卡片左侧图标：与网络设备「设备状态」共用同一套 glyph（定义在 CardIcon.jsx）
import CardIcon from './CardIcon'
import './ServerDetail.css'
import Icon from './AppIcon'

const STATUS_MAP = {
  online: { label: '在线', color: '#5cb85c' },
  monitored: { label: '在线', color: '#5cb85c' },
  warning: { label: '告警', color: '#f0ad4e' },
  critical: { label: '严重', color: '#d9534f' },
  offline: { label: '离线', color: '#777777' },
  registered: { label: '待审核', color: '#999999' },
  unknown: { label: '未知', color: '#999999' },
}

const STATUS_BADGE_MAP = {
  alert: { normal: ['正常', '#5cb85c'], warning: ['警告', '#f0ad4e'], critical: ['严重', '#d9534f'] },
}

const ALIVE_STATUS_MAP = {
  running: { label: '运行中', color: '#5cb85c' },
  stopped: { label: '已停止', color: '#d9534f' },
  unknown: { label: '未知', color: '#f0ad4e' },
}

const ALERT_STATUS_MAP = {
  normal: { label: '正常', color: '#5cb85c' },
  warning: { label: '警告', color: '#f0ad4e' },
  critical: { label: '严重', color: '#d9534f' },
}

const PROCESS_ACTION_STATUS = {
  killing: { label: '终止中', color: '#f0ad4e', dotClass: 'killing' },
  terminated: { label: '已终止', color: '#adb5bd', dotClass: 'terminated' },
  failed: { label: '终止失败', color: '#d9534f', dotClass: 'failed' },
}

const OPERATION_LEVEL_META = {
  view_only: { label: '仅查看', color: '#adb5bd', short: '禁操' },
  terminate_with_confirm: { label: '终止需确认', color: '#f0ad4e', short: '终止' },
  full: { label: '完全开放', color: '#5cb85c', short: '开放' },
}

const CATEGORY_META = {
  core_system: { label: '核心系统', color: '#d9534f' },
  system_service: { label: '系统服务', color: '#6c757d' },
  third_party_service: { label: '第三方服务', color: '#0275d8' },
  user_process: { label: '用户进程', color: '#5cb85c' },
}

const PROCESS_COLUMNS = [
  { key: 'name', label: '名称', field: 'name', className: 'col-name', width: '200px', minWidth: 120, resizable: true },
  { key: 'image', label: '文件', field: 'image_name', className: 'col-image', width: '130px', minWidth: 100, resizable: true },
  { key: 'status', label: '状态', field: 'alive_status', className: 'col-status', width: '70px', minWidth: 60, resizable: true },
  { key: 'path', label: '路径', field: 'path', className: 'col-path', width: '240px', minWidth: 150, resizable: true },
  { key: 'cpu', label: 'CPU', field: 'cpu_percent', className: 'col-metric', width: '90px', minWidth: 75, resizable: true },
  { key: 'memory', label: '内存', field: 'memory_percent', className: 'col-metric', width: '90px', minWidth: 75, resizable: true },
  { key: 'disk', label: '磁盘', field: 'disk_mbps', className: 'col-metric', width: '90px', minWidth: 75, resizable: true },
  { key: 'network', label: '网络', field: 'network_mbps', className: 'col-metric', width: '90px', minWidth: 75, resizable: true },
  { key: 'pid', label: 'PID', field: 'pid', className: 'col-pid', width: '70px', minWidth: 55, resizable: true },
  { key: 'port', label: '端口', field: 'port', className: 'col-port', width: '70px', minWidth: 55, resizable: true },
  { key: 'alert', label: '告警', field: 'alert_status', className: 'col-status', width: '70px', minWidth: 60, resizable: true },
  { key: 'action', label: '操作', field: null, className: 'col-action', width: '70px', minWidth: 55, resizable: true },
]

function joinPath(dir, file) {
  if (!dir || !file) return null
  const sep = dir.includes('/') && !dir.includes('\\') ? '/' : '\\'
  return dir.endsWith(sep) ? `${dir}${file}` : `${dir}${sep}${file}`
}

function StatusTextBadge({ status, type = 'alive' }) {
  return <StatusIcon status={status} type={type} />
}

function Sparkline({ data, dataKey, color = '#0275d8', height = 18 }) {
  if (!data || data.length < 2) {
    return <div className="sparkline-empty" style={{ height }} />
  }
  return (
    <div className="sparkline-wrap" style={{ height }}>
      <ResponsiveContainer width="100%" height={height}>
        <LineChart data={data} margin={{ top: 2, right: 0, left: 0, bottom: 2 }}>
          <Line
            type="monotone"
            dataKey={dataKey}
            stroke={color}
            strokeWidth={1.5}
            dot={false}
            isAnimationActive={false}
          />
        </LineChart>
      </ResponsiveContainer>
    </div>
  )
}

function MetricCell({ value, unit, history, dataKey, color }) {
  const num = value ?? 0
  return (
    <div className="metric-cell">
      <div className="metric-cell-value">{num.toFixed(1)}{unit}</div>
      <Sparkline data={history} dataKey={dataKey} color={color} />
    </div>
  )
}

/* 终止进程：圆里一个横杠 / 圆里一个叉（2026-09-22 换成全站那套 `status-minus` / `status-bad`）。
   class 仍在**外层 span** 上（`.terminate-icon { display: block }` 需要它），图标本身不接 className。 */
function TerminateIcon({ variant = 'minus', className = '' }) {
  return (
    <span className={`terminate-icon ${className}`}>
      <Icon kind={variant === 'x' ? 'status-bad' : 'status-minus'} size={16} />
    </span>
  )
}

function StatusIcon({ status, type = 'alive' }) {
  const map = type === 'alert' ? ALERT_STATUS_MAP : ALIVE_STATUS_MAP
  const info = map[status] || map.unknown
  if (type === 'alert') {
    /* 2026-09-22：原来是"实心色块 + 白色符号"（两套画风），改成**描边图形 + 状态色** ——
       颜色由外层 span 的 `style.color` 给（下面 info.color 绿/黄/红），图形走全站那套，
       形状仍两两可分（圆+勾 / 三角+叹号 / 圆+叉），所以颜色信息没丢。
       用户拍板："描边 + 保留状态色"。 */
    if (status === 'normal') {
      return (
        <span className="status-icon status-icon-alert status-icon-normal" title={info.label}
          style={{ color: info.color }}>
          <Icon kind="status-ok" size={14} />
        </span>
      )
    }
    if (status === 'warning') {
      return (
        <span className="status-icon status-icon-alert status-icon-warning" title={info.label}
          style={{ color: info.color }}>
          <Icon kind="status-warn" size={14} />
        </span>
      )
    }
    return (
      <span className="status-icon status-icon-alert status-icon-critical" title={info.label}
        style={{ color: info.color }}>
        <Icon kind="status-bad" size={14} />
      </span>
    )
  }
  return (
    <span className="status-icon status-icon-alive" title={info.label}>
      <span className="status-dot" style={{ background: info.color }} />
    </span>
  )
}

function SortHeader({ label, field, sort, onSort }) {
  const active = sort.column === field
  const arrow = active
    ? (sort.direction === 'asc' ? 'ui-chevron-up' : 'ui-chevron-down')
    : 'ui-chevron-up'
  return (
    <span className="sort-header" onClick={() => onSort(field)}>
      {label}
      <span className={`sort-arrow ${active ? 'active' : ''}`}><Icon kind={arrow} size={9} /></span>
    </span>
  )
}

function StatusBadge({ status, type }) {
  const [label, color] = STATUS_BADGE_MAP[type]?.[status] || ['未知', '#adb5bd']
  return <span className="status-badge" style={{ background: color }}>{label}</span>
}

const TIME_RANGES = [
  { value: '1h', label: '1小时',  sample: '1分钟/点' },
  { value: '6h', label: '6小时',  sample: '5分钟/点' },
  { value: '12h', label: '12小时', sample: '10分钟/点' },
  { value: '1d', label: '1天',    sample: '20分钟/点' },
  { value: '3d', label: '3天',    sample: '60分钟/点' },
  { value: '7d', label: '7天',    sample: '120分钟/点' },
  { value: '14d', label: '14天',  sample: '180分钟/点' },
]

function formatMemoryMB(mb) {
  if (mb === null || mb === undefined || mb === 0) return '-'
  if (mb >= 1024) {
    return `${(mb / 1024).toFixed(2)} GB`
  }
  return `${mb.toFixed(1)} MB`
}

// 卡片本身只显示「标题 + 数值 + 一行小字」，居中排；右侧那一列明细已经去掉 ——
// 五张卡横向排开时每格才 200 多像素，明细挤在里面只能靠省略号活着。
// 明细改到光标悬停时从卡片下方弹出的浮层里显示（宽度占满卡片，可滚动），

function MetricCard({ label, value, unit, color, sub, detail, icon }) {
  const [open, setOpen] = useState(false)

  return (
    <div
      className={`mcard${detail ? ' mcard-hoverable' : ''}`}
      onMouseEnter={detail ? () => setOpen(true) : undefined}
      onMouseLeave={detail ? () => setOpen(false) : undefined}
      title={detail ? '悬停查看详细参数' : undefined}
    >
      {/* 图标在左、内容在右，和网络设备「设备状态」的小卡片同一个排法。
          🚨 图标**不承载状态**：颜色一律同灰（见 CardIcon.css），状态由右侧数值的颜色表达。 */}
      {icon ? <CardIcon name={icon} className="mcard-icon" /> : null}
      <div className="mcard-left">
        <div className="mcard-label">{label}</div>
        <div className="mcard-value" style={{ color }}>
          {value ?? '--'}<span className="mcard-unit">{unit}</span>
        </div>
        {sub && <div className="mcard-sub">{sub}</div>}
      </div>
      {detail && open && (
        // 悬停展开：浮层紧贴卡片下沿，光标可以平滑移进去滚动查看，
        // 移开卡片（含浮层）范围就自动收回，所以不再需要关闭按钮
        <div className="mcard-pop">
          <div className="mcard-pop-head">
            <span className="mcard-pop-title">{label}</span>
          </div>
          <div className="mcard-detail-list">{detail}</div>
        </div>
      )}
    </div>
  )
}

function Skeleton({ width, height, circle, className = '' }) {
  const style = {
    width,
    height,
    borderRadius: circle ? '50%' : 4,
    background: 'linear-gradient(90deg, #f0f0f0 25%, #e0e0e0 50%, #f0f0f0 75%)',
    backgroundSize: '200% 100%',
    animation: 'skeleton-pulse 1.5s ease-in-out infinite',
  }
  return <div className={`skeleton ${className}`} style={style} />
}

function ProcessSkeletonRow() {
  return (
    <tr className="svc-skeleton-row">
      <td className="col-name"><Skeleton width="80%" height={14} /></td>
      <td className="col-image"><Skeleton width="70%" height={14} /></td>
      <td className="col-status"><Skeleton width={16} height={16} circle /></td>
      <td className="col-path"><Skeleton width="90%" height={14} /></td>
      <td className="col-metric"><Skeleton width={40} height={14} /></td>
      <td className="col-metric"><Skeleton width={40} height={14} /></td>
      <td className="col-metric"><Skeleton width={40} height={14} /></td>
      <td className="col-metric"><Skeleton width={40} height={14} /></td>
      <td className="col-pid"><Skeleton width={40} height={14} /></td>
      <td className="col-port"><Skeleton width={40} height={14} /></td>
      <td className="col-status"><Skeleton width={16} height={16} circle /></td>
      <td className="col-action"><Skeleton width={24} height={24} circle /></td>
    </tr>
  )
}

function DateTimeTick({ x, y, payload }) {
  const t = parseServerTime(payload.value)
  const time = t.toLocaleTimeString('zh-CN', { hour: '2-digit', minute: '2-digit' })
  const date = `${String(t.getMonth() + 1).padStart(2, '0')}-${String(t.getDate()).padStart(2, '0')}`
  return (
    <g transform={`translate(${x},${y + 8})`}>
      <text textAnchor="middle" fill="#999" fontSize={11}>
        <tspan x="0" dy="0">{time}</tspan>
        <tspan x="0" dy="14">{date}</tspan>
      </text>
    </g>
  )
}

function TimeChart({ title, data, dataKeys, colors, xDomain, sampleInterval, height = 220, showLegend = false, yUnit = '' }) {
  if (!data || data.length === 0) {
    return (
      <div className="chart-box">
        <div className="chart-title">{title}</div>
        {sampleInterval && <div className="chart-subtitle">周期 {sampleInterval}</div>}
        <div className="chart-empty">暂无数据</div>
      </div>
    )
  }

  return (
    <div className="chart-box">
      <div className="chart-title-row">
        <div className="chart-title">{title}</div>
        {showLegend && (
          <div className="chart-legend-inline">
            {dataKeys.map((dk, i) => (
              <span key={dk.key} className="legend-item">
                <span className="legend-dot" style={{ background: colors[i] }} />
                {dk.label}
              </span>
            ))}
          </div>
        )}
      </div>
      {sampleInterval && <div className="chart-subtitle">周期 {sampleInterval}</div>}
      <ResponsiveContainer width="100%" height={height}>
        <AreaChart data={data} margin={{ top: 10, right: 30, bottom: 0, left: 5 }}>
          <defs>
            {dataKeys.map((dk, i) => (
              <linearGradient key={dk.key} id={`grad-${dk.key}`} x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor={colors[i]} stopOpacity={0.3} />
                <stop offset="95%" stopColor={colors[i]} stopOpacity={0} />
              </linearGradient>
            ))}
          </defs>
          <CartesianGrid strokeDasharray="3 3" stroke="#f0f0f0" />
          <XAxis
            dataKey="ts"
            type="number"
            domain={xDomain || ['dataMin', 'dataMax']}
            tick={<DateTimeTick />}
            interval="preserveStartEnd"
            height={45}
          />
          <YAxis
            tick={{ fontSize: 11, fill: '#999' }}
            tickFormatter={(v) => `${v}${yUnit}`}
            width={yUnit ? 55 : 35}
          />
          <Tooltip
            contentStyle={{ fontSize: 12, borderRadius: 6, border: '1px solid #e9ecef' }}
            labelFormatter={(v) => formatDateTime(new Date(v).toISOString())}
            formatter={(value, name) => [`${Number(value).toFixed(1)}${yUnit}`, name]}
          />
          {dataKeys.map((dk, i) => (
            <Area
              key={dk.key}
              type="monotone"
              dataKey={dk.key}
              name={dk.label}
              stroke={colors[i]}
              fill={`url(#grad-${dk.key})`}
              strokeWidth={2}
              dot={false}
              connectNulls
            />
          ))}
        </AreaChart>
      </ResponsiveContainer>
    </div>
  )
}

function ServerDetailSkeleton() {
  return (
    <div className="server-detail">
      <div className="detail-topbar">
        <div className="detail-topbar-info">
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 8 }}>
            <Skeleton width={180} height={22} />
            <Skeleton width={60} height={22} circle={false} />
          </div>
          <div className="detail-topbar-meta">
            <Skeleton width={120} height={16} />
            <Skeleton width={140} height={16} />
            <Skeleton width={160} height={16} />
          </div>
        </div>
      </div>
      <div className="detail-tabs">
        <Skeleton width={80} height={32} />
        <Skeleton width={80} height={32} />
        <Skeleton width={80} height={32} />
        <Skeleton width={80} height={32} />
      </div>
      <div className="metrics-row">
        <Skeleton width="19%" height={90} />
        <Skeleton width="19%" height={90} />
        <Skeleton width="19%" height={90} />
        <Skeleton width="19%" height={90} />
        <Skeleton width="19%" height={90} />
      </div>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 16, marginTop: 16 }}>
        <Skeleton width="100%" height={220} />
        <Skeleton width="100%" height={220} />
        <Skeleton width="100%" height={220} />
        <Skeleton width="100%" height={220} />
        <Skeleton width="100%" height={220} />
        <Skeleton width="100%" height={220} />
      </div>
    </div>
  )
}

export default function ServerDetail({ serverId, onEdit, onDelete, isAdmin = true, refreshSignal = 0 }) {
  const [server, setServer] = useState(null)
  const [metrics, setMetrics] = useState(null)
  const [services, setServices] = useState([])
  const [pendingServices, setPendingServices] = useState([])
  const [dangerousPorts, setDangerousPorts] = useState([])
  const [history, setHistory] = useState([])
  const [timeRange, setTimeRange] = useState('1h')
  const nowStr = localDateTime(new Date())
  const [customStart, setCustomStart] = useState(nowStr)
  const [customEnd, setCustomEnd] = useState(nowStr)
  const [loadingStatic, setLoadingStatic] = useState(true)
  const [loadingMetrics, setLoadingMetrics] = useState(true)
  const [showServiceConfig, setShowServiceConfig] = useState(false)
  const [actionMenuOpen, setActionMenuOpen] = useState(false)
  const [powerConfirm, setPowerConfirm] = useState(null)
  const [remoteDesktopLoading, setRemoteDesktopLoading] = useState(false)
  const { can: canPerm, canManage } = usePerm()
  const [activeTab, setActiveTab] = useState('status')
  const tabsRef = useRef(null)

  // 权限派生值必须在组件顶部：下方存在 loadingStatic / !server 的提前 return，
  // （apps 下含 uninstall / startup 两个操作项），自定义角色需在角色管理里勾选
  const tabPerm = {
    status: canPerm('host', 'status', 'view'),
    info: canPerm('host', 'info', 'view'),
    apps: canPerm('host', 'apps', 'view'),
    services: canPerm('host', 'services', 'view'),
    resources: canPerm('host', 'resources', 'view'),
    terminal: canPerm('host', 'terminal', 'view'),
    rdp: canPerm('host', 'rdp', 'view'),
    events: canPerm('host', 'events', 'view'),
    // 方案 B：设备自带 Web 管理界面的代理入口（只有网络设备有数据来源）
    webadmin: canPerm('host', 'webadmin', 'view'),
  }
  const TAB_ORDER = ['status', 'info', 'apps', 'services', 'resources', 'terminal', 'webadmin', 'rdp', 'events']

  // 网络设备（交换机 / 路由器 / 防火墙）装不上 Agent，进程管理 / 应用管理 /
  // 资源管理 / 远程桌面这些页签的数据源全在 Agent 上，对它显示出来只会是一片
  // 空白。这里按 device_kind 决定"哪些页签有数据来源"，再和角色权限取交集 ——
  // 网络设备保留四个页签，内容全部换成设备自己的实现（不是主机的那套）：
  //   status   设备状态 → 设备运行状态：CPU / 内存 / 端口流量图表 + 端口 UP/DOWN
  //   info     系统信息 → 设备系统及硬件信息：sysDescr / 资产 / 端口表 / SSH 指纹
  //   events   事件日志 → 设备日志：服务端记的告警 + 审计
  // 原来的「网络」页签已删除 —— SNMPv3 凭据改到「主机管理 - 网络设备」页维护。
  const isNetworkDevice = !!server && server.device_kind === 'network'
  // 🚨 主机侧要**显式排除** webadmin：TAB_ORDER 里带着它，若直接 `new Set(TAB_ORDER)`
  // 就会因为角色有 `host/webadmin` 权限而把「WEB管理」显示在普通主机上 ——
  // 主机没有"设备自带的 Web 管理界面"，点进去是一片空白。
  const APPLICABLE = isNetworkDevice
    ? new Set(['status', 'info', 'terminal', 'webadmin', 'events'])
    : new Set(TAB_ORDER.filter((t) => t !== 'webadmin'))
  const tabShow = {}
  for (const t of TAB_ORDER) tabShow[t] = !!tabPerm[t] && APPLICABLE.has(t)

  // 当前页签被角色权限（或设备形态）隐藏时，自动切到第一个可见页签，避免空白内容区
  useEffect(() => {
    if (tabShow[activeTab]) return
    const first = TAB_ORDER.find((t) => tabShow[t])
    if (first) setActiveTab(first)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [activeTab, tabShow.status, tabShow.info, tabShow.apps, tabShow.services,
      tabShow.resources, tabShow.terminal, tabShow.webadmin, tabShow.rdp, tabShow.events])
  const [terminateModal, setTerminateModal] = useState(null)
  const [groupTerminateModal, setGroupTerminateModal] = useState(null)
  const [serviceSort, setServiceSort] = useState({ column: null, direction: 'asc' })
  const [refreshingServices, setRefreshingServices] = useState(false)
  const [refreshSlow, setRefreshSlow] = useState(false)
  const [showBlacklistModal, setShowBlacklistModal] = useState(false)
  const [blacklistForm, setBlacklistForm] = useState({ pattern: '', match_type: 'contains' })
  const [savingBlacklist, setSavingBlacklist] = useState(false)
  const [showWhitelistModal, setShowWhitelistModal] = useState(false)
  const [whitelistForm, setWhitelistForm] = useState({ pattern: '', match_type: 'contains' })
  const [savingWhitelist, setSavingWhitelist] = useState(false)

  // ── 头部「编辑」图标（2026-09-22）─────────────────────────────────────
  // 网络设备 → EditDeviceModal（与「设备管理 - 网络设备」的编辑同一个弹窗）
  // 🚨 存的是**点击那一刻的快照**，不是 server 本体：详情会被 WS / 轮询刷新，
  //    若把 server 对象直接当 initialData，刷新一次弹窗里的表单就被重置回原值。
  // 🚨 这几个 hook 必须在 `loadingStatic` / `!server` 的提前 return **之前** ——
  const [editHost, setEditHost] = useState(null)
  const [editDevice, setEditDevice] = useState(null)
  const [noteTip, setNoteTip] = useState(false)
  const noteTipTimer = useRef(0)

  const openEdit = useCallback(() => {
    if (!server) return
    if (isNetworkDevice) {
      // EditDeviceModal 只用到 id / name，凭据它自己按 id 重新拉
      setEditDevice({ id: server.id, name: server.name })
    } else {
      setEditHost({ ...server })
    }
  }, [server, isNetworkDevice])

  // 备注气泡：悬停 300ms 才弹（扫过不弹），移开立刻收起；没填备注就不弹
  const onTitleEnter = useCallback(() => {
    if (!server?.description) return
    window.clearTimeout(noteTipTimer.current)
    noteTipTimer.current = window.setTimeout(() => setNoteTip(true), 300)
  }, [server?.description])

  const onTitleLeave = useCallback(() => {
    window.clearTimeout(noteTipTimer.current)
    setNoteTip(false)
  }, [])

  useEffect(() => () => window.clearTimeout(noteTipTimer.current), [])
  const [processCategoryTab, setProcessCategoryTab] = useState('all')
  const [processPage, setProcessPage] = useState(1)
  const [processPageSize, setProcessPageSize] = useState(50)
  const [processActions, setProcessActions] = useState({})
  const [hiddenProcessIds, setHiddenProcessIds] = useState(new Set())
  const [expandedProcessIds, setExpandedProcessIds] = useState(new Set())
  const [expandedGroups, setExpandedGroups] = useState(new Set())
  const [processSearchKeyword, setProcessSearchKeyword] = useState('')
  const [processSearchActive, setProcessSearchActive] = useState('')
  const [serviceRefreshInterval, setServiceRefreshInterval] = useState(60)
  const [columnWidths, setColumnWidths] = useState({})
  const [resizingCol, setResizingCol] = useState(null)
  const resizeStartXRef = useRef(0)
  const resizeStartWidthRef = useRef(0)
  const wsRef = useRef(null)
  const actionMenuRef = useRef(null)
  const refreshTimerRef = useRef(null)
  const refreshSlowTimerRef = useRef(null)
  const terminateTimersRef = useRef(new Set())

  useEffect(() => {
    const handler = (e) => {
      if (actionMenuRef.current && !actionMenuRef.current.contains(e.target)) {
        setActionMenuOpen(false)
      }
    }
    document.addEventListener('mousedown', handler)
    return () => document.removeEventListener('mousedown', handler)
  }, [])

  // 切换服务器或离开进程页时清理本地操作状态
  useEffect(() => {
    setProcessActions({})
    setHiddenProcessIds(new Set())
    setExpandedProcessIds(new Set())
    setExpandedGroups(new Set())
    setProcessCategoryTab('all')
    setProcessPage(1)
    terminateTimersRef.current.forEach((t) => clearInterval(t))
    terminateTimersRef.current.clear()
  }, [serverId])

  useEffect(() => {
    setProcessPage(1)
  }, [processCategoryTab])

  useEffect(() => {
    if (!resizingCol) return
    const handleMove = (e) => {
      const delta = e.clientX - resizeStartXRef.current
      const newWidth = Math.max(40, resizeStartWidthRef.current + delta)
      setColumnWidths((prev) => ({ ...prev, [resizingCol]: `${newWidth}px` }))
    }
    const handleUp = () => setResizingCol(null)
    document.addEventListener('mousemove', handleMove)
    document.addEventListener('mouseup', handleUp)
    return () => {
      document.removeEventListener('mousemove', handleMove)
      document.removeEventListener('mouseup', handleUp)
    }
  }, [resizingCol])

  const loadServer = useCallback(async () => {
    try {
      const detail = await fetchServerDetail(serverId)
      setServer(detail)
    } catch (e) {
      console.error('Server detail error:', e)
    }
  }, [serverId])

  // 头部「编辑主机」弹窗的提交（保存后重拉详情，页头名称/备注立即刷新）
  // 🚨 必须定义在 `loadServer` **之后**：useCallback 的依赖数组在渲染时求值，
  const submitHostEdit = useCallback(async (data) => {
    await updateServer(serverId, data)
    await loadServer()
    showToast('已保存主机信息', 'success')
  }, [serverId, loadServer])

  const loadMetrics = useCallback(async () => {
    try {
      const data = await fetchServerMetrics(serverId)
      setMetrics(data)
    } catch (e) {
      console.error('Server metrics error:', e)
    }
  }, [serverId])

  const loadServices = useCallback(async () => {
    try {
      const data = await fetchServerServices(serverId)
      setServices(data)
    } catch (e) {
      console.error('Server services error:', e)
    }
  }, [serverId])

  const loadPendingServices = useCallback(async () => {
    try {
      const data = await fetchPendingServices(serverId)
      setPendingServices(data.pending_services || [])
      setDangerousPorts(data.dangerous_ports || [])
    } catch (e) {
      console.error('Pending services error:', e)
    }
  }, [serverId])

  const loadHistory = useCallback(async (range, start, end) => {
    try {
      const hist = await fetchMetricHistory(serverId, range, start, end)
      const data = hist.map((p) => ({ ...p, ts: parseServerTime(p.timestamp).getTime() }))
      setHistory(data)
    } catch (e) {
      console.error('History error:', e)
    }
  }, [serverId])

  useEffect(() => {
    setLoadingStatic(true)
    setLoadingMetrics(true)
    Promise.all([loadServer(), loadMetrics()]).finally(() => {
      setLoadingStatic(false)
      setLoadingMetrics(false)
    })
  }, [loadServer, loadMetrics])

  useEffect(() => {
    if (activeTab === 'services') {
      loadServices()
      loadPendingServices()
    }
  }, [activeTab, loadServices, loadPendingServices])

  useEffect(() => {
    if (refreshSignal > 0) {
      loadServer()
      loadMetrics()
      if (activeTab === 'services') {
        loadServices()
        loadPendingServices()
      }
    }
  }, [refreshSignal, loadServer, loadMetrics, activeTab, loadServices, loadPendingServices])

  useEffect(() => {
    if (timeRange === 'custom' && customStart && customEnd) {
      const startUTC = new Date(customStart).toISOString()
      const endUTC = new Date(customEnd).toISOString()
      loadHistory('custom', startUTC, endUTC)
    } else {
      loadHistory(timeRange)
    }
  }, [timeRange, customStart, customEnd, loadHistory])

  useEffect(() => {
    const interval = setInterval(() => {
      loadServer()
      if (activeTab === 'services') {
        loadServices()
        loadPendingServices()
      }
      if (timeRange === 'custom' && customStart && customEnd) {
        const startUTC = new Date(customStart).toISOString()
        const endUTC = new Date(customEnd).toISOString()
        loadHistory('custom', startUTC, endUTC)
      } else {
        loadHistory(timeRange)
      }
    }, serviceRefreshInterval * 1000)

    const ws = connectWS('/ws', localStorage.getItem('token') || '')
    wsRef.current = ws

    ws.onmessage = (event) => {
      try {
        const msg = JSON.parse(event.data)
        if (msg.type === 'metrics_update') {
          const svr = msg.servers?.find((s) => s.id === parseInt(serverId))
          if (svr) {
            setServer((prev) => {
              if (!prev) return prev
              return {
                ...prev,
                status: svr.status ?? prev.status,
              }
            })
            setMetrics((prev) => {
              if (!prev) return prev
              return {
                ...prev,
                cpu_percent: svr.cpu_percent ?? prev.cpu_percent,
                memory_percent: svr.memory_percent ?? prev.memory_percent,
                disk_percent: svr.disk_percent ?? prev.disk_percent,
                network_in_mbps: svr.network_in_mbps ?? prev.network_in_mbps,
                network_out_mbps: svr.network_out_mbps ?? prev.network_out_mbps,
              }
            })
          }
        }
      } catch (e) { }
    }

    return () => {
      clearInterval(interval)
      ws.close()
    }
  }, [serverId, timeRange, activeTab, serviceRefreshInterval, loadServer, loadMetrics, loadServices, loadPendingServices, loadHistory])

  const handleRangeChange = (range) => {
    setTimeRange(range)
  }

  const _alertError = (e, fallback = '操作失败') => {
    const msg = e?.message || (typeof e === 'string' ? e : (e ? JSON.stringify(e) : fallback))
    alert(msg || fallback)
  }

  const updateProcessAction = (id, updates) => {
    setProcessActions((prev) => ({ ...prev, [id]: { ...(prev[id] || {}), ...updates } }))
  }

  const removeProcessAction = (id) => {
    setProcessActions((prev) => {
      const next = { ...prev }
      delete next[id]
      return next
    })
  }

  const markTerminated = (id) => {
    updateProcessAction(id, { state: 'terminated' })
    setTimeout(() => {
      setHiddenProcessIds((prev) => new Set(prev).add(id))
      removeProcessAction(id)
    }, 2000)
  }

  const handleTerminate = async (mode) => {
    if (!terminateModal) return
    const svc = terminateModal
    setTerminateModal(null)
    const label = mode === 'force' ? '强制终止' : '退出进程'

    updateProcessAction(svc.id, { state: 'killing', mode, name: svc.name, startedAt: Date.now() })

    try {
      const result = await terminateService(serverId, svc.id, mode)
      // 2. Agent 协议异步执行，需要轮询结果；其他协议同步返回
      if (server?.protocol?.toLowerCase?.() === 'agent') {
        if (result.command_id) {
          pollTerminateResult(result.command_id, svc.id, svc.name, mode)
        } else {
          markTerminated(svc.id)
        }
      } else {
        markTerminated(svc.id)
      }
      await loadServer()
      await loadMetrics()
    } catch (e) {
      updateProcessAction(svc.id, { state: 'failed', error: e?.message || '终止失败' })
      showToast(e?.message || '终止进程失败', 'error')
    }
  }

  const handlePower = async () => {
    if (!powerConfirm) return
    const { action } = powerConfirm
    setPowerConfirm(null)
    const label = action === 'restart' ? '重启' : '关机'
    try {
      const result = await powerControl(serverId, action)
      showToast(result.message || `${label}命令已下发`, 'success')
    } catch (e) {
      showToast(e?.message || `${label}操作失败`, 'error')
    }
  }

  // 🚨 2026-09-23：旧的 `handleRemoteDesktopMeshCentral` 已随 MeshCentral 集成
  //    整体下线删除。它在移除前本来就是**死代码**（全项目只有定义、没有任何调用点），

  const handleGroupTerminate = async (mode) => {
    if (!groupTerminateModal) return
    const { main, children } = groupTerminateModal
    setGroupTerminateModal(null)

    const targets = [main, ...children.map((c) => c.child)].filter(
      (s) => s.operation_level !== 'view_only'
    )
    if (targets.length === 0) {
      showToast('进程组中没有可终止的进程', 'warning')
      return
    }

    targets.forEach((svc) => {
      updateProcessAction(svc.id, { state: 'killing', mode, name: svc.name, startedAt: Date.now() })
    })

    try {
      const results = await Promise.all(
        targets.map((svc) => terminateService(serverId, svc.id, mode).catch((e) => ({ error: e?.message || '失败', svc })))
      )
      const failed = results.filter((r) => r && r.error)
      if (failed.length) {
        failed.forEach((r) => {
          updateProcessAction(r.svc.id, { state: 'failed', error: r.error })
        })
        showToast(`${failed.length}/${targets.length} 个进程终止失败`, 'error')
      }
      const lastCommand = results.findLast((r) => r && r.command_id)
      if (server?.protocol?.toLowerCase?.() === 'agent' && lastCommand) {
        pollTerminateResult(lastCommand.command_id, main.id, main.name, mode)
      } else if (!failed.length) {
        targets.forEach((svc) => markTerminated(svc.id))
      }
      await loadServer()
      await loadMetrics()
    } catch (e) {
      targets.forEach((svc) => {
        updateProcessAction(svc.id, { state: 'failed', error: e?.message || '终止失败' })
      })
      showToast(e?.message || '终止进程组失败', 'error')
    }
  }

  const pollTerminateResult = (commandId, serviceId, name, mode) => {
    let attempts = 0
    const maxAttempts = 120
    const timer = setInterval(async () => {
      attempts += 1
      try {
        const cmd = await fetchAgentCommands(serverId)
        const stillPending = (cmd.pending_terminate || []).some((p) => p.id === commandId)
        if (stillPending && attempts < maxAttempts) return
        clearInterval(timer)
        terminateTimersRef.current.delete(timer)
        const result = (cmd.last_terminate_results || []).find((r) => r.id === commandId)
        if (result?.success) {
          markTerminated(serviceId)
        } else if (result) {
          const detail = (result.errors || []).slice(0, 2).join('；') || '未知错误'
          updateProcessAction(serviceId, { state: 'failed', error: detail })
        } else if (!stillPending) {
          markTerminated(serviceId)
        } else {
          updateProcessAction(serviceId, { state: 'failed', error: '等待 Agent 执行结果超时' })
        }
        await loadPendingServices()
        await loadMetrics()
      } catch (e) {
        if (attempts >= maxAttempts) {
          clearInterval(timer)
          terminateTimersRef.current.delete(timer)
          updateProcessAction(serviceId, { state: 'failed', error: '等待 Agent 执行结果超时' })
        }
      }
    }, 1000)
    terminateTimersRef.current.add(timer)
  }

  const handleSort = (field) => {
    setServiceSort((prev) => {
      if (prev.column === field) {
        return { column: field, direction: prev.direction === 'asc' ? 'desc' : 'asc' }
      }
      return { column: field, direction: 'asc' }
    })
  }

  const handleRefreshServices = async () => {
    if (refreshTimerRef.current) {
      clearInterval(refreshTimerRef.current)
      refreshTimerRef.current = null
    }
    if (refreshSlowTimerRef.current) {
      clearTimeout(refreshSlowTimerRef.current)
    }
    setRefreshingServices(true)
    setRefreshSlow(false)
    refreshSlowTimerRef.current = setTimeout(() => setRefreshSlow(true), 3000)

    try {
      await triggerServerCollect(serverId)
      const startMetricTs = metrics?.timestamp ? parseServerTime(metrics.timestamp).getTime() : 0
      const startTs = Date.now()
      refreshTimerRef.current = setInterval(async () => {
        const elapsed = Date.now() - startTs
        try {
          const m = await fetchServerMetrics(serverId)
          const ts = m.timestamp ? parseServerTime(m.timestamp).getTime() : 0
          if (ts > startMetricTs + 1000) {
            clearInterval(refreshTimerRef.current)
            refreshTimerRef.current = null
            clearTimeout(refreshSlowTimerRef.current)
            setRefreshingServices(false)
            setRefreshSlow(false)
            await loadServer()
            await loadMetrics()
            await loadServices()
            await loadPendingServices()
            return
          }
          if (elapsed > 30000) {
            clearInterval(refreshTimerRef.current)
            refreshTimerRef.current = null
            clearTimeout(refreshSlowTimerRef.current)
            setRefreshingServices(false)
            setRefreshSlow(false)
          }
        } catch (e) {
          if (elapsed > 30000) {
            clearInterval(refreshTimerRef.current)
            refreshTimerRef.current = null
            clearTimeout(refreshSlowTimerRef.current)
            setRefreshingServices(false)
            setRefreshSlow(false)
          }
        }
      }, 2000)
    } catch (e) {
      clearTimeout(refreshSlowTimerRef.current)
      setRefreshingServices(false)
      setRefreshSlow(false)
      showToast(e?.message || '刷新失败', 'error')
      _alertError(e, '刷新失败')
    }
  }

  useEffect(() => {
    return () => {
      if (refreshTimerRef.current) {
        clearInterval(refreshTimerRef.current)
        refreshTimerRef.current = null
      }
      if (refreshSlowTimerRef.current) {
        clearTimeout(refreshSlowTimerRef.current)
      }
    }
  }, [])

  const blacklist = server?.extra_config?.service_blacklist || []
  const isBlacklistActive = blacklist.length > 0
  const whitelist = server?.extra_config?.service_whitelist || []
  const isWhitelistActive = whitelist.length > 0

  const handleAddBlacklist = async (e) => {
    e.preventDefault()
    const pattern = blacklistForm.pattern.trim()
    if (!pattern) {
      alert('请输入进程名称或匹配规则')
      return
    }
    setSavingBlacklist(true)
    try {
      const newRule = {
        id: `bl_${Date.now()}`,
        pattern,
        match_type: blacklistForm.match_type || 'contains',
        created_at: new Date().toISOString(),
      }
      const next = [...blacklist, newRule]
      await updateServer(serverId, {
        extra_config: {
          ...(server.extra_config || {}),
          service_blacklist: next,
        },
      })
      setBlacklistForm({ pattern: '', match_type: 'contains' })
      await loadServer()
      alert('已加入黑名单，Agent 下次采集时将强制退出匹配进程')
    } catch (e) {
      _alertError(e, '保存黑名单失败')
    } finally {
      setSavingBlacklist(false)
    }
  }

  const handleRemoveBlacklist = async (id) => {
    if (!confirm('确定从黑名单移除该规则？')) return
    try {
      const next = blacklist.filter((r) => r.id !== id)
      await updateServer(serverId, {
        extra_config: {
          ...(server.extra_config || {}),
          service_blacklist: next,
        },
      })
      await loadServer()
    } catch (e) {
      _alertError(e, '移除黑名单失败')
    }
  }

  const handleAddWhitelist = async (e) => {
    e.preventDefault()
    const pattern = whitelistForm.pattern.trim()
    if (!pattern) {
      alert('请输入进程名称或匹配规则')
      return
    }
    setSavingWhitelist(true)
    try {
      const newRule = {
        id: `wl_${Date.now()}`,
        pattern,
        match_type: whitelistForm.match_type || 'contains',
        created_at: new Date().toISOString(),
      }
      const next = [...whitelist, newRule]
      await updateServer(serverId, {
        extra_config: {
          ...(server.extra_config || {}),
          service_whitelist: next,
        },
      })
      setWhitelistForm({ pattern: '', match_type: 'contains' })
      await loadServer()
      alert('已加入白名单，Agent 下次采集时只上报匹配进程')
    } catch (e) {
      _alertError(e, '保存白名单失败')
    } finally {
      setSavingWhitelist(false)
    }
  }

  const handleRemoveWhitelist = async (id) => {
    if (!confirm('确定从白名单移除该规则？')) return
    try {
      const next = whitelist.filter((r) => r.id !== id)
      await updateServer(serverId, {
        extra_config: {
          ...(server.extra_config || {}),
          service_whitelist: next,
        },
      })
      await loadServer()
    } catch (e) {
      _alertError(e, '移除白名单失败')
    }
  }

  if (loadingStatic) return <ServerDetailSkeleton />
  if (!server) return <div className="page-loading">服务器不存在</div>

  const statusInfo = STATUS_MAP[server.status] || STATUS_MAP.unknown
  const osVersion = server.extra_config?.os_version || ''
  // 网络设备没有 os_type（SNMP 读不到操作系统版本），顶栏改显示识别出的厂商 + 型号
  const osText = isNetworkDevice
    ? [server.device_vendor, server.device_model].filter(Boolean).join(' ')
    : [server.os_type, osVersion].filter(Boolean).join(' ')

  const RANGE_MS = { '1h': 3600000, '6h': 21600000, '12h': 43200000, '1d': 86400000, '3d': 259200000, '7d': 604800000, '14d': 1209600000 }
  const now = Date.now()
  const xDomain = timeRange === 'custom' && customStart && customEnd
    ? [new Date(customStart).getTime(), new Date(customEnd).getTime()]
    : [now - (RANGE_MS[timeRange] || 3600000), now]
  const currentRange = TIME_RANGES.find((r) => r.value === timeRange) || TIME_RANGES[0]

  const cpuDetail = {
    cores: server.cpu_cores || 0,
    threads: server.cpu_cores || 0,
    model: server.extra_config?.cpu_model || '检测中...',
    current: (metrics?.cpu_percent || 0).toFixed(1),
  }

  const memPercent = metrics?.memory_percent || 0
  const memDetail = {
    total: server.total_memory_gb || 0,
    used: ((server.total_memory_gb || 0) * (memPercent / 100)).toFixed(1),
    available: ((server.total_memory_gb || 0) * ((100 - memPercent) / 100)).toFixed(1),
    percent: memPercent.toFixed(1),
  }

  // 头部「编辑」图标的权限点与各自列表页**完全一致**，不新造权限：
  const canEditThis = isNetworkDevice
    ? canPerm('sys', 'network_devices', 'edit', 'edit')
    : canPerm('sys', 'register', 'edit', 'edit')
  const canPower = canPerm('host', 'status', 'edit', 'power')
  const canSvcEdit = canPerm('host', 'services', 'edit')
  const canSvcConfig = canPerm('host', 'services', 'edit', 'config')
  const canTerminate = canPerm('host', 'services', 'edit', 'terminate')
  const manageable = canManage(serverId)

  const diskPercent = metrics?.disk_percent || 0
  const diskPartitions = server.disk_partitions && server.disk_partitions.length > 0
    ? server.disk_partitions
    : [{ name: '磁盘', total_gb: server.total_disk_gb || 0, used_gb: ((server.total_disk_gb || 0) * (diskPercent / 100)).toFixed(1), free_gb: ((server.total_disk_gb || 0) * ((100 - diskPercent) / 100)).toFixed(1), percent: diskPercent.toFixed(1), fstype: '', mount: '/' }]

  if (!manageable) {
    return (
      <div className="server-detail">
        <div className="no-access-page">
          <div className="no-access-icon"><Icon kind="ui-lock" size={32} /></div>
          <div className="no-access-text">该主机不在当前角色的管理范围内</div>
        </div>
      </div>
    )
  }

  return (
    <div className="server-detail">
      <div className="detail-topbar">
        <div className="detail-topbar-info">
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            {/* 标题 + 备注气泡：光标悬停主机名显示备注（server.description），移开自动收起。
                气泡 absolute 挂在标题下方；pointer-events:none 防止鼠标碰到气泡本身
                又被判成 leave → 一进一出地闪。 */}
            <span
              className="detail-title-wrap"
              onMouseEnter={onTitleEnter}
              onMouseLeave={onTitleLeave}
            >
              <h1 className="detail-title">{server.name}</h1>
              {noteTip && server.description && (
                <span className="detail-note-tip" role="tooltip">{server.description}</span>
              )}
            </span>
            {/* 编辑图标：插在「主机名 / 设备名」和「在线状态」之间（2026-09-22 需求）。
                主机弹 ServerFormModal，网络设备弹 EditDeviceModal；
                没有编辑权限就不显示（权限点同列表页）。 */}
            {canEditThis && (
              <button
                className="detail-edit-btn"
                onClick={openEdit}
                title={isNetworkDevice ? '编辑网络设备' : '编辑主机'}
                aria-label={isNetworkDevice ? '编辑网络设备' : '编辑主机'}
              >
                <Icon kind="ui-edit" size={15} />
              </button>
            )}
            <span className="status-pill" style={{ background: statusInfo.color }}>
              {statusInfo.label}
            </span>
          </div>
          <div className="detail-topbar-meta">
            <span>{osText || (isNetworkDevice ? '网络设备' : '未知系统')}</span>
            <span>IP: {server.ip_address}</span>
            <span>
              {isNetworkDevice
                ? `SNMP 采集 · 每 ${server.collect_period_sec || 300} 秒`
                : server.protocol === 'agent'
                  ? (server.extra_config?.computer_name || server.name)
                  : `${server.protocol}:${server.connection_port}`}
            </span>
          </div>
        </div>
        {/* 重启/关机是 Agent 能力，网络设备没有 Agent —— 不显示这个按钮 */}
        {canPower && !isNetworkDevice && (
          <div className="detail-topbar-actions">
            <div className="action-dropdown" ref={actionMenuRef}>
              <button
                className="btn-action-power"
                onClick={() => setActionMenuOpen(!actionMenuOpen)}
                title="点击选择重启/关机"
              >
                <Icon kind="ui-power" size={22} />
              </button>
              {actionMenuOpen && (
                <div className="action-dropdown-menu">
                  <button className="action-item action-danger" onClick={() => { setActionMenuOpen(false); setPowerConfirm({ action: 'restart' }); }}>
                    重启主机
                  </button>
                  <button className="action-item action-danger" onClick={() => { setActionMenuOpen(false); setPowerConfirm({ action: 'shutdown' }); }}>
                    关闭主机
                  </button>
                </div>
              )}
            </div>
          </div>
        )}
      </div>

      <div className="detail-tabs" ref={tabsRef}>
        {tabShow.status && (
          <button className={`detail-tab ${activeTab === 'status' ? 'active' : ''}`} onClick={() => setActiveTab('status')}>
            设备状态
          </button>
        )}
        {tabShow.info && (
          <button className={`detail-tab ${activeTab === 'info' ? 'active' : ''}`} onClick={() => setActiveTab('info')}>
            {/* 网络设备这里显示的是"设备系统及硬件信息"，沿用「系统信息」这个老名字 */}
            {isNetworkDevice ? '系统信息' : '设备信息'}
          </button>
        )}
        {tabShow.apps && (
          <button className={`detail-tab ${activeTab === 'apps' ? 'active' : ''}`} onClick={() => setActiveTab('apps')}>
            应用管理
          </button>
        )}
        {tabShow.services && (
          <button className={`detail-tab ${activeTab === 'services' ? 'active' : ''}`} onClick={() => setActiveTab('services')}>
            进程管理
          </button>
        )}
        {tabShow.resources && (
          <button className={`detail-tab ${activeTab === 'resources' ? 'active' : ''}`} onClick={() => setActiveTab('resources')}>
            资源管理
          </button>
        )}
        {tabShow.terminal && (
          <button className={`detail-tab ${activeTab === 'terminal' ? 'active' : ''}`} onClick={() => setActiveTab('terminal')}>
            WEB终端
          </button>
        )}
        {/* WEB管理只对网络设备 —— 这里再挡一道 isNetworkDevice，双保险：
            主机详情页绝不能出现这个页签（主机没有"设备自带的 Web 管理界面"） */}
        {tabShow.webadmin && isNetworkDevice && (
          <button className={`detail-tab ${activeTab === 'webadmin' ? 'active' : ''}`} onClick={() => setActiveTab('webadmin')}>
            WEB管理
          </button>
        )}
        {tabShow.rdp && (
          <button className={`detail-tab ${activeTab === 'rdp' ? 'active' : ''}`} onClick={() => setActiveTab('rdp')}>
            远程桌面
          </button>
        )}
        {tabShow.events && (
          <button className={`detail-tab ${activeTab === 'events' ? 'active' : ''}`} onClick={() => setActiveTab('events')}>
            事件日志
          </button>
        )}
      </div>

      {/* 网络设备：运行状态（CPU / 内存 / 端口流量图表 + 端口状态统计） */}
      {activeTab === 'status' && isNetworkDevice && (
        <NetworkDeviceStatus
          serverId={serverId}
          server={server}
          metrics={metrics}
          timeRange={timeRange}
          setTimeRange={setTimeRange}
          customStart={customStart}
          setCustomStart={setCustomStart}
          customEnd={customEnd}
          setCustomEnd={setCustomEnd}
          onCollect={() => { loadServer(); loadMetrics && loadMetrics() }}
        />
      )}

      {/* Live metrics — only on status tab（网络设备走自己的运行状态视图）
          主机侧：指标卡片行 + 周期横条 + 6 张图表收进同一张大卡片 */}
      {activeTab === 'status' && !isNetworkDevice && (
      <div className="status-wrap">
      <div className="metrics-row">
        <MetricCard
          icon="cpu"
          label="CPU 使用率"
          value={metrics?.cpu_percent?.toFixed(1)}
          unit="%"
          color={(metrics?.cpu_percent || 0) > 90 ? '#d9534f' : (metrics?.cpu_percent || 0) > 75 ? '#f0ad4e' : '#5cb85c'}
          sub={`${server.cpu_cores || '?'} 核`}
          detail={(
            <>
              <div className="mcard-detail-row" title={cpuDetail.model}>
                <span className="mcard-detail-k">型号</span>
                <span className="mcard-detail-v mcard-detail-ellipsis">{cpuDetail.model}</span>
              </div>
              <div className="mcard-detail-row">
                <span className="mcard-detail-k">核心</span>
                <span className="mcard-detail-v">{cpuDetail.cores} 核 / {cpuDetail.threads} 线程</span>
              </div>
            </>
          )}
        />
        <MetricCard
          icon="disk"
          label="磁盘使用率"
          value={metrics?.disk_percent?.toFixed(1)}
          unit="%"
          color={(metrics?.disk_percent || 0) > 95 ? '#d9534f' : (metrics?.disk_percent || 0) > 85 ? '#f0ad4e' : '#5cb85c'}
          sub={`${server.total_disk_gb || '?'} GB`}
          detail={(
            <>
              {diskPartitions.map((p, i) => (
                <div className="mcard-detail-row disk-row" key={i} title={`${p.mount || p.name}`}>
                  <span className="mcard-detail-k disk-name">{p.name}</span>
                  <div className="micro-bar">
                    <div
                      className="micro-bar-fill"
                      style={{
                        width: `${p.percent}%`,
                        background: p.percent > 90 ? '#d9534f' : p.percent > 80 ? '#f0ad4e' : '#5cb85c',
                      }}
                    />
                  </div>
                  <span className="mcard-detail-v disk-percent">{p.percent}%</span>
                </div>
              ))}
            </>
          )}
        />
        <MetricCard
          icon="memory"
          label="内存使用率"
          value={metrics?.memory_percent?.toFixed(1)}
          unit="%"
          color={(metrics?.memory_percent || 0) > 90 ? '#d9534f' : (metrics?.memory_percent || 0) > 80 ? '#f0ad4e' : '#5cb85c'}
          sub={`${server.total_memory_gb || '?'} GB`}
          detail={(
            <>
              <div className="mcard-detail-row">
                <span className="mcard-detail-k">总量</span>
                <span className="mcard-detail-v">{memDetail.total} GB</span>
              </div>
              <div className="mcard-detail-row memory-row">
                <span className="mcard-detail-k">使用率</span>
                <div className="micro-bar">
                  <div
                    className="micro-bar-fill"
                    style={{
                      width: `${memPercent}%`,
                      background: memPercent > 90 ? '#d9534f' : memPercent > 80 ? '#f0ad4e' : '#5cb85c',
                    }}
                  />
                </div>
                <span className="mcard-detail-v mem-percent">{memPercent.toFixed(1)}%</span>
              </div>
              <div className="mcard-detail-row">
                <span className="mcard-detail-k">已用</span>
                <span className="mcard-detail-v" style={{ color: '#d9534f' }}>{memDetail.used} GB</span>
                <span className="mcard-detail-k">可用</span>
                <span className="mcard-detail-v" style={{ color: '#5cb85c' }}>{memDetail.available} GB</span>
              </div>
            </>
          )}
        />
        <MetricCard
          icon="in"
          label="网络入站"
          value={metrics?.network_in_mbps?.toFixed(1)}
          unit="Mbps"
          color="#0275d8"
          detail={(
            <>
              <div className="mcard-detail-row">
                <span className="mcard-detail-k">流量</span>
                <span className="mcard-detail-v" style={{ color: '#0275d8' }}>{metrics?.network_in_mbps?.toFixed(2) ?? '--'} Mbps</span>
              </div>
              <div className="mcard-detail-row">
                <span className="mcard-detail-k">协议</span>
                <span className="mcard-detail-v">{server.protocol === 'agent' ? 'Agent' : `${server.protocol}:${server.connection_port}`}</span>
              </div>
            </>
          )}
        />
        <MetricCard
          icon="out"
          label="网络出站"
          value={metrics?.network_out_mbps?.toFixed(1)}
          unit="Mbps"
          color="#5cb85c"
          detail={(
            <>
              <div className="mcard-detail-row">
                <span className="mcard-detail-k">流量</span>
                <span className="mcard-detail-v" style={{ color: '#5cb85c' }}>{metrics?.network_out_mbps?.toFixed(2) ?? '--'} Mbps</span>
              </div>
              <div className="mcard-detail-row">
                <span className="mcard-detail-k">IP</span>
                <span className="mcard-detail-v">{server.ip_address}</span>
              </div>
            </>
          )}
        />
      </div>

      {/* 状态图表：周期工具栏 + 图表网格，紧跟在指标卡行下面，同属上面那张大卡片 */}
      <section className="status-panel">
      <div className="time-range-bar">
        <span className="time-range-label">周期：</span>
        {TIME_RANGES.map((r) => (
          <button
            key={r.value}
            className={`time-range-btn ${timeRange === r.value ? 'active' : ''}`}
            onClick={() => handleRangeChange(r.value)}
          >
            {r.label}
          </button>
        ))}
        <button
          className={`time-range-btn ${timeRange === 'custom' ? 'active' : ''}`}
          onClick={() => handleRangeChange('custom')}
        >
          自定义
        </button>
        {timeRange === 'custom' && (
          <div className="custom-range">
            <DateTimeInput value={customStart} onChange={(iso) => setCustomStart(iso)} />
            <span>至</span>
            <DateTimeInput value={customEnd} onChange={(iso) => setCustomEnd(iso)} />
          </div>
        )}
      </div>

      <div className="charts-grid">
        <TimeChart
          title="CPU 使用率（%）"
          data={history}
          dataKeys={[{ key: 'cpu_percent', label: 'CPU %' }]}
          colors={['#0275d8']}
          xDomain={xDomain}
          sampleInterval={currentRange.sample}
          yUnit="%"
        />
        <TimeChart
          title="内存使用率（%）"
          data={history}
          dataKeys={[{ key: 'memory_percent', label: '内存 %' }]}
          colors={['#5cb85c']}
          xDomain={xDomain}
          sampleInterval={currentRange.sample}
          yUnit="%"
        />
        <TimeChart
          title="磁盘使用率（%）"
          data={history}
          dataKeys={[{ key: 'disk_percent', label: '磁盘 %' }]}
          colors={['#f0ad4e']}
          xDomain={xDomain}
          sampleInterval={currentRange.sample}
          yUnit="%"
        />
        <TimeChart
          title="磁盘 I/O（MB/s）"
          data={history}
          dataKeys={[
            { key: 'disk_io_read_mbps', label: '读取' },
            { key: 'disk_io_write_mbps', label: '写入' },
          ]}
          colors={['#0275d8', '#f0ad4e']}
          xDomain={xDomain}
          sampleInterval={currentRange.sample}
          showLegend
          yUnit="MB/s"
        />
        <TimeChart
          title="网络流量（Mbps）"
          data={history}
          dataKeys={[
            { key: 'network_in_mbps', label: '入站' },
            { key: 'network_out_mbps', label: '出站' },
          ]}
          colors={['#0275d8', '#5cb85c']}
          xDomain={xDomain}
          sampleInterval={currentRange.sample}
          showLegend
          yUnit="Mbps"
        />
        <TimeChart
          title="TCP 连接数"
          data={history}
          dataKeys={[{ key: 'tcp_connections', label: '连接数' }]}
          colors={['#5cb85c']}
          xDomain={xDomain}
          sampleInterval={currentRange.sample}
          yUnit=""
        />
      </div>
      </section>
      </div>
      )}

      {activeTab === 'services' && (
        (() => {
          const allServices = (pendingServices || []).map(s => {
            const detailed = s.detailed_category || (
              s.is_system || s.category === 'system' ? 'core_system' :
              s.category === 'service' ? 'third_party_service' : 'user_process'
            )
            return {
              id: s.id || `pending_${s.name}_${s.port || 0}`,
              name: s.display_name || s.name,
              image_name: s.image_name || s.process_name || s.name,
              process_name: s.process_name,
              path: joinPath(s.path, s.image_name || s.process_name || s.name) || s.path || '',
              alive_status: s.alive_status || (s.status === 'running' ? 'running' : 'unknown'),
              alert_status: s.alert_status || 'normal',
              category: s.category || 'user',
              is_system: s.is_system || s.category === 'system' || false,
              detailed_category: detailed,
              operation_level: s.operation_level || (
                detailed === 'core_system' ? 'view_only' :
                detailed === 'system_service' || detailed === 'third_party_service' ? 'terminate_with_confirm' : 'full'
              ),
              cpu_percent: s.cpu_percent ?? 0,
              memory_percent: s.memory_percent ?? 0,
              memory_used_mb: s.memory_used_mb ?? 0,
              disk_mbps: s.disk_mbps ?? 0,
              disk_read_mbps: s.disk_read_mbps ?? 0,
              disk_write_mbps: s.disk_write_mbps ?? 0,
              network_mbps: s.network_mbps ?? 0,
              network_in_mbps: s.network_in_mbps ?? 0,
              network_out_mbps: s.network_out_mbps ?? 0,
              pid: s.pid || 0,
              ppid: s.ppid || 0,
              port: s.port || 0,
              start_time: s.start_time || '',
              cmdline: s.cmdline || '',
              username: s.username || '',
              history: Array.isArray(s.history) ? s.history : [],
            }
          })

          // Category filter: all / user_process / third_party_service / system_service / core_system
          const categoryFilteredServices = allServices.filter((s) => {
            if (processCategoryTab === 'all') return true
            return s.detailed_category === processCategoryTab
          })

          const filter = server.extra_config?.service_filter
          const filteredServices = applyServiceFilter(categoryFilteredServices, filter)
          const isFilterActive = filter?.enabled && filter?.rules?.length > 0

          const searchedServices = processSearchActive
            ? filteredServices.filter((s) => {
                const k = processSearchActive
                const text = [
                  s.name,
                  s.image_name,
                  s.process_name,
                  s.path,
                  s.cmdline,
                  s.username,
                ]
                  .filter(Boolean)
                  .join('\n')
                  .toLowerCase()
                return (
                  text.includes(k) ||
                  String(s.pid).includes(k) ||
                  String(s.port).includes(k)
                )
              })
            : filteredServices
          const isSearchActive = processSearchActive.length > 0

          const sortedServices = [...searchedServices].sort((a, b) => {
            if (!serviceSort.column) return 0
            const col = serviceSort.column
            const dir = serviceSort.direction === 'asc' ? 1 : -1
            const va = a[col] ?? ''
            const vb = b[col] ?? ''
            if (typeof va === 'number' && typeof vb === 'number') {
              return (va - vb) * dir
            }
            return String(va).localeCompare(String(vb), 'zh-CN') * dir
          })

          const groups = (() => {
            const map = new Map()
            sortedServices.forEach((s, idx) => {
              const key = (s.app_instance_id || s.image_name || s.name || '').toLowerCase()
              if (!map.has(key)) map.set(key, { key, items: [], firstIdx: idx })
              map.get(key).items.push(s)
            })
            const arr = []
            map.forEach((g) => {
              if (g.items.length <= 1) {
                arr.push({ type: 'single', key: g.key, main: g.items[0], firstIdx: g.firstIdx })
                return
              }

              const isInteractiveShell = (pid) => pid === 0 || pid === 1
              const itemsWithRole = g.items.map((s) => {
                const hasWindow = s.has_visible_window
                const ppid = s.ppid || 0
                const cmdline = (s.cmdline || '').toLowerCase()
                const image = (s.image_name || '').toLowerCase()

                const childMarkers = [
                  '--type=renderer', '--type=gpu', '--type=utility', '--type=broker',
                  '--type=crashpad', '--type=service', '--type=worker',
                  '/service', '-service', '--service',
                ]
                const isChildByCmdline = childMarkers.some((m) => cmdline.includes(m))

                const parentMarkers = ['--type=browser', '--main', '/foreground']
                const isParentByCmdline = parentMarkers.some((m) => cmdline.includes(m))

                if (isParentByCmdline || (hasWindow && !isInteractiveShell(ppid))) {
                  return { item: s, role: 'main', score: 100 }
                }
                if (isChildByCmdline) {
                  return { item: s, role: 'service', score: 30 }
                }
                if (hasWindow) {
                  return { item: s, role: 'main', score: 80 }
                }
                if (ppid === 0 || ppid === 1) {
                  return { item: s, role: 'service', score: 40 }
                }
                return { item: s, role: 'service', score: 20 }
              })

              itemsWithRole.sort((a, b) => {
                if (b.score !== a.score) return b.score - a.score
                return (b.item.memory_percent || 0) - (a.item.memory_percent || 0)
              })
              const mainWrapper = itemsWithRole[0]
              const main = mainWrapper.item
              const mainRole = mainWrapper.role

              const children = itemsWithRole
                .slice(1)
                .map((w) => ({ child: w.item, role: w.role }))
                .sort((a, b) => (b.child.memory_percent || 0) - (a.child.memory_percent || 0))

              arr.push({
                type: 'group',
                key: g.key,
                main,
                mainRole,
                children,
                size: g.items.length,
                firstIdx: g.firstIdx,
              })
            })
            arr.sort((a, b) => a.firstIdx - b.firstIdx)
            return arr
          })()

          const processTotal = groups.length
          const processTotalPages = Math.max(1, Math.ceil(processTotal / processPageSize))
          const safePage = Math.min(processPage, processTotalPages)
          const processStartIndex = (safePage - 1) * processPageSize
          const processEndIndex = Math.min(processStartIndex + processPageSize, processTotal)
          const pagedGroups = groups.slice(processStartIndex, processEndIndex)
          const toggleExpandedProcess = (id) => {
            setExpandedProcessIds((prev) => {
              const next = new Set(prev)
              if (next.has(id)) next.delete(id)
              else next.add(id)
              return next
            })
          }
          const toggleGroup = (key) => {
            setExpandedGroups((prev) => {
              const next = new Set(prev)
              if (next.has(key)) next.delete(key)
              else next.add(key)
              return next
            })
          }

          const renderProcessRow = (svc, options = {}) => {
            const {
              key,
              isChild = false,
              groupTag = null,
              isParent = false,
              groupExpanded = false,
              groupSize = 1,
              onToggleGroup = null,
              groupChildren = null,
            } = options
            if (hiddenProcessIds.has(svc.id)) return null
            const action = processActions[svc.id]
            const isKilling = action?.state === 'killing'
            const statusLabel = action ? PROCESS_ACTION_STATUS[action.state]?.label : null
            const isExpanded = expandedProcessIds.has(svc.id)
            return (
              <React.Fragment key={key || svc.id}>
                <tr
                  className={`svc-row ${action ? `svc-row-${action.state}` : ''} svc-row-${svc.detailed_category} ${isChild ? 'svc-row-child' : ''}`}
                  onClick={(e) => {
                    if (e.target.closest('button, .col-action, .svc-expand-btn')) return
                    toggleExpandedProcess(svc.id)
                  }}
                >
                  <td className="col-name">
                    <div className="svc-name-row">
                      {isParent ? (
                        <button
                          className={`svc-expand-btn ${groupExpanded ? 'expanded' : ''}`}
                          onClick={(e) => { e.stopPropagation(); onToggleGroup && onToggleGroup() }}
                        >
                          {groupExpanded ? <Icon kind="ui-chevron-down" size={10} /> : <Icon kind="ui-chevron-right" size={10} />}
                        </button>
                      ) : (
                        <button
                          className={`svc-expand-btn ${isExpanded ? 'expanded' : ''}`}
                          onClick={(e) => { e.stopPropagation(); toggleExpandedProcess(svc.id) }}
                        >
                          {isExpanded ? <Icon kind="ui-chevron-down" size={10} /> : <Icon kind="ui-chevron-right" size={10} />}
                        </button>
                      )}
                      <div className="svc-name-stack">
                        <div className="svc-name">
                          {svc.name}
                          {groupTag && <span className="svc-group-tag">{groupTag}</span>}
                          {isParent && <span className="svc-group-count">{groupSize} 进程</span>}
                        </div>
                        {statusLabel && <div className="svc-action-label" style={{ color: PROCESS_ACTION_STATUS[action.state].color }}>{statusLabel}</div>}
                      </div>
                    </div>
                  </td>
                  <td className="col-image">{svc.image_name || svc.process_name || '-'}</td>
                  <td className="col-status"><StatusTextBadge status={svc.alive_status} type="alive" /></td>
                  <td className="col-path" title={svc.path || '-'}>{svc.path || '-'}</td>
                  <td className="col-metric">
                    <MetricCell value={svc.cpu_percent} unit="%" history={svc.history} dataKey="cpu_percent" color="#0275d8" />
                  </td>
                  <td className="col-metric">
                    <MetricCell value={svc.memory_percent} unit="%" history={svc.history} dataKey="memory_percent" color="#5cb85c" />
                  </td>
                  <td className="col-metric">
                    <MetricCell value={svc.disk_mbps} unit=" MB/秒" history={svc.history} dataKey="disk_mbps" color="#f0ad4e" />
                  </td>
                  <td className="col-metric">
                    <MetricCell value={svc.network_mbps} unit=" Mbps" history={svc.history} dataKey="network_mbps" color="#5cb85c" />
                  </td>
                  <td className="col-pid">{svc.pid > 0 ? svc.pid : '-'}</td>
                  <td className="col-port">{svc.port > 0 ? svc.port : '-'}</td>
                  <td className="col-status"><StatusTextBadge status={svc.alert_status} type="alert" /></td>
                  <td className="col-action">
                    {!canTerminate ? null : svc.operation_level === 'view_only' ? (
                      <span className="terminate-btn terminate-disabled" title="禁操（仅查看）">
                        <TerminateIcon />
                      </span>
                    ) : isParent && groupChildren && groupChildren.length > 0 ? (
                      <button
                        className="terminate-btn terminate-group-btn"
                        title="终止进程组"
                        onClick={(e) => { e.stopPropagation(); if (!isKilling) setGroupTerminateModal({ main: svc, children: groupChildren }) }}
                        disabled={isKilling}
                      >
                        {isKilling ? (
                          <span className="terminate-spinner">
                            <Icon kind="ui-spinner" size={16} />
                          </span>
                        ) : (
                          <TerminateIcon variant="x" />
                        )}
                      </button>
                    ) : (
                      <button
                        className="terminate-btn"
                        onClick={(e) => { e.stopPropagation(); if (!isKilling) setTerminateModal(svc) }}
                        disabled={isKilling}
                      >
                        {isKilling ? (
                          <span className="terminate-spinner">
                            <Icon kind="ui-spinner" size={16} />
                          </span>
                        ) : (
                          <TerminateIcon />
                        )}
                      </button>
                    )}
                  </td>
                </tr>
                {isExpanded && (
                  <tr className="svc-detail-row">
                    <td colSpan="12">
                      <div className="svc-detail-grid">
                        <div className="svc-detail-item">
                          <span className="svc-detail-label">启动时间</span>
                          <span className="svc-detail-value">{formatDateTimeShort(svc.start_time)}</span>
                        </div>
                        <div className="svc-detail-item">
                          <span className="svc-detail-label">所属用户</span>
                          <span className="svc-detail-value">{svc.username || '-'}</span>
                        </div>
                        <div className="svc-detail-item">
                          <span className="svc-detail-label">父进程 PID</span>
                          <span className="svc-detail-value">{svc.ppid > 0 ? svc.ppid : '-'}</span>
                        </div>
                        <div className="svc-detail-item">
                          <span className="svc-detail-label">磁盘读取</span>
                          <span className="svc-detail-value">{(svc.disk_read_mbps || 0).toFixed(2)} MB/s</span>
                        </div>
                        <div className="svc-detail-item">
                          <span className="svc-detail-label">磁盘写入</span>
                          <span className="svc-detail-value">{(svc.disk_write_mbps || 0).toFixed(2)} MB/s</span>
                        </div>
                        <div className="svc-detail-item">
                          <span className="svc-detail-label">网络入站</span>
                          <span className="svc-detail-value">{(svc.network_in_mbps || 0).toFixed(2)} Mbps</span>
                        </div>
                        <div className="svc-detail-item">
                          <span className="svc-detail-label">网络出站</span>
                          <span className="svc-detail-value">{(svc.network_out_mbps || 0).toFixed(2)} Mbps</span>
                        </div>
                        <div className="svc-detail-item wide">
                          <span className="svc-detail-label">命令行</span>
                          <span className="svc-detail-value cmdline">{svc.cmdline || '-'}</span>
                        </div>
                        {isParent && groupChildren && groupChildren.length > 0 && (
                          <div className="svc-detail-item wide">
                            <span className="svc-detail-label">子进程资源占比</span>
                            <span className="svc-detail-value">
                              {(() => {
                                const all = [svc, ...groupChildren.map((c) => c.child)]
                                const totalMem = all.reduce((sum, p) => sum + (p.memory_percent || 0), 0) || 1
                                const totalCpu = all.reduce((sum, p) => sum + (p.cpu_percent || 0), 0) || 1
                                const totalDisk = all.reduce((sum, p) => sum + (p.disk_mbps || 0), 0) || 1
                                const totalNet = all.reduce((sum, p) => sum + (p.network_mbps || 0), 0) || 1
                                const colors = ['#0275d8', '#5cb85c', '#f0ad4e', '#d9534f', '#6f42c1', '#20c997']
                                const items = [
                                  { label: 'CPU', total: totalCpu, key: 'cpu_percent' },
                                  { label: '内存', total: totalMem, key: 'memory_percent' },
                                  { label: '磁盘', total: totalDisk, key: 'disk_mbps' },
                                  { label: '网络', total: totalNet, key: 'network_mbps' },
                                ]
                                return (
                                  <div className="resource-share-grid">
                                    {items.map((item) => {
                                      if (item.total <= 0) return null
                                      return (
                                        <div key={item.label} className="resource-share-row">
                                          <span className="resource-share-label">{item.label}</span>
                                          <div className="resource-share-bar">
                                            {all.map((p, idx) => {
                                              const v = p[item.key] || 0
                                              const pct = Math.max(0, Math.min(100, (v / item.total) * 100))
                                              if (pct < 0.5) return null
                                              return (
                                                <div
                                                  key={p.id}
                                                  className="resource-share-segment"
                                                  style={{
                                                    width: `${pct}%`,
                                                    backgroundColor: colors[idx % colors.length],
                                                  }}
                                                  title={`PID ${p.pid} ${p.name}: ${v.toFixed(1)} (${pct.toFixed(1)}%)`}
                                                />
                                              )
                                            })}
                                          </div>
                                          <span className="resource-share-total">{item.total.toFixed(1)}</span>
                                        </div>
                                      )
                                    })}
                                    <div className="resource-share-legend">
                                      {all.map((p, idx) => (
                                        <span key={p.id} className="resource-share-legend-item">
                                          <span className="resource-share-dot" style={{ backgroundColor: colors[idx % colors.length] }} />
                                          PID {p.pid} {p.name}
                                        </span>
                                      ))}
                                    </div>
                                  </div>
                                )
                              })()}
                            </span>
                          </div>
                        )}
                      </div>
                    </td>
                  </tr>
                )}
              </React.Fragment>
            )
          }

          return (
            <div className="service-monitor-full">
                  <div className="service-monitor-header">
                    <div className="service-monitor-title-row">
                      <h3 className="panel-title">进程管理</h3>
                      <div className="service-monitor-subtitle-stack">
                        {isFilterActive && (
                          <span className="filter-active-badge">已启用筛选</span>
                        )}
                        {isSearchActive && (
                          <span className="filter-active-badge" style={{ background: '#e7f3ff', color: '#004085' }}>
                            搜索: {processSearchActive}
                          </span>
                        )}
                        {(isBlacklistActive || isWhitelistActive) && (
                          <span className="filter-active-badge" style={{ background: '#fff3cd', color: '#856404' }}>
                            黑白名单已启用
                          </span>
                        )}
                      </div>
                    </div>
                    {canSvcEdit && (
                      <div className="service-monitor-actions">
                        <div className="process-search-box">
                          <input
                            type="text"
                            className="process-search-input"
                            placeholder="搜索进程..."
                            value={processSearchKeyword}
                            onChange={(e) => setProcessSearchKeyword(e.target.value)}
                            onKeyDown={(e) => {
                              if (e.key === 'Enter') {
                                setProcessSearchActive(processSearchKeyword.trim().toLowerCase())
                              }
                            }}
                          />
                          <button
                            className="btn-edit-server process-search-btn"
                            onClick={() => setProcessSearchActive(processSearchKeyword.trim().toLowerCase())}
                          >
                            搜索
                          </button>
                          {isSearchActive && (
                            <button
                              className="btn-edit-server process-search-clear"
                              onClick={() => { setProcessSearchKeyword(''); setProcessSearchActive('') }}
                            >
                              清除
                            </button>
                          )}
                        </div>
                        {(() => {
                      const groupKeys = groups.filter((g) => g.type === 'group').map((g) => g.key)
                      const allExpanded = groupKeys.length > 0 && groupKeys.every((k) => expandedGroups.has(k))
                      return (
                        <button
                          className="btn-edit-server group-toggle-btn"
                          onClick={() => {
                            if (allExpanded) {
                              setExpandedGroups(new Set())
                            } else {
                              setExpandedGroups(new Set(groupKeys))
                            }
                          }}
                          title={allExpanded ? '收起所有分组' : '展开所有分组'}
                        >
                          {allExpanded ? '平铺' : '分组'}
                        </button>
                      )
                    })()}
                    {canSvcConfig && (
                    <button
                          className="btn-edit-server"
                          onClick={() => setShowWhitelistModal(true)}
                        >
                      白名单
                      {isWhitelistActive && <span className="blacklist-badge" style={{ background: '#28a745' }}>{whitelist.length}</span>}
                    </button>
                    )}
                    {canSvcConfig && (
                    <button
                      className="btn-edit-server"
                      onClick={() => setShowBlacklistModal(true)}
                    >
                      黑名单
                      {isBlacklistActive && <span className="blacklist-badge">{blacklist.length}</span>}
                    </button>
                    )}
                    <select
                      className="refresh-interval-select"
                      value={serviceRefreshInterval}
                      onChange={(e) => setServiceRefreshInterval(Number(e.target.value))}
                      title="自动刷新周期"
                    >
                      <option value={5}>5秒刷新</option>
                      <option value={10}>10秒刷新</option>
                      <option value={60}>60秒刷新</option>
                    </select>
                    <button
                      className="reg-refresh-btn"
                      onClick={handleRefreshServices}
                      disabled={refreshingServices}
                    >
                      {refreshingServices ? '刷新中...' : '手动刷新'}
                    </button>
                    {canSvcConfig && (
                    <button className="btn-edit-server" onClick={() => setShowServiceConfig(true)}>
                      筛选
                    </button>
                    )}
                  </div>
                )}
              </div>
              {refreshSlow && (
                <div className="service-refresh-slow">
                  加载较慢，仍在获取 Agent 最新进程数据...
                </div>
              )}
              {(() => {
                const stats = {}
                allServices.forEach((s) => {
                  const c = s.detailed_category || 'user_process'
                  if (!stats[c]) stats[c] = { count: 0, cpu: 0, mem: 0, disk: 0, net: 0 }
                  stats[c].count += 1
                  stats[c].cpu += s.cpu_percent || 0
                  stats[c].mem += s.memory_percent || 0
                  stats[c].disk += s.disk_mbps || 0
                  stats[c].net += s.network_mbps || 0
                })
                const total = allServices.length
                const totalStats = { count: total, cpu: 0, mem: 0, disk: 0, net: 0 }
                allServices.forEach((s) => {
                  totalStats.cpu += s.cpu_percent || 0
                  totalStats.mem += s.memory_percent || 0
                  totalStats.disk += s.disk_mbps || 0
                  totalStats.net += s.network_mbps || 0
                })
                return (
                  <div className="process-category-summary">
                    <button
                      className={`process-summary-card all-card ${processCategoryTab === 'all' ? 'active' : ''}`}
                      onClick={() => setProcessCategoryTab('all')}
                    >
                      <span className="summary-dot" style={{ background: '#333' }} />
                      <span className="summary-name">全部进程</span>
                      <span className="summary-count">{totalStats.count}</span>
                      <div className="summary-sub">
                        <div>CPU {totalStats.cpu.toFixed(1)}% · 内存 {totalStats.mem.toFixed(1)}%</div>
                        <div>磁盘 {totalStats.disk.toFixed(1)} MB/s · 网络 {totalStats.net.toFixed(1)} Mbps</div>
                      </div>
                    </button>
                    {Object.entries(CATEGORY_META).map(([key, meta]) => {
                      const st = stats[key] || { count: 0, cpu: 0, mem: 0, disk: 0, net: 0 }
                      return (
                        <button
                          key={key}
                          className={`process-summary-card ${processCategoryTab === key ? 'active' : ''}`}
                          onClick={() => setProcessCategoryTab(key)}
                        >
                          <span className="summary-dot" style={{ background: meta.color }} />
                          <span className="summary-name">{meta.label}</span>
                          <span className="summary-count">{st.count}</span>
                          <div className="summary-sub">
                            <div>CPU {st.cpu.toFixed(1)}% · 内存 {st.mem.toFixed(1)}%</div>
                            <div>磁盘 {st.disk.toFixed(1)} MB/s · 网络 {st.net.toFixed(1)} Mbps</div>
                          </div>
                        </button>
                      )
                    })}
                  </div>
                )
              })()}
              <div className="service-table-wrap">
                <table className="service-table">
                  <colgroup>
                    {PROCESS_COLUMNS.map((col) => (
                      <col
                        key={col.key}
                        style={{
                          width: columnWidths[col.key] || col.width,
                          minWidth: col.minWidth,
                        }}
                      />
                    ))}
                  </colgroup>
                  <thead>
                    <tr>
                      {PROCESS_COLUMNS.map((col) => (
                        <th
                          key={col.key}
                          className={`${col.className} ${col.resizable ? 'resizable' : ''} ${resizingCol === col.key ? 'resizing' : ''}`}
                        >
                          {col.field ? (
                            <SortHeader label={col.label} field={col.field} sort={serviceSort} onSort={handleSort} />
                          ) : (
                            col.label
                          )}
                          {col.resizable && (
                            <span
                              className="col-resize-handle"
                              title="拖动调整列宽"
                              onMouseDown={(e) => {
                                e.preventDefault()
                                e.stopPropagation()
                                const th = e.currentTarget.parentElement
                                if (!th) return
                                const rect = th.getBoundingClientRect()
                                resizeStartXRef.current = e.clientX
                                resizeStartWidthRef.current = rect.width
                                setResizingCol(col.key)
                              }}
                            />
                          )}
                        </th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {refreshingServices && pagedServices.length === 0 ? (
                      <>
                        <ProcessSkeletonRow />
                        <ProcessSkeletonRow />
                        <ProcessSkeletonRow />
                        <ProcessSkeletonRow />
                        <ProcessSkeletonRow />
                        <ProcessSkeletonRow />
                      </>
                    ) : pagedGroups.length > 0 ? (
                      pagedGroups.map((g) => {
                        if (g.type === 'single') {
                          return renderProcessRow(g.main, { key: g.key })
                        }
                        const groupExpanded = expandedGroups.has(g.key)
                        const parentTag = g.mainRole === 'main' ? '主程序' : '进程组'
                        return (
                          <React.Fragment key={g.key}>
                            {renderProcessRow(g.main, {
                              key: `${g.key}-main`,
                              isParent: true,
                              groupTag: parentTag,
                              groupExpanded,
                              groupSize: g.size,
                              onToggleGroup: () => toggleGroup(g.key),
                              groupChildren: g.children,
                            })}
                            {groupExpanded && g.children.map(({ child, role }) => {
                              const childTag = role === 'main' ? '主程序' : '后台服务'
                              return renderProcessRow(child, {
                                key: `${g.key}-${child.id}`,
                                isChild: true,
                                groupTag: childTag,
                              })
                            })}
                          </React.Fragment>
                        )
                      })
                    ) : (
                      <tr>
                        <td colSpan="12" className="empty-row">
                          {allServices.length > 0 ? '当前筛选条件下无匹配进程' : 'Agent 尚未推送进程数据'}
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
              <div className="service-table-footer">
                <div className="service-table-status">
                  <span>共 {allServices.length} 进程 / {processTotal} 分组</span>
                  <span className="status-divider">·</span>
                  <span>每 {serviceRefreshInterval} 秒刷新</span>
                  {processTotal > 0 && (
                    <>
                      <span className="status-divider">·</span>
                      <span>第 {processStartIndex + 1}-{processEndIndex} 分组</span>
                    </>
                  )}
                </div>
                <div className="service-table-pagination">
                  <select
                    className="page-size-select"
                    value={processPageSize}
                    onChange={(e) => {
                      setProcessPageSize(Number(e.target.value))
                      setProcessPage(1)
                    }}
                    title="每页条数"
                  >
                    <option value={20}>20 条/页</option>
                    <option value={50}>50 条/页</option>
                    <option value={100}>100 条/页</option>
                    <option value={200}>200 条/页</option>
                  </select>
                  <button
                    className="page-btn"
                    onClick={() => setProcessPage((p) => Math.max(1, p - 1))}
                    disabled={safePage <= 1}
                    title="上一页"
                  >
                    ‹
                  </button>
                  <span className="page-info">
                    {safePage} / {processTotalPages}
                  </span>
                  <button
                    className="page-btn"
                    onClick={() => setProcessPage((p) => Math.min(processTotalPages, p + 1))}
                    disabled={safePage >= processTotalPages}
                    title="下一页"
                  >
                    ›
                  </button>
                </div>
              </div>
            </div>
          )
        })()
      )}

      {/* 系统信息：网络设备显示设备系统及硬件信息（sysDescr / 资产 / 端口表 / SSH 指纹） */}
      {activeTab === 'info' && isNetworkDevice && (
        <NetworkPanel serverId={serverId} server={server} mode="info" />
      )}

      {activeTab === 'info' && !isNetworkDevice && (
        <HostInfo serverId={serverId} serverName={server?.name} />
      )}

      {activeTab === 'apps' && (
        <ApplicationManager serverId={serverId} />
      )}

      {activeTab === 'resources' && (
        <ResourceManager serverId={serverId} />
      )}

      {activeTab === 'terminal' && (
        <WebTerminal serverId={serverId} network={isNetworkDevice} />
      )}

      {/* WEB管理：设备自带的 Web 界面 —— 服务端反向代理后嵌在这里（仅网络设备） */}
      {activeTab === 'webadmin' && isNetworkDevice && (
        <NetworkWebAdmin serverId={serverId} />
      )}

      {activeTab === 'rdp' && (
        <RemoteDesktop
          serverId={serverId}
          serverName={server?.name}
          onClose={() => setActiveTab('status')}
        />
      )}

      {/* 事件日志：网络设备没有 Windows 事件日志，显示服务端记录的告警 + 审计 */}
      {activeTab === 'events' && isNetworkDevice && (
        <NetworkEventLogs serverId={serverId} server={server} />
      )}

      {activeTab === 'events' && !isNetworkDevice && (
        <EventLogs serverId={serverId} />
      )}

      <ServiceConfigModal
        visible={showServiceConfig}
        onClose={() => setShowServiceConfig(false)}
        serverId={serverId}
        services={services}
        pendingServices={[...(pendingServices || []), ...(dangerousPorts || [])]}
        onRefresh={() => { loadServer(); loadServices() }}
        filter={server.extra_config?.service_filter}
      />

      {/* 头部「编辑」图标点开的两个弹窗（2026-09-22）：
          主机复用「注册管理」的 ServerFormModal，但**不传 onDelete** ——
          详情页里没有"删除主机"这个动作（删主机仍在注册管理做）。 */}
      <ServerFormModal
        visible={!!editHost}
        onClose={() => setEditHost(null)}
        onSubmit={submitHostEdit}
        initialData={editHost}
      />

      {editDevice && (
        <EditDeviceModal
          device={editDevice}
          onClose={() => setEditDevice(null)}
          onSaved={loadServer}
        />
      )}

      {terminateModal && (
        <div className="terminate-modal-overlay" onClick={() => setTerminateModal(null)}>
          <div className="terminate-modal" onClick={(e) => e.stopPropagation()}>
            <div className="terminate-modal-header">
              <h3>{terminateModal.operation_level === 'full' ? '关闭进程' : '终止进程（需确认）'}</h3>
              <button className="modal-close-btn" onClick={() => setTerminateModal(null)}><Icon kind="ui-close" size={18} /></button>
            </div>
            <div className="terminate-modal-body">
              <p>
                确定要{terminateModal.operation_level === 'full' ? '关闭' : '终止'} <b>{terminateModal.name}</b> 吗？
                {terminateModal.operation_level !== 'full' && (
                  <span className="terminate-warning-hint">该进程属于{CATEGORY_META[terminateModal.detailed_category]?.label || '系统/服务'}，操作前请确认影响范围。</span>
                )}
              </p>
              <div className="terminate-modal-actions">
                <button className="btn-terminate-graceful" onClick={() => handleTerminate('graceful')}>
                  退出进程
                </button>
                <button className="btn-terminate-force" onClick={() => handleTerminate('force')}>
                  强制终止
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {groupTerminateModal && (
        <div className="terminate-modal-overlay" onClick={() => setGroupTerminateModal(null)}>
          <div className="terminate-modal group-terminate-modal" onClick={(e) => e.stopPropagation()}>
            <div className="terminate-modal-header">
              <h3>终止进程组</h3>
              <button className="modal-close-btn" onClick={() => setGroupTerminateModal(null)}><Icon kind="ui-close" size={18} /></button>
            </div>
            <div className="terminate-modal-body">
              <p>
                即将终止 <b>{groupTerminateModal.main.name}</b> 进程组，共 {groupTerminateModal.children.length + 1} 个进程：
              </p>
              <div className="group-terminate-list">
                {[groupTerminateModal.main, ...groupTerminateModal.children.map((c) => c.child)].map((s) => (
                  <div key={s.id} className="group-terminate-item">
                    <span className="group-terminate-pid">PID {s.pid}</span>
                    <span className="group-terminate-name" title={s.cmdline}>{s.name}</span>
                    <span className="group-terminate-mem">内存 {(s.memory_percent || 0).toFixed(1)}%</span>
                    <span className="group-terminate-cpu">CPU {(s.cpu_percent || 0).toFixed(1)}%</span>
                    {s.operation_level === 'view_only' && <span className="group-terminate-skip">跳过</span>}
                  </div>
                ))}
              </div>
              <p className="terminate-warning-hint">进程组终止会同时结束所有列出的进程，请确认影响范围。</p>
              <div className="terminate-modal-actions">
                <button className="btn-terminate-graceful" onClick={() => handleGroupTerminate('graceful')}>
                  退出进程组
                </button>
                <button className="btn-terminate-force" onClick={() => handleGroupTerminate('force')}>
                  强制终止进程组
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {showBlacklistModal && (
        <div className="terminate-modal-overlay" onClick={() => setShowBlacklistModal(false)}>
          <div className="terminate-modal blacklist-modal" onClick={(e) => e.stopPropagation()}>
            <div className="terminate-modal-header">
              <h3>进程黑名单</h3>
              <button className="modal-close-btn" onClick={() => setShowBlacklistModal(false)}><Icon kind="ui-close" size={18} /></button>
            </div>
            <div className="terminate-modal-body">
              <p className="modal-hint">Agent 采集时发现匹配进程会立即强制退出。</p>
              <form className="blacklist-form" onSubmit={handleAddBlacklist}>
                <input
                  type="text"
                  className="blacklist-input"
                  placeholder="进程名称，如 notepad、chrome"
                  value={blacklistForm.pattern}
                  onChange={(e) => setBlacklistForm((prev) => ({ ...prev, pattern: e.target.value }))}
                />
                <select
                  className="blacklist-select"
                  value={blacklistForm.match_type}
                  onChange={(e) => setBlacklistForm((prev) => ({ ...prev, match_type: e.target.value }))}
                >
                  <option value="contains">包含</option>
                  <option value="exact">等于</option>
                  <option value="startswith">开头</option>
                  <option value="endswith">结尾</option>
                  <option value="regex">正则</option>
                </select>
                <button type="submit" className="btn-edit-server" disabled={savingBlacklist}>
                  {savingBlacklist ? '保存中...' : '添加'}
                </button>
              </form>
              <div className="blacklist-list">
                {blacklist.length === 0 ? (
                  <div className="blacklist-empty">暂无黑名单规则</div>
                ) : (
                  blacklist.map((rule) => (
                    <div key={rule.id} className="blacklist-item">
                      <span className="blacklist-pattern" title={rule.pattern}>{rule.pattern}</span>
                      <span className="blacklist-match">{rule.match_type || 'contains'}</span>
                      <button
                        className="blacklist-remove"
                        onClick={() => handleRemoveBlacklist(rule.id)}
                        title="移除"
                      >
                        <Icon kind="ui-close" size={13} />
                      </button>
                    </div>
                  ))
                )}
              </div>
            </div>
          </div>
        </div>
      )}

      {showWhitelistModal && (
        <div className="terminate-modal-overlay" onClick={() => setShowWhitelistModal(false)}>
          <div className="terminate-modal blacklist-modal" onClick={(e) => e.stopPropagation()}>
            <div className="terminate-modal-header">
              <h3>进程白名单</h3>
              <button className="modal-close-btn" onClick={() => setShowWhitelistModal(false)}><Icon kind="ui-close" size={18} /></button>
            </div>
            <div className="terminate-modal-body">
              <p className="modal-hint">白名单为空时采集所有进程；有规则时 Agent 只上报匹配进程。</p>
              <form className="blacklist-form" onSubmit={handleAddWhitelist}>
                <input
                  type="text"
                  className="blacklist-input"
                  placeholder="进程名称，如 chrome、lx-music-desktop"
                  value={whitelistForm.pattern}
                  onChange={(e) => setWhitelistForm((prev) => ({ ...prev, pattern: e.target.value }))}
                />
                <select
                  className="blacklist-select"
                  value={whitelistForm.match_type}
                  onChange={(e) => setWhitelistForm((prev) => ({ ...prev, match_type: e.target.value }))}
                >
                  <option value="contains">包含</option>
                  <option value="exact">等于</option>
                  <option value="startswith">开头</option>
                  <option value="endswith">结尾</option>
                  <option value="regex">正则</option>
                </select>
                <button type="submit" className="btn-edit-server" disabled={savingWhitelist}>
                  {savingWhitelist ? '保存中...' : '添加'}
                </button>
              </form>
              <div className="blacklist-list">
                {whitelist.length === 0 ? (
                  <div className="blacklist-empty">暂无白名单规则</div>
                ) : (
                  whitelist.map((rule) => (
                    <div key={rule.id} className="blacklist-item">
                      <span className="blacklist-pattern" title={rule.pattern}>{rule.pattern}</span>
                      <span className="blacklist-match">{rule.match_type || 'contains'}</span>
                      <button
                        className="blacklist-remove"
                        onClick={() => handleRemoveWhitelist(rule.id)}
                        title="移除"
                      >
                        <Icon kind="ui-close" size={13} />
                      </button>
                    </div>
                  ))
                )}
              </div>
            </div>
          </div>
        </div>
      )}

      {powerConfirm && (
        <div className="terminate-modal-overlay" onClick={() => setPowerConfirm(null)}>
          <div className="terminate-modal power-confirm-modal" onClick={(e) => e.stopPropagation()}>
            <div className="terminate-modal-header">
              <h3>请确认是否{powerConfirm.action === 'restart' ? '重启' : '关机'}？</h3>
              <button className="modal-close-btn" onClick={() => setPowerConfirm(null)}><Icon kind="ui-close" size={18} /></button>
            </div>
            <div className="terminate-modal-body">
              <div className="power-warning-list" style={{ fontSize: 14, color: '#333', lineHeight: 1.8 }}>
                <p style={{ margin: '0 0 8px' }}>1. 请确认 Agent 是否勾选「开机自动启动」，避免目标主机在{powerConfirm.action === 'restart' ? '重启' : '关机'}后失联；</p>
                <p style={{ margin: 0 }}>2. 请注意正在运行的程序和未保存的数据，避免目标主机在{powerConfirm.action === 'restart' ? '重启' : '关机'}后丢失。</p>
              </div>
            </div>
            <div className="terminate-modal-footer" style={{ display: 'flex', justifyContent: 'flex-end', gap: 10, marginTop: 18 }}>
              <button className="btn-cancel" onClick={() => setPowerConfirm(null)}>取消</button>
              <button className="btn-danger" onClick={handlePower}>确认{powerConfirm.action === 'restart' ? '重启' : '关机'}</button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
