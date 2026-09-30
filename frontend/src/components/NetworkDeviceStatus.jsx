/* 方案 B：网络设备「设备状态」页签 —— 设备运行状态
 *
 * 主机那套状态页（CPU / 磁盘 / 内存 / 磁盘 IO / TCP 连接）对交换机没意义：
 * 它没有磁盘、没有进程、也数不出 TCP 连接。所以这里换成设备真正有的指标：
 * · CPU / 内存（HOST-RESOURCES，设备不支持就显示"未提供"）
 * · 入站 / 出站总流量（IF-MIB 汇总，64 位计数）
 * · 端口 UP / DOWN 统计 + 错包（运维最关心的两件事）
 * · 采集状态（上次成功时间、连续失败次数）
 *
 * 图表 / 卡片 / 周期工具栏都按现有状态页的样式来，只是内容换掉。 */
import { useCallback, useEffect, useMemo, useState } from 'react'
import { parseServerTime } from '../utils/format'
import {
  ResponsiveContainer, LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, Legend,
} from 'recharts'
import { fetchMetricHistory, fetchNetworkInterfaces } from '../services/api'
import { isVirtualIface, periodLabel } from '../utils/ifaces'
// 小卡片左侧图标：与主机「设备状态」共用同一套 glyph（定义在 CardIcon.jsx）
import CardIcon from './CardIcon'
import './NetworkDeviceStatus.css'

const RANGES = [
  { value: '1h', label: '近 1 小时' },
  { value: '6h', label: '近 6 小时' },
  { value: '24h', label: '近 24 小时' },
]

function fmtTime(iso) {
  if (!iso) return '—'
  const d = parseServerTime(iso)
  if (Number.isNaN(d.getTime())) return '—'
  const p = (x) => String(x).padStart(2, '0')
  return `${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`
}

function fmtFullTime(iso) {
  if (!iso) return '—'
  const d = parseServerTime(iso)
  if (Number.isNaN(d.getTime())) return '—'
  const p = (x) => String(x).padStart(2, '0')
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`
}

/* KB → GB（UCD-SNMP 的内存分项单位是 KB） */
function fmtGB(kb) {
  return (Number(kb || 0) / 1024 / 1024).toFixed(2)
}

function fmtCap(gb) {
  const n = Number(gb) || 0
  if (n >= 1024) return `${(n / 1024).toFixed(2)} TB`
  return `${n.toFixed(0)} GB`
}

function pctColor(v, warn, crit) {
  const n = Number(v) || 0
  if (n > crit) return '#d9534f'
  if (n > warn) return '#f0ad4e'
  return '#5cb85c'
}

/* 小卡片左侧图标已抽到 `CardIcon.jsx`（与主机「设备状态」共用同一套 glyph）。
 * 2026-09-21 抽出的原因：主机那边要"加同一套图标"，两处各写一份迟早会漂移
 * （尺寸 22 vs 26、线宽 1.6 vs 1.8）。尺寸常量也挪到那里了。 */

function MetricBox({ label, value, unit, color, sub, unknown, icon }) {
  return (
    <div className="nds-card">
      {icon ? <CardIcon name={icon} className="nds-card-icon" /> : null}
      <div className="nds-card-body">
        <div className="nds-card-label">{label}</div>
        <div className="nds-card-value" style={{ color: unknown ? '#999' : color }}>
          {unknown ? '未提供' : (value == null ? '--' : value)}
          {!unknown && unit ? <span className="nds-card-unit">{unit}</span> : null}
        </div>
        {sub ? <div className="nds-card-sub">{sub}</div> : null}
      </div>
    </div>
  )
}

function StatChart({ title, data, keys, colors, unit, emptyText }) {
  const rows = data || []
  // 设备不提供这几个指标时，后端存的是 NULL（不再是 0）。整段都是 null 就别画
  // 一条贴在 0 上的假曲线，直接说清楚"设备没给这个指标"。
  const hasAny = rows.some((r) => keys.some((k) => r[k.key] != null))
  const emptyMsg = emptyText || '该时间范围内还没有采集数据'

  return (
    <div className="nds-chart">
      <div className="nds-chart-title">{title}</div>
      <div className="nds-chart-body">
        {(!hasAny) ? (
          <div className="nds-chart-empty">{rows.length === 0 ? '该时间范围内还没有采集数据' : emptyMsg}</div>
        ) : (
          <ResponsiveContainer width="100%" height="100%">
            {/* X 轴必须用接口返回的 timestamp（以前写成了 time，字段对不上 →
 整张图一条线都画不出来，看起来就是"没有线条颜色"） */}
            <LineChart data={rows} margin={{ top: 8, right: 12, bottom: 0, left: -12 }}>
              <CartesianGrid stroke="#eceef1" strokeDasharray="3 3" />
              <XAxis
                dataKey="timestamp"
                tick={{ fontSize: 11, fill: '#6c757d' }}
                tickFormatter={fmtTime}
                minTickGap={40}
                stroke="#d9dde3"
              />
              <YAxis tick={{ fontSize: 11, fill: '#6c757d' }} stroke="#d9dde3" width={44} />
              <Tooltip
                labelFormatter={(v) => fmtFullTime(v)}
                formatter={(v, name) => (v == null ? ['未提供', name] : [`${Number(v).toFixed(2)} ${unit}`, name])}
                contentStyle={{ fontSize: 12, borderRadius: 2, border: '1px solid #d9dde3' }}
              />
              <Legend
                verticalAlign="top"
                align="right"
                height={22}
                iconType="plainline"
                iconSize={14}
                wrapperStyle={{ fontSize: 11, color: '#6c757d' }}
              />
              {keys.map((k, i) => (
                <Line
                  key={k.key}
                  type="monotone"
                  dataKey={k.key}
                  name={k.label}
                  stroke={colors[i % colors.length]}
                  strokeWidth={1.6}
                  dot={false}
                  connectNulls={false}
                  isAnimationActive={false}
                />
              ))}
            </LineChart>
          </ResponsiveContainer>
        )}
      </div>
    </div>
  )
}

export default function NetworkDeviceStatus({
  serverId,
  server,
  metrics,
  timeRange,
  setTimeRange,
  onCollect,
}) {
  const [range, setRange] = useState(timeRange && timeRange !== 'custom' ? timeRange : '1h')
  const [history, setHistory] = useState([])
  const [net, setNet] = useState(null)
  const [loading, setLoading] = useState(true)
  const [busy, setBusy] = useState('')

  const loadHistory = useCallback(async () => {
    try {
      const rows = await fetchMetricHistory(serverId, range)
      setHistory(Array.isArray(rows) ? rows : (rows && rows.items) || [])
    } catch (e) {
      setHistory([])
    }
  }, [serverId, range])

  const loadIfaces = useCallback(async () => {
    try {
      setNet(await fetchNetworkInterfaces(serverId))
    } catch (e) {
      setNet(null)
    }
  }, [serverId])

  useEffect(() => {
    setLoading(true)
    Promise.all([loadHistory(), loadIfaces()]).finally(() => setLoading(false))
  }, [loadHistory, loadIfaces])

  useEffect(() => {
    if (setTimeRange && range !== timeRange) setTimeRange(range)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [range])

  // 刷新：重拉图表数据 + 端口表，并顺带让父级刷新设备信息 / 最新指标。
  // 2026-09-21 按需求删掉了「立即采集」按钮 —— 它原来调 `collectSnmp()`
  // 去触发一次服务端 SNMP 采集，但和「刷新」在用户眼里就是一回事，
  // · 只留「刷新」（纯读，不触发采集，因此**不需要**采集权限）
  // · 采集节奏完全交给服务端的采集周期，不再提供手动催采
  // `onCollect` 这个 prop 保留 —— 它是父级的刷新回调（重载设备信息/指标），
  // 跟着刷新一起调用仍然有意义，所以没有连带删掉。
  const onRefresh = async () => {
    setBusy('refresh')
    try {
      await Promise.all([loadHistory(), loadIfaces()])
      onCollect && onCollect()
    } finally {
      setBusy('')
    }
  }

  const ifaces = (net && net.interfaces) || []
  const dev = (net && net.device) || {}

  // 端口统计**只算物理口**（2026-09-21）：虚拟 / 管理口永远 UP 或永远 DOWN，
  // 混进来只会把"DOWN 42"这种数放大，看不出真有几条链路断了。
  // 端口表也是同一套过滤规则（utils/ifaces.js），两处口径保持一致。
  const portStat = useMemo(() => {
    const phys = ifaces.filter((i) => !isVirtualIface(i))
    let up = 0
    let down = 0
    let errs = 0
    let abnormal = 0
    for (const i of phys) {
      const op = String(i.oper_status || '').toLowerCase()
      const ad = String(i.admin_status || '').toLowerCase()
      if (op === 'up') up += 1
      else if (op === 'down') down += 1
      if (ad === 'up' && op === 'down') abnormal += 1
      errs += (Number(i.in_errors) || 0) + (Number(i.out_errors) || 0)
    }
    return {
      up, down, errs, abnormal,
      total: phys.length,
      all: ifaces.length,
      hidden: ifaces.length - phys.length,
    }
  }, [ifaces])

  // 入/出站卡片下挂"峰值"，替代原来挂的 UP / DOWN 数（那是端口健康的事）
  const peak = useMemo(() => {
    let pi = 0
    let po = 0
    for (const r of history) {
      const a = Number(r.network_in_mbps)
      const b = Number(r.network_out_mbps)
      if (!Number.isNaN(a) && a > pi) pi = a
      if (!Number.isNaN(b) && b > po) po = b
    }
    return { in: pi, out: po }
  }, [history])

  // 图表上标注数据粒度：300 秒采集周期下"近 1 小时"只有 12 个点，
  // 不写清楚的话曲线表现类似断断续续，实际是采样就这么稀（2026-09-21 现场反馈）
  const granularity = useMemo(() => {
    const p = (net && net.asset && net.asset.collect_period_sec) || server?.collect_period_sec
    return periodLabel(p)
  }, [net, server])

  const cpu = metrics?.cpu_percent
  const mem = metrics?.memory_percent
  const cpuUnknown = cpu == null
  const memUnknown = mem == null

  // Linux / NAS 才有的补充指标（存储池、磁盘健康、内存缓存分项）。
  // 交换机那台后端给的是 null → 下面那几张卡片整段不渲染，别摆空卡片。
  const nas = (net && net.device && net.device.nas) || null
  const memDetail = (nas && nas.memory) || null
  const storage = (nas && nas.storage) || null
  const disks = (nas && nas.disks) || []
  const raid = (nas && nas.raid) || null
  const icmp = (net && net.device && net.device.icmp) || null

  // 硬件健康：温度 / 电源 / 风扇 / 整机功率（2026-09-21 加）
  // 走哪条路子由后端自动挑（华为私有 → 群晖私有 → 思科 ENVMON → 标准 ENTITY-MIB →
  // ENTITY-SENSOR-MIB），所以 NAS / 路由 / 防火墙 / 交换机是同一套卡片。
  // 某一项设备没提供 → 后端给 null → 那张卡片整段不渲染，不摆一个假的 0。
  const env = (net && net.device && net.device.env) || null
  const envTemp = (env && env.temperature) || null
  const envPower = (env && env.power) || null
  const envFan = (env && env.fan) || null
  const envUsage = (env && env.power_usage) || null
  // 电源卡原来还会把"未供电"的槽位名点出来（如 `未供电：0/5`），2026-09-21 按需求去掉：
  // 这台交换机两个电源槽只插了一个，天天挂着一条红字纯属噪音；1/2 这个数本身已经说明问题。
  // 风扇卡下面的"异常"点名保留 —— 风扇真坏了是要立刻处理的，和"备用槽没插"不是一回事。
  const envBadFan = ((envFan && envFan.items) || []).filter((i) => i.ok === false)

  // 内存到底该显示哪个数：Linux 上 hrStorageTable 算出来的"使用率"把磁盘缓存也算成
  // 已用，常年 90%+（这台 NAS 实测 91.5%），按它配色会一直橙/红，是误报。
  // 有分项时显示**不含缓存的应用占用**（同一台机器实测 18.7%），并在下面注明缓存量。
  const memShown = memDetail ? memDetail.app_percent : mem
  const memShownUnknown = memShown == null

  const diskOk = disks.filter((d) => d.ok).length
  const diskTemps = disks.map((d) => d.temp_c).filter((t) => t != null && !Number.isNaN(Number(t)))
  const tempRange = diskTemps.length
    ? (diskTemps.length === 1 ? `${diskTemps[0]}℃`
      : `${Math.min(...diskTemps)}~${Math.max(...diskTemps)}℃`)
    : ''

  return (
    <div className="nds-wrap">
      <div className="nds-cards">
        <MetricBox
          icon="cpu"
          label="CPU 使用率"
          value={cpuUnknown ? null : Number(cpu).toFixed(1)}
          unit="%"
          color={pctColor(cpu, 75, 90)}
          unknown={cpuUnknown}
          sub={cpuUnknown ? '设备未提供 CPU 指标' : ''}
        />
        <MetricBox
          icon="memory"
          label={memDetail ? '内存占用（不含缓存）' : '内存使用率'}
          value={memShownUnknown ? null : Number(memShown).toFixed(1)}
          unit="%"
          color={pctColor(memShown, 80, 95)}
          unknown={memShownUnknown}
          sub={memShownUnknown ? '设备未提供内存指标'
            : memDetail ? `含缓存 ${fmtGB(memDetail.cached_kb)} GB · 总口径 ${memDetail.percent}%`
              : ''}
        />
        {/* 入/出站卡片只讲带宽：实时值 + 本周期峰值。
 以前把「UP / DOWN 端口数」挂在这两张卡下面，跟"流量"没关系，
 表现类似"入站 20 / 出站 42"是某种流量配比，实际是端口状态（2026-09-21 拆走）。 */}
        <MetricBox
          icon="in"
          label="入站流量"
          value={metrics?.network_in_mbps == null ? null : Number(metrics.network_in_mbps).toFixed(2)}
          unit="Mbps"
          color="#0275d8"
          sub={peak.in > 0 ? `区间峰值 ${peak.in.toFixed(2)} Mbps` : '区间内暂无峰值'}
        />
        <MetricBox
          icon="out"
          label="出站流量"
          value={metrics?.network_out_mbps == null ? null : Number(metrics.network_out_mbps).toFixed(2)}
          unit="Mbps"
          color="#5cb85c"
          sub={peak.out > 0 ? `区间峰值 ${peak.out.toFixed(2)} Mbps` : '区间内暂无峰值'}
        />
        {/* 只留 UP / DOWN / 异常三计数：以前下面还挂一行「已断开：GE0/0/1、GE0/0/2 等 N 个」，
 小卡片塞不下就折成三行、把数字挤没了（2026-09-21 按需求去掉）；
 具体是哪些口断开，看下方端口表格。 */}
        <MetricBox
          icon="port"
          label="端口健康"
          value={ifaces.length ? portStat.total : null}
          unit="个"
          color={portStat.abnormal > 0 ? '#d9534f' : (portStat.down > 0 ? '#f0ad4e' : '#5cb85c')}
          sub={<span>物理口 UP {portStat.up} · DOWN {portStat.down} · 异常 {portStat.abnormal}</span>}
        />
        {/* 网络延迟 / 丢包：ICMP 由内核应答，SNMP 由代理进程应答。
 SNMP 超时但 ping 得通 = 链路在、控制面卡了；两条路分开显示才看得出来。 */}
        {icmp ? (
          <MetricBox
            icon="latency"
            label="网络延迟"
            value={icmp.ok ? Number(icmp.avg_ms).toFixed(icmp.avg_ms < 10 ? 1 : 0) : null}
            unit={icmp.ok ? 'ms' : ''}
            color={!icmp.ok ? '#d9534f'
              : (icmp.loss_percent > 0 ? '#f0ad4e'
                : (Number(icmp.avg_ms) > 50 ? '#f0ad4e' : '#5cb85c'))}
            unknown={!icmp.ok}
            sub={icmp.ok
              ? `丢包 ${icmp.loss_percent}% · ${icmp.received}/${icmp.sent}`
              : '不通（设备离线或 ICMP 被拦）'}
          />
        ) : null}
        {/* 硬件健康三张卡：温度 / 电源 / 风扇。
 后端按「华为私有 → 群晖私有 → 思科 ENVMON → 标准 ENTITY-MIB → ENTITY-SENSOR」
 自动选路，所以 NAS / 路由 / 防火墙 / 交换机共用同一套卡片；
 某项设备没提供就是 null，对应卡片整张不渲染。 */}
        {envTemp ? (
          <MetricBox
            icon="temp"
            label="设备温度"
            value={envTemp.c}
            unit="℃"
            color={(() => {
              const c = Number(envTemp.c)
              const t = envTemp.threshold_c == null ? null : Number(envTemp.threshold_c)
              // 有阈值就按阈值判（离阈值 8 ℃ 以内先变橙），没有阈值按 60 / 75 兜底
              if (t != null) return c >= t ? '#d9534f' : (c >= t - 8 ? '#f0ad4e' : '#5cb85c')
              return c >= 75 ? '#d9534f' : (c >= 60 ? '#f0ad4e' : '#5cb85c')
            })()}
            sub={envTemp.threshold_c != null ? `告警阈值 ${envTemp.threshold_c} ℃` : '设备未提供阈值'}
          />
        ) : null}
        {envPower ? (
          <MetricBox
            icon="power"
            label="电源"
            value={`${envPower.ok}/${envPower.total}`}
            unit="供电"
            color={envPower.ok === envPower.total ? '#5cb85c' : '#d9534f'}
            sub={envUsage ? `整机 ${envUsage.used_w} W / ${envUsage.total_w} W` : ''}
          />
        ) : null}
        {envFan ? (
          <MetricBox
            icon="fan"
            label="风扇"
            value={`${envFan.ok}/${envFan.total}`}
            unit="正常"
            color={envFan.ok === envFan.total ? '#5cb85c' : '#d9534f'}
            sub={
              <>
                {envFan.speed_percent != null ? <span>转速 {envFan.speed_percent}%</span> : null}
                {envBadFan.length ? (
                  <span className="nds-card-warn">异常：{envBadFan.map((i) => i.name).join('、')}</span>
                ) : null}
              </>
            }
          />
        ) : null}
        {/* 下面两张只有 Linux / NAS 才有数据（交换机那台后端给 null → 整段不渲染） */}
        {storage ? (
          <MetricBox
            icon="storage"
            label="存储空间"
            value={Number(storage.percent).toFixed(1)}
            unit="%"
            color={pctColor(storage.percent, 80, 92)}
            sub={`${storage.name} · 已用 ${fmtCap(storage.used_gb)} / ${fmtCap(storage.total_gb)}`}
          />
        ) : null}
        {disks.length > 0 ? (
          <MetricBox
            icon="disk"
            label="磁盘健康"
            value={`${diskOk}/${disks.length}`}
            unit="正常"
            color={diskOk === disks.length ? '#5cb85c' : '#d9534f'}
            sub={
              <>
                <span>{tempRange ? `温度 ${tempRange}` : '温度未提供'}</span>
                {raid ? (
                  <span className={raid.ok ? '' : 'nds-card-warn'}>
                    {raid.name || 'RAID'}：{raid.ok ? '正常' : `异常（${raid.status_raw}）`}
                  </span>
                ) : null}
              </>
            }
          />
        ) : null}
      </div>

      {/* 周期条按用户要求插在两行卡片之间（指标卡片行 ↑ / 图表行 ↓）。
 2026-09-21 按需求去掉「立即采集」按钮 —— 「刷新」已经能拉最新数据，
 两个按钮功能上重叠，只留一个。采集节奏由服务端的采集周期决定，
 手动"立即采集"并不会真的提前下一次采集，容易让人误以为能催。 */}
      <div className="nds-toolbar">
        <span className="nds-toolbar-label">周期：</span>
        {RANGES.map((r) => (
          <button
            key={r.value}
            className={`nds-range-btn ${range === r.value ? 'active' : ''}`}
            onClick={() => setRange(r.value)}
          >{r.label}</button>
        ))}
        <span className="nds-spacer" />
        <button className="nds-btn" onClick={onRefresh} disabled={!!busy}>
          {busy ? '刷新中…' : '刷新'}
        </button>
      </div>

      <div className="nds-charts">
        <StatChart
          title="CPU / 内存（%）"
          data={history}
          keys={[{ key: 'cpu_percent', label: 'CPU' }, { key: 'memory_percent', label: '内存' }]}
          colors={['#0275d8', '#5cb85c']}
          unit="%"
          emptyText="该设备未提供 CPU / 内存指标（未实现 HOST-RESOURCES-MIB）"
        />
        <StatChart
          title={`端口总流量（Mbps）${granularity ? ` · 粒度 ${granularity}` : ''}`}
          data={history}
          keys={[{ key: 'network_in_mbps', label: '入站' }, { key: 'network_out_mbps', label: '出站' }]}
          colors={['#0275d8', '#f0ad4e']}
          unit="Mbps"
        />
      </div>

      <div className="nds-foot">
        <div className="nds-foot-row">
          <span className="nds-foot-k">端口</span>
          <span className="nds-foot-v">
            共 {portStat.all} 个接口（虚拟 / 管理 {portStat.hidden} 个） ·
            物理口<b className="nds-up"> UP {portStat.up}</b> ·
            <b className="nds-down"> DOWN {portStat.down}</b>
            {portStat.errs > 0 ? <b className="nds-down"> · 错包累计 {portStat.errs}</b> : null}
          </span>
        </div>
        <div className="nds-foot-row">
          <span className="nds-foot-k">上次采集</span>
          <span className="nds-foot-v">
            {fmtFullTime(dev.last_attempt_at)}
            {dev.ok === false && (
              <span className="nds-err">
                （失败 ×{dev.consecutive_failures || 0}：{dev.error || '未知错误'}）
              </span>
            )}
          </span>
        </div>
        <div className="nds-foot-row">
          <span className="nds-foot-k">采集周期</span>
          <span className="nds-foot-v">
            {(() => {
              // 详情接口不带 collect_period_sec，端口接口的 asset 里有（含单台覆盖和全局配置）
              const p = (net && net.asset && net.asset.collect_period_sec) || server?.collect_period_sec
              return p ? `${p} 秒（在线判定 = ${Math.round(p * 2.5)} 秒）` : '跟随全局配置'
            })()}
            {loading ? ' · 加载中…' : ''}
          </span>
        </div>
      </div>
    </div>
  )
}
