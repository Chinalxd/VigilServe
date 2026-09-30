import { useState, useEffect, useCallback } from 'react'
import { fetchHostInfo, refreshHostInfo, USE_MOCK } from '../services/hostInfo'
import './HostInfo.css'

function V({ children }) {
  if (children === null || children === undefined || children === '') return <span className="hi-empty">—</span>
  return children
}

/**
 * 分类行：分类名作为整行的标题条（横跨卡片全宽），下方是内容。
 * 整页只用一个大卡片（.hi-panel），页面内不再有「系统信息 / 硬件信息」这类分组标题。
 * show=false（搜索无命中）时整组隐藏。
 */
function Section({ title, show = true, children }) {
  if (!show) return null
  return (
    <section className="hi-row">
      <div className="hi-row-head">
        <span className="hi-row-name">{title}</span>
      </div>
      <div className="hi-row-body">{children}</div>
    </section>
  )
}

/**
 * 状态文案 → 底色档位：已开启/已启用 = 绿（ok），已关闭/已禁用 = 红（bad），
 * 其余（未知、空）不给底色，避免把不确定的信息涂成结论。
 */
function stateTag(v) {
  const s = String(v ?? '')
  if (/已开启|已启用/.test(s)) return 'ok'
  if (/已关闭|已禁用/.test(s)) return 'bad'
  return undefined
}

/* 键值列表：rows = [[键, 值] | [键, 值, 'ok'|'bad'], ...]（已由调用方按关键字过滤）
 * 第三项给定时，值渲染成带底色的状态标签；只给两项时保持原来的纯文本。
 * 注意：搜索仍按第二项的字符串匹配，所以状态值要保持可读的纯文本。 */
function Rows({ rows, empty = '无匹配项' }) {
  if (!rows || rows.length === 0) return <div className="hi-empty-box">{empty}</div>
  return (
    <table className="hi-kv">
      <tbody>
        {rows.map(([k, v, tag], i) => (
          <tr key={`${k}-${i}`}>
            <th>{k}</th>
            <td>
              {tag ? <StateTag ok={tag === 'ok'} text={v} /> : <V>{v}</V>}
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  )
}

function Grid({ columns, rows, empty = '无匹配项', wrapCls = 'hi-table-wrap' }) {
  if (!rows || rows.length === 0) return <div className="hi-empty-box">{empty}</div>
  return (
    <div className={wrapCls}>
      <table className="hi-table">
        <thead>
          <tr>{columns.map((c) => <th key={c.key} style={c.width ? { width: c.width } : undefined}>{c.title}</th>)}</tr>
        </thead>
        <tbody>
          {rows.map((r, i) => (
            <tr key={r.id ?? i}>
              {columns.map((c) => (
                <td key={c.key} className={c.cls}>{c.render ? c.render(r) : <V>{r[c.key]}</V>}</td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function StateTag({ ok, text }) {
  const cls = ok === true ? 'ok' : ok === false ? 'bad' : 'warn'
  return <span className={`hi-tag ${cls}`}>{text}</span>
}

/** 共享权限：Agent 返回的是分号拼接的一条长字符串，拆成一行一条更好读 */
function AccessList({ value }) {
  const items = String(value || '').split(';').map((s) => s.trim()).filter(Boolean)
  if (items.length === 0) return <span className="hi-empty">—</span>
  return (
    <div className="hi-acc-list">
      {items.map((t, i) => <div className="hi-acc-item" key={i}>{t}</div>)}
    </div>
  )
}

function fmtUptime(sec) {
  if (sec === null || sec === undefined) return null
  const d = Math.floor(sec / 86400)
  const h = Math.floor((sec % 86400) / 3600)
  const m = Math.floor((sec % 3600) / 60)
  return `${d} 天 ${h} 小时 ${m} 分钟`
}

function DisplayLayout({ displays }) {
  if (!displays || displays.length === 0) return <div className="hi-empty-box">未检测到显示器</div>
  const minX = Math.min(...displays.map((d) => d.x))
  const minY = Math.min(...displays.map((d) => d.y))
  const maxX = Math.max(...displays.map((d) => d.x + d.width))
  const maxY = Math.max(...displays.map((d) => d.y + d.height))
  const w = maxX - minX
  const h = maxY - minY
  const scale = 100 / Math.max(w, 1)
  return (
    <div className="hi-layout" style={{ height: Math.max(150, (h * scale) / 4.2 + 40) }}>
      <div className="hi-layout-inner" style={{ width: '100%', height: '100%', position: 'relative' }}>
        {displays.map((d) => (
          <div
            key={d.index}
            className={`hi-screen${d.primary ? ' primary' : ''}`}
            style={{
              left: `${((d.x - minX) / w) * 100}%`,
              top: `${((d.y - minY) / h) * 100}%`,
              width: `${(d.width / w) * 100}%`,
              height: `${(d.height / h) * 100}%`,
            }}
            title={`${d.name} · ${d.width}×${d.height} @ ${d.refresh}Hz · ${d.connection}`}
          >
            <div className="hi-screen-idx">{d.index}</div>
            <div className="hi-screen-res">{d.width}×{d.height}</div>
            {d.primary && <div className="hi-screen-main">主屏</div>}
          </div>
        ))}
      </div>
    </div>
  )
}

export default function HostInfo({ serverId, serverName }) {
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [keyword, setKeyword] = useState('')

  const load = useCallback(async () => {
    setLoading(true)
    setError('')
    try {
      setData(await fetchHostInfo(serverId, serverName))
    } catch (e) {
      setError(e.message || '加载失败')
    } finally {
      setLoading(false)
    }
  }, [serverId, serverName])

  useEffect(() => { load() }, [load])

  // 点「刷新」走服务端的异步采集队列：一轮 WMI 好几秒，不要卡住页面
  const [refreshing, setRefreshing] = useState(false)
  const onRefresh = async () => {
    setRefreshing(true)
    try {
      await refreshHostInfo(serverId, ['system-info'])
      await load()
    } catch (e) {
      setError(e.message || '刷新失败')
    } finally {
      setRefreshing(false)
    }
  }

  if (loading) return <div className="hi-loading">正在采集设备信息…</div>
  if (error) return <div className="hi-error">{error}</div>
  if (!data) return <div className="hi-empty-box">暂无数据</div>

  const kw = keyword.trim().toLowerCase()
  const hit = (...vals) => !kw || vals.some((v) => String(v ?? '').toLowerCase().includes(kw))

  const os = data.os || {}
  const sec = data.security || {}
  const upd = data.updates || {}
  const users = data.users || {}
  const cpu = data.cpu || {}
  const mem = data.memory || {}
  const df = sec.defender || {}

  /* ── 搜索 ────────────────────────────────────────────────
 * 分组标题命中关键字 → 该分组整组原样展示；
 * 否则组内键值行 / 表格行逐条过滤，整组无命中则隐藏整组。 */
  const tHit = (t) => !!kw && String(t).toLowerCase().includes(kw)
  const kvRows = (rows, all) => (all ? rows : rows.filter(([k, v]) => hit(k, v)))
  const listRows = (arr, keys, all) => (arr || []).filter((r) => (all ? true : hit(...keys.map((k) => r[k]))))

  const osAll = tHit('操作系统')
  const osRows = kvRows([
    ['操作系统', os.name],
    ['版本 / 内部版本', [os.version, os.build].filter(Boolean).join(' (') + (os.version && os.build ? ')' : '')],
    ['版本类型', os.edition],
    ['系统架构', os.arch],
    ['安装日期', os.install_date],
    ['系统目录', os.system_dir],
    ['区域与语言', os.locale],
    ['产品 ID', os.product_id],
  ], osAll)

  const mbAll = tHit('主机与主板')
  const mbRows = kvRows([
    ['计算机名', data.machine?.computer_name],
    ['域 / 工作组', data.machine?.domain],
    ['制造商', data.machine?.manufacturer],
    ['型号', data.machine?.model],
    ['机箱类型', data.machine?.chassis_type],
    ['序列号', data.machine?.serial],
    ['主板', data.machine?.motherboard && [data.machine.motherboard.manufacturer, data.machine.motherboard.model].filter(Boolean).join(' ')],
    ['芯片组', data.machine?.motherboard?.chipset],
    ['BIOS', data.machine?.bios && [data.machine.bios.vendor, data.machine.bios.version, data.machine.bios.date].filter(Boolean).join(' / ')],
    ['启动模式', data.machine?.bios?.mode],
  ], mbAll)

  const bootAll = tHit('启动与运行时间')
  const bootRows = kvRows([
    ['最近启动时间', os.last_boot],
    ['运行时长', fmtUptime(os.uptime_seconds)],
    ['时区', os.timezone],
  ], bootAll)

  /* 系统安全软件状态 */
  const secAll = tHit('系统安全软件状态')
  const secRows = kvRows([
    ['防病毒软件', df.name],
    ['实时保护', df.realtime_protection ? '已启用' : '已禁用', df.realtime_protection ? 'ok' : 'bad'],
    ['防间谍软件', df.antispyware ? '已启用' : '已禁用', df.antispyware ? 'ok' : 'bad'],
    ['篡改保护', df.tamper_protection ? '已启用' : '已禁用', df.tamper_protection ? 'ok' : 'bad'],
    ['云提供的保护', df.cloud_protection ? '已启用' : '已禁用', df.cloud_protection ? 'ok' : 'bad'],
    ['引擎版本', df.engine_version],
    ['病毒库版本', df.signature_version],
    ['病毒库更新', df.signature_updated],
    ['上次扫描', [df.last_scan, df.last_scan_type].filter(Boolean).join('（') + (df.last_scan && df.last_scan_type ? '）' : '')],
    ['防火墙(域/专用/公用)', [sec.firewall?.domain, sec.firewall?.private, sec.firewall?.public].filter(Boolean).join(' / ')],
    ['用户账户控制', sec.uac],
    ['安全启动', sec.secure_boot],
    ['TPM', sec.tpm?.present ? `有 · ${sec.tpm.version}` : '无'],
  ], secAll)
  const secProducts = listRows(sec.products, ['type', 'name', 'state'], secAll)

  const updAll = tHit('系统更新状态')
  const updRows = kvRows([['系统更新', upd.auto_update, stateTag(upd.auto_update)]], updAll)

  const userAll = tHit('用户信息')
  const userRows = kvRows([
    ['当前登录用户', users.current && `${users.current.domain}\\${users.current.name}`],
    ['登录时间', users.current?.logon_time],
    ['会话类型', users.current?.session],
    ['管理员权限', users.current?.elevated ? '是' : '否'],
  ], userAll)
  const accounts = listRows(users.accounts, ['name', 'full_name', 'description'], userAll)

  const shareAll = tHit('系统共享目录')
  const shares = listRows(data.shares, ['name', 'path', 'description', 'access'], shareAll)

  const cpuAll = tHit('处理器 (CPU)')
  const cpuRows = kvRows([
    ['型号', cpu.model],
    ['制造商', cpu.vendor],
    ['插槽 / 核心 / 线程', cpu.cores !== undefined ? `${cpu.sockets || 1} / ${cpu.cores} / ${cpu.threads}` : null],
    ['基础频率', cpu.base_mhz ? `${(cpu.base_mhz / 1000).toFixed(2)} GHz` : null],
    ['当前频率', cpu.current_mhz ? `${(cpu.current_mhz / 1000).toFixed(2)} GHz` : null],
    ['最大睿频', cpu.max_mhz ? `${(cpu.max_mhz / 1000).toFixed(2)} GHz` : null],
    ['一级缓存', cpu.cache && [cpu.cache.l1d, cpu.cache.l1i].filter(Boolean).join(' / ')],
    ['二级缓存', cpu.cache?.l2],
    ['三级缓存', cpu.cache?.l3],
    ['制程', cpu.process],
    ['封装功耗', cpu.package_power !== null && cpu.package_power !== undefined ? `${cpu.package_power} W` : null],
    ['温度', cpu.temperature !== null && cpu.temperature !== undefined ? `${cpu.temperature} °C` : null],
    ['当前使用率', cpu.usage !== null && cpu.usage !== undefined ? `${cpu.usage} %` : null],
    ['特性', (cpu.features || []).join('、')],
  ], cpuAll)

  const memAll = tHit('内存')
  const memRows = kvRows([
    ['总容量', mem.total_gb ? `${mem.total_gb} GB` : null],
    ['已用插槽 / 总数', mem.slots_used !== undefined ? `${mem.slots_used} / ${mem.slots_total}` : null],
    ['内存类型', mem.type],
    ['通道', mem.channels],
    ['频率', mem.speed_mhz ? `${mem.speed_mhz} MHz` : null],
    ['使用率', mem.usage !== null && mem.usage !== undefined ? `${mem.usage} %` : null],
  ], memAll)
  const memModules = listRows(mem.modules, ['slot', 'type', 'manufacturer', 'part_number'], memAll)

  /* 存储设备：逐块盘判断，块内键值行与分区表分别过滤 */
  const storage = (data.storage || []).map((s) => {
    const all = tHit('存储设备') || hit(s.model, s.serial, s.firmware, s.interface, s.media_type, s.health)
    const rows = kvRows([
      ['型号', s.model],
      ['接口 / 介质', [s.interface, s.media_type].filter(Boolean).join(' · ')],
      ['容量', s.size_gb ? `${s.size_gb} GB` : null],
      ['序列号', s.serial],
      ['固件', s.firmware],
      ['温度', s.temperature !== null && s.temperature !== undefined ? `${s.temperature} °C` : null],
      ['健康状态', s.health],
      ['通电时间', s.smart?.power_on_hours !== null && s.smart?.power_on_hours !== undefined ? `${s.smart.power_on_hours} 小时` : null],
      ['通电次数', s.smart?.power_cycle_count],
      ['重映射扇区', s.smart?.reallocated_sectors],
      ['磨损程度', s.smart?.wear_leveling],
    ], all)
    const parts = listRows(s.partitions, ['letter', 'label', 'fs'], all)
    return { s, rows, parts }
  }).filter((d) => d.rows.length > 0 || d.parts.length > 0)

  const netAll = tHit('网络适配器')
  const network = (data.network || []).filter((n) => (netAll ? true : hit(n.name, n.status, n.mac, (n.ipv4 || []).join(' '), (n.gateway || []).join(' '), (n.dns || []).join(' '))))

  const dispAll = tHit('显示器布局')
  const displays = (data.displays || []).filter((d) => (dispAll ? true : hit(d.name, d.connection)))

  const devAll = tHit('整体硬件清单')
  const devices = listRows(data.devices, ['category', 'name', 'vendor', 'details'], devAll)

  const noMatch =
    osRows.length === 0 && mbRows.length === 0 && bootRows.length === 0 &&
    secRows.length === 0 && secProducts.length === 0 && updRows.length === 0 &&
    userRows.length === 0 && accounts.length === 0 && shares.length === 0 &&
    cpuRows.length === 0 && memRows.length === 0 && memModules.length === 0 &&
    storage.length === 0 && network.length === 0 && displays.length === 0 && devices.length === 0

  return (
    <div className="host-info">
      <section className="hi-panel">
        <header className="hi-panel-head">
          <span className="hi-collected">
            采集时间：{data.collected_at || '—'} · Agent {data.agent_version || '—'}
          </span>
          <input
            className="hi-search"
            value={keyword}
            onChange={(e) => setKeyword(e.target.value)}
            placeholder="搜索字段 / 值"
          />
          <button className="hi-btn" onClick={onRefresh} disabled={refreshing}>
            {refreshing ? '采集中…' : '刷新'}
          </button>
        </header>

        <div className="hi-panel-body">
          {USE_MOCK && (
            <div className="hi-mock-tip">当前为示例数据（前端先行），后端与 Agent 采集落地后自动切换为真实数据。</div>
          )}

          <Section title="操作系统" show={osRows.length > 0}>
            <Rows rows={osRows} />
          </Section>

          <Section title="主机与主板" show={mbRows.length > 0}>
            <Rows rows={mbRows} />
          </Section>

          <Section title="启动与运行时间" show={bootRows.length > 0}>
            <Rows rows={bootRows} />
          </Section>

          <Section title="系统安全软件状态" show={secRows.length > 0 || secProducts.length > 0}>
            <Rows rows={secRows} />
            <Grid
              columns={[
                { key: 'type', title: '类别', width: '90px' },
                { key: 'name', title: '安全软件' },
                {
                  key: 'state',
                  title: '状态',
                  width: '90px',
                  render: (r) => {
                    const t = stateTag(r.state)
                    return t ? <StateTag ok={t === 'ok'} text={r.state} /> : <V>{r.state}</V>
                  },
                },
                { key: 'up_to_date', title: '已更新', width: '80px', render: (r) => (r.up_to_date ? <StateTag ok text="是" /> : <StateTag ok={false} text="否" />) },
              ]}
              rows={secProducts}
              empty="无安全软件信息"
            />
          </Section>

          {/* 只保留「系统更新是否开启」一项：补丁 / 待安装 / 时间等不再展示 */}
          <Section title="系统更新状态" show={updRows.length > 0}>
            <Rows rows={updRows} />
          </Section>

          <Section title="用户信息" show={userRows.length > 0 || accounts.length > 0}>
            <Rows rows={userRows} />
            <div className="hi-sub">已启用 / 全部本地用户</div>
            <Grid
              columns={[
                { key: 'name', title: '用户名', width: '130px' },
                { key: 'full_name', title: '全名', width: '130px' },
                { key: 'enabled', title: '已启用', width: '80px', render: (r) => (r.enabled ? <StateTag ok text="是" /> : <StateTag text="否" />) },
                { key: 'admin', title: '管理员', width: '80px', render: (r) => (r.admin ? <StateTag ok text="是" /> : '否') },
                { key: 'locked', title: '已锁定', width: '80px', render: (r) => (r.locked ? <StateTag ok={false} text="是" /> : '否') },
                { key: 'password_expires', title: '密码过期', width: '90px', render: (r) => (r.password_expires ? '是' : '否') },
                { key: 'last_logon', title: '上次登录', width: '150px' },
                { key: 'description', title: '描述' },
              ]}
              rows={accounts}
              empty="无用户数据"
            />
          </Section>


          <Section title="系统共享目录" show={shares.length > 0}>
            <Grid
              columns={[
                { key: 'name', title: '共享名', width: '200px', cls: 'hi-nowrap' },
                { key: 'path', title: '路径', width: '330px', cls: 'hi-nowrap' },
                { key: 'description', title: '描述', width: '150px', cls: 'hi-nowrap' },
                { key: 'access', title: '访问权限', width: '580px', cls: 'hi-col-access', render: (r) => <AccessList value={r.access} /> },
                { key: 'hidden', title: '隐藏', width: '70px', render: (r) => (r.hidden ? '是' : '否') },
              ]}
              rows={shares}
              empty="无共享目录"
            />
          </Section>

          <Section title="处理器 (CPU)" show={cpuRows.length > 0}>
            <Rows rows={cpuRows} />
            {cpu.load_per_core && cpu.load_per_core.length > 0 && (
              <div className="hi-cores">
                {cpu.load_per_core.map((v, i) => (
                  <div className="hi-core" key={i} title={`核心 ${i + 1}：${v}%`}>
                    <div className="hi-core-bar"><div className="hi-core-fill" style={{ height: `${Math.min(100, v)}%`, background: v > 90 ? '#d9534f' : v > 75 ? '#f0ad4e' : '#5cb85c' }} /></div>
                    <div className="hi-core-label">{i + 1}</div>
                  </div>
                ))}
              </div>
            )}
          </Section>

          <Section title="内存" show={memRows.length > 0 || memModules.length > 0}>
            <Rows rows={memRows} />
            <div className="hi-sub">内存模块</div>
            <Grid
              columns={[
                { key: 'slot', title: '插槽', width: '100px' },
                { key: 'capacity_gb', title: '容量', width: '80px', render: (r) => `${r.capacity_gb} GB` },
                { key: 'type', title: '类型', width: '110px' },
                { key: 'speed_mhz', title: '频率', width: '90px', render: (r) => (r.speed_mhz ? `${r.speed_mhz} MHz` : null) },
                { key: 'manufacturer', title: '制造商', width: '110px' },
                { key: 'part_number', title: '部件号' },
                { key: 'voltage', title: '电压', width: '80px', render: (r) => (r.voltage ? `${r.voltage} V` : null) },
                { key: 'temperature', title: '温度', width: '80px', render: (r) => (r.temperature !== null && r.temperature !== undefined ? `${r.temperature} °C` : null) },
                { key: 'ecc', title: 'ECC', width: '60px', render: (r) => (r.ecc ? '是' : '否') },
              ]}
              rows={memModules}
              empty="无内存模块信息"
            />
          </Section>

          <Section title="存储设备" show={storage.length > 0}>
            {storage.map(({ s, rows, parts }, i) => (
              <div className="hi-disk" key={i}>
                <div className="hi-disk-head">{s.model} <span className="hi-disk-meta">{s.interface} · {s.media_type} · {s.size_gb} GB</span></div>
                <Rows rows={rows} />
                <div className="hi-sub">分区</div>
                <Grid
                  columns={[
                    { key: 'letter', title: '盘符', width: '80px' },
                    { key: 'label', title: '卷标', width: '120px' },
                    { key: 'fs', title: '文件系统', width: '100px' },
                    { key: 'size_gb', title: '容量', width: '90px', render: (r) => `${r.size_gb} GB` },
                    { key: 'used_gb', title: '已用', width: '90px', render: (r) => `${r.used_gb} GB` },
                    { key: 'free_gb', title: '可用', width: '90px', render: (r) => `${r.free_gb} GB` },
                    {
                      key: 'percent', title: '使用率', width: '160px',
                      render: (r) => (
                        <div className="hi-mini-bar">
                          <div className="hi-mini-fill" style={{ width: `${r.percent}%`, background: r.percent > 90 ? '#d9534f' : r.percent > 80 ? '#f0ad4e' : '#5cb85c' }} />
                          <span>{r.percent}%</span>
                        </div>
                      ),
                    },
                  ]}
                  rows={parts}
                  empty="无分区信息"
                />
              </div>
            ))}
          </Section>

          <Section title="网络适配器" show={network.length > 0}>
            <Grid
              columns={[
                { key: 'name', title: '适配器', width: '230px' },
                { key: 'status', title: '状态', width: '90px', render: (r) => (r.status === '已连接' ? <StateTag ok text={r.status} /> : <StateTag text={r.status} />) },
                { key: 'mac', title: 'MAC', width: '160px' },
                { key: 'ipv4', title: 'IPv4', width: '160px', render: (r) => (r.ipv4 || []).join(', ') || '—' },
                { key: 'ipv6', title: 'IPv6', width: '190px', render: (r) => (r.ipv6 || []).join(', ') || '—' },
                { key: 'gateway', title: '网关', width: '120px', render: (r) => (r.gateway || []).join(', ') || '—' },
                { key: 'dns', title: 'DNS', width: '160px', render: (r) => (r.dns || []).join(', ') || '—' },
                { key: 'dhcp', title: 'DHCP', width: '70px', render: (r) => (r.dhcp ? '是' : '否') },
                { key: 'speed', title: '速率', width: '90px' },
                { key: 'mtu', title: 'MTU', width: '70px' },
              ]}
              rows={network}
              empty="无网络适配器信息"
            />
          </Section>

          <Section title="显示器布局" show={displays.length > 0}>
            <DisplayLayout displays={displays} />
            <Grid
              columns={[
                { key: 'index', title: '#', width: '40px' },
                { key: 'name', title: '显示器', width: '200px' },
                { key: 'res', title: '分辨率', width: '130px', render: (r) => `${r.width}×${r.height}` },
                { key: 'refresh', title: '刷新率', width: '80px', render: (r) => (r.refresh ? `${r.refresh} Hz` : null) },
                { key: 'scale', title: '缩放', width: '70px', render: (r) => (r.scale ? `${r.scale}%` : null) },
                { key: 'connection', title: '接口', width: '110px' },
                { key: 'primary', title: '主屏', width: '70px', render: (r) => (r.primary ? <StateTag ok text="是" /> : '否') },
              ]}
              rows={displays}
              empty="无显示器信息"
            />
          </Section>

          <Section title="整体硬件清单" show={devices.length > 0}>
            <Grid
              columns={[
                { key: 'category', title: '类别', width: '130px' },
                { key: 'name', title: '设备', width: '280px' },
                { key: 'vendor', title: '制造商', width: '130px' },
                { key: 'status', title: '状态', width: '90px', render: (r) => (r.status === '正常' ? <StateTag ok text={r.status} /> : <StateTag ok={false} text={r.status} />) },
                { key: 'details', title: '详细信息' },
              ]}
              rows={devices}
              empty="无硬件清单"
            />
          </Section>

          {noMatch && <div className="hi-empty-box">没有匹配「{keyword.trim()}」的项目</div>}
        </div>
      </section>
    </div>
  )
}
