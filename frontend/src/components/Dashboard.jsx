import { useState, useEffect, useRef, useCallback } from 'react'
import { fetchDashboard } from '../services/api'
import { connectWS } from '../services/ws'
import { formatDateTime } from '../utils/format'
import './Dashboard.css'
import Icon from './AppIcon'

const STATUS_MAP = {
  online: { label: '在线', color: '#5cb85c', bg: '#eaf6ea' },
  monitored: { label: '在线', color: '#5cb85c', bg: '#eaf6ea' },
  warning: { label: '告警', color: '#f0ad4e', bg: '#fcf6e8' },
  critical: { label: '严重', color: '#d9534f', bg: '#f9ecec' },
  offline: { label: '离线', color: '#777777', bg: '#f0f3f5' },
  unknown: { label: '未知', color: '#999999', bg: '#f8f9fa' },
}

const ALERT_LEVEL = {
  critical: { color: '#d9534f', bg: '#f9ecec' },
  warning: { color: '#f0ad4e', bg: '#fcf6e8' },
  info: { color: '#0275d8', bg: '#eaf4fc' },
}

function Gauge({ value, label, color }) {
  const clamped = Math.min(100, Math.max(0, value))
  return (
    <div className="gauge">
      <svg viewBox="0 0 100 60" className="gauge-svg">
        <path d="M 15 50 A 35 35 0 0 1 85 50" fill="none" stroke="#e9ecef" strokeWidth="8" />
        <path
          d="M 15 50 A 35 35 0 0 1 85 50"
          fill="none"
          stroke={color}
          strokeWidth="8"
          strokeDasharray={`${(clamped / 100) * 110} 110`}
          strokeLinecap="round"
        />
      </svg>
      <div className="gauge-value" style={{ color }}>{clamped.toFixed(1)}%</div>
      <div className="gauge-label">{label}</div>
    </div>
  )
}

export default function Dashboard() {
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(true)
  const wsRef = useRef(null)

  const loadData = useCallback(async () => {
    try {
      const d = await fetchDashboard()
      setData(d)
    } catch (e) {
      console.error('Dashboard fetch error:', e)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    loadData()
    const interval = setInterval(loadData, 10000)

    const ws = connectWS('/ws', localStorage.getItem('token') || '')
    wsRef.current = ws

    ws.onmessage = (event) => {
      try {
        const msg = JSON.parse(event.data)
        if (msg.type === 'metrics_update' && msg.servers) {
          setData((prev) => {
            if (!prev) return prev
            const newServers = prev.servers.map((s) => {
              const update = msg.servers.find((u) => u.id === s.id)
              if (!update) return s
              return {
                ...s,
                status: update.status ?? s.status,
                cpu_percent: update.cpu_percent ?? s.cpu_percent,
                memory_percent: update.memory_percent ?? s.memory_percent,
                disk_percent: update.disk_percent ?? s.disk_percent,
                network_in_mbps: update.network_in_mbps ?? s.network_in_mbps,
                network_out_mbps: update.network_out_mbps ?? s.network_out_mbps,
                alerts: update.alerts ?? s.alerts,
              }
            })
            return {
              ...prev,
              servers: newServers,
              summary: {
                total: newServers.length,
                online: newServers.filter((s) => s.status === 'online' || s.status === 'monitored').length,
                warning: newServers.filter((s) => s.status === 'warning').length,
                critical: newServers.filter((s) => s.status === 'critical').length,
                offline: newServers.filter((s) => s.status === 'offline').length,
                total_alerts: newServers.reduce((sum, s) => sum + (s.alerts || 0), 0),
              },
            }
          })
        }
      } catch (e) { }
    }

    ws.onclose = () => { }

    return () => {
      clearInterval(interval)
      ws.close()
    }
  }, [loadData])

  if (loading) {
    return <div className="page-loading">加载中...</div>
  }

  if (!data) {
    return <div className="page-loading">暂无数据</div>
  }

  const { summary, servers, recent_alerts } = data

  return (
    <div className="dashboard">
      <h1 className="page-title"><Icon kind="nav-dashboard" size={18} /> 监控看板</h1>
      <p className="page-desc">全部服务器设备状态总览 — 数据每 10 秒自动刷新</p>

      <div className="summary-row">
        <div className="summary-card" style={{ borderLeftColor: '#0275d8' }}>
          <div className="summary-num">{summary.total}</div>
          <div className="summary-tag">服务器总数</div>
        </div>
        <div className="summary-card" style={{ borderLeftColor: '#5cb85c' }}>
          <div className="summary-num">{summary.online}</div>
          <div className="summary-tag">正常运行</div>
        </div>
        <div className="summary-card" style={{ borderLeftColor: '#f0ad4e' }}>
          <div className="summary-num">{summary.warning}</div>
          <div className="summary-tag">警告</div>
        </div>
        <div className="summary-card" style={{ borderLeftColor: '#d9534f' }}>
          <div className="summary-num">{summary.critical}</div>
          <div className="summary-tag">严重</div>
        </div>
        <div className="summary-card" style={{ borderLeftColor: '#d9534f' }}>
          <div className="summary-num">{summary.total_alerts}</div>
          <div className="summary-tag">未处理告警</div>
        </div>
      </div>

      <h2 className="section-title">服务器运行概况</h2>
      <div className="server-grid">
        {servers.map((s) => (
          <div key={s.id} className="server-card">
            <div className="server-card-header">
              <div className="server-card-name">
                <span className="server-os-icon"><Icon kind="host-generic" size={15} /></span>
                <span>{s.name}</span>
              </div>
              <span
                className="status-badge"
                style={{
                  background: STATUS_MAP[s.status]?.bg || '#f8f9fa',
                  color: STATUS_MAP[s.status]?.color || '#adb5bd',
                }}
              >
                {STATUS_MAP[s.status]?.label || '未知'}
              </span>
            </div>
            <div className="server-card-meta">
              <span className="meta-tag">{s.os_type}</span>
            </div>
            <div className="server-card-metrics">
              <div className="metric-mini">
                <span className="metric-mini-label">CPU</span>
                <div className="mini-bar">
                  <div
                    className="mini-bar-fill"
                    style={{
                      width: `${Math.min(100, s.cpu_percent)}%`,
                      background: s.cpu_percent > 90 ? '#d9534f' : s.cpu_percent > 75 ? '#f0ad4e' : '#5cb85c',
                    }}
                  />
                </div>
                <span className="metric-mini-val">{s.cpu_percent.toFixed(0)}%</span>
              </div>
              <div className="metric-mini">
                <span className="metric-mini-label">内存</span>
                <div className="mini-bar">
                  <div
                    className="mini-bar-fill"
                    style={{
                      width: `${Math.min(100, s.memory_percent)}%`,
                      background: s.memory_percent > 90 ? '#d9534f' : s.memory_percent > 80 ? '#f0ad4e' : '#5cb85c',
                    }}
                  />
                </div>
                <span className="metric-mini-val">{s.memory_percent.toFixed(0)}%</span>
              </div>
              <div className="metric-mini">
                <span className="metric-mini-label">磁盘</span>
                <div className="mini-bar">
                  <div
                    className="mini-bar-fill"
                    style={{
                      width: `${Math.min(100, s.disk_percent)}%`,
                      background: s.disk_percent > 95 ? '#d9534f' : s.disk_percent > 85 ? '#f0ad4e' : '#5cb85c',
                    }}
                  />
                </div>
                <span className="metric-mini-val">{s.disk_percent.toFixed(0)}%</span>
              </div>
            </div>
            {s.alerts > 0 && (
              <div className="server-card-alert"><Icon kind="ui-warning" size={11} /> 未处理告警: {s.alerts}</div>
            )}
          </div>
        ))}
      </div>

      <h2 className="section-title">最近告警</h2>
      <div className="alerts-table-wrap">
        {recent_alerts && recent_alerts.length > 0 ? (
          <table className="alerts-table">
            <thead>
              <tr>
                <th>时间</th>
                <th>服务器</th>
                <th>级别</th>
                <th>标题</th>
                <th>状态</th>
              </tr>
            </thead>
            <tbody>
              {recent_alerts.map((a) => (
                <tr key={a.id}>
                  <td className="td-time">{formatDateTime(a.timestamp)}</td>
                  <td>{a.server_name}</td>
                  <td>
                    <span
                      className="alert-level-badge"
                      style={{
                        background: ALERT_LEVEL[a.level]?.bg || '#f8f9fa',
                        color: ALERT_LEVEL[a.level]?.color || '#6c757d',
                      }}
                    >
                      {a.level === 'critical' ? '严重' : a.level === 'warning' ? '警告' : '信息'}
                    </span>
                  </td>
                  <td>{a.title}</td>
                  <td>
                    <span className={a.acknowledged ? 'ack-badge done' : 'ack-badge pending'}>
                      {a.acknowledged ? '已确认' : '未确认'}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <div className="empty-state">暂无告警，系统运行正常 <Icon kind="ui-check" size={13} /></div>
        )}
      </div>
    </div>
  )
}
