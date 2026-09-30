import { useState, useEffect } from 'react'
import './ServiceConfigModal.css'

const FIELDS = [
  { key: 'name', label: '名称' },
  { key: 'display_name', label: '显示名称' },
  { key: 'process_name', label: '进程名' },
  { key: 'path', label: '路径' },
  { key: 'port', label: '端口', numeric: true },
  { key: 'pid', label: 'PID', numeric: true },
  { key: 'description', label: '描述' },
]

const OPERATORS = [
  { key: 'contains', label: '包含', needsValue: true },
  { key: 'not_contains', label: '不包含', needsValue: true },
  { key: 'equals', label: '等于', needsValue: true, numeric: true },
  { key: 'not_equals', label: '不等于', needsValue: true, numeric: true },
  { key: 'startsWith', label: '开头是', needsValue: true },
  { key: 'endsWith', label: '结尾是', needsValue: true },
  { key: 'regex', label: '正则匹配', needsValue: true },
  { key: 'notEmpty', label: '不为空', needsValue: false },
  { key: 'empty', label: '为空', needsValue: false },
  { key: 'greaterThan', label: '大于', needsValue: true, numeric: true },
  { key: 'lessThan', label: '小于', needsValue: true, numeric: true },
]

function matchRule(item, rule) {
  const field = rule.field
  const raw = item[field]
  const value = raw == null ? '' : String(raw)
  const test = rule.value == null ? '' : String(rule.value)
  const numValue = Number(test)
  const numRaw = Number(value)

  switch (rule.operator) {
    case 'contains':
      return value.toLowerCase().includes(test.toLowerCase())
    case 'not_contains':
      return !value.toLowerCase().includes(test.toLowerCase())
    case 'equals':
      return value.toLowerCase() === test.toLowerCase()
    case 'not_equals':
      return value.toLowerCase() !== test.toLowerCase()
    case 'startsWith':
      return value.toLowerCase().startsWith(test.toLowerCase())
    case 'endsWith':
      return value.toLowerCase().endsWith(test.toLowerCase())
    case 'regex':
      try {
        const re = new RegExp(test, 'i')
        return re.test(value)
      } catch {
        return false
      }
    case 'notEmpty':
      return value.trim() !== '' && numRaw !== 0
    case 'empty':
      return value.trim() === '' || numRaw === 0
    case 'greaterThan':
      return !isNaN(numRaw) && !isNaN(numValue) && numRaw > numValue
    case 'lessThan':
      return !isNaN(numRaw) && !isNaN(numValue) && numRaw < numValue
    default:
      return true
  }
}

export function applyServiceFilter(items, filter) {
  if (!filter || !filter.enabled || !filter.rules || filter.rules.length === 0) {
    return items || []
  }
  const combine = filter.combine || 'AND'
  return (items || []).filter((item) => {
    const results = filter.rules.map((rule) => matchRule(item, rule))
    if (combine === 'OR') {
      return results.some(Boolean)
    }
    return results.every(Boolean)
  })
}

export default function ServiceConfigModal({ visible, onClose, serverId, services = [], pendingServices = [], onRefresh, filter = null }) {
  const [enabled, setEnabled] = useState(false)
  const [combine, setCombine] = useState('AND')
  const [rules, setRules] = useState([])
  const [saving, setSaving] = useState(false)

  useEffect(() => {
    if (visible) {
      const current = filter || {}
      setEnabled(current.enabled || false)
      setCombine(current.combine || 'AND')
      setRules((current.rules && current.rules.length > 0) ? current.rules.map(r => ({ ...r })) : [{
        field: 'name',
        operator: 'contains',
        value: '',
      }])
    }
  }, [visible, filter])

  const handleAddRule = () => {
    setRules(prev => [...prev, { field: 'name', operator: 'contains', value: '' }])
  }

  const handleRemoveRule = (idx) => {
    setRules(prev => prev.filter((_, i) => i !== idx))
  }

  const updateRule = (idx, key, val) => {
    setRules(prev => prev.map((r, i) => {
      if (i !== idx) return r
      const next = { ...r, [key]: val }
      if (key === 'field') {
        const fieldMeta = FIELDS.find(f => f.key === val)
        const opMeta = OPERATORS.find(o => o.key === next.operator)
        if (fieldMeta?.numeric && !opMeta?.numeric) {
          next.operator = 'greaterThan'
          next.value = ''
        } else if (!fieldMeta?.numeric && opMeta?.numeric) {
          next.operator = 'contains'
          next.value = ''
        }
      }
      return next
    }))
  }

  const handleSave = async () => {
    setSaving(true)
    try {
      const { updateServer } = await import('../services/api')
      const cleanRules = rules
        .filter(r => r.operator === 'notEmpty' || r.operator === 'empty' || String(r.value).trim() !== '')
        .map(r => ({ field: r.field, operator: r.operator, value: String(r.value) }))
      const newFilter = {
        enabled: cleanRules.length > 0 ? enabled : false,
        combine,
        rules: cleanRules,
      }
      await updateServer(serverId, { extra_config: { service_filter: newFilter } })
      onRefresh && onRefresh()
      onClose()
    } catch (e) {
      alert('保存筛选条件失败：' + (e.message || '未知错误'))
    } finally {
      setSaving(false)
    }
  }

  const handleClear = async () => {
    setSaving(true)
    try {
      const { updateServer } = await import('../services/api')
      await updateServer(serverId, { extra_config: { service_filter: { enabled: false, combine: 'AND', rules: [] } } })
      onRefresh && onRefresh()
      onClose()
    } catch (e) {
      alert('清除筛选条件失败：' + (e.message || '未知错误'))
    } finally {
      setSaving(false)
    }
  }

  if (!visible) return null

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="service-config-modal filter-modal" onClick={(e) => e.stopPropagation()}>
        <div className="modal-header">
          <h2>进程管理筛选</h2>
          <button className="modal-close" onClick={onClose}>×</button>
        </div>

        <div className="filter-body">
          <div className="filter-toolbar">
            <label className="filter-toggle">
              <input
                type="checkbox"
                checked={enabled}
                onChange={(e) => setEnabled(e.target.checked)}
              />
              <span>启用筛选</span>
            </label>
            <div className="filter-combine">
              <span>组合方式：</span>
              <label>
                <input
                  type="radio"
                  name="combine"
                  value="AND"
                  checked={combine === 'AND'}
                  onChange={() => setCombine('AND')}
                  disabled={!enabled}
                />
                全部满足（AND）
              </label>
              <label>
                <input
                  type="radio"
                  name="combine"
                  value="OR"
                  checked={combine === 'OR'}
                  onChange={() => setCombine('OR')}
                  disabled={!enabled}
                />
                任一满足（OR）
              </label>
            </div>
          </div>

          <div className="filter-rules">
            {rules.map((rule, idx) => {
              const fieldMeta = FIELDS.find(f => f.key === rule.field)
              const opMeta = OPERATORS.find(o => o.key === rule.operator)
              const numericField = fieldMeta?.numeric
              return (
                <div key={idx} className="filter-rule">
                  <select
                    value={rule.field}
                    onChange={(e) => updateRule(idx, 'field', e.target.value)}
                    disabled={!enabled}
                  >
                    {FIELDS.map(f => <option key={f.key} value={f.key}>{f.label}</option>)}
                  </select>
                  <select
                    value={rule.operator}
                    onChange={(e) => updateRule(idx, 'operator', e.target.value)}
                    disabled={!enabled}
                  >
                    {OPERATORS.filter(o => !numericField || o.numeric || (!o.numeric && !o.needsValue)).map(o => (
                      <option key={o.key} value={o.key}>{o.label}</option>
                    ))}
                  </select>
                  {opMeta?.needsValue && (
                    <input
                      type={numericField ? 'number' : 'text'}
                      value={rule.value}
                      onChange={(e) => updateRule(idx, 'value', e.target.value)}
                      placeholder={numericField ? '0' : '输入匹配值'}
                      disabled={!enabled}
                    />
                  )}
                  <button
                    className="btn-remove-rule"
                    onClick={() => handleRemoveRule(idx)}
                    disabled={!enabled}
                    title="删除条件"
                  >
                    －
                  </button>
                </div>
              )
            })}
            <button
              className="btn-add-rule"
              onClick={handleAddRule}
              disabled={!enabled}
            >
              ＋ 添加条件
            </button>
          </div>

        </div>

        <div className="filter-actions">
          <button className="btn-clear-filter" onClick={handleClear} disabled={saving}>
            清除筛选
          </button>
          <div className="filter-actions-right">
            <button className="btn-cancel" onClick={onClose} disabled={saving}>
              取消
            </button>
            <button className="btn-save" onClick={handleSave} disabled={saving}>
              {saving ? '保存中...' : '保存'}
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}
