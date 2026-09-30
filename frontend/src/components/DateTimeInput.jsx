import { useState, useEffect, useRef } from 'react'
import { parseServerTime } from '../utils/format'
import './DateTimeInput.css'
import Icon from './AppIcon'

const pad = (n) => String(n).padStart(2, '0')

function toDisplayText(value) {
  if (!value) return ''
  const d = parseServerTime(value)
  if (isNaN(d.getTime())) return String(value)
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}`
}

function toDateTimeLocal(value) {
  if (!value) return ''
  const d = parseServerTime(value)
  if (isNaN(d.getTime())) return ''
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`
}

function parseInput(str) {
  if (!str) return null
  const normalized = str.replace('T', ' ').trim()
  const d = parseServerTime(normalized)
  return isNaN(d.getTime()) ? null : d.toISOString()
}

/**
 * Custom datetime input that always displays YYYY-MM-DD HH:mm:ss.
 * Uses a hidden native datetime-local picker for the calendar UI.
 */
export default function DateTimeInput({ value, onChange, placeholder = 'YYYY-MM-DD HH:mm', className = '' }) {
  const [text, setText] = useState(() => toDisplayText(value))
  const hiddenRef = useRef(null)

  useEffect(() => {
    setText(toDisplayText(value))
  }, [value])

  const handleTextChange = (e) => {
    const str = e.target.value
    setText(str)
    const iso = parseInput(str)
    if (iso) {
      onChange(iso)
    }
  }

  const handleBlur = () => {
    const iso = parseInput(text)
    if (iso) {
      setText(toDisplayText(iso))
      onChange(iso)
    } else if (!text) {
      onChange('')
    } else {
      setText(toDisplayText(value))
    }
  }

  const handleHiddenChange = (e) => {
    const iso = parseInput(e.target.value)
    if (iso) {
      setText(toDisplayText(iso))
      onChange(iso)
    }
  }

  return (
    <div className={`datetime-input-wrap ${className}`}>
      <input
        type="text"
        className="datetime-text form-input-sm"
        value={text}
        onChange={handleTextChange}
        onBlur={handleBlur}
        placeholder={placeholder}
      />
      <button
        type="button"
        className="datetime-picker-btn"
        onClick={() => hiddenRef.current?.showPicker?.()}
        title="选择日期时间"
      >
        <Icon kind="ui-calendar" size={14} />
      </button>
      <input
        ref={hiddenRef}
        type="datetime-local"
        className="datetime-hidden"
        value={toDateTimeLocal(value)}
        onChange={handleHiddenChange}
      />
    </div>
  )
}
