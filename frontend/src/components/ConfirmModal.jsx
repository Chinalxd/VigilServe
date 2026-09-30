import './ConfirmModal.css'

export default function ConfirmModal({ visible, title, message, onConfirm, onCancel, danger = false }) {
  if (!visible) return null
  return (
    <div className="confirm-overlay" onClick={onCancel}>
      <div className="confirm-modal" onClick={(e) => e.stopPropagation()}>
        <h3 className="confirm-title">{title || '确认操作'}</h3>
        <p className="confirm-message">{message || '确定要执行此操作吗？'}</p>
        <div className="confirm-buttons">
          <button className="confirm-btn cancel" onClick={onCancel}>取消</button>
          <button className={`confirm-btn ${danger ? 'danger' : 'primary'}`} onClick={onConfirm}>确定</button>
        </div>
      </div>
    </div>
  )
}
