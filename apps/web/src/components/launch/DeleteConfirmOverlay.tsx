'use client'

interface Props {
  onCancel: () => void
  onConfirm: () => void
  loading: boolean
}

export function DeleteConfirmOverlay({ onCancel, onConfirm, loading }: Props) {
  return (
    <div style={overlay}>
      <div style={confirmCard}>
        <div style={{ fontSize: 32, marginBottom: 12 }}>⚠️</div>
        <div style={title}>Wipe everything?</div>
        <div style={msg}>
          This deletes the operator account, the local database, and all assessment data.{' '}
          <strong style={{ color: '#f87171' }}>This cannot be undone.</strong>
        </div>
        <div style={btns}>
          <button style={cancelBtn} onClick={onCancel} disabled={loading}>Cancel</button>
          <button style={deleteBtn} onClick={onConfirm} disabled={loading}>
            {loading ? 'Wiping…' : 'Yes, wipe it'}
          </button>
        </div>
      </div>
    </div>
  )
}

const overlay: React.CSSProperties = {
  position: 'absolute', inset: 0,
  display: 'flex', alignItems: 'center', justifyContent: 'center',
  zIndex: 10, backdropFilter: 'blur(4px)', background: 'rgba(0,0,0,0.4)',
}
const confirmCard: React.CSSProperties = {
  background: '#12101e', border: '1px solid rgba(239,68,68,0.3)',
  borderRadius: 16, padding: 32, width: 340, textAlign: 'center',
  boxShadow: '0 0 60px rgba(239,68,68,0.15)',
}
const title: React.CSSProperties = { fontSize: 18, fontWeight: 700, color: '#f1f5f9', marginBottom: 8 }
const msg: React.CSSProperties = { fontSize: 13, color: '#6b7280', marginBottom: 24, lineHeight: 1.6 }
const btns: React.CSSProperties = { display: 'flex', gap: 10 }
const cancelBtn: React.CSSProperties = {
  flex: 1, padding: 11, borderRadius: 8, fontSize: 13, fontWeight: 600,
  cursor: 'pointer', background: 'rgba(139,92,246,0.1)',
  border: '1px solid rgba(139,92,246,0.2)', color: '#a78bfa',
}
const deleteBtn: React.CSSProperties = {
  flex: 1, padding: 11, borderRadius: 8, fontSize: 13, fontWeight: 600,
  cursor: 'pointer', background: 'linear-gradient(90deg, #dc2626, #b91c1c)',
  border: 'none', color: '#fff',
}
