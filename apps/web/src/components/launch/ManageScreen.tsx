'use client'
import { useState } from 'react'
import { getApiBaseUrl } from '@/lib/apiBase'
import { card, field, label, input, btnPrimary, btnDanger } from './styles'
import { DeleteConfirmOverlay } from './DeleteConfirmOverlay'

type Tab = 'profile' | 'danger'

interface Props {
  profile: { callsign: string; role: string }
  onBack: () => void
  onSaved: (p: { callsign: string; role: string }) => void
  onDeleted: () => void
}

export function ManageScreen({ profile, onBack, onSaved, onDeleted }: Props) {
  const [tab, setTab] = useState<Tab>('profile')
  const [callsign, setCallsign] = useState(profile.callsign)
  const [passphrase, setPassphrase] = useState('')
  const [error, setError] = useState('')
  const [saving, setSaving] = useState(false)
  const [showConfirm, setShowConfirm] = useState(false)
  const [deleting, setDeleting] = useState(false)

  async function handleSave(e: React.FormEvent) {
    e.preventDefault()
    setError('')
    if (passphrase && passphrase.length < 8) {
      setError('Passphrase must be at least 8 characters'); return
    }
    setSaving(true)
    try {
      const body: Record<string, string> = {}
      if (callsign.trim() !== profile.callsign) body['callsign'] = callsign.trim()
      if (passphrase) body['passphrase'] = passphrase

      const res = await fetch(`${getApiBaseUrl()}/setup/profile`, {
        method: 'PUT',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest' },
        body: JSON.stringify(body),
      })
      if (!res.ok) {
        const e = await res.json().catch(() => ({})) as { detail?: string }
        setError(e.detail || 'Save failed'); return
      }
      const updated = await res.json() as { callsign: string; role: string }
      onSaved(updated)
    } catch {
      setError('Could not reach API')
    } finally {
      setSaving(false)
    }
  }

  async function handleDelete() {
    setDeleting(true)
    try {
      const res = await fetch(`${getApiBaseUrl()}/setup/profile`, {
        method: 'DELETE',
        credentials: 'include',
        headers: { 'X-Requested-With': 'XMLHttpRequest' },
      })
      if (!res.ok) {
        setError('Delete failed — server returned an error')
        return
      }
      onDeleted()
    } catch {
      setError('Delete failed')
    } finally {
      setDeleting(false)
      setShowConfirm(false)
    }
  }

  return (
    <div style={{ ...card, position: 'relative' }}>
      {showConfirm && (
        <DeleteConfirmOverlay
          onCancel={() => setShowConfirm(false)}
          onConfirm={handleDelete}
          loading={deleting}
        />
      )}
      <div style={tabs}>
        <button style={tabBtn} onClick={onBack}>← Back</button>
        <button style={{ ...tabBtn, ...(tab === 'profile' ? tabActive : {}) }}
          onClick={() => setTab('profile')}>Profile</button>
        <button style={{ ...tabBtn, ...(tab === 'danger' ? tabActive : {}) }}
          onClick={() => setTab('danger')}>Danger</button>
      </div>

      {tab === 'profile' && (
        <form onSubmit={handleSave}>
          <div style={field}>
            <label style={label}>Callsign</label>
            <input style={input} value={callsign} onChange={e => setCallsign(e.target.value)} />
          </div>
          <div style={field}>
            <label style={label}>New passphrase</label>
            <input style={input} type="password"
              placeholder="leave blank to keep current"
              value={passphrase} onChange={e => setPassphrase(e.target.value)} />
          </div>
          {error && <div style={errStyle}>{error}</div>}
          <button style={{ ...btnPrimary, opacity: saving ? 0.7 : 1 }} type="submit" disabled={saving}>
            {saving ? 'Saving…' : 'Save changes'}
          </button>
        </form>
      )}

      {tab === 'danger' && (
        <div>
          <div style={{ color: '#4a2020', fontSize: 11, marginBottom: 20, lineHeight: 1.8, fontFamily: '"Share Tech Mono", monospace', letterSpacing: 1 }}>
            Permanently destroys the operator covenant, purges the local database, and erases all assessment records from existence.
          </div>
          <button style={btnDanger} onClick={() => setShowConfirm(true)}>
            ⚠ Destroy Covenant + Purge All Data
          </button>
        </div>
      )}
    </div>
  )
}

const tabs: React.CSSProperties = {
  display: 'flex', gap: 0, background: 'rgba(10,0,0,0.5)',
  borderRadius: 2, padding: 4, marginBottom: 28,
  border: '1px solid rgba(80,0,0,0.3)',
}
const tabBtn: React.CSSProperties = {
  flex: 1, padding: 8, borderRadius: 2, textAlign: 'center',
  fontSize: 10, cursor: 'pointer', color: '#4a2020',
  background: 'transparent', border: 'none',
  letterSpacing: 2, textTransform: 'uppercase',
  fontFamily: '"Share Tech Mono", monospace',
}
const tabActive: React.CSSProperties = {
  background: 'rgba(100,0,0,0.25)', color: '#cc2020',
  border: '1px solid rgba(139,0,0,0.4)',
}
const errStyle: React.CSSProperties = {
  color: '#cc2020', fontSize: 12, marginBottom: 10,
  padding: '8px 12px', background: 'rgba(100,0,0,0.12)',
  borderRadius: 2, border: '1px solid rgba(139,0,0,0.3)',
  fontFamily: '"Share Tech Mono", monospace',
  letterSpacing: 1,
}
