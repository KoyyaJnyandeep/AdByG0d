'use client'
import { useState } from 'react'
import { getApiBaseUrl } from '@/lib/apiBase'
import { card, cardTitle, cardSub, field, label, input, btnPrimary } from './styles'

interface Props {
  onDone: (profile: { callsign: string; role: string }) => void
}

export function FirstRunScreen({ onDone }: Props) {
  const [callsign, setCallsign] = useState('')
  const [passphrase, setPassphrase] = useState('')
  const [confirm, setConfirm] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    setError('')
    if (!callsign.trim()) { setError('Callsign is required'); return }
    if (passphrase.length < 8) { setError('Passphrase must be at least 8 characters'); return }
    if (passphrase !== confirm) { setError('Passphrases do not match'); return }

    setLoading(true)
    try {
      const res = await fetch(`${getApiBaseUrl()}/setup/init`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ callsign: callsign.trim(), passphrase }),
      })
      if (!res.ok) {
        const err = await res.json().catch(() => ({}))
        setError((err as { detail?: string }).detail || 'Initialisation failed')
        return
      }
      const profile = await res.json()
      onDone(profile as { callsign: string; role: string })
    } catch {
      setError('Could not reach API — is the server running?')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div style={card} className="launch-card">
      <div style={cardTitle}>Bind Your Identity</div>
      <div style={cardSub}>one-time covenant — sealed in darkness, never demanded again</div>
      <form onSubmit={handleSubmit}>
        <div style={field}>
          <label style={label}>Designation</label>
          <input style={input} placeholder="your callsign" value={callsign}
            onChange={e => setCallsign(e.target.value)} autoFocus />
        </div>
        <div style={field}>
          <label style={label}>Blood Oath</label>
          <input style={input} type="password" placeholder="min 8 chars" value={passphrase}
            onChange={e => setPassphrase(e.target.value)} />
        </div>
        <div style={field}>
          <label style={label}>Confirm Oath</label>
          <input style={input} type="password" placeholder="repeat" value={confirm}
            onChange={e => setConfirm(e.target.value)} />
        </div>
        {error && <div style={errorStyle}>{error}</div>}
        <button style={{ ...btnPrimary, opacity: loading ? 0.7 : 1 }} type="submit" disabled={loading}>
          {loading ? 'Invoking…' : 'Invoke the Platform →'}
        </button>
      </form>
    </div>
  )
}

const errorStyle: React.CSSProperties = {
  color: '#f87171', fontSize: 13, marginBottom: 10,
  padding: '8px 12px', background: 'rgba(239,68,68,0.08)',
  borderRadius: 6, border: '1px solid rgba(239,68,68,0.2)',
}
