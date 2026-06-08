'use client'
import { useEffect, useState } from 'react'
import { getApiBaseUrl } from '@/lib/apiBase'
import { card, cardTitle, btnPrimary, btnGhost } from './styles'

interface Props {
  profile: { callsign: string; role: string }
  onManage: () => void
  onLaunch: () => void
}

interface ServiceStatus {
  api: boolean
  web: boolean
  db: boolean
}

export function ReturningScreen({ profile, onManage, onLaunch }: Props) {
  const [status, setStatus] = useState<ServiceStatus>({ api: false, web: false, db: false })

  useEffect(() => {
    async function checkServices() {
      try {
        const res = await fetch(`${getApiBaseUrl()}/health`)
        if (res.ok) {
          const data = await res.json() as Record<string, unknown>
          setStatus({
            api: true,
            web: true,
            db: data['database'] === 'ok' || data['db'] === 'ok',
          })
        }
      } catch {
        setStatus({ api: false, web: true, db: false })
      }
    }
    checkServices()
    const id = setInterval(checkServices, 5000)
    return () => clearInterval(id)
  }, [])

  const initials = profile.callsign.slice(0, 2).toUpperCase()

  return (
    <div style={card} className="launch-card">
      <div style={avatarStyle}>{initials}</div>
      <div style={{ ...cardTitle, textAlign: 'center' }}>{profile.callsign}</div>
      <div style={roleStyle}>{profile.role}</div>
      <div style={statusRow}>
        <StatusDot label="API :8000" on={status.api} />
        <StatusDot label="Web :3000" on={status.web} />
        <StatusDot label="DB" on={status.db} />
      </div>
      <button style={btnPrimary} onClick={onLaunch}>Enter the Abyss →</button>
      <button style={btnGhost} onClick={onManage}>Manage Covenant</button>
    </div>
  )
}

function StatusDot({ label, on }: { label: string; on: boolean }) {
  return (
    <div style={dotWrap}>
      <span style={{
        ...dot,
        background: on ? '#cc0000' : '#2a1010',
        boxShadow: on ? '0 0 8px rgba(200,0,0,0.8)' : 'none',
      }} />
      <span style={{ fontSize: 10, color: on ? '#cc2020' : '#3a1515', fontFamily: '"Share Tech Mono", monospace', letterSpacing: 1 }}>{label}</span>
    </div>
  )
}

const avatarStyle: React.CSSProperties = {
  width: 64, height: 64, borderRadius: '50%',
  background: 'linear-gradient(135deg, #3d0000, #8b0000)',
  display: 'flex', alignItems: 'center', justifyContent: 'center',
  fontSize: 22, fontWeight: 700, color: '#e8d8c8',
  margin: '0 auto 20px',
  boxShadow: '0 0 30px rgba(139,0,0,0.6)',
  fontFamily: '"Cinzel", serif',
  letterSpacing: 2,
  border: '1px solid rgba(180,0,0,0.4)',
}
const roleStyle: React.CSSProperties = {
  textAlign: 'center', fontSize: 10, letterSpacing: 4,
  color: '#6b0000', textTransform: 'uppercase', marginBottom: 28,
  fontFamily: '"Share Tech Mono", monospace',
}
const statusRow: React.CSSProperties = {
  display: 'flex', gap: 8, marginBottom: 20, padding: '10px 14px',
  background: 'rgba(10,0,0,0.5)', borderRadius: 2,
  border: '1px solid rgba(80,0,0,0.3)',
}
const dotWrap: React.CSSProperties = {
  display: 'flex', alignItems: 'center', gap: 6, flex: 1,
}
const dot: React.CSSProperties = {
  width: 7, height: 7, borderRadius: '50%', display: 'inline-block',
}
