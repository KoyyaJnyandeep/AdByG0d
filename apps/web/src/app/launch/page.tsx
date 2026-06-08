'use client'
import { useEffect, useState } from 'react'
import { getApiBaseUrl } from '@/lib/apiBase'
import { FirstRunScreen } from '@/components/launch/FirstRunScreen'
import { ReturningScreen } from '@/components/launch/ReturningScreen'
import { ManageScreen } from '@/components/launch/ManageScreen'

type Screen = 'loading' | 'first-run' | 'returning' | 'manage'

interface Profile {
  callsign: string
  role: string
}

export default function LaunchPage() {
  const [screen, setScreen] = useState<Screen>('loading')
  const [profile, setProfile] = useState<Profile | null>(null)

  useEffect(() => {
    async function tryFetch(timeoutMs: number): Promise<Response> {
      const controller = new AbortController()
      const timer = setTimeout(() => controller.abort(), timeoutMs)
      try {
        const res = await fetch(`${getApiBaseUrl()}/setup/status`, {
          signal: controller.signal,
          cache: 'no-store',
        })
        return res
      } finally {
        clearTimeout(timer)
      }
    }

    async function checkStatus() {
      // Two-attempt strategy: quick first probe, longer fallback.
      // start.sh pre-warms this page so the API should respond immediately,
      // but on slower machines the API can still be initialising mid-compile.
      let res: Response | null = null
      try {
        res = await tryFetch(4000)
      } catch {
        try {
          res = await tryFetch(6000)
        } catch {
          setScreen('first-run')
          return
        }
      }

      if (!res || !res.ok) { setScreen('first-run'); return }

      try {
        const data = await res.json()
        if (data.setup_complete && data.profile) {
          setProfile(data.profile)
          setScreen('returning')
        } else {
          setScreen('first-run')
        }
      } catch {
        setScreen('first-run')
      }
    }

    checkStatus()
  }, [])

  const handleInitDone = (p: Profile) => {
    setProfile(p)
    window.location.href = '/'
  }

  const handleDeleteDone = () => {
    setProfile(null)
    setScreen('first-run')
  }

  if (screen === 'loading') return <LoadingPulse />

  return (
    <div style={outerStyle}>
      <div style={glowTop} />
      <div style={glowBottom} />
      <TopBar />
      <div style={centerStyle}>
        {screen === 'first-run' && <FirstRunScreen onDone={handleInitDone} />}
        {screen === 'returning' && profile && (
          <ReturningScreen
            profile={profile}
            onManage={() => setScreen('manage')}
            onLaunch={() => { window.location.href = '/' }}
          />
        )}
        {screen === 'manage' && profile && (
          <ManageScreen
            profile={profile}
            onBack={() => setScreen('returning')}
            onSaved={(p) => { setProfile(p); setScreen('returning') }}
            onDeleted={handleDeleteDone}
          />
        )}
      </div>
    </div>
  )
}

function TopBar() {
  return (
    <div style={topBarStyle}>
      <span style={logoStyle}>AdByG0d</span>
      <span style={versionStyle}>v1.0.0</span>
    </div>
  )
}

function LoadingPulse() {
  const [elapsed, setElapsed] = useState(0)
  useEffect(() => {
    const t = setInterval(() => setElapsed(s => s + 1), 1000)
    return () => clearInterval(t)
  }, [])

  return (
    <div style={{ ...outerStyle, alignItems: 'center', justifyContent: 'center', gap: 16 }}>
      <div style={{ display: 'flex', gap: 8 }}>
        {[0, 1, 2].map(i => (
          <div key={i} style={{
            width: 10, height: 10, borderRadius: '50%',
            background: 'rgba(139,92,246,0.6)',
            animation: `pulse 1.2s ease-in-out ${i * 0.2}s infinite`,
          }} />
        ))}
      </div>
      {elapsed >= 5 && (
        <div style={{ fontFamily: 'monospace', fontSize: 11, color: 'rgba(139,92,246,0.5)', letterSpacing: '0.15em' }}>
          CONNECTING TO BACKEND{'.'.repeat((elapsed % 3) + 1)}
        </div>
      )}
      <style>{`
        @keyframes pulse {
          0%, 100% { opacity: 0.3; transform: scale(0.8); }
          50% { opacity: 1; transform: scale(1.2); }
        }
      `}</style>
    </div>
  )
}

const outerStyle: React.CSSProperties = {
  minHeight: '100vh', display: 'flex', flexDirection: 'column',
  position: 'relative', overflow: 'hidden',
}
const glowTop: React.CSSProperties = {
  position: 'absolute', top: -80, left: '50%', transform: 'translateX(-50%)',
  width: 500, height: 350,
  background: 'radial-gradient(ellipse, rgba(139,92,246,0.18) 0%, transparent 70%)',
  pointerEvents: 'none',
}
const glowBottom: React.CSSProperties = {
  position: 'absolute', bottom: -80, right: -80, width: 400, height: 400,
  background: 'radial-gradient(ellipse, rgba(236,72,153,0.1) 0%, transparent 70%)',
  pointerEvents: 'none',
}
const topBarStyle: React.CSSProperties = {
  padding: '16px 28px', display: 'flex', alignItems: 'center', justifyContent: 'space-between',
  borderBottom: '1px solid rgba(139,92,246,0.1)', position: 'relative', zIndex: 1,
}
const logoStyle: React.CSSProperties = {
  fontSize: 16, fontWeight: 700, letterSpacing: 1,
  background: 'linear-gradient(90deg, #a78bfa, #ec4899)',
  WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent',
}
const versionStyle: React.CSSProperties = { fontSize: 11, color: '#4b5563', letterSpacing: 2 }
const centerStyle: React.CSSProperties = {
  flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center',
  padding: '40px 24px', position: 'relative', zIndex: 1,
}
