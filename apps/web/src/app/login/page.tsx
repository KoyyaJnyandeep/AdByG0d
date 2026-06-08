'use client'

import { FormEvent, useCallback, useEffect, useRef, useState } from 'react'
import { Lock, User, Loader2, AlertTriangle, Eye, EyeOff } from 'lucide-react'
import { authApi } from '@/lib/api'
import { getErrorDetail } from '@/lib/utils'

const OP_LOG_LINES = [
  '[00:42:11] Imported directory graph snapshot :: CORP.LOCAL',
  '[00:42:15] Kerberos posture review queued for analyst scoring',
  '[00:42:19] AD CS template exposure model refreshed',
  '[00:42:23] Shadow credential indicators flagged for review',
  '[00:42:28] Delegation paths re-scored against current graph',
  '[00:42:33] Tier-0 control edges corroborated with stored evidence',
  '[00:42:38] Risk narrative updated for report drafting',
  '[00:42:44] Imported path data normalized for research view',
  '[00:42:49] Trust boundary anomalies queued for follow-up',
  '[00:42:55] Session ready. Awaiting authenticated analyst.',
]

interface PublicAssessmentSummary {
  has_data: boolean
  name?: string | null
  domain?: string | null
  status?: string | null
  exposure_score: number
  total_findings: number
  critical_findings: number
  high_findings: number
  total_entities: number
  total_edges: number
  tier0_assets: number
  crown_jewels: number
  admin_accounts: number
  exposure_paths: number
  certificate_templates: number
  analysis_tracks: number
  research_modules: number
  zero_day_refs: number
  certificate_chains: number
  coverage: {
    kerberos: number
    adcs: number
    acl: number
    replication: number
    graph: number
  }
}

const EMPTY_SUMMARY: PublicAssessmentSummary = {
  has_data: false,
  exposure_score: 0,
  total_findings: 0,
  critical_findings: 0,
  high_findings: 0,
  total_entities: 0,
  total_edges: 0,
  tier0_assets: 0,
  crown_jewels: 0,
  admin_accounts: 0,
  exposure_paths: 0,
  certificate_templates: 0,
  analysis_tracks: 0,
  research_modules: 0,
  zero_day_refs: 0,
  certificate_chains: 0,
  coverage: { kerberos: 0, adcs: 0, acl: 0, replication: 0, graph: 0 },
}

function compact(value: number) {
  return new Intl.NumberFormat('en', { notation: 'compact', maximumFractionDigits: 1 }).format(value)
}


function DemonicSigil() {
  return (
    <svg viewBox="0 0 400 400" width="340" height="340" xmlns="http://www.w3.org/2000/svg"
      className="pointer-events-none select-none"
      style={{ opacity: 0.06, filter: 'blur(0.3px)' }}>
      <circle cx="200" cy="200" r="188" stroke="#C41230" strokeWidth="1.2" fill="none" />
      <circle cx="200" cy="200" r="160" stroke="#8B0000" strokeWidth="0.6" fill="none" strokeDasharray="4 8" />
      <circle cx="200" cy="200" r="130" stroke="#C41230" strokeWidth="0.8" fill="none" />
      {[0,1,2,3,4].map(i => {
        const a = (i * 72 - 90) * Math.PI / 180
        const b = ((i+2) * 72 - 90) * Math.PI / 180
        const c = ((i+1) * 72 - 90) * Math.PI / 180
        const r = 160
        return (
          <g key={i}>
            <line x1={200+r*Math.cos(a)} y1={200+r*Math.sin(a)} x2={200+r*Math.cos(b)} y2={200+r*Math.sin(b)} stroke="#C41230" strokeWidth="0.9" />
            <circle cx={200+r*Math.cos(c)} cy={200+r*Math.sin(c)} r="4" fill="#8B0000" />
          </g>
        )
      })}
      {[0,1,2,3,4,5,6,7].map(i => {
        const a = (i * 45) * Math.PI / 180
        const r1 = 130, r2 = 188
        return <line key={i} x1={200+r1*Math.cos(a)} y1={200+r1*Math.sin(a)} x2={200+r2*Math.cos(a)} y2={200+r2*Math.sin(a)} stroke="#6B0000" strokeWidth="0.5" strokeDasharray="2 6" />
      })}
      <circle cx="200" cy="200" r="18" stroke="#C41230" strokeWidth="1.5" fill="none" />
      <path d="M200 182 L207 194 L222 194 L211 203 L215 218 L200 209 L185 218 L189 203 L178 194 L193 194 Z" fill="none" stroke="#8B0000" strokeWidth="1" />
      <text x="200" y="84" textAnchor="middle" fontFamily="serif" fontSize="9" fill="#C41230" letterSpacing="3">ᚠᚢᚦᚨᚱᚲ</text>
      <text x="200" y="325" textAnchor="middle" fontFamily="serif" fontSize="9" fill="#C41230" letterSpacing="3">ᛏᛒᛖᛗᛚᛜ</text>
    </svg>
  )
}

function RuneCorner({ pos, rot }: { pos: string; rot: number }) {
  return (
    <div className={`absolute ${pos} pointer-events-none`} style={{ transform: `rotate(${rot}deg)` }}>
      <svg width="48" height="48" viewBox="0 0 48 48" fill="none">
        <path d="M2 40 L2 2 L40 2" stroke="#C41230" strokeWidth="1.5" strokeLinecap="square" />
        <path d="M2 2 L14 14" stroke="#8B0000" strokeWidth="0.8" />
        <circle cx="2" cy="2" r="2" fill="#C41230" />
        <path d="M8 2 L8 8 M14 2 L14 12 M20 2 L20 8" stroke="#6B0000" strokeWidth="0.6" />
      </svg>
    </div>
  )
}

function ScaryCursedTitle() {
  return (
    <div className="relative select-none inline-block">
      <style>{`
        @keyframes burn{0%,100%{text-shadow:0 0 8px #FF2200,0 0 24px #C41230,0 0 60px #6B0000,0 0 100px rgba(139,0,0,.4)}33%{text-shadow:0 0 14px #FF4400,0 0 40px #DC143C,0 0 80px #8B0000,0 0 140px rgba(180,0,0,.5),2px 2px 0 rgba(255,0,0,.1)}66%{text-shadow:0 0 6px #FF1100,0 0 18px #A00020,0 0 50px #500010,0 0 90px rgba(100,0,0,.3),-2px -1px 0 rgba(200,0,0,.08)}}
        @keyframes hellGlitch{0%,88%,100%{transform:none;filter:none}89%{transform:skewX(-8deg) translate(6px,-3px);filter:hue-rotate(180deg) brightness(2) contrast(1.5)}91%{transform:skewX(4deg) translate(-5px,2px);filter:brightness(0.8)}93%{transform:skewX(-3deg) translate(3px,-1px);filter:hue-rotate(90deg) brightness(1.6)}95%{transform:none;filter:none}96%{transform:translate(8px,0);filter:hue-rotate(0deg) brightness(1.3)}97.5%{transform:translate(-4px,1px)}99%{transform:none}}
        @keyframes hellGlitchLayer1{0%,88%,100%{opacity:0;transform:none}89%{opacity:.9;transform:translate(8px,0);color:#FF0000}92%{opacity:.6;transform:translate(-5px,0)}95%{opacity:0}}
        @keyframes hellGlitchLayer2{0%,90%,100%{opacity:0;transform:none}91%{opacity:.75;transform:translate(-9px,3px);color:#FF6600}94%{opacity:.4;transform:translate(4px,-2px)}97%{opacity:0}}
        .cursed-title{animation:burn 2.8s ease-in-out infinite,hellGlitch 9s infinite;font-family:'Cinzel Decorative',serif;color:#DC143C;letter-spacing:.05em}
        .cursed-layer1{animation:hellGlitchLayer1 9s infinite;clip-path:polygon(0 25%,100% 25%,100% 55%,0 55%)}
        .cursed-layer2{animation:hellGlitchLayer2 9s infinite;clip-path:polygon(0 60%,100% 60%,100% 85%,0 85%)}
      `}</style>
      <span className="cursed-title block text-5xl font-black">AdByG0d</span>
      <span className="cursed-layer1 pointer-events-none absolute inset-0 text-5xl font-black" style={{ fontFamily: "'Cinzel Decorative',serif", color: '#FF2200' }} aria-hidden>AdByG0d</span>
      <span className="cursed-layer2 pointer-events-none absolute inset-0 text-5xl font-black" style={{ fontFamily: "'Cinzel Decorative',serif", color: '#FF6600' }} aria-hidden>AdByG0d</span>
    </div>
  )
}

function BloodBar({ label, val, col }: { label: string; val: number; col: string }) {
  const [w, setW] = useState(0)
  useEffect(() => { const t = setTimeout(() => setW(val), 900); return () => clearTimeout(t) }, [val])
  return (
    <div className="space-y-1.5">
      <div className="flex justify-between" style={{ fontFamily: "'Share Tech Mono',monospace", fontSize: '10px' }}>
        <span style={{ color: 'rgba(180,140,120,.45)' }}>{label}</span>
        <span style={{ color: col, textShadow: `0 0 10px ${col}` }}>{val}%</span>
      </div>
      <div className="relative h-[3px] overflow-hidden" style={{ background: 'rgba(40,0,0,.8)', boxShadow: 'inset 0 0 4px rgba(0,0,0,.6)' }}>
        <div className="h-full transition-all duration-[2000ms] ease-out"
          style={{ width: `${w}%`, background: `linear-gradient(90deg,${col}44,${col}cc,${col})`, boxShadow: `0 0 12px ${col},0 0 6px ${col}88`, position: 'relative' }}>
          <div className="absolute right-0 top-0 bottom-0 w-[2px]" style={{ background: col, boxShadow: `0 0 8px ${col},0 0 16px ${col}` }} />
        </div>
        <div className="absolute inset-0" style={{ background: 'repeating-linear-gradient(90deg,transparent,transparent 6px,rgba(0,0,0,.25) 6px,rgba(0,0,0,.25) 7px)' }} />
      </div>
    </div>
  )
}

function LogStream() {
  const [off, setOff] = useState(0)
  useEffect(() => {
    const t = setInterval(() => setOff(o => (o + 1) % OP_LOG_LINES.length), 2400)
    return () => clearInterval(t)
  }, [])
  return (
    <div className="overflow-hidden h-8 relative">
      <div className="transition-transform duration-500 ease-in-out" style={{ transform: `translateY(-${off * 32}px)` }}>
        {OP_LOG_LINES.map((l, i) => <div key={i} className="h-8 flex items-center truncate" style={{ fontFamily: "'Share Tech Mono',monospace", fontSize: '9px', color: 'rgba(180,60,60,.5)' }}>{l}</div>)}
      </div>
      <div className="absolute inset-y-0 left-0 w-8" style={{ background: 'linear-gradient(90deg,rgba(5,0,2,.98),transparent)' }} />
      <div className="absolute inset-y-0 right-0 w-12" style={{ background: 'linear-gradient(270deg,rgba(5,0,2,.98),transparent)' }} />
    </div>
  )
}

function TypeWriter({ lines }: { lines: string[] }) {
  const [i, setI] = useState(0); const [t, setT] = useState(''); const [ch, setCh] = useState(0); const [d, setD] = useState(false)
  useEffect(() => {
    const cur = lines[i]
    const tm = setTimeout(() => {
      if (!d) {
        setT(cur.slice(0, ch + 1))
        if (ch + 1 === cur.length) setTimeout(() => setD(true), 1800)
        else setCh(x => x + 1)
      } else {
        setT(cur.slice(0, ch - 1))
        if (ch - 1 === 0) { setD(false); setI(x => (x + 1) % lines.length); setCh(0) }
        else setCh(x => x - 1)
      }
    }, d ? 20 : 44)
    return () => clearTimeout(tm)
  }, [ch, d, i, lines])
  return (
    <span style={{ fontFamily: "'Share Tech Mono',monospace", fontSize: '10px', color: 'rgba(200,60,60,.65)' }}>
      {t}<span className="animate-pulse" style={{ color: '#C41230' }}>█</span>
    </span>
  )
}

function TiltCard({ children }: { children: React.ReactNode }) {
  const r = useRef<HTMLDivElement>(null)
  const [tilt, setTilt] = useState({ x: 0, y: 0 })
  const [hov, setHov] = useState(false)
  const onMove = useCallback((e: React.MouseEvent) => {
    const el = r.current; if (!el) return
    const rect = el.getBoundingClientRect()
    const dx = (e.clientX - rect.left - rect.width / 2) / (rect.width / 2)
    const dy = (e.clientY - rect.top - rect.height / 2) / (rect.height / 2)
    setTilt({ x: dy * -7, y: dx * 7 })
  }, [])
  return (
    <div ref={r} onMouseMove={onMove} onMouseEnter={() => setHov(true)} onMouseLeave={() => { setTilt({ x: 0, y: 0 }); setHov(false) }}
      style={{ perspective: '1800px' }}>
      <div style={{ transform: `rotateX(${tilt.x}deg) rotateY(${tilt.y}deg)`, transition: hov ? 'transform .07s ease-out' : 'transform .9s cubic-bezier(.23,1,.32,1)', transformStyle: 'preserve-3d' }}>
        {children}
      </div>
    </div>
  )
}

export default function LoginPage() {
  const [user, setUser] = useState('admin')
  const [pass, setPass] = useState('')
  const [show, setShow] = useState(false)
  const [err, setErr] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const [focus, setFocus] = useState<'u' | 'p' | null>(null)
  const [time, setTime] = useState('')
  const [phase, setPhase] = useState(0)
  const [summary, setSummary] = useState<PublicAssessmentSummary>(EMPTY_SUMMARY)
  const [shake, setShake] = useState(false)

  useEffect(() => {
    const t = setInterval(() => setTime(new Date().toISOString().replace('T', ' ').slice(0, 19) + ' UTC'), 1000)
    return () => clearInterval(t)
  }, [])

  useEffect(() => {
    let alive = true
    fetch('/api/v1/public/assessment-summary', { headers: { accept: 'application/json' }, cache: 'no-store' })
      .then(r => r.ok ? r.json() : Promise.reject())
      .then((data: PublicAssessmentSummary) => {
        if (alive) setSummary({ ...EMPTY_SUMMARY, ...data, coverage: { ...EMPTY_SUMMARY.coverage, ...(data.coverage ?? {}) } })
      })
      .catch(() => { if (alive) setSummary(EMPTY_SUMMARY) })
    return () => { alive = false }
  }, [])

  const submit = async (e: FormEvent) => {
    e.preventDefault()
    setErr(null)
    const submittedUser = user.trim()
    const submittedPass = pass.trim()
    if (!submittedUser || !submittedPass) {
      setErr('IDENTITY UNPROVEN — CREDENTIALS REQUIRED')
      setShake(true); setTimeout(() => setShake(false), 600)
      return
    }
    setBusy(true)
    try {
      setPhase(2); await new Promise(r => setTimeout(r, 700))
      await authApi.login({ username: submittedUser, password: submittedPass })
      await authApi.me()
      setPhase(3)
      const requestedNext = new URLSearchParams(window.location.search).get('next')
      const safeNext = requestedNext && requestedNext.startsWith('/') && !requestedNext.startsWith('//') ? requestedNext : '/'
      window.location.replace(safeNext)
    } catch (e: unknown) {
      setErr(getErrorDetail(e, 'SOUL REJECTED — CREDENTIALS UNRECOGNIZED'))
      setShake(true); setTimeout(() => setShake(false), 600)
      setPhase(0)
    } finally { setBusy(false) }
  }

  const phases = ['', 'AWAKENING...', 'BINDING SOUL...', 'PACT SEALED']

  return (<>
    <style>{`
      @import url('https://fonts.googleapis.com/css2?family=Cinzel+Decorative:wght@400;700;900&family=Cinzel:wght@400;600;700;900&family=Crimson+Text:ital,wght@0,400;0,600;1,400;1,600&family=Share+Tech+Mono&display=swap');

      :root{
        --blood:#C41230;
        --blood-rgb:196,18,48;
        --hellfire:#FF2200;
        --hellfire-rgb:255,34,0;
        --deepblood:#6B0000;
        --deepblood-rgb:107,0,0;
        --bone:#D4C5A9;
        --bone-rgb:212,197,169;
        --void:#050002;
        --rot:#1A0006;
        --shadow:#0D0002;
        --brand:var(--blood);
        --brand-rgb:var(--blood-rgb);
        --brand-light:var(--bone);
        --accent1:var(--hellfire);
        --accent1-rgb:var(--hellfire-rgb);
        --accent2:var(--deepblood);
        --accent2-rgb:var(--deepblood-rgb);
      }

      @keyframes veinPulse{
        0%,100%{box-shadow:0 0 20px rgba(196,18,48,.5),0 0 60px rgba(107,0,0,.2),0 0 120px rgba(107,0,0,.08),inset 0 0 40px rgba(0,0,0,.5)}
        50%{box-shadow:0 0 40px rgba(196,18,48,.85),0 0 100px rgba(196,18,48,.35),0 0 200px rgba(107,0,0,.18),inset 0 0 60px rgba(0,0,0,.4)}
      }
      @keyframes hellScan{0%{top:-2px;opacity:0}3%{opacity:1}90%{opacity:.4}100%{top:100%;opacity:0}}
      @keyframes bloodDrip{
        0%{transform:scaleY(0) translateY(0);opacity:.8;transform-origin:top}
        60%{transform:scaleY(1) translateY(0);opacity:.9}
        85%{transform:scaleY(1) translateY(8px);opacity:.7;border-radius:0 0 50% 50%}
        100%{transform:scaleY(0.2) translateY(16px);opacity:0;border-radius:0 0 50% 50%}
      }
      @keyframes fadeFromAbyss{from{opacity:0;transform:translateY(28px) scale(.98)}to{opacity:1;transform:translateY(0) scale(1)}}
      @keyframes flicker{0%,100%{opacity:1}92%{opacity:1}93%{opacity:.3}94%{opacity:.9}96%{opacity:.2}97%{opacity:1}}
      @keyframes staticNoise{0%{background-position:0 0}100%{background-position:100px 100px}}
      @keyframes runeRotate{from{transform:rotate(0deg)}to{transform:rotate(360deg)}}
      @keyframes runeRotateR{from{transform:rotate(0deg)}to{transform:rotate(-360deg)}}
      @keyframes shakeHell{0%,100%{transform:translateX(0)}15%{transform:translateX(-8px) rotate(-1deg)}30%{transform:translateX(8px) rotate(1deg)}45%{transform:translateX(-6px)}60%{transform:translateX(6px)}75%{transform:translateX(-3px)}90%{transform:translateX(3px)}}
      @keyframes eyeGlow{0%,100%{opacity:.15}50%{opacity:.28}}
      @keyframes borderBleed{0%{background-position:0% 50%}100%{background-position:200% 50%}}
      @keyframes dataCorrupt{0%,91%,100%{opacity:.35}92%{opacity:.9}93%{opacity:.2}94%{opacity:.8}95%{opacity:.35}}

      .a1{animation:fadeFromAbyss .8s .05s cubic-bezier(.23,1,.32,1) both}
      .a2{animation:fadeFromAbyss .8s .15s cubic-bezier(.23,1,.32,1) both}
      .a3{animation:fadeFromAbyss .8s .28s cubic-bezier(.23,1,.32,1) both}
      .a4{animation:fadeFromAbyss .8s .42s cubic-bezier(.23,1,.32,1) both}
      .a5{animation:fadeFromAbyss .8s .58s cubic-bezier(.23,1,.32,1) both}
      .a6{animation:fadeFromAbyss .8s .72s cubic-bezier(.23,1,.32,1) both}
      .cursed-card{animation:veinPulse 5s ease-in-out infinite}
      .hell-scan{animation:hellScan 7s ease-in-out infinite}
      .flicker{animation:flicker 8s infinite}
      .rune-spin{animation:runeRotate 30s linear infinite}
      .rune-spin-r{animation:runeRotateR 42s linear infinite}
      .data-corrupt{animation:dataCorrupt 4s ease-in-out infinite}

      .hell-input{
        appearance:none;
        background:transparent!important;
        background-color:transparent!important;
        caret-color:var(--blood);
        color-scheme:dark;
        font-family:'Share Tech Mono',monospace;
      }
      .hell-input::placeholder{color:rgba(180,60,60,.3);opacity:1}
      input:-webkit-autofill,input:-webkit-autofill:hover,input:-webkit-autofill:focus{
        -webkit-text-fill-color:#D4C5A9!important;
        caret-color:var(--blood)!important;
        -webkit-background-clip:text!important;
        background-clip:text!important;
        -webkit-box-shadow:0 0 0 1000px transparent inset!important;
        transition:background-color 999999s ease-in-out 0s!important;
      }

      .shake-hell{animation:shakeHell .5s ease-in-out}

      .summon-btn::before{
        content:'';
        position:absolute;
        inset:-1px;
        border-radius:inherit;
        background:linear-gradient(135deg,#6B0000,#C41230,#FF2200,#C41230,#6B0000);
        background-size:300% 300%;
        animation:borderBleed 3s linear infinite;
        z-index:-1;
        opacity:0;
        transition:opacity .3s;
      }
      .summon-btn:hover::before{opacity:1}
      .summon-btn:hover{transform:scale(1.01)}

      .drip{
        position:absolute;
        width:2px;
        background:linear-gradient(180deg,#C41230,#6B0000);
        animation:bloodDrip 3.5s ease-in-out infinite;
        transform-origin:top;
        border-radius:1px;
      }
    `}</style>

    {/* ABYSS BACKGROUND */}
    <div className="fixed inset-0 z-0" style={{ background: 'var(--void)' }}>
      <div aria-hidden className="absolute inset-0" style={{
        backgroundImage: "url('/bg-launch.jpg')",
        backgroundPosition: 'center center',
        backgroundRepeat: 'no-repeat',
        backgroundSize: 'cover',
        opacity: 1,
        filter: 'saturate(1.1) brightness(1.15) contrast(1.05) hue-rotate(340deg)',
      }} />
      <div className="absolute inset-0" style={{
        background:
          'radial-gradient(ellipse 100% 100% at 50% 50%, transparent 60%, rgba(0,0,0,.28) 85%, rgba(0,0,0,.7) 100%),' +
          'linear-gradient(180deg, rgba(0,0,0,.28) 0%, transparent 8%, transparent 90%, rgba(0,0,0,.35) 100%)',
      }} />
      {/* kill the sparkle artifact at bottom-right of the source image */}
      <div className="pointer-events-none absolute bottom-0 right-0 w-48 h-48" style={{
        background: 'radial-gradient(ellipse at 100% 100%, rgba(0,0,0,.95) 0%, rgba(0,0,0,.7) 40%, transparent 70%)',
      }} />
    </div>

    {/* SCANLINES */}
    <div className="pointer-events-none fixed inset-0 z-[2]"
      style={{ background: 'repeating-linear-gradient(0deg,transparent,transparent 2px,rgba(0,0,0,.12) 2px,rgba(0,0,0,.12) 3px)' }} />

    {/* HELL SCANBEAM */}
    <div className="pointer-events-none fixed inset-x-0 z-[3] overflow-hidden" style={{ top: 0, bottom: 0 }}>
      <div className="hell-scan absolute left-0 right-0 h-[2px]"
        style={{ background: 'linear-gradient(90deg,transparent,rgba(196,18,48,.6),rgba(255,34,0,.4),rgba(196,18,48,.6),transparent)', filter: 'blur(1px)', boxShadow: '0 0 12px rgba(196,18,48,.5)' }} />
    </div>

    <div className="relative z-10 flex min-h-screen flex-col items-center justify-center px-6 py-8">
      <div className="w-full max-w-[1100px]">

        {/* TOP BAR */}
        <div className="a1 mb-5 flex items-center justify-between px-1">
          <div className="flex items-center gap-3">
            <div className="flex items-center gap-2 flicker" style={{ fontFamily: "'Share Tech Mono',monospace", fontSize: '10px', color: 'rgba(196,18,48,.7)' }}>
              <span className="inline-block h-2 w-2 rounded-full" style={{ background: '#C41230', boxShadow: '0 0 8px #C41230, 0 0 16px #6B0000', animation: 'eyeGlow 1.8s ease-in-out infinite' }} />
              <span style={{ color: '#C41230', textShadow: '0 0 8px #C41230' }}>⬡</span>
              <span style={{ fontFamily: "'Cinzel',serif", fontSize: '9px', letterSpacing: '.2em', color: 'rgba(196,18,48,.8)' }}>GHOST PROTOCOL v1.0 // ACTIVE</span>
            </div>
            <span style={{ color: 'rgba(196,18,48,.2)' }}>{'//'}</span>
            <TypeWriter lines={[
              `> Domain breach loaded :: ${summary.domain ?? 'pending'}`,
              `> Exposure score ${summary.exposure_score.toFixed(1)} — ${summary.critical_findings} critical findings catalogued`,
              `> ${compact(summary.tier0_assets)} Tier-0 souls and ${compact(summary.total_edges)} control edges indexed`,
              `> ${compact(summary.certificate_templates)} certificate chains exposed for exploitation`,
              `> ${compact(summary.exposure_paths)} attack paths await activation`,
              '> All operators are watched. All sessions are permanent.',
            ]} />
          </div>
          <div className="data-corrupt" style={{ fontFamily: "'Share Tech Mono',monospace", fontSize: '9px', color: 'rgba(180,60,60,.35)' }}>
            {time}
          </div>
        </div>

        {/* MAIN CARD */}
        <div className="a2">
          <TiltCard>
            <div className={`cursed-card relative overflow-hidden ${shake ? 'shake-hell' : ''}`}
              style={{
                background: 'linear-gradient(155deg, rgba(20,0,4,.92) 0%, rgba(8,0,1,.88) 40%, rgba(15,0,3,.94) 100%)',
                border: '1px solid rgba(196,18,48,.5)',
                borderRadius: '16px',
                backdropFilter: 'blur(12px) saturate(1.1)',
                WebkitBackdropFilter: 'blur(12px) saturate(1.1)',
              }}>

              {/* BLOOD DRIPS */}
              {[8, 22, 38, 55, 72, 88].map((left, i) => (
                <div key={i} className="drip" style={{
                  left: `${left}%`,
                  height: `${14 + (i % 3) * 8}px`,
                  top: 0,
                  animationDelay: `${i * 0.7}s`,
                  animationDuration: `${3.2 + i * 0.4}s`,
                  opacity: 0.5 + (i % 3) * 0.1,
                }} />
              ))}

              {/* CORNERS */}
              <RuneCorner pos="top-2 left-2" rot={0} />
              <RuneCorner pos="top-2 right-2" rot={90} />
              <RuneCorner pos="bottom-2 right-2" rot={180} />
              <RuneCorner pos="bottom-2 left-2" rot={270} />

              {/* TOP BLEED LINE */}
              <div className="absolute inset-x-0 top-0 h-[1px]"
                style={{ background: 'linear-gradient(90deg,transparent,rgba(196,18,48,1) 20%,rgba(255,34,0,.9) 50%,rgba(107,0,0,.9) 80%,transparent)', animation: 'dataCorrupt 3.5s ease-in-out infinite', boxShadow: '0 0 12px rgba(196,18,48,.6)', borderRadius: '16px 16px 0 0' }} />
              <div className="absolute inset-y-0 left-0 w-[1px]"
                style={{ background: 'linear-gradient(180deg,transparent,rgba(196,18,48,.6),rgba(107,0,0,.4),transparent)' }} />
              <div className="absolute inset-y-0 right-0 w-[1px]"
                style={{ background: 'linear-gradient(180deg,transparent,rgba(196,18,48,.4),rgba(107,0,0,.3),transparent)' }} />

              <div className="grid lg:grid-cols-[1.25fr_.75fr]">

                {/* LEFT — DOSSIER */}
                <div className="relative p-7 lg:p-8" style={{ borderRight: '1px solid rgba(196,18,48,.12)' }}>
                  {/* BG RUNE RINGS */}
                  <div className="rune-spin pointer-events-none absolute right-4 top-4 opacity-[.04]">
                    <svg width="180" height="180" viewBox="0 0 180 180" fill="none">
                      <polygon points="90,4 170,47 170,133 90,176 10,133 10,47" stroke="#C41230" strokeWidth="1.5" fill="none" strokeDasharray="5 4" />
                      <polygon points="90,20 150,55 150,125 90,160 30,125 30,55" stroke="#FF2200" strokeWidth=".7" fill="none" />
                    </svg>
                  </div>
                  <div className="rune-spin-r pointer-events-none absolute right-4 top-4 opacity-[.025]">
                    <svg width="240" height="240" viewBox="0 0 240 240" fill="none">
                      <circle cx="120" cy="120" r="110" stroke="#C41230" strokeWidth="1" fill="none" strokeDasharray="8 6" />
                    </svg>
                  </div>

                  {/* CLASSIFIED BADGE */}
                  <div className="a2 inline-flex items-center gap-2 px-3.5 py-1.5"
                    style={{ background: 'rgba(107,0,0,.2)', border: '1px solid rgba(196,18,48,.4)', boxShadow: '0 0 20px rgba(107,0,0,.3)' }}>
                    <span className="h-1.5 w-1.5 rounded-full inline-block" style={{ background: '#C41230', boxShadow: '0 0 8px #C41230', animation: 'eyeGlow 2s ease-in-out infinite' }} />
                    <span style={{ fontFamily: "'Cinzel',serif", fontSize: '9px', letterSpacing: '.3em', color: '#C41230', textShadow: '0 0 12px rgba(196,18,48,.6)' }}>
                      CLASSIFIED // TIER-0 CLEARANCE
                    </span>
                  </div>

                  {/* TITLE */}
                  <div className="a3 mt-6">
                    <ScaryCursedTitle />
                    <div className="mt-3 flex items-center gap-2">
                      <div className="h-px flex-1" style={{ background: 'linear-gradient(90deg,rgba(196,18,48,.6),rgba(196,18,48,.1),transparent)' }} />
                      <p style={{ fontFamily: "'Cinzel',serif", fontSize: '9px', letterSpacing: '.22em', color: 'rgba(180,120,120,.5)' }}>
                        AD ENUMERATION AND EXPLOITATION FRAMEWORK
                      </p>
                      <div className="h-px flex-1" style={{ background: 'linear-gradient(270deg,rgba(107,0,0,.4),transparent)' }} />
                    </div>
                  </div>

                  {/* STATS GRID */}
                  <div className="a4 mt-8 grid grid-cols-2 gap-2.5">
                    {[
                      { v: String(summary.analysis_tracks), l: 'ANALYSIS TRACKS', s: `${summary.total_findings} findings · ${summary.critical_findings} critical`, c: '#C41230' },
                      { v: String(summary.research_modules), l: 'RESEARCH MODULES', s: `${compact(summary.total_entities)} entities · ${compact(summary.total_edges)} edges`, c: '#FF2200' },
                      { v: summary.exposure_score.toFixed(1), l: 'EXPOSURE SCORE', s: `${summary.high_findings} high · ${summary.status ?? 'pending'}`, c: '#8B0000' },
                      { v: compact(summary.certificate_chains), l: 'CERTIFICATE CHAINS', s: 'AD CS coverage', c: '#D4856A' },
                    ].map(s => (
                      <div key={s.l} className="p-3.5"
                        style={{ background: 'rgba(20,0,4,.6)', border: '1px solid rgba(196,18,48,.1)', boxShadow: 'inset 0 0 20px rgba(0,0,0,.4)' }}>
                        <div className="font-black leading-none text-2xl" style={{ fontFamily: "'Cinzel Decorative',serif", color: s.c, textShadow: `0 0 24px ${s.c}88` }}>{s.v}</div>
                        <div className="mt-1.5" style={{ fontFamily: "'Cinzel',serif", fontSize: '8px', letterSpacing: '.25em', color: 'rgba(180,120,100,.3)' }}>{s.l}</div>
                        <div className="mt-0.5 truncate" style={{ fontFamily: "'Share Tech Mono',monospace", fontSize: '9px', color: 'rgba(180,120,100,.2)' }}>{s.s}</div>
                      </div>
                    ))}
                  </div>

                  {/* COVERAGE BARS */}
                  <div className="a5 mt-7 space-y-3.5">
                    <p style={{ fontFamily: "'Cinzel',serif", fontSize: '8px', letterSpacing: '.3em', color: 'rgba(196,18,48,.3)', marginBottom: '12px' }}>
                      {'// IDENTITY SURFACE COVERAGE'}
                    </p>
                    <BloodBar label="Kerberos Posture (preauth/SPN/delegation)" val={summary.coverage.kerberos} col="#C41230" />
                    <BloodBar label="AD CS Certificate Exposure (ESC1–ESC8)" val={summary.coverage.adcs} col="#FF2200" />
                    <BloodBar label="ACL / DACL Control Paths" val={summary.coverage.acl} col="#8B0000" />
                    <BloodBar label="Replication Rights / Shadow Creds / SID History" val={summary.coverage.replication} col="#D4856A" />
                    <BloodBar label="Graph Coverage (imported and collected)" val={summary.coverage.graph} col="#C41230" />
                  </div>

                  {/* MITRE */}
                  <div className="a6 mt-7 space-y-0.5">
                    <p style={{ fontFamily: "'Cinzel',serif", fontSize: '8px', letterSpacing: '.3em', color: 'rgba(196,18,48,.3)', marginBottom: '10px' }}>
                      {'// MITRE ATT&CK REFERENCES'}
                    </p>
                    {[
                      { t: 'T1558.003', n: 'Kerberoasting exposure' },
                      { t: 'T1558.004', n: 'AS-REP roasting exposure' },
                      { t: 'T1649', n: 'Certificate misuse exposure (ESC1-8)' },
                      { t: 'T1484.001', n: 'GPO modification risk' },
                      { t: 'T1003.003', n: 'Credential replication exposure' },
                    ].map(m => (
                      <div key={m.t} className="flex items-center gap-3 px-3 py-2"
                        style={{ borderLeft: '2px solid rgba(107,0,0,.3)' }}>
                        <span className="flex-shrink-0 font-bold" style={{ fontFamily: "'Share Tech Mono',monospace", fontSize: '10px', color: 'rgba(196,18,48,.55)', minWidth: '80px' }}>{m.t}</span>
                        <span style={{ fontFamily: "'Crimson Text',serif", fontSize: '12px', color: 'rgba(200,160,140,.4)', fontStyle: 'italic' }}>{m.n}</span>
                      </div>
                    ))}
                  </div>

                  {/* LIVE FEED */}
                  <div className="mt-6 p-3" style={{ background: 'rgba(0,0,0,.5)', border: '1px solid rgba(196,18,48,.08)' }}>
                    <div className="mb-2" style={{ fontFamily: "'Cinzel',serif", fontSize: '8px', letterSpacing: '.3em', color: 'rgba(196,18,48,.25)' }}>{'// LIVE OP FEED'}</div>
                    <LogStream />
                  </div>
                </div>

                {/* RIGHT — THE RITUAL */}
                <div className="flex flex-col justify-center p-7 lg:p-8 relative">

                  {/* SIGIL BACKGROUND */}
                  <div className="pointer-events-none absolute inset-0 flex items-center justify-center overflow-hidden">
                    <DemonicSigil />
                  </div>

                  {/* BLOOD VIGNETTE */}
                  <div className="pointer-events-none absolute inset-0"
                    style={{ background: 'radial-gradient(ellipse at center, transparent 40%, rgba(5,0,2,.6) 100%)' }} />

                  <div className="relative z-10">
                    {/* AUTH HEADER */}
                    <div className="a2 mb-8">
                      <div className="flex items-center gap-2 mb-4">
                        <div className="h-px flex-1" style={{ background: 'rgba(196,18,48,.2)' }} />
                        <span style={{ fontFamily: "'Cinzel',serif", fontSize: '8px', letterSpacing: '.35em', color: 'rgba(196,18,48,.4)' }}>OPERATOR AUTHENTICATION</span>
                        <div className="h-px flex-1" style={{ background: 'rgba(196,18,48,.2)' }} />
                      </div>
                      <h2 className="flicker" style={{ fontFamily: "'Cinzel Decorative',serif", fontSize: '38px', fontWeight: 900, color: '#D4C5A9', textShadow: '0 0 30px rgba(196,18,48,.7), 0 0 60px rgba(196,18,48,.35), 0 0 120px rgba(107,0,0,.4)', lineHeight: 1.1 }}>
                        ADbyG0d
                      </h2>
                      <div className="mt-2 h-px w-2/3" style={{ background: 'linear-gradient(90deg,rgba(196,18,48,.5),transparent)' }} />
                      <p className="mt-3" style={{ fontFamily: "'Crimson Text',serif", fontSize: '14px', fontStyle: 'italic', lineHeight: 1.7, color: 'rgba(180,140,120,.5)' }}>
                        Your identity will be verified.<br />
                        <span style={{ color: 'rgba(196,18,48,.5)' }}>All breach operations are logged and attributed.</span>
                      </p>
                    </div>

                    <form onSubmit={submit} className="space-y-5">
                      {/* USERNAME */}
                      <div className="a3">
                        <label className="block mb-2" style={{ fontFamily: "'Cinzel',serif", fontSize: '8px', letterSpacing: '.3em', color: 'rgba(196,18,48,.45)' }}>
                          OPERATOR ID
                        </label>
                        <div className="flex items-center px-4 py-3.5 transition-all duration-300"
                          style={{
                            background: focus === 'u' ? 'rgba(107,0,0,.12)' : 'rgba(20,0,4,.6)',
                            border: `1px solid ${focus === 'u' ? 'rgba(196,18,48,.6)' : 'rgba(107,0,0,.3)'}`,
                            boxShadow: focus === 'u' ? '0 0 0 2px rgba(196,18,48,.06), 0 0 30px rgba(196,18,48,.15), inset 0 0 20px rgba(0,0,0,.4)' : 'inset 0 0 20px rgba(0,0,0,.4)',
                          }}>
                          <User className="h-4 w-4 mr-3 flex-shrink-0" style={{ color: focus === 'u' ? '#C41230' : 'rgba(180,60,60,.3)' }} />
                          <input name="username" value={user} onChange={e => setUser(e.target.value)}
                            onFocus={() => setFocus('u')} onBlur={() => setFocus(null)}
                            className="hell-input w-full text-sm outline-none tracking-wide"
                            style={{ color: '#D4C5A9', backgroundColor: 'transparent' }}
                            placeholder="operator" autoComplete="off" />
                        </div>
                      </div>

                      {/* PASSWORD */}
                      <div className="a3">
                        <label className="block mb-2" style={{ fontFamily: "'Cinzel',serif", fontSize: '8px', letterSpacing: '.3em', color: 'rgba(196,18,48,.45)' }}>
                          ACCESS TOKEN
                        </label>
                        <div className="flex items-center px-4 py-3.5 transition-all duration-300"
                          style={{
                            background: focus === 'p' ? 'rgba(107,0,0,.12)' : 'rgba(20,0,4,.6)',
                            border: `1px solid ${focus === 'p' ? 'rgba(196,18,48,.6)' : 'rgba(107,0,0,.3)'}`,
                            boxShadow: focus === 'p' ? '0 0 0 2px rgba(196,18,48,.06), 0 0 30px rgba(196,18,48,.15), inset 0 0 20px rgba(0,0,0,.4)' : 'inset 0 0 20px rgba(0,0,0,.4)',
                          }}>
                          <Lock className="h-4 w-4 mr-3 flex-shrink-0" style={{ color: focus === 'p' ? '#C41230' : 'rgba(180,60,60,.3)' }} />
                          <input name="password" type={show ? 'text' : 'password'} value={pass}
                            onChange={e => setPass(e.target.value)}
                            onFocus={() => setFocus('p')} onBlur={() => setFocus(null)}
                            className="hell-input w-full text-sm outline-none flex-1 tracking-widest"
                            style={{ color: '#D4C5A9', backgroundColor: 'transparent' }}
                            placeholder="••••••••••••••••" autoComplete="new-password" />
                          <button type="button" onClick={() => setShow(s => !s)} className="ml-2 flex-shrink-0 transition-colors"
                            style={{ color: show ? '#C41230' : 'rgba(180,60,60,.3)' }}>
                            {show ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                          </button>
                        </div>
                      </div>

                      {/* ERROR */}
                      {err && (
                        <div className="a2 flex items-start gap-3 px-4 py-3"
                          style={{ background: 'rgba(107,0,0,.18)', border: '1px solid rgba(196,18,48,.45)', boxShadow: '0 0 30px rgba(196,18,48,.2), inset 0 0 20px rgba(0,0,0,.3)' }}>
                          <AlertTriangle className="mt-0.5 h-4 w-4 flex-shrink-0" style={{ color: '#FF2200' }} />
                          <span style={{ fontFamily: "'Cinzel',serif", fontSize: '10px', letterSpacing: '.1em', color: '#D4856A' }}>
                            {err}
                          </span>
                        </div>
                      )}

                      {/* SUMMON BUTTON */}
                      <div className="a4 pt-2">
                        <button type="submit" disabled={busy}
                          className="summon-btn group relative z-20 w-full overflow-hidden py-4 font-black tracking-[.25em] uppercase transition-all duration-300 disabled:cursor-wait disabled:opacity-60"
                          style={{
                            fontFamily: "'Cinzel',serif",
                            fontSize: '13px',
                            background: busy
                              ? 'rgba(107,0,0,.15)'
                              : 'linear-gradient(135deg, rgba(107,0,0,.35) 0%, rgba(196,18,48,.2) 50%, rgba(107,0,0,.3) 100%)',
                            border: '1px solid rgba(196,18,48,.6)',
                            color: '#D4C5A9',
                            textShadow: '0 0 20px rgba(196,18,48,.8)',
                            boxShadow: '0 0 40px rgba(196,18,48,.2), 0 0 80px rgba(107,0,0,.1), inset 0 1px 0 rgba(196,18,48,.2), inset 0 -1px 0 rgba(0,0,0,.4)',
                          }}>
                          {/* sweep shimmer */}
                          <span className="pointer-events-none absolute inset-0 opacity-0 group-hover:opacity-100 transition-opacity duration-300"
                            style={{ background: 'linear-gradient(110deg,transparent 35%,rgba(196,18,48,.08) 50%,transparent 65%)', backgroundSize: '300% 100%', animation: 'borderBleed 2s linear infinite' }} />
                          <span className="relative flex items-center justify-center gap-3">
                            {busy
                              ? <><Loader2 className="h-4 w-4 animate-spin" />{phases[phase]}</>
                              : <>
                                  <span style={{ color: 'rgba(196,18,48,.7)', fontSize: '16px' }}>⛧</span>
                                  BREACH SYSTEM
                                  <span style={{ color: 'rgba(196,18,48,.7)', fontSize: '16px' }}>⛧</span>
                                </>
                            }
                          </span>
                        </button>
                      </div>
                    </form>

                    {/* SECURITY PROTOCOLS */}
                    <div className="a5 mt-8 pt-6" style={{ borderTop: '1px solid rgba(107,0,0,.2)' }}>
                      <p className="mb-3" style={{ fontFamily: "'Cinzel',serif", fontSize: '8px', letterSpacing: '.3em', color: 'rgba(196,18,48,.22)' }}>
                        {'// SECURITY PROTOCOLS'}
                      </p>
                      <div className="grid grid-cols-3 gap-2">
                        {[
                          { l: 'TLS 1.3', s: 'Transport' },
                          { l: 'AES-256', s: 'Encryption' },
                          { l: 'SESSION', s: 'Zero-persist' },
                        ].map(b => (
                          <div key={b.l} className="py-3 px-2 text-center"
                            style={{ background: 'rgba(20,0,4,.5)', border: '1px solid rgba(107,0,0,.2)' }}>
                            <div className="font-bold" style={{ fontFamily: "'Cinzel',serif", fontSize: '10px', letterSpacing: '.15em', color: 'rgba(196,18,48,.55)', textShadow: '0 0 8px rgba(196,18,48,.3)' }}>{b.l}</div>
                            <div className="mt-1" style={{ fontFamily: "'Share Tech Mono',monospace", fontSize: '8px', color: 'rgba(180,140,120,.2)' }}>{b.s}</div>
                          </div>
                        ))}
                      </div>
                    </div>

                    {/* HEX DUMP */}
                    <div className="a6 mt-5 data-corrupt select-none"
                      style={{ fontFamily: "'Share Tech Mono',monospace", fontSize: '8px', lineHeight: 1.7, color: 'rgba(107,0,0,.35)' }}>
                      <div>4D 5A 90 00 03 00 00 00 04 00 00 FF FF 00 00</div>
                      <div>B8 00 00 00 40 00 00 00 00 00 00 00 00 00 00</div>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </TiltCard>
        </div>

        {/* BOTTOM TAGS */}
        <div className="a6 mt-6 flex flex-wrap items-center justify-center gap-5"
          style={{ fontFamily: "'Cinzel',serif", fontSize: '8px', letterSpacing: '.25em', color: 'rgba(107,0,0,.4)' }}>
          {['Kerberos Audit', 'AD CS Review', 'ACL Analysis', 'Replication Rights', 'Graph Engine', 'Delegation Paths', 'Shadow Creds', 'GPO Hygiene'].map(tag => (
            <span key={tag} className="flex items-center gap-1.5">
              <span className="h-1 w-1 inline-block" style={{ background: '#6B0000', boxShadow: '0 0 4px #C41230' }} />
              {tag}
            </span>
          ))}
        </div>
      </div>
    </div>
  </>)
}
