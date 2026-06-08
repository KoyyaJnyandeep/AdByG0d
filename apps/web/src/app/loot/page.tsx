'use client'

import { copyText } from '@/lib/clipboard'
import { useEffect, useMemo, useRef, useState } from 'react'
import type { ComponentType, CSSProperties } from 'react'
import { useMutation, useQuery } from '@tanstack/react-query'
import {
  AlertTriangle, ArrowRight, Binary, ChevronDown, ChevronUp, Check, Copy,
  Cpu, Database, Download, FileKey2, Fingerprint, HardDrive, Hash,
  KeyRound, Layers3, Loader2, LockKeyhole, Monitor, Play, Plus, Radar,
  RefreshCw, Search, Server, ShieldAlert, Sparkles, Terminal, Upload,
  Wifi, X, Zap,
} from 'lucide-react'

import { AppShell } from '@/components/layout/AppShell'
import { lootApi, type LootHashIntelItem } from '@/lib/api'
import { cn } from '@/lib/utils'

const SEV: Record<string, { color: string; bg: string; border: string }> = {
  CRITICAL: { color: '#ff4d6d', bg: 'rgba(255,77,109,.08)', border: 'rgba(255,77,109,.28)' },
  HIGH:     { color: '#ff8a3d', bg: 'rgba(255,138,61,.08)', border: 'rgba(255,138,61,.25)' },
  MEDIUM:   { color: '#ffd166', bg: 'rgba(255,209,102,.08)', border: 'rgba(255,209,102,.22)' },
  LOW:      { color: '#64748b', bg: 'rgba(100,116,139,.06)', border: 'rgba(100,116,139,.18)' },
}

const SOURCE_ACCENTS = ['#22d3ee', '#818cf8', '#f472b6', '#fb7185', '#f97316', '#34d399', '#a855f7']

const HASH_PAGE_SIZE = 50

function sevStyle(value?: string) {
  return SEV[value ?? 'LOW'] ?? SEV.LOW
}

function sourceIcon(name: string) {
  if (/lsass/i.test(name)) return Monitor
  if (/sam/i.test(name)) return HardDrive
  if (/ntds|dcsync/i.test(name)) return Server
  if (/dcc2|cached/i.test(name)) return Fingerprint
  if (/app|secret/i.test(name)) return FileKey2
  if (/remote/i.test(name)) return Wifi
  return Layers3
}

function SectionLabel({ icon: Icon, label, sub, action }: {
  icon: ComponentType<{ className?: string }>
  label: string
  sub?: string
  action?: React.ReactNode
}) {
  return (
    <div className="flex items-center justify-between gap-4 py-1">
      <div className="flex items-center gap-2.5">
        <Icon className="h-3.5 w-3.5 text-zinc-500" />
        <span className="text-[11px] font-semibold uppercase tracking-[0.18em] text-zinc-400">{label}</span>
        {sub && <span className="text-[10px] text-zinc-600">{sub}</span>}
      </div>
      {action}
    </div>
  )
}

function StatCard({ label, value, color, icon: Icon, detail }: {
  label: string
  value: string | number
  color: string
  icon: ComponentType<{ className?: string; style?: CSSProperties }>
  detail: string
}) {
  return (
    <div className="flex flex-col gap-3 border border-white/[0.07] bg-[#0a0a0a] p-4">
      <div className="flex items-center justify-between">
        <span className="text-[10px] font-semibold uppercase tracking-[0.16em] text-zinc-600">{label}</span>
        <Icon className="h-3.5 w-3.5 text-zinc-700" />
      </div>
      <div className="font-mono text-3xl font-bold tabular-nums" style={{ color }}>
        {value}
      </div>
      <div className="text-[10px] text-zinc-600">{detail}</div>
    </div>
  )
}

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false)
  return (
    <button
      onClick={e => { e.stopPropagation(); copyText(text); setCopied(true); setTimeout(() => setCopied(false), 1200) }}
      className="grid h-7 w-7 shrink-0 place-items-center border border-white/[0.07] text-zinc-600 transition hover:border-white/15 hover:text-zinc-300"
      title="Copy"
    >
      {copied ? <Check className="h-3 w-3 text-emerald-400" /> : <Copy className="h-3 w-3" />}
    </button>
  )
}

function HashRow({ item, selected, onToggle }: { item: LootHashIntelItem; selected: boolean; onToggle: () => void }) {
  const sev = sevStyle(item.severity)
  return (
    <div
      onClick={onToggle}
      role="button"
      tabIndex={0}
      onKeyDown={e => (e.key === 'Enter' || e.key === ' ') && onToggle()}
      className="group grid cursor-pointer grid-cols-[16px_1fr_auto] items-center gap-3 border-b border-white/[0.05] px-3 py-2.5 transition last:border-b-0 hover:bg-white/[0.02]"
      style={{ background: selected ? sev.bg : undefined }}
    >
      <span
        className="h-3 w-3 shrink-0 border transition"
        style={{ borderColor: selected ? sev.color : 'rgba(255,255,255,.12)', background: selected ? sev.color + '33' : undefined }}
      >
        {selected ? <Check className="h-2.5 w-2.5" style={{ color: sev.color }} /> : null}
      </span>
      <span className="min-w-0">
        <span className="flex flex-wrap items-center gap-1.5">
          <span className="text-xs font-semibold text-zinc-200">{item.hash_type}</span>
          <span className="rounded border px-1 py-0.5 font-mono text-[9px]" style={{ color: sev.color, borderColor: sev.border }}>
            mode {item.hashcat_mode}
          </span>
          {item.pass_the_hash_ready && (
            <span className="rounded border border-red-500/25 px-1 py-0.5 text-[9px] font-semibold text-red-400">PTH</span>
          )}
        </span>
        <span className="mt-0.5 block overflow-hidden text-ellipsis whitespace-nowrap font-mono text-[11px] text-cyan-400/70">{item.hash}</span>
        <span className="mt-0.5 block text-[10px] text-zinc-600">
          {item.source}{item.principal ? ` · ${item.principal}` : ''}
        </span>
      </span>
      <CopyButton text={item.hash} />
    </div>
  )
}

function EmptyVault({ hashcatReady, johnReady }: { hashcatReady: boolean; johnReady: boolean }) {
  return (
    <div className="flex flex-col items-center justify-center gap-6 border border-white/[0.07] bg-[#0a0a0a] py-20 text-center">
      <div className="grid h-16 w-16 place-items-center border border-white/10 bg-black">
        <LockKeyhole className="h-7 w-7 text-zinc-600" />
      </div>
      <div>
        <div className="text-sm font-semibold text-zinc-400">No credential material detected</div>
        <div className="mt-1 text-xs text-zinc-600">Load hashes or run an assessment to populate the vault</div>
      </div>
      <div className="flex gap-2">
        {[['loot stream', true], ['classifier', true], ['hashcat', hashcatReady], ['john', johnReady]].map(([label, ready]) => (
          <div key={String(label)} className="border border-white/[0.07] bg-black px-3 py-2 text-left">
            <div className={cn('text-[9px] font-semibold uppercase tracking-[0.14em]', ready ? 'text-zinc-400' : 'text-zinc-700')}>{label}</div>
            <div className={cn('mt-1 h-1 w-6', ready ? 'bg-emerald-500' : 'bg-zinc-800')} />
          </div>
        ))}
      </div>
    </div>
  )
}

const TECHNIQUES: Array<{
  id: string
  label: string
  desc: string
  icon: React.ComponentType<{ className?: string }>
  severity: string
  needsCreds: boolean
}> = [
  { id: 'dcsync',               label: 'DCSync',              desc: 'Replicate all domain hashes via DRSUAPI (requires DA or DCSync rights)',          icon: Server,      severity: 'CRITICAL', needsCreds: true },
  { id: 'secretsdump',          label: 'Secretsdump',         desc: 'Dump SAM, LSA secrets, and cached hashes from a Windows host',                   icon: HardDrive,   severity: 'CRITICAL', needsCreds: true },
  { id: 'cred_dump_secretsdump', label: 'Full Remote Dump',   desc: 'Full SAM + LSA + NTDS dump over SMB — all secrets in one run',                   icon: Server,      severity: 'CRITICAL', needsCreds: true },
  { id: 'cred_dump_ntds_vss',   label: 'NTDS via VSS',        desc: 'Extract NTDS.dit via Volume Shadow Copy — manual steps + offline parse',          icon: HardDrive,   severity: 'CRITICAL', needsCreds: true },
  { id: 'dpapi_backup_key',     label: 'DPAPI Backup Key',    desc: 'Steal the DPAPI domain backup key — decrypt all user DPAPI blobs offline',        icon: FileKey2,    severity: 'CRITICAL', needsCreds: true },
  { id: 'kerberoast',           label: 'Kerberoast',          desc: 'Request TGS tickets for SPN accounts — offline RC4/AES cracking',                 icon: KeyRound,    severity: 'HIGH',     needsCreds: true },
  { id: 'asreproast',           label: 'AS-REP Roast',        desc: 'Collect AS-REP hashes from accounts with pre-auth disabled',                      icon: Fingerprint, severity: 'HIGH',     needsCreds: false },
  { id: 'laps_dump',            label: 'LAPS Dump',           desc: 'Read ms-Mcs-AdmPwd / msLAPS-Password from LDAP',                                  icon: Monitor,     severity: 'HIGH',     needsCreds: true },
  { id: 'gmsa_dump',            label: 'gMSA Dump',           desc: 'Retrieve group Managed Service Account password material via LDAP',                icon: Wifi,        severity: 'MEDIUM',   needsCreds: true },
]

const SEV_COLORS: Record<string, { color: string; bg: string; border: string }> = {
  CRITICAL: { color: '#ff4d6d', bg: 'rgba(255,77,109,.10)', border: 'rgba(255,77,109,.30)' },
  HIGH:     { color: '#ff8a3d', bg: 'rgba(255,138,61,.10)', border: 'rgba(255,138,61,.28)' },
  MEDIUM:   { color: '#ffd166', bg: 'rgba(255,209,102,.08)', border: 'rgba(255,209,102,.22)' },
}

interface CollectLine { stream: 'stdout' | 'stderr'; text: string }
interface LootCapture { loot_type: string; label: string; count: number }

function HashCollector({ onCollected }: { onCollected: () => void }) {
  const [open, setOpen] = useState(false)
  const [selectedTechniques, setSelectedTechniques] = useState<Set<string>>(new Set(['dcsync']))
  const [target, setTarget] = useState('')
  const [domain, setDomain] = useState('')
  const [username, setUsername] = useState('')
  const [authMode, setAuthMode] = useState<'password' | 'hash'>('password')
  const [password, setPassword] = useState('')
  const [ntHash, setNtHash] = useState('')
  const [dcIp, setDcIp] = useState('')
  const [running, setRunning] = useState(false)
  const [lines, setLines] = useState<CollectLine[]>([])
  const [captures, setCaptures] = useState<LootCapture[]>([])
  const [totalCaptured, setTotalCaptured] = useState(0)
  const [done, setDone] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const termRef = useRef<HTMLDivElement>(null)

  // Auto-scroll terminal
  useEffect(() => {
    if (termRef.current) termRef.current.scrollTop = termRef.current.scrollHeight
  }, [lines])

  function toggleTechnique(id: string) {
    setSelectedTechniques(prev => {
      const s = new Set(prev)
      if (s.has(id)) s.delete(id); else s.add(id)
      return s
    })
  }

  async function runCollector() {
    if (!target || !domain || selectedTechniques.size === 0) return
    setRunning(true); setLines([]); setCaptures([]); setTotalCaptured(0); setDone(false); setError(null)

    try {
      const resp = await lootApi.collectStream({
        techniques: [...selectedTechniques],
        target,
        domain,
        username,
        password: authMode === 'password' ? password : '',
        hashes: authMode === 'hash' ? ntHash : '',
        dc_ip: dcIp || target,
      })

      if (!resp.ok) {
        const body = await resp.json().catch(() => ({}))
        setError((body as { detail?: string }).detail ?? `HTTP ${resp.status}`)
        return
      }

      const reader = resp.body?.getReader()
      if (!reader) { setError('No response body'); return }

      const decoder = new TextDecoder()
      let buf = ''

      while (true) {
        const { done: streamDone, value } = await reader.read()
        if (streamDone) break

        buf += decoder.decode(value, { stream: true })
        const parts = buf.split('\n\n')
        buf = parts.pop() ?? ''

        for (const part of parts) {
          const line = part.replace(/^data: /, '').trim()
          if (!line) continue
          try {
            const evt = JSON.parse(line)
            if (evt.type === 'output') {
              setLines(prev => [...prev, { stream: evt.stream as 'stdout' | 'stderr', text: evt.line }])
            } else if (evt.type === 'loot_captured') {
              setCaptures(prev => [...prev, { loot_type: evt.loot_type, label: evt.label, count: evt.count }])
              setTotalCaptured(evt.total ?? 0)
            } else if (evt.type === 'session_done') {
              setDone(true)
              onCollected()
            } else if (evt.type === 'error') {
              setError(evt.message)
            }
          } catch { /* non-JSON chunk */ }
        }
      }
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Collection failed')
    } finally {
      setRunning(false)
    }
  }

  const canRun = target.trim() && domain.trim() && selectedTechniques.size > 0 &&
    (authMode === 'password' ? !!username.trim() : !!ntHash.trim())

  return (
    <div className="border border-white/[0.07] bg-[#0a0a0a]">
      {/* Header */}
      <button
        onClick={() => setOpen(p => !p)}
        className="w-full flex items-center justify-between px-4 py-3 hover:bg-white/[0.02] transition"
      >
        <div className="flex items-center gap-2.5">
          <Radar className="h-3.5 w-3.5 text-cyan-400" />
          <span className="text-[11px] font-semibold uppercase tracking-[0.18em] text-zinc-300">Collect Hashes from AD</span>
          <span className="border border-cyan-500/20 bg-cyan-500/[0.08] px-2 py-0.5 text-[9px] font-semibold uppercase tracking-[0.14em] text-cyan-400">Live Collector</span>
          {totalCaptured > 0 && (
            <span className="border border-emerald-500/25 bg-emerald-500/10 px-2 py-0.5 text-[9px] font-bold text-emerald-300">
              {totalCaptured} captured
            </span>
          )}
        </div>
        {open ? <ChevronUp className="h-3.5 w-3.5 text-zinc-500" /> : <ChevronDown className="h-3.5 w-3.5 text-zinc-500" />}
      </button>

      {open && (
        <div className="border-t border-white/[0.07] p-4 space-y-4">

          {/* Technique grid */}
          <div>
            <div className="text-[10px] font-semibold uppercase tracking-[0.14em] text-zinc-500 mb-2">Select Techniques</div>
            <div className="grid gap-2 sm:grid-cols-2 xl:grid-cols-3">
              {TECHNIQUES.map(t => {
                const sel = selectedTechniques.has(t.id)
                const sev = SEV_COLORS[t.severity] ?? SEV_COLORS.MEDIUM
                return (
                  <button
                    key={t.id}
                    onClick={() => toggleTechnique(t.id)}
                    className={cn(
                      'flex items-start gap-3 border p-3 text-left transition',
                      sel
                        ? 'border-cyan-500/35 bg-cyan-500/[0.08]'
                        : 'border-white/[0.07] bg-black hover:border-white/15',
                    )}
                  >
                    <span className={cn('mt-0.5 h-3.5 w-3.5 shrink-0 border transition', sel ? 'bg-cyan-400 border-cyan-400' : 'border-white/20')}>
                      {sel && <Check className="h-3 w-3 text-black" />}
                    </span>
                    <div className="min-w-0 flex-1">
                      <div className="flex items-center justify-between gap-2">
                        <span className={cn('text-xs font-semibold', sel ? 'text-cyan-200' : 'text-zinc-300')}>{t.label}</span>
                        <span className="shrink-0 border px-1.5 py-0.5 text-[8px] font-bold uppercase" style={{ color: sev.color, borderColor: sev.border }}>
                          {t.severity}
                        </span>
                      </div>
                      <p className="mt-0.5 text-[10px] text-zinc-600 leading-relaxed">{t.desc}</p>
                    </div>
                  </button>
                )
              })}
            </div>
          </div>

          {/* Credential form */}
          <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
            <div>
              <label className="block text-[10px] font-semibold uppercase tracking-[0.14em] text-zinc-500 mb-1">Target (DC IP / Host) *</label>
              <input value={target} onChange={e => setTarget(e.target.value)}
                placeholder="192.168.1.10"
                className="w-full border border-white/[0.07] bg-black px-2.5 py-2 font-mono text-xs text-zinc-200 outline-none focus:border-white/20 placeholder:text-zinc-700" />
            </div>
            <div>
              <label className="block text-[10px] font-semibold uppercase tracking-[0.14em] text-zinc-500 mb-1">Domain *</label>
              <input value={domain} onChange={e => setDomain(e.target.value)}
                placeholder="corp.local"
                className="w-full border border-white/[0.07] bg-black px-2.5 py-2 font-mono text-xs text-zinc-200 outline-none focus:border-white/20 placeholder:text-zinc-700" />
            </div>
            <div>
              <label className="block text-[10px] font-semibold uppercase tracking-[0.14em] text-zinc-500 mb-1">Username *</label>
              <input value={username} onChange={e => setUsername(e.target.value)}
                placeholder="Administrator"
                className="w-full border border-white/[0.07] bg-black px-2.5 py-2 font-mono text-xs text-zinc-200 outline-none focus:border-white/20 placeholder:text-zinc-700" />
            </div>
            <div>
              <label className="block text-[10px] font-semibold uppercase tracking-[0.14em] text-zinc-500 mb-1">DC IP (if different)</label>
              <input value={dcIp} onChange={e => setDcIp(e.target.value)}
                placeholder="same as target"
                className="w-full border border-white/[0.07] bg-black px-2.5 py-2 font-mono text-xs text-zinc-200 outline-none focus:border-white/20 placeholder:text-zinc-700" />
            </div>
          </div>

          {/* Auth: password vs hash tabs */}
          <div>
            <div className="flex gap-0 mb-2">
              {(['password', 'hash'] as const).map(m => (
                <button key={m} onClick={() => setAuthMode(m)}
                  className={cn(
                    'px-3 py-1.5 text-[10px] font-semibold uppercase tracking-[0.14em] border transition',
                    authMode === m
                      ? 'border-cyan-500/35 bg-cyan-500/10 text-cyan-300'
                      : 'border-white/[0.07] bg-black text-zinc-600 hover:text-zinc-300',
                  )}>
                  {m === 'password' ? 'Password' : 'NT Hash (PTH)'}
                </button>
              ))}
            </div>
            {authMode === 'password' ? (
              <input value={password} onChange={e => setPassword(e.target.value)}
                type="password"
                placeholder="Cleartext password"
                className="w-full max-w-sm border border-white/[0.07] bg-black px-2.5 py-2 font-mono text-xs text-zinc-200 outline-none focus:border-white/20 placeholder:text-zinc-700" />
            ) : (
              <input value={ntHash} onChange={e => setNtHash(e.target.value)}
                placeholder="LM:NT  or  :NTHash"
                className="w-full max-w-sm border border-white/[0.07] bg-black px-2.5 py-2 font-mono text-xs text-zinc-200 outline-none focus:border-white/20 placeholder:text-zinc-700" />
            )}
          </div>

          {/* Error */}
          {error && (
            <div className="border border-red-500/25 bg-red-500/8 px-3 py-2.5 text-sm text-red-300 flex items-start gap-2">
              <AlertTriangle className="h-4 w-4 mt-0.5 flex-shrink-0" />
              <div>
                <span>{error}</span>
                {error.includes('ENABLE_COMMAND_EXECUTION') && (
                  <div className="mt-1.5 text-xs text-zinc-500">
                    Add <code className="bg-black px-1.5 py-0.5 text-cyan-400 font-mono">ENABLE_COMMAND_EXECUTION=true</code> to your API <code className="bg-black px-1 text-zinc-300 font-mono">.env</code> and restart the server.
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Run button */}
          <div className="flex items-center gap-3">
            <button
              onClick={runCollector}
              disabled={!canRun || running}
              className="flex items-center gap-2 border border-orange-500/30 bg-orange-500/10 px-5 py-2.5 text-xs font-bold uppercase tracking-[0.18em] text-orange-300 transition hover:border-orange-500/50 hover:bg-orange-500/18 disabled:opacity-40 disabled:cursor-not-allowed"
            >
              {running ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Play className="h-3.5 w-3.5" />}
              {running ? 'Running...' : `Run ${selectedTechniques.size} Technique${selectedTechniques.size > 1 ? 's' : ''}`}
            </button>
            {done && (
              <span className="flex items-center gap-1.5 text-xs text-emerald-300">
                <Check className="h-3.5 w-3.5" /> Done — {totalCaptured} item{totalCaptured !== 1 ? 's' : ''} captured
              </span>
            )}
          </div>

          {/* Captured loot summary */}
          {captures.length > 0 && (
            <div className="flex flex-wrap gap-2">
              {captures.map((c, i) => (
                <div key={`${c.loot_type}-${i}`} className="border border-emerald-500/20 bg-emerald-500/6 px-3 py-1.5 text-xs">
                  <span className="font-bold text-emerald-300">{c.count}</span>
                  <span className="text-zinc-500 ml-1">{c.label}</span>
                </div>
              ))}
            </div>
          )}

          {/* Live terminal */}
          {(running || lines.length > 0) && (
            <div>
              <div className="text-[10px] font-semibold uppercase tracking-[0.14em] text-zinc-600 mb-1.5 flex items-center gap-1.5">
                <Terminal className="h-3 w-3" /> Output
                {running && <span className="h-1.5 w-1.5 rounded-full bg-orange-400 animate-pulse" />}
              </div>
              <div
                ref={termRef}
                className="h-64 overflow-y-auto border border-white/[0.07] bg-black p-3 font-mono text-[11px] leading-5 space-y-0.5"
              >
                {lines.map((l, i) => (
                  <div key={i} className={l.stream === 'stderr' ? 'text-red-400' : 'text-zinc-300'}>
                    {l.text}
                  </div>
                ))}
                {running && (
                  <div className="text-zinc-600 flex items-center gap-1">
                    <span className="animate-pulse">▮</span>
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  )
}

function AddHashModal({ onClose, onAdded }: { onClose: () => void; onAdded: () => void }) {
  const [hash, setHash] = useState('')
  const [principal, setPrincipal] = useState('')
  const [source, setSource] = useState('Manual Entry')
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState<{ hash_type: string; hashcat_mode: number; severity: string } | null>(null)

  const HASH_EXAMPLES = [
    { label: 'NT Hash (32 hex)',    example: 'aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c' },
    { label: 'Net-NTLMv2',         example: 'user::domain:challenge:response' },
    { label: 'Kerberoast TGS-REP', example: '$krb5tgs$23$...' },
    { label: 'AS-REP',             example: '$krb5asrep$23$...' },
    { label: 'DCC2 / MSCACHE2',    example: '$DCC2$10240#user#hash' },
  ]

  async function submit() {
    if (!hash.trim()) return
    setError(null)
    setLoading(true)
    try {
      const res = await lootApi.addManualHash({
        hash: hash.trim(),
        principal: principal.trim() || undefined,
        source: source.trim() || 'Manual Entry',
      })
      setResult({ hash_type: res.hash.hash_type, hashcat_mode: res.hash.hashcat_mode, severity: res.hash.severity })
      onAdded()
    } catch (err: unknown) {
      const detail = (err as { response?: { data?: { detail?: string } } })?.response?.data?.detail
      setError(detail ?? 'Failed to add hash. Check format and try again.')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm" onClick={onClose}>
      <div
        className="w-full max-w-lg mx-4 border border-white/12 bg-zinc-950 shadow-2xl"
        onClick={e => e.stopPropagation()}
      >
        {/* Header */}
        <div className="flex items-center justify-between border-b border-white/[0.08] px-5 py-4">
          <div className="flex items-center gap-2.5">
            <Plus className="h-4 w-4 text-cyan-400" />
            <span className="text-sm font-semibold uppercase tracking-[0.16em] text-zinc-200">Add Hash Manually</span>
          </div>
          <button onClick={onClose} className="text-zinc-500 hover:text-white transition p-1">
            <X className="h-4 w-4" />
          </button>
        </div>

        <div className="p-5 space-y-4">
          {/* Hash input */}
          <div>
            <label className="block text-xs font-semibold uppercase tracking-[0.14em] text-zinc-500 mb-1.5">
              Hash Value <span className="text-red-400">*</span>
            </label>
            <textarea
              value={hash}
              onChange={e => setHash(e.target.value)}
              placeholder="Paste hash here…"
              rows={3}
              className="w-full border border-white/[0.07] bg-black px-3 py-2.5 font-mono text-sm text-cyan-300 outline-none focus:border-cyan-500/30 resize-none placeholder:text-zinc-700"
            />
            {/* Format hints */}
            <div className="mt-1.5 flex flex-wrap gap-x-3 gap-y-1">
              {HASH_EXAMPLES.map(h => (
                <button
                  key={h.label}
                  onClick={() => setHash(h.example)}
                  className="text-[10px] text-zinc-600 hover:text-cyan-400 transition"
                  type="button"
                >
                  {h.label}
                </button>
              ))}
            </div>
          </div>

          {/* Principal */}
          <div>
            <label className="block text-xs font-semibold uppercase tracking-[0.14em] text-zinc-500 mb-1.5">Principal</label>
            <input
              value={principal}
              onChange={e => setPrincipal(e.target.value)}
              placeholder="DOMAIN\username or username@domain.com"
              className="w-full border border-white/[0.07] bg-black px-3 py-2 font-mono text-sm text-zinc-200 outline-none focus:border-white/20 placeholder:text-zinc-700"
            />
          </div>

          {/* Source */}
          <div>
            <label className="block text-xs font-semibold uppercase tracking-[0.14em] text-zinc-500 mb-1.5">Source</label>
            <input
              value={source}
              onChange={e => setSource(e.target.value)}
              placeholder="Manual Entry"
              className="w-full border border-white/[0.07] bg-black px-3 py-2 text-sm text-zinc-200 outline-none focus:border-white/20 placeholder:text-zinc-600"
            />
          </div>

          {/* Error */}
          {error && (
            <div className="border border-red-500/25 bg-red-500/8 px-3 py-2.5 text-sm text-red-300 flex items-start gap-2">
              <AlertTriangle className="h-4 w-4 mt-0.5 flex-shrink-0" />
              {error}
            </div>
          )}

          {/* Success */}
          {result && (
            <div className="border border-emerald-500/25 bg-emerald-500/8 px-3 py-2.5 text-sm text-emerald-300 flex items-center gap-2">
              <Check className="h-4 w-4 flex-shrink-0" />
              Added as <span className="font-semibold">{result.hash_type}</span> · mode {result.hashcat_mode} · severity {result.severity}
            </div>
          )}

          {/* Actions */}
          <div className="flex gap-3 pt-1">
            <button
              onClick={submit}
              disabled={!hash.trim() || loading}
              className="flex-1 flex items-center justify-center gap-2 border border-cyan-500/30 bg-cyan-500/10 py-2.5 text-sm font-semibold uppercase tracking-[0.14em] text-cyan-300 transition hover:border-cyan-500/50 hover:bg-cyan-500/18 disabled:opacity-40 disabled:cursor-not-allowed"
            >
              {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : <Plus className="h-4 w-4" />}
              {result ? 'Add Another' : 'Add to Vault'}
            </button>
            {result && (
              <button
                onClick={onClose}
                className="px-4 border border-white/[0.07] text-sm text-zinc-400 hover:text-white transition"
              >
                Done
              </button>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}

function LoadHashesPrompt({ onLoad }: { onLoad: () => void }) {
  return (
    <div className="flex flex-col items-center justify-center gap-5 border border-dashed border-white/10 py-16 text-center">
      <div className="grid h-12 w-12 place-items-center border border-white/10">
        <Hash className="h-5 w-5 text-zinc-600" />
      </div>
      <div>
        <div className="text-sm font-semibold text-zinc-400">Hashes not loaded</div>
        <div className="mt-1 text-xs text-zinc-600">Click below to fetch and classify hash intelligence from the vault</div>
      </div>
      <button
        onClick={onLoad}
        className="flex items-center gap-2 border border-cyan-500/25 bg-cyan-500/10 px-5 py-2.5 text-xs font-semibold uppercase tracking-[0.16em] text-cyan-300 transition hover:border-cyan-500/45 hover:bg-cyan-500/15"
      >
        <Zap className="h-3.5 w-3.5" /> Load Hashes
      </button>
    </div>
  )
}

function SourceStrip({ sources }: { sources: Array<{ name: string; signals: string[]; risk: string }> }) {
  const rows = sources.length ? sources : [
    { name: 'LSASS Memory',           signals: ['NT hashes', 'Kerberos tickets', 'WDigest plaintext'],   risk: 'CRITICAL' },
    { name: 'SAM Database',           signals: ['local NT hashes', 'local admin reuse'],                 risk: 'HIGH' },
    { name: 'NTDS.dit / DCSync',      signals: ['domain hashes', 'krbtgt', 'AES keys'],                  risk: 'CRITICAL' },
    { name: 'DCC2 Cached Creds',      signals: ['MSCACHEV2', 'mode 2100'],                               risk: 'MEDIUM' },
    { name: 'App Secrets',            signals: ['browser', 'Wi-Fi', 'RDP'],                              risk: 'HIGH' },
    { name: 'RemoteMonologue',        signals: ['Net-NTLMv1/v2', 'DCOM'],                                risk: 'HIGH' },
    { name: 'SCCM / goLAPS',          signals: ['NAA', 'LAPS', 'task sequence'],                         risk: 'HIGH' },
  ]

  return (
    <div className="grid gap-2 md:grid-cols-2 2xl:grid-cols-3">
      {rows.map((source, i) => {
        const Icon = sourceIcon(source.name)
        const accent = SOURCE_ACCENTS[i % SOURCE_ACCENTS.length]
        const sev = sevStyle(source.risk)
        return (
          <div key={source.name} className="flex gap-3 border border-white/[0.07] bg-[#0a0a0a] p-3">
            <div className="grid h-8 w-8 shrink-0 place-items-center border border-white/[0.07]" style={{ color: accent }}>
              <Icon className="h-3.5 w-3.5" />
            </div>
            <div className="min-w-0 flex-1">
              <div className="flex items-center justify-between gap-2">
                <span className="text-xs font-semibold text-zinc-300">{source.name}</span>
                <span className="shrink-0 border px-1.5 py-0.5 text-[9px] font-semibold" style={{ color: sev.color, borderColor: sev.border }}>
                  {source.risk}
                </span>
              </div>
              <div className="mt-1.5 flex flex-wrap gap-1">
                {source.signals.slice(0, 3).map(sig => (
                  <span key={sig} className="rounded bg-white/[0.04] px-1.5 py-0.5 text-[9px] text-zinc-500">{sig}</span>
                ))}
              </div>
            </div>
          </div>
        )
      })}
    </div>
  )
}

function CrackDock({
  hashcatReady, johnReady, hashcatPath, johnPath,
  wordlist, setWordlist, defaultWordlist, wordlistCount,
  selectedCount, selectedModes, activeMode, ack, setAck,
  canCrack, pending, onCrack, error, job,
}: {
  hashcatReady: boolean; johnReady: boolean
  hashcatPath?: string | null; johnPath?: string | null
  wordlist: string; setWordlist: (v: string) => void
  defaultWordlist: string; wordlistCount: number
  selectedCount: number; selectedModes: Set<number>; activeMode?: number
  ack: boolean; setAck: (v: boolean) => void
  canCrack: boolean; pending: boolean; onCrack: () => void
  error?: unknown
  job?: { status?: string; tool?: string | null; mode?: number | null; output?: string[]; cracked?: Array<{ hash: string; plaintext: string }> }
}) {
  return (
    <aside className="space-y-3 xl:sticky xl:top-6">

      {/* Tool status */}
      <div className="border border-white/[0.07] bg-[#0a0a0a]">
        <div className="border-b border-white/[0.07] px-4 py-3">
          <SectionLabel icon={Cpu} label="Crack Dock" />
        </div>
        <div className="grid grid-cols-2 divide-x divide-white/[0.07] border-b border-white/[0.07]">
          {[['hashcat', hashcatReady, hashcatPath], ['john', johnReady, johnPath]].map(([label, ready, path]) => (
            <div key={String(label)} className="px-4 py-3">
              <div className="text-[9px] uppercase tracking-[0.16em] text-zinc-600">{label}</div>
              <div className={cn('mt-0.5 text-xs font-semibold', ready ? 'text-emerald-400' : 'text-red-400')}>{ready ? 'ready' : 'missing'}</div>
              <div className="mt-0.5 truncate font-mono text-[9px] text-zinc-700">{String(path ?? '—')}</div>
            </div>
          ))}
        </div>
        <div className="grid grid-cols-3 divide-x divide-white/[0.07] border-b border-white/[0.07]">
          {[['selected', selectedCount], ['mode', selectedModes.size === 1 ? activeMode ?? '—' : 'mix'], ['lists', wordlistCount]].map(([label, value]) => (
            <div key={String(label)} className="px-3 py-2.5">
              <div className="text-[9px] uppercase tracking-[0.14em] text-zinc-600">{label}</div>
              <div className="mt-0.5 font-mono text-sm font-bold text-zinc-200">{value}</div>
            </div>
          ))}
        </div>

        <div className="space-y-3 p-4">
          <div>
            <label className="block text-[10px] font-semibold uppercase tracking-[0.16em] text-zinc-600">Wordlist</label>
            <div className="mt-1.5 flex gap-2">
              <input
                value={wordlist}
                onChange={e => setWordlist(e.target.value)}
                placeholder={defaultWordlist || '/usr/share/wordlists/rockyou.txt'}
                className="min-w-0 flex-1 border border-white/[0.07] bg-black px-2.5 py-2 font-mono text-xs text-zinc-300 outline-none focus:border-white/20"
              />
              <button className="grid h-9 w-9 place-items-center border border-white/[0.07] text-zinc-600 transition hover:text-zinc-300">
                <Upload className="h-3.5 w-3.5" />
              </button>
            </div>
            {defaultWordlist && <div className="mt-1 font-mono text-[10px] text-zinc-700">{defaultWordlist}</div>}
          </div>

          <label className="flex items-start gap-2 text-xs leading-5 text-zinc-500">
            <input type="checkbox" checked={ack} onChange={e => setAck(e.target.checked)} className="mt-1 accent-cyan-500" />
            <span>I confirm these hashes are from an authorized lab or assessment and cracking is allowed.</span>
          </label>

          {selectedModes.size > 1 && (
            <div className="border border-yellow-500/20 bg-yellow-500/5 px-3 py-2 text-xs text-yellow-300">Select one hash mode at a time.</div>
          )}
          {!!error && (
            <div className="border border-red-500/20 bg-red-500/5 px-3 py-2 text-xs text-red-300">
              {(error as { response?: { data?: { detail?: string } } })?.response?.data?.detail ?? 'Unable to start cracking job'}
            </div>
          )}

          <button
            disabled={!canCrack || pending}
            onClick={onCrack}
            className="flex w-full items-center justify-center gap-2 border border-orange-500/25 bg-orange-500/8 px-4 py-2.5 text-xs font-semibold uppercase tracking-[0.16em] text-orange-300 transition hover:border-orange-500/45 disabled:cursor-not-allowed disabled:opacity-40"
          >
            {pending ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Play className="h-3.5 w-3.5" />}
            Start Local Crack
          </button>
        </div>
      </div>

      {/* Job stream */}
      <div className="border border-white/[0.07] bg-[#0a0a0a]">
        <div className="border-b border-white/[0.07] px-4 py-3">
          <SectionLabel icon={Terminal} label="Job Stream" />
        </div>
        <div className="p-3">
          {!job ? (
            <div className="flex items-center gap-2 py-4 text-xs text-zinc-600">
              <Terminal className="h-3.5 w-3.5" /> No cracking job launched this session.
            </div>
          ) : (
            <div className="space-y-2">
              <div className="flex items-center justify-between text-xs">
                <span className="text-zinc-500">{job.tool} · mode {job.mode}</span>
                <span className={cn('font-semibold', job.status === 'COMPLETED' ? 'text-emerald-400' : job.status === 'FAILED' ? 'text-red-400' : 'text-orange-400')}>{job.status}</span>
              </div>
              {job.cracked?.length ? (
                <div className="space-y-1">
                  {job.cracked.map((c, i) => (
                    <div key={`${c.hash}-${i}`} className="border border-emerald-500/20 bg-emerald-500/5 p-2 text-xs">
                      <div className="font-mono font-semibold text-emerald-300">{c.plaintext}</div>
                      <div className="mt-0.5 truncate font-mono text-zinc-600">{c.hash}</div>
                    </div>
                  ))}
                </div>
              ) : null}
              <pre className="max-h-48 overflow-auto border border-white/[0.07] bg-black p-2.5 font-mono text-[10px] leading-5 text-zinc-500">
                {(job.output ?? []).join('\n') || 'Waiting for output...'}
              </pre>
            </div>
          )}
        </div>
      </div>

      {/* Notes */}
      <div className="space-y-2">
        <div className="border border-cyan-500/10 bg-cyan-500/[0.04] px-3 py-2.5 text-[11px] leading-5 text-cyan-200/60">
          <Sparkles className="mb-1.5 h-3 w-3 text-cyan-400/60" />
          Page load inventories only. Cracking starts after selecting hashes, authorizing, and providing a wordlist.
        </div>
        <div className="border border-red-500/10 bg-red-500/[0.04] px-3 py-2.5 text-[11px] leading-5 text-red-200/60">
          <ShieldAlert className="mb-1.5 h-3 w-3 text-red-400/60" />
          NT hashes may not need cracking for PTH. Treat krbtgt, Administrator, and DCSync material as crown-jewel evidence.
        </div>
      </div>
    </aside>
  )
}

export default function LootPage() {
  const [query, setQuery] = useState('')
  const [mode, setMode] = useState<string>('all')
  const [selected, setSelected] = useState<Set<string>>(new Set())
  const [wordlist, setWordlist] = useState('')
  const [ack, setAck] = useState(false)
  const [jobId, setJobId] = useState<string | null>(null)
  const [hashesEnabled, setHashesEnabled] = useState(false)
  const [showAddHash, setShowAddHash] = useState(false)

  useEffect(() => {
    const saved = sessionStorage.getItem('loot_crack_job_id')
    if (saved) setJobId(saved)
  }, [])

  useEffect(() => {
    if (jobId) sessionStorage.setItem('loot_crack_job_id', jobId)
    else sessionStorage.removeItem('loot_crack_job_id')
  }, [jobId])

  const { data: summary } = useQuery({
    queryKey: ['loot-summary'],
    queryFn: () => lootApi.summary(),
    refetchInterval: 12_000,
  })

  const { data: intel, isLoading, isError, refetch: refetchIntel } = useQuery({
    queryKey: ['loot-hash-intel'],
    queryFn: () => lootApi.hashIntel(),
    refetchInterval: hashesEnabled ? 12_000 : false,
  })

  const { data: job } = useQuery({
    queryKey: ['loot-crack-job', jobId],
    queryFn: () => lootApi.crackJob(jobId!),
    enabled: !!jobId,
    refetchInterval: d => d.state.data?.status === 'RUNNING' || d.state.data?.status === 'QUEUED' ? 2500 : false,
  })

  const hashes = useMemo(() => {
    const section = intel?.hashes
    if (Array.isArray(section)) return section
    return section?.items ?? intel?.hash_items ?? []
  }, [intel?.hashes, intel?.hash_items])

  const modes = useMemo(() =>
    ['all', ...Object.keys(intel?.by_hashcat_mode ?? {}).sort((a, b) => Number(a) - Number(b))],
    [intel?.by_hashcat_mode]
  )

  const defaultWordlist = intel?.tools.default_wordlist ?? ''
  const hashcatReady = !!(intel?.tools.hashcat?.present || intel?.tools.hashcat_available)
  const johnReady = !!(intel?.tools.john?.present || intel?.tools.john_available)
  const sourceCount = Object.keys(intel?.by_source ?? {}).length

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase()
    return hashes.filter(item => {
      if (mode !== 'all' && String(item.hashcat_mode) !== mode) return false
      if (!q) return true
      return [item.hash, item.hash_type, item.source, item.principal ?? '', item.chain_name ?? '', item.notes].join(' ').toLowerCase().includes(q)
    })
  }, [hashes, mode, query])

  const [hashPage, setHashPage] = useState(0)
  const pagedHashes = filtered.slice(hashPage * HASH_PAGE_SIZE, (hashPage + 1) * HASH_PAGE_SIZE)
  const totalHashPages = Math.ceil(filtered.length / HASH_PAGE_SIZE)

  useEffect(() => { setHashPage(0) }, [query, mode])

  const selectedHashes = hashes.filter(item => selected.has(item.id))
  const selectedModes = new Set(selectedHashes.map(item => item.hashcat_mode))
  const activeMode = selectedHashes[0]?.hashcat_mode
  const canCrack = selectedHashes.length > 0 && selectedModes.size === 1 && ack && !!(wordlist || defaultWordlist)

  const crackMutation = useMutation({
    mutationFn: () => lootApi.startCrack({
      hashes: selectedHashes.map(item => item.hash),
      hashcat_mode: activeMode!,
      wordlist: wordlist || defaultWordlist,
      tool: 'auto',
      acknowledge_authorized: ack,
    }),
    onSuccess: response => setJobId(response.job_id),
  })

  function toggle(item: LootHashIntelItem) {
    setSelected(prev => {
      const next = new Set(prev)
      if (next.has(item.id)) next.delete(item.id)
      else next.add(item.id)
      return next
    })
  }

  return (
    <AppShell>
      {showAddHash && (
        <AddHashModal
          onClose={() => setShowAddHash(false)}
          onAdded={() => { setHashesEnabled(true); refetchIntel() }}
        />
      )}
      <div className="min-h-full bg-transparent p-4 text-zinc-100 sm:p-6">
        <div className="mx-auto max-w-[1500px] space-y-4">

          {/* Header */}
          <div className="flex flex-wrap items-start justify-between gap-4">
            <div>
              <div className="flex items-center gap-2">
                <Hash className="h-4 w-4 text-cyan-400" />
                <h1 className="text-sm font-semibold uppercase tracking-[0.18em] text-zinc-200">Hash Dump & Break</h1>
                <span className="border border-cyan-500/20 bg-cyan-500/[0.08] px-2 py-0.5 text-[9px] font-semibold uppercase tracking-[0.16em] text-cyan-400">Vault</span>
              </div>
              <p className="mt-1 max-w-xl text-xs text-zinc-600">
                LSASS · SAM · NTDS.dit · DCC2 · App secrets · RemoteMonologue · SCCM · goLAPS
              </p>
            </div>
            <div className="flex items-center gap-2">
              <div className="flex gap-1.5">
                {[
                  { label: 'hashcat', ready: hashcatReady },
                  { label: 'john', ready: johnReady },
                ].map(({ label, ready }) => (
                  <div key={label} className="flex items-center gap-1.5 border border-white/[0.07] bg-[#0a0a0a] px-2.5 py-1.5">
                    <span className={cn('h-1.5 w-1.5 rounded-full', ready ? 'bg-emerald-400' : 'bg-zinc-700')} />
                    <span className="text-[10px] font-medium text-zinc-500">{label}</span>
                  </div>
                ))}
              </div>
              <button
                onClick={() => setShowAddHash(true)}
                className="flex items-center gap-1.5 border border-cyan-500/25 bg-cyan-500/[0.08] px-3 py-1.5 text-[10px] font-semibold uppercase tracking-[0.14em] text-cyan-300 transition hover:border-cyan-500/45 hover:bg-cyan-500/15"
              >
                <Plus className="h-3.5 w-3.5" /> Add Hash
              </button>
              <a
                href={lootApi.exportUrl()}
                className="flex items-center gap-1.5 border border-white/[0.07] bg-[#0a0a0a] px-3 py-1.5 text-[10px] font-semibold uppercase tracking-[0.14em] text-zinc-400 transition hover:border-white/15 hover:text-zinc-200"
              >
                <Download className="h-3.5 w-3.5" /> Export
              </a>
            </div>
          </div>

          {/* Stats row */}
          <div className="grid grid-cols-2 gap-2 md:grid-cols-5">
            <StatCard label="Loot Items"  value={summary?.total_items ?? 0}     color="#818cf8" icon={Database} detail="raw entries" />
            <StatCard label="Hashes"      value={intel?.total_hashes ?? 0}      color="#22d3ee" icon={Hash}     detail={`${sourceCount} sources`} />
            <StatCard label="Crackable"   value={intel?.crackable_hashes ?? 0}  color="#f97316" icon={Zap}      detail="wordlist ready" />
            <StatCard label="PTH Ready"   value={intel?.pass_the_hash_ready ?? 0} color="#ff4d6d" icon={KeyRound} detail="no crack needed" />
            <StatCard label="Chains"      value={summary?.chains_with_loot ?? 0} color="#a855f7" icon={Radar}   detail="with loot" />
          </div>

          {/* Main content */}
          <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_360px]">
            <main className="space-y-3">

              {/* Hash Collector */}
              <HashCollector onCollected={() => { setHashesEnabled(true); void refetchIntel() }} />

              {/* Search + filters */}
              <div className="border border-white/[0.07] bg-[#0a0a0a]">
                <div className="flex flex-col gap-2 p-3 lg:flex-row lg:items-center">
                  <div className="relative flex-1">
                    <Search className="absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-zinc-600" />
                    <input
                      value={query}
                      onChange={e => setQuery(e.target.value)}
                      placeholder="Search hashes, principals, sources, chains..."
                      className="h-9 w-full border border-white/[0.07] bg-black pl-9 pr-3 text-xs text-zinc-200 outline-none transition focus:border-white/15"
                    />
                  </div>
                  <div className="flex gap-1.5 overflow-x-auto">
                    {modes.map(item => (
                      <button
                        key={item}
                        onClick={() => setMode(item)}
                        className={cn(
                          'shrink-0 border px-2.5 py-1.5 text-[10px] font-semibold uppercase tracking-[0.14em] transition',
                          mode === item
                            ? 'border-cyan-500/35 bg-cyan-500/10 text-cyan-300'
                            : 'border-white/[0.07] bg-black text-zinc-600 hover:text-zinc-300'
                        )}
                      >
                        {item === 'all' ? 'All' : `M${item}`}
                      </button>
                    ))}
                  </div>
                </div>
                {selectedHashes.length > 0 && (
                  <div className="flex items-center gap-2 border-t border-white/[0.07] px-3 py-2">
                    <span className="text-[10px] font-semibold text-cyan-400">{selectedHashes.length} selected</span>
                    <ArrowRight className="h-3 w-3 text-zinc-700" />
                    <span className="text-[10px] text-zinc-600">{selectedModes.size === 1 ? `mode ${activeMode} ready` : 'mixed modes'}</span>
                    <button onClick={() => setSelected(new Set())} className="ml-auto text-[10px] text-zinc-600 transition hover:text-zinc-300">clear</button>
                  </div>
                )}
              </div>

              {/* Hash list */}
              <div className="border border-white/[0.07] bg-[#0a0a0a]">
                <div className="flex items-center justify-between border-b border-white/[0.07] px-4 py-3">
                  <SectionLabel icon={Hash} label="Hashes" sub={hashesEnabled && !isLoading ? `${filtered.length} items` : undefined} />
                  <div className="flex items-center gap-2">
                    {hashesEnabled && !isLoading && (
                      <button
                        onClick={() => refetchIntel()}
                        className="flex items-center gap-1.5 text-[10px] text-zinc-600 transition hover:text-zinc-300"
                        title="Refresh"
                      >
                        <RefreshCw className="h-3 w-3" /> Refresh
                      </button>
                    )}
                    <div className="flex items-center gap-2">
                      <button
                        onClick={() => setShowAddHash(true)}
                        className="flex items-center gap-1 border border-cyan-500/20 bg-cyan-500/[0.06] px-2.5 py-1 text-[10px] font-semibold uppercase tracking-[0.14em] text-cyan-400 transition hover:border-cyan-500/40"
                      >
                        <Plus className="h-3 w-3" /> Add
                      </button>
                      {!hashesEnabled && (
                        <button
                          onClick={() => setHashesEnabled(true)}
                          className="flex items-center gap-1.5 border border-cyan-500/25 bg-cyan-500/8 px-3 py-1.5 text-[10px] font-semibold uppercase tracking-[0.14em] text-cyan-300 transition hover:border-cyan-500/45"
                        >
                          <Zap className="h-3 w-3" /> Load Hashes
                        </button>
                      )}
                    </div>
                  </div>
                </div>

                {!hashesEnabled ? (
                  <LoadHashesPrompt onLoad={() => setHashesEnabled(true)} />
                ) : isLoading ? (
                  <div className="flex items-center gap-2 px-4 py-10 text-xs text-zinc-600">
                    <Loader2 className="h-3.5 w-3.5 animate-spin text-cyan-500" /> Classifying hashes...
                  </div>
                ) : isError ? (
                  <div className="flex flex-col items-center gap-3 py-8 text-zinc-500">
                    <AlertTriangle className="h-6 w-6 text-red-400/60" />
                    <p className="text-xs">Failed to load hash intelligence</p>
                    <button
                      onClick={() => refetchIntel()}
                      className="flex items-center gap-1.5 rounded border border-zinc-700 px-3 py-1.5 text-[10px] text-zinc-400 hover:border-zinc-500 hover:text-zinc-300"
                    >
                      <RefreshCw className="h-3 w-3" /> Retry
                    </button>
                  </div>
                ) : filtered.length === 0 ? (
                  hashes.length === 0 ? (
                    <EmptyVault hashcatReady={hashcatReady} johnReady={johnReady} />
                  ) : (
                    <div className="flex flex-col items-center gap-2 py-12 text-center">
                      <Search className="h-8 w-8 text-zinc-700" />
                      <div className="text-xs font-semibold text-zinc-500">No hashes match this filter</div>
                      <div className="text-[10px] text-zinc-700">Try another mode or clear the search</div>
                    </div>
                  )
                ) : (
                  <div>
                    {pagedHashes.map(item => (
                      <HashRow key={item.id} item={item} selected={selected.has(item.id)} onToggle={() => toggle(item)} />
                    ))}
                    {totalHashPages > 1 && (
                      <div className="flex items-center justify-between border-t border-white/[0.07] px-4 py-3">
                        <button
                          onClick={() => setHashPage(p => Math.max(0, p - 1))}
                          disabled={hashPage === 0}
                          className="text-[10px] text-zinc-500 hover:text-zinc-300 disabled:opacity-30 disabled:cursor-not-allowed"
                        >
                          ← Prev
                        </button>
                        <span className="text-[10px] text-zinc-600">
                          Page {hashPage + 1} of {totalHashPages} · {filtered.length} hashes
                        </span>
                        <button
                          onClick={() => setHashPage(p => Math.min(totalHashPages - 1, p + 1))}
                          disabled={hashPage >= totalHashPages - 1}
                          className="text-[10px] text-zinc-500 hover:text-zinc-300 disabled:opacity-30 disabled:cursor-not-allowed"
                        >
                          Next →
                        </button>
                      </div>
                    )}
                  </div>
                )}
              </div>

              {/* Source radar */}
              {hashesEnabled && !isLoading && !isError && (
                <div className="border border-white/[0.07] bg-[#0a0a0a]">
                  <div className="border-b border-white/[0.07] px-4 py-3">
                    <SectionLabel
                      icon={Binary}
                      label="Credential Source Radar"
                      sub={`${(intel?.deep_dive?.length || 7)} lanes`}
                    />
                  </div>
                  <div className="p-3">
                    <SourceStrip sources={intel?.deep_dive ?? []} />
                  </div>
                </div>
              )}
            </main>

            <CrackDock
              hashcatReady={hashcatReady}
              johnReady={johnReady}
              hashcatPath={intel?.tools.hashcat?.path ?? intel?.tools.hashcat_path}
              johnPath={intel?.tools.john?.path ?? intel?.tools.john_path}
              wordlist={wordlist}
              setWordlist={setWordlist}
              defaultWordlist={defaultWordlist}
              wordlistCount={intel?.tools.wordlist_candidates.length ?? 0}
              selectedCount={selectedHashes.length}
              selectedModes={selectedModes}
              activeMode={activeMode}
              ack={ack}
              setAck={setAck}
              canCrack={!!canCrack}
              pending={crackMutation.isPending}
              onCrack={() => crackMutation.mutate()}
              error={crackMutation.error}
              job={job}
            />
          </div>
        </div>
      </div>
    </AppShell>
  )
}
