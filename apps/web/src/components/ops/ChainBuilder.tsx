'use client'

import { copyText } from '@/lib/clipboard'
import { useState, useEffect, useRef, useCallback } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Wifi, User, Key, Shield, Server, GitBranch,
  ChevronRight, ChevronDown, ChevronLeft,
  Square, RefreshCw, Loader2,
  CheckCircle2, XCircle, Circle, AlertTriangle,
  Zap, Crown, Eye, EyeOff,
  Database, Copy, Check,
  Activity,
  ArrowRight,
} from 'lucide-react'
import dynamic from 'next/dynamic'
import { assessmentApi } from '@/lib/api'
import {
  resolveChain, createChain, startChain, stopChain,
  connectChainWs, listChains, getSituations, getLibrary, preflightChain, getChain,
  type Chain, type ChainStep, type ChainEvent, type ChainRequest,
  type ChainSituation, type PathLibraryEntry, type ChainPreflightResult,
} from '@/lib/chainApi'

const LiveOutputTerminal = dynamic(() => import('./LiveOutputTerminal'), { ssr: false })

const MONO = { fontFamily: 'JetBrains Mono, monospace' }
const RED   = '#f43f5e'
const GREEN = '#22c55e'

type Phase = 'situation' | 'library' | 'config' | 'preview' | 'running' | 'done'
type StepStatus = 'pending' | 'running' | 'done' | 'failed'

interface StepState {
  status: StepStatus
  jobId: string | null
  lines: string[]
  exitCode: number | null
}

const SITUATION_ICONS: Record<string, React.ElementType> = {
  wifi: Wifi,
  user: User,
  key: Key,
  shield: Shield,
  server: Server,
  'git-branch': GitBranch,
}

const LOOT_COLORS: Record<string, string> = {
  da_hashes: '#ef4444',
  nt_hashes: '#f97316',
  // backend emits singular forms — keep both for forward-compat
  kerberos_hash: '#a855f7',
  kerberos_hashes: '#a855f7',
  cleartext_creds: '#f59e0b',
  ccache: '#818cf8',
  ccache_ticket: '#818cf8',
  golden_ticket: '#fbbf24',
  da_certificate: '#10b981',
  dc_certificate: '#10b981',
  shadow_cert: '#c084fc',
  asrep_hash: '#8b5cf6',
  asrep_hashes: '#8b5cf6',
  krbtgt_hash: '#ef4444',
  vulnerable_template: '#f59e0b',
  modified_template: '#fb923c',
  ca_name: '#6ee7b7',
  default: '#94a3b8',
}

const TECH_COLORS: Record<string, string> = {
  dcsync: '#ef4444', secretsdump: '#f97316', wmiexec: '#38bdf8',
  smbexec: '#34d399', psexec: '#fb923c', kerberoast: '#818cf8',
  asreproast: '#a78bfa', getst: '#fbbf24', getTGT: '#6ee7b7',
  certipy_req: '#10b981', certipy_auth: '#34d399', certipy_find: '#6ee7b7',
  whisker: '#c084fc', ntlmrelayx: '#38bdf8', coerce: '#f59e0b',
  ticketer: '#fbbf24', addcomputer: '#94a3b8', lookupsid: '#6b7280',
  gmsa_dump: '#c084fc', rbcd_write: '#22d3ee', sccm_naa: '#f59e0b',
  manual_crack: '#fbbf24',
}

function techColor(id: string) { return TECH_COLORS[id] ?? '#818cf8' }
function lootColor(type: string) { return LOOT_COLORS[type] ?? LOOT_COLORS.default }

function hexRgb(hex: string): string {
  const map: Record<string, string> = {
    '#ef4444': '239,68,68', '#f97316': '249,115,22', '#38bdf8': '56,189,248',
    '#34d399': '52,211,153', '#a78bfa': '167,139,250', '#818cf8': '129,140,248',
    '#fbbf24': '251,191,36', '#6b7280': '107,114,128', '#fb923c': '251,146,60',
    '#10b981': '16,185,129', '#c084fc': '192,132,252', '#22d3ee': '34,211,238',
    '#f43f5e': '244,63,94', '#22c55e': '34,197,94', '#a855f7': '168,85,247',
    '#f59e0b': '245,158,11', '#94a3b8': '148,163,184', '#6ee7b7': '110,231,183',
  }
  return map[hex] ?? '200,190,240'
}

function confBar(conf: number, color: string) {
  return (
    <div className="flex items-center gap-2">
      <div className="h-1.5 flex-1 rounded-full overflow-hidden" style={{ background: 'rgba(255,255,255,0.06)' }}>
        <div className="h-full rounded-full transition-all" style={{ width: `${Math.round(conf * 100)}%`, background: `linear-gradient(90deg,${color}88,${color})` }} />
      </div>
      <span className="text-[9px] tabular-nums font-bold" style={{ color }}>{Math.round(conf * 100)}%</span>
    </div>
  )
}

function CopyBtn({ text }: { text: string }) {
  const [copied, setCopied] = useState(false)
  return (
    <button onClick={() => { copyText(text); setCopied(true); setTimeout(() => setCopied(false), 1500) }}
      className="rounded p-1 text-zinc-600 transition hover:text-zinc-300">
      {copied ? <Check className="h-3 w-3 text-green-400" /> : <Copy className="h-3 w-3" />}
    </button>
  )
}

function SituationSelector({ situations, selected, onSelect }: {
  situations: ChainSituation[]
  selected: string
  onSelect: (id: string) => void
}) {
  return (
    <div className="space-y-3">
      <div className="mb-4">
        <h2 className="text-base font-black tracking-tight" style={{ color: RED }}>STARTING POSITION</h2>
        <p className="text-[10px] mt-0.5" style={{ color: 'rgba(200,190,240,0.4)', ...MONO }}>
          {'// what do you have right now?'}
        </p>
      </div>
      <div className="grid gap-2.5 sm:grid-cols-2 xl:grid-cols-3">
        {situations.map(sit => {
          const Icon = SITUATION_ICONS[sit.icon] ?? Wifi
          const isActive = selected === sit.id
          return (
            <motion.button
              key={sit.id}
              onClick={() => onSelect(sit.id)}
              whileHover={{ scale: 1.015 }}
              whileTap={{ scale: 0.985 }}
              className="relative overflow-hidden rounded-xl p-4 text-left transition-all"
              style={{
                background: isActive ? `rgba(${hexRgb(sit.color)},0.12)` : 'rgba(255,255,255,0.025)',
                border: `1px solid ${isActive ? sit.color + '66' : 'rgba(255,255,255,0.07)'}`,
                boxShadow: isActive ? `0 0 28px rgba(${hexRgb(sit.color)},0.18)` : 'none',
              }}>
              {isActive && (
                <div className="pointer-events-none absolute inset-x-0 top-0 h-px"
                  style={{ background: `linear-gradient(90deg,transparent,${sit.color},transparent)` }} />
              )}
              <div className="flex items-start gap-3">
                <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg border"
                  style={{ background: `rgba(${hexRgb(sit.color)},0.14)`, borderColor: sit.color + '44' }}>
                  <Icon className="h-4 w-4" style={{ color: sit.color }} />
                </div>
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-1.5">
                    <span className="text-xs font-black" style={{ color: isActive ? sit.color : '#e2e8f0' }}>{sit.label}</span>
                    {!sit.credential_required && (
                      <span className="rounded border px-1.5 py-0.5 text-[8px] font-bold"
                        style={{ color: '#22d3ee', borderColor: '#22d3ee33', background: '#22d3ee0d' }}>NO CREDS</span>
                    )}
                  </div>
                  <p className="mt-1 text-[10px] leading-relaxed" style={{ color: 'rgba(200,190,240,0.5)' }}>{sit.description}</p>
                  <p className="mt-1.5 text-[9px] italic" style={{ color: 'rgba(200,190,240,0.3)', ...MONO }}>e.g. {sit.example}</p>
                </div>
                {isActive && <ChevronRight className="h-3.5 w-3.5 shrink-0 mt-0.5" style={{ color: sit.color }} />}
              </div>
            </motion.button>
          )
        })}
      </div>
    </div>
  )
}

function PathLibraryPanel({ paths, selectedId, onSelect }: {
  paths: PathLibraryEntry[]
  selectedId: string | null
  onSelect: (id: string) => void
}) {
  const [expanded, setExpanded] = useState<string | null>(null)

  return (
    <div className="space-y-3">
      <div className="mb-4">
        <h2 className="text-base font-black tracking-tight" style={{ color: RED }}>ATTACK PATH LIBRARY</h2>
        <p className="text-[10px] mt-0.5" style={{ color: 'rgba(200,190,240,0.4)', ...MONO }}>
          {'// ' + paths.length + ' paths available · select one to execute'}
        </p>
      </div>
      <div className="space-y-2 max-h-[640px] overflow-y-auto pr-1">
        {paths.map(path => {
          const isSelected = selectedId === path.id
          const isExpanded = expanded === path.id
          const color = path.confidence >= 0.88 ? '#ef4444' : path.confidence >= 0.78 ? '#f97316' : '#eab308'

          return (
            <motion.div
              key={path.id}
              initial={{ opacity: 0, y: 6 }}
              animate={{ opacity: 1, y: 0 }}
              className="overflow-hidden rounded-xl border transition-all"
              style={{
                background: isSelected ? `rgba(${hexRgb(color)},0.08)` : 'rgba(255,255,255,0.02)',
                borderColor: isSelected ? color + '55' : 'rgba(255,255,255,0.07)',
                boxShadow: isSelected ? `0 0 24px rgba(${hexRgb(color)},0.14)` : 'none',
              }}>
              <button
                onClick={() => { onSelect(path.id); setExpanded(isExpanded ? null : path.id) }}
                className="w-full px-4 py-3 text-left">
                <div className="flex items-start gap-3">
                  <div className="flex h-10 w-10 shrink-0 flex-col items-center justify-center rounded-lg border"
                    style={{ background: `rgba(${hexRgb(color)},0.12)`, borderColor: color + '44' }}>
                    <span className="text-sm font-black tabular-nums" style={{ color }}>{Math.round(path.confidence * 100)}</span>
                    <span className="text-[7px] uppercase tracking-wider" style={{ color }}>conf</span>
                  </div>
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center justify-between gap-2">
                      <span className="text-xs font-black text-zinc-100">{path.name}</span>
                      <div className="flex items-center gap-1.5 shrink-0">
                        <span className="text-[9px] text-zinc-600">{path.step_count} steps</span>
                        {isExpanded ? <ChevronDown className="h-3 w-3 text-zinc-600" /> : <ChevronRight className="h-3 w-3 text-zinc-600" />}
                      </div>
                    </div>
                    <p className="mt-0.5 text-[10px] text-zinc-500 line-clamp-2">{path.description}</p>
                    <div className="mt-2">{confBar(path.confidence, color)}</div>
                    <div className="mt-2 flex flex-wrap gap-1">
                      {path.tags.slice(0, 5).map(tag => (
                        <span key={tag} className="rounded border px-1.5 py-0.5 text-[8px] font-semibold"
                          style={{ color: color + 'cc', borderColor: color + '28', background: color + '0d' }}>
                          {tag}
                        </span>
                      ))}
                    </div>
                  </div>
                </div>
              </button>

              <AnimatePresence>
                {isExpanded && (
                  <motion.div initial={{ height: 0, opacity: 0 }} animate={{ height: 'auto', opacity: 1 }} exit={{ height: 0, opacity: 0 }}
                    className="border-t px-4 pb-3 pt-2" style={{ borderColor: 'rgba(255,255,255,0.05)' }}>
                    <div className="space-y-1.5">
                      {path.steps_preview.map((step, i) => (
                        <div key={i} className="flex items-start gap-2.5 rounded-lg border border-white/[.04] bg-white/[.015] px-2.5 py-2">
                          <div className="flex h-5 w-5 shrink-0 items-center justify-center rounded text-[9px] font-black"
                            style={{ background: `rgba(${hexRgb(techColor(step.technique_id))},0.14)`, color: techColor(step.technique_id) }}>
                            {i + 1}
                          </div>
                          <div className="min-w-0 flex-1">
                            <div className="flex items-center gap-1.5 flex-wrap">
                              <span className="text-[10px] font-bold text-zinc-200">{step.label}</span>
                              <span className="font-mono text-[8px] text-zinc-600">{step.mitre}</span>
                              {step.is_manual && (
                                <span className="rounded border border-yellow-500/30 bg-yellow-500/10 px-1.5 py-0.5 text-[8px] font-bold text-yellow-400">MANUAL</span>
                              )}
                              {step.loot_produces && (
                                <span className="rounded border px-1.5 py-0.5 text-[8px] font-bold"
                                  style={{ color: lootColor(step.loot_produces), borderColor: lootColor(step.loot_produces) + '33', background: lootColor(step.loot_produces) + '0d' }}>
                                  ⟶ {step.loot_produces.replace(/_/g, ' ')}
                                </span>
                              )}
                            </div>
                            <p className="mt-0.5 text-[9px] text-zinc-600">{step.src_label} → {step.tgt_label}</p>
                          </div>
                        </div>
                      ))}
                    </div>
                  </motion.div>
                )}
              </AnimatePresence>
            </motion.div>
          )
        })}
      </div>
    </div>
  )
}

function ConfigPanel({
  form, onChange, situation,
}: {
  form: ChainRequest
  onChange: (f: ChainRequest) => void
  situation: string
}) {
  const [showPass, setShowPass] = useState(false)
  const { data: assessments } = useQuery({
    queryKey: ['assessments', 'latest'],
    queryFn: () => assessmentApi.list({ limit: 5 }),
    staleTime: 60_000,
  })

  function autofill(a: { domain?: string; dc_ip?: string; collection_config?: { target?: { username?: string; password?: string } } }) {
    onChange({
      ...form,
      domain: a.domain ?? form.domain,
      dc_ip: a.dc_ip ?? form.dc_ip,
      target: a.dc_ip ?? form.target,
      username: a.collection_config?.target?.username ?? form.username,
      password: a.collection_config?.target?.password ?? form.password,
    })
  }

  const sitNeedsCred = !['ANON'].includes(situation)

  return (
    <div className="space-y-5">
      <div>
        <h2 className="text-base font-black tracking-tight" style={{ color: RED }}>TARGET & CREDENTIALS</h2>
        <p className="text-[10px] mt-0.5" style={{ color: 'rgba(200,190,240,0.4)', ...MONO }}>{'// configure the attack parameters'}</p>
      </div>

      {assessments && assessments.length > 0 && (
        <div className="rounded-lg border border-indigo-500/20 bg-indigo-500/5 p-3">
          <div className="mb-2 text-[9px] uppercase tracking-widest text-zinc-500">Autofill from Assessment</div>
          <div className="flex flex-wrap gap-1.5">
            {assessments.map(a => (
              <button key={a.id} onClick={() => autofill(a)}
                className="rounded-lg border border-indigo-400/20 bg-indigo-500/10 px-2.5 py-1.5 text-[10px] text-indigo-300 transition hover:bg-indigo-500/20">
                {a.domain || a.name}
              </button>
            ))}
          </div>
        </div>
      )}

      <div className="grid gap-3 sm:grid-cols-2">
        <InputField label="Target IP / DC IP" placeholder="192.168.1.10"
          value={form.target} onChange={v => onChange({ ...form, target: v, dc_ip: form.dc_ip || v })} />
        <InputField label="Domain" placeholder="corp.local"
          value={form.domain} onChange={v => onChange({ ...form, domain: v })} />
        <InputField label="DC IP (if different)" placeholder="192.168.1.10"
          value={form.dc_ip ?? ''} onChange={v => onChange({ ...form, dc_ip: v })} />
        {sitNeedsCred && (
          <InputField label="Username" placeholder="jsmith"
            value={form.username ?? ''} onChange={v => onChange({ ...form, username: v })} />
        )}
        {sitNeedsCred && (
          <div className="relative">
            <InputField label="Password" placeholder="P@ssw0rd (optional)"
              type={showPass ? 'text' : 'password'}
              value={form.password ?? ''} onChange={v => onChange({ ...form, password: v })} />
            <button onClick={() => setShowPass(p => !p)}
              className="absolute right-2 top-7 text-zinc-600 hover:text-zinc-400 transition">
              {showPass ? <EyeOff className="h-3.5 w-3.5" /> : <Eye className="h-3.5 w-3.5" />}
            </button>
          </div>
        )}
        {sitNeedsCred && (
          <InputField label="NTLM Hash (LM:NT or :NT)" placeholder="aad3b435:31d6cfe0..."
            value={form.hashes ?? ''} onChange={v => onChange({ ...form, hashes: v })} mono />
        )}
      </div>

      <div>
        <div className="mb-2 text-[9px] uppercase tracking-widest text-zinc-500">OPSEC Profile</div>
        <div className="grid grid-cols-3 gap-2">
          {([
            { id: 'GHOST',    color: '#22d3ee', desc: 'Silent · minimal artefacts · no noisy queries' },
            { id: 'BALANCED', color: '#818cf8', desc: 'Default · moderate speed · some logging' },
            { id: 'LOUD',     color: '#ef4444', desc: 'Fast · noisy · maximise success rate' },
          ] as const).map(p => (
            <button key={p.id} onClick={() => onChange({ ...form, opsec_profile: p.id })}
              className="rounded-xl border p-3 text-left transition-all"
              style={{
                background: form.opsec_profile === p.id ? `rgba(${hexRgb(p.color)},0.12)` : 'rgba(255,255,255,0.025)',
                borderColor: form.opsec_profile === p.id ? p.color + '55' : 'rgba(255,255,255,0.07)',
                boxShadow: form.opsec_profile === p.id ? `0 0 18px rgba(${hexRgb(p.color)},0.18)` : 'none',
              }}>
              <div className="text-xs font-black mb-1" style={{ color: form.opsec_profile === p.id ? p.color : '#e2e8f0' }}>{p.id}</div>
              <div className="text-[9px] leading-relaxed" style={{ color: 'rgba(200,190,240,0.4)' }}>{p.desc}</div>
            </button>
          ))}
        </div>
      </div>
    </div>
  )
}

function InputField({ label, value, onChange, placeholder, type = 'text', mono }: {
  label: string; value: string; onChange: (v: string) => void
  placeholder: string; type?: string; mono?: boolean
}) {
  return (
    <div>
      <label className="mb-1 block text-[9px] uppercase tracking-widest text-zinc-500">{label}</label>
      <input type={type} value={value} onChange={e => onChange(e.target.value)} placeholder={placeholder}
        className="h-9 w-full rounded-lg border border-white/[.07] bg-white/[.025] px-3 text-xs text-zinc-200 outline-none transition placeholder:text-zinc-700 focus:border-red-400/40"
        style={mono ? MONO : undefined} />
    </div>
  )
}

function PathPreviewPanel({ steps, pathNodes, pathName }: {
  steps: ChainStep[]; pathNodes: string[]; pathName: string
}) {
  return (
    <div className="space-y-4">
      <div>
        <h2 className="text-base font-black tracking-tight" style={{ color: RED }}>PATH PREVIEW</h2>
        <p className="text-[10px] mt-0.5" style={{ color: 'rgba(200,190,240,0.4)', ...MONO }}>
          {'// ' + steps.length + ' techniques · ' + pathName}
        </p>
      </div>

      {pathNodes.length > 0 && (
        <div className="rounded-xl border border-white/[.06] bg-white/[.02] p-4">
          <div className="mb-2 text-[9px] uppercase tracking-widest text-zinc-600">Attack Route</div>
          <div className="flex flex-wrap items-center gap-1.5">
            {pathNodes.map((node, i) => (
              <div key={i} className="flex items-center gap-1.5">
                <span className="rounded-lg border border-red-400/20 bg-red-400/10 px-2.5 py-1 text-[10px] font-bold text-red-300">
                  {node}
                </span>
                {i < pathNodes.length - 1 && <ArrowRight className="h-3 w-3 text-zinc-700" />}
              </div>
            ))}
          </div>
        </div>
      )}

      <div className="space-y-2">
        {steps.map((step, i) => {
          const color = techColor(step.technique_id)
          return (
            <div key={i} className="flex items-start gap-3 rounded-xl border border-white/[.06] bg-white/[.02] p-3">
              <div className="flex h-7 w-7 shrink-0 flex-col items-center justify-center rounded-lg text-[10px] font-black"
                style={{ background: `rgba(${hexRgb(color)},0.14)`, color }}>
                {i + 1}
              </div>
              <div className="min-w-0 flex-1">
                <div className="flex flex-wrap items-center gap-1.5">
                  <span className="text-xs font-bold text-zinc-100">{step.label}</span>
                  <span className="font-mono text-[9px] text-zinc-600">{step.mitre}</span>
                  {step.is_manual && (
                    <span className="rounded border border-yellow-500/30 bg-yellow-500/10 px-1.5 py-0.5 text-[8px] font-bold text-yellow-400">MANUAL STEP</span>
                  )}
                  <span className="rounded border px-1.5 py-0.5 text-[8px]"
                    style={{ color: color + 'cc', borderColor: color + '28', background: color + '0d' }}>
                    {step.edge_type.replace(/_/g, ' ')}
                  </span>
                </div>
                <p className="mt-1 text-[10px] text-zinc-500">{step.src_label} → {step.tgt_label}</p>
                <p className="mt-0.5 text-[10px] text-zinc-600">{step.description}</p>
              </div>
            </div>
          )
        })}
      </div>
    </div>
  )
}

function ExecutionPanel({
  steps, stepStates, expandedStep, onToggle, allDone, progress,
}: {
  steps: ChainStep[]; stepStates: StepState[]
  expandedStep: number | null; onToggle: (i: number) => void
  allDone: boolean; progress: number
}) {
  return (
    <div className="space-y-3">
      {/* Progress */}
      <div className="rounded-xl border border-white/[.06] bg-white/[.02] p-4">
        <div className="mb-2 flex items-center justify-between">
          <span className="text-[9px] uppercase tracking-widest text-zinc-500">Execution Progress</span>
          <span className="text-[10px] font-bold text-zinc-400">
            {stepStates.filter(s => s.status === 'done').length}/{steps.length} completed
          </span>
        </div>
        <div className="h-2 rounded-full overflow-hidden" style={{ background: 'rgba(244,63,94,0.1)' }}>
          <motion.div className="h-full rounded-full" animate={{ width: `${progress}%` }} transition={{ duration: 0.5 }}
            style={{ background: allDone ? GREEN : `linear-gradient(90deg,${RED},#9f1239)` }} />
        </div>
        {allDone && (
          <motion.div initial={{ opacity: 0, scale: 0.9 }} animate={{ opacity: 1, scale: 1 }}
            className="mt-3 flex items-center gap-3 rounded-lg border border-green-400/30 bg-green-400/10 p-3">
            <Crown className="h-5 w-5 text-yellow-400" />
            <div>
              <div className="text-sm font-black text-green-300">CHAIN COMPLETED</div>
              <div className="text-[9px] text-green-600 mt-0.5">All {steps.length} techniques executed successfully</div>
            </div>
          </motion.div>
        )}
      </div>

      {/* Steps */}
      <div className="space-y-2">
        {steps.map((step, idx) => {
          const state = stepStates[idx] ?? { status: 'pending', jobId: null, lines: [], exitCode: null }
          const color = techColor(step.technique_id)
          const isRunning = state.status === 'running'
          const isDoneStep = state.status === 'done'
          const isFailed = state.status === 'failed'
          const isExpanded = expandedStep === idx

          return (
            <motion.div key={idx} initial={{ opacity: 0, x: 20 }} animate={{ opacity: 1, x: 0 }}
              transition={{ delay: idx * 0.04 }}
              className="overflow-hidden rounded-xl border transition-all"
              style={{
                background: isRunning ? `rgba(${hexRgb(color)},0.07)` : 'rgba(255,255,255,0.02)',
                borderColor: isRunning ? color + '55' : isDoneStep ? '#22c55e33' : isFailed ? '#ef444433' : 'rgba(255,255,255,0.06)',
                boxShadow: isRunning ? `0 0 20px rgba(${hexRgb(color)},0.12)` : 'none',
              }}>
              <button onClick={() => onToggle(idx)} className="flex w-full items-center gap-3 px-4 py-3 text-left">
                <div className="relative shrink-0">
                  <div className="flex h-8 w-8 items-center justify-center rounded-lg text-sm"
                    style={{ background: `rgba(${hexRgb(color)},0.14)`, color }}>
                    {idx + 1}
                  </div>
                  {isRunning && <div className="absolute -inset-0.5 animate-ping rounded-lg" style={{ background: `rgba(${hexRgb(color)},0.15)`, animationDuration: '1.5s' }} />}
                </div>
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-1.5">
                    <span className="text-xs font-black" style={{ color }}>{step.label}</span>
                    <span className="font-mono text-[8px] text-zinc-700">{step.mitre}</span>
                  </div>
                  <div className="text-[10px] text-zinc-600">{step.src_label} → {step.tgt_label}</div>
                </div>
                <div className="flex shrink-0 items-center gap-2">
                  {isRunning && <Loader2 className="h-3.5 w-3.5 animate-spin" style={{ color }} />}
                  {isDoneStep && <CheckCircle2 className="h-3.5 w-3.5 text-green-400" />}
                  {isFailed && <XCircle className="h-3.5 w-3.5 text-red-400" />}
                  {state.status === 'pending' && <Circle className="h-3.5 w-3.5 text-zinc-700" />}
                  <ChevronRight className="h-3 w-3 text-zinc-700 transition-transform" style={{ transform: isExpanded ? 'rotate(90deg)' : 'none' }} />
                </div>
              </button>

              <AnimatePresence>
                {isExpanded && (
                  <motion.div initial={{ height: 0, opacity: 0 }} animate={{ height: 'auto', opacity: 1 }}
                    exit={{ height: 0, opacity: 0 }} transition={{ duration: 0.18 }}>
                    <div className="border-t border-white/[.05] px-4 pb-3 pt-2">
                      <p className="mb-2 text-[10px] text-zinc-500">{step.description}</p>
                      {state.jobId ? (
                        <div className="overflow-hidden rounded-lg" style={{ height: 180, border: '1px solid rgba(255,255,255,0.06)' }}>
                          <LiveOutputTerminal jobId={state.jobId} />
                        </div>
                      ) : state.lines.length > 0 ? (
                        <div className="max-h-36 overflow-y-auto rounded-lg p-2 text-[9px] space-y-0.5"
                          style={{ background: '#000', border: '1px solid rgba(255,255,255,0.05)', ...MONO }}>
                          {state.lines.map((line, li) => (
                            <div key={li} style={{ color: line.startsWith('[+]') ? '#4ade80' : line.startsWith('[!]') ? '#f87171' : 'rgba(200,190,240,0.7)' }}>
                              {line}
                            </div>
                          ))}
                        </div>
                      ) : (
                        <div className="py-4 text-center text-[9px] text-zinc-700">
                          {state.status === 'pending' ? '— awaiting execution —' : '— no output captured —'}
                        </div>
                      )}
                      {state.exitCode !== null && (
                        <div className="mt-2 text-[9px] font-bold" style={{ color: state.exitCode === 0 ? GREEN : RED }}>
                          EXIT CODE: {state.exitCode}
                        </div>
                      )}
                    </div>
                  </motion.div>
                )}
              </AnimatePresence>
            </motion.div>
          )
        })}
      </div>
    </div>
  )
}

function LootPanel({ loot }: { loot: Record<string, unknown> }) {
  const entries = Object.entries(loot)
  if (entries.length === 0) {
    return (
      <div className="flex h-32 items-center justify-center rounded-xl border border-white/[.06] bg-white/[.015]">
        <div className="text-center">
          <Database className="mx-auto mb-2 h-6 w-6 text-zinc-700" />
          <p className="text-[10px] text-zinc-700">No loot captured yet</p>
        </div>
      </div>
    )
  }
  return (
    <div className="space-y-2">
      {entries.map(([type, values]) => {
        const items = Array.isArray(values) ? values : [values]
        const color = lootColor(type)
        return (
          <div key={type} className="rounded-xl border p-3"
            style={{ borderColor: color + '33', background: color + '08' }}>
            <div className="mb-2 flex items-center gap-2">
              <Crown className="h-3 w-3" style={{ color }} />
              <span className="text-[9px] font-black uppercase tracking-widest" style={{ color }}>
                {type.replace(/_/g, ' ')}
              </span>
              <span className="ml-auto text-[9px] text-zinc-600">{items.length} captured</span>
            </div>
            <div className="space-y-1">
              {(items as string[]).map((val, i) => (
                <div key={i} className="flex items-center gap-2 rounded-lg border border-white/[.04] bg-black px-2.5 py-1.5">
                  <span className="flex-1 truncate font-mono text-[10px]" style={{ color }}>{String(val)}</span>
                  <CopyBtn text={String(val)} />
                </div>
              ))}
            </div>
          </div>
        )
      })}
    </div>
  )
}

function ChainHistoryPanel({ onLoad }: { onLoad: (chain: Chain) => void }) {
  const { data: chains, isLoading } = useQuery({
    queryKey: ['chains', 'history'],
    queryFn: () => listChains(10),
    staleTime: 30_000,
    refetchInterval: 15_000,
  })

  const statusColor: Record<string, string> = {
    COMPLETED: '#22c55e', RUNNING: '#f97316', FAILED: '#ef4444',
    STOPPED: '#94a3b8', PENDING: '#818cf8',
  }

  return (
    <div className="space-y-2">
      <div className="mb-3 text-[9px] uppercase tracking-widest text-zinc-600">Chain History</div>
      {isLoading && <div className="flex items-center gap-2 py-3 text-xs text-zinc-600"><Loader2 className="h-3.5 w-3.5 animate-spin" />Loading...</div>}
      {(chains ?? []).map(c => (
        <button key={c.id} onClick={() => onLoad(c)}
          className="w-full rounded-xl border border-white/[.06] bg-white/[.02] p-3 text-left transition hover:border-white/10 hover:bg-white/[.03]">
          <div className="flex items-center justify-between gap-2">
            <span className="truncate text-[10px] font-bold text-zinc-200">{c.name}</span>
            <span className="shrink-0 text-[9px] font-bold" style={{ color: statusColor[c.status] ?? '#94a3b8' }}>{c.status}</span>
          </div>
          <div className="mt-1 flex items-center gap-2 text-[9px] text-zinc-600">
            <span>{c.domain ?? '—'}</span>
            <span>·</span>
            <span>{c.target ?? '—'}</span>
            <span>·</span>
            <span>{c.steps.length} steps</span>
          </div>
          {Object.keys(c.loot).length > 0 && (
            <div className="mt-1.5 flex flex-wrap gap-1">
              {Object.keys(c.loot).map(k => (
                <span key={k} className="rounded border px-1.5 py-0.5 text-[8px]"
                  style={{ color: lootColor(k), borderColor: lootColor(k) + '33', background: lootColor(k) + '0d' }}>
                  {k.replace(/_/g, ' ')}
                </span>
              ))}
            </div>
          )}
        </button>
      ))}
      {!isLoading && (!chains || chains.length === 0) && (
        <div className="py-4 text-center text-[10px] text-zinc-700">No chains executed yet</div>
      )}
    </div>
  )
}

const PHASES: { id: Phase; label: string }[] = [
  { id: 'situation', label: '01 Situation' },
  { id: 'library',   label: '02 Path' },
  { id: 'config',    label: '03 Config' },
  { id: 'preview',   label: '04 Preview' },
  { id: 'running',   label: '05 Execute' },
]

const DEFAULT_FORM: ChainRequest = {
  target: '', domain: '', username: '', password: '',
  hashes: '', dc_ip: '', opsec_profile: 'BALANCED',
  situation: 'DOMAIN_USER', path_id: null,
}

export function ChainBuilder() {
  const qc = useQueryClient()
  const [phase, setPhase] = useState<Phase>('situation')
  const [form, setForm] = useState<ChainRequest>(DEFAULT_FORM)
  const [selectedSituation, setSelectedSituation] = useState('DOMAIN_USER')
  const [selectedPathId, setSelectedPathId] = useState<string | null>(null)
  const [previewSteps, setPreviewSteps] = useState<ChainStep[]>([])
  const [previewNodes, setPreviewNodes] = useState<string[]>([])
  const [previewPathName, setPreviewPathName] = useState('')
  const [chain, setChain] = useState<Chain | null>(null)
  const [stepStates, setStepStates] = useState<StepState[]>([])
  const [expandedStep, setExpandedStep] = useState<number | null>(null)
  const [loading, setLoading] = useState(false)
  const [err, setErr] = useState<string | null>(null)
  const [mounted, setMounted] = useState(false)
  const [loot, setLoot] = useState<Record<string, string[]>>({})
  const [preflight, setPreflight] = useState<ChainPreflightResult | null>(null)
  const wsRef = useRef<WebSocket | null>(null)
  const wsConnectedRef = useRef(false)

  useEffect(() => { setMounted(true) }, [])

  // Keep handlerRef current so WS callbacks always call the latest handleEvent
  // (prevents stale closure when React re-renders between mount and execute)
  const handlerRef = useRef<(evt: ChainEvent) => void>(() => { /* placeholder */ })

  const { data: situationsData, isLoading: sitLoading } = useQuery({
    queryKey: ['chain-situations'],
    queryFn: getSituations,
    staleTime: Infinity,
  })

  const { data: libraryData, isLoading: libLoading } = useQuery({
    queryKey: ['chain-library', selectedSituation],
    queryFn: () => getLibrary(selectedSituation),
    enabled: phase === 'library' || phase !== 'situation',
    staleTime: 300_000,
  })

  const situations = situationsData?.situations ?? []
  const libraryPaths = libraryData?.paths ?? []

  const handleEvent = useCallback((evt: ChainEvent) => {
    if (evt.event === 'step_started') {
      setStepStates(prev => {
        const next = [...prev]
        if (next[evt.step!]) next[evt.step!] = { ...next[evt.step!], status: 'running', jobId: evt.job_id ?? null }
        return next
      })
      setExpandedStep(evt.step ?? null)
    } else if (evt.event === 'step_output') {
      setStepStates(prev => {
        const next = [...prev]
        if (next[evt.step!]) next[evt.step!] = { ...next[evt.step!], lines: [...next[evt.step!].lines, evt.line ?? ''] }
        return next
      })
    } else if (evt.event === 'step_completed') {
      setStepStates(prev => {
        const next = [...prev]
        if (next[evt.step!]) next[evt.step!] = { ...next[evt.step!], status: 'done', exitCode: evt.exit_code ?? 0 }
        return next
      })
    } else if (evt.event === 'step_waiting') {
      setStepStates(prev => {
        const next = [...prev]
        if (evt.step !== undefined && next[evt.step]) {
          next[evt.step] = { ...next[evt.step], status: 'done', exitCode: 2 }
        }
        return next
      })
    } else if (evt.event === 'loot_captured') {
      qc.invalidateQueries({ queryKey: ['chains', 'history'] })
      if (evt.loot_type && evt.value) {
        setLoot(prev => ({
          ...prev,
          [evt.loot_type!]: [...(prev[evt.loot_type!] ?? []), evt.value!],
        }))
      }
    } else if (evt.event === 'chain_completed') {
      setPhase('done')
      qc.invalidateQueries({ queryKey: ['chains', 'history'] })
    } else if (evt.event === 'chain_failed') {
      setPhase('done')
      setStepStates(prev => {
        const next = [...prev]
        if (evt.step !== undefined && next[evt.step]) {
          next[evt.step] = { ...next[evt.step], status: 'failed', exitCode: evt.exit_code ?? 1 }
        }
        return next
      })
    }
  }, [qc])

  useEffect(() => { handlerRef.current = handleEvent }, [handleEvent])

  useEffect(() => {
    if (phase !== 'running' || !chain?.id) return
    let cancelled = false
    const sync = async () => {
      // Skip if WS is connected and live — avoid overwriting real-time state with stale DB reads
      if (wsConnectedRef.current) return
      try {
        const fresh = await getChain(chain.id)
        if (cancelled) return
        setChain(fresh)
        setStepStates(prev => fresh.steps.map((_, i) => {
          const existing = prev[i] ?? { status: 'pending' as StepStatus, jobId: null, lines: [], exitCode: null }
          let status: StepStatus = 'pending'
          if (fresh.status === 'FAILED' && i === fresh.current_step - 1) status = 'failed'
          else if (fresh.status === 'COMPLETED' || i < fresh.current_step - 1) status = 'done'
          else if (fresh.status === 'RUNNING' && i === fresh.current_step - 1) status = existing.status === 'done' ? 'done' : 'running'
          return { ...existing, jobId: fresh.job_ids[i] ?? existing.jobId, status }
        }))
        if (fresh.status === 'COMPLETED' || fresh.status === 'FAILED' || fresh.status === 'STOPPED') {
          setPhase('done')
          qc.invalidateQueries({ queryKey: ['chains', 'history'] })
        }
      } catch {
        /* poll is fallback — ignore errors */
      }
    }
    void sync()
    const timer = window.setInterval(sync, 4000)
    return () => {
      cancelled = true
      window.clearInterval(timer)
    }
  }, [phase, chain?.id, qc])

  async function handlePreview() {
    if (!form.target || !form.domain) { setErr('Target IP and domain required'); return }
    if (selectedSituation !== 'ANON' && !form.username && !form.hashes) {
      setErr('Username/password or NTLM hash required for this starting position')
      return
    }
    setErr(null); setLoading(true)
    try {
      const payload: ChainRequest = { ...form, situation: selectedSituation, path_id: selectedPathId }
      const checks = await preflightChain(payload)
      setPreflight(checks)
      if (!checks.ok) {
        setErr(`Preflight failed: ${checks.errors.join('; ')}`)
        return
      }
      const res = await resolveChain(payload)
      setPreviewSteps(res.steps)
      setPreviewNodes(res.path_nodes)
      const lib = libraryPaths.find(p => p.id === selectedPathId)
      setPreviewPathName(lib?.name ?? `Path to DA — ${form.domain}`)
      setStepStates(res.steps.map(() => ({ status: 'pending', jobId: null, lines: [], exitCode: null })))
      setPhase('preview')
    } catch (e: unknown) {
      setErr(e instanceof Error ? e.message : String(e))
    } finally {
      setLoading(false)
    }
  }

  async function handleExecute() {
    setErr(null); setLoading(true)
    try {
      const payload: ChainRequest = { ...form, situation: selectedSituation, path_id: selectedPathId }
      const c = await createChain(payload)
      const started = await startChain(c.id)
      setChain(started)
      setStepStates(started.steps.map(() => ({ status: 'pending', jobId: null, lines: [], exitCode: null })))
      setPhase('running')
      wsRef.current?.close()
      const ws = connectChainWs(started.id, (evt) => handlerRef.current(evt))
      ws.onopen = () => { wsConnectedRef.current = true }
      ws.onclose = () => { wsConnectedRef.current = false }
      ws.onerror = () => { wsConnectedRef.current = false }
      wsRef.current = ws
      qc.invalidateQueries({ queryKey: ['chains', 'history'] })
    } catch (e: unknown) {
      setErr(e instanceof Error ? e.message : String(e))
    } finally {
      setLoading(false)
    }
  }

  async function handleStop() {
    const c = chain
    if (!c) return
    try {
      await stopChain(c.id)
    } catch (e) {
      console.error('stopChain failed', e)
    }
    wsRef.current?.close()
    setPhase('done')
    qc.invalidateQueries({ queryKey: ['chains', 'history'] })
  }

  function handleReset() {
    wsRef.current?.close()
    setChain(null); setPreviewSteps([]); setPreviewNodes([])
    setStepStates([]); setPhase('situation'); setErr(null); setExpandedStep(null)
    setSelectedPathId(null); setPreflight(null)
  }

  function loadHistoryChain(c: Chain) {
    setChain(c)
    setPreviewSteps(c.steps)
    setPreviewNodes(c.path_nodes)
    setPreviewPathName(c.name)
    setStepStates(c.steps.map((_, i) => ({
      status: c.current_step > i ? 'done' : i === c.current_step && c.status === 'RUNNING' ? 'running' : 'pending',
      jobId: c.job_ids[i] ?? null,
      lines: [],
      exitCode: null,
    })))
    setPhase(c.status === 'COMPLETED' || c.status === 'FAILED' || c.status === 'STOPPED' ? 'done' : 'running')
    if (c.status === 'RUNNING') {
      wsRef.current?.close()
      const ws = connectChainWs(c.id, (evt) => handlerRef.current(evt))
      ws.onopen = () => { wsConnectedRef.current = true }
      ws.onclose = () => { wsConnectedRef.current = false }
      ws.onerror = () => { wsConnectedRef.current = false }
      wsRef.current = ws
    }
  }

  const runningSteps = chain?.steps ?? previewSteps
  const completedSteps = stepStates.filter(s => s.status === 'done').length
  const progress = runningSteps.length > 0 ? (completedSteps / runningSteps.length) * 100 : 0
  const isDone = phase === 'done'
  const allDone = isDone && stepStates.length > 0 && stepStates.every(s => s.status === 'done')
  const activeLoot = loot

  const phaseIdx = PHASES.findIndex(p => p.id === phase)

  // Cleanup WS on unmount (prevents dangling connection if user navigates away)
  useEffect(() => {
    return () => { wsRef.current?.close() }
  }, [])

  if (!mounted) return null

  return (
    <div className="min-h-screen p-6">
      {/* Header */}
      <motion.div initial={{ opacity: 0, y: -16 }} animate={{ opacity: 1, y: 0 }} className="mb-6">
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div className="flex items-center gap-4">
            <div className="relative flex h-12 w-12 items-center justify-center rounded-2xl"
              style={{ background: 'rgba(244,63,94,0.12)', border: '1px solid rgba(244,63,94,0.4)' }}>
              <Crown className="h-6 w-6 text-red-400" />
              {phase === 'running' && <div className="absolute inset-0 animate-ping rounded-2xl" style={{ background: 'rgba(244,63,94,0.08)', animationDuration: '2s' }} />}
            </div>
            <div>
              <h1 className="text-xl font-black tracking-tight" style={{ color: RED, ...MONO }}>PATH TO DOMAIN ADMIN</h1>
              <p className="text-[10px]" style={{ color: 'rgba(244,63,94,0.45)', ...MONO }}>
                {'// ' + ((chain?.domain ?? form.domain) || 'configure target') + ' · ' + (chain?.steps.length ?? previewSteps.length) + ' steps · ' + (form.opsec_profile ?? 'BALANCED') + ' opsec'}
              </p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            {phase === 'running' && (
              <button onClick={handleStop}
                className="flex items-center gap-2 rounded-xl border border-red-400/40 bg-red-400/10 px-4 py-2 text-xs font-black text-red-300 transition hover:bg-red-400/20">
                <Square className="h-3.5 w-3.5" /> ABORT
              </button>
            )}
            {phase !== 'situation' && (
              <button onClick={handleReset}
                className="flex items-center gap-2 rounded-xl border border-white/10 bg-white/[.03] px-4 py-2 text-xs text-zinc-500 transition hover:text-zinc-300">
                <RefreshCw className="h-3.5 w-3.5" /> Reset
              </button>
            )}
          </div>
        </div>

        {/* Phase stepper */}
        <div className="mt-5 flex items-center gap-1 overflow-x-auto pb-1">
          {PHASES.map((p, i) => {
            const isPast = i < phaseIdx
            const isCurrent = i === phaseIdx
            return (
              <div key={p.id} className="flex items-center gap-1">
                <div className="flex items-center gap-1.5 rounded-lg border px-2.5 py-1.5 text-[9px] font-bold uppercase tracking-widest transition-all"
                  style={{
                    borderColor: isCurrent ? RED + '66' : isPast ? '#22c55e44' : 'rgba(255,255,255,0.07)',
                    background: isCurrent ? 'rgba(244,63,94,0.1)' : isPast ? 'rgba(34,197,94,0.06)' : 'transparent',
                    color: isCurrent ? RED : isPast ? '#22c55e' : '#71717a',
                  }}>
                  {isPast && <CheckCircle2 className="h-2.5 w-2.5" />}
                  {isCurrent && <Activity className="h-2.5 w-2.5" />}
                  {p.label}
                </div>
                {i < PHASES.length - 1 && <ChevronRight className="h-3 w-3 shrink-0 text-zinc-800" />}
              </div>
            )
          })}
        </div>
      </motion.div>

      {err && (
        <motion.div initial={{ opacity: 0, height: 0 }} animate={{ opacity: 1, height: 'auto' }}
          className="mb-4 flex items-center gap-2 rounded-xl border border-red-400/30 bg-red-400/10 px-4 py-3 text-sm text-red-300">
          <AlertTriangle className="h-4 w-4 shrink-0" /> {err}
        </motion.div>
      )}

      <div className="grid gap-5 xl:grid-cols-[1fr_280px]">
        {/* Main content */}
        <div>
          <AnimatePresence mode="wait">
            {/* PHASE: situation */}
            {phase === 'situation' && (
              <motion.div key="situation" initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -8 }}>
                {sitLoading
                  ? <div className="flex items-center gap-2 py-12 text-sm text-zinc-600"><Loader2 className="h-4 w-4 animate-spin" />Loading situations…</div>
                  : <SituationSelector situations={situations} selected={selectedSituation} onSelect={s => { setSelectedSituation(s); setForm(f => ({ ...f, situation: s })) }} />
                }
                <div className="mt-6 flex justify-end">
                  <button onClick={() => setPhase('library')}
                    className="flex items-center gap-2 rounded-xl px-6 py-3 text-sm font-black transition-all"
                    style={{ background: `linear-gradient(135deg,${RED},#9f1239)`, color: '#fff', boxShadow: `0 0 24px rgba(244,63,94,0.3)` }}>
                    Next — Choose Path <ChevronRight className="h-4 w-4" />
                  </button>
                </div>
              </motion.div>
            )}

            {/* PHASE: library */}
            {phase === 'library' && (
              <motion.div key="library" initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -8 }}>
                {libLoading
                  ? <div className="flex items-center gap-2 py-12 text-sm text-zinc-600"><Loader2 className="h-4 w-4 animate-spin" />Loading paths…</div>
                  : <PathLibraryPanel paths={libraryPaths} selectedId={selectedPathId} onSelect={setSelectedPathId} />
                }
                <div className="mt-6 flex items-center justify-between">
                  <button onClick={() => setPhase('situation')}
                    className="flex items-center gap-2 rounded-xl border border-white/10 bg-white/[.03] px-4 py-2.5 text-xs text-zinc-400 transition hover:text-zinc-200">
                    <ChevronLeft className="h-3.5 w-3.5" /> Back
                  </button>
                  <button onClick={() => setPhase('config')}
                    className="flex items-center gap-2 rounded-xl px-6 py-3 text-sm font-black transition-all"
                    style={{ background: `linear-gradient(135deg,${RED},#9f1239)`, color: '#fff', boxShadow: `0 0 24px rgba(244,63,94,0.3)` }}>
                    {selectedPathId ? 'Use Selected Path' : 'Best Path Auto-Select'} <ChevronRight className="h-4 w-4" />
                  </button>
                </div>
              </motion.div>
            )}

            {/* PHASE: config */}
            {phase === 'config' && (
              <motion.div key="config" initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -8 }}>
                <ConfigPanel form={form} onChange={setForm} situation={selectedSituation} />
                <div className="mt-6 flex items-center justify-between">
                  <button onClick={() => setPhase('library')}
                    className="flex items-center gap-2 rounded-xl border border-white/10 bg-white/[.03] px-4 py-2.5 text-xs text-zinc-400 transition hover:text-zinc-200">
                    <ChevronLeft className="h-3.5 w-3.5" /> Back
                  </button>
                  <button onClick={handlePreview} disabled={loading}
                    className="flex items-center gap-2 rounded-xl px-6 py-3 text-sm font-black transition-all disabled:opacity-50"
                    style={{ background: `linear-gradient(135deg,${RED},#9f1239)`, color: '#fff', boxShadow: `0 0 24px rgba(244,63,94,0.3)` }}>
                    {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : <Eye className="h-4 w-4" />}
                    {loading ? 'Resolving…' : 'Preview Path'} <ChevronRight className="h-4 w-4" />
                  </button>
                </div>
              </motion.div>
            )}

            {/* PHASE: preview */}
            {phase === 'preview' && (
              <motion.div key="preview" initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -8 }}>
                <PathPreviewPanel steps={previewSteps} pathNodes={previewNodes} pathName={previewPathName} />
                <div className="mt-6 flex items-center justify-between">
                  <button onClick={() => setPhase('config')}
                    className="flex items-center gap-2 rounded-xl border border-white/10 bg-white/[.03] px-4 py-2.5 text-xs text-zinc-400 transition hover:text-zinc-200">
                    <ChevronLeft className="h-3.5 w-3.5" /> Back
                  </button>
                  <button onClick={handleExecute} disabled={loading}
                    className="flex items-center gap-2 rounded-xl px-8 py-3.5 text-sm font-black transition-all disabled:opacity-50"
                    style={{ background: `linear-gradient(135deg,${RED},#7f1d1d)`, color: '#fff', boxShadow: `0 0 32px rgba(244,63,94,0.4), 0 0 64px rgba(244,63,94,0.15)` }}>
                    {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : <Zap className="h-4 w-4" />}
                    {loading ? 'LAUNCHING…' : 'EXECUTE CHAIN'}
                  </button>
                </div>
              </motion.div>
            )}

            {/* PHASE: running / done */}
            {(phase === 'running' || phase === 'done') && (
              <motion.div key="running" initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -8 }}>
                <ExecutionPanel
                  steps={runningSteps} stepStates={stepStates}
                  expandedStep={expandedStep} onToggle={i => setExpandedStep(expandedStep === i ? null : i)}
                  allDone={allDone} progress={progress}
                />
                {Object.keys(activeLoot).length > 0 && (
                  <div className="mt-5">
                    <div className="mb-3 flex items-center gap-2">
                      <Crown className="h-4 w-4 text-yellow-400" />
                      <span className="text-[10px] uppercase tracking-widest text-zinc-500">Live Loot</span>
                    </div>
                    <LootPanel loot={activeLoot} />
                  </div>
                )}
              </motion.div>
            )}
          </AnimatePresence>
        </div>

        {/* Right sidebar */}
        <div className="space-y-4">
          {/* Current status card */}
          <div className="rounded-xl border border-white/[.07] bg-white/[.02] p-4">
            <div className="mb-3 text-[9px] uppercase tracking-widest text-zinc-600">Session</div>
            <div className="space-y-2 text-[10px]">
              <Row label="Situation" value={situations.find(s => s.id === selectedSituation)?.label ?? selectedSituation} />
              <Row label="Target" value={form.target || '—'} />
              <Row label="Domain" value={form.domain || '—'} />
              <Row label="OPSEC" value={form.opsec_profile ?? 'BALANCED'} />
              {selectedPathId && <Row label="Path" value={libraryPaths.find(p => p.id === selectedPathId)?.name ?? selectedPathId} />}
              {chain && <Row label="Chain ID" value={chain.id.slice(0, 8) + '…'} mono />}
            </div>
          </div>

          {preflight && (
            <div className="rounded-xl border p-4"
              style={{
                borderColor: preflight.ok ? 'rgba(34,197,94,0.25)' : 'rgba(239,68,68,0.28)',
                background: preflight.ok ? 'rgba(34,197,94,0.05)' : 'rgba(239,68,68,0.06)',
              }}>
              <div className="mb-3 flex items-center justify-between gap-2">
                <span className="text-[9px] uppercase tracking-widest text-zinc-500">Preflight</span>
                <span className="text-[9px] font-black" style={{ color: preflight.ok ? GREEN : RED }}>
                  {preflight.ok ? 'READY' : 'BLOCKED'}
                </span>
              </div>
              <div className="space-y-1.5 text-[10px]">
                {Object.entries(preflight.ports).map(([port, ok]) => (
                  <Row key={port} label={`TCP ${port}`} value={ok ? 'open' : 'unreachable'} />
                ))}
                <Row label="LDAP bind" value={preflight.ldap_bind?.ok ? 'ok' : 'not verified'} />
              </div>
              {preflight.errors.length > 0 && (
                <div className="mt-3 space-y-1">
                  {preflight.errors.slice(0, 3).map(error => (
                    <p key={error} className="text-[9px] leading-relaxed text-red-300/80">{error}</p>
                  ))}
                </div>
              )}
            </div>
          )}

          {/* Loot summary */}
          {Object.keys(activeLoot).length > 0 && (phase === 'running' || phase === 'done') && (
            <div className="rounded-xl border border-yellow-400/20 bg-yellow-400/5 p-4">
              <div className="mb-3 flex items-center gap-2">
                <Crown className="h-4 w-4 text-yellow-400" />
                <span className="text-[9px] uppercase tracking-widest text-zinc-500">Captured Loot</span>
              </div>
              <LootPanel loot={activeLoot} />
            </div>
          )}

          {/* Chain history */}
          <div className="rounded-xl border border-white/[.07] bg-white/[.02] p-4">
            <ChainHistoryPanel onLoad={loadHistoryChain} />
          </div>
        </div>
      </div>
    </div>
  )
}

function Row({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="flex items-center justify-between gap-2">
      <span className="text-zinc-600">{label}</span>
      <span className="truncate text-right text-zinc-300 max-w-[140px]" style={mono ? MONO : undefined}>{value}</span>
    </div>
  )
}
