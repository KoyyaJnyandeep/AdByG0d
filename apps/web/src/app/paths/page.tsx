'use client'

import { copyText } from '@/lib/clipboard'
import { useEffect, useMemo, useRef, useState } from 'react'
import type { ComponentType, CSSProperties } from 'react'
import { AnimatePresence, motion } from 'framer-motion'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Activity, AlertTriangle, ArrowDownWideNarrow, ArrowRight, Bookmark,
  BookmarkCheck, ChevronRight, Crosshair, Database, Download, Eye,
  Filter, GitBranch, KeyRound, Layers3, Loader2, Network,
  RefreshCw, Route, Search, ShieldAlert, ShieldCheck, Sparkles,
  Swords, Target, Zap, X, Copy, Check, TrendingDown,
  ChevronDown, ChevronUp,
} from 'lucide-react'

import { AttackMiniGraph } from '@/components/attack-paths/AttackMiniGraph'
import { PathStepTimeline } from '@/components/attack-paths/PathStepTimeline'
import { AppShell } from '@/components/layout/AppShell'
import { TiltCard } from '@/components/ui/TiltCard'
import { CornerFrame } from '@/components/ui/CornerFrame'
import { graphApi } from '@/lib/api'
import { cn, fmtNumber } from '@/lib/utils'
import { downloadTextFile } from '@/lib/clientDownload'
import { useRouteAssessmentScope } from '@/lib/useRouteAssessmentScope'
import type {
  AttackCategory, AttackPathEntry, ChokePoint, ExposurePath,
  GraphSimulationResult, PathStep, SimulationEdge, SimulationAlternativePath,
} from '@/lib/types'

type RiskLevel = AttackPathEntry['risk_level']
type SortMode = 'risk' | 'hops' | 'source' | 'target'

const CATEGORY_ORDER = [
  'direct_control','acl_abuse','shadow_admin','dcsync','delegation','adcs','kerberoast','asrep',
  'rbcd','relay','trust_escalation','sccm','shadow_credentials','cve','credential_access','mssql',
]

const CATEGORY_FALLBACK: Record<string, { name: string; color: string; icon: ComponentType<{ className?: string }> }> = {
  direct_control: { name: 'Direct Control', color: '#fb7185', icon: Crosshair },
  acl_abuse:      { name: 'ACL Abuse',      color: '#ef4444', icon: ShieldAlert },
  shadow_admin:   { name: 'Shadow Admin',   color: '#a855f7', icon: Eye },
  dcsync:         { name: 'DCSync',         color: '#ef4444', icon: Database },
  delegation:     { name: 'Delegation',     color: '#06b6d4', icon: Network },
  adcs:           { name: 'AD CS',          color: '#10b981', icon: ShieldCheck },
  kerberoast:     { name: 'Kerberoast',     color: '#f97316', icon: KeyRound },
  asrep:          { name: 'AS-REP',         color: '#eab308', icon: Zap },
  rbcd:           { name: 'RBCD Chains',    color: '#22d3ee', icon: Network },
  relay:          { name: 'Relay Chains',   color: '#38bdf8', icon: Network },
  trust_escalation:{ name: 'Trust Escalation', color: '#a855f7', icon: GitBranch },
  sccm:           { name: 'SCCM Chains',    color: '#f59e0b', icon: Layers3 },
  shadow_credentials:{ name: 'Shadow Creds', color: '#c084fc', icon: Eye },
  cve:            { name: 'CVE Chains',     color: '#fb7185', icon: AlertTriangle },
  credential_access:{ name: 'Cred Access',  color: '#f472b6', icon: Database },
  mssql:          { name: 'MSSQL Chains',   color: '#eab308', icon: Database },
}

const KILL_CHAIN = ['Recon', 'Discovery', 'Lateral Move', 'Priv Esc', 'Impact'] as const

const EDGE_MITRE: Record<string, { id: string; name: string; phase: typeof KILL_CHAIN[number] }> = {
  HAS_SPN:               { id: 'T1558.003', name: 'Kerberoasting',    phase: 'Priv Esc' },
  AS_REP:                { id: 'T1558.004', name: 'AS-REP Roast',     phase: 'Priv Esc' },
  FORCE_CHANGE_PASSWORD: { id: 'T1098',     name: 'Acct Manipulation',phase: 'Priv Esc' },
  DCSYNC:                { id: 'T1003.006', name: 'DCSync',            phase: 'Impact' },
  ALLOWED_TO_DELEGATE:   { id: 'T1558.001', name: 'Delegation Abuse', phase: 'Lateral Move' },
  ALLOWED_TO_ACT:        { id: 'T1558.001', name: 'RBCD Abuse',       phase: 'Lateral Move' },
  GENERIC_ALL:           { id: 'T1222',     name: 'ACL Modification', phase: 'Priv Esc' },
  WRITE_DACL:            { id: 'T1222',     name: 'DACL Modification',phase: 'Priv Esc' },
  WRITE_OWNER:           { id: 'T1222',     name: 'Owner Takeover',   phase: 'Priv Esc' },
  OWNS:                  { id: 'T1222',     name: 'Object Ownership', phase: 'Priv Esc' },
  ADD_MEMBER:            { id: 'T1098.002', name: 'Group Manipulation',phase: 'Priv Esc' },
  MEMBER_OF:             { id: 'T1078',     name: 'Valid Accounts',   phase: 'Discovery' },
  LOCAL_ADMIN:           { id: 'T1078.003', name: 'Local Accounts',   phase: 'Lateral Move' },
  ADMIN_TO:              { id: 'T1078',     name: 'Admin Access',     phase: 'Lateral Move' },
  CAN_ENROLL:            { id: 'T1649',     name: 'Forge Certificate',phase: 'Priv Esc' },
  APPLIES_GPO:           { id: 'T1484.001', name: 'GPO Modification', phase: 'Priv Esc' },
  ASREP_ROAST:           { id: 'T1558.004', name: 'AS-REP Roast', phase: 'Priv Esc' },
  KERBEROAST:            { id: 'T1558.003', name: 'Kerberoasting', phase: 'Priv Esc' },
  PASS_THE_HASH:         { id: 'T1550.002', name: 'Pass the Hash', phase: 'Lateral Move' },
  PASS_THE_TICKET:       { id: 'T1550.003', name: 'Pass the Ticket', phase: 'Lateral Move' },
  PASS_THE_CERT:         { id: 'T1649',     name: 'Certificate Auth', phase: 'Priv Esc' },
  NTLM_RELAY:            { id: 'T1557.001', name: 'Relay', phase: 'Lateral Move' },
  COERCION:              { id: 'T1187',     name: 'Forced Auth', phase: 'Discovery' },
  POISONING:             { id: 'T1557.001', name: 'Adversary-in-the-Middle', phase: 'Discovery' },
  GOLDEN_TICKET:         { id: 'T1558.001', name: 'Golden Ticket', phase: 'Impact' },
  EXTRASID:              { id: 'T1558.001', name: 'ExtraSID Ticket', phase: 'Impact' },
  SID_HISTORY:           { id: 'T1134.005', name: 'SID History Injection', phase: 'Priv Esc' },
  CVE_CHAIN:             { id: 'T1068',     name: 'Exploitation for Privilege Escalation', phase: 'Priv Esc' },
  MACHINE_ACCOUNT:       { id: 'T1136.002', name: 'Create Machine Account', phase: 'Priv Esc' },
  ADCS_ESC1:             { id: 'T1649',     name: 'ESC1 Certificate Abuse', phase: 'Priv Esc' },
  ADCS_ESC8:             { id: 'T1649',     name: 'ESC8 Certificate Relay', phase: 'Priv Esc' },
  ADCS_ESC15:            { id: 'T1649',     name: 'ESC15 Certificate Abuse', phase: 'Priv Esc' },
  ADD_KEY_CREDENTIAL_LINK:{ id: 'T1558.004', name: 'Shadow Credentials', phase: 'Priv Esc' },
  READ_GMSA_PASSWORD:    { id: 'T1552.006', name: 'gMSA Secret Read', phase: 'Priv Esc' },
  SQL_ADMIN:             { id: 'T1505.001', name: 'SQL Procedure Execution', phase: 'Lateral Move' },
  REMOTE_EXEC:           { id: 'T1021',     name: 'Remote Services', phase: 'Lateral Move' },
  KERBEROS_RELAY:        { id: 'T1557',     name: 'Kerberos Relay', phase: 'Lateral Move' },
  NTLM_CAPTURE:          { id: 'T1187',     name: 'Forced Authentication', phase: 'Discovery' },
  ADIDNS_CAN_WRITE:      { id: 'T1557',     name: 'DNS Relay Setup', phase: 'Priv Esc' },
}

const RISK: Record<RiskLevel, { color: string; soft: string; label: string; border: string; glow: string }> = {
  CRITICAL: { color: '#ef4444', soft: 'rgba(239,68,68,.12)',   label: 'Critical', border: 'rgba(239,68,68,.42)',  glow: 'rgba(239,68,68,.35)' },
  HIGH:     { color: '#f97316', soft: 'rgba(249,115,22,.12)',  label: 'High',     border: 'rgba(249,115,22,.38)', glow: 'rgba(249,115,22,.28)' },
  MEDIUM:   { color: '#eab308', soft: 'rgba(234,179,8,.10)',   label: 'Medium',   border: 'rgba(234,179,8,.32)',  glow: 'rgba(234,179,8,.22)' },
  LOW:      { color: '#94a3b8', soft: 'rgba(148,163,184,.08)', label: 'Low',      border: 'rgba(148,163,184,.22)',glow: 'rgba(148,163,184,.12)' },
}

const EDGE_COLOR: Record<string, string> = {
  GENERIC_ALL: '#ef4444', WRITE_DACL: '#fb923c', WRITE_OWNER: '#f97316',
  ADD_MEMBER: '#eab308', DCSYNC: '#ef4444', FORCE_CHANGE_PASSWORD: '#eab308',
  ALLOWED_TO_ACT: '#06b6d4', ALLOWED_TO_DELEGATE: '#22d3ee', CAN_ENROLL: '#10b981',
  MEMBER_OF: '#818cf8', APPLIES_GPO: '#c084fc', LOCAL_ADMIN: '#fb7185',
  ADMIN_TO: '#fb7185', HAS_SPN: '#f97316', AS_REP: '#eab308',
  ASREP_ROAST: '#eab308', KERBEROAST: '#f97316', PASS_THE_HASH: '#fb7185',
  PASS_THE_TICKET: '#818cf8', PASS_THE_CERT: '#10b981', NTLM_RELAY: '#38bdf8',
  COERCION: '#f59e0b', POISONING: '#22d3ee', GOLDEN_TICKET: '#ef4444',
  EXTRASID: '#a855f7', SID_HISTORY: '#c084fc', CVE_CHAIN: '#fb7185',
  MACHINE_ACCOUNT: '#94a3b8', ADCS_ESC1: '#10b981', ADCS_ESC8: '#34d399',
  ADCS_ESC15: '#6ee7b7', ADD_KEY_CREDENTIAL_LINK: '#c084fc',
  READ_GMSA_PASSWORD: '#f472b6', SQL_ADMIN: '#eab308', REMOTE_EXEC: '#fb7185',
  KERBEROS_RELAY: '#38bdf8', NTLM_CAPTURE: '#f472b6', ADIDNS_CAN_WRITE: '#22d3ee',
}

const APT_PROFILES = [
  { name: 'APT29 / COZY BEAR',  match: (p: AttackPathEntry) => !!(p.involves_delegation || p.edge_types?.some(e => /DCSYNC|DELEGATE/i.test(e))), color: '#ef4444' },
  { name: 'APT28 / FANCY BEAR', match: (p: AttackPathEntry) => !!(p.involves_credential_access || p.edge_types?.some(e => /KERBEROAST|HAS_SPN/i.test(e))), color: '#f97316' },
  { name: 'LAZARUS GROUP',      match: (p: AttackPathEntry) => !!(p.involves_adcs || p.edge_types?.some(e => /CAN_ENROLL|ADCS/i.test(e))), color: '#a855f7' },
]

function riskLevel(score: number): RiskLevel {
  if (score >= 85) return 'CRITICAL'
  if (score >= 65) return 'HIGH'
  if (score >= 40) return 'MEDIUM'
  return 'LOW'
}
function edgeColor(edge?: string) { return EDGE_COLOR[edge ?? ''] ?? '#818cf8' }
function pathKey(p: AttackPathEntry) {
  return `${p.category}:${p.source_label}:${p.target_label}:${p.hop_count}:${(p.edge_types??[]).join('|')}`
}
function categoryMeta(id: string, cat?: AttackCategory) {
  const fb = CATEGORY_FALLBACK[id] ?? { name: id.replace(/_/g,' '), color: '#818cf8', icon: Swords }
  return { name: cat?.name ?? fb.name, color: cat?.color ?? fb.color, icon: fb.icon }
}
function normalizePersistedPath(path: ExposurePath): AttackPathEntry {
  return {
    source_id: path.source_id, target_id: path.target_id,
    source_label: path.source_label || path.path_steps?.[0]?.entity_label || 'Unknown',
    target_label: path.target_label || path.path_steps?.at(-1)?.entity_label || 'Unknown',
    hop_count: path.hop_count, path_score: path.path_score,
    risk_level: path.risk_level ?? riskLevel(path.path_score),
    explanation: path.explanation || `${path.source_label} can reach ${path.target_label}`,
    steps: path.path_steps ?? [],
    edge_types: path.edge_types ?? path.path_steps?.map(s => s.edge_type).filter(Boolean).map(String) ?? [],
    category: path.path_type,
  }
}
function dedupePaths(paths: AttackPathEntry[]) {
  const seen = new Set<string>()
  return paths.filter(p => { const k = pathKey(p); if (seen.has(k)) return false; seen.add(k); return true })
}
function detectKillChainPhase(path: AttackPathEntry): typeof KILL_CHAIN[number] {
  const edges = path.edge_types ?? path.steps.map(s => s.edge_type).filter(Boolean).map(String)
  for (const e of edges) { if (EDGE_MITRE[e]) return EDGE_MITRE[e].phase }
  if (path.path_score >= 85) return 'Impact'
  if (path.hop_count <= 2) return 'Priv Esc'
  return 'Lateral Move'
}
function exportPaths(paths: AttackPathEntry[]) {
  downloadTextFile(`attack-paths-${Date.now()}.json`, JSON.stringify(paths, null, 2), 'application/json')
}
function exportCsv(paths: AttackPathEntry[]) {
  const rows = [['source','target','hops','score','risk','category','edges'].join(','),
    ...paths.map(p => [p.source_label,p.target_label,p.hop_count,p.path_score.toFixed(1),
      p.risk_level,p.category??'',`"${(p.edge_types??[]).join(';')}"`].join(','))]
  downloadTextFile(`attack-paths-${Date.now()}.csv`, rows.join('\n'), 'text/csv;charset=utf-8;')
}

function StatTile({ label, value, sub, color, Icon, pulse }: {
  label: string; value: string | number; sub?: string; color: string
  Icon: ComponentType<{ className?: string; style?: CSSProperties }>; pulse?: boolean
}) {
  return (
    <TiltCard intensity={5}>
      <div className="relative min-h-[108px] overflow-hidden rounded-lg border p-4"
        style={{ background: '#000', borderColor: `${color}38`, boxShadow: `0 0 34px ${color}1f` }}>
        <CornerFrame size={14} color={`${color}bb`} />
        {pulse && <span className="absolute right-3 top-3 flex h-2 w-2"><span className="absolute inline-flex h-full w-full animate-ping rounded-full opacity-75" style={{ background: color }} /><span className="relative inline-flex h-2 w-2 rounded-full" style={{ background: color }} /></span>}
        <div className="relative z-10 flex items-start justify-between gap-3">
          <span className="text-[10px] uppercase tracking-[.22em] text-zinc-500">{label}</span>
          <Icon className="h-4 w-4" style={{ color }} />
        </div>
        <div className="relative z-10 mt-4 text-3xl font-black tabular-nums" style={{ color, textShadow: `0 0 24px ${color}8a` }}>
          {typeof value === 'number' ? fmtNumber(value) : value}
        </div>
        {sub && <div className="relative z-10 mt-1 text-[10px] text-zinc-500">{sub}</div>}
      </div>
    </TiltCard>
  )
}

function KillChainRail({ phase }: { phase: typeof KILL_CHAIN[number] }) {
  const idx = KILL_CHAIN.indexOf(phase)
  return (
    <div className="flex items-center gap-0.5">
      {KILL_CHAIN.map((stage, i) => {
        const active = i <= idx
        const current = i === idx
        return (
          <div key={stage} className="flex items-center gap-0.5">
            <div className={cn('h-1.5 rounded-full transition-all', current ? 'w-6' : 'w-3')}
              style={{ background: active ? (i === 4 ? '#ef4444' : i >= 3 ? '#f97316' : i >= 2 ? '#eab308' : '#818cf8') : 'rgba(255,255,255,.08)' }} />
          </div>
        )
      })}
      <span className="ml-1.5 text-[9px] uppercase tracking-[.14em] text-zinc-500">{phase}</span>
    </div>
  )
}

function PathCard({ path, active, bookmarked, onClick, onBookmark }: {
  path: AttackPathEntry; active: boolean; bookmarked: boolean
  onClick: () => void; onBookmark: (e: React.MouseEvent) => void
}) {
  const risk = RISK[path.risk_level]
  const edges = path.edge_types ?? path.steps.map(s => s.edge_type).filter(Boolean).map(String)
  const phase = detectKillChainPhase(path)
  const mitreIds = [...new Set(edges.map(e => EDGE_MITRE[e]?.id).filter(Boolean))]

  return (
    <motion.div layout onClick={onClick}
      className="group relative w-full cursor-pointer overflow-hidden rounded-lg border p-3 text-left transition"
      style={{
        background: active ? risk.soft : '#000',
        borderColor: active ? risk.border : 'rgba(255,255,255,.08)',
        boxShadow: active ? `0 0 38px ${risk.color}24,inset 0 1px 0 rgba(255,255,255,.06)` : undefined,
      }}>
      <div className="pointer-events-none absolute inset-x-0 top-0 h-px"
        style={{ background: `linear-gradient(90deg,transparent,${active ? risk.color : edgeColor(edges[0])},transparent)` }} />

      <div className="flex items-start gap-3">
        <div className="flex h-14 w-12 shrink-0 flex-col items-center justify-center rounded-lg border"
          style={{ background: risk.soft, borderColor: risk.border }}>
          <span className="text-lg font-black tabular-nums" style={{ color: risk.color }}>{path.path_score.toFixed(0)}</span>
          <span className="text-[8px] uppercase tracking-[.16em]" style={{ color: risk.color }}>{risk.label}</span>
        </div>

        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-1.5">
            <span className="truncate text-sm font-bold text-zinc-100">{path.source_label}</span>
            <ArrowRight className="h-3 w-3 shrink-0 text-zinc-600" />
            <span className="truncate text-sm font-bold" style={{ color: path.path_score >= 85 ? '#fecaca' : '#e5e7eb' }}>
              {path.target_label}
            </span>
          </div>
          <p className="mt-0.5 line-clamp-1 text-[11px] text-zinc-500">{path.explanation}</p>

          <div className="mt-1.5 flex flex-wrap items-center gap-1.5">
            <KillChainRail phase={phase} />
            {mitreIds.slice(0, 2).map(id => (
              <span key={id} className="rounded border border-cyan-500/20 bg-cyan-500/10 px-1.5 py-0.5 text-[9px] font-mono font-bold text-cyan-300">{id}</span>
            ))}
          </div>

          <div className="mt-1.5 flex flex-wrap gap-1">
            {edges.slice(0, 3).map((e, i) => (
              <span key={`${e}-${i}`} className="rounded border px-1.5 py-0.5 text-[9px] font-semibold"
                style={{ color: edgeColor(e), borderColor: `${edgeColor(e)}33`, background: `${edgeColor(e)}10` }}>
                {e.replace(/_/g,' ')}
              </span>
            ))}
          </div>
        </div>

        <div className="flex shrink-0 flex-col items-end gap-1">
          <button onClick={onBookmark} className="rounded p-0.5 transition hover:scale-110">
            {bookmarked
              ? <BookmarkCheck className="h-3.5 w-3.5 text-yellow-400" />
              : <Bookmark className="h-3.5 w-3.5 text-zinc-600 group-hover:text-zinc-400" />}
          </button>
          <div className="text-right">
            <div className="text-sm font-black tabular-nums text-white">{path.hop_count}</div>
            <div className="text-[8px] uppercase text-zinc-600">hops</div>
          </div>
          <ChevronRight className={cn('h-4 w-4 text-zinc-600 transition', active && 'rotate-90 text-zinc-300')} />
        </div>
      </div>
    </motion.div>
  )
}

function QuickWins({ paths }: { paths: AttackPathEntry[] }) {
  const wins = useMemo(() =>
    [...paths].sort((a, b) => b.path_score - a.path_score || a.hop_count - b.hop_count)
      .filter(p => p.hop_count <= 2 && p.path_score >= 65).slice(0, 3),
    [paths]
  )
  if (!wins.length) return null
  return (
    <div className="relative overflow-hidden rounded-lg border border-yellow-500/20 bg-yellow-500/5 p-4">
      <CornerFrame size={12} color="rgba(234,179,8,.45)" />
      <div className="mb-3 flex items-center gap-2">
        <Zap className="h-4 w-4 text-yellow-300" />
        <span className="text-[10px] uppercase tracking-[.22em] text-zinc-400">Quick Wins</span>
        <span className="ml-auto text-[9px] text-yellow-400">high-impact, low-hop</span>
      </div>
      <div className="space-y-2">
        {wins.map((p, i) => (
          <div key={`${pathKey(p)}-${i}`} className="flex items-center gap-2 rounded-md border border-white/[.06] bg-black px-2 py-1.5">
            <span className="text-[10px] font-black" style={{ color: RISK[p.risk_level].color }}>{p.path_score.toFixed(0)}</span>
            <span className="truncate text-xs text-zinc-300">{p.source_label} → {p.target_label}</span>
            <span className="shrink-0 text-[9px] text-zinc-600">{p.hop_count}h</span>
          </div>
        ))}
      </div>
    </div>
  )
}

function EdgeMatrix({ edgeCounts, selected, onSelect }: { edgeCounts: Record<string,number>; selected: string; onSelect: (e:string)=>void }) {
  const entries = Object.entries(edgeCounts).sort((a,b) => b[1]-a[1]).slice(0,12)
  const max = Math.max(...entries.map(([,c]) => c), 1)
  return (
    <div className="relative overflow-hidden rounded-lg border border-white/10 bg-white/[.025] p-4">
      <CornerFrame size={12} color="rgba(6,182,212,.42)" />
      <div className="mb-3 flex items-center gap-2">
        <Layers3 className="h-4 w-4 text-cyan-300" />
        <span className="text-[10px] uppercase tracking-[.22em] text-zinc-400">Edge Matrix</span>
      </div>
      <div className="space-y-2">
        <button onClick={() => onSelect('all')}
          className={cn('mb-1 rounded-md border px-2 py-1 text-[10px] uppercase tracking-[.18em] transition', selected==='all' ? 'text-cyan-200' : 'text-zinc-500')}
          style={{ borderColor: selected==='all' ? 'rgba(6,182,212,.45)' : 'rgba(255,255,255,.08)', background: selected==='all' ? 'rgba(6,182,212,.08)' : 'transparent' }}>
          All edges
        </button>
        {entries.map(([edge, count]) => {
          const color = edgeColor(edge); const active = selected === edge
          return (
            <button key={edge} onClick={() => onSelect(active ? 'all' : edge)} className="group flex w-full items-center gap-2 text-left">
              <div className="min-w-0">
                <span className="block truncate text-[10px] font-semibold uppercase tracking-[.12em]" style={{ color: active ? color : '#71717a' }}>
                  {edge.replace(/_/g,' ')}
                </span>
                {EDGE_MITRE[edge] && <span className="text-[8px] text-zinc-600">{EDGE_MITRE[edge].id}</span>}
              </div>
              <span className="h-1.5 flex-1 overflow-hidden rounded-full bg-white/[.045]">
                <motion.span className="block h-full rounded-full" style={{ background: `linear-gradient(90deg,${color}77,${color})` }}
                  initial={{ width: 0 }} animate={{ width: `${(count/max)*100}%` }} />
              </span>
              <span className="w-7 text-right text-[10px] tabular-nums text-zinc-500">{count}</span>
            </button>
          )
        })}
      </div>
    </div>
  )
}

function ChokePanel({ chokes, loading, error }: { chokes: ChokePoint[]; loading: boolean; error?: boolean }) {
  return (
    <div className="relative overflow-hidden rounded-lg border border-white/10 bg-white/[.025] p-4">
      <CornerFrame size={12} color="rgba(168,85,247,.45)" />
      <div className="mb-3 flex items-center gap-2">
        <GitBranch className="h-4 w-4 text-purple-300" />
        <span className="text-[10px] uppercase tracking-[.22em] text-zinc-400">Choke Points</span>
        <span className="ml-auto text-[9px] text-zinc-600">remove to collapse paths</span>
      </div>
      {loading
        ? <div className="flex items-center gap-2 text-xs text-zinc-500"><Loader2 className="h-3.5 w-3.5 animate-spin" />Computing</div>
        : error
          ? <div className="flex items-center gap-1.5 text-xs text-red-400"><span>⚠</span> Failed to load choke points</div>
          : chokes.length === 0
          ? <div className="text-xs text-zinc-600">No choke points detected</div>
          : <div className="space-y-2">
              {chokes.slice(0, 8).map((cp, i) => {
                const rawImpact = cp.removal_impact?.elimination_pct ?? cp.elimination_pct ?? 0
                const impact = Math.round(rawImpact * (rawImpact <= 1 ? 100 : 1))
                const tierColor = cp.tier === 0 ? '#ef4444' : cp.tier === 1 ? '#f97316' : '#a855f7'
                return (
                  <div key={cp.node_id} className="grid grid-cols-[16px_1fr_40px] items-center gap-2">
                    <span className="text-[10px] text-zinc-600">{i+1}</span>
                    <div className="min-w-0">
                      <div className="flex items-center gap-1.5">
                        <span className="truncate text-xs text-zinc-200">{cp.label}</span>
                        {cp.tier !== undefined && (
                          <span className="rounded px-1 text-[8px] font-bold" style={{ color: tierColor, background: `${tierColor}18` }}>T{cp.tier}</span>
                        )}
                      </div>
                      <div className="mt-1 h-1.5 overflow-hidden rounded-full bg-white/[.05]">
                        <motion.div className="h-full rounded-full" style={{ background: `linear-gradient(90deg,${tierColor}88,${tierColor})` }}
                          initial={{ width: 0 }} animate={{ width: `${Math.min(100, impact)}%` }} />
                      </div>
                    </div>
                    <span className="text-right text-[10px] text-purple-300">-{impact}%</span>
                  </div>
                )
              })}
            </div>
      }
    </div>
  )
}

function BlastPanel({ assessmentId }: { assessmentId: string }) {
  const { data, isLoading } = useQuery({
    queryKey: ['blast-radius', assessmentId],
    queryFn: () => graphApi.getBlastRadius(assessmentId),
    enabled: !!assessmentId, staleTime: 300_000,
  })
  const typed = data as { entities_in_blast_radius?: number; top_100?: { label: string; paths_to_tier0: number; type?: string }[] } | undefined
  const top = typed?.top_100?.slice(0, 8) ?? []
  const max = Math.max(...top.map(i => i.paths_to_tier0), 1)
  return (
    <div className="relative overflow-hidden rounded-lg border border-white/10 bg-white/[.025] p-4">
      <CornerFrame size={12} color="rgba(239,68,68,.42)" />
      <div className="mb-3 flex items-center gap-2">
        <Activity className="h-4 w-4 text-red-300" />
        <span className="text-[10px] uppercase tracking-[.22em] text-zinc-400">Blast Radius</span>
        <span className="ml-auto text-sm font-black text-red-300">{fmtNumber(typed?.entities_in_blast_radius ?? 0)}</span>
      </div>
      {isLoading
        ? <div className="flex items-center gap-2 text-xs text-zinc-500"><Loader2 className="h-3.5 w-3.5 animate-spin" />Computing</div>
        : top.length === 0
          ? <div className="text-xs text-zinc-600">No Tier-0 blast data</div>
          : <div className="space-y-2">
              {top.map((item, i) => (
                <div key={`${item.label}-${i}`}>
                  <div className="mb-1 flex items-center justify-between gap-3">
                    <span className="truncate text-xs text-zinc-300">{item.label}</span>
                    <span className="text-[10px] text-red-300">{item.paths_to_tier0} paths</span>
                  </div>
                  <div className="h-1.5 overflow-hidden rounded-full bg-white/[.05]">
                    <motion.div className="h-full rounded-full bg-gradient-to-r from-red-600 to-red-400"
                      initial={{ width: 0 }} animate={{ width: `${(item.paths_to_tier0/max)*100}%` }} />
                  </div>
                </div>
              ))}
            </div>
      }
    </div>
  )
}

function CopyBtn({ text }: { text: string }) {
  const [copied, setCopied] = useState(false)
  return (
    <button onClick={() => { copyText(text); setCopied(true); setTimeout(()=>setCopied(false),1500) }}
      className="rounded p-1 text-zinc-500 transition hover:text-zinc-300">
      {copied ? <Check className="h-3.5 w-3.5 text-green-400" /> : <Copy className="h-3.5 w-3.5" />}
    </button>
  )
}

const EDGE_TYPE_COLOR: Record<string, string> = {
  GENERIC_ALL: '#fb7185', WRITE_DACL: '#f97316', WRITE_OWNER: '#f97316',
  DCSYNC: '#ef4444', OWNS: '#f97316', FORCE_CHANGE_PASSWORD: '#facc15',
  ADD_MEMBER: '#a78bfa', ALLOWED_TO_DELEGATE: '#38bdf8', ALLOWED_TO_ACT: '#22d3ee',
  ADMIN_TO: '#fb7185', LOCAL_ADMIN: '#fb7185', CAN_ENROLL: '#34d399',
  PASS_THE_HASH: '#f472b6', PASS_THE_TICKET: '#c084fc', KERBEROAST: '#fbbf24',
}

function EdgeTypeBadge({ type }: { type: string }) {
  const color = EDGE_TYPE_COLOR[type] ?? '#94a3b8'
  return (
    <span className="inline-flex items-center rounded px-1.5 py-0.5 text-[9px] font-bold uppercase tracking-wider"
      style={{ background: `${color}18`, border: `1px solid ${color}40`, color }}>
      {type.replace(/_/g, ' ')}
    </span>
  )
}

function ReductionBar({ before, after }: { before: number; after: number }) {
  const pct = before > 0 ? Math.round(((before - after) / before) * 100) : 0
  return (
    <div className="space-y-1">
      <div className="flex items-center justify-between text-[10px]">
        <span className="text-zinc-500">Exposure pressure</span>
        <span className="font-bold text-emerald-300">−{pct}%</span>
      </div>
      <div className="relative h-2 overflow-hidden rounded-full bg-white/[.06]">
        <div className="absolute left-0 top-0 h-full rounded-full bg-red-500/60" style={{ width: '100%' }} />
        <motion.div className="absolute left-0 top-0 h-full rounded-full"
          style={{ background: 'linear-gradient(90deg,#10b981,#34d399)', width: `${pct}%` }}
          initial={{ width: 0 }} animate={{ width: `${pct}%` }} transition={{ duration: 0.8, ease: 'easeOut' }} />
      </div>
      <div className="flex justify-between text-[9px] text-zinc-600">
        <span>{before} before</span><span>{after} after</span>
      </div>
    </div>
  )
}

function CountermovePanel({ simulation, simulating, canSimulate, onSimulate }: {
  simulation?: GraphSimulationResult; simulating: boolean; canSimulate: boolean; onSimulate: () => void
}) {
  const [expandedEdge, setExpandedEdge] = useState<number | null>(null)
  const [showAllSteps, setShowAllSteps] = useState<number | null>(null)

  const reductionPct = Math.round(
    simulation?.reduction_pct ?? simulation?.risk_reduction_pct ?? simulation?.reduction ?? 0
  )
  const exposedBefore = simulation?.exposed_principals_before ?? simulation?.before
  const exposedAfter = simulation?.exposed_principals_after ?? simulation?.after
  const exposedEliminated = simulation?.exposed_principals_eliminated ?? simulation?.eliminated ?? 0

  return (
    <div className="relative overflow-hidden rounded-lg border border-white/10 bg-white/[.025] p-4">
      <div className="mb-3 flex items-center gap-2">
        <Sparkles className="h-4 w-4 text-cyan-300" />
        <span className="text-[10px] uppercase tracking-[.22em] text-zinc-400">Countermove</span>
        {simulation && (
          <span className="ml-auto flex items-center gap-1 rounded-full border border-emerald-400/30 bg-emerald-400/10 px-2 py-0.5 text-[10px] font-bold text-emerald-300">
            <TrendingDown className="h-3 w-3" />−{reductionPct}%
          </span>
        )}
      </div>

      {/* Simulate button */}
      <button disabled={!canSimulate || simulating} onClick={onSimulate}
        className="mb-3 w-full rounded-lg border px-3 py-2 text-[11px] font-bold uppercase tracking-[.16em] transition disabled:cursor-not-allowed disabled:opacity-40"
        style={{ borderColor: 'rgba(6,182,212,.35)', background: 'rgba(6,182,212,.08)', color: '#67e8f9' }}>
        {simulating
          ? <span className="flex items-center justify-center gap-2"><Loader2 className="h-3.5 w-3.5 animate-spin" />Analysing graph…</span>
          : simulation ? 'Re-simulate' : 'Simulate Removal'}
      </button>

      <AnimatePresence>
        {simulation && (
          <motion.div initial={{ opacity: 0, height: 0 }} animate={{ opacity: 1, height: 'auto' }} exit={{ opacity: 0, height: 0 }}
            className="space-y-4 overflow-hidden">

            {/* Key metrics grid */}
            <div className="grid grid-cols-2 gap-2">
              {[
                { label: 'Principals removed', value: exposedEliminated, color: '#34d399' },
                { label: 'Principals exposed', value: exposedAfter ?? 0, color: simulation.is_fully_remediated ? '#34d399' : '#fb7185' },
                { label: 'Blast radius Δ', value: `−${simulation.blast_radius_reduction ?? 0}`, color: '#a78bfa' },
                { label: 'Residual risk', value: simulation.residual_risk_score !== undefined ? `${simulation.residual_risk_score.toFixed(0)}%` : '—', color: '#facc15' },
              ].map(m => (
                <div key={m.label} className="rounded-md border border-white/10 bg-black p-2.5 text-center">
                  <div className="text-lg font-black tabular-nums" style={{ color: m.color }}>{String(m.value)}</div>
                  <div className="mt-0.5 text-[9px] uppercase tracking-wider text-zinc-500">{m.label}</div>
                </div>
              ))}
            </div>

            {/* Path pressure bar */}
            {(exposedBefore !== undefined && exposedAfter !== undefined) && (
              <ReductionBar before={exposedBefore} after={exposedAfter} />
            )}

            {/* Fully remediated badge */}
            {simulation.is_fully_remediated && (
              <div className="flex items-center gap-2 rounded-md border border-emerald-400/25 bg-emerald-400/10 p-3 text-xs text-emerald-300">
                <ShieldCheck className="h-4 w-4 shrink-0" />
                <span>All Tier-0 paths through this route are eliminated.</span>
              </div>
            )}

            {/* Optimal single removal recommendation */}
            {simulation.optimal_removal && (
              <div>
                <div className="mb-1.5 text-[9px] font-bold uppercase tracking-[.2em] text-cyan-400/70">Highest-impact cut</div>
                <div className="rounded-md border border-cyan-400/20 bg-cyan-400/5 p-3 space-y-1.5">
                  <div className="flex items-center gap-2 flex-wrap">
                    <EdgeTypeBadge type={simulation.optimal_removal.edge_type} />
                    <span className="text-xs text-zinc-300">
                      {simulation.optimal_removal.source_label} → {simulation.optimal_removal.target_label}
                    </span>
                  </div>
                  <div className="text-[10px] text-zinc-400">{simulation.optimal_removal.remediation}</div>
                  <div className="text-[10px] font-semibold text-cyan-300">
                    Removes {simulation.optimal_removal.exposed_principals_eliminated_if_removed} exposed principal{simulation.optimal_removal.exposed_principals_eliminated_if_removed !== 1 ? 's' : ''} alone
                  </div>
                </div>
              </div>
            )}

            {/* Per-edge analysis */}
            {simulation.per_edge_analysis && simulation.per_edge_analysis.length > 0 && (
              <div>
                <div className="mb-1.5 text-[9px] font-bold uppercase tracking-[.2em] text-zinc-500">Edge-by-edge impact</div>
                <div className="space-y-1.5">
                  {simulation.per_edge_analysis.map((edge: SimulationEdge, i: number) => (
                    <div key={`${edge.source}-${edge.target}`}
                      className="rounded-md border border-white/10 bg-black">
                      <button className="flex w-full items-center gap-2 p-2.5 text-left"
                        onClick={() => setExpandedEdge(expandedEdge === i ? null : i)}>
                        <EdgeTypeBadge type={edge.edge_type} />
                        <span className="flex-1 truncate text-[10px] text-zinc-300">
                          {edge.source_label} → {edge.target_label}
                        </span>
                        <span className="shrink-0 text-[10px] font-bold text-emerald-300">
                          −{edge.exposed_principals_eliminated_if_removed}
                        </span>
                        {expandedEdge === i
                          ? <ChevronUp className="h-3 w-3 shrink-0 text-zinc-500" />
                          : <ChevronDown className="h-3 w-3 shrink-0 text-zinc-500" />}
                      </button>

                      <AnimatePresence>
                        {expandedEdge === i && (
                          <motion.div initial={{ height: 0, opacity: 0 }} animate={{ height: 'auto', opacity: 1 }}
                            exit={{ height: 0, opacity: 0 }} className="overflow-hidden">
                            <div className="border-t border-white/10 p-2.5 space-y-2">
                              <div className="h-1.5 overflow-hidden rounded-full bg-white/[.06]">
                                <motion.div className="h-full rounded-full bg-emerald-500"
                                  initial={{ width: 0 }}
                                  animate={{ width: `${edge.reduction_pct_if_removed ?? 0}%` }}
                                  transition={{ duration: 0.6 }} />
                              </div>
                              {edge.remediation_steps && edge.remediation_steps.length > 0 && (
                                <div className="space-y-1">
                                  <div className="text-[9px] font-bold uppercase tracking-wider text-zinc-600">Remediation steps</div>
                                  {(showAllSteps === i
                                    ? edge.remediation_steps
                                    : edge.remediation_steps.slice(0, 2)
                                  ).map((step: string, si: number) => (
                                    <div key={si} className="flex gap-1.5 text-[10px] text-zinc-400">
                                      <span className="shrink-0 text-zinc-600">{si + 1}.</span>
                                      <span>{step}</span>
                                    </div>
                                  ))}
                                  {edge.remediation_steps.length > 2 && (
                                    <button onClick={() => setShowAllSteps(showAllSteps === i ? null : i)}
                                      className="text-[9px] text-cyan-400/70 hover:text-cyan-300 transition">
                                      {showAllSteps === i ? 'Show less' : `+${edge.remediation_steps.length - 2} more steps`}
                                    </button>
                                  )}
                                </div>
                              )}
                            </div>
                          </motion.div>
                        )}
                      </AnimatePresence>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Alternative paths warning */}
            {simulation.alternative_paths && simulation.alternative_paths.length > 0 && (
              <div>
                <div className="mb-1.5 flex items-center gap-1.5 text-[9px] font-bold uppercase tracking-[.2em] text-yellow-400/70">
                  <AlertTriangle className="h-3 w-3" />Alternative routes remain
                </div>
                <div className="space-y-1.5">
                  {simulation.alternative_paths.map((alt: SimulationAlternativePath, i: number) => (
                    <div key={i} className="rounded-md border border-yellow-400/15 bg-yellow-400/5 p-2.5">
                      <div className="flex items-center gap-1.5 flex-wrap mb-1">
                        <span className="text-[10px] text-zinc-300">{alt.source_label}</span>
                        <ArrowRight className="h-2.5 w-2.5 text-zinc-600" />
                        <span className="text-[10px] text-zinc-300">{alt.target_label}</span>
                        <span className="ml-auto text-[9px] text-zinc-500">{alt.hop_count} hop{alt.hop_count !== 1 ? 's' : ''}</span>
                      </div>
                      <div className="flex flex-wrap gap-1">
                        {alt.edge_types.map((et, j) => <EdgeTypeBadge key={j} type={et} />)}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Blast radius delta */}
            {simulation.blast_radius_before !== undefined && (
              <div className="rounded-md border border-white/10 bg-black p-2.5 text-[10px] text-zinc-400 space-y-1">
                <div className="flex justify-between">
                  <span>Blast radius before</span>
                  <span className="text-red-300 font-semibold">{simulation.blast_radius_before} entities</span>
                </div>
                <div className="flex justify-between">
                  <span>Blast radius after</span>
                  <span className="text-emerald-300 font-semibold">{simulation.blast_radius_after} entities</span>
                </div>
              </div>
            )}

          </motion.div>
        )}
      </AnimatePresence>

      {!simulation && !simulating && (
        <div className="rounded-md border border-white/10 bg-black p-3 text-[10px] text-zinc-500">
          Simulates edge removal across all hops, recomputes Tier-0 reachability, and surfaces alternative attack routes.
        </div>
      )}
    </div>
  )
}

function DetailPanel({ path, simulation, simulating, onSimulate }: {
  path: AttackPathEntry | null; simulation?: GraphSimulationResult
  simulating: boolean; onSimulate: () => void
}) {
  if (!path) {
    return (
      <div className="relative flex min-h-[520px] items-center justify-center rounded-lg border border-white/10 bg-white/[.02]">
        <CornerFrame size={14} color="rgba(255,255,255,.14)" />
        <div className="text-center">
          <Target className="mx-auto mb-3 h-10 w-10 text-zinc-700" />
          <div className="text-sm font-semibold text-zinc-500">Select a path</div>
          <div className="mt-1 text-xs text-zinc-700">Click any route to drill down</div>
        </div>
      </div>
    )
  }

  const risk = RISK[path.risk_level]
  const steps = path.steps ?? []
  const graphSteps: PathStep[] = steps.length > 0 ? steps : [
    { entity_id: path.source_id ?? 'src', entity_label: path.source_label, entity_type: 'USER', explanation: '', edge_type: path.edge_types?.[0] },
    { entity_id: path.target_id ?? 'tgt', entity_label: path.target_label, entity_type: 'DOMAIN', explanation: '' },
  ]
  const edges = path.edge_types ?? graphSteps.map(s => s.edge_type).filter(Boolean).map(String)
  const mitreEntries = [...new Map(edges.map(e => EDGE_MITRE[e]).filter(Boolean).map(m => [m.id, m])).values()]
  const aptMatches = APT_PROFILES.filter(a => a.match(path))
  const canSimulate = graphSteps.length > 1 && !!graphSteps[0]?.entity_id && !!graphSteps[1]?.entity_id
  const phase = detectKillChainPhase(path)

  return (
    <motion.div key={pathKey(path)} initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} className="space-y-4">
      {/* header */}
      <div className="relative overflow-hidden rounded-lg border p-5"
        style={{ background: '#000', borderColor: risk.border, boxShadow: `0 0 48px ${risk.glow}` }}>
        <CornerFrame size={16} color={risk.color} />
        <div className="relative z-10 flex items-start gap-4">
          <div className="flex h-16 w-16 shrink-0 flex-col items-center justify-center rounded-lg border" style={{ background: risk.soft, borderColor: risk.border }}>
            <span className="text-2xl font-black tabular-nums" style={{ color: risk.color }}>{path.path_score.toFixed(0)}</span>
            <span className="text-[8px] uppercase tracking-[.16em]" style={{ color: risk.color }}>{risk.label}</span>
          </div>
          <div className="min-w-0 flex-1">
            <div className="flex flex-wrap items-center gap-2">
              <span className="text-lg font-black text-white">{path.source_label}</span>
              <ArrowRight className="h-4 w-4 text-zinc-500" />
              <span className="text-lg font-black" style={{ color: risk.color }}>{path.target_label}</span>
              <CopyBtn text={`${path.source_label} → ${path.target_label}`} />
            </div>
            <p className="mt-2 text-sm leading-relaxed text-zinc-400">{path.explanation}</p>
            <div className="mt-3 flex flex-wrap gap-2">
              <span className="rounded-md border border-white/10 bg-white/[.04] px-2 py-1 text-[10px] uppercase tracking-[.16em] text-zinc-400">{path.hop_count} hops</span>
              <span className="rounded-md border border-white/10 bg-white/[.04] px-2 py-1 text-[10px] uppercase tracking-[.16em] text-zinc-400">{phase}</span>
              {edges.slice(0, 4).map((e, i) => (
                <span key={`${e}-${i}`} className="rounded-md border px-2 py-1 text-[10px] font-bold uppercase"
                  style={{ color: edgeColor(e), borderColor: `${edgeColor(e)}38`, background: `${edgeColor(e)}10` }}>
                  {e.replace(/_/g,' ')}
                </span>
              ))}
            </div>
            {aptMatches.length > 0 && (
              <div className="mt-2 flex flex-wrap gap-1">
                <span className="text-[9px] text-zinc-600 mr-1">Matches:</span>
                {aptMatches.map(a => <span key={a.name} className="rounded border px-1.5 py-0.5 text-[9px] font-bold" style={{ color: a.color, borderColor: `${a.color}33`, background: `${a.color}10` }}>{a.name}</span>)}
              </div>
            )}
          </div>
        </div>
      </div>

      {/* MITRE ATT&CK strip */}
      {mitreEntries.length > 0 && (
        <div className="flex flex-wrap gap-2 rounded-lg border border-cyan-500/15 bg-cyan-500/5 p-3">
          <span className="text-[9px] uppercase tracking-[.18em] text-zinc-600 self-center">MITRE ATT&CK</span>
          {mitreEntries.map(m => (
            <div key={m.id} className="flex items-center gap-1.5 rounded border border-cyan-500/20 bg-cyan-500/10 px-2 py-1">
              <span className="font-mono text-[10px] font-bold text-cyan-300">{m.id}</span>
              <span className="text-[10px] text-zinc-400">{m.name}</span>
            </div>
          ))}
        </div>
      )}

      {/* route map */}
      <div className="relative overflow-hidden rounded-lg border border-white/10 bg-white/[.025] p-4">
        <div className="mb-3 flex items-center gap-2">
          <Route className="h-4 w-4 text-indigo-300" />
          <span className="text-[10px] uppercase tracking-[.22em] text-zinc-400">Route Map</span>
        </div>
        <div className="overflow-x-auto pb-2">
          <AttackMiniGraph steps={graphSteps} width={Math.max(540, Math.min(900, graphSteps.length * 132 + 90))} height={178} />
        </div>
      </div>

      {/* execution chain + countermove */}
      <div className="grid gap-4 xl:grid-cols-[1fr_280px]">
        <div className="relative overflow-hidden rounded-lg border border-white/10 bg-white/[.025] p-4">
          <div className="mb-3 flex items-center gap-2">
            <GitBranch className="h-4 w-4 text-purple-300" />
            <span className="text-[10px] uppercase tracking-[.22em] text-zinc-400">Execution Chain</span>
          </div>
          <PathStepTimeline steps={graphSteps} />
        </div>

        <CountermovePanel simulation={simulation} simulating={simulating} canSimulate={canSimulate} onSimulate={onSimulate} />
      </div>
    </motion.div>
  )
}

export default function AttackPathsPage() {
  const qc = useQueryClient()
  const [selectedCategory, setSelectedCategory] = useState('all')
  const [selectedEdge, setSelectedEdge] = useState('all')
  const [selectedPath, setSelectedPath] = useState<AttackPathEntry | null>(null)
  const [search, setSearch] = useState('')
  const [sortMode, setSortMode] = useState<SortMode>('risk')
  const [minRisk, setMinRisk] = useState(0)
  const [simulation, setSimulation] = useState<GraphSimulationResult | undefined>()
  const [mounted, setMounted] = useState(false)
  const [bookmarks, setBookmarks] = useState<Set<string>>(() => new Set())
  const autoComputedRef = useRef(false)

  useEffect(() => {
    setMounted(true)
    try {
      setBookmarks(new Set(JSON.parse(localStorage.getItem('path-bookmarks') ?? '[]')))
    } catch {
      setBookmarks(new Set())
    }
  }, [])

  const { assessment, assessmentId: scopedAssessmentId } = useRouteAssessmentScope()
  const assessmentId = scopedAssessmentId ?? ''

  const { data: catData, isLoading: catsLoading } = useQuery({
    queryKey: ['attack-categories', assessmentId],
    queryFn: () => graphApi.getCategories(assessmentId),
    enabled: !!assessmentId, staleTime: 180_000,
  })

  const { data: persistedData, isLoading: pathsLoading } = useQuery({
    queryKey: ['paths', assessmentId],
    queryFn: () => graphApi.getPaths(assessmentId, { max_paths: 100 }),
    enabled: !!assessmentId, staleTime: 180_000,
  })

  const { data: chokeData, isLoading: chokeLoading, isError: chokeError } = useQuery({
    queryKey: ['choke-points', assessmentId],
    queryFn: () => graphApi.getChokePoints(assessmentId),
    enabled: !!assessmentId, staleTime: 300_000,
  })

  const computeMutation = useMutation({
    mutationFn: () => graphApi.computePaths(assessmentId),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['paths', assessmentId] })
      qc.invalidateQueries({ queryKey: ['attack-categories', assessmentId] })
      qc.invalidateQueries({ queryKey: ['choke-points', assessmentId] })
    },
  })

  const simulateMutation = useMutation({
    mutationFn: (path: AttackPathEntry) => {
      const steps = path.steps ?? []
      // Build all edges in the path for full graph simulation
      const edgePairs: { source: string; target: string }[] = []
      for (let i = 0; i < steps.length - 1; i++) {
        const src = steps[i]?.entity_id
        const tgt = steps[i + 1]?.entity_id
        if (src && tgt) edgePairs.push({ source: src, target: tgt })
      }
      // Fallback to first/second node if no step data
      if (edgePairs.length === 0) {
        const src = steps[0]?.entity_id || path.source_id
        const tgt = steps[1]?.entity_id || path.target_id
        if (!src || !tgt) throw new Error('No removable edge')
        edgePairs.push({ source: src, target: tgt })
      }
      return graphApi.simulateRemoval(assessmentId, edgePairs)
    },
    onSuccess: result => setSimulation(result),
  })

  const categories = useMemo(() => catData?.categories ?? {}, [catData?.categories])

  const mergedCategories = categories

  const allCategoryPaths = useMemo(() => {
    const ordered = [...CATEGORY_ORDER, ...Object.keys(mergedCategories).filter(k => !CATEGORY_ORDER.includes(k))]
    return dedupePaths(ordered.flatMap(key => (mergedCategories[key]?.paths ?? []).map(p => ({ ...p, category: p.category ?? key }))))
  }, [mergedCategories])

  const persistedPaths = useMemo(() => {
    const raw = Array.isArray(persistedData) ? persistedData : (persistedData as { paths?: ExposurePath[] } | undefined)?.paths ?? []
    return raw.map(normalizePersistedPath)
  }, [persistedData])

  const allPaths = useMemo(() => dedupePaths([...allCategoryPaths, ...persistedPaths]), [allCategoryPaths, persistedPaths])

  // auto-compute once when assessment loads and has no paths yet
  useEffect(() => {
    if (!assessmentId || catsLoading || pathsLoading || autoComputedRef.current) return
    if (allPaths.length === 0 && !computeMutation.isPending) {
      autoComputedRef.current = true
      computeMutation.mutate()
    }
  }, [assessmentId, allPaths.length, catsLoading, pathsLoading]) // eslint-disable-line react-hooks/exhaustive-deps

  const edgeCounts = useMemo(() => {
    const counts: Record<string,number> = {}
    for (const path of allPaths)
      for (const e of path.edge_types ?? path.steps.map(s => s.edge_type).filter(Boolean).map(String))
        counts[e] = (counts[e] ?? 0) + 1
    if (!Object.keys(counts).length) return { ...(catData?.edge_type_counts ?? {}) }
    return counts
  }, [allPaths, catData?.edge_type_counts])

  const filteredPaths = useMemo(() => {
    const q = search.trim().toLowerCase()
    let rows = allPaths
    if (selectedCategory !== 'all')
      rows = rows.filter(p => p.category === selectedCategory || (selectedCategory === 'tier0' && p.path_score >= 85))
    if (selectedEdge !== 'all')
      rows = rows.filter(p => (p.edge_types ?? p.steps.map(s=>s.edge_type).filter(Boolean).map(String)).includes(selectedEdge))
    if (minRisk > 0) rows = rows.filter(p => p.path_score >= minRisk)
    if (q) rows = rows.filter(p => [p.source_label, p.target_label, p.explanation, p.category??'', ...(p.edge_types??[])].join(' ').toLowerCase().includes(q))
    const sorted = [...rows]
    sorted.sort((a,b) => {
      if (sortMode === 'hops') return a.hop_count - b.hop_count || b.path_score - a.path_score
      if (sortMode === 'source') return a.source_label.localeCompare(b.source_label)
      if (sortMode === 'target') return a.target_label.localeCompare(b.target_label)
      return b.path_score - a.path_score || a.hop_count - b.hop_count
    })
    return sorted
  }, [allPaths, minRisk, search, selectedCategory, selectedEdge, sortMode])

  const categoryTabs = useMemo(() => {
    const keys = [...CATEGORY_ORDER, ...Object.keys(mergedCategories).filter(k => !CATEGORY_ORDER.includes(k))]
    return [
      { id: 'all',   name: 'All',    count: allPaths.length,                                  color: '#818cf8', icon: Swords },
      { id: 'tier0', name: 'Tier-0', count: allPaths.filter(p => p.path_score >= 85).length,  color: '#ef4444', icon: Target },
      ...keys.filter(k => (mergedCategories[k]?.count ?? mergedCategories[k]?.paths?.length ?? 0) > 0)
        .map(key => { const meta = categoryMeta(key, mergedCategories[key]); return { id: key, name: meta.name, count: mergedCategories[key]?.count ?? mergedCategories[key]?.paths?.length ?? 0, color: meta.color, icon: meta.icon } }),
    ]
  }, [allPaths, mergedCategories])

  const criticalCount = allPaths.filter(p => p.path_score >= 85).length
  const avgRisk = allPaths.length ? Math.round(allPaths.reduce((s,p) => s + p.path_score, 0) / allPaths.length) : 0
  const chokes = chokeData?.choke_points ?? []
  const loading = catsLoading || pathsLoading

  function toggleBookmark(path: AttackPathEntry, e: React.MouseEvent) {
    e.stopPropagation()
    const key = pathKey(path)
    setBookmarks(prev => {
      const next = new Set(prev)
      if (next.has(key)) next.delete(key)
      else next.add(key)
      try { localStorage.setItem('path-bookmarks', JSON.stringify([...next])) } catch { /* noop */ }
      return next
    })
  }

  return (
    <AppShell>
      <div className="min-h-full overflow-hidden p-6">

        {/* grid overlay */}
        <div className="pointer-events-none fixed inset-x-[255px] bottom-0 h-52 opacity-25"
          style={{ background: 'repeating-linear-gradient(90deg,rgba(168,85,247,.18) 0 1px,transparent 1px 72px)' }} />

        <div className="relative z-10 space-y-5">
          {/* title row */}
          <div className="flex flex-wrap items-start justify-between gap-4">
            <div>
              <div className="flex items-center gap-3">
                <div className="flex h-11 w-11 items-center justify-center rounded-lg border border-red-400/30 bg-red-500/10 shadow-[0_0_28px_rgba(239,68,68,.18)]">
                  <Route className="h-5 w-5 text-red-300" />
                </div>
                <div>
                  <h1 className="text-2xl font-black tracking-tight text-white">Attack Paths</h1>
                  <div className="mt-1 flex flex-wrap items-center gap-2 text-xs text-zinc-500">
                    <span>{assessment?.domain ?? 'No assessment'}</span>
                    <span>·</span>
                    <span>{fmtNumber(allPaths.length)} routes indexed</span>
                    <span>·</span>
                    <span>{fmtNumber(Object.keys(edgeCounts).length)} edge types</span>
                    {bookmarks.size > 0 && <><span>·</span><span className="text-yellow-400">{bookmarks.size} bookmarked</span></>}
                  </div>
                </div>
              </div>
            </div>
            <div className="flex items-center gap-2">
              <button onClick={() => exportCsv(filteredPaths)} disabled={!mounted || !filteredPaths.length}
                className="flex items-center gap-2 rounded-lg border border-white/10 bg-white/[.04] px-3 py-2 text-xs text-zinc-400 transition hover:text-zinc-200 disabled:opacity-30">
                <Download className="h-4 w-4" />CSV
              </button>
              <button onClick={() => exportPaths(filteredPaths)} disabled={!mounted || !filteredPaths.length}
                className="flex items-center gap-2 rounded-lg border border-white/10 bg-white/[.04] px-3 py-2 text-xs text-zinc-400 transition hover:text-zinc-200 disabled:opacity-30">
                <Download className="h-4 w-4" />JSON
              </button>
              <button onClick={() => computeMutation.mutate()} disabled={!mounted || computeMutation.isPending || !assessmentId}
                className="btn-primary gap-2 text-xs" style={{ padding: '0.58rem 1rem' }}>
                {computeMutation.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <RefreshCw className="h-4 w-4" />}
                {computeMutation.isPending ? 'Computing…' : 'Compute Paths'}
              </button>
            </div>
          </div>

          {/* auto-compute banner */}
          <AnimatePresence>
            {computeMutation.isPending && (
              <motion.div initial={{ opacity: 0, height: 0 }} animate={{ opacity: 1, height: 'auto' }} exit={{ opacity: 0, height: 0 }}
                className="flex items-center gap-3 rounded-lg border border-purple-500/30 bg-purple-500/10 px-4 py-3">
                <Loader2 className="h-4 w-4 animate-spin text-purple-300" />
                <span className="text-sm text-purple-200">Running graph analysis — computing all attack paths, choke points, and blast radius…</span>
              </motion.div>
            )}
            {computeMutation.isError && (
              <motion.div initial={{ opacity: 0, height: 0 }} animate={{ opacity: 1, height: 'auto' }} exit={{ opacity: 0, height: 0 }}
                className="flex items-center gap-3 rounded-lg border border-red-500/30 bg-red-500/10 px-4 py-3">
                <AlertTriangle className="h-4 w-4 text-red-300" />
                <span className="text-sm text-red-200">Path computation failed — check API connectivity and retry.</span>
              </motion.div>
            )}
            {computeMutation.isSuccess && allPaths.length === 0 && !loading && (
              <motion.div initial={{ opacity: 0, height: 0 }} animate={{ opacity: 1, height: 'auto' }} exit={{ opacity: 0, height: 0 }}
                className="flex items-center gap-3 rounded-lg border border-emerald-500/30 bg-emerald-500/10 px-4 py-3">
                <ShieldCheck className="h-4 w-4 text-emerald-300" />
                <span className="text-sm text-emerald-200">Analysis complete — no attack paths found. Domain posture is clean.</span>
              </motion.div>
            )}
          </AnimatePresence>

          {/* stat tiles */}
          <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-5">
            <StatTile label="Routes"   value={allPaths.length}              color="#818cf8" Icon={Swords}        sub={`${fmtNumber(filteredPaths.length)} visible`} pulse={computeMutation.isPending} />
            <StatTile label="Critical" value={criticalCount}                color="#ef4444" Icon={AlertTriangle} sub="score 85+" />
            <StatTile label="Avg Risk" value={avgRisk}                      color={avgRisk>=65?'#f97316':'#eab308'} Icon={Activity} sub="/ 100" />
            <StatTile label="Chokes"   value={chokes.length}                color="#a855f7" Icon={GitBranch}    sub="remediation pivots" />
            <StatTile label="Edges"    value={Object.keys(edgeCounts).length} color="#06b6d4" Icon={Layers3}   sub="abuse primitives" />
          </div>

          <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_330px]">
            <div className="space-y-4">
              {/* search + filter bar */}
              <div className="relative rounded-lg border border-white/10 bg-white/[.025] p-3">
                <div className="flex flex-wrap items-center gap-2">
                  <div className="relative min-w-[240px] flex-1">
                    <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-zinc-600" />
                    <input value={search} onChange={e => setSearch(e.target.value)}
                      placeholder="Search principals, targets, edges, MITRE IDs…"
                      className="h-10 w-full rounded-lg border border-white/10 bg-black pl-9 pr-3 text-sm text-zinc-100 outline-none transition placeholder:text-zinc-700 focus:border-purple-400/50" />
                    {search && <button onClick={() => setSearch('')} className="absolute right-3 top-1/2 -translate-y-1/2 text-zinc-600 hover:text-zinc-400"><X className="h-3.5 w-3.5" /></button>}
                  </div>
                  <div className="flex items-center gap-2 rounded-lg border border-white/10 bg-black px-3 py-2">
                    <Filter className="h-4 w-4 text-zinc-500" />
                    <select value={minRisk} onChange={e => setMinRisk(Number(e.target.value))} className="bg-transparent text-xs text-zinc-300 outline-none">
                      <option value={0}>All risk</option>
                      <option value={40}>Medium+</option>
                      <option value={65}>High+</option>
                      <option value={85}>Critical</option>
                    </select>
                  </div>
                  <div className="flex items-center gap-2 rounded-lg border border-white/10 bg-black px-3 py-2">
                    <ArrowDownWideNarrow className="h-4 w-4 text-zinc-500" />
                    <select value={sortMode} onChange={e => setSortMode(e.target.value as SortMode)} className="bg-transparent text-xs text-zinc-300 outline-none">
                      <option value="risk">Risk</option>
                      <option value="hops">Shortest</option>
                      <option value="source">Source</option>
                      <option value="target">Target</option>
                    </select>
                  </div>
                </div>
              </div>

              {/* category tabs */}
              <div className="flex gap-2 overflow-x-auto pb-1">
                {categoryTabs.map(tab => {
                  const Icon = tab.icon; const active = selectedCategory === tab.id
                  return (
                    <button key={tab.id} onClick={() => { setSelectedCategory(tab.id); setSelectedPath(null); setSimulation(undefined) }}
                      className="flex shrink-0 items-center gap-2 rounded-lg border px-3 py-2 text-xs font-semibold transition"
                      style={{ color: active ? tab.color : '#71717a', borderColor: active ? `${tab.color}66` : 'rgba(255,255,255,.08)', background: active ? `${tab.color}12` : 'rgba(255,255,255,.025)', boxShadow: active ? `0 0 28px ${tab.color}18` : undefined }}>
                      <Icon className="h-3.5 w-3.5" />
                      <span>{tab.name}</span>
                      <span className="rounded bg-white/[.06] px-1.5 py-0.5 text-[10px] tabular-nums">{fmtNumber(tab.count)}</span>
                    </button>
                  )
                })}
              </div>

              {/* path list + detail */}
              <div className="grid gap-4 lg:grid-cols-[minmax(360px,480px)_1fr]">
                <div className="max-h-[690px] space-y-2 overflow-y-auto pr-1">
                  {loading && (
                    <div className="flex items-center justify-center gap-2 rounded-lg border border-white/10 bg-white/[.02] py-12 text-sm text-zinc-500">
                      <Loader2 className="h-4 w-4 animate-spin" /> Loading attack graph…
                    </div>
                  )}
                  {!loading && filteredPaths.length === 0 && (
                    <div className="rounded-lg border border-white/10 bg-white/[.02] py-12 text-center">
                      <Swords className="mx-auto mb-3 h-9 w-9 text-zinc-700" />
                      <div className="text-sm font-semibold text-zinc-500">
                        {allPaths.length === 0 ? 'No paths computed yet' : 'No matching routes'}
                      </div>
                      {allPaths.length === 0 && !computeMutation.isPending && (
                        <button onClick={() => computeMutation.mutate()} disabled={!mounted || !assessmentId}
                          className="mt-4 rounded-lg border border-purple-400/30 bg-purple-500/10 px-4 py-2 text-xs font-bold uppercase tracking-widest text-purple-300 transition hover:bg-purple-500/20">
                          Run Analysis
                        </button>
                      )}
                    </div>
                  )}
                  <AnimatePresence mode="popLayout">
                    {filteredPaths.slice(0, 220).map((path, index) => (
                      <motion.div key={pathKey(path)} initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -6 }}
                        transition={{ delay: Math.min(index * 0.015, 0.18) }}>
                        <PathCard path={path} active={selectedPath ? pathKey(selectedPath) === pathKey(path) : false}
                          bookmarked={bookmarks.has(pathKey(path))}
                          onClick={() => { setSelectedPath(path); setSimulation(undefined) }}
                          onBookmark={(e) => toggleBookmark(path, e)} />
                      </motion.div>
                    ))}
                  </AnimatePresence>
                </div>

                <DetailPanel path={selectedPath} simulation={simulation} simulating={simulateMutation.isPending}
                  onSimulate={() => selectedPath && simulateMutation.mutate(selectedPath)} />
              </div>
            </div>

            {/* right sidebar */}
            <div className="space-y-4">
              <QuickWins paths={allPaths} />
              <EdgeMatrix edgeCounts={edgeCounts} selected={selectedEdge} onSelect={edge => { setSelectedEdge(edge); setSelectedPath(null) }} />
              <ChokePanel chokes={chokes} loading={chokeLoading} error={chokeError} />
              {assessmentId && <BlastPanel assessmentId={assessmentId} />}
            </div>
          </div>
        </div>
      </div>
    </AppShell>
  )
}
