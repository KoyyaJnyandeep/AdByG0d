'use client'

import { copyText } from '@/lib/clipboard'
import { useMemo, useState } from 'react'
import Link from 'next/link'
import { useMutation, useQuery, useQuery as usePEQuery } from '@tanstack/react-query'
import {
  Activity, AlertTriangle, ArrowRight, ChevronDown, ChevronRight,
  ExternalLink, Filter, Loader2, Network, RefreshCw, Search,
  Shield, ShieldAlert, Swords, Target, Zap,
  Copy, ChevronRight as PEChevR, Search as PESearch,
} from 'lucide-react'

import { AppShell } from '@/components/layout/AppShell'
import { adCommandsApi, findingsApi, graphApi } from '@/lib/api'
import { cn, fmtNumber } from '@/lib/utils'
import { useRouteAssessmentScope } from '@/lib/useRouteAssessmentScope'
import type { AttackPathEntry, ChokePoint, ExposurePath, Finding, PathStep } from '@/lib/types'
import { BackButton } from '@/components/ui/BackButton'

const SEV_COLOR: Record<string, string> = {
  CRITICAL: '#ff4d6d',
  HIGH:     '#ff8a3d',
  MEDIUM:   '#ffd166',
  LOW:      '#64748b',
}

const SEV_BG: Record<string, string> = {
  CRITICAL: 'rgba(255,77,109,.08)',
  HIGH:     'rgba(255,138,61,.08)',
  MEDIUM:   'rgba(255,209,102,.08)',
  LOW:      'rgba(100,116,139,.06)',
}

function sevStyle(sev: string) {
  return { color: SEV_COLOR[sev] ?? '#64748b', bg: SEV_BG[sev] ?? SEV_BG.LOW }
}

function SevBadge({ sev }: { sev: string }) {
  const { color, bg } = sevStyle(sev)
  return (
    <span className="border px-1.5 py-0.5 text-[9px] font-semibold uppercase tracking-[0.14em]"
      style={{ color, borderColor: `${color}30`, background: bg }}>
      {sev}
    </span>
  )
}

function PathCard({ path, index }: { path: ExposurePath | AttackPathEntry; index: number }) {
  const [open, setOpen] = useState(false)
  const sev: string = ('risk_level' in path && path.risk_level)
    ? path.risk_level
    : 'path_score' in path
      ? (path.path_score >= 8 ? 'CRITICAL' : path.path_score >= 6 ? 'HIGH' : path.path_score >= 4 ? 'MEDIUM' : 'LOW')
      : 'MEDIUM'
  const steps: PathStep[] = 'steps' in path ? (path.steps ?? []) : ('path_steps' in path ? (path.path_steps ?? []) : [])
  const hops = 'hop_count' in path ? path.hop_count : steps.length
  const score = 'path_score' in path ? path.path_score : 0
  const explanation = 'explanation' in path ? path.explanation : ''
  const mitre = ('mitre_attack_ids' in path && path.mitre_attack_ids) ? path.mitre_attack_ids : []
  const edgeTypes = ('edge_types' in path && path.edge_types) ? path.edge_types : []
  const { color } = sevStyle(sev)

  const srcLabel = ('source_label' in path ? path.source_label : '') ?? ''
  const tgtLabel = ('target_label' in path ? path.target_label : '') ?? ''

  return (
    <div className="border border-white/[0.07] bg-[#0a0a0a]" style={{ borderLeftColor: color, borderLeftWidth: 2 }}>
      <button
        onClick={() => setOpen(v => !v)}
        className="flex w-full items-start gap-3 px-4 py-3 text-left transition hover:bg-white/[0.02]"
      >
        <div className="mt-0.5 flex h-5 w-5 shrink-0 items-center justify-center border border-white/10 font-mono text-[9px] text-zinc-600">
          {index + 1}
        </div>
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <SevBadge sev={sev} />
            {score > 0 && (
              <span className="font-mono text-[10px] text-zinc-600">score {score.toFixed(1)}</span>
            )}
            {mitre.slice(0, 2).map(m => (
              <span key={m} className="border border-blue-500/20 px-1.5 py-0.5 font-mono text-[9px] text-blue-400">{m}</span>
            ))}
          </div>
          <div className="mt-1.5 flex items-center gap-1.5 text-xs">
            <span className="font-medium text-zinc-200">{srcLabel || 'Source'}</span>
            <ArrowRight className="h-3 w-3 shrink-0 text-zinc-600" />
            <span className="font-medium text-zinc-200">{tgtLabel || 'Target'}</span>
          </div>
          {explanation && (
            <p className="mt-1 text-[10px] leading-relaxed text-zinc-600 line-clamp-2">{explanation}</p>
          )}
        </div>
        <div className="flex shrink-0 flex-col items-end gap-1 text-[10px] text-zinc-600">
          <span>{hops} hop{hops !== 1 ? 's' : ''}</span>
          {open ? <ChevronDown className="h-3.5 w-3.5 text-zinc-500" /> : <ChevronRight className="h-3.5 w-3.5 text-zinc-700" />}
        </div>
      </button>

      {open && (
        <div className="border-t border-white/[0.06] px-4 pb-3 pt-2 space-y-2">
          {/* Edge types */}
          {edgeTypes.length > 0 && (
            <div className="flex flex-wrap gap-1">
              {edgeTypes.map(e => (
                <span key={e} className="border border-white/10 px-1.5 py-0.5 font-mono text-[9px] text-zinc-500">{e}</span>
              ))}
            </div>
          )}
          {/* Steps */}
          {steps.length > 0 && (
            <div className="space-y-1">
              {steps.map((step, si) => (
                <div key={si} className="flex items-start gap-2 text-[10px]">
                  <span className="mt-0.5 h-3.5 w-3.5 shrink-0 border border-white/10 flex items-center justify-center font-mono text-[8px] text-zinc-700">{si + 1}</span>
                  <div className="min-w-0">
                    <span className="font-medium text-zinc-300">{step.entity_label}</span>
                    {step.edge_type && <span className="ml-1.5 font-mono text-zinc-600">→ {step.edge_type}</span>}
                    {step.explanation && <div className="mt-0.5 text-zinc-600">{step.explanation}</div>}
                  </div>
                </div>
              ))}
            </div>
          )}
          {/* MITRE full */}
          {mitre.length > 0 && (
            <div className="flex flex-wrap gap-1 pt-1">
              {mitre.map(m => (
                <span key={m} className="border border-blue-500/20 bg-blue-500/5 px-2 py-0.5 font-mono text-[9px] text-blue-400">{m}</span>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  )
}

function ChokePointCard({ cp, rank }: { cp: ChokePoint; rank: number }) {
  const impact = cp.removal_impact?.elimination_pct ?? cp.elimination_pct ?? 0
  const impactColor = impact >= 50 ? '#ff4d6d' : impact >= 25 ? '#ff8a3d' : '#ffd166'

  return (
    <div className="flex items-start gap-3 border border-white/[0.07] bg-[#0a0a0a] px-4 py-3">
      <div className="flex h-7 w-7 shrink-0 items-center justify-center border border-white/10 font-mono text-[10px] text-zinc-600">
        {rank}
      </div>
      <div className="min-w-0 flex-1">
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-sm font-semibold text-zinc-100">{cp.label}</span>
          {cp.tier !== undefined && (
            <span className="border border-white/10 px-1.5 py-0.5 text-[9px] text-zinc-500">T{cp.tier}</span>
          )}
          <span className="border border-white/10 px-1.5 py-0.5 font-mono text-[9px] text-zinc-500">{cp.node_type}</span>
          {cp.is_articulation_point && (
            <span className="border border-red-500/25 bg-red-500/8 px-1.5 py-0.5 text-[9px] font-semibold text-red-400">articulation point</span>
          )}
        </div>
        <div className="mt-1.5 flex items-center gap-4 text-[10px] text-zinc-600">
          <span>{cp.paths_through} path{cp.paths_through !== 1 ? 's' : ''} through</span>
          {impact > 0 && (
            <span style={{ color: impactColor }}>{impact.toFixed(0)}% eliminated on removal</span>
          )}
          <span>score {cp.betweenness_score.toFixed(3)}</span>
        </div>
      </div>
    </div>
  )
}

function FindingCard({ finding }: { finding: Finding }) {
  const { color } = sevStyle(finding.severity)
  return (
    <div className="flex items-start gap-3 border border-white/[0.07] bg-[#0a0a0a] px-4 py-3"
      style={{ borderLeftColor: color, borderLeftWidth: 2 }}>
      <div className="min-w-0 flex-1">
        <div className="flex flex-wrap items-center gap-2">
          <SevBadge sev={finding.severity} />
          <span className="text-[10px] text-zinc-600">{finding.module}</span>
          {finding.mitre_attack_ids?.slice(0, 2).map(m => (
            <span key={m} className="border border-blue-500/20 px-1.5 py-0.5 font-mono text-[9px] text-blue-400">{m}</span>
          ))}
        </div>
        <div className="mt-1 text-xs font-semibold text-zinc-200">{finding.title}</div>
        {finding.description && (
          <p className="mt-0.5 line-clamp-2 text-[10px] leading-5 text-zinc-600">{finding.description}</p>
        )}
        {finding.affected_count > 0 && (
          <div className="mt-1 text-[10px] text-zinc-600">{finding.affected_count} affected object{finding.affected_count !== 1 ? 's' : ''}</div>
        )}
      </div>
      <Link href={`/findings?assessment_id=${finding.assessment_id}`}
        className="shrink-0 text-zinc-700 transition hover:text-zinc-300" title="View finding">
        <ExternalLink className="h-3.5 w-3.5" />
      </Link>
    </div>
  )
}

function FlowChainCard({ category, entry }: {
  category: string
  entry: AttackPathEntry
}) {
  const [open, setOpen] = useState(false)
  const { color } = sevStyle(entry.risk_level)

  return (
    <div className="border border-white/[0.07] bg-[#0a0a0a]" style={{ borderLeftColor: color, borderLeftWidth: 2 }}>
      <button onClick={() => setOpen(v => !v)}
        className="flex w-full items-start gap-3 px-4 py-3 text-left transition hover:bg-white/[0.02]">
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <SevBadge sev={entry.risk_level} />
            <span className="text-[10px] text-zinc-500">{category}</span>
            {entry.involves_delegation && <span className="border border-yellow-500/20 px-1.5 py-0.5 text-[9px] text-yellow-400">delegation</span>}
            {entry.involves_adcs && <span className="border border-purple-500/20 px-1.5 py-0.5 text-[9px] text-purple-400">ADCS</span>}
            {entry.crosses_trust && <span className="border border-cyan-500/20 px-1.5 py-0.5 text-[9px] text-cyan-400">cross-trust</span>}
            {entry.involves_credential_access && <span className="border border-red-500/20 px-1.5 py-0.5 text-[9px] text-red-400">cred access</span>}
          </div>
          <div className="mt-1.5 flex items-center gap-1.5 text-xs">
            <span className="font-medium text-zinc-200">{entry.source_label}</span>
            <ArrowRight className="h-3 w-3 shrink-0 text-zinc-600" />
            <span className="font-medium text-zinc-200">{entry.target_label}</span>
          </div>
          <p className="mt-0.5 line-clamp-2 text-[10px] leading-relaxed text-zinc-600">{entry.explanation}</p>
        </div>
        <div className="shrink-0 flex flex-col items-end gap-1 text-[10px] text-zinc-600">
          <span>{entry.hop_count} hops</span>
          {open ? <ChevronDown className="h-3.5 w-3.5 text-zinc-500" /> : <ChevronRight className="h-3.5 w-3.5 text-zinc-700" />}
        </div>
      </button>

      {open && entry.steps.length > 0 && (
        <div className="border-t border-white/[0.06] px-4 pb-3 pt-2 space-y-1.5">
          {entry.steps.map((step, si) => (
            <div key={si} className="flex items-start gap-2 text-[10px]">
              <span className="mt-0.5 h-3.5 w-3.5 shrink-0 border border-white/10 flex items-center justify-center font-mono text-[8px] text-zinc-700">{si + 1}</span>
              <div>
                <span className="font-medium text-zinc-300">{step.entity_label}</span>
                {step.edge_type && <span className="ml-1.5 font-mono text-zinc-600">→ {step.edge_type}</span>}
                {step.explanation && <div className="text-zinc-600">{step.explanation}</div>}
              </div>
            </div>
          ))}
          {entry.mitre_attack_ids && entry.mitre_attack_ids.length > 0 && (
            <div className="flex flex-wrap gap-1 pt-1">
              {entry.mitre_attack_ids.map(m => (
                <span key={m} className="border border-blue-500/20 bg-blue-500/5 px-2 py-0.5 font-mono text-[9px] text-blue-400">{m}</span>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  )
}

const PE_MONO = { fontFamily: 'JetBrains Mono, monospace' }
const PE_RISK_COLORS: Record<string, string> = { CRITICAL: '#ff4d6d', HIGH: '#ffa94d', MEDIUM: '#ffd166', LOW: '#51cf66' }

const PE_TABS = [
  { key: 'local',      label: 'Local PrivEsc',   color: '#f97316' },
  { key: 'kerberos',   label: 'Kerberos Abuse',  color: '#a78bfa' },
  { key: 'adcs',       label: 'ADCS ESC',        color: '#60a5fa' },
  { key: 'delegation', label: 'Delegation',      color: '#34d399' },
  { key: 'acl',        label: 'ACL Escalation',  color: '#fbbf24' },
  { key: 'rodc',       label: 'RODC Attacks',    color: '#ef4444' },
  { key: 'jea',        label: 'JEA Attacks',     color: '#f472b6' },
  { key: 'rbcd',       label: 'RBCD / MAQ',      color: '#fb923c' },
] as const

type PETabKey = typeof PE_TABS[number]['key']

const PE_IDS: Record<PETabKey, string[]> = {
  local:      ['lpe-unquoted-svc','lpe-weak-svc-perms','lpe-svc-bin-replace','lpe-dll-hijack','lpe-always-install-elevated','lpe-potato','lpe-printspoofer','lpe-godpotato','lpe-token-impersonation','lpe-backup-operators'],
  kerberos:   ['pe-kerberoast-crack','pe-asrep-roast','pe-s4u2self-abuse','pe-unconstrained-privesc','pe-constrained-abuse','pe-rbcd-privesc','pe-silver-ticket-pe','pe-golden-ticket-pe','pe-nopac','pe-samaccountname-spoof'],
  adcs:       ['pe-esc1-san','pe-esc2-any-purpose','pe-esc3-enrollment-agent','pe-esc4-template-write','pe-esc6-flag-disable','pe-esc7-officer','pe-esc8-relay','pe-esc9-no-security','pe-golden-cert-pe','pe-shadow-cred-pe'],
  delegation: ['pe-unconstrained-dump','pe-unconstrained-coerce','pe-constrained-s4u','pe-rbcd-add','pe-rbcd-exploit','pe-resource-based','pe-delegation-enum','pe-delegation-cross-domain','pe-delegation-msds-allowedto','pe-delegation-self-s4u'],
  acl:        ['pe-acl-genericall-user','pe-acl-genericall-group','pe-acl-forcechangepassword','pe-acl-writedacl','pe-acl-addself','pe-acl-addmember','pe-acl-generic-write','pe-acl-ds-replication','pe-acl-aclpwn','pe-acl-targetedkerberoast'],
  rodc:       ['rodc-enum','rodc-krbtgt-dump','rodc-reveal-accounts','rodc-allow-list','rodc-cache-enum','rodc-ticket-forge','rodc-privesc-path','rodc-coerce','rodc-silver-ticket','rodc-golden-rodc'],
  jea:        ['jea-enum-endpoints','jea-enum-roles','jea-bypass-constrained','jea-bypass-commands','jea-abuse-role','jea-runspace-escape','jea-script-execution','jea-module-abuse','jea-dsregcmd','jea-mitigate'],
  rbcd:       ['rbcd-enum','rbcd-add-computer','rbcd-set-msds','rbcd-s4u-exploit','rbcd-from-writedacl','rbcd-from-genericall','maq-enum','maq-add-computer','maq-abuse-spn','maq-rbcd-chain'],
}

type PETech = { id: string; title: string; tool: string; risk_level: string; mitre_technique_id: string; description: string; commands: { label: string; command: string; params: string[] }[] }

function PETechCard({ tech, isOpen, onToggle }: { tech: PETech; isOpen: boolean; onToggle: () => void }) {
  const rColor = PE_RISK_COLORS[tech.risk_level.toUpperCase()] ?? '#64748b'
  return (
    <div className="rounded-xl border border-white/5 bg-white/[0.02] hover:border-white/10 transition-colors">
      <button className="flex w-full items-center gap-3 px-4 py-3 text-left" onClick={onToggle}>
        <PEChevR className={cn('h-3.5 w-3.5 text-zinc-600 transition-transform', isOpen && 'rotate-90')} />
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2">
            <span className="text-sm font-medium text-zinc-200">{tech.title}</span>
            <span className="rounded border px-1.5 py-0.5 text-[9px] font-bold uppercase" style={{ color: rColor, borderColor: `${rColor}30`, background: `${rColor}10` }}>{tech.risk_level}</span>
          </div>
          <div className="flex items-center gap-2 mt-0.5">
            <span className="text-[10px] text-zinc-600" style={PE_MONO}>{tech.tool}</span>
            <span className="text-[10px] text-zinc-700">·</span>
            <span className="text-[10px] text-zinc-600" style={PE_MONO}>{tech.mitre_technique_id}</span>
          </div>
        </div>
      </button>
      {isOpen && (
        <div className="border-t border-white/5 px-4 pb-4 pt-3 space-y-3">
          <p className="text-[11px] text-zinc-400">{tech.description}</p>
          {tech.commands.map(cmd => (
            <div key={cmd.label} className="rounded-lg border border-white/5 bg-black/40 p-3">
              <div className="flex items-center justify-between mb-2">
                <span className="text-[10px] font-semibold text-zinc-300">{cmd.label}</span>
                <button onClick={() => copyText(cmd.command)} className="flex items-center gap-1 rounded border border-white/10 px-2 py-0.5 text-[9px] text-zinc-500 hover:text-cyan-400 hover:border-cyan-500/30 transition-colors"><Copy className="h-2.5 w-2.5" />copy</button>
              </div>
              <pre className="text-[10px] text-emerald-400 whitespace-pre-wrap break-all" style={PE_MONO}>{cmd.command}</pre>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

function PrivEscTechniqueBrowser() {
  const [activeTab, setActiveTab] = useState<PETabKey>('local')
  const [openId, setOpenId] = useState<string | null>(null)
  const [search, setSearch] = useState('')
  const ids = PE_IDS[activeTab]
  const { data: techniques = [], isLoading } = usePEQuery({
    queryKey: ['ad-commands', 'priv-esc', activeTab],
    queryFn: () => adCommandsApi.list<PETech>({ ids: ids.join(',') }),
    staleTime: 5 * 60 * 1000,
  })
  const visible = techniques.filter(t => !search || t.title.toLowerCase().includes(search.toLowerCase()))
  const tab = PE_TABS.find(t => t.key === activeTab)!
  return (
    <div className="space-y-4 border border-white/[0.07] bg-[#0a0a0a] p-6 mt-4">
      <h2 className="text-lg font-bold text-white">Technique Browser</h2>
      <div className="flex flex-wrap gap-2">
        {PE_TABS.map(({ key, label, color }) => (
          <button key={key} onClick={() => { setActiveTab(key); setOpenId(null); setSearch('') }}
            className={cn('rounded-xl border px-4 py-2 text-sm font-medium transition-all', activeTab === key ? 'border-transparent text-black' : 'border-white/10 text-zinc-500 hover:border-white/20 hover:text-zinc-300 bg-white/[0.02]')}
            style={activeTab === key ? { background: color } : {}}>{label}</button>
        ))}
      </div>
      <div className="relative">
        <PESearch className="absolute left-3 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-zinc-600" />
        <input value={search} onChange={e => setSearch(e.target.value)} placeholder={`Search ${tab.label}…`}
          className="w-full rounded-xl border border-white/10 bg-white/[0.03] py-2.5 pl-9 pr-4 text-sm text-zinc-200 outline-none placeholder:text-zinc-600 focus:border-white/20" />
      </div>
      {isLoading ? <div className="py-12 text-center text-zinc-600 text-sm">Loading…</div> : (
        <div className="space-y-2">
          {visible.length === 0 && <div className="py-12 text-center text-sm text-zinc-600">No techniques found</div>}
          {visible.map(tech => <PETechCard key={tech.id} tech={tech} isOpen={openId === tech.id} onToggle={() => setOpenId(openId === tech.id ? null : tech.id)} />)}
        </div>
      )}
    </div>
  )
}

type Tab = 'paths' | 'choke-points' | 'findings' | 'attack-chains'

export default function PrivEscMappingPage() {
  const [tab, setTab] = useState<Tab>('paths')
  const [search, setSearch] = useState('')
  const [sevFilter, setSevFilter] = useState<string>('all')

  const { assessment, isScopeLoading } = useRouteAssessmentScope()
  const assessmentId = assessment?.id ?? null

  // ── Data fetching ──────────────────────────────────────────────────────────

  const { data: pathsData, isLoading: pathsLoading, refetch: refetchPaths } = useQuery({
    queryKey: ['priv-esc-paths', assessmentId],
    queryFn: async () => {
      const raw = await graphApi.getPaths(assessmentId!, { max_paths: 200 })
      return raw
    },
    enabled: !!assessmentId && tab === 'paths',
    staleTime: 60_000,
  })

  const { data: chokeData, isLoading: chokeLoading, isError: chokeError, refetch: refetchChoke } = useQuery({
    queryKey: ['priv-esc-choke', assessmentId],
    queryFn: () => graphApi.getChokePoints(assessmentId!),
    enabled: !!assessmentId && tab === 'choke-points',
    staleTime: 60_000,
  })

  const { data: findingsData, isLoading: findingsLoading } = useQuery({
    queryKey: ['priv-esc-findings', assessmentId],
    queryFn: () => findingsApi.list({ assessment_id: assessmentId!, severity: ['CRITICAL', 'HIGH', 'MEDIUM'], page_size: 100 }),
    enabled: !!assessmentId && tab === 'findings',
    staleTime: 60_000,
  })

  const { data: flowChains, isLoading: chainsLoading } = useQuery({
    queryKey: ['priv-esc-chains'],
    queryFn: () => graphApi.getAttackFlowChains(),
    staleTime: 300_000,
    enabled: tab === 'attack-chains',
  })

  const { data: categoriesData } = useQuery({
    queryKey: ['priv-esc-categories', assessmentId],
    queryFn: () => graphApi.getCategories(assessmentId!),
    enabled: !!assessmentId,
    staleTime: 60_000,
  })

  const computeMutation = useMutation({
    mutationFn: () => graphApi.computePaths(assessmentId!),
    onSuccess: () => refetchPaths(),
  })

  // ── Derived data ───────────────────────────────────────────────────────────

  const paths = useMemo(() => {
    const all = pathsData ?? []
    const q = search.trim().toLowerCase()
    return all.filter(p => {
      if (sevFilter !== 'all') {
        const pSev = 'risk_level' in p ? p.risk_level
          : p.path_score >= 8 ? 'CRITICAL' : p.path_score >= 6 ? 'HIGH' : p.path_score >= 4 ? 'MEDIUM' : 'LOW'
        if (pSev !== sevFilter) return false
      }
      if (!q) return true
      const text = [
        'source_label' in p ? p.source_label : '',
        'target_label' in p ? p.target_label : '',
        'explanation' in p ? p.explanation : '',
        ...('path_steps' in p ? p.path_steps.map((s: PathStep) => s.entity_label) : []),
      ].join(' ').toLowerCase()
      return text.includes(q)
    })
  }, [pathsData, search, sevFilter])

  const chokePoints = chokeData?.choke_points ?? []

  const privEscFindings = useMemo(() => {
    const all = findingsData?.items ?? []
    const q = search.trim().toLowerCase()
    return all.filter(f => {
      if (sevFilter !== 'all' && f.severity !== sevFilter) return false
      if (!q) return true
      return [f.title, f.module, f.description ?? '', f.finding_type].join(' ').toLowerCase().includes(q)
    })
  }, [findingsData, search, sevFilter])

  const chainEntries = useMemo(() => {
    if (!flowChains) return []
    const entries: Array<{ category: string; entry: AttackPathEntry }> = []
    for (const [cat, data] of Object.entries(flowChains.categories ?? {})) {
      for (const e of data.paths ?? []) {
        entries.push({ category: cat, entry: e })
      }
    }
    // also top-level paths
    for (const e of flowChains.paths ?? []) {
      entries.push({ category: e.category ?? 'General', entry: e })
    }
    const q = search.trim().toLowerCase()
    return entries.filter(({ category, entry }) => {
      if (sevFilter !== 'all' && entry.risk_level !== sevFilter) return false
      if (!q) return true
      return [category, entry.source_label, entry.target_label, entry.explanation].join(' ').toLowerCase().includes(q)
    })
  }, [flowChains, search, sevFilter])

  // ── Stat counts ────────────────────────────────────────────────────────────

  const critPaths = (pathsData ?? []).filter(p => {
    const s = 'risk_level' in p ? p.risk_level : p.path_score >= 8 ? 'CRITICAL' : ''
    return s === 'CRITICAL'
  }).length

  const critFindings = (findingsData?.items ?? []).filter(f => f.severity === 'CRITICAL').length
  const articulationPoints = chokePoints.filter(cp => cp.is_articulation_point).length

  // ── Tabs ───────────────────────────────────────────────────────────────────

  const tabs: Array<{ id: Tab; label: string; icon: React.ElementType; count?: number }> = [
    { id: 'paths',         label: 'Priv Esc Paths',   icon: Swords,     count: pathsData?.length },
    { id: 'choke-points',  label: 'Choke Points',     icon: Target,     count: chokePoints.length },
    { id: 'findings',      label: 'Findings',         icon: ShieldAlert, count: findingsData?.total },
    { id: 'attack-chains', label: 'Attack Chains',    icon: Network,    count: chainEntries.length },
  ]

  return (
    <AppShell>
      <div className="min-h-full bg-transparent p-4 text-zinc-100 sm:p-6">
        <div className="mx-auto max-w-7xl space-y-4">

          <BackButton />
          {/* Header */}
          <div className="flex flex-wrap items-start justify-between gap-4">
            <div>
              <div className="flex items-center gap-2">
                <Swords className="h-4 w-4 text-zinc-500" />
                <h1 className="text-[11px] font-semibold uppercase tracking-[0.18em] text-zinc-400">Privilege Escalation Mapping</h1>
              </div>
              <p className="mt-1 text-xs text-zinc-600">
                {assessment
                  ? <span>Assessment: <span className="text-zinc-400">{assessment.domain}</span> · <span className="text-zinc-500">{assessment.name}</span></span>
                  : isScopeLoading
                    ? <span className="text-zinc-600">Loading assessment scope...</span>
                    : <span className="text-amber-500/80">No assessment selected — showing static attack chain library</span>
                }
              </p>
            </div>
            <div className="flex items-center gap-2">
              {assessmentId && (
                <button
                  onClick={() => computeMutation.mutate()}
                  disabled={computeMutation.isPending}
                  className="flex items-center gap-1.5 border border-white/[0.07] px-3 py-1.5 text-[10px] font-semibold text-zinc-500 transition hover:border-white/15 hover:text-zinc-200 disabled:opacity-40"
                >
                  {computeMutation.isPending
                    ? <><Loader2 className="h-3.5 w-3.5 animate-spin" /> Computing...</>
                    : <><RefreshCw className="h-3.5 w-3.5" /> Compute Paths</>}
                </button>
              )}
              <Link href="/assessments"
                className="flex items-center gap-1.5 border border-indigo-500/25 bg-indigo-500/8 px-3 py-1.5 text-[10px] font-semibold text-indigo-300 transition hover:border-indigo-500/45">
                <Activity className="h-3.5 w-3.5" /> Assessments
              </Link>
            </div>
          </div>

          {/* KPI row */}
          <div className="grid grid-cols-2 gap-2 md:grid-cols-4">
            {[
              { label: 'Total Paths',        value: pathsData?.length ?? 0,       color: '#818cf8' },
              { label: 'Critical Paths',     value: critPaths,                     color: '#ff4d6d' },
              { label: 'Critical Findings',  value: critFindings,                  color: '#ff8a3d' },
              { label: 'Choke Points',       value: articulationPoints,            color: '#22d3ee' },
            ].map(({ label, value, color }) => (
              <div key={label} className="flex flex-col gap-3 border border-white/[0.07] bg-[#0a0a0a] p-4">
                <span className="text-[10px] font-semibold uppercase tracking-[0.16em] text-zinc-600">{label}</span>
                <span className="font-mono text-3xl font-bold tabular-nums" style={{ color }}>{fmtNumber(value)}</span>
              </div>
            ))}
          </div>

          {/* Category summary (when assessment loaded) */}
          {categoriesData && Object.keys(categoriesData.categories).length > 0 && (
            <div className="flex flex-wrap gap-2">
              {Object.entries(categoriesData.categories).map(([key, cat]) => (
                <div key={key} className="flex items-center gap-2 border border-white/[0.07] bg-[#0a0a0a] px-3 py-2">
                  <span className="h-2 w-2 rounded-full" style={{ background: cat.color || '#818cf8' }} />
                  <span className="text-[10px] text-zinc-400">{cat.name}</span>
                  <span className="font-mono text-[10px] text-zinc-600">{cat.count}</span>
                </div>
              ))}
            </div>
          )}

          {/* Compute paths hint */}
          {computeMutation.data && (
            <div className="border border-emerald-500/20 bg-emerald-500/5 px-4 py-2 text-xs text-emerald-300">
              Computed {computeMutation.data.paths_computed} paths.{' '}
              {computeMutation.data.warning_count ? `${computeMutation.data.warning_count} warnings.` : ''}
            </div>
          )}
          {computeMutation.isError && (
            <div className="border border-red-500/20 bg-red-500/5 px-4 py-2 text-xs text-red-300">
              Failed to compute paths. Check that graph data has been ingested first.
            </div>
          )}

          {/* Tabs + filters */}
          <div className="border border-white/[0.07] bg-[#0a0a0a]">
            <div className="flex flex-wrap items-center gap-0 border-b border-white/[0.07]">
              {tabs.map(t => (
                <button key={t.id} onClick={() => setTab(t.id)}
                  className={cn(
                    'flex items-center gap-1.5 border-b-2 px-4 py-3 text-[11px] font-semibold transition -mb-px',
                    tab === t.id
                      ? 'border-indigo-400 text-indigo-300'
                      : 'border-transparent text-zinc-600 hover:text-zinc-300'
                  )}>
                  <t.icon className="h-3.5 w-3.5" />
                  {t.label}
                  {t.count !== undefined && t.count > 0 && (
                    <span className={cn('border px-1 py-0.5 font-mono text-[9px]',
                      tab === t.id ? 'border-indigo-500/35 text-indigo-400' : 'border-white/[0.07] text-zinc-700')}>
                      {t.count}
                    </span>
                  )}
                </button>
              ))}
            </div>

            {/* Search + sev filter */}
            <div className="flex flex-wrap items-center gap-2 border-b border-white/[0.07] p-3">
              <div className="relative flex-1 min-w-48">
                <Search className="absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-zinc-600" />
                <input
                  value={search}
                  onChange={e => setSearch(e.target.value)}
                  placeholder="Search paths, labels, techniques..."
                  className="h-9 w-full border border-white/[0.07] bg-black pl-9 pr-3 text-xs text-zinc-200 outline-none transition focus:border-white/15"
                />
              </div>
              <div className="flex items-center gap-1">
                <Filter className="h-3 w-3 text-zinc-600" />
                {['all', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map(s => (
                  <button key={s} onClick={() => setSevFilter(s)}
                    className={cn('border px-2.5 py-1.5 text-[9px] font-semibold uppercase tracking-[0.14em] transition',
                      sevFilter === s
                        ? s === 'all' ? 'border-white/20 text-zinc-200' : ''
                        : 'border-white/[0.07] text-zinc-600 hover:text-zinc-300'
                    )}
                    style={sevFilter === s && s !== 'all' ? {
                      borderColor: `${SEV_COLOR[s]}35`,
                      color: SEV_COLOR[s],
                      background: SEV_BG[s],
                    } : undefined}
                  >
                    {s === 'all' ? 'All' : s}
                  </button>
                ))}
              </div>
            </div>

            {/* Tab content */}
            <div className="p-3 space-y-2">

              {/* ── Paths tab ─────────────────────────────────────────── */}
              {tab === 'paths' && (
                <>
                  {!assessmentId ? (
                    <div className="flex flex-col items-center gap-3 py-12 text-center">
                      <Swords className="h-8 w-8 text-zinc-700" />
                      <div className="text-sm font-semibold text-zinc-500">No assessment selected</div>
                      <p className="max-w-sm text-xs text-zinc-600">
                        Select a completed assessment to see real privilege escalation paths computed from your graph data.
                        Click &quot;Compute Paths&quot; to generate paths from ingested graph data.
                      </p>
                      <Link href="/assessments" className="flex items-center gap-1.5 border border-indigo-500/25 bg-indigo-500/8 px-4 py-2 text-xs font-semibold text-indigo-300 transition hover:border-indigo-500/45">
                        Go to Assessments
                      </Link>
                    </div>
                  ) : pathsLoading ? (
                    <div className="flex items-center gap-2 py-10 text-xs text-zinc-600">
                      <Loader2 className="h-4 w-4 animate-spin text-indigo-400" /> Loading paths...
                    </div>
                  ) : paths.length === 0 ? (
                    <div className="flex flex-col items-center gap-3 py-12 text-center">
                      <Target className="h-8 w-8 text-zinc-700" />
                      <div className="text-sm font-semibold text-zinc-500">No privilege escalation paths found</div>
                      <p className="max-w-sm text-xs text-zinc-600">
                        Paths are computed from graph data. Click &quot;Compute Paths&quot; to generate them from ingested data, or ingest graph data first.
                      </p>
                      <button
                        onClick={() => computeMutation.mutate()}
                        disabled={computeMutation.isPending}
                        className="flex items-center gap-1.5 border border-indigo-500/25 bg-indigo-500/8 px-4 py-2 text-xs font-semibold text-indigo-300 transition hover:border-indigo-500/45 disabled:opacity-40"
                      >
                        {computeMutation.isPending ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Zap className="h-3.5 w-3.5" />}
                        Compute Paths
                      </button>
                    </div>
                  ) : (
                    <>
                      <div className="mb-2 text-[10px] text-zinc-600">
                        <span className="text-zinc-400">{paths.length}</span> path{paths.length !== 1 ? 's' : ''}
                        {sevFilter !== 'all' && <span> · filtered to {sevFilter}</span>}
                      </div>
                      {paths.map((p, i) => <PathCard key={`path-${i}`} path={p} index={i} />)}
                    </>
                  )}
                </>
              )}

              {/* ── Choke Points tab ──────────────────────────────────── */}
              {tab === 'choke-points' && (
                <>
                  {!assessmentId ? (
                    <div className="flex flex-col items-center gap-3 py-12 text-center">
                      <Target className="h-8 w-8 text-zinc-700" />
                      <div className="text-sm font-semibold text-zinc-500">No assessment selected</div>
                      <p className="text-xs text-zinc-600">Choke points are computed from your graph topology.</p>
                    </div>
                  ) : chokeLoading ? (
                    <div className="flex items-center gap-2 py-10 text-xs text-zinc-600">
                      <Loader2 className="h-4 w-4 animate-spin text-indigo-400" /> Loading choke points...
                    </div>
                  ) : chokeError ? (
                    <div className="flex flex-col items-center gap-3 py-12 text-zinc-500">
                      <AlertTriangle className="h-8 w-8 text-red-400/60" />
                      <p className="text-sm">Failed to load choke points</p>
                      <button
                        onClick={() => refetchChoke()}
                        className="flex items-center gap-1.5 rounded border border-zinc-700 px-3 py-1.5 text-xs text-zinc-400 hover:border-zinc-500 hover:text-zinc-300"
                      >
                        <RefreshCw className="h-3 w-3" /> Retry
                      </button>
                    </div>
                  ) : chokePoints.length === 0 ? (
                    <div className="flex flex-col items-center gap-3 py-12 text-center">
                      <Target className="h-8 w-8 text-zinc-700" />
                      <div className="text-sm font-semibold text-zinc-500">No choke points found</div>
                      <p className="text-xs text-zinc-600">Compute attack paths first to identify high-value bottleneck nodes.</p>
                      <button onClick={() => computeMutation.mutate()} disabled={computeMutation.isPending}
                        className="flex items-center gap-1.5 border border-indigo-500/25 bg-indigo-500/8 px-4 py-2 text-xs font-semibold text-indigo-300 transition hover:border-indigo-500/45 disabled:opacity-40">
                        {computeMutation.isPending ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Zap className="h-3.5 w-3.5" />}
                        Compute Paths
                      </button>
                    </div>
                  ) : (
                    <>
                      <div className="mb-2 text-[10px] text-zinc-600">
                        <span className="text-zinc-400">{chokePoints.length}</span> choke point{chokePoints.length !== 1 ? 's' : ''} ·
                        {' '}<span className="text-zinc-400">{articulationPoints}</span> articulation points
                      </div>
                      {chokePoints
                        .filter(cp => !search || cp.label.toLowerCase().includes(search.toLowerCase()))
                        .sort((a, b) => b.betweenness_score - a.betweenness_score)
                        .map((cp, i) => <ChokePointCard key={cp.node_id} cp={cp} rank={i + 1} />)}
                    </>
                  )}
                </>
              )}

              {/* ── Findings tab ──────────────────────────────────────── */}
              {tab === 'findings' && (
                <>
                  {!assessmentId ? (
                    <div className="flex flex-col items-center gap-3 py-12 text-center">
                      <ShieldAlert className="h-8 w-8 text-zinc-700" />
                      <div className="text-sm font-semibold text-zinc-500">No assessment selected</div>
                      <p className="text-xs text-zinc-600">Select an assessment to view privilege escalation findings.</p>
                    </div>
                  ) : findingsLoading ? (
                    <div className="flex items-center gap-2 py-10 text-xs text-zinc-600">
                      <Loader2 className="h-4 w-4 animate-spin text-indigo-400" /> Loading findings...
                    </div>
                  ) : privEscFindings.length === 0 ? (
                    <div className="flex flex-col items-center gap-3 py-12 text-center">
                      <Shield className="h-8 w-8 text-zinc-700" />
                      <div className="text-sm font-semibold text-zinc-500">No findings match</div>
                      <p className="text-xs text-zinc-600">Run a collection or import graph data to generate findings.</p>
                      <Link href={`/findings?assessment_id=${assessmentId}`}
                        className="flex items-center gap-1.5 border border-indigo-500/25 bg-indigo-500/8 px-4 py-2 text-xs font-semibold text-indigo-300 transition hover:border-indigo-500/45">
                        <ExternalLink className="h-3.5 w-3.5" /> View All Findings
                      </Link>
                    </div>
                  ) : (
                    <>
                      <div className="mb-2 flex items-center justify-between text-[10px] text-zinc-600">
                        <span><span className="text-zinc-400">{privEscFindings.length}</span> finding{privEscFindings.length !== 1 ? 's' : ''}</span>
                        <Link href={`/findings?assessment_id=${assessmentId}`}
                          className="flex items-center gap-1 text-indigo-400 transition hover:text-indigo-300">
                          View all <ExternalLink className="h-3 w-3" />
                        </Link>
                      </div>
                      {privEscFindings.map(f => <FindingCard key={f.id} finding={f} />)}
                    </>
                  )}
                </>
              )}

              {/* ── Attack Chains tab ──────────────────────────────────── */}
              {tab === 'attack-chains' && (
                <>
                  {chainsLoading ? (
                    <div className="flex items-center gap-2 py-10 text-xs text-zinc-600">
                      <Loader2 className="h-4 w-4 animate-spin text-indigo-400" /> Loading attack chains...
                    </div>
                  ) : chainEntries.length === 0 ? (
                    <div className="flex flex-col items-center gap-3 py-12 text-center">
                      <Network className="h-8 w-8 text-zinc-700" />
                      <div className="text-sm font-semibold text-zinc-500">No attack chains available</div>
                      <p className="text-xs text-zinc-600">Attack flow chains are static reference paths from the AD attack architecture library.</p>
                    </div>
                  ) : (
                    <>
                      <div className="mb-2 text-[10px] text-zinc-600">
                        <span className="text-zinc-400">{chainEntries.length}</span> attack chain{chainEntries.length !== 1 ? 's' : ''}
                        {' '}across {new Set(chainEntries.map(e => e.category)).size} categories
                      </div>
                      {chainEntries.map(({ category, entry }, i) => (
                        <FlowChainCard key={`chain-${i}`} category={category} entry={entry} />
                      ))}
                    </>
                  )}
                </>
              )}
            </div>
          </div>

          {/* No-data guidance */}
          {assessmentId && !isScopeLoading && assessment?.status !== 'COMPLETED' && (
            <div className="flex items-start gap-2 border border-amber-500/15 bg-amber-500/[0.04] px-4 py-3 text-xs text-amber-300/70">
              <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0 text-amber-400/60" />
              Assessment status: <span className="font-semibold">{assessment?.status}</span>.
              Privilege escalation paths require a completed collection. Run the assessment to completion first.
            </div>
          )}

          <PrivEscTechniqueBrowser />
        </div>
      </div>
    </AppShell>
  )
}
