'use client'

import { useState } from 'react'
import { useQuery, useQuery as useTechQuery } from '@tanstack/react-query'
import {
  Activity, AlertTriangle, ChevronDown, ChevronRight,
  Crosshair, Loader2, Network, RefreshCw, Swords, Zap,
  Search as SearchIcon,
} from 'lucide-react'
import { AppShell } from '@/components/layout/AppShell'
import { adCommandsApi, lateralMovementApi } from '@/lib/api'
import { useRouteAssessmentScope } from '@/lib/useRouteAssessmentScope'
import { cn, fmtNumber } from '@/lib/utils'
import type { LMChain, LMPath, LMTechnique } from '@/lib/types'
import { AttackTechCard } from '@/components/ui/AttackTechCard'

const SEV_COLOR: Record<string, string> = {
  CRITICAL: '#ff4d6d',
  HIGH:     '#ff8a3d',
  MEDIUM:   '#ffd166',
  LOW:      '#64748b',
}

function SevBadge({ severity }: { severity: string }) {
  const color = SEV_COLOR[severity] ?? SEV_COLOR.LOW
  return (
    <span
      className="rounded-full border px-2.5 py-0.5 text-[10px] font-bold uppercase tracking-wide"
      style={{ color, borderColor: `${color}40`, background: `${color}12` }}
    >
      {severity}
    </span>
  )
}

function ErrorCard({ message, onRetry }: { message: string; onRetry: () => void }) {
  return (
    <div className="flex flex-col items-center gap-3 py-12 text-zinc-500">
      <AlertTriangle className="h-8 w-8 text-red-400/60" />
      <p className="text-sm">{message}</p>
      <button
        onClick={onRetry}
        className="flex items-center gap-1.5 rounded border border-zinc-700 px-3 py-1.5 text-xs text-zinc-400 hover:border-zinc-500 hover:text-zinc-300"
      >
        <RefreshCw className="h-3 w-3" /> Retry
      </button>
    </div>
  )
}

function TechniqueCard({ tech }: { tech: LMTechnique }) {
  const [open, setOpen] = useState(false)
  return (
    <div className="rounded-[18px] border border-white/10 bg-black p-4">
      <button
        type="button"
        onClick={() => setOpen(v => !v)}
        className="flex w-full items-start gap-3 text-left"
      >
        <Crosshair className="mt-0.5 h-4 w-4 shrink-0 text-orange-400" />
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <span className="font-medium text-white">{tech.name}</span>
            <SevBadge severity={tech.severity} />
            {tech.mitre_id && (
              <code className="rounded bg-zinc-800 px-1.5 py-0.5 text-[10px] text-zinc-400">{tech.mitre_id}</code>
            )}
            {tech.tier > 0 && (
              <span className="text-[10px] text-zinc-500">Tier {tech.tier}</span>
            )}
          </div>
        </div>
        {open ? <ChevronDown className="h-4 w-4 shrink-0 text-zinc-500" /> : <ChevronRight className="h-4 w-4 shrink-0 text-zinc-500" />}
      </button>
      {open && tech.attack_steps.length > 0 && (
        <ol className="mt-3 ml-7 space-y-1.5">
          {tech.attack_steps.map((step, i) => (
            <li key={i} className="text-xs text-zinc-400">
              <span className="mr-2 text-zinc-600">{i + 1}.</span>{step}
            </li>
          ))}
        </ol>
      )}
    </div>
  )
}

function ChainCard({ chain }: { chain: LMChain }) {
  return (
    <div className="rounded-[18px] border border-white/10 bg-black p-4">
      <div className="flex flex-wrap items-center gap-3">
        <Swords className="h-4 w-4 shrink-0 text-red-400" />
        <span className="font-medium text-white">{chain.name}</span>
        <SevBadge severity={chain.severity} />
      </div>
      {chain.techniques.length > 0 && (
        <p className="mt-2 ml-7 text-xs text-zinc-500">{chain.techniques.join(' → ')}</p>
      )}
      {chain.mitre_ids.length > 0 && (
        <div className="mt-2 ml-7 flex flex-wrap gap-1">
          {chain.mitre_ids.map(id => (
            <code key={id} className="rounded bg-zinc-800 px-1.5 py-0.5 text-[10px] text-zinc-400">{id}</code>
          ))}
        </div>
      )}
    </div>
  )
}

function PathCard({ path }: { path: LMPath }) {
  const [open, setOpen] = useState(false)
  const src = path.steps[0]?.source_label ?? 'Unknown'
  const dst = path.steps[path.steps.length - 1]?.target_label ?? 'Unknown'
  return (
    <div className="rounded-[18px] border border-white/10 bg-black p-4">
      <button type="button" onClick={() => setOpen(v => !v)} className="flex w-full items-center gap-3 text-left">
        <Network className="h-4 w-4 shrink-0 text-cyan-400" />
        <span className="min-w-0 flex-1 truncate text-sm text-white">
          <span className="font-mono">{src}</span>
          <span className="mx-2 text-zinc-600">→</span>
          <span className="font-mono">{dst}</span>
        </span>
        <span className="shrink-0 text-[10px] text-zinc-500">{path.hop_count} hop{path.hop_count !== 1 ? 's' : ''}</span>
        {open ? <ChevronDown className="h-4 w-4 shrink-0 text-zinc-500" /> : <ChevronRight className="h-4 w-4 shrink-0 text-zinc-500" />}
      </button>
      {open && (
        <ol className="mt-3 ml-7 space-y-1.5">
          {path.steps.map((step, i) => (
            <li key={i} className="flex items-center gap-2 text-xs text-zinc-400">
              <span className="font-mono text-zinc-300">{step.source_label ?? step.source_id ?? '?'}</span>
              {step.edge_type && <code className="rounded bg-zinc-800 px-1 text-[10px] text-zinc-500">{step.edge_type}</code>}
              <span className="text-zinc-600">→</span>
              <span className="font-mono text-zinc-300">{step.target_label ?? step.target_id ?? '?'}</span>
            </li>
          ))}
        </ol>
      )}
    </div>
  )
}

const LM_TABS = [
  { key: 'netexec', label: 'NetExec / NXC', color: '#60a5fa' },
  { key: 'mssql',   label: 'MSSQL Lateral', color: '#22d3ee' },
  { key: 'sccm',    label: 'SCCM / MECM',  color: '#fbbf24' },
  { key: 'coerce',   label: 'Coercion',        color: '#f472b6' },
  { key: 'rubeus',   label: 'Rubeus',          color: '#a78bfa' },
  { key: 'password', label: 'Password Attacks', color: '#ef4444' },
] as const

type LMTabKey = typeof LM_TABS[number]['key']

const LM_IDS: Record<LMTabKey, string[]> = {
  netexec: ['nxc-smb-scan','nxc-smb-enum-shares','nxc-smb-sessions','nxc-smb-enum-users','nxc-wmi-exec','nxc-winrm-exec','nxc-mssql-scan','nxc-ldap-enum','nxc-pass-spray','nxc-lsa-dump','nxc-sam-dump','nxc-ntds-dump'],
  mssql:   ['mssql-linked-servers','mssql-xp-cmdshell','mssql-impersonation','mssql-ole-automation','mssql-clr-assembly','mssql-linked-exec','mssql-agent-jobs','mssql-token-impersonation','mssql-coerce','mssql-credential-objects'],
  sccm:    ['sccm-enum-sites','sccm-enum-clients','sccm-cred-harvest','sccm-exec-script','sccm-relay-http','sccm-pxe-attack','sccm-naa-creds','sccm-task-seq-creds','sccm-client-push','sccm-coerce'],
  coerce:  ['coerce-printerbug','coerce-petitpotam','coerce-dfscoerce','coerce-shadowcoerce','coerce-printspooler','coerce-msrprn','coerce-msefsrpc','coerce-to-relay','coerce-to-adcs','coerce-multi-target'],
  rubeus:   ['rubeus-kerberoast','rubeus-asreproast','rubeus-harvest','rubeus-dump','rubeus-ptt','rubeus-s4u','rubeus-golden','rubeus-silver','rubeus-diamond','rubeus-shadow'],
  password: ['lm-pass-kerbrute','lm-pass-spray-nxc','lm-pass-stuffing','lm-pass-relay','nxc-password-spray','nxc-smb-password-policy'],
}

type LMTech = { id: string; title: string; tool: string; risk_level: string; platform: string; mitre_technique_id: string; description: string; commands: { label: string; command: string; params: string[]; platform?: string }[] }

function LMTechniqueBrowser() {
  const [activeTab, setActiveTab] = useState<LMTabKey>('netexec')
  const [openId, setOpenId] = useState<string | null>(null)
  const [search, setSearch] = useState('')
  const [platform, setPlatform] = useState<'linux' | 'windows' | 'all'>('all')
  const ids = LM_IDS[activeTab]
  const { data: techniques = [], isLoading } = useTechQuery({
    queryKey: ['ad-commands', 'lateral', activeTab],
    queryFn: () => adCommandsApi.list<LMTech>({ ids: ids.join(',') }),
    staleTime: 5 * 60 * 1000,
  })
  const visible = techniques.filter(t => !search || t.title.toLowerCase().includes(search.toLowerCase()))
  const tab = LM_TABS.find(t => t.key === activeTab)!
  return (
    <div className="space-y-4 mt-8 border-t border-white/10 pt-8 px-6 pb-6">
      <h2 className="text-lg font-bold text-white">Technique Browser</h2>
      <div className="flex flex-wrap gap-2">
        {LM_TABS.map(({ key, label, color }) => (
          <button key={key} onClick={() => { setActiveTab(key); setOpenId(null); setSearch('') }}
            className={cn('rounded-xl border px-4 py-2 text-sm font-medium transition-all', activeTab === key ? 'border-transparent text-black' : 'border-white/10 text-zinc-500 hover:border-white/20 hover:text-zinc-300 bg-white/[0.02]')}
            style={activeTab === key ? { background: color } : {}}>{label}</button>
        ))}
      </div>
      <div className="flex items-center gap-2">
        <div className="relative flex-1">
          <SearchIcon className="absolute left-3 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-zinc-600" />
          <input value={search} onChange={e => setSearch(e.target.value)} placeholder={`Search ${tab.label}…`}
            className="w-full rounded-xl border border-white/10 bg-white/[0.03] py-2.5 pl-9 pr-4 text-sm text-zinc-200 outline-none placeholder:text-zinc-600 focus:border-white/20" />
        </div>
        {(['all', 'linux', 'windows'] as const).map(p => (
          <button key={p} onClick={() => setPlatform(p)}
            className={cn('rounded-xl border px-3 py-2 text-[11px] font-semibold transition-all flex-shrink-0',
              platform === p ? 'border-transparent text-black' : 'border-white/10 text-zinc-500 hover:text-zinc-300 bg-white/[0.02]'
            )}
            style={platform === p ? { background: p === 'linux' ? '#34d399' : p === 'windows' ? '#60a5fa' : '#6366f1' } : {}}>
            {p === 'all' ? 'All' : p === 'linux' ? '🐧' : '🪟'}
          </button>
        ))}
      </div>
      {isLoading ? <div className="py-12 text-center text-zinc-600 text-sm">Loading…</div> : (
        <div className="space-y-2">
          {visible.length === 0 && <div className="py-12 text-center text-sm text-zinc-600">No techniques found</div>}
          {visible.map(tech => (
            <AttackTechCard
              key={tech.id}
              tech={tech}
              isOpen={openId === tech.id}
              onToggle={() => setOpenId(openId === tech.id ? null : tech.id)}
              accentColor={tab.color}
              platformFilter={platform}
            />
          ))}
        </div>
      )}
    </div>
  )
}

export default function LateralMovementPage() {
  const { assessmentId } = useRouteAssessmentScope()

  const { data: summary, isLoading: summaryLoading, isError: summaryError, refetch: refetchSummary } = useQuery({
    queryKey: ['lm-summary', assessmentId],
    queryFn: () => lateralMovementApi.getSummary(assessmentId!),
    enabled: !!assessmentId,
    staleTime: 60_000,
  })

  const { data: techniques = [], isLoading: techLoading, isError: techError, refetch: refetchTech } = useQuery({
    queryKey: ['lm-techniques', assessmentId],
    queryFn: () => lateralMovementApi.getTechniques(assessmentId!),
    enabled: !!assessmentId,
    staleTime: 60_000,
  })

  const { data: chains = [], isLoading: chainsLoading, isError: chainsError, refetch: refetchChains } = useQuery({
    queryKey: ['lm-chains', assessmentId],
    queryFn: () => lateralMovementApi.getChains(assessmentId!),
    enabled: !!assessmentId,
    staleTime: 60_000,
  })

  const { data: paths = [], isLoading: pathsLoading, isError: pathsError, refetch: refetchPaths } = useQuery({
    queryKey: ['lm-paths', assessmentId],
    queryFn: () => lateralMovementApi.getPaths(assessmentId!),
    enabled: !!assessmentId,
    staleTime: 60_000,
  })

  if (!assessmentId) {
    return (
      <AppShell>
        <div className="flex min-h-[60vh] items-center justify-center">
          <p className="text-sm text-zinc-500">Select an assessment to view lateral movement analysis.</p>
        </div>
      </AppShell>
    )
  }

  const statCards = [
    { label: 'Total Paths', value: summary?.total_paths ?? 0, icon: Network, color: '#22d3ee' },
    { label: 'Techniques', value: summary?.techniques_detected ?? 0, icon: Activity, color: '#818cf8' },
    { label: 'Coercion Vectors', value: summary?.coercion_vectors ?? 0, icon: Zap, color: '#f97316' },
    { label: 'Critical Chains', value: summary?.critical_chains ?? 0, icon: Swords, color: '#ff4d6d' },
  ]

  return (
    <AppShell>
      <div className="min-h-full page-bg p-8">
        {/* Header */}
        <div className="mb-8 rounded-[28px] border border-white/10 bg-black p-8">
          <div className="inline-flex items-center gap-2 rounded-full border border-orange-400/20 bg-orange-400/10 px-3 py-1 text-xs font-medium text-orange-200">
            <Crosshair className="h-3.5 w-3.5" /> Lateral Movement Analysis
          </div>
          <h1 className="mt-4 text-3xl font-semibold text-white">Lateral Movement</h1>
          <p className="mt-2 max-w-2xl text-sm text-zinc-400">
            Detected multi-step attack chains, lateral movement techniques, and privilege escalation paths identified in the selected assessment.
          </p>
        </div>

        {/* Summary stats */}
        <div className="mb-8 grid gap-4 xl:grid-cols-4">
          {statCards.map(({ label, value, icon: Icon, color }) => (
            <div key={label} className="rounded-2xl border border-white/10 bg-black p-5">
              <div className="flex items-center gap-2">
                <Icon className="h-4 w-4" style={{ color }} />
                <span className="text-xs uppercase tracking-[0.22em] text-zinc-500">{label}</span>
              </div>
              <div className="mt-3 text-3xl font-semibold text-white">
                {summaryLoading ? <Loader2 className="h-6 w-6 animate-spin text-zinc-600" /> : fmtNumber(value)}
              </div>
            </div>
          ))}
        </div>

        {summaryError && <ErrorCard message="Failed to load summary" onRetry={refetchSummary} />}

        {/* Techniques */}
        <section className="mb-8">
          <h2 className="mb-4 text-sm font-semibold uppercase tracking-[0.2em] text-zinc-400">Techniques Detected</h2>
          {techLoading && <div className="flex items-center gap-2 text-sm text-zinc-500"><Loader2 className="h-4 w-4 animate-spin" /> Loading...</div>}
          {techError && <ErrorCard message="Failed to load techniques" onRetry={refetchTech} />}
          {!techLoading && !techError && techniques.length === 0 && (
            <p className="text-sm text-zinc-500">No lateral movement techniques detected in this assessment.</p>
          )}
          {!techLoading && !techError && techniques.length > 0 && (
            <div className="grid gap-3 xl:grid-cols-2">
              {techniques.map((tech: LMTechnique) => <TechniqueCard key={tech.technique_id} tech={tech} />)}
            </div>
          )}
        </section>

        {/* Chains */}
        <section className="mb-8">
          <h2 className="mb-4 text-sm font-semibold uppercase tracking-[0.2em] text-zinc-400">Attack Chains</h2>
          {chainsLoading && <div className="flex items-center gap-2 text-sm text-zinc-500"><Loader2 className="h-4 w-4 animate-spin" /> Loading...</div>}
          {chainsError && <ErrorCard message="Failed to load attack chains" onRetry={refetchChains} />}
          {!chainsLoading && !chainsError && chains.length === 0 && (
            <p className="text-sm text-zinc-500">No multi-step attack chains detected.</p>
          )}
          {!chainsLoading && !chainsError && chains.length > 0 && (
            <div className="grid gap-3 xl:grid-cols-2">
              {chains.map((chain: LMChain) => <ChainCard key={chain.chain_id} chain={chain} />)}
            </div>
          )}
        </section>

        {/* Paths */}
        <section>
          <h2 className="mb-4 text-sm font-semibold uppercase tracking-[0.2em] text-zinc-400">
            Lateral Movement Paths
            {paths.length > 0 && <span className="ml-2 text-zinc-600">({fmtNumber(paths.length)})</span>}
          </h2>
          {pathsLoading && <div className="flex items-center gap-2 text-sm text-zinc-500"><Loader2 className="h-4 w-4 animate-spin" /> Loading...</div>}
          {pathsError && <ErrorCard message="Failed to load paths" onRetry={refetchPaths} />}
          {!pathsLoading && !pathsError && paths.length === 0 && (
            <p className="text-sm text-zinc-500">No lateral movement paths found in this assessment.</p>
          )}
          {!pathsLoading && !pathsError && paths.length > 0 && (
            <div className="space-y-3">
              {paths.map((path: LMPath) => <PathCard key={path.id} path={path} />)}
            </div>
          )}
        </section>

        <LMTechniqueBrowser />
      </div>
    </AppShell>
  )
}
