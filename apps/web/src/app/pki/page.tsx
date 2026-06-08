'use client'

import { copyText } from '@/lib/clipboard'
import { useMemo, useState } from 'react'
import type { ComponentType, CSSProperties } from 'react'
import Link from 'next/link'
import { useQuery } from '@tanstack/react-query'
import { motion } from 'framer-motion'
import {
  AlertTriangle,
  BadgeCheck,
  CheckCircle2,
  ChevronRight,
  FileTerminal,
  Filter,
  KeyRound,
  Layers3,
  Loader2,
  Lock,
  RadioTower,
  Search,
  Shield,
  ShieldAlert,
  Sparkles,
  Target,
  Zap,
  Copy,
} from 'lucide-react'
import { useQuery as useTechQuery } from '@tanstack/react-query'

import { AppShell } from '@/components/layout/AppShell'
import { TiltCard } from '@/components/ui/TiltCard'
import { CornerFrame } from '@/components/ui/CornerFrame'
import { adCommandsApi, pkiApi } from '@/lib/api'
import { fallbackCollectionModules } from '@/lib/moduleCatalog'
import { cn, fmtNumber } from '@/lib/utils'
import { useRouteAssessmentScope } from '@/lib/useRouteAssessmentScope'
import type { CertTemplate } from '@/lib/types'

const PKI_MONO = { fontFamily: 'JetBrains Mono, monospace' }
const PKI_RISK_COLORS: Record<string, string> = { CRITICAL: '#ff4d6d', HIGH: '#ffa94d', MEDIUM: '#ffd166', LOW: '#51cf66' }

const PKI_TABS = [
  { key: 'rodc',       label: 'RODC Attacks',       color: '#f472b6' },
  { key: 'goldencert', label: 'Golden Cert / UnPAC', color: '#fbbf24' },
  { key: 'passthcert', label: 'PassTheCert',         color: '#34d399' },
] as const
type PKITabKey = typeof PKI_TABS[number]['key']

const PKI_IDS: Record<PKITabKey, string[]> = {
  rodc: [
    'rodc-enum','rodc-krbtgt-dump','rodc-reveal-accounts','rodc-allow-list','rodc-deny-list',
    'rodc-cache-enum','rodc-key-list','rodc-ticket-forge','rodc-silver-ticket',
    'rodc-golden-rodc','rodc-managed-by','rodc-coerce','rodc-replication',
    'rodc-bypass-detection','rodc-priv-path',
  ],
  goldencert: [
    'pki-golden-cert-steal-ca','pki-golden-cert-forge','pki-golden-cert-auth',
    'pki-golden-cert-persistence','pki-unpac-hash','pki-unpac-pkinit','pki-unpac-convert',
    'pki-esc13-issuance-policy',
    'persist-adcs-golden-cert',
    'certipy-ca-backup','certipy-ca-add-officer','certipy-ca-restore',
  ],
  passthcert: [
    'pki-passthe-cert-ldap','pki-passthe-cert-schannel','pki-passthe-cert-shadow',
    'certipy-auth','certipy-req','certipy-find',
    'shadow-credentials-whisker','shadow-credentials-certipy',
  ],
}

type PKITech = { id: string; title: string; tool: string; risk_level: string; mitre_technique_id: string; description: string; commands: { label: string; command: string; params: string[] }[] }

function PKITechCard({ tech, isOpen, onToggle }: { tech: PKITech; isOpen: boolean; onToggle: () => void }) {
  const rColor = PKI_RISK_COLORS[tech.risk_level?.toUpperCase()] ?? '#64748b'
  return (
    <div className="rounded-xl border border-white/5 bg-white/[0.02] hover:border-white/10 transition-colors">
      <button className="flex w-full items-center gap-3 px-4 py-3 text-left" onClick={onToggle}>
        <ChevronRight className={cn('h-3.5 w-3.5 text-zinc-600 transition-transform flex-shrink-0', isOpen && 'rotate-90')} />
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-sm font-medium text-zinc-200">{tech.title}</span>
            <span className="rounded border px-1.5 py-0.5 text-[9px] font-bold uppercase flex-shrink-0" style={{ color: rColor, borderColor: `${rColor}30`, background: `${rColor}10` }}>{tech.risk_level}</span>
          </div>
          <div className="flex items-center gap-2 mt-0.5">
            <span className="text-[10px] text-zinc-600" style={PKI_MONO}>{tech.tool}</span>
            <span className="text-[10px] text-zinc-700">·</span>
            <span className="text-[10px] text-zinc-600" style={PKI_MONO}>{tech.mitre_technique_id}</span>
          </div>
        </div>
      </button>
      {isOpen && (
        <div className="border-t border-white/5 px-4 pb-4 pt-3 space-y-3">
          <p className="text-[11px] text-zinc-400">{tech.description}</p>
          {tech.commands?.map(cmd => (
            <div key={cmd.label} className="rounded-lg border border-white/5 bg-black/40 p-3">
              <div className="flex items-center justify-between mb-2">
                <span className="text-[10px] font-semibold text-zinc-300">{cmd.label}</span>
                <button onClick={() => copyText(cmd.command)} className="flex items-center gap-1 rounded border border-white/10 px-2 py-0.5 text-[9px] text-zinc-500 hover:text-cyan-400 hover:border-cyan-500/30 transition-colors">
                  <Copy className="h-2.5 w-2.5" />copy
                </button>
              </div>
              <pre className="text-[10px] text-emerald-400 whitespace-pre-wrap break-all" style={PKI_MONO}>{cmd.command}</pre>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

function PKIAttackBrowser() {
  const [activeTab, setActiveTab] = useState<PKITabKey>('rodc')
  const [openId, setOpenId] = useState<string | null>(null)
  const [search, setSearch] = useState('')
  const ids = PKI_IDS[activeTab]
  const { data: techniques = [], isLoading } = useTechQuery({
    queryKey: ['ad-commands', 'pki', activeTab],
    queryFn: () => adCommandsApi.list<PKITech>({ ids: ids.join(',') }),
    staleTime: 5 * 60 * 1000,
  })
  const visible = techniques.filter(t => !search || t.title.toLowerCase().includes(search.toLowerCase()))
  const tab = PKI_TABS.find(t => t.key === activeTab)!

  return (
    <div className="space-y-4 mt-8 border-t border-white/10 pt-8 px-6 pb-6 rounded-[28px] border border-white/10 bg-black">
      <div className="flex items-center gap-3">
        <Shield className="h-5 w-5 text-purple-400" />
        <h2 className="text-lg font-bold text-white">Advanced Certificate &amp; RODC Attacks</h2>
      </div>
      <div className="flex flex-wrap gap-2">
        {PKI_TABS.map(({ key, label, color }) => (
          <button key={key} onClick={() => { setActiveTab(key); setOpenId(null); setSearch('') }}
            className={cn('rounded-xl border px-4 py-2 text-sm font-medium transition-all', activeTab === key ? 'border-transparent text-black' : 'border-white/10 text-zinc-500 hover:border-white/20 hover:text-zinc-300 bg-white/[0.02]')}
            style={activeTab === key ? { background: color } : {}}>{label}</button>
        ))}
      </div>
      <div className="relative">
        <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-zinc-600" />
        <input value={search} onChange={e => setSearch(e.target.value)} placeholder={`Search ${tab.label}…`}
          className="w-full rounded-xl border border-white/10 bg-white/[0.03] py-2.5 pl-9 pr-4 text-sm text-zinc-200 outline-none placeholder:text-zinc-600 focus:border-white/20" />
      </div>
      {isLoading ? <div className="py-12 text-center text-zinc-600 text-sm">Loading…</div> : (
        <div className="space-y-2">
          {visible.length === 0 && <div className="py-12 text-center text-sm text-zinc-600">No techniques found</div>}
          {visible.map(tech => <PKITechCard key={tech.id} tech={tech} isOpen={openId === tech.id} onToggle={() => setOpenId(openId === tech.id ? null : tech.id)} />)}
        </div>
      )}
    </div>
  )
}

type EscId = 'ESC1' | 'ESC2' | 'ESC3' | 'ESC4'
type ExposureFilter = 'ALL' | 'VULNERABLE' | 'ESC1' | 'ESC2' | 'ESC3' | 'ESC4' | 'SAFE'

const ESC_META: Record<EscId, { color: string; label: string; detail: string; signal: (template: CertTemplate) => boolean }> = {
  ESC1: {
    color: '#ef4444',
    label: 'ESC1',
    detail: 'Subject/SAN supplied by enrollee',
    signal: template => template.esc1_vulnerable,
  },
  ESC2: {
    color: '#f97316',
    label: 'ESC2',
    detail: 'Any-purpose or overly broad EKU',
    signal: template => template.esc2_vulnerable,
  },
  ESC3: {
    color: '#f59e0b',
    label: 'ESC3',
    detail: 'Enrollment agent abuse path',
    signal: template => template.esc3_vulnerable,
  },
  ESC4: {
    color: '#a855f7',
    label: 'ESC4',
    detail: 'Template write/control exposure',
    signal: template => template.esc4_vulnerable,
  },
}

const EXPOSURE_OPTIONS: Array<{ id: ExposureFilter; label: string }> = [
  { id: 'ALL', label: 'All templates' },
  { id: 'VULNERABLE', label: 'Any ESC' },
  { id: 'ESC1', label: 'ESC1' },
  { id: 'ESC2', label: 'ESC2' },
  { id: 'ESC3', label: 'ESC3' },
  { id: 'ESC4', label: 'ESC4' },
  { id: 'SAFE', label: 'No ESC flags' },
]

function escFlags(template: CertTemplate): EscId[] {
  return (Object.keys(ESC_META) as EscId[]).filter(esc => ESC_META[esc].signal(template))
}

function isVulnerable(template: CertTemplate) {
  return escFlags(template).length > 0
}

function riskScore(template: CertTemplate) {
  let score = 18
  if (template.esc1_vulnerable) score += 36
  if (template.esc2_vulnerable) score += 24
  if (template.esc3_vulnerable) score += 24
  if (template.esc4_vulnerable) score += 28
  if (template.enrollee_supplies_subject) score += 12
  if (!template.requires_manager_approval) score += 8
  if (template.authorized_signatures_required === 0) score += 7
  if (template.enrollment_rights.some(right => /domain users|authenticated users|everyone/i.test(right))) score += 10
  return Math.min(100, score)
}

function riskTone(score: number) {
  if (score >= 85) return { label: 'Critical', color: '#ef4444' }
  if (score >= 65) return { label: 'High', color: '#f97316' }
  if (score >= 40) return { label: 'Elevated', color: '#f59e0b' }
  return { label: 'Managed', color: '#34d399' }
}

function StatTile({
  label,
  value,
  detail,
  color,
  Icon,
}: {
  label: string
  value: string | number
  detail: string
  color: string
  Icon: ComponentType<{ className?: string; style?: CSSProperties }>
}) {
  return (
    <TiltCard>
      <div className="relative min-h-[112px] overflow-hidden rounded-lg border p-4" style={{ background: 'rgba(0,0,0,.5)', borderColor: `${color}38`, boxShadow: `0 0 34px ${color}20` }}>
        <CornerFrame size={13} color={`${color}bb`} />
        <div className="relative z-10 flex items-start justify-between gap-3">
          <span className="font-mono text-[10px] uppercase tracking-[.22em] text-zinc-500">{label}</span>
          <Icon className="h-4 w-4" style={{ color }} />
        </div>
        <div className="relative z-10 mt-4 font-mono text-3xl font-black tabular-nums" style={{ color, textShadow: `0 0 24px ${color}8a` }}>
          {typeof value === 'number' ? fmtNumber(value) : value}
        </div>
        <div className="relative z-10 mt-1 text-[10px] text-zinc-500">{detail}</div>
      </div>
    </TiltCard>
  )
}

function EscBadge({ esc, active }: { esc: EscId; active: boolean }) {
  const meta = ESC_META[esc]
  return (
    <span
      className="rounded border px-2 py-1 font-mono text-[10px] font-black uppercase tracking-[.14em]"
      style={{
        color: active ? meta.color : '#71717a',
        borderColor: active ? `${meta.color}55` : 'rgba(255,255,255,.09)',
        background: active ? `${meta.color}14` : 'rgba(255,255,255,.025)',
      }}
    >
      {esc}
    </span>
  )
}

function TemplateCard({
  template,
  selected,
  onClick,
}: {
  template: CertTemplate
  selected: boolean
  onClick: () => void
}) {
  const score = riskScore(template)
  const tone = riskTone(score)
  const flags = escFlags(template)

  return (
    <motion.button
      layout
      onClick={onClick}
      className="group relative w-full overflow-hidden rounded-lg border p-4 text-left transition"
      style={{
        background: selected ? `${tone.color}12` : 'rgba(0,0,0,.44)',
        borderColor: selected ? `${tone.color}66` : isVulnerable(template) ? `${tone.color}38` : 'rgba(255,255,255,.08)',
        boxShadow: selected ? `0 0 34px ${tone.color}24, inset 0 1px 0 rgba(255,255,255,.06)` : undefined,
      }}
    >
      <CornerFrame size={12} color={selected || isVulnerable(template) ? tone.color : 'rgba(255,255,255,.12)'} />
      <div className="relative z-10 flex items-start gap-3">
        <div className="flex h-12 w-12 shrink-0 flex-col items-center justify-center rounded-lg border" style={{ background: `${tone.color}14`, borderColor: `${tone.color}38` }}>
          <span className="font-mono text-lg font-black tabular-nums" style={{ color: tone.color }}>{score}</span>
          <span className="font-mono text-[7px] uppercase tracking-[.12em]" style={{ color: tone.color }}>{tone.label}</span>
        </div>
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <span className="truncate text-sm font-black text-zinc-100">{template.name}</span>
            {flags.length > 0 ? (
              <span className="rounded border border-red-300/30 bg-red-400/10 px-1.5 py-0.5 text-[8px] font-black uppercase tracking-[.14em] text-red-100">
                Exposed
              </span>
            ) : (
              <span className="rounded border border-emerald-300/20 bg-emerald-400/10 px-1.5 py-0.5 text-[8px] font-black uppercase tracking-[.14em] text-emerald-100">
                No ESC
              </span>
            )}
          </div>
          <div className="mt-1 truncate font-mono text-[10px] text-zinc-600">{template.ca_name || 'Unknown CA'}</div>
          <div className="mt-2 flex flex-wrap gap-1.5">
            {(Object.keys(ESC_META) as EscId[]).map(esc => <EscBadge key={esc} esc={esc} active={flags.includes(esc)} />)}
          </div>
        </div>
        <ChevronRight className={cn('mt-1 h-4 w-4 shrink-0 text-zinc-600 transition', selected && 'rotate-90')} />
      </div>
    </motion.button>
  )
}

function TemplateDetail({ template, assessmentId }: { template: CertTemplate; assessmentId: string | null }) {
  const score = riskScore(template)
  const tone = riskTone(score)
  const flags = escFlags(template)
  const findingsHref = assessmentId
    ? `/findings?assessment_id=${assessmentId}&module=AD%20CS`
    : '/findings?module=AD%20CS'
  const controls = [
    { label: 'Enrollee Supplies Subject', value: template.enrollee_supplies_subject ? 'Yes' : 'No', risky: template.enrollee_supplies_subject },
    { label: 'Manager Approval', value: template.requires_manager_approval ? 'Required' : 'Not required', risky: !template.requires_manager_approval },
    { label: 'Authorized Signatures', value: String(template.authorized_signatures_required), risky: template.authorized_signatures_required === 0 },
    { label: 'Validity Period', value: template.validity_period ?? 'Unknown', risky: false },
  ]

  return (
    <motion.div key={template.id} initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} className="space-y-4">
      <div className="relative overflow-hidden rounded-lg border p-5" style={{ background: 'rgba(0,0,0,.52)', borderColor: `${tone.color}55`, boxShadow: `0 0 42px ${tone.color}24` }}>
        <CornerFrame size={16} color={tone.color} />
        <div className="relative z-10 flex flex-wrap items-start gap-4">
          <div className="flex h-16 w-16 shrink-0 flex-col items-center justify-center rounded-xl border" style={{ background: `${tone.color}16`, borderColor: `${tone.color}42` }}>
            <span className="font-mono text-2xl font-black" style={{ color: tone.color }}>{score}</span>
            <span className="font-mono text-[8px] uppercase tracking-[.14em]" style={{ color: tone.color }}>{tone.label}</span>
          </div>
          <div className="min-w-0 flex-1">
            <h2 className="text-2xl font-black tracking-tight text-white">{template.name}</h2>
            <p className="mt-1 font-mono text-xs text-zinc-500">{template.ca_name || 'Unknown certificate authority'}</p>
            {template.distinguished_name && <p className="mt-2 break-all text-[11px] text-zinc-600">{template.distinguished_name}</p>}
            <div className="mt-4 flex flex-wrap gap-2">
              {(Object.keys(ESC_META) as EscId[]).map(esc => <EscBadge key={esc} esc={esc} active={flags.includes(esc)} />)}
            </div>
          </div>
          <Link href={findingsHref} className="rounded-lg border border-cyan-300/30 bg-cyan-400/10 px-3 py-2 text-xs font-bold uppercase tracking-[.16em] text-cyan-100 transition hover:bg-cyan-400/15">
            Findings
          </Link>
        </div>
      </div>

      <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
        {controls.map(control => (
          <div key={control.label} className="rounded-lg border border-white/10 bg-black/45 p-4">
            <div className="font-mono text-[10px] uppercase tracking-[.18em] text-zinc-500">{control.label}</div>
            <div className={cn('mt-3 text-sm font-black', control.risky ? 'text-red-200' : 'text-emerald-200')}>{control.value}</div>
          </div>
        ))}
      </div>

      <div className="grid gap-4 xl:grid-cols-2">
        <div className="relative overflow-hidden rounded-lg border border-white/10 bg-black/45 p-4">
          <div className="mb-3 flex items-center gap-2">
            <KeyRound className="h-4 w-4 text-cyan-200" />
            <span className="font-mono text-[10px] uppercase tracking-[.22em] text-zinc-400">EKUs</span>
          </div>
          {template.ekus.length ? (
            <div className="flex flex-wrap gap-2">
              {template.ekus.map(eku => <span key={eku} className="rounded border border-cyan-300/15 bg-cyan-400/10 px-2 py-1 text-[11px] text-cyan-100">{eku}</span>)}
            </div>
          ) : <p className="text-xs text-zinc-600">No EKUs captured.</p>}
        </div>

        <div className="relative overflow-hidden rounded-lg border border-white/10 bg-black/45 p-4">
          <div className="mb-3 flex items-center gap-2">
            <Target className="h-4 w-4 text-fuchsia-200" />
            <span className="font-mono text-[10px] uppercase tracking-[.22em] text-zinc-400">Rights</span>
          </div>
          <div className="space-y-3">
            <div>
              <div className="mb-1 text-[10px] uppercase tracking-[.16em] text-zinc-600">Enrollment</div>
              {template.enrollment_rights.length ? (
                <div className="flex flex-wrap gap-2">
                  {template.enrollment_rights.map(right => <span key={right} className="rounded border border-white/10 bg-white/[.04] px-2 py-1 text-[11px] text-zinc-300">{right}</span>)}
                </div>
              ) : <p className="text-xs text-zinc-600">No enrollment rights captured.</p>}
            </div>
            <div>
              <div className="mb-1 text-[10px] uppercase tracking-[.16em] text-zinc-600">Write Control</div>
              {template.write_rights.length ? (
                <div className="flex flex-wrap gap-2">
                  {template.write_rights.map(right => <span key={right} className="rounded border border-red-300/20 bg-red-400/10 px-2 py-1 text-[11px] text-red-100">{right}</span>)}
                </div>
              ) : <p className="text-xs text-zinc-600">No write rights captured.</p>}
            </div>
          </div>
        </div>
      </div>

      <div className="relative overflow-hidden rounded-lg border border-emerald-300/15 bg-emerald-400/[.035] p-4">
        <div className="mb-3 flex items-center gap-2">
          <BadgeCheck className="h-4 w-4 text-emerald-200" />
          <span className="font-mono text-[10px] uppercase tracking-[.22em] text-zinc-400">Remediation Focus</span>
        </div>
        <ul className="space-y-2 text-xs leading-relaxed text-zinc-400">
          {template.enrollee_supplies_subject && <li>Disable enrollee-supplied subject/SAN unless the template is tightly scoped and approved.</li>}
          {!template.requires_manager_approval && <li>Require manager approval for sensitive templates that can produce authentication certificates.</li>}
          {template.authorized_signatures_required === 0 && <li>Require authorized signatures for templates with enrollment-agent or privileged EKUs.</li>}
          {template.write_rights.length > 0 && <li>Remove template write/control rights from non-PKI administrators.</li>}
          {flags.length === 0 && <li>No ESC1-ESC4 flags were detected for this template in the latest assessment data.</li>}
        </ul>
      </div>
    </motion.div>
  )
}

function EmptyPkiState() {
  const adcsModule = fallbackCollectionModules.find(module => module.id === 'adcs')
  const commandGroups = adcsModule?.command_groups ?? []

  return (
    <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_420px]">
      <div className="relative overflow-hidden rounded-lg border border-cyan-300/15 bg-black/45 p-8">
        <CornerFrame size={18} color="rgba(34,211,238,.42)" />
        <Shield className="h-14 w-14 text-cyan-100 drop-shadow-[0_0_18px_rgba(34,211,238,.75)]" />
        <h2 className="mt-5 text-3xl font-black tracking-tight text-white" style={{ textShadow: '3px 0 0 rgba(255,0,128,.62), -3px 0 0 rgba(0,255,255,.62)' }}>
          No AD CS evidence yet
        </h2>
        <p className="mt-3 max-w-2xl text-base leading-relaxed text-zinc-300">
          Run an assessment with the Certificate Services Posture module, or import collector output containing certificate templates. This page will populate from real PKI records only.
        </p>
        <div className="mt-6 flex flex-wrap gap-3">
          <Link href="/assessments" className="inline-flex items-center gap-2 rounded-lg border border-cyan-300/40 bg-cyan-400/10 px-4 py-2 text-sm font-black text-cyan-100 transition hover:bg-cyan-400/15">
            <Sparkles className="h-4 w-4" />
            Start AD CS assessment
          </Link>
          <Link href="/validation" className="inline-flex items-center gap-2 rounded-lg border border-fuchsia-300/35 bg-fuchsia-400/10 px-4 py-2 text-sm font-black text-fuchsia-100 transition hover:bg-fuchsia-400/15">
            Validate controls
          </Link>
        </div>
      </div>

      <div className="space-y-3">
        {commandGroups.map(group => (
          <div key={group.id} className="rounded-lg border border-white/10 bg-black/45 p-4">
            <div className="mb-2 flex items-center gap-2">
              <FileTerminal className="h-4 w-4 text-cyan-200" />
              <span className="text-sm font-black text-zinc-100">{group.name}</span>
            </div>
            <p className="mb-3 text-xs text-zinc-500">{group.description}</p>
            <div className="space-y-2">
              {group.commands.slice(0, 3).map(command => (
                <div key={command.id} className="rounded border border-white/[.07] bg-black/55 p-2">
                  <div className="text-xs font-bold text-zinc-200">{command.title}</div>
                  <code className="mt-1 block overflow-x-auto font-mono text-[10px] text-cyan-100">{command.command}</code>
                </div>
              ))}
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}

export default function PKIPage() {
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const [query, setQuery] = useState('')
  const [exposure, setExposure] = useState<ExposureFilter>('ALL')
  const [caFilter, setCaFilter] = useState('ALL')

  const { assessment, assessmentId } = useRouteAssessmentScope()
  const adcsFindingsHref = assessmentId
    ? `/findings?assessment_id=${assessmentId}&module=AD%20CS`
    : '/findings?module=AD%20CS'

  const { data: templates = [], isLoading } = useQuery({
    queryKey: ['pki-templates', assessmentId],
    queryFn: () => pkiApi.templates(assessmentId!),
    enabled: !!assessmentId,
    staleTime: 60_000,
  })

  const { data: summary } = useQuery({
    queryKey: ['pki-summary', assessmentId],
    queryFn: () => pkiApi.summary(assessmentId!),
    enabled: !!assessmentId,
    staleTime: 60_000,
  })

  const caNames = useMemo(
    () => summary?.ca_names ?? Array.from(new Set(templates.map(template => template.ca_name).filter(Boolean))).sort(),
    [summary?.ca_names, templates]
  )

  const escCounts = useMemo(() => ({
    ESC1: summary?.esc1_count ?? templates.filter(template => template.esc1_vulnerable).length,
    ESC2: summary?.esc2_count ?? templates.filter(template => template.esc2_vulnerable).length,
    ESC3: summary?.esc3_count ?? templates.filter(template => template.esc3_vulnerable).length,
    ESC4: summary?.esc4_count ?? templates.filter(template => template.esc4_vulnerable).length,
  }), [summary, templates])

  const vulnerableCount = summary?.vulnerable_templates ?? templates.filter(isVulnerable).length
  const topRisk = useMemo(() => templates.reduce((max, template) => Math.max(max, riskScore(template)), 0), [templates])

  const filteredTemplates = useMemo(() => {
    const q = query.trim().toLowerCase()
    return templates.filter(template => {
      if (caFilter !== 'ALL' && template.ca_name !== caFilter) return false
      if (exposure === 'VULNERABLE' && !isVulnerable(template)) return false
      if (exposure === 'SAFE' && isVulnerable(template)) return false
      if (['ESC1', 'ESC2', 'ESC3', 'ESC4'].includes(exposure) && !ESC_META[exposure as EscId].signal(template)) return false
      if (!q) return true
      const haystack = [
        template.name,
        template.ca_name,
        template.distinguished_name ?? '',
        ...template.ekus,
        ...template.enrollment_rights,
        ...template.write_rights,
      ].join(' ').toLowerCase()
      return haystack.includes(q)
    }).sort((a, b) => riskScore(b) - riskScore(a) || a.name.localeCompare(b.name))
  }, [caFilter, exposure, query, templates])

  const selectedTemplate = useMemo(
    () => templates.find(template => template.id === selectedId) ?? filteredTemplates[0] ?? null,
    [filteredTemplates, selectedId, templates]
  )

  const caBreakdown = useMemo(() => caNames.map(ca => {
    const caTemplates = templates.filter(template => template.ca_name === ca)
    return {
      ca,
      total: caTemplates.length,
      vulnerable: caTemplates.filter(isVulnerable).length,
      topRisk: caTemplates.reduce((max, template) => Math.max(max, riskScore(template)), 0),
    }
  }), [caNames, templates])

  return (
    <AppShell>
      <div className="min-h-full overflow-hidden p-6">
        <div className="pointer-events-none fixed inset-x-[255px] bottom-0 h-52 opacity-25" style={{ background: 'repeating-linear-gradient(90deg,rgba(34,211,238,.16) 0 1px,transparent 1px 72px)' }} />
        <div className="relative z-10 space-y-5">
          <div className="relative overflow-hidden rounded-lg border border-cyan-300/15 bg-black/45 p-6">
            <CornerFrame size={18} color="rgba(34,211,238,.42)" />
            <div className="relative z-10 flex flex-wrap items-start justify-between gap-4">
              <div className="flex items-center gap-4">
                <div className="flex h-14 w-14 items-center justify-center rounded-xl border border-cyan-300/30 bg-cyan-400/10 shadow-[0_0_30px_rgba(34,211,238,.2)]">
                  <Lock className="h-7 w-7 text-cyan-100" />
                </div>
                <div>
                  <div className="mb-2 inline-flex items-center gap-2 rounded-full border border-cyan-300/25 bg-cyan-400/10 px-3 py-1 font-mono text-[10px] font-black uppercase tracking-[.18em] text-cyan-100">
                    PKI Attack Surface
                  </div>
                  <h1 className="text-3xl font-black tracking-tight text-white">AD CS Command Deck</h1>
                  <div className="mt-1 flex flex-wrap items-center gap-2 font-mono text-xs text-zinc-500">
                    <span>{assessment?.domain ?? 'No assessment selected'}</span>
                    <span>·</span>
                    <span>{fmtNumber(templates.length)} templates</span>
                    <span>·</span>
                    <span>{fmtNumber(vulnerableCount)} exposed</span>
                  </div>
                </div>
              </div>
              <div className="flex flex-wrap gap-2">
                <Link href="/assessments" className="rounded-lg border border-cyan-300/35 bg-cyan-400/10 px-4 py-2 text-sm font-black text-cyan-100 transition hover:bg-cyan-400/15">
                  Run collection
                </Link>
                <Link href={adcsFindingsHref} className="rounded-lg border border-red-300/30 bg-red-400/10 px-4 py-2 text-sm font-black text-red-100 transition hover:bg-red-400/15">
                  AD CS findings
                </Link>
              </div>
            </div>
          </div>

          <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-5">
            <StatTile label="CAs" value={summary?.ca_names?.length ?? caNames.length} detail="enterprise authorities" color="#22d3ee" Icon={RadioTower} />
            <StatTile label="Templates" value={summary?.total_templates ?? templates.length} detail={`${fmtNumber(filteredTemplates.length)} visible`} color="#818cf8" Icon={Layers3} />
            <StatTile label="Exposed" value={vulnerableCount} detail="ESC1-ESC4 flags" color={vulnerableCount > 0 ? '#ef4444' : '#34d399'} Icon={vulnerableCount > 0 ? ShieldAlert : CheckCircle2} />
            <StatTile label="ESC1" value={escCounts.ESC1} detail="SAN identity exposure" color={escCounts.ESC1 > 0 ? '#ef4444' : '#34d399'} Icon={AlertTriangle} />
            <StatTile label="Top Risk" value={topRisk} detail={topRisk ? riskTone(topRisk).label : 'no data'} color={topRisk >= 65 ? '#f97316' : '#34d399'} Icon={Zap} />
          </div>

          <div className="grid gap-3 md:grid-cols-4">
            {(Object.keys(ESC_META) as EscId[]).map(esc => {
              const meta = ESC_META[esc]
              const count = escCounts[esc]
              return (
                <button
                  key={esc}
                  onClick={() => setExposure(exposure === esc ? 'ALL' : esc)}
                  className="relative overflow-hidden rounded-lg border bg-black/40 p-4 text-left transition"
                  style={{ borderColor: exposure === esc ? `${meta.color}66` : 'rgba(255,255,255,.08)', boxShadow: exposure === esc ? `0 0 28px ${meta.color}24` : undefined }}
                >
                  <div className="font-mono text-[10px] uppercase tracking-[.22em] text-zinc-500">{meta.label}</div>
                  <div className="mt-2 font-mono text-2xl font-black" style={{ color: count > 0 ? meta.color : '#d4d4d8' }}>{fmtNumber(count)}</div>
                  <div className="mt-1 text-xs text-zinc-500">{meta.detail}</div>
                </button>
              )
            })}
          </div>

          <div className="relative rounded-lg border border-white/10 bg-black/35 p-3">
            <div className="flex flex-wrap items-center gap-2">
              <div className="relative min-w-[260px] flex-1">
                <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-zinc-600" />
                <input
                  value={query}
                  onChange={event => setQuery(event.target.value)}
                  placeholder="Search templates, EKUs, rights, distinguished names..."
                  className="h-10 w-full rounded-lg border border-white/10 bg-black/55 pl-9 pr-3 text-sm text-zinc-100 outline-none transition placeholder:text-zinc-700 focus:border-cyan-300/45"
                />
              </div>
              <div className="flex items-center gap-2 rounded-lg border border-white/10 bg-black/55 px-3 py-2">
                <Filter className="h-4 w-4 text-zinc-500" />
                <select value={exposure} onChange={event => setExposure(event.target.value as ExposureFilter)} className="bg-transparent text-xs text-zinc-300 outline-none">
                  {EXPOSURE_OPTIONS.map(option => <option key={option.id} value={option.id}>{option.label}</option>)}
                </select>
              </div>
              <div className="flex items-center gap-2 rounded-lg border border-white/10 bg-black/55 px-3 py-2">
                <RadioTower className="h-4 w-4 text-zinc-500" />
                <select value={caFilter} onChange={event => setCaFilter(event.target.value)} className="bg-transparent text-xs text-zinc-300 outline-none">
                  <option value="ALL">All CAs</option>
                  {caNames.map(ca => <option key={ca} value={ca}>{ca}</option>)}
                </select>
              </div>
            </div>
          </div>

          {isLoading && (
            <div className="flex min-h-[320px] items-center justify-center rounded-lg border border-white/10 bg-black/35 text-zinc-400">
              <div className="flex items-center gap-3 text-sm"><Loader2 className="h-5 w-5 animate-spin" /> Loading certificate templates...</div>
            </div>
          )}

          {!isLoading && templates.length === 0 && <EmptyPkiState />}

          {!isLoading && templates.length > 0 && (
            <div className="grid gap-4 xl:grid-cols-[minmax(360px,520px)_1fr]">
              <div className="max-h-[720px] space-y-2 overflow-y-auto pr-1">
                {filteredTemplates.length === 0 ? (
                  <div className="rounded-lg border border-white/10 bg-black/35 py-12 text-center">
                    <Shield className="mx-auto mb-3 h-10 w-10 text-zinc-700" />
                    <div className="text-sm font-semibold text-zinc-500">No templates match these filters</div>
                  </div>
                ) : (
                  filteredTemplates.map(template => (
                    <TemplateCard
                      key={template.id}
                      template={template}
                      selected={selectedTemplate?.id === template.id}
                      onClick={() => setSelectedId(template.id)}
                    />
                  ))
                )}
              </div>

              <div className="space-y-4">
                {selectedTemplate && <TemplateDetail template={selectedTemplate} assessmentId={assessmentId} />}

                <div className="relative overflow-hidden rounded-lg border border-white/10 bg-black/45 p-4">
                  <div className="mb-3 flex items-center gap-2">
                    <RadioTower className="h-4 w-4 text-cyan-200" />
                    <span className="font-mono text-[10px] uppercase tracking-[.22em] text-zinc-400">CA Pressure</span>
                  </div>
                  <div className="space-y-2">
                    {caBreakdown.map(ca => (
                      <button
                        key={ca.ca}
                        onClick={() => setCaFilter(caFilter === ca.ca ? 'ALL' : ca.ca)}
                        className="grid w-full grid-cols-[minmax(0,1fr)_60px_60px] items-center gap-3 rounded-md border border-white/[.07] bg-white/[.025] px-3 py-2 text-left"
                      >
                        <span className="truncate text-xs font-bold text-zinc-200">{ca.ca}</span>
                        <span className="text-right font-mono text-[10px] text-zinc-500">{ca.total} templates</span>
                        <span className={cn('text-right font-mono text-[10px]', ca.vulnerable > 0 ? 'text-red-300' : 'text-emerald-300')}>{ca.vulnerable} exposed</span>
                      </button>
                    ))}
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
      <div className="px-6 pb-8 max-w-[1500px] mx-auto mt-4">
        <PKIAttackBrowser />
      </div>
    </AppShell>
  )
}
