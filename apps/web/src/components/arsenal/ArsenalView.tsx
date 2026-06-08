'use client'

import { copyText } from '@/lib/clipboard'
import { useState, useEffect, useRef, useCallback, useMemo, type KeyboardEvent } from 'react'
import { useRouter } from 'next/navigation'
import { motion, AnimatePresence } from 'framer-motion'
import {
  ChevronRight, Play, PlayCircle, CheckSquare,
  Square, Search, X, Shield, Info,
  Terminal as TerminalIcon, BarChart3, Copy, Loader2,
  FlaskConical, Bug, Settings, Eye, EyeOff, RefreshCw,
  AlertCircle, CheckCircle2, Database, ArrowLeft,
} from 'lucide-react'
import {
  arsenalApi, CVE, CheckResult, StreamLine, SEVERITY_CONFIG, VERDICT_CONFIG,
} from '@/lib/arsenalApi'

const MONO = { fontFamily: 'JetBrains Mono, monospace' }
const SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as const

export interface TargetConfig {
  target: string       // target IP (default scan host)
  dc_ip: string        // domain controller IP
  dc_name: string      // DC hostname (without domain)
  domain: string       // domain FQDN e.g. corp.local
  username: string     // operator username
  password: string     // operator password
  attacker_ip: string  // listener IP for coercion/relay
  exchange_host: string
  ca_host: string      // ADCS certificate authority
  spn: string          // Service Principal Name
  template: string     // cert template name
  gpo_name: string     // GPO display name
}

const EMPTY_TARGET: TargetConfig = {
  target: '', dc_ip: '', dc_name: '', domain: '', username: '', password: '',
  attacker_ip: '', exchange_host: '', ca_host: '', spn: '', template: '', gpo_name: '',
}

function extractPlaceholders(cmd: string): string[] {
  return [...new Set([...cmd.matchAll(/\{([^}]+)\}/g)].map(m => m[1]))]
}

function resolveCmdParams(cmd: string, config: TargetConfig): Record<string, string> {
  const params: Record<string, string> = {}
  for (const ph of extractPlaceholders(cmd)) {
    if ((ph in EMPTY_TARGET) && config[ph as keyof TargetConfig])
      params[ph] = config[ph as keyof TargetConfig]
  }
  return params
}

function getMissingParams(cmd: string, config: TargetConfig): string[] {
  return extractPlaceholders(cmd).filter(ph => !(ph in EMPTY_TARGET) || !config[ph as keyof TargetConfig])
}

function cveRef(cve: CVE): string {
  return cve.arsenal_key ?? cve.id
}

function resultRef(result: CheckResult): string {
  return result.arsenal_key ?? result.cve_id
}

interface Assessment { id: string; name: string; domain: string; dc_ip: string }

interface AssessmentPickerProps {
  onImport: (config: Partial<TargetConfig>) => void
}
function AssessmentPicker({ onImport }: AssessmentPickerProps) {
  const [open, setOpen] = useState(false)
  const [assessments, setAssessments] = useState<Assessment[]>([])
  const [loading, setLoading] = useState(false)

  const load = () => {
    if (assessments.length) { setOpen(v => !v); return }
    setLoading(true)
    arsenalApi.listAssessments()
      .then(r => { setAssessments(r); setOpen(true) })
      .catch(() => {})
      .finally(() => setLoading(false))
  }

  const pick = async (a: Assessment) => {
    setOpen(false)
    try {
      const data = await arsenalApi.targetFromAssessment(a.id)
      onImport(data as Partial<TargetConfig>)
    } catch {
      onImport({ domain: a.domain, dc_ip: a.dc_ip, target: a.dc_ip })
    }
  }

  return (
    <div className="relative">
      <button onClick={load}
        className="flex items-center gap-1.5 rounded-xl px-3 py-2 text-[10px] font-bold w-full"
        style={{ background: 'rgba(34,211,238,0.08)', border: '1px solid rgba(34,211,238,0.22)', color: '#67e8f9', ...MONO }}>
        {loading ? <Loader2 className="h-3 w-3 animate-spin" /> : <Database className="h-3 w-3" />}
        Import from Assessment
        <ChevronRight className="ml-auto h-3 w-3" style={{ transform: open ? 'rotate(90deg)' : 'none', transition: 'transform 0.15s' }} />
      </button>
      <AnimatePresence>
        {open && (
          <motion.div initial={{ opacity: 0, y: -4 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -4 }}
            className="absolute left-0 right-0 z-20 mt-1 rounded-xl overflow-hidden"
            style={{ background: '#0a0f1e', border: '1px solid rgba(34,211,238,0.2)', boxShadow: '0 8px 32px rgba(0,0,0,0.6)' }}>
            {assessments.length === 0 ? (
              <div className="p-3 text-[11px]" style={{ color: '#475569', ...MONO }}>No assessments found</div>
            ) : (
              <div className="max-h-48 overflow-y-auto" style={{ scrollbarWidth: 'thin' }}>
                {assessments.map(a => (
                  <button key={a.id} onClick={() => pick(a)} className="flex w-full flex-col px-3 py-2.5 text-left hover:bg-white/5 transition-colors border-b last:border-0"
                    style={{ borderColor: 'rgba(255,255,255,0.04)' }}>
                    <span className="text-[12px] font-bold" style={{ color: '#e2e8f0', ...MONO }}>{a.name}</span>
                    <span className="text-[10px]" style={{ color: '#475569', ...MONO }}>{a.domain}{a.dc_ip ? ` · ${a.dc_ip}` : ''}</span>
                  </button>
                ))}
              </div>
            )}
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  )
}

const FIELD_META: { key: keyof TargetConfig; label: string; placeholder: string; secret?: boolean; hint: string }[] = [
  { key: 'target',        label: 'Target IP',       placeholder: '192.168.1.100',   hint: 'Host to scan/test (default: dc_ip)' },
  { key: 'dc_ip',         label: 'DC IP',            placeholder: '192.168.1.10',    hint: 'Domain Controller IP address' },
  { key: 'dc_name',       label: 'DC Name',          placeholder: 'DC01',            hint: 'DC hostname (without domain suffix)' },
  { key: 'domain',        label: 'Domain',           placeholder: 'corp.local',      hint: 'Target domain FQDN' },
  { key: 'username',      label: 'Username',         placeholder: 'operator',        hint: 'Operator domain username' },
  { key: 'password',      label: 'Password',         placeholder: '••••••••',       hint: 'Operator password', secret: true },
  { key: 'attacker_ip',   label: 'Attacker IP',      placeholder: '10.10.10.5',     hint: 'Your IP for coercion/relay listener' },
  { key: 'exchange_host', label: 'Exchange Host',    placeholder: 'mail.corp.local', hint: 'Exchange server FQDN or IP' },
  { key: 'ca_host',       label: 'CA Host',          placeholder: 'CA01.corp.local', hint: 'Certificate Authority host' },
  { key: 'spn',           label: 'SPN',              placeholder: 'MSSQLSvc/sql01',  hint: 'Service Principal Name for delegation' },
  { key: 'template',      label: 'Cert Template',    placeholder: 'User',            hint: 'Certificate template name' },
  { key: 'gpo_name',      label: 'GPO Name',         placeholder: 'Default Domain',  hint: 'GPO display name for GPO attacks' },
]

interface TargetConfigPanelProps {
  config: TargetConfig
  onChange: (update: Partial<TargetConfig>) => void
  onImport: (c: Partial<TargetConfig>) => void
  filledCount: number
}
function TargetConfigPanel({ config, onChange, onImport, filledCount }: TargetConfigPanelProps) {
  const [open, setOpen] = useState(true)
  const [showSecrets, setShowSecrets] = useState(false)
  const total = FIELD_META.length

  return (
    <div className="border-b" style={{ borderColor: 'rgba(255,255,255,0.05)' }}>
      {/* Header toggle */}
      <button onClick={() => setOpen(v => !v)}
        className="flex w-full items-center gap-2 px-3 py-2.5"
        style={{ background: 'rgba(255,255,255,0.015)' }}>
        <motion.div animate={{ rotate: open ? 90 : 0 }} transition={{ duration: 0.15 }}>
          <ChevronRight className="h-3.5 w-3.5" style={{ color: '#22d3ee' }} />
        </motion.div>
        <Settings className="h-3.5 w-3.5" style={{ color: '#22d3ee' }} />
        <span className="flex-1 text-left text-[11px] font-bold" style={{ color: '#94a3b8', ...MONO }}>Target Settings</span>
        <div className="flex items-center gap-1.5">
          {filledCount > 0 && (
            <span className="rounded-full px-2 py-0.5 text-[9px] font-bold"
              style={{ background: filledCount === total ? 'rgba(34,197,94,0.12)' : 'rgba(234,179,8,0.12)', color: filledCount === total ? '#22c55e' : '#eab308', border: `1px solid ${filledCount === total ? 'rgba(34,197,94,0.3)' : 'rgba(234,179,8,0.3)'}`, ...MONO }}>
              {filledCount}/{total}
            </span>
          )}
        </div>
      </button>

      <AnimatePresence>
        {open && (
          <motion.div initial={{ opacity: 0, height: 0 }} animate={{ opacity: 1, height: 'auto' }} exit={{ opacity: 0, height: 0 }}
            className="overflow-hidden">
            <div className="px-3 pb-2 pt-1 space-y-1.5">
              <AssessmentPicker onImport={onImport} />

              <div className="flex items-center justify-between py-1">
                <span className="text-[9px] uppercase tracking-widest" style={{ color: '#334155', ...MONO }}>Fields</span>
                <button onClick={() => setShowSecrets(v => !v)} className="flex items-center gap-1 text-[9px]" style={{ color: '#475569', ...MONO }}>
                  {showSecrets ? <EyeOff className="h-3 w-3" /> : <Eye className="h-3 w-3" />}
                  {showSecrets ? 'Hide' : 'Show'} secrets
                </button>
              </div>

              <div className="grid grid-cols-2 gap-1.5">
                {FIELD_META.map(({ key, label, placeholder, secret, hint }) => {
                  const filled = !!config[key]
                  return (
                    <div key={key} title={hint}>
                      <div className="flex items-center gap-1 mb-0.5">
                        {filled
                          ? <CheckCircle2 className="h-2.5 w-2.5 shrink-0" style={{ color: '#22c55e' }} />
                          : <AlertCircle className="h-2.5 w-2.5 shrink-0" style={{ color: '#334155' }} />}
                        <label className="text-[9px] font-bold uppercase tracking-wider truncate" style={{ color: filled ? '#94a3b8' : '#475569', ...MONO }}>{label}</label>
                      </div>
                      <input
                        type={secret && !showSecrets ? 'password' : 'text'}
                        autoComplete={secret ? 'new-password' : 'off'}
                        className="w-full rounded-lg px-2.5 py-1.5 text-[10px] outline-none"
                        style={{ background: filled ? 'rgba(34,197,94,0.06)' : 'rgba(255,255,255,0.025)', border: `1px solid ${filled ? 'rgba(34,197,94,0.25)' : 'rgba(255,255,255,0.06)'}`, color: '#e2e8f0', ...MONO }}
                        placeholder={placeholder}
                        value={config[key]}
                        onChange={e => onChange({ [key]: e.target.value })}
                      />
                    </div>
                  )
                })}
              </div>

              {filledCount > 0 && (
                <button onClick={() => onChange(EMPTY_TARGET)}
                  className="mt-1 flex w-full items-center justify-center gap-1.5 rounded-xl py-1.5 text-[9px] font-bold"
                  style={{ background: 'rgba(239,68,68,0.06)', border: '1px solid rgba(239,68,68,0.15)', color: '#fca5a5', ...MONO }}>
                  <RefreshCw className="h-3 w-3" /> Clear All
                </button>
              )}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  )
}

interface MissingParamDialogProps {
  cve: CVE
  missing: string[]
  onRun: (extra: Record<string, string>) => void
  onClose: () => void
}
function MissingParamDialog({ cve, missing, onRun, onClose }: MissingParamDialogProps) {
  const [vals, setVals] = useState<Record<string, string>>(() => Object.fromEntries(missing.map(k => [k, ''])))
  const sev = SEVERITY_CONFIG[cve.severity as keyof typeof SEVERITY_CONFIG]

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center" style={{ background: 'rgba(0,0,0,0.75)' }}>
      <motion.div initial={{ opacity: 0, scale: 0.94, y: 8 }} animate={{ opacity: 1, scale: 1, y: 0 }}
        className="w-[420px] rounded-2xl p-6" style={{ background: '#080d1a', border: `1px solid ${sev.border}`, boxShadow: `0 0 60px ${sev.glow}` }}>

        <div className="mb-4 flex items-start justify-between">
          <div>
            <div className="flex items-center gap-2">
              <span className="text-[12px] font-black" style={{ color: sev.color, ...MONO }}>{cve.id}</span>
              <span className="rounded-md px-1.5 py-0.5 text-[8px] font-bold" style={{ background: sev.bg, color: sev.color, ...MONO }}>{cve.severity}</span>
            </div>
            <div className="text-[13px] font-bold mt-0.5" style={{ color: '#f1f5f9', ...MONO }}>{cve.name}</div>
          </div>
          <button onClick={onClose}><X className="h-4 w-4" style={{ color: '#64748b' }} /></button>
        </div>

        <div className="mb-3 rounded-xl p-2.5" style={{ background: 'rgba(234,179,8,0.08)', border: '1px solid rgba(234,179,8,0.22)' }}>
          <div className="text-[10px] font-bold mb-1" style={{ color: '#fde68a', ...MONO }}>
            {missing.length} param{missing.length > 1 ? 's' : ''} not in global config
          </div>
          <div className="flex flex-wrap gap-1">
            {missing.map(p => (
              <span key={p} className="rounded-md px-1.5 py-0.5 text-[9px]" style={{ background: 'rgba(234,179,8,0.12)', color: '#fde68a', border: '1px solid rgba(234,179,8,0.25)', ...MONO }}>{'{'+p+'}'}</span>
            ))}
          </div>
        </div>

        <div className="mb-3 rounded-xl p-2.5" style={{ background: 'rgba(0,0,0,0.4)', border: '1px solid rgba(255,255,255,0.05)' }}>
          <div className="text-[9px] uppercase tracking-widest mb-1" style={{ color: '#334155', ...MONO }}>Command</div>
          <div className="text-[10px] break-all leading-5" style={{ color: '#67e8f9', ...MONO }}>{cve.check_cmd}</div>
        </div>

        <div className="space-y-2.5 mb-4">
          {missing.map(k => (
            <div key={k}>
              <label className="block text-[10px] font-bold uppercase tracking-wider mb-1" style={{ color: '#64748b', ...MONO }}>{k}</label>
              <input className="w-full rounded-xl px-3 py-2.5 text-[12px] outline-none"
                style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.08)', color: '#e2e8f0', ...MONO }}
                placeholder={`Enter {${k}}`}
                value={vals[k] ?? ''}
                onChange={e => setVals(v => ({ ...v, [k]: e.target.value }))} />
            </div>
          ))}
        </div>

        <div className="flex gap-2">
          <button onClick={onClose} className="flex-1 rounded-xl py-2.5 text-[12px] font-bold"
            style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.08)', color: '#64748b', ...MONO }}>Cancel</button>
          <button onClick={() => onRun(vals)} className="flex-1 rounded-xl py-2.5 text-[12px] font-bold flex items-center justify-center gap-2"
            style={{ background: sev.bg, border: `1px solid ${sev.border}`, color: sev.color, boxShadow: `0 0 16px ${sev.glow}`, ...MONO }}>
            <Play className="h-3.5 w-3.5" /> Run Check
          </button>
        </div>
      </motion.div>
    </div>
  )
}

interface TerminalPanelProps { lines: StreamLine[]; running: boolean; results: CheckResult[] }
function TerminalPanel({ lines, running, results }: TerminalPanelProps) {
  const ref = useRef<HTMLDivElement>(null)
  useEffect(() => { if (ref.current) ref.current.scrollTop = ref.current.scrollHeight }, [lines])

  const lineColor = (t: StreamLine['type']) => {
    if (t === 'info') return '#22d3ee'
    if (t === 'warn') return '#f97316'
    if (t === 'error') return '#ef4444'
    if (t === 'header') return '#a78bfa'
    if (t === 'separator') return '#334155'
    if (t === 'verdict') return '#fbbf24'
    return '#94a3b8'
  }

  return (
    <div className="flex h-full flex-col">
      <div className="flex items-center justify-between border-b px-4 py-2.5" style={{ borderColor: 'rgba(255,255,255,0.05)' }}>
        <div className="flex items-center gap-2">
          <TerminalIcon className="h-3.5 w-3.5" style={{ color: '#22d3ee' }} />
          <span className="text-[11px] font-bold uppercase tracking-wider" style={{ color: '#94a3b8', ...MONO }}>Output</span>
          {running && <Loader2 className="h-3 w-3 animate-spin" style={{ color: '#22d3ee' }} />}
        </div>
        {results.slice(-4).map(r => {
          const cfg = VERDICT_CONFIG[r.verdict] ?? { color: '#6b7280', label: r.verdict }
          return (
            <span key={resultRef(r)} className="rounded-full px-2 py-0.5 text-[9px] font-bold"
              style={{ background: cfg.color + '18', color: cfg.color, border: `1px solid ${cfg.color}40`, ...MONO }}>
              {cfg.label}
            </span>
          )
        })}
      </div>
      <div ref={ref} className="flex-1 overflow-y-auto p-4" style={{ scrollbarWidth: 'thin', background: 'rgba(0,0,0,0.45)', fontFamily: 'JetBrains Mono, monospace' }}>
        {lines.length === 0 ? (
          <div className="flex h-full flex-col items-center justify-center gap-2 opacity-25">
            <TerminalIcon className="h-10 w-10" style={{ color: '#475569' }} />
            <span className="text-[11px]" style={{ color: '#475569' }}>Set target config → Select a CVE → Run</span>
          </div>
        ) : (
          <div className="space-y-px">
            {lines.map((l, i) => (
              <div key={i} className="flex items-start gap-2.5">
                <span className="shrink-0 select-none text-[10px]" style={{ color: '#1e293b' }}>
                  {String(i + 1).padStart(4, '0')}
                </span>
                <span className="text-[11px] break-all leading-5" style={{ color: lineColor(l.type) }}>
                  {l.type === 'separator' ? '─'.repeat(70) : l.line || ' '}
                </span>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}

interface CVECardProps {
  cve: CVE
  selected: boolean
  active: boolean
  result?: CheckResult
  missingCount: number
  onSelect: () => void
  onClick: () => void
  onRun: () => void
}
function CVECard({ cve, selected, active, result, missingCount, onSelect, onClick, onRun }: CVECardProps) {
  const sev = SEVERITY_CONFIG[cve.severity as keyof typeof SEVERITY_CONFIG]
  const verdict = result ? (VERDICT_CONFIG[result.verdict] ?? { color: '#6b7280', label: result.verdict }) : null

  return (
    <motion.div initial={{ opacity: 0, x: -6 }} animate={{ opacity: 1, x: 0 }} whileHover={{ x: 2 }}
      onClick={onClick}
      className="group relative flex cursor-pointer items-start gap-2 rounded-xl px-2.5 py-2"
      style={{
        background: active ? `linear-gradient(135deg, ${sev.bg}, rgba(0,0,0,0.55))` : 'rgba(255,255,255,0.012)',
        border: `1px solid ${active ? sev.border : 'rgba(255,255,255,0.04)'}`,
        boxShadow: active ? `0 0 16px ${sev.glow}` : 'none',
      }}>
      <button onClick={e => { e.stopPropagation(); onSelect() }} className="mt-0.5 shrink-0">
        {selected
          ? <CheckSquare className="h-3.5 w-3.5" style={{ color: sev.color }} />
          : <Square className="h-3.5 w-3.5" style={{ color: 'rgba(71,85,105,0.6)' }} />}
      </button>

      <div className="min-w-0 flex-1">
        <div className="flex items-center gap-1 flex-wrap">
          <span className="text-[10px] font-bold" style={{ color: sev.color, ...MONO }}>{cve.id}</span>
          {cve.poc_available && (
            <span className="rounded-sm px-1 text-[8px] font-bold" style={{ background: 'rgba(168,85,247,0.15)', color: '#c084fc', ...MONO }}>PoC</span>
          )}
          {verdict && (
            <span className="rounded-sm px-1 text-[8px] font-bold" style={{ background: verdict.color + '18', color: verdict.color, ...MONO }}>{verdict.label}</span>
          )}
          {missingCount > 0 && !verdict && (
            <span className="rounded-sm px-1 text-[8px] font-bold" style={{ background: 'rgba(234,179,8,0.12)', color: '#fbbf24', ...MONO }}>
              {missingCount}p missing
            </span>
          )}
        </div>
        <div className="truncate text-[11px] font-semibold mt-0.5" style={{ color: active ? '#f1f5f9' : 'rgba(226,232,240,0.72)', ...MONO }}>{cve.name}</div>
        <div className="flex items-center gap-2 mt-0.5">
          <span className="text-[9px]" style={{ color: '#3f5068', ...MONO }}>CVSS {cve.cvss.toFixed(1)}</span>
          <span style={{ color: '#1e293b' }}>·</span>
          <span className="text-[9px]" style={{ color: '#3f5068', ...MONO }}>{cve.check_type}</span>
        </div>
      </div>

      <button onClick={e => { e.stopPropagation(); onRun() }}
        className="shrink-0 opacity-0 group-hover:opacity-100 rounded-lg p-1.5 transition-all"
        style={{ background: 'rgba(239,68,68,0.10)', border: '1px solid rgba(239,68,68,0.22)' }}
        title="Run Check">
        <Play className="h-3 w-3" style={{ color: '#fca5a5' }} />
      </button>
    </motion.div>
  )
}

interface CategoryGroupProps {
  category: string; cves: CVE[]
  selectedIds: Set<string>; activeCveId: string | null; results: Map<string, CheckResult>
  targetConfig: TargetConfig
  onSelect: (id: string) => void; onActivate: (id: string) => void; onRunSingle: (cve: CVE) => void
}
function CategoryGroup({ category, cves, selectedIds, activeCveId, results, targetConfig, onSelect, onActivate, onRunSingle }: CategoryGroupProps) {
  const [open, setOpen] = useState(false)
  return (
    <div className="ml-3 mb-1">
      <button onClick={() => setOpen(v => !v)}
        className="flex w-full items-center gap-2 rounded-lg px-2.5 py-1.5 mb-1"
        style={{ background: 'rgba(255,255,255,0.018)', border: '1px solid rgba(255,255,255,0.04)' }}>
        <motion.div animate={{ rotate: open ? 90 : 0 }} transition={{ duration: 0.12 }}>
          <ChevronRight className="h-3 w-3" style={{ color: '#3f5068' }} />
        </motion.div>
        <span className="flex-1 text-left text-[10px] font-bold truncate" style={{ color: '#64748b', ...MONO }}>{category}</span>
        <span className="text-[9px]" style={{ color: '#334155', ...MONO }}>{cves.length}</span>
      </button>
      <AnimatePresence>
        {open && (
          <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} className="ml-3 space-y-1">
            {cves.map(cve => {
              const ref = cveRef(cve)
              return (
              <CVECard key={ref} cve={cve}
                selected={selectedIds.has(ref)}
                active={activeCveId === ref}
                result={results.get(ref)}
                missingCount={getMissingParams(cve.check_cmd, targetConfig).length}
                onSelect={() => onSelect(ref)}
                onClick={() => onActivate(ref)}
                onRun={() => onRunSingle(cve)}
              />
            )})}
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  )
}

interface SeveritySectionProps {
  severity: typeof SEVERITIES[number]; cves: CVE[]
  selectedIds: Set<string>; activeCveId: string | null; results: Map<string, CheckResult>
  targetConfig: TargetConfig
  onSelect: (id: string) => void; onActivate: (id: string) => void; onRunSingle: (cve: CVE) => void
}
function SeveritySection(p: SeveritySectionProps) {
  const [open, setOpen] = useState(p.severity === 'CRITICAL' || p.severity === 'HIGH')
  const sev = SEVERITY_CONFIG[p.severity]

  const allSelected = p.cves.every(c => p.selectedIds.has(cveRef(c)))
  const someSelected = p.cves.some(c => p.selectedIds.has(cveRef(c)))

  const toggleAll = () => {
    if (allSelected) p.cves.forEach(c => p.onSelect(cveRef(c)))
    else p.cves.filter(c => !p.selectedIds.has(cveRef(c))).forEach(c => p.onSelect(cveRef(c)))
  }
  const toggleOpen = () => setOpen(v => !v)
  const handleHeaderKeyDown = (e: KeyboardEvent<HTMLDivElement>) => {
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault()
      toggleOpen()
    }
  }

  const byCategory = useMemo(() => {
    const m = new Map<string, CVE[]>()
    for (const c of p.cves) {
      if (!m.has(c.category)) m.set(c.category, [])
      m.get(c.category)!.push(c)
    }
    return m
  }, [p.cves])

  if (p.cves.length === 0) return null

  return (
    <div className="mb-1.5">
      <div
        role="button"
        tabIndex={0}
        onClick={toggleOpen}
        onKeyDown={handleHeaderKeyDown}
        className="flex w-full items-center gap-2.5 rounded-xl px-3 py-2 mb-1"
        style={{ background: `linear-gradient(135deg, ${sev.bg}, rgba(0,0,0,0.5))`, border: `1px solid ${sev.border}` }}>
        <motion.div animate={{ rotate: open ? 90 : 0 }} transition={{ duration: 0.15 }}>
          <ChevronRight className="h-3.5 w-3.5" style={{ color: sev.color }} />
        </motion.div>
        <span className="text-[11px] font-black tracking-wider flex-1 text-left" style={{ color: sev.color, ...MONO }}>{p.severity}</span>
        <span className="text-[10px]" style={{ color: sev.color + 'aa', ...MONO }}>{p.cves.length}</span>
        <motion.div className="h-1.5 w-1.5 rounded-full" animate={{ scale: [1,1.5,1], opacity: [0.5,1,0.5] }} transition={{ duration: 2.5, repeat: Infinity }}
          style={{ background: sev.color, boxShadow: `0 0 6px ${sev.color}` }} />
        <button onClick={e => { e.stopPropagation(); toggleAll() }}
          className="rounded-lg px-2 py-0.5 text-[9px] font-bold"
          style={{ background: someSelected ? sev.bg : 'rgba(255,255,255,0.02)', color: someSelected ? sev.color : '#3f5068', border: `1px solid ${someSelected ? sev.border : 'rgba(255,255,255,0.05)'}`, ...MONO }}>
          {allSelected ? 'Deselect' : 'All'}
        </button>
      </div>
      <AnimatePresence>
        {open && (
          <motion.div initial={{ opacity: 0, height: 0 }} animate={{ opacity: 1, height: 'auto' }} exit={{ opacity: 0, height: 0 }}>
            {[...byCategory.entries()].map(([cat, catCves]) => (
              <CategoryGroup key={cat} category={cat} cves={catCves}
                selectedIds={p.selectedIds} activeCveId={p.activeCveId} results={p.results}
                targetConfig={p.targetConfig}
                onSelect={p.onSelect} onActivate={p.onActivate} onRunSingle={p.onRunSingle}
              />
            ))}
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  )
}

function CVEDetail({ cve, result, targetConfig, onRun }: { cve: CVE; result?: CheckResult; targetConfig: TargetConfig; onRun: () => void }) {
  const sev = SEVERITY_CONFIG[cve.severity as keyof typeof SEVERITY_CONFIG]
  const [copied, setCopied] = useState(false)
  const missing = getMissingParams(cve.check_cmd, targetConfig)

  const resolvedCmd = useMemo(() => {
    let cmd = cve.check_cmd
    const params = resolveCmdParams(cmd, targetConfig)
    for (const [k, v] of Object.entries(params)) cmd = cmd.replaceAll(`{${k}}`, v)
    return cmd
  }, [cve.check_cmd, targetConfig])

  const copy = () => { copyText(resolvedCmd); setCopied(true); setTimeout(() => setCopied(false), 1500) }

  return (
    <div className="space-y-3 p-4">
      <div className="flex items-start justify-between gap-3">
        <div>
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-[13px] font-black" style={{ color: sev.color, ...MONO }}>{cve.id}</span>
            <span className="rounded-md px-2 py-0.5 text-[9px] font-bold uppercase"
              style={{ background: sev.bg, color: sev.color, border: `1px solid ${sev.border}`, ...MONO }}>{cve.severity}</span>
            {cve.poc_available && <span className="rounded-md px-2 py-0.5 text-[9px] font-bold" style={{ background: 'rgba(168,85,247,0.15)', color: '#c084fc', border: '1px solid rgba(168,85,247,0.3)', ...MONO }}>PoC</span>}
          </div>
          <div className="mt-1 text-[15px] font-bold" style={{ color: '#f1f5f9', ...MONO }}>{cve.name}</div>
        </div>
        <div className="shrink-0 text-center rounded-xl p-2" style={{ background: sev.bg, border: `1px solid ${sev.border}` }}>
          <div className="text-[20px] font-black" style={{ color: sev.color, ...MONO }}>{cve.cvss.toFixed(1)}</div>
          <div className="text-[8px] uppercase tracking-widest" style={{ color: sev.color + 'aa', ...MONO }}>CVSS</div>
        </div>
      </div>

      {/* Param status */}
      {missing.length > 0 && (
        <div className="rounded-xl p-3" style={{ background: 'rgba(234,179,8,0.07)', border: '1px solid rgba(234,179,8,0.22)' }}>
          <div className="text-[10px] font-bold mb-2" style={{ color: '#fde68a', ...MONO }}>
            ⚠ {missing.length} param{missing.length > 1 ? 's' : ''} needed — set in Target Settings or enter when running
          </div>
          <div className="flex flex-wrap gap-1">
            {missing.map(p => (
              <span key={p} className="rounded-md px-1.5 py-0.5 text-[9px]"
                style={{ background: 'rgba(234,179,8,0.12)', color: '#fbbf24', border: '1px solid rgba(234,179,8,0.25)', ...MONO }}>{'{'+p+'}'}</span>
            ))}
          </div>
        </div>
      )}

      {missing.length === 0 && (
        <div className="rounded-xl p-2.5" style={{ background: 'rgba(34,197,94,0.07)', border: '1px solid rgba(34,197,94,0.22)' }}>
          <div className="text-[10px] font-bold flex items-center gap-1.5" style={{ color: '#86efac', ...MONO }}>
            <CheckCircle2 className="h-3 w-3" /> All params resolved from Target Settings
          </div>
        </div>
      )}

      <div className="grid grid-cols-2 gap-2">
        {[{ label: 'Category', val: cve.category }, { label: 'Check Type', val: cve.check_type }].map(({ label, val }) => (
          <div key={label} className="rounded-xl p-2.5" style={{ background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.05)' }}>
            <div className="text-[9px] uppercase tracking-widest mb-1" style={{ color: '#334155', ...MONO }}>{label}</div>
            <div className="text-[11px] font-bold" style={{ color: '#94a3b8', ...MONO }}>{val}</div>
          </div>
        ))}
      </div>

      <div className="rounded-xl p-3" style={{ background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.05)' }}>
        <div className="text-[9px] uppercase tracking-widest mb-1.5" style={{ color: '#334155', ...MONO }}>Description</div>
        <p className="text-[11px] leading-5" style={{ color: '#94a3b8', ...MONO }}>{cve.description}</p>
      </div>

      <div className="rounded-xl p-3" style={{ background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.05)' }}>
        <div className="text-[9px] uppercase tracking-widest mb-1.5" style={{ color: '#334155', ...MONO }}>Affected</div>
        <div className="flex flex-wrap gap-1">
          {cve.affected.map(a => (
            <span key={a} className="rounded-md px-1.5 py-0.5 text-[9px]" style={{ background: 'rgba(239,68,68,0.08)', color: '#fca5a5', border: '1px solid rgba(239,68,68,0.18)', ...MONO }}>{a}</span>
          ))}
        </div>
      </div>

      <div className="rounded-xl p-3" style={{ background: 'rgba(0,0,0,0.45)', border: '1px solid rgba(255,255,255,0.05)' }}>
        <div className="mb-2 flex items-center justify-between">
          <div className="text-[9px] uppercase tracking-widest" style={{ color: '#334155', ...MONO }}>Resolved Command</div>
          <button onClick={copy} className="flex items-center gap-1 text-[9px]" style={{ color: copied ? '#22c55e' : '#475569', ...MONO }}>
            <Copy className="h-3 w-3" />{copied ? 'Copied!' : 'Copy'}
          </button>
        </div>
        <div className="text-[10px] break-all leading-5" style={{ color: '#67e8f9', ...MONO }}>{resolvedCmd}</div>
      </div>

      <div className="rounded-xl p-3" style={{ background: 'rgba(34,197,94,0.05)', border: '1px solid rgba(34,197,94,0.15)' }}>
        <div className="text-[9px] uppercase tracking-widest mb-1.5 flex items-center gap-1.5" style={{ color: '#22c55e', ...MONO }}>
          <Shield className="h-3 w-3" />Remediation
        </div>
        <p className="text-[11px] leading-5" style={{ color: '#86efac', ...MONO }}>{cve.remediation}</p>
      </div>

      <div className="flex flex-wrap gap-1">
        {cve.tags.map(t => (
          <span key={t} className="rounded-md px-1.5 py-0.5 text-[9px]" style={{ background: 'rgba(139,156,255,0.08)', color: '#a5b4fc', border: '1px solid rgba(139,156,255,0.18)', ...MONO }}>{t}</span>
        ))}
      </div>

      <button onClick={onRun}
        className="w-full flex items-center justify-center gap-2 rounded-xl py-3 text-[12px] font-bold transition-all"
        style={{ background: `linear-gradient(135deg, ${sev.bg}, rgba(0,0,0,0.5))`, border: `1px solid ${sev.border}`, color: sev.color, boxShadow: `0 0 20px ${sev.glow}`, ...MONO }}>
        <Play className="h-4 w-4" /> Run Check
        {missing.length > 0 && <span className="text-[10px] opacity-70">({missing.length} param prompt)</span>}
      </button>

      {result && (
        <div className="rounded-xl p-3 text-center"
          style={{ background: (VERDICT_CONFIG[result.verdict]?.color ?? '#6b7280') + '14', border: `1px solid ${(VERDICT_CONFIG[result.verdict]?.color ?? '#6b7280')}30` }}>
          <div className="text-[12px] font-black" style={{ color: VERDICT_CONFIG[result.verdict]?.color ?? '#6b7280', ...MONO }}>
            {VERDICT_CONFIG[result.verdict]?.label ?? result.verdict}
          </div>
        </div>
      )}
    </div>
  )
}

function ResultsTable({ results }: { results: CheckResult[] }) {
  const { vuln, safe } = results.reduce(
    (acc, r) => {
      if (r.verdict === 'VULNERABLE') acc.vuln++
      else if (r.verdict === 'NOT_VULNERABLE') acc.safe++
      return acc
    },
    { vuln: 0, safe: 0 },
  )
  const unk = results.length - vuln - safe
  if (results.length === 0) return (
    <div className="flex h-full flex-col items-center justify-center gap-2 opacity-25 p-8">
      <BarChart3 className="h-10 w-10" style={{ color: '#475569' }} />
      <span className="text-[11px]" style={{ color: '#475569', ...MONO }}>Run checks to see results</span>
    </div>
  )
  return (
    <div className="flex h-full flex-col p-4 gap-3">
      <div className="grid grid-cols-3 gap-2">
        {[{ label: 'Vulnerable', val: vuln, c: '#ef4444' }, { label: 'Safe', val: safe, c: '#22c55e' }, { label: 'Unknown', val: unk, c: '#eab308' }].map(({ label, val, c }) => (
          <div key={label} className="rounded-xl p-3 text-center" style={{ background: c + '10', border: `1px solid ${c}28` }}>
            <div className="text-[22px] font-black" style={{ color: c, ...MONO }}>{val}</div>
            <div className="text-[9px] uppercase tracking-widest" style={{ color: c + 'aa', ...MONO }}>{label}</div>
          </div>
        ))}
      </div>
      <div className="flex-1 overflow-y-auto space-y-1" style={{ scrollbarWidth: 'thin' }}>
        {results.map(r => {
          const cfg = VERDICT_CONFIG[r.verdict] ?? { color: '#6b7280', label: r.verdict }
          const sev = r.severity ? SEVERITY_CONFIG[r.severity as keyof typeof SEVERITY_CONFIG] : undefined
          return (
            <div key={resultRef(r)} className="flex items-center gap-3 rounded-xl px-3 py-2.5"
              style={{ background: 'rgba(255,255,255,0.018)', border: '1px solid rgba(255,255,255,0.04)' }}>
              <div className="flex-1 min-w-0">
                <div className="text-[11px] font-bold truncate" style={{ color: '#f1f5f9', ...MONO }}>{r.cve_id}</div>
                {r.name && <div className="text-[10px] truncate" style={{ color: '#475569', ...MONO }}>{r.name}</div>}
              </div>
              {sev && <span className="text-[8px] font-bold" style={{ color: sev.color, ...MONO }}>{r.severity}</span>}
              <span className="rounded-md px-2 py-0.5 text-[9px] font-bold shrink-0"
                style={{ background: cfg.color + '18', color: cfg.color, border: `1px solid ${cfg.color}35`, ...MONO }}>
                {cfg.label}
              </span>
            </div>
          )
        })}
      </div>
    </div>
  )
}

export function ArsenalView() {
  const router = useRouter()
  const [cves, setCves] = useState<CVE[]>([])
  const [stats, setStats] = useState<{ total: number; by_severity: Record<string, number> } | null>(null)
  const [loading, setLoading] = useState(true)
  const [search, setSearch] = useState('')
  const [filterSev, setFilterSev] = useState('')
  const [pocOnly, setPocOnly] = useState(false)

  const [targetConfig, setTargetConfig] = useState<TargetConfig>(EMPTY_TARGET)
  const filledCount = useMemo(() => Object.values(targetConfig).filter(v => !!v).length, [targetConfig])

  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set())
  const [activeCveId, setActiveCveId] = useState<string | null>(null)
  const [rightTab, setRightTab] = useState<'detail' | 'terminal' | 'results'>('detail')

  // pending CVE waiting for extra param input
  const [pendingRun, setPendingRun] = useState<{ cve: CVE; missing: string[] } | null>(null)

  const [termLines, setTermLines] = useState<StreamLine[]>([])
  const [termRunning, setTermRunning] = useState(false)
  const [results, setResults] = useState<Map<string, CheckResult>>(new Map())
  const [allResults, setAllResults] = useState<CheckResult[]>([])

  const esRef = useRef<EventSource | null>(null)

  useEffect(() => {
    arsenalApi.listCves()
      .then(d => { setCves(d.cves); setLoading(false) })
      .catch(() => setLoading(false))
    arsenalApi.getStats()
      .then(d => setStats(d.stats))
      .catch(() => {})
  }, [])

  const updateTarget = useCallback((update: Partial<TargetConfig>) => {
    setTargetConfig(prev => {
      const keys = Object.keys(update) as (keyof TargetConfig)[]
      if (keys.length === FIELD_META.length && keys.every(key => update[key] === '')) return { ...EMPTY_TARGET }
      return { ...prev, ...update }
    })
  }, [])

  const filtered = useMemo(() => {
    let list = cves
    if (search) { const q = search.toLowerCase(); list = list.filter(c => c.id.toLowerCase().includes(q) || c.name.toLowerCase().includes(q) || c.tags.some(t => t.includes(q))) }
    if (filterSev) list = list.filter(c => c.severity === filterSev)
    if (pocOnly) list = list.filter(c => c.poc_available)
    return list
  }, [cves, search, filterSev, pocOnly])

  const bySeverity = useMemo(() => {
    const m = new Map<string, CVE[]>()
    for (const s of SEVERITIES) m.set(s, [])
    for (const c of filtered) m.get(c.severity)?.push(c)
    return m
  }, [filtered])

  const activeCve = useMemo(() => cves.find(c => cveRef(c) === activeCveId) ?? null, [cves, activeCveId])

  const toggleSelect = useCallback((id: string) => {
    setSelectedIds(prev => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  }, [])

  const subscribeJob = useCallback((job_id: string) => {
    if (esRef.current) esRef.current.close()
    setTermRunning(true)
    setTermLines([])
    setRightTab('terminal')

    const es = arsenalApi.streamJob(job_id)
    esRef.current = es

    es.addEventListener('line', (e: MessageEvent) => {
      const data: StreamLine = JSON.parse(e.data)
      setTermLines(prev => [...prev, data])
    })
    es.addEventListener('done', (e: MessageEvent) => {
      const data = JSON.parse(e.data)
      const res: CheckResult[] = data.results ?? []
      setTermRunning(false)
      setAllResults(prev => { const m = new Map(prev.map(r => [resultRef(r), r])); res.forEach(r => m.set(resultRef(r), r)); return [...m.values()] })
      setResults(prev => { const next = new Map(prev); res.forEach(r => next.set(resultRef(r), r)); return next })
      es.close()
      if (res.length > 0) setRightTab('results')
    })
  }, [])

  const runCveWithParams = useCallback((cve: CVE, extraParams: Record<string, string> = {}) => {
    setPendingRun(null)
    const baseParams = resolveCmdParams(cve.check_cmd, targetConfig)
    const merged = { ...baseParams, ...extraParams }
    arsenalApi.runCheck(cveRef(cve), merged)
      .then(({ job_id }) => subscribeJob(job_id))
      .catch(err => { console.error('Arsenal check failed:', err); setTermRunning(false) })
  }, [targetConfig, subscribeJob])

  const initRunCve = useCallback((cve: CVE) => {
    const missing = getMissingParams(cve.check_cmd, targetConfig)
    if (missing.length === 0) {
      runCveWithParams(cve)
    } else {
      setPendingRun({ cve, missing })
    }
  }, [targetConfig, runCveWithParams])

  const runSelected = useCallback(() => {
    const ids = [...selectedIds]
    const params = Object.fromEntries(
      Object.entries(targetConfig).filter(([, v]) => !!v)
    ) as Record<string, string>
    arsenalApi.runBatch(ids, params)
      .then(({ job_id }) => subscribeJob(job_id))
      .catch(err => { console.error('Arsenal batch failed:', err); setTermRunning(false) })
  }, [selectedIds, targetConfig, subscribeJob])

  const runAll = useCallback(() => {
    const ids = filtered.map(c => c.id)
    const params = Object.fromEntries(Object.entries(targetConfig).filter(([, v]) => !!v)) as Record<string, string>
    arsenalApi.runBatch(ids, params)
      .then(({ job_id }) => subscribeJob(job_id))
      .catch(err => { console.error('Arsenal run-all failed:', err); setTermRunning(false) })
  }, [filtered, targetConfig, subscribeJob])

  return (
    <div className="flex h-full" style={{ background: 'rgba(4,5,12,0.98)' }}>

      {/* ── LEFT PANEL ── */}
      <div className="flex w-[360px] shrink-0 flex-col border-r" style={{ borderColor: 'rgba(255,255,255,0.05)' }}>

        {/* Header */}
        <div className="border-b px-4 pt-4 pb-3" style={{ borderColor: 'rgba(255,255,255,0.05)' }}>
          <div className="mb-3 flex items-center gap-2.5">
            <button
              type="button"
              onClick={() => router.back()}
              aria-label="Go back"
              title="Back"
              className="flex h-9 w-9 shrink-0 items-center justify-center rounded-xl transition-colors hover:bg-white/[0.06]"
              style={{ background: 'rgba(255,255,255,0.025)', border: '1px solid rgba(255,255,255,0.06)', color: '#64748b' }}
            >
              <ArrowLeft className="h-4 w-4" />
            </button>
            <div className="flex h-9 w-9 items-center justify-center rounded-xl" style={{ background: 'rgba(239,68,68,0.12)', border: '1px solid rgba(239,68,68,0.25)' }}>
              <FlaskConical className="h-5 w-5" style={{ color: '#f87171' }} />
            </div>
            <div>
              <div className="text-[14px] font-black" style={{ color: '#f1f5f9', ...MONO }}>Exploit Arsenal</div>
              <div className="text-[9px] uppercase tracking-widest" style={{ color: 'rgba(239,68,68,0.55)', ...MONO }}>AD Vulnerability Scanner</div>
            </div>
            {stats && (
              <div className="ml-auto rounded-full px-2.5 py-1 text-[9px] font-bold" style={{ background: 'rgba(255,255,255,0.04)', color: '#475569', ...MONO }}>
                {stats.total} CVEs
              </div>
            )}
          </div>

          {/* Severity filter pills */}
          {stats && (
            <div className="mb-3 flex flex-wrap gap-1.5">
              {SEVERITIES.map(s => {
                const cfg = SEVERITY_CONFIG[s]
                const n = stats.by_severity[s] ?? 0
                return n > 0 ? (
                  <span key={s} className="cursor-pointer rounded-full px-2.5 py-1 text-[9px] font-bold transition-all"
                    style={{ background: filterSev === s ? cfg.bg : 'rgba(255,255,255,0.028)', color: cfg.color, border: `1px solid ${filterSev === s ? cfg.border : 'transparent'}`, ...MONO }}
                    onClick={() => setFilterSev(v => v === s ? '' : s)}>
                    {n} {s}
                  </span>
                ) : null
              })}
            </div>
          )}

          {/* Search */}
          <div className="relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-3.5 w-3.5" style={{ color: '#3f5068' }} />
            <input className="w-full rounded-xl py-2.5 pl-9 pr-3 text-[12px] outline-none"
              style={{ background: 'rgba(255,255,255,0.025)', border: '1px solid rgba(255,255,255,0.06)', color: '#e2e8f0', ...MONO }}
              placeholder="CVE ID, name, tags..."
              value={search} onChange={e => setSearch(e.target.value)} />
          </div>

          <div className="mt-2 flex items-center gap-2">
            <button onClick={() => setPocOnly(v => !v)}
              className="flex items-center gap-1.5 rounded-xl px-2.5 py-1.5 text-[10px] font-bold"
              style={{ background: pocOnly ? 'rgba(168,85,247,0.12)' : 'rgba(255,255,255,0.02)', color: pocOnly ? '#c084fc' : '#475569', border: `1px solid ${pocOnly ? 'rgba(168,85,247,0.3)' : 'rgba(255,255,255,0.05)'}`, ...MONO }}>
              <Bug className="h-3 w-3" /> PoC Only
            </button>
            {selectedIds.size > 0 && (
              <span className="ml-auto text-[10px]" style={{ color: '#fbbf24', ...MONO }}>{selectedIds.size} selected</span>
            )}
          </div>
        </div>

        {/* Target Config Panel */}
        <TargetConfigPanel config={targetConfig} onChange={updateTarget} onImport={updateTarget} filledCount={filledCount} />

        {/* Action buttons */}
        <div className="flex gap-2 border-b px-3 py-2.5" style={{ borderColor: 'rgba(255,255,255,0.05)' }}>
          <button onClick={runAll}
            className="flex flex-1 items-center justify-center gap-1.5 rounded-xl py-2 text-[10px] font-bold"
            style={{ background: 'rgba(239,68,68,0.09)', border: '1px solid rgba(239,68,68,0.22)', color: '#fca5a5', ...MONO }}>
            <PlayCircle className="h-3.5 w-3.5" /> Run All ({filtered.length})
          </button>
          {selectedIds.size > 0 && (
            <button onClick={runSelected}
              className="flex flex-1 items-center justify-center gap-1.5 rounded-xl py-2 text-[10px] font-bold"
              style={{ background: 'rgba(234,179,8,0.09)', border: '1px solid rgba(234,179,8,0.22)', color: '#fde68a', ...MONO }}>
              <Play className="h-3.5 w-3.5" /> Run Selected ({selectedIds.size})
            </button>
          )}
        </div>

        {/* CVE Tree */}
        <div className="flex-1 overflow-y-auto p-2" style={{ scrollbarWidth: 'thin' }}>
          {loading ? (
            <div className="flex h-32 items-center justify-center">
              <Loader2 className="h-5 w-5 animate-spin" style={{ color: '#475569' }} />
            </div>
          ) : (
            SEVERITIES.map(sev => (
              <SeveritySection key={sev} severity={sev} cves={bySeverity.get(sev) ?? []}
                selectedIds={selectedIds} activeCveId={activeCveId} results={results}
                targetConfig={targetConfig}
                onSelect={toggleSelect}
                onActivate={id => { setActiveCveId(id); setRightTab('detail') }}
                onRunSingle={initRunCve}
              />
            ))
          )}
        </div>
      </div>

      {/* ── RIGHT PANEL ── */}
      <div className="flex flex-1 flex-col min-w-0">
        <div className="flex items-center border-b px-4" style={{ borderColor: 'rgba(255,255,255,0.05)', minHeight: '48px' }}>
          {[
            { id: 'detail', label: 'Details', icon: Info },
            { id: 'terminal', label: 'Terminal', icon: TerminalIcon },
            { id: 'results', label: `Results${allResults.length > 0 ? ` (${allResults.length})` : ''}`, icon: BarChart3 },
          ].map(({ id, label, icon: Icon }) => (
            <button key={id} onClick={() => setRightTab(id as typeof rightTab)}
              className="flex items-center gap-1.5 border-b-2 px-4 py-3 text-[11px] font-bold transition-all"
              style={{ borderColor: rightTab === id ? '#22d3ee' : 'transparent', color: rightTab === id ? '#22d3ee' : '#475569', ...MONO }}>
              <Icon className="h-3.5 w-3.5" />{label}
            </button>
          ))}
          <div className="flex-1" />
          {termRunning && (
            <div className="flex items-center gap-2 text-[10px]" style={{ color: '#22d3ee', ...MONO }}>
              <Loader2 className="h-3.5 w-3.5 animate-spin" />Running...
            </div>
          )}
        </div>

        <div className="flex-1 overflow-y-auto" style={{ scrollbarWidth: 'thin' }}>
          {rightTab === 'detail' && activeCve ? (
            <CVEDetail cve={activeCve} result={results.get(cveRef(activeCve))} targetConfig={targetConfig} onRun={() => initRunCve(activeCve)} />
          ) : rightTab === 'detail' ? (
            <div className="flex h-full flex-col items-center justify-center gap-3 opacity-25">
              <FlaskConical className="h-12 w-12" style={{ color: '#475569' }} />
              <div className="text-center">
                <div className="text-[13px] font-bold" style={{ color: '#475569', ...MONO }}>Select a CVE</div>
                <div className="text-[11px] mt-1" style={{ color: '#334155', ...MONO }}>Click any CVE in the tree</div>
              </div>
            </div>
          ) : rightTab === 'terminal' ? (
            <TerminalPanel lines={termLines} running={termRunning} results={allResults} />
          ) : (
            <ResultsTable results={allResults} />
          )}
        </div>
      </div>

      {/* Missing param dialog */}
      {pendingRun && (
        <MissingParamDialog
          cve={pendingRun.cve}
          missing={pendingRun.missing}
          onRun={extra => runCveWithParams(pendingRun.cve, extra)}
          onClose={() => setPendingRun(null)}
        />
      )}
    </div>
  )
}
