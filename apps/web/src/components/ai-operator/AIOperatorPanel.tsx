'use client'

import { copyText } from '@/lib/clipboard'
import { useState, useRef, useEffect, useCallback } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { motion, AnimatePresence } from 'framer-motion'
import Link from 'next/link'
import {
  Bot, Send, Sparkles, Clock, ChevronRight, AlertTriangle, Zap,
  Play, Square, Plus, X, Terminal, Brain,
  Check, Loader2, ChevronDown, ChevronUp,
  Copy, BookOpen, Settings,
} from 'lucide-react'
import { aiOperatorApi, type Suggestion, type PlaybookEntry, type AuditEntry, type ProviderInfo, type ChatContextItem, type AnalysisResult } from '@/lib/aiOperatorApi'
import { loadAISettings } from '@/lib/aiSettings'
import { cn, fmtTime } from '@/lib/utils'
import { BackButton } from '@/components/ui/BackButton'
import { parseAgentEvent, type TraceItem, type CriticalAlertEvent, type ApprovalRequiredEvent, type TargetCardUpdateEvent } from '@/lib/agentEvents'
import { approvalApi } from '@/lib/approvalApi'
import { AgentTracePanel } from './AgentTracePanel'
import { ApprovalCard } from './ApprovalCard'
import { TargetIntelCard } from './TargetIntelCard'
import { CriticalAlertBanner } from './CriticalAlertBanner'
import { SubAgentStatusRow, type SubAgentState } from './SubAgentStatusRow'
import { CampaignProgressBar } from './CampaignProgressBar'
import { PlaybookSelector } from './PlaybookSelector'
import { ReportDraftPanel } from './ReportDraftPanel'
import { HandoffBriefModal } from './HandoffBriefModal'

const MONO = { fontFamily: 'JetBrains Mono, monospace' }

const PHASE_COLORS: Record<number, string> = {
  0: '#60a5fa', 1: '#f97316', 2: '#fbbf24', 3: '#fb923c',
  4: '#a78bfa', 5: '#34d399', 6: '#f472b6', 7: '#ef4444',
}
const PHASE_LABELS: Record<number, string> = {
  0: 'Recon', 1: 'Access', 2: 'Enum', 3: 'PrivEsc',
  4: 'Lateral', 5: 'Persist', 6: 'Evasion', 7: 'Kill',
}

const PROVIDER_COLORS: Record<string, { color: string; bg: string; border: string; icon: string }> = {
  claude:  { color: '#f97316', bg: 'rgba(249,115,22,0.1)', border: 'rgba(249,115,22,0.3)', icon: '◆' },
  openai:  { color: '#34d399', bg: 'rgba(52,211,153,0.1)', border: 'rgba(52,211,153,0.3)', icon: '◉' },
  ollama:  { color: '#a78bfa', bg: 'rgba(167,139,250,0.1)', border: 'rgba(167,139,250,0.3)', icon: '◈' },
}

type ChatTab = 'chat' | 'suggest' | 'playbook' | 'analyze' | 'history'

function ProviderBar({
  providers, selected, onSelect,
  selectedModel, onModelChange,
}: {
  providers: ProviderInfo[]
  selected: string
  onSelect: (id: string) => void
  selectedModel: string
  onModelChange: (m: string) => void
}) {
  const prov = providers.find(p => p.id === selected)
  const pc = PROVIDER_COLORS[selected] ?? { color: '#64748b', bg: 'rgba(100,116,139,0.1)', border: 'rgba(100,116,139,0.3)', icon: '●' }

  return (
    <div className="flex items-center gap-2 flex-wrap">
      {providers.map(p => {
        const c = PROVIDER_COLORS[p.id] ?? PROVIDER_COLORS.claude
        const isSelected = selected === p.id
        return (
          <button
            key={p.id}
            onClick={() => onSelect(p.id)}
            className="flex items-center gap-2 px-3 py-1.5 rounded-xl text-[11px] font-semibold transition-all"
            style={{
              background: isSelected ? c.bg : 'rgba(255,255,255,0.02)',
              border: `1px solid ${isSelected ? c.border : 'rgba(255,255,255,0.06)'}`,
              color: isSelected ? c.color : 'rgba(100,116,139,0.5)',
              fontFamily: 'JetBrains Mono, monospace',
            }}
          >
            <span className="text-xs">{c.icon}</span>
            <span>{p.id === 'claude' ? 'Claude' : p.id === 'openai' ? 'GPT-4o' : 'Ollama'}</span>
            <span
              className="h-1.5 w-1.5 rounded-full"
              style={{ background: p.available ? '#34d399' : '#ef4444', boxShadow: p.available ? '0 0 4px #34d399' : 'none' }}
            />
          </button>
        )
      })}

      {/* Model selector */}
      {prov && prov.models.length > 0 && (
        <select
          value={selectedModel || prov.default_model}
          onChange={e => onModelChange(e.target.value)}
          className="px-2.5 py-1.5 rounded-xl text-[10px] outline-none transition-all cursor-pointer"
          style={{
            background: pc.bg,
            border: `1px solid ${pc.border}`,
            color: pc.color,
            fontFamily: 'JetBrains Mono, monospace',
          }}
        >
          {prov.models.slice(0, 8).map(m => (
            <option key={m} value={m}>{m}</option>
          ))}
        </select>
      )}
    </div>
  )
}

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;')
}

function ChatMessage({ msg, providerColor }: { msg: { role: string; content: string; streaming?: boolean }; providerColor: string }) {
  const isUser = msg.role === 'user'
  const [copied, setCopied] = useState(false)

  // Simple markdown-ish code block renderer
  const renderContent = (text: string) => {
    const parts = text.split(/(```[\w]*\n[\s\S]*?```)/g)
    return parts.map((part, i) => {
      if (part.startsWith('```')) {
        const lines = part.split('\n')
        const lang = lines[0].replace('```', '') || 'bash'
        const code = lines.slice(1, -1).join('\n')
        return (
          <div key={i} className="my-2 rounded-xl overflow-hidden" style={{ border: '1px solid rgba(255,255,255,0.07)' }}>
            <div className="flex items-center justify-between px-3 py-1.5" style={{ background: 'rgba(255,255,255,0.03)', borderBottom: '1px solid rgba(255,255,255,0.05)' }}>
              <span className="text-[9px] text-zinc-600" style={MONO}>{lang}</span>
              <button
                onClick={() => { copyText(code); setCopied(true); setTimeout(() => setCopied(false), 1400) }}
                className="flex items-center gap-1 text-[9px] transition-colors"
                style={{ color: copied ? '#34d399' : 'rgba(100,116,139,0.6)' }}
              >
                {copied ? <Check className="h-2.5 w-2.5" /> : <Copy className="h-2.5 w-2.5" />}
                {copied ? 'copied' : 'copy'}
              </button>
            </div>
            <pre className="px-3 py-3 text-[11px] leading-relaxed overflow-x-auto" style={{ color: '#4ade80', ...MONO }}>{code}</pre>
          </div>
        )
      }
      // Bold **text**, inline code `text`
      const rendered = escapeHtml(part)
        .replace(/\*\*(.+?)\*\*/g, '<strong style="color:#e2e8f0">$1</strong>')
        .replace(/`([^`]+)`/g, '<code style="background:rgba(255,255,255,0.06);padding:1px 5px;border-radius:4px;font-family:JetBrains Mono,monospace;font-size:10px;color:#67e8f9">$1</code>')
      return <span key={i} dangerouslySetInnerHTML={{ __html: rendered }} />
    })
  }

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      className={cn('flex gap-3', isUser && 'flex-row-reverse')}
    >
      {/* Avatar */}
      <div
        className="flex h-7 w-7 shrink-0 items-center justify-center rounded-xl text-[10px] font-black"
        style={{
          background: isUser ? 'rgba(96,165,250,0.15)' : `rgba(${providerColor.replace('#', '').match(/.{2}/g)?.map(h => parseInt(h, 16)).join(',')},0.15)`,
          border: `1px solid ${isUser ? 'rgba(96,165,250,0.3)' : `${providerColor}50`}`,
          color: isUser ? '#60a5fa' : providerColor,
        }}
      >
        {isUser ? 'OP' : <Bot className="h-3.5 w-3.5" />}
      </div>

      {/* Bubble */}
      <div
        className={cn('max-w-[80%] rounded-[18px] px-4 py-3 text-[12px] leading-relaxed', isUser && 'rounded-tr-sm', !isUser && 'rounded-tl-sm')}
        style={{
          background: isUser ? 'rgba(96,165,250,0.08)' : 'rgba(255,255,255,0.03)',
          border: `1px solid ${isUser ? 'rgba(96,165,250,0.18)' : 'rgba(255,255,255,0.06)'}`,
          color: isUser ? '#bfdbfe' : '#d1d5db',
        }}
      >
        {renderContent(msg.content)}
        {msg.streaming && (
          <motion.span
            animate={{ opacity: [1, 0, 1] }}
            transition={{ duration: 0.8, repeat: Infinity }}
            className="inline-block w-[2px] h-[14px] bg-current ml-0.5 align-middle"
          />
        )}
      </div>
    </motion.div>
  )
}

function ContextPanel({
  items, onAdd, onRemove,
}: {
  items: ChatContextItem[]
  onAdd: (item: ChatContextItem) => void
  onRemove: (i: number) => void
}) {
  const [open, setOpen] = useState(false)
  const [type, setType] = useState<ChatContextItem['type']>('output')
  const [label, setLabel] = useState('')
  const [content, setContent] = useState('')

  const CONTEXT_TYPES: { id: ChatContextItem['type']; label: string; color: string }[] = [
    { id: 'output', label: 'Tool Output', color: '#34d399' },
    { id: 'finding', label: 'Finding', color: '#f97316' },
    { id: 'bloodhound', label: 'BloodHound JSON', color: '#818cf8' },
    { id: 'hash', label: 'Hash / Cred', color: '#ff4d6d' },
    { id: 'text', label: 'Notes', color: '#60a5fa' },
  ]

  return (
    <div className="border-t" style={{ borderColor: 'rgba(255,255,255,0.05)' }}>
      {/* Attachment chips */}
      {items.length > 0 && (
        <div className="flex flex-wrap gap-1.5 px-4 pt-2">
          {items.map((item, i) => (
            <div
              key={i}
              className="flex items-center gap-1.5 rounded-lg px-2 py-1 text-[10px]"
              style={{ background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.08)' }}
            >
              <Terminal className="h-3 w-3 text-zinc-500" />
              <span className="text-zinc-400">{item.label || item.type}</span>
              <button onClick={() => onRemove(i)} className="text-zinc-600 hover:text-red-400 transition-colors ml-0.5">
                <X className="h-2.5 w-2.5" />
              </button>
            </div>
          ))}
        </div>
      )}

      {/* Toggle */}
      <button
        onClick={() => setOpen(o => !o)}
        className="flex items-center gap-2 px-4 py-2 text-[10px] text-zinc-600 hover:text-zinc-300 transition-colors w-full text-left"
      >
        <Plus className="h-3 w-3" />
        Attach context ({items.length})
        {open ? <ChevronUp className="h-3 w-3 ml-auto" /> : <ChevronDown className="h-3 w-3 ml-auto" />}
      </button>

      <AnimatePresence>
        {open && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            className="overflow-hidden"
          >
            <div className="px-4 pb-3 space-y-2">
              <div className="flex gap-1.5 flex-wrap">
                {CONTEXT_TYPES.map(ct => (
                  <button
                    key={ct.id}
                    onClick={() => setType(ct.id)}
                    className="px-2.5 py-1 rounded-lg text-[9px] font-semibold transition-all"
                    style={{
                      background: type === ct.id ? `${ct.color}18` : 'rgba(255,255,255,0.02)',
                      border: `1px solid ${type === ct.id ? `${ct.color}40` : 'rgba(255,255,255,0.06)'}`,
                      color: type === ct.id ? ct.color : 'rgba(100,116,139,0.5)',
                      fontFamily: 'JetBrains Mono, monospace',
                    }}
                  >
                    {ct.label}
                  </button>
                ))}
              </div>
              <input
                value={label}
                onChange={e => setLabel(e.target.value)}
                placeholder="Label (optional)"
                className="w-full rounded-xl px-3 py-2 text-xs text-zinc-300 outline-none"
                style={{ background: 'rgba(0,0,0,0.4)', border: '1px solid rgba(255,255,255,0.07)', fontFamily: 'JetBrains Mono, monospace' }}
              />
              <textarea
                value={content}
                onChange={e => setContent(e.target.value)}
                placeholder="Paste tool output, finding, hash, or BloodHound JSON here…"
                rows={4}
                className="w-full rounded-xl px-3 py-2 text-xs text-zinc-300 outline-none resize-none"
                style={{ background: 'rgba(0,0,0,0.4)', border: '1px solid rgba(255,255,255,0.07)', fontFamily: 'JetBrains Mono, monospace' }}
              />
              <div className="flex gap-2">
                <button
                  onClick={() => {
                    if (!content.trim()) return
                    onAdd({ type, label: label || type, content: content.trim() })
                    setContent(''); setLabel('')
                    setOpen(false)
                  }}
                  className="flex items-center gap-1.5 px-3 py-1.5 rounded-xl text-[10px] font-semibold transition-all"
                  style={{ background: 'rgba(52,211,153,0.1)', border: '1px solid rgba(52,211,153,0.3)', color: '#34d399' }}
                >
                  <Plus className="h-3 w-3" /> Attach
                </button>
                <button
                  onClick={() => setOpen(false)}
                  className="px-3 py-1.5 rounded-xl text-[10px] text-zinc-600 hover:text-zinc-300 transition-colors"
                  style={{ border: '1px solid rgba(255,255,255,0.06)' }}
                >
                  Cancel
                </button>
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  )
}

function SuggestionCard({ s }: { s: Suggestion }) {
  const phaseColor = PHASE_COLORS[s.phase_id] ?? '#64748b'
  return (
    <div className="rounded-[18px] p-4 space-y-3" style={{ border: '1px solid rgba(255,255,255,0.08)', background: 'rgba(255,255,255,0.02)' }}>
      <div className="flex items-start justify-between gap-3">
        <div>
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-sm font-semibold text-zinc-100">{s.title}</span>
            {s.requires_human_approval && (
              <span className="flex items-center gap-1 rounded-lg border border-yellow-500/30 bg-yellow-500/10 px-1.5 py-0.5 text-[9px] font-bold text-yellow-400 uppercase">
                <AlertTriangle className="h-2.5 w-2.5" />approval needed
              </span>
            )}
          </div>
          <div className="flex items-center gap-2 mt-1">
            <span className="text-[10px] text-zinc-600" style={MONO}>{s.technique_id}</span>
            <span className="text-zinc-700 text-[10px]">·</span>
            <span className="text-[10px] font-semibold text-zinc-500" style={MONO}>{s.mitre_id}</span>
          </div>
        </div>
        <span className="shrink-0 rounded-full px-2.5 py-0.5 text-[9px] font-bold uppercase"
          style={{ color: phaseColor, background: `${phaseColor}18`, border: `1px solid ${phaseColor}30` }}>
          P{s.phase_id} {PHASE_LABELS[s.phase_id]}
        </span>
      </div>
      <p className="text-[11px] text-zinc-400 leading-relaxed">{s.reason}</p>
      <div className="rounded-xl border border-white/5 bg-black/40 px-3 py-2">
        <span className="text-[10px] text-zinc-600">Expected: </span>
        <span className="text-[10px] text-zinc-300">{s.expected_outcome}</span>
      </div>
      {s.auth_level_promotion && (
        <div className="flex items-center gap-1.5 text-[10px] text-purple-400">
          <Zap className="h-3 w-3" />Promotes auth level
        </div>
      )}
    </div>
  )
}

function AnalysisCard({ result }: { result: AnalysisResult }) {
  const sevColor = { CRITICAL: '#ff4d6d', HIGH: '#f97316', MEDIUM: '#ffd166', LOW: '#51cf66', INFO: '#60a5fa' }[result.severity] ?? '#64748b'
  return (
    <div className="space-y-3">
      <div className="flex items-center gap-2">
        <span className="text-xs font-black px-2 py-0.5 rounded-lg" style={{ color: sevColor, background: `${sevColor}15`, border: `1px solid ${sevColor}30` }}>{result.severity}</span>
        <p className="text-[12px] text-zinc-300">{result.summary}</p>
      </div>
      {result.key_findings.length > 0 && (
        <div className="rounded-xl p-3 space-y-1.5" style={{ background: 'rgba(0,0,0,0.4)', border: '1px solid rgba(255,255,255,0.06)' }}>
          <div className="text-[9px] uppercase tracking-widest text-zinc-600 mb-2" style={MONO}>Key Findings</div>
          {result.key_findings.map((f, i) => (
            <div key={i} className="flex items-start gap-2 text-[11px] text-zinc-300">
              <span className="text-zinc-600 mt-0.5 shrink-0">→</span>{f}
            </div>
          ))}
        </div>
      )}
      {result.credentials_found.length > 0 && (
        <div className="rounded-xl p-3" style={{ background: 'rgba(255,77,109,0.05)', border: '1px solid rgba(255,77,109,0.2)' }}>
          <div className="text-[9px] uppercase tracking-widest text-red-400 mb-2" style={MONO}>Credentials Found</div>
          {result.credentials_found.map((c, i) => (
            <div key={i} className="text-[10px] text-red-300 font-mono">{c}</div>
          ))}
        </div>
      )}
      {result.next_techniques.length > 0 && (
        <div className="space-y-1">
          <div className="text-[9px] uppercase tracking-widest text-zinc-600" style={MONO}>Next Steps</div>
          {result.next_techniques.map((t, i) => (
            <div key={i} className="flex items-center gap-2 text-[11px] text-zinc-400">
              <ChevronRight className="h-3 w-3 text-cyan-500 shrink-0" />{t}
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

function AuditRow({ entry }: { entry: AuditEntry }) {
  const [expanded, setExpanded] = useState(false)
  const actionColor: Record<string, string> = {
    chat: '#60a5fa', suggest: '#fbbf24', playbook: '#a78bfa', analyze: '#34d399',
    explain: '#f97316', auto_run_start: '#ff4d6d', auto_run_stop: '#64748b', report_generate: '#818cf8',
  }
  const color = actionColor[entry.action_type] ?? '#64748b'
  return (
    <div className="border-b border-white/[0.04] last:border-0">
      <button className="flex w-full items-center gap-3 py-2.5 px-3 text-left hover:bg-white/[0.02] transition-colors" onClick={() => setExpanded(e => !e)}>
        <span className="h-1.5 w-1.5 rounded-full shrink-0" style={{ background: color }} />
        <span className="text-[10px] font-semibold uppercase tracking-wider flex-shrink-0" style={{ color, ...MONO }}>{entry.action_type.replace('_', ' ')}</span>
        {entry.technique_id && <span className="text-[10px] text-zinc-600 truncate" style={MONO}>{entry.technique_id}</span>}
        <span className="text-[9px] text-zinc-700 ml-auto shrink-0" style={MONO}>{fmtTime(entry.created_at)}</span>
      </button>
      {expanded && (
        <div className="px-8 pb-3 space-y-1.5">
          {entry.reasoning && <p className="text-[10px] text-zinc-400">{entry.reasoning}</p>}
          {entry.command_executed && <pre className="text-[10px] text-emerald-400 bg-black/40 rounded-xl p-2 whitespace-pre-wrap break-all" style={MONO}>{entry.command_executed}</pre>}
        </div>
      )}
    </div>
  )
}

export function AIOperatorPanel() {
  const qc = useQueryClient()
  const [activeTab, setActiveTab] = useState<ChatTab>('chat')
  const [aiCfg, setAiCfg] = useState(loadAISettings)
  const [provider, setProvider] = useState<string>('claude')
  const [model, setModel] = useState('')

  // Reload settings on mount — also syncs provider from localStorage (avoids SSR hydration mismatch)
  useEffect(() => {
    const s = loadAISettings()
    setAiCfg(s)
    setProvider(s.defaultProvider || 'claude')
  }, [])
  const [phaseScope, setPhaseScope] = useState<number[]>([0, 1, 2, 3, 4, 5, 6, 7])
  const [maxWorkers, setMaxWorkers] = useState(2)

  // Chat state
  const [messages, setMessages] = useState<{ role: string; content: string; streaming?: boolean }[]>([{
    role: 'assistant',
    content: `**N3mo online.** I'm your AI red-team operator.\n\nI can help you:\n- Plan attack paths and prioritize techniques\n- Explain AD attacks (Kerberoast, DCSync, ADCS, delegation)\n- Interpret command output and BloodHound data\n- Generate tailored exploit commands\n- Write pentest report narratives\n\nAttach tool output or findings using the **+Attach** button below, then ask me anything.`,
  }])
  const [input, setInput] = useState('')
  const [streaming, setStreaming] = useState(false)
  const [contextItems, setContextItems] = useState<ChatContextItem[]>([])
  const chatRef = useRef<HTMLDivElement>(null)
  const abortRef = useRef<AbortController | null>(null)

  // N3mo god mode state
  const [traceItems, setTraceItems] = useState<TraceItem[]>([])
  const [pendingApproval, setPendingApproval] = useState<ApprovalRequiredEvent | null>(null)
  const [targetCard, setTargetCard] = useState<TargetCardUpdateEvent['card']>({})
  const [criticalAlerts, setCriticalAlerts] = useState<CriticalAlertEvent[]>([])
  const [subAgents, setSubAgents] = useState<SubAgentState[]>([])
  const [activePhase, setActivePhase] = useState<string | null>(null)
  const [completedPhases, setCompletedPhases] = useState<string[]>([])
  const [reportSections, setReportSections] = useState<Record<string, { content: string; updated_at: string }>>({})
  const [handoffContent, setHandoffContent] = useState<string | null>(null)
  const currentTraceRef = useRef<TraceItem[]>([])

  // Analyze state
  const [analyzeOutput, setAnalyzeOutput] = useState('')
  const [analyzeResult, setAnalyzeResult] = useState<AnalysisResult | null>(null)

  // Suggestion / playbook state
  const [suggestion, setSuggestion] = useState<Suggestion | null>(null)
  const [playbook, setPlaybook] = useState<PlaybookEntry[]>([])

  const { data: providers = [] } = useQuery({
    queryKey: ['ai-providers'],
    queryFn: aiOperatorApi.providers,
    refetchInterval: 30_000,
    staleTime: 15_000,
  })

  const { data: status } = useQuery({
    queryKey: ['ai-operator-status'],
    queryFn: aiOperatorApi.status,
    refetchInterval: 5000,
  })

  const { data: history = [] } = useQuery({
    queryKey: ['ai-operator-history'],
    queryFn: () => aiOperatorApi.history(50),
    refetchInterval: activeTab === 'history' ? 10_000 : false,
    enabled: activeTab === 'history',
  })

  const getModel = () => model || (provider === 'ollama' ? aiCfg.ollamaModel : undefined)
  const getApiKey = () => provider === 'claude' ? aiCfg.claudeApiKey : provider === 'openai' ? aiCfg.openaiApiKey : undefined
  const getBaseUrl = () => provider === 'ollama' ? aiCfg.ollamaBaseUrl : provider === 'openai' ? aiCfg.openaiBaseUrl : undefined

  const suggestMut = useMutation({
    mutationFn: () => aiOperatorApi.suggest(phaseScope, [], provider, getModel(), getApiKey(), getBaseUrl()),
    onSuccess: s => setSuggestion(s),
  })

  const playbookMut = useMutation({
    mutationFn: () => aiOperatorApi.playbook(phaseScope, [], provider, getModel(), getApiKey(), getBaseUrl()),
    onSuccess: data => setPlaybook(data.playbook ?? []),
  })

  const analyzeMut = useMutation({
    mutationFn: () => aiOperatorApi.analyze(analyzeOutput, undefined, provider, getModel(), getApiKey(), getBaseUrl()),
    onSuccess: r => setAnalyzeResult(r),
  })

  const autoRunMut = useMutation({
    mutationFn: () => aiOperatorApi.autoRun(maxWorkers, phaseScope),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['ai-operator-status'] }),
  })

  const stopMut = useMutation({
    mutationFn: aiOperatorApi.stop,
    onSuccess: () => qc.invalidateQueries({ queryKey: ['ai-operator-status'] }),
  })

  // Auto-scroll chat
  useEffect(() => {
    if (chatRef.current) chatRef.current.scrollTop = chatRef.current.scrollHeight
  }, [messages])

  const sendMessage = useCallback(async () => {
    if (!input.trim() || streaming) return
    const userMsg = input.trim()
    setInput('')
    const userHistory = [...messages.filter(m => !m.streaming)]
    setMessages(prev => [...prev, { role: 'user', content: userMsg }, { role: 'assistant', content: '', streaming: true }])
    setStreaming(true)

    const ctrl = new AbortController()
    abortRef.current = ctrl

    try {
      const storedKey = provider === 'claude' ? aiCfg.claudeApiKey : provider === 'openai' ? aiCfg.openaiApiKey : undefined
      const storedBaseUrl = provider === 'ollama' ? aiCfg.ollamaBaseUrl : provider === 'openai' ? aiCfg.openaiBaseUrl : undefined
      const resp = await aiOperatorApi.chatStream(
        userMsg,
        userHistory.map(m => ({ role: m.role, content: m.content })),
        contextItems,
        null,
        provider,
        model || (provider === 'ollama' ? aiCfg.ollamaModel : null),
        ctrl.signal,
        storedKey || null,
        storedBaseUrl || null,
      )
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`)
      const reader = resp.body?.getReader()
      if (!reader) throw new Error('No body')
      const dec = new TextDecoder()
      let buf = ''

      while (true) {
        const { done, value } = await reader.read()
        if (done) break
        buf += dec.decode(value, { stream: true })
        const parts = buf.split('\n\n')
        buf = parts.pop() ?? ''
        for (const part of parts) {
          for (const line of part.split('\n')) {
            const event = parseAgentEvent(line)
            if (!event) continue

            if (event.type === 'chunk') {
              setMessages(prev => {
                const copy = [...prev]
                const last = copy[copy.length - 1]
                if (last?.streaming) copy[copy.length - 1] = { ...last, content: last.content + event.text }
                return copy
              })
            } else if (event.type === 'done') {
              currentTraceRef.current = []
            } else if (event.type === 'error') {
              setMessages(prev => {
                const copy = [...prev]
                const last = copy[copy.length - 1]
                if (last?.streaming) copy[copy.length - 1] = { ...last, content: `Error: ${event.message}`, streaming: false }
                return copy
              })
            } else if (event.type === 'tool_call') {
              const item: TraceItem = { id: event.id, tool: event.tool, args: event.args, status: 'pending' }
              currentTraceRef.current = [...currentTraceRef.current, item]
              setTraceItems([...currentTraceRef.current])
            } else if (event.type === 'tool_result') {
              currentTraceRef.current = currentTraceRef.current.map(t =>
                t.id === event.id ? { ...t, summary: event.summary, duration_ms: event.duration_ms, status: 'done' } : t
              )
              setTraceItems([...currentTraceRef.current])
            } else if (event.type === 'approval_required') {
              setPendingApproval(event)
            } else if (event.type === 'approved' || event.type === 'rejected') {
              setPendingApproval(null)
            } else if (event.type === 'target_card_update') {
              setTargetCard(c => ({ ...c, ...event.card }))
            } else if (event.type === 'critical_alert') {
              setCriticalAlerts(prev => [event, ...prev])
            } else if (event.type === 'sub_agent_spawned') {
              setSubAgents(prev => [...prev, { agent_id: event.agent_id, task: event.task, status: 'starting', done: false }])
            } else if (event.type === 'sub_agent_update') {
              setSubAgents(prev => prev.map(a => a.agent_id === event.agent_id ? { ...a, status: event.status } : a))
            } else if (event.type === 'sub_agent_done') {
              setSubAgents(prev => prev.map(a => a.agent_id === event.agent_id ? { ...a, done: true, summary: event.summary } : a))
            } else if (event.type === 'campaign_phase') {
              if (event.status === 'starting') setActivePhase(event.phase)
              if (event.status === 'done') {
                setCompletedPhases(prev => [...prev, event.phase])
                setActivePhase(null)
              }
            } else if (event.type === 'report_section_written') {
              setReportSections(prev => ({
                ...prev,
                [event.section]: { content: event.preview, updated_at: new Date().toISOString() }
              }))
            }
          }
        }
      }
    } catch (e: unknown) {
      if ((e as Error).name !== 'AbortError') {
        setMessages(prev => {
          const copy = [...prev]
          const last = copy[copy.length - 1]
          if (last?.streaming) copy[copy.length - 1] = { ...last, content: `Error: ${(e as Error).message}`, streaming: false }
          return copy
        })
      }
    } finally {
      setStreaming(false)
      setContextItems([])
      setMessages(prev => prev.map(m => m.streaming ? { ...m, streaming: false } : m))
    }
  }, [
    input,
    streaming,
    messages,
    contextItems,
    provider,
    model,
    aiCfg.claudeApiKey,
    aiCfg.openaiApiKey,
    aiCfg.openaiBaseUrl,
    aiCfg.ollamaBaseUrl,
    aiCfg.ollamaModel,
  ])

  const handleApprove = useCallback(async () => {
    if (!pendingApproval) return
    try {
      await approvalApi.approve(pendingApproval.request_id)
    } catch (e) {
      console.error('Approve failed', e)
    }
  }, [pendingApproval])

  const handleReject = useCallback(async () => {
    if (!pendingApproval) return
    try {
      await approvalApi.reject(pendingApproval.request_id)
    } catch (e) {
      console.error('Reject failed', e)
    }
  }, [pendingApproval])

  const handlePlaybookLaunch = useCallback((playbookName: string) => {
    setInput(`Run the "${playbookName}" playbook`)
  }, [])

  const providerColor = PROVIDER_COLORS[provider]?.color ?? '#64748b'

  const TABS: { key: ChatTab; label: string; icon: React.FC<{ className?: string }> }[] = [
    { key: 'chat',     label: 'Chat',     icon: Bot },
    { key: 'suggest',  label: 'Suggest',  icon: Sparkles },
    { key: 'playbook', label: 'Playbook', icon: BookOpen },
    { key: 'analyze',  label: 'Analyze',  icon: Brain },
    { key: 'history',  label: 'History',  icon: Clock },
  ]

  return (
    <div className="flex flex-col h-full min-h-screen" style={{ background: 'rgba(2,3,8,0.98)' }}>
      <div className="max-w-[1400px] mx-auto w-full px-6 py-6 flex flex-col gap-5 flex-1">
        <BackButton />

        {/* ── Header ── */}
        <div className="relative overflow-hidden rounded-[22px] p-6" style={{ border: `1px solid ${providerColor}28`, background: `linear-gradient(135deg, ${providerColor}08 0%, rgba(0,0,0,0.92) 100%)` }}>
          <div className="absolute inset-x-0 top-0 h-px" style={{ background: `linear-gradient(90deg, transparent, ${providerColor}80, transparent)` }} />
          <div className="flex items-center gap-3 flex-wrap justify-between">
            <div className="flex items-center gap-3">
              <motion.div
                animate={{ boxShadow: [`0 0 8px ${providerColor}40`, `0 0 20px ${providerColor}70`, `0 0 8px ${providerColor}40`] }}
                transition={{ duration: 2.5, repeat: Infinity }}
                className="flex items-center justify-center w-10 h-10 rounded-[14px]"
                style={{ background: `${providerColor}18`, border: `1px solid ${providerColor}35` }}
              >
                <Bot className="h-5 w-5" style={{ color: providerColor }} />
              </motion.div>
              <div>
                <div className="flex items-center gap-2">
                  <h1 className="text-xl font-black text-white">N3mo</h1>
                  <span className="text-[10px] font-bold px-2 py-0.5 rounded-full" style={{ background: `${providerColor}15`, border: `1px solid ${providerColor}30`, color: providerColor, ...MONO }}>AI OPERATOR</span>
                </div>
                <p className="text-[11px] text-zinc-500">Multi-model red-team assistant · Claude · GPT-4o · Ollama</p>
              </div>
            </div>
            {/* Auto-run status */}
            {status && (
              <div className="flex items-center gap-2">
                <div className={cn('h-2 w-2 rounded-full', status.running ? 'bg-green-400 animate-pulse' : 'bg-zinc-700')} />
                <span className="text-[10px] text-zinc-500" style={MONO}>{status.running ? `${status.active_workers}/${status.max_workers} workers` : 'idle'}</span>
              </div>
            )}
          </div>

          {/* Provider selector */}
          <div className="mt-4 flex items-center gap-3 flex-wrap">
            {providers.length > 0 ? (
              <ProviderBar providers={providers} selected={provider} onSelect={(id) => { setProvider(id as 'claude' | 'openai' | 'ollama'); setModel(''); setAiCfg(loadAISettings()) }} selectedModel={model} onModelChange={setModel} />
            ) : (
              <div className="flex items-center gap-2 text-[10px] text-zinc-600" style={MONO}>
                <Loader2 className="h-3 w-3 animate-spin" />Loading providers…
              </div>
            )}
            <Link href="/settings" className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-xl text-[10px] text-zinc-600 hover:text-zinc-300 transition-all ml-auto"
              style={{ border: '1px solid rgba(255,255,255,0.06)', fontFamily: 'JetBrains Mono, monospace' }}>
              <Settings className="h-3 w-3" /> API Keys
            </Link>
          </div>

          {/* Ollama small-model warning */}
          {provider === 'ollama' && (
            <div className="mt-2 flex items-start gap-2 px-3 py-2 rounded-xl text-[10px] text-amber-400/80"
              style={{ background: 'rgba(251,191,36,0.06)', border: '1px solid rgba(251,191,36,0.15)' }}>
              <AlertTriangle className="h-3 w-3 mt-0.5 shrink-0 text-amber-400" />
              <span>
                Small local models (llama3.2, mistral) often return free-form text instead of JSON,
                breaking Suggest, Playbook, and Analyze. Use <strong>GPT-4.1</strong> or <strong>Claude</strong> for
                structured outputs. Ollama works best for Chat only.
              </span>
            </div>
          )}
        </div>

        {/* ── Tabs ── */}
        <div className="flex gap-1.5 flex-wrap">
          {TABS.map(({ key, label, icon: Icon }) => (
            <button
              key={key}
              onClick={() => setActiveTab(key)}
              className="flex items-center gap-2 px-4 py-2 rounded-xl text-[12px] font-semibold transition-all"
              style={{
                background: activeTab === key ? `${providerColor}15` : 'rgba(255,255,255,0.02)',
                border: activeTab === key ? `1px solid ${providerColor}35` : '1px solid rgba(255,255,255,0.05)',
                color: activeTab === key ? providerColor : 'rgba(100,116,139,0.5)',
                fontFamily: 'JetBrains Mono, monospace',
              }}
            >
              <Icon className="h-3.5 w-3.5" />
              {label}
            </button>
          ))}
        </div>

        {/* ── Chat Panel ── */}
        {activeTab === 'chat' && (
          <div className="flex flex-col flex-1 rounded-[22px] overflow-hidden" style={{ border: '1px solid rgba(255,255,255,0.06)', background: 'rgba(0,0,0,0.4)', minHeight: 500 }}>
            {/* Messages */}
            <div ref={chatRef} className="flex-1 overflow-y-auto p-5 space-y-4" style={{ maxHeight: 'calc(100vh - 500px)', minHeight: 320 }}>
              {messages.map((msg, i) => (
                <ChatMessage key={i} msg={msg} providerColor={providerColor} />
              ))}
            </div>

            {/* N3mo god mode panels */}
            <div className="px-5 pb-2 space-y-2">
              {/* Critical alerts */}
              <CriticalAlertBanner
                alerts={criticalAlerts}
                onDismiss={idx => setCriticalAlerts(prev => prev.filter((_, i) => i !== idx))}
              />

              {/* Target intel card */}
              {Object.keys(targetCard).length > 0 && <TargetIntelCard card={targetCard} />}

              {/* Campaign progress */}
              <CampaignProgressBar activePhase={activePhase} completedPhases={completedPhases} />

              {/* Sub-agents */}
              <SubAgentStatusRow agents={subAgents} />

              {/* Agent trace */}
              {traceItems.length > 0 && <AgentTracePanel items={traceItems} isActive={streaming} />}

              {/* Approval card */}
              {pendingApproval && (
                <ApprovalCard
                  event={pendingApproval}
                  onApprove={handleApprove}
                  onReject={handleReject}
                />
              )}

              {/* Report draft panel */}
              {Object.keys(reportSections).length > 0 && <ReportDraftPanel sections={reportSections} />}
            </div>

            {/* Context + Input */}
            <div style={{ borderTop: '1px solid rgba(255,255,255,0.05)' }}>
              <ContextPanel items={contextItems} onAdd={item => setContextItems(p => [...p, item])} onRemove={i => setContextItems(p => p.filter((_, j) => j !== i))} />
              <div className="px-4 pt-3">
                <PlaybookSelector onLaunch={handlePlaybookLaunch} />
              </div>
              <div className="flex gap-3 p-4">
                <textarea
                  value={input}
                  onChange={e => setInput(e.target.value)}
                  onKeyDown={e => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); sendMessage() } }}
                  placeholder="Ask N3mo anything — attack paths, technique explanations, output interpretation, report writing… (Enter to send)"
                  rows={2}
                  className="flex-1 rounded-[14px] px-4 py-3 text-sm text-zinc-200 outline-none resize-none transition-all"
                  style={{ background: 'rgba(255,255,255,0.03)', border: `1px solid ${input ? `${providerColor}25` : 'rgba(255,255,255,0.07)'}`, fontFamily: 'JetBrains Mono, monospace' }}
                />
                <div className="flex flex-col gap-2">
                  <button
                    onClick={sendMessage}
                    disabled={!input.trim() || streaming}
                    className="flex items-center justify-center w-11 h-11 rounded-[14px] transition-all disabled:opacity-40"
                    style={{ background: `${providerColor}18`, border: `1px solid ${providerColor}35`, color: providerColor }}
                  >
                    {streaming ? <Loader2 className="h-4 w-4 animate-spin" /> : <Send className="h-4 w-4" />}
                  </button>
                  {streaming && (
                    <button
                      onClick={() => { abortRef.current?.abort(); setStreaming(false) }}
                      className="flex items-center justify-center w-11 h-11 rounded-[14px] transition-all"
                      style={{ background: 'rgba(239,68,68,0.1)', border: '1px solid rgba(239,68,68,0.3)', color: '#ef4444' }}
                    >
                      <Square className="h-4 w-4" />
                    </button>
                  )}
                </div>
              </div>
            </div>
          </div>
        )}

        {/* ── Suggest Panel ── */}
        {activeTab === 'suggest' && (
          <div className="space-y-4">
            <div className="flex items-center gap-3 flex-wrap">
              <div className="flex flex-wrap gap-1.5">
                {Object.entries(PHASE_LABELS).map(([p, label]) => (
                  <button
                    key={p}
                    onClick={() => setPhaseScope(prev => prev.includes(+p) ? prev.filter(x => x !== +p) : [...prev, +p])}
                    className="px-2.5 py-1 rounded-lg text-[10px] font-semibold transition-all"
                    style={{
                      background: phaseScope.includes(+p) ? `${PHASE_COLORS[+p]}18` : 'rgba(255,255,255,0.02)',
                      border: `1px solid ${phaseScope.includes(+p) ? `${PHASE_COLORS[+p]}35` : 'rgba(255,255,255,0.06)'}`,
                      color: phaseScope.includes(+p) ? PHASE_COLORS[+p] : 'rgba(100,116,139,0.4)',
                      fontFamily: 'JetBrains Mono, monospace',
                    }}
                  >
                    {label}
                  </button>
                ))}
              </div>
              <button
                onClick={() => suggestMut.mutate()}
                disabled={suggestMut.isPending}
                className="flex items-center gap-2 px-4 py-2 rounded-xl text-[12px] font-semibold transition-all ml-auto"
                style={{ background: `${providerColor}15`, border: `1px solid ${providerColor}35`, color: providerColor }}
              >
                {suggestMut.isPending ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Sparkles className="h-3.5 w-3.5" />}
                {suggestMut.isPending ? 'Thinking…' : 'Suggest Next'}
              </button>
            </div>
            {suggestion && <SuggestionCard s={suggestion} />}
            {suggestMut.isError && (
              <div className="text-sm text-red-400 flex items-start gap-2">
                <AlertTriangle className="h-4 w-4 mt-0.5 shrink-0" />
                <span>
                  {(suggestMut.error as Error)?.message?.includes("empty response")
                    ? "Model returned empty response — ensure Ollama is running and the model is loaded, or switch to GPT-4o."
                    : (suggestMut.error as Error)?.message?.includes("JSON")
                      ? "Model did not return valid JSON — try GPT-4.1 or a larger Ollama model."
                      : "Suggestion failed: " + ((suggestMut.error as Error)?.message || "unknown error")}
                </span>
              </div>
            )}
          </div>
        )}

        {/* ── Playbook Panel ── */}
        {activeTab === 'playbook' && (
          <div className="space-y-4">
            <div className="flex items-center gap-3">
              <p className="text-sm text-zinc-400 flex-1">Generate a full prioritized engagement playbook for the current session.</p>
              <button
                onClick={() => playbookMut.mutate()}
                disabled={playbookMut.isPending}
                className="flex items-center gap-2 px-4 py-2 rounded-xl text-[12px] font-semibold transition-all"
                style={{ background: `${providerColor}15`, border: `1px solid ${providerColor}35`, color: providerColor }}
              >
                {playbookMut.isPending ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <BookOpen className="h-3.5 w-3.5" />}
                {playbookMut.isPending ? 'Generating…' : 'Generate Playbook'}
              </button>
            </div>
            {playbook.length > 0 && (
              <div className="space-y-2">
                {playbook.map((entry, i) => (
                  <div key={i} className="flex items-center gap-3 rounded-[14px] px-4 py-3" style={{ background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.06)' }}>
                    <span className="text-[10px] text-zinc-600 w-5 shrink-0 text-right" style={MONO}>{i + 1}</span>
                    <div className="w-2 h-2 rounded-full shrink-0" style={{ background: PHASE_COLORS[entry.phase_id] ?? '#64748b' }} />
                    <div className="flex-1 min-w-0">
                      <div className="text-[12px] font-semibold text-zinc-200">{entry.title}</div>
                      <div className="text-[10px] text-zinc-600" style={MONO}>{entry.technique_id} · {entry.mitre_id}</div>
                    </div>
                    <p className="text-[10px] text-zinc-500 max-w-[200px] truncate">{entry.reason}</p>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* ── Analyze Panel ── */}
        {activeTab === 'analyze' && (
          <div className="space-y-4">
            <div>
              <div className="text-[10px] uppercase tracking-widest text-zinc-600 mb-2" style={MONO}>Paste Tool Output to Analyze</div>
              <textarea
                value={analyzeOutput}
                onChange={e => setAnalyzeOutput(e.target.value)}
                placeholder="Paste raw output from impacket, certipy, netexec, BloodHound, Rubeus, or any tool…"
                rows={8}
                className="w-full rounded-[14px] px-4 py-3 text-xs text-zinc-300 outline-none resize-none transition-all"
                style={{ background: 'rgba(0,0,0,0.5)', border: '1px solid rgba(255,255,255,0.07)', fontFamily: 'JetBrains Mono, monospace' }}
              />
            </div>
            <div className="flex items-center gap-3">
              <button
                onClick={() => analyzeMut.mutate()}
                disabled={analyzeMut.isPending || !analyzeOutput.trim()}
                className="flex items-center gap-2 px-4 py-2 rounded-xl text-[12px] font-semibold transition-all"
                style={{ background: `${providerColor}15`, border: `1px solid ${providerColor}35`, color: providerColor }}
              >
                {analyzeMut.isPending ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Brain className="h-3.5 w-3.5" />}
                {analyzeMut.isPending ? 'Analyzing…' : 'Analyze Output'}
              </button>
              {analyzeResult && (
                <button onClick={() => {
                  setMessages(prev => [...prev, {
                    role: 'user',
                    content: `I analyzed this output. Summary: ${analyzeResult.summary}. Key findings: ${analyzeResult.key_findings.join(', ')}. What should I do next?`,
                  }])
                  setActiveTab('chat')
                }} className="flex items-center gap-2 px-3 py-2 rounded-xl text-[11px] text-zinc-400 hover:text-zinc-200 transition-colors" style={{ border: '1px solid rgba(255,255,255,0.06)' }}>
                  <Send className="h-3 w-3" /> Ask N3mo
                </button>
              )}
            </div>
            {analyzeResult && <AnalysisCard result={analyzeResult} />}
          </div>
        )}

        {/* ── History Panel ── */}
        {activeTab === 'history' && (
          <div className="rounded-[18px] overflow-hidden" style={{ border: '1px solid rgba(255,255,255,0.06)', background: 'rgba(0,0,0,0.3)' }}>
            {history.length === 0 ? (
              <div className="py-16 text-center text-zinc-600 text-sm">No AI operator activity yet.</div>
            ) : (
              history.map(entry => <AuditRow key={entry.id} entry={entry} />)
            )}
          </div>
        )}

        {/* ── Auto-run panel (always visible at bottom when suggest/playbook active) ── */}
        {(activeTab === 'suggest' || activeTab === 'playbook') && (
          <div className="rounded-[18px] p-4 flex items-center gap-4" style={{ border: status?.running ? '1px solid rgba(52,211,153,0.2)' : '1px solid rgba(255,255,255,0.05)', background: status?.running ? 'rgba(52,211,153,0.04)' : 'rgba(0,0,0,0.3)' }}>
            <div className={cn('h-2.5 w-2.5 rounded-full', status?.running ? 'bg-green-400 animate-pulse' : 'bg-zinc-700')} />
            <div className="flex-1">
              <div className="text-[12px] font-semibold text-zinc-200">{status?.running ? 'Auto-Run Active' : 'Auto-Run'}</div>
              <div className="text-[10px] text-zinc-500" style={MONO}>{status?.running ? `${status.active_workers}/${status.max_workers} workers · ${status.tasks_completed} completed` : 'Start autonomous technique execution'}</div>
            </div>
            <div className="flex items-center gap-2">
              {!status?.running && (
                <select value={maxWorkers} onChange={e => setMaxWorkers(+e.target.value)} className="rounded-xl px-2 py-1.5 text-[10px] outline-none" style={{ background: 'rgba(0,0,0,0.5)', border: '1px solid rgba(255,255,255,0.08)', color: '#9ca3af', fontFamily: 'JetBrains Mono, monospace' }}>
                  {[1, 2, 3, 4, 5].map(n => <option key={n} value={n}>{n} worker{n > 1 ? 's' : ''}</option>)}
                </select>
              )}
              {status?.running ? (
                <button onClick={() => stopMut.mutate()} className="flex items-center gap-1.5 px-3 py-1.5 rounded-xl text-[11px] font-semibold" style={{ background: 'rgba(239,68,68,0.1)', border: '1px solid rgba(239,68,68,0.3)', color: '#ef4444' }}>
                  <Square className="h-3 w-3" /> Stop
                </button>
              ) : (
                <button onClick={() => autoRunMut.mutate()} disabled={autoRunMut.isPending} className="flex items-center gap-1.5 px-3 py-1.5 rounded-xl text-[11px] font-semibold" style={{ background: 'rgba(52,211,153,0.1)', border: '1px solid rgba(52,211,153,0.3)', color: '#34d399' }}>
                  <Play className="h-3 w-3" /> Start
                </button>
              )}
            </div>
          </div>
        )}

        {/* Handoff modal */}
        {handoffContent && <HandoffBriefModal content={handoffContent} onClose={() => setHandoffContent(null)} />}
      </div>
    </div>
  )
}
