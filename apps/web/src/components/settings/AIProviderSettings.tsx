'use client'

import { useEffect, useState, useCallback } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import {
  Eye, EyeOff, Check, X, Loader2, RefreshCw, Save,
  Bot, Server, Wifi, AlertTriangle, CheckCircle2, Info,
  ExternalLink,
} from 'lucide-react'
import { aiOperatorApi } from '@/lib/aiOperatorApi'
import { loadAISettings, saveAISettings, clearAISettings, maskKey, type AISettings } from '@/lib/aiSettings'

const MONO = { fontFamily: 'JetBrains Mono, monospace' }

type ProviderStatus = 'idle' | 'testing' | 'ok' | 'error'

interface ProviderResult {
  status: ProviderStatus
  message: string
  models?: string[]
}

function SecretInput({
  value, onChange, placeholder, hasStored,
}: {
  value: string
  onChange: (v: string) => void
  placeholder: string
  hasStored: boolean
}) {
  const [visible, setVisible] = useState(false)
  const [focused, setFocused] = useState(false)

  return (
    <div
      className="flex items-center gap-2 rounded-xl px-3 py-2.5 transition-all"
      style={{
        background: 'rgba(0,0,0,0.5)',
        border: `1px solid ${focused ? 'rgba(96,165,250,0.3)' : 'rgba(255,255,255,0.07)'}`,
        boxShadow: focused ? '0 0 0 3px rgba(96,165,250,0.06)' : 'none',
      }}
    >
      <input
        type={visible ? 'text' : 'password'}
        value={value}
        onChange={e => onChange(e.target.value)}
        onFocus={() => setFocused(true)}
        onBlur={() => setFocused(false)}
        placeholder={hasStored && !value ? '••••••••  (saved)' : placeholder}
        className="flex-1 bg-transparent text-sm text-zinc-200 outline-none placeholder:text-zinc-600"
        style={MONO}
        autoComplete="off"
        spellCheck={false}
      />
      <button
        type="button"
        onClick={() => setVisible(v => !v)}
        className="shrink-0 text-zinc-600 hover:text-zinc-300 transition-colors"
        tabIndex={-1}
      >
        {visible ? <EyeOff className="h-3.5 w-3.5" /> : <Eye className="h-3.5 w-3.5" />}
      </button>
    </div>
  )
}

function StatusBadge({ result }: { result: ProviderResult }) {
  if (result.status === 'idle') return null
  const cfg = {
    testing: { color: '#60a5fa', icon: <Loader2 className="h-3 w-3 animate-spin" />, label: 'Testing…' },
    ok:      { color: '#34d399', icon: <CheckCircle2 className="h-3 w-3" />, label: result.message },
    error:   { color: '#f87171', icon: <AlertTriangle className="h-3 w-3" />, label: result.message },
  }[result.status]

  return (
    <motion.div
      initial={{ opacity: 0, y: -4 }}
      animate={{ opacity: 1, y: 0 }}
      className="flex items-center gap-2 rounded-xl px-3 py-2 text-[11px]"
      style={{ background: `${cfg.color}0f`, border: `1px solid ${cfg.color}28`, color: cfg.color }}
    >
      {cfg.icon}
      <span className="flex-1">{cfg.label}</span>
      {result.status === 'ok' && result.models && result.models.length > 0 && (
        <span className="text-[10px] opacity-60" style={MONO}>{result.models.slice(0, 3).join(' · ')}</span>
      )}
    </motion.div>
  )
}

function ProviderSection({
  id, label, icon, accentColor,
  children, result, onTest, testLabel = 'Test connection',
}: {
  id: string
  label: string
  icon: React.ReactNode
  accentColor: string
  children: React.ReactNode
  result: ProviderResult
  onTest: () => void
  testLabel?: string
}) {
  return (
    <div
      id={id}
      className="rounded-[18px] overflow-hidden transition-all"
      style={{ border: `1px solid rgba(255,255,255,0.06)`, background: 'rgba(0,0,0,0.3)' }}
    >
      {/* Header */}
      <div
        className="flex items-center gap-3 px-5 py-4"
        style={{ borderBottom: '1px solid rgba(255,255,255,0.05)', background: `linear-gradient(90deg, ${accentColor}08 0%, transparent 60%)` }}
      >
        <div
          className="flex items-center justify-center w-8 h-8 rounded-xl shrink-0"
          style={{ background: `${accentColor}15`, border: `1px solid ${accentColor}30` }}
        >
          <span style={{ color: accentColor }}>{icon}</span>
        </div>
        <div className="flex-1">
          <div className="text-sm font-bold text-zinc-100">{label}</div>
          <div
            className="flex items-center gap-1.5 mt-0.5"
          >
            <span
              className="h-1.5 w-1.5 rounded-full"
              style={{
                background: result.status === 'ok' ? '#34d399' : result.status === 'error' ? '#f87171' : '#3f3f46',
                boxShadow: result.status === 'ok' ? '0 0 4px #34d399' : 'none',
              }}
            />
            <span className="text-[10px] text-zinc-600">
              {result.status === 'ok' ? 'Connected' : result.status === 'error' ? 'Failed' : 'Not tested'}
            </span>
          </div>
        </div>
        <button
          onClick={onTest}
          disabled={result.status === 'testing'}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-xl text-[11px] font-semibold transition-all disabled:opacity-50"
          style={{ background: `${accentColor}12`, border: `1px solid ${accentColor}28`, color: accentColor }}
        >
          {result.status === 'testing'
            ? <Loader2 className="h-3 w-3 animate-spin" />
            : <RefreshCw className="h-3 w-3" />}
          {testLabel}
        </button>
      </div>

      {/* Fields */}
      <div className="px-5 py-4 space-y-3">
        {children}
        <AnimatePresence mode="wait">
          {result.status !== 'idle' && (
            <motion.div
              key={result.status + result.message}
              initial={{ opacity: 0, height: 0 }}
              animate={{ opacity: 1, height: 'auto' }}
              exit={{ opacity: 0, height: 0 }}
            >
              <StatusBadge result={result} />
            </motion.div>
          )}
        </AnimatePresence>
      </div>
    </div>
  )
}

function FieldLabel({ label, hint, href }: { label: string; hint?: string; href?: string }) {
  return (
    <div className="flex items-center justify-between mb-1.5">
      <label className="text-[11px] font-semibold uppercase tracking-[0.15em] text-zinc-500">{label}</label>
      {hint && href ? (
        <a href={href} target="_blank" rel="noreferrer"
          className="flex items-center gap-1 text-[10px] text-zinc-600 hover:text-zinc-300 transition-colors">
          {hint} <ExternalLink className="h-2.5 w-2.5" />
        </a>
      ) : hint ? (
        <span className="text-[10px] text-zinc-700">{hint}</span>
      ) : null}
    </div>
  )
}

function TextInput({ value, onChange, placeholder }: { value: string; onChange: (v: string) => void; placeholder: string }) {
  const [focused, setFocused] = useState(false)
  return (
    <input
      value={value}
      onChange={e => onChange(e.target.value)}
      onFocus={() => setFocused(true)}
      onBlur={() => setFocused(false)}
      placeholder={placeholder}
      className="w-full rounded-xl px-3 py-2.5 text-sm text-zinc-200 outline-none transition-all placeholder:text-zinc-600"
      style={{ background: 'rgba(0,0,0,0.5)', border: `1px solid ${focused ? 'rgba(96,165,250,0.3)' : 'rgba(255,255,255,0.07)'}`, ...MONO }}
    />
  )
}

function OllamaModelPicker({ models, selected, onSelect }: { models: string[]; selected: string; onSelect: (m: string) => void }) {
  if (!models.length) return null
  return (
    <div className="flex flex-wrap gap-1.5 mt-1">
      {models.slice(0, 12).map(m => (
        <button
          key={m}
          onClick={() => onSelect(m)}
          className="px-2.5 py-1 rounded-lg text-[10px] font-semibold transition-all"
          style={{
            background: selected === m ? 'rgba(167,139,250,0.15)' : 'rgba(255,255,255,0.03)',
            border: `1px solid ${selected === m ? 'rgba(167,139,250,0.4)' : 'rgba(255,255,255,0.06)'}`,
            color: selected === m ? '#a78bfa' : 'rgba(100,116,139,0.6)',
            fontFamily: 'JetBrains Mono, monospace',
          }}
        >
          {m}
        </button>
      ))}
    </div>
  )
}

export function AIProviderSettings() {
  const [settings, setSettings] = useState<AISettings>({
    claudeApiKey: '', openaiApiKey: '',
    openaiBaseUrl: 'https://api.openai.com/v1',
    ollamaBaseUrl: 'http://localhost:11434',
    ollamaModel: 'llama3.2',
    defaultProvider: 'claude',
  })
  const [storedKeys, setStoredKeys] = useState({ claude: false, openai: false })
  const [saved, setSaved] = useState(false)
  const [ollamaModels, setOllamaModels] = useState<string[]>([])

  const [claudeResult, setClaudeResult] = useState<ProviderResult>({ status: 'idle', message: '' })
  const [openaiResult, setOpenaiResult] = useState<ProviderResult>({ status: 'idle', message: '' })
  const [ollamaResult, setOllamaResult] = useState<ProviderResult>({ status: 'idle', message: '' })

  useEffect(() => {
    const s = loadAISettings()
    setSettings(s)
    setStoredKeys({ claude: !!s.claudeApiKey, openai: !!s.openaiApiKey })
  }, [])

  const update = useCallback((patch: Partial<AISettings>) => {
    setSettings(prev => ({ ...prev, ...patch }))
  }, [])

  const handleSave = () => {
    const trimmed = {
      ...settings,
      claudeApiKey: settings.claudeApiKey.trim(),
      openaiApiKey: settings.openaiApiKey.trim(),
      openaiBaseUrl: settings.openaiBaseUrl.trim(),
    }
    setSettings(trimmed)
    saveAISettings(trimmed)
    setStoredKeys({ claude: !!trimmed.claudeApiKey, openai: !!trimmed.openaiApiKey })
    setSaved(true)
    setTimeout(() => setSaved(false), 2000)
  }

  const handleClear = () => {
    clearAISettings()
    setSettings({
      claudeApiKey: '', openaiApiKey: '',
      openaiBaseUrl: 'https://api.openai.com/v1',
      ollamaBaseUrl: 'http://localhost:11434',
      ollamaModel: 'llama3.2',
      defaultProvider: 'claude',
    })
    setStoredKeys({ claude: false, openai: false })
    setClaudeResult({ status: 'idle', message: '' })
    setOpenaiResult({ status: 'idle', message: '' })
    setOllamaResult({ status: 'idle', message: '' })
  }

  const testClaude = async () => {
    setClaudeResult({ status: 'testing', message: '' })
    try {
      const info = await aiOperatorApi.testProvider('claude', settings.claudeApiKey || undefined)
      if (info.available) {
        setClaudeResult({ status: 'ok', message: 'Connected · claude-sonnet-4-6 ready', models: info.models })
      } else {
        setClaudeResult({ status: 'error', message: info.error || 'Connection failed' })
      }
    } catch (e: unknown) {
      setClaudeResult({ status: 'error', message: (e as Error).message || 'Request failed' })
    }
  }

  const testOpenAI = async () => {
    setOpenaiResult({ status: 'testing', message: '' })
    const key = settings.openaiApiKey.trim()
    if (!key) {
      setOpenaiResult({ status: 'error', message: 'Enter an API key first.' })
      return
    }
    try {
      const info = await aiOperatorApi.testProvider('openai', key, settings.openaiBaseUrl.trim() || undefined)
      if (info.available) {
        setOpenaiResult({ status: 'ok', message: `Connected · ${info.default_model ?? 'gpt-4.1'} ready`, models: info.models })
      } else {
        setOpenaiResult({ status: 'error', message: info.error || 'Connection failed' })
      }
    } catch (e: unknown) {
      setOpenaiResult({ status: 'error', message: (e as Error).message || 'Request failed' })
    }
  }

  const testOllama = async () => {
    setOllamaResult({ status: 'testing', message: '' })
    try {
      const info = await aiOperatorApi.testProvider('ollama', undefined, settings.ollamaBaseUrl || undefined)
      if (info.available) {
        const all = info.models
        setOllamaModels(all)
        if (!settings.ollamaModel && all.length) update({ ollamaModel: all[0] })
        setOllamaResult({
          status: 'ok',
          message: `Connected · ${all.length} model${all.length !== 1 ? 's' : ''} available`,
          models: all.slice(0, 5),
        })
      } else {
        setOllamaResult({ status: 'error', message: info.error || 'Cannot connect to Ollama' })
      }
    } catch (e: unknown) {
      setOllamaResult({ status: 'error', message: (e as Error).message || 'Request failed' })
    }
  }

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div className="flex items-center gap-2">
          <Bot className="h-4 w-4 text-zinc-400" />
          <span className="text-sm font-semibold text-zinc-200">AI Provider Configuration</span>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={handleClear}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-xl text-[11px] text-zinc-500 hover:text-zinc-300 transition-colors"
            style={{ border: '1px solid rgba(255,255,255,0.06)' }}
          >
            <X className="h-3 w-3" /> Clear all
          </button>
          <button
            onClick={handleSave}
            className="flex items-center gap-1.5 px-4 py-1.5 rounded-xl text-[11px] font-semibold transition-all"
            style={{
              background: saved ? 'rgba(52,211,153,0.12)' : 'rgba(96,165,250,0.12)',
              border: `1px solid ${saved ? 'rgba(52,211,153,0.3)' : 'rgba(96,165,250,0.3)'}`,
              color: saved ? '#34d399' : '#60a5fa',
            }}
          >
            {saved ? <Check className="h-3 w-3" /> : <Save className="h-3 w-3" />}
            {saved ? 'Saved!' : 'Save settings'}
          </button>
        </div>
      </div>

      {/* Info note */}
      <div
        className="flex items-start gap-2.5 rounded-xl px-4 py-3 text-[11px] leading-relaxed text-zinc-400"
        style={{ background: 'rgba(96,165,250,0.05)', border: '1px solid rgba(96,165,250,0.12)' }}
      >
        <Info className="h-3.5 w-3.5 text-blue-400 shrink-0 mt-0.5" />
        Keys are stored in your browser&apos;s localStorage and only sent to your local AdByG0d API — never to third parties directly. They override server environment variables for your session only.
      </div>

      {/* Default provider */}
      <div>
        <FieldLabel label="Default Provider" hint="Used when no provider is explicitly selected" />
        <div className="flex gap-2">
          {(['claude', 'openai', 'ollama'] as const).map(p => {
            const cfg = { claude: { label: 'Claude', color: '#f97316' }, openai: { label: 'GPT-4o', color: '#34d399' }, ollama: { label: 'Ollama', color: '#a78bfa' } }[p]
            return (
              <button
                key={p}
                onClick={() => update({ defaultProvider: p })}
                className="px-4 py-2 rounded-xl text-[12px] font-semibold transition-all"
                style={{
                  background: settings.defaultProvider === p ? `${cfg.color}12` : 'rgba(255,255,255,0.02)',
                  border: `1px solid ${settings.defaultProvider === p ? `${cfg.color}35` : 'rgba(255,255,255,0.06)'}`,
                  color: settings.defaultProvider === p ? cfg.color : 'rgba(100,116,139,0.5)',
                  fontFamily: 'JetBrains Mono, monospace',
                }}
              >
                {cfg.label}
              </button>
            )
          })}
        </div>
      </div>

      {/* Claude */}
      <ProviderSection id="claude" label="Claude (Anthropic)" accentColor="#f97316"
        icon={<Bot className="h-4 w-4" />}
        result={claudeResult} onTest={testClaude} testLabel="Test key">
        <div>
          <FieldLabel label="API Key" hint="console.anthropic.com" href="https://console.anthropic.com/keys" />
          <SecretInput
            value={settings.claudeApiKey}
            onChange={v => update({ claudeApiKey: v })}
            placeholder="sk-ant-api03-…"
            hasStored={storedKeys.claude}
          />
          {storedKeys.claude && !settings.claudeApiKey && (
            <div className="mt-1 text-[10px] text-zinc-600" style={MONO}>
              Stored: {maskKey(loadAISettings().claudeApiKey)}
            </div>
          )}
        </div>
        <div className="text-[10px] text-zinc-600 leading-relaxed">
          Available models: claude-sonnet-4-6 · claude-opus-4-8 · claude-haiku-4-5
        </div>
      </ProviderSection>

      {/* OpenAI */}
      <ProviderSection id="openai" label="GPT-4o (OpenAI)" accentColor="#34d399"
        icon={<Server className="h-4 w-4" />}
        result={openaiResult} onTest={testOpenAI} testLabel="Test key">
        <div>
          <FieldLabel label="API Key" hint="platform.openai.com" href="https://platform.openai.com/api-keys" />
          <SecretInput
            value={settings.openaiApiKey}
            onChange={v => update({ openaiApiKey: v.trim() })}
            placeholder="sk-proj-…"
            hasStored={storedKeys.openai}
          />
          {storedKeys.openai && !settings.openaiApiKey && (
            <div className="mt-1 text-[10px] text-zinc-600" style={MONO}>
              Stored: {maskKey(loadAISettings().openaiApiKey)}
            </div>
          )}
        </div>
        <div>
          <FieldLabel label="Base URL" hint="Change for Azure OpenAI or custom endpoints" />
          <TextInput value={settings.openaiBaseUrl} onChange={v => update({ openaiBaseUrl: v })} placeholder="https://api.openai.com/v1" />
        </div>
        <div className="text-[10px] text-zinc-600 leading-relaxed">
          Available models: gpt-4.1 · gpt-4.1-mini · gpt-4o · gpt-4o-mini · o3 · o4-mini · o1 · gpt-4-turbo
        </div>
      </ProviderSection>

      {/* Ollama */}
      <ProviderSection id="ollama" label="Ollama (Local)" accentColor="#a78bfa"
        icon={<Wifi className="h-4 w-4" />}
        result={ollamaResult} onTest={testOllama} testLabel="Detect models">
        <div>
          <FieldLabel label="Server URL" hint="No key needed — runs locally" />
          <TextInput value={settings.ollamaBaseUrl} onChange={v => update({ ollamaBaseUrl: v })} placeholder="http://localhost:11434" />
        </div>
        <div>
          <FieldLabel label="Default Model" hint="Must be pulled first: ollama pull llama3.2" />
          <TextInput value={settings.ollamaModel} onChange={v => update({ ollamaModel: v })} placeholder="llama3.2" />
          {ollamaResult.status === 'ok' && ollamaModels.length > 0 && (
            <div className="mt-2">
              <div className="text-[9px] text-zinc-600 mb-1.5 uppercase tracking-widest" style={MONO}>Installed models</div>
              <OllamaModelPicker models={ollamaModels} selected={settings.ollamaModel} onSelect={m => update({ ollamaModel: m })} />
            </div>
          )}
        </div>
        <div className="text-[10px] text-zinc-600 leading-relaxed">
          Install Ollama at <span className="text-zinc-500">ollama.com</span> · Recommended: llama3.2 · mistral · codellama · phi3
        </div>
      </ProviderSection>
    </div>
  )
}
