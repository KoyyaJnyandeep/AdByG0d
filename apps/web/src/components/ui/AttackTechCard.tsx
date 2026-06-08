'use client'

import { copyText } from '@/lib/clipboard'
import { useState, useMemo, useCallback } from 'react'
import { AnimatePresence, motion } from 'framer-motion'
import {
  ChevronRight, Copy, Check, AlertTriangle, Terminal,
  Monitor, FileText, ShieldAlert, Eye, EyeOff,
} from 'lucide-react'
import { cn } from '@/lib/utils'
import { reportsApi } from '@/lib/api'

const MONO = { fontFamily: 'JetBrains Mono, monospace' }

const RISK_COLORS: Record<string, string> = {
  CRITICAL: '#ff4d6d',
  HIGH:     '#ffa94d',
  MEDIUM:   '#ffd166',
  LOW:      '#51cf66',
}

export type AttackCommand = {
  label: string
  command: string
  params: string[]
  platform?: string
}

export type AttackTechnique = {
  id: string
  title: string
  tool: string
  risk_level: string
  platform: string
  mitre_technique_id: string
  description: string
  commands: AttackCommand[]
}

function extractParams(command: string): string[] {
  const matches = command.match(/\{([A-Za-z_][A-Za-z0-9_]*)\}/g) ?? []
  return [...new Set(matches.map(m => m.slice(1, -1)))]
}

function fillCommand(command: string, values: Record<string, string>): string {
  return command.replace(/\{([A-Za-z_][A-Za-z0-9_]*)\}/g, (_, key) =>
    values[key] ? values[key] : `{${key}}`
  )
}

function PlatformBadge({ platform }: { platform?: string }) {
  if (!platform) return null
  const isWin = platform === 'windows'
  return (
    <span
      className="flex items-center gap-1 rounded border px-1.5 py-0.5 text-[9px] font-bold uppercase tracking-wide flex-shrink-0"
      style={{
        color: isWin ? '#60a5fa' : '#34d399',
        borderColor: isWin ? '#60a5fa30' : '#34d39930',
        background: isWin ? '#60a5fa0d' : '#34d3990d',
      }}
    >
      {isWin ? <Monitor className="h-2.5 w-2.5" /> : <Terminal className="h-2.5 w-2.5" />}
      {isWin ? 'Win' : 'Linux'}
    </span>
  )
}

function CopyButton({ text, size = 'sm' }: { text: string; size?: 'sm' | 'xs' }) {
  const [copied, setCopied] = useState(false)
  const copy = useCallback(() => {
    copyText(text)
    setCopied(true)
    setTimeout(() => setCopied(false), 1600)
  }, [text])
  return (
    <button
      onClick={copy}
      className={cn(
        'flex items-center gap-1 rounded border transition-all duration-200',
        size === 'xs' ? 'px-1.5 py-0.5 text-[9px]' : 'px-2 py-0.5 text-[10px]',
      )}
      style={
        copied
          ? { color: '#34d399', borderColor: '#34d39940', background: '#34d3990d' }
          : { color: '#52525b', borderColor: 'rgba(255,255,255,0.09)' }
      }
    >
      {copied ? <Check className="h-2.5 w-2.5" /> : <Copy className="h-2.5 w-2.5" />}
      {copied ? 'copied' : 'copy'}
    </button>
  )
}

function CommandBlock({
  cmd,
  globalParams,
  platformFilter,
}: {
  cmd: AttackCommand
  globalParams: Record<string, string>
  platformFilter: 'linux' | 'windows' | 'all'
}) {
  const [localParams, setLocalParams] = useState<Record<string, string>>({})
  const [showRaw, setShowRaw] = useState(false)

  if (
    platformFilter !== 'all' &&
    cmd.platform &&
    cmd.platform !== platformFilter
  ) return null

  const merged = { ...globalParams, ...localParams }
  const paramKeys = extractParams(cmd.command)
  const filled = fillCommand(cmd.command, merged)
  const allFilled = paramKeys.every(k => !!merged[k])

  return (
    <div
      className="rounded-xl border p-3 space-y-2.5"
      style={{ background: 'rgba(0,0,0,0.5)', borderColor: 'rgba(255,255,255,0.06)' }}
    >
      {/* Command header */}
      <div className="flex items-center justify-between gap-2">
        <div className="flex items-center gap-2 min-w-0">
          <span
            className="text-[10px] font-semibold text-zinc-300 truncate"
            style={MONO}
          >
            {cmd.label}
          </span>
          <PlatformBadge platform={cmd.platform} />
        </div>
        <div className="flex items-center gap-1.5 flex-shrink-0">
          {paramKeys.length > 0 && (
            <button
              onClick={() => setShowRaw(v => !v)}
              className="flex items-center gap-1 rounded border px-1.5 py-0.5 text-[9px] text-zinc-600 border-white/8 hover:text-zinc-400 transition-colors"
            >
              {showRaw ? <Eye className="h-2.5 w-2.5" /> : <EyeOff className="h-2.5 w-2.5" />}
              {showRaw ? 'filled' : 'raw'}
            </button>
          )}
          <CopyButton text={filled} size="xs" />
        </div>
      </div>

      {/* Param inputs */}
      {paramKeys.length > 0 && !showRaw && (
        <div className="grid grid-cols-2 gap-1.5">
          {paramKeys.map(key => (
            <div key={key}>
              <label
                className="block text-[9px] text-zinc-600 mb-0.5 uppercase tracking-wider"
                style={MONO}
              >
                {key}
              </label>
              <input
                value={localParams[key] ?? globalParams[key] ?? ''}
                onChange={e => setLocalParams(p => ({ ...p, [key]: e.target.value }))}
                placeholder={key}
                className="w-full rounded-lg border bg-transparent px-2 py-1 text-[10px] text-zinc-200 outline-none placeholder:text-zinc-700 focus:border-purple-500/50 transition-colors"
                style={{ ...MONO, borderColor: 'rgba(255,255,255,0.08)' }}
              />
            </div>
          ))}
        </div>
      )}

      {/* Command display */}
      <pre
        className="whitespace-pre-wrap break-all text-[10px] leading-relaxed rounded-lg p-2"
        style={{
          ...MONO,
          color: allFilled ? '#86efac' : '#4b5563',
          background: 'rgba(0,0,0,0.3)',
        }}
      >
        {showRaw ? cmd.command : filled}
      </pre>
    </div>
  )
}

export type AttackTechCardProps = {
  tech: AttackTechnique
  isOpen: boolean
  onToggle: () => void
  accentColor?: string
  globalParams?: Record<string, string>
  platformFilter?: 'linux' | 'windows' | 'all'
  onExportToReport?: (tech: AttackTechnique) => void
}

export function AttackTechCard({
  tech,
  isOpen,
  onToggle,
  accentColor = '#a78bfa',
  globalParams = {},
  platformFilter = 'all',
  onExportToReport,
}: AttackTechCardProps) {
  const [authConfirmed, setAuthConfirmed] = useState(false)
  const [exporting, setExporting] = useState(false)
  const [exportDone, setExportDone] = useState(false)

  const rColor = RISK_COLORS[tech.risk_level?.toUpperCase()] ?? '#64748b'
  const needsGate = ['CRITICAL', 'HIGH'].includes(tech.risk_level?.toUpperCase())
  const locked = needsGate && !authConfirmed

  const visibleCmds = useMemo(() => {
    if (platformFilter === 'all') return tech.commands
    return tech.commands.filter(c => !c.platform || c.platform === platformFilter)
  }, [tech.commands, platformFilter])

  const handleExport = useCallback(async () => {
    if (onExportToReport) {
      onExportToReport(tech)
      return
    }
    setExporting(true)
    try {
      await reportsApi.exportTechnique({
        technique_id: tech.id,
        title: tech.title,
        mitre_id: tech.mitre_technique_id,
        risk_level: tech.risk_level,
        description: tech.description,
      })
      setExportDone(true)
      setTimeout(() => setExportDone(false), 2000)
    } catch {
      // non-blocking — report endpoint may not be available in all contexts
    } finally {
      setExporting(false)
    }
  }, [tech, onExportToReport])

  return (
    <div
      className="rounded-xl border transition-all duration-150"
      style={{
        borderColor: isOpen ? `${accentColor}35` : 'rgba(255,255,255,0.05)',
        background: isOpen ? `${accentColor}07` : 'rgba(255,255,255,0.01)',
      }}
    >
      {/* ── Header row ── */}
      <button
        className="flex w-full items-center gap-3 px-4 py-3 text-left"
        onClick={onToggle}
      >
        <ChevronRight
          className={cn(
            'h-3.5 w-3.5 flex-shrink-0 transition-transform text-zinc-600',
            isOpen && 'rotate-90',
          )}
          style={isOpen ? { color: accentColor } : {}}
        />

        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-sm font-semibold text-zinc-100 leading-tight">
              {tech.title}
            </span>
            <span
              className="rounded border px-1.5 py-0.5 text-[9px] font-bold uppercase flex-shrink-0"
              style={{ color: rColor, borderColor: `${rColor}30`, background: `${rColor}10` }}
            >
              {tech.risk_level}
            </span>
            <PlatformBadge platform={tech.platform} />
          </div>
          <div className="flex items-center gap-2 mt-0.5">
            <span className="text-[10px] text-zinc-600 truncate" style={MONO}>
              {tech.tool}
            </span>
            <span className="text-zinc-800 flex-shrink-0">·</span>
            <span className="text-[10px] text-zinc-600 flex-shrink-0" style={MONO}>
              {tech.mitre_technique_id}
            </span>
          </div>
        </div>

        {/* Export to report — must be a div, not button, because it sits inside the toggle <button> */}
        <div
          role="button"
          tabIndex={0}
          aria-disabled={exporting}
          onClick={e => { e.stopPropagation(); if (!exporting) handleExport() }}
          onKeyDown={e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); e.stopPropagation(); if (!exporting) handleExport() } }}
          className="flex items-center gap-1 rounded border px-2 py-1 text-[9px] transition-all flex-shrink-0 cursor-pointer select-none"
          style={
            exportDone
              ? { color: '#34d399', borderColor: '#34d39940', background: '#34d3990d' }
              : exporting
              ? { color: '#52525b', borderColor: 'rgba(255,255,255,0.04)', cursor: 'default' }
              : { color: '#3f3f46', borderColor: 'rgba(255,255,255,0.07)' }
          }
          title="Add to report"
        >
          <FileText className="h-2.5 w-2.5" />
          {exporting ? '…' : exportDone ? 'added' : 'report'}
        </div>
      </button>

      {/* ── Expanded body ── */}
      <AnimatePresence initial={false}>
        {isOpen && (
          <motion.div
            key="body"
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: 'auto' }}
            exit={{ opacity: 0, height: 0 }}
            transition={{ duration: 0.18, ease: 'easeInOut' }}
            className="overflow-hidden"
          >
            <div className="border-t border-white/5 px-4 pb-4 pt-3 space-y-3">
              <p className="text-[11px] text-zinc-400 leading-relaxed">
                {tech.description}
              </p>

              {/* Risk gate */}
              {needsGate && (
                <div
                  className="flex items-start gap-3 rounded-xl border p-3"
                  style={{ background: `${rColor}08`, borderColor: `${rColor}22` }}
                >
                  <ShieldAlert
                    className="h-4 w-4 flex-shrink-0 mt-0.5"
                    style={{ color: rColor }}
                  />
                  <div className="flex-1 min-w-0">
                    <p className="text-[10px] font-bold mb-1 uppercase tracking-wide" style={{ color: rColor }}>
                      {tech.risk_level === 'CRITICAL' ? 'Critical impact' : 'High impact'} — requires authorization
                    </p>
                    <p className="text-[10px] text-zinc-500 mb-2 leading-relaxed">
                      Confirm this technique is within your current engagement scope before copying commands.
                    </p>
                    <label className="flex items-center gap-2 cursor-pointer select-none">
                      <input
                        type="checkbox"
                        checked={authConfirmed}
                        onChange={e => setAuthConfirmed(e.target.checked)}
                        className="rounded accent-purple-500"
                      />
                      <span className="text-[10px] text-zinc-300">
                        I confirm this engagement is authorized
                      </span>
                    </label>
                  </div>
                </div>
              )}

              {/* Commands — locked or unlocked */}
              {locked ? (
                <div
                  className="flex flex-col items-center gap-2 rounded-xl border py-5"
                  style={{ borderColor: 'rgba(255,255,255,0.05)', background: 'rgba(0,0,0,0.2)' }}
                >
                  <AlertTriangle className="h-4 w-4 text-zinc-700" />
                  <p className="text-[10px] text-zinc-600">
                    Confirm authorization above to reveal commands
                  </p>
                </div>
              ) : (
                <div className="space-y-2">
                  {visibleCmds.length === 0 ? (
                    <p className="text-center text-[10px] text-zinc-600 py-4">
                      No commands available for selected platform
                    </p>
                  ) : (
                    visibleCmds.map(cmd => (
                      <CommandBlock
                        key={cmd.label}
                        cmd={cmd}
                        globalParams={globalParams}
                        platformFilter={platformFilter}
                      />
                    ))
                  )}
                </div>
              )}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  )
}
