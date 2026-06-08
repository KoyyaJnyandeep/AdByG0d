'use client'

import { copyText } from '@/lib/clipboard'
import { useState, useCallback } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import {
  X, Download, Copy, CheckCheck, Terminal,
  Zap, BookOpen,
} from 'lucide-react'
import { CollectorScriptResult } from '@/lib/powershellCollectorGenerator'
import { cn } from '@/lib/utils'
import { downloadTextFile } from '@/lib/clientDownload'

interface PSScriptModalProps {
  result: CollectorScriptResult
  domain: string
  onClose: () => void
}

const TABS = [
  { id: 'script',   label: 'Collector Script', icon: Terminal },
  { id: 'oneliner', label: 'Quick Run',         icon: Zap      },
  { id: 'guide',    label: 'Import Guide',      icon: BookOpen },
] as const

type Tab = (typeof TABS)[number]['id']

function useCopy(text: string) {
  const [copied, setCopied] = useState(false)
  const copy = useCallback(async () => {
    try {
      await copyText(text)
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    } catch {
      // clipboard permission denied — silently ignore
    }
  }, [text])
  return { copied, copy }
}

function downloadScript(script: string, domain: string) {
  // Prepend UTF-8 BOM so PowerShell 5.1 reads the file as UTF-8 rather than ANSI.
  // Without the BOM, box-drawing chars (e.g. ╝ = E2 95 9D in UTF-8) are decoded
  // as Windows-1252 where byte 0x9D is a curly quote — a valid PS string delimiter
  // — causing "string missing terminator" parse errors.
  downloadTextFile(`Invoke-AdByGodCollector-${domain || 'collector'}.ps1`, '﻿' + script, 'text/plain;charset=utf-8')
}

export function PSScriptModal({ result, domain, onClose }: PSScriptModalProps) {
  const [tab, setTab] = useState<Tab>('script')
  const scriptCopy   = useCopy(result.script)
  const oneLinerCopy = useCopy(result.runOneLiner)

  return (
    <div
      className="fixed inset-0 z-[60] flex flex-col"
      style={{ background: '#000', backdropFilter: 'blur(32px)' }}
    >
      <motion.div
        initial={{ opacity: 0, y: 16 }}
        animate={{ opacity: 1, y: 0 }}
        exit={{ opacity: 0, y: 16 }}
        transition={{ duration: 0.28, ease: [0.23, 1, 0.32, 1] }}
        className="flex h-full flex-col overflow-hidden"
      >
        {/* Top gradient line */}
        <div className="absolute inset-x-0 top-0 h-px"
          style={{ background: 'linear-gradient(90deg, transparent, rgba(250,204,21,0.9) 30%, rgba(251,146,60,0.8) 70%, transparent)' }} />

        {/* Header */}
        <div className="flex shrink-0 items-center justify-between gap-4 border-b border-white/8 px-6 py-4"
          style={{ background: '#000' }}>
          <div className="flex items-center gap-3">
            <div className="flex h-9 w-9 items-center justify-center rounded-xl"
              style={{ background: 'rgba(250,204,21,0.12)', border: '1px solid rgba(250,204,21,0.3)' }}>
              <Terminal className="h-4 w-4 text-yellow-400" />
            </div>
            <div>
              <div className="text-[10px] font-bold uppercase tracking-[0.2em] text-yellow-400/60">Windows Local Collector</div>
              <h2 className="text-base font-bold text-white">Invoke-AdByGodCollector.ps1</h2>
            </div>
            <div className="hidden sm:flex items-center gap-2 ml-2">
              {[
                { label: `${result.moduleCount} modules`,   color: '#facc15' },
                { label: `${result.commandCount} commands`, color: '#fb923c' },
              ].map(s => (
                <span key={s.label}
                  className="rounded-full px-2.5 py-1 text-[10px] font-bold tracking-wide"
                  style={{ background: `${s.color}12`, border: `1px solid ${s.color}30`, color: s.color }}>
                  {s.label}
                </span>
              ))}
            </div>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={() => downloadScript(result.script, domain)}
              className="flex items-center gap-2 rounded-xl px-4 py-2 text-xs font-bold tracking-wide transition-all hover:brightness-110"
              style={{
                background: 'linear-gradient(135deg, rgba(250,204,21,0.85), rgba(251,146,60,0.8))',
                border: '1px solid rgba(250,204,21,0.4)',
                color: '#000',
                boxShadow: '0 0 24px rgba(250,204,21,0.25)',
              }}
            >
              <Download className="h-3.5 w-3.5" /> Download .ps1
            </button>
            <button onClick={onClose}
              className="rounded-xl border border-white/10 p-2 text-zinc-500 transition hover:border-white/20 hover:text-zinc-300">
              <X className="h-4 w-4" />
            </button>
          </div>
        </div>

        {/* Tab bar */}
        <div className="flex shrink-0 items-center gap-1 border-b border-white/6 px-6 py-2"
          style={{ background: '#000' }}>
          {TABS.map(t => {
            const Icon = t.icon
            const active = tab === t.id
            return (
              <button key={t.id} onClick={() => setTab(t.id)}
                className="flex items-center gap-1.5 rounded-lg px-3.5 py-1.5 text-xs font-semibold transition-all"
                style={active
                  ? { background: 'rgba(250,204,21,0.12)', border: '1px solid rgba(250,204,21,0.3)', color: '#fde047' }
                  : { background: 'transparent', border: '1px solid transparent', color: 'rgba(161,161,170,0.5)' }}>
                <Icon className="h-3 w-3" /> {t.label}
              </button>
            )
          })}
        </div>

        {/* Body */}
        <div className="min-h-0 flex-1 overflow-hidden">
          <AnimatePresence mode="wait">
            {tab === 'script' && (
              <motion.div key="script"
                initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
                transition={{ duration: 0.15 }}
                className="relative flex h-full flex-col"
              >
                <button
                  onClick={scriptCopy.copy}
                  className={cn(
                    'absolute right-5 top-4 z-10 flex items-center gap-1.5 rounded-xl px-3.5 py-2 text-xs font-bold tracking-wide transition-all',
                    scriptCopy.copied ? 'text-emerald-300' : 'text-yellow-300 hover:brightness-110',
                  )}
                  style={{
                    background: scriptCopy.copied ? 'rgba(52,211,153,0.12)' : 'rgba(250,204,21,0.12)',
                    border: `1px solid ${scriptCopy.copied ? 'rgba(52,211,153,0.35)' : 'rgba(250,204,21,0.3)'}`,
                    boxShadow: scriptCopy.copied ? '0 0 20px rgba(52,211,153,0.2)' : '0 0 16px rgba(250,204,21,0.15)',
                  }}
                >
                  {scriptCopy.copied
                    ? <><CheckCheck className="h-3.5 w-3.5" /> Copied!</>
                    : <><Copy className="h-3.5 w-3.5" /> Copy Script</>}
                </button>
                <pre
                  className="h-full overflow-auto px-6 py-5 font-mono text-xs leading-5 text-zinc-300"
                  style={{ background: '#000', tabSize: 4 }}
                >
                  <code>{result.script}</code>
                </pre>
              </motion.div>
            )}

            {tab === 'oneliner' && (
              <motion.div key="oneliner"
                initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
                transition={{ duration: 0.15 }}
                className="flex h-full flex-col items-center justify-center gap-8 p-10"
              >
                <div className="w-full max-w-3xl space-y-6">
                  <div>
                    <div className="mb-2 text-[10px] font-bold uppercase tracking-[0.2em] text-yellow-400/60">
                      Quick Run (after downloading .ps1)
                    </div>
                    <div className="group relative overflow-hidden rounded-2xl"
                      style={{ background: '#000', border: '1px solid rgba(250,204,21,0.2)' }}>
                      <pre className="overflow-x-auto px-5 py-4 font-mono text-sm text-yellow-200/90 leading-6">
                        {result.runOneLiner}
                      </pre>
                      <button onClick={oneLinerCopy.copy}
                        className="absolute right-3 top-3 flex items-center gap-1.5 rounded-lg px-2.5 py-1.5 text-[10px] font-bold opacity-0 transition-all group-hover:opacity-100"
                        style={{
                          background: oneLinerCopy.copied ? 'rgba(52,211,153,0.15)' : 'rgba(250,204,21,0.12)',
                          border: `1px solid ${oneLinerCopy.copied ? 'rgba(52,211,153,0.3)' : 'rgba(250,204,21,0.25)'}`,
                          color: oneLinerCopy.copied ? '#6ee7b7' : '#fde047',
                        }}>
                        {oneLinerCopy.copied
                          ? <><CheckCheck className="h-3 w-3" /> Copied</>
                          : <><Copy className="h-3 w-3" /> Copy</>}
                      </button>
                    </div>
                  </div>

                  <div className="rounded-2xl border border-white/6 bg-black p-5 space-y-2">
                    <div className="text-[10px] font-bold uppercase tracking-[0.2em] text-zinc-500">Script Parameters</div>
                    {[
                      ['-Domain',     domain || 'corp.local',      'Target AD domain'],
                      ['-DCServer',   '10.10.10.1',                'Domain controller IP'],
                      ['-Username',   'scanner@corp.local',         'Optional — domain account'],
                      ['-Password',   '(supply at runtime)',        'Optional — account password'],
                      ['-OutputPath', '%TEMP%\\adbygod-collector',  'Where to write the zip'],
                    ].map(([param, example, desc]) => (
                      <div key={param} className="flex items-baseline gap-3 text-xs">
                        <span className="shrink-0 font-mono text-yellow-300/80">{param}</span>
                        <span className="shrink-0 font-mono text-zinc-500">{example}</span>
                        <span className="text-zinc-600">{desc}</span>
                      </div>
                    ))}
                  </div>
                </div>
              </motion.div>
            )}

            {tab === 'guide' && (
              <motion.div key="guide"
                initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
                transition={{ duration: 0.15 }}
                className="flex h-full flex-col items-center justify-center gap-6 p-10"
              >
                <div className="w-full max-w-2xl space-y-4">
                  <div className="text-center mb-2">
                    <div className="text-[10px] font-bold uppercase tracking-[0.2em] text-yellow-400/60">How to collect and import</div>
                    <h3 className="mt-1 text-lg font-bold text-white">3 steps to get AD data into AdByGod</h3>
                  </div>
                  {[
                    {
                      n: '01',
                      title: 'Download and run on a domain-joined Windows host',
                      body: 'Click "Download .ps1" above. Copy the file to a domain-joined Windows machine. Open PowerShell as a standard domain user and run it.',
                      color: '#facc15',
                    },
                    {
                      n: '02',
                      title: 'Find the output zip',
                      body: `The script writes adbygod-${domain || 'corp.local'}-<timestamp>.zip to %TEMP%\\adbygod-collector by default. Change -OutputPath to control where it lands.`,
                      color: '#fb923c',
                    },
                    {
                      n: '03',
                      title: "Drag the zip into AdByGod's Import drop zone",
                      body: 'On the Assessments page, drag the zip onto the Import drop zone (or click Browse Files). AdByGod detects the native format and creates an assessment automatically.',
                      color: '#a78bfa',
                    },
                  ].map(step => (
                    <div key={step.n} className="flex gap-4 rounded-2xl border border-white/6 bg-black p-5">
                      <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl font-mono text-lg font-bold"
                        style={{ background: `${step.color}12`, border: `1px solid ${step.color}25`, color: step.color }}>
                        {step.n}
                      </div>
                      <div className="min-w-0">
                        <div className="text-sm font-semibold text-white">{step.title}</div>
                        <p className="mt-1 text-xs leading-5 text-zinc-500">{step.body}</p>
                      </div>
                    </div>
                  ))}
                </div>
              </motion.div>
            )}
          </AnimatePresence>
        </div>
      </motion.div>
    </div>
  )
}
