'use client'

import { useEffect, useRef } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import { motion, AnimatePresence } from 'framer-motion'
import { CheckCircle, AlertCircle, Loader2, X, FileArchive } from 'lucide-react'
import { useImportStore } from '@/lib/importStore'
import { jobsApi } from '@/lib/api'

export function GlobalImportBar() {
  const { job, pct, message, phase, done, error, updateProgress, clearImport } = useImportStore()
  const qc = useQueryClient()
  const clearTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null)
  const progressPct = Math.min(100, Math.max(0, Number.isFinite(pct) ? pct : 0))

  useEffect(() => {
    if (!job) return

    const es = jobsApi.stream(job.jobId, job.streamToken)

    es.onmessage = (ev) => {
      try {
        const d = JSON.parse(ev.data)
        if (d.heartbeat) return
        updateProgress({
          pct: d.pct,
          message: d.message,
          phase: d.phase,
          done: d.done,
          error: d.error,
        })
        if (d.done || d.error) {
          es.close()
          // Invalidate all assessment-related queries so every page refreshes
          qc.invalidateQueries({ queryKey: ['assessments'] })
          qc.invalidateQueries({ queryKey: ['graph'] })
          qc.invalidateQueries({ queryKey: ['findings'] })
          clearTimerRef.current = setTimeout(clearImport, d.error ? 5000 : 2500)
        }
      } catch { /* ignore */ }
    }

    es.onerror = () => {
      updateProgress({ error: 'Connection lost', done: true })
      es.close()
      clearTimerRef.current = setTimeout(clearImport, 5000)
    }

    return () => {
      es.close()
      if (clearTimerRef.current) clearTimeout(clearTimerRef.current)
    }
  }, [job, updateProgress, qc, clearImport])

  const handleDismiss = () => {
    if (clearTimerRef.current) clearTimeout(clearTimerRef.current)
    clearImport()
  }

  return (
    <AnimatePresence>
      {job && (
        <motion.div
          initial={{ opacity: 0, y: 80 }}
          animate={{ opacity: 1, y: 0 }}
          exit={{ opacity: 0, y: 80 }}
          transition={{ duration: 0.35, ease: [0.23, 1, 0.32, 1] }}
          className="fixed bottom-6 left-1/2 z-[200] w-[420px] max-w-[calc(100vw-2rem)] -translate-x-1/2"
        >
          <div
            className="relative overflow-hidden rounded-2xl border"
            style={{
              background: '#000',
              borderColor: error ? 'rgba(239,68,68,0.4)' : done ? 'rgba(34,197,94,0.4)' : 'rgba(99,102,241,0.4)',
              boxShadow: error
                ? '0 0 40px rgba(239,68,68,0.15), 0 20px 60px rgba(0,0,0,0.5)'
                : done
                ? '0 0 40px rgba(34,197,94,0.15), 0 20px 60px rgba(0,0,0,0.5)'
                : '0 0 40px rgba(99,102,241,0.2), 0 20px 60px rgba(0,0,0,0.5)',
            }}
          >
            {/* Top accent line */}
            <div
              className="absolute inset-x-0 top-0 h-px"
              style={{
                background: error
                  ? 'linear-gradient(90deg, transparent, rgba(239,68,68,0.9), transparent)'
                  : done
                  ? 'linear-gradient(90deg, transparent, rgba(34,197,94,0.9), transparent)'
                  : 'linear-gradient(90deg, transparent, rgba(99,102,241,0.9), rgba(168,85,247,0.7), transparent)',
              }}
            />

            <div className="p-4">
              <div className="flex items-start gap-3">
                {/* Icon */}
                <div
                  className="mt-0.5 flex h-8 w-8 shrink-0 items-center justify-center rounded-xl"
                  style={{
                    background: error
                      ? 'rgba(239,68,68,0.15)'
                      : done
                      ? 'rgba(34,197,94,0.15)'
                      : 'rgba(99,102,241,0.15)',
                    border: `1px solid ${error ? 'rgba(239,68,68,0.3)' : done ? 'rgba(34,197,94,0.3)' : 'rgba(99,102,241,0.3)'}`,
                  }}
                >
                  {error ? (
                    <AlertCircle className="h-4 w-4 text-red-400" />
                  ) : done ? (
                    <CheckCircle className="h-4 w-4 text-emerald-400" />
                  ) : (
                    <FileArchive className="h-4 w-4 text-indigo-400" />
                  )}
                </div>

                {/* Content */}
                <div className="min-w-0 flex-1">
                  <div className="flex items-center justify-between gap-2">
                    <span className="truncate text-sm font-semibold text-white">{job.filename}</span>
                    {(done || error) && (
                      <button
                        type="button"
                        aria-label="Dismiss import progress"
                        onClick={handleDismiss}
                        className="shrink-0 rounded-lg p-1 text-zinc-500 transition hover:text-zinc-300"
                      >
                        <X className="h-3.5 w-3.5" />
                      </button>
                    )}
                    {!done && !error && (
                      <Loader2 className="h-3.5 w-3.5 shrink-0 animate-spin text-indigo-400" />
                    )}
                  </div>

                  <p className="mt-0.5 text-xs text-zinc-400">{error ?? message}</p>

                  {!error && (
                    <div className="mt-2.5">
                      <div className="mb-1 flex items-center justify-between">
                        {phase && (
                          <span className="text-[10px] font-bold uppercase tracking-[0.2em] text-zinc-500">
                            {phase}
                          </span>
                        )}
                        <span
                          className="ml-auto text-[10px] font-mono tabular-nums"
                          style={{ color: done ? '#4ade80' : '#818cf8' }}
                        >
                          {progressPct}%
                        </span>
                      </div>
                      <div className="h-1 w-full overflow-hidden rounded-full bg-white/10">
                        <motion.div
                          className="h-full rounded-full"
                          animate={{ width: `${progressPct}%` }}
                          transition={{ duration: 0.5, ease: 'easeOut' }}
                          style={{
                            background: done
                              ? 'linear-gradient(90deg, #22c55e, #4ade80)'
                              : 'linear-gradient(90deg, #6366f1, #a855f7, #ec4899)',
                          }}
                        />
                      </div>
                    </div>
                  )}
                </div>
              </div>
            </div>
          </div>
        </motion.div>
      )}
    </AnimatePresence>
  )
}
