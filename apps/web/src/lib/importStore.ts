import { create } from 'zustand'

export interface ImportJob {
  jobId: string
  streamToken: string
  filename: string
}

interface ImportState {
  job: ImportJob | null
  pct: number
  message: string
  phase: string
  done: boolean
  error: string | null
  startImport: (job: ImportJob) => void
  updateProgress: (event: { pct?: number; message?: string; phase?: string; done?: boolean; error?: string }) => void
  clearImport: () => void
}

function clampProgress(value: number) {
  if (!Number.isFinite(value)) return 0
  return Math.min(100, Math.max(0, Math.round(value)))
}

export const useImportStore = create<ImportState>((set) => ({
  job: null,
  pct: 0,
  message: 'Starting…',
  phase: '',
  done: false,
  error: null,

  startImport: (job) => set({ job, pct: 0, message: 'Uploading…', phase: '', done: false, error: null }),

  updateProgress: (event) =>
    set((s) => ({
      pct: event.pct !== undefined ? clampProgress(event.pct) : s.pct,
      message: event.message ?? s.message,
      phase: event.phase ?? s.phase,
      done: event.done ?? s.done,
      error: event.error ?? s.error,
    })),

  clearImport: () => set({ job: null, pct: 0, message: 'Starting…', phase: '', done: false, error: null }),
}))
