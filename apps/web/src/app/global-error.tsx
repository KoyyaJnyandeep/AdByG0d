
'use client'

import './globals.css'
import { AlertOctagon, RefreshCw } from 'lucide-react'

export default function GlobalError({
  error,
  reset,
}: {
  error: Error & { digest?: string }
  reset: () => void
}) {
  return (
    <html lang="en" className="dark">
      <body className="bg-black text-white">
        <main className="grid min-h-screen place-items-center px-5 py-10">
          <section className="w-full max-w-2xl overflow-hidden rounded-[32px] border border-rose-300/20 bg-black p-7 shadow-[0_28px_90px_rgba(0,0,0,0.65)]">
            <div className="inline-flex items-center gap-2 rounded-full border border-rose-300/25 bg-rose-300/10 px-3 py-1 text-xs font-bold uppercase tracking-[0.22em] text-rose-100">
              <AlertOctagon className="h-3.5 w-3.5" /> Application Recovery
            </div>
            <h1 className="mt-5 text-3xl font-semibold tracking-tight text-white">The application shell failed to load.</h1>
            <p className="mt-3 max-w-xl text-sm leading-6 text-zinc-400">
              Retry the full application boundary. This path is reserved for root layout and provider failures.
            </p>
            {error.digest ? (
              <div className="mt-5 rounded-2xl border border-white/10 bg-white/[0.03] px-4 py-3 font-mono text-xs text-zinc-400">
                Reference: {error.digest}
              </div>
            ) : null}
            <div className="mt-6">
              <button
                type="button"
                onClick={() => reset()}
                className="inline-flex items-center gap-2 rounded-2xl border border-cyan-300/30 bg-cyan-300/10 px-4 py-2.5 text-sm font-semibold text-cyan-50 transition hover:border-cyan-200/50 hover:bg-cyan-300/15"
              >
                <RefreshCw className="h-4 w-4" /> Retry application
              </button>
            </div>
          </section>
        </main>
      </body>
    </html>
  )
}
