
'use client'

import Link from 'next/link'
import { AlertTriangle, ArrowLeft, RefreshCw } from 'lucide-react'

export default function ErrorPage({
  error,
  reset,
}: {
  error: Error & { digest?: string }
  reset: () => void
}) {
  return (
    <main className="grid min-h-screen place-items-center bg-black px-5 py-10 text-white">
      <section className="w-full max-w-2xl overflow-hidden rounded-[32px] border border-rose-300/20 bg-black p-7 shadow-[0_28px_90px_rgba(0,0,0,0.65)]">
        <div className="inline-flex items-center gap-2 rounded-full border border-rose-300/25 bg-rose-300/10 px-3 py-1 text-xs font-bold uppercase tracking-[0.22em] text-rose-100">
          <AlertTriangle className="h-3.5 w-3.5" /> Route Recovery
        </div>
        <h1 className="mt-5 text-3xl font-semibold tracking-tight text-white">This workspace panel could not render.</h1>
        <p className="mt-3 max-w-xl text-sm leading-6 text-zinc-400">
          Retry the route to refresh server data and client state. The rest of the platform remains available.
        </p>
        {error.digest ? (
          <div className="mt-5 rounded-2xl border border-white/10 bg-white/[0.03] px-4 py-3 font-mono text-xs text-zinc-400">
            Reference: {error.digest}
          </div>
        ) : null}
        <div className="mt-6 flex flex-wrap gap-3">
          <button
            type="button"
            onClick={() => reset()}
            className="inline-flex items-center gap-2 rounded-2xl border border-cyan-300/30 bg-cyan-300/10 px-4 py-2.5 text-sm font-semibold text-cyan-50 transition hover:border-cyan-200/50 hover:bg-cyan-300/15"
          >
            <RefreshCw className="h-4 w-4" /> Retry route
          </button>
          <Link
            href="/"
            className="inline-flex items-center gap-2 rounded-2xl border border-white/10 bg-white/[0.03] px-4 py-2.5 text-sm font-semibold text-zinc-100 transition hover:border-white/20 hover:bg-white/[0.06]"
          >
            <ArrowLeft className="h-4 w-4" /> Return to dashboard
          </Link>
        </div>
      </section>
    </main>
  )
}
