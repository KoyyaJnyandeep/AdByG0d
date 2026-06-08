
import Link from 'next/link'
import { ArrowLeft, SearchX } from 'lucide-react'

import { AppShell } from '@/components/layout/AppShell'

export default function NotFound() {
  return (
    <AppShell>
      <main className="grid min-h-[calc(100vh-4rem)] place-items-center px-5 py-10">
        <section className="w-full max-w-2xl overflow-hidden rounded-[32px] border border-white/10 bg-black p-7 shadow-[0_28px_90px_rgba(0,0,0,0.65)]">
          <div className="inline-flex items-center gap-2 rounded-full border border-cyan-300/20 bg-cyan-300/10 px-3 py-1 text-xs font-bold uppercase tracking-[0.22em] text-cyan-100">
            <SearchX className="h-3.5 w-3.5" /> Route Not Found
          </div>
          <h1 className="mt-5 text-3xl font-semibold tracking-tight text-white">That workspace route does not exist.</h1>
          <p className="mt-3 max-w-xl text-sm leading-6 text-zinc-400">
            Use the dashboard or command palette to return to a valid assessment, findings, graph, or reporting view.
          </p>
          <div className="mt-6">
            <Link
              href="/"
              className="inline-flex items-center gap-2 rounded-2xl border border-white/10 bg-white/[0.03] px-4 py-2.5 text-sm font-semibold text-zinc-100 transition hover:border-white/20 hover:bg-white/[0.06]"
            >
              <ArrowLeft className="h-4 w-4" /> Return to dashboard
            </Link>
          </div>
        </section>
      </main>
    </AppShell>
  )
}
