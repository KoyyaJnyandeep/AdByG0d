
'use client'

import { useCallback, useEffect, useMemo, useState } from 'react'
import dynamic from 'next/dynamic'
import { usePathname } from 'next/navigation'
import { motion } from 'framer-motion'
import { Menu, Search, X } from 'lucide-react'

import { Sidebar } from './Sidebar'
import { GlobalImportBar } from '@/components/ui/GlobalImportBar'
import { cn } from '@/lib/utils'

const CommandPalette = dynamic(
  () => import('@/components/ui/CommandPalette').then(m => ({ default: m.CommandPalette })),
  { ssr: false }
)

interface AppShellProps {
  children: React.ReactNode
  className?: string
}

function routeLabel(pathname: string) {
  if (pathname === '/') return 'Dashboard'

  return pathname
    .split('/')
    .filter(Boolean)
    .map((part) => part
      .replaceAll('-', ' ')
      .replace(/^./, (letter) => letter.toUpperCase()))
    .join(' / ')
}

export function AppShell({ children, className }: AppShellProps) {
  const pathname = usePathname()
  const [paletteOpen, setPaletteOpen] = useState(false)
  const [sidebarOpen, setSidebarOpen] = useState(false)

  const openPalette = useCallback(() => setPaletteOpen(true), [])
  const closePalette = useCallback(() => setPaletteOpen(false), [])
  const currentRouteLabel = useMemo(() => routeLabel(pathname), [pathname])

  useEffect(() => {
    const handler = (event: KeyboardEvent) => {
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === 'k') {
        event.preventDefault()
        setPaletteOpen((open) => !open)
      }
    }

    window.addEventListener('keydown', handler)
    return () => window.removeEventListener('keydown', handler)
  }, [])

  useEffect(() => {
    setSidebarOpen(false)
  }, [pathname])

  useEffect(() => {
    if (!sidebarOpen) return

    const previousOverflow = document.body.style.overflow
    document.body.style.overflow = 'hidden'

    const closeOnEscape = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        setSidebarOpen(false)
      }
    }

    window.addEventListener('keydown', closeOnEscape)
    return () => {
      document.body.style.overflow = previousOverflow
      window.removeEventListener('keydown', closeOnEscape)
    }
  }, [sidebarOpen])

  return (
    <div className="flex min-h-screen flex-col bg-black text-white">
      {/* subtle brand glow only — no image bleed-through on content pages */}
      <div className="pointer-events-none fixed inset-0 z-0">
        <div className="absolute inset-0"
          style={{ background: 'radial-gradient(ellipse 70% 50% at 50% 10%, rgba(var(--brand-rgb),0.04) 0%, transparent 70%)' }} />
      </div>

      {paletteOpen ? <CommandPalette open={paletteOpen} onClose={closePalette} /> : null}
      <GlobalImportBar />

      <header className="sticky top-0 z-40 border-b border-white/10 bg-black/95 px-4 py-3 backdrop-blur lg:hidden">
        <div className="flex items-center justify-between gap-3">
          <button
            type="button"
            aria-label={sidebarOpen ? 'Close navigation' : 'Open navigation'}
            aria-expanded={sidebarOpen}
            onClick={() => setSidebarOpen((open) => !open)}
            className="inline-flex h-10 w-10 items-center justify-center rounded-2xl border border-white/10 bg-white/[0.03] text-zinc-100 transition hover:border-cyan-300/30 hover:bg-cyan-300/10"
          >
            {sidebarOpen ? <X className="h-4 w-4" /> : <Menu className="h-4 w-4" />}
          </button>

          <div className="min-w-0 flex-1">
            <div className="text-[10px] font-bold uppercase tracking-[0.24em] text-zinc-500">Identity Exposure</div>
            <div className="truncate text-sm font-semibold text-white">{currentRouteLabel}</div>
          </div>

          <button
            type="button"
            aria-label="Open command palette"
            onClick={openPalette}
            className="inline-flex h-10 w-10 items-center justify-center rounded-2xl border border-white/10 bg-white/[0.03] text-zinc-100 transition hover:border-cyan-300/30 hover:bg-cyan-300/10"
          >
            <Search className="h-4 w-4" />
          </button>
        </div>
      </header>

      <div className="flex flex-1 overflow-hidden">
        {sidebarOpen ? (
          <button
            type="button"
            aria-label="Close navigation overlay"
            onClick={() => setSidebarOpen(false)}
            className="fixed inset-0 z-40 bg-black/70 backdrop-blur-sm lg:hidden"
          />
        ) : null}

        <Sidebar
          onOpenSearch={openPalette}
          mobileOpen={sidebarOpen}
          onRequestClose={() => setSidebarOpen(false)}
        />

        <main className={cn('relative min-h-[calc(100vh-4rem)] flex-1 overflow-y-auto lg:ml-[272px] lg:min-h-screen', className)}>
          <motion.div
            key={pathname}
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.38, ease: [0.23, 1, 0.32, 1] }}
          >
            {children}
          </motion.div>
        </main>
      </div>
    </div>
  )
}
