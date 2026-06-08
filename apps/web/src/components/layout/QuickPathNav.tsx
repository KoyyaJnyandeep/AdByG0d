'use client'

import Link from 'next/link'
import { usePathname } from 'next/navigation'
import { cn } from '@/lib/utils'

const MONO = { fontFamily: 'JetBrains Mono, monospace' }

const PHASES = [
  { label: 'P0 Recon',    href: '/recon',           color: '#60a5fa' },
  { label: 'P1 Access',   href: '/initial-access',   color: '#f97316' },
  { label: 'P2 Enum',     href: '/enumeration',      color: '#fbbf24' },
  { label: 'P3 PrivEsc',  href: '/priv-esc',         color: '#fb923c' },
  { label: 'P4 Lateral',  href: '/lateral-movement', color: '#a78bfa' },
  { label: 'P5 Persist',  href: '/persistence',      color: '#34d399' },
  { label: 'P6 Evasion',  href: '/evasion',          color: '#f472b6' },
  { label: 'P7 Kill',     href: '/kill-chain',       color: '#ef4444' },
]

export function QuickPathNav() {
  const pathname = usePathname()

  return (
    <div className="flex flex-wrap items-center gap-1.5 border-b border-white/5 bg-black/50 px-4 py-2">
      {PHASES.map(({ label, href, color }) => {
        const active = pathname === href || pathname.startsWith(href + '/')
        return (
          <Link
            key={href}
            href={href}
            className={cn(
              'rounded-full border px-3 py-0.5 text-[10px] font-semibold uppercase tracking-widest transition-all',
              active
                ? 'border-transparent text-black'
                : 'border-white/10 text-zinc-500 hover:border-white/20 hover:text-zinc-300'
            )}
            style={{
              ...MONO,
              background: active ? color : 'transparent',
              borderColor: active ? color : undefined,
            }}
          >
            {label}
          </Link>
        )
      })}
    </div>
  )
}
