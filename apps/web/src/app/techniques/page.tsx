'use client'

import { useMemo, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import {
  Activity, Braces, ChevronDown, ChevronRight, Crosshair, Database,
  GitBranch, Layers, Network, Search, Shield, Swords, Terminal, Zap,
} from 'lucide-react'
import { motion, AnimatePresence } from 'framer-motion'

import { AppShell } from '@/components/layout/AppShell'
import { collectionModulesApi } from '@/lib/api'
import { fallbackCollectionModules } from '@/lib/moduleCatalog'
import { cn } from '@/lib/utils'

const CATEGORY_META: Record<string, { color: string; icon: React.ElementType }> = {
  'directory':             { color: '#22d3ee', icon: Database },
  'topology':              { color: '#38bdf8', icon: Network },
  'identity':              { color: '#818cf8', icon: Shield },
  'authorization':         { color: '#a78bfa', icon: Shield },
  'policy':                { color: '#a3e635', icon: Layers },
  'certificate-services':  { color: '#fbbf24', icon: Braces },
  'host-access':           { color: '#fb923c', icon: Terminal },
  'identity-hygiene':      { color: '#34d399', icon: Activity },
  'infrastructure':        { color: '#38bdf8', icon: Network },
  'host-activity':         { color: '#94a3b8', icon: Activity },
  'host-persistence':      { color: '#c084fc', icon: Layers },
  'hybrid':                { color: '#34d399', icon: Network },
  'lateral-movement':      { color: '#f97316', icon: Crosshair },
  'credential-access':     { color: '#fb7185', icon: Database },
  'privilege-escalation':  { color: '#e879f9', icon: Zap },
  'enterprise-management': { color: '#fbbf24', icon: Braces },
  'domain-dominance':      { color: '#f87171', icon: Swords },
  'vulnerability':         { color: '#f472b6', icon: Activity },
  'graph':                 { color: '#22d3ee', icon: GitBranch },
}

function catMeta(cat: string) {
  return CATEGORY_META[cat] ?? { color: '#71717a', icon: Terminal }
}

function ModuleCard({ module, index }: {
  module: typeof fallbackCollectionModules[number]
  index: number
}) {
  const [open, setOpen] = useState(false)
  const meta = catMeta(module.category)
  const Icon = meta.icon
  const allCommands = module.command_groups.flatMap(g => g.commands)
  const cmdCount = allCommands.length
  const groupCount = module.command_groups.length

  return (
    <motion.article
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay: Math.min(index * 0.015, 0.3) }}
      className="border border-white/[0.07] bg-[#0a0a0a]"
    >
      {/* Header */}
      <button
        onClick={() => setOpen(v => !v)}
        className="flex w-full items-start justify-between gap-3 px-4 py-3 text-left transition hover:bg-white/[0.02]"
      >
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2">
            <Icon className="h-3.5 w-3.5 shrink-0" style={{ color: meta.color }} />
            <span className="text-[9px] font-semibold uppercase tracking-[0.16em]" style={{ color: meta.color }}>
              {module.category.replace(/-/g, ' ')}
            </span>
          </div>
          <h2 className="mt-1 text-sm font-semibold text-zinc-100">{module.name}</h2>
          <p className="mt-0.5 text-[11px] leading-5 text-zinc-500">{module.description}</p>
        </div>
        <div className="flex shrink-0 flex-col items-end gap-1.5 pt-0.5">
          <div
            className="border px-2 py-0.5 font-mono text-[11px] font-semibold"
            style={{ borderColor: `${meta.color}30`, color: meta.color, background: `${meta.color}08` }}
          >
            {cmdCount} cmd{cmdCount !== 1 ? 's' : ''}
          </div>
          <div className="flex items-center gap-1 text-[9px] text-zinc-600">
            {groupCount} group{groupCount !== 1 ? 's' : ''}
            {open
              ? <ChevronDown className="h-3 w-3 text-zinc-500" />
              : <ChevronRight className="h-3 w-3 text-zinc-600" />}
          </div>
        </div>
      </button>

      {/* Expandable body */}
      <AnimatePresence initial={false}>
        {open && (
          <motion.div
            key="body"
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.2 }}
            className="overflow-hidden"
          >
            <div className="border-t border-white/[0.06]">
              {module.command_groups.map((group, gi) => (
                <div key={group.id} className={cn(gi > 0 && 'border-t border-white/[0.04]')}>
                  {/* Group label */}
                  <div className="flex items-center gap-2 bg-white/[0.015] px-4 py-2">
                    <span className="text-[10px] font-semibold text-zinc-500">{group.name}</span>
                    {group.description && (
                      <span className="truncate text-[10px] text-zinc-700">· {group.description}</span>
                    )}
                  </div>
                  {/* Commands */}
                  <div className="divide-y divide-white/[0.04]">
                    {group.commands.map(cmd => (
                      <div key={cmd.id} className="group px-4 py-2.5 transition hover:bg-white/[0.02]">
                        <div className="flex items-start justify-between gap-2">
                          <span className="text-xs font-medium leading-snug text-zinc-300">{cmd.title}</span>
                          <ChevronRight className="mt-0.5 h-3.5 w-3.5 shrink-0 text-zinc-700 transition group-hover:text-zinc-500" />
                        </div>
                        <div className="mt-1 overflow-hidden text-ellipsis whitespace-nowrap font-mono text-[10px] text-zinc-600">
                          {cmd.command}
                        </div>
                        {cmd.notes && (
                          <div className="mt-0.5 text-[10px] leading-relaxed text-zinc-600">{cmd.notes}</div>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              ))}

              {/* Excluded capabilities */}
              {module.excluded_capabilities?.length ? (
                <div className="flex flex-wrap gap-1 border-t border-white/[0.04] px-4 py-2.5">
                  {module.excluded_capabilities.map(item => (
                    <span key={item} className="border border-red-500/15 px-1.5 py-0.5 text-[9px] text-red-400/60">
                      excludes {item}
                    </span>
                  ))}
                </div>
              ) : null}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </motion.article>
  )
}

export default function TechniquesPage() {
  const [search, setSearch] = useState('')
  const [category, setCategory] = useState('all')

  const { data: liveModules } = useQuery({
    queryKey: ['collection-modules'],
    queryFn: collectionModulesApi.list,
    staleTime: 5 * 60 * 1000,
  })
  const modules = liveModules ?? fallbackCollectionModules

  const categories = useMemo(
    () => ['all', ...Array.from(new Set(modules.map(m => m.category))).sort()],
    [modules]
  )

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase()
    return modules.filter(m => {
      if (category !== 'all' && m.category !== category) return false
      if (!q) return true
      return [
        m.name, m.category, m.description,
        ...m.command_groups.flatMap(g => [
          g.name, g.description ?? '',
          ...g.commands.flatMap(c => [c.title, c.command, c.notes ?? '']),
        ]),
      ].join(' ').toLowerCase().includes(q)
    })
  }, [category, modules, search])

  const totalCommands = useMemo(
    () => modules.reduce((s, m) => s + m.command_groups.reduce((g, cg) => g + cg.commands.length, 0), 0),
    [modules]
  )

  const familyCount = categories.length - 1

  return (
    <AppShell>
      <div className="min-h-full bg-transparent p-4 text-zinc-100 sm:p-6">
        <div className="mx-auto max-w-7xl space-y-4">

          {/* Header */}
          <div className="border border-white/[0.07] bg-[#0a0a0a]">
            <div className="flex flex-col gap-4 p-5 xl:flex-row xl:items-start xl:justify-between">
              <div className="min-w-0 flex-1">
                <div className="flex items-center gap-2">
                  <Swords className="h-3.5 w-3.5 text-zinc-500" />
                  <span className="text-[11px] font-semibold uppercase tracking-[0.18em] text-zinc-400">AD Attack Architecture</span>
                  <span className="border border-fuchsia-500/20 bg-fuchsia-500/[0.08] px-1.5 py-0.5 text-[9px] font-semibold uppercase tracking-[0.14em] text-fuchsia-400">v1.1</span>
                </div>
                <h1 className="mt-3 text-2xl font-bold text-white">Technique Browser</h1>
                <p className="mt-1.5 max-w-3xl text-xs leading-6 text-zinc-500">
                  Complete AdByG0d module catalog — directory inventory, Kerberos posture, credential access,
                  coercion/relay, delegation abuse, SCCM, ADIDNS, lateral movement, domain dominance,
                  persistence, CVEs, hybrid identity, local/Linux paths, OPSEC, WSUS, Exchange, and more.
                  Click any card to expand its full command groups.
                </p>
              </div>

              <div className="grid grid-cols-3 divide-x divide-white/[0.07] border border-white/[0.07] xl:w-64 xl:shrink-0">
                {[
                  { label: 'Modules',  value: modules.length, color: '#22d3ee' },
                  { label: 'Commands', value: totalCommands,   color: '#818cf8' },
                  { label: 'Families', value: familyCount,     color: '#f472b6' },
                ].map(({ label, value, color }) => (
                  <div key={label} className="px-4 py-3">
                    <div className="font-mono text-2xl font-bold tabular-nums" style={{ color }}>{value}</div>
                    <div className="mt-0.5 text-[9px] font-semibold uppercase tracking-[0.16em] text-zinc-600">{label}</div>
                  </div>
                ))}
              </div>
            </div>

            {/* Search + filter */}
            <div className="flex flex-col gap-2 border-t border-white/[0.07] p-3 lg:flex-row lg:items-center">
              <div className="relative flex-1">
                <Search className="absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-zinc-600" />
                <input
                  value={search}
                  onChange={e => setSearch(e.target.value)}
                  placeholder="Search modules, commands, tools, CVEs, families..."
                  className="h-9 w-full border border-white/[0.07] bg-black pl-9 pr-4 text-xs text-zinc-200 outline-none transition focus:border-white/15"
                />
              </div>
              <div className="flex gap-1.5 overflow-x-auto pb-1">
                {categories.map(item => {
                  const active = item === category
                  const meta = catMeta(item)
                  return (
                    <button
                      key={item}
                      onClick={() => setCategory(item)}
                      className={cn(
                        'shrink-0 border px-2.5 py-1.5 text-[10px] font-semibold uppercase tracking-[0.12em] transition',
                        active
                          ? 'text-white'
                          : 'border-white/[0.07] bg-black text-zinc-600 hover:text-zinc-300'
                      )}
                      style={active ? {
                        borderColor: `${meta.color}35`,
                        background: `${meta.color}10`,
                        color: meta.color,
                      } : undefined}
                    >
                      {item === 'all' ? 'All' : item.replace(/-/g, ' ')}
                    </button>
                  )
                })}
              </div>
            </div>
          </div>

          {/* Results info */}
          <div className="flex items-center gap-2 text-[10px] text-zinc-600">
            <span className="text-zinc-400">{filtered.length}</span> of {modules.length} modules
            {search && <span>· matching <span className="text-zinc-400">&ldquo;{search}&rdquo;</span></span>}
            {category !== 'all' && <span>· in <span className="text-zinc-400">{category.replace(/-/g, ' ')}</span></span>}
            <span className="ml-auto text-zinc-700">click to expand</span>
          </div>

          {/* Module list — single expandable column for density, 2-col on xl */}
          {filtered.length === 0 ? (
            <div className="flex flex-col items-center justify-center gap-3 border border-white/[0.07] bg-[#0a0a0a] py-16 text-center">
              <Search className="h-8 w-8 text-zinc-700" />
              <div className="text-sm font-semibold text-zinc-500">No modules match</div>
              <button
                onClick={() => { setSearch(''); setCategory('all') }}
                className="border border-white/[0.07] px-4 py-1.5 text-xs text-zinc-600 transition hover:text-zinc-300"
              >
                Clear filters
              </button>
            </div>
          ) : (
            <div className="grid gap-2 xl:grid-cols-2">
              {filtered.map((module, i) => (
                <ModuleCard key={module.id} module={module} index={i} />
              ))}
            </div>
          )}
        </div>
      </div>
    </AppShell>
  )
}
