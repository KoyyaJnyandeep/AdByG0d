'use client'

import { copyText } from '@/lib/clipboard'
import { useEffect, useMemo, useRef, useState, type MouseEvent } from 'react'
import { Keyboard, Search, X } from 'lucide-react'
import { motion } from 'framer-motion'
import toast from 'react-hot-toast'

import type { GraphNode, VirtualGroupNode } from '@/lib/types'
import { cn } from '@/lib/utils'
import type { CtxMenu } from './engine/types'
import { SHORTCUTS, getLetter } from './engine/constants'

interface PaletteItem {
  id: string
  label: string
  sub: string
  action: () => void
  icon?: string
}

export function CommandPalette({
  nodes, onClose, onFocusNode,
  onRunQuery,
}: {
  nodes: GraphNode[]
  onClose: () => void
  onFocusNode: (id: string) => void
  onRunQuery: (id: string) => void
}) {
  const [q, setQ] = useState('')
  const inputRef = useRef<HTMLInputElement>(null)

  useEffect(() => { inputRef.current?.focus() }, [])

  const QUERIES = useMemo(() => [
    { id: 'das',        icon: '●', label: 'Highlight Tier-0 nodes' },
    { id: 'jewels',     icon: '◆', label: 'Highlight Crown Jewels' },
    { id: 'dcsync',     icon: '⬡', label: 'Highlight DCSync capable' },
    { id: 'crit-edges', icon: '▲', label: 'Highlight Critical edges' },
    { id: 'genericall', icon: '◉', label: 'Highlight GenericAll rights' },
    { id: 'path-to-da', icon: '→', label: 'Shortest path to Domain Admin' },
    { id: 'delegation', icon: '⬡', label: 'Highlight Delegation rights' },
    { id: 'write-dacl', icon: '✎', label: 'Highlight WriteDACL / WriteOwner' },
  ], [])

  const results = useMemo((): PaletteItem[] => {
    const lq = q.toLowerCase().trim()
    if (!lq) return QUERIES.map(qr => ({
      id: 'q:' + qr.id, label: qr.label, sub: 'Query', icon: qr.icon,
      action: () => { onRunQuery(qr.id); onClose() },
    }))

    const nodeMatches: PaletteItem[] = nodes
      .filter(n => n.label.toLowerCase().includes(lq) || n.entity_type.toLowerCase().includes(lq))
      .slice(0, 8)
      .map(n => ({
        id: 'n:' + n.id,
        label: n.label,
        sub: n.entity_type + (n.tier !== undefined ? ` · T${n.tier}` : ''),
        icon: getLetter(n.entity_type),
        action: () => { onFocusNode(n.id); onClose() },
      }))

    const queryMatches: PaletteItem[] = QUERIES
      .filter(qr => qr.label.toLowerCase().includes(lq))
      .map(qr => ({
        id: 'q:' + qr.id, label: qr.label, sub: 'Query', icon: qr.icon,
        action: () => { onRunQuery(qr.id); onClose() },
      }))

    return [...nodeMatches, ...queryMatches]
  }, [q, nodes, QUERIES, onFocusNode, onRunQuery, onClose])

  const [sel, setSel] = useState(0)
  useEffect(() => { setSel(0) }, [results])

  const handleKey = (e: React.KeyboardEvent) => {
    if (e.key === 'ArrowDown') { e.preventDefault(); setSel(s => Math.min(s+1, results.length-1)) }
    if (e.key === 'ArrowUp') { e.preventDefault(); setSel(s => Math.max(s-1, 0)) }
    if (e.key === 'Enter') { e.preventDefault(); results[sel]?.action() }
    if (e.key === 'Escape') { e.preventDefault(); onClose() }
  }

  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      exit={{ opacity: 0 }}
      className="fixed inset-0 z-[80] flex items-start justify-center pt-[15vh] bg-black/60 backdrop-blur-sm"
      onClick={onClose}
      role="dialog"
      aria-modal="true"
      aria-label="Command palette"
    >
      <motion.div
        initial={{ opacity: 0, scale: 0.95, y: -8 }}
        animate={{ opacity: 1, scale: 1, y: 0 }}
        exit={{ opacity: 0, scale: 0.95, y: -8 }}
        transition={{ duration: 0.14 }}
        className="w-full max-w-lg mx-4 rounded-2xl border border-white/12 bg-zinc-950/98 shadow-2xl overflow-hidden"
        onClick={(e: MouseEvent) => e.stopPropagation()}
      >
        {/* Input */}
        <div className="flex items-center gap-3 px-4 py-3 border-b border-white/8">
          <Search className="h-4 w-4 text-zinc-500 flex-shrink-0" />
          <input
            ref={inputRef}
            value={q}
            onChange={e => setQ(e.target.value)}
            onKeyDown={handleKey}
            placeholder="Search nodes or run a query…"
            className="flex-1 bg-transparent text-sm text-white placeholder:text-zinc-600 outline-none"
          />
          <kbd className="hidden sm:flex items-center gap-0.5 rounded border border-white/15 bg-white/5 px-1.5 py-0.5 text-[9px] text-zinc-500">
            ESC
          </kbd>
        </div>

        {/* Results */}
        <div className="max-h-80 overflow-y-auto py-1.5" role="listbox">
          {results.length === 0 && (
            <div className="px-4 py-8 text-center text-sm text-zinc-600">No results</div>
          )}
          {results.map((item, i) => (
            <button
              key={item.id}
              role="option"
              aria-selected={i === sel}
              onClick={item.action}
              onMouseEnter={() => setSel(i)}
              className={cn(
                'w-full flex items-center gap-3 px-4 py-2.5 text-left transition-colors',
                i === sel ? 'bg-white/[0.07]' : 'hover:bg-white/[0.04]',
              )}
            >
              <span className="flex-shrink-0 w-6 h-6 rounded-lg bg-white/6 border border-white/10 flex items-center justify-center text-[10px] font-bold font-mono text-zinc-400">
                {item.icon ?? '?'}
              </span>
              <div className="min-w-0">
                <div className="text-sm text-zinc-200 truncate">{item.label}</div>
                <div className="text-[10px] text-zinc-600 mt-0.5">{item.sub}</div>
              </div>
            </button>
          ))}
        </div>

        {/* Footer */}
        <div className="px-4 py-2 border-t border-white/6 flex items-center justify-between">
          <div className="flex items-center gap-3 text-[9px] text-zinc-600">
            <span>↑↓ navigate</span>
            <span>↩ select</span>
          </div>
          <span className="text-[9px] text-zinc-700">{results.length} results</span>
        </div>
      </motion.div>
    </motion.div>
  )
}

export function ContextMenu({
  ctx, onClose, onOwned, onHighValue, onSetStart, onSetEnd, onFocus, onCollapseGroup, ownedNodes, highValueNodes,
}: {
  ctx: CtxMenu; onClose: () => void
  onOwned: (id: string) => void; onHighValue: (id: string) => void
  onSetStart: (n: GraphNode) => void; onSetEnd: (n: GraphNode) => void
  onFocus: (n: GraphNode) => void
  onCollapseGroup?: (id: string) => void
  ownedNodes: Set<string>; highValueNodes: Set<string>
}) {
  const isOwned = ownedNodes.has(ctx.node.id)
  const isHV = highValueNodes.has(ctx.node.id)
  const items = [
    { label: isOwned ? 'Unmark Owned' : 'Mark as Owned',      icon: '☠', action: () => { onOwned(ctx.node.id); onClose() } },
    { label: isHV ? 'Unmark High Value' : 'Mark High Value',  icon: '★', action: () => { onHighValue(ctx.node.id); onClose() } },
    { label: 'Set as Start Node',                              icon: '▶', action: () => { onSetStart(ctx.node); onClose() } },
    { label: 'Set as End Node',                                icon: '■', action: () => { onSetEnd(ctx.node); onClose() } },
    { label: 'N-Hop Focus',                                    icon: '◎', action: () => { onFocus(ctx.node); onClose() } },
    { label: 'Copy Name',                                      icon: '⎘', action: () => { copyText(ctx.node.label); toast('Copied', { duration: 900 }); onClose() } },
    ...((ctx.node.entity_type === 'GROUP' || (ctx.node as VirtualGroupNode).isVirtual) ? [{
      label: (ctx.node as VirtualGroupNode).isVirtual ? `Expand Group (${(ctx.node as VirtualGroupNode).memberCount ?? 0} members)` : 'Collapse Group',
      icon: (ctx.node as VirtualGroupNode).isVirtual ? '⊞' : '⊟',
      action: () => { onCollapseGroup?.(ctx.node.id); onClose() },
    }] : []),
  ]
  return (
    <motion.div
      initial={{ opacity: 0, scale: 0.92 }} animate={{ opacity: 1, scale: 1 }}
      exit={{ opacity: 0, scale: 0.92 }} transition={{ duration: 0.1 }}
      className="absolute z-[60] min-w-[196px] rounded-2xl border border-white/12 bg-zinc-950/97 py-1.5 shadow-2xl"
      style={{ left: ctx.x, top: ctx.y }}
      onMouseLeave={onClose}
      role="menu"
    >
      <div className="mb-1 px-3 py-1.5 border-b border-white/6">
        <div className="text-[11px] font-semibold text-white truncate max-w-[160px]">{ctx.node.label}</div>
        <div className="text-[9px] uppercase tracking-widest text-zinc-500 mt-0.5">{ctx.node.entity_type}</div>
      </div>
      {items.map(item => (
        <button key={item.label} onClick={item.action} role="menuitem"
          className="w-full px-3 py-1.5 text-left text-[11px] text-zinc-300 hover:bg-white/8 hover:text-white transition-colors flex items-center gap-2.5">
          <span className="text-zinc-500 text-xs">{item.icon}</span>
          {item.label}
        </button>
      ))}
    </motion.div>
  )
}

export function ShortcutsModal({ onClose }: { onClose: () => void }) {
  return (
    <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
      className="fixed inset-0 z-[60] flex items-center justify-center bg-black/70 backdrop-blur-sm"
      onClick={onClose}>
      <motion.div initial={{ scale: 0.92 }} animate={{ scale: 1 }} exit={{ scale: 0.92 }}
        transition={{ duration: 0.15 }}
        className="rounded-2xl border border-white/12 bg-zinc-950/97 p-6 shadow-2xl w-80"
        onClick={(e: MouseEvent) => e.stopPropagation()}>
        <div className="flex items-center justify-between mb-4">
          <div className="text-sm font-semibold text-white flex items-center gap-2">
            <Keyboard className="h-4 w-4 text-cyan-400" /> Keyboard Shortcuts
          </div>
          <button onClick={onClose} aria-label="Close shortcuts" className="text-zinc-500 hover:text-white rounded-lg p-0.5 hover:bg-white/8">
            <X className="h-4 w-4" />
          </button>
        </div>
        <div className="space-y-2">
          {SHORTCUTS.map(s => (
            <div key={s.key} className="flex items-center justify-between">
              <span className="text-xs text-zinc-400">{s.desc}</span>
              <kbd className="rounded border border-white/18 bg-white/5 px-1.5 py-0.5 text-[10px] font-mono text-zinc-300">{s.key}</kbd>
            </div>
          ))}
        </div>
      </motion.div>
    </motion.div>
  )
}
