'use client'

import { memo, useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { CheckCircle2, AlertTriangle, XCircle, RotateCcw } from 'lucide-react'
import { cn } from '@/lib/utils'
import { CoverageItem } from '@/lib/types'

const StatusIcon = ({ status }: { status: 'good' | 'warn' | 'critical' }) => {
  switch (status) {
    case 'good':     return <CheckCircle2  className="w-3.5 h-3.5 text-emerald-400 flex-shrink-0" />
    case 'warn':     return <AlertTriangle className="w-3.5 h-3.5 text-yellow-400  flex-shrink-0" />
    case 'critical': return <XCircle       className="w-3.5 h-3.5 text-red-400     flex-shrink-0" />
  }
}

const BAR_GRADIENT: Record<string, string> = {
  good:     'linear-gradient(90deg, #16a34a 0%, #22c55e 100%)',
  warn:     'linear-gradient(90deg, #a16207 0%, #eab308 100%)',
  critical: 'linear-gradient(90deg, #b91c1c 0%, #ef4444 100%)',
}

const BAR_GLOW: Record<string, string> = {
  good:     '0 0 10px rgba(34,197,94,0.55)',
  warn:     '0 0 10px rgba(234,179,8,0.55)',
  critical: '0 0 10px rgba(239,68,68,0.55)',
}

// 8 entry animations; index determines which one. Each animates FROM initial TO visible.
// framer-motion's transformPerspective means no parent wrapper needed.

interface Anim3D {
  initial: Record<string, number>
  visible: Record<string, number>
  baseStyle?: Record<string, number | string>
}

const ANIMS_3D: Anim3D[] = [
  // 0 — barrel-roll down: rotateX from 90° (top face) → 0°
  {
    initial: { scaleX: 0, rotateX: 90, opacity: 0 },
    visible: { scaleX: 1, rotateX: 0,  opacity: 1 },
    baseStyle: { transformPerspective: 400, transformOrigin: 'left top' },
  },
  // 1 — Y-swing from left wall
  {
    initial: { scaleX: 0, rotateY: -75, opacity: 0 },
    visible: { scaleX: 1, rotateY: 0,   opacity: 1 },
    baseStyle: { transformPerspective: 500, transformOrigin: 'left center' },
  },
  // 2 — stomp-down: tall scaleY + rotateX
  {
    initial: { scaleX: 0, scaleY: 4, rotateX: 50, opacity: 0 },
    visible: { scaleX: 1, scaleY: 1, rotateX: 0,  opacity: 1 },
    baseStyle: { transformPerspective: 350, transformOrigin: 'left center' },
  },
  // 3 — shear warp: skewX with perspective dive
  {
    initial: { scaleX: 0, skewX: 35, rotateY: 20, opacity: 0 },
    visible: { scaleX: 1, skewX: 0,  rotateY: 0,  opacity: 1 },
    baseStyle: { transformPerspective: 450, transformOrigin: 'left center' },
  },
  // 4 — elevator rise: rotateX from below
  {
    initial: { scaleX: 0, rotateX: -80, opacity: 0 },
    visible: { scaleX: 1, rotateX: 0,   opacity: 1 },
    baseStyle: { transformPerspective: 400, transformOrigin: 'left bottom' },
  },
  // 5 — diagonal warp: rotateY from right + skewX
  {
    initial: { scaleX: 0, rotateY: 60, skewX: -15, opacity: 0 },
    visible: { scaleX: 1, rotateY: 0,  skewX: 0,   opacity: 1 },
    baseStyle: { transformPerspective: 500, transformOrigin: 'right center' },
  },
  // 6 — squeezed ribbon: flat scaleY + rotateX unfurl
  {
    initial: { scaleX: 0, scaleY: 0.1, rotateX: 45, opacity: 0 },
    visible: { scaleX: 1, scaleY: 1,   rotateX: 0,  opacity: 1 },
    baseStyle: { transformPerspective: 380, transformOrigin: 'left center' },
  },
  // 7 — flat-flip in: full rotateY 90° (like a card turning face-on)
  {
    initial: { scaleX: 0, rotateY: 90, opacity: 0 },
    visible: { scaleX: 1, rotateY: 0,  opacity: 1 },
    baseStyle: { transformPerspective: 600, transformOrigin: 'left center' },
  },
]

const EASING = [
  [0.16, 1,    0.3,  1],   // fast ease-out
  [0.23, 1,    0.32, 1],   // smooth decel
  [0.34, 1.56, 0.64, 1],   // spring overshoot
  [0.22, 0.68, 0.0,  1.2], // heavy spring
  [0.16, 1,    0.3,  1],
  [0.23, 1,    0.32, 1],
  [0.34, 1.56, 0.64, 1],
  [0.22, 0.68, 0.0,  1.2],
] as const

interface RowProps {
  item: CoverageItem
  index: number
  animKey: number
}

const CoverageRow = memo(function CoverageRow({ item, index, animKey }: RowProps) {
  const slot  = index % 8
  const anim  = ANIMS_3D[slot]
  const ease  = EASING[slot]
  const delay = 0.05 + index * 0.08
  const pct   = Math.min(100, Math.max(0, item.pct))

  return (
    <div className="space-y-1.5">
      {/* label row */}
      <div className="flex items-center gap-2">
        <StatusIcon status={item.status} />
        <span className="text-zinc-400 text-xs flex-1 truncate">{item.name}</span>
        <span className={cn(
          'text-xs font-bold tabular-nums',
          item.status === 'good'     ? 'text-emerald-400'
          : item.status === 'warn'   ? 'text-yellow-400'
          : 'text-red-400'
        )}>
          {Math.round(pct)}%
        </span>
      </div>

      {/* bar track */}
      <div
        className="h-2 rounded-full overflow-hidden"
        style={{ background: 'rgba(255,255,255,0.05)' }}
      >
        <AnimatePresence mode="wait">
          <motion.div
            key={`${animKey}-${index}`}
            className="h-full rounded-full"
            initial={anim.initial}
            animate={{ ...anim.visible, scaleX: pct / 100 }}
            exit={{ opacity: 0, scaleX: 0 }}
            transition={{
              duration: 0.72,
              delay,
              ease,
            }}
            style={{
              width: '100%',
              background: BAR_GRADIENT[item.status],
              boxShadow: BAR_GLOW[item.status],
              transformOrigin: 'left center',
              ...anim.baseStyle,
            }}
          />
        </AnimatePresence>
      </div>

      {/* coverage count */}
      <div className="text-zinc-600 text-[10px] pl-5">
        {item.covered} / {item.total} objects covered
      </div>
    </div>
  )
})

interface Props {
  items: CoverageItem[]
}

export const CoverageMatrix = memo(function CoverageMatrix({ items }: Props) {
  const [animKey, setAnimKey] = useState(0)

  if (!items || items.length === 0) {
    return (
      <div className="rounded-xl border border-dashed border-white/10 bg-black px-4 py-6 text-sm text-zinc-500">
        No coverage data available for this assessment yet.
      </div>
    )
  }

  return (
    <div className="space-y-3">
      {/* Reset button */}
      <div className="flex justify-end">
        <button
          onClick={() => setAnimKey(k => k + 1)}
          title="Replay 3D animations"
          className="flex items-center gap-1.5 px-2.5 py-1 rounded-lg border border-white/10 text-zinc-500 text-[11px] hover:text-zinc-300 hover:border-white/20 transition-all group"
        >
          <RotateCcw className="w-3 h-3 group-hover:rotate-180 transition-transform duration-500" />
          Replay
        </button>
      </div>

      {items.map((item, i) => (
        <CoverageRow key={item.name} item={item} index={i} animKey={animKey} />
      ))}
    </div>
  )
})
