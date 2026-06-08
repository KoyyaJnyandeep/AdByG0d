'use client'

import { memo } from 'react'
import { useQuery } from '@tanstack/react-query'
import { motion } from 'framer-motion'
import { graphApi } from '@/lib/api'
import { ChevronRight, AlertTriangle, Loader2 } from 'lucide-react'
import { entityTypeColor } from '@/lib/utils'
import type { EntityType, ExposurePath } from '@/lib/types'

const EDGE_COLORS: Record<string, string> = {
  DCSYNC:        'rgba(239,68,68,0.7)',
  GENERIC_ALL:   'rgba(239,68,68,0.6)',
  WRITE_DACL:    'rgba(249,115,22,0.65)',
  WRITE_OWNER:   'rgba(249,115,22,0.6)',
  MEMBER_OF:     'rgba(139,92,246,0.55)',
  LOCAL_ADMIN:   'rgba(var(--accent2-rgb),0.6)',
  CAN_ENROLL:    'rgba(var(--accent2-rgb),0.55)',
  ADMIN_TO:      'rgba(239,68,68,0.65)',
  HAS_CONTROL:   'rgba(249,115,22,0.55)',
  ALLOWED_TO_DELEGATE: 'rgba(234,179,8,0.6)',
}

function edgeColor(type: string): string {
  return EDGE_COLORS[type] ?? 'rgba(113,113,122,0.5)'
}

interface Path {
  source: string
  target: string
  path: string[]
  edge_types: string[]
  hop_count: number
  path_score: number
  explanation?: string
}

function normalizeMiniPaths(data: ExposurePath[] | { paths: ExposurePath[] } | undefined): Path[] {
  const rawPaths = Array.isArray(data) ? data : data?.paths ?? []
  return rawPaths.slice(0, 5).map((path, index) => ({
    source: path.source_label,
    target: path.target_label,
    path: path.path_steps.map((step) => step.entity_label || step.entity_id || `node-${index}`),
    edge_types: path.path_steps.map((step) => step.edge_type ?? '').filter(Boolean),
    hop_count: path.hop_count,
    path_score: path.path_score,
    explanation: path.explanation,
  }))
}

interface PathNodeProps {
  label: string
  type: string
  isTier0?: boolean
}

const PathNode = memo(function PathNode({ label, type, isTier0 }: PathNodeProps) {
  const color = entityTypeColor(type as EntityType)
  return (
    <div
      className="flex flex-col items-center gap-1 flex-shrink-0"
    >
      <div
        className="px-2.5 py-1 rounded-lg text-xs font-semibold border max-w-[100px] truncate"
        style={{
          background: `${color}15`,
          borderColor: `${color}${isTier0 ? '55' : '30'}`,
          color: isTier0 ? '#fca5a5' : '#e4e4e7',
          boxShadow: isTier0 ? `0 0 10px ${color}30` : undefined,
        }}
        title={label}
      >
        {label}
      </div>
      <div className="text-[9px] uppercase tracking-widest" style={{ color: `${color}90` }}>
        {type?.replace('_', ' ')}
      </div>
    </div>
  )
})

interface EdgePillProps {
  type: string
}

const EdgePill = memo(function EdgePill({ type }: EdgePillProps) {
  const color = edgeColor(type)
  return (
    <div className="flex items-center gap-0.5 flex-shrink-0">
      <div className="w-4 h-px" style={{ background: color }} />
      <div
        className="px-1.5 py-0.5 rounded text-[9px] font-semibold uppercase tracking-wide border"
        style={{
          background: `${color.replace(')', ', 0.12)').replace('rgba', 'rgba')}`,
          borderColor: color,
          color: '#e4e4e7',
        }}
      >
        {type?.replace(/_/g, ' ')}
      </div>
      <ChevronRight className="w-3 h-3 text-zinc-600 flex-shrink-0" />
    </div>
  )
})

interface SinglePathProps {
  path: Path
  index: number
}

const SinglePath = memo(function SinglePath({ path, index }: SinglePathProps) {
  // path.path is an array of entity IDs, path.edge_types is an array of edge type strings
  // We don't have labels here — we'll use truncated IDs as labels
  const steps = path.path.map((id, i) => ({
    id,
    label: id.slice(0, 8),
    isLast: i === path.path.length - 1,
    edgeType: path.edge_types?.[i],
  }))

  return (
    <motion.div
      initial={{ opacity: 0, y: 6 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.35, delay: index * 0.08 }}
      className="flex items-center gap-1.5 overflow-x-auto py-2 px-3 rounded-xl border border-white/[0.06] bg-black min-h-[52px]"
      style={{ scrollbarWidth: 'none' }}
    >
      <div className="flex items-center gap-1 flex-shrink-0">
        <span className="text-[10px] text-zinc-600 font-mono w-4">{index + 1}.</span>
      </div>
      {steps.map((step) => (
        <div key={step.id} className="flex items-center gap-1.5 flex-shrink-0">
          <PathNode
            label={step.label}
            type="USER"
            isTier0={step.isLast}
          />
          {!step.isLast && step.edgeType && (
            <EdgePill type={step.edgeType} />
          )}
        </div>
      ))}
      <div className="ml-auto flex-shrink-0 text-[10px] text-zinc-500 pl-2">
        {path.hop_count}h · {path.path_score?.toFixed(2) ?? '—'}
      </div>
    </motion.div>
  )
})

interface PathMiniGraphProps {
  assessmentId: string
}

export const PathMiniGraph = memo(function PathMiniGraph({ assessmentId }: PathMiniGraphProps) {
  const { data, isLoading } = useQuery({
    queryKey: ['paths-mini', assessmentId],
    queryFn: () => graphApi.getPaths(assessmentId, { max_paths: 5, tier: 0 }),
    staleTime: 60_000,
    enabled: !!assessmentId,
  })

  const paths = normalizeMiniPaths(data)

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-24 text-zinc-500">
        <Loader2 className="w-4 h-4 animate-spin mr-2" />
        <span className="text-sm">Loading paths…</span>
      </div>
    )
  }

  if (!paths.length) {
    return (
      <div className="flex flex-col items-center justify-center h-24 text-zinc-500 gap-2">
        <AlertTriangle className="w-5 h-5" />
        <span className="text-sm">No privilege escalation paths found</span>
      </div>
    )
  }

  return (
    <div className="space-y-2">
      {paths.map((path, i) => (
        <SinglePath key={`${path.source}-${path.target}-${i}`} path={path} index={i} />
      ))}
    </div>
  )
})
