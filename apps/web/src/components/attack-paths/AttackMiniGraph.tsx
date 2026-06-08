'use client'

import { useEffect, useRef } from 'react'
import type { PathStep } from '@/lib/types'

const ENTITY_COLORS: Record<string, string> = {
  USER: '#818cf8',
  SERVICE_ACCOUNT: '#a78bfa',
  COMPUTER: '#38bdf8',
  DC: '#ef4444',
  DOMAIN: '#ef4444',
  FOREST: '#ef4444',
  GROUP: '#fb923c',
  CA: '#f43f5e',
  CERT_TEMPLATE: '#10b981',
  GPO: '#eab308',
  OU: '#94a3b8',
  GMSA: '#c084fc',
  DMSA: '#c084fc',
  UNKNOWN: '#6b7280',
}

const EDGE_COLORS: Record<string, string> = {
  GENERIC_ALL: '#ef4444',
  OWNS: '#ef4444',
  WRITE_DACL: '#f97316',
  WRITE_OWNER: '#f97316',
  FORCE_CHANGE_PASSWORD: '#eab308',
  DCSYNC: '#ef4444',
  ADMIN_TO: '#f97316',
  LOCAL_ADMIN: '#fb923c',
  ADD_MEMBER: '#eab308',
  ALLOWED_TO_ACT: '#06b6d4',
  ALLOWED_TO_DELEGATE: '#06b6d4',
  MEMBER_OF: '#818cf8',
  HAS_SPN: '#a78bfa',
  CAN_ENROLL: '#10b981',
  CONTAINS: '#6b7280',
  APPLIES_GPO: '#94a3b8',
  TRUSTS: '#f59e0b',
  HAS_CONTROL: '#f97316',
  CAN_RDP: '#38bdf8',
  CAN_WINRM: '#38bdf8',
}

interface AttackMiniGraphProps {
  steps: PathStep[]
  width?: number
  height?: number
  animated?: boolean
}

export function AttackMiniGraph({ steps, width = 480, height = 160, animated = true }: AttackMiniGraphProps) {
  const pathRefs = useRef<(SVGPathElement | null)[]>([])

  const nodeCount = steps.length

  const padding = { x: 48, y: 40 }
  const usableW = width - padding.x * 2
  const nodeSpacing = nodeCount > 1 ? usableW / (nodeCount - 1) : 0
  const cy = height / 2

  const positions = steps.map((_, i) => ({
    x: nodeCount === 1 ? width / 2 : padding.x + i * nodeSpacing,
    y: cy + (i % 2 === 0 ? 0 : (nodeCount > 3 ? -18 : 0)),
  }))

  useEffect(() => {
    if (!animated) return
    pathRefs.current.forEach((el, i) => {
      if (!el) return
      const len = el.getTotalLength()
      el.style.strokeDasharray = String(len)
      el.style.strokeDashoffset = String(len)
      el.style.animation = `none`
      el.getBoundingClientRect()
      el.style.transition = `stroke-dashoffset 0.6s ease ${i * 0.18}s`
      el.style.strokeDashoffset = '0'
    })
  }, [steps, animated])
  if (nodeCount === 0) return null

  return (
    <svg
      width={width}
      height={height}
      viewBox={`0 0 ${width} ${height}`}
      className="overflow-visible"
      style={{ filter: 'drop-shadow(0 0 8px rgba(0,0,0,0.6))' }}
    >
      {/* Edge paths */}
      {steps.slice(0, -1).map((step, i) => {
        const src = positions[i]
        const tgt = positions[i + 1]
        const edgeColor = EDGE_COLORS[step.edge_type ?? ''] ?? '#6b7280'
        const cpX = (src.x + tgt.x) / 2
        const cpY1 = src.y - 24
        const cpY2 = tgt.y - 24
        const d = `M ${src.x} ${src.y} C ${cpX} ${cpY1}, ${cpX} ${cpY2}, ${tgt.x} ${tgt.y}`

        return (
          <g key={i}>
            {/* Glow layer */}
            <path
              d={d}
              stroke={edgeColor}
              strokeWidth={4}
              fill="none"
              opacity={0.15}
              strokeLinecap="round"
            />
            {/* Main edge */}
            <path
              ref={el => { pathRefs.current[i] = el }}
              d={d}
              stroke={edgeColor}
              strokeWidth={1.8}
              fill="none"
              strokeLinecap="round"
              opacity={0.9}
            />
            {/* Arrowhead */}
            <polygon
              points={`${tgt.x - 6},${tgt.y - 4} ${tgt.x},${tgt.y} ${tgt.x - 6},${tgt.y + 4}`}
              fill={edgeColor}
              opacity={0.85}
            />
            {/* Edge type label */}
            {step.edge_type && (
              <text
                x={(src.x + tgt.x) / 2}
                y={Math.min(src.y, tgt.y) - 30}
                textAnchor="middle"
                fontSize="8"
                fill={edgeColor}
                fontFamily="monospace"
                opacity={0.9}
                style={{ textShadow: '0 0 4px rgba(0,0,0,0.8)' }}
              >
                {step.edge_type.replace(/_/g, ' ')}
              </text>
            )}
          </g>
        )
      })}

      {/* Nodes */}
      {steps.map((step, i) => {
        const { x, y } = positions[i]
        const color = ENTITY_COLORS[step.entity_type] ?? '#6b7280'
        const isTier0 = ['DOMAIN', 'DC', 'CA', 'FOREST'].includes(step.entity_type)
        const r = isTier0 ? 14 : 11
        const label = step.entity_label.length > 14
          ? step.entity_label.slice(0, 13) + '…'
          : step.entity_label

        return (
          <g key={i}>
            {/* Outer glow ring for tier-0 */}
            {isTier0 && (
              <circle cx={x} cy={y} r={r + 6} fill="none" stroke="#ef4444" strokeWidth={1} opacity={0.3}>
                <animate attributeName="r" values={`${r + 4};${r + 8};${r + 4}`} dur="2s" repeatCount="indefinite" />
                <animate attributeName="opacity" values="0.4;0.1;0.4" dur="2s" repeatCount="indefinite" />
              </circle>
            )}
            {/* Node fill */}
            <circle cx={x} cy={y} r={r} fill={`${color}22`} stroke={color} strokeWidth={1.5} />
            {/* Index badge */}
            <text x={x} y={y + 4} textAnchor="middle" fontSize="9" fill={color} fontWeight="700" fontFamily="monospace">
              {i + 1}
            </text>
            {/* Label below */}
            <text x={x} y={y + r + 13} textAnchor="middle" fontSize="8.5" fill="#cbd5e1" fontFamily="sans-serif">
              {label}
            </text>
            {/* Type label below label */}
            <text x={x} y={y + r + 23} textAnchor="middle" fontSize="7" fill="#64748b" fontFamily="monospace">
              {step.entity_type.replace(/_/g, ' ')}
            </text>
          </g>
        )
      })}
    </svg>
  )
}
