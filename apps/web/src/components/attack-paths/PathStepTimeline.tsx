'use client'

import { motion } from 'framer-motion'
import {
  User, Server, Shield, Database, Key, Users, FileText, Globe, Cpu, AlertTriangle,
} from 'lucide-react'
import type { PathStep } from '@/lib/types'
import { cn } from '@/lib/utils'

const ENTITY_ICONS: Record<string, React.ComponentType<{ className?: string }>> = {
  USER: User, SERVICE_ACCOUNT: Key, COMPUTER: Server, DC: Shield, DOMAIN: Globe,
  FOREST: Globe, GROUP: Users, CA: FileText, CERT_TEMPLATE: FileText,
  GPO: Cpu, OU: Database, GMSA: Key, DMSA: Key, UNKNOWN: AlertTriangle,
}

const MITRE_MAP: Record<string, { id: string; name: string }> = {
  HAS_SPN: { id: 'T1558.003', name: 'Kerberoasting' },
  FORCE_CHANGE_PASSWORD: { id: 'T1098', name: 'Account Manipulation' },
  DCSYNC: { id: 'T1003.006', name: 'DCSync' },
  ALLOWED_TO_DELEGATE: { id: 'T1558.001', name: 'Delegation Abuse' },
  ALLOWED_TO_ACT: { id: 'T1558.001', name: 'RBCD Abuse' },
  GENERIC_ALL: { id: 'T1222', name: 'ACL Modification' },
  WRITE_DACL: { id: 'T1222', name: 'DACL Modification' },
  WRITE_OWNER: { id: 'T1222', name: 'Owner Modification' },
  OWNS: { id: 'T1222', name: 'Object Ownership' },
  ADD_MEMBER: { id: 'T1098.002', name: 'Account Manipulation' },
  MEMBER_OF: { id: 'T1078', name: 'Valid Accounts' },
  LOCAL_ADMIN: { id: 'T1078.003', name: 'Local Accounts' },
  ADMIN_TO: { id: 'T1078', name: 'Admin Access' },
  CAN_ENROLL: { id: 'T1649', name: 'Steal/Forge Cert' },
  TRUSTS: { id: 'T1482', name: 'Domain Trust Discovery' },
}

const EDGE_COLORS: Record<string, string> = {
  GENERIC_ALL: 'text-red-400', OWNS: 'text-red-400', WRITE_DACL: 'text-orange-400',
  WRITE_OWNER: 'text-orange-400', FORCE_CHANGE_PASSWORD: 'text-yellow-400',
  DCSYNC: 'text-red-400', ADMIN_TO: 'text-orange-400', LOCAL_ADMIN: 'text-orange-300',
  ADD_MEMBER: 'text-yellow-400', ALLOWED_TO_ACT: 'text-cyan-400',
  ALLOWED_TO_DELEGATE: 'text-cyan-400', MEMBER_OF: 'text-indigo-400',
  HAS_SPN: 'text-purple-400', CAN_ENROLL: 'text-emerald-400',
  TRUSTS: 'text-amber-400', HAS_CONTROL: 'text-orange-400',
}

interface PathStepTimelineProps {
  steps: PathStep[]
}

export function PathStepTimeline({ steps }: PathStepTimelineProps) {
  return (
    <div className="space-y-0">
      {steps.map((step, i) => {
        const Icon = ENTITY_ICONS[step.entity_type] ?? AlertTriangle
        const isTier0 = ['DOMAIN', 'DC', 'CA', 'FOREST'].includes(step.entity_type)
        const isLast = i === steps.length - 1
        const edgeColor = step.edge_type ? (EDGE_COLORS[step.edge_type] ?? 'text-zinc-400') : 'text-zinc-400'
        const mitre = step.edge_type ? MITRE_MAP[step.edge_type] : null

        return (
          <motion.div
            key={i}
            initial={{ opacity: 0, x: -8 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ delay: i * 0.06 }}
          >
            {/* Node row */}
            <div className="flex items-start gap-3">
              {/* Timeline spine */}
              <div className="flex flex-col items-center" style={{ width: 32, flexShrink: 0 }}>
                <div
                  className={cn(
                    'flex h-8 w-8 items-center justify-center rounded-full border',
                    isTier0
                      ? 'border-red-400/50 bg-red-500/10'
                      : 'border-white/15 bg-black',
                  )}
                >
                  <Icon className={cn('h-3.5 w-3.5', isTier0 ? 'text-red-400' : 'text-zinc-300')} />
                </div>
                {!isLast && <div className="w-px flex-1 bg-white/10 mt-1" style={{ minHeight: 24 }} />}
              </div>

              {/* Node info */}
              <div className="flex-1 pb-2">
                <div className="flex items-center gap-2 flex-wrap">
                  <span className={cn(
                    'font-semibold text-sm',
                    isTier0 ? 'text-red-300' : 'text-white',
                  )}>
                    {step.entity_label}
                  </span>
                  {isTier0 && (
                    <span className="rounded-full bg-red-500/15 px-1.5 py-0.5 text-[9px] font-bold text-red-400 border border-red-400/20">
                      T0
                    </span>
                  )}
                  <span className="rounded bg-white/5 px-1.5 py-0.5 text-[9px] font-mono text-zinc-500 border border-white/5">
                    {step.entity_type.replace(/_/g, ' ')}
                  </span>
                </div>
                {step.explanation && (
                  <p className="mt-0.5 text-[11px] text-zinc-500 leading-relaxed">{step.explanation}</p>
                )}
              </div>
            </div>

            {/* Edge connector between nodes */}
            {!isLast && step.edge_type && (
              <div className="flex items-start gap-3 -mt-1 mb-1">
                <div className="flex flex-col items-center" style={{ width: 32, flexShrink: 0 }}>
                  <div className="w-px flex-1 bg-white/10" style={{ minHeight: 20 }} />
                </div>
                <div className="flex items-center gap-2 pl-1 py-1">
                  <div className={cn('text-[10px] font-mono font-semibold px-2 py-0.5 rounded border', edgeColor, 'border-current/20 bg-current/5')}>
                    {step.edge_type.replace(/_/g, '_')}
                  </div>
                  {mitre && (
                    <span className="text-[9px] text-zinc-600 font-mono">
                      {mitre.id} · {mitre.name}
                    </span>
                  )}
                </div>
              </div>
            )}
          </motion.div>
        )
      })}
    </div>
  )
}
