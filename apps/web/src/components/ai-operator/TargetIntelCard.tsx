'use client'
import { useState } from 'react'
import { ChevronDown, ChevronRight, Target } from 'lucide-react'
import type { TargetCardUpdateEvent } from '@/lib/agentEvents'

type Card = TargetCardUpdateEvent['card']

const NOISE_COLORS: Record<string, string> = {
  LOW:      '#34d399',
  MEDIUM:   '#fbbf24',
  HIGH:     '#f97316',
  CRITICAL: '#ef4444',
}

export function TargetIntelCard({ card }: { card: Card }) {
  const [collapsed, setCollapsed] = useState(false)
  if (!card.domain && !card.dc_ip) return null

  const noiseColor = NOISE_COLORS[card.opsec_noise ?? ''] ?? '#34d399'

  return (
    <div
      className="rounded-xl overflow-hidden mb-3"
      style={{ background: 'rgba(0,0,0,0.5)', border: '1px solid rgba(96,165,250,0.15)' }}
    >
      <button
        onClick={() => setCollapsed(c => !c)}
        className="w-full flex items-center gap-2 px-3 py-2 hover:bg-white/[0.03] transition-colors"
      >
        <Target className="h-3.5 w-3.5 text-blue-400 shrink-0" />
        <span className="text-[11px] font-bold text-blue-400 flex-1 text-left">TARGET INTELLIGENCE</span>
        {card.domain && <span className="text-[10px] text-zinc-600 font-mono">{card.domain}</span>}
        {collapsed
          ? <ChevronRight className="h-3 w-3 text-zinc-600 shrink-0" />
          : <ChevronDown className="h-3 w-3 text-zinc-600 shrink-0" />
        }
      </button>
      {!collapsed && (
        <div className="px-3 pb-3">
          <div className="grid grid-cols-2 gap-x-4 gap-y-1 text-[11px] mb-2">
            {([
              ['Domain', card.domain, null],
              ['DC', card.dc_ip, null],
              ['Auth', card.auth_level, null],
              ['OPSEC', card.opsec_noise, noiseColor],
              ['Critical findings', card.findings_critical?.toString(), null],
              ['Hashes captured', card.hashes_captured?.toString(), null],
              ['Hashes cracked', card.hashes_cracked?.toString(), null],
              ['Paths to DA', card.paths_to_da?.toString(), '#ef4444'],
            ] as [string, string | undefined, string | null][])
              .filter(([, v]) => v !== undefined && v !== null)
              .map(([k, v, color]) => (
                <div key={k} className="flex gap-1 truncate">
                  <span className="text-zinc-600 shrink-0">{k}:</span>
                  <span
                    className="text-zinc-300 font-mono truncate"
                    style={color ? { color } : {}}
                  >
                    {v}
                  </span>
                </div>
              ))
            }
          </div>
          {card.owned_accounts && card.owned_accounts.length > 0 && (
            <div className="text-[11px] mb-1">
              <span className="text-zinc-600">Owned ({card.owned_accounts.length}): </span>
              <span className="text-emerald-400 font-mono">
                {card.owned_accounts.slice(0, 3).join(', ')}
                {card.owned_accounts.length > 3 && ` +${card.owned_accounts.length - 3}`}
              </span>
            </div>
          )}
          {card.next_best_action && (
            <div className="text-[11px] text-violet-300 italic">
              → {card.next_best_action}
            </div>
          )}
        </div>
      )}
    </div>
  )
}
