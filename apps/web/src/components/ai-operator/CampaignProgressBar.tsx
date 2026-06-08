'use client'

const PHASES = ['recon', 'enum', 'loot', 'privesc', 'lateral', 'da', 'report'] as const

export function CampaignProgressBar({
  activePhase,
  completedPhases,
}: {
  activePhase: string | null
  completedPhases: string[]
}) {
  if (!activePhase && completedPhases.length === 0) return null

  return (
    <div className="my-2 px-1">
      <div className="flex items-center gap-0.5">
        {PHASES.map((phase, i) => {
          const done = completedPhases.includes(phase)
          const active = activePhase === phase
          return (
            <div key={phase} className="flex items-center gap-0.5 flex-1">
              <div
                className="flex-1 text-center py-1 rounded text-[9px] font-bold uppercase tracking-wider transition-all"
                style={{
                  background: done
                    ? 'rgba(52,211,153,0.12)'
                    : active
                      ? 'rgba(96,165,250,0.12)'
                      : 'rgba(255,255,255,0.03)',
                  border: `1px solid ${
                    done
                      ? 'rgba(52,211,153,0.3)'
                      : active
                        ? 'rgba(96,165,250,0.3)'
                        : 'rgba(255,255,255,0.06)'
                  }`,
                  color: done ? '#34d399' : active ? '#60a5fa' : 'rgba(100,116,139,0.4)',
                }}
              >
                {phase}
              </div>
              {i < PHASES.length - 1 && (
                <div
                  className="h-px shrink-0"
                  style={{
                    width: '4px',
                    background: done ? 'rgba(52,211,153,0.3)' : 'rgba(255,255,255,0.06)',
                  }}
                />
              )}
            </div>
          )
        })}
      </div>
    </div>
  )
}
