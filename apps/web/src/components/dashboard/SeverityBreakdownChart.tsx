'use client'

import { memo, useMemo } from 'react'
import { PieChart, Pie, Cell, Tooltip } from 'recharts'

const ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']

const CHART_STYLES = `
  @keyframes hellVeinPulse {
    0%,100%{box-shadow:0 0 6px rgba(196,18,48,0.5),0 0 18px rgba(107,0,0,0.25)}
    50%{box-shadow:0 0 14px rgba(196,18,48,0.9),0 0 36px rgba(196,18,48,0.35)}
  }
  @keyframes eyeGlow {
    0%,100%{opacity:0.3;transform:scale(0.8)}
    50%{opacity:1;transform:scale(1.2)}
  }
  @keyframes drip {
    0%{transform:scaleY(0);opacity:0.8;transform-origin:top}
    60%{transform:scaleY(1);opacity:0.9;transform-origin:top}
    85%{transform:scaleY(1) translateY(6px);opacity:0.7;border-radius:0 0 50% 50%;transform-origin:top}
    100%{transform:scaleY(0.15) translateY(14px);opacity:0;border-radius:0 0 50% 50%;transform-origin:top}
  }
  @keyframes borderBleed {
    0%{background-position:0% 50%}
    100%{background-position:200% 50%}
  }
  @keyframes cursedBurn {
    0%,100%{text-shadow:0 0 8px #FF2200,0 0 24px #C41230,0 0 50px #6B0000}
    50%{text-shadow:0 0 16px #FF4400,0 0 40px #DC143C,0 0 80px #8B0000}
  }
  @keyframes glitchNum {
    0%,90%,100%{transform:none;filter:none}
    91%{transform:translate(4px,-2px) skewX(-6deg);filter:hue-rotate(180deg) brightness(1.8)}
    93%{transform:translate(-3px,1px) skewX(4deg);filter:brightness(0.7)}
    95%{transform:none;filter:none}
    97%{transform:translate(6px,0);filter:brightness(1.4)}
  }
  @keyframes runeRotate{from{transform:rotate(0deg)}to{transform:rotate(360deg)}}
  @keyframes runeRotateR{from{transform:rotate(0deg)}to{transform:rotate(-360deg)}}
  @keyframes barShimmer {
    0%{background-position:-200% 0}
    100%{background-position:200% 0}
  }
  @keyframes flicker{
    0%,100%{opacity:1}
    92%{opacity:1}93%{opacity:0.2}94%{opacity:0.9}96%{opacity:0.15}97%{opacity:1}
  }

  .hell-eye{animation:eyeGlow 1.8s ease-in-out infinite}
  .rune-cw{animation:runeRotate 24s linear infinite}
  .rune-ccw{animation:runeRotateR 36s linear infinite}
  .doom-num{animation:glitchNum 5s ease-in-out infinite,cursedBurn 2.8s ease-in-out infinite}
  .hell-flicker{animation:flicker 8s infinite}
  .hell-drip{animation:drip 3.2s ease-in-out infinite;transform-origin:top}
  .sev-bar-fill{
    background-size:300% 100%;
    animation:barShimmer 3s linear infinite;
  }
`

const HELL: Record<string, { primary: string; glow: string; dark: string }> = {
  CRITICAL: { primary: '#FF2200', glow: '#C41230', dark: '#6B0000' },
  HIGH:     { primary: '#FF6B00', glow: '#C44B00', dark: '#6B2600' },
  MEDIUM:   { primary: '#FFB800', glow: '#C48800', dark: '#6B4700' },
  LOW:      { primary: '#22c55e', glow: '#15803d', dark: '#064e3b' },
  INFO:     { primary: '#3b82f6', glow: '#1d4ed8', dark: '#1e3a5f' },
}

interface Props { counts: Record<string, number> }

export const SeverityBreakdownChart = memo(function SeverityBreakdownChart({ counts }: Props) {
  const { data, total } = useMemo(() => {
    const data = ORDER.filter((k) => (counts[k] ?? 0) > 0).map((k) => ({ name: k, value: counts[k] }))
    return { data, total: data.reduce((s, d) => s + d.value, 0) }
  }, [counts])

  return (
    <>
      <style>{CHART_STYLES}</style>

      {/* Blood drips along top */}
      <div className="pointer-events-none absolute left-0 right-0 top-0 overflow-hidden" style={{ height: '18px' }}>
        {[8, 22, 35, 52, 68, 84].map((left, i) => (
          <div
            key={i}
            className="hell-drip absolute"
            style={{
              left: `${left}%`,
              top: 0,
              width: '2px',
              height: `${8 + (i % 3) * 5}px`,
              background: 'linear-gradient(180deg,#C41230,#6B0000)',
              borderRadius: '1px',
              animationDelay: `${i * 0.55}s`,
              animationDuration: `${3.0 + i * 0.35}s`,
              opacity: 0.55,
            }}
          />
        ))}
      </div>

      <div className="relative flex items-center gap-6 pt-2">

        {/* ── Donut ─────────────────────────────────────────────────── */}
        <div className="relative shrink-0">

          {/* Rune rings behind donut */}
          <div className="rune-cw pointer-events-none absolute" style={{ inset: '-14px', opacity: 0.07 }}>
            <svg width="168" height="168" viewBox="0 0 168 168" fill="none">
              <circle cx="84" cy="84" r="80" stroke="#C41230" strokeWidth="1" fill="none" strokeDasharray="5 7" />
              {[0,1,2,3,4,5,6,7].map(i => {
                const a = (i * 45) * Math.PI / 180
                return (
                  <line key={i}
                    x1={84 + 68 * Math.cos(a)} y1={84 + 68 * Math.sin(a)}
                    x2={84 + 80 * Math.cos(a)} y2={84 + 80 * Math.sin(a)}
                    stroke="#C41230" strokeWidth="1"
                  />
                )
              })}
            </svg>
          </div>
          <div className="rune-ccw pointer-events-none absolute" style={{ inset: '-6px', opacity: 0.05 }}>
            <svg width="152" height="152" viewBox="0 0 152 152" fill="none">
              <circle cx="76" cy="76" r="72" stroke="#FF2200" strokeWidth="0.6" fill="none" strokeDasharray="2 8" />
            </svg>
          </div>

          {/* Red vein glow ring — animated */}
          <div
            className="pointer-events-none absolute rounded-full"
            style={{
              inset: '-4px',
              borderRadius: '50%',
              border: '1px solid rgba(196,18,48,0.2)',
              animation: 'hellVeinPulse 4s ease-in-out infinite',
            }}
          />

          <PieChart width={140} height={140} margin={{ top: 0, right: 0, bottom: 0, left: 0 }}>
            <Pie
              data={data}
              cx={70}
              cy={70}
              innerRadius={42}
              outerRadius={62}
              paddingAngle={3}
              dataKey="value"
              stroke="rgba(0,0,0,0.6)"
              strokeWidth={2}
              startAngle={90}
              endAngle={-270}
            >
              {data.map((entry) => (
                <Cell
                  key={entry.name}
                  fill={HELL[entry.name]?.primary ?? '#ef4444'}
                  style={{ filter: `drop-shadow(0 0 6px ${HELL[entry.name]?.glow ?? '#991b1b'})` }}
                />
              ))}
            </Pie>
            <Tooltip
              contentStyle={{
                background: '#0D0002',
                border: '1px solid rgba(196,18,48,0.5)',
                borderRadius: '4px',
                fontSize: '11px',
                color: '#D4C5A9',
                fontFamily: "'Share Tech Mono', monospace",
                boxShadow: '0 0 20px rgba(107,0,0,0.5)',
              }}
            />
          </PieChart>

          {/* Centre text */}
          <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center">
            <span
              className="doom-num tabular-nums leading-none"
              style={{
                fontFamily: "'Cinzel Decorative', serif",
                fontSize: '22px',
                fontWeight: 900,
                color: '#DC143C',
              }}
            >
              {total}
            </span>
            <span
              className="hell-flicker mt-0.5"
              style={{
                fontFamily: "'Cinzel', serif",
                fontSize: '7px',
                letterSpacing: '0.35em',
                color: 'rgba(196,18,48,0.45)',
              }}
            >
              SOULS
            </span>
          </div>

          {/* Hellfire scan beam across donut — CSS animation, no rAF */}
          <div
            className="hell-scan pointer-events-none absolute left-0 right-0"
            style={{
              height: '2px',
              background: 'linear-gradient(90deg, transparent, rgba(196,18,48,0.25), rgba(255,34,0,0.15), rgba(196,18,48,0.25), transparent)',
              filter: 'blur(1px)',
              borderRadius: '1px',
            }}
          />
        </div>

        {/* ── Severity rows ──────────────────────────────────────────── */}
        <div className="min-w-0 flex-1 space-y-3.5">
          {data.map(({ name, value }, idx) => {
            const pct = total > 0 ? Math.round((value / total) * 100) : 0
            const h = HELL[name] ?? HELL.INFO
            return (
              <div key={name} className="group relative">

                {/* Label row */}
                <div className="mb-1.5 flex items-center justify-between gap-2">
                  <div className="flex items-center gap-2.5">
                    {/* Demon eye dot */}
                    <span
                      className="hell-eye h-2.5 w-2.5 shrink-0 rounded-full"
                      style={{
                        background: h.primary,
                        boxShadow: `0 0 8px ${h.glow}, 0 0 16px ${h.dark}`,
                        animationDelay: `${idx * 0.32}s`,
                      }}
                    />
                    <span
                      style={{
                        fontFamily: "'Cinzel', serif",
                        fontSize: '10px',
                        letterSpacing: '0.25em',
                        color: 'rgba(212,197,169,0.65)',
                        textShadow: `0 0 10px ${h.dark}88`,
                      }}
                    >
                      {name}
                    </span>
                  </div>

                  <div className="flex shrink-0 items-center gap-2">
                    <span
                      style={{
                        fontFamily: "'Cinzel Decorative', serif",
                        fontSize: '13px',
                        fontWeight: 900,
                        color: h.primary,
                        textShadow: `0 0 16px ${h.glow}, 0 0 32px ${h.dark}`,
                      }}
                    >
                      {value}
                    </span>
                    <span
                      style={{
                        fontFamily: "'Share Tech Mono', monospace",
                        fontSize: '10px',
                        color: 'rgba(180,60,60,0.35)',
                        minWidth: '30px',
                        textAlign: 'right',
                      }}
                    >
                      {pct}%
                    </span>
                  </div>
                </div>

                {/* Bar track */}
                <div
                  className="relative h-2 overflow-hidden"
                  style={{
                    background: 'rgba(30,0,0,0.85)',
                    border: '1px solid rgba(107,0,0,0.25)',
                    boxShadow: 'inset 0 0 6px rgba(0,0,0,0.7)',
                  }}
                >
                  {/* Segment ticks */}
                  <div
                    className="pointer-events-none absolute inset-0"
                    style={{
                      background: 'repeating-linear-gradient(90deg,transparent,transparent 9px,rgba(0,0,0,0.3) 9px,rgba(0,0,0,0.3) 10px)',
                    }}
                  />
                  {/* Filled portion */}
                  <div
                    className="sev-bar-fill h-full transition-all duration-1000"
                    style={{
                      width: `${pct}%`,
                      background: `linear-gradient(90deg, ${h.dark}, ${h.glow} 40%, ${h.primary} 70%, ${h.primary})`,
                      backgroundSize: '300% 100%',
                      boxShadow: `0 0 10px ${h.glow}, 0 0 20px ${h.dark}66`,
                      position: 'relative',
                    }}
                  >
                    {/* Bright leading edge */}
                    <div
                      className="absolute bottom-0 right-0 top-0 w-[3px]"
                      style={{
                        background: h.primary,
                        boxShadow: `0 0 8px ${h.primary}, 0 0 16px ${h.glow}`,
                        opacity: 0.9,
                      }}
                    />
                  </div>
                </div>
              </div>
            )
          })}

          {/* Classification stamp at bottom */}
          <div
            className="hell-flicker mt-2 flex items-center gap-2"
            style={{ borderTop: '1px solid rgba(107,0,0,0.2)', paddingTop: '8px' }}
          >
            <span
              className="h-1.5 w-1.5 rounded-full"
              style={{ background: '#C41230', boxShadow: '0 0 8px #C41230', animation: 'eyeGlow 2s ease-in-out infinite' }}
            />
            <span
              style={{
                fontFamily: "'Cinzel', serif",
                fontSize: '8px',
                letterSpacing: '0.28em',
                color: 'rgba(196,18,48,0.35)',
              }}
            >
              CLASSIFIED // TIER-0 THREAT SPECTRUM
            </span>
          </div>
        </div>
      </div>
    </>
  )
})
