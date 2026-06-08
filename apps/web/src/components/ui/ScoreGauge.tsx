'use client'

import { useEffect, useState } from 'react'
import { motion } from 'framer-motion'
import { cn } from '@/lib/utils'

interface ScoreGaugeProps {
  score: number
  size?: 'sm' | 'md' | 'lg'
  showLabel?: boolean
  delta?: number
  className?: string
}

const getHellColor = (score: number) => {
  if (score >= 85) return { stroke: '#FF2200', glow: 'rgba(196,18,48,0.85)', track: 'rgba(107,0,0,0.25)', label: 'CRITICAL', textColor: '#FF2200', dark: '#6B0000' }
  if (score >= 65) return { stroke: '#FF6B00', glow: 'rgba(196,75,0,0.8)',  track: 'rgba(107,38,0,0.25)', label: 'HIGH',     textColor: '#FF6B00', dark: '#6B2600' }
  if (score >= 40) return { stroke: '#FFB800', glow: 'rgba(196,136,0,0.7)', track: 'rgba(107,71,0,0.25)', label: 'ELEVATED', textColor: '#FFB800', dark: '#6B4700' }
  if (score >= 20) return { stroke: '#22c55e', glow: 'rgba(34,197,94,0.6)', track: 'rgba(6,78,59,0.25)',  label: 'MANAGED',  textColor: '#22c55e', dark: '#064e3b' }
  return                  { stroke: '#636366', glow: 'rgba(99,99,102,0.4)', track: 'rgba(39,39,42,0.25)', label: 'OFFLINE',  textColor: '#71717a', dark: '#27272a' }
}

export function ScoreGauge({ score, size = 'md', showLabel = true, delta, className }: ScoreGaugeProps) {
  const clampedScore = Math.min(100, Math.max(0, score))
  const hell = getHellColor(clampedScore)

  const [displayScore, setDisplayScore] = useState(0)
  const [glitch, setGlitch] = useState(false)

  useEffect(() => {
    let raf: number
    const duration = 1100
    const startTime = performance.now()
    const animate = (now: number) => {
      const progress = Math.min(1, (now - startTime) / duration)
      const eased = 1 - Math.pow(1 - progress, 3)
      setDisplayScore(Math.round(eased * clampedScore))
      if (progress < 1) raf = requestAnimationFrame(animate)
    }
    raf = requestAnimationFrame(animate)
    return () => cancelAnimationFrame(raf)
  }, [clampedScore])

  useEffect(() => {
    const t = setInterval(() => {
      setGlitch(true)
      setTimeout(() => setGlitch(false), 160)
    }, 3800 + Math.random() * 2500)
    return () => clearInterval(t)
  }, [])

  const sizes  = { sm: 80, md: 120, lg: 160 }
  const sz     = sizes[size]
  const sw     = size === 'sm' ? 7 : size === 'md' ? 10 : 13
  const radius = (sz - sw * 2) / 2
  const circ   = 2 * Math.PI * radius
  const arc    = circ * 0.75
  const offset = arc - (arc * clampedScore) / 100
  const center = sz / 2

  return (
    <div
      style={{
        perspective: '900px',
        perspectiveOrigin: '50% 50%',
        '--gauge-glow': hell.glow,
        '--gauge-dark': hell.dark,
        '--gauge-stroke': hell.stroke,
      } as React.CSSProperties}
    >
        <motion.div
          initial={{ opacity: 0, scale: 0.82, rotateY: 360 }}
          animate={{ opacity: 1, scale: 1, rotateY: 0 }}
          transition={{ duration: 1.15, ease: [0.16, 1, 0.3, 1], opacity: { duration: 0.35 }, scale: { duration: 0.8, ease: [0.34, 1.56, 0.64, 1] } }}
          style={{ transformStyle: 'preserve-3d' }}
          className={cn('inline-flex flex-col items-center gap-2', className)}
        >
          <div className="relative inline-flex" style={{ width: sz, height: sz }}>

            {/* SVG arc */}
            <svg width={sz} height={sz} className="-rotate-90 absolute inset-0">
              {/* Void track */}
              <circle
                cx={center} cy={center} r={radius}
                fill="none"
                stroke={hell.track}
                strokeWidth={sw}
                strokeDasharray={`${arc} ${circ - arc}`}
                strokeDashoffset={-circ * 0.125}
                strokeLinecap="round"
              />
              {/* Hellfire fill arc */}
              <circle
                cx={center} cy={center} r={radius}
                fill="none"
                stroke={hell.stroke}
                strokeWidth={sw}
                strokeDasharray={`${arc - offset} ${circ - (arc - offset)}`}
                strokeDashoffset={-circ * 0.125}
                strokeLinecap="round"
                style={{
                  transition: 'stroke-dasharray 0.85s cubic-bezier(0.23, 1, 0.32, 1)',
                  animation: 'hellArcPulse 3s ease-in-out infinite',
                }}
              />
              {/* Bright leading-edge spark */}
              {clampedScore > 2 && (() => {
                const angleFraction = (arc - offset) / circ
                const angle = -(Math.PI / 4) - angleFraction * 2 * Math.PI
                const sparkX = center + radius * Math.cos(angle)
                const sparkY = center + radius * Math.sin(angle)
                return (
                  <circle
                    cx={sparkX} cy={sparkY} r={sw * 0.55}
                    fill={hell.stroke}
                    style={{ filter: `drop-shadow(0 0 4px ${hell.stroke}) drop-shadow(0 0 8px ${hell.glow})` }}
                  />
                )
              })()}
            </svg>

            {/* Centre */}
            <div className="absolute inset-0 flex flex-col items-center justify-center gap-0.5">
              <span
                className="tabular-nums leading-none"
                style={{
                  fontFamily: "'Cinzel Decorative', serif",
                  fontSize: size === 'sm' ? '1rem' : size === 'md' ? '1.6rem' : '2.1rem',
                  fontWeight: 900,
                  color: hell.textColor,
                  animation: glitch
                    ? 'gaugeGlitch 0.2s ease-in-out, hellBurn 2.8s ease-in-out infinite'
                    : 'hellBurn 2.8s ease-in-out infinite',
                }}
              >
                {displayScore}
              </span>
              {size !== 'sm' && (
                <span style={{
                  fontFamily: "'Cinzel', serif",
                  fontSize: '9px',
                  letterSpacing: '0.2em',
                  color: 'rgba(196,18,48,0.35)',
                }}>
                  / 100
                </span>
              )}
            </div>
          </div>

          {showLabel && (
            <div className="flex flex-col items-center gap-0.5">
              <span
                style={{
                  fontFamily: "'Cinzel', serif",
                  fontSize: size === 'sm' ? '8px' : '11px',
                  fontWeight: 700,
                  letterSpacing: '0.28em',
                  color: hell.textColor,
                  textShadow: `0 0 14px ${hell.glow}, 0 0 28px ${hell.dark}`,
                }}
              >
                {hell.label}
              </span>
              {delta !== undefined && (
                <span style={{
                  fontFamily: "'Share Tech Mono', monospace",
                  fontSize: '10px',
                  color: delta > 0 ? '#FF2200' : delta < 0 ? '#22c55e' : 'rgba(196,18,48,0.3)',
                }}>
                  {delta > 0 ? `▲ +${delta.toFixed(1)}` : delta < 0 ? `▼ ${delta.toFixed(1)}` : '— stable'}
                </span>
              )}
            </div>
          )}
        </motion.div>
    </div>
  )
}
