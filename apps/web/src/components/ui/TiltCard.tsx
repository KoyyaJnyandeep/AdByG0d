'use client'

import { useCallback, useRef, useState } from 'react'

interface TiltCardProps {
  children: React.ReactNode
  className?: string
  intensity?: number
}

export function TiltCard({ children, className = '', intensity = 9 }: TiltCardProps) {
  const r = useRef<HTMLDivElement>(null)
  const [tilt, setTilt] = useState({ x: 0, y: 0 })
  const [gp, setGp] = useState({ x: 50, y: 50 })
  const [hov, setHov] = useState(false)

  const onMove = useCallback((e: React.MouseEvent) => {
    const el = r.current; if (!el) return
    const rect = el.getBoundingClientRect()
    const dx = (e.clientX - rect.left - rect.width/2) / (rect.width/2)
    const dy = (e.clientY - rect.top - rect.height/2) / (rect.height/2)
    setTilt({ x: dy * -intensity, y: dx * intensity })
    setGp({ x:((e.clientX-rect.left)/rect.width)*100, y:((e.clientY-rect.top)/rect.height)*100 })
  }, [intensity])

  return (
    <div
      ref={r}
      onMouseMove={onMove}
      onMouseEnter={() => setHov(true)}
      onMouseLeave={() => { setTilt({x:0,y:0}); setHov(false) }}
      style={{ perspective: '1600px' }}
      className={className}
    >
      <div style={{
        transform: `rotateX(${tilt.x}deg) rotateY(${tilt.y}deg)`,
        transition: hov ? 'transform .06s ease-out' : 'transform .8s cubic-bezier(.23,1,.32,1)',
        transformStyle: 'preserve-3d',
        position: 'relative',
      }}>
        {/* Holographic glare */}
        <div
          className="pointer-events-none absolute inset-0 rounded-2xl z-20 transition-opacity duration-200"
          style={{
            opacity: hov ? 0.12 : 0,
            background: `radial-gradient(circle at ${gp.x}% ${gp.y}%, rgba(200,160,255,.9) 0%, transparent 55%)`,
            borderRadius: 'inherit',
          }}
        />
        {/* Depth shadow */}
        <div
          className="pointer-events-none absolute -inset-2 rounded-2xl transition-all duration-500"
          style={{
            opacity: hov ? 1 : 0.4,
            boxShadow: `0 ${20+tilt.x*2}px 80px rgba(0,0,0,0.9), 0 0 100px rgba(var(--brand-rgb),0.1)`,
            borderRadius: '20px',
            zIndex: -1,
          }}
        />
        {children}
      </div>
    </div>
  )
}
