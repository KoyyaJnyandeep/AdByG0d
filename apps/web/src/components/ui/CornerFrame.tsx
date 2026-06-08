'use client'

interface CornerFrameProps {
  color?: string
  size?: number
}

export function CornerFrame({ color = 'var(--brand)', size = 30 }: CornerFrameProps) {
  const C = (pos: string, rot: number) => (
    <div className={`absolute ${pos}`} style={{ transform: `rotate(${rot}deg)` }}>
      <svg width={size} height={size} viewBox="0 0 30 30" fill="none">
        <path d="M2 18 L2 2 L18 2" stroke={color} strokeWidth="1.8" strokeLinecap="round" />
        <circle cx="2" cy="2" r="1.5" fill={color} />
      </svg>
    </div>
  )
  return (
    <div className="pointer-events-none absolute inset-0 z-10">
      {C('top-2 left-2', 0)}
      {C('top-2 right-2', 90)}
      {C('bottom-2 right-2', 180)}
      {C('bottom-2 left-2', 270)}
    </div>
  )
}
