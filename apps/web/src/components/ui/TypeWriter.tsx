'use client'

import { useEffect, useState } from 'react'

interface TypeWriterProps {
  lines: string[]
  className?: string
}

export function TypeWriter({ lines, className = '' }: TypeWriterProps) {
  const [i, setI] = useState(0)
  const [t, setT] = useState('')
  const [ch, setCh] = useState(0)
  const [d, setD] = useState(false)

  useEffect(() => {
    const cur = lines[i]
    const tm = setTimeout(() => {
      if (!d) {
        setT(cur.slice(0, ch+1))
        if (ch+1 === cur.length) setTimeout(() => setD(true), 1800)
        else setCh(x => x+1)
      } else {
        setT(cur.slice(0, ch-1))
        if (ch-1 === 0) { setD(false); setI(x => (x+1) % lines.length); setCh(0) }
        else setCh(x => x-1)
      }
    }, d ? 22 : 46)
    return () => clearTimeout(tm)
  }, [ch, d, i, lines])

  return (
    <span className={`font-mono text-[11px] ${className}`} style={{ color: 'rgba(var(--brand-rgb),.7)' }}>
      {t}<span className="animate-pulse" style={{ color: 'var(--brand)' }}>▌</span>
    </span>
  )
}
