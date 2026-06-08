'use client'

import Image from 'next/image'

interface N3moProps {
  className?: string
  style?: React.CSSProperties
}

export function N3mo({ className = '', style }: N3moProps) {
  return (
    <Image
      src="/lucy.png"
      alt=""
      width={474}
      height={297}
      className={`pointer-events-none ${className}`}
      style={{
        filter: 'drop-shadow(0 0 18px rgba(var(--brand-rgb),0.55)) drop-shadow(0 0 40px rgba(var(--brand-rgb),0.2))',
        objectFit: 'contain',
        ...style,
      }}
    />
  )
}
