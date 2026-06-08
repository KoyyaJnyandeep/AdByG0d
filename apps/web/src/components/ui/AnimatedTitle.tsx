'use client'

interface AnimatedTitleProps {
  text: string
  className?: string
  size?: 'sm' | 'md' | 'lg' | 'xl'
}

const SIZE_CLASS = {
  sm: 'text-2xl',
  md: 'text-3xl',
  lg: 'text-4xl',
  xl: 'text-5xl',
}

export function AnimatedTitle({ text, className = '', size = 'lg' }: AnimatedTitleProps) {
  const sz = SIZE_CLASS[size]
  return (
    <div className={`relative select-none inline-block ${className}`}>
      <span className={`glitch-main block font-mono ${sz} font-black tracking-tighter`}>{text}</span>
      <span className={`glitch-cyan pointer-events-none absolute inset-0 font-mono ${sz} font-black tracking-tighter`} aria-hidden>{text}</span>
      <span className={`glitch-pink pointer-events-none absolute inset-0 font-mono ${sz} font-black tracking-tighter`} aria-hidden>{text}</span>
    </div>
  )
}
