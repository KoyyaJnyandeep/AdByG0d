'use client'

import { useLayoutEffect } from 'react'

interface Palette {
  brand: string
  brandRgb: string
  brandLight: string
  accent1: string
  accent1Rgb: string
  accent2: string
  accent2Rgb: string
}

const PALETTES: Palette[] = [
  {
    // Phantom — purple / cyan / pink
    brand: '#a855f7',
    brandRgb: '168,85,247',
    brandLight: '#d8b4fe',
    accent1: '#06b6d4',
    accent1Rgb: '6,182,212',
    accent2: '#ec4899',
    accent2Rgb: '236,72,153',
  },
  {
    // Sakura — pink / teal / violet
    brand: '#f472b6',
    brandRgb: '244,114,182',
    brandLight: '#fce7f3',
    accent1: '#14b8a6',
    accent1Rgb: '20,184,166',
    accent2: '#8b5cf6',
    accent2Rgb: '139,92,246',
  },
  {
    // Ghost — white / red / cyan
    brand: '#e2e8f0',
    brandRgb: '226,232,240',
    brandLight: '#f1f5f9',
    accent1: '#ef4444',
    accent1Rgb: '239,68,68',
    accent2: '#06b6d4',
    accent2Rgb: '6,182,212',
  },
]

export function ThemeProvider({ children }: { children: React.ReactNode }) {
  useLayoutEffect(() => {
    const palette = PALETTES[Math.floor(Math.random() * PALETTES.length)]
    const root = document.documentElement
    root.style.setProperty('--brand', palette.brand)
    root.style.setProperty('--brand-rgb', palette.brandRgb)
    root.style.setProperty('--brand-light', palette.brandLight)
    root.style.setProperty('--accent1', palette.accent1)
    root.style.setProperty('--accent1-rgb', palette.accent1Rgb)
    root.style.setProperty('--accent2', palette.accent2)
    root.style.setProperty('--accent2-rgb', palette.accent2Rgb)
  }, [])

  return <>{children}</>
}
