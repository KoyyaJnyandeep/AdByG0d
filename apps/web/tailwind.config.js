/** @type {import('tailwindcss').Config} */
module.exports = {
  darkMode: 'class',
  content: [
    './src/pages/**/*.{js,ts,jsx,tsx,mdx}',
    './src/components/**/*.{js,ts,jsx,tsx,mdx}',
    './src/app/**/*.{js,ts,jsx,tsx,mdx}',
  ],
  theme: {
    extend: {
      colors: {
        // ── Cyberpunk design tokens ──────────────────────────────────
        background: {
          DEFAULT: '#020108',
          subtle: '#04020f',
        },
        surface: {
          DEFAULT: 'rgba(4,2,16,0.94)',
          raised: 'rgba(8,4,28,0.96)',
          overlay: 'rgba(168,85,247,0.06)',
        },
        border: {
          DEFAULT: 'rgba(168,85,247,0.25)',
          subtle: 'rgba(168,85,247,0.12)',
          strong: 'rgba(168,85,247,0.5)',
        },
        text: {
          primary: '#ede0ff',
          secondary: 'rgba(200,190,240,0.65)',
          tertiary: 'rgba(168,85,247,0.45)',
          inverse: '#020108',
        },
        brand: {
          DEFAULT: 'var(--brand)',
          hover: 'var(--brand-light)',
          muted: 'rgba(var(--brand-rgb),0.15)',
          subtle: 'rgba(var(--brand-rgb),0.08)',
        },
        cyan: {
          DEFAULT: 'var(--accent1)',
          muted: 'rgba(var(--accent1-rgb),0.15)',
          subtle: 'rgba(var(--accent1-rgb),0.08)',
        },
        pink: {
          DEFAULT: 'var(--accent2)',
          muted: 'rgba(var(--accent2-rgb),0.15)',
        },
        // ── Severity (keep semantic colors) ─────────────────────────
        critical: {
          DEFAULT: '#ef4444',
          bg: 'rgba(239,68,68,0.1)',
          border: 'rgba(239,68,68,0.35)',
          text: '#fca5a5',
        },
        high: {
          DEFAULT: '#f97316',
          bg: 'rgba(249,115,22,0.1)',
          border: 'rgba(249,115,22,0.35)',
          text: '#fdba74',
        },
        medium: {
          DEFAULT: '#eab308',
          bg: 'rgba(234,179,8,0.1)',
          border: 'rgba(234,179,8,0.3)',
          text: '#fde047',
        },
        low: {
          DEFAULT: '#22c55e',
          bg: 'rgba(34,197,94,0.1)',
          border: 'rgba(34,197,94,0.3)',
          text: '#86efac',
        },
        info: {
          DEFAULT: '#3b82f6',
          bg: 'rgba(59,130,246,0.1)',
          border: 'rgba(59,130,246,0.3)',
          text: '#93c5fd',
        },
        // ── Graph node types ─────────────────────────────────────────
        node: {
          user: '#8b5cf6',
          group: '#06b6d4',
          computer: '#3b82f6',
          domain: '#a855f7',
          gpo: '#84cc16',
          ca: '#ec4899',
          tier0: '#ef4444',
        },
      },
      fontFamily: {
        sans: ['JetBrains Mono', 'Cascadia Code', 'Fira Code', 'monospace'],
        mono: ['JetBrains Mono', 'Cascadia Code', 'Fira Code', 'monospace'],
      },
      fontSize: {
        '2xs': ['0.625rem', { lineHeight: '0.875rem' }],
      },
      borderRadius: {
        'xl': '0.75rem',
        '2xl': '1rem',
        '3xl': '1.25rem',
      },
      boxShadow: {
        'sm-dark': '0 1px 3px rgba(0,0,0,0.6), 0 0 8px rgba(168,85,247,0.06)',
        'md-dark': '0 4px 16px rgba(0,0,0,0.6), 0 0 24px rgba(168,85,247,0.08)',
        'lg-dark': '0 10px 40px rgba(0,0,0,0.7), 0 0 60px rgba(168,85,247,0.1)',
        'xl-dark': '0 20px 60px rgba(0,0,0,0.8), 0 0 100px rgba(168,85,247,0.12)',
        'glow-brand': '0 0 24px rgba(var(--brand-rgb),0.4), 0 0 48px rgba(var(--brand-rgb),0.2)',
        'glow-cyan': '0 0 24px rgba(var(--accent1-rgb),0.35)',
        'glow-critical': '0 0 20px rgba(239,68,68,0.35)',
        'neon': '0 0 12px rgba(var(--brand-rgb),0.4), 0 0 40px rgba(var(--brand-rgb),0.15), inset 0 0 24px rgba(var(--brand-rgb),0.04)',
      },
      animation: {
        'fade-in': 'fadeIn 0.2s ease-out',
        'slide-up': 'slideUp 0.25s ease-out',
        'slide-in-right': 'slideInRight 0.25s ease-out',
        'pulse-slow': 'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'spin-slow': 'spin 3s linear infinite',
        'neon-pulse': 'neonPulse 4.5s ease-in-out infinite',
        'data-flash': 'dataFlash 1.6s ease-in-out infinite',
        'scanline': 'scanlineMove 14s linear infinite',
      },
      keyframes: {
        fadeIn: {
          '0%': { opacity: '0' },
          '100%': { opacity: '1' },
        },
        slideUp: {
          '0%': { opacity: '0', transform: 'translateY(8px)' },
          '100%': { opacity: '1', transform: 'translateY(0)' },
        },
        slideInRight: {
          '0%': { opacity: '0', transform: 'translateX(12px)' },
          '100%': { opacity: '1', transform: 'translateX(0)' },
        },
        neonPulse: {
          '0%,100%': { boxShadow: '0 0 12px rgba(var(--brand-rgb),.4),0 0 40px rgba(var(--brand-rgb),.15),inset 0 0 24px rgba(var(--brand-rgb),.04)' },
          '50%': { boxShadow: '0 0 24px rgba(var(--brand-rgb),.75),0 0 80px rgba(var(--brand-rgb),.28),inset 0 0 36px rgba(var(--brand-rgb),.08)' },
        },
        dataFlash: {
          '0%,100%': { opacity: '0.35' },
          '50%': { opacity: '1' },
        },
        scanlineMove: {
          '0%': { transform: 'translateY(-100%)' },
          '100%': { transform: 'translateY(100vh)' },
        },
      },
      backgroundImage: {
        'gradient-radial': 'radial-gradient(var(--tw-gradient-stops))',
        'cyber-grid': "linear-gradient(rgba(var(--brand-rgb),0.05) 1px, transparent 1px), linear-gradient(90deg, rgba(var(--brand-rgb),0.05) 1px, transparent 1px)",
      },
    },
  },
  plugins: [],
}
