import type { CSSProperties } from 'react'

export const card: CSSProperties = {
  background: 'rgba(6,0,2,0.93)',
  border: '1px solid rgba(139,0,0,0.55)',
  borderRadius: 3,
  padding: '36px 40px',
  width: 420,
  backdropFilter: 'blur(24px)',
  boxShadow: '0 0 0 1px rgba(80,0,0,0.2), 0 0 50px rgba(120,0,0,0.25), inset 0 0 60px rgba(0,0,0,0.6)',
}

export const cardTitle: CSSProperties = {
  fontSize: 18,
  fontWeight: 700,
  color: '#e8d8c8',
  marginBottom: 6,
  fontFamily: '"Cinzel", serif',
  letterSpacing: 3,
  textTransform: 'uppercase',
  textShadow: '0 0 20px rgba(180,0,0,0.5)',
}

export const cardSub: CSSProperties = {
  fontSize: 11,
  color: '#5a3030',
  marginBottom: 28,
  fontFamily: '"Share Tech Mono", monospace',
  letterSpacing: 1.5,
}

export const field: CSSProperties = { marginBottom: 16 }

export const label: CSSProperties = {
  display: 'block',
  fontSize: 10,
  letterSpacing: 3,
  color: '#8b0000',
  textTransform: 'uppercase',
  marginBottom: 7,
  fontFamily: '"Share Tech Mono", monospace',
}

export const input: CSSProperties = {
  width: '100%',
  background: 'rgba(20,0,0,0.85)',
  border: '1px solid rgba(100,0,0,0.45)',
  borderRadius: 2,
  padding: '12px 14px',
  color: '#d4b8b8',
  fontSize: 13,
  outline: 'none',
  boxSizing: 'border-box',
  fontFamily: '"Share Tech Mono", monospace',
  letterSpacing: 1,
}

export const btnPrimary: CSSProperties = {
  width: '100%',
  background: 'linear-gradient(90deg, #3d0000 0%, #6b0000 50%, #3d0000 100%)',
  border: '1px solid rgba(180,20,20,0.5)',
  borderRadius: 2,
  padding: '14px 13px',
  color: '#e8d8c8',
  fontSize: 11,
  fontWeight: 600,
  letterSpacing: 4,
  cursor: 'pointer',
  marginTop: 10,
  textTransform: 'uppercase',
  fontFamily: '"Share Tech Mono", monospace',
  boxShadow: '0 0 25px rgba(139,0,0,0.35), inset 0 1px 0 rgba(255,80,80,0.1)',
}

export const btnGhost: CSSProperties = {
  width: '100%',
  background: 'transparent',
  border: '1px solid rgba(100,0,0,0.35)',
  borderRadius: 2,
  padding: '12px 13px',
  color: '#6b3030',
  fontSize: 11,
  cursor: 'pointer',
  marginTop: 8,
  letterSpacing: 3,
  textTransform: 'uppercase',
  fontFamily: '"Share Tech Mono", monospace',
}

export const btnDanger: CSSProperties = {
  width: '100%',
  background: 'rgba(80,0,0,0.15)',
  border: '1px solid rgba(180,0,0,0.35)',
  borderRadius: 2,
  padding: '12px 13px',
  color: '#c04040',
  fontSize: 11,
  cursor: 'pointer',
  marginTop: 8,
  letterSpacing: 2,
  textTransform: 'uppercase',
  fontFamily: '"Share Tech Mono", monospace',
}
