export const metadata = { title: 'AdByG0d — Launcher' }

export default function LaunchLayout({ children }: { children: React.ReactNode }) {
  return (
    <div style={{
      margin: 0,
      minHeight: '100vh',
      background: '#050005',
      color: '#e8d8c8',
      fontFamily: '"Cinzel", serif',
      position: 'relative',
      overflow: 'hidden',
    }}>
      {/* Demon — engraved into the void */}
      <div style={{
        position: 'fixed',
        inset: 0,
        backgroundImage: 'url(/bg-launch.jpg)',
        backgroundSize: 'cover',
        backgroundPosition: 'center top',
        opacity: 0.13,
        zIndex: 0,
        pointerEvents: 'none',
        filter: 'grayscale(30%) contrast(1.2)',
      }} />

      {/* Dark vignette — swallows the edges */}
      <div style={{
        position: 'fixed',
        inset: 0,
        background: 'radial-gradient(ellipse 80% 80% at 50% 40%, transparent 10%, rgba(5,0,8,0.7) 65%, #050005 100%)',
        zIndex: 1,
        pointerEvents: 'none',
      }} />

      {/* Hellfire glow rising from below */}
      <div style={{
        position: 'fixed',
        bottom: 0,
        left: 0,
        right: 0,
        height: '45%',
        background: 'linear-gradient(to top, rgba(100,0,0,0.18) 0%, rgba(80,0,0,0.08) 40%, transparent 100%)',
        zIndex: 1,
        pointerEvents: 'none',
      }} />

      {/* Top crimson bleed */}
      <div style={{
        position: 'fixed',
        top: 0,
        left: 0,
        right: 0,
        height: '30%',
        background: 'linear-gradient(to bottom, rgba(60,0,0,0.12), transparent)',
        zIndex: 1,
        pointerEvents: 'none',
      }} />

      <div style={{ position: 'relative', zIndex: 2 }}>
        {children}
      </div>
    </div>
  )
}
