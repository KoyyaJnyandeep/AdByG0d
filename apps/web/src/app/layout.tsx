import type { Metadata, Viewport } from 'next'
import './globals.css'
import { Providers } from './providers'

export const viewport: Viewport = {
  width: 'device-width',
  initialScale: 1,
}

export const metadata: Metadata = {
  title: {
    default: 'AdByG0d — Enterprise Identity Exposure Platform',
    template: '%s | AdByG0d',
  },
  description: 'Enterprise Active Directory Identity Exposure Validation and Remediation Intelligence Platform',
  icons: {
    icon: '/favicon.ico',
    apple: '/logo.jpg',
  },
  openGraph: {
    title: 'AdByG0d — Enterprise Identity Exposure Platform',
    description: 'Enterprise Active Directory Identity Exposure Validation and Remediation Intelligence Platform',
    images: [{ url: '/logo.jpg', width: 512, height: 512, alt: 'AdByG0d' }],
  },
  twitter: {
    card: 'summary',
    images: ['/logo.jpg'],
  },
}

export default function RootLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <html lang="en" className="dark" suppressHydrationWarning>
      <body className="overflow-x-hidden antialiased">
        <Providers>
          {children}
        </Providers>
      </body>
    </html>
  )
}
