'use client'

import { QueryClientProvider } from '@tanstack/react-query'
import { useState } from 'react'
import { Toaster } from 'react-hot-toast'
import { LazyMotion, domAnimation } from 'framer-motion'
import { ThemeProvider } from '@/components/ui/ThemeProvider'
import { makeQueryClient } from '@/lib/queryClient'

export function Providers({ children }: { children: React.ReactNode }) {
  const [queryClient] = useState(makeQueryClient)

  return (
    <ThemeProvider>
      <QueryClientProvider client={queryClient}>
        <LazyMotion features={domAnimation}>
          {children}
        </LazyMotion>
        <Toaster
        position="bottom-right"
        toastOptions={{
          style: {
            background: '#18181b',
            color: '#fafafa',
            border: '1px solid #27272a',
            borderRadius: '12px',
            fontSize: '14px',
          },
          success: {
            iconTheme: { primary: '#22c55e', secondary: '#18181b' },
          },
          error: {
            iconTheme: { primary: '#ef4444', secondary: '#18181b' },
          },
        }}
      />
      </QueryClientProvider>
    </ThemeProvider>
  )
}
