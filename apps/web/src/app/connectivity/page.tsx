import { AppShell } from '@/components/layout/AppShell'
import { ConnectivityDashboard } from '@/components/connectivity/ConnectivityDashboard'

export const metadata = { title: 'Pivoting Layer — AdByG0d' }

export default function ConnectivityPage() {
  return (
    <AppShell>
      <ConnectivityDashboard />
    </AppShell>
  )
}
