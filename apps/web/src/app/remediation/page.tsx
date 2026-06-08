import { AppShell } from '@/components/layout/AppShell'
import { RemediationSimulator } from '@/components/remediation/RemediationSimulator'

export const metadata = { title: 'Remediation Simulator' }

export default function RemediationPage() {
  return (
    <AppShell>
      <RemediationSimulator />
    </AppShell>
  )
}
