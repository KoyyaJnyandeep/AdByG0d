import { AppShell } from '@/components/layout/AppShell'
import { GraphExplorer } from '@/components/graph/GraphExplorer'

export const metadata = { title: 'Graph Explorer' }

export default function GraphPage() {
  return (
    <AppShell>
      <GraphExplorer />
    </AppShell>
  )
}
