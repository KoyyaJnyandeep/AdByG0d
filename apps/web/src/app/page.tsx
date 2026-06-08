import { AppShell } from '@/components/layout/AppShell'
import { Dashboard } from '@/components/dashboard/Dashboard'
import { HydrationBoundary, dehydrate } from '@tanstack/react-query'
import { makeQueryClient } from '@/lib/queryClient'
import { assessmentKeys } from '@/lib/queryKeys'
import { isUnauthorizedServerApiError, serverAssessmentApi } from '@/lib/server-api'
import { redirect } from 'next/navigation'

export default async function DashboardPage() {
  const queryClient = makeQueryClient()
  const assessments = await queryClient.fetchQuery({
    queryKey: assessmentKeys.latest(),
    queryFn: () => serverAssessmentApi.latest(),
  }).catch((error: unknown) => {
    if (isUnauthorizedServerApiError(error)) {
      redirect('/login')
    }
    throw error
  })
  const latestAssessment = assessments[0] ?? null

  if (latestAssessment?.id) {
    await queryClient.prefetchQuery({
      queryKey: assessmentKeys.dashboard(latestAssessment.id),
      queryFn: () => serverAssessmentApi.dashboard(latestAssessment.id),
    })
  }

  return (
    <AppShell>
      <HydrationBoundary state={dehydrate(queryClient)}>
        <Dashboard />
      </HydrationBoundary>
    </AppShell>
  )
}
