import { AppShell } from '@/components/layout/AppShell'
import { FindingsExplorer } from '@/components/findings/FindingsExplorer'
import { HydrationBoundary, dehydrate } from '@tanstack/react-query'
import { makeQueryClient } from '@/lib/queryClient'
import { assessmentKeys, findingsKeys } from '@/lib/queryKeys'
import { ServerApiError, isUnauthorizedServerApiError, serverAssessmentApi, serverFindingsApi } from '@/lib/server-api'
import { redirect } from 'next/navigation'

export const metadata = { title: 'Findings' }

export default async function FindingsPage() {
  const queryClient = makeQueryClient()
  const assessments = await queryClient.fetchQuery({
    queryKey: assessmentKeys.latest(),
    queryFn: () => serverAssessmentApi.latest(),
  }).catch((error: unknown) => {
    if (isUnauthorizedServerApiError(error)) {
      redirect('/login')
    }
    if (error instanceof ServerApiError) {
      return []
    }
    throw error
  })
  const latestAssessment = assessments[0] ?? null

  if (latestAssessment?.id) {
    await queryClient.prefetchQuery({
      queryKey: findingsKeys.list(latestAssessment.id, 500),
      queryFn: () => serverFindingsApi.list(latestAssessment.id, 500),
    }).catch(() => undefined)
  }

  return (
    <AppShell>
      <HydrationBoundary state={dehydrate(queryClient)}>
        <FindingsExplorer />
      </HydrationBoundary>
    </AppShell>
  )
}
