import { AppShell } from '@/components/layout/AppShell'
import { AssessmentsView } from '@/components/assessments/AssessmentsView'
import { HydrationBoundary, dehydrate } from '@tanstack/react-query'
import { makeQueryClient } from '@/lib/queryClient'
import { assessmentKeys, authKeys, collectionModuleKeys } from '@/lib/queryKeys'
import { serverAssessmentApi, serverAuthApi, serverCollectionModulesApi } from '@/lib/server-api'

export const metadata = { title: 'Assessments' }

export default async function AssessmentsPage() {
  const queryClient = makeQueryClient()

  await Promise.all([
    queryClient.prefetchQuery({
      queryKey: assessmentKeys.list(100),
      queryFn: () => serverAssessmentApi.list(100),
    }),
    queryClient.prefetchQuery({
      queryKey: authKeys.me(),
      queryFn: () => serverAuthApi.me(),
    }),
    queryClient.prefetchQuery({
      queryKey: assessmentKeys.workspaces(),
      queryFn: () => serverAssessmentApi.workspaces(),
    }),
    queryClient.prefetchQuery({
      queryKey: collectionModuleKeys.all(),
      queryFn: () => serverCollectionModulesApi.list(),
    }),
  ])

  return (
    <AppShell className="bg-black">
      <HydrationBoundary state={dehydrate(queryClient)}>
        <AssessmentsView />
      </HydrationBoundary>
    </AppShell>
  )
}
