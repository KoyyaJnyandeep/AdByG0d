'use client'

import { useEffect, useMemo, useState } from 'react'
import { useQuery } from '@tanstack/react-query'

import { assessmentApi, findingsApi } from '@/lib/api'
import { assessmentKeys } from '@/lib/queryKeys'

interface RouteAssessmentScopeOptions {
  inferFromFinding?: boolean
  findingParamNames?: string[]
}

function cleanId(value: string | null) {
  const trimmed = value?.trim()
  return trimmed ? trimmed : null
}

export function useRouteAssessmentScope(options: RouteAssessmentScopeOptions = {}) {
  const findingParamKey = useMemo(
    () => (options.findingParamNames?.length ? options.findingParamNames : ['finding']).join('|'),
    [options.findingParamNames],
  )
  const inferFromFinding = options.inferFromFinding ?? false

  const [routeAssessmentId, setRouteAssessmentId] = useState<string | null>(null)
  const [routeFindingId, setRouteFindingId] = useState<string | null>(null)

  useEffect(() => {
    if (typeof window === 'undefined') return
    const params = new URLSearchParams(window.location.search)
    setRouteAssessmentId(cleanId(params.get('assessment_id')))
    const findingParamNames = findingParamKey.split('|').filter(Boolean)
    const firstFindingId = findingParamNames
      .map((name) => cleanId(params.get(name)))
      .find((value): value is string => !!value) ?? null
    setRouteFindingId(firstFindingId)
  }, [findingParamKey])

  const { data: latestAssessments = [], isLoading: latestLoading } = useQuery({
    queryKey: assessmentKeys.latest(),
    queryFn: () => assessmentApi.list({ limit: 1 }),
    staleTime: 5 * 60_000,
  })
  const latestAssessment = latestAssessments[0] ?? null

  const { data: linkedFinding, isLoading: linkedFindingLoading } = useQuery({
    queryKey: ['route-linked-finding', routeFindingId],
    queryFn: () => findingsApi.get(routeFindingId!),
    enabled: inferFromFinding && !!routeFindingId,
    staleTime: 60_000,
  })

  const assessmentId = routeAssessmentId ?? linkedFinding?.assessment_id ?? latestAssessment?.id ?? null
  const needsScopedAssessment = !!assessmentId && assessmentId !== latestAssessment?.id

  const { data: scopedAssessment, isLoading: scopedAssessmentLoading } = useQuery({
    queryKey: ['assessment', 'route-scope', assessmentId],
    queryFn: () => assessmentApi.get(assessmentId!),
    enabled: needsScopedAssessment,
    staleTime: 5 * 60_000,
  })

  const assessment = needsScopedAssessment ? scopedAssessment ?? null : latestAssessment

  return {
    assessment,
    assessmentId,
    latestAssessment,
    linkedFinding,
    routeAssessmentId,
    routeFindingId,
    hasExplicitScope: !!routeAssessmentId || !!routeFindingId,
    isScopeLoading: latestLoading || linkedFindingLoading || scopedAssessmentLoading,
  }
}
