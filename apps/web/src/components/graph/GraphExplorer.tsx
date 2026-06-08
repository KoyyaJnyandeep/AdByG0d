'use client'

import {
  useCallback, useDeferredValue, useEffect, useMemo, useRef, useState,
} from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Command, Layers, Loader2,
  RefreshCw, Sparkles, Target,
  Upload, Workflow, X,
} from 'lucide-react'
import { motion, AnimatePresence } from 'framer-motion'
import { useRouter } from 'next/navigation'
import toast from 'react-hot-toast'

import { graphApi, importApi } from '@/lib/api'
import { useGraphStream } from '@/lib/useGraphStream'
import { useImportStore } from '@/lib/importStore'
import type { GraphEdge, GraphNode, GraphData, VirtualGroupNode, SavedGraphView, PathNarration, MonteCarloResult, AnomalyResult, PathStep } from '@/lib/types'
import { cn, fmtNumber } from '@/lib/utils'
import { useRouteAssessmentScope } from '@/lib/useRouteAssessmentScope'

import { GraphCanvas } from './GraphCanvas'
import { NodeInfoPanel } from './NodeInfoPanel'
import { ContextMenu, CommandPalette, ShortcutsModal } from './GraphOverlays'
import {
  PathFinderPanel, EdgeDetailsPanel, EdgeHoverTip,
  PrebuiltQueriesPanel, AnalyticsPanel, ColorModeLegend,
  SimProgressBar, EdgeBundlePanel, SavedViewsPanel,
  SnapshotTimelinePanel, NarrationPanel, AnomalyFeedPanel,
} from './GraphPanels'
import { GraphToolbar } from './GraphToolbar'
import type { ColorMode, ContainerBox, CtxMenu, EdgeHoverState, ForceGraphHandle, GraphMode, GraphToggles, LayoutMode, RenderProps } from './engine/types'
import { DEFAULT_TOGGLES } from './engine/types'
import { MODE_PRESETS, applyModeToState } from './GraphModes'
import { LEGEND, getLetter } from './engine/constants'
import {
  findPath, getErrDetail, getId,
  getNHopNeighborhood, nodeBaseColor,
} from './engine/utils'
import { edgeRiskColor } from './engine/constants'

type QueryResult = { nodeIds?: Set<string>; edgeIds?: Set<string>; label: string }

export function GraphExplorer() {
  const graphRef = useRef<ForceGraphHandle>(null)
  const shellRef = useRef<HTMLDivElement>(null)
  const routeFocusAppliedRef = useRef<string | null>(null)
  const markingsSaveTimer = useRef<ReturnType<typeof setTimeout> | null>(null)
  const router = useRouter()

  // Search / filter
  const [searchInput, setSearchInput] = useState('')
  const [tier0Only, setTier0Only] = useState(false)
  const [edgeTypeFilter, setEdgeTypeFilter] = useState<Set<string>>(new Set())
  const [minRiskFilter, setMinRiskFilter] = useState(0)

  // Graph mode / toggles
  const [graphMode, setGraphMode] = useState<GraphMode | null>(null)
  const [toggles, setToggles] = useState<GraphToggles>(DEFAULT_TOGGLES)
  const search = useDeferredValue(searchInput)

  // Layout / view
  const [layoutMode, setLayoutMode] = useState<LayoutMode>('force')
  const [showEdgeLabels, setShowEdgeLabels] = useState(false)
  const [isFullscreen, setIsFullscreen] = useState(false)
  const [colorMode, setColorMode] = useState<ColorMode>('default')
  const [sizeByDegree, setSizeByDegree] = useState(false)
  const [showParticles, setShowParticles] = useState(true)

  // Panels
  const [showPathFinder, setShowPathFinder] = useState(false)
  const [showShortcuts, setShowShortcuts] = useState(false)
  const [showQueries, setShowQueries] = useState(false)
  const [showAnalytics, setShowAnalytics] = useState(false)
  const [showPalette, setShowPalette] = useState(false)
  const [showViews, setShowViews] = useState(false)
  const [showTimeline, setShowTimeline] = useState(false)

  // Diff state
  const [activeDiff, setActiveDiff] = useState<{ fromId: string; toId: string } | null>(null)
  const [diffAddedNodeIds, setDiffAddedNodeIds] = useState<Set<string>>(new Set())
  const [diffRemovedNodeIds, setDiffRemovedNodeIds] = useState<Set<string>>(new Set())
  const [diffAddedEdgeIds, setDiffAddedEdgeIds] = useState<Set<string>>(new Set())
  const [diffRemovedEdgeIds, setDiffRemovedEdgeIds] = useState<Set<string>>(new Set())

  // Analysis
  const [highlightNodeIds, setHighlightNodeIds] = useState<Set<string>>(new Set())
  const [highlightEdgeIds, setHighlightEdgeIds] = useState<Set<string>>(new Set())
  const [nlFilterNodeIds, setNlFilterNodeIds] = useState<Set<string> | null>(null)
  const [queryLabel, setQueryLabel] = useState('')
  const [focusNodeId, setFocusNodeId] = useState<string | null>(null)
  const [focusHops, setFocusHops] = useState(2)

  // Edge interaction
  const [hoveredEdge, setHoveredEdge] = useState<EdgeHoverState | null>(null)
  const [selectedEdge, setSelectedEdge] = useState<GraphEdge | null>(null)
  const [selectedBundle, setSelectedBundle] = useState<{sourceId: string; targetId: string; edges: GraphEdge[]} | null>(null)

  // Path finding
  const [startNode, setStartNode] = useState<GraphNode | null>(null)
  const [endNode, setEndNode] = useState<GraphNode | null>(null)
  const [pathNodeIds, setPathNodeIds] = useState<Set<string>>(new Set())
  const [pathEdgeIds, setPathEdgeIds] = useState<Set<string>>(new Set())
  const [directedPaths, setDirectedPaths] = useState(false)

  // Markings
  const [ownedNodes, setOwnedNodes] = useState<Set<string>>(new Set())
  const [highValueNodes, setHighValueNodes] = useState<Set<string>>(new Set())
  const [pinnedNodes, setPinnedNodes] = useState<Set<string>>(new Set())

  // Group collapse
  const [collapsedGroups, setCollapsedGroups] = useState<Map<string, string[]>>(new Map())

  // Selection
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null)
  const [contextMenu, setContextMenu] = useState<CtxMenu | null>(null)
  const [simulationData, setSimulationData] = useState<{ reduction: number } | null>(null)
  const [simAlpha, setSimAlpha] = useState(0)

  // Phase 5 AI states
  const [nlQueryInput, setNlQueryInput] = useState('')
  const [showNlBar, setShowNlBar] = useState(false)
  const [narration, setNarration] = useState<PathNarration | null>(null)
  const [monteCarlo, setMonteCarlo] = useState<MonteCarloResult | null>(null)
  const [showAnomalyFeed, setShowAnomalyFeed] = useState(false)
  const [anomalies, setAnomalies] = useState<AnomalyResult[]>([])
  const [heatMap, setHeatMap] = useState<Map<string, number>>(new Map())
  const [streamActive, setStreamActive] = useState(false)

  // ARIA live region for screen readers
  const [ariaLive, setAriaLive] = useState('')

  // Import
  const startImport = useImportStore(s => s.startImport)
  const importJobActive = useImportStore(s => s.job)
  const [isImporting, setIsImporting] = useState(false)

  // Data
  const { assessmentId, routeFindingId, linkedFinding } = useRouteAssessmentScope({
    inferFromFinding: true,
    findingParamNames: ['finding', 'highlight'],
  })

  const queryClient = useQueryClient()

  useGraphStream({
    assessmentId,
    enabled: streamActive,
    onDelta: useCallback((delta) => {
      if (!assessmentId) return
      queryClient.setQueryData(['graph', assessmentId], (old: GraphData | undefined) => {
        if (!old) return old
        return {
          ...old,
          nodes: [...(old.nodes ?? []), ...(delta.added_nodes ?? [])],
          edges: [...(old.edges ?? []), ...(delta.added_edges ?? [])],
          node_count: (old.node_count ?? 0) + (delta.added_nodes?.length ?? 0),
          edge_count: (old.edge_count ?? 0) + (delta.added_edges?.length ?? 0),
        }
      })
    }, [assessmentId, queryClient]),
    onThreatAlert: useCallback((msg) => {
      toast.error(`⚠ ${msg}`, { duration: 6000 })
    }, []),
  })

  const { data, isLoading, isError, refetch } = useQuery({
    queryKey: ['graph', assessmentId],
    queryFn: () => graphApi.getData(assessmentId!, { max_nodes: 2000 }),
    enabled: !!assessmentId,
    staleTime: 30_000,
  })

  const { data: markingsData } = useQuery({
    queryKey: ['graph-markings', assessmentId],
    queryFn: () => graphApi.getMarkings(assessmentId!),
    enabled: !!assessmentId,
    staleTime: 60_000,
  })

  const { data: viewsData } = useQuery({
    queryKey: ['graph-views', assessmentId],
    queryFn: () => graphApi.getViews(assessmentId!),
    enabled: !!assessmentId,
  })
  const savedViews = viewsData?.views ?? []

  const { data: snapshotsData, refetch: refetchSnapshots } = useQuery({
    queryKey: ['graph-snapshots', assessmentId],
    queryFn: () => graphApi.getSnapshots(assessmentId!),
    enabled: !!assessmentId,
    staleTime: 30_000,
  })

  const allNodes = useMemo(() => data?.nodes ?? [], [data])
  const allEdges = useMemo(() => data?.edges ?? [], [data])

  // localStorage fallback for markings (runs before DB data arrives)
  useEffect(() => {
    if (!assessmentId) return
    const key = `graph_markings_${assessmentId}`
    const saved = localStorage.getItem(key)
    if (saved && !markingsData) {
      try {
        const parsed = JSON.parse(saved)
        setOwnedNodes(new Set(parsed.owned_ids ?? []))
        setHighValueNodes(new Set(parsed.high_value_ids ?? []))
        setPinnedNodes(new Set(parsed.pinned_ids ?? []))
      } catch { /* ignore corrupt data */ }
    }
  }, [assessmentId, markingsData])

  // Load markings from DB when available
  useEffect(() => {
    if (!markingsData) return
    setOwnedNodes(new Set(markingsData.owned_ids))
    setHighValueNodes(new Set(markingsData.high_value_ids))
    setPinnedNodes(new Set(markingsData.pinned_ids))
  }, [markingsData])

  const saveMarkings = useCallback((
    owned: Set<string>, highValue: Set<string>, pinned: Set<string>
  ) => {
    if (!assessmentId) return
    if (markingsSaveTimer.current) clearTimeout(markingsSaveTimer.current)
    markingsSaveTimer.current = setTimeout(async () => {
      try {
        await graphApi.putMarkings(assessmentId, {
          owned_ids: [...owned],
          high_value_ids: [...highValue],
          pinned_ids: [...pinned],
        })
      } catch {
        const key = `graph_markings_${assessmentId}`
        localStorage.setItem(key, JSON.stringify({
          owned_ids: [...owned], high_value_ids: [...highValue], pinned_ids: [...pinned],
        }))
      }
    }, 1500)
  }, [assessmentId])

  useEffect(() => {
    if (!routeFindingId || !linkedFinding || routeFocusAppliedRef.current === routeFindingId || allNodes.length === 0) return

    const nodeIdsInGraph = new Set(allNodes.map((node) => node.id))
    const pathNodeIds = new Set(
      (linkedFinding.attack_path ?? [])
        .map((step) => step.entity_id)
        .filter((id) => nodeIdsInGraph.has(id)),
    )
    const pathEdgeIds = new Set(
      allEdges
        .filter((edge) => pathNodeIds.has(getId(edge.source)) && pathNodeIds.has(getId(edge.target)))
        .map((edge) => edge.id),
    )

    if (pathNodeIds.size > 0) {
      const firstNodeId = linkedFinding.attack_path?.find((step) => pathNodeIds.has(step.entity_id))?.entity_id ?? null
      setHighlightNodeIds(pathNodeIds)
      setHighlightEdgeIds(pathEdgeIds)
      setPathNodeIds(pathNodeIds)
      setPathEdgeIds(pathEdgeIds)
      setQueryLabel(`Finding path: ${linkedFinding.title}`)
      setFocusNodeId(firstNodeId)
      setSelectedNode(allNodes.find((node) => node.id === firstNodeId) ?? null)
      setAriaLive(`Highlighted the graph path for ${linkedFinding.title}`)
    } else {
      setQueryLabel(`Finding linked: ${linkedFinding.title}`)
      setAriaLive(`${linkedFinding.title} is open, but no graph path was recorded for this finding.`)
    }

    routeFocusAppliedRef.current = routeFindingId
  }, [allEdges, allNodes, linkedFinding, routeFindingId])

  const degreeMap = useMemo(() => {
    const m = new Map<string, number>()
    for (const n of allNodes) m.set(n.id, 0)
    for (const e of allEdges) {
      const s = getId(e.source), t = getId(e.target)
      m.set(s, (m.get(s) ?? 0) + 1)
      m.set(t, (m.get(t) ?? 0) + 1)
    }
    return m
  }, [allNodes, allEdges])

  const maxDegree = useMemo(() => {
    let max = 1
    degreeMap.forEach(v => { if (v > max) max = v })
    return max
  }, [degreeMap])

  const riskMap = useMemo(() => {
    const m = new Map<string, number>()
    for (const e of allEdges) {
      const s = getId(e.source), t = getId(e.target)
      const w = e.risk_weight ?? 0
      m.set(s, Math.max(m.get(s) ?? 0, w))
      m.set(t, Math.max(m.get(t) ?? 0, w))
    }
    return m
  }, [allEdges])

  // Filter pipeline
  const { filteredNodes: _fn, filteredEdges: _fe } = useMemo(() => {
    const q = search.trim().toLowerCase()
    let nodes = allNodes, edges = allEdges

    if (tier0Only) {
      const tierIds = new Set(nodes.filter(n => n.tier===0 || n.is_crown_jewel).map(n => n.id))
      edges = edges.filter(e => { const s = getId(e.source), t = getId(e.target); return tierIds.has(s) || tierIds.has(t) })
      const active = new Set<string>()
      edges.forEach(e => { active.add(getId(e.source)); active.add(getId(e.target)) })
      nodes = nodes.filter(n => active.has(n.id) || tierIds.has(n.id))
    }
    if (edgeTypeFilter.size > 0) {
      edges = edges.filter(e => edgeTypeFilter.has(e.edge_type))
      const active = new Set<string>()
      edges.forEach(e => { active.add(getId(e.source)); active.add(getId(e.target)) })
      nodes = nodes.filter(n => active.has(n.id))
    }
    if (q) {
      const matchIds = new Set(nodes.filter(n => n.label.toLowerCase().includes(q) || n.entity_type.toLowerCase().includes(q)).map(n => n.id))
      edges = edges.filter(e => matchIds.has(getId(e.source)) || matchIds.has(getId(e.target)))
      const visible = new Set<string>()
      edges.forEach(e => { visible.add(getId(e.source)); visible.add(getId(e.target)) })
      nodes = nodes.filter(n => visible.has(n.id) || matchIds.has(n.id))
    }
    // Attack edges only / hide membership
    if (toggles.attackEdgesOnly || toggles.hideMembership) {
      const MEMBERSHIP = ['MEMBER_OF', 'CONTAINS', 'APPLIES_GPO', 'TRUSTS']
      if (toggles.attackEdgesOnly) {
        edges = edges.filter(e => !MEMBERSHIP.includes(e.edge_type))
      } else if (toggles.hideMembership) {
        edges = edges.filter(e => e.edge_type !== 'MEMBER_OF')
      }
      const active = new Set<string>()
      edges.forEach(e => { active.add(getId(e.source)); active.add(getId(e.target)) })
      nodes = nodes.filter(n => active.has(n.id))
    }
    // Hide low risk
    if (toggles.hideLowRisk) {
      edges = edges.filter(e => (e.risk_weight ?? 0) >= 0.3)
      const active = new Set<string>()
      edges.forEach(e => { active.add(getId(e.source)); active.add(getId(e.target)) })
      nodes = nodes.filter(n => active.has(n.id))
    }
    // Group collapse
    if (collapsedGroups.size > 0 || toggles.collapseGroups) {
      const toCollapse = new Map(collapsedGroups)
      if (toggles.collapseGroups) {
        nodes.filter(n => n.entity_type === 'GROUP').forEach(grp => {
          if (!toCollapse.has(grp.id)) {
            const memberIds = edges
              .filter(e => getId(e.target) === grp.id && e.edge_type === 'MEMBER_OF')
              .map(e => getId(e.source))
            if (memberIds.length > 0) toCollapse.set(grp.id, memberIds)
          }
        })
      }
      const allMemberIds = new Set<string>()
      toCollapse.forEach(mids => mids.forEach(m => allMemberIds.add(m)))

      nodes = nodes
        .filter(n => !allMemberIds.has(n.id))
        .map(n => {
          if (toCollapse.has(n.id)) {
            return { ...n, isVirtual: true, memberCount: toCollapse.get(n.id)!.length } as VirtualGroupNode
          }
          return n
        })

      const memberToGroup = new Map<string, string>()
      toCollapse.forEach((mids, gid) => mids.forEach(m => memberToGroup.set(m, gid)))
      edges = edges
        .filter(e => !allMemberIds.has(getId(e.source)) || !allMemberIds.has(getId(e.target)))
        .map(e => {
          const s = getId(e.source), t = getId(e.target)
          const newS = memberToGroup.get(s) ?? s
          const newT = memberToGroup.get(t) ?? t
          if (newS === newT) return null
          if (newS !== s || newT !== t) {
            return { ...e, source: newS, target: newT, id: `${e.id}_remapped` }
          }
          return e
        })
        .filter((e): e is GraphEdge => e !== null)
    }
    return { filteredNodes: nodes, filteredEdges: edges }
  }, [allNodes, allEdges, search, tier0Only, edgeTypeFilter, toggles, collapsedGroups])

  const AUTO_EDGE_CAP = 1200
  const { filteredNodes, filteredEdges } = useMemo(() => {
    let edges = _fe, nodes = _fn
    if (minRiskFilter > 0) {
      edges = edges.filter(e => (e.risk_weight ?? 0) >= minRiskFilter)
      const active = new Set<string>()
      edges.forEach(e => { active.add(getId(e.source)); active.add(getId(e.target)) })
      nodes = nodes.filter(n => active.has(n.id))
    } else if (edges.length > AUTO_EDGE_CAP) {
      const sorted = [...edges].sort((a, b) => (b.risk_weight??0) - (a.risk_weight??0))
      edges = sorted.slice(0, AUTO_EDGE_CAP)
      const active = new Set<string>()
      edges.forEach(e => { active.add(getId(e.source)); active.add(getId(e.target)) })
      nodes = nodes.filter(n => active.has(n.id))
    }
    return { filteredNodes: nodes, filteredEdges: edges }
  }, [_fn, _fe, minRiskFilter])

  // Clear focusNodeId if node removed
  useEffect(() => {
    if (focusNodeId && !filteredNodes.some(n => n.id === focusNodeId)) setFocusNodeId(null)
  }, [filteredNodes, focusNodeId])

  const { focusedNodes: _focusedNodes, focusedEdges: _focusedEdges } = useMemo(() => {
    if (!focusNodeId) return { focusedNodes: filteredNodes, focusedEdges: filteredEdges }
    const r = getNHopNeighborhood(filteredNodes, filteredEdges, focusNodeId, focusHops)
    return { focusedNodes: r.nodes, focusedEdges: r.edges }
  }, [filteredNodes, filteredEdges, focusNodeId, focusHops])

  const { focusedNodes, focusedEdges } = useMemo(() => {
    if (nlFilterNodeIds === null) return { focusedNodes: _focusedNodes, focusedEdges: _focusedEdges }
    const nodes = _focusedNodes.filter(n => nlFilterNodeIds.has(n.id))
    const visibleIds = new Set(nodes.map(n => n.id))
    const edges = _focusedEdges.filter(e => visibleIds.has(getId(e.source as string | GraphNode)) && visibleIds.has(getId(e.target as string | GraphNode)))
    return { focusedNodes: nodes, focusedEdges: edges }
  }, [_focusedNodes, _focusedEdges, nlFilterNodeIds])

  const allEdgeTypes = useMemo(() => [...new Set(allEdges.map(e => e.edge_type))].sort(), [allEdges])
  const tier0Count = focusedNodes.filter(n => n.tier===0 || n.is_crown_jewel).length
  const isAutoCapped = allEdges.length > 1200 && minRiskFilter <= 0

  // Use most of the viewport in both modes. Non-fullscreen gets ~70% of
  // viewport height so the graph actually fills the visible area.
  const graphHeight = typeof window !== 'undefined'
    ? isFullscreen
      ? window.innerHeight - 52
      : Math.max(560, window.innerHeight * 0.68)
    : 700

  // Compute container bounding boxes for OU/domain nodes
  const containerBoxes = useMemo<ContainerBox[]>(() => {
    if (!toggles.showContainers) return []
    const containsEdges = focusedEdges.filter(e => e.edge_type === 'CONTAINS')
    return containsEdges.map(e => {
      const containerId = getId(e.source as string | GraphNode)
      const container = focusedNodes.find(n => n.id === containerId)
      if (!container) return null
      return {
        nodeId: containerId,
        label: container.label,
        color: nodeBaseColor(container),
        minX: 0, minY: 0, maxX: 0, maxY: 0,
      }
    }).filter((c): c is ContainerBox => c !== null)
  }, [focusedEdges, focusedNodes, toggles.showContainers])

  // Build renderProps — memoised so GraphCanvas only re-renders when something actually changed
  const renderProps = useMemo<RenderProps>(() => ({
    showEdgeLabels, ownedNodes, highValueNodes, pathNodeIds, pathEdgeIds,
    colorMode, sizeByDegree, degreeMap, maxDegree, riskMap,
    highlightNodeIds, highlightEdgeIds,
    startNodeId: startNode?.id ?? null, endNodeId: endNode?.id ?? null,
    selectedId: selectedNode?.id ?? null,
    connectedIds: new Set(),  // managed in GraphCanvas
    pinnedIds: pinnedNodes,
    isSimulating: simAlpha > 0.05,
    showParticles,
    graphHeight,
    bundleEdges: toggles.bundleEdges,
    showProvenance: toggles.showProvenance,
    heatMap,
    containerBoxes,
    directedMode: directedPaths,
    diffAddedNodeIds,
    diffRemovedNodeIds,
    diffAddedEdgeIds,
    diffRemovedEdgeIds,
  }), [showEdgeLabels, ownedNodes, highValueNodes, pathNodeIds, pathEdgeIds, colorMode,
      sizeByDegree, degreeMap, maxDegree, riskMap, highlightNodeIds, highlightEdgeIds,
      startNode, endNode, selectedNode, simAlpha, showParticles, graphHeight, pinnedNodes,
      toggles.bundleEdges, toggles.showProvenance, containerBoxes, directedPaths,
      diffAddedNodeIds, diffRemovedNodeIds, diffAddedEdgeIds, diffRemovedEdgeIds, heatMap])

  // Handlers
  const handleOwned = useCallback((id: string) => {
    setOwnedNodes(prev => {
      const s = new Set(prev)
      if (s.has(id)) { s.delete(id) } else { s.add(id) }
      saveMarkings(s, highValueNodes, pinnedNodes)
      return s
    })
  }, [highValueNodes, pinnedNodes, saveMarkings])

  const handleHighValue = useCallback((id: string) => {
    setHighValueNodes(prev => {
      const s = new Set(prev)
      if (s.has(id)) { s.delete(id) } else { s.add(id) }
      saveMarkings(ownedNodes, s, pinnedNodes)
      return s
    })
  }, [ownedNodes, pinnedNodes, saveMarkings])

  const handlePin = useCallback((id: string) => {
    setPinnedNodes(prev => {
      const s = new Set(prev)
      if (s.has(id)) { s.delete(id) } else { s.add(id) }
      saveMarkings(ownedNodes, highValueNodes, s)
      return s
    })
  }, [ownedNodes, highValueNodes, saveMarkings])

  const handleCollapseGroup = useCallback((groupId: string) => {
    setCollapsedGroups(prev => {
      const next = new Map(prev)
      if (next.has(groupId)) {
        next.delete(groupId)
      } else {
        const memberIds = allEdges
          .filter(e => getId(e.target) === groupId && e.edge_type === 'MEMBER_OF')
          .map(e => getId(e.source))
        next.set(groupId, memberIds)
      }
      return next
    })
  }, [allEdges])

  const handleFindPath = useCallback(async () => {
    if (!startNode || !endNode) return
    if (directedPaths && assessmentId) {
      try {
        const result = await graphApi.getPaths(assessmentId, {
          source_id: startNode.id, target_id: endNode.id, directed: true,
        })
        if (result && result.length > 0) {
          const path = result[0].path_steps
          const nodeIds = new Set<string>(
            (path ?? []).map((s: PathStep) => s.entity_id).filter(Boolean)
          )
          const edgeIds = new Set<string>(
            filteredEdges
              .filter(e => nodeIds.has(getId(e.source as string | GraphNode)) && nodeIds.has(getId(e.target as string | GraphNode)))
              .map(e => e.id)
          )
          setPathNodeIds(nodeIds)
          setPathEdgeIds(edgeIds)
          if (!nodeIds.size) toast.error('No directed path found')
          else toast.success(`Directed path: ${nodeIds.size} nodes`)
        } else {
          toast.error('No directed path found between these nodes')
        }
      } catch {
        toast.error('Path search failed')
      }
    } else {
      const { pathNodeIds, pathEdgeIds } = findPath(filteredNodes, filteredEdges, startNode.id, endNode.id)
      setPathNodeIds(pathNodeIds)
      setPathEdgeIds(pathEdgeIds)
      if (!pathNodeIds.size) toast.error('No path found between these nodes')
      else toast.success(`Path: ${pathNodeIds.size} nodes · ${pathEdgeIds.size} hops`)
    }
  }, [startNode, endNode, filteredNodes, filteredEdges, directedPaths, assessmentId])

  const handleClearPath = useCallback(() => {
    setPathNodeIds(new Set()); setPathEdgeIds(new Set())
    setStartNode(null); setEndNode(null)
  }, [])

  const handleQueryResult = useCallback((r: QueryResult) => {
    setHighlightNodeIds(r.nodeIds ?? new Set())
    setHighlightEdgeIds(r.edgeIds ?? new Set())
    setNlFilterNodeIds(r.nodeIds ?? new Set())
    setQueryLabel(r.label)
    if (r.nodeIds?.size === 0 && !r.edgeIds?.size) toast(r.label, { icon: 'ℹ' })
    else {
      if (r.nodeIds && r.edgeIds?.size) { setPathNodeIds(r.nodeIds); setPathEdgeIds(r.edgeIds) }
      toast.success(`${r.label}: ${(r.nodeIds?.size??0)+(r.edgeIds?.size??0)} results`)
    }
  }, [])

  // Command palette query runner
  const handlePaletteQuery = useCallback((id: string) => {
    const qMap: Record<string, () => QueryResult> = {
      das:        () => ({ nodeIds: new Set(filteredNodes.filter(n => n.tier===0).map(n => n.id)), label: 'Domain Admins' }),
      jewels:     () => ({ nodeIds: new Set(filteredNodes.filter(n => n.is_crown_jewel).map(n => n.id)), label: 'Crown Jewels' }),
      dcsync:     () => { const ids = new Set<string>(); filteredEdges.filter(e => e.edge_type==='DCSYNC').forEach(e => ids.add(getId(e.source))); return { nodeIds: ids, label: 'DCSync' } },
      'crit-edges': () => ({ edgeIds: new Set(filteredEdges.filter(e => (e.risk_weight??0)>=0.8).map(e => e.id)), label: 'Critical Edges' }),
      genericall: () => { const ids = new Set<string>(); filteredEdges.filter(e => e.edge_type==='GENERIC_ALL').forEach(e => ids.add(getId(e.source))); return { nodeIds: ids, label: 'GenericAll' } },
      'path-to-da': () => {
        const da = filteredNodes.filter(n => n.tier===0)
        for (const ownId of ownedNodes) {
          for (const d of da) {
            const r = findPath(filteredNodes, filteredEdges, ownId, d.id)
            if (r.pathNodeIds.size > 0) return { nodeIds: r.pathNodeIds, edgeIds: r.pathEdgeIds, label: 'Path to DA' }
          }
        }
        return { nodeIds: new Set(), label: 'No path (mark owned nodes first)' }
      },
      delegation: () => { const ids = new Set<string>(); filteredEdges.filter(e => ['ALLOWED_TO_DELEGATE','ALLOWED_TO_ACT'].includes(e.edge_type)).forEach(e => ids.add(getId(e.source))); return { nodeIds: ids, label: 'Delegation' } },
      'write-dacl': () => { const ids = new Set<string>(); filteredEdges.filter(e => ['WRITE_DACL','WRITE_OWNER'].includes(e.edge_type)).forEach(e => ids.add(getId(e.source))); return { nodeIds: ids, label: 'WriteDACL/WriteOwner' } },
    }
    const fn = qMap[id]
    if (fn) handleQueryResult(fn())
  }, [filteredNodes, filteredEdges, ownedNodes, handleQueryResult])

  const handleClearHighlight = useCallback(() => {
    setHighlightNodeIds(new Set()); setHighlightEdgeIds(new Set()); setNlFilterNodeIds(null); setQueryLabel('')
  }, [])

  const handleModeChange = useCallback((mode: GraphMode | null) => {
    setGraphMode(mode)
    if (mode) {
      const result = applyModeToState(MODE_PRESETS[mode])
      setEdgeTypeFilter(result.edgeTypeFilter)
      setColorMode(result.colorMode as ColorMode)
      setLayoutMode(result.layoutMode)
      setTier0Only(result.tier0Only)
      setToggles(result.toggles)
    }
  }, [])

  const handleSaveView = useCallback(async (name: string) => {
    if (!assessmentId) return
    const config = {
      mode: graphMode,
      edgeTypeFilter: [...edgeTypeFilter],
      colorMode,
      layoutMode,
      tier0Only,
      minRiskFilter,
      toggles: toggles as unknown as Record<string, boolean>,
    }
    await graphApi.createView(assessmentId, name, config)
    queryClient.invalidateQueries({ queryKey: ['graph-views', assessmentId] })
    toast.success(`View "${name}" saved`)
  }, [assessmentId, graphMode, edgeTypeFilter, colorMode, layoutMode, tier0Only, minRiskFilter, toggles, queryClient])

  const handleLoadView = useCallback((view: SavedGraphView) => {
    const c = view.config
    if (c.mode) handleModeChange(c.mode as GraphMode)
    setEdgeTypeFilter(new Set(c.edgeTypeFilter))
    setColorMode(c.colorMode as ColorMode)
    setLayoutMode(c.layoutMode as LayoutMode)
    setTier0Only(c.tier0Only)
    setMinRiskFilter(c.minRiskFilter)
    if (c.toggles) setToggles(prev => ({ ...prev, ...c.toggles }))
    setShowViews(false)
    toast.success(`Loaded view: ${view.name}`)
  }, [handleModeChange])

  const handleDeleteView = useCallback(async (id: string) => {
    if (!assessmentId) return
    await graphApi.deleteView(assessmentId, id)
    queryClient.invalidateQueries({ queryKey: ['graph-views', assessmentId] })
  }, [assessmentId, queryClient])

  const handleSelectDiff = useCallback(async (fromId: string, toId: string) => {
    if (!assessmentId) return
    try {
      const diff = await graphApi.getSnapshotDiff(assessmentId, fromId, toId)
      setActiveDiff({ fromId, toId })
      setDiffAddedNodeIds(new Set(diff.added_nodes.map((n: { id: string }) => n.id)))
      setDiffRemovedNodeIds(new Set(diff.removed_nodes.map((n: { id: string }) => n.id)))
      setDiffAddedEdgeIds(new Set(diff.added_edges.map((e: { id: string }) => e.id)))
      setDiffRemovedEdgeIds(new Set(diff.removed_edges.map((e: { id: string }) => e.id)))
      toast.success(`Diff: +${diff.added_nodes.length} nodes, -${diff.removed_nodes.length} nodes`)
    } catch {
      toast.error('Failed to load diff')
    }
  }, [assessmentId])

  const handleCreateSnapshot = useCallback(async () => {
    if (!assessmentId) return
    await graphApi.createSnapshot(assessmentId)
    refetchSnapshots()
    toast.success('Snapshot captured')
  }, [assessmentId, refetchSnapshots])

  const clearDiff = useCallback(() => {
    setActiveDiff(null)
    setDiffAddedNodeIds(new Set())
    setDiffRemovedNodeIds(new Set())
    setDiffAddedEdgeIds(new Set())
    setDiffRemovedEdgeIds(new Set())
  }, [])

  // Phase 5 handlers
  const handleNlQuery = useCallback(async () => {
    if (!assessmentId || !nlQueryInput.trim()) return
    const q = nlQueryInput.trim().toLowerCase()

    // Client-side patterns that rely on frontend state
    const CLIENT_PATTERNS: [string[], () => { nodeIds: Set<string>; label: string }][] = [
      [
        ['own', 'owned', 'i own', 'mine', 'marked owned', 'compromised', 'pwned'],
        () => ({ nodeIds: new Set(ownedNodes), label: `Owned/compromised nodes` }),
      ],
      [
        ['crown jewel', 'jewel', 'critical asset', 'high value'],
        () => ({ nodeIds: new Set(filteredNodes.filter(n => n.is_crown_jewel).map(n => n.id)), label: 'Crown Jewels' }),
      ],
      [
        ['user ', 'users', 'show user', 'all user', 'list user', 'user account'],
        () => ({ nodeIds: new Set(filteredNodes.filter(n => n.entity_type === 'USER').map(n => n.id)), label: 'User accounts' }),
      ],
      [
        ['group', 'groups', 'show group'],
        () => ({ nodeIds: new Set(filteredNodes.filter(n => n.entity_type === 'GROUP').map(n => n.id)), label: 'Groups' }),
      ],
    ]

    for (const [keywords, fn] of CLIENT_PATTERNS) {
      if (keywords.some(kw => q.includes(kw))) {
        const { nodeIds, label } = fn()
        setHighlightNodeIds(nodeIds)
        setHighlightEdgeIds(new Set())
        setNlFilterNodeIds(nodeIds)
        setQueryLabel(label)
        toast.success(`${label}: ${nodeIds.size} results`)
        return
      }
    }

    const tid = toast.loading('Searching…')
    try {
      const result = await graphApi.nlQuery(assessmentId, nlQueryInput)
      toast.dismiss(tid)
      const nodeIdSet = new Set(result.node_ids)
      setHighlightNodeIds(nodeIdSet)
      setHighlightEdgeIds(new Set(result.edge_ids))
      setNlFilterNodeIds(nodeIdSet)
      setQueryLabel(result.explanation)
      toast.success(`${result.explanation}: ${result.result_count} results`)
    } catch { toast.error('Query failed', { id: tid }) }
  }, [assessmentId, nlQueryInput, ownedNodes, filteredNodes])

  const handleNarratePath = useCallback(async () => {
    if (!assessmentId || !pathNodeIds.size) { toast('Find a path first', { icon: 'ℹ' }); return }
    const tid = toast.loading('Generating narration…')
    try {
      const steps = [...pathNodeIds].map(id => {
        const node = filteredNodes.find(n => n.id === id)
        return { entity_id: id, entity_label: node?.label ?? id, entity_type: node?.entity_type ?? 'UNKNOWN', edge_type: '', explanation: '' }
      })
      const n = await graphApi.narratePath(assessmentId, steps, startNode?.label ?? '', endNode?.label ?? '')
      setNarration(n)
      toast.dismiss(tid)
    } catch { toast.error('Narration failed', { id: tid }) }
  }, [assessmentId, pathNodeIds, filteredNodes, startNode, endNode])

  const handleExportPlaybook = useCallback(async (format: 'markdown' | 'navigator_json') => {
    if (!assessmentId || !narration) return
    const result = await graphApi.exportPlaybook(assessmentId, narration.steps.map(s => ({ edge_type: s.technique_name })), narration.source, narration.target, format)
    const content = format === 'markdown' ? (typeof result.content === 'string' ? result.content : JSON.stringify(result.content, null, 2)) : JSON.stringify(result.content, null, 2)
    const blob = new Blob([content], { type: format === 'markdown' ? 'text/markdown' : 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url; a.download = `playbook.${format === 'markdown' ? 'md' : 'json'}`;
    a.click(); URL.revokeObjectURL(url)
    toast.success('Playbook downloaded')
  }, [assessmentId, narration])

  const handleMonteCarlo = useCallback(async () => {
    if (!assessmentId || !pathNodeIds.size) return
    const tid = toast.loading('Running simulation…')
    try {
      const steps = filteredEdges
        .filter(e => pathEdgeIds.has(e.id))
        .map(e => ({ edge_type: e.edge_type }))
      const result = await graphApi.monteCarlo(assessmentId, steps, 1000)
      setMonteCarlo(result)
      toast.dismiss(tid)
      toast.success(`P(success): ${result.success_pct_label}`)
    } catch { toast.error('Simulation failed', { id: tid }) }
  }, [assessmentId, pathNodeIds, pathEdgeIds, filteredEdges])

  const handleLoadAnomalies = useCallback(async () => {
    if (!assessmentId) return
    const result = await graphApi.getAnomalies(assessmentId)
    setAnomalies(result.anomalies)
    setShowAnomalyFeed(true)
    if (result.count === 0) toast('No anomalies detected', { icon: 'ℹ' })
  }, [assessmentId])

  const handleEdgeHover = useCallback((edge: GraphEdge | null, x: number, y: number) => {
    setHoveredEdge(edge ? { edge, x, y } : null)
  }, [])

  const handleEdgeClick = useCallback((edge: GraphEdge) => {
    const s = getId(edge.source as string | GraphNode), t = getId(edge.target as string | GraphNode)
    const parallelEdges = filteredEdges.filter(e => {
      const es = getId(e.source as string | GraphNode), et = getId(e.target as string | GraphNode)
      return (es === s && et === t) || (es === t && et === s)
    })
    if (parallelEdges.length >= 3) {
      setSelectedBundle({ sourceId: s, targetId: t, edges: parallelEdges })
      setSelectedEdge(null)
    } else {
      setSelectedEdge(e => e?.id === edge.id ? null : edge)
    }
    setHoveredEdge(null)
  }, [filteredEdges])

  const cycleColorMode = useCallback(() => {
    const modes: ColorMode[] = ['default', 'risk', 'degree', 'tier']
    setColorMode(prev => modes[(modes.indexOf(prev)+1) % modes.length])
  }, [])

  const toggleFullscreen = useCallback(() => {
    if (isFullscreen) {
      setIsFullscreen(false)
      if (document.fullscreenElement) void document.exitFullscreen().catch(() => {})
      return
    }

    setIsFullscreen(true)
    void shellRef.current?.requestFullscreen?.().catch(() => {})
  }, [isFullscreen])

  const handleFileImport = useCallback(async (file: File, targetId?: string) => {
    if (isImporting || importJobActive) return
    setIsImporting(true)
    const tid = toast.loading(`Uploading ${file.name}…`)
    try {
      const r = targetId
        ? await importApi.bloodhound(targetId, file)
        : await importApi.bloodhoundAuto(file)
      toast.dismiss(tid)
      startImport({ jobId: r.job_id, streamToken: r.stream_token, filename: file.name })
    } catch (err) {
      toast.error(getErrDetail(err, 'Upload failed'), { id: tid })
    } finally {
      setIsImporting(false)
    }
  }, [isImporting, importJobActive, startImport])

  const handleSimRemediation = useCallback(async (id: string) => {
    if (!assessmentId) return
    const tid = toast.loading('Simulating remediation…')
    try {
      const nodeEdges = focusedEdges.filter(e => {
        const s = getId(e.source), t = getId(e.target)
        return (s===id||t===id) && (e.risk_weight??0)>=0.5
      })
      const removals = nodeEdges.slice(0, 20).map(e => ({ source: getId(e.source), target: getId(e.target) }))
      if (!removals.length) { toast.dismiss(tid); toast('No high-risk edges', { icon: 'ℹ' }); return }
      const r = await graphApi.simulateRemoval(assessmentId, removals)
      toast.dismiss(tid)
      setSimulationData({ reduction: Math.round(r?.reduction_pct ?? r?.risk_reduction_pct ?? r?.reduction ?? 0) })
    } catch (err) { toast.error(getErrDetail(err, 'Simulation failed'), { id: tid }) }
  }, [assessmentId, focusedEdges])

  const handleSelect = useCallback((node: GraphNode | null) => {
    setSelectedNode(node)
    if (node) {
      setAriaLive(`Selected: ${node.label}, type ${node.entity_type}${node.tier !== undefined ? `, Tier ${node.tier}` : ''}`)
      setFocusNodeId(null)
    } else {
      setAriaLive('Selection cleared')
    }
  }, [])

  // Keyboard shortcuts
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if (e.target instanceof HTMLInputElement || e.target instanceof HTMLTextAreaElement) return
      if ((e.metaKey || e.ctrlKey) && e.key === 'k') { e.preventDefault(); setShowPalette(p => !p); return }
      if (e.key === 'f' || e.key === 'F') toggleFullscreen()
      if (e.key === 'l' || e.key === 'L') setShowEdgeLabels(p => !p)
      if (e.key === 'r' || e.key === 'R') graphRef.current?.restart()
      if (e.key === 'a' || e.key === 'A') setShowAnalytics(p => !p)
      if (e.key === 'q' || e.key === 'Q') setShowQueries(p => !p)
      if (e.key === 'c' || e.key === 'C') cycleColorMode()
      if (e.key === 'p' || e.key === 'P') setShowParticles(p => !p)
      if (e.key === '+' || e.key === '=') graphRef.current?.zoomIn()
      if (e.key === '-') graphRef.current?.zoomOut()
      if (e.key === '0') graphRef.current?.fit()
      if (e.key === 'ArrowRight') graphRef.current?.navigateToConnected('next')
      if (e.key === 'ArrowLeft') graphRef.current?.navigateToConnected('prev')
      if (e.key === 'Escape') {
        if (document.fullscreenElement) void document.exitFullscreen().catch(() => {})
        setIsFullscreen(false); setContextMenu(null); setShowShortcuts(false)
        setSelectedEdge(null); setFocusNodeId(null); handleClearHighlight()
        setShowPalette(false)
      }
    }
    window.addEventListener('keydown', handler)
    return () => window.removeEventListener('keydown', handler)
  }, [cycleColorMode, handleClearHighlight, toggleFullscreen])

  useEffect(() => {
    const handleFullscreenChange = () => {
      if (!document.fullscreenElement) setIsFullscreen(false)
    }

    document.addEventListener('fullscreenchange', handleFullscreenChange)
    return () => document.removeEventListener('fullscreenchange', handleFullscreenChange)
  }, [])

  // Re-fit to the larger canvas whenever fullscreen state changes
  useEffect(() => {
    const t = setTimeout(() => graphRef.current?.fit(), 120)
    return () => clearTimeout(t)
  }, [isFullscreen])

  // Heat map: load choke points when toggle is on
  useEffect(() => {
    if (!toggles.showHeatMap || !assessmentId) return
    graphApi.getChokePoints?.(assessmentId).then((data: { choke_points?: { node_id: string; attack_paths_through?: number }[] }) => {
      if (data?.choke_points) {
        const maxCount = Math.max(...data.choke_points.map(c => c.attack_paths_through || 0), 1)
        const map = new Map<string, number>()
        data.choke_points.forEach(c => {
          map.set(c.node_id, (c.attack_paths_through || 0) / maxCount)
        })
        setHeatMap(map)
      }
    }).catch(() => {})
  }, [toggles.showHeatMap, assessmentId])

  // ── Empty state ─────────────────────────────────────────────────
  if (!assessmentId) {
    return (
      <div className="flex min-h-[70vh] items-center justify-center p-10 text-center">
        <motion.div initial={{ opacity: 0, y: 16 }} animate={{ opacity: 1, y: 0 }}>
          <Sparkles className="mx-auto h-16 w-16 text-cyan-100 drop-shadow-[0_0_18px_rgba(34,211,238,0.8)]" />
          <h2 className="mt-5 text-3xl font-black tracking-wide text-white md:text-4xl"
            style={{ textShadow: '3px 0 0 rgba(255,0,128,0.72),-3px 0 0 rgba(0,255,255,0.72),0 0 26px rgba(255,255,255,0.55)' }}>
            No assessment selected
          </h2>
          <p className="mt-3 text-lg font-semibold text-zinc-100 md:text-xl"
            style={{ textShadow: '2px 0 0 rgba(255,0,128,0.45),-2px 0 0 rgba(0,255,255,0.45)' }}>
            Add an assessment, then import your SharpHound / BloodHound data.
          </p>
          <div className="mt-8 flex justify-center">
            <button onClick={() => router.push('/assessments')}
              className="inline-flex items-center gap-2 rounded-xl border border-cyan-300/45 bg-cyan-400/15 px-6 py-3 text-lg font-black text-cyan-100 shadow-[0_0_28px_rgba(34,211,238,0.24)] transition hover:border-fuchsia-300/50 hover:bg-fuchsia-400/15 hover:text-fuchsia-100"
              style={{ textShadow: '1px 0 0 rgba(255,0,128,0.6),-1px 0 0 rgba(0,255,255,0.6)' }}>
              <Target className="h-5 w-5" /> Add an Assessment
            </button>
          </div>
        </motion.div>
      </div>
    )
  }

  return (
    <div className={cn(
      isFullscreen ? 'fixed inset-0 z-50 flex flex-col bg-black overflow-hidden' : 'min-h-full p-8',
    )} ref={shellRef}>
      {/* ARIA live region */}
      <div role="status" aria-live="polite" aria-atomic="true" className="sr-only">
        {ariaLive}
      </div>

      {/* Context menu */}
      <AnimatePresence>
        {contextMenu && (
          <ContextMenu ctx={contextMenu} onClose={() => setContextMenu(null)}
            onOwned={handleOwned} onHighValue={handleHighValue}
            onSetStart={n => { setStartNode(n); setShowPathFinder(true) }}
            onSetEnd={n => { setEndNode(n); setShowPathFinder(true) }}
            onFocus={n => setFocusNodeId(n.id)}
            onCollapseGroup={handleCollapseGroup}
            ownedNodes={ownedNodes} highValueNodes={highValueNodes} />
        )}
      </AnimatePresence>

      {/* Shortcuts modal */}
      <AnimatePresence>
        {showShortcuts && <ShortcutsModal onClose={() => setShowShortcuts(false)} />}
      </AnimatePresence>

      {/* Command palette */}
      <AnimatePresence>
        {showPalette && (
          <CommandPalette
            nodes={filteredNodes}
            onClose={() => setShowPalette(false)}
            onFocusNode={id => { graphRef.current?.focusNode(id) }}
            onRunQuery={handlePaletteQuery}
          />
        )}
      </AnimatePresence>

      {/* ── Header ───────────────────────────────────────────────── */}
      {!isFullscreen && (
        <motion.div initial={{ opacity: 0, y: 14 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.4 }}
          className="mb-6 rounded-[28px] border border-white/10 bg-black p-6">
          <div className="flex flex-col gap-4 xl:flex-row xl:items-end xl:justify-between">
            <div>
              <div className="inline-flex items-center gap-2 rounded-full border border-cyan-400/20 bg-cyan-400/10 px-3 py-1 text-xs font-medium text-cyan-200">
                <Workflow className="h-3.5 w-3.5" /> Relationship Graph
              </div>
              <h1 className="mt-3 text-3xl font-semibold text-white">Identity Graph</h1>
              <p className="mt-1 text-sm text-zinc-400">
                BloodHound-grade AD privilege graph · right-click nodes · drag · zoom · box-select
              </p>
            </div>
            <div className="flex flex-wrap gap-2">
              {/* Command palette hint */}
              <button onClick={() => setShowPalette(true)}
                className="flex items-center gap-2 rounded-full border border-white/10 bg-black px-4 py-2 text-sm text-zinc-400 transition hover:bg-white/[0.06] hover:text-zinc-200">
                <Command className="h-3.5 w-3.5 text-zinc-500" />
                <span>Search</span>
                <kbd className="ml-1 rounded border border-white/15 bg-white/5 px-1.5 py-0.5 text-[10px] text-zinc-500">⌘K</kbd>
              </button>
              <label className={cn('cursor-pointer rounded-full border border-white/10 bg-black px-4 py-2 text-sm text-zinc-300 transition hover:bg-white/[0.07] flex items-center gap-2', isImporting && 'pointer-events-none opacity-50')}>
                {isImporting ? <Loader2 className="h-4 w-4 animate-spin text-cyan-400" /> : <Upload className="h-4 w-4 text-cyan-400" />}
                Import
                <input type="file" accept=".zip,.json" className="hidden" disabled={isImporting}
                  onChange={e => { const f = e.target.files?.[0]; if (f && assessmentId) handleFileImport(f, assessmentId); e.target.value = '' }} />
              </label>
              <button onClick={() => refetch()}
                className="rounded-full border border-white/10 bg-black px-4 py-2 text-sm text-zinc-300 transition hover:bg-white/[0.07] flex items-center gap-1.5">
                <RefreshCw className="h-3.5 w-3.5" /> Refresh
              </button>
            </div>
          </div>
        </motion.div>
      )}

      {/* ── Stat cards ───────────────────────────────────────────── */}
      {!isFullscreen && (
        <div className="mb-5 grid gap-4 xl:grid-cols-4">
          {[
            { label: 'Nodes',  value: fmtNumber(focusedNodes.length), sub: 'Visible entities',  color: 'var(--accent1)' },
            { label: 'Edges',  value: fmtNumber(focusedEdges.length), sub: 'Relationship edges', color: '#a78bfa' },
            { label: 'Tier-0', value: fmtNumber(tier0Count),           sub: 'Critical anchors',   color: '#ef4444' },
            { label: 'Owned',  value: fmtNumber(ownedNodes.size),      sub: 'Marked owned',       color: '#71717a' },
          ].map((card, i) => (
            <motion.div key={card.label}
              initial={{ opacity: 0, y: 16 }} animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.38, delay: 0.06*i }}
              className="rounded-2xl border border-white/10 bg-black p-5">
              <div className="text-xs uppercase tracking-[0.22em] text-zinc-500">{card.label}</div>
              <div className="mt-3 text-3xl font-semibold" style={{ color: card.color }}>{card.value}</div>
              <div className="mt-1 text-sm text-zinc-400">{card.sub}</div>
            </motion.div>
          ))}
        </div>
      )}

      {/* Auto-cap banner */}
      {isAutoCapped && (
        <div className="mb-3 flex items-center gap-2 rounded-xl border border-amber-500/22 bg-amber-500/8 px-3 py-2">
          <span className="inline-flex items-center gap-1 rounded-full bg-amber-500/15 border border-amber-500/25 px-2 py-0.5 text-[9px] text-amber-300 font-semibold">
            ⚡ {focusedEdges.length}/{allEdges.length} edges shown — use risk filter to see more
          </span>
        </div>
      )}

      {/* ── Toolbar ─────────────────────────────────────────────── */}
      <GraphToolbar
        searchInput={searchInput}
        onSearchChange={setSearchInput}
        tier0Only={tier0Only}
        onTier0Toggle={() => setTier0Only(p => !p)}
        edgeTypeFilter={edgeTypeFilter}
        allEdgeTypes={allEdgeTypes}
        onEdgeTypeFilterChange={setEdgeTypeFilter}
        layoutMode={layoutMode}
        onLayoutChange={setLayoutMode}
        colorMode={colorMode}
        onColorModeChange={setColorMode}
        showEdgeLabels={showEdgeLabels}
        onEdgeLabelsToggle={() => setShowEdgeLabels(p => !p)}
        sizeByDegree={sizeByDegree}
        onSizeByDegreeToggle={() => setSizeByDegree(p => !p)}
        showParticles={showParticles}
        onParticlesToggle={() => setShowParticles(p => !p)}
        toggles={toggles}
        onToggleChange={key => setToggles(prev => ({ ...prev, [key]: !prev[key] }))}
        graphMode={graphMode}
        onModeChange={handleModeChange}
        minRiskFilter={minRiskFilter}
        onMinRiskChange={setMinRiskFilter}
        isFullscreen={isFullscreen}
        onToggleFullscreen={toggleFullscreen}
        showViews={showViews}
        onViewsToggle={() => setShowViews(p => !p)}
        showTimeline={showTimeline}
        onTimelineToggle={() => setShowTimeline(p => !p)}
        showNlBar={showNlBar}
        onNlBarToggle={() => setShowNlBar(p => !p)}
        showAnomalyFeed={showAnomalyFeed}
        onAnomalyFeedToggle={handleLoadAnomalies}
        streamActive={streamActive}
        onStreamToggle={() => setStreamActive(p => !p)}
      />

      {/* NL query bar */}
      {showNlBar && (
        <div className="mb-3 flex gap-2">
          <input
            value={nlQueryInput}
            onChange={e => setNlQueryInput(e.target.value)}
            onKeyDown={e => { if (e.key === 'Enter') handleNlQuery() }}
            placeholder="Ask in plain English: 'show kerberoastable accounts' or 'find delegation chains'…"
            className="flex-1 rounded-xl border border-purple-400/25 bg-black/80 px-4 py-2.5 text-sm text-white outline-none placeholder:text-zinc-600 focus:border-purple-400/40"
          />
          <button onClick={handleNlQuery}
            className="rounded-xl border border-purple-500/35 bg-purple-500/15 px-4 py-2.5 text-sm text-purple-300 hover:bg-purple-500/25 transition">
            Query
          </button>
          <button onClick={() => setShowNlBar(false)}
            className="rounded-xl border border-white/10 bg-black/60 px-3 py-2.5 text-zinc-400 hover:text-white transition">
            <X className="h-4 w-4" />
          </button>
        </div>
      )}

      {/* Path finder panel */}
      {!isFullscreen && showPathFinder && (
        <div className="mb-4">
          <PathFinderPanel
            nodes={filteredNodes} startNode={startNode} endNode={endNode}
            pathNodeIds={pathNodeIds} pathEdgeIds={pathEdgeIds}
            onSetStart={setStartNode} onSetEnd={setEndNode}
            onFind={handleFindPath} onClear={handleClearPath}
            directedPaths={directedPaths} onDirectedToggle={() => setDirectedPaths(p => !p)}
            onExplain={handleNarratePath} />
        </div>
      )}

      {/* ── Graph canvas area ────────────────────────────────────── */}
      {isLoading && (
        <div className="flex min-h-[380px] items-center justify-center rounded-[24px] border border-white/10 text-zinc-400">
          <div className="flex items-center gap-3"><Loader2 className="h-5 w-5 animate-spin" /> Loading graph data…</div>
        </div>
      )}
      {isError && !isLoading && (
        <div className="rounded-[24px] border border-red-400/20 bg-red-500/8 p-8 text-center text-zinc-200" role="alert">
          Graph request failed. Verify API connection and assessment data.
        </div>
      )}
      {!isLoading && !isError && filteredNodes.length === 0 && (
        <div className="rounded-[24px] border border-white/10 bg-black p-8 text-center text-zinc-300">
          No graph data matches the current filters.
        </div>
      )}

      {!isLoading && !isError && filteredNodes.length > 0 && (
        <div className={cn(
          'relative rounded-[24px] border border-white/10 bg-black overflow-hidden',
          isFullscreen ? 'flex-1 mx-4 mb-4' : 'mb-5',
        )}>
          {/* Sim progress bar */}
          <AnimatePresence>
            {simAlpha > 0.05 && <SimProgressBar alpha={simAlpha} />}
          </AnimatePresence>

          <GraphCanvas
            ref={graphRef}
            nodes={focusedNodes} edges={focusedEdges}
            layoutMode={layoutMode} graphHeight={graphHeight}
            renderProps={renderProps}
            onSelect={handleSelect}
            onContextMenu={setContextMenu}
            onMultiSelect={ids => toast(`Selected ${ids.size} nodes`, { icon: '◻', duration: 1400 })}
            onEdgeHover={handleEdgeHover}
            onEdgeClick={handleEdgeClick}
            onPinToggle={() => {}}
            onSimProgress={setSimAlpha}
            showFps={false}
          />

          {/* Queries panel */}
          <AnimatePresence>
            {showQueries && (
              <div className="absolute top-4 left-4 z-30">
                <PrebuiltQueriesPanel
                  nodes={focusedNodes} edges={focusedEdges} ownedNodes={ownedNodes}
                  onResult={r => { handleQueryResult(r); setShowQueries(false) }}
                  onClose={() => setShowQueries(false)} />
              </div>
            )}
          </AnimatePresence>

          {/* Saved views panel */}
          <AnimatePresence>
            {showViews && (
              <div className="absolute top-4 left-4 z-30">
                <SavedViewsPanel
                  views={savedViews}
                  onLoad={handleLoadView}
                  onSave={handleSaveView}
                  onDelete={handleDeleteView}
                  onClose={() => setShowViews(false)}
                />
              </div>
            )}
          </AnimatePresence>

          {/* Analytics panel */}
          <AnimatePresence>
            {showAnalytics && (
              <div className="absolute top-4 right-4 z-30">
                <AnalyticsPanel
                  nodes={focusedNodes} edges={focusedEdges} degreeMap={degreeMap}
                  ownedNodes={ownedNodes} highValueNodes={highValueNodes}
                  onClose={() => setShowAnalytics(false)} />
              </div>
            )}
          </AnimatePresence>

          {/* Default legend */}
          {colorMode === 'default' && !showQueries && (
            <div className="absolute left-4 top-4 flex flex-wrap gap-1.5 max-w-[260px] pointer-events-none">
              {LEGEND.map(item => (
                <div key={item.label} className="flex items-center gap-1.5 rounded-full border border-white/8 bg-black/70 px-2.5 py-1 text-[10px] text-zinc-300 backdrop-blur">
                  <span className="h-2 w-2 rounded-full flex-shrink-0" style={{ backgroundColor: item.color }} />
                  {item.label}
                </div>
              ))}
            </div>
          )}

          {/* Color mode legend */}
          <ColorModeLegend mode={colorMode} />

          {/* Active query badge */}
          <AnimatePresence>
            {queryLabel && (
              <motion.div initial={{ opacity: 0, y: -8 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }}
                className="absolute top-4 left-1/2 -translate-x-1/2 flex items-center gap-2 rounded-full border border-amber-500/30 bg-amber-500/10 px-3 py-1.5 shadow-lg backdrop-blur">
                <span className="h-1.5 w-1.5 rounded-full bg-amber-400 animate-pulse" />
                <span className="text-[10px] font-semibold text-amber-300">{queryLabel}</span>
                <button onClick={handleClearHighlight} aria-label="Clear query highlight"
                  className="text-amber-500 hover:text-white transition ml-1">
                  <X className="h-3 w-3" />
                </button>
              </motion.div>
            )}
          </AnimatePresence>

          {/* Focus mode indicator */}
          <AnimatePresence>
            {focusNodeId && (
              <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }}
                className="absolute bottom-16 left-1/2 -translate-x-1/2 flex items-center gap-2 rounded-full border border-purple-500/30 bg-purple-500/10 px-3 py-1.5 backdrop-blur">
                <span className="text-[10px] text-purple-300 font-semibold">
                  Focus · {focusedNodes.length} nodes · {focusHops}-hop
                </span>
                <button aria-label="Increase focus hops" className="text-xs text-purple-400 hover:text-white"
                  onClick={() => setFocusHops(h => Math.min(h+1, 5))}>+</button>
                <button aria-label="Decrease focus hops" className="text-xs text-purple-400 hover:text-white"
                  onClick={() => setFocusHops(h => Math.max(h-1, 1))}>−</button>
                <button onClick={() => setFocusNodeId(null)} aria-label="Exit focus mode"
                  className="text-purple-500 hover:text-white"><X className="h-3 w-3" /></button>
              </motion.div>
            )}
          </AnimatePresence>

          {/* Box select mode indicator */}
          {/* (box select activated by shift+drag) */}

          {/* Remediation sim badge */}
          <AnimatePresence>
            {simulationData && (
              <motion.div initial={{ opacity: 0, y: -20 }} animate={{ opacity: 1, y: 0 }}
                className="absolute top-4 right-4 z-30 rounded-2xl border border-indigo-500/30 bg-indigo-500/10 px-5 py-3 shadow-2xl flex items-center gap-4 backdrop-blur">
                <Workflow className="h-5 w-5 text-indigo-400 flex-shrink-0" />
                <div>
                  <div className="text-[9px] uppercase tracking-widest text-indigo-300 font-bold">Remediation Sim</div>
                  <div className="text-sm text-white font-medium">
                    Risk Reduction: <span className="text-green-400 font-bold">+{simulationData.reduction}%</span>
                  </div>
                </div>
                <button onClick={() => setSimulationData(null)} aria-label="Close remediation result"
                  className="rounded-lg bg-white/10 p-1.5 text-white hover:bg-white/20 transition ml-2">
                  <X className="h-3.5 w-3.5" />
                </button>
              </motion.div>
            )}
          </AnimatePresence>

          {/* Fullscreen path finder */}
          {isFullscreen && showPathFinder && (
            <div className="absolute top-4 right-4 z-30 w-64">
              <PathFinderPanel
                nodes={focusedNodes} startNode={startNode} endNode={endNode}
                pathNodeIds={pathNodeIds} pathEdgeIds={pathEdgeIds}
                onSetStart={setStartNode} onSetEnd={setEndNode}
                onFind={handleFindPath} onClear={handleClearPath}
                directedPaths={directedPaths} onDirectedToggle={() => setDirectedPaths(p => !p)}
                onExplain={handleNarratePath} />
            </div>
          )}

          {/* Edge hover tooltip */}
          <AnimatePresence>
            {hoveredEdge && !selectedEdge && (
              <EdgeHoverTip edge={hoveredEdge.edge} x={hoveredEdge.x} y={hoveredEdge.y} nodes={focusedNodes} showProvenance={toggles.showProvenance} />
            )}
          </AnimatePresence>

          {/* Edge details panel */}
          <AnimatePresence>
            {selectedEdge && (
              <EdgeDetailsPanel edge={selectedEdge} nodes={focusedNodes} onClose={() => setSelectedEdge(null)} />
            )}
          </AnimatePresence>

          {/* Edge bundle panel */}
          <AnimatePresence>
            {selectedBundle && (
              <EdgeBundlePanel
                bundle={selectedBundle}
                nodes={filteredNodes}
                onClose={() => setSelectedBundle(null)}
              />
            )}
          </AnimatePresence>

          {/* Narration panel */}
          <AnimatePresence>
            {narration && (
              <NarrationPanel
                narration={narration}
                onExportPlaybook={handleExportPlaybook}
                onMonteCarlo={handleMonteCarlo}
                onClose={() => { setNarration(null); setMonteCarlo(null) }}
              />
            )}
          </AnimatePresence>

          {/* Anomaly feed panel */}
          <AnimatePresence>
            {showAnomalyFeed && (
              <div className="absolute top-4 left-4 z-30">
                <AnomalyFeedPanel
                  anomalies={anomalies}
                  onFocusNode={id => { graphRef.current?.focusNode(id); setShowAnomalyFeed(false) }}
                  onClose={() => setShowAnomalyFeed(false)}
                />
              </div>
            )}
          </AnimatePresence>

          {/* Monte Carlo result */}
          {monteCarlo && (
            <div className="absolute bottom-20 left-1/2 -translate-x-1/2 z-50 rounded-2xl border border-purple-500/35 bg-black/95 px-6 py-3 shadow-2xl backdrop-blur">
              <span className="text-[11px] text-purple-300 font-bold">P(success): {monteCarlo.success_pct_label}</span>
              <span className="text-[9px] text-zinc-500 ml-2">({monteCarlo.iterations} iterations)</span>
              <button onClick={() => setMonteCarlo(null)} className="ml-3 text-zinc-600 hover:text-white"><X className="h-3 w-3" /></button>
            </div>
          )}

          {/* Snapshot timeline panel */}
          <AnimatePresence>
            {showTimeline && (
              <SnapshotTimelinePanel
                snapshots={snapshotsData?.snapshots ?? []}
                activeDiff={activeDiff}
                onSelectDiff={handleSelectDiff}
                onCreateSnapshot={handleCreateSnapshot}
                onClose={() => { setShowTimeline(false); clearDiff() }}
              />
            )}
          </AnimatePresence>

          {/* Node info panel */}
          <AnimatePresence>
            {selectedNode && (
              <NodeInfoPanel
                node={selectedNode} onClose={() => setSelectedNode(null)}
                onSimRemediation={handleSimRemediation}
                ownedNodes={ownedNodes} highValueNodes={highValueNodes}
                edges={focusedEdges}
                allNodes={focusedNodes}
                onOwned={handleOwned} onHighValue={handleHighValue}
                onSetStart={n => { setStartNode(n); setShowPathFinder(true) }}
                onSetEnd={n => { setEndNode(n); setShowPathFinder(true) }}
                onFocus={n => setFocusNodeId(n.id)}
                onPin={handlePin}
                pinnedNodes={pinnedNodes}
                assessmentId={assessmentId ?? null}
              />
            )}
          </AnimatePresence>
        </div>
      )}

      {/* ── Bottom panels (non-fullscreen) ───────────────────────── */}
      {!isFullscreen && !isLoading && !isError && filteredNodes.length > 0 && (
        <div className="grid gap-5 xl:grid-cols-[minmax(0,1.3fr)_minmax(320px,400px)]">
          {/* Entity grid */}
          <div className="rounded-[22px] border border-white/10 bg-black p-5">
            <div className="mb-4 text-xs uppercase tracking-[0.2em] text-zinc-500 flex items-center gap-2">
              <Layers className="h-3.5 w-3.5" /> Entities ({fmtNumber(focusedNodes.length)})
            </div>
            <div className="grid max-h-64 gap-2 overflow-y-auto md:grid-cols-2 xl:grid-cols-3 pr-1">
              {focusedNodes.map(node => {
                const color = nodeBaseColor(node)
                return (
                  <button key={node.id}
                    onClick={() => {
                      setSelectedNode(p => p?.id === node.id ? null : node)
                      graphRef.current?.focusNode(node.id)
                    }}
                    aria-pressed={selectedNode?.id === node.id}
                    className={cn('rounded-xl border p-2.5 text-left transition',
                      selectedNode?.id === node.id
                        ? 'border-cyan-400/30 bg-cyan-400/10'
                        : 'border-white/8 bg-black hover:border-white/15 hover:bg-black',
                    )}>
                    <div className="flex items-center gap-2">
                      <span className="inline-flex h-5 w-5 items-center justify-center rounded text-[9px] font-bold font-mono flex-shrink-0"
                        style={{ backgroundColor: color+'22', color }}>
                        {getLetter(node.entity_type)}
                      </span>
                      <span className="truncate text-[11px] font-medium text-white">{node.label}</span>
                    </div>
                    <div className="mt-1 text-[9px] uppercase tracking-widest text-zinc-500">
                      {node.entity_type}
                      {node.tier !== undefined && ` · T${node.tier}`}
                      {node.is_crown_jewel && ' · ★'}
                      {ownedNodes.has(node.id) && ' · ☠'}
                    </div>
                  </button>
                )
              })}
            </div>
          </div>

          {/* Edge list */}
          <div className="rounded-[22px] border border-white/10 bg-black p-5">
            <div className="mb-4 text-xs uppercase tracking-[0.2em] text-zinc-500">
              Relationships ({fmtNumber(focusedEdges.length)})
            </div>
            <div className="max-h-64 space-y-1.5 overflow-y-auto pr-1">
              {focusedEdges.slice(0, 80).map(edge => {
                const src = focusedNodes.find(n => n.id === getId(edge.source))
                const tgt = focusedNodes.find(n => n.id === getId(edge.target))
                const w = edge.risk_weight ?? 0
                const col = edgeRiskColor(w)
                return (
                  <div key={edge.id}
                    className="grid items-center gap-2 rounded-xl border border-white/8 bg-black p-2"
                    style={{ gridTemplateColumns: '1fr auto 1fr' }}>
                    <span className="truncate text-[10px] text-zinc-300">{src?.label ?? getId(edge.source)}</span>
                    <span className="rounded-full border px-1.5 py-0.5 text-center text-[8px] uppercase tracking-wider whitespace-nowrap"
                      style={{ borderColor: col+'60', color: col, backgroundColor: col+'18' }}>
                      {edge.edge_type}
                    </span>
                    <span className="truncate text-right text-[10px] text-zinc-300">{tgt?.label ?? getId(edge.target)}</span>
                  </div>
                )
              })}
              {focusedEdges.length > 80 && (
                <div className="py-2 text-center text-[10px] text-zinc-500">+{focusedEdges.length-80} more edges</div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
