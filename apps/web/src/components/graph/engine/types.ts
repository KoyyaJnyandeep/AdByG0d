import type * as d3 from 'd3'
import type { GraphEdge, GraphNode } from '@/lib/types'

export type LayoutMode = 'force' | 'hierarchical' | 'radial' | 'attack'
export type SelectMode = 'pointer' | 'box'
export type ColorMode = 'default' | 'risk' | 'degree' | 'tier'

export type SimNode = GraphNode & d3.SimulationNodeDatum
export type SimLink = GraphEdge & d3.SimulationLinkDatum<SimNode>

export interface CtxMenu { x: number; y: number; node: GraphNode }
export interface EdgeHoverState { edge: GraphEdge; x: number; y: number }

export interface RenderProps {
  showEdgeLabels: boolean
  ownedNodes: Set<string>
  highValueNodes: Set<string>
  pathNodeIds: Set<string>
  pathEdgeIds: Set<string>
  colorMode: ColorMode
  sizeByDegree: boolean
  degreeMap: Map<string, number>
  maxDegree: number
  riskMap: Map<string, number>
  highlightNodeIds: Set<string>
  highlightEdgeIds: Set<string>
  startNodeId: string | null
  endNodeId: string | null
  selectedId: string | null
  connectedIds: Set<string>
  pinnedIds: Set<string>
  isSimulating: boolean
  showParticles: boolean
  graphHeight: number
  bundleEdges?: boolean
  showProvenance?: boolean
  heatMap?: Map<string, number>
  containerBoxes?: ContainerBox[]
  directedMode?: boolean
  diffAddedNodeIds?: Set<string>
  diffRemovedNodeIds?: Set<string>
  diffAddedEdgeIds?: Set<string>
  diffRemovedEdgeIds?: Set<string>
}

export interface ForceGraphHandle {
  zoomIn: () => void
  zoomOut: () => void
  fit: () => void
  restart: () => void
  exportPNG: () => void
  exportSVG: () => void
  focusNode: (id: string) => void
  navigateToConnected: (direction: 'next' | 'prev') => void
}

export type GraphMode =
  | 'ExposureOverview'
  | 'Tier0Path'
  | 'ADCSView'
  | 'DelegationView'
  | 'LateralMovement'
  | 'GroupMembership'
  | 'RemediationSim'

export interface GraphToggles {
  attackEdgesOnly: boolean
  hideMembership: boolean
  hideLowRisk: boolean
  collapseGroups: boolean
  tier0PathsOnly: boolean
  neighborhoodOnly: boolean
  showContainers: boolean
  bundleEdges: boolean
  showHeatMap: boolean
  showProvenance: boolean
}

export const DEFAULT_TOGGLES: GraphToggles = {
  attackEdgesOnly: false,
  hideMembership: false,
  hideLowRisk: false,
  collapseGroups: false,
  tier0PathsOnly: false,
  neighborhoodOnly: false,
  showContainers: false,
  bundleEdges: false,
  showHeatMap: false,
  showProvenance: false,
}

export interface ContainerBox {
  nodeId: string
  label: string
  color: string
  minX: number
  minY: number
  maxX: number
  maxY: number
}

export interface EdgeBundle {
  sourceId: string
  targetId: string
  edges: import('@/lib/types').GraphEdge[]
  maxRisk: number
}
