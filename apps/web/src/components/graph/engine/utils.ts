import type { ColorMode, SimNode } from './types'
import type { GraphEdge, GraphNode } from '@/lib/types'
import { entityTypeColor } from '@/lib/utils'

export const getId = (x: string | GraphNode | SimNode): string =>
  typeof x === 'string' ? x : (x as GraphNode).id

export function nodeRadius(d: GraphNode): number {
  if (d.tier === 0) return 20
  if (d.is_crown_jewel) return 16
  if (d.entity_type === 'DC' || d.entity_type === 'DOMAIN') return 14
  if (d.is_admin_count) return 11
  return 9
}

export function nodeBaseColor(d: GraphNode): string {
  if (d.tier === 0) return '#ef4444'
  if (d.is_crown_jewel) return '#f97316'
  return entityTypeColor(d.entity_type)
}

export function getNodeColorForMode(
  d: GraphNode, mode: ColorMode,
  degreeMap: Map<string, number>, maxDegree: number,
  riskMap: Map<string, number>,
): string {
  switch (mode) {
    case 'risk': {
      const r = riskMap.get(d.id) ?? 0
      if (r >= 0.8) return '#ef4444'
      if (r >= 0.6) return '#f97316'
      if (r >= 0.4) return '#eab308'
      if (r >= 0.2) return '#22d3ee'
      return '#3f3f46'
    }
    case 'degree': {
      const deg = degreeMap.get(d.id) ?? 0
      const ratio = maxDegree > 0 ? deg / maxDegree : 0
      return `rgb(${Math.round(ratio*239)},${Math.round(68+ratio*100)},${Math.round(238-ratio*170)})`
    }
    case 'tier': {
      const t = d.tier ?? 5
      return ['#ef4444','#f97316','#eab308','#22c55e','#06b6d4','#6b7280'][Math.min(t, 5)]
    }
    default:
      return nodeBaseColor(d)
  }
}

export function getNodeSizeForDegree(
  d: GraphNode, sizeByDegree: boolean,
  degreeMap: Map<string, number>, maxDegree: number,
): number {
  if (!sizeByDegree) return nodeRadius(d)
  const deg = degreeMap.get(d.id) ?? 0
  const ratio = maxDegree > 0 ? deg / maxDegree : 0
  return Math.max(7, 7 + ratio * 22)
}

export function drawArrowHead(
  ctx: CanvasRenderingContext2D,
  ex: number, ey: number, angle: number, size: number,
) {
  ctx.beginPath()
  ctx.moveTo(ex, ey)
  ctx.lineTo(ex - size * Math.cos(angle - 0.45), ey - size * Math.sin(angle - 0.45))
  ctx.lineTo(ex - size * Math.cos(angle + 0.45), ey - size * Math.sin(angle + 0.45))
  ctx.closePath()
  ctx.fill()
}

export function findPath(
  nodes: GraphNode[], edges: GraphEdge[], startId: string, endId: string,
): { pathNodeIds: Set<string>; pathEdgeIds: Set<string> } {
  const adj = new Map<string, { to: string; eid: string }[]>()
  for (const n of nodes) adj.set(n.id, [])
  for (const e of edges) {
    const s = getId(e.source), t = getId(e.target)
    adj.get(s)?.push({ to: t, eid: e.id })
    adj.get(t)?.push({ to: s, eid: e.id })
  }
  const visited = new Set([startId])
  const parent = new Map<string, { from: string; eid: string }>()
  const q = [startId]
  while (q.length) {
    const curr = q.shift()!
    if (curr === endId) {
      const pn = new Set<string>(), pe = new Set<string>()
      let n = curr
      while (parent.has(n)) {
        pn.add(n)
        const { from, eid } = parent.get(n)!
        pe.add(eid); n = from
      }
      pn.add(startId)
      return { pathNodeIds: pn, pathEdgeIds: pe }
    }
    for (const { to, eid } of adj.get(curr) ?? []) {
      if (!visited.has(to)) { visited.add(to); parent.set(to, { from: curr, eid }); q.push(to) }
    }
  }
  return { pathNodeIds: new Set(), pathEdgeIds: new Set() }
}

export function getNHopNeighborhood(
  allNodes: GraphNode[], allEdges: GraphEdge[], nodeId: string, hops: number,
): { nodes: GraphNode[]; edges: GraphEdge[] } {
  let frontier = new Set([nodeId])
  const reachable = new Set([nodeId])
  for (let h = 0; h < hops; h++) {
    const next = new Set<string>()
    for (const e of allEdges) {
      const s = getId(e.source), t = getId(e.target)
      if (frontier.has(s) && !reachable.has(t)) { next.add(t); reachable.add(t) }
      if (frontier.has(t) && !reachable.has(s)) { next.add(s); reachable.add(s) }
    }
    frontier = next
    if (!frontier.size) break
  }
  return {
    nodes: allNodes.filter(n => reachable.has(n.id)),
    edges: allEdges.filter(e => reachable.has(getId(e.source)) && reachable.has(getId(e.target))),
  }
}

export function computeAnalytics(
  nodes: GraphNode[], edges: GraphEdge[], degreeMap: Map<string, number>,
) {
  let totalDegree = 0, maxDeg = 0, mostConnectedId = ''
  degreeMap.forEach((deg, id) => {
    totalDegree += deg
    if (deg > maxDeg) { maxDeg = deg; mostConnectedId = id }
  })
  const avg = nodes.length ? totalDegree / nodes.length : 0
  const density = nodes.length > 1 ? edges.length / (nodes.length * (nodes.length - 1)) : 0
  const mostConnected = nodes.find(n => n.id === mostConnectedId)

  let totalRisk = 0, critEdges = 0
  for (const e of edges) {
    const w = e.risk_weight ?? 0
    totalRisk += w
    if (w >= 0.8) critEdges++
  }

  const tier0 = nodes.filter(n => n.tier === 0).length
  const crownJewels = nodes.filter(n => n.is_crown_jewel).length
  const adminCounts = nodes.filter(n => n.is_admin_count).length

  return {
    nodes: nodes.length, edges: edges.length,
    avgDegree: avg.toFixed(1), maxDegree: maxDeg,
    density: (density * 100).toFixed(3) + '%',
    mostConnected: mostConnected?.label ?? '—',
    mostConnectedDegree: maxDeg,
    totalRisk: totalRisk.toFixed(1), critEdges,
    tier0, crownJewels, adminCounts,
    riskScore: Math.min(100, Math.round(totalRisk / Math.max(edges.length, 1) * 100)),
  }
}

export function applyHierarchical(nodes: SimNode[], W: number, H: number) {
  const grps = new Map<number, SimNode[]>()
  for (const n of nodes) {
    const t = n.tier ?? 4
    if (!grps.has(t)) grps.set(t, [])
    grps.get(t)!.push(n)
  }
  const tiers = [...grps.keys()].sort()
  tiers.forEach((tier, i) => {
    const g = grps.get(tier)!
    const y = H / (tiers.length + 1) * (i + 1)
    g.forEach((n, j) => { n.fx = W / (g.length + 1) * (j + 1); n.fy = y })
  })
}

export function applyRadial(nodes: SimNode[], W: number, H: number) {
  const cx = W / 2, cy = H / 2
  const grps = new Map<number, SimNode[]>()
  for (const n of nodes) {
    const t = n.tier ?? 4
    if (!grps.has(t)) grps.set(t, [])
    grps.get(t)!.push(n)
  }
  const tiers = [...grps.keys()].sort()
  const maxR = Math.min(W, H) * 0.42
  tiers.forEach((tier, i) => {
    const g = grps.get(tier)!
    const r = i === 0 ? 0 : maxR / tiers.length * (i + 1)
    g.forEach((n, j) => {
      if (i === 0) { n.fx = cx; n.fy = cy }
      else {
        const a = 2 * Math.PI / g.length * j - Math.PI / 2
        n.fx = cx + r * Math.cos(a); n.fy = cy + r * Math.sin(a)
      }
    })
  })
}

export { edgeRiskColor as edgeColor } from './constants'

export function getErrDetail(err: unknown, fb: string): string {
  return (err as { response?: { data?: { detail?: string } } })?.response?.data?.detail ?? fb
}

export interface NodeReachability {
  tier0Reachable: number
  hopsToNearestTier0: number   // -1 if none reachable
  ownedReachable: number
  criticalEdgeCount: number    // edges on this node with risk_weight >= 0.8
  inboundHighRisk: number      // inbound edges with risk_weight >= 0.6
  outboundHighRisk: number     // outbound edges with risk_weight >= 0.6
}

export function computeNodeReachability(
  allNodes: GraphNode[],
  allEdges: GraphEdge[],
  nodeId: string,
  ownedIds: Set<string>,
): NodeReachability {
  const nodeMap = new Map(allNodes.map(n => [n.id, n]))
  const queue: Array<{ id: string; depth: number }> = [{ id: nodeId, depth: 0 }]
  const visited = new Set<string>([nodeId])
  let tier0Reachable = 0
  let hopsToNearestTier0 = -1
  let ownedReachable = 0

  while (queue.length) {
    const { id, depth } = queue.shift()!
    for (const e of allEdges) {
      if (getId(e.source) !== id) continue
      const tid = getId(e.target)
      if (visited.has(tid)) continue
      visited.add(tid)
      const tnode = nodeMap.get(tid)
      if (!tnode) continue
      if (tnode.tier === 0 || tnode.is_crown_jewel) {
        tier0Reachable++
        if (hopsToNearestTier0 === -1) hopsToNearestTier0 = depth + 1
      }
      if (ownedIds.has(tid)) ownedReachable++
      queue.push({ id: tid, depth: depth + 1 })
    }
  }

  const nodeEdges = allEdges.filter(e => getId(e.source) === nodeId || getId(e.target) === nodeId)
  const criticalEdgeCount = nodeEdges.filter(e => (e.risk_weight ?? 0) >= 0.8).length
  const inboundHighRisk   = allEdges.filter(e => getId(e.target) === nodeId && (e.risk_weight ?? 0) >= 0.6).length
  const outboundHighRisk  = allEdges.filter(e => getId(e.source) === nodeId && (e.risk_weight ?? 0) >= 0.6).length

  return { tier0Reachable, hopsToNearestTier0, ownedReachable, criticalEdgeCount, inboundHighRisk, outboundHighRisk }
}
