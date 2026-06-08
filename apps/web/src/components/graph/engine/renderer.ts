import * as d3 from 'd3'
import type { RenderProps, SimNode, SimLink } from './types'
import type { GraphNode, VirtualGroupNode } from '@/lib/types'
import {
  nodeRadius, getNodeColorForMode, getNodeSizeForDegree,
  drawArrowHead, getId,
} from './utils'
import { edgeRiskColor, edgeRiskOpacity, getLetter } from './constants'

const MM_W = 192
const MM_H = 118

class LabelGrid {
  private cells = new Map<string, number>()
  private cellSize: number
  constructor(cellSize = 16) { this.cellSize = cellSize }
  private key(x: number, y: number) {
    return `${Math.floor(x / this.cellSize)},${Math.floor(y / this.cellSize)}`
  }
  countNear(x: number, y: number, radius: number): number {
    let count = 0
    const steps = Math.ceil(radius / this.cellSize)
    for (let dx = -steps; dx <= steps; dx++) {
      for (let dy = -steps; dy <= steps; dy++) {
        const cx = Math.floor(x / this.cellSize) + dx
        const cy = Math.floor(y / this.cellSize) + dy
        count += this.cells.get(`${cx},${cy}`) ?? 0
      }
    }
    return count
  }
  mark(x: number, y: number) {
    const k = this.key(x, y)
    this.cells.set(k, (this.cells.get(k) ?? 0) + 1)
  }
  clear() { this.cells.clear() }
}

export class GraphRenderer {
  private canvas: HTMLCanvasElement
  private ctx: CanvasRenderingContext2D
  private mmCanvas: HTMLCanvasElement
  private mmCtx: CanvasRenderingContext2D
  private transform: d3.ZoomTransform = d3.zoomIdentity
  private rafId: number | null = null
  private dirty = false
  private fps = 0
  private fpsFrames = 0
  private fpsLastTime = 0
  private showFps = false

  nodes: SimNode[] = []
  links: SimLink[] = []
  parallelCount = new Map<string, number>()
  edgeCurveIdx = new Map<string, number>()
  props: RenderProps

  // Minimap click callback
  onMinimapClick: ((gx: number, gy: number) => void) | null = null

  // Label grid for collision-avoiding label placement
  private labelGrid: LabelGrid | null = null

  // Quadtree for fast hit-testing (rebuilt per render when needed)
  private qtree: d3.Quadtree<SimNode> | null = null
  private qtreeDirty = true

  constructor(
    canvas: HTMLCanvasElement,
    mmCanvas: HTMLCanvasElement,
    props: RenderProps,
  ) {
    this.canvas = canvas
    this.mmCanvas = mmCanvas
    this.ctx = canvas.getContext('2d', { alpha: false })!
    this.mmCtx = mmCanvas.getContext('2d')!
    this.props = props

    // Wire up minimap click
    mmCanvas.addEventListener('click', this.handleMinimapClick)
  }

  private handleMinimapClick = (ev: MouseEvent) => {
    const nodes = this.nodes
    if (!nodes.length || !this.onMinimapClick) return
    const rect = this.mmCanvas.getBoundingClientRect()
    const mx = ev.clientX - rect.left
    const my = ev.clientY - rect.top
    // Convert minimap coords → graph coords
    const xs = nodes.map(n => n.x ?? 0), ys = nodes.map(n => n.y ?? 0)
    const minX = Math.min(...xs), maxX = Math.max(...xs)
    const minY = Math.min(...ys), maxY = Math.max(...ys)
    const rx = maxX - minX || 1, ry = maxY - minY || 1
    const pad = 10
    const sc = Math.min((MM_W - pad*2) / rx, (MM_H - pad*2) / ry)
    const offX = pad + ((MM_W - pad*2) - rx*sc) / 2
    const offY = pad + ((MM_H - pad*2) - ry*sc) / 2
    const gx = (mx - offX) / sc + minX
    const gy = (my - offY) / sc + minY
    this.onMinimapClick(gx, gy)
  }

  setTransform(t: d3.ZoomTransform) {
    this.transform = t
    this.requestFrame()
  }

  setProps(props: RenderProps) {
    this.props = props
    this.requestFrame()
  }

  setNodes(nodes: SimNode[]) {
    this.nodes = nodes
    this.qtreeDirty = true
    this.requestFrame()
  }

  setLinks(links: SimLink[]) {
    this.links = links
    this.requestFrame()
  }

  setParallelMaps(parallelCount: Map<string, number>, edgeCurveIdx: Map<string, number>) {
    this.parallelCount = parallelCount
    this.edgeCurveIdx = edgeCurveIdx
  }

  markDirty() {
    this.requestFrame()
  }

  toggleFps(v: boolean) {
    this.showFps = v
    this.requestFrame()
  }

  private requestFrame() {
    this.dirty = true
    if (this.rafId === null) {
      this.rafId = requestAnimationFrame(this.renderFrame)
    }
  }

  private renderFrame = (now: number) => {
    this.rafId = null

    if (this.dirty) {
      this.dirty = false
      this.drawAll()
    }

    // FPS tracking
    this.fpsFrames++
    if (now - this.fpsLastTime >= 1000) {
      this.fps = this.fpsFrames
      this.fpsFrames = 0
      this.fpsLastTime = now
    }

    // Keep looping if simulating or particles active
    const needsLoop =
      this.props.isSimulating ||
      (this.props.showParticles && this.props.pathEdgeIds.size > 0)

    if (needsLoop) {
      this.dirty = true
      this.rafId = requestAnimationFrame(this.renderFrame)
    }
  }

  private drawAll() {
    const canvas = this.canvas
    const W = canvas.clientWidth
    const H = this.props.graphHeight
    if (!W || !H) return

    const dpr = window.devicePixelRatio || 1
    const cw = Math.round(W * dpr), ch = Math.round(H * dpr)
    if (canvas.width !== cw || canvas.height !== ch) {
      canvas.width = cw; canvas.height = ch
      canvas.style.width = W + 'px'; canvas.style.height = H + 'px'
    }

    const ctx = this.ctx
    const t = this.transform
    const k = t.k

    ctx.save()
    ctx.scale(dpr, dpr)

    // Background
    ctx.fillStyle = '#060608'
    ctx.fillRect(0, 0, W, H)

    // Subtle vignette gradient (skip during sim for speed)
    if (!this.props.isSimulating && k > 0.1) {
      const grad = ctx.createRadialGradient(W/2, H*0.22, 0, W/2, H*0.22, W*0.52)
      grad.addColorStop(0, 'rgba(99,102,241,0.055)')
      grad.addColorStop(1, 'transparent')
      ctx.fillStyle = grad
      ctx.fillRect(0, 0, W, H)
    }

    ctx.translate(t.x, t.y)
    ctx.scale(k, k)

    // Viewport bounds for frustum culling
    const [vx1, vy1] = t.invert([0, 0])
    const [vx2, vy2] = t.invert([W, H])
    const margin = 60 / k

    // Container bounding boxes behind everything
    this.drawContainers(ctx)

    // Reset label grid each frame
    if (!this.labelGrid) this.labelGrid = new LabelGrid(16)
    this.labelGrid.clear()

    // Cull edges during heavy sim to keep framerate up
    const skipEdgeDetail = this.props.isSimulating && this.links.length > 200
    this.drawEdges(ctx, k, vx1-margin, vy1-margin, vx2+margin, vy2+margin, skipEdgeDetail)
    this.drawNodes(ctx, k, vx1-margin, vy1-margin, vx2+margin, vy2+margin)

    if (this.props.showParticles && this.props.pathEdgeIds.size > 0 && !this.props.isSimulating) {
      this.drawPathParticles(ctx, k)
    }

    ctx.restore()

    // FPS overlay
    if (this.showFps) {
      ctx.save()
      ctx.font = '11px monospace'
      ctx.fillStyle = 'rgba(34,211,238,0.7)'
      ctx.fillText(`${this.fps} fps`, 12, 20)
      ctx.restore()
    }

    this.drawMinimap()
  }

  private drawContainers(ctx: CanvasRenderingContext2D): void {
    const containerBoxes = this.props.containerBoxes
    if (!containerBoxes || containerBoxes.length === 0) return
    const PAD = 28
    for (const container of containerBoxes) {
      const containedNodes = this.nodes.filter(n => {
        return this.links.some(l => {
          const s = getId(l.source as string | SimNode), t = getId(l.target as string | SimNode)
          return s === container.nodeId && t === n.id && l.edge_type === 'CONTAINS'
        })
      })
      if (containedNodes.length === 0) continue
      const xs = containedNodes.map(n => n.x ?? 0)
      const ys = containedNodes.map(n => n.y ?? 0)
      const minX = Math.min(...xs) - PAD
      const minY = Math.min(...ys) - PAD
      const maxX = Math.max(...xs) + PAD
      const maxY = Math.max(...ys) + PAD
      const w = maxX - minX, h = maxY - minY
      const r = 12
      ctx.save()
      ctx.globalAlpha = 0.08
      ctx.fillStyle = container.color
      this.roundRect(ctx, minX, minY, w, h, r)
      ctx.fill()
      ctx.globalAlpha = 0.18
      ctx.strokeStyle = container.color
      ctx.lineWidth = 1.5
      ctx.setLineDash([6, 4])
      this.roundRect(ctx, minX, minY, w, h, r)
      ctx.stroke()
      ctx.setLineDash([])
      ctx.globalAlpha = 0.55
      ctx.fillStyle = container.color
      const k = this.transform.k
      ctx.font = `${Math.max(8, Math.round(9 / k))}px sans-serif`
      ctx.textAlign = 'left'
      ctx.textBaseline = 'top'
      ctx.fillText(container.label, minX + 8, minY + 6)
      ctx.restore()
    }
  }

  private roundRect(ctx: CanvasRenderingContext2D, x: number, y: number, w: number, h: number, r: number) {
    ctx.beginPath()
    ctx.moveTo(x + r, y)
    ctx.lineTo(x + w - r, y)
    ctx.arcTo(x + w, y, x + w, y + r, r)
    ctx.lineTo(x + w, y + h - r)
    ctx.arcTo(x + w, y + h, x + w - r, y + h, r)
    ctx.lineTo(x + r, y + h)
    ctx.arcTo(x, y + h, x, y + h - r, r)
    ctx.lineTo(x, y + r)
    ctx.arcTo(x, y, x + r, y, r)
    ctx.closePath()
  }

  private computeEdgeBundles(): Map<string, SimLink[]> {
    if (!this.props.bundleEdges) return new Map()
    const pairMap = new Map<string, SimLink[]>()
    for (const link of this.links) {
      const s = getId(link.source as string | SimNode)
      const t = getId(link.target as string | SimNode)
      const key = s < t ? `${s}__${t}` : `${t}__${s}`
      const arr = pairMap.get(key) ?? []
      arr.push(link)
      pairMap.set(key, arr)
    }
    const result = new Map<string, SimLink[]>()
    pairMap.forEach((links, key) => {
      if (links.length >= 3) result.set(key, links)
    })
    return result
  }

  private getLabelOffset(node: SimNode, r: number): { dx: number; dy: number } {
    const candidates = [
      { dx: r + 5, dy: 4 },
      { dx: -(r + 5), dy: 4 },
      { dx: 0, dy: -(r + 10) },
      { dx: 0, dy: r + 12 },
      { dx: r + 4, dy: -(r + 4) },
      { dx: -(r + 4), dy: -(r + 4) },
    ]
    if (!this.labelGrid) return candidates[0]
    let best = candidates[0]
    let bestScore = Infinity
    for (const c of candidates) {
      const lx = (node.x ?? 0) + c.dx
      const ly = (node.y ?? 0) + c.dy
      const score = this.labelGrid.countNear(lx, ly, 20)
      if (score < bestScore) { bestScore = score; best = c }
    }
    this.labelGrid.mark((node.x ?? 0) + best.dx, (node.y ?? 0) + best.dy)
    return best
  }

  private drawEdges(
    ctx: CanvasRenderingContext2D, k: number,
    x1: number, y1: number, x2: number, y2: number,
    skipDetail = false,
  ) {
    const p = this.props
    const hasEdgeHL = p.highlightEdgeIds.size > 0
    const selId = p.selectedId

    ctx.lineCap = 'round'

    const bundles = this.computeEdgeBundles()
    const bundledPairs = new Set(bundles.keys())

    for (const l of this.links) {
      const src = l.source as SimNode, tgt = l.target as SimNode
      if (!src || !tgt) continue
      const sx = src.x ?? 0, sy = src.y ?? 0
      const tx = tgt.x ?? 0, ty = tgt.y ?? 0

      // Edge bundling — replace 3+ parallel edges between same pair with one thick line + badge
      const sId = getId(l.source as string | SimNode)
      const tId = getId(l.target as string | SimNode)
      const pairKey = sId < tId ? `${sId}__${tId}` : `${tId}__${sId}`

      if (bundledPairs.has(pairKey)) {
        const bundleLinks = bundles.get(pairKey)!
        const isFirst = bundleLinks[0] === l
        if (!isFirst) continue  // skip non-first edges in bundle — drawn once

        // Frustum cull the bundle
        if (sx < x1 && tx < x1) continue
        if (sx > x2 && tx > x2) continue
        if (sy < y1 && ty < y1) continue
        if (sy > y2 && ty > y2) continue

        const maxRisk = Math.max(...bundleLinks.map(bl => bl.risk_weight ?? 0))
        const col = edgeRiskColor(maxRisk)
        ctx.save()
        ctx.strokeStyle = col
        ctx.lineWidth = (2 + bundleLinks.length * 0.6) / k
        ctx.globalAlpha = edgeRiskOpacity(maxRisk) * 0.85
        ctx.beginPath()
        ctx.moveTo(sx, sy)
        ctx.lineTo(tx, ty)
        ctx.stroke()
        ctx.restore()
        // Draw count badge at midpoint
        const mx = (sx + tx) / 2, my = (sy + ty) / 2
        ctx.save()
        ctx.fillStyle = '#18181b'
        ctx.beginPath()
        ctx.arc(mx, my, 8 / k, 0, Math.PI * 2)
        ctx.fill()
        ctx.fillStyle = col
        ctx.font = `bold ${8/k}px sans-serif`
        ctx.textAlign = 'center'
        ctx.textBaseline = 'middle'
        ctx.fillText(`${bundleLinks.length}×`, mx, my)
        ctx.restore()
        continue
      }

      // Frustum cull: skip if entirely outside viewport
      if (sx < x1 && tx < x1) continue
      if (sx > x2 && tx > x2) continue
      if (sy < y1 && ty < y1) continue
      if (sy > y2 && ty > y2) continue

      const w = l.risk_weight ?? 0.3
      const isPath = p.pathEdgeIds.has(l.id)
      const isHLEdge = hasEdgeHL && p.highlightEdgeIds.has(l.id)

      let color = edgeRiskColor(w)
      let opacity = edgeRiskOpacity(w)
      let lineW = Math.max(0.8, w * 2.6)

      if (isPath) {
        color = '#22d3ee'; opacity = 0.9; lineW = 2.5
      } else if (isHLEdge) {
        color = '#f59e0b'; opacity = 0.88
      } else if (hasEdgeHL) {
        opacity = 0.04
      } else if (selId) {
        const srcId = getId(l.source as string | SimNode)
        const tgtId = getId(l.target as string | SimNode)
        opacity = (srcId === selId || tgtId === selId) ? Math.min(0.9, opacity * 2.1) : 0.04
      }

      ctx.globalAlpha = opacity
      ctx.strokeStyle = color
      ctx.lineWidth = lineW / k

      // Provenance overlay: dim uncertain edges
      if (this.props.showProvenance) {
        const conf = l.edge_confidence ?? 1.0
        ctx.globalAlpha *= (0.3 + conf * 0.7)
      }

      // Diff overlay on edges
      if (this.props.diffAddedEdgeIds?.has(l.id)) {
        ctx.strokeStyle = '#22c55e'
        ctx.lineWidth = (ctx.lineWidth ?? 1) + 1
        ctx.setLineDash([6, 3])
      }
      if (this.props.diffRemovedEdgeIds?.has(l.id)) {
        ctx.globalAlpha *= 0.5
        ctx.strokeStyle = '#ef4444'
        ctx.setLineDash([4, 4])
      }

      const dx = tx - sx, dy = ty - sy
      const dist = Math.sqrt(dx*dx + dy*dy) || 1
      const arrowOff = nodeRadius(tgt as GraphNode) + 5
      const ex = tx - dx/dist * arrowOff
      const ey = ty - dy/dist * arrowOff

      const sKey = [getId(l.source as string | SimNode), getId(l.target as string | SimNode)].sort().join('|')
      const total = this.parallelCount.get(sKey) ?? 1
      const cidx = this.edgeCurveIdx.get(l.id) ?? 0
      const curv = (cidx - (total-1)/2) * 28

      let endAngle = Math.atan2(ey-sy, ex-sx)

      ctx.beginPath()
      if (skipDetail || Math.abs(curv) < 1) {
        ctx.moveTo(sx, sy); ctx.lineTo(ex, ey)
      } else {
        const cpx = (sx+tx)/2 - dy/dist*curv
        const cpy = (sy+ty)/2 + dx/dist*curv
        ctx.moveTo(sx, sy); ctx.quadraticCurveTo(cpx, cpy, ex, ey)
        endAngle = Math.atan2(ey-cpy, ex-cpx)
      }
      ctx.stroke()
      ctx.setLineDash([])

      if (!skipDetail) {
        ctx.fillStyle = color
        ctx.globalAlpha = opacity
        const arrowSize = (this.props.directedMode && this.props.pathEdgeIds?.has(l.id))
          ? 14
          : 8
        drawArrowHead(ctx, ex, ey, endAngle, arrowSize / k)
      }

      if (p.showEdgeLabels && k > 0.4) {
        const lmx = (sx+tx)/2 - (Math.abs(curv) >= 1 ? dy/dist*curv*0.5 : 0)
        const lmy = (sy+ty)/2 + (Math.abs(curv) >= 1 ? dx/dist*curv*0.5 : 0)
        ctx.globalAlpha = 0.58
        ctx.fillStyle = '#a1a1aa'
        ctx.font = `${7/k}px monospace`
        ctx.textAlign = 'center'
        ctx.textBaseline = 'middle'
        ctx.fillText(l.edge_type, lmx, lmy)
      }
    }
    ctx.globalAlpha = 1
  }

  private drawNodes(
    ctx: CanvasRenderingContext2D, k: number,
    x1: number, y1: number, x2: number, y2: number,
  ) {
    const p = this.props
    const hasNodeHL = p.highlightNodeIds.size > 0
    const selId = p.selectedId

    for (const n of this.nodes) {
      const nx = n.x ?? 0, ny = n.y ?? 0

      // Frustum cull
      const cullR = 90 / k + 30
      if (nx + cullR < x1 || nx - cullR > x2 || ny + cullR < y1 || ny - cullR > y2) continue

      const r = getNodeSizeForDegree(n, p.sizeByDegree, p.degreeMap, p.maxDegree)
      const color = getNodeColorForMode(n, p.colorMode, p.degreeMap, p.maxDegree, p.riskMap)
      const isPathNode = p.pathNodeIds.has(n.id)
      const isHLNode = hasNodeHL && p.highlightNodeIds.has(n.id)
      const isOwned = p.ownedNodes.has(n.id)
      const isHighValue = p.highValueNodes.has(n.id)
      const isMarked = isOwned || isHighValue

      let alpha = 1
      if (hasNodeHL) {
        alpha = p.highlightNodeIds.has(n.id) ? 1 : 0.07
      } else if (selId && selId !== n.id) {
        alpha = p.connectedIds.has(n.id) ? 1 : 0.09
      }
      if (isMarked) alpha = Math.max(alpha, 0.92)

      ctx.globalAlpha = alpha

      // Soft glow via layered rings (NO shadowBlur — too expensive)
      if (!p.isSimulating && (n.tier === 0 || n.is_crown_jewel || isPathNode || isMarked)) {
        const gc = isOwned ? '#f43f5e' : isHighValue ? '#facc15' : isPathNode ? '#22d3ee' : n.tier === 0 ? '#ef4444' : '#f97316'
        ctx.fillStyle = gc + '12'
        ctx.beginPath(); ctx.arc(nx, ny, r + (isMarked ? 26/k : 12), 0, Math.PI*2); ctx.fill()
        ctx.fillStyle = gc + '0c'
        ctx.beginPath(); ctx.arc(nx, ny, r + (isMarked ? 18/k : 8), 0, Math.PI*2); ctx.fill()
        ctx.fillStyle = gc + '08'
        ctx.beginPath(); ctx.arc(nx, ny, r + (isMarked ? 10/k : 5), 0, Math.PI*2); ctx.fill()
      }

      // Outer ring for tier-0 / crown jewel
      if (n.tier === 0 || n.is_crown_jewel) {
        ctx.beginPath()
        ctx.arc(nx, ny, r + 10, 0, Math.PI*2)
        ctx.strokeStyle = color
        ctx.lineWidth = 0.6/k
        ctx.globalAlpha = alpha * 0.2
        ctx.stroke()
        ctx.globalAlpha = alpha
      }

      // Path / query highlight ring
      if (isPathNode || isHLNode) {
        ctx.beginPath()
        ctx.arc(nx, ny, r + 5, 0, Math.PI*2)
        ctx.strokeStyle = isHLNode ? '#f59e0b' : '#22d3ee'
        ctx.lineWidth = 1.8/k
        ctx.globalAlpha = alpha * 0.88
        ctx.stroke()
        ctx.globalAlpha = alpha
      }

      // Start / end indicator
      if (n.id === p.startNodeId || n.id === p.endNodeId) {
        ctx.beginPath()
        ctx.arc(nx, ny, r + 4, 0, Math.PI*2)
        ctx.strokeStyle = n.id === p.startNodeId ? '#22c55e' : '#f87171'
        ctx.lineWidth = 2.2/k
        ctx.globalAlpha = 1
        ctx.stroke()
        ctx.globalAlpha = alpha
      }

      // Marked nodes need to remain readable even at zoomed-out scale.
      if (isMarked) {
        const rings = isOwned && isHighValue
          ? ['#f43f5e', '#facc15']
          : [isOwned ? '#f43f5e' : '#facc15']
        rings.forEach((ringColor, idx) => {
          ctx.beginPath()
          ctx.arc(nx, ny, r + (14 + idx * 9)/k, 0, Math.PI*2)
          ctx.strokeStyle = ringColor
          ctx.lineWidth = 3.2/k
          ctx.globalAlpha = 0.95
          ctx.stroke()
        })
        ctx.globalAlpha = alpha
      }

      // Heat map glow — choke point prominence
      const heat = this.props.heatMap?.get(n.id) ?? 0
      if (heat > 0.1) {
        const glowRadius = r * (1 + heat * 3.5)
        const grad = ctx.createRadialGradient(nx, ny, r, nx, ny, glowRadius)
        grad.addColorStop(0, `rgba(239,68,68,${heat * 0.55})`)
        grad.addColorStop(1, 'rgba(239,68,68,0)')
        ctx.save()
        ctx.fillStyle = grad
        ctx.beginPath()
        ctx.arc(nx, ny, glowRadius, 0, Math.PI * 2)
        ctx.fill()
        ctx.restore()
      }

      // Node body
      ctx.beginPath()
      ctx.arc(nx, ny, r, 0, Math.PI*2)
      ctx.fillStyle = color + '28'
      ctx.fill()

      ctx.strokeStyle = color
      ctx.lineWidth = (n.tier === 0 ? 2.2 : 1.4)/k
      if (p.pinnedIds.has(n.id)) ctx.setLineDash([4/k, 2/k])
      ctx.stroke()
      ctx.setLineDash([])

      // Virtual group node (collapsed) — dashed border + member count badge
      if ((n as VirtualGroupNode).isVirtual) {
        ctx.save()
        ctx.setLineDash([4, 3])
        ctx.strokeStyle = '#a78bfa'
        ctx.lineWidth = 2
        ctx.beginPath()
        ctx.arc(nx, ny, r, 0, Math.PI * 2)
        ctx.stroke()
        ctx.setLineDash([])
        // Member count badge
        const count = (n as VirtualGroupNode).memberCount ?? 0
        ctx.fillStyle = '#a78bfa'
        ctx.font = 'bold 8px sans-serif'
        ctx.textAlign = 'center'
        ctx.textBaseline = 'middle'
        ctx.fillText(`${count}m`, nx + r * 0.6, ny - r * 0.6)
        ctx.restore()
      }

      // Diff overlay — added nodes glow green
      if (this.props.diffAddedNodeIds?.has(n.id)) {
        ctx.save()
        ctx.shadowColor = '#22c55e'
        ctx.shadowBlur = 14 + Math.sin(Date.now() / 300) * 6
        ctx.strokeStyle = '#22c55e'
        ctx.lineWidth = 2
        ctx.beginPath()
        ctx.arc(nx, ny, r, 0, Math.PI * 2)
        ctx.stroke()
        ctx.restore()
        this.dirty = true  // keep animating for the pulse
      }
      // Diff overlay — removed nodes faded red dashed
      if (this.props.diffRemovedNodeIds?.has(n.id)) {
        ctx.save()
        ctx.globalAlpha *= 0.35
        ctx.setLineDash([4, 3])
        ctx.strokeStyle = '#ef4444'
        ctx.lineWidth = 2
        ctx.beginPath()
        ctx.arc(nx, ny, r, 0, Math.PI * 2)
        ctx.stroke()
        ctx.setLineDash([])
        ctx.restore()
      }

      // Icon letter — much faster than emoji
      const letter = getLetter(n.entity_type)
      const iconSize = Math.max(5.5, r * (letter.length > 1 ? 0.52 : 0.7))
      ctx.fillStyle = color
      ctx.globalAlpha = alpha * 0.92
      ctx.font = `700 ${iconSize}px monospace`
      ctx.textAlign = 'center'
      ctx.textBaseline = 'middle'
      ctx.fillText(letter, nx, ny)

      // Owned / high-value badges
      if (isMarked) {
        const tagY = ny - r - 26/k
        const tags = [
          ...(isOwned ? [{ text: 'OWNED', color: '#f43f5e', x: nx - (isHighValue ? 27/k : 0) }] : []),
          ...(isHighValue ? [{ text: 'HIGH', color: '#facc15', x: nx + (isOwned ? 27/k : 0) }] : []),
        ]
        for (const tag of tags) {
          const tw = tag.text.length * 7.5/k
          ctx.globalAlpha = 0.92
          ctx.fillStyle = '#050506'
          ctx.strokeStyle = tag.color
          ctx.lineWidth = 1.4/k
          ctx.beginPath()
          ctx.roundRect(tag.x - tw/2 - 5/k, tagY - 8/k, tw + 10/k, 16/k, 4/k)
          ctx.fill()
          ctx.stroke()
          ctx.globalAlpha = 1
          ctx.fillStyle = tag.color
          ctx.font = `800 ${10/k}px monospace`
          ctx.textAlign = 'center'
          ctx.textBaseline = 'middle'
          ctx.fillText(tag.text, tag.x, tagY)
        }
      }

      // Labels: hide during simulation entirely (avoids expensive text rendering
      // every frame). Show tier-0 / crown jewels at any zoom; show others only
      // when zoomed in enough that text is actually legible.
      const important = isMarked || n.tier === 0 || n.is_crown_jewel
      const showLabel = !p.isSimulating && (important || k > 0.5)
      if (showLabel) {
        // Smooth fade-in as user zooms in, instant for important nodes
        const fadeAlpha = important ? 1 : Math.min(1, (k - 0.4) / 0.2)
        const labelAlpha = alpha * fadeAlpha
        if (labelAlpha > 0.05) {
          const fontSize = Math.max(important ? 11 : 9, (important ? 13 : 11) / k)
          const label = n.label.length > 26 ? n.label.slice(0, 26) + '…' : n.label
          const labelOff = this.getLabelOffset(n, r)
          const lx = nx + labelOff.dx
          const ly = ny + labelOff.dy

          ctx.font = `${fontSize}px Inter,ui-sans-serif,sans-serif`
          const tw = ctx.measureText(label).width
          const pH = 4 / k, pV = 3 / k

          // Dark pill background — makes text readable over any edge/node
          ctx.globalAlpha = Math.min(labelAlpha * 0.8, 0.8)
          ctx.fillStyle = '#060608'
          ctx.beginPath()
          ctx.roundRect(lx - pH, ly - fontSize / 2 - pV, tw + pH * 2, fontSize + pV * 2, 3 / k)
          ctx.fill()

          ctx.globalAlpha = labelAlpha
          ctx.fillStyle = important ? '#f4f4f5' : '#b4b4b8'
          ctx.textAlign = 'left'
          ctx.textBaseline = 'middle'
          ctx.fillText(label, lx, ly)
        }
      }

      ctx.globalAlpha = 1
    }
  }

  private drawPathParticles(ctx: CanvasRenderingContext2D, k: number) {
    const p = this.props
    const now = performance.now() / 1000  // seconds
    ctx.globalAlpha = 1

    for (const l of this.links) {
      if (!p.pathEdgeIds.has(l.id)) continue
      const src = l.source as SimNode, tgt = l.target as SimNode
      if (!src || !tgt) continue

      const sx = src.x ?? 0, sy = src.y ?? 0
      const tx = tgt.x ?? 0, ty = tgt.y ?? 0
      const dx = tx-sx, dy = ty-sy
      const dist = Math.sqrt(dx*dx + dy*dy)
      if (dist < 1) continue

      // 3 particles per edge, evenly spaced
      for (let i = 0; i < 3; i++) {
        const phase = (now * 0.55 + i / 3) % 1
        const px = sx + dx * phase
        const py = sy + dy * phase
        const a = Math.sin(phase * Math.PI)  // fade in/out at ends
        ctx.globalAlpha = a * 0.9
        ctx.fillStyle = '#22d3ee'
        ctx.beginPath()
        ctx.arc(px, py, 2.8/k, 0, Math.PI*2)
        ctx.fill()
      }
    }
    ctx.globalAlpha = 1
  }

  private drawMinimap() {
    const mm = this.mmCanvas
    const nodes = this.nodes
    const dpr = window.devicePixelRatio || 1

    if (mm.width !== MM_W*dpr || mm.height !== MM_H*dpr) {
      mm.width = MM_W*dpr; mm.height = MM_H*dpr
      mm.style.width = MM_W + 'px'; mm.style.height = MM_H + 'px'
    }

    const mctx = this.mmCtx
    mctx.clearRect(0, 0, mm.width, mm.height)
    mctx.save()
    mctx.scale(dpr, dpr)

    // Glass background
    mctx.fillStyle = 'rgba(6,6,8,0.82)'
    mctx.strokeStyle = 'rgba(255,255,255,0.08)'
    mctx.lineWidth = 1
    const rr = 10
    mctx.beginPath()
    mctx.moveTo(rr, 0); mctx.lineTo(MM_W-rr, 0); mctx.arcTo(MM_W, 0, MM_W, rr, rr)
    mctx.lineTo(MM_W, MM_H-rr); mctx.arcTo(MM_W, MM_H, MM_W-rr, MM_H, rr)
    mctx.lineTo(rr, MM_H); mctx.arcTo(0, MM_H, 0, MM_H-rr, rr)
    mctx.lineTo(0, rr); mctx.arcTo(0, 0, rr, 0, rr)
    mctx.closePath()
    mctx.fill()
    mctx.stroke()

    if (!nodes.length) { mctx.restore(); return }

    let minX = Infinity, maxX = -Infinity, minY = Infinity, maxY = -Infinity
    for (const nd of nodes) {
      const x = nd.x ?? 0, y = nd.y ?? 0
      if (x < minX) minX = x; if (x > maxX) maxX = x
      if (y < minY) minY = y; if (y > maxY) maxY = y
    }
    const rx = maxX - minX || 1, ry = maxY - minY || 1
    const pad = 10
    const sc = Math.min((MM_W - pad*2) / rx, (MM_H - pad*2) / ry)
    const offX = pad + ((MM_W - pad*2) - rx*sc) / 2
    const offY = pad + ((MM_H - pad*2) - ry*sc) / 2
    const p = this.props

    for (const nd of nodes) {
      const mx = offX + ((nd.x ?? 0) - minX) * sc
      const my = offY + ((nd.y ?? 0) - minY) * sc
      const c2 = getNodeColorForMode(nd, p.colorMode, p.degreeMap, p.maxDegree, p.riskMap)
      mctx.fillStyle = c2
      mctx.globalAlpha = nd.tier === 0 ? 1 : 0.7
      mctx.beginPath()
      mctx.arc(mx, my, Math.max(1.5, nodeRadius(nd) * 0.22), 0, Math.PI*2)
      mctx.fill()
    }
    mctx.globalAlpha = 1

    // Viewport rectangle
    const vt = this.transform
    const W = this.canvas.clientWidth, H = this.props.graphHeight
    const [vx1, vy1] = vt.invert([0, 0])
    const [vx2, vy2] = vt.invert([W, H])
    const vrx = offX + (vx1 - minX) * sc
    const vry = offY + (vy1 - minY) * sc
    const vrw = (vx2 - vx1) * sc, vrh = (vy2 - vy1) * sc
    mctx.strokeStyle = '#22d3ee'
    mctx.lineWidth = 1.5
    mctx.fillStyle = 'rgba(34,211,238,0.06)'
    mctx.fillRect(vrx, vry, vrw, vrh)
    mctx.strokeRect(vrx, vry, vrw, vrh)

    // Label
    mctx.fillStyle = '#3f3f46'
    mctx.font = '7px monospace'
    mctx.textAlign = 'left'
    mctx.textBaseline = 'top'
    mctx.fillText('OVERVIEW', 6, 4)

    // Click hint
    mctx.fillStyle = '#27272a'
    mctx.textAlign = 'right'
    mctx.fillText('click to pan', MM_W-5, 4)

    mctx.restore()
  }

  // ── Hit testing ────────────────────────────────────────────────────
  getNodeAt(canvasX: number, canvasY: number): SimNode | null {
    const [gx, gy] = this.transform.invert([canvasX, canvasY])
    for (let i = this.nodes.length - 1; i >= 0; i--) {
      const nd = this.nodes[i]
      const nr = nodeRadius(nd as GraphNode) + 6
      const ddx = (nd.x ?? 0) - gx, ddy = (nd.y ?? 0) - gy
      if (ddx*ddx + ddy*ddy <= nr*nr) return nd
    }
    return null
  }

  getEdgeAt(canvasX: number, canvasY: number): SimLink | null {
    const tr = this.transform
    const [gx, gy] = tr.invert([canvasX, canvasY])
    const thresh = 8 / tr.k
    for (const l of this.links) {
      const src = l.source as SimNode, tgt = l.target as SimNode
      if (!src || !tgt) continue
      const sx = src.x ?? 0, sy = src.y ?? 0
      const tx = tgt.x ?? 0, ty = tgt.y ?? 0
      const ddx = tx-sx, ddy = ty-sy
      const len2 = ddx*ddx + ddy*ddy
      if (len2 === 0) continue
      const param = Math.max(0, Math.min(1, ((gx-sx)*ddx + (gy-sy)*ddy) / len2))
      const px = sx + param*ddx, py = sy + param*ddy
      if ((gx-px)**2 + (gy-py)**2 <= thresh*thresh) return l
    }
    return null
  }

  // ── Export ──────────────────────────────────────────────────────────
  exportPNG() {
    const a = document.createElement('a')
    a.download = `adbyg0d-graph-${Date.now()}.png`
    a.href = this.canvas.toDataURL('image/png')
    a.click()
  }

  exportSVG(W: number, H: number) {
    const p = this.props
    const t = this.transform
    const k = t.k
    const lines: string[] = [
      `<svg xmlns="http://www.w3.org/2000/svg" width="${W}" height="${H}" viewBox="0 0 ${W} ${H}">`,
      `<rect width="${W}" height="${H}" fill="#060608"/>`,
      `<g transform="translate(${t.x},${t.y}) scale(${k})">`,
    ]

    for (const l of this.links) {
      const src = l.source as SimNode, tgt = l.target as SimNode
      if (!src || !tgt) continue
      const w = l.risk_weight ?? 0.3
      const color = edgeRiskColor(w)
      lines.push(`<line x1="${src.x??0}" y1="${src.y??0}" x2="${tgt.x??0}" y2="${tgt.y??0}" stroke="${color}" stroke-width="${w*2}" opacity="0.6"/>`)
    }

    for (const n of this.nodes) {
      const r = nodeRadius(n)
      const color = getNodeColorForMode(n, p.colorMode, p.degreeMap, p.maxDegree, p.riskMap)
      const letter = getLetter(n.entity_type)
      lines.push(`<circle cx="${n.x??0}" cy="${n.y??0}" r="${r}" fill="${color}28" stroke="${color}" stroke-width="1.5"/>`)
      lines.push(`<text x="${n.x??0}" y="${n.y??0}" text-anchor="middle" dominant-baseline="middle" font-size="${r*0.7}" font-family="monospace" fill="${color}" font-weight="700">${letter}</text>`)
      const label = n.label.length > 24 ? n.label.slice(0, 24) + '…' : n.label
      lines.push(`<text x="${(n.x??0)+r+4}" y="${n.y??0}" font-size="9" font-family="Inter,sans-serif" fill="#d4d4d8" dominant-baseline="middle">${label}</text>`)
    }

    lines.push('</g></svg>')
    const blob = new Blob([lines.join('\n')], { type: 'image/svg+xml' })
    const a = document.createElement('a')
    a.href = URL.createObjectURL(blob)
    a.download = `adbyg0d-graph-${Date.now()}.svg`
    a.click()
    setTimeout(() => URL.revokeObjectURL(a.href), 5000)
  }

  destroy() {
    if (this.rafId !== null) cancelAnimationFrame(this.rafId)
    this.mmCanvas.removeEventListener('click', this.handleMinimapClick)
  }
}
