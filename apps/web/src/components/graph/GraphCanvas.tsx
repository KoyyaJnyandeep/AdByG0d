'use client'

import {
  forwardRef, useEffect, useImperativeHandle, useRef, useState,
} from 'react'
import * as d3 from 'd3'
import { motion, AnimatePresence } from 'framer-motion'
import { Map as MapIcon } from 'lucide-react'
import toast from 'react-hot-toast'

import type { GraphEdge, GraphNode } from '@/lib/types'
import type { CtxMenu, ForceGraphHandle, LayoutMode, RenderProps, SimLink, SimNode } from './engine/types'
import { GraphRenderer } from './engine/renderer'
import { nodeRadius, getId, applyHierarchical, applyRadial } from './engine/utils'

interface GraphCanvasProps {
  nodes: GraphNode[]
  edges: GraphEdge[]
  layoutMode: LayoutMode
  graphHeight: number
  renderProps: RenderProps
  onSelect: (node: GraphNode | null) => void
  onContextMenu: (ctx: CtxMenu) => void
  onMultiSelect: (ids: Set<string>) => void
  onEdgeHover: (edge: GraphEdge | null, x: number, y: number) => void
  onEdgeClick: (edge: GraphEdge) => void
  onPinToggle: (id: string) => void
  onSimProgress: (alpha: number) => void
  showFps?: boolean
}

const MM_W = 192

export const GraphCanvas = forwardRef<ForceGraphHandle, GraphCanvasProps>(function GraphCanvas(
  {
    nodes: rawNodes, edges: rawEdges, layoutMode, graphHeight, renderProps,
    onSelect, onContextMenu, onMultiSelect, onEdgeHover, onEdgeClick,
    onPinToggle, onSimProgress, showFps = false,
  },
  ref,
) {
  const canvasRef = useRef<HTMLCanvasElement>(null)
  const mmCanvasRef = useRef<HTMLCanvasElement>(null)
  const containerRef = useRef<HTMLDivElement>(null)
  const rendererRef = useRef<GraphRenderer | null>(null)
  const zoomRef = useRef<d3.ZoomBehavior<HTMLCanvasElement, unknown> | null>(null)
  const simRef = useRef<d3.Simulation<SimNode, SimLink> | null>(null)
  const nodesDataRef = useRef<SimNode[]>([])
  const linksDataRef = useRef<SimLink[]>([])
  const selIdRef = useRef<string | null>(null)
  const connectedSetRef = useRef<Set<string>>(new Set())
  const pinnedIds = useRef<Set<string>>(new Set())
  const [showMinimap, setShowMinimap] = useState(true)

  // Keep renderProps in a ref so renderer always reads latest
  const propsRef = useRef(renderProps)
  useEffect(() => {
    propsRef.current = renderProps
    rendererRef.current?.setProps(renderProps)
  }, [renderProps])

  useEffect(() => {
    rendererRef.current?.toggleFps(showFps ?? false)
  }, [showFps])

  useEffect(() => {
    const container = containerRef.current
    const canvas = canvasRef.current
    if (!container || !canvas) return

    const resize = () => {
      canvas.style.width = '100%'
      rendererRef.current?.markDirty()
    }

    resize()
    const ro = new ResizeObserver(resize)
    ro.observe(container)
    window.addEventListener('resize', resize)

    return () => {
      ro.disconnect()
      window.removeEventListener('resize', resize)
    }
  }, [])

  // ── Imperative API ─────────────────────────────────────────────────
  useImperativeHandle(ref, () => ({
    zoomIn() {
      const canvas = canvasRef.current
      if (canvas && zoomRef.current)
        d3.select(canvas).transition().duration(220).call(zoomRef.current.scaleBy, 1.5)
    },
    zoomOut() {
      const canvas = canvasRef.current
      if (canvas && zoomRef.current)
        d3.select(canvas).transition().duration(220).call(zoomRef.current.scaleBy, 0.67)
    },
    fit() {
      const canvas = canvasRef.current, container = containerRef.current
      if (!canvas || !container || !zoomRef.current) return
      const ns = nodesDataRef.current
      if (!ns.length) return
      let minX = Infinity, maxX = -Infinity, minY = Infinity, maxY = -Infinity
      for (const n of ns) {
        const x = n.x ?? 0, y = n.y ?? 0
        if (x < minX) minX = x; if (x > maxX) maxX = x
        if (y < minY) minY = y; if (y > maxY) maxY = y
      }
      const W = container.clientWidth, H = graphHeight
      const pad = 100
      const bw = Math.max(maxX - minX, 1)
      const bh = Math.max(maxY - minY, 1)
      const s = Math.min((W - pad * 2) / bw, (H - pad * 2) / bh)
      const cx = (minX + maxX) / 2, cy = (minY + maxY) / 2
      d3.select(canvas).transition().duration(700).ease(d3.easeCubicInOut)
        .call(zoomRef.current.transform, d3.zoomIdentity.translate(W/2 - s*cx, H/2 - s*cy).scale(s))
    },
    restart() { simRef.current?.alpha(0.8).restart() },
    exportPNG() { rendererRef.current?.exportPNG() },
    exportSVG() {
      const container = containerRef.current
      if (!container) return
      rendererRef.current?.exportSVG(container.clientWidth, graphHeight)
    },
    focusNode(id: string) {
      const n = nodesDataRef.current.find(nd => nd.id === id)
      const canvas = canvasRef.current, container = containerRef.current
      if (!n || !canvas || !zoomRef.current || !container) return
      const W = container.clientWidth, H = graphHeight
      d3.select(canvas).transition().duration(580).ease(d3.easeCubicInOut).call(
        zoomRef.current.transform,
        d3.zoomIdentity.translate(W/2 - (n.x??0)*1.5, H/2 - (n.y??0)*1.5).scale(1.5),
      )
    },
    navigateToConnected(direction: 'next' | 'prev') {
      const selId = selIdRef.current
      if (!selId) return
      const connected = [...connectedSetRef.current]
      if (!connected.length) return
      const curIdx = connected.indexOf(selId)
      const nextIdx = direction === 'next'
        ? (curIdx + 1) % connected.length
        : (curIdx - 1 + connected.length) % connected.length
      const nextId = connected[nextIdx]
      const nextNode = nodesDataRef.current.find(n => n.id === nextId)
      if (nextNode) {
        selIdRef.current = nextId
        const conn = new Set<string>()
        for (const l of linksDataRef.current) {
          const s = getId(l.source as string | SimNode), t = getId(l.target as string | SimNode)
          if (s === nextId) conn.add(t)
          if (t === nextId) conn.add(s)
        }
        connectedSetRef.current = conn
        onSelect(nextNode)
        rendererRef.current?.setProps({
          ...propsRef.current,
          selectedId: nextId,
          connectedIds: conn,
        })
      }
    },
  }), [graphHeight, onSelect])

  // ── Main setup: sim + renderer + events ──────────────────────────
  useEffect(() => {
    const canvas = canvasRef.current, mmCanvas = mmCanvasRef.current
    const container = containerRef.current
    if (!canvas || !mmCanvas || !container || rawNodes.length === 0) return

    const W = container.clientWidth || 900
    const H = graphHeight

    // Initialise renderer
    const renderer = new GraphRenderer(canvas, mmCanvas, propsRef.current)
    rendererRef.current = renderer
    renderer.toggleFps(showFps)

    // Wire minimap click → zoom.translateTo
    renderer.onMinimapClick = (gx, gy) => {
      if (!zoomRef.current) return
      d3.select(canvas).transition().duration(350).call(
        zoomRef.current.translateTo, gx, gy,
      )
    }

    // Build sim nodes / links
    const nodes: SimNode[] = rawNodes.map(n => ({ ...n }))
    const nodeById = new Map(nodes.map(n => [n.id, n]))
    nodesDataRef.current = nodes
    renderer.setNodes(nodes)

    const links: SimLink[] = rawEdges.map(e => ({
      ...e,
      source: nodeById.get(getId(e.source)) ?? getId(e.source),
      target: nodeById.get(getId(e.target)) ?? getId(e.target),
    })) as SimLink[]
    linksDataRef.current = links
    renderer.setLinks(links)

    // Parallel edge detection
    const pCount = new Map<string, number>()
    const cIdx = new Map<string, number>()
    for (const l of links) {
      const s = getId(l.source as string | SimNode), tg = getId(l.target as string | SimNode)
      const key = [s, tg].sort().join('|')
      const idx = pCount.get(key) ?? 0
      cIdx.set(l.id, idx)
      pCount.set(key, idx + 1)
    }
    renderer.setParallelMaps(pCount, cIdx)

    // D3 zoom
    const zoom = d3.zoom<HTMLCanvasElement, unknown>()
      .scaleExtent([0.02, 16])
      .on('zoom', ev => {
        renderer.setTransform(ev.transform)
      })
    d3.select(canvas).call(zoom)
    zoomRef.current = zoom

    // ── Pre-compute degree map ─────────────────────────────────────────
    // Without degree normalization, hub nodes (40+ edges) get pulled 40×
    // harder by link forces than leaf nodes → classic AD hairball collapse.
    const degMap = new Map<string, number>()
    for (const l of links) {
      const s = getId(l.source as string | SimNode)
      const t = getId(l.target as string | SimNode)
      degMap.set(s, (degMap.get(s) ?? 0) + 1)
      degMap.set(t, (degMap.get(t) ?? 0) + 1)
    }

    const N = nodes.length
    const isLarge = N > 100, isHuge = N > 400

    // ── Initial positions ─────────────────────────────────────────────
    // Fibonacci / golden-ratio spiral starting at 2× the canvas diagonal.
    // This gives each of N nodes roughly sqrt(area/N) pixels of personal
    // space before any forces run, ensuring the final layout fills the screen.
    if (layoutMode === 'force') {
      // Per-node cell size that produces a spread filling the whole canvas
      const cellPx   = isHuge ? 160 : isLarge ? 200 : 260
      const discR    = cellPx * Math.sqrt(N) // radius of the initial disc
      const phi      = (1 + Math.sqrt(5)) / 2
      nodes.forEach((n, i) => {
        const angle = 2 * Math.PI * i / phi
        const r     = discR * Math.sqrt((i + 0.5) / N)
        n.x = W / 2 + r * Math.cos(angle)
        n.y = H / 2 + r * Math.sin(angle)
      })
    } else if (layoutMode === 'hierarchical') {
      applyHierarchical(nodes, W, H)
    } else if (layoutMode === 'radial') {
      applyRadial(nodes, W, H)
    }

    // ── Force parameters ───────────────────────────────────────────────
    // KEY FIX: theta=0.1 for small graphs (N<150) → exact N-body calculation.
    // Barnes-Hut with theta=0.9 badly underestimates repulsion inside dense
    // clusters, making them collapse. Exact calc costs O(N²) per tick but
    // for N=67 that's only ~4500 ops — completely trivial.
    const nbodyTheta = N < 150 ? 0.1 : N < 400 ? 0.45 : 0.85
    // Moderate decay: enough ticks to resolve collisions, not so many that
    // link forces collapse everything into a hairball.
    const alphaDecay = isHuge ? 0.022 : isLarge ? 0.025 : 0.028
    const velDecay   = isHuge ? 0.50  : isLarge ? 0.45  : 0.42

    const sim = d3.forceSimulation<SimNode>(nodes)
      // ── Link force ─────────────────────────────────────────────────
      // CRITICAL: distance must be >> 0. distance=0 pulls every pair to
      // the same point (force ∝ separation). Use a comfortable target gap.
      // strength=1/degree so hub nodes' total pull stays bounded.
      .force('link',
        d3.forceLink<SimNode, SimLink>(links).id(d => d.id)
          .distance(d => {
            const s  = d.source as SimNode, tg = d.target as SimNode
            const sdeg = degMap.get(s.id) ?? 1
            const tdeg = degMap.get(tg.id) ?? 1
            const base = isHuge ? 120 : isLarge ? 160 : 220
            const tierF = (s.tier === 0 || tg.tier === 0) ? 2.2
              : (s.entity_type === 'DOMAIN' || tg.entity_type === 'DOMAIN') ? 1.8
              : 1.0
            // √degree scaling: connected hubs sit further apart
            return base * Math.sqrt(Math.max(sdeg, tdeg) / 3) * tierF
          })
          .strength(d => {
            const sdeg = degMap.get(getId(d.source as string | SimNode)) ?? 1
            const tdeg = degMap.get(getId(d.target as string | SimNode)) ?? 1
            // 1/degree normalization: hub node with 40 edges → 0.025 each
            return Math.min(0.4, 1.0 / Math.max(sdeg, tdeg))
          }),
      )
      // ── Charge (repulsion) ─────────────────────────────────────────
      .force('charge',
        d3.forceManyBody<SimNode>()
          .strength(d => {
            const deg      = degMap.get(d.id) ?? 1
            const logBoost = 1 + Math.log2(deg + 1)
            const tierBoost = d.tier === 0 ? 4.5
              : (d.entity_type === 'DOMAIN' || d.entity_type === 'DC') ? 3.0
              : d.is_crown_jewel ? 2.0 : 1.0
            const base = isHuge ? -1000 : isLarge ? -3000 : -6000
            return base * logBoost * tierBoost
          })
          .distanceMax(isHuge ? 1500 : 3500)
          .theta(nbodyTheta),
      )
      .force('center', d3.forceCenter(W / 2, H / 2).strength(0.04))
      // ── Collision ──────────────────────────────────────────────────
      .force('collision',
        d3.forceCollide<SimNode>()
          .radius(d => {
            const labelLen = Math.min((d.label?.length ?? 8), 24)
            return nodeRadius(d) + labelLen * 5 + 20
          })
          .strength(1.0)
          .iterations(4),
      )
      .force('x', d3.forceX(W / 2).strength(0.006))
      .force('y', d3.forceY(H / 2).strength(0.006))
      .alphaDecay(alphaDecay)
      .velocityDecay(velDecay)

    // ── Attack-path-first layout ──────────────────────────────────────
    if (layoutMode === 'attack') {
      // Hoist path array + index map so the accessor is O(1) per node per tick
      const pathArr = [...propsRef.current.pathNodeIds]
      const pathIndexMap = new Map(pathArr.map((id, i) => [id, i]))

      sim
        .force('y', d3.forceY<SimNode>(node => {
          if ((node.tier ?? 9) === 0 || node.is_crown_jewel) return H * 0.12
          if (propsRef.current.pathNodeIds.has(node.id)) return H * 0.45
          return H * 0.78
        }).strength(0.45))
        .force('x', d3.forceX<SimNode>(node => {
          if (propsRef.current.pathNodeIds.has(node.id)) {
            const idx = pathIndexMap.get(node.id) ?? -1
            return W * 0.1 + (idx / Math.max(pathArr.length - 1, 1)) * W * 0.8
          }
          return W / 2
        }).strength(node => propsRef.current.pathNodeIds.has(node.id) ? 0.5 : 0.04))
    } else {
      // Restore soft centering for non-attack layouts (weak pull back to center)
      sim
        .force('y', d3.forceY<SimNode>(() => H / 2).strength(0.004))
        .force('x', d3.forceX<SimNode>(() => W / 2).strength(0.004))
    }

    // ── Path prominence force (active when path nodes exist) ──────────
    const prominenceForce = (alpha: number) => {
      if (!propsRef.current.pathNodeIds || propsRef.current.pathNodeIds.size === 0) return
      const cx = W / 2, cy = H / 2
      const pushRadius = Math.min(W, H) * 0.38
      const simNodes = sim.nodes()
      for (const node of simNodes) {
        if (propsRef.current.pathNodeIds.has(node.id)) {
          node.vx! += (cx - (node.x ?? cx)) * 0.03 * alpha
          node.vy! += (cy - (node.y ?? cy)) * 0.03 * alpha
        } else {
          const dx = (node.x ?? cx) - cx
          const dy = (node.y ?? cy) - cy
          const dist = Math.sqrt(dx * dx + dy * dy) || 1
          if (dist < pushRadius) {
            node.vx! += (dx / dist) * (pushRadius - dist) * 0.015 * alpha
            node.vy! += (dy / dist) * (pushRadius - dist) * 0.015 * alpha
          }
        }
      }
    }
    sim.force('prominence', prominenceForce)

    simRef.current = sim

    // ── Auto-fit helper ────────────────────────────────────────────────
    // Scales the view so ALL nodes fill the canvas with padding.
    // No upper-bound cap: if nodes are well-spread the view zooms in
    // to make them fill the screen, not shrink them into a corner.
    const autoFit = (animated: boolean) => {
      const ns = nodesDataRef.current
      if (!ns.length || !canvas || !zoomRef.current) return
      let minX = Infinity, maxX = -Infinity, minY = Infinity, maxY = -Infinity
      for (const n of ns) {
        const x = n.x ?? 0, y = n.y ?? 0
        if (x < minX) minX = x; if (x > maxX) maxX = x
        if (y < minY) minY = y; if (y > maxY) maxY = y
      }
      const pad = 100
      const bw = Math.max(maxX - minX, 1)
      const bh = Math.max(maxY - minY, 1)
      // Scale to fill canvas while preserving aspect ratio
      const s = Math.min((W - pad * 2) / bw, (H - pad * 2) / bh)
      const cx = (minX + maxX) / 2
      const cy = (minY + maxY) / 2
      const tx = W / 2 - s * cx
      const ty = H / 2 - s * cy
      const tr = d3.zoomIdentity.translate(tx, ty).scale(s)
      if (animated) {
        d3.select(canvas).transition().duration(900).ease(d3.easeCubicInOut)
          .call(zoomRef.current.transform, tr)
      } else {
        d3.select(canvas).call(zoomRef.current.transform, tr)
      }
    }

    // ── Sim tick → render throttle ─────────────────────────────────
    const frameMs = isHuge ? 48 : isLarge ? 28 : 18
    let lastRender = 0
    let tickCount = 0
    sim.on('tick', () => {
      tickCount++
      if (tickCount % 4 === 0) onSimProgress(sim.alpha())
      const simulating = sim.alpha() > 0.04
      if (simulating !== propsRef.current.isSimulating) {
        renderer.setProps({ ...propsRef.current, isSimulating: simulating })
      }
      const now = performance.now()
      if (now - lastRender >= frameMs) { lastRender = now; renderer.markDirty() }
    })
    sim.on('end', () => {
      onSimProgress(0)
      renderer.setProps({ ...propsRef.current, isSimulating: false })
      renderer.markDirty()
      // Fit to full spread once sim has settled
      autoFit(true)
    })

    // Also fit after 1.5s in case the sim takes longer (large graphs)
    const fitTimer = setTimeout(() => autoFit(true), 1500)

    // ── Mouse events ──────────────────────────────────────────────
    let isDragging = false, dragNode: SimNode | null = null
    let boxStart: [number, number] | null = null
    const ac = new AbortController()
    const opts = { signal: ac.signal }

    canvas.addEventListener('mousemove', ev => {
      if (isDragging && dragNode) {
        const [gx, gy] = renderer['transform'].invert([ev.offsetX, ev.offsetY])
        dragNode.fx = gx; dragNode.fy = gy
        sim.alphaTarget(0.12).restart()
        renderer.markDirty()
        return
      }
      const node = renderer.getNodeAt(ev.offsetX, ev.offsetY)
      if (node) {
        canvas.style.cursor = 'pointer'
        onEdgeHover(null, 0, 0)
      } else {
        canvas.style.cursor = renderProps.selectedId ? 'default' : 'default'
        const edge = renderer.getEdgeAt(ev.offsetX, ev.offsetY)
        if (edge) {
          canvas.style.cursor = 'pointer'
          onEdgeHover(edge as GraphEdge, ev.offsetX, ev.offsetY)
        } else {
          onEdgeHover(null, 0, 0)
        }
      }
    }, opts)

    canvas.addEventListener('mousedown', ev => {
      if (ev.button !== 0) return
      const node = renderer.getNodeAt(ev.offsetX, ev.offsetY)
      if (node) {
        isDragging = true; dragNode = node
        dragNode.fx = dragNode.x; dragNode.fy = dragNode.y
      } else if (ev.shiftKey || propsRef.current.selectedId === null) {
        boxStart = [ev.offsetX, ev.offsetY]
      }
    }, opts)

    canvas.addEventListener('mouseup', ev => {
      if (isDragging && dragNode) {
        sim.alphaTarget(0)
        if (!pinnedIds.current.has(dragNode.id)) { dragNode.fx = null; dragNode.fy = null }
        isDragging = false; dragNode = null
        return
      }
      if (boxStart) {
        const bx = Math.min(ev.offsetX, boxStart[0]), by = Math.min(ev.offsetY, boxStart[1])
        const bw = Math.abs(ev.offsetX - boxStart[0]), bh = Math.abs(ev.offsetY - boxStart[1])
        boxStart = null
        if (bw >= 6 && bh >= 6) {
          const sel = new Set<string>()
          const tr = renderer['transform']
          for (const nd of nodesDataRef.current) {
            const [sx, sy] = tr.apply([nd.x??0, nd.y??0])
            if (sx >= bx && sx <= bx+bw && sy >= by && sy <= by+bh) sel.add(nd.id)
          }
          if (sel.size) onMultiSelect(sel)
        }
      }
    }, opts)

    canvas.addEventListener('click', ev => {
      if (isDragging) return
      ev.stopPropagation()
      const node = renderer.getNodeAt(ev.offsetX, ev.offsetY)
      if (node) {
        if (selIdRef.current === node.id) {
          selIdRef.current = null; connectedSetRef.current = new Set()
          onSelect(null)
          renderer.setProps({ ...propsRef.current, selectedId: null, connectedIds: new Set() })
        } else {
          selIdRef.current = node.id
          const conn = new Set<string>()
          for (const l of linksDataRef.current) {
            const s = getId(l.source as string | SimNode), t = getId(l.target as string | SimNode)
            if (s === node.id) conn.add(t)
            if (t === node.id) conn.add(s)
          }
          connectedSetRef.current = conn
          onSelect(node)
          renderer.setProps({ ...propsRef.current, selectedId: node.id, connectedIds: conn })
        }
        renderer.markDirty()
      } else {
        const edge = renderer.getEdgeAt(ev.offsetX, ev.offsetY)
        if (edge) {
          onEdgeClick(edge as GraphEdge)
        } else {
          selIdRef.current = null; connectedSetRef.current = new Set()
          onSelect(null)
          renderer.setProps({ ...propsRef.current, selectedId: null, connectedIds: new Set() })
          renderer.markDirty()
        }
      }
    }, opts)

    canvas.addEventListener('dblclick', ev => {
      const node = renderer.getNodeAt(ev.offsetX, ev.offsetY)
      if (!node) return
      ev.stopPropagation()
      onPinToggle(node.id)
      if (pinnedIds.current.has(node.id)) {
        pinnedIds.current.delete(node.id); node.fx = null; node.fy = null
        toast('Node unpinned', { duration: 1200 })
      } else {
        pinnedIds.current.add(node.id); node.fx = node.x; node.fy = node.y
        toast('Node pinned', { duration: 1200 })
      }
      renderer.setProps({ ...propsRef.current, pinnedIds: new Set(pinnedIds.current) })
      renderer.markDirty()
    }, opts)

    canvas.addEventListener('contextmenu', ev => {
      ev.preventDefault()
      const node = renderer.getNodeAt(ev.offsetX, ev.offsetY)
      if (node) onContextMenu({ x: ev.offsetX, y: ev.offsetY, node })
    }, opts)

    canvas.addEventListener('mouseleave', () => {
      onEdgeHover(null, 0, 0)
      if (isDragging && dragNode) {
        sim.alphaTarget(0)
        if (!pinnedIds.current.has(dragNode.id)) { dragNode.fx = null; dragNode.fy = null }
        isDragging = false; dragNode = null
      }
    }, opts)

    // Initial render
    renderer.markDirty()

    return () => {
      sim.stop()
      clearTimeout(fitTimer)
      ac.abort()
      d3.select(canvas).on('.zoom', null)
      renderer.destroy()
      rendererRef.current = null
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [rawNodes, rawEdges, layoutMode, graphHeight])

  return (
    <div
      ref={containerRef}
      role="application"
      aria-label="Active Directory relationship graph. Use arrow keys to navigate, right-click nodes for actions."
      className="relative w-full select-none overflow-hidden"
      style={{ height: graphHeight }}
    >
      <canvas
        ref={canvasRef}
        className="block !w-full"
        tabIndex={0}
        aria-label="Graph canvas"
        style={{ display: 'block', outline: 'none', width: '100%' }}
      />

      {/* Minimap */}
      <AnimatePresence>
        {showMinimap && (
          <motion.div
            initial={{ opacity: 0, scale: 0.88, y: 8 }}
            animate={{ opacity: 1, scale: 1, y: 0 }}
            exit={{ opacity: 0, scale: 0.88, y: 8 }}
            transition={{ duration: 0.18 }}
            className="absolute bottom-14 right-4 overflow-hidden rounded-xl shadow-2xl cursor-pointer"
            title="Click to pan graph"
          >
            <canvas
              ref={mmCanvasRef}
              width={MM_W}
              height={118}
              className="block"
            />
          </motion.div>
        )}
      </AnimatePresence>

      {/* Minimap toggle */}
      <button
        onClick={() => setShowMinimap(p => !p)}
        title={showMinimap ? 'Hide mini-map' : 'Show mini-map'}
        aria-label={showMinimap ? 'Hide mini-map' : 'Show mini-map'}
        className="absolute bottom-4 right-4 rounded-xl border border-white/10 bg-black/80 p-2 text-zinc-400 backdrop-blur transition hover:bg-black hover:text-white"
      >
        <MapIcon className="h-3.5 w-3.5" />
      </button>
    </div>
  )
})
