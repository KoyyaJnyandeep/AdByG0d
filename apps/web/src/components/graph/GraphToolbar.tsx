'use client'

import { useState } from 'react'
import {
  Search, Filter, Network, Shield, SlidersHorizontal,
  Activity, Eye, Layers, X, Bookmark, Clock, Sparkles, AlertTriangle, Radio,
  Maximize2, Minimize2,
} from 'lucide-react'
import { motion, AnimatePresence } from 'framer-motion'
import type { ColorMode, GraphMode, GraphToggles, LayoutMode } from './engine/types'
import { MODE_PRESETS } from './GraphModes'
import { cn } from '@/lib/utils'

interface GraphToolbarProps {
  searchInput: string
  onSearchChange: (v: string) => void
  tier0Only: boolean
  onTier0Toggle: () => void
  edgeTypeFilter: Set<string>
  allEdgeTypes: string[]
  onEdgeTypeFilterChange: (types: Set<string>) => void
  layoutMode: LayoutMode
  onLayoutChange: (m: LayoutMode) => void
  colorMode: ColorMode
  onColorModeChange: (m: ColorMode) => void
  showEdgeLabels: boolean
  onEdgeLabelsToggle: () => void
  sizeByDegree: boolean
  onSizeByDegreeToggle: () => void
  showParticles: boolean
  onParticlesToggle: () => void
  toggles: GraphToggles
  onToggleChange: (key: keyof GraphToggles) => void
  graphMode: GraphMode | null
  onModeChange: (mode: GraphMode | null) => void
  minRiskFilter: number
  onMinRiskChange: (v: number) => void
  isFullscreen: boolean
  onToggleFullscreen: () => void
  showViews: boolean
  onViewsToggle: () => void
  showTimeline: boolean
  onTimelineToggle: () => void
  showNlBar: boolean
  onNlBarToggle: () => void
  showAnomalyFeed: boolean
  onAnomalyFeedToggle: () => void
  streamActive: boolean
  onStreamToggle: () => void
}

function ToolbarBtn({
  active, onClick, icon, label, shortcut, danger = false,
}: {
  active: boolean; onClick: () => void; icon: React.ReactNode; label: string
  shortcut?: string; danger?: boolean
}) {
  return (
    <button onClick={onClick} title={shortcut ? `${label} [${shortcut}]` : label} aria-label={label}
      aria-pressed={active}
      className={cn(
        'inline-flex items-center gap-1.5 rounded-xl border px-2.5 py-1.5 text-[11px] font-medium transition-all whitespace-nowrap',
        active
          ? danger
            ? 'border-red-500/35 bg-red-500/15 text-red-300'
            : 'border-cyan-400/30 bg-cyan-400/12 text-cyan-200'
          : 'border-white/10 bg-black text-zinc-400 hover:border-white/18 hover:bg-white/[0.06] hover:text-zinc-200',
      )}>
      {icon}
      <span className="hidden sm:inline">{label}</span>
    </button>
  )
}

const MODE_ICON_MAP: Record<GraphMode, React.ReactNode> = {
  ExposureOverview: <Activity className="h-3 w-3" />,
  Tier0Path: <Shield className="h-3 w-3" />,
  ADCSView: <Layers className="h-3 w-3" />,
  DelegationView: <Network className="h-3 w-3" />,
  LateralMovement: <SlidersHorizontal className="h-3 w-3" />,
  GroupMembership: <Filter className="h-3 w-3" />,
  RemediationSim: <Eye className="h-3 w-3" />,
}

export function GraphToolbar(props: GraphToolbarProps) {
  const [showFilterPanel, setShowFilterPanel] = useState(false)
  const [showModePanel, setShowModePanel] = useState(false)
  const [showTogglePanel, setShowTogglePanel] = useState(false)
  const {
    searchInput, onSearchChange, tier0Only, onTier0Toggle,
    edgeTypeFilter, allEdgeTypes, onEdgeTypeFilterChange,
    layoutMode, onLayoutChange,
    showEdgeLabels, onEdgeLabelsToggle,
    toggles, onToggleChange,
    graphMode, onModeChange, minRiskFilter, onMinRiskChange, isFullscreen, onToggleFullscreen,
    showViews, onViewsToggle, showTimeline, onTimelineToggle,
    showNlBar, onNlBarToggle, showAnomalyFeed, onAnomalyFeedToggle,
    streamActive, onStreamToggle,
  } = props

  const TOGGLE_LABELS: { key: keyof GraphToggles; label: string }[] = [
    { key: 'attackEdgesOnly', label: 'Attack Edges Only' },
    { key: 'hideMembership', label: 'Hide Membership Edges' },
    { key: 'hideLowRisk', label: 'Hide Low Risk (< 30%)' },
    { key: 'collapseGroups', label: 'Collapse Groups' },
    { key: 'tier0PathsOnly', label: 'Only Paths to Tier-0' },
    { key: 'showContainers', label: 'Show OU Containers' },
    { key: 'bundleEdges', label: 'Bundle Parallel Edges' },
    { key: 'showHeatMap', label: 'Choke Point Heat Map' },
    { key: 'showProvenance', label: 'Edge Provenance Overlay' },
  ]

  return (
    <div className={cn(
      'mb-4 flex flex-wrap items-center gap-2 rounded-[20px] border border-white/10 bg-black p-3',
      isFullscreen && 'mx-4 mt-4',
    )}>
      {/* Search */}
      <div className="relative min-w-[180px] flex-1">
        <Search className="absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-zinc-500" />
        <input value={searchInput} onChange={e => onSearchChange(e.target.value)}
          placeholder="Filter entities…"
          className="w-full rounded-xl border border-white/10 bg-black py-2 pl-9 pr-3 text-sm text-white outline-none placeholder:text-zinc-600 focus:border-cyan-400/25 transition-colors" />
      </div>

      {/* Graph Modes */}
      <div className="relative">
        <button
          onClick={() => setShowModePanel(p => !p)}
          className={cn(
            'inline-flex items-center gap-1.5 rounded-xl border px-2.5 py-1.5 text-[11px] font-medium transition-all',
            graphMode
              ? 'border-purple-400/30 bg-purple-400/12 text-purple-200'
              : 'border-white/10 bg-black text-zinc-400 hover:border-white/18 hover:bg-white/[0.06] hover:text-zinc-200',
          )}
        >
          <Layers className="h-3.5 w-3.5" />
          <span className="hidden sm:inline">{graphMode ? MODE_PRESETS[graphMode].label : 'Mode'}</span>
        </button>
        <AnimatePresence>
          {showModePanel && (
            <motion.div initial={{ opacity: 0, y: -6 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -6 }}
              className="absolute top-full mt-2 left-0 z-30 w-56 rounded-2xl border border-white/10 bg-zinc-950/97 py-1.5 shadow-2xl backdrop-blur">
              {graphMode && (
                <button onClick={() => { onModeChange(null); setShowModePanel(false) }}
                  className="w-full px-3 py-2 text-left text-[11px] text-red-400 hover:bg-white/5 flex items-center gap-2">
                  <X className="h-3 w-3" /> Clear Mode
                </button>
              )}
              {Object.values(MODE_PRESETS).map(p => (
                <button key={p.mode} onClick={() => { onModeChange(p.mode); setShowModePanel(false) }}
                  className={cn(
                    'w-full px-3 py-2 text-left hover:bg-white/5 transition',
                    graphMode === p.mode && 'bg-purple-500/10',
                  )}>
                  <div className="flex items-center gap-2">
                    <span className="text-purple-400">{MODE_ICON_MAP[p.mode]}</span>
                    <span className="text-[11px] font-semibold text-zinc-200">{p.label}</span>
                  </div>
                  <div className="text-[9px] text-zinc-600 mt-0.5 pl-5">{p.description}</div>
                </button>
              ))}
            </motion.div>
          )}
        </AnimatePresence>
      </div>

      <ToolbarBtn active={tier0Only} onClick={onTier0Toggle}
        icon={<Shield className="h-3.5 w-3.5" />} label="Tier-0" />

      {/* Edge type filter */}
      <div className="relative">
        <ToolbarBtn active={showFilterPanel || edgeTypeFilter.size > 0}
          onClick={() => setShowFilterPanel(p => !p)}
          icon={<Filter className="h-3.5 w-3.5" />}
          label={edgeTypeFilter.size > 0 ? `Filter (${edgeTypeFilter.size})` : 'Filter'} />
        <AnimatePresence>
          {showFilterPanel && (
            <motion.div initial={{ opacity: 0, y: -6 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -6 }}
              className="absolute top-full mt-2 left-0 z-30 w-60 rounded-2xl border border-white/10 bg-zinc-950/97 p-3 shadow-2xl backdrop-blur">
              <div className="text-[9px] uppercase tracking-widest text-zinc-500 mb-2">Edge Types</div>
              <div className="mb-2">
                <input placeholder="Min risk %" type="number" min={0} max={100}
                  value={Math.round(minRiskFilter * 100) || ''}
                  onChange={e => onMinRiskChange((parseInt(e.target.value) || 0) / 100)}
                  className="w-full rounded-lg border border-white/10 bg-black/60 px-2 py-1 text-[11px] text-white outline-none placeholder:text-zinc-600" />
              </div>
              <div className="max-h-48 overflow-y-auto space-y-1">
                {allEdgeTypes.map(t => (
                  <label key={t} className="flex items-center gap-2 cursor-pointer rounded-lg px-2 py-1 hover:bg-white/6">
                    <input type="checkbox" checked={edgeTypeFilter.has(t)}
                      onChange={() => {
                        const s = new Set(edgeTypeFilter)
                        if (s.has(t)) { s.delete(t) } else { s.add(t) }
                        onEdgeTypeFilterChange(s)
                      }}
                      className="h-3 w-3 accent-cyan-400" />
                    <span className="text-[11px] text-zinc-300 truncate">{t}</span>
                  </label>
                ))}
              </div>
              {edgeTypeFilter.size > 0 && (
                <button onClick={() => onEdgeTypeFilterChange(new Set())}
                  className="mt-2 w-full text-[10px] text-red-400 hover:text-red-300 transition">
                  Clear filters
                </button>
              )}
            </motion.div>
          )}
        </AnimatePresence>
      </div>

      <div className="h-5 w-px bg-white/10" />

      {/* Layout */}
      {(['force', 'hierarchical', 'radial', 'attack'] as LayoutMode[]).map(m => (
        <ToolbarBtn key={m} active={layoutMode === m} onClick={() => onLayoutChange(m)}
          icon={<Network className="h-3.5 w-3.5" />}
          label={m === 'attack' ? 'Attack' : m.charAt(0).toUpperCase() + m.slice(1)} />
      ))}

      <div className="h-5 w-px bg-white/10" />

      <ToolbarBtn active={showEdgeLabels} onClick={onEdgeLabelsToggle}
        shortcut="L" icon={<Eye className="h-3.5 w-3.5" />} label="Labels" />

      <ToolbarBtn active={showViews} onClick={onViewsToggle}
        icon={<Bookmark className="h-3.5 w-3.5" />} label="Views" />

      <ToolbarBtn active={showTimeline} onClick={onTimelineToggle}
        icon={<Clock className="h-3.5 w-3.5" />} label="Timeline" />

      <ToolbarBtn active={showNlBar} onClick={onNlBarToggle}
        icon={<Sparkles className="h-3.5 w-3.5" />} label="AI Query" />
      <ToolbarBtn active={showAnomalyFeed} onClick={onAnomalyFeedToggle}
        icon={<AlertTriangle className="h-3.5 w-3.5" />} label="Anomalies" />
      <ToolbarBtn active={streamActive} onClick={onStreamToggle}
        icon={<Radio className={cn("h-3.5 w-3.5", streamActive && "animate-pulse")} />}
        label={streamActive ? 'Live' : 'Stream'} />

      <div className="h-5 w-px bg-white/10" />

      {/* Fullscreen toggle */}
      <button
        onClick={onToggleFullscreen}
        title={isFullscreen ? 'Exit fullscreen [F]' : 'Fullscreen [F]'}
        aria-label={isFullscreen ? 'Exit fullscreen' : 'Enter fullscreen'}
        className={cn(
          'inline-flex items-center gap-1.5 rounded-xl border px-2.5 py-1.5 text-[11px] font-medium transition-all whitespace-nowrap',
          isFullscreen
            ? 'border-cyan-400/30 bg-cyan-400/12 text-cyan-200'
            : 'border-white/10 bg-black text-zinc-400 hover:border-white/18 hover:bg-white/[0.06] hover:text-zinc-200',
        )}
      >
        {isFullscreen
          ? <Minimize2 className="h-3.5 w-3.5" />
          : <Maximize2 className="h-3.5 w-3.5" />}
        <span className="hidden sm:inline">{isFullscreen ? 'Exit' : 'Fullscreen'}</span>
      </button>

      {/* Toggles panel */}
      <div className="relative">
        <ToolbarBtn
          active={showTogglePanel || Object.values(toggles).some(Boolean)}
          onClick={() => setShowTogglePanel(p => !p)}
          icon={<SlidersHorizontal className="h-3.5 w-3.5" />}
          label={Object.values(toggles).filter(Boolean).length > 0
            ? `Toggles (${Object.values(toggles).filter(Boolean).length})`
            : 'Toggles'} />
        <AnimatePresence>
          {showTogglePanel && (
            <motion.div initial={{ opacity: 0, y: -6 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -6 }}
              className="absolute top-full mt-2 right-0 z-30 w-64 rounded-2xl border border-white/10 bg-zinc-950/97 p-3 shadow-2xl backdrop-blur">
              <div className="text-[9px] uppercase tracking-widest text-zinc-500 mb-2">Graph Toggles</div>
              <div className="space-y-1">
                {TOGGLE_LABELS.map(({ key, label }) => (
                  <label key={key} className="flex items-center gap-2 cursor-pointer rounded-lg px-2 py-1.5 hover:bg-white/6">
                    <input type="checkbox" checked={toggles[key] as boolean}
                      onChange={() => onToggleChange(key)}
                      className="h-3 w-3 accent-cyan-400" />
                    <span className="text-[11px] text-zinc-300">{label}</span>
                  </label>
                ))}
              </div>
            </motion.div>
          )}
        </AnimatePresence>
      </div>
    </div>
  )
}
