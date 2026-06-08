"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  Activity, BrainCircuit, ChevronDown, ChevronUp,
  FlaskConical, Layers3, Map, Network,
  ScrollText, Shield, Sparkles, Target, Zap,
} from "lucide-react";

import { AppShell } from "@/components/layout/AppShell";
import { useRouteAssessmentScope } from "@/lib/useRouteAssessmentScope";
import { cn } from "@/lib/utils";

import { fetchModules, fetchPostureTimeline } from "./lib/api";
import type { ExpertDecision, FusionResult } from "./lib/types";

import ModuleGrid from "./components/ModuleGrid";
import RunPanel from "./components/RunPanel";
import VerdictPanel from "./components/VerdictPanel";
import ExpertDecisionList from "./components/ExpertDecisionList";
import KillChainView from "./components/KillChainView";
import BlastRadiusPanel from "./components/BlastRadiusPanel";
import HeatMap from "./components/HeatMap";
import PostureTimeline from "./components/PostureTimeline";
import SyntheticDataPanel from "./components/SyntheticDataPanel";
import AttackGraph from "./components/AttackGraph";
import RunComparison from "./components/RunComparison";
import PlaybookPanel from "./components/PlaybookPanel";
import NarrativePanel from "./components/NarrativePanel";
import MitrePanel from "./components/MitrePanel";

type Tab = "modules" | "graph" | "heatmap" | "timeline" | "compare" | "killchain" | "blast" | "playbook" | "narrative" | "mitre" | "synthetic";
type RunMode = "live" | "synthetic";

const TABS: Array<{ id: Tab; label: string; icon: React.ElementType }> = [
  { id: "modules", label: "Modules", icon: Layers3 },
  { id: "graph", label: "Graph", icon: Network },
  { id: "heatmap", label: "Heat Map", icon: Map },
  { id: "timeline", label: "Timeline", icon: Activity },
  { id: "compare", label: "Compare", icon: Activity },
  { id: "killchain", label: "Kill Chain", icon: Target },
  { id: "blast", label: "Blast Radius", icon: Zap },
  { id: "playbook", label: "Playbook", icon: ScrollText },
  { id: "narrative", label: "Narrative", icon: ScrollText },
  { id: "mitre", label: "MITRE", icon: Shield },
  { id: "synthetic", label: "Synthetic", icon: FlaskConical },
];

export default function ExposureValidationPage() {
  const { assessmentId } = useRouteAssessmentScope();

  const [activeTab, setActiveTab] = useState<Tab>("modules");
  const [runMode, setRunMode] = useState<RunMode>("live");

  const [selectedModuleId, setSelectedModuleId] = useState<string | null>(null);
  const [syntheticPreset, setSyntheticPreset] = useState<string | undefined>(undefined);

  // Run-All state
  const [, setRunAllQueue] = useState<string[]>([]);
  const [isRunningAll, setIsRunningAll] = useState(false);
  const [runAllProgress, setRunAllProgress] = useState({ done: 0, total: 0 });

  // Results cache: moduleId -> FusionResult
  const [results, setResults] = useState<Record<string, FusionResult>>({});
  const [activeResult, setActiveResult] = useState<FusionResult | null>(null);
  const [runningModuleId, setRunningModuleId] = useState<string | null>(null);

  // Expert decisions for the active run
  const [decisions, setDecisions] = useState<ExpertDecision[]>([]);

  // Drawer state
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [triggerRun, setTriggerRun] = useState(0); // bump to re-trigger RunPanel

  const { data: modules = [] } = useQuery({
    queryKey: ["v2-modules"],
    queryFn: fetchModules,
    staleTime: 5 * 60_000,
  });

  const { data: timelineData } = useQuery({
    queryKey: ["v2-posture-timeline", assessmentId],
    queryFn: () => fetchPostureTimeline(assessmentId!),
    enabled: !!assessmentId,
    staleTime: 30_000,
  });

  // Auto-select first module
  useEffect(() => {
    if (!selectedModuleId && modules.length > 0) {
      setSelectedModuleId(modules[0].id);
    }
  }, [modules, selectedModuleId]);

  const selectedModule = useMemo(
    () => modules.find((m) => m.id === selectedModuleId) ?? modules[0] ?? null,
    [modules, selectedModuleId]
  );

  const handleModuleSelect = useCallback(
    (moduleId: string) => {
      setSelectedModuleId(moduleId);
      setActiveResult(results[moduleId] ?? null);
      setDecisions([]);
    },
    [results]
  );

  const handleRunModule = useCallback(
    (moduleId: string, preset?: string) => {
      setSelectedModuleId(moduleId);
      setSyntheticPreset(preset);
      setRunningModuleId(moduleId);
      setDecisions([]);
      setDrawerOpen(true);
      setTriggerRun((n) => n + 1);
    },
    []
  );

  const handleRunComplete = useCallback(
    (result: FusionResult) => {
      const mid = result.module_id ?? selectedModuleId ?? "";
      setResults((prev) => ({ ...prev, [mid]: result }));
      setActiveResult(result);
      setRunningModuleId(null);
    },
    [selectedModuleId]
  );

  // Run-all: fires after each module completes, advances to next in queue
  const handleRunAllComplete = useCallback(
    (result: FusionResult) => {
      const mid = result.module_id ?? selectedModuleId ?? "";
      setResults((prev) => ({ ...prev, [mid]: result }));
      setActiveResult(result);
      setRunningModuleId(null);
      setRunAllProgress((p) => ({ ...p, done: p.done + 1 }));

      setRunAllQueue((queue) => {
        if (queue.length === 0) {
          setIsRunningAll(false);
          return [];
        }
        const [next, ...rest] = queue;
        // Kick off the next module on the next tick so state settles.
        setTimeout(() => {
          setSelectedModuleId(next);
          setRunningModuleId(next);
          setTriggerRun((n) => n + 1);
          setDrawerOpen(true);
        }, 50);
        return rest;
      });
    },
    [selectedModuleId]
  );

  const handleRunAll = useCallback(() => {
    if (modules.length === 0 || !assessmentId) return;
    const ids = modules.map((m) => m.id);
    const [first, ...rest] = ids;
    setRunAllQueue(rest);
    setIsRunningAll(true);
    setRunAllProgress({ done: 0, total: ids.length });
    setSelectedModuleId(first);
    setSyntheticPreset(undefined);
    setRunningModuleId(first);
    setDecisions([]);
    setDrawerOpen(true);
    setTriggerRun((n) => n + 1);
  }, [modules, assessmentId]);

  const handleStop = useCallback(() => {
    setRunningModuleId(null);
    setIsRunningAll(false);
    setRunAllQueue([]);
  }, []);

  const timelineRuns = timelineData?.runs ?? [];
  const isRunning = runningModuleId !== null;
  const comparisonRuns = useMemo(() => {
    const values = Object.values(results);
    return {
      before: values.length >= 2 ? values[values.length - 2] : null,
      after: values.length >= 1 ? values[values.length - 1] : null,
    };
  }, [results]);

  return (
    <AppShell>
      <div className="flex h-full min-h-0 flex-col">
        {/* ── Header ────────────────────────────────────────── */}
        <div className="flex shrink-0 items-center gap-3 border-b border-white/10 px-6 py-3">
          <div className="flex items-center gap-2">
            <BrainCircuit className="h-5 w-5 text-purple-400" />
            <span className="text-base font-bold text-white">Exposure Validation</span>
          </div>

          {/* Run All */}
          <button
            onClick={isRunningAll ? handleStop : handleRunAll}
            disabled={!assessmentId || (isRunning && !isRunningAll)}
            className={cn(
              "flex items-center gap-2 rounded-lg px-4 py-2 text-sm font-semibold transition-all",
              isRunningAll
                ? "bg-orange-600 text-white shadow-lg shadow-orange-900/30 hover:bg-red-600"
                : isRunning
                  ? "cursor-not-allowed bg-gray-800 text-gray-500"
                  : "bg-purple-600 text-white shadow-lg shadow-purple-900/30 hover:bg-purple-500"
            )}
          >
            {isRunningAll ? (
              <>
                <Sparkles className="h-4 w-4 animate-spin" />
                <span>{runAllProgress.done}/{runAllProgress.total}</span>
                <span className="text-xs opacity-70">Stop</span>
              </>
            ) : (
              <><Zap className="h-4 w-4" /> Run All</>
            )}
          </button>
        </div>

        {/* ── Tabs ──────────────────────────────────────────── */}
        <div className="flex shrink-0 items-center gap-0.5 overflow-x-auto border-b border-white/10 px-4">
          {TABS.map(({ id, label, icon: Icon }) => (
            <button
              key={id}
              onClick={() => setActiveTab(id)}
              className={cn(
                "flex items-center gap-1.5 whitespace-nowrap border-b-2 px-3 py-2.5 text-xs font-medium transition-all",
                activeTab === id
                  ? "border-purple-500 text-white"
                  : "border-transparent text-gray-500 hover:text-gray-300"
              )}
            >
              <Icon className="h-3.5 w-3.5" />
              {label}
            </button>
          ))}
        </div>

        {/* ── Tab content ───────────────────────────────────── */}
        <div className="min-h-0 flex-1 overflow-y-auto px-6 py-4">
          {activeTab === "modules" && (
            <div className="flex flex-col gap-4 lg:flex-row">
              <div className="min-w-0 flex-1">
                <ModuleGrid
                  modules={modules}
                  results={results}
                  activeModuleId={selectedModuleId}
                  runningModuleId={runningModuleId}
                  onSelectModule={handleModuleSelect}
                />
              </div>
              {activeResult && (
                <div className="flex w-full shrink-0 flex-col gap-4 lg:w-[380px]">
                  <VerdictPanel result={activeResult} moduleId={selectedModuleId ?? ""} />
                  {decisions.length > 0 && (
                    <ExpertDecisionList decisions={decisions} moduleId={selectedModuleId ?? ""} />
                  )}
                </div>
              )}
            </div>
          )}

          {activeTab === "heatmap" && (
            <HeatMap
              modules={modules}
              results={results}
              onCellClick={(moduleId) => {
                handleModuleSelect(moduleId);
                setActiveTab("modules");
              }}
            />
          )}

          {activeTab === "graph" && (
            <AttackGraph result={activeResult} />
          )}

          {activeTab === "timeline" && (
            <PostureTimeline
              runs={timelineRuns}
              assessmentId={assessmentId ?? ""}
            />
          )}

          {activeTab === "compare" && (
            <RunComparison before={comparisonRuns.before} after={comparisonRuns.after} />
          )}

          {activeTab === "killchain" && (
            <KillChainView
              killChains={activeResult?.kill_chains ?? []}
              threatActors={activeResult?.threat_actor_matches ?? []}
            />
          )}

          {activeTab === "blast" && (
            activeResult?.blast_radius
              ? <BlastRadiusPanel blastRadius={activeResult.blast_radius} />
              : <div className="py-16 text-center text-sm text-gray-600">Run a module to see blast radius analysis.</div>
          )}

          {activeTab === "playbook" && <PlaybookPanel result={activeResult} />}
          {activeTab === "narrative" && <NarrativePanel result={activeResult} />}
          {activeTab === "mitre" && <MitrePanel result={activeResult} />}

          {activeTab === "synthetic" && (
            <div className="flex flex-col gap-3">
              {/* Module selector for synthetic runs */}
              <div className="flex items-center gap-2">
                <span className="text-xs text-gray-500">Target module:</span>
                <select
                  value={selectedModuleId ?? ""}
                  onChange={(e) => setSelectedModuleId(e.target.value)}
                  className="rounded border border-white/10 bg-black/30 px-2 py-1 text-xs text-gray-300"
                >
                  {modules.map((m) => (
                    <option key={m.id} value={m.id}>{m.name}</option>
                  ))}
                </select>
              </div>
              <SyntheticDataPanel
                isRunning={isRunning}
                onRunPreset={(presetName) => {
                  setRunMode("synthetic");
                  setSyntheticPreset(presetName);
                  handleRunModule(selectedModuleId ?? modules[0]?.id ?? "", presetName);
                  setActiveTab("modules");
                }}
                onCustomGenerate={() => {
                  // Custom configs run as "custom" preset via API.
                  setRunMode("synthetic");
                  handleRunModule(selectedModuleId ?? modules[0]?.id ?? "", "pentest_target");
                  setActiveTab("modules");
                }}
              />
            </div>
          )}
        </div>

        {/* ── Bottom drawer: RunPanel ────────────────────────── */}
        <div
          className={cn(
            "shrink-0 border-t border-white/10 bg-black/20 transition-all duration-300",
            drawerOpen ? "h-[min(720px,calc(100vh-11rem))] min-h-[420px]" : "h-10"
          )}
        >
          <button
            onClick={() => setDrawerOpen((v) => !v)}
            className="flex h-10 w-full items-center justify-between px-4 text-xs text-gray-500 transition-colors hover:text-gray-300"
          >
            <div className="flex items-center gap-2">
              <Network className="h-3.5 w-3.5" />
              <span className="font-medium">
                {isRunning ? `Running ${selectedModule?.name ?? "..."}` : "Run Panel"}
              </span>
              {isRunning && <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-green-400" />}
            </div>
            {drawerOpen ? <ChevronDown className="h-4 w-4" /> : <ChevronUp className="h-4 w-4" />}
          </button>

          {drawerOpen && selectedModule && (
            <div className="h-[calc(100%-2.5rem)] overflow-hidden">
              <RunPanel
                key={`${selectedModule.id}-${triggerRun}`}
                moduleId={selectedModule.id}
                assessmentId={assessmentId ?? ""}
                syntheticPreset={runMode === "synthetic" ? syntheticPreset : undefined}
                onComplete={isRunningAll ? handleRunAllComplete : handleRunComplete}
                onStop={handleStop}
                isOpen={drawerOpen}
              />
            </div>
          )}
        </div>
      </div>
    </AppShell>
  );
}
