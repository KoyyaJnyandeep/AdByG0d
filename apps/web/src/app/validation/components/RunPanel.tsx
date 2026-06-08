"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import { createSSEStream, runSyntheticSimulation, subscribeToStream, syntheticToFusionResult } from "../lib/api";
import type {
  ExpertVerdict,
  FusionResult,
  SSEAnalyticsCompleteEvent,
  SSEExpertDecisionEvent,
  SSEFusionCompleteEvent,
} from "../lib/types";

interface RunPanelProps {
  moduleId: string;
  assessmentId: string;
  syntheticPreset?: string;
  onComplete: (result: FusionResult) => void;
  onStop?: () => void;
  isOpen: boolean;
}

const VERDICT_CHIP_COLORS: Record<ExpertVerdict, string> = {
  SUPPORTS_EXPOSURE: "bg-red-900/50 text-red-300 border-red-700/50",
  WEAK_SUPPORT: "bg-orange-900/50 text-orange-300 border-orange-700/50",
  NEUTRAL: "bg-gray-800/50 text-gray-400 border-gray-700/50",
  CONTRADICTS_EXPOSURE: "bg-green-900/50 text-green-300 border-green-700/50",
  INSUFFICIENT_DATA: "bg-blue-900/50 text-blue-400 border-blue-700/50",
};

const PHASES: Array<{ id: RunPhase; label: string }> = [
  { id: "experts", label: "Experts" },
  { id: "fusion", label: "Fusion" },
  { id: "analytics", label: "Analytics" },
  { id: "done", label: "Done" },
];

type RunPhase = "idle" | "experts" | "fusion" | "analytics" | "done" | "error";

function pct(value: number) {
  return `${Math.round(value * 100)}%`;
}

function phaseIndex(phase: RunPhase) {
  if (phase === "idle" || phase === "error") return -1;
  return Math.max(0, PHASES.findIndex((p) => p.id === phase));
}

function MetricTile({ label, value, detail, tone = "text-white" }: { label: string; value: string; detail?: string; tone?: string }) {
  return (
    <div className="rounded-lg border border-white/10 bg-white/[0.035] p-3">
      <div className="text-[10px] font-semibold uppercase tracking-[0.14em] text-gray-500">{label}</div>
      <div className={`mt-1 font-mono text-lg font-bold ${tone}`}>{value}</div>
      {detail ? <div className="mt-1 truncate text-[10px] text-gray-500">{detail}</div> : null}
    </div>
  );
}

function VerdictChip({ verdict }: { verdict: ExpertVerdict }) {
  return (
    <span className={`shrink-0 rounded border px-1.5 py-0.5 text-[9px] font-semibold ${VERDICT_CHIP_COLORS[verdict] ?? ""}`}>
      {verdict.replace(/_/g, " ")}
    </span>
  );
}

export default function RunPanel({
  moduleId, assessmentId, syntheticPreset, onComplete, onStop, isOpen,
}: RunPanelProps) {
  const [logs, setLogs] = useState<string[]>([]);
  const [decisions, setDecisions] = useState<SSEExpertDecisionEvent[]>([]);
  const [fusionEvent, setFusionEvent] = useState<SSEFusionCompleteEvent | null>(null);
  const [analyticsEvent, setAnalyticsEvent] = useState<SSEAnalyticsCompleteEvent | null>(null);
  const [isRunning, setIsRunning] = useState(false);
  const [phase, setPhase] = useState<RunPhase>("idle");
  const [error, setError] = useState<string | null>(null);
  const logEndRef = useRef<HTMLDivElement>(null);
  const sourceRef = useRef<EventSource | null>(null);

  useEffect(() => {
    if (!moduleId || !assessmentId) return;

    setLogs(syntheticPreset ? [`Synthetic preset: ${syntheticPreset}`] : []);
    setDecisions([]);
    setFusionEvent(null);
    setAnalyticsEvent(null);
    setError(null);
    setPhase("experts");
    setIsRunning(true);

    if (syntheticPreset) {
      let cancelled = false;
      setLogs([`Synthetic preset: ${syntheticPreset}`, "Running synthetic validation..."]);
      runSyntheticSimulation(moduleId, syntheticPreset)
        .then((result) => {
          if (cancelled) return;
          setPhase("done");
          setIsRunning(false);
          setLogs((prev) => [...prev, `Synthetic result: ${result.verdict} - ${result.risk_score.toFixed(1)}/10`]);
          onComplete(syntheticToFusionResult(result));
        })
        .catch((err: unknown) => {
          if (cancelled) return;
          const message = err instanceof Error ? err.message : "Synthetic validation failed";
          setError(message);
          setPhase("error");
          setIsRunning(false);
          setLogs((prev) => [...prev, `ERROR: ${message}`]);
        });
      return () => {
        cancelled = true;
      };
    }

    const source = createSSEStream(moduleId, assessmentId);
    sourceRef.current = source;

    const cleanup = subscribeToStream(source, {
      onLog: (msg) => setLogs((prev) => [...prev, msg]),
      onExpertDecision: (d) => {
        setDecisions((prev) => [...prev, d]);
        setPhase("experts");
      },
      onFusionComplete: (e) => {
        setFusionEvent(e);
        setPhase("fusion");
        setLogs((prev) => [...prev, `Fusion: ${e.verdict} - ${e.risk_score.toFixed(1)}/10`]);
      },
      onAnalyticsComplete: (e) => {
        setAnalyticsEvent(e);
        setPhase("analytics");
        setLogs((prev) => [...prev, `Analytics: ${e.kill_chains} kill chains, ${e.threat_actors} threat actors`]);
      },
      onResult: (result) => {
        setPhase("done");
        setIsRunning(false);
        onComplete(result);
      },
      onError: (msg) => {
        setError(msg);
        setPhase("error");
        setIsRunning(false);
        setLogs((prev) => [...prev, `ERROR: ${msg}`]);
      },
    });

    return () => {
      cleanup();
      sourceRef.current = null;
    };
  }, [moduleId, assessmentId, syntheticPreset, onComplete]);

  useEffect(() => {
    if (isRunning && logs.length > 0) {
      logEndRef.current?.scrollIntoView({ behavior: "smooth" });
    }
  }, [logs, isRunning]);

  const summary = useMemo(() => {
    const supports = decisions.filter((d) => d.verdict === "SUPPORTS_EXPOSURE").length;
    const weak = decisions.filter((d) => d.verdict === "WEAK_SUPPORT").length;
    const contradicts = decisions.filter((d) => d.verdict === "CONTRADICTS_EXPOSURE").length;
    const avgConfidence = decisions.length
      ? decisions.reduce((sum, d) => sum + d.confidence, 0) / decisions.length
      : 0;
    const techniques = Array.from(new Set(decisions.flatMap((d) => d.mitre_techniques ?? [])));

    return { supports, weak, contradicts, avgConfidence, techniques };
  }, [decisions]);

  const latestDecision = decisions[decisions.length - 1] ?? null;
  const currentPhaseIndex = phaseIndex(phase);

  const handleStop = () => {
    sourceRef.current?.close();
    setIsRunning(false);
    setPhase("idle");
    onStop?.();
  };

  if (!isOpen) return null;

  return (
    <div className="flex h-full min-h-0 flex-col overflow-hidden rounded-xl border border-white/10 bg-[#08080d]">
      <div className="flex shrink-0 items-center justify-between gap-3 border-b border-white/10 bg-white/[0.045] px-4 py-2">
        <div className="min-w-0">
          <div className="flex items-center gap-2">
            {isRunning ? <div className="h-2 w-2 rounded-full bg-green-400 shadow-[0_0_10px_rgba(74,222,128,0.8)]" /> : null}
            <span className="truncate font-mono text-sm font-semibold text-white">
              {moduleId.replace(/_/g, " ").toUpperCase()}
            </span>
            <span className={`rounded border px-2 py-0.5 text-[10px] font-semibold ${
              phase === "done" ? "border-green-700/30 bg-green-900/30 text-green-400" :
              phase === "error" ? "border-red-700/30 bg-red-900/30 text-red-400" :
              "border-blue-700/30 bg-blue-900/30 text-blue-400"
            }`}>
              {phase.toUpperCase()}
            </span>
          </div>
          {syntheticPreset ? <div className="mt-0.5 text-[10px] text-gray-500">Synthetic preset: {syntheticPreset}</div> : null}
        </div>
        {isRunning ? (
          <button onClick={handleStop} className="rounded-lg border border-red-700/30 px-3 py-1.5 text-xs text-red-400 transition-colors hover:border-red-700/60 hover:text-red-300">
            Stop
          </button>
        ) : null}
      </div>

      <div className="grid min-h-0 flex-1 grid-cols-1 xl:grid-cols-[250px_minmax(0,1fr)_360px]">
        <aside className="min-h-0 overflow-y-auto border-b border-white/10 p-3 xl:border-b-0 xl:border-r">
          <div className="grid grid-cols-2 gap-2 xl:grid-cols-1">
            <MetricTile label="Experts" value={`${decisions.length}`} detail={isRunning ? "streaming decisions" : "decisions received"} />
            <MetricTile label="Support" value={`${summary.supports + summary.weak}`} detail={`${summary.contradicts} contradict`} tone="text-orange-300" />
            <MetricTile label="Risk" value={fusionEvent ? `${fusionEvent.risk_score.toFixed(1)}/10` : "--"} detail={fusionEvent?.severity_projection ?? "awaiting fusion"} tone="text-red-300" />
            <MetricTile label="Confidence" value={decisions.length ? pct(summary.avgConfidence) : "--"} detail={fusionEvent ? `${fusionEvent.confidence}% fused` : "expert average"} tone="text-blue-300" />
          </div>

          <div className="mt-3 rounded-lg border border-white/10 bg-black/25 p-3">
            <div className="text-[10px] font-semibold uppercase tracking-[0.14em] text-gray-500">Run Progress</div>
            <div className="mt-3 space-y-2">
              {PHASES.map((item, index) => {
                const active = item.id === phase;
                const complete = currentPhaseIndex >= index || phase === "done";
                return (
                  <div key={item.id} className="flex items-center gap-2">
                    <div className={`h-2.5 w-2.5 rounded-full border ${
                      active ? "border-blue-300 bg-blue-400 shadow-[0_0_10px_rgba(96,165,250,0.8)]" :
                      complete ? "border-green-400 bg-green-500" :
                      "border-white/15 bg-white/5"
                    }`} />
                    <span className={active ? "text-xs text-white" : complete ? "text-xs text-green-300" : "text-xs text-gray-600"}>
                      {item.label}
                    </span>
                  </div>
                );
              })}
            </div>
          </div>

          {summary.techniques.length > 0 ? (
            <div className="mt-3 rounded-lg border border-white/10 bg-black/25 p-3">
              <div className="text-[10px] font-semibold uppercase tracking-[0.14em] text-gray-500">MITRE Signals</div>
              <div className="mt-2 flex flex-wrap gap-1">
                {summary.techniques.slice(0, 8).map((technique) => (
                  <span key={technique} className="rounded bg-white/5 px-1.5 py-0.5 font-mono text-[9px] text-gray-400">{technique}</span>
                ))}
              </div>
            </div>
          ) : null}
        </aside>

        <main className="flex min-h-0 flex-col gap-3 border-b border-white/10 p-3 xl:border-b-0">
          <div className="grid shrink-0 grid-cols-1 gap-2 md:grid-cols-3">
            <div className="rounded-lg border border-white/10 bg-white/[0.035] p-3">
              <div className="text-[10px] font-semibold uppercase tracking-[0.14em] text-gray-500">Latest Signal</div>
              <div className="mt-1 min-h-10 text-xs leading-5 text-gray-300">
                {latestDecision ? latestDecision.summary : "Waiting for expert output..."}
              </div>
            </div>
            <div className="rounded-lg border border-white/10 bg-white/[0.035] p-3">
              <div className="text-[10px] font-semibold uppercase tracking-[0.14em] text-gray-500">Fusion</div>
              <div className="mt-1 font-mono text-sm font-bold text-white">
                {fusionEvent ? fusionEvent.verdict.replace(/_/g, " ") : "PENDING"}
              </div>
              <div className="mt-1 text-[10px] text-gray-500">{fusionEvent ? `${fusionEvent.confidence}% confidence` : "Consensus not ready"}</div>
            </div>
            <div className="rounded-lg border border-white/10 bg-white/[0.035] p-3">
              <div className="text-[10px] font-semibold uppercase tracking-[0.14em] text-gray-500">Analytics</div>
              <div className="mt-1 font-mono text-sm font-bold text-white">
                {analyticsEvent ? `${analyticsEvent.kill_chains} chains` : "PENDING"}
              </div>
              <div className="mt-1 text-[10px] text-gray-500">
                {analyticsEvent ? `${analyticsEvent.threat_actors} actors, ${analyticsEvent.playbook_steps} steps` : "Graph enrichment queued"}
              </div>
            </div>
          </div>

          <div className="flex min-h-0 flex-1 flex-col overflow-hidden rounded-lg border border-white/10 bg-black/55">
            <div className="flex shrink-0 items-center justify-between border-b border-white/10 px-3 py-2">
              <span className="text-[10px] font-semibold uppercase tracking-[0.14em] text-gray-500">Execution Stream</span>
              <span className="font-mono text-[10px] text-gray-600">{logs.length} lines</span>
            </div>
            <div className="min-h-0 flex-1 overflow-y-auto p-3 font-mono text-xs text-green-400">
              {logs.length === 0 ? (
                <div className="text-gray-600">No stream events yet.</div>
              ) : logs.map((log, i) => (
                <div key={i} className="leading-5 opacity-90">
                  <span className="mr-2 text-gray-600">[{i.toString().padStart(3, "0")}]</span>
                  {log}
                </div>
              ))}
              {isRunning ? (
                <div className="mt-1 flex items-center gap-1 text-green-500">
                  <span className="animate-pulse">|</span>
                </div>
              ) : null}
              <div ref={logEndRef} />
            </div>
          </div>
        </main>

        <aside className="flex min-h-0 flex-col gap-3 overflow-y-auto p-3">
          {fusionEvent ? (
            <div className="rounded-lg border border-white/20 bg-white/[0.055] p-3">
              <div className="text-[10px] font-semibold uppercase tracking-[0.14em] text-gray-500">Fusion Result</div>
              <div className="mt-2 text-base font-bold text-white">{fusionEvent.verdict.replace(/_/g, " ")}</div>
              <div className="font-mono text-sm text-orange-400">{fusionEvent.risk_score.toFixed(1)}/10</div>
              <div className="mt-2 h-1.5 overflow-hidden rounded-full bg-white/10">
                <div className="h-full rounded-full bg-blue-500" style={{ width: `${fusionEvent.confidence}%` }} />
              </div>
              <div className="mt-1 text-[10px] text-gray-500">{fusionEvent.confidence}% confidence</div>
            </div>
          ) : null}

          <div className="min-h-0 rounded-lg border border-white/10 bg-white/[0.025]">
            <div className="flex items-center justify-between border-b border-white/10 px-3 py-2">
              <span className="text-[10px] font-semibold uppercase tracking-[0.14em] text-gray-500">Expert Decisions</span>
              <span className="font-mono text-[10px] text-gray-500">{decisions.length}</span>
            </div>
            <div className="max-h-[360px] space-y-2 overflow-y-auto p-2">
              {decisions.length === 0 ? (
                <div className="rounded-lg border border-dashed border-white/10 p-4 text-center text-xs text-gray-600">
                  Waiting for expert decisions.
                </div>
              ) : decisions.map((d, i) => (
                <div key={i} className="rounded-lg border border-white/5 bg-white/[0.045] p-2">
                  <div className="mb-1 flex items-start justify-between gap-2">
                    <span className="min-w-0 text-[11px] font-semibold leading-tight text-white">{d.expert_name}</span>
                    <VerdictChip verdict={d.verdict} />
                  </div>
                  <p className="mb-2 text-[10px] leading-4 text-gray-400">{d.summary}</p>
                  <div className="flex items-center gap-2">
                    <div className="h-1.5 flex-1 overflow-hidden rounded-full bg-white/10">
                      <div className="h-full rounded-full bg-blue-500" style={{ width: pct(d.confidence) }} />
                    </div>
                    <span className="font-mono text-[9px] text-gray-600">{pct(d.confidence)}</span>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {error ? (
            <div className="rounded-lg border border-red-700/30 bg-red-950/20 p-3 text-xs text-red-300">
              {error}
            </div>
          ) : null}
        </aside>
      </div>
    </div>
  );
}
