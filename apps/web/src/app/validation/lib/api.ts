import { getApiBaseUrl } from "@/lib/apiBase";
import type {
  ValidationModule,
  FusionResult,
  KillChain,
  BlastRadiusResult,
  SyntheticConfig,
  SyntheticPresetsResponse,
  SSEEvent,
  SSEExpertDecisionEvent,
  SSEFusionCompleteEvent,
  SSEAnalyticsCompleteEvent,
} from "./types";

const BASE = getApiBaseUrl();

async function apiFetch<T>(path: string, options?: RequestInit): Promise<T> {
  const headers: HeadersInit = {
    "Content-Type": "application/json",
    "X-Requested-With": "XMLHttpRequest",
    ...(options?.headers ?? {}),
  };
  const res = await fetch(`${BASE}${path}`, { ...options, headers, credentials: "include" });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`API ${res.status}: ${text}`);
  }
  return res.json() as Promise<T>;
}

export async function fetchModules(): Promise<ValidationModule[]> {
  return apiFetch<ValidationModule[]>("/validation/modules");
}

export async function runSimulation(
  moduleId: string,
  assessmentId: string,
  target = assessmentId
): Promise<FusionResult> {
  return apiFetch<FusionResult>(
    `/validation/simulate/${moduleId}/${assessmentId}`,
    { method: "POST", body: JSON.stringify({ target, mode: "simulation" }) }
  );
}

export function createSSEStream(
  moduleId: string,
  assessmentId: string
): EventSource {
  return new EventSource(`${BASE}/validation/stream/${moduleId}/${assessmentId}`, { withCredentials: true });
}

export function createStreamAll(assessmentId: string): EventSource {
  return new EventSource(`${BASE}/validation/stream-all/${assessmentId}`, { withCredentials: true });
}

export interface SSECallbacks {
  onLog?: (message: string) => void;
  onExpertDecision?: (d: SSEExpertDecisionEvent) => void;
  onFusionComplete?: (e: SSEFusionCompleteEvent) => void;
  onAnalyticsComplete?: (e: SSEAnalyticsCompleteEvent) => void;
  onResult?: (result: FusionResult) => void;
  onError?: (message: string) => void;
}

export function subscribeToStream(
  source: EventSource,
  callbacks: SSECallbacks
): () => void {
  let completed = false;

  source.onmessage = (event) => {
    try {
      const data = JSON.parse(event.data) as SSEEvent;
      switch (data.type) {
        case "log":
          callbacks.onLog?.((data as { message: string }).message);
          break;
        case "expert_decision":
          callbacks.onExpertDecision?.(data as SSEExpertDecisionEvent);
          break;
        case "fusion_complete":
          callbacks.onFusionComplete?.(data as SSEFusionCompleteEvent);
          break;
        case "analytics_complete":
          callbacks.onAnalyticsComplete?.(data as SSEAnalyticsCompleteEvent);
          break;
        case "result": {
          completed = true;
          const fusion = (data as { fusion: FusionResult }).fusion;
          if (fusion && Object.keys(fusion).length > 0) callbacks.onResult?.(fusion);
          break;
        }
        case "error":
          callbacks.onError?.((data as { message: string }).message);
          break;
      }
    } catch {
      // Ignore parse errors
    }
  };

  source.onerror = () => {
    source.close();
    if (!completed) callbacks.onError?.("SSE connection error");
  };

  return () => source.close();
}

export async function generateSynthetic(
  config: SyntheticConfig
): Promise<{ context_id: string; entity_count: number; finding_count: number }> {
  return apiFetch("/validation/synthetic/generate", {
    method: "POST",
    body: JSON.stringify(config),
  });
}

export async function fetchPresets(): Promise<SyntheticPresetsResponse> {
  return apiFetch<SyntheticPresetsResponse>("/validation/synthetic/presets");
}

export interface SyntheticSimulationResult {
  module_id: string;
  preset: string;
  verdict: string;
  risk_score: number;
  confidence: number;
  severity_projection: string;
  kill_chains: number;
  threat_actors: string[];
  playbook_steps: number;
  summary: string;
}

export async function runSyntheticSimulation(
  moduleId: string,
  presetName: string
): Promise<SyntheticSimulationResult> {
  return apiFetch(`/validation/simulate-synthetic/${moduleId}/${presetName}`, {
    method: "POST",
  });
}

export function syntheticToFusionResult(result: SyntheticSimulationResult): FusionResult {
  const verdict = result.verdict as FusionResult["final_verdict"];
  const severity = result.severity_projection as FusionResult["severity_projection"];
  return {
    final_verdict: verdict,
    risk_score: result.risk_score,
    confidence: result.confidence,
    consensus_score: result.confidence,
    evidence_quality_score: result.confidence,
    evidence_quality_band: "MODERATE",
    confidence_band: result.confidence >= 0.75 ? "HIGH" : result.confidence >= 0.5 ? "MODERATE" : "LOW",
    severity_projection: severity,
    summary: result.summary,
    operator_brief: result.summary,
    impact: `Synthetic preset: ${result.preset}`,
    blast_radius: {
      origin_entity_id: result.preset,
      reachable_computers: 0,
      reachable_domain_controllers: 0,
      reachable_domains: 0,
      reachable_ous: 0,
      reachable_groups: 0,
      reachable_users: 0,
      total_reachable: 0,
      tier0_reachable: false,
      critical_paths: [],
    },
    mapped_attack_steps: 0,
    what_increased_confidence: [],
    what_reduced_confidence: [],
    what_would_raise_confidence: [],
    recommended_actions: [],
    safeguards: [],
    control_mapping: [],
    kill_chains: [],
    cross_module_chains: [],
    threat_actor_matches: result.threat_actors.map((actor, index) => ({
      actor_id: actor.toLowerCase().replace(/[^a-z0-9]+/g, "_") || `actor_${index + 1}`,
      actor_name: actor,
      match_score: 1,
      matched_techniques: [],
      known_campaigns: [],
      description: "Synthetic scenario match",
    })),
    remediation_playbook: [],
    red_team_narrative: result.summary,
    mitre_coverage: {},
    remediation_impact: {},
    module_id: result.module_id,
    run_id: `synthetic:${result.module_id}:${result.preset}`,
    assessment_id: `synthetic:${result.preset}`,
    duration_ms: 0,
    telemetry: {
      synthetic: true,
      preset: result.preset,
      compact_kill_chain_count: result.kill_chains,
      playbook_steps: result.playbook_steps,
    },
    support_count: 0,
    contradiction_count: 0,
    insufficient_count: 0,
    evidence_summary: {},
    contradictions: [],
  };
}

export async function runAllModules(assessmentId: string): Promise<{
  assessment_id: string;
  results: Record<string, FusionResult>;
  errors: Record<string, string>;
  module_count: number;
  completed: number;
}> {
  return apiFetch(`/validation/simulate-all/${assessmentId}`, {
    method: "POST",
  });
}

export async function fetchAnalytics(runId: string): Promise<FusionResult> {
  return apiFetch<FusionResult>(`/validation/analytics/${runId}`);
}

export async function fetchKillChains(runId: string): Promise<KillChain[]> {
  const response = await apiFetch<{ kill_chains: KillChain[] }>(`/validation/kill-chains/${runId}`);
  return response.kill_chains;
}

export async function fetchBlastRadius(runId: string, entityId: string): Promise<BlastRadiusResult> {
  return apiFetch<BlastRadiusResult>(`/validation/blast-radius/${runId}/${entityId}`);
}

export async function fetchComparison(
  runIdA: string,
  runIdB: string
): Promise<{ before: FusionResult; after: FusionResult; diff: Record<string, unknown> }> {
  return apiFetch(`/validation/comparison/${runIdA}/${runIdB}`);
}

export async function exportRunJson(runId: string): Promise<{ schema: string; version: string; run: FusionResult }> {
  return apiFetch(`/validation/export/${runId}/json`);
}

export async function fetchPostureTimeline(assessmentId: string): Promise<{
  assessment_id: string;
  run_count: number;
  runs: Array<{
    run_id: string;
    module_id: string;
    verdict: string;
    risk_score: number;
    created_at: string | null;
  }>;
}> {
  return apiFetch(`/validation/posture-timeline/${assessmentId}`);
}
