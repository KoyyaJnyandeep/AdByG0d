export type ExpertVerdict =
  | "SUPPORTS_EXPOSURE"
  | "WEAK_SUPPORT"
  | "NEUTRAL"
  | "CONTRADICTS_EXPOSURE"
  | "INSUFFICIENT_DATA";

export type FinalVerdict =
  | "LIKELY_EXPOSED"
  | "CONDITIONALLY_EXPOSED"
  | "LOW_CONFIDENCE_SIGNAL"
  | "INSUFFICIENT_DATA"
  | "NOT_SUPPORTED_BY_CURRENT_EVIDENCE";

export type EvidenceQualityBand = "VERY_HIGH" | "HIGH" | "MODERATE" | "LOW" | "FRAGILE";
export type ConfidenceBand = "VERY_HIGH" | "HIGH" | "MODERATE" | "LOW";
export type SeverityLevel = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";

export interface ExpertDecision {
  expert_id: string;
  expert_name: string;
  module_id: string;
  verdict: ExpertVerdict;
  score_delta: number;
  confidence: number;
  severity_hint: SeverityLevel | null;
  summary: string;
  reasoning: string[];
  supporting_signals: string[];
  contradicting_signals: string[];
  missing_signals: string[];
  evidence_refs: string[];
  related_finding_ids: string[];
  related_entity_ids: string[];
  related_edge_ids: string[];
  mitre_techniques: string[];
  kill_chain_stage: string;
  blast_radius_hint: number;
  remediation_commands: string[];
  detection_opportunities: string[];
  cve_refs: string[];
  telemetry: Record<string, unknown>;
}

export interface KillChainStep {
  step_index: number;
  module_id: string;
  finding_id: string | null;
  technique: string;
  mitre_id: string;
  description: string;
  entity_ids: string[];
}

export interface KillChain {
  chain_id: string;
  name: string;
  composite_risk: number;
  steps: KillChainStep[];
  narrative: string;
  threat_actors: string[];
}

export interface BlastRadiusResult {
  origin_entity_id: string;
  reachable_computers: number;
  reachable_domain_controllers: number;
  reachable_domains: number;
  reachable_ous: number;
  reachable_groups: number;
  reachable_users: number;
  total_reachable: number;
  tier0_reachable: boolean;
  critical_paths: string[];
}

export interface CrossModuleChain {
  chain_id: string;
  modules: string[];
  individual_severities: string[];
  compound_severity: SeverityLevel;
  compound_risk: number;
  explanation: string;
  steps: string[];
}

export interface ThreatActorMatch {
  actor_id: string;
  actor_name: string;
  match_score: number;
  matched_techniques: string[];
  known_campaigns: string[];
  description: string;
}

export interface PlaybookStep {
  step_index: number;
  title: string;
  description: string;
  commands: string[];
  applies_to: string[];
  verification_command: string;
  mitre_mitigates: string[];
  priority: SeverityLevel;
}

export interface FusionResult {
  final_verdict: FinalVerdict;
  risk_score: number;
  confidence: number;
  consensus_score: number;
  evidence_quality_score: number;
  evidence_quality_band: EvidenceQualityBand;
  confidence_band: ConfidenceBand;
  severity_projection: SeverityLevel;
  summary: string;
  operator_brief: string;
  impact: string;
  blast_radius: BlastRadiusResult;
  mapped_attack_steps: number;
  what_increased_confidence: string[];
  what_reduced_confidence: string[];
  what_would_raise_confidence: string[];
  recommended_actions: string[];
  safeguards: string[];
  control_mapping: string[];
  kill_chains: KillChain[];
  cross_module_chains: CrossModuleChain[];
  threat_actor_matches: ThreatActorMatch[];
  remediation_playbook: PlaybookStep[];
  red_team_narrative: string;
  mitre_coverage: Record<string, string[]>;
  remediation_impact: Record<string, number>;
  module_id: string;
  run_id: string;
  assessment_id: string;
  duration_ms: number;
  telemetry: Record<string, unknown>;
  support_count: number;
  contradiction_count: number;
  insufficient_count: number;
  evidence_summary: Record<string, unknown>;
  contradictions: string[];
}

export interface ValidationModule {
  id: string;
  name: string;
  description: string;
  version: string;
  expert_count: number;
  mitre_techniques: string[];
  severity_range: [string, string];
  risk_category: string;
}

export type SSEEventType =
  | "log"
  | "expert_start"
  | "expert_decision"
  | "fusion_start"
  | "fusion_complete"
  | "analytics_start"
  | "analytics_complete"
  | "result"
  | "error";

export interface SSELogEvent {
  type: "log";
  message: string;
  ts: number;
}

export interface SSEExpertDecisionEvent {
  type: "expert_decision";
  expert_id: string;
  expert_name: string;
  verdict: ExpertVerdict;
  score_delta: number;
  confidence: number;
  summary: string;
  mitre_techniques: string[];
  kill_chain_stage: string;
  ts: number;
}

export interface SSEFusionCompleteEvent {
  type: "fusion_complete";
  verdict: FinalVerdict;
  risk_score: number;
  confidence: number;
  severity_projection: string;
  ts: number;
}

export interface SSEAnalyticsCompleteEvent {
  type: "analytics_complete";
  kill_chains: number;
  threat_actors: number;
  playbook_steps: number;
  duration_ms: number;
  ts: number;
}

export interface SSEResultEvent {
  type: "result";
  fusion: Partial<FusionResult>;
  ts: number;
}

export interface SSEErrorEvent {
  type: "error";
  message: string;
  ts: number;
}

export type SSEEvent =
  | SSELogEvent
  | SSEExpertDecisionEvent
  | SSEFusionCompleteEvent
  | SSEAnalyticsCompleteEvent
  | SSEResultEvent
  | SSEErrorEvent
  | { type: SSEEventType; [key: string]: unknown };

export interface SyntheticConfig {
  preset?: string;
  user_count?: number;
  computer_count?: number;
  dc_count?: number;
  asrep_pct?: number;
  kerberoastable_pct?: number;
  acl_misconfiguration_pct?: number;
  laps_coverage_pct?: number;
  esc1_templates?: number;
  shadow_credential_write_edges?: number;
  gpo_write_edges?: number;
  maq_value?: number;
  sid_history_count?: number;
  rbcd_edges?: number;
  password_policy_minlength?: number;
  password_lockout_threshold?: number;
}

export interface SyntheticPreset {
  name: string;
  description: string;
  user_count: number;
  computer_count: number;
}

export interface SyntheticPresetsResponse {
  presets: Record<string, SyntheticPreset>;
  apt_scenarios: Record<string, {
    name: string;
    description: string;
    expected_modules: string[];
    threat_actor: string;
  }>;
}

export type ValidationTab =
  | "modules"
  | "graph"
  | "heatmap"
  | "timeline"
  | "compare"
  | "playbook"
  | "narrative"
  | "mitre";

export type ValidationMode = "live" | "synthetic";

export interface ModuleRunState {
  isRunning: boolean;
  logs: string[];
  expertDecisions: SSEExpertDecisionEvent[];
  fusionResult: FusionResult | null;
  error: string | null;
  startedAt: number | null;
  completedAt: number | null;
}

export interface HeatMapCell {
  moduleId: string;
  severity: SeverityLevel;
  count: number;
  peakScore: number;
}

export const VERDICT_COLORS: Record<FinalVerdict, string> = {
  LIKELY_EXPOSED: "#ef4444",
  CONDITIONALLY_EXPOSED: "#f97316",
  LOW_CONFIDENCE_SIGNAL: "#eab308",
  INSUFFICIENT_DATA: "#6b7280",
  NOT_SUPPORTED_BY_CURRENT_EVIDENCE: "#22c55e",
};

export const SEVERITY_COLORS: Record<string, string> = {
  CRITICAL: "#ef4444",
  HIGH: "#f97316",
  MEDIUM: "#eab308",
  LOW: "#22c55e",
  INFO: "#6b7280",
};

export const VERDICT_LABELS: Record<FinalVerdict, string> = {
  LIKELY_EXPOSED: "LIKELY EXPOSED",
  CONDITIONALLY_EXPOSED: "CONDITIONALLY EXPOSED",
  LOW_CONFIDENCE_SIGNAL: "LOW CONFIDENCE",
  INSUFFICIENT_DATA: "INSUFFICIENT DATA",
  NOT_SUPPORTED_BY_CURRENT_EVIDENCE: "NOT EXPOSED",
};

export const MODULE_ICONS: Record<string, string> = {
  kerberos: "🔑",
  acl: "🛡",
  dcsync: "⚡",
  ntlm_relay: "🔄",
  trust: "🌐",
  adcs: "📜",
  shadow_credentials: "👥",
  gpo_abuse: "⚙",
  laps_exposure: "🔓",
  delegation: "➡",
  password_policy: "🔐",
  sid_history: "🪄",
  maq_rbcd: "💻",
};
