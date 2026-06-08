export type SeverityLevel = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO'
export type FindingStatus = 'OPEN' | 'IN_REVIEW' | 'REMEDIATED' | 'ACCEPTED' | 'FALSE_POSITIVE' | 'REGRESSED'
export type AssessmentStatus = 'PENDING' | 'RUNNING' | 'PAUSED' | 'COMPLETED' | 'FAILED' | 'CANCELLED'
export type DataOrigin = 'COLLECTED' | 'IMPORTED' | 'INFERRED' | 'SIMULATED'
export type EntityType =
  | 'USER' | 'GROUP' | 'COMPUTER' | 'DOMAIN' | 'FOREST'
  | 'OU' | 'GPO' | 'SERVICE_ACCOUNT' | 'GMSA' | 'DMSA'
  | 'CA' | 'CERT_TEMPLATE' | 'TRUST' | 'SITE' | 'DC' | 'UNKNOWN'

export type EdgeType =
  | 'MEMBER_OF' | 'HAS_CONTROL' | 'GENERIC_ALL' | 'WRITE_DACL' | 'WRITE_OWNER'
  | 'FORCE_CHANGE_PASSWORD' | 'ADD_MEMBER' | 'ALLOWED_TO_DELEGATE' | 'ALLOWED_TO_ACT'
  | 'HAS_SPN' | 'CAN_ENROLL' | 'OWNS' | 'CONTAINS' | 'APPLIES_GPO'
  | 'TRUSTS' | 'LOCAL_ADMIN' | 'CAN_RDP' | 'CAN_WINRM' | 'DCSYNC' | 'ADMIN_TO'

export interface AssessmentStats {
  total_findings: number
  CRITICAL?: number; HIGH?: number; MEDIUM?: number; LOW?: number; INFO?: number
  total_entities?: number; total_edges?: number
  [key: string]: number | undefined
}

export interface Assessment {
  id: string; name: string; domain: string; dc_ip?: string
  status: AssessmentStatus; collection_mode?: string
  started_at?: string; completed_at?: string; created_at: string
  modules_run: string[]
  connectivity_profile_id?: string
  collection_config?: {
    target?: {
      username?: string
      password?: string
      [key: string]: unknown
    }
    [key: string]: unknown
  }
  stats: AssessmentStats | Record<string, unknown>
  exposure_score: number
  progress_pct?: number
  last_message?: string
}

export interface WorkspaceOption { id: string; name: string; description?: string }

export interface EntitySummary {
  total: number; by_type: Record<string, number>
  tier0_count: number; crown_jewel_count: number; admin_count: number
}

export interface EntityIntelCard {
  id: string
  label: string
  sam_account_name?: string
  entity_type: EntityType
  domain?: string
  tier?: number
  is_crown_jewel: boolean
  is_admin_count: boolean
  is_enabled: boolean
  is_sensitive: boolean
  last_logon?: string
  password_last_set?: string
}

export interface EntityIntelligence {
  assessment_id: string
  total: number
  by_tier: Record<string, number>
  by_flags: Record<string, number>
  exposure_pressure: number
  stale_cutoff_days: number
  watchlist: EntityIntelCard[]
  dormant_privileged: EntityIntelCard[]
}

export interface Finding {
  id: string; assessment_id: string; finding_type: string; module: string
  title: string; description?: string; origin: DataOrigin; severity: SeverityLevel
  confidence: number; composite_score?: number; affected_count: number; affected_objects: unknown[]
  root_cause?: string; causal_chain: string[]; status: FindingStatus
  drift_status?: 'new' | 'persistent' | 'regressed' | 'resolved'
  remediation?: string; remediation_steps: string[]
  fix_complexity?: 'trivial' | 'low' | 'medium' | 'high'
  references: string[]; first_seen: string; last_seen: string; created_at: string
  attack_path?: PathStep[]; cve_ids?: string[]; mitre_attack_ids?: string[]
  technical_severity?: number; reachability_score?: number; asset_criticality?: number
  estimated_effort?: string; waiver_reason?: string; waiver_expiry?: string
  is_tier0_direct?: boolean
}

export interface FindingsPage { items: Finding[]; total: number; page: number; page_size: number; pages: number }

export interface GraphNode {
  id: string; label: string; entity_type: EntityType; tier?: number
  is_crown_jewel: boolean; is_admin_count?: boolean; severity_count?: Record<string, number>
  x?: number; y?: number; vx?: number; vy?: number; fx?: number | null; fy?: number | null
  community_id?: number
}

export interface GraphEdge {
  id: string; source: string | GraphNode; target: string | GraphNode
  edge_type: EdgeType; provenance?: string; risk_weight: number
  edge_confidence?: number
  edge_provenance_type?: 'collected' | 'inferred' | 'heuristic'
  connects_to_tier0?: boolean
}

export interface VirtualGroupNode extends GraphNode {
  isVirtual: true
  memberCount: number
  memberIds: string[]
}

export interface GraphData { nodes: GraphNode[]; edges: GraphEdge[]; node_count: number; edge_count: number }

export interface PathStep {
  entity_id: string; entity_label: string; entity_type: EntityType
  edge_type?: EdgeType | string; provenance?: string; explanation: string
  tier?: number; edge_risk?: number; is_crown_jewel?: boolean
}

export interface ExposurePath {
  id: string; source_id?: string; target_id?: string; source_label: string; target_label: string; path_steps: PathStep[]
  edge_types?: string[]; hop_count: number; path_score: number; risk_level?: AttackPathEntry['risk_level']
  target_tier?: number; path_type?: string; explanation: string
}

export interface ExposurePathsResponse { paths: ExposurePath[] }

export interface SimulationEdge {
  source: string; target: string
  source_label: string; target_label: string
  edge_type: string; risk_weight?: number
  exposed_principals_eliminated_if_removed?: number
  reduction_pct_if_removed?: number
  remediation: string
  remediation_steps: string[]
}

export interface SimulationAlternativePath {
  source_label: string; target_label: string
  hop_count: number; edge_types: string[]
}

export interface GraphSimulationResult {
  reduction_pct?: number; risk_reduction_pct?: number; reduction?: number
  before?: number; after?: number; eliminated?: number
  metric?: string
  exposed_principals_before?: number
  exposed_principals_after?: number
  exposed_principals_eliminated?: number
  blast_radius_before?: number; blast_radius_after?: number; blast_radius_reduction?: number
  edges_removed?: SimulationEdge[]
  per_edge_analysis?: SimulationEdge[]
  optimal_removal?: SimulationEdge
  alternative_paths?: SimulationAlternativePath[]
  residual_risk_score?: number
  is_fully_remediated?: boolean
  edges_requested?: number
}

export interface Entity {
  id: string; entity_type: EntityType; distinguished_name?: string
  object_sid?: string; sam_account_name?: string; display_name?: string
  domain?: string; dns_hostname?: string
  is_enabled: boolean; is_admin_count: boolean; is_sensitive: boolean; is_protected_user: boolean
  tier?: number; is_crown_jewel: boolean; business_tags: string[]; owner_team?: string
  attributes: Record<string, unknown>
  object_created?: string; object_modified?: string; last_logon?: string; password_last_set?: string
}

export interface CertTemplate {
  id: string; name: string; ca_name: string; distinguished_name?: string
  enrollee_supplies_subject: boolean; requires_manager_approval: boolean
  authorized_signatures_required: number; validity_period?: string
  ekus: string[]; enrollment_rights: string[]; write_rights: string[]
  esc1_vulnerable: boolean; esc2_vulnerable: boolean; esc3_vulnerable: boolean; esc4_vulnerable: boolean
}

export interface PKISummary {
  assessment_id: string; total_templates: number; vulnerable_templates: number
  esc1_count: number; esc2_count: number; esc3_count: number; esc4_count: number; ca_names: string[]
}

export interface DashboardData {
  assessment: Assessment; exposure: ExposureSummary
  top_findings: Finding[]; coverage: CoverageItem[]
  domain_info: Record<string, unknown>; module_breakdown: Record<string, number>
}

export interface ExposureSummary {
  exposure_score: number; score_delta?: number
  severity_counts: Record<string, number>; severity_deltas: Record<string, number>
  total_findings: number; new_findings: number; resolved_findings: number; regressed_findings: number
}

export interface CoverageItem { name: string; covered: number; total: number; pct: number; status: 'good' | 'warn' | 'critical' }

export interface ReportCoverageAssurance {
  integrity_status: string
  all_findings_present_in_payload?: boolean
  selected_output_renders_complete_register_and_details?: boolean
  finding_count_reconciliation: {
    stored_findings: number
    finding_register_rows: number
    detailed_finding_rows: number
    unreported_payload_rows: number
  }
  evidence_linkage_pct?: number
  findings_without_linked_evidence?: string[]
  findings_without_remediation?: string[]
  modules_run_without_findings?: string[]
  coverage_statement?: string
}

export interface ReportDataQuality {
  readiness_score: number
  readiness_grade: string
  average_finding_confidence?: number
  finding_evidence_linkage_pct?: number
  evidence_records?: number
  corroborated_evidence_pct?: number
  quality_flags?: Record<string, number>
}

export interface ReportRiskThemeSummary {
  theme_count: number
  unique_findings_covered: number
  themes: Array<{ theme: string; finding_count: number; critical_high_count: number; max_score: number }>
}

export interface ReportPriorityActionBoard {
  total_actions: number
  immediate_actions: number
  near_term_actions: number
  planned_actions: number
}

export interface ReportPreview {
  assessment: {
    id: string; name: string; domain: string; status: string
    created_at?: string | null; started_at?: string | null; completed_at?: string | null
    modules_run: string[]; exposure_score: number; rating?: string
  }
  risk_analysis?: Record<string, unknown>
  exposure: { total_findings: number; severity_counts: Record<string, number>; origin_counts: Record<string, number>; status_counts?: Record<string, number> }
  entity_counts: Record<string, number>
  module_breakdown: Array<{ module: string; total: number }>
  coverage_assurance?: ReportCoverageAssurance
  data_quality?: ReportDataQuality
  risk_theme_summary?: ReportRiskThemeSummary
  priority_action_board?: ReportPriorityActionBoard
  top_findings: Array<{
    id: string; title: string; severity: string; module: string
    origin: DataOrigin; composite_score?: number; affected_count: number; status: string
    cve_ids?: string[]; mitre_attack_ids?: string[]; attack_path?: PathStep[]
  }>
  report_meta?: Record<string, unknown>
  available_sections?: Array<{ id: string; label: string; description: string }>
}

export interface EvidenceRecord {
  id: string; source_type: string; source_host?: string; source_port?: number; collection_method?: string
  origin: DataOrigin; collected_at: string; confidence: number
  is_corroborated: boolean; raw_data?: Record<string, unknown>
}

export interface RemediationSimResult {
  mode: string; estimate_basis: string; origin: DataOrigin; assessment_id: string
  paths_eliminated: number; paths_remaining: number; findings_resolved: string[]
  risk_reduction_pct: number; operational_impact: string[]; fix_order: RemediationFixItem[]
}

export interface RemediationFixItem {
  finding_id: string; title: string; priority: number; effort: string; impact: string; dependencies: string[]
}

export interface PlatformUser { id: string; username: string; email: string; full_name?: string; is_active: boolean; is_superadmin: boolean }
export interface AuthTokenResponse { access_token: string; token_type: string; expires_in: number; user: PlatformUser }

export interface CollectionModuleCommand { id: string; title: string; command: string; notes?: string }
export interface CollectionModuleGroup { id: string; name: string; description: string; commands: CollectionModuleCommand[] }
export interface CollectionModule {
  id: string; name: string; description: string; category: string
  supported_modes: string[]; read_only: boolean; command_groups: CollectionModuleGroup[]
  excluded_capabilities?: string[]
}

export interface ValidationModule {
  id: string
  name: string
  description: string
  /** Backend field name is risk_category (not category) */
  risk_category: string
  /** Legacy alias kept for backward compat — prefer risk_category */
  category?: string
  version?: string
  expert_count?: number
  mitre_techniques?: string[]
  severity_range?: [string, string]
}
export interface ValidationLogEntry { timestamp: number; level: string; message: string }
export interface ValidationEvidenceStep {
  title: string
  detail: string
  signal: string
  confidence: number
}

export type FinalVerdict =
  | 'LIKELY_EXPOSED'
  | 'CONDITIONALLY_EXPOSED'
  | 'LOW_CONFIDENCE_SIGNAL'
  | 'INSUFFICIENT_DATA'
  | 'NOT_SUPPORTED_BY_CURRENT_EVIDENCE'

export type ExpertVerdictValue =
  | 'SUPPORTS_EXPOSURE'
  | 'WEAK_SUPPORT'
  | 'NEUTRAL'
  | 'CONTRADICTS_EXPOSURE'
  | 'INSUFFICIENT_DATA'

export type EvidenceQualityBand = 'VERY_HIGH' | 'HIGH' | 'MODERATE' | 'LOW' | 'FRAGILE'

export interface ExpertDecision {
  expert_id: string
  expert_name: string
  /** Present in validation run detail responses */
  module_id?: string
  verdict: ExpertVerdictValue
  score_delta: number
  confidence: number
  severity_hint: string | null
  summary: string
  reasoning: string[]
  supporting_signals: string[]
  contradicting_signals: string[]
  missing_signals: string[]
  evidence_refs: string[]
  telemetry: Record<string, unknown>
  // Extended fields returned by validation run detail
  related_finding_ids?: string[]
  related_entity_ids?: string[]
  related_edge_ids?: string[]
  mitre_techniques?: string[]
  kill_chain_stage?: string
  blast_radius_hint?: number
  remediation_commands?: string[]
  detection_opportunities?: string[]
  cve_refs?: string[]
}

export interface ValidationEvidenceSummary {
  quality_score: number
  quality_band: EvidenceQualityBand
  total_records: number
  origin_distribution: Record<string, number>
  reasons: string[]
}

export interface ValidationRunSummary {
  run_id: string
  module_id: string
  status: string
  final_verdict: FinalVerdict | null
  risk_score: number | null
  confidence: number | null
  severity_projection: string | null
  execution_mode: string
  simulated: boolean
  origin: string
  created_at: string
  completed_at: string | null
}

export interface ValidationOverviewModule {
  module_id: string
  module_name: string
  has_run: boolean
  last_run_id: string | null
  last_run_at: string | null
  final_verdict: FinalVerdict | null
  risk_score: number | null
  confidence: number | null
  severity_projection: string | null
}

export interface ValidationOverview {
  assessment_id: string
  modules: ValidationOverviewModule[]
  total_modules: number
  modules_with_runs: number
}

export interface ValidationRunHistory {
  assessment_id: string
  runs: ValidationRunSummary[]
  total: number
}

export interface ValidationResult {
  // Backward-compatible fields
  module: string; status: string; logs: ValidationLogEntry[]; findings: number
  risk_score: number; origin?: DataOrigin; execution_mode?: string; simulated?: boolean
  requested_mode?: string; next_action?: { title: string; impact: string }
  confidence?: number
  operator_brief?: string
  impact?: string
  blast_radius?: string | Record<string, unknown>
  estimated_time_to_validate?: string
  mapped_attack_steps?: number
  affected_assets?: string[]
  evidence?: ValidationEvidenceStep[]
  safeguards?: string[]
  recommended_actions?: string[]
  telemetry?: Record<string, number | string | boolean>
  control_mapping?: string[]
  // consensus enriched fields
  run_id?: string
  final_verdict?: FinalVerdict
  confidence_band?: string
  consensus_score?: number
  evidence_quality_score?: number
  evidence_quality_band?: EvidenceQualityBand
  severity_projection?: string
  expert_decisions?: ExpertDecision[]
  evidence_summary?: ValidationEvidenceSummary
  contradictions?: string[]
  what_increased_confidence?: string[]
  what_reduced_confidence?: string[]
  what_would_raise_confidence?: string[]
  counts?: {
    experts_run: number
    supporting_experts: number
    contradicting_experts: number
    insufficient_data_experts: number
    supporting_evidence: number
    contradicting_signals: number
  }
  // Rich FusionResult fields returned by validation/analytics and run-detail endpoints
  module_id?: string
  assessment_id?: string
  duration_ms?: number
  support_count?: number
  contradiction_count?: number
  insufficient_count?: number
  posture_delta?: number | null
  kill_chains?: unknown[]
  cross_module_chains?: unknown[]
  threat_actor_matches?: unknown[]
  remediation_playbook?: unknown[]
  red_team_narrative?: string
  mitre_coverage?: Record<string, unknown>
  remediation_impact?: Record<string, unknown>
}

export interface ReportExportResponse {
  filename: string
  mime_type: string
  content: string
  content_encoding?: 'utf-8' | 'base64' | 'binary' | string
  byte_length?: number
  payload: Record<string, unknown>
}
export interface AuditLogEntry {
  id: string; action: string; resource_type?: string; resource_id?: string
  details: Record<string, unknown>; created_at: string; ip_address?: string
}

export interface AttackPathEntry {
  source_id?: string | null
  target_id?: string | null
  source_label: string
  target_label: string
  hop_count: number
  path_score: number
  risk_level: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'
  explanation: string
  steps: PathStep[]
  edge_types?: string[]
  category?: string
  involves_credential_access?: boolean
  involves_delegation?: boolean
  involves_adcs?: boolean
  crosses_trust?: boolean
  mitre_attack_ids?: string[]
  origin?: string
}

export interface AttackCategory {
  name: string
  icon: string
  color: string
  count: number
  paths: AttackPathEntry[]
}

export interface AttackCategoriesResponse {
  categories: Record<string, AttackCategory>
  total_paths: number
  critical_count: number
  edge_type_counts?: Record<string, number>
}

export interface AttackFlowChainsResponse extends AttackCategoriesResponse {
  paths: AttackPathEntry[]
}

export interface ChokePoint {
  node_id: string
  label: string
  node_type: string
  tier?: number
  betweenness_score: number
  paths_through: number
  paths_eliminated_on_removal?: number
  elimination_pct?: number
  is_articulation_point?: boolean
  removal_impact?: {
    paths_before: number
    paths_after: number
    paths_eliminated: number
    elimination_pct: number
  }
}

export interface ChokePointsResponse {
  choke_points: ChokePoint[]
  count: number
}

export interface ComputePathsResult {
  paths_computed: number
  assessment_id: string
  message: string
  warning_count?: number
  warnings?: string[]
}

export interface PrivEscTechnique {
  id: string
  name: string
  mitre_id: string
  mitre_url: string
  category: string
  color: string
  icon: string
  count: number
  risk: number
  description: string
  entities: string[]
  remediation: string
}

// These shapes mirror the FastAPI analyzer payloads consumed by dedicated
// frontend pages. Keep these precise: broad `unknown` index signatures break
// React rendering and erase contextual typing in page maps.

export type OffensiveSeverity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'

export interface TrustAbuseTechnique {
  technique_id: string
  name: string
  mitre_id: string | null
  cve: string | null
  tier: number
  severity: OffensiveSeverity
  attack_steps: string[]
  remediation_steps: string[]
  opsec_notes: string
  detected?: boolean
  trust?: string
  affected_domains?: string[]
}

export interface TrustAbuseChain {
  chain_id: string
  name: string
  steps: string[]
  severity: OffensiveSeverity
}

export interface TrustAbuseSummary {
  total_techniques: number
  critical_count: number
  high_count: number
  medium_count: number
  chains_detected: number
}

export interface TrustAbuseReport {
  assessment_id: string
  techniques: TrustAbuseTechnique[]
  chains: TrustAbuseChain[]
  summary: TrustAbuseSummary
}

export interface LMPathStep {
  edge_type?: string
  source_id?: string
  target_id?: string
  source_label?: string
  target_label?: string
  label?: string
}

export interface LMPath {
  id: string
  source_entity_id: string | null
  target_entity_id: string | null
  steps: LMPathStep[]
  hop_count: number
  path_score: number
}

export interface LMTechnique {
  technique_id: string
  name: string
  mitre_id: string | null
  cve: string | null
  tier: number
  severity: OffensiveSeverity
  attack_steps: string[]
  remediation_steps: string[]
  opsec_notes: string
  edge_types: string[]
}

export interface LMChain {
  chain_id: string
  name: string
  mitre_ids: string[]
  severity: OffensiveSeverity
  techniques: string[]
}

export interface LMSummary {
  total_paths: number
  techniques_detected: number
  coercion_vectors: number
  critical_chains: number
  chains: LMChain[]
  techniques: LMTechnique[]
}

export interface ForestPivotTechnique {
  technique_id: string
  name: string
  mitre_id: string | null
  cve: string | null
  tier: number
  severity: OffensiveSeverity
  attack_steps: string[]
  remediation_steps: string[]
  opsec_notes: string
  trust?: string
}

export interface ForestPivotPath {
  path: string[]
  hops: number
  start: string
  end: string
}

export interface ForestGraphNode {
  id: string
  label: string
  x: number
  y: number
  has_adcs: boolean
}

export interface ForestGraphEdge {
  source: string
  target: string
  direction: string
  transitive: boolean
  risk: OffensiveSeverity
  sid_filtering: boolean
}

export interface ForestGraph {
  nodes: ForestGraphNode[]
  edges: ForestGraphEdge[]
}

export interface ForestPivotSummary {
  total_techniques: number
  critical_count: number
  high_count: number
  forest_count: number
  pivot_paths_count: number
}

export interface ForestPivotReport {
  assessment_id: string
  techniques: ForestPivotTechnique[]
  pivot_paths: ForestPivotPath[]
  graph: ForestGraph
  summary: ForestPivotSummary
}

export interface GraphMarkingsData {
  owned_ids: string[]
  high_value_ids: string[]
  pinned_ids: string[]
}

export interface SavedGraphView {
  id: string
  name: string
  config: {
    mode: string | null
    edgeTypeFilter: string[]
    colorMode: string
    layoutMode: string
    tier0Only: boolean
    minRiskFilter: number
    toggles: Record<string, boolean>
  }
  created_at: string
}

export interface SnapshotSummary {
  id: string
  label: string | null
  created_at: string
  node_count: number
  edge_count: number
}

export interface SnapshotDiff {
  added_nodes: GraphNode[]
  removed_nodes: GraphNode[]
  added_edges: GraphEdge[]
  removed_edges: GraphEdge[]
  changed_edges: Array<{ id: string; old: GraphEdge; new: GraphEdge }>
}

export interface NLQueryResult {
  query: string
  filter_type: 'node' | 'edge' | 'none'
  node_ids: string[]
  edge_ids: string[]
  result_count: number
  explanation: string
}

export interface PathNarration {
  source: string
  target: string
  summary: string
  steps: Array<{
    hop: number
    action: string
    technique_id: string | null
    technique_name: string
    tactic: string
    tool: string
    detection_sigma: string
    remediation: string
  }>
  mitre_techniques: Array<{ technique_id: string; technique_name: string; tactic: string }>
}

export interface MonteCarloResult {
  p_success: number
  iterations: number
  histogram: number[]
  success_pct_label: string
}

export interface AnomalyResult {
  node_id: string
  node_label: string
  node_type: string
  reason: 'outlier_degree' | 'recent_edge'
  z_score?: number
  degree?: number
  severity: 'HIGH' | 'MEDIUM'
  edge_type?: string
  target_label?: string
  first_seen?: string
}

export interface AssessmentDiff {
  added_nodes: Array<{ id: string; label: string; type: string }>
  removed_nodes: Array<{ id: string; label: string; type: string }>
  added_edges: Array<{ source: string; target: string; edge_type: string; source_label: string; target_label: string }>
  removed_edges: Array<{ source: string; target: string; edge_type: string; source_label: string; target_label: string }>
  summary: { new_nodes: number; removed_nodes: number; new_edges: number; removed_edges: number }
}
