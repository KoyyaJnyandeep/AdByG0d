from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_serializer

from adbygod_api.core.security.at_rest import redact_sensitive_mapping
from adbygod_api.models import AssessmentStatus, ConnectivityMode, ConnectivityProfileStatus, DataOrigin, EntityType, FindingStatus, SeverityLevel

_orm = ConfigDict(from_attributes=True)


class LoginRequest(BaseModel):
    username: str
    password: str


class UserOut(BaseModel):
    model_config = _orm

    id: UUID
    username: str
    email: str
    full_name: str | None = None
    is_active: bool
    is_superadmin: bool


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    user: "UserOut"


class AssessmentCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    domain: str = Field(..., description="Target domain FQDN")
    dc_ip: str | None = None
    collection_mode: str = "LINUX_REMOTE"
    collection_config: dict[str, Any] = Field(default_factory=dict)
    workspace_id: UUID | None = None
    connectivity_profile_id: UUID | None = None


class AssessmentOut(BaseModel):
    model_config = _orm

    id: UUID
    name: str
    domain: str
    dc_ip: str | None = None
    status: AssessmentStatus
    collection_mode: str | None = None
    started_at: datetime | None = None
    completed_at: datetime | None = None
    created_at: datetime
    modules_run: list[str]
    stats: dict[str, Any]
    exposure_score: float
    progress_pct: int = 0
    last_message: str | None = None
    connectivity_profile_id: UUID | None = None


class AssessmentDetail(AssessmentOut):
    collection_config: dict[str, Any]
    error_message: str | None = None
    previous_assessment_id: UUID | None = None

    @field_serializer("collection_config")
    def redact_collection_config(self, value: dict[str, Any], _info) -> dict[str, Any]:
        return redact_sensitive_mapping(value or {})


class AssessmentUpdate(BaseModel):
    name: str | None = Field(None, min_length=1, max_length=255)
    domain: str | None = None
    dc_ip: str | None = None
    username: str | None = None
    password: str | None = None


class WorkspaceOption(BaseModel):
    model_config = _orm

    id: UUID
    name: str
    description: str | None = None


class FindingOut(BaseModel):
    model_config = _orm

    id: UUID
    assessment_id: UUID
    finding_type: str
    module: str
    title: str
    description: str | None = None
    origin: DataOrigin
    severity: SeverityLevel
    confidence: float
    composite_score: float | None = None
    affected_count: int
    affected_objects: list[Any]
    root_cause: str | None = None
    causal_chain: list[Any]
    status: FindingStatus
    drift_status: str | None = None
    remediation: str | None = None
    remediation_steps: list[Any]
    fix_complexity: str | None = None
    references: list[str]
    attack_path: list[Any]
    cve_ids: list[str]
    mitre_attack_ids: list[str]
    first_seen: datetime
    last_seen: datetime
    created_at: datetime


class FindingEvidenceLinkOut(BaseModel):
    id: UUID
    evidence_id: UUID
    relation_type: str = "supports"
    # edge_level | object_level | aggregate_level | payload_level_fallback
    evidence_strength: str = "payload_level_fallback"
    relevance: str | None = None
    source_ref: dict[str, Any] = Field(default_factory=dict)
    source_type: str | None = None
    source_host: str | None = None
    collection_method: str | None = None
    origin: DataOrigin | None = None
    confidence: float | None = None
    is_corroborated: bool | None = None


class FindingDetail(FindingOut):
    technical_severity: float | None = None
    reachability_score: float | None = None
    asset_criticality: float | None = None
    estimated_effort: str | None = None
    waiver_reason: str | None = None
    waiver_expiry: datetime | None = None
    evidence_links: list[FindingEvidenceLinkOut] = Field(default_factory=list)


class FindingUpdate(BaseModel):
    status: FindingStatus | None = None
    assigned_to: UUID | None = None
    waiver_reason: str | None = None
    waiver_expiry: datetime | None = None
    waiver_owner: str | None = None


class FindingsFilter(BaseModel):
    severity: list[SeverityLevel] | None = None
    module: list[str] | None = None
    status: list[FindingStatus] | None = None
    min_score: float | None = None
    drift_status: str | None = None
    assigned_to: UUID | None = None
    search: str | None = None
    page: int = 1
    page_size: int = 50
    sort_by: str = "composite_score"
    sort_desc: bool = True


class FindingsPage(BaseModel):
    items: list[FindingOut]
    total: int
    page: int
    page_size: int
    pages: int


class EntityOut(BaseModel):
    model_config = _orm

    id: UUID
    entity_type: EntityType
    distinguished_name: str | None = None
    object_sid: str | None = None
    sam_account_name: str | None = None
    display_name: str | None = None
    domain: str | None = None
    is_enabled: bool
    is_admin_count: bool
    is_sensitive: bool
    is_protected_user: bool
    tier: int | None = None
    is_crown_jewel: bool
    business_tags: list[str]


class EntityDetail(EntityOut):
    dns_hostname: str | None = None
    owner_team: str | None = None
    attributes: dict[str, Any]
    object_created: datetime | None = None
    object_modified: datetime | None = None
    last_logon: datetime | None = None
    password_last_set: datetime | None = None


class GraphNode(BaseModel):
    id: str
    label: str
    entity_type: str
    tier: int | None = None
    is_crown_jewel: bool
    is_admin_count: bool = False
    severity_count: dict[str, int] = Field(default_factory=dict)
    attributes: dict[str, Any] = Field(default_factory=dict)


class GraphEdgeOut(BaseModel):
    id: str
    source: str
    target: str
    edge_type: str
    provenance: str | None = None
    risk_weight: float
    edge_confidence: float = 1.0
    edge_provenance_type: str = "collected"


class GraphData(BaseModel):
    nodes: list[GraphNode]
    edges: list[GraphEdgeOut]
    node_count: int
    edge_count: int


class PathStep(BaseModel):
    entity_id: str
    entity_label: str
    entity_type: str
    edge_type: str | None = None
    provenance: str | None = None
    explanation: str


class ExposurePathOut(BaseModel):
    model_config = _orm

    id: UUID
    source_label: str
    target_label: str
    path_steps: list[PathStep]
    hop_count: int
    path_score: float
    target_tier: int | None = None
    explanation: str


class EvidenceOut(BaseModel):
    model_config = _orm

    id: UUID
    source_type: str
    source_host: str | None = None
    source_port: int | None = None
    collection_method: str | None = None
    origin: DataOrigin
    collected_at: datetime
    confidence: float
    is_corroborated: bool
    raw_data: dict[str, Any] | None = None


class ExposureSummary(BaseModel):
    exposure_score: float
    score_delta: float | None = None
    severity_counts: dict[str, int]
    severity_deltas: dict[str, int]
    total_findings: int
    new_findings: int
    resolved_findings: int
    regressed_findings: int


class CoverageItem(BaseModel):
    name: str
    covered: int
    total: int
    pct: float
    status: str


class DashboardData(BaseModel):
    assessment: AssessmentOut
    exposure: ExposureSummary
    top_findings: list[FindingOut]
    coverage: list[CoverageItem]
    domain_info: dict[str, Any]
    module_breakdown: dict[str, int]


class RemediationCandidate(BaseModel):
    finding_id: str
    title: str
    severity: str
    score: float
    effort: str
    impact: str


class RemediationSimInput(BaseModel):
    assessment_id: UUID
    finding_ids: list[UUID]
    simulate_edge_removal: list[dict[str, str]] | None = None


class RemediationSimResult(BaseModel):
    mode: str = "ESTIMATED_SIMULATION"
    estimate_basis: str = "Heuristic estimate"
    origin: DataOrigin = DataOrigin.SIMULATED
    assessment_id: UUID
    paths_eliminated: int
    paths_remaining: int
    findings_resolved: list[UUID]
    risk_reduction_pct: float
    blast_radius_reduction: int = 0
    graph_powered: bool = False
    operational_impact: list[str]
    fix_order: list[dict[str, Any]]


class CollectorIngest(BaseModel):
    schema_version: str = "1.0"
    tool: str = "AdByG0d"
    collection_mode: str
    domain: str
    dc_ip: str | None = None
    collected_at: str
    collector_version: str
    modules_run: list[str]
    entities: list[dict[str, Any]]
    edges: list[dict[str, Any]]
    evidence: list[dict[str, Any]]
    findings: list[dict[str, Any]]
    # mutable defaults replaced with Field(default_factory=...)
    cert_templates: list[dict[str, Any]] = Field(default_factory=list)
    ca_flags: list[dict[str, Any]] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


TokenResponse.model_rebuild()


class ConnectivityProfileCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    mode: "ConnectivityMode"
    config: dict[str, Any] = Field(default_factory=dict)
    is_default: bool = False
    notes: str | None = None


class ConnectivityProfileUpdate(BaseModel):
    name: str | None = None
    config: dict[str, Any] | None = None
    is_default: bool | None = None
    notes: str | None = None


class ConnectivityProfileOut(BaseModel):
    model_config = _orm

    id: UUID
    name: str
    mode: "ConnectivityMode"
    config: dict[str, Any]
    is_default: bool
    status: "ConnectivityProfileStatus"
    last_tested_at: datetime | None = None
    last_latency_ms: int | None = None
    notes: str | None = None
    created_at: datetime


class ConnectivityTestResult(BaseModel):
    profile_id: UUID
    success: bool
    status: ConnectivityProfileStatus = ConnectivityProfileStatus.OFFLINE
    latency_ms: int | None = None
    error: str | None = None
    details: dict[str, Any] = Field(default_factory=dict)
    capabilities: dict[str, bool] = Field(default_factory=dict)
    readiness_pct: int = 0
    open_ports: list[int] = Field(default_factory=list)


class ConnectivityStats(BaseModel):
    total: int
    online: int
    offline: int
    degraded: int
    unknown: int
    active_tunnels: int
    best_latency_ms: int | None = None
    total_open_ports: int
    modes_used: list[str]


class ChiselServerStatus(BaseModel):
    running: bool
    pid: int | None = None
    port: int | None = None
    client_cmd: str | None = None
    client_cmd_template: str | None = None
    connected_clients: int = 0


class LigoloStatus(BaseModel):
    running: bool
    pid: int | None = None
    port: int | None = None
    tun_interface: str | None = None
    routes: list[str] = Field(default_factory=list)
    sessions: list[dict[str, Any]] = Field(default_factory=list)


class TunnelStartRequest(BaseModel):
    password: str | None = None  # runtime-only, never persisted


class TunnelSessionOut(BaseModel):
    model_config = _orm

    id: UUID
    profile_id: UUID
    mode: str
    jumpbox_host: str
    jumpbox_port: int
    jumpbox_username: str
    local_host: str
    local_port: int
    process_pid: int | None = None
    status: str
    started_by: UUID
    started_at: datetime
    stopped_at: datetime | None = None
    last_healthcheck_at: datetime | None = None
    error_summary: str | None = None
    sanitized_command_preview: str
    metadata_json: dict[str, Any]
    tunnel_endpoint: str | None = None  # set by route, not DB column
