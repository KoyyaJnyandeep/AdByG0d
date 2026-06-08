from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Any


class ExpertVerdict(str, enum.Enum):
    SUPPORTS_EXPOSURE = "SUPPORTS_EXPOSURE"
    WEAK_SUPPORT = "WEAK_SUPPORT"
    NEUTRAL = "NEUTRAL"
    CONTRADICTS_EXPOSURE = "CONTRADICTS_EXPOSURE"
    INSUFFICIENT_DATA = "INSUFFICIENT_DATA"


class FinalVerdict(str, enum.Enum):
    LIKELY_EXPOSED = "LIKELY_EXPOSED"
    CONDITIONALLY_EXPOSED = "CONDITIONALLY_EXPOSED"
    LOW_CONFIDENCE_SIGNAL = "LOW_CONFIDENCE_SIGNAL"
    INSUFFICIENT_DATA = "INSUFFICIENT_DATA"
    NOT_SUPPORTED_BY_CURRENT_EVIDENCE = "NOT_SUPPORTED_BY_CURRENT_EVIDENCE"


class EvidenceQualityBand(str, enum.Enum):
    VERY_HIGH = "VERY_HIGH"
    HIGH = "HIGH"
    MODERATE = "MODERATE"
    LOW = "LOW"
    FRAGILE = "FRAGILE"


class ConfidenceBand(str, enum.Enum):
    VERY_HIGH = "VERY_HIGH"
    HIGH = "HIGH"
    MODERATE = "MODERATE"
    LOW = "LOW"


@dataclass
class ExpertDecision:
    expert_id: str
    expert_name: str
    module_id: str
    verdict: ExpertVerdict
    score_delta: float = 0.0          # -1.0 to +1.0
    confidence: float = 0.5           # 0.0-1.0
    severity_hint: str | None = None
    summary: str = ""
    reasoning: list[str] = field(default_factory=list)
    supporting_signals: list[str] = field(default_factory=list)
    contradicting_signals: list[str] = field(default_factory=list)
    missing_signals: list[str] = field(default_factory=list)
    evidence_refs: list[str] = field(default_factory=list)
    related_finding_ids: list[str] = field(default_factory=list)
    related_entity_ids: list[str] = field(default_factory=list)
    related_edge_ids: list[str] = field(default_factory=list)
    telemetry: dict[str, Any] = field(default_factory=dict)
    mitre_techniques: list[str] = field(default_factory=list)      # e.g. ["T1558.003"]
    kill_chain_stage: str = ""                                       # "initial_access"|"credential_access"|"lateral_movement"|"persistence"|"privilege_escalation"|"exfiltration"
    blast_radius_hint: int = 0                                       # estimated reachable assets
    remediation_commands: list[str] = field(default_factory=list)   # PowerShell one-liners
    detection_opportunities: list[str] = field(default_factory=list) # blue team signals
    cve_refs: list[str] = field(default_factory=list)               # e.g. ["CVE-2022-26923"]


@dataclass
class KillChainStep:
    step_index: int
    module_id: str
    finding_id: str | None
    technique: str
    mitre_id: str
    description: str
    entity_ids: list[str] = field(default_factory=list)


@dataclass
class KillChain:
    chain_id: str
    name: str
    composite_risk: float
    steps: list[KillChainStep] = field(default_factory=list)
    narrative: str = ""
    threat_actors: list[str] = field(default_factory=list)


@dataclass
class BlastRadiusResult:
    origin_entity_id: str = ""
    reachable_computers: int = 0
    reachable_domain_controllers: int = 0
    reachable_domains: int = 0
    reachable_ous: int = 0
    reachable_groups: int = 0
    reachable_users: int = 0
    total_reachable: int = 0
    tier0_reachable: bool = False
    critical_paths: list[str] = field(default_factory=list)


@dataclass
class CrossModuleChain:
    chain_id: str
    modules: list[str] = field(default_factory=list)
    individual_severities: list[str] = field(default_factory=list)
    compound_severity: str = "HIGH"
    compound_risk: float = 0.0
    explanation: str = ""
    steps: list[str] = field(default_factory=list)


@dataclass
class ThreatActorMatch:
    actor_id: str
    actor_name: str
    match_score: float = 0.0
    matched_techniques: list[str] = field(default_factory=list)
    known_campaigns: list[str] = field(default_factory=list)
    description: str = ""


@dataclass
class PlaybookStep:
    step_index: int
    title: str
    description: str = ""
    commands: list[str] = field(default_factory=list)
    applies_to: list[str] = field(default_factory=list)
    verification_command: str = ""
    mitre_mitigates: list[str] = field(default_factory=list)
    priority: str = "MEDIUM"


@dataclass
class FusionResult:
    final_verdict: FinalVerdict
    risk_score: float               # 0.0-10.0
    confidence: int                 # 0-100
    consensus_score: int            # 0-100
    evidence_quality_score: int     # 0-100
    evidence_quality_band: EvidenceQualityBand
    confidence_band: ConfidenceBand
    severity_projection: str        # CRITICAL | HIGH | MEDIUM | LOW | INFO
    summary: str
    operator_brief: str
    impact: str
    blast_radius: BlastRadiusResult
    mapped_attack_steps: int
    what_increased_confidence: list[str]
    what_reduced_confidence: list[str]
    what_would_raise_confidence: list[str]
    recommended_actions: list[str]
    safeguards: list[str]
    control_mapping: list[str]
    telemetry: dict[str, Any]
    support_count: int
    contradiction_count: int
    insufficient_count: int
    evidence_summary: dict[str, Any]
    contradictions: list[str]
    kill_chains: list[KillChain] = field(default_factory=list)
    cross_module_chains: list[CrossModuleChain] = field(default_factory=list)
    threat_actor_matches: list[ThreatActorMatch] = field(default_factory=list)
    remediation_playbook: list[PlaybookStep] = field(default_factory=list)
    red_team_narrative: str = ""
    mitre_coverage: dict[str, list[str]] = field(default_factory=dict)
    remediation_impact: dict[str, float] = field(default_factory=dict)
    posture_delta: float | None = None
    module_id: str = ""
    run_id: str = ""
    assessment_id: str = ""
    duration_ms: int = 0
