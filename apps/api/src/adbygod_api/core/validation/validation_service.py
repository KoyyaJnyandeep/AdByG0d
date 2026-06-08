from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any


class ExposureValidationService:
    """
    Safe validation simulation service.

    This service does not execute live offensive workflows. It models likely
    exposure outcomes from already-collected assessment data and returns clearly
    labeled simulated logs.
    """

    execution_mode = "SIMULATION"

    def __init__(self, assessment_id: str):
        self.assessment_id = assessment_id

    async def run_validation(self, module_id: str, target: str, mode: str = "simulation") -> dict[str, Any]:
        await asyncio.sleep(1.5)

        scenario = SIMULATION_SCENARIOS.get(module_id)
        if scenario is None:
            return {
                "status": "error",
                "message": f"Unknown module: {module_id}",
                "execution_mode": self.execution_mode,
                "origin": "SIMULATED",
                "simulated": True,
            }

        result = self._build_result(scenario, target, mode)
        result["execution_mode"] = self.execution_mode
        result["origin"] = "SIMULATED"
        result["simulated"] = True
        result["requested_mode"] = mode
        result["assessment_id"] = self.assessment_id
        return result

    def _generate_log(self, time_offset: float, level: str, message: str) -> dict[str, Any]:
        return {
            "timestamp": time_offset,
            "level": level,
            "message": message,
        }

    def _build_result(self, scenario: "ValidationSimulationScenario", target: str, mode: str) -> dict[str, Any]:
        logs = [
            self._generate_log(
                step.time_offset,
                step.level,
                step.message.format(mode=mode.upper(), target=target),
            )
            for step in scenario.logs
        ]
        return {
            "module": scenario.module,
            "status": scenario.status,
            "logs": logs,
            "findings": scenario.findings,
            "risk_score": scenario.risk_score,
            "confidence": scenario.confidence,
            "operator_brief": scenario.operator_brief,
            "impact": scenario.impact,
            "blast_radius": scenario.blast_radius,
            "estimated_time_to_validate": scenario.estimated_time_to_validate,
            "mapped_attack_steps": scenario.mapped_attack_steps,
            "affected_assets": list(scenario.affected_assets),
            "evidence": [step.as_payload() for step in scenario.evidence],
            "safeguards": list(scenario.safeguards),
            "recommended_actions": list(scenario.recommended_actions),
            "telemetry": scenario.telemetry,
            "control_mapping": list(scenario.control_mapping),
        }


@dataclass(frozen=True, slots=True)
class ValidationLogStep:
    time_offset: float
    level: str
    message: str


@dataclass(frozen=True, slots=True)
class ValidationEvidenceStep:
    title: str
    detail: str
    signal: str
    confidence: int

    def as_payload(self) -> dict[str, Any]:
        return {
            "title": self.title,
            "detail": self.detail,
            "signal": self.signal,
            "confidence": self.confidence,
        }


@dataclass(frozen=True, slots=True)
class ValidationSimulationScenario:
    module: str
    status: str
    findings: int
    risk_score: float
    confidence: int
    operator_brief: str
    impact: str
    blast_radius: str
    estimated_time_to_validate: str
    mapped_attack_steps: int
    logs: tuple[ValidationLogStep, ...]
    affected_assets: tuple[str, ...]
    evidence: tuple[ValidationEvidenceStep, ...]
    safeguards: tuple[str, ...]
    recommended_actions: tuple[str, ...]
    telemetry: dict[str, Any]
    control_mapping: tuple[str, ...]


SIMULATION_SCENARIOS: dict[str, ValidationSimulationScenario] = {
    "kerberos": ValidationSimulationScenario(
        module="Kerberos Exposure Validation",
        status="vulnerable",
        findings=15,
        risk_score=8.5,
        confidence=91,
        operator_brief="Credential exposure model shows roastable and SPN-bearing principals that could convert weak service hygiene into privileged identity compromise.",
        impact="Offline credential cracking pressure against service and legacy accounts with downstream privilege path potential.",
        blast_radius="12 service principals, 3 pre-auth disabled users, 4 privileged group intersections",
        estimated_time_to_validate="6-9 min",
        mapped_attack_steps=7,
        logs=(
            ValidationLogStep(0.0, "INFO", "[SIMULATION:{mode}] Modeling Kerberos exposure conditions for {target}..."),
            ValidationLogStep(0.2, "INFO", "Target domain identified: ACME.CORP"),
            ValidationLogStep(0.4, "INFO", "Reviewing AS-REP roast preconditions from collected directory state..."),
            ValidationLogStep(0.8, "WARN", "Found 3 accounts with 'Does not require pre-authentication' enabled."),
            ValidationLogStep(1.3, "INFO", "Modeling Kerberoast exposure from discovered SPN-bearing principals..."),
            ValidationLogStep(2.1, "WARN", "Discovered 12 high-privilege service tickets structurally exposed to offline cracking."),
            ValidationLogStep(2.4, "SUCCESS", "Simulation complete. 15 logical exposures mapped in the graph."),
        ),
        affected_assets=("svc_sql_legacy", "svc_backup", "web-tier-spn", "ACME.CORP"),
        evidence=(
            ValidationEvidenceStep("AS-REP roast window", "Three enabled principals are modeled with pre-authentication disabled.", "Directory attribute: DONT_REQ_PREAUTH", 94),
            ValidationEvidenceStep("SPN privilege concentration", "Twelve SPN-bearing accounts intersect with privileged groups or admin host reachability.", "Graph joins: HAS_SPN + MEMBER_OF", 89),
            ValidationEvidenceStep("Delegation adjacency", "One exposed service identity is adjacent to constrained delegation paths.", "Edge class: ALLOWED_TO_DELEGATE", 82),
        ),
        safeguards=("Simulation-only execution", "No ticket requests issued", "No credential material generated", "Audit labels include SIMULATED origin"),
        recommended_actions=("Rotate high-privilege service passwords with managed identity migration", "Disable pre-auth exemption unless a documented legacy dependency exists", "Move SPN accounts out of privileged groups and add tiering guardrails"),
        telemetry={"queries_modeled": 18, "graph_edges_reviewed": 146, "tier0_intersections": 4, "policy_checks": 9},
        control_mapping=("MITRE ATT&CK T1558", "CIS Microsoft Windows Server 18.9", "AD tiering model: Credential boundary"),
    ),
    "ntlm_relay": ValidationSimulationScenario(
        module="Relay Exposure Assessment",
        status="vulnerable",
        findings=42,
        risk_score=9.8,
        confidence=96,
        operator_brief="Relay precondition model indicates broad SMB signing weakness and coercion-compatible paths that could pressure identity infrastructure.",
        impact="High probability of lateral movement and certificate relay exposure where coercion and unsigned services overlap.",
        blast_radius="42 relay-compatible assets, 1 domain controller exposure adjacency, 2 PKI relay candidates",
        estimated_time_to_validate="8-12 min",
        mapped_attack_steps=9,
        logs=(
            ValidationLogStep(0.0, "INFO", "[SIMULATION:{mode}] Modeling NTLM relay preconditions for {target}..."),
            ValidationLogStep(0.3, "INFO", "Reviewing SMB signing requirements across discovered hosts..."),
            ValidationLogStep(0.5, "WARN", "SMB signing is disabled or not required on 42 distinct target assets."),
            ValidationLogStep(1.1, "INFO", "Modeling coercion paths against the current graph and service posture..."),
            ValidationLogStep(1.8, "WARN", "Relay-compatible coercion exposure identified against DC01.ACME.CORP."),
            ValidationLogStep(2.5, "SUCCESS", "Simulation completed successfully for PKI/CA relay exposure scenarios."),
        ),
        affected_assets=("DC01.ACME.CORP", "CA01.ACME.CORP", "FS-LEGACY-07", "PRINT-03"),
        evidence=(
            ValidationEvidenceStep("Unsigned SMB posture", "Forty-two hosts are modeled as signing disabled or not required.", "SMB posture collection", 97),
            ValidationEvidenceStep("Coercion adjacency", "Domain controller service posture overlaps with relay-compatible paths.", "Service graph + host policy", 92),
            ValidationEvidenceStep("PKI relay candidate", "CA web enrollment posture is modeled as reachable from relay paths.", "AD CS endpoint metadata", 86),
        ),
        safeguards=("No coercion traffic emitted", "No relay listener started", "No authentication forwarding attempted", "Result is safe modeled validation"),
        recommended_actions=("Require SMB signing on servers and workstations", "Disable unnecessary coercion surfaces and spooler exposure", "Harden AD CS web enrollment and require EPA/channel binding"),
        telemetry={"hosts_modeled": 128, "unsigned_hosts": 42, "coercion_candidates": 6, "pki_paths": 2},
        control_mapping=("MITRE ATT&CK T1557.001", "Microsoft SMB signing baseline", "AD CS ESC8 hardening"),
    ),
    "acl": ValidationSimulationScenario(
        module="Privilege Delegation Risk",
        status="vulnerable",
        findings=1,
        risk_score=10.0,
        confidence=93,
        operator_brief="Graph-backed ACL modeling shows a lower-tier identity path that can structurally cross into Tier-0 control.",
        impact="Single toxic delegation edge creates a direct privilege escalation route into Domain Admins.",
        blast_radius="1 high-impact path, 3 hops to Tier-0, Domain Admins target group",
        estimated_time_to_validate="4-6 min",
        mapped_attack_steps=5,
        logs=(
            ValidationLogStep(0.0, "INFO", "[SIMULATION:{mode}] Modeling privilege delegation paths for {target}..."),
            ValidationLogStep(0.2, "INFO", "Traversed graph edges for WriteDacl, GenericAll, and ForceChangePassword relationships..."),
            ValidationLogStep(0.6, "INFO", "Identified structurally anomalous GenericAll permission on Domain Admins via 'Helpdesk' tier grouping."),
            ValidationLogStep(1.4, "WARN", "Simulation shows lower-tier identity takeover path into Domain Admins."),
            ValidationLogStep(1.7, "SUCCESS", "Simulation completed for delegation misconfiguration path to Tier-0."),
        ),
        affected_assets=("Helpdesk", "Domain Admins", "ADG0D_TARGET_SVC1"),
        evidence=(
            ValidationEvidenceStep("Toxic DACL", "GenericAll is modeled from a lower-tier operator group toward a privileged principal.", "ACL edge: GENERIC_ALL", 95),
            ValidationEvidenceStep("Tier boundary crossing", "Path crosses from Tier-2 administration into Tier-0 group control.", "Tier metadata + graph traversal", 91),
            ValidationEvidenceStep("Low hop count", "The modeled route reaches crown-jewel control within three hops.", "Shortest path analysis", 93),
        ),
        safeguards=("No ACL writes performed", "No group membership changed", "No password reset attempted", "Read-only graph simulation"),
        recommended_actions=("Remove toxic ACLs from privileged groups", "Apply owner review for delegated admin groups", "Add continuous drift detection for Tier-0 ACL changes"),
        telemetry={"paths_scored": 31, "toxic_edges": 1, "tier_crossings": 1, "average_hops": 3},
        control_mapping=("MITRE ATT&CK T1098", "Microsoft ESAE tiering", "CIS control: Account permissions"),
    ),
    "dcsync": ValidationSimulationScenario(
        module="Replication Rights Exposure",
        status="vulnerable",
        findings=2,
        risk_score=10.0,
        confidence=95,
        operator_brief="Replication-rights model identifies non-default principals with sufficient directory replication privileges to threaten domain credential material.",
        impact="Modeled path could expose krbtgt-equivalent credential replication if abused in a live environment.",
        blast_radius="2 replication-capable principals, domain root scope, krbtgt exposure path",
        estimated_time_to_validate="5-8 min",
        mapped_attack_steps=6,
        logs=(
            ValidationLogStep(0.0, "INFO", "[SIMULATION:{mode}] Modeling replication rights exposure for {target}..."),
            ValidationLogStep(0.1, "INFO", "Reviewing domain root ACL for DS-Replication-Get-Changes-All permissions..."),
            ValidationLogStep(0.4, "WARN", "Found 2 non-default principals with high-value replication rights: 'svc_azure_sync' and 'Admin-Bob'."),
            ValidationLogStep(1.1, "INFO", "Mapping Directory Replication Service exposure paths from those principals..."),
            ValidationLogStep(1.4, "SUCCESS", "Simulation confirms plausible krbtgt replication exposure path to Tier-0."),
        ),
        affected_assets=("svc_azure_sync", "Admin-Bob", "ACME.CORP domain root"),
        evidence=(
            ValidationEvidenceStep("Replication permission", "Two non-default principals are modeled with replication-all semantics.", "DS-Replication-Get-Changes-All", 96),
            ValidationEvidenceStep("Domain root scope", "Rights are scoped at domain root, not a constrained OU boundary.", "ACL inheritance analysis", 94),
            ValidationEvidenceStep("Privileged identity overlap", "One principal intersects with administrative identity posture.", "Entity tier + group membership", 88),
        ),
        safeguards=("No DRSUAPI call issued", "No secrets requested", "No credential extraction performed", "Simulation preserves domain safety"),
        recommended_actions=("Remove replication rights from non-approved principals", "Validate Azure AD Connect service account scoping", "Alert on directory replication permission drift"),
        telemetry={"acl_entries_reviewed": 84, "replication_principals": 2, "domain_scope_edges": 2, "tier0_links": 1},
        control_mapping=("MITRE ATT&CK T1003.006", "Microsoft privileged access model", "Identity secure score: Directory roles"),
    ),
    "trust": ValidationSimulationScenario(
        module="Trust Boundary Risk",
        status="vulnerable",
        findings=1,
        risk_score=9.0,
        confidence=87,
        operator_brief="Trust boundary model flags a bidirectional external relationship where SID filtering posture could allow privileged context bleed across realms.",
        impact="Cross-forest trust abuse may allow privilege influence outside the intended identity boundary.",
        blast_radius="1 external trust, 2 privileged group mappings, vendor forest adjacency",
        estimated_time_to_validate="7-10 min",
        mapped_attack_steps=6,
        logs=(
            ValidationLogStep(0.0, "INFO", "[SIMULATION:{mode}] Modeling trust boundary policies for {target}..."),
            ValidationLogStep(0.3, "INFO", "Analyzing transitive trust relationships across forest boundaries..."),
            ValidationLogStep(0.7, "INFO", "Found bidirectional trust linkage mapped to VENDOR.LOCAL lacking SID filtering."),
            ValidationLogStep(1.5, "WARN", "Simulation indicates cross-realm SID history abuse could affect privileged trust flow."),
            ValidationLogStep(2.0, "SUCCESS", "Simulation completed for cross-forest trust exposure modeling."),
        ),
        affected_assets=("VENDOR.LOCAL", "ACME.CORP", "Enterprise Admins shadow path"),
        evidence=(
            ValidationEvidenceStep("Trust direction", "Bidirectional trust relationship is modeled across forest boundary.", "Trust attribute collection", 89),
            ValidationEvidenceStep("SID filtering gap", "SID filtering is modeled as absent or insufficiently enforced.", "Trust policy metadata", 84),
            ValidationEvidenceStep("Privilege mapping", "Privileged group flow intersects with trusted-domain identities.", "Cross-domain graph traversal", 86),
        ),
        safeguards=("No cross-realm authentication attempted", "No SID history manipulation", "No trust modification", "Modeled trust policy evaluation only"),
        recommended_actions=("Enforce SID filtering and selective authentication", "Review cross-forest privileged mappings", "Document trust owners and add recurring trust posture review"),
        telemetry={"trusts_reviewed": 5, "external_trusts": 1, "policy_gaps": 1, "privileged_mappings": 2},
        control_mapping=("MITRE ATT&CK T1484.002", "Microsoft forest trust hardening", "Zero Trust identity boundary controls"),
    ),
}
