from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from adbygod_api.models import (
    Assessment,
    CertTemplate,
    Entity,
    EvidenceRecord,
    ExposurePath,
    Finding,
    GraphEdge,
)
from adbygod_api.core.graph.graph_service import ADGraphAnalyzer

log = logging.getLogger(__name__)


@dataclass
class ValidationAssessmentContext:
    assessment_id: str
    domain: str
    collection_mode: str

    entities: list[Any] = field(default_factory=list)
    entity_index: dict[str, Any] = field(default_factory=dict)       # id -> Entity ORM

    edges: list[Any] = field(default_factory=list)
    edge_type_index: dict[str, list[Any]] = field(default_factory=dict)  # edge_type -> [GraphEdge]

    findings: list[Any] = field(default_factory=list)
    finding_index: dict[str, Any] = field(default_factory=dict)      # id -> Finding ORM
    module_findings: dict[str, list[Any]] = field(default_factory=dict)  # module -> [Finding]

    evidence: list[Any] = field(default_factory=list)
    evidence_index: dict[str, Any] = field(default_factory=dict)     # id -> EvidenceRecord ORM

    cert_templates: list[Any] = field(default_factory=list)
    exposure_paths: list[Any] = field(default_factory=list)

    analyzer: ADGraphAnalyzer | None = None

    # Completeness flags
    has_entities: bool = False
    has_edges: bool = False
    has_findings: bool = False
    has_evidence: bool = False
    has_cert_templates: bool = False
    has_exposure_paths: bool = False

    # Origin distribution
    origin_distribution: dict[str, int] = field(default_factory=dict)

    # Module coverage (set of module names that appear in findings)
    module_coverage: set[str] = field(default_factory=set)

    # Scale metrics
    computer_count: int = 0
    dc_count: int = 0
    domain_count: int = 1
    ou_count: int = 0

    # Tier-0 tracking
    tier0_entities: list[str] = field(default_factory=list)   # entity IDs flagged as tier-0

    # ADCS
    certificate_templates: list[dict] = field(default_factory=list)

    # GPO
    gpo_objects: list[dict] = field(default_factory=list)

    # LAPS
    laps_computers: list[str] = field(default_factory=list)   # computer entity IDs with LAPS enabled

    # Shadow Credentials
    shadow_credential_edges: list[dict] = field(default_factory=list)   # msDS-KeyCredentialLink write edges

    # SID History
    sid_history_entities: list[dict] = field(default_factory=list)   # {entity_id, sid_history, resolved_sids}

    # Password Policy
    password_policy_objects: list[dict] = field(default_factory=list)   # fine-grained + default policies

    # MAQ
    maq_value: int = 10   # ms-DS-MachineAccountQuota default

    # Delegation
    unconstrained_delegation: list[str] = field(default_factory=list)   # entity IDs with TrustedForDelegation
    constrained_delegation: list[dict] = field(default_factory=list)   # {entity_id, allowed_spns}
    rbcd_edges: list[dict] = field(default_factory=list)   # msDS-AllowedToActOnBehalfOfOtherIdentity edges

    # Spray candidates
    spray_candidates: list[dict] = field(default_factory=list)   # accounts with weak/no policy

    # Alias for domain (some callers use domain_name)
    @property
    def domain_name(self) -> str:
        return self.domain

    def entity_name(self, entity_id: str) -> str:
        e = self.entity_index.get(str(entity_id))
        if e is None:
            return entity_id
        return e.sam_account_name or e.display_name or str(entity_id)

    def edge_name(self, src_id: str, tgt_id: str) -> str:
        return f"{self.entity_name(src_id)} -> {self.entity_name(tgt_id)}"


async def build_validation_context(
    assessment_id: str,
    db: AsyncSession,
) -> ValidationAssessmentContext:
    import uuid as _uuid
    aid = _uuid.UUID(str(assessment_id))

    # Load assessment
    assessment = (await db.execute(select(Assessment).where(Assessment.id == aid))).scalar_one_or_none()
    if assessment is None:
        raise ValueError(f"Assessment {assessment_id} not found")

    domain = assessment.domain or ""
    collection_mode = (assessment.collection_mode.value if assessment.collection_mode else "UNKNOWN")

    ctx = ValidationAssessmentContext(
        assessment_id=str(assessment_id),
        domain=domain,
        collection_mode=collection_mode,
    )

    # Load entities
    entities = (await db.execute(select(Entity).where(Entity.assessment_id == aid))).scalars().all()
    ctx.entities = list(entities)
    ctx.entity_index = {str(e.id): e for e in entities}
    ctx.has_entities = bool(entities)

    # Load edges
    edges = (await db.execute(select(GraphEdge).where(GraphEdge.assessment_id == aid))).scalars().all()
    ctx.edges = list(edges)
    ctx.has_edges = bool(edges)
    for edge in edges:
        etype = edge.edge_type.value if edge.edge_type else "UNKNOWN"
        ctx.edge_type_index.setdefault(etype, []).append(edge)

    # Load findings
    findings = (await db.execute(select(Finding).where(Finding.assessment_id == aid))).scalars().all()
    ctx.findings = list(findings)
    ctx.finding_index = {str(f.id): f for f in findings}
    ctx.has_findings = bool(findings)
    for f in findings:
        ctx.module_findings.setdefault(f.module, []).append(f)
        ctx.module_coverage.add(f.module)

    # Load evidence
    evidence = (await db.execute(select(EvidenceRecord).where(EvidenceRecord.assessment_id == aid))).scalars().all()
    ctx.evidence = list(evidence)
    ctx.evidence_index = {str(e.id): e for e in evidence}
    ctx.has_evidence = bool(evidence)

    # Build origin distribution
    for ev in evidence:
        origin = ev.origin.value if ev.origin else "UNKNOWN"
        ctx.origin_distribution[origin] = ctx.origin_distribution.get(origin, 0) + 1

    # Load cert templates
    cert_templates = (await db.execute(select(CertTemplate).where(CertTemplate.assessment_id == aid))).scalars().all()
    ctx.cert_templates = list(cert_templates)
    ctx.has_cert_templates = bool(cert_templates)

    # Load exposure paths
    exposure_paths = (await db.execute(select(ExposurePath).where(ExposurePath.assessment_id == aid))).scalars().all()
    ctx.exposure_paths = list(exposure_paths)
    ctx.has_exposure_paths = bool(exposure_paths)

    # Populate scale metrics from entity list
    tier0_names = {"domain admins", "enterprise admins", "krbtgt", "schema admins", "administrators"}
    tier0_ids: list[str] = []
    computer_count = 0
    dc_count = 0
    ou_count = 0

    for e in entities:
        etype = (e.entity_type.value if e.entity_type else "") or ""
        etype_lower = etype.lower()
        props = e.attributes or {}

        if "computer" in etype_lower:
            computer_count += 1
        if "domaincontroller" in etype_lower or "domain_controller" in etype_lower or props.get("isDC") or props.get("is_dc"):
            dc_count += 1
        if "organizationalunit" in etype_lower or "ou" == etype_lower:
            ou_count += 1

        # Tier-0 check: name-based heuristic
        name_lower = (
            (e.sam_account_name or e.display_name or "")
        ).lower()
        if any(t0 in name_lower for t0 in tier0_names):
            tier0_ids.append(str(e.id))

    ctx.computer_count = computer_count
    ctx.dc_count = dc_count
    ctx.ou_count = ou_count
    ctx.tier0_entities = tier0_ids

    # Build graph analyzer
    analyzer = ADGraphAnalyzer()
    analyzer.load_from_db(entities, edges)
    ctx.analyzer = analyzer

    # ── Derive context attributes from findings ─────────────────────────────
    # Build a name→entity_id lookup so findings with object names can be resolved
    _name_to_id: dict[str, str] = {}
    for e in entities:
        for name in (e.sam_account_name, e.display_name):
            if name:
                _name_to_id[name.lower()] = str(e.id)

    def _resolve_objects(affected_objects) -> list[str]:
        """Resolve a list of object names/IDs to entity UUIDs."""
        out: list[str] = []
        if not isinstance(affected_objects, list):
            return out
        for obj in affected_objects:
            obj_str = str(obj)
            resolved = _name_to_id.get(obj_str.lower())
            if resolved:
                out.append(resolved)
            else:
                # Store the raw name as a sentinel so experts know something exists
                out.append(obj_str)
        return out

    # Index findings by type for quick lookup
    import re as _re
    _ftype_index: dict[str, list] = {}
    for f in findings:
        ft = getattr(f, 'finding_type', '') or ''
        _ftype_index.setdefault(ft, []).append(f)

    def _first(ftype: str):
        return (_ftype_index.get(ftype) or [None])[0]

    # Unconstrained delegation
    if f := _first('UNCONSTRAINED_DELEGATION'):
        ctx.unconstrained_delegation = _resolve_objects(f.affected_objects or []) or ['_finding_present']

    # Constrained delegation (KCD + protocol-transition)
    for ftype in ('CONSTRAINED_DELEGATION_KCD', 'CONSTRAINED_DELEGATION_ANY_PROTOCOL'):
        for f in _ftype_index.get(ftype, []):
            for obj in (f.affected_objects or []):
                entity_id = _name_to_id.get(str(obj).lower(), str(obj))
                ctx.constrained_delegation.append({'entity_id': entity_id, 'allowed_spns': [], 'protocol_transition': 'ANY_PROTOCOL' in ftype})

    # RBCD
    if f := _first('RBCD_CONFIGURED'):
        for obj in (f.affected_objects or ['_finding_present']):
            entity_id = _name_to_id.get(str(obj).lower(), str(obj))
            ctx.rbcd_edges.append({'source': entity_id, 'target': '_target'})

    # SID History
    if f := _first('SID_HISTORY_POPULATED'):
        for obj in (f.affected_objects or ['_finding_present']):
            entity_id = _name_to_id.get(str(obj).lower(), str(obj))
            ctx.sid_history_entities.append({'entity_id': entity_id, 'sid_history': ['_populated'], 'resolved_sids': []})

    # Shadow Credentials
    if f := _first('SHADOW_CREDENTIALS'):
        for obj in (f.affected_objects or ['_finding_present']):
            entity_id = _name_to_id.get(str(obj).lower(), str(obj))
            ctx.shadow_credential_edges.append({'source': '_writer', 'target': entity_id})

    # MAQ
    if f := _first('MACHINE_ACCOUNT_QUOTA'):
        title = getattr(f, 'title', '') or ''
        m = _re.search(r'(?:is|quota)\s+(\d+)', title, _re.IGNORECASE)
        if m:
            ctx.maq_value = int(m.group(1))

    # Password policy: populate from findings
    pw_policy: dict = {}
    for ftype, key, val in (
        ('WEAK_PASSWORD_LENGTH', 'min_length', 7),
        ('NO_PASSWORD_COMPLEXITY', 'complexity', False),
        ('NO_LOCKOUT_POLICY', 'lockout_threshold', 0),
        ('WEAK_PASSWORD_HISTORY', 'history', 3),
        ('REVERSIBLE_ENCRYPTION_ENABLED', 'reversible_encryption', True),
    ):
        if ftype in _ftype_index:
            pw_policy[key] = val
    if pw_policy:
        ctx.password_policy_objects = [pw_policy]

    # Spray candidates: derive count from LARGE_SPRAY_SURFACE
    if f := _first('LARGE_SPRAY_SURFACE'):
        title = getattr(f, 'title', '') or ''
        m = _re.search(r'(\d+)\s+enabled', title, _re.IGNORECASE)
        count = int(m.group(1)) if m else f.affected_count or 0
        if count:
            ctx.spray_candidates = [{'count': count, 'source': 'finding'}]

    # LAPS: computers without LAPS
    if f := _first('COMPUTERS_NO_LAPS'):
        ctx.laps_computers = _resolve_objects(f.affected_objects or [])

    # ───────────────────────────────────────────────────────────────────────

    log.debug(
        "ValidationContext built for %s: %d entities, %d edges, %d findings, %d evidence | "
        "uncon_deleg=%d constrained=%d rbcd=%d sid_hist=%d shadow=%d",
        assessment_id,
        len(entities), len(edges), len(findings), len(evidence),
        len(ctx.unconstrained_delegation), len(ctx.constrained_delegation),
        len(ctx.rbcd_edges), len(ctx.sid_history_entities), len(ctx.shadow_credential_edges),
    )
    return ctx
