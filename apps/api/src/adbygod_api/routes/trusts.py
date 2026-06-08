from __future__ import annotations

from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from adbygod_api.core.security.authorization import require_assessment_access
from adbygod_api.core.analyzers.trust_abuse_analyzer import TrustAbuseAnalyzer, TECHNIQUE_CATALOGUE
from adbygod_api.core.analyzers.forest_pivot_analyzer import ForestPivotAnalyzer
from adbygod_api.database import get_db
from adbygod_api.models import Entity, EntityType, Finding, GraphEdge, PlatformUser
from adbygod_api.routes.auth import get_current_user

router = APIRouter(prefix="/trusts", tags=["trusts"])


class TrustSimOverride(BaseModel):
    trust_name: str
    sid_filtering: bool | None = None
    selective_auth: bool | None = None
    direction: str | None = None


class TrustSimRequest(BaseModel):
    overrides: list[TrustSimOverride] = []


def _normalize_bool(value: Any, default: bool) -> bool:
    """Normalize a potentially-stringified boolean attribute to a Python bool."""
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.lower() not in ("false", "0", "no", "")
    return bool(value)


def _parse_trust_attrs(attrs: dict[str, Any]) -> dict[str, bool | int]:
    """Parse and normalize trust attribute dict into typed values."""
    direction_raw = attrs.get("direction_val", 3)
    try:
        direction_val = int(direction_raw or 3)
    except (ValueError, TypeError):
        s = str(direction_raw).upper()
        direction_val = 3 if "BI" in s else (2 if "OUT" in s else 1)

    return {
        "forest_trust": _normalize_bool(attrs.get("forest_trust", False), default=False),
        "sid_filtering": _normalize_bool(attrs.get("sid_filtering", True), default=True),
        "selective_auth": _normalize_bool(attrs.get("selective_auth", False), default=False),
        "transitive": _normalize_bool(attrs.get("transitive", True), default=True),
        "direction_val": direction_val,
        "quarantine": _normalize_bool(attrs.get("quarantine", False), default=False),
        "is_pam": _normalize_bool(attrs.get("is_pam_trust", False), default=False),
        "is_rodc": _normalize_bool(attrs.get("is_rodc_involved", False), default=False),
    }


def _trust_risk(attrs: dict[str, Any]) -> str:
    """Derive trust risk level using the full available attribute set."""
    p = _parse_trust_attrs(attrs)
    forest_trust = p["forest_trust"]
    sid_filtering = p["sid_filtering"]
    selective_auth = p["selective_auth"]
    transitive = p["transitive"]
    direction_val = p["direction_val"]
    quarantine = p["quarantine"]
    is_pam = p["is_pam"]
    is_rodc = p["is_rodc"]

    if forest_trust and not sid_filtering:
        return "CRITICAL"
    if direction_val == 3 and not sid_filtering:
        return "CRITICAL"
    if not sid_filtering:
        return "HIGH"
    if forest_trust and not selective_auth:
        return "HIGH"
    if selective_auth or quarantine:
        return "LOW"
    if transitive and not selective_auth:
        return "MEDIUM"
    if is_rodc:
        return "MEDIUM"
    if is_pam:
        return "MEDIUM"
    return "MEDIUM"


def _trust_risk_factors(attrs: dict[str, Any]) -> list[str]:
    """Return human-readable list explaining the trust risk level."""
    factors: list[str] = []
    p = _parse_trust_attrs(attrs)
    forest_trust = p["forest_trust"]
    sid_filtering = p["sid_filtering"]
    selective_auth = p["selective_auth"]
    transitive = p["transitive"]
    direction_val = p["direction_val"]
    quarantine = p["quarantine"]
    is_pam = p["is_pam"]
    is_rodc = p["is_rodc"]

    if forest_trust and not sid_filtering:
        factors.append("Forest trust with SID filtering disabled — ExtraSID / cross-forest Golden Ticket possible")
    elif direction_val == 3 and not sid_filtering:
        factors.append("Bidirectional trust with SID filtering disabled — mutual exploitation surface")
    elif not sid_filtering:
        factors.append("SID filtering disabled — SID history injection risk")
    if forest_trust and not selective_auth:
        factors.append("Forest trust without selective authentication — shadow principal exposure")
    if transitive and not selective_auth:
        factors.append("Transitive trust without selective authentication")
    if is_rodc:
        factors.append("RODC involved — complex delegated authentication scenarios")
    if is_pam:
        factors.append("PAM trust — privileged access management bidirectional admin exposure")
    if selective_auth:
        factors.append("Selective authentication mitigates lateral movement risk")
    if quarantine:
        factors.append("Quarantine mode active — strongly restricts cross-forest resource access")
    return factors


def _entity_to_trust(entity: Entity) -> dict[str, Any]:
    attrs = entity.attributes or {}
    return {
        "id": str(entity.id),
        "assessment_id": str(entity.assessment_id),
        "source": entity.domain or "current-domain",
        "target": str(
            attrs.get("target_domain")
            or attrs.get("target")
            or attrs.get("partner")
            or entity.display_name
            or entity.sam_account_name
            or str(entity.id)
        ),
        "trust_type": str(attrs.get("trust_type", "TRUST")),
        "direction": str(attrs.get("direction", "BIDIRECTIONAL")),
        "sid_filtering": _normalize_bool(attrs.get("sid_filtering", True), default=True),
        "selective_auth": bool(attrs.get("selective_auth", False)),
        "transitive": attrs.get("transitive", True),
        "risk": _trust_risk(attrs),
        "risk_factors": _trust_risk_factors(attrs),
        "notes": entity.distinguished_name or entity.display_name or "",
        "domain": entity.domain,
        "sam_account_name": entity.sam_account_name,
        "display_name": entity.display_name,
        "created_at": entity.created_at.isoformat() if entity.created_at else None,
    }


@router.get("")
async def list_trusts(
    assessment_id: UUID = Query(..., description="Assessment to query"),
    db: AsyncSession = Depends(get_db),
    current_user: PlatformUser = Depends(get_current_user),
) -> list[dict]:
    """Return all trust-type entities for an assessment with enriched posture data."""
    await require_assessment_access(assessment_id, db, current_user)
    entities = (
        await db.execute(
            select(Entity).where(
                Entity.assessment_id == assessment_id,
                Entity.entity_type == EntityType.TRUST,
            )
        )
    ).scalars().all()
    return [_entity_to_trust(e) for e in entities]


@router.get("/summary")
async def trust_summary(
    assessment_id: UUID = Query(..., description="Assessment to query"),
    db: AsyncSession = Depends(get_db),
    current_user: PlatformUser = Depends(get_current_user),
) -> dict[str, Any]:
    """Return aggregated trust posture metrics for an assessment."""
    await require_assessment_access(assessment_id, db, current_user)

    entities = (
        await db.execute(
            select(Entity).where(
                Entity.assessment_id == assessment_id,
                Entity.entity_type == EntityType.TRUST,
            )
        )
    ).scalars().all()

    trust_findings_count = (
        await db.execute(
            select(func.count(Finding.id)).where(
                Finding.assessment_id == assessment_id,
                Finding.module.ilike("%trust%"),
            )
        )
    ).scalar_one()

    trusts = [_entity_to_trust(e) for e in entities]
    return {
        "assessment_id": str(assessment_id),
        "total_trusts": len(trusts),
        "sid_filtering_off": sum(1 for t in trusts if not t["sid_filtering"]),
        "selective_auth_off": sum(1 for t in trusts if not t["selective_auth"]),
        "forest_trusts": sum(1 for t in trusts if "FOREST" in t["trust_type"]),
        "high_risk": sum(1 for t in trusts if t["risk"] == "HIGH"),
        "critical_risk": sum(1 for t in trusts if t["risk"] == "CRITICAL"),
        "trust_findings": trust_findings_count,
        "trusts": trusts,
    }


def _entity_trust_to_dict(entity: Entity) -> dict[str, Any]:
    attrs = entity.attributes or {}
    direction = str(attrs.get("direction", "BIDIRECTIONAL")).upper()
    direction_val = 3 if "BI" in direction else (2 if "OUTBOUND" in direction else 1)
    return {
        "name": str(attrs.get("target_domain") or attrs.get("partner") or entity.display_name or ""),
        "partner": entity.domain or "",
        "direction_val": direction_val,
        "attrs_raw": int(attrs.get("trust_attributes_raw", attrs.get("attrs_raw", 0)) or 0),
        "sid_filtering": bool(attrs.get("sid_filtering", True)),
        "forest_trust": "FOREST" in str(attrs.get("trust_type", "")).upper(),
        "transitive": bool(attrs.get("transitive", True)),
        "trust_type": str(attrs.get("trust_type", "Uplevel (AD)")),
        "when_changed_days": int(attrs.get("when_changed_days", 999) or 999),
        "quarantine": bool(attrs.get("quarantine", False)),
        "is_pam_trust": bool(attrs.get("is_pam_trust", False)),
        "is_rodc_involved": bool(attrs.get("is_rodc_involved", False)),
        "direction": direction,
        "attribute_flags": list(attrs.get("attribute_flags", [])),
    }


@router.get("/abuse")
async def trust_abuse_report(
    assessment_id: UUID = Query(..., description="Assessment to query"),
    db: AsyncSession = Depends(get_db),
    current_user: PlatformUser = Depends(get_current_user),
) -> dict[str, Any]:
    """Full trust abuse analysis report with detected techniques and chains."""
    await require_assessment_access(assessment_id, db, current_user)

    trust_entities = (
        await db.execute(
            select(Entity).where(
                Entity.assessment_id == assessment_id,
                Entity.entity_type == EntityType.TRUST,
            )
        )
    ).scalars().all()

    all_entities = (
        await db.execute(
            select(Entity).where(Entity.assessment_id == assessment_id)
        )
    ).scalars().all()

    all_edges = (
        await db.execute(
            select(GraphEdge).where(GraphEdge.assessment_id == assessment_id)
        )
    ).scalars().all()

    trusts_data = [_entity_trust_to_dict(e) for e in trust_entities]
    entities_data = [
        {
            "entity_type": e.entity_type.value if hasattr(e.entity_type, "value") else str(e.entity_type),
            "domain": e.domain or "",
            "attributes": e.attributes or {},
        }
        for e in all_entities
    ]
    edges_data = [
        {"edge_type": str(edge.edge_type.value if hasattr(edge.edge_type, "value") else edge.edge_type)}
        for edge in all_edges
    ]

    analyzer = TrustAbuseAnalyzer(trusts_data, entities_data, edges_data)
    report = analyzer.analyze()
    report["assessment_id"] = str(assessment_id)
    return report


@router.get("/abuse/techniques")
async def trust_abuse_techniques(
    assessment_id: UUID = Query(..., description="Assessment to query"),
    db: AsyncSession = Depends(get_db),
    current_user: PlatformUser = Depends(get_current_user),
) -> list[dict[str, Any]]:
    """Return full technique catalogue with detection status for the assessment."""
    await require_assessment_access(assessment_id, db, current_user)

    trust_entities = (
        await db.execute(
            select(Entity).where(
                Entity.assessment_id == assessment_id,
                Entity.entity_type == EntityType.TRUST,
            )
        )
    ).scalars().all()

    all_entities = (
        await db.execute(
            select(Entity).where(Entity.assessment_id == assessment_id)
        )
    ).scalars().all()

    all_edges = (
        await db.execute(
            select(GraphEdge).where(GraphEdge.assessment_id == assessment_id)
        )
    ).scalars().all()

    trusts_data = [_entity_trust_to_dict(e) for e in trust_entities]
    entities_data = [
        {
            "entity_type": e.entity_type.value if hasattr(e.entity_type, "value") else str(e.entity_type),
            "domain": e.domain or "",
            "attributes": e.attributes or {},
        }
        for e in all_entities
    ]
    edges_data = [
        {"edge_type": str(edge.edge_type.value if hasattr(edge.edge_type, "value") else edge.edge_type)}
        for edge in all_edges
    ]

    from adbygod_api.core.analyzers.trust_abuse_analyzer import detect_trust_techniques
    detected = {t["technique_id"] for t in detect_trust_techniques(trusts_data, entities_data, edges_data)}

    result = []
    for tid, cat in TECHNIQUE_CATALOGUE.items():
        result.append({
            "technique_id": tid,
            "detected": tid in detected,
            **{k: v for k, v in cat.items()},
        })
    return result


@router.get("/forest-pivot")
async def forest_pivot_report(
    assessment_id: UUID = Query(..., description="Assessment to query"),
    db: AsyncSession = Depends(get_db),
    current_user: PlatformUser = Depends(get_current_user),
) -> dict[str, Any]:
    """Full forest pivoting analysis report."""
    await require_assessment_access(assessment_id, db, current_user)

    trust_entities = (
        await db.execute(
            select(Entity).where(
                Entity.assessment_id == assessment_id,
                Entity.entity_type == EntityType.TRUST,
            )
        )
    ).scalars().all()

    all_entities = (
        await db.execute(
            select(Entity).where(Entity.assessment_id == assessment_id)
        )
    ).scalars().all()

    all_edges = (
        await db.execute(
            select(GraphEdge).where(GraphEdge.assessment_id == assessment_id)
        )
    ).scalars().all()

    trusts_data = [_entity_trust_to_dict(e) for e in trust_entities]
    entities_data = [
        {
            "entity_type": e.entity_type.value if hasattr(e.entity_type, "value") else str(e.entity_type),
            "domain": e.domain or "",
            "attributes": e.attributes or {},
        }
        for e in all_entities
    ]
    edges_data = [
        {"edge_type": str(edge.edge_type.value if hasattr(edge.edge_type, "value") else edge.edge_type)}
        for edge in all_edges
    ]

    analyzer = ForestPivotAnalyzer(trusts_data, entities_data, edges_data)
    report = analyzer.analyze()
    report["assessment_id"] = str(assessment_id)
    return report


@router.get("/forest-pivot/paths")
async def forest_pivot_paths(
    assessment_id: UUID = Query(..., description="Assessment to query"),
    db: AsyncSession = Depends(get_db),
    current_user: PlatformUser = Depends(get_current_user),
) -> list[dict[str, Any]]:
    """Return computed forest pivot paths for visualization."""
    await require_assessment_access(assessment_id, db, current_user)

    trust_entities = (
        await db.execute(
            select(Entity).where(
                Entity.assessment_id == assessment_id,
                Entity.entity_type == EntityType.TRUST,
            )
        )
    ).scalars().all()

    trusts_data = [_entity_trust_to_dict(e) for e in trust_entities]
    from adbygod_api.core.analyzers.forest_pivot_analyzer import compute_pivot_paths
    return compute_pivot_paths(trusts_data)


@router.post("/simulate")
async def simulate_trust_posture(
    payload: TrustSimRequest,
    assessment_id: UUID = Query(..., description="Assessment to simulate against"),
    db: AsyncSession = Depends(get_db),
    current_user: PlatformUser = Depends(get_current_user),
) -> dict[str, Any]:
    """What-if simulation: apply posture overrides and re-run abuse/pivot analysis.

    Returns baseline counts, simulated counts, and which techniques are
    introduced or eliminated by the proposed changes.
    """
    await require_assessment_access(assessment_id, db, current_user)

    trust_entities = (
        await db.execute(
            select(Entity).where(
                Entity.assessment_id == assessment_id,
                Entity.entity_type == EntityType.TRUST,
            )
        )
    ).scalars().all()
    all_entities = (
        await db.execute(select(Entity).where(Entity.assessment_id == assessment_id))
    ).scalars().all()
    all_edges = (
        await db.execute(select(GraphEdge).where(GraphEdge.assessment_id == assessment_id))
    ).scalars().all()

    base_trusts = [_entity_trust_to_dict(e) for e in trust_entities]
    entities_data = [
        {
            "entity_type": e.entity_type.value if hasattr(e.entity_type, "value") else str(e.entity_type),
            "domain": e.domain or "",
            "attributes": e.attributes or {},
        }
        for e in all_entities
    ]
    edges_data = [
        {"edge_type": str(edge.edge_type.value if hasattr(edge.edge_type, "value") else edge.edge_type)}
        for edge in all_edges
    ]

    # Baseline analysis
    from adbygod_api.core.analyzers.trust_abuse_analyzer import detect_trust_techniques
    from adbygod_api.core.analyzers.forest_pivot_analyzer import compute_pivot_paths
    baseline_techniques = {t["technique_id"] for t in detect_trust_techniques(base_trusts, entities_data, edges_data)}
    baseline_pivot_count = len(compute_pivot_paths(base_trusts))

    # Apply overrides to produce simulated trust set
    override_index = {o.trust_name: o for o in payload.overrides}
    sim_trusts: list[dict[str, Any]] = []
    for trust in base_trusts:
        t = dict(trust)
        ovr = override_index.get(t["name"])
        if ovr:
            if ovr.sid_filtering is not None:
                t["sid_filtering"] = ovr.sid_filtering
            if ovr.selective_auth is not None:
                t["selective_auth"] = ovr.selective_auth
            if ovr.direction is not None:
                d = ovr.direction.upper()
                t["direction"] = d
                t["direction_val"] = 3 if "BI" in d else (2 if "OUTBOUND" in d else 1)
        sim_trusts.append(t)

    # Simulated analysis
    sim_techniques = {t["technique_id"] for t in detect_trust_techniques(sim_trusts, entities_data, edges_data)}
    sim_pivot_count = len(compute_pivot_paths(sim_trusts))

    eliminated = sorted(baseline_techniques - sim_techniques)
    introduced = sorted(sim_techniques - baseline_techniques)

    return {
        "assessment_id": str(assessment_id),
        "simulation": True,
        "overrides_applied": len(payload.overrides),
        "baseline": {
            "technique_count": len(baseline_techniques),
            "pivot_paths": baseline_pivot_count,
            "techniques": sorted(baseline_techniques),
        },
        "simulated": {
            "technique_count": len(sim_techniques),
            "pivot_paths": sim_pivot_count,
            "techniques": sorted(sim_techniques),
        },
        "delta": {
            "techniques_eliminated": eliminated,
            "techniques_introduced": introduced,
            "net_technique_change": len(sim_techniques) - len(baseline_techniques),
            "pivot_path_change": sim_pivot_count - baseline_pivot_count,
        },
    }
