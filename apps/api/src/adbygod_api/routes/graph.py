from __future__ import annotations

import asyncio
import hashlib
import logging
import time
from datetime import datetime, timezone
from typing import Any, Callable, List, Optional
from uuid import UUID
from uuid import UUID as _UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
import dataclasses
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from adbygod_api.database import get_db
from adbygod_api.models import Entity, ExposurePath, GraphEdge, GraphProjectionState, PlatformUser
from adbygod_api.schemas import GraphData
from adbygod_api.core.graph.attack_flow_chains import attack_flow_categories, list_attack_flow_chains
from adbygod_api.core.graph.graph_service import ADGraphAnalyzer
from adbygod_api.core.security.authorization import require_assessment_access, require_assessment_write_access
from adbygod_api.routes.auth import get_current_user


class EdgeRemoval(BaseModel):
    source: str
    target: str


class LayoutSaveRequest(BaseModel):
    layout_name: str
    positions: dict  # {node_id: {"x": float, "y": float}}


class SnapshotCreateRequest(BaseModel):
    label: Optional[str] = None


log = logging.getLogger(__name__)


def _compute_snapshot_diff(snap_a: dict, snap_b: dict) -> dict:
    """Compute diff between two snapshot dicts."""
    nodes_a = {n["id"]: n for n in snap_a.get("nodes", [])}
    nodes_b = {n["id"]: n for n in snap_b.get("nodes", [])}
    edges_a = {e["id"]: e for e in snap_a.get("edges", [])}
    edges_b = {e["id"]: e for e in snap_b.get("edges", [])}
    added_node_ids = set(nodes_b) - set(nodes_a)
    removed_node_ids = set(nodes_a) - set(nodes_b)
    added_edge_ids = set(edges_b) - set(edges_a)
    removed_edge_ids = set(edges_a) - set(edges_b)
    changed_edges = []
    for eid in set(edges_a) & set(edges_b):
        if edges_a[eid] != edges_b[eid]:
            changed_edges.append({"id": eid, "old": edges_a[eid], "new": edges_b[eid]})
    return {
        "added_nodes": [nodes_b[i] for i in added_node_ids],
        "removed_nodes": [nodes_a[i] for i in removed_node_ids],
        "added_edges": [edges_b[i] for i in added_edge_ids],
        "removed_edges": [edges_a[i] for i in removed_edge_ids],
        "changed_edges": changed_edges,
    }


def _run_monte_carlo(path_steps: list, iterations: int = 1000) -> dict:
    """Monte Carlo simulation of path success probability."""
    from scipy.stats import beta as beta_dist
    import random
    BETA_PARAMS: dict[str, tuple] = {
        "GENERIC_ALL": (9, 1), "DCSYNC": (9.5, 0.5), "WRITE_DACL": (8.5, 1.5),
        "ALLOWED_TO_DELEGATE": (7, 3), "ADD_MEMBER": (7.5, 2.5),
        "FORCE_CHANGE_PASSWORD": (8, 2), "PASS_THE_HASH": (8, 2),
        "PASS_THE_TICKET": (7.5, 2.5), "ADMIN_TO": (8, 2),
        "LOCAL_ADMIN": (7, 3), "HAS_SPN": (6, 2),
        "MEMBER_OF": (9, 1), "CONTAINS": (9.5, 0.5),
    }
    DEFAULT_PARAMS = (5, 5)
    successes = 0
    for _ in range(iterations):
        chain_ok = True
        for step in path_steps:
            etype = (step.get("edge_type") or "").upper()
            a, b = BETA_PARAMS.get(etype, DEFAULT_PARAMS)
            p = beta_dist.rvs(a, b)
            if random.random() > p:
                chain_ok = False
                break
        if chain_ok:
            successes += 1
    p_success = successes / iterations
    histogram = [0] * 10
    histogram[min(9, int(p_success * 10))] = 1
    return {
        "p_success": round(p_success, 3),
        "iterations": iterations,
        "histogram": histogram,
        "success_pct_label": f"{p_success*100:.1f}%",
    }


router = APIRouter(prefix="/graph", tags=["graph"])

_graph_cache: dict[str, tuple[float, ADGraphAnalyzer]] = {}
_CACHE_TTL = 300  # 5 minutes
_CACHE_MAX = 50   # max cached analyzers — evict LRU entries beyond this
_graph_cache_lock = asyncio.Lock()
_PATH_TIMEOUT = 30.0  # seconds before path computation is aborted


async def _run_path_with_timeout(func: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
    work = asyncio.to_thread(func, *args, **kwargs)
    try:
        return await asyncio.wait_for(work, timeout=_PATH_TIMEOUT)
    except asyncio.TimeoutError:
        # Some test doubles raise before wait_for consumes the coroutine.
        # Close it so timeout responses do not leak RuntimeWarning noise.
        try:
            work.close()
        except RuntimeError:
            pass
        raise


@router.get("/attack-flow-chains")
async def get_attack_flow_chains():
    """Return static AD Attack Architecture flow-chain playbooks."""
    chains = list_attack_flow_chains()
    edge_type_counts: dict[str, int] = {}
    for chain in chains:
        for edge_type in chain.get("edge_types", []) or []:
            edge_type_counts[edge_type] = edge_type_counts.get(edge_type, 0) + 1
    return {
        "categories": attack_flow_categories(),
        "paths": chains,
        "total_paths": len(chains),
        "critical_count": sum(1 for chain in chains if chain.get("risk_level") == "CRITICAL"),
        "edge_type_counts": edge_type_counts,
    }


def invalidate_graph_cache(assessment_id: str) -> None:
    _graph_cache.pop(assessment_id, None)


async def _get_analyzer(assessment_id: str, db: AsyncSession) -> ADGraphAnalyzer:
    async with _graph_cache_lock:
        cached = _graph_cache.get(assessment_id)
        if cached:
            ts, analyzer = cached
            if time.monotonic() - ts < _CACHE_TTL:
                _graph_cache[assessment_id] = (time.monotonic(), analyzer)
                return analyzer

    # DB queries outside the lock — these are the expensive part
    entities_result = await db.execute(select(Entity).where(Entity.assessment_id == _UUID(str(assessment_id))))
    edges_result = await db.execute(select(GraphEdge).where(GraphEdge.assessment_id == _UUID(str(assessment_id))))

    analyzer = ADGraphAnalyzer()
    analyzer.load_from_db(entities_result.scalars().all(), edges_result.scalars().all())

    async with _graph_cache_lock:
        _graph_cache[assessment_id] = (time.monotonic(), analyzer)
        if len(_graph_cache) > _CACHE_MAX:
            oldest = sorted(_graph_cache.items(), key=lambda kv: kv[1][0])
            for key, _ in oldest[:len(_graph_cache) - _CACHE_MAX]:
                _graph_cache.pop(key, None)

    return analyzer


def _risk_level(score: float) -> str:
    if score >= 85:
        return "CRITICAL"
    if score >= 65:
        return "HIGH"
    if score >= 40:
        return "MEDIUM"
    return "LOW"


def _normalize_path_step(step) -> dict:
    data = dataclasses.asdict(step) if dataclasses.is_dataclass(step) else (step if isinstance(step, dict) else vars(step))
    return {
        "entity_id": data.get("node_id") or data.get("entity_id", ""),
        "entity_label": data.get("node_label") or data.get("entity_label", ""),
        "entity_type": data.get("node_type") or data.get("entity_type", "UNKNOWN"),
        "edge_type": data.get("edge_type"),
        "provenance": data.get("edge_provenance") or data.get("provenance"),
        "edge_risk": data.get("edge_risk", 0.0),
        "explanation": data.get("explanation", ""),
        "tier": data.get("tier"),
        "is_crown_jewel": bool(data.get("is_crown_jewel", False)),
    }


def _attack_path_to_dict(ap, category: str | None = None) -> dict:
    steps = [_normalize_path_step(s) for s in getattr(ap, "steps", [])]
    edge_types = list(getattr(ap, "edge_types", []) or [s.get("edge_type") for s in steps if s.get("edge_type")])
    score = round(float(getattr(ap, "path_score", 0.0) or 0.0), 2)
    result = {
        "source_id": getattr(ap, "source_id", None),
        "target_id": getattr(ap, "target_id", None),
        "source_label": getattr(ap, "source_label", "") or (steps[0].get("entity_label") if steps else ""),
        "target_label": getattr(ap, "target_label", "") or (steps[-1].get("entity_label") if steps else ""),
        "hop_count": int(getattr(ap, "hop_count", 0) or 0),
        "path_score": score,
        "risk_level": getattr(ap, "risk_level", None) or _risk_level(score),
        "explanation": getattr(ap, "explanation", "") or "",
        "steps": steps,
        "edge_types": edge_types,
        "involves_credential_access": bool(getattr(ap, "involves_credential_access", False)),
        "involves_delegation": bool(getattr(ap, "involves_delegation", False)),
        "involves_adcs": bool(getattr(ap, "involves_adcs", False)),
        "crosses_trust": bool(getattr(ap, "crosses_trust", False)),
    }
    if category:
        result["category"] = category
    return result


@router.get("/{assessment_id}/data", response_model=GraphData)
async def get_graph_data(
    assessment_id: UUID,
    max_nodes: int = Query(2000, ge=1, le=5000),
    entity_types: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    current_user: PlatformUser = Depends(get_current_user),
):
    """Return full graph nodes+edges for the frontend visualizer."""
    await require_assessment_access(assessment_id, db, current_user)
    filter_types = entity_types.split(",") if entity_types else None
    analyzer = await _get_analyzer(str(assessment_id), db)
    data = analyzer.export_for_frontend(max_nodes=max_nodes, filter_types=filter_types)
    return GraphData(**data)


@router.get("/{assessment_id}/paths")
async def get_exposure_paths(
    assessment_id: UUID,
    source_id: Optional[str] = None,
    target_id: Optional[str] = None,
    tier: Optional[int] = None,
    max_paths: int = Query(20, ge=1, le=100),
    algorithm: str = Query("bfs", pattern="^(bfs|yen)$"),
    directed: bool = Query(False),
    k: int = Query(1, ge=1, le=10),
    db: AsyncSession = Depends(get_db),
    current_user: PlatformUser = Depends(get_current_user),
):
    """Compute and return exposure paths."""
    await require_assessment_access(assessment_id, db, current_user)
    analyzer = await _get_analyzer(str(assessment_id), db)

    paths = None
    try:
        if source_id and target_id:
            if directed:
                raw = await _run_path_with_timeout(analyzer.find_directed_path, source_id, target_id)
                paths = [raw] if raw else []
            elif algorithm == "yen":
                paths = await _run_path_with_timeout(analyzer.find_k_shortest_paths, source_id, target_id, k)
            else:
                paths = await _run_path_with_timeout(analyzer.get_all_paths, source_id, target_id, max_paths=max_paths)
        elif source_id:
            paths = await _run_path_with_timeout(analyzer.get_paths_to_tier0, source_id, max_paths=max_paths)
    except asyncio.TimeoutError as exc:
        raise HTTPException(
            status_code=503,
            detail="Path computation timed out — graph may be too large; try with a specific source_id or reduce scope",
        ) from exc

    if paths is None:
        q = select(ExposurePath).where(ExposurePath.assessment_id == assessment_id)
        if tier is not None:
            q = q.where(ExposurePath.target_tier == tier)
        q = q.order_by(ExposurePath.path_score.desc()).limit(max_paths)
        ep_result = await db.execute(q)
        rows = []
        for ep in ep_result.scalars().all():
            steps = ep.path_steps or []
            source_label = (
                steps[0].get("entity_label")
                if steps and isinstance(steps[0], dict)
                else analyzer._label_of(str(ep.source_entity_id)) if ep.source_entity_id else None
            )
            target_label = (
                steps[-1].get("entity_label")
                if steps and isinstance(steps[-1], dict)
                else analyzer._label_of(str(ep.target_entity_id)) if ep.target_entity_id else None
            )
            edge_types = [
                step.get("edge_type")
                for step in steps
                if isinstance(step, dict) and step.get("edge_type")
            ]
            rows.append({
                "id": str(ep.id),
                "source_id": str(ep.source_entity_id) if ep.source_entity_id else (steps[0].get("entity_id") if steps and isinstance(steps[0], dict) else None),
                "target_id": str(ep.target_entity_id) if ep.target_entity_id else (steps[-1].get("entity_id") if steps and isinstance(steps[-1], dict) else None),
                "source_label": source_label or "Unknown source",
                "target_label": target_label or "Unknown target",
                "path_steps": steps,
                "edge_types": edge_types,
                "hop_count": ep.hop_count or 0,
                "path_score": ep.path_score or 0.0,
                "risk_level": _risk_level(float(ep.path_score or 0.0)),
                "target_tier": ep.target_tier,
                "path_type": ep.path_type,
                "explanation": ep.explanation or "",
            })
        return rows

    return [
        {
            "source": path.source_id,
            "target": path.target_id,
            "source_label": analyzer._label_of(path.source_id),
            "target_label": analyzer._label_of(path.target_id),
            "path": path.path,
            "path_steps": [_normalize_path_step(step) for step in analyzer._build_attack_path(path.path).steps],
            "edge_types": path.edge_types,
            "hop_count": path.hop_count,
            "path_score": path.path_score,
            "risk_level": _risk_level(float(path.path_score or 0.0)),
            "explanation": path.explanation,
        }
        for path in paths
    ]


@router.get("/{assessment_id}/blast-radius")
async def get_tier0_blast_radius(
    assessment_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: PlatformUser = Depends(get_current_user),
):
    """Return all entities that can reach Tier-0, with path counts."""
    await require_assessment_access(assessment_id, db, current_user)
    analyzer = await _get_analyzer(str(assessment_id), db)
    blast = await asyncio.to_thread(analyzer.compute_tier0_blast_radius)

    results = []
    for entity_id, path_count in sorted(blast.items(), key=lambda item: item[1], reverse=True)[:100]:
        meta = analyzer.entity_meta.get(entity_id, {})
        results.append({
            "entity_id": entity_id,
            "label": meta.get("sam_account_name") or meta.get("display_name") or entity_id[:12],
            "type": meta.get("type"),
            "tier": meta.get("tier"),
            "paths_to_tier0": path_count,
        })

    return {"entities_in_blast_radius": len(blast), "top_100": results}


@router.post("/{assessment_id}/simulate-removal")
async def simulate_edge_removal(
    assessment_id: UUID,
    edge_removals: List[EdgeRemoval],
    db: AsyncSession = Depends(get_db),
    current_user: PlatformUser = Depends(get_current_user),
):
    """Simulate what happens when edges are removed (remediation preview)."""
    await require_assessment_access(assessment_id, db, current_user)
    if not edge_removals:
        raise HTTPException(status_code=400, detail="At least one edge removal must be specified")
    analyzer = await _get_analyzer(str(assessment_id), db)
    pairs = [(edge.source, edge.target) for edge in edge_removals]
    return await asyncio.to_thread(analyzer.simulate_edge_removal, pairs)


@router.post("/{assessment_id}/compute-paths")
async def compute_and_persist_paths(
    assessment_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: PlatformUser = Depends(get_current_user),
):
    """Compute all attack paths and persist to exposure_paths table."""
    await require_assessment_write_access(assessment_id, db, current_user)

    analyzer = await _get_analyzer(str(assessment_id), db)

    def _compute():
        rows = []
        warnings: list[str] = []

        # 1. Paths from top blast-radius sources → Tier-0
        blast = analyzer.compute_tier0_blast_radius()
        top_sources = sorted(blast.items(), key=lambda x: x[1], reverse=True)[:40]
        for src_id, _ in top_sources:
            try:
                paths = analyzer.find_attack_paths_to_tier0(src_id, max_hops=8, max_paths=3)
                for ap in paths:
                    rows.append({
                        "source_entity_id": _UUID(str(ap.source_id)) if ap.source_id else None,
                        "target_entity_id": _UUID(str(ap.target_id)) if ap.target_id else None,
                        "path_steps": [_normalize_path_step(s) for s in ap.steps],
                        "hop_count": ap.hop_count,
                        "path_score": round(ap.path_score, 2),
                        "target_tier": 0,
                        "path_type": "tier0_path",
                        "explanation": ap.explanation or "",
                    })
            except Exception as exc:
                log.warning("Tier-0 path computation skipped for one source: %s", exc, exc_info=True)
                if len(warnings) < 10:
                    warnings.append(f"Tier-0 path computation skipped for one source ({type(exc).__name__}).")

        # 2. ACL abuse paths
        try:
            for ap in analyzer.detect_acl_abuse_paths(max_paths=20):
                rows.append({
                    "source_entity_id": _UUID(str(ap.source_id)) if ap.source_id else None,
                    "target_entity_id": _UUID(str(ap.target_id)) if ap.target_id else None,
                    "path_steps": [_normalize_path_step(s) for s in ap.steps],
                    "hop_count": ap.hop_count, "path_score": round(ap.path_score, 2),
                    "target_tier": ap.steps[-1].tier if ap.steps else None,
                    "path_type": "acl_abuse", "explanation": ap.explanation or "",
                })
        except Exception as exc:
            log.warning("ACL abuse path computation failed: %s", exc, exc_info=True)
            if len(warnings) < 10:
                warnings.append(f"ACL abuse path computation failed ({type(exc).__name__}).")

        # Deduplicate by (path_score rounded, hop_count, first+last label)
        seen: set = set()
        deduped = []
        for r in sorted(rows, key=lambda x: x["path_score"], reverse=True):
            steps = r.get("path_steps", [])
            key = (
                round(r["path_score"]),
                r["hop_count"],
                steps[0].get("entity_label", "") if steps else "",
                steps[-1].get("entity_label", "") if steps else "",
            )
            if key not in seen:
                seen.add(key)
                deduped.append(r)

        return deduped[:200], warnings  # Cap at 200 persisted paths

    path_rows, compute_warnings = await asyncio.to_thread(_compute)

    # Replace persisted paths only after successful computation.
    await db.execute(delete(ExposurePath).where(ExposurePath.assessment_id == assessment_id))
    await db.flush()

    # Bulk insert ExposurePath records
    from uuid import uuid4 as _uuid4
    for r in path_rows:
        db.add(ExposurePath(
            id=_uuid4(),
            assessment_id=assessment_id,
            source_entity_id=r["source_entity_id"],
            target_entity_id=r["target_entity_id"],
            path_steps=r["path_steps"],
            hop_count=r["hop_count"],
            path_score=r["path_score"],
            target_tier=r["target_tier"],
            path_type=r["path_type"],
            explanation=r["explanation"],
        ))
    await db.commit()

    return {
        "paths_computed": len(path_rows),
        "assessment_id": str(assessment_id),
        "message": f"Computed and persisted {len(path_rows)} attack paths",
        "warning_count": len(compute_warnings),
        "warnings": compute_warnings,
    }


@router.get("/{assessment_id}/categories")
async def get_attack_categories(
    assessment_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: PlatformUser = Depends(get_current_user),
):
    """Return attack paths grouped by technique category."""
    await require_assessment_access(assessment_id, db, current_user)
    analyzer = await _get_analyzer(str(assessment_id), db)

    def _compute_categories():
        cats: dict = {}

        def _ap_to_dict(ap) -> dict:
            return _attack_path_to_dict(ap)

        def _safe(fn, *args, default=None, **kwargs):
            try:
                return fn(*args, **kwargs)
            except Exception:
                return default if default is not None else []

        # Direct control inventory: every high-signal edge the operator can act on.
        direct_edge_types = {
            "GENERIC_ALL", "WRITE_DACL", "WRITE_OWNER", "OWNS", "FORCE_CHANGE_PASSWORD",
            "ADD_MEMBER", "DCSYNC", "ALLOWED_TO_ACT", "ALLOWED_TO_DELEGATE",
            "LOCAL_ADMIN", "ADMIN_TO", "CAN_ENROLL",
        }
        direct_paths = []
        for src, tgt, edge_data in analyzer.graph.edges(data=True):
            etype = edge_data.get("edge_type", "")
            if etype not in direct_edge_types or src in analyzer._tier0:
                continue
            try:
                direct_paths.append(analyzer._build_attack_path([src, tgt]))
            except Exception:
                continue
        direct_paths.sort(
            key=lambda p: (
                p.path_score,
                1 if any(label.startswith("ADG0D") for label in (p.source_label, p.target_label)) else 0,
                -p.hop_count,
            ),
            reverse=True,
        )
        cats["direct_control"] = {"name": "Direct Control", "icon": "crosshair", "color": "#fb7185",
                                  "count": len(direct_paths), "paths": [_ap_to_dict(p) for p in direct_paths[:160]]}

        # ACL Abuse
        acl = _safe(analyzer.detect_acl_abuse_paths, max_paths=30)
        cats["acl_abuse"] = {"name": "ACL Abuse", "icon": "shield-x", "color": "#ef4444",
                              "count": len(acl), "paths": [_ap_to_dict(p) for p in acl[:10]]}

        # Shadow Admins
        shadows = _safe(analyzer.detect_shadow_admins)
        shadow_paths = []
        for s in shadows[:10]:
            shadow_paths.append({
                "source_id": s.entity_id,
                "target_id": None,
                "source_label": s.entity_label, "target_label": "Tier-0 (via ACL)",
                "hop_count": 1, "path_score": round(float(s.risk_score), 2),
                "risk_level": "CRITICAL" if s.risk_score >= 85 else "HIGH",
                "explanation": f"{s.entity_label} has direct control over {len(s.targets)} Tier-0 object(s)",
                "steps": [], "edge_types": s.control_paths,
            })
        cats["shadow_admin"] = {"name": "Shadow Admin", "icon": "user-x", "color": "#a855f7",
                                  "count": len(shadows), "paths": shadow_paths}

        # Kerberoastable
        kerb = _safe(analyzer.detect_kerberoastable_paths)
        kerb_paths = []
        for k in kerb[:10]:
            kerb_paths.append({
                "source_id": k.get("account_id"),
                "target_id": None,
                "source_label": k["account_label"], "target_label": "Crackable TGS",
                "hop_count": 1, "path_score": round(float(k["risk_score"]), 2),
                "risk_level": "CRITICAL" if k["risk_score"] >= 85 else "HIGH",
                "explanation": k.get("attack") or f"{k['account_label']} has SPN registered — TGS hash can be requested and cracked offline",
                "steps": [], "edge_types": ["HAS_SPN"],
            })
        cats["kerberoast"] = {"name": "Kerberoast", "icon": "key", "color": "#f97316",
                               "count": len(kerb), "paths": kerb_paths}

        # AS-REP Roastable
        asrep = _safe(analyzer.detect_asrep_roastable)
        asrep_paths = []
        for a in asrep[:10]:
            asrep_paths.append({
                "source_id": None,
                "target_id": a.get("account_id"),
                "source_label": "Unauthenticated Attacker", "target_label": a["account_label"],
                "hop_count": 1, "path_score": round(float(a["risk_score"]), 2),
                "risk_level": "CRITICAL" if a["risk_score"] >= 85 else "HIGH",
                "explanation": a.get("attack") or f"{a['account_label']} has pre-auth disabled — AS-REP hash retrievable without credentials",
                "steps": [], "edge_types": ["ASREP_ROAST"],
            })
        cats["asrep"] = {"name": "AS-REP Roast", "icon": "zap", "color": "#eab308",
                          "count": len(asrep), "paths": asrep_paths}

        # Delegation (Unconstrained + Constrained + RBCD)
        ucd = _safe(analyzer.detect_unconstrained_delegation)
        ucd_paths = []
        for d in ucd[:10]:
            ucd_paths.append({
                "source_id": d.entity_id,
                "target_id": None,
                "source_label": d.entity_label, "target_label": (d.delegation_targets[0] if d.delegation_targets else "Any Tier-0"),
                "hop_count": 1, "path_score": round(float(d.risk_score), 2),
                "risk_level": "CRITICAL",
                "explanation": getattr(d, 'explanation', None) or f"{d.entity_label} has unconstrained delegation — captures TGTs of any authenticating user",
                "steps": [], "edge_types": ["ALLOWED_TO_DELEGATE"],
            })
        cod = _safe(analyzer.detect_constrained_delegation_abuse)
        ucd_paths += [{
            "source_id": d.entity_id,
            "target_id": None,
            "source_label": d.entity_label, "target_label": (d.delegation_targets[0] if d.delegation_targets else "Target SPN"),
            "hop_count": 1, "path_score": round(float(d.risk_score), 2),
            "risk_level": "HIGH",
            "explanation": getattr(d, 'explanation', None) or f"{d.entity_label} has constrained delegation — S4U2Proxy abuse possible",
            "steps": [], "edge_types": ["ALLOWED_TO_DELEGATE"],
        } for d in cod[:5]]
        rbcd = _safe(analyzer.detect_rbcd_abuse)
        ucd_paths += [{
            "source_id": d.entity_id,
            "target_id": None,
            "source_label": d.entity_label, "target_label": (d.delegation_targets[0] if d.delegation_targets else "RBCD Target"),
            "hop_count": 1, "path_score": round(float(d.risk_score), 2),
            "risk_level": "HIGH",
            "explanation": getattr(d, 'explanation', None) or f"{d.entity_label} — RBCD configured, impersonation possible",
            "steps": [], "edge_types": ["ALLOWED_TO_ACT"],
        } for d in rbcd[:5]]
        cats["delegation"] = {"name": "Delegation", "icon": "repeat", "color": "#06b6d4",
                               "count": len(ucd) + len(cod) + len(rbcd), "paths": ucd_paths[:10]}

        # ADCS
        adcs = _safe(analyzer.detect_adcs_paths)
        adcs_paths = []
        for a in adcs[:10]:
            adcs_paths.append({
                "source_id": None,
                "target_id": None,
                "source_label": (a.enrolling_principals[0] if a.enrolling_principals else "Any Domain User"), "target_label": a.ca_name or "CA",
                "hop_count": 1, "path_score": round(float(a.risk_score), 2),
                "risk_level": "CRITICAL" if a.risk_score >= 85 else "HIGH",
                "explanation": f"{a.esc_type}: {a.template_name} — {a.description}",
                "steps": [], "edge_types": ["CAN_ENROLL"],
            })
        cats["adcs"] = {"name": "ADCS / PKI", "icon": "certificate", "color": "#10b981",
                         "count": len(adcs), "paths": adcs_paths}

        # DCSync
        dcsync = _safe(analyzer.detect_dcsync_principals)
        dc_paths = [{
            "source_id": d.get("principal_id"),
            "target_id": d.get("target_id"),
            "source_label": d["principal_label"], "target_label": d.get("target_label") or "NTDS.dit (All Hashes)",
            "hop_count": 1, "path_score": 100.0, "risk_level": "CRITICAL",
            "explanation": f"{d['principal_label']} has DCSync rights on {d.get('target_label', 'the domain')} — can replicate all AD secrets",
            "steps": [], "edge_types": ["DCSYNC"],
        } for d in dcsync[:10]]
        cats["dcsync"] = {"name": "DCSync", "icon": "database", "color": "#ef4444",
                           "count": len(dcsync), "paths": dc_paths}

        return cats

    categories = await asyncio.to_thread(_compute_categories)

    total_paths = sum(c["count"] for c in categories.values())
    critical_count = sum(
        sum(1 for p in c["paths"] if p.get("risk_level") == "CRITICAL")
        for c in categories.values()
    )
    edge_type_counts: dict[str, int] = {}
    for category in categories.values():
        for path in category.get("paths", []):
            for edge_type in path.get("edge_types", []) or []:
                if not edge_type:
                    continue
                edge_type_counts[edge_type] = edge_type_counts.get(edge_type, 0) + 1
    return {
        "categories": categories,
        "total_paths": total_paths,
        "critical_count": critical_count,
        "edge_type_counts": edge_type_counts,
    }


@router.get("/{assessment_id}/choke-points")
async def get_choke_points(
    assessment_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: PlatformUser = Depends(get_current_user),
):
    """Return top choke points with removal impact simulation."""
    await require_assessment_access(assessment_id, db, current_user)
    analyzer = await _get_analyzer(str(assessment_id), db)

    def _compute():
        try:
            chokes = analyzer.find_choke_points(top_n=15)
            result = []
            for cp in chokes:
                d = dataclasses.asdict(cp) if dataclasses.is_dataclass(cp) else vars(cp)
                result.append(d)
            return result
        except Exception as exc:
            log.warning("Choke point computation failed: %s", exc)
            return []

    choke_points = await asyncio.to_thread(_compute)
    return {"choke_points": choke_points, "count": len(choke_points)}


@router.get("/{assessment_id}/communities")
async def get_communities(
    assessment_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: PlatformUser = Depends(get_current_user),
):
    """Return Louvain community partition for the assessment graph."""
    await require_assessment_access(assessment_id, db, current_user)
    analyzer = await _get_analyzer(str(assessment_id), db)

    def _compute():
        try:
            return analyzer.get_communities_summary()
        except Exception as exc:
            log.warning("Community detection failed: %s", exc)
            return []

    communities = await asyncio.to_thread(_compute)
    return {"communities": communities, "count": len(communities)}


@router.get("/{assessment_id}/centrality")
async def get_centrality(
    assessment_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: PlatformUser = Depends(get_current_user),
):
    """Return centrality metrics, computing and persisting on first call (1hr cache)."""
    await require_assessment_access(assessment_id, db, current_user)
    from adbygod_api.models import GraphCentrality as GraphCentralityModel
    from datetime import timedelta
    from uuid import uuid4

    cutoff = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(hours=1)
    existing = await db.execute(
        select(GraphCentralityModel)
        .where(GraphCentralityModel.assessment_id == assessment_id)
        .limit(1)
    )
    row = existing.scalar_one_or_none()
    if row and row.computed_at > cutoff:
        all_rows = await db.execute(
            select(GraphCentralityModel).where(GraphCentralityModel.assessment_id == assessment_id)
        )
        nodes = [
            {"entity_id": str(r.entity_id), "betweenness": r.betweenness,
             "degree_centrality": r.degree_centrality, "eigenvector": r.eigenvector,
             "pagerank": r.pagerank}
            for r in all_rows.scalars().all()
        ]
        return {"nodes": nodes, "cached": True}

    analyzer = await _get_analyzer(str(assessment_id), db)
    metrics = await asyncio.to_thread(analyzer.compute_centrality_metrics)

    await db.execute(
        delete(GraphCentralityModel).where(GraphCentralityModel.assessment_id == assessment_id)
    )
    for node_id, m in metrics.items():
        try:
            entity_uuid = UUID(node_id)
        except ValueError:
            continue
        db.add(GraphCentralityModel(
            id=uuid4(), assessment_id=assessment_id, entity_id=entity_uuid,
            betweenness=m["betweenness"], degree_centrality=m["degree_centrality"],
            eigenvector=m["eigenvector"], pagerank=m["pagerank"],
        ))
    await db.commit()

    nodes = [{"entity_id": nid, **m} for nid, m in metrics.items()]
    return {"nodes": nodes, "cached": False}


@router.get("/{assessment_id}/neighborhood/{node_id}")
async def get_neighborhood(
    assessment_id: UUID,
    node_id: str,
    hops: int = Query(2, ge=1, le=5),
    max_nodes: int = Query(200, ge=10, le=1000),
    db: AsyncSession = Depends(get_db),
    current_user: PlatformUser = Depends(get_current_user),
):
    """Return the N-hop subgraph around a single node."""
    await require_assessment_access(assessment_id, db, current_user)
    analyzer = await _get_analyzer(str(assessment_id), db)
    result = await asyncio.to_thread(analyzer.get_neighborhood, node_id, hops, max_nodes)
    return result


@router.post("/{assessment_id}/layout")
async def save_layout(
    assessment_id: UUID,
    body: LayoutSaveRequest,
    db: AsyncSession = Depends(get_db),
    current_user: PlatformUser = Depends(get_current_user),
):
    """Save node positions for a named layout."""
    await require_assessment_access(assessment_id, db, current_user)
    from adbygod_api.models import GraphLayout
    from uuid import uuid4
    existing = await db.execute(
        select(GraphLayout).where(
            GraphLayout.assessment_id == assessment_id,
            GraphLayout.user_id == current_user.id,
            GraphLayout.layout_name == body.layout_name,
        )
    )
    row = existing.scalar_one_or_none()
    if row:
        row.node_positions = body.positions
    else:
        db.add(GraphLayout(
            id=uuid4(), assessment_id=assessment_id, user_id=current_user.id,
            layout_name=body.layout_name, node_positions=body.positions,
        ))
    await db.commit()
    return {"saved": True, "layout_name": body.layout_name}


@router.get("/{assessment_id}/layout/{layout_name}")
async def get_layout(
    assessment_id: UUID,
    layout_name: str,
    db: AsyncSession = Depends(get_db),
    current_user: PlatformUser = Depends(get_current_user),
):
    """Load saved node positions for a named layout."""
    await require_assessment_access(assessment_id, db, current_user)
    from adbygod_api.models import GraphLayout
    existing = await db.execute(
        select(GraphLayout).where(
            GraphLayout.assessment_id == assessment_id,
            GraphLayout.user_id == current_user.id,
            GraphLayout.layout_name == layout_name,
        )
    )
    row = existing.scalar_one_or_none()
    if not row:
        raise HTTPException(status_code=404, detail="Layout not found")
    return {"layout_name": layout_name, "positions": row.node_positions}


@router.delete("/{assessment_id}/layout/{layout_name}", status_code=204)
async def delete_layout(
    assessment_id: UUID,
    layout_name: str,
    db: AsyncSession = Depends(get_db),
    current_user: PlatformUser = Depends(get_current_user),
):
    """Delete a saved layout."""
    await require_assessment_access(assessment_id, db, current_user)
    from adbygod_api.models import GraphLayout
    await db.execute(
        delete(GraphLayout).where(
            GraphLayout.assessment_id == assessment_id,
            GraphLayout.user_id == current_user.id,
            GraphLayout.layout_name == layout_name,
        )
    )
    await db.commit()


@router.post("/{assessment_id}/snapshot")
async def create_snapshot(
    assessment_id: UUID,
    body: SnapshotCreateRequest,
    db: AsyncSession = Depends(get_db),
    current_user: PlatformUser = Depends(get_current_user),
):
    """Capture the current graph state as a named snapshot."""
    await require_assessment_access(assessment_id, db, current_user)
    from adbygod_api.models import GraphSnapshot
    from uuid import uuid4
    analyzer = await _get_analyzer(str(assessment_id), db)
    data = analyzer.export_for_frontend(max_nodes=5000)
    snap = GraphSnapshot(
        id=uuid4(), assessment_id=assessment_id, user_id=current_user.id,
        label=body.label, node_count=data["node_count"], edge_count=data["edge_count"],
        snapshot_data={"nodes": data["nodes"], "edges": data["edges"]},
    )
    db.add(snap)
    await db.commit()
    return {"id": str(snap.id), "label": snap.label,
            "created_at": snap.created_at.isoformat(),
            "node_count": snap.node_count, "edge_count": snap.edge_count}


@router.get("/{assessment_id}/snapshots")
async def list_snapshots(
    assessment_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: PlatformUser = Depends(get_current_user),
):
    """List all snapshots for this assessment."""
    await require_assessment_access(assessment_id, db, current_user)
    from adbygod_api.models import GraphSnapshot
    result = await db.execute(
        select(GraphSnapshot).where(GraphSnapshot.assessment_id == assessment_id)
        .order_by(GraphSnapshot.created_at.desc())
    )
    rows = result.scalars().all()
    return {"snapshots": [
        {"id": str(r.id), "label": r.label, "created_at": r.created_at.isoformat(),
         "node_count": r.node_count, "edge_count": r.edge_count}
        for r in rows
    ]}


@router.get("/{assessment_id}/markings")
async def get_markings(
    assessment_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: PlatformUser = Depends(get_current_user),
):
    await require_assessment_access(assessment_id, db, current_user)
    from adbygod_api.models import GraphMarkings
    result = await db.execute(
        select(GraphMarkings).where(
            GraphMarkings.assessment_id == assessment_id,
            GraphMarkings.user_id == current_user.id,
        )
    )
    row = result.scalar_one_or_none()
    if not row:
        return {"owned_ids": [], "high_value_ids": [], "pinned_ids": []}
    return {"owned_ids": row.owned_ids, "high_value_ids": row.high_value_ids, "pinned_ids": row.pinned_ids}


@router.put("/{assessment_id}/markings")
async def put_markings(
    assessment_id: UUID,
    body: dict,
    db: AsyncSession = Depends(get_db),
    current_user: PlatformUser = Depends(get_current_user),
):
    await require_assessment_access(assessment_id, db, current_user)
    from adbygod_api.models import GraphMarkings
    result = await db.execute(
        select(GraphMarkings).where(
            GraphMarkings.assessment_id == assessment_id,
            GraphMarkings.user_id == current_user.id,
        )
    )
    row = result.scalar_one_or_none()
    if row:
        if "owned_ids" in body:
            row.owned_ids = body["owned_ids"]
        if "high_value_ids" in body:
            row.high_value_ids = body["high_value_ids"]
        if "pinned_ids" in body:
            row.pinned_ids = body["pinned_ids"]
    else:
        db.add(GraphMarkings(
            assessment_id=assessment_id, user_id=current_user.id,
            owned_ids=body.get("owned_ids", []),
            high_value_ids=body.get("high_value_ids", []),
            pinned_ids=body.get("pinned_ids", []),
        ))
    await db.commit()
    return {"saved": True}


@router.get("/{assessment_id}/views")
async def get_views(
    assessment_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: PlatformUser = Depends(get_current_user),
):
    await require_assessment_access(assessment_id, db, current_user)
    from adbygod_api.models import GraphView
    result = await db.execute(
        select(GraphView).where(
            GraphView.assessment_id == assessment_id,
            GraphView.user_id == current_user.id,
        ).order_by(GraphView.created_at.desc())
    )
    rows = result.scalars().all()
    return {"views": [
        {"id": str(r.id), "name": r.name, "config": r.config, "created_at": r.created_at.isoformat()}
        for r in rows
    ]}


@router.post("/{assessment_id}/views")
async def create_view(
    assessment_id: UUID,
    body: dict,
    db: AsyncSession = Depends(get_db),
    current_user: PlatformUser = Depends(get_current_user),
):
    await require_assessment_access(assessment_id, db, current_user)
    from adbygod_api.models import GraphView
    from uuid import uuid4
    row = GraphView(
        id=uuid4(), assessment_id=assessment_id, user_id=current_user.id,
        name=body.get("name", "Unnamed View"), config=body.get("config", {}),
    )
    db.add(row)
    await db.commit()
    return {"id": str(row.id), "name": row.name, "config": row.config, "created_at": row.created_at.isoformat()}


@router.delete("/{assessment_id}/views/{view_id}", status_code=204)
async def delete_view(
    assessment_id: UUID,
    view_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: PlatformUser = Depends(get_current_user),
):
    await require_assessment_access(assessment_id, db, current_user)
    from adbygod_api.models import GraphView
    await db.execute(
        delete(GraphView).where(
            GraphView.id == view_id,
            GraphView.user_id == current_user.id,
        )
    )
    await db.commit()


@router.get("/{assessment_id}/diff")
async def get_snapshot_diff(
    assessment_id: UUID,
    from_snap: str = Query(..., alias="from"),
    to_snap: str = Query(..., alias="to"),
    db: AsyncSession = Depends(get_db),
    current_user: PlatformUser = Depends(get_current_user),
):
    """Compute diff between two snapshots."""
    await require_assessment_access(assessment_id, db, current_user)
    from adbygod_api.models import GraphSnapshot
    from uuid import UUID as _UUID2
    snap_a_row = await db.get(GraphSnapshot, _UUID2(from_snap))
    snap_b_row = await db.get(GraphSnapshot, _UUID2(to_snap))
    if not snap_a_row or not snap_b_row:
        raise HTTPException(status_code=404, detail="One or both snapshots not found")
    if snap_a_row.assessment_id != assessment_id or snap_b_row.assessment_id != assessment_id:
        raise HTTPException(status_code=403, detail="Snapshot does not belong to this assessment")
    diff = _compute_snapshot_diff(snap_a_row.snapshot_data, snap_b_row.snapshot_data)
    return diff


def _get_edge_remediation(edge_type: str) -> str:
    REMEDIATIONS = {
        "GENERIC_ALL": "Remove GenericAll ACE: Remove-ADObjectAcl -TargetIdentity TARGET -PrincipalIdentity PRINCIPAL -Rights GenericAll -AccessControlType Allow",
        "WRITE_DACL":  "Remove WriteDACL ACE: Remove-ADObjectAcl -TargetIdentity TARGET -PrincipalIdentity PRINCIPAL -Rights WriteDacl -AccessControlType Allow",
        "DCSYNC":      "Remove DCSync rights: Remove Replicating Directory Changes from the principal using ADSI or AD PowerShell",
        "ALLOWED_TO_DELEGATE": "Disable delegation: Set-ADAccountControl -Identity ACCOUNT -TrustedForDelegation $false",
        "ALLOWED_TO_ACT": "Clear msDS-AllowedToActOnBehalfOfOtherIdentity: Set-ADComputer -Identity TARGET -Clear msDS-AllowedToActOnBehalfOfOtherIdentity",
        "ADD_MEMBER":  "Remove AddMember right: Remove-ADGroupMember or restrict group write ACL",
        "FORCE_CHANGE_PASSWORD": "Remove User-Force-Change-Password extended right from ACL",
        "HAS_SPN":     "Remove the SPN: Set-ADUser -Identity USER -ServicePrincipalNames @{Remove='SPN/value'} or use managed service accounts",
        "CAN_ENROLL":  "Restrict template enrollment: modify Certificate Template ACL to remove Enroll permission",
        "ADMIN_TO":    "Remove local admin membership: net localgroup administrators PRINCIPAL /delete on TARGET",
        "LOCAL_ADMIN": "Remove local admin: Restrict via GPO or LAPS to eliminate standing privilege",
    }
    return REMEDIATIONS.get(edge_type, f"Review and restrict the {edge_type} privilege/right.")


_narration_cache: dict[str, dict] = {}
_NARRATION_CACHE_MAX = 100


def _generate_playbook_markdown(steps: list, source_label: str, target_label: str) -> str:
    from adbygod_api.core.graph.mitre_mapping import path_to_techniques
    techniques = path_to_techniques(steps)
    lines = [
        f"# Attack Path Playbook: {source_label} → {target_label}",
        "",
        f"**Source:** {source_label}  ",
        f"**Target:** {target_label}  ",
        f"**Total Hops:** {len(steps)}  ",
        "",
        "## MITRE ATT&CK Techniques",
        "",
        "| # | Technique ID | Name | Tactic |",
        "|---|---|---|---|",
    ]
    for i, t in enumerate(techniques, 1):
        lines.append(f"| {i} | [{t['technique_id']}](https://attack.mitre.org/techniques/{t['technique_id'].replace('.','/')}) | {t['technique_name']} | {t['tactic']} |")
    lines += ["", "## Step-by-Step Exploitation", ""]
    for i, step in enumerate(steps, 1):
        etype = (step.get("edge_type") or "").upper()
        mapping = next((t for t in techniques if t.get("edge_type") == etype), None)
        lines += [f"### Hop {i}: {etype}", "", f"**Actor:** {step.get('entity_label', 'N/A')} ({step.get('entity_type', 'N/A')})", ""]
        if mapping:
            lines += [
                f"**Technique:** {mapping['technique_id']} — {mapping['technique_name']}",
                f"**Tactic:** {mapping['tactic']}", "",
            ]
            if mapping.get("tool_suggestion"):
                lines += ["**Tools:**", "```", mapping["tool_suggestion"], "```", ""]
            if mapping.get("detection_sigma") or mapping.get("sigma_snippet"):
                sigma = mapping.get("detection_sigma") or mapping.get("sigma_snippet", "")
                lines += ["**Detection (Sigma):**", "```yaml", sigma, "```", ""]
            rem = _get_edge_remediation(etype)
            lines += ["**Remediation:**", "```powershell", rem, "```", ""]
    return "\n".join(lines)


def _generate_navigator_json(steps: list) -> dict:
    from adbygod_api.core.graph.mitre_mapping import path_to_techniques
    techniques = path_to_techniques(steps)
    return {
        "name": "AdByG0d Attack Path",
        "versions": {"attack": "14", "navigator": "4.9.0", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": "Generated by AdByG0d graph analysis",
        "techniques": [
            {
                "techniqueID": t["technique_id"],
                "tactic": t["tactic"].lower().replace(" ", "-"),
                "color": "#ef4444",
                "comment": t["technique_name"],
                "enabled": True,
                "score": 100,
            }
            for t in techniques
        ],
        "gradient": {"colors": ["#ffffff", "#ef4444"], "minValue": 0, "maxValue": 100},
    }


class PlaybookExportRequest(BaseModel):
    path_steps: list
    source_label: str = ""
    target_label: str = ""
    format: str = "markdown"


class MonteCarloRequest(BaseModel):
    path_steps: list
    iterations: int = 1000


@router.post("/{assessment_id}/monte-carlo")
async def run_monte_carlo(
    assessment_id: UUID,
    body: MonteCarloRequest,
    db: AsyncSession = Depends(get_db),
    current_user: PlatformUser = Depends(get_current_user),
):
    """Run Monte Carlo simulation on a path to compute P(success)."""
    await require_assessment_access(assessment_id, db, current_user)
    if not body.path_steps:
        return {"p_success": 0.0, "iterations": 0, "histogram": [0]*10, "success_pct_label": "0%"}
    iters = min(max(body.iterations, 100), 5000)
    result = await asyncio.to_thread(_run_monte_carlo, body.path_steps, iters)
    return result


class NarratePathRequest(BaseModel):
    path_steps: list
    source_label: str = ""
    target_label: str = ""


@router.post("/{assessment_id}/narrate-path")
async def narrate_path(
    assessment_id: UUID,
    body: NarratePathRequest,
    db: AsyncSession = Depends(get_db),
    current_user: PlatformUser = Depends(get_current_user),
):
    """Generate step-by-step attack path narration with MITRE ATT&CK mapping."""
    await require_assessment_access(assessment_id, db, current_user)
    cache_key = hashlib.sha256(
        str([(s.get("edge_type"), s.get("entity_type")) for s in body.path_steps]).encode()
    ).hexdigest()[:16]
    if cache_key in _narration_cache:
        return _narration_cache[cache_key]
    from adbygod_api.core.graph.mitre_mapping import path_to_techniques
    techniques = path_to_techniques(body.path_steps)
    steps_out = []
    for i, step in enumerate(body.path_steps):
        etype = (step.get("edge_type") or "").upper()
        mapping = next((t for t in techniques if t.get("edge_type") == etype), None)
        steps_out.append({
            "hop": i + 1,
            "action": f"{step.get('entity_label', 'Object')} → {etype}",
            "technique_id": mapping["technique_id"] if mapping else None,
            "technique_name": mapping["technique_name"] if mapping else etype,
            "tactic": mapping["tactic"] if mapping else "Unknown",
            "tool": mapping["tool_suggestion"] if mapping else "",
            "detection_sigma": mapping["sigma_snippet"] if mapping else "",
            "remediation": _get_edge_remediation(etype),
        })
    result = {
        "source": body.source_label,
        "target": body.target_label,
        "summary": f"Attacker moves from {body.source_label} to {body.target_label} in {len(body.path_steps)} hop(s) using {', '.join(set(s.get('edge_type','') for s in body.path_steps))}.",
        "steps": steps_out,
        "mitre_techniques": techniques,
    }
    if len(_narration_cache) >= _NARRATION_CACHE_MAX:
        oldest_key = next(iter(_narration_cache))
        del _narration_cache[oldest_key]
    _narration_cache[cache_key] = result
    return result


@router.post("/{assessment_id}/export-playbook")
async def export_playbook(
    assessment_id: UUID,
    body: PlaybookExportRequest,
    db: AsyncSession = Depends(get_db),
    current_user: PlatformUser = Depends(get_current_user),
):
    """Export attack path as MITRE ATT&CK-aligned playbook."""
    await require_assessment_access(assessment_id, db, current_user)
    if not body.path_steps:
        raise HTTPException(status_code=400, detail="path_steps required")
    if body.format == "navigator_json":
        content = _generate_navigator_json(body.path_steps)
        return {"format": "navigator_json", "content": content}
    md = _generate_playbook_markdown(body.path_steps, body.source_label, body.target_label)
    return {"format": "markdown", "content": md}


class NLQueryRequest(BaseModel):
    query: str


@router.post("/{assessment_id}/nl-query")
async def nl_graph_query(
    assessment_id: UUID,
    body: NLQueryRequest,
    db: AsyncSession = Depends(get_db),
    current_user: PlatformUser = Depends(get_current_user),
):
    """Translate natural language query into graph filter results using rule-based patterns."""
    await require_assessment_access(assessment_id, db, current_user)
    if not body.query.strip():
        raise HTTPException(status_code=400, detail="Query must not be empty")
    analyzer = await _get_analyzer(str(assessment_id), db)
    q = body.query.lower()
    node_ids: list[str] = []
    edge_ids: list[str] = []
    explanation = ""
    PATTERNS = [
        # Kerberos attacks
        (["kerberoast", "kerberoastable", "has spn", "spn"],
         lambda: [n for n in analyzer.graph.nodes() if
                  any(d.get("edge_type") == "HAS_SPN"
                      for _, _, d in analyzer.graph.out_edges(n, data=True))],
         "node", "Kerberoastable accounts (nodes with HAS_SPN edges)"),
        (["as-rep", "asrep", "as rep", "preauth", "doesnotrequirepreauth", "no preauth"],
         lambda: [n for n in analyzer.graph.nodes()
                  if analyzer.entity_meta.get(n, {}).get("uac_dont_req_preauth")
                  and analyzer.entity_meta.get(n, {}).get("type") == "USER"],
         "node", "AS-REP roastable accounts (no preauthentication required)"),
        # DCSync / replication
        (["dcsync", "dc sync", "replication", "replicate", "getchanges"],
         lambda: [u for u, v, d in analyzer.graph.edges(data=True) if d.get("edge_type") == "DCSYNC"],
         "node", "Accounts with DCSync rights"),
        # Tier-0 / domain admins
        (["tier 0", "tier-0", "domain admin", "privileged", "enterprise admin"],
         lambda: [n for n in analyzer.graph.nodes() if analyzer.is_tier0(n)],
         "node", "Tier-0 privileged nodes"),
        # Delegation
        (["unconstrained", "unconstrained delegation", "trusted for delegation"],
         lambda: [n for n in analyzer.graph.nodes()
                  if analyzer.entity_meta.get(n, {}).get("uac_trusted_for_deleg")],
         "node", "Hosts with unconstrained delegation"),
        (["constrained delegation", "constrained", "allowed to delegate", "s4u"],
         lambda: [u for u, v, d in analyzer.graph.edges(data=True)
                  if d.get("edge_type") in ("ALLOWED_TO_DELEGATE",)],
         "node", "Accounts with constrained delegation"),
        (["delegation", "delegate", "allowed to act", "rbcd", "resource based"],
         lambda: [u for u, v, d in analyzer.graph.edges(data=True)
                  if d.get("edge_type") in ("ALLOWED_TO_DELEGATE", "ALLOWED_TO_ACT")],
         "node", "Nodes with delegation rights"),
        # ACL abuse
        (["genericall", "generic all", "full control", "full rights"],
         lambda: [u for u, v, d in analyzer.graph.edges(data=True) if d.get("edge_type") == "GENERIC_ALL"],
         "node", "Nodes with GenericAll rights"),
        (["writedacl", "write dacl", "write the dacl", "dacl"],
         lambda: [u for u, v, d in analyzer.graph.edges(data=True) if d.get("edge_type") == "WRITE_DACL"],
         "node", "Nodes with WriteDACL rights"),
        (["writeowner", "write owner", "owns"],
         lambda: [u for u, v, d in analyzer.graph.edges(data=True) if d.get("edge_type") == "WRITE_OWNER"],
         "node", "Nodes with WriteOwner rights"),
        (["genericwrite", "generic write"],
         lambda: [u for u, v, d in analyzer.graph.edges(data=True) if d.get("edge_type") == "GENERIC_WRITE"],
         "node", "Nodes with GenericWrite rights"),
        (["forcechangepassword", "force change password", "change password", "reset password"],
         lambda: [u for u, v, d in analyzer.graph.edges(data=True)
                  if d.get("edge_type") in ("FORCE_CHANGE_PASSWORD", "HAS_CONTROL")],
         "node", "Accounts that can force password change"),
        (["acl", "access control", "ace", "abuse"],
         lambda: list({u for u, v, d in analyzer.graph.edges(data=True)
                       if d.get("edge_type") in ("GENERIC_ALL", "WRITE_DACL", "WRITE_OWNER",
                                                  "GENERIC_WRITE", "FORCE_CHANGE_PASSWORD")}),
         "node", "Nodes with abusable ACL rights"),
        # Risk-based
        (["high risk", "critical edge", "critical path", "critical"],
         lambda: [str(d.get("id", f"{u}__{v}")) for u, v, d in analyzer.graph.edges(data=True)
                  if d.get("risk_weight", 0) >= 0.8],
         "edge", "Critical-risk edges (risk >= 80%)"),
        (["medium risk", "medium"],
         lambda: [str(d.get("id", f"{u}__{v}")) for u, v, d in analyzer.graph.edges(data=True)
                  if 0.5 <= d.get("risk_weight", 0) < 0.8],
         "edge", "Medium-risk edges (50-79%)"),
        # Object types
        (["computer", "workstation", "server", "machine", "host", "device"],
         lambda: [n for n in analyzer.graph.nodes()
                  if analyzer.entity_meta.get(n, {}).get("type") == "COMPUTER"],
         "node", "Computer objects"),
        (["user", "users", "user account", "person", "people", "human"],
         lambda: [n for n in analyzer.graph.nodes()
                  if analyzer.entity_meta.get(n, {}).get("type") == "USER"],
         "node", "User accounts"),
        (["group", "groups", "group member"],
         lambda: [n for n in analyzer.graph.nodes()
                  if analyzer.entity_meta.get(n, {}).get("type") == "GROUP"],
         "node", "Group objects"),
        (["service account", "service accounts", "gmsa", "msa"],
         lambda: [n for n in analyzer.graph.nodes()
                  if analyzer.entity_meta.get(n, {}).get("gmsa")
                  or (analyzer.entity_meta.get(n, {}).get("type") in ("USER", "SERVICE_ACCOUNT")
                      and any(kw in (
                          (analyzer.entity_meta.get(n, {}).get("sam_account_name") or "") + " " +
                          (analyzer._label_of(n) or "")
                      ).lower() for kw in ("svc", "service", "sa-", "_svc", "svc-")))],
         "node", "Service accounts (gMSA or svc/service naming)"),
        # Remote access
        (["can rdp", "rdp access", "remote desktop", "rdp"],
         lambda: [u for u, v, d in analyzer.graph.edges(data=True) if d.get("edge_type") == "CAN_RDP"],
         "node", "Accounts with RDP access"),
        (["can winrm", "winrm", "remote management", "wsman"],
         lambda: [u for u, v, d in analyzer.graph.edges(data=True) if d.get("edge_type") == "CAN_WINRM"],
         "node", "Accounts with WinRM access"),
        (["sql admin", "sqladmin", "sql server", "xp_cmdshell"],
         lambda: [u for u, v, d in analyzer.graph.edges(data=True) if d.get("edge_type") == "SQL_ADMIN"],
         "node", "Accounts with SQL admin rights"),
        (["golden cert", "golden certificate", "esc", "manage ca", "ca control"],
         lambda: [u for u, v, d in analyzer.graph.edges(data=True)
                  if d.get("edge_type") in ("MANAGE_CA", "MANAGE_CERTIFICATES", "GOLDEN_CERT",
                                             "CA_PRIVATE_KEY_CONTROL")],
         "node", "Accounts with CA management or golden cert rights"),
        (["read laps", "laps password", "laps read"],
         lambda: [u for u, v, d in analyzer.graph.edges(data=True) if d.get("edge_type") == "READ_LAPS_PASSWORD"],
         "node", "Accounts that can read LAPS passwords"),
        (["crown jewel", "jewel", "high value target", "hvt"],
         lambda: [n for n in analyzer.graph.nodes()
                  if analyzer.entity_meta.get(n, {}).get("is_crown_jewel")],
         "node", "Crown Jewel / high value targets"),
        (["organizational unit", "container", " ou ", "ou:"],
         lambda: [n for n in analyzer.graph.nodes()
                  if analyzer.entity_meta.get(n, {}).get("type") in ("OU", "CONTAINER")],
         "node", "Organizational units and containers"),
        # AdminCount / sensitive
        (["admin count", "admincount", "sensitive", "protected"],
         lambda: [n for n in analyzer.graph.nodes()
                  if analyzer.entity_meta.get(n, {}).get("is_admin_count")],
         "node", "Objects with AdminCount=1"),
        # Password / account hygiene
        (["password never expire", "no password expiry", "pwdneverexpires", "password expiry", "never expire"],
         lambda: [n for n in analyzer.graph.nodes()
                  if analyzer.entity_meta.get(n, {}).get("attributes", {}).get("pwd_never_expires")
                  and analyzer.entity_meta.get(n, {}).get("type") == "USER"],
         "node", "Users with passwords that never expire"),
        (["stale", "inactive", "old account", "disabled"],
         lambda: [n for n in analyzer.graph.nodes()
                  if not analyzer.entity_meta.get(n, {}).get("is_enabled", True)],
         "node", "Disabled/inactive accounts"),
        # Local admin (before LAPS — "local admin" would match LAPS if LAPS came first)
        (["local admin", "admin to", "localadmin", "admin rights"],
         lambda: [u for u, v, d in analyzer.graph.edges(data=True) if d.get("edge_type") == "ADMIN_TO"],
         "node", "Accounts with local admin rights"),
        (["laps", "no laps", "without laps", "laps missing", "local admin password"],
         lambda: [n for n in analyzer.graph.nodes()
                  if analyzer.entity_meta.get(n, {}).get("type") == "COMPUTER"
                  and not analyzer.entity_meta.get(n, {}).get("laps_enabled")],
         "node", "Computers without LAPS"),
        # ADCS / PKI
        (["certificate", "cert template", "adcs", "pki", "esc", "enrollment"],
         lambda: [n for n in analyzer.graph.nodes()
                  if analyzer.entity_meta.get(n, {}).get("type") in ("CERT_TEMPLATE", "CA")],
         "node", "Certificate templates and CAs"),
        # SID history
        (["sid history", "sidhistory", "sid"],
         lambda: [u for u, v, d in analyzer.graph.edges(data=True) if d.get("edge_type") == "HAS_SID_HISTORY"],
         "node", "Accounts with SID history"),
        # Shadow credentials
        (["shadow credential", "shadow cred", "msds-keycredential", "keycredlink", "add key"],
         lambda: [u for u, v, d in analyzer.graph.edges(data=True) if d.get("edge_type") == "ADD_KEY_CREDENTIAL_LINK"],
         "node", "Accounts that can add shadow credentials"),
    ]
    for keywords, fn, result_type, desc in PATTERNS:
        if any(kw in q for kw in keywords):
            try:
                ids = await asyncio.to_thread(fn)
                if result_type == "node":
                    node_ids = ids[:500]
                else:
                    edge_ids = ids[:500]
                explanation = desc
            except Exception:
                pass
            break
    if not node_ids and not edge_ids:
        explanation = (
            f"No pattern matched for: '{body.query}'. "
            "Try: kerberoastable, dcsync, tier-0, delegation, genericall, writedacl, "
            "admincount, high risk, computers, users, groups, stale, laps, adcs, local admin"
        )
    return {
        "query": body.query,
        "filter_type": "node" if node_ids else "edge" if edge_ids else "none",
        "node_ids": node_ids,
        "edge_ids": edge_ids,
        "result_count": len(node_ids) + len(edge_ids),
        "explanation": explanation,
    }


@router.get("/{assessment_id}/anomalies")
async def get_anomalies(
    assessment_id: UUID,
    days_back: int = Query(7, ge=1, le=365),
    db: AsyncSession = Depends(get_db),
    current_user: PlatformUser = Depends(get_current_user),
):
    """Detect statistical anomalies and recent edge changes."""
    await require_assessment_access(assessment_id, db, current_user)
    analyzer = await _get_analyzer(str(assessment_id), db)
    anomalies = await asyncio.to_thread(analyzer.detect_anomalies, days_back)
    return {"anomalies": anomalies, "count": len(anomalies), "days_back": days_back}


@router.get("/{assessment_id}/diff-assessment")
async def diff_assessment(
    assessment_id: UUID,
    compare_to: UUID = Query(...),
    db: AsyncSession = Depends(get_db),
    current_user: PlatformUser = Depends(get_current_user),
):
    """Diff current assessment graph against another assessment."""
    await require_assessment_access(assessment_id, db, current_user)
    await require_assessment_access(compare_to, db, current_user)
    analyzer_a = await _get_analyzer(str(assessment_id), db)
    analyzer_b = await _get_analyzer(str(compare_to), db)

    nodes_a = set(analyzer_a.graph.nodes())
    nodes_b = set(analyzer_b.graph.nodes())
    edges_a = {(u, v, d.get("edge_type")) for u, v, d in analyzer_a.graph.edges(data=True)}
    edges_b = {(u, v, d.get("edge_type")) for u, v, d in analyzer_b.graph.edges(data=True)}

    added_nodes = [
        {"id": n, "label": analyzer_b._label_of(n), "type": analyzer_b.entity_meta.get(n, {}).get("type")}
        for n in nodes_b - nodes_a
    ]
    removed_nodes = [
        {"id": n, "label": analyzer_a._label_of(n), "type": analyzer_a.entity_meta.get(n, {}).get("type")}
        for n in nodes_a - nodes_b
    ]
    added_edges = [
        {"source": u, "target": v, "edge_type": et,
         "source_label": analyzer_b._label_of(u), "target_label": analyzer_b._label_of(v)}
        for u, v, et in edges_b - edges_a
    ]
    removed_edges = [
        {"source": u, "target": v, "edge_type": et,
         "source_label": analyzer_a._label_of(u), "target_label": analyzer_a._label_of(v)}
        for u, v, et in edges_a - edges_b
    ]

    return {
        "assessment_id": str(assessment_id),
        "compare_to": str(compare_to),
        "added_nodes": added_nodes[:200],
        "removed_nodes": removed_nodes[:200],
        "added_edges": added_edges[:500],
        "removed_edges": removed_edges[:500],
        "summary": {
            "new_nodes": len(added_nodes),
            "removed_nodes": len(removed_nodes),
            "new_edges": len(added_edges),
            "removed_edges": len(removed_edges),
        },
    }


def _enqueue_projection(assessment_id) -> None:
    from adbygod_api.core.tasks.graph_projection import enqueue
    enqueue(assessment_id)


@router.post("/{assessment_id}/reproject", status_code=202)
async def reproject_graph(
    assessment_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: PlatformUser = Depends(get_current_user),
):
    """Enqueue a (re)projection of the assessment graph into Neo4j."""
    await require_assessment_write_access(assessment_id, db, current_user)
    state = await db.get(GraphProjectionState, assessment_id)
    if state is None:
        state = GraphProjectionState(assessment_id=assessment_id)
        db.add(state)
    state.status = "projecting"
    await db.commit()
    _enqueue_projection(assessment_id)
    return {"status": "projecting", "assessment_id": str(assessment_id)}


@router.get("/{assessment_id}/projection-state")
async def get_projection_state(
    assessment_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: PlatformUser = Depends(get_current_user),
):
    """Return the current Neo4j projection state for an assessment."""
    await require_assessment_access(assessment_id, db, current_user)
    state = await db.get(GraphProjectionState, assessment_id)
    if state is None:
        return {
            "assessment_id": str(assessment_id),
            "status": "pending",
            "node_count": 0,
            "edge_count": 0,
            "last_projected_at": None,
        }
    return {
        "assessment_id": str(assessment_id),
        "status": state.status,
        "node_count": state.node_count,
        "edge_count": state.edge_count,
        "last_projected_at": (
            state.last_projected_at.isoformat() if state.last_projected_at else None
        ),
    }
