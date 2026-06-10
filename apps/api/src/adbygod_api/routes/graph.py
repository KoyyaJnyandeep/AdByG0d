from __future__ import annotations

import asyncio
import hashlib
import logging
from typing import Any, List, Optional
from uuid import UUID
from uuid import UUID as _UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
import dataclasses
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from neo4j.exceptions import Neo4jError, ServiceUnavailable

from adbygod_api.config import settings
from adbygod_api.database import get_db
from adbygod_api.models import ExposurePath, GraphProjectionState, PlatformUser
from adbygod_api.schemas import GraphData
from adbygod_api.core.graph.attack_flow_chains import attack_flow_categories, list_attack_flow_chains
from adbygod_api.core.graph.neo4j_graph_service import Neo4jGraphService
from adbygod_api.core.security.authorization import require_assessment_access, require_assessment_write_access
from adbygod_api.routes.auth import get_current_user

# Routes for analytics not yet ported to the Neo4j engine (spec Phases 3-5:
# centrality, community detection, detectors, blast radius, simulation). They
# return 501 until those phases land, so the app imports and the merge-gate
# routes work. Listed in the PR description.
_PHASE3_DETAIL = (
    "This graph analytic is not yet available on the Neo4j engine "
    "(scheduled for a follow-on phase of the Neo4j migration)."
)


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

def _get_service(assessment_id: str) -> Neo4jGraphService:
    """Per-request handle to the Neo4j-backed graph engine for one assessment.

    No caching: Neo4j keeps the projected graph; each call is index-free
    adjacency over the live read-model (replaces the old in-memory analyzer
    cache, which was the source of stale-graph bugs)."""
    return Neo4jGraphService(str(assessment_id))


async def _run_query(coro: Any) -> Any:
    """Await a graph-engine coroutine, mapping engine failures to HTTP errors.

    - query exceeding GRAPH_QUERY_TIMEOUT_SECONDS  -> 503 (too large / slow)
    - Neo4j unavailable / driver not initialised    -> 503 (engine unavailable)
    """
    try:
        return await asyncio.wait_for(coro, timeout=settings.GRAPH_QUERY_TIMEOUT_SECONDS)
    except asyncio.TimeoutError as exc:
        raise HTTPException(
            status_code=503,
            detail="Graph query timed out — graph may be too large; narrow the query (source/target) or reduce scope.",
        ) from exc
    except (ServiceUnavailable, Neo4jError) as exc:
        raise HTTPException(status_code=503, detail="graph engine unavailable") from exc
    except RuntimeError as exc:
        # neo4j_client.get_driver() raises this when the driver isn't connected.
        if "driver not initialised" in str(exc).lower() or "not initialized" in str(exc).lower():
            raise HTTPException(status_code=503, detail="graph engine unavailable") from exc
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
    service = _get_service(str(assessment_id))
    data = await _run_query(
        service.export_for_frontend(max_nodes=max_nodes, filter_types=filter_types)
    )
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
    """Compute and return exposure paths from the Neo4j engine."""
    await require_assessment_access(assessment_id, db, current_user)
    service = _get_service(str(assessment_id))

    paths = None
    if source_id and target_id:
        if directed:
            ap = await _run_query(service.find_shortest_path(source_id, target_id))
            paths = [ap] if ap else []
        elif algorithm == "yen":
            paths = await _run_query(service.find_k_shortest_paths(source_id, target_id, k=k))
        else:
            paths = await _run_query(
                service.find_all_shortest_paths(source_id, target_id, limit=max_paths)
            )
    elif source_id:
        # Source-only "paths to Tier-0" needs Tier-0 enumeration + multi-target
        # search, not yet ported to the Neo4j engine.
        raise HTTPException(status_code=501, detail=_PHASE3_DETAIL)

    if paths is None:
        # No source given: serve previously computed/persisted exposure paths.
        q = select(ExposurePath).where(ExposurePath.assessment_id == assessment_id)
        if tier is not None:
            q = q.where(ExposurePath.target_tier == tier)
        q = q.order_by(ExposurePath.path_score.desc()).limit(max_paths)
        ep_result = await db.execute(q)
        rows = []
        for ep in ep_result.scalars().all():
            steps = ep.path_steps or []
            first = steps[0] if steps and isinstance(steps[0], dict) else {}
            last = steps[-1] if steps and isinstance(steps[-1], dict) else {}
            source_label = first.get("entity_label") or (str(ep.source_entity_id) if ep.source_entity_id else None)
            target_label = last.get("entity_label") or (str(ep.target_entity_id) if ep.target_entity_id else None)
            edge_types = [
                step.get("edge_type")
                for step in steps
                if isinstance(step, dict) and step.get("edge_type")
            ]
            rows.append({
                "id": str(ep.id),
                "source_id": str(ep.source_entity_id) if ep.source_entity_id else first.get("entity_id"),
                "target_id": str(ep.target_entity_id) if ep.target_entity_id else last.get("entity_id"),
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
            "source": ap.source_id,
            "target": ap.target_id,
            "source_label": ap.source_label,
            "target_label": ap.target_label,
            "path": ap.node_ids,
            "path_steps": [_normalize_path_step(step) for step in ap.steps],
            "edge_types": ap.edge_types,
            "hop_count": ap.hop_count,
            "path_score": ap.path_score,
            "risk_level": ap.risk_level or _risk_level(float(ap.path_score or 0.0)),
            "explanation": ap.explanation,
        }
        for ap in paths
    ]


@router.get("/{assessment_id}/blast-radius")
async def get_tier0_blast_radius(
    assessment_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: PlatformUser = Depends(get_current_user),
):
    """Return all entities that can reach Tier-0, with path counts."""
    await require_assessment_access(assessment_id, db, current_user)
    # TODO(neo4j-phase-3): port blast radius (GDS reachability) to Neo4j.
    raise HTTPException(status_code=501, detail=_PHASE3_DETAIL)


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
    # TODO(neo4j-phase-5): port edge-removal simulation to Neo4j.
    raise HTTPException(status_code=501, detail=_PHASE3_DETAIL)


@router.post("/{assessment_id}/compute-paths")
async def compute_and_persist_paths(
    assessment_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: PlatformUser = Depends(get_current_user),
):
    """Compute all attack paths and persist to exposure_paths table."""
    await require_assessment_write_access(assessment_id, db, current_user)
    # TODO(neo4j-phase-3/4): port path/detector computation + persistence to Neo4j.
    raise HTTPException(status_code=501, detail=_PHASE3_DETAIL)


@router.get("/{assessment_id}/categories")
async def get_attack_categories(
    assessment_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: PlatformUser = Depends(get_current_user),
):
    """Return attack paths grouped by technique category."""
    await require_assessment_access(assessment_id, db, current_user)
    # TODO(neo4j-phase-4): port attack-path detectors/categories to Neo4j.
    raise HTTPException(status_code=501, detail=_PHASE3_DETAIL)


@router.get("/{assessment_id}/choke-points")
async def get_choke_points(
    assessment_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: PlatformUser = Depends(get_current_user),
):
    """Return top choke points with removal impact simulation."""
    await require_assessment_access(assessment_id, db, current_user)
    # TODO(neo4j-phase-3): port choke-point (betweenness) analysis to Neo4j/GDS.
    raise HTTPException(status_code=501, detail=_PHASE3_DETAIL)


@router.get("/{assessment_id}/communities")
async def get_communities(
    assessment_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: PlatformUser = Depends(get_current_user),
):
    """Return Louvain community partition for the assessment graph."""
    await require_assessment_access(assessment_id, db, current_user)
    # TODO(neo4j-phase-3): port community detection (Louvain) to Neo4j/GDS.
    raise HTTPException(status_code=501, detail=_PHASE3_DETAIL)


@router.get("/{assessment_id}/centrality")
async def get_centrality(
    assessment_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: PlatformUser = Depends(get_current_user),
):
    """Return centrality metrics, computing and persisting on first call (1hr cache)."""
    await require_assessment_access(assessment_id, db, current_user)
    # TODO(neo4j-phase-3): port centrality metrics to Neo4j/GDS.
    raise HTTPException(status_code=501, detail=_PHASE3_DETAIL)


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
    service = _get_service(str(assessment_id))
    return await _run_query(service.get_neighborhood(node_id, hops, max_nodes))


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
    service = _get_service(str(assessment_id))
    data = await _run_query(service.export_for_frontend(max_nodes=5000))
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
    # TODO(neo4j-phase-4): port NL graph-query patterns to Cypher.
    raise HTTPException(status_code=501, detail=_PHASE3_DETAIL)


@router.get("/{assessment_id}/anomalies")
async def get_anomalies(
    assessment_id: UUID,
    days_back: int = Query(7, ge=1, le=365),
    db: AsyncSession = Depends(get_db),
    current_user: PlatformUser = Depends(get_current_user),
):
    """Detect statistical anomalies and recent edge changes."""
    await require_assessment_access(assessment_id, db, current_user)
    # TODO(neo4j-phase-4): port anomaly detection to Neo4j.
    raise HTTPException(status_code=501, detail=_PHASE3_DETAIL)


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
    # TODO(neo4j-phase-4): port cross-assessment graph diff to Neo4j.
    raise HTTPException(status_code=501, detail=_PHASE3_DETAIL)


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
