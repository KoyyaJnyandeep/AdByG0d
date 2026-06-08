from __future__ import annotations
from sqlalchemy import select, func, desc


_STATUS_ALIASES = {
    "open": "OPEN",
    "confirmed": "ACCEPTED",
    "accepted": "ACCEPTED",
    "false_positive": "FALSE_POSITIVE",
    "resolved": "REMEDIATED",
    "remediated": "REMEDIATED",
    "in_review": "IN_REVIEW",
    "regressed": "REGRESSED",
}


def _technique_count(value) -> int:
    if isinstance(value, list):
        return len(value)
    return int(value or 0)


async def _verify_assessment_access(aid, ctx) -> bool:
    """Return True if current user can access this assessment. Return False to block."""
    if not aid or not ctx or not ctx.current_user:
        return False
    try:
        from uuid import UUID
        from adbygod_api.core.security.authorization import require_assessment_access
        await require_assessment_access(UUID(str(aid)), ctx.db, ctx.current_user)
        return True
    except Exception:
        return False


async def _get_assessment_summary(args: dict, ctx) -> dict:
    aid = args.get("assessment_id") or (ctx.assessment_id if ctx else None)
    if not aid:
        return {"error": "No active assessment. Start or select an assessment first."}
    if not await _verify_assessment_access(aid, ctx):
        return {"error": "Assessment not found or access denied"}
    from adbygod_api.models import Assessment, Finding, Entity
    result = await ctx.db.execute(select(Assessment).where(Assessment.id == aid))
    a = result.scalars().first()
    if not a:
        return {"error": f"Assessment {aid} not found"}
    f_count = (await ctx.db.execute(
        select(func.count()).select_from(Finding).where(Finding.assessment_id == a.id)
    )).scalar() or 0
    e_count = (await ctx.db.execute(
        select(func.count()).select_from(Entity).where(Entity.assessment_id == a.id)
    )).scalar() or 0
    return {
        "id": str(a.id),
        "name": a.name,
        "domain": a.domain,
        "dc_ip": a.dc_ip,
        "status": a.status.value if hasattr(a.status, "value") else str(a.status),
        "findings_count": f_count,
        "entities_count": e_count,
        "created_at": str(a.created_at),
    }


async def _list_findings(args: dict, ctx) -> list:
    aid = args.get("assessment_id") or (ctx.assessment_id if ctx else None)
    if not aid:
        return []
    if not await _verify_assessment_access(aid, ctx):
        return []
    from adbygod_api.models import Finding, SeverityLevel, FindingStatus
    stmt = select(Finding).where(Finding.assessment_id == aid)
    if sev := args.get("severity"):
        stmt = stmt.where(Finding.severity == SeverityLevel(sev))
    if st := args.get("status"):
        stmt = stmt.where(Finding.status == FindingStatus(_STATUS_ALIASES.get(str(st).lower(), str(st))))
    stmt = stmt.order_by(desc(Finding.severity)).limit(args.get("limit", 20))
    result = await ctx.db.execute(stmt)
    findings = result.scalars().all()
    return [
        {
            "id": str(f.id),
            "title": f.title,
            "severity": f.severity.value if hasattr(f.severity, "value") else str(f.severity),
            "status": f.status.value if hasattr(f.status, "value") else str(f.status),
            "module": f.module,
            "description": (f.description or "")[:300],
        }
        for f in findings
    ]


async def _get_entities(args: dict, ctx) -> list:
    aid = args.get("assessment_id") or (ctx.assessment_id if ctx else None)
    if not aid:
        return []
    if not await _verify_assessment_access(aid, ctx):
        return []
    from adbygod_api.models import Entity, EntityType
    stmt = select(Entity).where(Entity.assessment_id == aid)
    if et := args.get("entity_type"):
        stmt = stmt.where(Entity.entity_type == EntityType(et.upper()))
    if search := args.get("search"):
        stmt = stmt.where(
            Entity.sam_account_name.ilike(f"%{search}%") |
            Entity.display_name.ilike(f"%{search}%") |
            Entity.dns_hostname.ilike(f"%{search}%")
        )
    stmt = stmt.limit(args.get("limit", 30))
    result = await ctx.db.execute(stmt)
    entities = result.scalars().all()
    return [
        {
            "id": str(e.id),
            "label": e.display_name or e.sam_account_name or e.dns_hostname or str(e.id),
            "type": e.entity_type.value if hasattr(e.entity_type, "value") else str(e.entity_type),
            "tier": e.tier,
            "is_admin_count": e.is_admin_count,
            "is_enabled": e.is_enabled,
        }
        for e in entities
    ]


async def _get_attack_paths(args: dict, ctx) -> list:
    aid = args.get("assessment_id") or (ctx.assessment_id if ctx else None)
    if not aid:
        return []
    if not await _verify_assessment_access(aid, ctx):
        return []
    from adbygod_api.models import ExposurePath
    stmt = select(ExposurePath).where(ExposurePath.assessment_id == aid).limit(args.get("limit", 10))
    result = await ctx.db.execute(stmt)
    paths = result.scalars().all()
    return [
        {
            "id": str(p.id),
            "source_entity_id": str(p.source_entity_id) if p.source_entity_id else None,
            "target_entity_id": str(p.target_entity_id) if p.target_entity_id else None,
            "path_type": p.path_type,
            "hop_count": p.hop_count,
            "path_score": p.path_score,
            "target_tier": p.target_tier,
            "explanation": (p.explanation or "")[:300],
        }
        for p in paths
    ]


async def _get_kill_chain_status(args: dict, ctx) -> dict:
    aid = args.get("assessment_id") or (ctx.assessment_id if ctx else None)
    if not aid:
        return {"error": "No active assessment"}
    if not await _verify_assessment_access(aid, ctx):
        return {"error": "Assessment not found or access denied"}
    from adbygod_api.models import Assessment, KillChainProgress
    result = await ctx.db.execute(select(Assessment).where(Assessment.id == aid))
    a = result.scalars().first()
    if not a:
        return {"error": "Assessment not found"}
    kc_result = await ctx.db.execute(
        select(KillChainProgress).where(KillChainProgress.assessment_id == aid).order_by(KillChainProgress.phase_id)
    )
    phases = kc_result.scalars().all()
    return {
        "assessment_id": str(aid),
        "phases": [
            {
                "phase_id": p.phase_id,
                "label": p.label,
                "status": p.status.value if hasattr(p.status, "value") else str(p.status),
                "findings_count": p.findings_count,
                "techniques_run": p.techniques_run,
            }
            for p in phases
        ],
    }


async def _get_loot(args: dict, ctx) -> list:
    from adbygod_api.models import AttackChain
    if ctx is None or ctx.current_user is None:
        return []
    # If a specific assessment_id is supplied, verify access before reading loot
    aid = args.get("assessment_id") or (ctx.assessment_id if ctx else None)
    if aid and not await _verify_assessment_access(aid, ctx):
        return []
    stmt = select(AttackChain).limit(args.get("limit", 20))
    # Scope to current user unless superadmin
    if not getattr(ctx.current_user, 'is_superadmin', False):
        stmt = stmt.where(AttackChain.owner_user_id == ctx.current_user.id)
    # Further scope to assessment if provided
    if aid:
        stmt = stmt.where(AttackChain.assessment_id == aid)
    result = await ctx.db.execute(stmt)
    chains = result.scalars().all()
    out = []
    for c in chains:
        loot = c.loot or {}
        if loot:
            # loot is a dict — expose top-level keys as items
            loot_items = [{"key": k, "value": v} for k, v in list(loot.items())[:5]]
            out.append({"chain_id": str(c.id), "name": c.name, "loot": loot_items})
    return out


async def _get_graph_summary(args: dict, ctx) -> dict:
    aid = args.get("assessment_id") or (ctx.assessment_id if ctx else None)
    if not aid:
        return {"error": "No active assessment"}
    if not await _verify_assessment_access(aid, ctx):
        return {"error": "Assessment not found or access denied"}
    from adbygod_api.models import Entity, ExposurePath
    e_count = (await ctx.db.execute(
        select(func.count()).select_from(Entity).where(Entity.assessment_id == aid)
    )).scalar() or 0
    p_count = (await ctx.db.execute(
        select(func.count()).select_from(ExposurePath).where(ExposurePath.assessment_id == aid)
    )).scalar() or 0
    tier0 = (await ctx.db.execute(
        select(func.count()).select_from(Entity).where(
            Entity.assessment_id == aid, Entity.tier == 0
        )
    )).scalar() or 0
    return {
        "entity_count": e_count,
        "attack_path_count": p_count,
        "tier0_entities": tier0,
        "summary": f"{e_count} entities, {p_count} attack paths, {tier0} Tier-0 targets",
    }


async def _get_validation_results(args: dict, ctx) -> list:
    aid = args.get("assessment_id") or (ctx.assessment_id if ctx else None)
    if not aid:
        return []
    if not await _verify_assessment_access(aid, ctx):
        return []
    from adbygod_api.models import ValidationRun
    stmt = (
        select(ValidationRun)
        .where(ValidationRun.assessment_id == aid)
        .order_by(desc(ValidationRun.created_at))
        .limit(20)
    )
    result = await ctx.db.execute(stmt)
    runs = result.scalars().all()
    return [
        {
            "id": str(r.id),
            "module_id": r.module_id,
            "status": r.status,
            "risk_score": r.risk_score,
            "final_verdict": r.final_verdict,
            "severity_projection": r.severity_projection,
            "created_at": str(r.created_at),
        }
        for r in runs
    ]


async def _get_lateral_movement(args: dict, ctx) -> dict:
    aid = args.get("assessment_id") or (ctx.assessment_id if ctx else None)
    if not aid:
        return {"error": "No active assessment"}
    if not await _verify_assessment_access(aid, ctx):
        return {"error": "Assessment not found or access denied"}
    try:
        from adbygod_api.core.analyzers.lateral_movement_analyzer import LateralMovementAnalyzer
        from adbygod_api.core.graph.graph_service import GraphService
        gs = GraphService(ctx.db)
        graph_data = await gs.get_graph_data(aid)
        analyzer = LateralMovementAnalyzer(graph_data)
        chains = analyzer.find_lateral_movement_chains()
        return {
            "chains": [
                {"id": getattr(c, "id", str(i)), "techniques": getattr(c, "techniques", []), "path": getattr(c, "path", [])}
                for i, c in enumerate(chains[:10])
            ]
        }
    except Exception as e:
        return {"error": str(e), "chains": []}


async def _search_platform(args: dict, ctx) -> dict:
    query = args.get("query")
    if not query:
        raise ValueError("query is required for search_platform")
    # Cap query length to prevent abuse
    query = query[:200]
    aid = args.get("assessment_id") or (ctx.assessment_id if ctx else None)

    # If caller supplied a specific assessment_id, verify access before scoping
    if aid and not await _verify_assessment_access(aid, ctx):
        return {"findings": [], "entities": [], "query": query, "error": "Assessment not found or access denied"}

    from adbygod_api.models import Finding, Entity
    from adbygod_api.core.security.authorization import scope_assessment_child_query

    # Build findings query
    f_stmt = select(Finding).where(Finding.title.ilike(f"%{query}%"))
    if aid:
        f_stmt = f_stmt.where(Finding.assessment_id == aid)
    elif ctx and ctx.current_user and not ctx.current_user.is_superadmin:
        # Scope to user's workspace assessments
        f_stmt = await scope_assessment_child_query(
            f_stmt, Finding.assessment_id, ctx.db, ctx.current_user
        )
    f_result = await ctx.db.execute(f_stmt.limit(5))
    findings = [
        {"id": str(f.id), "title": f.title, "severity": str(f.severity)}
        for f in f_result.scalars().all()
    ]

    # Build entities query
    e_stmt = select(Entity).where(
        Entity.sam_account_name.ilike(f"%{query}%") |
        Entity.display_name.ilike(f"%{query}%") |
        Entity.dns_hostname.ilike(f"%{query}%")
    )
    if aid:
        e_stmt = e_stmt.where(Entity.assessment_id == aid)
    elif ctx and ctx.current_user and not ctx.current_user.is_superadmin:
        # Scope to user's workspace assessments
        e_stmt = await scope_assessment_child_query(
            e_stmt, Entity.assessment_id, ctx.db, ctx.current_user
        )
    e_result = await ctx.db.execute(e_stmt.limit(5))
    entities = [
        {
            "id": str(e.id),
            "label": e.display_name or e.sam_account_name or e.dns_hostname or str(e.id),
            "type": str(e.entity_type),
        }
        for e in e_result.scalars().all()
    ]
    return {"findings": findings, "entities": entities, "query": query}


async def _get_entity_details(args: dict, ctx) -> dict:
    entity_id = args.get("entity_id")
    if not entity_id:
        return {"error": "entity_id is required"}
    aid = args.get("assessment_id") or (ctx.assessment_id if ctx else None)
    if aid and not await _verify_assessment_access(aid, ctx):
        return {"error": "Assessment not found or access denied"}
    from adbygod_api.models import Entity, GraphEdge, Finding
    from uuid import UUID
    try:
        eid = UUID(str(entity_id))
    except ValueError:
        return {"error": f"Invalid entity_id: {entity_id}"}
    if not aid:
        return {"error": "No active assessment"}
    result = await ctx.db.execute(select(Entity).where(Entity.id == eid, Entity.assessment_id == aid))
    e = result.scalars().first()
    if not e:
        return {"error": f"Entity {entity_id} not found"}
    # Outbound edges (what this entity can do)
    out_result = await ctx.db.execute(
        select(GraphEdge).where(GraphEdge.assessment_id == aid, GraphEdge.source_id == eid).limit(50)
    )
    outbound = [
        {"edge_type": ge.edge_type.value if hasattr(ge.edge_type, "value") else str(ge.edge_type),
         "target_id": str(ge.target_id), "risk_weight": ge.risk_weight,
         "confidence": ge.edge_confidence}
        for ge in out_result.scalars().all()
    ]
    # Inbound edges (who has rights over this entity)
    in_result = await ctx.db.execute(
        select(GraphEdge).where(GraphEdge.assessment_id == aid, GraphEdge.target_id == eid).limit(50)
    )
    inbound = [
        {"edge_type": ge.edge_type.value if hasattr(ge.edge_type, "value") else str(ge.edge_type),
         "source_id": str(ge.source_id), "risk_weight": ge.risk_weight,
         "confidence": ge.edge_confidence}
        for ge in in_result.scalars().all()
    ]
    # Findings referencing this entity
    findings_result = await ctx.db.execute(
        select(Finding).where(
            Finding.assessment_id == aid,
            Finding.affected_objects.contains([str(eid)])
        ).limit(10)
    )
    related_findings = [
        {"id": str(f.id), "title": f.title,
         "severity": f.severity.value if hasattr(f.severity, "value") else str(f.severity)}
        for f in findings_result.scalars().all()
    ]
    return {
        "id": str(e.id),
        "label": e.display_name or e.sam_account_name or e.dns_hostname or str(e.id),
        "type": e.entity_type.value if hasattr(e.entity_type, "value") else str(e.entity_type),
        "sam_account_name": e.sam_account_name,
        "display_name": e.display_name,
        "dns_hostname": e.dns_hostname,
        "distinguished_name": e.distinguished_name,
        "object_sid": e.object_sid,
        "domain": e.domain,
        "tier": e.tier,
        "is_enabled": e.is_enabled,
        "is_admin_count": e.is_admin_count,
        "is_sensitive": e.is_sensitive,
        "is_protected_user": e.is_protected_user,
        "is_crown_jewel": e.is_crown_jewel,
        "business_tags": e.business_tags,
        "attributes": e.attributes,
        "last_logon": str(e.last_logon) if e.last_logon else None,
        "password_last_set": str(e.password_last_set) if e.password_last_set else None,
        "object_created": str(e.object_created) if e.object_created else None,
        "acl_outbound": outbound,
        "acl_inbound": inbound,
        "related_findings": related_findings,
    }


async def _get_acl_edges(args: dict, ctx) -> list:
    entity_id = args.get("entity_id")
    if not entity_id:
        return [{"error": "entity_id is required"}]
    aid = args.get("assessment_id") or (ctx.assessment_id if ctx else None)
    if aid and not await _verify_assessment_access(aid, ctx):
        return [{"error": "Assessment not found or access denied"}]
    direction = args.get("direction", "outbound")
    edge_type_filter = args.get("edge_types", [])
    from adbygod_api.models import GraphEdge, Entity, EdgeType
    from uuid import UUID
    try:
        eid = UUID(str(entity_id))
    except ValueError:
        return [{"error": f"Invalid entity_id: {entity_id}"}]
    if not aid:
        return [{"error": "No active assessment"}]
    entity_check = await ctx.db.execute(
        select(Entity.id).where(Entity.id == eid, Entity.assessment_id == aid)
    )
    if entity_check.scalar_one_or_none() is None:
        return [{"error": f"Entity {entity_id} not found"}]
    edge_types = []
    for item in edge_type_filter:
        try:
            edge_types.append(EdgeType(str(item)))
        except ValueError:
            continue
    out_rows: list = []
    in_rows: list = []
    if direction in ("outbound", "both"):
        stmt = select(GraphEdge).where(GraphEdge.assessment_id == aid, GraphEdge.source_id == eid)
        if edge_type_filter:
            stmt = stmt.where(GraphEdge.edge_type.in_(edge_types))
        out_rows = (await ctx.db.execute(stmt.limit(100))).scalars().all()
    if direction in ("inbound", "both"):
        stmt = select(GraphEdge).where(GraphEdge.assessment_id == aid, GraphEdge.target_id == eid)
        if edge_type_filter:
            stmt = stmt.where(GraphEdge.edge_type.in_(edge_types))
        in_rows = (await ctx.db.execute(stmt.limit(100))).scalars().all()

    # Batch-load all referenced entities in one query
    neighbour_ids = {ge.target_id for ge in out_rows} | {ge.source_id for ge in in_rows}
    neighbour_map: dict = {}
    if neighbour_ids:
        nb_result = await ctx.db.execute(select(Entity).where(Entity.id.in_(list(neighbour_ids))))
        neighbour_map = {e.id: e for e in nb_result.scalars().all()}

    def _label(e) -> str:
        return (e.display_name or e.sam_account_name or e.dns_hostname) if e else ""

    edges = []
    for ge in out_rows:
        tgt = neighbour_map.get(ge.target_id)
        edges.append({
            "direction": "outbound",
            "edge_type": ge.edge_type.value if hasattr(ge.edge_type, "value") else str(ge.edge_type),
            "target_id": str(ge.target_id),
            "target_label": _label(tgt) or str(ge.target_id),
            "risk_weight": ge.risk_weight,
            "confidence": ge.edge_confidence,
        })
    for ge in in_rows:
        src = neighbour_map.get(ge.source_id)
        edges.append({
            "direction": "inbound",
            "edge_type": ge.edge_type.value if hasattr(ge.edge_type, "value") else str(ge.edge_type),
            "source_id": str(ge.source_id),
            "source_label": _label(src) or str(ge.source_id),
            "risk_weight": ge.risk_weight,
            "confidence": ge.edge_confidence,
        })
    return edges


async def _get_domain_info(args: dict, ctx) -> dict:
    aid = args.get("assessment_id") or (ctx.assessment_id if ctx else None)
    if not aid:
        return {"error": "No active assessment"}
    if not await _verify_assessment_access(aid, ctx):
        return {"error": "Assessment not found or access denied"}
    from adbygod_api.models import Assessment, Entity, EntityType, GraphEdge, EdgeType
    result = await ctx.db.execute(select(Assessment).where(Assessment.id == aid))
    a = result.scalars().first()
    if not a:
        return {"error": "Assessment not found"}
    # Domain Controller entities
    dc_result = await ctx.db.execute(
        select(Entity).where(
            Entity.assessment_id == aid,
            Entity.entity_type.in_([EntityType.COMPUTER, EntityType.DC]),
        ).limit(20)
    )
    dcs = [
        {"id": str(e.id), "label": e.dns_hostname or e.display_name or str(e.id),
         "attributes": e.attributes}
        for e in dc_result.scalars().all()
        if e.entity_type == EntityType.DC or (e.attributes or {}).get("is_dc")
    ]
    # Privileged groups: Domain Admins, Enterprise Admins, etc.
    priv_groups = []
    for gname in ("Domain Admins", "Enterprise Admins", "Schema Admins", "Backup Operators", "Account Operators"):
        g_result = await ctx.db.execute(
            select(Entity).where(
                Entity.assessment_id == aid,
                Entity.entity_type == EntityType.GROUP,
                Entity.display_name.ilike(f"%{gname}%"),
            ).limit(1)
        )
        g = g_result.scalars().first()
        if g:
            # Count members
            mem_count = (await ctx.db.execute(
                select(func.count()).select_from(GraphEdge).where(
                    GraphEdge.target_id == g.id,
                    GraphEdge.edge_type == EdgeType.MEMBER_OF,
                )
            )).scalar() or 0
            priv_groups.append({"group": gname, "entity_id": str(g.id), "member_count": mem_count})
    # Trust relationships
    trust_result = await ctx.db.execute(
        select(GraphEdge).where(
            GraphEdge.assessment_id == aid,
            GraphEdge.edge_type == EdgeType.TRUSTS,
        ).limit(20)
    )
    trusts = [
        {"source": str(ge.source_id), "target": str(ge.target_id),
         "attributes": ge.attributes}
        for ge in trust_result.scalars().all()
    ]
    domain_ent_result = await ctx.db.execute(
        select(Entity).where(
            Entity.assessment_id == aid,
            Entity.entity_type == EntityType.DOMAIN,
        ).limit(1)
    )
    domain_ent = domain_ent_result.scalars().first()
    _attrs = (domain_ent.attributes or {}) if domain_ent else {}
    _maq = _attrs.get("ms-DS-MachineAccountQuota") or _attrs.get("machine_account_quota", "Unknown")
    return {
        "assessment_id": str(aid),
        "domain": a.domain,
        "dc_ip": a.dc_ip,
        "domain_controllers": dcs,
        "privileged_groups": priv_groups,
        "trust_relationships": trusts,
        "functional_level": "Unknown",
        "machine_account_quota": _maq,
    }


async def _get_technique_catalog(args: dict, ctx) -> list:
    from adbygod_api.data.ad_commands import AD_COMMANDS
    category = (args.get("category") or "").lower()
    keyword = (args.get("keyword") or "").lower()
    platform = args.get("platform", "")
    executable_only = args.get("executable_only", False)
    limit = args.get("limit", 20)
    results = []
    for t in AD_COMMANDS:
        if category and category not in t.get("category", "").lower():
            continue
        if keyword and keyword not in t.get("title", "").lower() and keyword not in t.get("description", "").lower():
            continue
        if platform and t.get("platform", "") != platform:
            continue
        if executable_only and not t.get("executable_on_linux", False):
            continue
        results.append({
            "id": t["id"],
            "title": t["title"],
            "category": t["category"],
            "tool": t["tool"],
            "platform": t["platform"],
            "executable_on_linux": t.get("executable_on_linux", False),
            "risk_level": t.get("risk_level", "unknown"),
            "mitre_technique_id": t.get("mitre_technique_id", ""),
            "description": t.get("description", "")[:200],
            "command_count": len(t.get("commands", [])),
        })
        if len(results) >= limit:
            break
    return results


async def _get_reachable_from(args: dict, ctx) -> dict:
    principals = args.get("principals", [])
    if not principals:
        return {"error": "principals is required", "reachable": []}
    aid = args.get("assessment_id") or (ctx.assessment_id if ctx else None)
    if not aid:
        return {"error": "No active assessment", "reachable": []}
    if not await _verify_assessment_access(aid, ctx):
        return {"error": "Assessment not found or access denied", "reachable": []}
    max_hops = min(args.get("max_hops", 4), 6)
    tier0_only = args.get("tier0_only", False)
    from adbygod_api.models import GraphEdge, Entity
    from uuid import UUID
    # Resolve principal IDs (accept UUID strings or SAM account names)
    start_ids: set[UUID] = set()
    for p in principals:
        try:
            candidate = UUID(str(p))
            r = await ctx.db.execute(
                select(Entity.id).where(Entity.id == candidate, Entity.assessment_id == aid).limit(1)
            )
            if r.scalar_one_or_none() is not None:
                start_ids.add(candidate)
        except ValueError:
            r = await ctx.db.execute(
                select(Entity).where(
                    Entity.assessment_id == aid,
                    Entity.sam_account_name.ilike(p),
                ).limit(1)
            )
            e = r.scalars().first()
            if e:
                start_ids.add(e.id)
    if not start_ids:
        return {"error": "None of the provided principals were found", "reachable": []}
    # BFS
    visited: dict[UUID, dict] = {eid: {"hops": 0, "path": []} for eid in start_ids}
    frontier = set(start_ids)
    for hop in range(1, max_hops + 1):
        if not frontier:
            break
        edge_result = await ctx.db.execute(
            select(GraphEdge).where(GraphEdge.assessment_id == aid, GraphEdge.source_id.in_(list(frontier)))
        )
        next_frontier: set[UUID] = set()
        for ge in edge_result.scalars().all():
            tgt = ge.target_id
            if tgt not in visited:
                visited[tgt] = {
                    "hops": hop,
                    "path": visited[ge.source_id]["path"] + [
                        {"from": str(ge.source_id),
                         "edge": ge.edge_type.value if hasattr(ge.edge_type, "value") else str(ge.edge_type),
                         "to": str(tgt)}
                    ],
                }
                next_frontier.add(tgt)
        frontier = next_frontier
    # Enrich reachable nodes
    reachable_ids = [eid for eid in visited if eid not in start_ids]
    if not reachable_ids:
        return {"reachable": [], "tier0_count": 0, "total_reachable": 0}
    ENRICH_CAP = 500
    entity_result = await ctx.db.execute(
        select(Entity).where(Entity.assessment_id == aid, Entity.id.in_(reachable_ids[:ENRICH_CAP]))
    )
    entities = {e.id: e for e in entity_result.scalars().all()}
    reachable = []
    tier0_count = 0
    for eid, info in visited.items():
        if eid in start_ids:
            continue
        e = entities.get(eid)
        if not e:
            continue
        is_tier0 = (e.tier == 0 or e.is_crown_jewel)
        if tier0_only and not is_tier0:
            continue
        if is_tier0:
            tier0_count += 1
        reachable.append({
            "id": str(eid),
            "label": e.display_name or e.sam_account_name or e.dns_hostname or str(eid),
            "type": e.entity_type.value if hasattr(e.entity_type, "value") else str(e.entity_type),
            "tier": e.tier,
            "is_tier0": is_tier0,
            "hops": info["hops"],
            "path": info["path"],
        })
    reachable.sort(key=lambda x: (x["hops"], -(1 if x["is_tier0"] else 0)))
    total = len(reachable)
    return {
        "reachable": reachable[:100],
        "tier0_count": tier0_count,
        "total_reachable": total,
        "truncated": total > 100,
        "starting_principals": [str(s) for s in start_ids],
    }


async def _get_opsec_status(args: dict, ctx) -> dict:
    aid = args.get("assessment_id") or (ctx.assessment_id if ctx else None)
    if not aid:
        return {"error": "No active assessment"}
    if not await _verify_assessment_access(aid, ctx):
        return {"error": "Assessment not found or access denied"}
    from adbygod_api.models import KillChainProgress
    kc_result = await ctx.db.execute(
        select(KillChainProgress).where(KillChainProgress.assessment_id == aid)
    )
    phases = kc_result.scalars().all()
    total_techniques = sum(_technique_count(p.techniques_run) for p in phases)
    # Aggregate noise from kill chain phases
    noise_score = 0
    for p in phases:
        count = _technique_count(p.techniques_run)
        if count:
            noise_score += count * (2 if p.phase_id in (3, 5, 6) else 1)
    if noise_score == 0:
        noise_level = "LOW"
    elif noise_score < 10:
        noise_level = "MEDIUM"
    elif noise_score < 25:
        noise_level = "HIGH"
    else:
        noise_level = "CRITICAL"
    recommendations = []
    if noise_level in ("HIGH", "CRITICAL"):
        recommendations.append("Switch to targeted single-account Kerberoasting instead of spray")
        recommendations.append("Use DCOnly BloodHound collection to avoid session enumeration noise")
        recommendations.append("Prefer LDAP queries over SMB scanning")
    elif noise_level == "MEDIUM":
        recommendations.append("Consider spacing technique execution to avoid burst detection")
    else:
        recommendations.append("Footprint is clean — safe to proceed with enumeration")
    return {
        "assessment_id": str(aid),
        "noise_level": noise_level,
        "noise_score": noise_score,
        "techniques_run": total_techniques,
        "phases_active": [p.phase_id for p in phases if _technique_count(p.techniques_run) > 0],
        "recommendations": recommendations,
    }


async def _get_mitre_coverage(args: dict, ctx) -> dict:
    aid = args.get("assessment_id") or (ctx.assessment_id if ctx else None)
    if not aid:
        return {"error": "No active assessment"}
    if not await _verify_assessment_access(aid, ctx):
        return {"error": "Assessment not found or access denied"}
    from adbygod_api.models import Finding
    findings_result = await ctx.db.execute(
        select(Finding).where(Finding.assessment_id == aid)
    )
    findings = findings_result.scalars().all()
    tactic_map: dict[str, list[str]] = {}
    for f in findings:
        for mid in (f.mitre_attack_ids or []):
            tactic = _mitre_id_to_tactic(str(mid))
            tactic_map.setdefault(tactic, []).append(f.title)
    all_tactics = [
        "TA0043 Reconnaissance", "TA0042 Resource Development",
        "TA0001 Initial Access", "TA0002 Execution", "TA0003 Persistence",
        "TA0004 Privilege Escalation", "TA0005 Defense Evasion",
        "TA0006 Credential Access", "TA0007 Discovery",
        "TA0008 Lateral Movement", "TA0009 Collection",
        "TA0011 Command and Control", "TA0010 Exfiltration", "TA0040 Impact",
    ]
    covered = [t for t in all_tactics if t in tactic_map]
    gaps = [t for t in all_tactics if t not in covered]
    return {
        "tactics_covered": covered,
        "tactics_gap": gaps,
        "coverage_percent": round(len(covered) / len(all_tactics) * 100, 1),
        "findings_by_tactic": {k: v[:5] for k, v in tactic_map.items()},
    }


def _mitre_id_to_tactic(mid: str) -> str:
    """Best-effort mapping of a MITRE technique ID prefix to tactic name."""
    prefix_map = {
        "T1595": "TA0043 Reconnaissance", "T1590": "TA0043 Reconnaissance",
        "T1566": "TA0001 Initial Access", "T1078": "TA0001 Initial Access",
        "T1059": "TA0002 Execution", "T1053": "TA0002 Execution",
        "T1547": "TA0003 Persistence", "T1098": "TA0003 Persistence",
        "T1548": "TA0004 Privilege Escalation", "T1134": "TA0004 Privilege Escalation",
        "T1484": "TA0004 Privilege Escalation",
        "T1562": "TA0005 Defense Evasion", "T1218": "TA0005 Defense Evasion",
        "T1003": "TA0006 Credential Access", "T1558": "TA0006 Credential Access",
        "T1552": "TA0006 Credential Access", "T1110": "TA0006 Credential Access",
        "T1087": "TA0007 Discovery", "T1069": "TA0007 Discovery",
        "T1018": "TA0007 Discovery", "T1482": "TA0007 Discovery",
        "T1021": "TA0008 Lateral Movement", "T1550": "TA0008 Lateral Movement",
        "T1557": "TA0008 Lateral Movement",
    }
    for prefix, tactic in prefix_map.items():
        if mid.startswith(prefix):
            return tactic
    return "Unknown"


async def _diff_assessments(args: dict, ctx) -> dict:
    aid_a = args.get("assessment_id_a")
    aid_b = args.get("assessment_id_b")
    if not aid_a or not aid_b:
        return {"error": "Both assessment_id_a and assessment_id_b are required"}
    for aid in (aid_a, aid_b):
        if not await _verify_assessment_access(aid, ctx):
            return {"error": f"Assessment {aid} not found or access denied"}
    from adbygod_api.models import Finding, ExposurePath
    # Findings in A
    fa_result = await ctx.db.execute(select(Finding).where(Finding.assessment_id == aid_a))
    fa = {f.title: f for f in fa_result.scalars().all()}
    # Findings in B
    fb_result = await ctx.db.execute(select(Finding).where(Finding.assessment_id == aid_b))
    fb = {f.title: f for f in fb_result.scalars().all()}
    new_findings = [
        {"title": t, "severity": fb[t].severity.value if hasattr(fb[t].severity, "value") else str(fb[t].severity)}
        for t in fb if t not in fa
    ]
    resolved_findings = [
        {"title": t, "severity": fa[t].severity.value if hasattr(fa[t].severity, "value") else str(fa[t].severity)}
        for t in fa if t not in fb
    ]
    severity_changes = []
    for t in fa:
        if t in fb and fa[t].severity != fb[t].severity:
            severity_changes.append({
                "title": t,
                "before": fa[t].severity.value if hasattr(fa[t].severity, "value") else str(fa[t].severity),
                "after": fb[t].severity.value if hasattr(fb[t].severity, "value") else str(fb[t].severity),
            })
    pa_count = (await ctx.db.execute(
        select(func.count()).select_from(ExposurePath).where(ExposurePath.assessment_id == aid_a)
    )).scalar() or 0
    pb_count = (await ctx.db.execute(
        select(func.count()).select_from(ExposurePath).where(ExposurePath.assessment_id == aid_b)
    )).scalar() or 0
    return {
        "assessment_a": str(aid_a),
        "assessment_b": str(aid_b),
        "new_findings": new_findings,
        "resolved_findings": resolved_findings,
        "severity_changes": severity_changes,
        "attack_paths_before": pa_count,
        "attack_paths_after": pb_count,
        "attack_paths_delta": pb_count - pa_count,
        "summary": (
            f"+{len(new_findings)} new findings, "
            f"-{len(resolved_findings)} resolved, "
            f"{len(severity_changes)} severity changes, "
            f"{pb_count - pa_count:+d} attack paths"
        ),
    }


HANDLERS = {
    "get_assessment_summary": _get_assessment_summary,
    "list_findings": _list_findings,
    "get_entities": _get_entities,
    "get_attack_paths": _get_attack_paths,
    "get_kill_chain_status": _get_kill_chain_status,
    "get_loot": _get_loot,
    "get_graph_summary": _get_graph_summary,
    "get_validation_results": _get_validation_results,
    "get_lateral_movement": _get_lateral_movement,
    "search_platform": _search_platform,
    # god-mode additions
    "get_entity_details": _get_entity_details,
    "get_acl_edges": _get_acl_edges,
    "get_domain_info": _get_domain_info,
    "get_technique_catalog": _get_technique_catalog,
    "get_reachable_from": _get_reachable_from,
    "get_opsec_status": _get_opsec_status,
    "get_mitre_coverage": _get_mitre_coverage,
    "diff_assessments": _diff_assessments,
}
