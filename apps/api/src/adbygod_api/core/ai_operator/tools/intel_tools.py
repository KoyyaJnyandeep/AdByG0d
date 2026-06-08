from __future__ import annotations
import re


async def _verify_intel_access(aid, ctx) -> bool:
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


def _classify_hash(h: str) -> dict:
    h = h.strip()
    tgs_pattern = re.compile(r'^\$krb5tgs\$')
    asrep_pattern = re.compile(r'^\$krb5asrep\$')
    ntlmv2_pattern = re.compile(r'^.+::.+:[a-fA-F0-9]{16}:[a-fA-F0-9]{32}:.+$')
    ntlm_pattern = re.compile(r'^[a-fA-F0-9]{32}:[a-fA-F0-9]{32}$|^[a-fA-F0-9]{32}$')

    if tgs_pattern.match(h):
        return {"hash_type": "Kerberos TGS", "hashcat_mode": 13100, "pth_ready": False,
                "crackable": True, "severity": "HIGH", "note": "Kerberoast hash — crack offline"}
    if asrep_pattern.match(h):
        return {"hash_type": "Kerberos AS-REP", "hashcat_mode": 18200, "pth_ready": False,
                "crackable": True, "severity": "HIGH", "note": "AS-REP Roast hash — crack offline"}
    if ntlmv2_pattern.match(h):
        return {"hash_type": "NTLMv2", "hashcat_mode": 5600, "pth_ready": False,
                "crackable": True, "severity": "MEDIUM", "note": "NTLMv2 — crack or relay"}
    if ntlm_pattern.match(h):
        return {"hash_type": "NTLM", "hashcat_mode": 1000, "pth_ready": True,
                "crackable": True, "severity": "CRITICAL",
                "note": "NTLM — Pass-the-Hash ready. Attempt PTH immediately."}
    return {"hash_type": "Unknown", "hashcat_mode": None, "pth_ready": False,
            "crackable": False, "severity": "LOW", "note": "Could not classify hash"}


async def _get_credential_intel(args: dict, ctx) -> list:
    hashes = args.get("hashes", [])
    domain = args.get("domain", "")
    results = []
    for h in hashes:
        intel = _classify_hash(h)
        intel["hash"] = h[:20] + "..." if len(h) > 20 else h
        if domain:
            parts = domain.lower().split(".")
            intel["wordlist_hints"] = [
                parts[0],
                parts[0].capitalize(),
                parts[0] + "123",
                parts[0].capitalize() + "1",
                parts[0] + "@2024",
            ]
        results.append(intel)
    return results


async def _parse_bloodhound(args: dict, ctx) -> dict:
    """Analyze ExposurePath records for DA paths and choke-points.

    ExposurePath fields used:
        assessment_id, source_entity_id, target_entity_id,
        hop_count, path_score, path_type
    """
    aid = args.get("assessment_id") or (ctx.assessment_id if ctx else None)
    if not aid:
        return {"error": "assessment_id is required", "blocked": True}
    if not await _verify_intel_access(aid, ctx):
        return {"error": "Assessment not found or access denied", "blocked": True}

    from sqlalchemy import select
    from adbygod_api.models import ExposurePath

    try:
        paths_result = await ctx.db.execute(
            select(ExposurePath).where(ExposurePath.assessment_id == aid).limit(50)
        )
        paths = paths_result.scalars().all()
    except Exception as e:
        return {"error": str(e), "paths_to_da": [], "choke_points": []}

    da_paths: list[dict] = []
    node_freq: dict[str, int] = {}

    for p in paths:
        src = str(p.source_entity_id or "")
        tgt = str(p.target_entity_id or "")
        technique = str(p.path_type or "unknown")
        hops = p.hop_count or 0
        score = p.path_score or 0.0
        # target_tier == 0 signals Domain Admin tier in most BloodHound imports
        is_da = p.target_tier == 0 or "admin" in technique.lower()

        if is_da:
            da_paths.append({
                "source": src,
                "target": tgt,
                "technique": technique,
                "hops": hops,
                "risk": score,
            })
        for node in (src, tgt):
            if node:
                node_freq[node] = node_freq.get(node, 0) + 1

    choke_points = sorted(node_freq.items(), key=lambda x: x[1], reverse=True)[:5]
    return {
        "paths_to_da": da_paths[:10],
        "choke_points": [{"node": n, "path_count": c} for n, c in choke_points],
        "total_paths_analyzed": len(paths),
        "recommendation": (
            da_paths[0]["technique"] if da_paths else "No direct DA paths found in graph"
        ),
    }


async def _get_engagement_memory(args: dict, ctx) -> dict:
    aid = args.get("assessment_id") or (ctx.assessment_id if ctx else None)
    if not aid:
        return {"error": "assessment_id is required", "blocked": True}
    if not await _verify_intel_access(aid, ctx):
        return {"error": "Assessment not found or access denied", "blocked": True}
    if not ctx or not ctx.memory_store:
        return {}
    return await ctx.memory_store.load(aid)


async def _simulate_attack_chain(args: dict, ctx) -> dict:
    """Simulate paths from owned principals to a target using ExposurePath data.

    ExposurePath fields used:
        assessment_id, source_entity_id, target_entity_id,
        hop_count, path_score, path_type
    """
    aid = args.get("assessment_id") or (ctx.assessment_id if ctx else None)
    owned = args.get("owned", [])
    target = args.get("target", "Domain Admins")
    if not aid:
        return {"error": "assessment_id is required", "blocked": True}
    if not await _verify_intel_access(aid, ctx):
        return {"error": "Assessment not found or access denied", "blocked": True}

    from sqlalchemy import select
    from adbygod_api.models import ExposurePath

    try:
        paths_result = await ctx.db.execute(
            select(ExposurePath).where(ExposurePath.assessment_id == aid).limit(100)
        )
        paths = paths_result.scalars().all()
    except Exception as e:
        return {"error": str(e), "direct_paths_to_target": [], "indirect_paths": []}

    matching: list[dict] = []
    indirect: list[dict] = []

    for p in paths:
        src = str(p.source_entity_id or "")
        tgt = str(p.target_entity_id or "")
        technique = str(p.path_type or "unknown")
        hops = p.hop_count or 0
        score = float(p.path_score or 0.0)

        src_owned = any(o.lower() in src.lower() for o in owned)
        tgt_match = target.lower() in tgt.lower() or target.lower() in technique.lower()

        if src_owned and tgt_match:
            matching.append({
                "path": f"{src} -> {tgt}",
                "technique": technique,
                "hops": hops,
                "success_probability": "HIGH" if score > 0.7 else "MEDIUM",
                "detection_risk": "MEDIUM",
            })
        elif src_owned:
            indirect.append({"source": src, "target": tgt, "technique": technique})

    if not matching:
        return {
            "direct_paths_to_target": [],
            "indirect_paths": indirect[:5],
            "verdict": (
                f"No direct path from {owned} to {target} found. Check indirect paths."
            ),
        }
    return {
        "direct_paths_to_target": matching,
        "recommended_path": matching[0],
        "verdict": (
            f"Found {len(matching)} path(s) to {target}. "
            f"Recommended: {matching[0]['technique']}"
        ),
    }


async def _get_session_intel(args: dict, ctx) -> dict:
    """Active sessions on machines: who is logged in where, privilege level, golden ticket opportunity."""
    aid = args.get("assessment_id") or (ctx.assessment_id if ctx else None)
    if not aid:
        return {"error": "No active assessment"}
    if not await _verify_intel_access(aid, ctx):
        return {"error": "Assessment not found or access denied"}
    from sqlalchemy import select
    from adbygod_api.models import GraphEdge, Entity, EdgeType
    # HAS_SESSION edges represent active sessions
    stmt = select(GraphEdge).where(
        GraphEdge.assessment_id == aid,
        GraphEdge.edge_type == EdgeType.HAS_SESSION,
    ).limit(50)
    if computer_id := args.get("computer_id"):
        from uuid import UUID
        try:
            stmt = stmt.where(GraphEdge.target_id == UUID(str(computer_id)))
        except ValueError:
            pass
    result = await ctx.db.execute(stmt)
    sessions = result.scalars().all()
    output = []
    for ge in sessions:
        user = await ctx.db.get(Entity, ge.source_id)
        machine = await ctx.db.get(Entity, ge.target_id)
        is_privileged = user.is_admin_count if user else False
        is_tier0 = (user.tier == 0) if user else False
        output.append({
            "user": (user.display_name or user.sam_account_name or str(ge.source_id)) if user else str(ge.source_id),
            "user_id": str(ge.source_id),
            "machine": (machine.dns_hostname or machine.display_name or str(ge.target_id)) if machine else str(ge.target_id),
            "machine_id": str(ge.target_id),
            "is_privileged_user": is_privileged,
            "is_tier0_user": is_tier0,
            "golden_ticket_opportunity": is_tier0,
            "risk": "CRITICAL" if is_tier0 else ("HIGH" if is_privileged else "MEDIUM"),
        })
    output.sort(key=lambda x: x["risk"])
    return {
        "sessions": output,
        "total": len(output),
        "privileged_sessions": sum(1 for s in output if s["is_privileged_user"]),
        "tier0_sessions": sum(1 for s in output if s["is_tier0_user"]),
        "note": "HAS_SESSION edges from BloodHound/collection. Privileged user sessions are immediate escalation opportunities.",
    }


async def _get_trust_map(args: dict, ctx) -> dict:
    """Full domain trust map with attack paths across trust boundaries."""
    aid = args.get("assessment_id") or (ctx.assessment_id if ctx else None)
    if not aid:
        return {"error": "No active assessment"}
    if not await _verify_intel_access(aid, ctx):
        return {"error": "Assessment not found or access denied"}
    from sqlalchemy import select
    from adbygod_api.models import GraphEdge, Entity, EdgeType
    trust_result = await ctx.db.execute(
        select(GraphEdge).where(
            GraphEdge.assessment_id == aid,
            GraphEdge.edge_type == EdgeType.TRUSTS,
        )
    )
    trusts = trust_result.scalars().all()
    trust_map = []
    for ge in trusts:
        src = await ctx.db.get(Entity, ge.source_id)
        tgt = await ctx.db.get(Entity, ge.target_id)
        attrs = ge.attributes or {}
        trust_type = attrs.get("trust_type", "unknown")
        trust_direction = attrs.get("trust_direction", "unknown")
        sid_filtering = attrs.get("sid_filtering", True)
        trust_map.append({
            "source_domain": (src.domain or src.display_name or str(ge.source_id)) if src else str(ge.source_id),
            "target_domain": (tgt.domain or tgt.display_name or str(ge.target_id)) if tgt else str(ge.target_id),
            "trust_type": trust_type,
            "trust_direction": trust_direction,
            "sid_filtering": sid_filtering,
            "exploitable": not sid_filtering,
            "attack_vectors": (
                ["SID History injection", "Extra SID abuse", "Cross-forest Kerberoasting"]
                if not sid_filtering else
                ["Cross-forest Kerberoasting (limited)", "Password spray across trust"]
            ),
        })
    return {
        "trusts": trust_map,
        "exploitable_trusts": sum(1 for t in trust_map if t["exploitable"]),
        "note": "Trusts without SID filtering allow SID history injection for cross-forest DA.",
    }


async def _get_owned_graph(args: dict, ctx) -> dict:
    """Subgraph of everything reachable from currently owned principals."""
    aid = args.get("assessment_id") or (ctx.assessment_id if ctx else None)
    if not aid:
        return {"error": "No active assessment"}
    if not await _verify_intel_access(aid, ctx):
        return {"error": "Assessment not found or access denied"}
    # Load owned assets from engagement memory
    owned_accounts: list[str] = []
    owned_machines: list[str] = []
    if ctx and ctx.memory_store:
        mem = await ctx.memory_store.load(aid)
        owned_accounts = mem.get("owned_accounts", [])
        owned_machines = mem.get("owned_machines", [])
    if not owned_accounts and not owned_machines:
        return {
            "error": "No owned principals in engagement memory. Use save_to_memory with key=owned_accounts first.",
            "owned_graph": [],
        }
    from sqlalchemy import select
    from adbygod_api.models import Entity, GraphEdge
    from uuid import UUID
    # Resolve owned principals to entity IDs
    all_owned_names = owned_accounts + owned_machines
    principals: list[UUID] = []
    for name in all_owned_names:
        try:
            candidate = UUID(str(name))
            r = await ctx.db.execute(
                select(Entity.id).where(Entity.id == candidate, Entity.assessment_id == aid).limit(1)
            )
            if r.scalar_one_or_none() is not None:
                principals.append(candidate)
        except ValueError:
            r = await ctx.db.execute(
                select(Entity).where(
                    Entity.assessment_id == aid,
                    Entity.sam_account_name.ilike(name) | Entity.dns_hostname.ilike(name),
                ).limit(1)
            )
            e = r.scalars().first()
            if e:
                principals.append(e.id)
    max_hops = min(args.get("max_hops", 5), 6)
    # BFS from owned principals (reuse logic pattern)
    visited: dict[UUID, int] = {p: 0 for p in principals}
    frontier = set(principals)
    edges_seen: list[dict] = []
    for hop in range(1, max_hops + 1):
        if not frontier:
            break
        edge_result = await ctx.db.execute(
            select(GraphEdge).where(GraphEdge.assessment_id == aid, GraphEdge.source_id.in_(list(frontier)))
        )
        next_frontier: set[UUID] = set()
        for ge in edge_result.scalars().all():
            tgt = ge.target_id
            edges_seen.append({
                "source": str(ge.source_id),
                "target": str(tgt),
                "edge_type": ge.edge_type.value if hasattr(ge.edge_type, "value") else str(ge.edge_type),
                "hop": hop,
            })
            if tgt not in visited:
                visited[tgt] = hop
                next_frontier.add(tgt)
        frontier = next_frontier
    # Enrich nodes
    node_ids = list(visited.keys())
    entity_result = await ctx.db.execute(
        select(Entity).where(Entity.assessment_id == aid, Entity.id.in_(node_ids[:300]))
    )
    entities = {e.id: e for e in entity_result.scalars().all()}
    nodes = []
    tier0_count = 0
    for eid, hop in visited.items():
        e = entities.get(eid)
        is_tier0 = e and (e.tier == 0 or e.is_crown_jewel)
        if is_tier0:
            tier0_count += 1
        nodes.append({
            "id": str(eid),
            "label": (e.display_name or e.sam_account_name or e.dns_hostname or str(eid)) if e else str(eid),
            "type": (e.entity_type.value if hasattr(e.entity_type, "value") else str(e.entity_type)) if e else "unknown",
            "tier": e.tier if e else None,
            "is_tier0": bool(is_tier0),
            "hops_from_owned": hop,
            "is_owned": hop == 0,
        })
    return {
        "nodes": nodes,
        "edges": edges_seen[:500],
        "owned_count": len(principals),
        "total_reachable": len(nodes),
        "tier0_reachable": tier0_count,
        "summary": f"{len(principals)} owned → {len(nodes)} reachable nodes, {tier0_count} Tier-0 targets",
    }


HANDLERS = {
    "get_credential_intel": _get_credential_intel,
    "parse_bloodhound": _parse_bloodhound,
    "get_engagement_memory": _get_engagement_memory,
    "simulate_attack_chain": _simulate_attack_chain,
    # god-mode additions
    "get_session_intel": _get_session_intel,
    "get_trust_map": _get_trust_map,
    "get_owned_graph": _get_owned_graph,
}
