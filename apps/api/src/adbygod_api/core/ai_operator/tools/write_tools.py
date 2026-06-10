from __future__ import annotations
from sqlalchemy import select


async def _verify_write_access(aid, ctx) -> bool:
    """Return True if current user can write to this assessment."""
    if not aid or not ctx or not ctx.current_user:
        return False
    try:
        from uuid import UUID
        from adbygod_api.core.security.authorization import require_assessment_write_access
        await require_assessment_write_access(UUID(str(aid)), ctx.db, ctx.current_user)
        return True
    except Exception:
        return False


async def _commit_db(ctx) -> None:
    if ctx and getattr(ctx, "db", None):
        await ctx.db.commit()


async def _save_to_memory(args: dict, ctx) -> dict:
    aid = args.get("assessment_id") or (ctx.assessment_id if ctx else None)
    if not aid:
        return {"error": "assessment_id is required", "blocked": True}
    if not await _verify_write_access(aid, ctx):
        return {"error": "Assessment not found or access denied", "blocked": True}
    key = args["key"]
    value = args["value"]
    if ctx and ctx.memory_store:
        await ctx.memory_store.append(aid, key, value)
    try:
        if ctx and hasattr(ctx, "audit_log") and ctx.audit_log:
            await ctx.audit_log.record(
                action="ai_write.save_to_memory",
                user_id=str(ctx.current_user.id) if ctx.current_user else None,
                assessment_id=str(aid),
                details={"key": key},
            )
    except Exception:
        pass
    return {"saved": True, "key": key}


async def _write_report_section(args: dict, ctx) -> dict:
    aid = args.get("assessment_id") or (ctx.assessment_id if ctx else None)
    if not aid:
        return {"error": "assessment_id is required", "blocked": True}
    if not await _verify_write_access(aid, ctx):
        return {"error": "Assessment not found or access denied", "blocked": True}
    section = args["section"]
    content = args["content"]
    if ctx and ctx.memory_store:
        await ctx.memory_store.set_report_section(aid, section, content)
    try:
        if ctx and hasattr(ctx, "audit_log") and ctx.audit_log:
            await ctx.audit_log.record(
                action="ai_write.write_report_section",
                user_id=str(ctx.current_user.id) if ctx.current_user else None,
                assessment_id=str(aid),
                details={"key": section},
            )
    except Exception:
        pass
    return {"section": section, "length": len(content), "preview": content[:200]}


async def _update_target_card(args: dict, ctx) -> dict:
    aid = args.get("assessment_id") or (ctx.assessment_id if ctx else None)
    if not aid:
        return {"error": "assessment_id is required", "blocked": True}
    if not await _verify_write_access(aid, ctx):
        return {"error": "Assessment not found or access denied", "blocked": True}
    if ctx and ctx.memory_store:
        await ctx.memory_store.append(aid, "target_card", args)
    try:
        if ctx and hasattr(ctx, "audit_log") and ctx.audit_log:
            await ctx.audit_log.record(
                action="ai_write.update_target_card",
                user_id=str(ctx.current_user.id) if ctx.current_user else None,
                assessment_id=str(aid),
                details={"key": "target_card"},
            )
    except Exception:
        pass
    return {"updated": True, "assessment_id": str(aid), "fields": list(args.keys())}


async def _flag_finding(args: dict, ctx) -> dict:
    finding_id = args.get("finding_id")
    if not finding_id:
        return {"error": "finding_id is required", "blocked": True}
    new_status = args.get("status")
    new_severity = args.get("severity")
    note = args.get("note", "")
    from adbygod_api.models import Finding, FindingStatus, SeverityLevel
    from uuid import UUID
    try:
        fid = UUID(str(finding_id))
    except ValueError:
        return {"error": f"Invalid finding_id: {finding_id}", "blocked": True}
    result = await ctx.db.execute(
        select(Finding).where(Finding.id == fid)
    )
    f = result.scalars().first()
    if not f:
        return {"error": f"Finding {finding_id} not found", "blocked": True}
    if not await _verify_write_access(str(f.assessment_id), ctx):
        return {"error": "Assessment not found or access denied", "blocked": True}
    old_status = f.status.value if hasattr(f.status, "value") else str(f.status)
    old_severity = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
    if new_status:
        f.status = FindingStatus(new_status)
    if new_severity:
        f.severity = SeverityLevel(new_severity)
    await _commit_db(ctx)
    try:
        if ctx and hasattr(ctx, "audit_log") and ctx.audit_log:
            await ctx.audit_log.record(
                action="ai_write.flag_finding",
                user_id=str(ctx.current_user.id) if ctx.current_user else None,
                assessment_id=str(f.assessment_id),
                details={"finding_id": str(fid), "old_status": old_status,
                         "new_status": new_status, "note": note},
            )
    except Exception:
        pass
    return {
        "updated": True,
        "finding_id": str(fid),
        "title": f.title,
        "status": f.status.value if hasattr(f.status, "value") else str(f.status),
        "severity": f.severity.value if hasattr(f.severity, "value") else str(f.severity),
        "previous_status": old_status,
        "previous_severity": old_severity,
    }


async def _add_finding(args: dict, ctx) -> dict:
    aid = args.get("assessment_id") or (ctx.assessment_id if ctx else None)
    if not aid:
        return {"error": "assessment_id is required", "blocked": True}
    if not await _verify_write_access(aid, ctx):
        return {"error": "Assessment not found or access denied", "blocked": True}
    title = args.get("title")
    if not title:
        return {"error": "title is required", "blocked": True}
    severity_raw = args.get("severity", "MEDIUM")
    from adbygod_api.models import Finding, SeverityLevel, FindingStatus, DataOrigin
    import uuid as _uuid
    f = Finding(
        id=_uuid.uuid4(),
        assessment_id=aid,
        finding_type="manual",
        module=args.get("module", "manual"),
        title=title[:500],
        description=args.get("description", ""),
        severity=SeverityLevel(severity_raw),
        status=FindingStatus.OPEN,
        mitre_attack_ids=args.get("mitre_attack_ids", []),
        affected_objects=args.get("affected_objects", []),
        remediation=args.get("remediation", ""),
        origin=DataOrigin.COLLECTED,
    )
    ctx.db.add(f)
    await _commit_db(ctx)
    try:
        if ctx and hasattr(ctx, "audit_log") and ctx.audit_log:
            await ctx.audit_log.record(
                action="ai_write.add_finding",
                user_id=str(ctx.current_user.id) if ctx.current_user else None,
                assessment_id=str(aid),
                details={"finding_id": str(f.id), "title": title},
            )
    except Exception:
        pass
    return {
        "created": True,
        "finding_id": str(f.id),
        "title": f.title,
        "severity": severity_raw,
        "module": f.module,
    }


async def _annotate_entity(args: dict, ctx) -> dict:
    entity_id = args.get("entity_id")
    if not entity_id:
        return {"error": "entity_id is required", "blocked": True}
    aid = args.get("assessment_id") or (ctx.assessment_id if ctx else None)
    if aid and not await _verify_write_access(aid, ctx):
        return {"error": "Assessment not found or access denied", "blocked": True}
    from adbygod_api.models import Entity
    from uuid import UUID
    try:
        eid = UUID(str(entity_id))
    except ValueError:
        return {"error": f"Invalid entity_id: {entity_id}", "blocked": True}
    result = await ctx.db.execute(
        select(Entity).where(Entity.id == eid, Entity.assessment_id == aid)
    )
    e = result.scalars().first()
    if not e:
        return {"error": f"Entity {entity_id} not found", "blocked": True}
    if notes := args.get("notes"):
        attrs = dict(e.attributes or {})
        existing = attrs.get("operator_notes", [])
        if isinstance(existing, list):
            existing.append(notes)
        else:
            existing = [existing, notes]
        attrs["operator_notes"] = existing
        e.attributes = attrs
    if tags := args.get("business_tags"):
        existing_tags = list(e.business_tags or [])
        for tag in tags:
            if tag not in existing_tags:
                existing_tags.append(tag)
        e.business_tags = existing_tags
    if args.get("is_crown_jewel") is not None:
        e.is_crown_jewel = args["is_crown_jewel"]
    if args.get("is_sensitive") is not None:
        e.is_sensitive = args["is_sensitive"]
    await _commit_db(ctx)
    if aid:
        try:
            from adbygod_api.core.tasks.graph_projection import enqueue
            enqueue(str(aid))
        except Exception:
            pass
        try:
            from adbygod_api.core.graph.websocket_manager import broadcast_graph_delta
            await broadcast_graph_delta(str(aid))
        except Exception:
            pass
    # If marking as owned, persist to engagement memory too
    if args.get("owned") and ctx and ctx.memory_store and aid:
        label = e.display_name or e.sam_account_name or e.dns_hostname or str(eid)
        key = "owned_machines" if e.entity_type.value == "COMPUTER" else "owned_accounts"
        await ctx.memory_store.append(aid, key, label)
    return {
        "updated": True,
        "entity_id": str(eid),
        "label": e.display_name or e.sam_account_name or e.dns_hostname or str(eid),
        "is_crown_jewel": e.is_crown_jewel,
        "is_sensitive": e.is_sensitive,
        "business_tags": e.business_tags,
    }


async def _set_opsec_mode(args: dict, ctx) -> dict:
    mode = args.get("mode")
    if mode not in ("stealth", "normal", "aggressive"):
        return {"error": "mode must be stealth, normal, or aggressive", "blocked": True}
    aid = args.get("assessment_id") or (ctx.assessment_id if ctx else None)
    if aid and not await _verify_write_access(aid, ctx):
        return {"error": "Assessment not found or access denied", "blocked": True}
    if ctx and ctx.memory_store and aid:
        await ctx.memory_store.append(aid, "notes", {
            "type": "opsec_mode_change",
            "mode": mode,
            "reason": args.get("reason", ""),
        })
    noise_profiles = {
        "stealth": {"max_techniques_per_hour": 3, "preferred_tools": ["ldap", "bloodhound-python DCOnly"], "avoid": ["spray", "brute", "scan"]},
        "normal": {"max_techniques_per_hour": 10, "preferred_tools": ["impacket", "nxc", "bloodhound-python"], "avoid": ["scan sprays"]},
        "aggressive": {"max_techniques_per_hour": 50, "preferred_tools": ["any"], "avoid": []},
    }
    return {
        "mode": mode,
        "assessment_id": str(aid) if aid else None,
        "profile": noise_profiles[mode],
        "note": f"OPSEC mode set to {mode}. Technique suggestions will be filtered accordingly.",
    }


HANDLERS = {
    "save_to_memory": _save_to_memory,
    "write_report_section": _write_report_section,
    "update_target_card": _update_target_card,
    # god-mode additions
    "flag_finding": _flag_finding,
    "add_finding": _add_finding,
    "annotate_entity": _annotate_entity,
    "set_opsec_mode": _set_opsec_mode,
}
