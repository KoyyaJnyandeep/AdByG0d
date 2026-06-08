from __future__ import annotations
import asyncio
import re
import shlex
from adbygod_api.services.command_execution import (
    execute_technique as _svc_execute_technique,
    _redact,
    _STDOUT_CAP,
    _STDERR_CAP,
)

# Shell metacharacters that are disallowed in run_shell_command to prevent injection
_SHELL_META = re.compile(r'[|;&`$\n\r><\\]')


async def _verify_exec_read_access(aid, ctx) -> bool:
    if not aid or not ctx or not ctx.current_user:
        return False
    try:
        from uuid import UUID
        from adbygod_api.core.security.authorization import require_assessment_access
        await require_assessment_access(UUID(str(aid)), ctx.db, ctx.current_user)
        return True
    except Exception:
        return False


async def _verify_exec_write_access(aid, ctx) -> bool:
    if not aid or not ctx or not ctx.current_user:
        return False
    try:
        from uuid import UUID
        from adbygod_api.core.security.authorization import require_assessment_write_access
        await require_assessment_write_access(UUID(str(aid)), ctx.db, ctx.current_user)
        return True
    except Exception:
        return False


async def _execute_technique(args: dict, ctx) -> dict:
    """Thin wrapper — delegates all policy to the shared command_execution service."""
    technique_id = args.get("technique_id")
    if not technique_id:
        return {"error": "technique_id is required", "blocked": True}

    command_index = args.get("command_index", 0)
    params = args.get("params", {})

    current_user = ctx.current_user if ctx is not None else None
    if current_user is None:
        return {"error": "Command execution requires superadmin privileges.", "blocked": True}

    result = await _svc_execute_technique(
        technique_id=technique_id,
        command_index=command_index,
        params=params,
        current_user=current_user,
    )

    # Convert dataclass to dict for backward compat with tool dispatch
    if result.error is not None:
        out: dict = {"error": result.error, "blocked": result.blocked}
        if result.technique_id:
            out["technique_id"] = result.technique_id
        return out

    return {
        "technique_id": result.technique_id,
        "command": result.command,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "exit_code": result.exit_code,
    }


async def _run_shell_command(args: dict, ctx) -> dict:
    from adbygod_api.config import settings
    # When false (default), run_shell_command AI tool is blocked even with approval
    if not getattr(settings, 'ENABLE_AI_ARBITRARY_SHELL', False):
        return {
            "error": "Arbitrary shell execution is disabled. Set ENABLE_AI_ARBITRARY_SHELL=true in .env to enable (lab use only).",
            "blocked": True,
        }
    if ctx is None or ctx.current_user is None or not ctx.current_user.is_superadmin:
        return {
            "error": "Arbitrary shell execution requires superadmin privileges.",
            "blocked": True,
        }

    command = args["command"]           # KeyError if missing
    description = args["description"]  # KeyError if missing
    timeout = args.get("timeout_seconds", 30)

    # Reject shell metacharacters to prevent injection
    if _SHELL_META.search(command):
        return {
            "error": "Command contains disallowed shell metacharacters. Use execute_technique for catalog-based commands.",
            "blocked": True,
        }

    try:
        argv = shlex.split(command)
        if not argv:
            return {"error": "Command is empty", "blocked": True}
        if len(argv) > 32:
            return {"error": "Command has too many arguments", "blocked": True}
        proc = await asyncio.create_subprocess_exec(
            *argv,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        return {
            "description": description,
            "command": command,
            "stdout": _redact(stdout.decode("utf-8", errors="replace")[:_STDOUT_CAP]),
            "stderr": _redact(stderr.decode("utf-8", errors="replace")[:_STDERR_CAP]),
            "exit_code": proc.returncode,
        }
    except asyncio.TimeoutError:
        return {"error": f"Command timed out after {timeout}s", "command": command}


async def _run_campaign_step(args: dict, ctx) -> dict:
    phase = args["phase"]
    step_description = args["step_description"]
    aid = getattr(ctx, "assessment_id", None)
    if aid and not await _verify_exec_write_access(aid, ctx):
        return {"error": "Assessment not found or access denied", "blocked": True}
    if ctx and getattr(ctx, "memory_store", None) and aid:
        await ctx.memory_store.append(
            aid, "kill_chain_progress",
            {"phase": phase, "step": step_description, "status": "executed"}
        )
    return {"phase": phase, "step": step_description, "status": "recorded"}


async def _spawn_sub_agent(args: dict, ctx) -> dict:
    return {"agent_id": args["agent_id"], "task": args["task"], "status": "queued"}


async def _crack_hashes(args: dict, ctx) -> dict:
    hashes = args["hashes"]
    mode = args["hashcat_mode"]  # KeyError if missing
    wordlist = args.get("wordlist")

    current_user = getattr(ctx, "current_user", None)
    if current_user is not None:
        try:
            from adbygod_api.core.privileged_operations import require_dangerous_action_allowed, DangerousAction
            await require_dangerous_action_allowed(DangerousAction.CREDENTIAL_HANDLING, current_user)
        except Exception as e:
            return {"error": str(e), "blocked": True}

    owner_user_id = str(getattr(current_user, "id", "")) or "ai_operator"

    try:
        from adbygod_api.core.loot.hash_intel import start_crack_job, is_allowed_wordlist_path
        if wordlist and not is_allowed_wordlist_path(wordlist):
            return {"error": f"Wordlist path not allowed: {wordlist}"}

        job = await start_crack_job(
            owner_user_id=owner_user_id,
            hashes=hashes,
            mode=int(mode),
            wordlist=wordlist or "",
        )
        return {
            "job_id": job.id,
            "status": job.status,
            "hashes_count": len(hashes),
        }
    except Exception as e:
        return {"error": str(e), "hashes_count": len(hashes)}


async def _export_report(args: dict, ctx) -> dict:
    aid = args.get("assessment_id") or (ctx.assessment_id if ctx else None)
    if not aid:
        return {"error": "No active assessment", "blocked": True}
    if not await _verify_exec_write_access(aid, ctx):
        return {"error": "Assessment not found or access denied", "blocked": True}
    sections_to_include = args.get("sections") or [
        "executive_summary", "attack_narrative", "findings_detail",
        "attack_path_walkthrough", "recommendations",
    ]
    # Pull existing report sections from memory
    saved_sections: dict = {}
    if ctx and ctx.memory_store:
        mem = await ctx.memory_store.load(aid)
        saved_sections = mem.get("report_sections", {})
    output_sections = {}
    for sec in sections_to_include:
        output_sections[sec] = saved_sections.get(sec, f"[{sec} not yet drafted — use write_report_section to add content]")
    report_md = "# Assessment Report\n\n"
    section_titles = {
        "executive_summary": "Executive Summary",
        "attack_narrative": "Attack Narrative",
        "findings_detail": "Findings Detail",
        "attack_path_walkthrough": "Attack Path Walkthrough",
        "recommendations": "Recommendations",
    }
    for sec in sections_to_include:
        report_md += f"## {section_titles.get(sec, sec.replace('_', ' ').title())}\n\n"
        report_md += output_sections[sec] + "\n\n"
    if ctx and ctx.memory_store:
        await ctx.memory_store.append(aid, "notes", {
            "type": "report_exported",
            "sections": sections_to_include,
            "char_count": len(report_md),
        })
    return {
        "report_markdown": report_md,
        "sections_included": sections_to_include,
        "char_count": len(report_md),
        "word_count": len(report_md.split()),
    }


async def _run_technique_chain(args: dict, ctx) -> dict:
    techniques = args.get("techniques", [])
    if not techniques:
        return {"error": "techniques list is required", "blocked": True}
    stop_on_failure = args.get("stop_on_failure", True)
    aid = args.get("assessment_id") or (ctx.assessment_id if ctx else None)
    if aid and not await _verify_exec_write_access(aid, ctx):
        return {"error": "Assessment not found or access denied", "blocked": True}
    results = []
    for i, step in enumerate(techniques):
        technique_id = step.get("technique_id")
        if not technique_id:
            results.append({"step": i, "error": "technique_id missing", "skipped": True})
            if stop_on_failure:
                break
            continue
        step_result = await _execute_technique(
            {"technique_id": technique_id,
             "command_index": step.get("command_index", 0),
             "params": step.get("params", {})},
            ctx,
        )
        results.append({"step": i, "technique_id": technique_id, **step_result})
        if stop_on_failure and step_result.get("exit_code", 0) not in (0, None):
            results.append({"step": i + 1, "skipped": True, "reason": "previous step failed"})
            break
        if ctx and ctx.memory_store and aid:
            await ctx.memory_store.append(aid, "tried_techniques", technique_id)
    return {
        "steps_executed": len([r for r in results if not r.get("skipped")]),
        "steps_total": len(techniques),
        "results": results,
    }


async def _import_tool_output(args: dict, ctx) -> dict:
    tool_name = args.get("tool_name", "generic")
    raw_output = args.get("raw_output", "")
    aid = args.get("assessment_id") or (ctx.assessment_id if ctx else None)
    create_findings = args.get("create_findings", True)
    create_entities = args.get("create_entities", True)
    if not raw_output:
        return {"error": "raw_output is required", "blocked": True}
    if not aid:
        return {"error": "No active assessment", "blocked": True}
    if not await _verify_exec_write_access(aid, ctx):
        return {"error": "Assessment not found or access denied", "blocked": True}
    findings_created = []
    entities_created = []
    # Parse based on tool type
    if tool_name in ("nxc", "crackmapexec"):
        findings_created, entities_created = _parse_nxc_output(raw_output)
    elif tool_name == "nmap":
        findings_created, entities_created = _parse_nmap_output(raw_output)
    elif tool_name == "certipy":
        findings_created, entities_created = _parse_certipy_output(raw_output)
    elif tool_name == "ldapsearch":
        findings_created, entities_created = _parse_ldapsearch_output(raw_output)
    else:
        # Generic: look for common patterns
        findings_created, entities_created = _parse_generic_output(raw_output)
    # Persist parsed findings to DB if requested
    created_finding_ids = []
    if create_findings and findings_created:
        from adbygod_api.models import Finding, SeverityLevel, FindingStatus, DataOrigin
        import uuid as _uuid
        for f_data in findings_created[:20]:  # Cap at 20 auto-created findings
            f = Finding(
                id=_uuid.uuid4(),
                assessment_id=aid,
                finding_type="imported",
                module=tool_name,
                title=f_data["title"][:500],
                description=f_data.get("description", ""),
                severity=SeverityLevel(f_data.get("severity", "MEDIUM")),
                status=FindingStatus.OPEN,
                mitre_attack_ids=f_data.get("mitre_ids", []),
                origin=DataOrigin.COLLECTED,
            )
            ctx.db.add(f)
            created_finding_ids.append(str(f.id))
        await ctx.db.commit()
    # Persist parsed entities to DB if requested
    created_entity_ids: list[str] = []
    if create_entities and entities_created:
        from adbygod_api.models import Entity, EntityType
        from sqlalchemy import select as _select
        import uuid as _uuid
        seen_in_batch: set[str] = set()
        for e_data in entities_created[:50]:  # Cap at 50
            e_type_raw = e_data.get("type", "COMPUTER").upper()
            try:
                e_type = EntityType(e_type_raw)
            except ValueError:
                e_type = EntityType.COMPUTER
            dedup_key = (e_data.get("hostname") or e_data.get("dn") or e_data.get("ip") or "").strip()
            if not dedup_key or dedup_key in seen_in_batch:
                continue
            existing = await ctx.db.execute(
                _select(Entity).where(
                    Entity.assessment_id == aid,
                    Entity.display_name == dedup_key,
                ).limit(1)
            )
            if existing.scalars().first():
                continue
            seen_in_batch.add(dedup_key)
            raw_hostname = e_data.get("hostname", "")
            clean_hostname = re.sub(r'\s*\([^)]+\)\s*$', '', raw_hostname).strip() if raw_hostname else None
            e = Entity(
                id=_uuid.uuid4(),
                assessment_id=aid,
                entity_type=e_type,
                display_name=dedup_key,
                dns_hostname=clean_hostname or None,
                distinguished_name=e_data.get("dn") or None,
                is_enabled=True,
                is_admin_count=False,
                is_sensitive=False,
                is_protected_user=False,
                is_crown_jewel=False,
                business_tags=[],
                attributes={k: v for k, v in e_data.items() if k != "type"},
            )
            ctx.db.add(e)
            created_entity_ids.append(str(e.id))
        if created_entity_ids:
            await ctx.db.commit()
    return {
        "tool": tool_name,
        "findings_parsed": len(findings_created),
        "findings_created": len(created_finding_ids),
        "entities_parsed": len(entities_created),
        "entities_created": len(created_entity_ids),
        "findings_preview": findings_created[:5],
        "entities_preview": entities_created[:5],
    }


def _parse_nxc_output(output: str) -> tuple[list, list]:
    findings, entities = [], []
    for line in output.splitlines():
        if "Pwn3d!" in line or "Admin!" in line:
            findings.append({"title": "Local Admin Access Confirmed via NXC", "severity": "CRITICAL",
                              "description": line.strip(), "mitre_ids": ["T1021.002"]})
        if "SMB" in line and re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', line):
            ip_match = re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', line)
            if ip_match:
                entities.append({"type": "COMPUTER", "ip": ip_match.group(), "raw": line.strip()})
        if "STATUS_PASSWORD_MUST_CHANGE" in line:
            findings.append({"title": "Account Requires Password Change", "severity": "MEDIUM",
                              "description": line.strip(), "mitre_ids": ["T1078"]})
    return findings, entities


def _parse_nmap_output(output: str) -> tuple[list, list]:
    findings, entities = [], []
    for line in output.splitlines():
        ip_match = re.search(r'Nmap scan report for (.+)', line)
        if ip_match:
            entities.append({"type": "COMPUTER", "hostname": ip_match.group(1).strip()})
        if "445/tcp" in line and "open" in line:
            findings.append({"title": "SMB Port 445 Open", "severity": "INFO",
                              "description": line.strip(), "mitre_ids": ["T1021.002"]})
        if "88/tcp" in line and "open" in line:
            findings.append({"title": "Kerberos Port 88 Open — Domain Controller Candidate",
                              "severity": "INFO", "description": line.strip(), "mitre_ids": ["T1558"]})
    return findings, entities


def _parse_certipy_output(output: str) -> tuple[list, list]:
    findings, entities = [], []
    for line in output.splitlines():
        for esc in ("ESC1", "ESC2", "ESC3", "ESC4", "ESC6", "ESC7", "ESC8"):
            if esc in line:
                findings.append({
                    "title": f"ADCS {esc} Vulnerable Template Detected",
                    "severity": "CRITICAL",
                    "description": line.strip(),
                    "mitre_ids": ["T1649"],
                })
        if "CA Name" in line or "Certificate Authority" in line:
            entities.append({"type": "computer", "role": "CA", "raw": line.strip()})
    return findings, entities


def _parse_ldapsearch_output(output: str) -> tuple[list, list]:
    findings, entities = [], []
    current: dict = {}
    for line in output.splitlines():
        if line.startswith("dn:"):
            if current:
                obj_class = current.get("objectClass", "")
                if "user" in obj_class:
                    entities.append({"type": "USER", "dn": current.get("dn", ""), "attributes": current})
                elif "group" in obj_class:
                    entities.append({"type": "GROUP", "dn": current.get("dn", ""), "attributes": current})
            current = {"dn": line[3:].strip()}
        elif ":" in line:
            k, _, v = line.partition(":")
            current[k.strip()] = v.strip()
    # Flush the last parsed entry (not flushed by the loop since no trailing dn: line)
    if current:
        obj_class = current.get("objectClass", "")
        if "user" in obj_class:
            entities.append({"type": "USER", "dn": current.get("dn", ""), "attributes": current})
        elif "group" in obj_class:
            entities.append({"type": "GROUP", "dn": current.get("dn", ""), "attributes": current})
    if "adminCount: 1" in output:
        findings.append({"title": "AdminCount=1 accounts detected", "severity": "HIGH",
                          "description": "Accounts with adminCount=1 have protected ACLs and are Kerberoasting targets.",
                          "mitre_ids": ["T1558.003"]})
    return findings, entities


def _parse_generic_output(output: str) -> tuple[list, list]:
    findings, entities = [], []
    ip_pattern = re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b')
    hash_pattern = re.compile(r'\b[a-fA-F0-9]{32}\b')
    ips = set(ip_pattern.findall(output))
    for ip in list(ips)[:10]:
        entities.append({"type": "COMPUTER", "ip": ip})
    hashes = set(hash_pattern.findall(output))
    if hashes:
        findings.append({"title": f"Potential NTLM hashes found in output ({len(hashes)} candidates)",
                          "severity": "HIGH", "description": f"Hashes: {', '.join(list(hashes)[:3])}...",
                          "mitre_ids": ["T1003"]})
    return findings, entities


# Maps string phase labels used in technique_map to their numeric phase_id in KillChainProgress.
# "da" is a target milestone, not a kill-chain phase — treated as None so it is never suppressed.
_PHASE_NAME_TO_ID: dict[str, int | None] = {
    "recon": 0,
    "enum": 2,
    "loot": 5,
    "privesc": 3,
    "lateral": 4,
    "da": None,
}


async def _plan_attack(args: dict, ctx) -> dict:
    """Synthesize current assessment state into a prioritized step-by-step attack plan."""
    aid = args.get("assessment_id") or (ctx.assessment_id if ctx else None)
    if not aid:
        return {"error": "No active assessment", "blocked": True}
    if not await _verify_exec_read_access(aid, ctx):
        return {"error": "Assessment not found or access denied", "blocked": True}
    target = args.get("target", "Domain Admins")
    opsec_mode = args.get("opsec_mode", "normal")
    max_steps = min(args.get("max_steps", 10), 15)
    # Pull current state
    from adbygod_api.models import Finding, ExposurePath, KillChainProgress
    from sqlalchemy import select, desc
    findings_result = await ctx.db.execute(
        select(Finding).where(Finding.assessment_id == aid)
        .order_by(desc(Finding.composite_score), desc(Finding.severity))
        .limit(30)
    )
    findings = findings_result.scalars().all()
    paths_result = await ctx.db.execute(
        select(ExposurePath).where(ExposurePath.assessment_id == aid)
        .order_by(desc(ExposurePath.path_score)).limit(10)
    )
    paths = paths_result.scalars().all()
    kc_result = await ctx.db.execute(
        select(KillChainProgress).where(KillChainProgress.assessment_id == aid)
        .order_by(KillChainProgress.phase_id)
    )
    kc_phases = kc_result.scalars().all()
    completed_phases = {p.phase_id for p in kc_phases if p.status and "complete" in str(p.status).lower()}
    # Build plan steps based on findings
    steps = []
    _severity_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    technique_map = {
        "kerberoast": ("enum", "recon-kerberoasting", "T1558.003"),
        "asrep": ("enum", "recon-asrep-roasting", "T1558.004"),
        "delegation": ("privesc", "delegation-unconstrained", "T1558.002"),
        "adcs": ("privesc", "adcs-esc1-certipy", "T1649"),
        "dcsync": ("da", "credential-dcsync-impacket", "T1003.006"),
        "writedacl": ("privesc", "acl-abuse-dacl", "T1222.001"),
        "genericall": ("privesc", "acl-abuse-genericall", "T1222.001"),
        "shadow": ("privesc", "shadow-credentials-certipy", "T1556"),
        "laps": ("loot", "laps-read-nxc", "T1555"),
        "ntlm": ("loot", "credential-ntlm-relay", "T1557.001"),
    }
    for f in findings:
        title_lower = f.title.lower()
        sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
        for keyword, (phase, technique_id, mitre_id) in technique_map.items():
            if keyword in title_lower and _PHASE_NAME_TO_ID.get(phase) not in completed_phases:
                steps.append({
                    "step": len(steps) + 1,
                    "phase": phase,
                    "action": f.title,
                    "technique_id": technique_id,
                    "mitre_id": mitre_id,
                    "severity": sev,
                    "priority": _severity_rank.get(sev, 5),
                    "opsec_risk": "LOW" if opsec_mode == "stealth" and phase in ("da", "loot") else "MEDIUM",
                    "finding_id": str(f.id),
                })
                break
    # Add DA step if paths exist
    if paths and _PHASE_NAME_TO_ID.get("da") not in completed_phases:
        best_path = paths[0]
        steps.append({
            "step": len(steps) + 1,
            "phase": "da",
            "action": f"Exploit shortest path to {target} ({best_path.hop_count} hops via {best_path.path_type})",
            "technique_id": "credential-dcsync-impacket",
            "mitre_id": "T1003.006",
            "severity": "CRITICAL",
            "priority": 0,
            "opsec_risk": "HIGH",
        })
    steps.sort(key=lambda x: (x["priority"], x["phase"]))
    steps = steps[:max_steps]
    for i, s in enumerate(steps):
        s["step"] = i + 1
    return {
        "target": target,
        "opsec_mode": opsec_mode,
        "steps": steps,
        "total_steps": len(steps),
        "phases_remaining": [
            p for p in ["recon", "enum", "loot", "privesc", "lateral", "da"]
            if _PHASE_NAME_TO_ID.get(p) not in completed_phases
        ],
        "summary": f"{len(steps)}-step plan to {target}. Start with step 1.",
    }


async def _get_next_best_action(args: dict, ctx) -> dict:
    """Single highest-impact next action based on current state."""
    aid = args.get("assessment_id") or (ctx.assessment_id if ctx else None)
    if not aid:
        return {"error": "No active assessment", "blocked": True}
    # Delegate to plan_attack and return just the first step
    plan = await _plan_attack({"assessment_id": aid, "max_steps": 1}, ctx)
    if plan.get("error"):
        return plan
    steps = plan.get("steps", [])
    if not steps:
        # Fall back: check what kill chain phase is next
        from adbygod_api.models import KillChainProgress
        from sqlalchemy import select
        kc_result = await ctx.db.execute(
            select(KillChainProgress).where(KillChainProgress.assessment_id == aid)
        )
        phases = kc_result.scalars().all()
        next_phase = next(
            (p.phase_id for p in phases
             if not p.status or "pending" in str(p.status).lower()),
            "recon",
        )
        return {
            "next_action": f"Start {next_phase} phase",
            "phase": next_phase,
            "technique_id": None,
            "reason": "No direct attack paths found yet — begin enumeration",
        }
    s = steps[0]
    return {
        "next_action": s["action"],
        "phase": s["phase"],
        "technique_id": s.get("technique_id"),
        "mitre_id": s.get("mitre_id"),
        "severity": s.get("severity"),
        "opsec_risk": s.get("opsec_risk"),
        "reason": f"Highest-impact action based on {s['severity']} finding: {s['action']}",
    }


async def _run_bloodhound_collection(args: dict, ctx) -> dict:
    from adbygod_api.config import settings
    if not getattr(settings, "ENABLE_COMMAND_EXECUTION", False):
        return {
            "error": "Command execution is disabled. Set ENABLE_COMMAND_EXECUTION=true to enable.",
            "blocked": True,
        }
    if not getattr(settings, "ENABLE_AI_ARBITRARY_SHELL", False):
        return {
            "error": "BloodHound collection requires ENABLE_AI_ARBITRARY_SHELL=true in .env (lab use only).",
            "blocked": True,
        }
    if ctx is None or ctx.current_user is None or not ctx.current_user.is_superadmin:
        return {"error": "BloodHound collection requires superadmin privileges.", "blocked": True}
    dc_ip = args.get("dc_ip", "")
    domain = args.get("domain") or args.get("domain_name", "")
    username = args.get("username", "")
    password = args.get("password", "")
    nt_hash = args.get("nt_hash", "")
    collection_method = args.get("collection_method", "DCOnly")
    if not dc_ip or not domain or not username:
        return {"error": "dc_ip, domain, and username are required", "blocked": True}
    # Build bloodhound-python command
    cmd_parts = [
        "bloodhound-python",
        "-d", domain,
        "-u", username,
        "-ns", dc_ip,
        "-c", collection_method,
        "--zip",
        "--dns-tcp",
    ]
    if nt_hash:
        cmd_parts += ["--hashes", f":{nt_hash}"]
    elif password:
        cmd_parts += ["-p", password]
    else:
        return {"error": "Either password or nt_hash is required", "blocked": True}
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd_parts,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=120)
        stdout_text = _redact(stdout.decode("utf-8", errors="replace")[:_STDOUT_CAP])
        stderr_text = _redact(stderr.decode("utf-8", errors="replace")[:_STDERR_CAP])
        return {
            "exit_code": proc.returncode,
            "stdout": stdout_text,
            "stderr": stderr_text,
            "collection_method": collection_method,
            "note": "Import the generated zip into the platform via the BloodHound import endpoint to update the graph.",
        }
    except asyncio.TimeoutError:
        return {"error": "BloodHound collection timed out after 120s", "blocked": False}
    except FileNotFoundError:
        return {"error": "bloodhound-python not found. Install with: pip install bloodhound", "blocked": True}


async def _get_timeline(args: dict, ctx) -> dict:
    aid = args.get("assessment_id") or (ctx.assessment_id if ctx else None)
    if not aid:
        return {"error": "No active assessment", "blocked": True}
    if not await _verify_exec_read_access(aid, ctx):
        return {"error": "Assessment not found or access denied", "blocked": True}
    limit = min(args.get("limit", 50), 200)
    event_type_filter = set(args.get("event_types", []))
    # Pull from memory store (techniques, owned entities, report sections)
    events: list[dict] = []
    if ctx and ctx.memory_store:
        mem = await ctx.memory_store.load(aid)
        for technique in (mem.get("tried_techniques") or []):
            if not event_type_filter or "technique_executed" in event_type_filter:
                events.append({"type": "technique_executed", "detail": technique, "ts": None})
        for technique in (mem.get("failed_techniques") or []):
            if not event_type_filter or "technique_failed" in event_type_filter:
                events.append({"type": "technique_failed", "detail": technique, "ts": None})
        for account in (mem.get("owned_accounts") or []):
            if not event_type_filter or "entity_owned" in event_type_filter:
                events.append({"type": "entity_owned", "detail": f"account: {account}", "ts": None})
        for machine in (mem.get("owned_machines") or []):
            if not event_type_filter or "entity_owned" in event_type_filter:
                events.append({"type": "entity_owned", "detail": f"machine: {machine}", "ts": None})
        report_sections = mem.get("report_sections") or {}
        for section in report_sections:
            if not event_type_filter or "report_written" in event_type_filter:
                events.append({"type": "report_written", "detail": f"section: {section}", "ts": None})
        for note in (mem.get("notes") or []):
            if isinstance(note, dict) and note.get("type") == "opsec_mode_change":
                events.append({"type": "opsec_mode_change", "detail": f"mode → {note.get('mode')}", "ts": None})
    # Also pull kill chain progress
    from adbygod_api.models import KillChainProgress
    from sqlalchemy import select
    kc_result = await ctx.db.execute(
        select(KillChainProgress).where(KillChainProgress.assessment_id == aid)
    )
    for p in kc_result.scalars().all():
        techniques = p.techniques_run or []
        techniques_count = len(techniques) if isinstance(techniques, list) else int(techniques or 0)
        if techniques_count > 0:
            if not event_type_filter or "phase_progress" in event_type_filter:
                events.append({
                    "type": "phase_progress",
                    "detail": f"{p.label}: {techniques_count} techniques, {p.findings_count} findings",
                    "ts": None,
                })
    return {
        "events": events[:limit],
        "total": len(events),
        "assessment_id": str(aid),
    }


async def _generate_playbook(args: dict, ctx) -> dict:
    aid = args.get("assessment_id") or (ctx.assessment_id if ctx else None)
    if not aid:
        return {"error": "No active assessment", "blocked": True}
    if not await _verify_exec_read_access(aid, ctx):
        return {"error": "Assessment not found or access denied", "blocked": True}
    target = args.get("target", "Domain Admins")
    style = args.get("style", "technical")
    include_mitre = args.get("include_mitre", True)
    include_detection = args.get("include_detection", True)
    # Pull plan + assessment context
    plan = await _plan_attack({"assessment_id": aid, "target": target, "max_steps": 15}, ctx)
    from adbygod_api.models import Assessment, Finding
    from sqlalchemy import select, desc
    a_result = await ctx.db.execute(select(Assessment).where(Assessment.id == aid))
    a = a_result.scalars().first()
    domain = a.domain if a else "TARGET.LOCAL"
    dc_ip = a.dc_ip if a else "DC_IP"
    findings_result = await ctx.db.execute(
        select(Finding).where(Finding.assessment_id == aid)
        .order_by(desc(Finding.severity)).limit(5)
    )
    top_findings = findings_result.scalars().all()
    # Build markdown playbook
    md = f"# Kill-Chain Playbook: {domain} → {target}\n\n"
    md += f"**DC:** `{dc_ip}` | **Target:** {target} | **Style:** {style}\n\n"
    if style != "executive":
        md += "## Phase Overview\n\n"
        phases = ["Recon", "Enumeration", "Credential Access", "Privilege Escalation", "Lateral Movement", "Domain Admin"]
        for phase in phases:
            md += f"- {phase}\n"
        md += "\n"
    md += "## Attack Steps\n\n"
    detection_notes = {
        "recon": "Event ID 4662 (object access), LDAP query logs, DNS query logs",
        "enum": "Event ID 4768 (TGT request), 4769 (TGS request), net commands in process logs",
        "loot": "Event ID 4771 (pre-auth failure), 4776 (NTLM auth), LSASS access (4656/4663)",
        "privesc": "Event ID 4738 (account modified), 5136 (directory object modified), Sysmon process injection",
        "lateral": "Event ID 4624 (logon), 4648 (explicit creds), 7045 (new service)",
        "da": "Event ID 4672 (special logon), 4624 type 3, DCSync triggers replication event 4662",
    }
    for step in plan.get("steps", []):
        md += f"### Step {step['step']}: {step['action']}\n\n"
        if include_mitre and step.get("mitre_id"):
            md += f"**MITRE:** `{step['mitre_id']}`  "
        md += f"**Phase:** {step['phase']}  **Severity:** {step.get('severity', 'N/A')}  **OPSEC Risk:** {step.get('opsec_risk', 'MEDIUM')}\n\n"
        if style == "technical":
            tech_id = step.get("technique_id")
            if tech_id:
                from adbygod_api.data.ad_commands import AD_COMMANDS
                tech = next((t for t in AD_COMMANDS if t["id"] == tech_id), None)
                if tech and tech.get("commands"):
                    cmd = tech["commands"][0]
                    md += f"```bash\n{cmd['command'].replace('{Domain}', domain).replace('{DC_IP}', dc_ip)}\n```\n\n"
        if include_detection and step.get("phase") in detection_notes:
            md += f"**Detection:** {detection_notes[step['phase']]}\n\n"
    if top_findings and style != "executive":
        md += "## Top Findings Summary\n\n"
        for f in top_findings:
            sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
            md += f"- **[{sev}]** {f.title}\n"
        md += "\n"
    return {
        "playbook_markdown": md,
        "steps_count": len(plan.get("steps", [])),
        "target": target,
        "domain": domain,
        "char_count": len(md),
    }


HANDLERS = {
    "execute_technique": _execute_technique,
    "run_shell_command": _run_shell_command,
    "run_campaign_step": _run_campaign_step,
    "spawn_sub_agent": _spawn_sub_agent,
    "crack_hashes": _crack_hashes,
    # god-mode additions
    "export_report": _export_report,
    "run_technique_chain": _run_technique_chain,
    "import_tool_output": _import_tool_output,
    "plan_attack": _plan_attack,
    "get_next_best_action": _get_next_best_action,
    "run_bloodhound_collection": _run_bloodhound_collection,
    "get_timeline": _get_timeline,
    "generate_playbook": _generate_playbook,
}
