from __future__ import annotations

import ipaddress
import logging
import urllib.parse as _urlparse
from datetime import datetime
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from adbygod_api.core.ai_operator.orchestrator import get_next_suggestion, generate_playbook
from adbygod_api.core.ai_operator.worker_pool import create_pool, stop_pool, get_pool_status, get_pool
from adbygod_api.core.ai_operator.audit_log import log_action
from adbygod_api.core.ai_operator.analyzer import analyze_output, explain_technique, generate_report_narrative, analyze_bloodhound
from adbygod_api.core.ai_operator.providers.router import list_providers, check_provider_health
from adbygod_api.core.ai_operator.approval_store import get_approval_store
from adbygod_api.config import get_settings
from adbygod_api.core.ai_operator.memory_store import get_memory_store
from adbygod_api.core.session.manager import get_or_create_session
from adbygod_api.core.security.authorization import require_assessment_access, require_assessment_write_access, scope_assessment_query
from adbygod_api.database import get_db
from adbygod_api.models import PlatformUser, AIOperatorAction
from adbygod_api.routes.auth import get_current_user

log = logging.getLogger(__name__)
router = APIRouter(prefix="/ai-operator", tags=["ai-operator"])

_PRIVATE_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]


def _validate_provider_base_url(url: str, *, provider_id: str) -> None:
    """Raise HTTP 422 if url points to a private/loopback network or uses a disallowed scheme.

    For Ollama, also reject any URL that doesn't match the server-configured base.
    """
    if not url:
        return
    parsed = _urlparse.urlparse(url)

    # Only allow http/https schemes
    if parsed.scheme not in ("http", "https"):
        raise HTTPException(status_code=422, detail="base_url must use http or https scheme")

    hostname = (parsed.hostname or "").lower()

    if provider_id == "ollama":
        configured = (get_settings().OLLAMA_BASE_URL or "").rstrip("/")
        configured_parsed = _urlparse.urlparse(configured)
        configured_host = (configured_parsed.hostname or "").lower()
        configured_port = configured_parsed.port
        if (hostname != configured_host or parsed.port != configured_port
                or parsed.scheme != configured_parsed.scheme):
            raise HTTPException(
                status_code=422,
                detail="Ollama base_url must match the server-configured OLLAMA_BASE_URL",
            )
        return

    # For all other providers: block private/loopback ranges
    try:
        addr = ipaddress.ip_address(hostname)
        for net in _PRIVATE_NETWORKS:
            if addr in net:
                raise HTTPException(status_code=422, detail="base_url points to a private or loopback address")
    except ValueError:
        # hostname is not a raw IP — block well-known loopback names
        if hostname in ("localhost", "ip6-localhost", "ip6-loopback"):
            raise HTTPException(status_code=422, detail="base_url points to a loopback address")


class SuggestRequest(BaseModel):
    phase_scope: list[int] = Field(default_factory=lambda: list(range(9)))
    excluded_ids: list[str] = Field(default_factory=list)
    recent_findings: list[dict] = Field(default_factory=list)
    kill_chain_phases: list[dict] = Field(default_factory=list)
    provider: str | None = None
    model: str | None = None
    api_key: str | None = None
    base_url: str | None = None


class SuggestionOut(BaseModel):
    technique_id: str
    title: str
    reason: str
    expected_outcome: str
    mitre_id: str
    phase_id: int
    prerequisites_met: bool
    auth_level_promotion: bool
    requires_human_approval: bool


class PlaybookRequest(BaseModel):
    phase_scope: list[int] = Field(default_factory=lambda: list(range(9)))
    excluded_ids: list[str] = Field(default_factory=list)
    provider: str | None = None
    model: str | None = None
    api_key: str | None = None
    base_url: str | None = None


class AutoRunRequest(BaseModel):
    max_parallel_workers: int = Field(default=3, ge=1, le=5)
    phase_scope: list[int] = Field(default_factory=lambda: list(range(9)))


class StatusOut(BaseModel):
    running: bool
    session_id: str
    max_workers: int
    active_workers: int
    tasks_queued: int
    tasks_completed: int
    stop_requested: bool


class AuditEntryOut(BaseModel):
    id: str
    action_type: str
    technique_id: str | None
    command_executed: str | None
    output_snippet: str | None
    reasoning: str | None
    phase_id: int | None
    worker_id: int | None
    created_at: datetime


@router.post("/suggest", response_model=SuggestionOut)
async def suggest_next(
    body: SuggestRequest,
    current_user: PlatformUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    session = await get_or_create_session(db, current_user.id)
    session_dict = {
        "target_ip": session.target_ip,
        "domain": session.domain,
        "auth_level": session.auth_level,
        "commands_run": session.commands_run,
        "findings_count": session.findings_count,
        "machines_owned": session.machines_owned,
    }
    try:
        suggestion = await get_next_suggestion(
            session_dict, body.kill_chain_phases, body.recent_findings,
            body.phase_scope, body.excluded_ids,
            provider_id=body.provider,
            model=body.model,
            api_key=body.api_key,
            base_url=body.base_url,
        )
    except RuntimeError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    await log_action(db, session_id=session.id, action_type="suggest",
                     technique_id=suggestion.technique_id, reasoning=suggestion.reason,
                     phase_id=suggestion.phase_id)
    return SuggestionOut(**suggestion.__dict__)


@router.post("/playbook")
async def get_playbook(
    body: PlaybookRequest,
    current_user: PlatformUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    session = await get_or_create_session(db, current_user.id)
    session_dict = {"target_ip": session.target_ip, "domain": session.domain, "auth_level": session.auth_level}
    playbook = await generate_playbook(
        session_dict,
        body.phase_scope,
        body.excluded_ids,
        provider_id=body.provider,
        model=body.model,
        api_key=body.api_key,
    )
    await log_action(db, session_id=session.id, action_type="playbook")
    return {"playbook": playbook, "count": len(playbook)}


@router.post("/auto-run")
async def start_auto_run(
    body: AutoRunRequest,
    current_user: PlatformUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    session = await get_or_create_session(db, current_user.id)
    existing = get_pool(session.id)
    if existing and existing.running:
        raise HTTPException(status_code=409, detail="Auto-run already active for this session")
    pool = create_pool(session.id, max_workers=body.max_parallel_workers)
    pool.running = True
    await log_action(db, session_id=session.id, action_type="auto_run_start")
    return get_pool_status(session.id)


@router.get("/status", response_model=StatusOut)
async def get_status(
    current_user: PlatformUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    session = await get_or_create_session(db, current_user.id)
    return StatusOut(**get_pool_status(session.id))


@router.post("/stop")
async def stop_auto_run(
    current_user: PlatformUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    session = await get_or_create_session(db, current_user.id)
    stopped = stop_pool(session.id)
    await log_action(db, session_id=session.id, action_type="auto_run_stop")
    return {"status": "stopped" if stopped else "not_running"}


@router.get("/history", response_model=list[AuditEntryOut])
async def get_history(
    limit: int = 50,
    current_user: PlatformUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    session = await get_or_create_session(db, current_user.id)
    rows = (await db.execute(
        select(AIOperatorAction)
        .where(AIOperatorAction.session_id == session.id)
        .order_by(AIOperatorAction.created_at.desc())
        .limit(limit)
    )).scalars().all()
    return [
        AuditEntryOut(
            id=str(r.id),
            action_type=r.action_type,
            technique_id=r.technique_id,
            command_executed=r.command_executed,
            output_snippet=r.output_snippet,
            reasoning=r.reasoning,
            phase_id=r.phase_id,
            worker_id=r.worker_id,
            created_at=r.created_at,
        )
        for r in rows
    ]


class ProviderInfoOut(BaseModel):
    id: str
    name: str
    available: bool
    models: list[str]
    default_model: str
    local: bool = False
    error: str | None = None


@router.get("/providers", response_model=list[ProviderInfoOut])
async def get_providers(current_user: PlatformUser = Depends(get_current_user)):
    """List all AI providers with availability status."""
    providers = await list_providers()
    return [ProviderInfoOut(**p.__dict__) for p in providers]


@router.get("/providers/{provider_id}", response_model=ProviderInfoOut)
async def get_provider_status(
    provider_id: str,
    current_user: PlatformUser = Depends(get_current_user),
):
    """Health-check a specific provider using env-configured keys."""
    info = await check_provider_health(provider_id)
    return ProviderInfoOut(**info.__dict__)


class TestProviderRequest(BaseModel):
    api_key: str | None = None
    base_url: str | None = None
    model: str | None = None


@router.post("/providers/{provider_id}/test", response_model=ProviderInfoOut)
async def test_provider_key(
    provider_id: str,
    body: TestProviderRequest,
    current_user: PlatformUser = Depends(get_current_user),
):
    """Test a provider with caller-supplied credentials. Key never persisted server-side."""
    if body.base_url:
        _validate_provider_base_url(body.base_url, provider_id=provider_id)
    # When a server-side env key is configured, do not forward it to a caller-supplied origin.
    # The caller must provide their own api_key when supplying a custom base_url.
    info = await check_provider_health(provider_id, api_key=body.api_key, base_url=body.base_url)
    return ProviderInfoOut(**info.__dict__)


_RESOLVE_ERROR_STATUS: dict[str, int] = {
    "request_not_found": 404,
    "already_resolved": 409,
    "expired": 410,
    "user_mismatch": 403,
    "action_mismatch": 409,
    "tool_mismatch": 409,
}


@router.post("/approve/{request_id}")
async def approve_tool_execution(
    request_id: str,
    current_user: PlatformUser = Depends(get_current_user),
):
    """Approve a pending N3mo tool execution."""
    store = get_approval_store()

    # Check dangerous feature flags before approving execution tools
    pending = store.get(request_id)
    if pending is not None:
        settings = get_settings()
        tool = pending.tool_name
        if tool in ("run_shell_command", "execute_command", "execute_technique", "crack_hashes") and not settings.ENABLE_COMMAND_EXECUTION:
            raise HTTPException(
                status_code=403,
                detail="Command execution is disabled (ENABLE_COMMAND_EXECUTION=false)",
            )
        if tool == "run_shell_command" and not settings.ENABLE_AI_ARBITRARY_SHELL:
            raise HTTPException(
                status_code=403,
                detail="Arbitrary shell execution is disabled (ENABLE_AI_ARBITRARY_SHELL=false)",
            )

    ok, reason = store.resolve(request_id, approved=True, user_id=str(current_user.id))
    if not ok:
        status_code = _RESOLVE_ERROR_STATUS.get(reason, 400)
        raise HTTPException(status_code=status_code, detail=reason)
    return {"approved": True, "request_id": request_id}


@router.post("/reject/{request_id}")
async def reject_tool_execution(
    request_id: str,
    current_user: PlatformUser = Depends(get_current_user),
):
    """Reject a pending N3mo tool execution."""
    store = get_approval_store()
    ok, reason = store.resolve(request_id, approved=False, user_id=str(current_user.id))
    if not ok:
        status_code = _RESOLVE_ERROR_STATUS.get(reason, 400)
        raise HTTPException(status_code=status_code, detail=reason)
    return {"rejected": True, "request_id": request_id}


@router.get("/memory/{assessment_id}")
async def get_memory(
    assessment_id: str,
    current_user: PlatformUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Read engagement memory for an assessment."""
    try:
        await require_assessment_access(UUID(assessment_id), db, current_user)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail="Assessment not found") from exc
    store = get_memory_store()
    mem = await store.load(assessment_id)
    return {"assessment_id": assessment_id, "memory": mem}


@router.delete("/memory/{assessment_id}")
async def clear_memory(
    assessment_id: str,
    current_user: PlatformUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Clear engagement memory for an assessment."""
    try:
        await require_assessment_write_access(UUID(assessment_id), db, current_user)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail="Assessment not found") from exc
    import os
    from pathlib import Path
    path = Path(os.path.expanduser("~/.adbygod/memory")) / f"{assessment_id}.json"
    if path.exists():
        path.unlink()
    return {"cleared": True, "assessment_id": assessment_id}


@router.get("/playbooks")
async def list_playbooks(current_user: PlatformUser = Depends(get_current_user)):
    """List available YAML playbooks."""
    from adbygod_api.core.ai_operator.playbook_engine import PlaybookEngine
    engine = PlaybookEngine()
    return {"playbooks": engine.list_playbooks()}


@router.get("/target-card/{assessment_id}")
async def get_target_card(
    assessment_id: str,
    current_user: PlatformUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get current target intelligence card state from engagement memory."""
    try:
        assessment_uuid = UUID(assessment_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail="Assessment not found") from exc
    await require_assessment_access(assessment_uuid, db, current_user)
    store = get_memory_store()
    mem = await store.load(assessment_id)
    return {
        "assessment_id": assessment_id,
        "owned_accounts": mem.get("owned_accounts", []),
        "owned_machines": mem.get("owned_machines", []),
        "kill_chain_progress": mem.get("kill_chain_progress", {}),
        "notes": mem.get("notes", []),
    }


class ChatContextItem(BaseModel):
    type: str = "text"   # "output" | "finding" | "bloodhound" | "hash" | "text"
    label: str = ""
    content: str


class ChatRequest(BaseModel):
    message: str
    history: list[dict] = Field(default_factory=list)
    context_items: list[ChatContextItem] = Field(default_factory=list)
    session_ctx: dict | None = None
    provider: str | None = None
    model: str | None = None
    api_key: str | None = None       # caller-supplied key override (not persisted)
    base_url: str | None = None      # for Ollama custom URL


@router.post("/chat")
async def chat(
    body: ChatRequest,
    current_user: PlatformUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Streaming SSE chat endpoint. Returns text/event-stream."""
    from adbygod_api.models import Assessment
    from sqlalchemy import desc as _desc

    session = await get_or_create_session(db, current_user.id)

    # Resolve the actual assessment ID — always verify the stored ID still exists
    # and fall back to the most recent assessment if the stored one was deleted/reimported.
    assessment_id: str | None = None
    if session.assessment_id:
        exists = (await db.execute(
            select(Assessment).where(Assessment.id == session.assessment_id)
        )).scalar_one_or_none()
        if exists:
            assessment_id = str(session.assessment_id)

    if not assessment_id:
        stmt = select(Assessment).order_by(_desc(Assessment.created_at)).limit(1)
        stmt = await scope_assessment_query(stmt, db, current_user)
        latest_a = (await db.execute(stmt)).scalars().first()
        if latest_a:
            assessment_id = str(latest_a.id)
            session.assessment_id = latest_a.id
            await db.commit()

    session_ctx = body.session_ctx or {
        "target_ip": session.target_ip,
        "domain": session.domain,
        "auth_level": session.auth_level,
        "commands_run": session.commands_run,
        "findings_count": session.findings_count,
    }

    async def event_generator():
        from adbygod_api.core.ai_operator.agent import AgentLoop
        loop = AgentLoop()
        try:
            async for event in loop.run(
                session_ctx=session_ctx,
                user_message=body.message,
                history=body.history,
                provider_id=body.provider,
                model=body.model,
                api_key=body.api_key,
                base_url=body.base_url,
                assessment_id=assessment_id,
                db=db,
                current_user=current_user,
            ):
                yield event
        except Exception as e:
            import json as _json
            yield f"data: {_json.dumps({'type': 'error', 'message': str(e)})}\n\n"

    await log_action(db, session_id=session.id, action_type="chat", reasoning=body.message[:200])
    return StreamingResponse(event_generator(), media_type="text/event-stream")


class AnalyzeRequest(BaseModel):
    output: str
    technique_id: str | None = None
    session_ctx: dict | None = None
    provider: str | None = None
    model: str | None = None
    api_key: str | None = None
    base_url: str | None = None


@router.post("/analyze")
async def analyze(
    body: AnalyzeRequest,
    current_user: PlatformUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Analyze tool output and return structured findings."""
    session = await get_or_create_session(db, current_user.id)
    result = await analyze_output(
        tool_output=body.output,
        technique_id=body.technique_id,
        session_ctx=body.session_ctx,
        provider_id=body.provider,
        model=body.model,
        api_key=body.api_key,
        base_url=body.base_url,
    )
    await log_action(db, session_id=session.id, action_type="analyze", technique_id=body.technique_id)
    return result


class ExplainRequest(BaseModel):
    technique_id: str
    target_env: dict | None = None
    provider: str | None = None
    model: str | None = None


@router.post("/explain")
async def explain(
    body: ExplainRequest,
    current_user: PlatformUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Deep technique explanation: what, why, OPSEC, detection."""
    session = await get_or_create_session(db, current_user.id)
    result = await explain_technique(
        technique_id=body.technique_id,
        target_env=body.target_env,
        provider_id=body.provider,
        model=body.model,
    )
    await log_action(db, session_id=session.id, action_type="explain", technique_id=body.technique_id)
    return result


class ReportRequest(BaseModel):
    findings: list[dict] = Field(default_factory=list)
    session_ctx: dict | None = None
    severity_summary: dict | None = None
    provider: str | None = None
    model: str | None = None


@router.post("/generate-report")
async def generate_report(
    body: ReportRequest,
    current_user: PlatformUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Generate professional pentest report narrative from findings."""
    session = await get_or_create_session(db, current_user.id)
    narrative = await generate_report_narrative(
        findings=body.findings,
        session_ctx=body.session_ctx,
        severity_summary=body.severity_summary,
        provider_id=body.provider,
        model=body.model,
    )
    await log_action(db, session_id=session.id, action_type="report_generate")
    return {"narrative": narrative}


class BloodHoundRequest(BaseModel):
    data: dict
    provider: str | None = None
    model: str | None = None


@router.post("/analyze-bloodhound")
async def analyze_bh(
    body: BloodHoundRequest,
    current_user: PlatformUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Analyze BloodHound JSON export for attack paths."""
    session = await get_or_create_session(db, current_user.id)
    result = await analyze_bloodhound(
        bh_data=body.data,
        provider_id=body.provider,
        model=body.model,
    )
    await log_action(db, session_id=session.id, action_type="bloodhound_analyze")
    return result
