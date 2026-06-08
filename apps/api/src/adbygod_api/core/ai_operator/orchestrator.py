from __future__ import annotations

import json
import logging
from dataclasses import dataclass

from adbygod_api.data.ad_commands import AD_COMMANDS
from .providers.base import ChatMessage
from .providers.router import get_provider

log = logging.getLogger(__name__)
CLAUDE_MODEL = "claude-sonnet-4-6"  # kept for compat, use provider router

SYSTEM_PROMPT = """You are an expert Active Directory penetration tester acting as an AI operator assistant.
Analyze the current engagement state and suggest the most impactful next technique.

Rules:
- Only suggest techniques from the provided catalog
- Provide clear reasoning based on current findings
- Consider phase dependencies: enumeration before privilege escalation
- Output ONLY valid JSON, no prose outside the JSON

Output format:
{
  "technique_id": "exact-id-from-catalog",
  "title": "technique title",
  "reason": "why this technique now",
  "expected_outcome": "what success looks like",
  "mitre_id": "T1234.001",
  "phase_id": 2,
  "prerequisites_met": true,
  "auth_level_promotion": false,
  "requires_human_approval": false
}"""


@dataclass
class Suggestion:
    technique_id: str
    title: str
    reason: str
    expected_outcome: str
    mitre_id: str
    phase_id: int
    prerequisites_met: bool
    auth_level_promotion: bool
    requires_human_approval: bool


def _build_context(session: dict, kill_chain_phases: list, recent_findings: list, phase_scope: list) -> str:
    return json.dumps({
        "session": {
            "target_ip": session.get("target_ip"),
            "domain": session.get("domain"),
            "auth_level": session.get("auth_level"),
            "commands_run": session.get("commands_run", 0),
            "findings_count": session.get("findings_count", 0),
            "machines_owned": session.get("machines_owned", 0),
        },
        "kill_chain": kill_chain_phases,
        "recent_findings": recent_findings[:10],
        "phase_scope": phase_scope,
        "available_techniques": [
            {"id": t["id"], "category": t.get("category", ""), "title": t.get("title", t["id"]),
             "risk_level": t.get("risk_level", t.get("risk", "medium")),
             "requires_opt_in": t.get("requires_opt_in", t.get("requires_approval", False)),
             "mitre": t.get("mitre_technique_id", t.get("mitre_id", ""))}
            for t in AD_COMMANDS if t.get("executable_on_linux", True)
        ][:100],
    }, indent=2)


def _extract_json(raw: str) -> dict:
    """Extract a JSON object from an LLM response that may include markdown fences or prose."""
    raw = raw.strip()
    # Strip markdown code fences
    if "```" in raw:
        parts = raw.split("```")
        for part in parts:
            p = part.strip()
            if p.startswith("json"):
                p = p[4:].strip()
            if p.startswith("{"):
                raw = p
                break
    # Find first { … } block
    start = raw.find("{")
    end = raw.rfind("}")
    if start != -1 and end != -1 and end > start:
        raw = raw[start:end + 1]
    return json.loads(raw)


async def get_next_suggestion(
    session: dict,
    kill_chain_phases: list,
    recent_findings: list,
    phase_scope: list,
    excluded_ids: list,
    provider_id: str | None = None,
    model: str | None = None,
    api_key: str | None = None,
    base_url: str | None = None,
) -> Suggestion:
    provider = get_provider(provider_id)
    context = _build_context(session, kill_chain_phases, recent_findings, phase_scope)
    msgs = [
        ChatMessage(role="system", content=SYSTEM_PROMPT),
        ChatMessage(role="user", content=(
            f"Engagement state:\n{context}\n\n"
            f"Exclude these IDs: {excluded_ids}\n\n"
            "Suggest next technique. Respond with ONLY a JSON object, no prose:\n"
            '{"technique_id":"...","title":"...","reason":"...","expected_outcome":"...", '
            '"mitre_id":"T1XXX","phase_id":0,"prerequisites_met":true,'
            '"auth_level_promotion":false,"requires_human_approval":false}'
        )),
    ]
    raw = await provider.complete(msgs, model=model, max_tokens=600, temperature=0.2, api_key=api_key, base_url=base_url)
    if not raw or not raw.strip():
        raise ValueError(f"Provider '{provider_id or 'default'}' returned an empty response. Check that the model is running and has enough context.")
    try:
        data = _extract_json(raw)
    except json.JSONDecodeError as exc:
        log.error("Suggestion JSON parse failed. Raw: %s", raw[:300])
        raise ValueError(f"Model response was not valid JSON: {exc}. Raw preview: {raw[:150]}") from exc

    return Suggestion(
        technique_id=data.get("technique_id", "recon-001"),
        title=data.get("title", "Unknown technique"),
        reason=data.get("reason", ""),
        expected_outcome=data.get("expected_outcome", ""),
        mitre_id=data.get("mitre_id", ""),
        phase_id=int(data.get("phase_id", 0)),
        prerequisites_met=bool(data.get("prerequisites_met", True)),
        auth_level_promotion=bool(data.get("auth_level_promotion", False)),
        requires_human_approval=bool(data.get("requires_human_approval", False)),
    )


async def generate_playbook(session: dict, phase_scope: list, excluded_ids: list, provider_id: str | None = None, model: str | None = None, api_key: str | None = None, base_url: str | None = None) -> list[dict]:
    provider = get_provider(provider_id)
    context = _build_context(session, [], [], phase_scope)
    msgs = [
        ChatMessage(role="system", content="""You are an expert AD penetration tester. Generate a prioritized engagement playbook.
Output a JSON array ordered by recommended execution sequence.
Each element: {"technique_id": "...", "title": "...", "phase_id": N, "reason": "...", "mitre_id": "..."}
Output ONLY the JSON array."""),
        ChatMessage(role="user", content=f"Generate playbook for:\n{context}\n\nExclude: {excluded_ids}"),
    ]
    raw = await provider.complete(msgs, model=model, max_tokens=2000, temperature=0.2, api_key=api_key, base_url=base_url)
    raw = raw.strip()
    if raw.startswith("```"):
        raw = raw.split("```")[1]
        if raw.startswith("json"):
            raw = raw[4:]
    return json.loads(raw)
