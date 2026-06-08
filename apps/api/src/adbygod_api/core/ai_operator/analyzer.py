from __future__ import annotations

import json
import logging

from adbygod_api.data.ad_commands import AD_COMMANDS
from .providers.base import ChatMessage
from .providers.router import get_provider

log = logging.getLogger(__name__)


async def analyze_output(
    tool_output: str,
    technique_id: str | None = None,
    session_ctx: dict | None = None,
    provider_id: str | None = None,
    model: str | None = None,
    api_key: str | None = None,
    base_url: str | None = None,
) -> dict:
    """
    Analyze raw tool output and return structured findings.
    Returns: {summary, key_findings, next_steps, mitre_ids, severity}
    """
    provider = get_provider(provider_id)
    technique_hint = ""
    if technique_id:
        tech = next((t for t in AD_COMMANDS if t["id"] == technique_id), None)
        if tech:
            technique_hint = f"\nThis output is from: {tech['title']} ({tech.get('mitre_technique_id', '')})"

    system = """You are an expert Active Directory penetration tester analyzing tool output.
Extract key findings, credentials, vulnerabilities, and attack paths from raw output.
Output ONLY valid JSON — no prose outside JSON."""

    user = f"""Analyze this tool output from an authorized AD assessment:{technique_hint}

```
{tool_output[:6000]}
```

Session context: {json.dumps(session_ctx or {}, indent=2)}

Return JSON:
{{
  "summary": "one sentence summary",
  "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
  "key_findings": ["finding 1", "finding 2"],
  "credentials_found": ["user:hash or description"],
  "attack_paths_opened": ["what this enables"],
  "next_techniques": ["technique description with tool"],
  "mitre_ids": ["T1234"],
  "opsec_notes": "opsec considerations"
}}"""

    msgs = [ChatMessage(role="system", content=system), ChatMessage(role="user", content=user)]
    raw = await provider.complete(msgs, model=model, max_tokens=1000, temperature=0.2, api_key=api_key, base_url=base_url)
    raw = raw.strip()
    if raw.startswith("```"):
        raw = "\n".join(raw.split("\n")[1:])
        if raw.endswith("```"):
            raw = raw[:-3]
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return {"summary": raw[:500], "severity": "INFO", "key_findings": [], "credentials_found": [], "attack_paths_opened": [], "next_techniques": [], "mitre_ids": [], "opsec_notes": ""}


async def explain_technique(
    technique_id: str,
    target_env: dict | None = None,
    provider_id: str | None = None,
    model: str | None = None,
) -> dict:
    """
    Explain a technique in depth: what, why, how, OPSEC, detection, defense.
    Returns: {explanation, commands, opsec, detection_indicators, mitre_link, difficulty}
    """
    provider = get_provider(provider_id)
    tech = next((t for t in AD_COMMANDS if t["id"] == technique_id), None)
    if not tech:
        return {"error": f"Technique {technique_id!r} not found"}

    env_hint = f"\nTarget environment: {json.dumps(target_env)}" if target_env else ""

    system = "You are an expert AD pentester providing deep technique analysis. Output ONLY valid JSON."
    user = f"""Explain this technique for an authorized assessment:{env_hint}

Technique: {tech['title']}
ID: {tech['id']}
Category: {tech['category']}
MITRE: {tech.get('mitre_technique_id', 'N/A')}
Tool: {tech['tool']}
Description: {tech['description']}

Commands:
{json.dumps(tech.get('commands', []), indent=2)}

Return JSON:
{{
  "what": "what this technique does in 2-3 sentences",
  "why_effective": "why this works against AD",
  "step_by_step": ["step 1", "step 2", "step 3"],
  "prerequisites": ["prereq 1"],
  "expected_output": "what successful output looks like",
  "opsec_rating": "NOISY|MEDIUM|STEALTHY",
  "opsec_notes": "specific OPSEC considerations",
  "detection_indicators": ["event ID / log entry that detects this"],
  "defensive_mitigations": ["how defenders can prevent/detect"],
  "difficulty": "EASY|MEDIUM|HARD",
  "real_world_note": "real-world context about this technique"
}}"""

    msgs = [ChatMessage(role="system", content=system), ChatMessage(role="user", content=user)]
    raw = await provider.complete(msgs, model=model, max_tokens=1500, temperature=0.2)
    raw = raw.strip()
    if raw.startswith("```"):
        raw = "\n".join(raw.split("\n")[1:])
        if raw.endswith("```"):
            raw = raw[:-3]
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return {"what": raw[:1000], "why_effective": "", "step_by_step": [], "prerequisites": [], "expected_output": "", "opsec_rating": "UNKNOWN", "opsec_notes": "", "detection_indicators": [], "defensive_mitigations": [], "difficulty": "MEDIUM", "real_world_note": ""}


async def generate_report_narrative(
    findings: list[dict],
    session_ctx: dict | None = None,
    severity_summary: dict | None = None,
    provider_id: str | None = None,
    model: str | None = None,
) -> str:
    """
    Generate a professional pentest report narrative from raw findings.
    Returns: markdown-formatted executive summary and technical narrative.
    """
    provider = get_provider(provider_id)
    system = """You are an expert penetration testing report writer.
Write professional, clear, technically accurate pentest report sections.
Use markdown formatting. Be specific about impact and risk.
Never exaggerate but do not downplay critical risks."""

    user = f"""Write a penetration test report narrative for this Active Directory assessment.

Session context: {json.dumps(session_ctx or {}, indent=2)}
Severity breakdown: {json.dumps(severity_summary or {}, indent=2)}
Key findings ({len(findings)} total): {json.dumps(findings[:20], indent=2)}

Write:
1. **Executive Summary** (3-4 sentences, business risk language, suitable for C-level)
2. **Attack Narrative** (chronological story of the attack path taken, technical but readable)
3. **Critical Findings** (for each CRITICAL finding: what was found, impact, evidence)
4. **Risk Summary** (overall risk rating and key recommendations)

Use markdown headers, bullet points, and code blocks where appropriate."""

    msgs = [ChatMessage(role="system", content=system), ChatMessage(role="user", content=user)]
    return await provider.complete(msgs, model=model, max_tokens=4000, temperature=0.4)


async def analyze_bloodhound(
    bh_data: dict,
    provider_id: str | None = None,
    model: str | None = None,
) -> dict:
    """
    Analyze BloodHound JSON export and return attack path insights.
    Returns: {attack_paths, privileged_targets, quick_wins, recommendations}
    """
    provider = get_provider(provider_id)
    system = "You are an expert BloodHound analyst. Analyze AD graph data and identify attack paths. Output ONLY valid JSON."

    # Extract key stats from BH data without sending everything
    summary = {
        "domain_count": len(bh_data.get("domains", [])),
        "user_count": len(bh_data.get("users", [])),
        "computer_count": len(bh_data.get("computers", [])),
        "group_count": len(bh_data.get("groups", [])),
        "acl_abuses": [e for e in bh_data.get("edges", []) if e.get("type") in ("GenericAll", "GenericWrite", "WriteDacl", "WriteOwner", "Owns")][:20],
        "kerberoastable": [u for u in bh_data.get("users", []) if u.get("props", {}).get("hasspn")][:20],
        "asreproastable": [u for u in bh_data.get("users", []) if u.get("props", {}).get("dontreqpreauth")][:20],
        "unconstrained_delegation": [c for c in bh_data.get("computers", []) if c.get("props", {}).get("unconstraineddelegation")][:10],
        "high_value_targets": [n for n in bh_data.get("nodes", []) if n.get("props", {}).get("highvalue")][:20],
    }

    user = f"""Analyze this BloodHound data summary from an authorized AD assessment:

{json.dumps(summary, indent=2)}

Return JSON:
{{
  "attack_paths": ["path description prioritized by impact"],
  "quick_wins": ["technique: target (reason)"],
  "privileged_targets": ["account or computer with why it's valuable"],
  "lateral_movement_vectors": ["specific lateral movement opportunities"],
  "domain_escalation_paths": ["paths to domain admin"],
  "recommendations": ["defensive recommendation"],
  "risk_rating": "CRITICAL|HIGH|MEDIUM|LOW"
}}"""

    msgs = [ChatMessage(role="system", content=system), ChatMessage(role="user", content=user)]
    raw = await provider.complete(msgs, model=model, max_tokens=2000, temperature=0.2)
    raw = raw.strip()
    if raw.startswith("```"):
        raw = "\n".join(raw.split("\n")[1:])
        if raw.endswith("```"):
            raw = raw[:-3]
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return {"attack_paths": [], "quick_wins": [], "privileged_targets": [], "lateral_movement_vectors": [], "domain_escalation_paths": [], "recommendations": [], "risk_rating": "UNKNOWN"}
