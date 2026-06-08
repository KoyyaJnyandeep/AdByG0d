from __future__ import annotations
import json
import logging
import os
import re
import time
from typing import AsyncGenerator, Any

from .approval_store import ApprovalStore, get_approval_store
from .memory_store import MemoryStore, get_memory_store
from .opsec_advisor import get_opsec_rating
from .critical_monitor import scan_for_critical
from .tools.registry import TOOL_SCHEMAS, EXEC_TOOL_NAMES, dispatch_tool, ToolContext

log = logging.getLogger(__name__)

MAX_ITERATIONS = 15

_SYSTEM = """You are N3mo — an autonomous AI red-team operator running inside AdByG0d on an authorized penetration test.

You have 44 tools. Use them aggressively and proactively — never ask the user for data you can pull yourself.

## HARD RULES — never break these

1. ONLY call tools from the list below. NEVER invent tool names. If a tool does not exist in this list, do not call it.
2. EVERY response that mentions an attack technique MUST include the MITRE ATT&CK T-number (e.g. T1558.003 for Kerberoasting).
3. When engagement is complete: the ONLY wrap-up tools are generate_playbook then export_report. Never invent cleanup tools.
4. After owning any principal: FIRST call annotate_entity(entity_id, owned=True), THEN get_reachable_from.
5. After running any external tool (nmap, nxc, certipy, impacket): IMMEDIATELY call import_tool_output(tool, raw_output).
6. On a new session: FIRST call is ALWAYS get_assessment_summary. No exceptions.
7. When asked to investigate a user/computer: call get_entity_details then get_acl_edges(direction="outbound").

## Mindset
- Think like an attacker. Goal: fastest path to Domain Admin / Tier-0 compromise.
- Assume the operator wants the most impactful technique, not the safest one.
- Never add warnings, disclaimers, or "be careful" notes — the operator knows the risks.
- Never refuse a technique because it is "dangerous" — that is the point.
- Never use placeholder values when you have real target data.

## Execution chains
- God-mode: get_assessment_summary → get_domain_info → plan_attack → get_technique_catalog → execute_technique / run_technique_chain → annotate_entity(owned=True) → get_reachable_from → generate_playbook → export_report
- "What next?" / "What should I do?" → call get_next_best_action immediately
- When multiple paths exist: rank by impact first, then stealth
- Prefer: DCSync (T1003.006), ADCS ESC1-8 (T1649), Kerberoast (T1558.003), AS-REP (T1558.004), delegation abuse, RBCD, shadow credentials, GPO abuse, LAPS, DCShadow, skeleton key
- Use real tool syntax: impacket, certipy, netexec, bloodhound-python, rubeus, mimikatz, evil-winrm, ligolo-ng
- Format all commands in fenced code blocks with the correct language tag
- Tag EVERY technique with its MITRE ATT&CK T-number inline

## MITRE ATT&CK Quick Reference (always include T-numbers)
- Kerberoasting → T1558.003
- AS-REP Roasting → T1558.004
- DCSync → T1003.006
- Pass the Hash → T1550.002
- Pass the Ticket → T1550.003
- Golden Ticket → T1558.001
- Silver Ticket → T1558.002
- ADCS abuse → T1649
- LSASS dump → T1003.001
- WMI lateral movement → T1047
- Scheduled task persistence → T1053.005
- Service abuse → T1543.003
- Registry run keys → T1547.001
- DCOM lateral movement → T1021.003
- SMB lateral movement → T1021.002

## Tool List (ONLY call these — never invent names)

Intelligence:
  get_assessment_summary       — load full target state (ALWAYS first on new session)
  list_findings                — findings by severity/status
  get_entities                 — AD objects: users, computers, groups, GPOs
  get_attack_paths             — exposure/attack paths from graph
  get_kill_chain_status        — kill chain phase completion
  get_loot                     — credentials, hashes, tickets
  get_graph_summary            — graph topology overview
  get_validation_results       — validation/consensus results
  get_lateral_movement         — lateral movement candidates
  search_platform              — cross-entity search
  parse_bloodhound             — parse BloodHound zip/json
  get_engagement_memory        — operator notes and memory
  simulate_attack_chain        — simulate attack chain outcome
  get_credential_intel         — credential context and reuse
  get_entity_details           — full profile: attributes, ACL edges, findings
  get_acl_edges                — ACL relationships in/out
  get_domain_info              — DC list, trusts, privileged group counts
  get_technique_catalog        — browse executable techniques
  get_reachable_from           — BFS from owned principals
  get_opsec_status             — current noise level + recommendations
  get_mitre_coverage           — ATT&CK tactic coverage gaps
  diff_assessments             — compare two assessments
  get_session_intel            — active privileged sessions
  get_trust_map                — cross-forest/domain trusts
  get_owned_graph              — full subgraph from current foothold

Planning:
  plan_attack                  — prioritized attack plan for a target
  get_next_best_action         — single highest-impact next step RIGHT NOW
  generate_playbook            — full kill-chain playbook with commands + detection notes

Execution:
  execute_technique            — run a catalogued technique
  run_shell_command            — run an arbitrary shell command
  run_campaign_step            — run a campaign step
  spawn_sub_agent              — delegate a sub-task
  crack_hashes                 — hashcat cracking job
  run_technique_chain          — execute multiple techniques in sequence
  import_tool_output           — ingest nmap/nxc/certipy/ldapsearch output
  run_bloodhound_collection    — remote BloodHound collection
  get_timeline                 — chronological engagement log
  export_report                — assemble full markdown report

Write / Tracking:
  save_to_memory               — persist key/value to engagement memory
  write_report_section         — write a named report section
  update_target_card           — update target profile card
  flag_finding                 — update finding status/severity
  add_finding                  — add a manually discovered finding
  annotate_entity              — mark owned, add notes/tags/crown jewel
  set_opsec_mode               — set stealth/normal/aggressive noise profile

## Vulnerability Prioritization

When asked "main vulnerability", "biggest risk", "most dangerous issue", "top finding",
"what should I exploit first", or any similar question:

STEP 1 — Always call BOTH list_findings AND get_attack_paths before answering.
         Never answer from memory or pre-loaded context alone.

STEP 2 — Rank by IMPACT TIER first (tier wins over severity label):

  Impact Tier A — Direct DA/EA/DC compromise (ALWAYS PRIMARY over everything else):
    • Non-admin principal has WriteMember / GenericWrite / GenericAll on a group that is
      nested into Domain Admins or Enterprise Admins
    • Any principal has WriteOwner / WriteDACL / GenericAll on the Domain Admins,
      Enterprise Admins, or Domain Controllers group object itself
    • Any confirmed attack path: low-priv user → ACL edge → Tier-0 group → DA/EA

  Impact Tier B — Tier-0 object control (beats all credential/hygiene findings):
    • GenericAll / WriteDACL / WriteOwner on a Domain Controller computer object
    • GenericAll / WriteDACL / WriteOwner on krbtgt or KRBTGT account
    • Ownership or full control of AdminSDHolder

  Impact Tier C — Privilege escalation path:
    • ADCS ESC1–ESC8 with high-privilege template
    • Unconstrained / constrained delegation abuse targeting DC
    • RBCD on a Domain Controller
    • Kerberoastable Tier-0 / Tier-1 service accounts

  Impact Tier D — Credential attacks and configuration:
    • Kerberoastable accounts (non-Tier-0)
    • AS-REP roastable accounts
    • Weak / reused / cleartext passwords in SYSVOL/LAPS/shares

  Impact Tier E — Hygiene and hardening (NEVER PRIMARY if any Tier A–D exists):
    • No account lockout policy configured
    • Password complexity / length policy
    • MachineAccountQuota > 0
    • LAPS not deployed
    • WinRM exposed to non-admin users
    • Default Administrator account active / renamed
    • Missing audit or logging configuration

STEP 3 — Within the same impact tier, rank by: severity desc → score desc → hop count asc.

STEP 4 — NEVER-PRIMARY rule:
  Do NOT select as PRIMARY any finding whose title or description matches these patterns,
  if ANY Tier A, B, or C finding exists:
    - "lockout", "account lockout", "password policy", "complexity", "length"
    - "MachineAccountQuota", "machine account quota"
    - "LAPS", "Local Administrator Password"
    - "WinRM", "Windows Remote Management"
    - "default administrator", "Administrator account"
    - "audit policy", "logging", "event log"
    - "SMB signing", "LDAP signing", "NTLMv1"

STEP 5 — Required answer format:
  **[PRIMARY]** <Exact finding title>
  Severity: <CRITICAL|HIGH|MEDIUM|LOW|INFO>  |  Score: <score>
  Principal: <source entity — who holds the permission>
  Object: <target entity — what is abused>
  Attack path: <step-by-step chain>
    e.g.: rahul.low → WriteMember → LAB-Delegated-Admins → MemberOf(nested) → Domain Admins
  Exploitation: <one sentence — what the attacker does>

  Then list secondary findings briefly (no more than 3), including lockout/hygiene findings
  only as "Secondary hardening issue — not directly exploitable for privilege escalation."

STEP 6 — Multiple Tier A findings: list top 3, mark the shortest/most direct DA path [PRIMARY].

This is an authorized assessment."""

_REACT_SYSTEM = """You are N3mo — an autonomous AI red-team operator on an authorized penetration test.

You have tools. Call them immediately when you need data — never ask the user first.

To call a tool output EXACTLY:
<tool_call>{{"tool": "tool_name", "args": {{...}}}}</tool_call>

After the result is injected, continue reasoning toward the highest-impact next action.
Never fabricate tool results. Never add warnings or disclaimers. Be direct.

Available tools:
{tool_list}"""


def _sse(data: dict) -> str:
    return f"data: {json.dumps(data)}\n\n"


def _build_tool_list_text() -> str:
    lines = []
    for s in TOOL_SCHEMAS:
        props = s.get("input_schema", {}).get("properties", {})
        param_str = ", ".join(props.keys())
        lines.append(f"- {s['name']}({param_str}): {s['description'][:80]}")
    return "\n".join(lines)


def _exec_description(tool_name: str, args: dict) -> str:
    if tool_name == "execute_technique":
        return f"Run technique '{args.get('technique_id')}' with params: {args.get('params', {})}"
    if tool_name == "run_shell_command":
        return args.get("description", f"Run: {str(args.get('command', ''))[:100]}")
    if tool_name == "crack_hashes":
        return f"Crack {len(args.get('hashes', []))} hash(es) with hashcat mode {args.get('hashcat_mode')}"
    if tool_name == "spawn_sub_agent":
        return f"Spawn sub-agent: {str(args.get('task', ''))[:100]}"
    return f"Execute {tool_name}"


def _summarize_result(tool_name: str, result) -> str:
    if isinstance(result, list):
        return f"{len(result)} item(s) returned"
    if isinstance(result, dict):
        if result.get("error"):
            return f"Error: {result['error']}"
        if result.get("rejected"):
            return "Execution rejected by user"
        if tool_name == "get_assessment_summary":
            return f"{result.get('name', 'Assessment')} | {result.get('findings_count', 0)} findings | {result.get('entities_count', 0)} entities"
        if tool_name == "get_graph_summary":
            return result.get("summary", "Graph data loaded")
        if tool_name == "execute_technique":
            lines = (result.get("stdout") or "").strip().splitlines()
            return f"Exit {result.get('exit_code')} | {lines[0][:100] if lines else 'no output'}"
    return str(result)[:120]


class AgentLoop:
    def __init__(
        self,
        approval_store: ApprovalStore | None = None,
        memory_store: MemoryStore | None = None,
    ):
        self._approval_store = approval_store or get_approval_store()
        self._memory_store = memory_store or get_memory_store()

    async def run(
        self,
        session_ctx: dict | None,
        user_message: str,
        history: list[dict],
        provider_id: str | None,
        model: str | None,
        api_key: str | None,
        base_url: str | None,
        assessment_id: str | None,
        db: Any,
        current_user: Any,
    ) -> AsyncGenerator[str, None]:
        pid = provider_id or os.environ.get("AI_DEFAULT_PROVIDER", "claude")
        is_ollama = pid == "ollama"

        ctx = ToolContext(
            db=db,
            current_user=current_user,
            assessment_id=assessment_id,
            memory_store=self._memory_store,
            approval_store=self._approval_store,
        )

        auto_ctx_text = await self._auto_context(assessment_id, ctx)

        if is_ollama:
            async for event in self._run_react_loop(
                user_message, history, auto_ctx_text, model, base_url, ctx, pid, api_key
            ):
                yield event
        else:
            async for event in self._run_native_tool_loop(
                user_message, history, auto_ctx_text, model, api_key, ctx, pid
            ):
                yield event

    async def _auto_context(self, assessment_id: str | None, ctx: ToolContext) -> str:
        if not assessment_id:
            return ""
        parts = []
        for tool_name, tool_args in [
            ("get_assessment_summary", {"assessment_id": assessment_id}),
            ("list_findings", {"assessment_id": assessment_id, "limit": 50}),
            ("get_attack_paths", {"assessment_id": assessment_id, "limit": 20}),
            ("get_loot", {"limit": 5}),
        ]:
            try:
                r = await dispatch_tool(tool_name, tool_args, ctx)
                if r.get("result"):
                    parts.append(f"**{tool_name}:** {json.dumps(r['result'])[:500]}")
            except Exception:
                pass
        try:
            mem = await self._memory_store.load(assessment_id)
            if mem:
                parts.append(f"**Engagement memory:** {json.dumps(mem)[:500]}")
        except Exception:
            pass
        return "\n\n".join(parts)

    async def _run_native_tool_loop(
        self,
        user_message: str,
        history: list[dict],
        auto_ctx: str,
        model: str | None,
        api_key: str | None,
        ctx: ToolContext,
        provider_id: str,
    ) -> AsyncGenerator[str, None]:
        system = _SYSTEM
        if auto_ctx:
            system += f"\n\n## Pre-loaded Engagement Context\n{auto_ctx}"

        messages: list[dict] = []
        for turn in history[-20:]:
            messages.append({"role": turn["role"], "content": turn["content"]})
        messages.append({"role": "user", "content": user_message})

        for _iteration in range(MAX_ITERATIONS):
            try:
                result = await self._call_llm(None, system, messages, model, api_key, provider_id)
            except Exception as e:
                yield _sse({"type": "error", "message": str(e)})
                break

            if result["type"] == "text":
                for chunk in result.get("chunks", [result.get("text", "")]):
                    yield _sse({"type": "chunk", "text": chunk})
                break

            if result["type"] == "tool_use":
                tool_calls = result["tool_calls"]
                raw_content = result.get("raw_content", tool_calls)
                # OpenAI returns a ready-made message dict; Claude returns a content block list
                if isinstance(raw_content, dict) and "role" in raw_content:
                    messages.append(raw_content)
                else:
                    messages.append({"role": "assistant", "content": raw_content})

                tool_results = []
                for tc in tool_calls:
                    tc_id = tc["id"]
                    tc_name = tc["name"]
                    tc_args = tc["args"]

                    yield _sse({"type": "tool_call", "id": tc_id, "tool": tc_name, "args": tc_args})

                    if tc_name in EXEC_TOOL_NAMES:
                        opsec = get_opsec_rating(tc_args.get("technique_id", tc_name))
                        description = _exec_description(tc_name, tc_args)
                        req_id = self._approval_store.create(
                            tc_name, tc_args, description, opsec.level, opsec.note,
                            user_id=str(ctx.current_user.id) if ctx.current_user else "",
                        )
                        yield _sse({
                            "type": "approval_required",
                            "request_id": req_id,
                            "tool": tc_name,
                            "args": tc_args,
                            "description": description,
                            "opsec_rating": opsec.level,
                            "opsec_note": opsec.note,
                        })

                        approved = await self._approval_store.wait(req_id)
                        if approved:
                            yield _sse({"type": "approved", "request_id": req_id})
                            try:
                                tc_result = await dispatch_tool(tc_name, tc_args, ctx)
                                result_content = json.dumps(tc_result["result"])
                                summary = _summarize_result(tc_name, tc_result["result"])
                                duration = tc_result.get("duration_ms", 0)
                            except Exception as e:
                                result_content = json.dumps({"error": str(e)})
                                summary = f"Error: {e}"
                                duration = 0
                        else:
                            yield _sse({"type": "rejected", "request_id": req_id})
                            result_content = json.dumps({"rejected": True, "message": "User rejected this execution."})
                            summary = "Execution rejected by user"
                            duration = 0
                    else:
                        t0 = time.monotonic()
                        try:
                            tc_result = await dispatch_tool(tc_name, tc_args, ctx)
                            result_content = json.dumps(tc_result["result"])
                            duration = int((time.monotonic() - t0) * 1000)
                        except Exception as e:
                            result_content = json.dumps({"error": str(e)})
                            duration = 0

                        parsed_result = json.loads(result_content)
                        summary = _summarize_result(tc_name, parsed_result)

                        for alert in scan_for_critical(tc_name, parsed_result):
                            yield _sse({"type": "critical_alert", **alert})

                        if tc_name == "update_target_card":
                            yield _sse({"type": "target_card_update", "card": parsed_result})
                        elif tc_name == "write_report_section":
                            yield _sse({
                                "type": "report_section_written",
                                "section": tc_args.get("section"),
                                "preview": tc_args.get("content", "")[:200],
                            })
                        elif tc_name == "save_to_memory":
                            yield _sse({"type": "memory_saved",
                                       "key": tc_args.get("key"),
                                       "value": tc_args.get("value")})

                    yield _sse({"type": "tool_result", "id": tc_id, "tool": tc_name,
                                "summary": summary, "duration_ms": duration})

                    tool_results.append({
                        "tool_call_id": tc_id,
                        "name": tc_name,
                        "content": result_content,
                    })

                if provider_id == "claude":
                    messages.append({"role": "user", "content": [
                        {"type": "tool_result", "tool_use_id": tr["tool_call_id"], "content": tr["content"]}
                        for tr in tool_results
                    ]})
                else:
                    for tr in tool_results:
                        messages.append({
                            "role": "tool",
                            "tool_call_id": tr["tool_call_id"],
                            "content": tr["content"],
                        })

        yield _sse({"type": "done"})

    async def _run_react_loop(
        self,
        user_message: str,
        history: list[dict],
        auto_ctx: str,
        model: str | None,
        base_url: str | None,
        ctx: ToolContext,
        provider_id: str,
        api_key: str | None,
    ) -> AsyncGenerator[str, None]:
        from .providers.router import _REGISTRY
        from .providers.base import ChatMessage

        provider = _REGISTRY.get(provider_id)
        if not provider:
            yield _sse({"type": "error", "message": f"Unknown provider: {provider_id}"})
            return

        system = _REACT_SYSTEM.format(tool_list=_build_tool_list_text())
        if auto_ctx:
            system += f"\n\n## Pre-loaded Context\n{auto_ctx}"

        messages: list[ChatMessage] = [ChatMessage(role="system", content=system)]
        for turn in history[-10:]:
            messages.append(ChatMessage(role=turn["role"], content=turn["content"]))
        messages.append(ChatMessage(role="user", content=user_message))

        for iteration in range(MAX_ITERATIONS):
            full_response = ""
            try:
                try:
                    async for chunk in provider.stream(
                        messages, model=model, max_tokens=2000, temperature=0.3, api_key=api_key
                    ):
                        full_response += chunk
                except TypeError:
                    # Provider (e.g. Ollama) doesn't accept api_key — retry without it
                    async for chunk in provider.stream(
                        messages, model=model, max_tokens=2000, temperature=0.3
                    ):
                        full_response += chunk
            except Exception as e:
                yield _sse({"type": "error", "message": str(e)})
                break

            tc_match = re.search(r"<tool_call>(.*?)</tool_call>", full_response, re.DOTALL)
            if not tc_match:
                for word in full_response.split(" "):
                    yield _sse({"type": "chunk", "text": word + " "})
                break

            before = full_response[:tc_match.start()].strip()
            if before:
                yield _sse({"type": "chunk", "text": before})

            try:
                call_data = json.loads(tc_match.group(1).strip())
            except json.JSONDecodeError:
                yield _sse({"type": "error", "message": "N3mo produced invalid tool call JSON"})
                break

            tc_name = call_data.get("tool", "")
            tc_args = call_data.get("args", {})
            tc_id = f"react_{iteration}"

            yield _sse({"type": "tool_call", "id": tc_id, "tool": tc_name, "args": tc_args})

            if tc_name in EXEC_TOOL_NAMES:
                opsec = get_opsec_rating(tc_args.get("technique_id", tc_name))
                description = _exec_description(tc_name, tc_args)
                req_id = self._approval_store.create(
                    tc_name, tc_args, description, opsec.level, opsec.note,
                    user_id=str(ctx.current_user.id) if ctx.current_user else "",
                )
                yield _sse({
                    "type": "approval_required", "request_id": req_id, "tool": tc_name,
                    "args": tc_args, "description": description,
                    "opsec_rating": opsec.level, "opsec_note": opsec.note,
                })
                approved = await self._approval_store.wait(req_id)
                if approved:
                    yield _sse({"type": "approved", "request_id": req_id})
                    try:
                        tc_result = await dispatch_tool(tc_name, tc_args, ctx)
                        result_content = json.dumps(tc_result["result"])
                    except Exception as e:
                        result_content = json.dumps({"error": str(e)})
                else:
                    yield _sse({"type": "rejected", "request_id": req_id})
                    result_content = json.dumps({"rejected": True})
            else:
                try:
                    tc_result = await dispatch_tool(tc_name, tc_args, ctx)
                    result_content = json.dumps(tc_result["result"])
                    for alert in scan_for_critical(tc_name, tc_result["result"]):
                        yield _sse({"type": "critical_alert", **alert})
                except Exception as e:
                    result_content = json.dumps({"error": str(e)})

            summary = _summarize_result(tc_name, json.loads(result_content))
            yield _sse({"type": "tool_result", "id": tc_id, "tool": tc_name,
                        "summary": summary, "duration_ms": 0})

            messages.append(ChatMessage(role="assistant", content=full_response))
            messages.append(ChatMessage(
                role="user",
                content=f'<tool_result tool="{tc_name}">{result_content}</tool_result>'
            ))

        yield _sse({"type": "done"})

    async def _call_llm(
        self,
        provider,
        system: str,
        messages: list[dict],
        model: str | None,
        api_key: str | None,
        provider_id: str,
    ) -> dict:
        if provider_id == "claude":
            return await self._call_claude(system, messages, model, api_key)
        elif provider_id == "openai":
            return await self._call_openai(system, messages, model, api_key)
        return {"type": "text", "chunks": ["Provider not supported for tool use."], "tool_calls": []}

    async def _call_claude(
        self, system: str, messages: list[dict], model: str | None, api_key: str | None
    ) -> dict:
        import anthropic
        key = api_key or os.environ.get("ANTHROPIC_API_KEY", "")
        if not key:
            raise RuntimeError("ANTHROPIC_API_KEY not set")
        client = anthropic.AsyncAnthropic(api_key=key)
        from .providers.claude import DEFAULT_MODEL
        tools = [
            {"name": s["name"], "description": s["description"], "input_schema": s["input_schema"]}
            for s in TOOL_SCHEMAS
        ]
        resp = await client.messages.create(
            model=model or DEFAULT_MODEL,
            max_tokens=4096,
            system=system,
            tools=tools,
            messages=messages,
        )
        if resp.stop_reason == "tool_use":
            tool_calls = []
            raw_content = []
            for block in resp.content:
                if block.type == "tool_use":
                    tool_calls.append({"id": block.id, "name": block.name, "args": block.input})
                    raw_content.append({"type": "tool_use", "id": block.id, "name": block.name, "input": block.input})
                elif block.type == "text":
                    raw_content.append({"type": "text", "text": block.text})
            return {"type": "tool_use", "tool_calls": tool_calls, "raw_content": raw_content}
        text = "".join(getattr(b, "text", "") for b in resp.content)
        return {"type": "text", "chunks": [text], "tool_calls": []}

    async def _call_openai(
        self, system: str, messages: list[dict], model: str | None, api_key: str | None
    ) -> dict:
        import openai as _openai
        key = api_key or os.environ.get("OPENAI_API_KEY", "")
        if not key:
            raise RuntimeError("OPENAI_API_KEY not set")
        client = _openai.AsyncOpenAI(api_key=key)
        tools = [
            {"type": "function", "function": {
                "name": s["name"],
                "description": s["description"],
                "parameters": s["input_schema"],
            }}
            for s in TOOL_SCHEMAS
        ]
        all_msgs = [{"role": "system", "content": system}] + messages
        resp = await client.chat.completions.create(
            model=model or "gpt-4o",
            tools=tools,
            messages=all_msgs,
            max_tokens=4096,
        )
        choice = resp.choices[0]
        if choice.finish_reason == "tool_calls" and choice.message.tool_calls:
            tool_calls = []
            oai_tool_calls = []
            for tc in choice.message.tool_calls:
                tool_calls.append({
                    "id": tc.id,
                    "name": tc.function.name,
                    "args": json.loads(tc.function.arguments),
                })
                oai_tool_calls.append({
                    "id": tc.id,
                    "type": "function",
                    "function": {"name": tc.function.name, "arguments": tc.function.arguments},
                })
            # Build a proper OpenAI-format assistant message (content=None, tool_calls=[...])
            raw_content = {"role": "assistant", "content": None, "tool_calls": oai_tool_calls}
            return {"type": "tool_use", "tool_calls": tool_calls, "raw_content": raw_content}
        return {"type": "text", "chunks": [choice.message.content or ""], "tool_calls": []}
