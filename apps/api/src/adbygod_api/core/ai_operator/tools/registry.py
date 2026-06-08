from __future__ import annotations
import time
from dataclasses import dataclass
from typing import Any

@dataclass
class ToolContext:
    db: Any            # AsyncSession
    current_user: Any  # PlatformUser
    assessment_id: str | None
    memory_store: Any  # MemoryStore
    approval_store: Any  # ApprovalStore

READ_TOOL_NAMES = {
    "get_assessment_summary", "list_findings", "get_entities",
    "get_attack_paths", "get_kill_chain_status", "get_loot",
    "get_graph_summary", "get_validation_results", "get_lateral_movement",
    "search_platform", "parse_bloodhound", "get_engagement_memory",
    "simulate_attack_chain", "get_credential_intel",
    # god-mode additions
    "get_entity_details", "get_acl_edges", "get_domain_info",
    "get_technique_catalog", "get_reachable_from", "get_opsec_status",
    "get_mitre_coverage", "diff_assessments",
    "get_session_intel", "get_trust_map", "get_owned_graph",
}

WRITE_TOOL_NAMES = {
    "save_to_memory", "write_report_section", "update_target_card",
    # god-mode additions
    "flag_finding", "add_finding", "annotate_entity", "set_opsec_mode",
}

EXEC_TOOL_NAMES = {
    "execute_technique", "run_shell_command", "run_campaign_step",
    "spawn_sub_agent", "crack_hashes",
    # god-mode additions
    "export_report", "run_technique_chain", "import_tool_output",
    "plan_attack", "get_next_best_action", "run_bloodhound_collection",
    "get_timeline", "generate_playbook",
}

TOOL_SCHEMAS: list[dict] = [
    {"name": "get_assessment_summary",
     "description": "Fetch full assessment state: domain, DC IP, status, entity/finding counts.",
     "input_schema": {"type": "object", "properties": {
         "assessment_id": {"type": "string", "description": "Assessment UUID. Omit to use active session assessment."}
     }}},

    {"name": "list_findings",
     "description": "List findings filtered by severity and/or status.",
     "input_schema": {"type": "object", "properties": {
         "assessment_id": {"type": "string"},
         "severity": {"type": "string", "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]},
         "status": {"type": "string", "enum": ["OPEN", "IN_REVIEW", "REMEDIATED", "ACCEPTED", "FALSE_POSITIVE", "REGRESSED",
                                                "open", "confirmed", "false_positive", "resolved"]},
         "limit": {"type": "integer", "default": 20},
     }}},

    {"name": "get_entities",
     "description": "List AD entities (users, computers, groups) with optional search and type filter.",
     "input_schema": {"type": "object", "properties": {
         "assessment_id": {"type": "string"},
         "entity_type": {"type": "string", "enum": ["user", "computer", "group", "gpo", "domain", "ou"]},
         "search": {"type": "string"},
         "limit": {"type": "integer", "default": 30},
     }}},

    {"name": "get_attack_paths",
     "description": "Get exposure paths / attack paths from the graph engine.",
     "input_schema": {"type": "object", "properties": {
         "assessment_id": {"type": "string"},
         "limit": {"type": "integer", "default": 10},
     }}},

    {"name": "get_kill_chain_status",
     "description": "Get kill chain phase completion status for the active assessment.",
     "input_schema": {"type": "object", "properties": {
         "assessment_id": {"type": "string"},
     }}},

    {"name": "get_loot",
     "description": "Fetch captured credentials, hashes, and secrets.",
     "input_schema": {"type": "object", "properties": {
         "limit": {"type": "integer", "default": 20},
     }}},

    {"name": "get_graph_summary",
     "description": "Get graph statistics: node counts, choke points, blast radius.",
     "input_schema": {"type": "object", "properties": {
         "assessment_id": {"type": "string"},
     }}},

    {"name": "get_validation_results",
     "description": "Get expert module validation results (Kerberos posture, ADCS, delegation, etc.).",
     "input_schema": {"type": "object", "properties": {
         "assessment_id": {"type": "string"},
     }}},

    {"name": "get_lateral_movement",
     "description": "Get lateral movement chains and technique paths.",
     "input_schema": {"type": "object", "properties": {
         "assessment_id": {"type": "string"},
     }}},

    {"name": "search_platform",
     "description": "Global search across findings and entities.",
     "input_schema": {"type": "object", "properties": {
         "query": {"type": "string", "description": "Search term"},
         "assessment_id": {"type": "string"},
     }, "required": ["query"]}},

    {"name": "parse_bloodhound",
     "description": "Deep BloodHound analysis: shortest paths to DA, choke points, attack priority.",
     "input_schema": {"type": "object", "properties": {
         "assessment_id": {"type": "string", "description": "Assessment whose BH import to analyze"},
         "owned_principals": {"type": "array", "items": {"type": "string"}, "description": "Currently owned accounts"},
     }}},

    {"name": "get_engagement_memory",
     "description": "Read persistent engagement memory: owned assets, tried techniques, discovered creds, notes.",
     "input_schema": {"type": "object", "properties": {
         "assessment_id": {"type": "string"},
     }}},

    {"name": "simulate_attack_chain",
     "description": "Simulate an attack chain outcome using the graph engine — no execution, pure prediction.",
     "input_schema": {"type": "object", "properties": {
         "assessment_id": {"type": "string"},
         "owned": {"type": "array", "items": {"type": "string"}, "description": "Starting owned principals"},
         "target": {"type": "string", "description": "Target group/user (e.g. 'Domain Admins')"},
     }, "required": ["owned", "target"]}},

    {"name": "get_credential_intel",
     "description": "Analyze captured hashes: type detection, PTH-ready flag, crackability score, wordlist hints.",
     "input_schema": {"type": "object", "properties": {
         "hashes": {"type": "array", "items": {"type": "string"}, "description": "Raw hash strings"},
         "domain": {"type": "string", "description": "Target domain name for wordlist hints"},
     }, "required": ["hashes"]}},

    {"name": "save_to_memory",
     "description": "Save a finding, owned asset, or note to persistent engagement memory.",
     "input_schema": {"type": "object", "properties": {
         "assessment_id": {"type": "string"},
         "key": {"type": "string", "enum": ["owned_accounts", "owned_machines", "tried_techniques",
                                             "failed_techniques", "discovered_creds", "notes",
                                             "kill_chain_progress"]},
         "value": {"description": "Value to append (string or object)"},
     }, "required": ["key", "value"]}},

    {"name": "write_report_section",
     "description": "Draft a report section from current findings and save it to the assessment.",
     "input_schema": {"type": "object", "properties": {
         "assessment_id": {"type": "string"},
         "section": {"type": "string", "enum": ["executive_summary", "attack_narrative",
                                                 "findings_detail", "attack_path_walkthrough",
                                                 "recommendations"]},
         "content": {"type": "string", "description": "Markdown content for the section"},
     }, "required": ["section", "content"]}},

    {"name": "update_target_card",
     "description": "Push an update to the live Target Intelligence Card displayed in the UI.",
     "input_schema": {"type": "object", "properties": {
         "domain": {"type": "string"},
         "domain_name": {"type": "string", "description": "Alias for domain"},
         "dc_ip": {"type": "string"},
         "auth_level": {"type": "string"},
         "owned_accounts": {"type": "array", "items": {"type": "string"}},
         "owned_machines": {"type": "array", "items": {"type": "string"}},
         "findings_critical": {"type": "integer"},
         "hashes_captured": {"type": "integer"},
         "hashes_cracked": {"type": "integer"},
         "paths_to_da": {"type": "integer"},
         "opsec_noise": {"type": "string", "enum": ["LOW", "MEDIUM", "HIGH", "CRITICAL"]},
         "next_best_action": {"type": "string"},
     }}},

    {"name": "execute_technique",
     "description": "Run a platform AD command technique. REQUIRES USER APPROVAL before execution.",
     "input_schema": {"type": "object", "properties": {
         "technique_id": {"type": "string", "description": "Technique ID from AD_COMMANDS catalog"},
         "command_index": {"type": "integer", "default": 0},
         "params": {"type": "object", "description": "Parameter key-value pairs for the command"},
     }, "required": ["technique_id"]}},

    {"name": "run_shell_command",
     "description": "Run an arbitrary shell command on the operator host. REQUIRES USER APPROVAL.",
     "input_schema": {"type": "object", "properties": {
         "command": {"type": "string"},
         "description": {"type": "string", "description": "Human-readable description of what this does"},
         "timeout_seconds": {"type": "integer", "default": 30},
     }, "required": ["command", "description"]}},

    {"name": "run_campaign_step",
     "description": "Execute the next step in an autonomous kill chain campaign. REQUIRES USER APPROVAL.",
     "input_schema": {"type": "object", "properties": {
         "phase": {"type": "string", "enum": ["recon", "enum", "loot", "privesc", "lateral", "da", "report"]},
         "step_description": {"type": "string"},
     }, "required": ["phase", "step_description"]}},

    {"name": "spawn_sub_agent",
     "description": "Launch a parallel sub-agent with a specific task. REQUIRES USER APPROVAL.",
     "input_schema": {"type": "object", "properties": {
         "task": {"type": "string", "description": "What the sub-agent should do"},
         "agent_id": {"type": "string", "description": "Unique ID for this sub-agent"},
     }, "required": ["task", "agent_id"]}},

    {"name": "crack_hashes",
     "description": "Start hash cracking with auto-selected mode and wordlist. REQUIRES USER APPROVAL.",
     "input_schema": {"type": "object", "properties": {
         "hashes": {"type": "array", "items": {"type": "string"}},
         "hashcat_mode": {"type": "integer", "description": "Hashcat mode (1000=NTLM, 13100=TGS, 18200=AS-REP)"},
         "wordlist": {"type": "string", "description": "Path to wordlist. Omit for auto-select."},
     }, "required": ["hashes", "hashcat_mode"]}},

    # ── god-mode READ tools ──────────────────────────────────────────────────
    {"name": "get_entity_details",
     "description": "Full profile of a single AD entity: all attributes, group memberships, SPNs, delegations, last logon, ACL edges held and targeting it, and any findings that reference it.",
     "input_schema": {"type": "object", "properties": {
         "entity_id": {"type": "string", "description": "Entity UUID"},
         "assessment_id": {"type": "string"},
     }, "required": ["entity_id"]}},

    {"name": "get_acl_edges",
     "description": "Query graph ACL edges for an entity. direction=outbound: what this entity can do to others. inbound: who has rights over this entity. both: full picture.",
     "input_schema": {"type": "object", "properties": {
         "entity_id": {"type": "string"},
         "direction": {"type": "string", "enum": ["outbound", "inbound", "both"], "default": "outbound"},
         "assessment_id": {"type": "string"},
         "edge_types": {"type": "array", "items": {"type": "string"}, "description": "Filter to specific edge types e.g. GENERIC_ALL, WRITE_DACL"},
     }, "required": ["entity_id"]}},

    {"name": "get_domain_info",
     "description": "Domain-level settings: FQDN, DC list, functional level, machine account quota, privileged group member counts, trust relationships.",
     "input_schema": {"type": "object", "properties": {
         "assessment_id": {"type": "string"},
     }}},

    {"name": "get_technique_catalog",
     "description": "Browse the AD_COMMANDS technique catalog by category or keyword. Returns technique IDs, titles, tools, risk levels, and MITRE IDs — so you know what can be passed to execute_technique.",
     "input_schema": {"type": "object", "properties": {
         "category": {"type": "string", "description": "Filter by category name (partial match)"},
         "keyword": {"type": "string", "description": "Keyword search in title/description"},
         "platform": {"type": "string", "enum": ["linux", "windows"], "description": "Filter by platform"},
         "executable_only": {"type": "boolean", "description": "Only return Linux-executable techniques", "default": False},
         "limit": {"type": "integer", "default": 20},
     }}},

    {"name": "get_reachable_from",
     "description": "BFS over the graph from owned principals. Returns all reachable entities within max_hops, the edge chain to reach each, and whether any reachable node is Tier-0.",
     "input_schema": {"type": "object", "properties": {
         "principals": {"type": "array", "items": {"type": "string"}, "description": "Owned entity UUIDs or SAM account names"},
         "max_hops": {"type": "integer", "default": 4},
         "assessment_id": {"type": "string"},
         "tier0_only": {"type": "boolean", "description": "Only return paths that reach Tier-0", "default": False},
     }, "required": ["principals"]}},

    {"name": "get_opsec_status",
     "description": "Current OPSEC noise level, techniques run so far, and concrete recommendations to reduce detection risk.",
     "input_schema": {"type": "object", "properties": {
         "assessment_id": {"type": "string"},
     }}},

    {"name": "get_mitre_coverage",
     "description": "Map current findings and executed techniques to MITRE ATT&CK tactics. Shows coverage, gaps, and detection likelihood per tactic.",
     "input_schema": {"type": "object", "properties": {
         "assessment_id": {"type": "string"},
     }}},

    {"name": "diff_assessments",
     "description": "Compare two assessments: new findings, resolved findings, severity changes, new attack paths. For re-test engagements.",
     "input_schema": {"type": "object", "properties": {
         "assessment_id_a": {"type": "string", "description": "Baseline assessment UUID"},
         "assessment_id_b": {"type": "string", "description": "Re-test assessment UUID"},
     }, "required": ["assessment_id_a", "assessment_id_b"]}},

    {"name": "get_session_intel",
     "description": "Active sessions on compromised machines: who is logged into what, privileged session detection, golden ticket opportunities.",
     "input_schema": {"type": "object", "properties": {
         "assessment_id": {"type": "string"},
         "computer_id": {"type": "string", "description": "Filter to sessions on a specific computer"},
     }}},

    {"name": "get_trust_map",
     "description": "Full domain trust relationship map: trust direction, trust type (external/forest/shortcut), SID filtering status, and attack paths across trusts.",
     "input_schema": {"type": "object", "properties": {
         "assessment_id": {"type": "string"},
     }}},

    {"name": "get_owned_graph",
     "description": "Subgraph of everything reachable from currently owned principals — a live attack surface map. Shows all ACL edges, group memberships, and Tier-0 distances from current foothold.",
     "input_schema": {"type": "object", "properties": {
         "assessment_id": {"type": "string"},
         "max_hops": {"type": "integer", "default": 5},
     }}},

    # ── god-mode WRITE tools ─────────────────────────────────────────────────
    {"name": "flag_finding",
     "description": "Update a finding's status and optionally override severity. Use to track confirmed exploitable issues.",
     "input_schema": {"type": "object", "properties": {
         "finding_id": {"type": "string"},
         "status": {"type": "string", "enum": ["OPEN", "IN_REVIEW", "REMEDIATED", "ACCEPTED", "FALSE_POSITIVE", "REGRESSED"]},
         "severity": {"type": "string", "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]},
         "note": {"type": "string", "description": "Operator note explaining the status change"},
     }, "required": ["finding_id", "status"]}},

    {"name": "add_finding",
     "description": "Manually add a finding discovered outside the platform (e.g. from manual enum or custom tool output).",
     "input_schema": {"type": "object", "properties": {
         "assessment_id": {"type": "string"},
         "title": {"type": "string"},
         "description": {"type": "string"},
         "severity": {"type": "string", "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]},
         "module": {"type": "string", "description": "Source module label e.g. 'manual', 'certipy', 'custom'"},
         "mitre_attack_ids": {"type": "array", "items": {"type": "string"}},
         "affected_objects": {"type": "array", "items": {"type": "string"}},
         "remediation": {"type": "string"},
     }, "required": ["title", "severity"]}},

    {"name": "annotate_entity",
     "description": "Tag an entity as owned, add operator notes, set business tags, or update crown jewel / sensitive flags.",
     "input_schema": {"type": "object", "properties": {
         "entity_id": {"type": "string"},
         "owned": {"type": "boolean", "description": "Mark as owned (saves to engagement memory)"},
         "notes": {"type": "string"},
         "business_tags": {"type": "array", "items": {"type": "string"}},
         "is_crown_jewel": {"type": "boolean"},
         "is_sensitive": {"type": "boolean"},
         "assessment_id": {"type": "string"},
     }, "required": ["entity_id"]}},

    {"name": "set_opsec_mode",
     "description": "Switch OPSEC noise mode for the session. stealth=slow+quiet, normal=balanced, aggressive=fast+loud. Affects how technique suggestions are ranked.",
     "input_schema": {"type": "object", "properties": {
         "mode": {"type": "string", "enum": ["stealth", "normal", "aggressive"]},
         "assessment_id": {"type": "string"},
         "reason": {"type": "string", "description": "Why you're changing mode"},
     }, "required": ["mode"]}},

    # ── god-mode EXEC / synthesis tools ─────────────────────────────────────
    {"name": "export_report",
     "description": "Generate and save the full assessment report in markdown. Assembles executive summary, attack narrative, findings detail, attack path walkthrough, and recommendations.",
     "input_schema": {"type": "object", "properties": {
         "assessment_id": {"type": "string"},
         "sections": {"type": "array", "items": {"type": "string"},
                      "description": "Sections to include. Omit for all.",
                      "enum": ["executive_summary", "attack_narrative", "findings_detail",
                               "attack_path_walkthrough", "recommendations"]},
     }}},

    {"name": "run_technique_chain",
     "description": "Execute a sequence of techniques in order. Each step is subject to approval policy. Returns step-by-step results. REQUIRES USER APPROVAL.",
     "input_schema": {"type": "object", "properties": {
         "techniques": {"type": "array", "items": {
             "type": "object",
             "properties": {
                 "technique_id": {"type": "string"},
                 "params": {"type": "object"},
                 "command_index": {"type": "integer", "default": 0},
             }, "required": ["technique_id"]
         }},
         "stop_on_failure": {"type": "boolean", "default": True},
         "assessment_id": {"type": "string"},
     }, "required": ["techniques"]}},

    {"name": "import_tool_output",
     "description": "Parse raw output from external tools (nmap, crackmapexec/nxc, ldapsearch, certipy, enum4linux) and create findings/entities in the assessment.",
     "input_schema": {"type": "object", "properties": {
         "tool_name": {"type": "string", "enum": ["nmap", "nxc", "crackmapexec", "ldapsearch",
                                                    "certipy", "enum4linux", "bloodhound", "generic"]},
         "raw_output": {"type": "string", "description": "Raw stdout/stderr from the tool"},
         "assessment_id": {"type": "string"},
         "create_findings": {"type": "boolean", "default": True, "description": "Auto-create findings for detected issues"},
         "create_entities": {"type": "boolean", "default": True, "description": "Auto-create entities for discovered hosts/users"},
     }, "required": ["tool_name", "raw_output"]}},

    {"name": "plan_attack",
     "description": "Synthesize current assessment state into a prioritized, step-by-step attack plan targeting DA or a specified target. Deterministic — no LLM call, pure data aggregation.",
     "input_schema": {"type": "object", "properties": {
         "assessment_id": {"type": "string"},
         "target": {"type": "string", "description": "Target group/user/machine. Default: Domain Admins", "default": "Domain Admins"},
         "opsec_mode": {"type": "string", "enum": ["stealth", "normal", "aggressive"], "default": "normal"},
         "max_steps": {"type": "integer", "default": 10},
     }}},

    {"name": "get_next_best_action",
     "description": "What should the operator do right now? Returns the single highest-impact next action based on current owned assets, available attack paths, and kill chain progress.",
     "input_schema": {"type": "object", "properties": {
         "assessment_id": {"type": "string"},
     }}},

    {"name": "run_bloodhound_collection",
     "description": "Run bloodhound-python remote collection against the target DC. Saves output and triggers graph import. REQUIRES USER APPROVAL.",
     "input_schema": {"type": "object", "properties": {
         "dc_ip": {"type": "string"},
         "domain": {"type": "string"},
         "username": {"type": "string"},
         "password": {"type": "string", "description": "Cleartext password or omit if using hash"},
         "nt_hash": {"type": "string", "description": "NTLM hash for PTH collection"},
         "collection_method": {"type": "string", "enum": ["All", "DCOnly", "Session", "Trusts", "ACL"],
                               "default": "DCOnly"},
         "assessment_id": {"type": "string"},
     }, "required": ["dc_ip", "domain", "username"]}},

    {"name": "get_timeline",
     "description": "Engagement activity timeline: techniques executed, findings discovered, entities owned, report sections written — in chronological order.",
     "input_schema": {"type": "object", "properties": {
         "assessment_id": {"type": "string"},
         "limit": {"type": "integer", "default": 50},
         "event_types": {"type": "array", "items": {"type": "string"},
                         "description": "Filter by type: technique_executed, finding_added, entity_owned, report_written"},
     }}},

    {"name": "generate_playbook",
     "description": "Generate a complete kill-chain playbook for this assessment: phase-by-phase steps, exact commands with real target values, MITRE IDs, and detection notes.",
     "input_schema": {"type": "object", "properties": {
         "assessment_id": {"type": "string"},
         "target": {"type": "string", "default": "Domain Admins"},
         "style": {"type": "string", "enum": ["full", "executive", "technical"], "default": "technical"},
         "include_mitre": {"type": "boolean", "default": True},
         "include_detection": {"type": "boolean", "default": True},
     }}},
]

# Build lookup map
_SCHEMA_BY_NAME = {s["name"]: s for s in TOOL_SCHEMAS}


_TOOL_NAME_ALIASES = {
    "get_entity-details": "get_entity_details",
}


def _normalize_tool_call(name: str, args: dict) -> tuple[str, dict]:
    normalized_name = _TOOL_NAME_ALIASES.get(name, name)
    if normalized_name not in _SCHEMA_BY_NAME and "-" in normalized_name:
        candidate = normalized_name.replace("-", "_")
        if candidate in _SCHEMA_BY_NAME:
            normalized_name = candidate
    normalized_args = dict(args or {})
    if normalized_name == "run_bloodhound_collection" and "domain" not in normalized_args and "domain_name" in normalized_args:
        normalized_args["domain"] = normalized_args["domain_name"]
    return normalized_name, normalized_args


async def dispatch_tool(name: str, args: dict, ctx: ToolContext | None) -> dict:
    """Route a tool call to its implementation. Raises ValueError for unknown tools."""
    name, args = _normalize_tool_call(name, args)
    if name not in _SCHEMA_BY_NAME:
        raise ValueError(f"Unknown tool: {name!r}")

    t0 = time.monotonic()

    try:
        if name in READ_TOOL_NAMES or name in WRITE_TOOL_NAMES:
            from . import read_tools, intel_tools, write_tools
            handler_map = {**read_tools.HANDLERS, **intel_tools.HANDLERS, **write_tools.HANDLERS}
        else:
            from . import exec_tools
            handler_map = exec_tools.HANDLERS
    except ImportError as exc:
        raise NotImplementedError(f"Tool handlers not yet implemented for: {name!r}") from exc

    handler = handler_map.get(name)
    if handler is None:
        raise ValueError(f"No handler registered for tool: {name!r}")

    result = await handler(args, ctx)
    duration_ms = int((time.monotonic() - t0) * 1000)
    return {"result": result, "duration_ms": duration_ms}
