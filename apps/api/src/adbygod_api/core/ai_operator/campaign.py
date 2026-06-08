from __future__ import annotations
from dataclasses import dataclass, field


PHASES = ["recon", "enum", "loot", "privesc", "lateral", "da", "report"]


@dataclass
class CampaignPhase:
    name: str
    description: str
    read_tools: list[str]
    exec_tools: list[dict]
    depends_on: list[str] = field(default_factory=list)


CAMPAIGN_PLAN: list[CampaignPhase] = [
    CampaignPhase(
        name="recon",
        description="Load assessment context and enumerate domain basics",
        read_tools=["get_assessment_summary", "get_entities", "search_platform"],
        exec_tools=[],
        depends_on=[],
    ),
    CampaignPhase(
        name="enum",
        description="Full LDAP enumeration — users, groups, computers, ACLs",
        read_tools=["get_graph_summary", "get_attack_paths"],
        exec_tools=[{"technique_id": "ldap-full-enum", "params_hint": {"dc_ip": "auto"}}],
        depends_on=["recon"],
    ),
    CampaignPhase(
        name="loot",
        description="Kerberoast and AS-REP Roast to capture service account hashes",
        read_tools=["get_entities", "get_validation_results"],
        exec_tools=[
            {"technique_id": "kerberoast-spns", "params_hint": {"dc_ip": "auto"}},
            {"technique_id": "asrep-roast", "params_hint": {"dc_ip": "auto"}},
        ],
        depends_on=["enum"],
    ),
    CampaignPhase(
        name="privesc",
        description="Exploit best attack path to elevate privileges",
        read_tools=["get_attack_paths", "get_loot", "simulate_attack_chain"],
        exec_tools=[{"technique_id": "auto-best-path", "params_hint": {}}],
        depends_on=["loot"],
    ),
    CampaignPhase(
        name="lateral",
        description="Lateral movement to additional targets",
        read_tools=["get_lateral_movement"],
        exec_tools=[{"technique_id": "pth-wmiexec", "params_hint": {}}],
        depends_on=["privesc"],
    ),
    CampaignPhase(
        name="da",
        description="Domain Admin — DCSync and credential harvest",
        read_tools=["get_loot"],
        exec_tools=[{"technique_id": "dcsync-domain", "params_hint": {"dc_ip": "auto"}}],
        depends_on=["lateral"],
    ),
    CampaignPhase(
        name="report",
        description="Write report sections for all phases",
        read_tools=["list_findings", "get_loot"],
        exec_tools=[],
        depends_on=["da"],
    ),
]


def get_campaign_plan() -> list[CampaignPhase]:
    return CAMPAIGN_PLAN


def get_phase(name: str) -> CampaignPhase | None:
    return next((p for p in CAMPAIGN_PLAN if p.name == name), None)
