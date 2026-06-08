from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class PhaseSpec:
    phase_id: int
    label: str
    technique_prefixes: list[str] = field(default_factory=list)
    full_count: int = 10


PHASES: list[PhaseSpec] = [
    PhaseSpec(0, "Reconnaissance",       ["recon-"],               full_count=15),
    PhaseSpec(1, "Initial Access",        ["ia-"],                  full_count=25),
    PhaseSpec(2, "Enumeration",           ["enum-"],                full_count=16),
    PhaseSpec(3, "Privilege Escalation",  ["privesc-", "attack-"],  full_count=20),
    PhaseSpec(4, "Lateral Movement",      ["latmov-"],              full_count=12),
    PhaseSpec(5, "Credential Access",     ["cred-", "pen200-cred-", "pen200-pth-"], full_count=10),
    PhaseSpec(6, "Persistence",           ["persist-"],             full_count=10),
    PhaseSpec(7, "Cloud / Hybrid",        ["cloud-"],               full_count=0),
    PhaseSpec(8, "Advanced Ops",          ["adv-"],                 full_count=0),
]


def _technique_phase(technique_id: str) -> int | None:
    for phase in PHASES:
        if any(technique_id.startswith(pfx) for pfx in phase.technique_prefixes):
            return phase.phase_id
    return None


def compute_phase_coverage_sync(
    recon_findings: list[dict],
    techniques_run: list[str],
) -> list[dict]:
    results = []
    for phase in PHASES:
        phase_techniques = [
            t for t in techniques_run
            if any(t.startswith(pfx) for pfx in phase.technique_prefixes)
        ]
        findings_count = 0
        status = "not_started"
        completion_pct = 0

        if phase.phase_id == 0:
            findings_count = len(recon_findings)
            if findings_count > 0:
                completion_pct = min(int((findings_count / 6) * 100), 100)
                status = "complete" if findings_count >= 6 else "partial"
        elif phase_techniques:
            findings_count = len(phase_techniques)
            max_known = phase.full_count or 1
            completion_pct = min(int((len(phase_techniques) / max_known) * 100), 100)
            status = "complete" if completion_pct >= 80 else "partial"

        results.append({
            "phase_id": phase.phase_id,
            "label": phase.label,
            "status": status,
            "completion_pct": completion_pct,
            "techniques_run": phase_techniques,
            "findings_count": findings_count,
        })
    return results


_SUGGESTION_RULES: list[dict] = [
    {
        "id": "anon_ldap_to_rid",
        "check": lambda rf, tr, gs: (
            any(f.get("finding_type") == "ANONYMOUS_LDAP_ENABLED" or f.get("type") == "ldap_exposure" for f in rf)
            and "recon-rid-cycling" not in tr
        ),
        "suggestion": {
            "technique_id": "recon-rid-cycling",
            "title": "RID Cycling — Anonymous LDAP is open",
            "reason": "Anonymous LDAP detected — null session RID cycling will enumerate all domain accounts",
            "mitre_id": "T1087.002",
            "phase_id": 0,
        },
    },
    {
        "id": "smb_null_to_enum",
        "check": lambda rf, tr, gs: (
            any(f.get("type") == "smb_null" for f in rf)
            and "recon-smb-null" not in tr
        ),
        "suggestion": {
            "technique_id": "recon-smb-null",
            "title": "enum4linux-ng — SMB null session confirmed",
            "reason": "SMB null session is open — run enum4linux-ng for full share and RPC enumeration",
            "mitre_id": "T1135",
            "phase_id": 0,
        },
    },
    {
        "id": "timeroast_exposure",
        "check": lambda rf, tr, gs: (
            any(f.get("type") == "timeroast_exposure" or f.get("finding_type") == "TIMEROAST_EXPOSURE" for f in rf)
            and "ia-timeroast" not in tr
        ),
        "suggestion": {
            "technique_id": "ia-timeroast",
            "title": "Timeroasting — NTP port accessible",
            "reason": "MS-SNTP probe confirmed NTP reachability — extract computer account hashes without credentials",
            "mitre_id": "T1558",
            "phase_id": 1,
        },
    },
    {
        "id": "timeroast_to_pre2k",
        "check": lambda rf, tr, gs: (
            any(f.get("type") == "timeroast_exposure" for f in rf)
            and "ia-pre2k-detect" not in tr
        ),
        "suggestion": {
            "technique_id": "ia-pre2k-detect",
            "title": "Pre-Win2000 Detection — NTP active",
            "reason": "NTP accessible — check for Pre-Win2000 accounts with PASSWD_NOTREQD flag",
            "mitre_id": "T1078.002",
            "phase_id": 1,
        },
    },
    {
        "id": "users_to_spray",
        "check": lambda rf, tr, gs: (
            any(f.get("type") == "user_enum" for f in rf)
            and "ia-pre2k-auth" not in tr
        ),
        "suggestion": {
            "technique_id": "ia-pre2k-auth",
            "title": "Password Spray — users enumerated",
            "reason": "RID cycling found domain accounts — run targeted Pre2K/password spray",
            "mitre_id": "T1110.003",
            "phase_id": 1,
        },
    },
    {
        "id": "start_phase0",
        "check": lambda rf, tr, gs: len(rf) == 0 and len(tr) == 0,
        "suggestion": {
            "technique_id": "recon-ldap-anon",
            "title": "Start Phase 0 — LDAP Anonymous Probe",
            "reason": "No recon data yet — begin with LDAP anonymous bind check",
            "mitre_id": "T1087.002",
            "phase_id": 0,
        },
    },
    {
        "id": "no_phase1",
        "check": lambda rf, tr, gs: (
            len(rf) > 0
            and not any(_technique_phase(t) == 1 for t in tr)
        ),
        "suggestion": {
            "technique_id": "ia-responder-capture",
            "title": "Start Phase 1 — NTLM Capture",
            "reason": "Phase 0 complete — begin Initial Access with NTLM hash capture via Responder",
            "mitre_id": "T1557.001",
            "phase_id": 1,
        },
    },
]


def suggest_next_techniques(
    recon_findings: list[dict],
    techniques_run: list[str],
    graph_signals: dict[str, Any],
    max_results: int = 5,
) -> list[dict]:
    suggestions = []
    for rule in _SUGGESTION_RULES:
        try:
            if rule["check"](recon_findings, techniques_run, graph_signals):
                suggestions.append(rule["suggestion"])
        except Exception:
            pass
        if len(suggestions) >= max_results:
            break
    return suggestions
