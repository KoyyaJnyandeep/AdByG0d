from __future__ import annotations
from adbygod_api.core.validation.contracts import ThreatActorMatch, ExpertDecision


THREAT_ACTOR_PROFILES = [
    {
        "id": "apt29",
        "name": "APT29 (Cozy Bear / SVR)",
        "techniques": {"T1558.001", "T1558.003", "T1003.006", "T1649", "T1550.003", "T1098.004"},
        "campaigns": ["SolarWinds Supply Chain (2020)", "Microsoft Exchange (2021)", "TeamViewer (2024)", "RDP-based attacks (2022)"],
        "description": "Russian SVR-linked group known for stealthy Kerberos abuse, ADCS exploitation, and shadow credentials for persistent access.",
    },
    {
        "id": "apt28",
        "name": "APT28 (Fancy Bear / GRU)",
        "techniques": {"T1557.001", "T1110.003", "T1558.004", "T1484.001", "T1482", "T1134.005"},
        "campaigns": ["DNC Hack (2016)", "Bundestag (2015)", "Olympic Destroyer (2018)", "Various NATO targets"],
        "description": "Russian GRU-linked group specializing in NTLM relay, password spraying, GPO abuse, and domain trust exploitation.",
    },
    {
        "id": "lazarus",
        "name": "Lazarus Group (DPRK)",
        "techniques": {"T1078.002", "T1134.005", "T1550.003", "T1003.006", "T1552.001"},
        "campaigns": ["Bangladesh Bank Heist (2016)", "WannaCry (2017)", "Various financial sector attacks", "Crypto exchange attacks"],
        "description": "DPRK-linked group known for lateral movement via credential theft, SID history, and living-off-the-land techniques.",
    },
    {
        "id": "lockbit",
        "name": "LockBit Affiliates",
        "techniques": {"T1110.003", "T1078.002", "T1484.001", "T1552.001", "T1003.006"},
        "campaigns": ["LockBit 2.0 (2021-2022)", "LockBit 3.0 Black (2022-2023)", "Various ransomware campaigns"],
        "description": "Ransomware-as-a-service affiliates targeting AD environments for domain-wide encryption via GPO abuse and credential theft.",
    },
    {
        "id": "fin7",
        "name": "FIN7 / Carbanak",
        "techniques": {"T1558.003", "T1557.001", "T1134.005", "T1649", "T1550.003", "T1222.001"},
        "campaigns": ["Carbanak banking attacks", "Restaurant sector targeting", "Various financial sector attacks"],
        "description": "Financially motivated group with deep AD expertise, certificate abuse, and lateral movement via delegation chains.",
    },
]


class ThreatActorMatcher:
    def match(
        self,
        decisions: list[ExpertDecision],
    ) -> list[ThreatActorMatch]:
        decision_techniques: set[str] = set()
        for d in decisions:
            decision_techniques.update(getattr(d, 'mitre_techniques', []))
            # Also match on base technique IDs (without sub-technique)
            for tech in getattr(d, 'mitre_techniques', []):
                base = tech.split('.')[0]
                decision_techniques.add(base)

        matches: list[ThreatActorMatch] = []
        for actor in THREAT_ACTOR_PROFILES:
            actor_techs = actor["techniques"]
            # Also expand actor techs to base IDs
            actor_base = {t.split('.')[0] for t in actor_techs}
            decision_base = {t.split('.')[0] for t in decision_techniques}

            # Jaccard on base technique IDs
            union = actor_base | decision_base
            intersection = actor_base & decision_base

            if not union:
                continue

            score = len(intersection) / len(union)
            if score < 0.15:  # Minimum threshold
                continue

            matched_techs = sorted(actor_techs & decision_techniques) or sorted(actor_base & decision_base)

            matches.append(ThreatActorMatch(
                actor_id=actor["id"],
                actor_name=actor["name"],
                match_score=round(score, 3),
                matched_techniques=matched_techs[:10],
                known_campaigns=actor["campaigns"],
                description=actor["description"],
            ))

        return sorted(matches, key=lambda m: m.match_score, reverse=True)
