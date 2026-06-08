from __future__ import annotations
import uuid
from adbygod_api.core.validation.contracts import CrossModuleChain, ExpertDecision


COMPOUND_RULES = [
    {
        "modules": ["kerberos", "acl"],
        "min_scores": [4.0, 3.0],
        "compound_severity": "CRITICAL",
        "compound_risk": 9.5,
        "explanation": "Kerberoastable SPN + ACL write edge = direct DA path via cracked service account credentials",
        "steps": ["Kerberoast SPN account", "Crack TGS offline", "Use cracked creds for ACL abuse", "DCSync or escalate to DA"],
    },
    {
        "modules": ["ntlm_relay", "delegation"],
        "min_scores": [3.0, 3.0],
        "compound_severity": "CRITICAL",
        "compound_risk": 9.8,
        "explanation": "NTLM coerce + unconstrained delegation = TGT capture without any existing compromise",
        "steps": ["Coerce DC via PetitPotam/PrintSpooler", "DC authenticates to unconstrained host", "Capture DC TGT", "DCSync with DC TGT"],
    },
    {
        "modules": ["maq_rbcd", "delegation"],
        "min_scores": [2.0, 2.0],
        "compound_severity": "CRITICAL",
        "compound_risk": 9.2,
        "explanation": "MAQ + RBCD write = any domain user can escalate to local admin on any targeted computer",
        "steps": ["Create machine account (MAQ)", "Write RBCD to target", "S4U2Proxy as domain admin", "Local admin on target"],
    },
    {
        "modules": ["adcs", "ntlm_relay"],
        "min_scores": [3.0, 2.0],
        "compound_severity": "CRITICAL",
        "compound_risk": 9.6,
        "explanation": "ESC8 + HTTP enrollment = relay any machine account to CA = arbitrary certificate = DA",
        "steps": ["Coerce machine account auth (NTLM relay)", "Relay to CA HTTP enrollment (ESC8)", "Obtain certificate for target", "PKINIT → DA TGT"],
    },
    {
        "modules": ["shadow_credentials", "kerberos"],
        "min_scores": [3.0, 2.0],
        "compound_severity": "CRITICAL",
        "compound_risk": 9.0,
        "explanation": "Shadow credential write + PKINIT = persistent invisible backdoor on any targeted account",
        "steps": ["Add shadow credential to target (Whisker)", "Authenticate via PKINIT with shadow cert", "Obtain TGT for target account", "Persist: survives password resets"],
    },
    {
        "modules": ["password_policy", "kerberos"],
        "min_scores": [3.0, 3.0],
        "compound_severity": "HIGH",
        "compound_risk": 7.5,
        "explanation": "Weak password policy + Kerberoastable SPNs = offline crack trivially succeeds",
        "steps": ["Kerberoast SPN accounts", "Offline crack with weak policy = fast success", "Compromise service account", "Escalate via service account privileges"],
    },
    {
        "modules": ["laps_exposure", "acl"],
        "min_scores": [2.0, 2.0],
        "compound_severity": "HIGH",
        "compound_risk": 7.8,
        "explanation": "LAPS read exposure + ACL write = local admin on multiple computers + lateral movement chain",
        "steps": ["Read LAPS password for target computer", "Gain local admin access", "Pass-the-Hash laterally", "Reach privileged ACL target"],
    },
    {
        "modules": ["sid_history", "trust"],
        "min_scores": [2.0, 2.0],
        "compound_severity": "CRITICAL",
        "compound_risk": 9.3,
        "explanation": "SID history + trust without SID filtering = cross-forest privilege escalation",
        "steps": ["Identify privileged SID history entries", "Exploit trust without SID filtering", "Forge ticket with privileged SID", "Cross-forest DA access"],
    },
    {
        "modules": ["gpo_abuse", "password_policy"],
        "min_scores": [3.0, 2.0],
        "compound_severity": "HIGH",
        "compound_risk": 8.0,
        "explanation": "GPO write + weak policy = deploy password-harvesting GPO affecting many users",
        "steps": ["Write malicious GPO with credential harvest script", "Deploy to computers with weak LSASS protection", "Harvest plaintext credentials on next GP refresh"],
    },
]


class CrossModuleCorrelator:
    def correlate(
        self,
        module_scores: dict[str, float],
        module_decisions: dict[str, list[ExpertDecision]],
    ) -> list[CrossModuleChain]:
        chains: list[CrossModuleChain] = []

        for rule in COMPOUND_RULES:
            modules = rule["modules"]
            min_scores = rule["min_scores"]

            # Check if all modules have sufficient scores
            matched = all(
                module_scores.get(mod, 0.0) >= min_score
                for mod, min_score in zip(modules, min_scores, strict=True)
            )
            if not matched:
                continue

            # Collect individual severities
            individual_severities = []
            for mod in modules:
                decs = module_decisions.get(mod, [])
                if decs:
                    max_score = max(d.score_delta for d in decs)
                    if max_score >= 0.8:
                        individual_severities.append("HIGH")
                    elif max_score >= 0.5:
                        individual_severities.append("MEDIUM")
                    else:
                        individual_severities.append("LOW")
                else:
                    individual_severities.append("UNKNOWN")

            chains.append(CrossModuleChain(
                chain_id=str(uuid.uuid4())[:8],
                modules=modules,
                individual_severities=individual_severities,
                compound_severity=rule["compound_severity"],
                compound_risk=rule["compound_risk"],
                explanation=rule["explanation"],
                steps=rule["steps"],
            ))

        return sorted(chains, key=lambda c: c.compound_risk, reverse=True)
