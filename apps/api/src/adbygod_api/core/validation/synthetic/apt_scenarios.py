from __future__ import annotations
from .generator import SyntheticADConfig

APT_SCENARIOS: dict[str, dict] = {
    "apt29_compromise": {
        "name": "APT29 Compromise Simulation",
        "description": "Models the AD posture matching APT29 TTPs: Kerberoasting, ADCS ESC1, shadow credentials, DCSync",
        "config": SyntheticADConfig(
            user_count=750, computer_count=300, dc_count=2,
            kerberoastable_pct=0.15, esc1_templates=2, adcs_templates=5,
            shadow_credential_write_edges=5, asrep_pct=0.05, maq_value=10,
            rbcd_edges=3, acl_misconfiguration_pct=0.12,
            password_policy_minlength=8, password_lockout_threshold=0,
        ),
        "expected_modules": ["kerberos", "adcs", "shadow_credentials", "dcsync"],
        "threat_actor": "APT29 (Cozy Bear / SVR)",
        "mitre_techniques": ["T1558.001", "T1558.003", "T1003.006", "T1649", "T1098.004"],
    },
    "ransomware_prestage": {
        "name": "Ransomware Pre-Stage Environment",
        "description": "Typical pre-ransomware AD posture: spray viable, GPO abuse, LAPS gaps, lateral movement",
        "config": SyntheticADConfig(
            user_count=400, computer_count=150, dc_count=2,
            password_policy_minlength=8, password_lockout_threshold=0,
            gpo_write_edges=10, gpo_count=15, laps_coverage_pct=0.15,
            kerberoastable_pct=0.20, acl_misconfiguration_pct=0.15, maq_value=10,
        ),
        "expected_modules": ["password_policy", "gpo_abuse", "laps_exposure", "ntlm_relay"],
        "threat_actor": "LockBit Affiliates",
        "mitre_techniques": ["T1110.003", "T1484.001", "T1552.001"],
    },
    "insider_threat": {
        "name": "Insider Threat Profile",
        "description": "Legitimate user with elevated lateral movement via ACL abuse, SID history, RBCD",
        "config": SyntheticADConfig(
            user_count=300, computer_count=100, dc_count=2,
            acl_misconfiguration_pct=0.30, sid_history_count=15,
            rbcd_edges=6, shadow_credential_write_edges=3, maq_value=10,
            laps_coverage_pct=0.50, kerberoastable_pct=0.08,
        ),
        "expected_modules": ["acl", "sid_history", "maq_rbcd", "shadow_credentials"],
        "threat_actor": "Insider / Lazarus Group",
        "mitre_techniques": ["T1222.001", "T1134.005", "T1550.003", "T1098.004"],
    },
    "supply_chain_foothold": {
        "name": "Supply Chain Foothold Scenario",
        "description": "Low-privilege foothold with ADCS, delegation, and trust abuse as escalation paths",
        "config": SyntheticADConfig(
            user_count=600, computer_count=250, dc_count=3,
            esc1_templates=3, adcs_templates=8, unconstrained_delegation_pct=0.08,
            domain_count=2, maq_value=10, rbcd_edges=4, constrained_delegation_count=5,
            acl_misconfiguration_pct=0.08, asrep_pct=0.04,
        ),
        "expected_modules": ["adcs", "delegation", "trust", "maq_rbcd"],
        "threat_actor": "FIN7 / APT29",
        "mitre_techniques": ["T1649", "T1558.001", "T1550.003", "T1482"],
    },
}
