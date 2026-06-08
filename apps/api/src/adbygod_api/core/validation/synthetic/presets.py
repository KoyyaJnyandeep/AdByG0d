from __future__ import annotations
from .generator import SyntheticADConfig

PRESETS: dict[str, SyntheticADConfig] = {
    "corp_secure": SyntheticADConfig(
        user_count=1000, computer_count=500, dc_count=3, asrep_pct=0.0,
        kerberoastable_pct=0.02, laps_coverage_pct=0.95, acl_misconfiguration_pct=0.02,
        esc1_templates=0, maq_value=0, shadow_credential_write_edges=0,
        gpo_write_edges=0, rbcd_edges=0, sid_history_count=0,
        password_policy_minlength=14, password_lockout_threshold=5,
        description="Well-hardened enterprise. Minimal attack surface. Expect LOW/INFO verdicts.",
    ),
    "corp_typical": SyntheticADConfig(
        user_count=500, computer_count=200, dc_count=2, asrep_pct=0.05,
        kerberoastable_pct=0.08, laps_coverage_pct=0.60, acl_misconfiguration_pct=0.10,
        esc1_templates=1, maq_value=10, shadow_credential_write_edges=2,
        gpo_write_edges=3, rbcd_edges=2, sid_history_count=5,
        password_policy_minlength=8, password_lockout_threshold=0,
        description="Typical enterprise. Several misconfigurations. Expect MEDIUM-HIGH verdicts.",
    ),
    "smb_legacy": SyntheticADConfig(
        user_count=100, computer_count=50, dc_count=1, asrep_pct=0.15,
        kerberoastable_pct=0.20, laps_coverage_pct=0.10, acl_misconfiguration_pct=0.20,
        esc1_templates=2, maq_value=10, unconstrained_delegation_pct=0.10,
        shadow_credential_write_edges=3, gpo_write_edges=5, rbcd_edges=3,
        sid_history_count=10, password_policy_minlength=6, password_lockout_threshold=0,
        description="Small business with legacy AD. High exposure across multiple modules.",
    ),
    "pentest_target": SyntheticADConfig(
        user_count=750, computer_count=300, dc_count=2, asrep_pct=0.12,
        kerberoastable_pct=0.15, laps_coverage_pct=0.30, acl_misconfiguration_pct=0.20,
        esc1_templates=3, maq_value=10, shadow_credential_write_edges=5,
        gpo_write_edges=8, rbcd_edges=4, sid_history_count=10,
        password_policy_minlength=8, password_lockout_threshold=0,
        description="Classic pentest target. Multiple critical chains. Expect LIKELY_EXPOSED on most modules.",
    ),
    "post_breach": SyntheticADConfig(
        user_count=500, computer_count=200, dc_count=2, asrep_pct=0.08,
        kerberoastable_pct=0.12, acl_misconfiguration_pct=0.25,
        shadow_credential_write_edges=8, sid_history_count=20, laps_coverage_pct=0.40,
        gpo_write_edges=5, rbcd_edges=5, maq_value=10,
        description="Post-breach environment with attacker persistence artifacts.",
    ),
    "healthcare_compliance": SyntheticADConfig(
        user_count=2000, computer_count=800, dc_count=4, asrep_pct=0.03,
        kerberoastable_pct=0.05, laps_coverage_pct=0.70, acl_misconfiguration_pct=0.05,
        esc1_templates=0, maq_value=0, shadow_credential_write_edges=1,
        password_policy_minlength=14, password_lockout_threshold=5, sid_history_count=3,
        description="Healthcare org with compliance controls. Low-moderate exposure.",
    ),
    "financial_sector": SyntheticADConfig(
        user_count=5000, computer_count=2000, dc_count=6, asrep_pct=0.01,
        kerberoastable_pct=0.03, laps_coverage_pct=0.90, acl_misconfiguration_pct=0.03,
        esc1_templates=0, maq_value=0, shadow_credential_write_edges=0,
        gpo_write_edges=1, rbcd_edges=0, sid_history_count=2,
        password_policy_minlength=16, password_lockout_threshold=3,
        description="Financial sector. Tight controls but large attack surface by scale.",
    ),
    "red_team_worst_case": SyntheticADConfig(
        user_count=500, computer_count=200, dc_count=2, asrep_pct=0.25,
        kerberoastable_pct=0.30, laps_coverage_pct=0.05, acl_misconfiguration_pct=0.40,
        esc1_templates=5, maq_value=10, shadow_credential_write_edges=10,
        gpo_write_edges=15, rbcd_edges=8, sid_history_count=30,
        unconstrained_delegation_pct=0.20, constrained_delegation_count=10,
        password_policy_minlength=6, password_lockout_threshold=0,
        description="Worst-case scenario. Every module should return LIKELY_EXPOSED CRITICAL.",
    ),
}
