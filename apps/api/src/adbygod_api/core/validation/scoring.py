"""
Consensus Arbitrator v3 — Real-world calibrated AD exposure scoring.

Design principles:
  1. A single confirmed CRITICAL signal IS real exposure — don't dilute with silent experts.
  2. Findings from the rule engine are ground truth — they establish a risk floor.
  3. Evidence quality informs uncertainty, never silences confirmed signals.
  4. Risk = dominant_signal + diminishing_corroboration + finding_floor.
  5. Confidence = expert_certainty × corroboration_bonus × direct_evidence_boost.
  6. Verdicts map to real-world pentesting language, not just score thresholds.
"""
from __future__ import annotations

import logging

from adbygod_api.core.validation.contracts import (
    ConfidenceBand,
    EvidenceQualityBand,
    ExpertDecision,
    ExpertVerdict,
    FinalVerdict,
    FusionResult,
)
from adbygod_api.core.validation.context import ValidationAssessmentContext
from adbygod_api.core.validation.experts.evidence_quality import compute_evidence_quality

log = logging.getLogger(__name__)

# Verdict → signed weight (used only for confidence direction, not for risk)
_VERDICT_SIGN: dict[ExpertVerdict, float] = {
    ExpertVerdict.SUPPORTS_EXPOSURE:    1.00,
    ExpertVerdict.WEAK_SUPPORT:         0.45,
    ExpertVerdict.NEUTRAL:              0.00,
    ExpertVerdict.CONTRADICTS_EXPOSURE:-1.00,
    ExpertVerdict.INSUFFICIENT_DATA:    0.00,
}

# Expert authority weights — higher = more authoritative signal for this module
_EXPERT_WEIGHTS: dict[str, float] = {
    # kerberos
    "kerberos:kerberos_expert":             1.30,
    "kerberos:golden_ticket_risk":          1.40,
    "kerberos:delegation":                  1.10,
    "kerberos:encryption":                  0.85,
    # acl
    "acl:acl_expert":                       1.30,
    "acl:ownership_abuse":                  1.15,
    "acl:adminsd_holder":                   1.25,
    # dcsync
    "dcsync:dcsync_expert":                 1.50,
    # ntlm_relay
    "ntlm_relay:ntlm_relay_expert":         1.25,
    "ntlm_relay:petitpotam":                1.10,
    # trust
    "trust:trust_expert":                   1.20,
    "trust:sid_filtering":                  1.10,
    "trust:trust_forest_pivot_chain":       1.30,
    # adcs
    "adcs:esc1":                            1.40,
    "adcs:esc4":                            1.20,
    "adcs:esc8":                            1.30,
    "adcs:ca_config":                       1.10,
    "adcs:cert_mapping":                    1.20,
    # shadow_credentials
    "shadow_credentials:key_credential_link":       1.40,
    "shadow_credentials:whisker_reachability":      1.20,
    "shadow_credentials:shadow_credential_chain":   1.35,
    # gpo_abuse
    "gpo_abuse:gpo_write":                  1.30,
    "gpo_abuse:gpo_scope":                  1.10,
    "gpo_abuse:scheduled_task":             1.20,
    "gpo_abuse:gpo_delegation":             1.00,
    # laps_exposure
    "laps_exposure:laps_read":              1.30,
    "laps_exposure:laps_coverage":          1.15,
    "laps_exposure:laps_expiry":            0.90,
    # delegation
    "delegation:unconstrained":             1.40,
    "delegation:constrained":              1.20,
    "delegation:rbcd":                      1.30,
    "delegation:delegation_chain":          1.50,
    "delegation:kerberos_only_dc":          1.00,
    # password_policy
    "password_policy:default_policy":       1.20,
    "password_policy:fgpp":                 0.90,
    "password_policy:spray_candidate":      1.25,
    "password_policy:password_not_required":1.30,
    # sid_history
    "sid_history:sid_history_presence":     1.10,
    "sid_history:sid_history_privileged":   1.40,
    "sid_history:sid_filtering_trust":      1.20,
    # maq_rbcd
    "maq_rbcd:maq":                         1.20,
    "maq_rbcd:rbcd_via_maq":                1.40,
    "maq_rbcd:create_child_computer":       1.20,
    "maq_rbcd:computer_takeover_chain":     1.50,
    # network_posture
    "network_posture:net_smb_ldap_signing": 1.25,
    "network_posture:net_poisoning_vectors":1.15,
    "network_posture:net_service_exposure": 1.00,
    "network_posture:net_posture_aggregate":1.20,
    # user_accounts
    "user_accounts:usr_passwd_notreqd":     1.30,
    "user_accounts:usr_privileged_hygiene": 1.20,
    "user_accounts:usr_flag_sweep":         1.10,
    # service_accounts
    "service_accounts:svc_gmsa_adoption":   1.10,
    "service_accounts:svc_password_age":    1.20,
    # domain_config
    "domain_config:dom_krbtgt_rotation":    1.40,
    "domain_config:dom_functional_level":   1.00,
    "domain_config:dom_security_baseline":  1.20,
    # point-exposure modules
    "pre2k_exposure:pre2k_exposure_expert":         1.30,
    "recon_exposure:recon_exposure_expert":         1.00,
    "timeroast_exposure:timeroast_exposure_expert": 1.20,
    "wsus_exposure:wsus_exposure_expert":           1.30,
}

# Finding types → which validation modules they inform (multi-module overlap allowed)
_FINDING_MODULE_MAP: dict[str, list[str]] = {
    "ASREP_ROASTABLE":                  ["kerberos"],
    "KERBEROASTABLE_SERVICES":          ["kerberos", "service_accounts"],
    "KERBEROASTABLE_ADMIN":             ["kerberos"],
    "KERBEROAST_RC4_ONLY":              ["kerberos", "service_accounts"],
    "DES_ONLY_KERBEROS_ACCOUNT":        ["kerberos"],
    "KRBTGT_STALE":                     ["kerberos", "domain_config"],
    "CONSTRAINED_DELEGATION_KCD":       ["kerberos", "delegation"],
    "CONSTRAINED_DELEGATION_ANY_PROTOCOL": ["kerberos", "delegation"],
    "UNCONSTRAINED_DELEGATION":         ["delegation", "kerberos"],
    "RBCD_CONFIGURED":                  ["delegation", "maq_rbcd"],
    "WEAK_PASSWORD_LENGTH":             ["password_policy"],
    "NO_PASSWORD_COMPLEXITY":           ["password_policy"],
    "NO_LOCKOUT_POLICY":                ["password_policy"],
    "WEAK_PASSWORD_HISTORY":            ["password_policy"],
    "REVERSIBLE_ENCRYPTION_ENABLED":    ["password_policy"],
    "LARGE_SPRAY_SURFACE":              ["password_policy", "user_accounts"],
    "PASSWD_NOTREQD":                   ["password_policy", "user_accounts"],
    "STALE_ADMIN_ACCOUNT":              ["user_accounts"],
    "ADMIN_PWD_NEVER_EXPIRES":          ["user_accounts"],
    "ADMIN_NOT_PROTECTED_USERS":        ["user_accounts"],
    "USER_ACCOUNT_DOLLAR_SUFFIX":       ["user_accounts"],
    "PRIVILEGED_PRIMARY_GROUP_ID":      ["user_accounts"],
    "ACCOUNT_DESCRIPTION_SECRET":       ["user_accounts"],
    "DEFAULT_ADMIN_ENABLED":            ["user_accounts"],
    "ADMINSDHOLDER_ORPHAN":             ["user_accounts", "domain_config"],
    "SERVICE_ACCOUNTS_NO_GMSA":         ["service_accounts"],
    "GMSA_PASSWORD_READABLE":          ["service_accounts", "laps_exposure"],
    "LOW_DOMAIN_FUNCTIONAL_LEVEL":      ["domain_config"],
    "MACHINE_ACCOUNT_QUOTA":            ["domain_config", "maq_rbcd"],
    "ADMINSDHOLDER_DRIFT":              ["domain_config", "acl"],
    "SMB_SIGNING_DISABLED":             ["network_posture", "ntlm_relay"],
    "LDAP_SIGNING_DISABLED":            ["network_posture", "ntlm_relay"],
    "LDAP_CHANNEL_BINDING_DISABLED":    ["network_posture"],
    "LLMNR_ENABLED":                    ["network_posture", "recon_exposure"],
    "NBTNS_ENABLED":                    ["network_posture", "recon_exposure"],
    "WINRM_EXPOSED":                    ["network_posture"],
    "OPEN_SMB_SHARES":                  ["network_posture", "recon_exposure"],
    "NULL_SESSION_SMB_EXPOSURE":        ["network_posture", "recon_exposure"],
    "LEGACY_EOL_OPERATING_SYSTEMS":     ["network_posture"],
    "NTLM_DOWNGRADE":                   ["ntlm_relay", "network_posture"],
    "DCSYNC_RIGHTS":                    ["dcsync"],
    "GENERIC_ALL_TIER0":                ["acl"],
    "WRITE_DACL_ON_USERS":              ["acl"],
    "WRITE_OWNER_TIER0":                ["acl"],
    "ADD_MEMBER_GROUP_TAKEOVER":        ["acl"],
    "WRITE_SPN_ABUSE_PATH":             ["acl"],
    "WRITE_GP_LINK_ABUSE_PATH":         ["acl", "gpo_abuse"],
    "WRITE_ACCOUNT_RESTRICTIONS_ABUSE_PATH": ["acl"],
    "SQL_ADMIN_ATTACK_PATH":            ["acl"],
    "TRUST_NO_SID_FILTERING":           ["trust"],
    "BIDIRECTIONAL_EXTERNAL_TRUST":     ["trust"],
    "TREAT_AS_EXTERNAL_TRUST":          ["trust"],
    "SID_HISTORY_POPULATED":            ["sid_history", "trust"],
    "ESC1":                             ["adcs"],
    "ESC2":                             ["adcs"],
    "ESC3":                             ["adcs"],
    "ESC4":                             ["adcs"],
    "ESC5_PKI_OBJECT_CONTROL":          ["adcs"],
    "ESC6_CA_SAN_FLAG_ENABLED":         ["adcs"],
    "ESC7_CA_PERMISSION_ABUSE":         ["adcs"],
    "ESC9_WEAK_SECURITY_EXTENSION_MAPPING": ["adcs"],
    "ESC10_WEAK_CERTIFICATE_MAPPING":   ["adcs"],
    "ESC11_RPC_ENROLLMENT_RELAY":       ["adcs"],
    "ESC13_ISSUANCE_POLICY_GROUP_LINK": ["adcs"],
    "ESC16_CA_DISABLES_SID_EXTENSION":  ["adcs"],
    "GOLDEN_CERTIFICATE_RISK":          ["adcs"],
    "CA_PRIVATE_KEY_CONTROL":           ["adcs"],
    "NO_LAPS":                          ["laps_exposure"],
    "COMPUTERS_NO_LAPS":                ["laps_exposure"],
    "LAPS_PASSWORD_READABLE":           ["laps_exposure"],
    "DANGEROUS_GPO_DELEGATION":         ["gpo_abuse"],
    "SYSVOL_GPP_CPASSWORD":             ["gpo_abuse"],
    "SHADOW_CREDENTIALS":               ["shadow_credentials"],
    "ADD_KEY_CREDENTIAL_LINK_ABUSE_PATH": ["shadow_credentials"],
    "CRED_MANAGER_SECRETS":             ["network_posture"],
}

# Severity → base risk floor contribution per finding
_SEVERITY_RISK: dict[str, float] = {
    "CRITICAL": 2.50,
    "HIGH":     1.40,
    "MEDIUM":   0.70,
    "LOW":      0.25,
    "INFO":     0.05,
}


def _get_weight(d: ExpertDecision) -> float:
    key = f"{d.module_id}:{d.expert_id}"
    return _EXPERT_WEIGHTS.get(key, 1.0)


def _module_findings(findings: list, module_id: str) -> list:
    """Filter findings to those that inform this module."""
    result = []
    for f in findings:
        ft = getattr(f, 'finding_type', '') or ''
        modules = _FINDING_MODULE_MAP.get(ft, [])
        if module_id in modules:
            result.append(f)
    return result


def _finding_risk_floor(module_findings: list) -> float:
    """
    Compute risk floor from findings for this module.
    First finding contributes full value, each additional diminishes at 0.72x.
    This models: one CRITICAL = significant exposure; five CRITICAL = near-certain compromise.
    """
    contributions = sorted(
        [_SEVERITY_RISK.get(getattr(f, 'severity', '') or '', 0.0) for f in module_findings],
        reverse=True,
    )
    floor = 0.0
    for i, v in enumerate(contributions):
        floor += v * (0.78 ** i)
    return min(9.0, floor)


def compute_mitre_coverage(decisions: list) -> dict[str, list[str]]:
    TACTIC_MAP = {
        "T1558": "credential_access", "T1003": "credential_access",
        "T1649": "credential_access", "T1552": "credential_access",
        "T1557": "lateral_movement", "T1550": "lateral_movement",
        "T1482": "discovery",        "T1484": "defense_evasion",
        "T1053": "execution",        "T1078": "initial_access",
        "T1110": "initial_access",   "T1134": "privilege_escalation",
        "T1222": "defense_evasion",  "T1098": "persistence",
        "T1072": "lateral_movement", "T1087": "discovery",
        "T1171": "lateral_movement",
    }
    coverage: dict[str, list[str]] = {}
    for d in decisions:
        for tech in getattr(d, 'mitre_techniques', []):
            prefix = tech.split('.')[0]
            tactic = TACTIC_MAP.get(prefix, "other")
            coverage.setdefault(tactic, [])
            if tech not in coverage[tactic]:
                coverage[tactic].append(tech)
    return coverage


def _confidence_band(score: int) -> ConfidenceBand:
    if score >= 85:
        return ConfidenceBand.VERY_HIGH
    if score >= 70:
        return ConfidenceBand.HIGH
    if score >= 50:
        return ConfidenceBand.MODERATE
    return ConfidenceBand.LOW


def _severity_from_score(risk: float) -> str:
    if risk >= 9.0:
        return "CRITICAL"
    if risk >= 7.0:
        return "HIGH"
    if risk >= 4.0:
        return "MEDIUM"
    if risk >= 1.5:
        return "LOW"
    return "INFO"


class ConsensusArbitrator:
    """
    Fuses expert decisions into a calibrated FusionResult.

    Risk scoring (0-10):
      - Supporting experts are sorted by weighted contribution; primary dominates,
        each additional adds diminishing returns (0.65^n).
      - Findings establish a risk floor regardless of expert coverage gaps.
      - Contradicting experts subtract from risk (0.8 per contradiction).
      - Evidence quality: gentle ±10% adjustment only.

    Confidence (0-100%):
      - Weighted avg of supporting expert confidences.
      - Corroboration bonus: +8% per additional supporter (max +24%).
      - CRITICAL findings boost: +5% per finding (max +15%).
      - Contradiction penalty: -12% per contradicting expert.
      - Evidence quality: max -12% reduction (doesn't silence confirmed findings).
    """

    def fuse(
        self,
        expert_decisions: list[ExpertDecision],
        ctx: ValidationAssessmentContext,
        module_id: str,
    ) -> FusionResult:

        eq_score, eq_band, eq_reasons = compute_evidence_quality(ctx)

        # ── Categorise experts ─────────────────────────────────────────────
        supporting    = [d for d in expert_decisions if d.verdict in (ExpertVerdict.SUPPORTS_EXPOSURE, ExpertVerdict.WEAK_SUPPORT)]
        contradicting = [d for d in expert_decisions if d.verdict == ExpertVerdict.CONTRADICTS_EXPOSURE]
        support_count       = len(supporting)
        contradiction_count = len(contradicting)
        insufficient_count  = sum(1 for d in expert_decisions if d.verdict == ExpertVerdict.INSUFFICIENT_DATA)

        # ── Module-relevant findings ───────────────────────────────────────
        mod_findings = _module_findings(ctx.findings, module_id)
        crit_findings = [f for f in mod_findings if getattr(f, 'severity', '') == 'CRITICAL']
        high_findings = [f for f in mod_findings if getattr(f, 'severity', '') == 'HIGH']

        # ── Risk Score ────────────────────────────────────────────────────
        # Step 1: Expert-based risk
        #   Weighted average of (score_delta × verdict_sign) for supporting experts only.
        #   A single perfect expert (delta=1.0, SUPPORTS_EXPOSURE) yields 7.0/10 base,
        #   leaving room for: corroboration bonus (+up to 2.0), finding floor override.
        expert_risk = 0.0
        if supporting:
            total_w = sum(_get_weight(d) for d in supporting)
            avg_delta = sum(
                d.score_delta * _VERDICT_SIGN[d.verdict] * _get_weight(d)
                for d in supporting
            ) / max(total_w, 1e-9)

            # Base: scale avg_delta to 0-7.0 (leaves room for bonuses)
            base = avg_delta * 7.0

            # Corroboration bonus: each additional supporter beyond first adds 0.5, max +2.0
            corroboration = min(2.0, (support_count - 1) * 0.5)

            expert_risk = min(8.5, base + corroboration)

        # Step 2: Finding floor (ground truth — findings ARE evidence)
        #   Only applied when at least one expert supports exposure.
        floor = _finding_risk_floor(mod_findings) if support_count > 0 else 0.0

        # Step 3: Take the higher of expert score and finding floor
        raw_risk = max(expert_risk, floor)

        # Contradiction penalty (0.8 per contradicting expert)
        raw_risk = max(0.0, raw_risk - contradiction_count * 0.80)

        # Evidence quality: gentle ±12% adjustment (0.88–1.00)
        eq_adj = 0.88 + 0.12 * (eq_score / 100.0)
        raw_risk *= eq_adj

        risk_score = round(min(10.0, max(0.0, raw_risk)), 1)

        # ── Confidence ────────────────────────────────────────────────────
        if not supporting:
            raw_conf = 0.20
        else:
            total_w = sum(_get_weight(d) for d in supporting)
            raw_conf = sum(d.confidence * _get_weight(d) for d in supporting) / max(total_w, 1e-9)

            # Corroboration bonus: each additional supporter adds diminishing confidence
            # 2nd expert: +5%, 3rd: +4%, 4th: +3.2% — max total bonus +12%
            for i in range(1, min(support_count, 5)):
                raw_conf = min(0.95, raw_conf + 0.05 * (0.80 ** (i - 1)))

            # Direct finding boost: CRITICAL findings increase confidence (ground truth)
            # +2.5% per CRITICAL finding, max +7.5%; +1.5% per HIGH, max +4.5%
            if crit_findings:
                raw_conf = min(0.95, raw_conf + 0.025 * min(len(crit_findings), 3))
            elif high_findings:
                raw_conf = min(0.93, raw_conf + 0.015 * min(len(high_findings), 3))

            # Contradiction penalty
            raw_conf = max(0.08, raw_conf - contradiction_count * 0.12)

            # Evidence quality: max -12% when findings still exist, -18% when totally blind
            if eq_band == EvidenceQualityBand.FRAGILE:
                penalty = 0.18 if not mod_findings else 0.10
                raw_conf *= (1.0 - penalty)
            elif eq_band == EvidenceQualityBand.LOW:
                raw_conf *= 0.95

        confidence_int = int(min(97, max(5, raw_conf * 100)))

        # ── Consensus Score ───────────────────────────────────────────────
        if not expert_decisions:
            consensus_int = 0
        else:
            s_ratio  = support_count      / len(expert_decisions)
            c_ratio  = contradiction_count/ len(expert_decisions)
            consensus_int = int(min(100, max(0, (s_ratio - c_ratio * 0.5) * 100)))

        # ── Final Verdict ─────────────────────────────────────────────────
        all_insufficient = all(d.verdict == ExpertVerdict.INSUFFICIENT_DATA for d in expert_decisions)

        if all_insufficient or (support_count == 0 and insufficient_count == len(expert_decisions)):
            final_verdict = FinalVerdict.INSUFFICIENT_DATA
        elif contradiction_count > support_count * 2 and support_count > 0:
            final_verdict = FinalVerdict.NOT_SUPPORTED_BY_CURRENT_EVIDENCE
        elif risk_score >= 6.5 and support_count >= 1:
            final_verdict = FinalVerdict.LIKELY_EXPOSED
        elif risk_score >= 3.0 and support_count >= 1:
            final_verdict = FinalVerdict.CONDITIONALLY_EXPOSED
        elif risk_score >= 1.0 and support_count >= 1:
            final_verdict = FinalVerdict.LOW_CONFIDENCE_SIGNAL
        elif risk_score >= 0.5:
            final_verdict = FinalVerdict.LOW_CONFIDENCE_SIGNAL
        elif support_count == 0 and contradiction_count == 0:
            final_verdict = FinalVerdict.INSUFFICIENT_DATA
        else:
            final_verdict = FinalVerdict.NOT_SUPPORTED_BY_CURRENT_EVIDENCE

        severity = _severity_from_score(risk_score)
        conf_band = _confidence_band(confidence_int)

        # ── Explanatory text ──────────────────────────────────────────────
        increased: list[str] = []
        reduced:   list[str] = []
        raise_conf: list[str] = []

        for d in expert_decisions:
            if d.verdict == ExpertVerdict.SUPPORTS_EXPOSURE and d.score_delta >= 0.5:
                increased.append(f"{d.expert_name}: {d.summary}")
        for d in contradicting:
            reduced += d.contradicting_signals[:2]
        if eq_band in (EvidenceQualityBand.LOW, EvidenceQualityBand.FRAGILE):
            reduced.append(f"Evidence quality {eq_band.value} ({eq_score}/100)")

        if not ctx.has_evidence:
            raise_conf.append("Import evidence records for higher confidence")
        if not ctx.has_edges:
            raise_conf.append("Run graph collection to enable path analysis")
        for d in expert_decisions:
            raise_conf += d.missing_signals[:1]

        rec_actions = [
            "Review findings in the Findings tab and prioritize CRITICAL/HIGH severity",
            "Validate critical paths with a targeted manual pentest",
        ]
        module_recs = {
            "kerberos":      "Disable pre-auth exemptions; rotate all service account credentials",
            "dcsync":        "Audit and remove unexpected DCSync replication rights immediately",
            "acl":           "Remove toxic ACL edges from privileged group targets",
            "ntlm_relay":    "Enforce SMB signing domain-wide; disable WebClient service on DCs",
            "trust":         "Enable SID filtering on all external and forest trusts",
            "adcs":          "Remediate ESC template vulnerabilities; audit CA permissions",
            "delegation":    "Remove unconstrained delegation; migrate to RBCD or constrained",
            "password_policy": "Enforce 14+ char minimum, lockout policy, and complexity",
            "laps_exposure": "Deploy LAPS on all workstations; restrict LAPS read access",
            "shadow_credentials": "Audit msDS-KeyCredentialLink; restrict write access",
            "maq_rbcd":      "Set MachineAccountQuota=0; audit RBCD configurations",
            "gpo_abuse":     "Restrict GPO write access; audit delegated GPO control",
            "sid_history":   "Clear sIDHistory from migrated accounts; enforce SID filtering",
            "network_posture": "Enable SMB/LDAP signing; disable LLMNR/NBT-NS",
            "user_accounts": "Enforce Protected Users group for all admin accounts",
            "service_accounts": "Migrate service accounts to gMSA; rotate stale passwords",
            "domain_config": "Raise domain functional level; rotate krbtgt password twice",
            "wsus_exposure": "Configure WSUS for HTTPS; restrict update approval permissions",
        }
        if module_id in module_recs:
            rec_actions.insert(0, module_recs[module_id])

        # ── Affected entities ──────────────────────────────────────────────
        affected_names: list[str] = []
        for d in expert_decisions:
            for eid in d.related_entity_ids[:2]:
                name = ctx.entity_name(eid)
                if name and name not in affected_names:
                    affected_names.append(name)
        affected_names = affected_names[:8]

        safeguards = [
            "Simulation only — no credentials extracted, no sessions created",
            "LIKELY_EXPOSED = modelled from evidence, not confirmed exploitation",
            "Validate critical findings with manual pentest before remediation prioritisation",
        ]

        return FusionResult(
            final_verdict=final_verdict,
            risk_score=risk_score,
            confidence=confidence_int,
            consensus_score=consensus_int,
            evidence_quality_score=eq_score,
            evidence_quality_band=eq_band,
            confidence_band=conf_band,
            severity_projection=severity,
            summary=f"{final_verdict.value}: {supporting[0].summary if supporting else 'No supporting signals.'}",
            operator_brief=(
                f"{module_id.upper().replace('_', ' ')} module: {final_verdict.value.replace('_', ' ')} "
                f"(risk {risk_score}/10, {confidence_int}% confidence). "
                f"{len(supporting)} of {len(expert_decisions)} experts confirm exposure."
            ),
            impact=f"Severity projection: {severity}. {len(crit_findings)} CRITICAL, {len(high_findings)} HIGH module findings.",
            blast_radius=None,
            mapped_attack_steps=sum(len(getattr(d, 'mitre_techniques', [])) for d in expert_decisions),
            what_increased_confidence=increased[:5],
            what_reduced_confidence=reduced[:5],
            what_would_raise_confidence=raise_conf[:5],
            recommended_actions=rec_actions[:5],
            safeguards=safeguards,
            control_mapping=[],
            kill_chains=[],
            cross_module_chains=[],
            threat_actor_matches=[],
            remediation_playbook=[],
            red_team_narrative="",
            mitre_coverage={},
            remediation_impact={},
            support_count=support_count,
            contradiction_count=contradiction_count,
            insufficient_count=insufficient_count,
            evidence_summary={
                "total_findings": len(ctx.findings),
                "module_findings": len(mod_findings),
                "critical_findings": len(crit_findings),
                "high_findings": len(high_findings),
                "evidence_quality_score": eq_score,
                "evidence_quality_band": eq_band.value,
                "expert_count": len(expert_decisions),
                "supporting_experts": support_count,
            },
            contradictions=[d.summary for d in contradicting],
            telemetry={
                "eq_score": eq_score,
                "eq_band": eq_band.value,
                "expert_risk_raw": round(expert_risk, 3),
                "finding_floor": round(floor, 3),
                "raw_risk_pre_adj": round(raw_risk, 3),
                "support_count": support_count,
                "contradiction_count": contradiction_count,
                "module_findings": len(mod_findings),
            },
        )
