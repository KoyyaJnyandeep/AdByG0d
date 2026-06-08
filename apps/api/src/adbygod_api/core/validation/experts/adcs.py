from __future__ import annotations

from adbygod_api.core.validation.contracts import ExpertDecision, ExpertVerdict
from adbygod_api.core.validation.experts.base import BaseExpert
from adbygod_api.core.validation.registry import register


def _get(obj, key: str, default=None):
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)


@register("adcs")
class ESC1Expert(BaseExpert):
    """ESC1: Enrollee supplies subject — certificate template allows SAN override."""
    expert_id = "esc1"
    expert_name = "ADCS ESC1 Expert"

    async def analyze(self, ctx) -> ExpertDecision:
        esc1_templates = [
            t for t in getattr(ctx, 'certificate_templates', [])
            if _get(t, 'esc1_vulnerable', False)
        ]
        # Also check findings
        esc1_findings = [
            f for f in getattr(ctx, 'findings', [])
            if 'esc1' in str(_get(f, 'title', '')).lower()
            or ('certificate' in str(_get(f, 'category', '')).lower() and 'subject' in str(_get(f, 'description', '')).lower())
        ]
        all_esc1 = esc1_templates or esc1_findings
        count = len(esc1_templates) + len(esc1_findings)

        if count >= 2:
            verdict, score, sev = ExpertVerdict.SUPPORTS_EXPOSURE, 0.9, "CRITICAL"
        elif count == 1:
            verdict, score, sev = ExpertVerdict.SUPPORTS_EXPOSURE, 0.7, "HIGH"
        else:
            verdict, score, sev = ExpertVerdict.NEUTRAL, 0.0, None

        names = [_get(t, 'name', 'unknown') for t in esc1_templates[:3]]
        return ExpertDecision(
            expert_id=self.expert_id,
            expert_name=self.expert_name,
            module_id="adcs",
            verdict=verdict,
            score_delta=score,
            confidence=0.85 if all_esc1 else 0.5,
            severity_hint=sev,
            summary=f"ESC1: {count} vulnerable template(s) found{': ' + ', '.join(names) if names else ''}",
            reasoning=[
                "ESC1 allows any enrollee to request certificate with arbitrary SAN",
                "SAN override enables impersonation of any AD account including DAs",
                "Certificate can be used for PKINIT → TGT → pass-the-ticket",
            ] if all_esc1 else ["No ESC1-vulnerable templates found"],
            supporting_signals=[f"{count} ESC1 template(s)"] if all_esc1 else [],
            missing_signals=[] if all_esc1 else ["Certificate template inventory"],
            mitre_techniques=["T1649"],
            kill_chain_stage="credential_access",
            cve_refs=[],
            remediation_commands=[
                f"# For template: {n}" for n in names
            ] + [
                "# Set CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT = 0 on vulnerable templates",
                "certutil -v -dstemplate <TemplateName> msPKI-Certificate-Name-Flag",
            ],
            detection_opportunities=[
                "Monitor certificate requests with subjectAltName (event 4886)",
                "Alert on certificate enrollment from unusual accounts",
                "ADCS audit log: Certificate Services (event 4886, 4887)",
            ],
        )


@register("adcs")
class ESC4Expert(BaseExpert):
    """ESC4: Template ACL write access — low-priv user can modify template to become ESC1."""
    expert_id = "esc4"
    expert_name = "ADCS ESC4 Expert"

    async def analyze(self, ctx) -> ExpertDecision:
        # Check edges: WriteDACL / WriteProperty / GenericAll on certificate template objects
        template_write_edges = [
            e for e in getattr(ctx, 'edges', [])
            if (_get(e, 'relationship_type', '') or _get(getattr(e, 'edge_type', None), 'value', getattr(e, 'edge_type', ''))) in ('WriteDACL', 'WriteProperty', 'GenericAll', 'GenericWrite')
            and 'template' in str(_get(e, 'target_label', '')).lower()
        ]
        esc4_findings = [
            f for f in getattr(ctx, 'findings', [])
            if 'esc4' in str(_get(f, 'title', '')).lower()
        ]
        vulnerable = template_write_edges or esc4_findings

        if len(template_write_edges) >= 3:
            verdict, score, sev = ExpertVerdict.SUPPORTS_EXPOSURE, 0.8, "CRITICAL"
        elif vulnerable:
            verdict, score, sev = ExpertVerdict.SUPPORTS_EXPOSURE, 0.6, "HIGH"
        else:
            verdict, score, sev = ExpertVerdict.NEUTRAL, 0.0, None

        return ExpertDecision(
            expert_id=self.expert_id,
            expert_name=self.expert_name,
            module_id="adcs",
            verdict=verdict,
            score_delta=score,
            confidence=0.75 if vulnerable else 0.45,
            severity_hint=sev,
            summary=f"ESC4: {len(template_write_edges)} write edge(s) to certificate templates",
            reasoning=[
                "ESC4: write access to template object enables conversion to ESC1",
                "Attacker can set enrollee_supplies_subject flag then enroll",
            ] if vulnerable else ["No template write edges found"],
            supporting_signals=[f"{len(template_write_edges)} template write edges"] if template_write_edges else [],
            mitre_techniques=["T1649"],
            kill_chain_stage="credential_access",
            remediation_commands=[
                "# Audit certificate template ACLs: certutil -v -template",
                "# Remove non-admin write permissions from all certificate templates",
            ],
            detection_opportunities=[
                "Monitor for certificate template modifications (event 4899)",
                "Alert on ACL changes to CN=Certificate Templates container",
            ],
        )


@register("adcs")
class ESC8Expert(BaseExpert):
    """ESC8: NTLM relay to HTTP enrollment endpoint — relay machine account to CA."""
    expert_id = "esc8"
    expert_name = "ADCS ESC8 Expert"

    async def analyze(self, ctx) -> ExpertDecision:
        # Check for HTTP Web Enrollment enabled + NTLM auth
        esc8_findings = [
            f for f in getattr(ctx, 'findings', [])
            if 'esc8' in str(_get(f, 'title', '')).lower()
            or ('web enrollment' in str(_get(f, 'description', '')).lower())
        ]
        # Compound risk: if NTLM relay findings also present
        ntlm_findings = [
            f for f in getattr(ctx, 'findings', [])
            if 'ntlm' in str(_get(f, 'category', '')).lower()
        ]
        compound = bool(esc8_findings and ntlm_findings)
        has_esc8 = bool(esc8_findings)

        if compound:
            verdict, score, sev = ExpertVerdict.SUPPORTS_EXPOSURE, 0.85, "CRITICAL"
        elif has_esc8:
            verdict, score, sev = ExpertVerdict.WEAK_SUPPORT, 0.5, "HIGH"
        else:
            verdict, score, sev = ExpertVerdict.NEUTRAL, 0.0, None

        return ExpertDecision(
            expert_id=self.expert_id,
            expert_name=self.expert_name,
            module_id="adcs",
            verdict=verdict,
            score_delta=score,
            confidence=0.7 if has_esc8 else 0.4,
            severity_hint=sev,
            summary=f"ESC8: HTTP enrollment {'exposed' if has_esc8 else 'not detected'}{', NTLM relay compound risk' if compound else ''}",
            reasoning=[
                "ESC8: HTTP Web Enrollment endpoint accepts NTLM auth",
                "Relay any machine account auth to obtain domain controller certificate",
                "Certificate → PKINIT → DA TGT",
            ] if has_esc8 else ["No HTTP enrollment endpoint evidence"],
            supporting_signals=([f"{len(esc8_findings)} ESC8 indicator(s)"] if esc8_findings else [])
                + ([f"{len(ntlm_findings)} NTLM finding(s) — compound risk"] if compound else []),
            mitre_techniques=["T1649", "T1557.001"],
            kill_chain_stage="lateral_movement",
            remediation_commands=[
                "# Disable NTLM on Certificate Authority IIS endpoint",
                "# Enable Extended Protection for Authentication (EPA) on Web Enrollment",
                "# Configure HTTPS + require client certificates for enrollment",
            ],
            detection_opportunities=[
                "Monitor CA for certificate requests via relay (audit event 4886)",
                "Alert on certificate issuance to machine accounts from non-domain-join operations",
            ],
        )


@register("adcs")
class CAConfigExpert(BaseExpert):
    """CA configuration flags: EDITF_ATTRIBUTESUBJECTALTNAME2, enrollment agents, CA ACL."""
    expert_id = "ca_config"
    expert_name = "ADCS CA Config Expert"

    async def analyze(self, ctx) -> ExpertDecision:
        ca_findings = [
            f for f in getattr(ctx, 'findings', [])
            if any(kw in str(_get(f, 'title', '') + _get(f, 'description', '')).lower()
                   for kw in ['editf', 'attributesubjectaltname', 'ca flag', 'enrollment agent', 'ca acl'])
        ]
        has_issues = bool(ca_findings)

        return ExpertDecision(
            expert_id=self.expert_id,
            expert_name=self.expert_name,
            module_id="adcs",
            verdict=ExpertVerdict.WEAK_SUPPORT if has_issues else ExpertVerdict.NEUTRAL,
            score_delta=0.6 if has_issues else 0.0,
            confidence=0.65 if has_issues else 0.4,
            severity_hint="HIGH" if has_issues else None,
            summary=f"CA config: {len(ca_findings)} misconfiguration(s) found",
            reasoning=[
                "EDITF_ATTRIBUTESUBJECTALTNAME2 on CA enables SAN in any request",
                "Enrollment agents can request certs on behalf of any user",
            ] if has_issues else ["No CA misconfiguration findings"],
            supporting_signals=[f"{len(ca_findings)} CA config issue(s)"] if ca_findings else [],
            mitre_techniques=["T1649"],
            kill_chain_stage="credential_access",
            remediation_commands=[
                "certutil -setreg policy\\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2",
                "# Restart CertSvc: net stop certsvc && net start certsvc",
                "# Audit enrollment agent certificates: certutil -v -catemplates",
            ],
            detection_opportunities=[
                "Monitor CA policy flag changes",
                "Alert on enrollment agent certificate issuance",
            ],
        )


@register("adcs")
class CertificateMappingExpert(BaseExpert):
    """CVE-2022-26923: StrongCertificateBindingEnforcement = 0 — certificate impersonation."""
    expert_id = "cert_mapping"
    expert_name = "Certificate Mapping Expert"

    async def analyze(self, ctx) -> ExpertDecision:
        # Check findings referencing CVE-2022-26923 or StrongCertificateBindingEnforcement
        cve_findings = [
            f for f in getattr(ctx, 'findings', [])
            if any(kw in (getattr(f, 'title', '') or '').lower() for kw in ['cve-2022-26923', 'strongcertificate', 'certifried', 'strong mapping'])
        ]
        # Check entities for computer accounts that could be targeted
        computer_count = getattr(ctx, 'computer_count', len([
            e for e in getattr(ctx, 'entities', [])
            if 'computer' in str(_get(e, 'type', _get(e, 'entity_type', ''))).lower()
        ]))
        # High value: many computers + no findings = unknown risk
        if cve_findings:
            verdict, score, sev = ExpertVerdict.SUPPORTS_EXPOSURE, 0.8, "CRITICAL"
        elif computer_count > 10:
            verdict, score, sev = ExpertVerdict.WEAK_SUPPORT, 0.3, "HIGH"
        else:
            verdict, score, sev = ExpertVerdict.NEUTRAL, 0.0, None

        return ExpertDecision(
            expert_id=self.expert_id,
            expert_name=self.expert_name,
            module_id="adcs",
            verdict=verdict,
            score_delta=score,
            confidence=0.8 if cve_findings else 0.35,
            severity_hint=sev,
            summary=f"Certificate mapping: {'CVE-2022-26923 indicators' if cve_findings else f'{computer_count} computers = potential surface'}",
            reasoning=[
                "CVE-2022-26923: machine account SPN collision enables certificate-to-DA escalation",
                "StrongCertificateBindingEnforcement=0 allows weak certificate mapping",
            ] if cve_findings else [f"{computer_count} computers present — validate patching status"],
            supporting_signals=[f"{len(cve_findings)} CVE indicator(s)"] if cve_findings else [],
            mitre_techniques=["T1649"],
            kill_chain_stage="privilege_escalation",
            cve_refs=["CVE-2022-26923", "CVE-2022-34691"],
            remediation_commands=[
                "# Set StrongCertificateBindingEnforcement = 2 (Full Enforcement)",
                "reg add HKLM\\SYSTEM\\CurrentControlSet\\Services\\Kdc /v StrongCertificateBindingEnforcement /t REG_DWORD /d 2",
                "# Ensure all DCs are patched for May 2022 security update",
            ],
            detection_opportunities=[
                "Monitor for certificate-based authentication from unexpected accounts",
                "Alert on machine account name changes near certificate enrollment",
            ],
        )
