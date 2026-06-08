from __future__ import annotations
import logging
from adbygod_api.core.validation.contracts import ExpertDecision, ExpertVerdict
from adbygod_api.core.validation.context import ValidationAssessmentContext
from adbygod_api.core.validation.experts.base import BaseExpert
from adbygod_api.core.validation.registry import register

log = logging.getLogger(__name__)

def _get(obj, key: str, default=None):
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)

def _finding_type(f) -> str:
    return str(_get(f, "finding_type", "") or "").upper()

def _finding_title(f) -> str:
    return str(_get(f, "title", "") or "").lower()

def _attrs(e) -> dict:
    raw = _get(e, "attributes", None) or {}
    return raw if isinstance(raw, dict) else {}


@register("service_accounts")
class GMSAAdoptionExpert(BaseExpert):
    expert_id = "svc_gmsa_adoption"
    expert_name = "gMSA / sMSA Adoption Expert"

    def evaluate(self, module_id: str, ctx: ValidationAssessmentContext) -> ExpertDecision:
        gmsa_findings = [
            f for f in ctx.findings
            if _finding_type(f) in ("SERVICE_ACCOUNTS_NO_GMSA", "SVC-001", "NO_GMSA")
            or any(kw in _finding_title(f) for kw in ("gmsa", "smsa", "managed service account", "no gmsa"))
        ]

        # Count service account entities
        svc_entities = [
            e for e in ctx.entities
            if str(_get(e, "entity_type", "")).upper() in ("SERVICE_ACCOUNT",)
            or (
                _attrs(e).get("has_spn") and str(_get(e, "entity_type", "")).upper() not in ("COMPUTER", "DC")
            )
        ]
        gmsa_entities = [
            e for e in ctx.entities
            if str(_get(e, "entity_type", "")).upper() in ("GMSA", "DMSA")
        ]

        supporting: list[str] = []
        contradicting: list[str] = []
        missing: list[str] = []
        finding_ids = [str(_get(f, "id", "")) for f in gmsa_findings[:8]]

        if gmsa_findings:
            supporting.append(f"{len(gmsa_findings)} service account without gMSA finding(s) — manual password rotation risk.")
        if svc_entities:
            supporting.append(f"{len(svc_entities)} service account entity/entities with SPNs in assessment scope.")
        if gmsa_entities:
            contradicting.append(f"{len(gmsa_entities)} gMSA/DMSA account(s) already in use — partial gMSA adoption.")
        if not (gmsa_findings or svc_entities):
            missing.append("Service account inventory (SPN enumeration, GMSA type detection)")

        svc_count = len(svc_entities)
        gmsa_count = len(gmsa_entities)
        adoption_pct = int((gmsa_count / max(svc_count + gmsa_count, 1)) * 100)

        if gmsa_findings or (svc_count > 0 and gmsa_count == 0):
            verdict, score_delta, confidence, severity_hint = ExpertVerdict.SUPPORTS_EXPOSURE, 0.65, 0.72, "HIGH"
            summary = (
                f"Service accounts not using gMSA: {svc_count} with SPNs, {gmsa_count} gMSA "
                f"({adoption_pct}% gMSA adoption). Manual passwords expose Kerberoasting surface."
            )
        elif gmsa_count > 0 and svc_count == 0:
            verdict, score_delta, confidence, severity_hint = ExpertVerdict.CONTRADICTS_EXPOSURE, -0.2, 0.65, None
            summary = f"All detected service accounts use gMSA ({gmsa_count}) — no legacy password rotation risk."
        else:
            verdict, score_delta, confidence, severity_hint = ExpertVerdict.INSUFFICIENT_DATA, 0.0, 0.25, None
            summary = "Service account inventory not available — cannot assess gMSA adoption."

        return ExpertDecision(
            expert_id=self.expert_id, expert_name=self.expert_name, module_id=module_id,
            verdict=verdict, score_delta=score_delta, confidence=confidence,
            severity_hint=severity_hint, summary=summary,
            supporting_signals=supporting, contradicting_signals=contradicting, missing_signals=missing,
            related_finding_ids=finding_ids,
            related_entity_ids=[str(_get(e, "id", "")) for e in svc_entities[:10]],
            telemetry={"svc_with_spn": svc_count, "gmsa_count": gmsa_count, "adoption_pct": adoption_pct, "gmsa_findings": len(gmsa_findings)},
            mitre_techniques=["T1558.003"],
            kill_chain_stage="credential_access",
            remediation_commands=[
                "# Identify non-gMSA service accounts with SPNs:",
                "Get-ADUser -Filter {ServicePrincipalName -like '*'} -Properties ServicePrincipalName,PasswordLastSet | Where-Object {$_.ObjectClass -ne 'msDS-GroupManagedServiceAccount'}",
                "# Create a gMSA replacement:",
                "New-ADServiceAccount -Name 'svc-webapp-gmsa' -DNSHostName 'webapp.corp.local' -PrincipalsAllowedToRetrieveManagedPassword 'WebAppServers'",
            ],
            detection_opportunities=[
                "Monitor Kerberoastable service account TGS requests (event 4769 with RC4 encryption)",
                "Alert on service account password changes (event 4723/4724) to identify manual rotation",
            ],
        )


@register("service_accounts")
class ServiceAccountPasswordAgeExpert(BaseExpert):
    expert_id = "svc_password_age"
    expert_name = "Service Account Password Age & SPN Risk Expert"

    def evaluate(self, module_id: str, ctx: ValidationAssessmentContext) -> ExpertDecision:
        # Look for Kerberoastable / stale password findings in service accounts
        krb_findings = [
            f for f in ctx.findings
            if _finding_type(f) in ("KERBEROASTABLE_SERVICES", "KERBEROASTABLE_ADMIN", "KRB-002", "KRB-003", "KERBEROAST_RC4_ONLY")
            or any(kw in _finding_title(f) for kw in ("kerberoast", "service principal", "spn", "rc4"))
        ]

        svc_entities = [
            e for e in ctx.entities
            if str(_get(e, "entity_type", "")).upper() == "SERVICE_ACCOUNT"
        ]
        stale_svcs = [
            e for e in svc_entities
            if _attrs(e).get("days_since_last_logon", 0) and int(_attrs(e).get("days_since_last_logon", 0)) > 90
        ]
        rc4_svcs = [
            e for e in svc_entities
            if _attrs(e).get("rc4_only") or _attrs(e).get("supported_encryption_types") == 4
        ]

        supporting: list[str] = []
        missing: list[str] = []
        finding_ids = [str(_get(f, "id", "")) for f in krb_findings[:8]]

        if krb_findings:
            supporting.append(f"{len(krb_findings)} Kerberoastable service account finding(s) in assessment.")
        if stale_svcs:
            supporting.append(f"{len(stale_svcs)} service account(s) with no logon in 90+ days — stale SPN exposure.")
        if rc4_svcs:
            supporting.append(f"{len(rc4_svcs)} service account(s) using RC4-only encryption — weaker Kerberoast resistance.")
        if not (krb_findings or svc_entities):
            missing.append("Service account enumeration with encryption type attributes")

        total = len(krb_findings) + len(stale_svcs) + len(rc4_svcs)
        if total >= 3:
            verdict, score_delta, confidence, severity_hint = ExpertVerdict.SUPPORTS_EXPOSURE, 0.78, 0.80, "HIGH"
            summary = f"Service account Kerberoast risk: {len(krb_findings)} finding(s), {len(stale_svcs)} stale, {len(rc4_svcs)} RC4-only."
        elif total >= 1:
            verdict, score_delta, confidence, severity_hint = ExpertVerdict.WEAK_SUPPORT, 0.42, 0.60, "HIGH"
            summary = f"Service account password risk signals: {total} indicator(s)."
        else:
            verdict, score_delta, confidence, severity_hint = ExpertVerdict.INSUFFICIENT_DATA, 0.0, 0.25, None
            summary = "No service account password age data available."

        return ExpertDecision(
            expert_id=self.expert_id, expert_name=self.expert_name, module_id=module_id,
            verdict=verdict, score_delta=score_delta, confidence=confidence,
            severity_hint=severity_hint, summary=summary,
            supporting_signals=supporting, missing_signals=missing,
            related_finding_ids=finding_ids,
            related_entity_ids=[str(_get(e, "id", "")) for e in (stale_svcs + rc4_svcs)[:10]],
            telemetry={"krb_findings": len(krb_findings), "stale_svcs": len(stale_svcs), "rc4_svcs": len(rc4_svcs)},
            mitre_techniques=["T1558.003"],
            kill_chain_stage="credential_access",
            remediation_commands=[
                "# Rotate service account passwords regularly (or migrate to gMSA):",
                "Set-ADAccountPassword -Identity <svc_account> -Reset -NewPassword (Read-Host 'New password' -AsSecureString)",
                "# Force AES encryption on SPNs: Set-ADUser <account> -KerberosEncryptionType AES256,AES128",
            ],
            detection_opportunities=[
                "Alert on TGS requests using RC4 for service account SPNs (event 4769 etype 23)",
                "Monitor for offline Kerberoast cracking by correlating short-interval TGS bursts",
            ],
        )
