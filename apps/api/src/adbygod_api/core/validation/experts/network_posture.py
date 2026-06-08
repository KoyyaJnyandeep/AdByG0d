"""Network posture validation experts — covers NET-001 through NET-009 rule findings."""
from __future__ import annotations
import logging
from adbygod_api.core.validation.contracts import ExpertDecision, ExpertVerdict
from adbygod_api.core.validation.context import ValidationAssessmentContext
from adbygod_api.core.validation.experts.base import BaseExpert
from adbygod_api.core.validation.registry import register

log = logging.getLogger(__name__)

_NET_SIGNING_TYPES = frozenset(["SMB_SIGNING_DISABLED", "SMB_SIGNING_NOT_REQUIRED", "LDAP_SIGNING_DISABLED",
                                 "LDAP_CHANNEL_BINDING_DISABLED", "NTLM_DOWNGRADE", "NET-001", "NET-004", "NET-005", "NET-006"])
_NET_POISON_TYPES = frozenset(["LLMNR_ENABLED", "NBTNS_ENABLED", "NET-002", "NET-003"])
_NET_EXPOSURE_TYPES = frozenset(["WINRM_EXPOSED", "OPEN_SMB_SHARES", "CRED_MANAGER_SECRETS", "NET-007", "NET-008", "NET-009"])

def _get(obj, key: str, default=None):
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)

def _finding_type(f) -> str:
    return str(_get(f, "finding_type", "") or "").upper()

def _finding_title(f) -> str:
    return str(_get(f, "title", "") or "").lower()


@register("network_posture")
class SMBLDAPSigningExpert(BaseExpert):
    expert_id = "net_smb_ldap_signing"
    expert_name = "SMB / LDAP Signing Enforcement Expert"

    def evaluate(self, module_id: str, ctx: ValidationAssessmentContext) -> ExpertDecision:
        signing_findings = [
            f for f in ctx.findings
            if _finding_type(f) in _NET_SIGNING_TYPES
            or any(kw in _finding_type(f) for kw in ("SMB_SIGN", "LDAP_SIGN", "LDAP_CHANNEL", "NTLM_DOWN"))
            or any(kw in _finding_title(f) for kw in ("smb sign", "ldap sign", "channel bind", "ntlm lm compat"))
        ]
        network_evidence = [
            ev for ev in ctx.evidence
            if any(kw in (ev.collection_method or "").lower() for kw in ("smb", "ldap", "network", "registry"))
        ]

        smb_disabled = [f for f in signing_findings if "smb" in _finding_type(f).lower() or "smb" in _finding_title(f)]
        ldap_disabled = [f for f in signing_findings if "ldap" in _finding_type(f).lower() or "ldap" in _finding_title(f)]
        ntlm_downgrade = [f for f in signing_findings if "ntlm" in _finding_type(f).lower() or "ntlm" in _finding_title(f)]

        supporting: list[str] = []
        contradicting: list[str] = []
        missing: list[str] = []
        reasoning: list[str] = []
        finding_ids: list[str] = []

        if smb_disabled:
            supporting.append(f"{len(smb_disabled)} SMB signing gap(s) detected — relay precondition exists.")
            finding_ids += [str(_get(f, "id", "")) for f in smb_disabled[:5]]
            reasoning.append("SMB signing not required enables NTLM relay attacks across the domain.")
        else:
            missing.append("SMB signing posture (NET-001) — network config data may not have been collected")

        if ldap_disabled:
            supporting.append(f"{len(ldap_disabled)} LDAP signing/channel-binding gap(s) — enables LDAP relay.")
            finding_ids += [str(_get(f, "id", "")) for f in ldap_disabled[:5]]
            reasoning.append("LDAP without signing enables relaying credentials to create accounts or modify ACLs.")
        else:
            missing.append("LDAP signing policy (NET-005, NET-006)")

        if ntlm_downgrade:
            supporting.append(f"{len(ntlm_downgrade)} NTLM downgrade / LM compat finding(s).")
            finding_ids += [str(_get(f, "id", "")) for f in ntlm_downgrade[:3]]

        if network_evidence:
            contradicting.append(f"Network evidence records present ({len(network_evidence)}) — collection did run.")

        total = len(smb_disabled) + len(ldap_disabled) + len(ntlm_downgrade)
        if total >= 2:
            verdict, score_delta, confidence, severity_hint = ExpertVerdict.SUPPORTS_EXPOSURE, 0.82, 0.80, "CRITICAL"
            summary = f"Multiple signing enforcement gaps ({total}): SMB={len(smb_disabled)}, LDAP={len(ldap_disabled)}, NTLM={len(ntlm_downgrade)}"
        elif total == 1:
            verdict, score_delta, confidence, severity_hint = ExpertVerdict.WEAK_SUPPORT, 0.45, 0.60, "HIGH"
            summary = "Single signing gap detected — partial relay surface."
        elif network_evidence:
            verdict, score_delta, confidence, severity_hint = ExpertVerdict.CONTRADICTS_EXPOSURE, -0.3, 0.65, None
            summary = "Network evidence collected but no signing gaps detected — signing enforcement appears adequate."
        else:
            verdict, score_delta, confidence, severity_hint = ExpertVerdict.INSUFFICIENT_DATA, 0.0, 0.20, None
            summary = "No network posture data collected — signing enforcement status unknown."

        return ExpertDecision(
            expert_id=self.expert_id, expert_name=self.expert_name, module_id=module_id,
            verdict=verdict, score_delta=score_delta, confidence=confidence,
            severity_hint=severity_hint, summary=summary,
            reasoning=reasoning, supporting_signals=supporting,
            contradicting_signals=contradicting, missing_signals=missing,
            related_finding_ids=finding_ids[:10],
            telemetry={"smb_gaps": len(smb_disabled), "ldap_gaps": len(ldap_disabled), "ntlm_gaps": len(ntlm_downgrade), "network_evidence": len(network_evidence)},
            mitre_techniques=["T1557.001", "T1557"],
            kill_chain_stage="lateral_movement",
            remediation_commands=[
                "Set-SmbServerConfiguration -RequireSecuritySignature $true -Force",
                "# GPO: Computer Config > Windows Settings > Security Options > 'Microsoft network server: Digitally sign communications (always)'",
                "# Set LDAP signing: HKLM\\System\\CurrentControlSet\\Services\\NTDS\\Parameters\\LDAPServerIntegrity = 2",
                "# Set LM compatibility: HKLM\\System\\CurrentControlSet\\Control\\Lsa\\LmCompatibilityLevel = 5",
            ],
            detection_opportunities=[
                "Monitor event 4624 type 3 (network logon) NTLM from workstation sources",
                "Alert on SMB relay tool signatures in EDR telemetry",
                "Watch for LDAP binds from unexpected sources",
            ],
        )


@register("network_posture")
class PoisoningVectorExpert(BaseExpert):
    expert_id = "net_poisoning_vectors"
    expert_name = "LLMNR / NBT-NS Poisoning Vector Expert"

    def evaluate(self, module_id: str, ctx: ValidationAssessmentContext) -> ExpertDecision:
        poison_findings = [
            f for f in ctx.findings
            if _finding_type(f) in _NET_POISON_TYPES
            or any(kw in _finding_type(f) for kw in ("LLMNR", "NBTNS", "NBT_NS"))
            or any(kw in _finding_title(f) for kw in ("llmnr", "nbt-ns", "nbtns", "name resolution", "mdns"))
        ]

        llmnr = [f for f in poison_findings if "llmnr" in _finding_type(f).lower() or "llmnr" in _finding_title(f)]
        nbtns = [f for f in poison_findings if "nbt" in _finding_type(f).lower() or "nbt" in _finding_title(f)]

        supporting: list[str] = []
        contradicting: list[str] = []
        missing: list[str] = []
        finding_ids: list[str] = []

        if llmnr:
            supporting.append("LLMNR enabled — Responder/Inveigh can capture NTLMv2 hashes from misdirected queries.")
            finding_ids += [str(_get(f, "id", "")) for f in llmnr[:3]]
        else:
            missing.append("LLMNR configuration (registry key DisableMulticastDNSPublish / MDNS)")

        if nbtns:
            supporting.append("NBT-NS enabled — legacy broadcast name resolution enables credential capture on flat networks.")
            finding_ids += [str(_get(f, "id", "")) for f in nbtns[:3]]
        else:
            missing.append("NBT-NS configuration (NodeType registry key)")

        total = len(llmnr) + len(nbtns)
        if total >= 2:
            verdict, score_delta, confidence, severity_hint = ExpertVerdict.SUPPORTS_EXPOSURE, 0.75, 0.78, "HIGH"
            summary = "Both LLMNR and NBT-NS poisoning vectors enabled — passive credential capture surface confirmed."
        elif total == 1:
            verdict, score_delta, confidence, severity_hint = ExpertVerdict.WEAK_SUPPORT, 0.40, 0.60, "HIGH"
            summary = "Partial poisoning vector (LLMNR or NBT-NS) enabled."
        else:
            verdict, score_delta, confidence, severity_hint = ExpertVerdict.INSUFFICIENT_DATA, 0.0, 0.25, None
            summary = "No LLMNR/NBT-NS data in assessment — network collection may not have run."

        return ExpertDecision(
            expert_id=self.expert_id, expert_name=self.expert_name, module_id=module_id,
            verdict=verdict, score_delta=score_delta, confidence=confidence,
            severity_hint=severity_hint, summary=summary,
            supporting_signals=supporting, contradicting_signals=contradicting, missing_signals=missing,
            related_finding_ids=finding_ids[:8],
            telemetry={"llmnr_findings": len(llmnr), "nbtns_findings": len(nbtns)},
            mitre_techniques=["T1557.001"],
            kill_chain_stage="credential_access",
            remediation_commands=[
                "# Disable LLMNR via GPO: Computer Config > Admin Templates > Network > DNS Client > Turn off multicast name resolution",
                "# Disable NBT-NS: Network adapter properties > IPv4 > Advanced > WINS > Disable NetBIOS over TCP/IP",
                "# PowerShell: $NICs = Get-WmiObject Win32_NetworkAdapterConfiguration; $NICs | foreach {$_.SetTcpipNetbios(2)}",
            ],
            detection_opportunities=[
                "Monitor for Responder/Inveigh tool signatures in EDR",
                "Honeypot: deploy fake shares and alert on LLMNR queries for non-existent hostnames",
            ],
        )


@register("network_posture")
class NetworkExposureExpert(BaseExpert):
    expert_id = "net_service_exposure"
    expert_name = "WinRM / SMB Share / Credential Store Exposure Expert"

    def evaluate(self, module_id: str, ctx: ValidationAssessmentContext) -> ExpertDecision:
        exposure_findings = [
            f for f in ctx.findings
            if _finding_type(f) in _NET_EXPOSURE_TYPES
            or any(kw in _finding_type(f) for kw in ("WINRM", "SMB_SHARE", "CRED_MANAGER", "OPEN_SHARE"))
            or any(kw in _finding_title(f) for kw in ("winrm", "smb share", "credential manager", "open share", "cred manager"))
        ]

        winrm = [f for f in exposure_findings if "winrm" in _finding_type(f).lower() or "winrm" in _finding_title(f)]
        shares = [f for f in exposure_findings if "share" in _finding_type(f).lower() or "share" in _finding_title(f)]
        credmgr = [f for f in exposure_findings if "cred" in _finding_type(f).lower() or "cred" in _finding_title(f)]

        supporting: list[str] = []
        contradicting: list[str] = []
        missing: list[str] = []
        finding_ids: list[str] = []

        if winrm:
            supporting.append(f"{len(winrm)} WinRM exposure finding(s) — remote management attack surface identified.")
            finding_ids += [str(_get(f, "id", "")) for f in winrm[:3]]

        if shares:
            supporting.append(f"{len(shares)} open/accessible SMB share finding(s) — lateral movement / data staging risk.")
            finding_ids += [str(_get(f, "id", "")) for f in shares[:3]]

        if credmgr:
            supporting.append(f"{len(credmgr)} Credential Manager secret finding(s) — stored plaintext/cached credential risk.")
            finding_ids += [str(_get(f, "id", "")) for f in credmgr[:3]]

        if not (winrm or shares or credmgr):
            missing.append("WinRM, SMB share, and Credential Manager data (network collection modules)")

        total = len(winrm) + len(shares) + len(credmgr)
        if total >= 2:
            verdict, score_delta, confidence, severity_hint = ExpertVerdict.SUPPORTS_EXPOSURE, 0.65, 0.72, "HIGH"
            summary = f"Multiple network service exposure vectors ({total}): WinRM={len(winrm)}, Shares={len(shares)}, CredMgr={len(credmgr)}"
        elif total == 1:
            verdict, score_delta, confidence, severity_hint = ExpertVerdict.WEAK_SUPPORT, 0.35, 0.55, "MEDIUM"
            summary = "Single network exposure vector detected."
        else:
            verdict, score_delta, confidence, severity_hint = ExpertVerdict.INSUFFICIENT_DATA, 0.0, 0.20, None
            summary = "No WinRM/share/CredMgr exposure data available."

        return ExpertDecision(
            expert_id=self.expert_id, expert_name=self.expert_name, module_id=module_id,
            verdict=verdict, score_delta=score_delta, confidence=confidence,
            severity_hint=severity_hint, summary=summary,
            supporting_signals=supporting, contradicting_signals=contradicting, missing_signals=missing,
            related_finding_ids=finding_ids[:10],
            telemetry={"winrm_findings": len(winrm), "share_findings": len(shares), "credmgr_findings": len(credmgr)},
            mitre_techniques=["T1021.006", "T1135", "T1555.004"],
            kill_chain_stage="lateral_movement",
            remediation_commands=[
                "Disable-PSRemoting -Force  # Disable WinRM if not required",
                "# Audit SMB shares: Get-SmbShare | Where-Object {$_.Name -notmatch '^(ADMIN|IPC|C|NETLOGON|SYSVOL)\\$'}",
                "# Remove stored credentials: cmdkey /list | ForEach-Object {cmdkey /delete:$_}",
            ],
            detection_opportunities=[
                "Monitor WinRM connections from non-admin workstations (event 4624 + WinRM port 5985/5986)",
                "Alert on SMB share access from unexpected principals via file audit events (event 5145)",
            ],
        )


@register("network_posture")
class NetworkPostureScoringExpert(BaseExpert):
    expert_id = "net_posture_aggregate"
    expert_name = "Network Posture Aggregate Scoring Expert"

    def evaluate(self, module_id: str, ctx: ValidationAssessmentContext) -> ExpertDecision:
        net_findings = [
            f for f in ctx.findings
            if any(kw in _finding_type(f) for kw in (
                "SMB", "LDAP", "LLMNR", "NBTNS", "NBT", "WINRM", "NTLM", "NET", "SHARE", "CRED_MANAGER"
            ))
            or any(kw in _finding_title(f) for kw in (
                "smb", "ldap sign", "llmnr", "nbt", "winrm", "ntlm", "network", "credential manager"
            ))
        ]

        critical_net = [f for f in net_findings if str(_get(f, "severity", "")).upper() == "CRITICAL"]
        high_net = [f for f in net_findings if str(_get(f, "severity", "")).upper() == "HIGH"]

        supporting: list[str] = []
        missing: list[str] = []

        if critical_net:
            supporting.append(f"{len(critical_net)} CRITICAL network posture finding(s) in assessment scope.")
        if high_net:
            supporting.append(f"{len(high_net)} HIGH network posture finding(s) in assessment scope.")

        if ctx.dc_count > 0:
            supporting.append(f"{ctx.dc_count} domain controller(s) in scope — posture applies domain-wide.")

        if not net_findings:
            missing.append("Network posture collection (SMB signing, LLMNR, NBT-NS, LDAP signing modules)")

        total_net = len(net_findings)
        critical_count = len(critical_net)

        if critical_count >= 2:
            verdict, score_delta, confidence, severity_hint = ExpertVerdict.SUPPORTS_EXPOSURE, 0.88, 0.82, "CRITICAL"
            summary = f"Critical network posture gaps: {critical_count} CRITICAL + {len(high_net)} HIGH findings across {ctx.dc_count} DC(s)."
        elif total_net >= 3:
            verdict, score_delta, confidence, severity_hint = ExpertVerdict.SUPPORTS_EXPOSURE, 0.72, 0.75, "HIGH"
            summary = f"Significant network posture exposure: {total_net} network findings."
        elif total_net >= 1:
            verdict, score_delta, confidence, severity_hint = ExpertVerdict.WEAK_SUPPORT, 0.35, 0.55, "MEDIUM"
            summary = f"Partial network posture gaps: {total_net} finding(s)."
        else:
            verdict, score_delta, confidence, severity_hint = ExpertVerdict.INSUFFICIENT_DATA, 0.0, 0.20, None
            summary = "Network posture collection not run or no findings — cannot assess relay/poisoning surface."

        return ExpertDecision(
            expert_id=self.expert_id, expert_name=self.expert_name, module_id=module_id,
            verdict=verdict, score_delta=score_delta, confidence=confidence,
            severity_hint=severity_hint, summary=summary,
            supporting_signals=supporting, missing_signals=missing,
            related_finding_ids=[str(_get(f, "id", "")) for f in (critical_net + high_net)[:10]],
            telemetry={"total_network_findings": total_net, "critical": critical_count, "high": len(high_net), "dc_count": ctx.dc_count},
            mitre_techniques=["T1557", "T1557.001", "T1021.006", "T1135"],
            kill_chain_stage="lateral_movement",
            remediation_commands=[
                "# Comprehensive network hardening baseline: enable SMB/LDAP signing, disable LLMNR/NBT-NS, restrict WinRM",
            ],
            detection_opportunities=["Deploy network honeypots and monitor for relay tool traffic patterns"],
        )
