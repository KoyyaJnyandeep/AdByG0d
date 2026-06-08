from __future__ import annotations

import logging
import math
from typing import Any

log = logging.getLogger(__name__)

FOREST_TECHNIQUE_CATALOGUE: dict[str, dict[str, Any]] = {
    "FOREST_TRUST_KEY_FORGERY": {
        "name": "Forest Trust Key Forgery",
        "mitre_id": "T1558.001", "cve": None, "tier": 1, "severity": "CRITICAL",
        "attack_steps": [
            "DCSync the trust account (TARGETFOREST$) from source forest DC",
            "Extract RC4/AES keys of the inter-forest trust account",
            "Forge inter-realm TGT with ExtraSIDs for target forest Enterprise Admins",
            "Use forged ticket to access any resource in target forest",
        ],
        "remediation_steps": [
            "Enable SID Filtering + Quarantine on all forest trusts",
            "Rotate trust keys: netdom trust /resetpassword",
            "Monitor DCSync on trust account objects",
        ],
        "opsec_notes": "Trust key forgery is stealthier than krbtgt-based golden ticket. Use AES256 key.",
    },
    "FOREST_ADCS_ESC1_CROSS": {
        "name": "Cross-Forest ADCS ESC1 Certificate Enrollment",
        "mitre_id": "T1649", "cve": None, "tier": 1, "severity": "CRITICAL",
        "attack_steps": [
            "Identify CA in target forest accepting enrollment from source forest principals",
            "Find ESC1-vulnerable template (CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT)",
            "Enroll certificate with SAN = target forest DA UPN",
            "PKINIT TGT request as DA in target forest",
        ],
        "remediation_steps": [
            "Restrict cross-forest CA enrollment to specific groups",
            "Remove CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT from all templates",
        ],
        "opsec_notes": "Cross-forest cert enrollment blends with normal PKI. Use Certipy with --dc-ip of target forest DC.",
    },
    "FOREST_UGMC_STALE": {
        "name": "Universal Group Membership Caching (UGMC) Stale Cache Attack",
        "mitre_id": "T1078", "cve": None, "tier": 2, "severity": "HIGH",
        "attack_steps": [
            "Identify GC (Global Catalog) server with UGMC enabled",
            "Modify group membership in source forest before cache refresh",
            "Cached universal group membership in target forest reflects old state",
            "Exploit stale group membership for unauthorized access",
        ],
        "remediation_steps": [
            "Reduce UGMC TTL or disable where not needed",
            "Ensure GC servers replicate frequently across forest boundaries",
        ],
        "opsec_notes": "Cache staleness window creates temporary privilege window. Time attacks around cache refresh intervals.",
    },
    "FOREST_TRANSITIVE_HOP": {
        "name": "Multi-Hop Transitive Trust Chain (A→B→C)",
        "mitre_id": "T1078", "cve": None, "tier": 1, "severity": "HIGH",
        "attack_steps": [
            "Map full trust topology including indirect transitive paths",
            "Identify path: Forest A → Forest B → Forest C (where A has no direct trust to C)",
            "Compromise Forest B as stepping stone",
            "Use Forest B compromise to pivot into Forest C via that forest's trusts",
        ],
        "remediation_steps": [
            "Audit entire trust topology for unintended transitive paths",
            "Use non-transitive trusts between forests of differing security tiers",
        ],
        "opsec_notes": "Indirect transitive paths are often overlooked in security reviews. Map with BloodHound forest trust edges.",
    },
    "FOREST_SCHEMA_NC_WRITE": {
        "name": "Schema/Configuration NC Write for Forest-Wide Backdoor",
        "mitre_id": "T1484", "cve": None, "tier": 3, "severity": "CRITICAL",
        "attack_steps": [
            "Gain Schema Admin or Enterprise Admin access",
            "Modify Schema NC to add backdoor attribute or extend objects",
            "Add ACE to Configuration NC to grant permanent cross-forest access",
            "Modification replicates to all DCs in all domains across the forest",
        ],
        "remediation_steps": [
            "Treat Schema Admins and Enterprise Admins as tier-0",
            "Monitor Schema NC modifications (Event 5136 with objectClass=attributeSchema)",
        ],
        "opsec_notes": "Schema changes replicate silently. Extremely persistent — survives domain rebuilds short of full forest rebuild.",
    },
    "FOREST_SID_FILTER_PARTIAL": {
        "name": "Forest SID Filter Partial Bypass (RID < 1000)",
        "mitre_id": "T1134.005", "cve": None, "tier": 3, "severity": "HIGH",
        "attack_steps": [
            "Identify forest trust with SID filtering but without quarantine flag",
            "Inject well-known SIDs (RID < 1000: Enterprise Admins, Cert Publishers, etc.)",
            "If quarantine not set, these RIDs pass the SID filter",
            "Authenticate cross-forest with injected well-known SID",
        ],
        "remediation_steps": [
            "Enable SID Quarantine: netdom trust <forest> /quarantine:yes",
            "Block ALL cross-forest SID history (even RID < 1000)",
        ],
        "opsec_notes": "Extremely rare misconfiguration — high impact. Verify with Get-ADTrust | fl *.",
    },
    "FOREST_MIT_NO_FILTER": {
        "name": "MIT Kerberos Realm Trust (No SID Filtering)",
        "mitre_id": "T1558", "cve": None, "tier": 3, "severity": "CRITICAL",
        "attack_steps": [
            "Identify MIT Kerberos realm trust with AD forest",
            "MIT realm has no concept of SIDs — all SID filtering bypassed",
            "Obtain MIT Kerberos TGT",
            "Present cross-realm ticket to AD forest — arbitrary AD resource access",
        ],
        "remediation_steps": [
            "Remove MIT realm trusts unless absolutely required",
            "Implement application-level authorization on resources accessible via MIT realm",
        ],
        "opsec_notes": "MIT realm trusts unconditionally bypass all SID filtering — avoid creating them.",
    },
    "FOREST_EXCHANGE_WRITEDACL": {
        "name": "Exchange Windows Permissions Group WriteDACL Abuse Cross-Forest",
        "mitre_id": "T1222", "cve": "CVE-2018-8581", "tier": 2, "severity": "CRITICAL",
        "attack_steps": [
            "Identify Exchange deployment in forest (adds EWP group with WriteDACL on domain NC root)",
            "Compromise any Exchange server or EWP member",
            "Use WriteDACL to grant attacker DCSync rights on domain",
            "DCSync all hashes → full domain compromise",
        ],
        "remediation_steps": [
            "Apply Exchange CU addressing CVE-2018-8581",
            "Remove unnecessary WriteDACL from EWP on domain NC root",
            "Run Exchange split-permissions model",
        ],
        "opsec_notes": "WriteDACL → DCSync chain is fast. Exchange compromise often overlooked as forest-wide risk.",
    },
    "FOREST_RODC_REVEALED_CREDS": {
        "name": "RODC Revealed Credentials Cross-Forest",
        "mitre_id": "T1558", "cve": None, "tier": 2, "severity": "HIGH",
        "attack_steps": [
            "Compromise RODC at forest boundary",
            "Extract cached credentials from RODC NTDS partial replica",
            "Cached accounts may include cross-forest service accounts",
            "Use credentials for cross-forest lateral movement",
        ],
        "remediation_steps": [
            "Audit msDS-RevealedList on all RODCs",
            "Add privileged accounts to msDS-NeverRevealGroup",
            "Treat RODC compromise as forest-wide incident",
        ],
        "opsec_notes": "RODC contains partial NTDS — extract with secretsdump -just-dc-ntlm on the RODC itself.",
    },
    "FOREST_SHADOW_PRINCIPAL_PAM": {
        "name": "Shadow Principal Cross-Forest PAM Privilege",
        "mitre_id": "T1134.001", "cve": None, "tier": 1, "severity": "CRITICAL",
        "attack_steps": [
            "Enumerate shadow principal mappings in bastion forest (msDS-ShadowPrincipalSid)",
            "Identify shadow principal mapped to DA/EA in production forest",
            "Compromise the bastion forest account linked as shadow principal",
            "Authenticate to production forest with time-limited elevated access",
        ],
        "remediation_steps": [
            "Audit all shadow principal mappings regularly",
            "Enforce minimal JIT access windows",
        ],
        "opsec_notes": "PAM access is time-windowed — must act within JIT window.",
    },
    "FOREST_GPO_CROSS_DOMAIN": {
        "name": "Cross-Domain GPO Delegation for Forest Pivot",
        "mitre_id": "T1484.001", "cve": None, "tier": 2, "severity": "HIGH",
        "attack_steps": [
            "Identify GPO in child domain with write access from current context",
            "Modify GPO to execute payload on machines in child domain",
            "Pivot from child domain admin to forest-wide escalation via forest trust",
        ],
        "remediation_steps": [
            "Audit cross-domain GPO write delegations",
            "Segment GPO administration per domain",
        ],
        "opsec_notes": "GPO changes replicate over SYSVOL — detectable via FIM on SYSVOL. Use scheduled task inside GPO for delayed execution.",
    },
    "FOREST_TICKET_DECRYPTION_ORACLE": {
        "name": "Kerberos Ticket Decryption Oracle (AS-REP Pre-Auth Bypass)",
        "mitre_id": "T1558.004", "cve": None, "tier": 3, "severity": "HIGH",
        "attack_steps": [
            "Identify forest with AS-REP roastable accounts across trust boundary",
            "Request AS-REP from target forest DC without credentials",
            "Crack encrypted AS-REP offline",
            "Use cracked password for cross-forest authentication",
        ],
        "remediation_steps": [
            "Enable pre-authentication on all accounts",
            "Audit cross-forest ASREP requests in security logs",
        ],
        "opsec_notes": "AS-REP request to foreign DC generates Event 4768 on target — spread timing.",
    },
    "FOREST_RESOURCE_RBCD_CROSS": {
        "name": "RBCD Cross-Forest S4U2Proxy",
        "mitre_id": "T1558.001", "cve": None, "tier": 2, "severity": "HIGH",
        "attack_steps": [
            "Write msDS-AllowedToActOnBehalfOfOtherIdentity on target cross-forest machine",
            "Use S4U2Self on attacker-controlled principal",
            "Use S4U2Proxy to get TGS for target service in other forest",
        ],
        "remediation_steps": [
            "Restrict msDS-AllowedToActOnBehalfOfOtherIdentity write cross-forest",
            "Enable LDAP signing + channel binding to prevent relay-based writes",
        ],
        "opsec_notes": "RBCD write is a single LDAP modification — quiet. Whisker/Impacket for the LDAP write.",
    },
    "FOREST_DNSADMIN_CROSS": {
        "name": "Cross-Forest DNSAdmin DLL Injection",
        "mitre_id": "T1574.002", "cve": None, "tier": 2, "severity": "HIGH",
        "attack_steps": [
            "Compromise DnsAdmins member in child domain or trusted forest",
            "Set malicious DLL for DNS service on forest boundary DC",
            "Restart DNS service — DLL loads under SYSTEM context",
            "Use SYSTEM on boundary DC for cross-forest movement",
        ],
        "remediation_steps": [
            "Restrict DnsAdmins membership to minimum necessary",
            "Block outbound SMB from boundary DCs",
        ],
        "opsec_notes": "DNS service restart is auditable — use local path DLL to avoid UNC evidence.",
    },
    "FOREST_AADCONNECT_CLOUD_PIVOT": {
        "name": "AADConnect Cross-Forest Cloud Pivot",
        "mitre_id": "T1003.006", "cve": None, "tier": 2, "severity": "CRITICAL",
        "attack_steps": [
            "Identify AADConnect server syncing multiple forests",
            "Extract MSOL_ account with DCSync rights across all synced forests",
            "Use MSOL_ account to DCSync ALL synced forests simultaneously",
            "Also extract cloud user credentials for Azure/M365 pivot",
        ],
        "remediation_steps": [
            "One AADConnect server per forest — never multi-forest AADConnect",
            "Harden AADConnect server to tier-0 equivalent",
        ],
        "opsec_notes": "Single MSOL_ account may have DCSync across multiple forests — enormous blast radius.",
    },
    "FOREST_NETLOGON_ZEROLOGON": {
        "name": "Zerologon Cross-Forest Netlogon Exploit",
        "mitre_id": "T1210", "cve": "CVE-2020-1472", "tier": 3, "severity": "CRITICAL",
        "attack_steps": [
            "Identify unpatched DC in target forest accessible via Netlogon",
            "Exploit Zerologon to set DC machine account password to empty string",
            "DCSync target forest using compromised DC account",
        ],
        "remediation_steps": [
            "Apply August 2020 Netlogon patches (CVE-2020-1472)",
            "Enable full enforcement mode: FullSecureChannelProtection = 1",
        ],
        "opsec_notes": "Zerologon is extremely noisy — generates Event 4742 (password reset). Only use on unpatched targets.",
    },
    "FOREST_TRUST_CREATION_ABUSE": {
        "name": "Unauthorized Forest Trust Creation",
        "mitre_id": "T1484", "cve": None, "tier": 3, "severity": "HIGH",
        "attack_steps": [
            "Gain Enterprise Admin in source forest",
            "Create unauthorized outbound trust to attacker-controlled forest",
            "Use new trust for long-term persistent access",
        ],
        "remediation_steps": [
            "Monitor trust creation events (Event 4739 — Domain Policy Changed)",
            "Alert on any new forest trust creation",
        ],
        "opsec_notes": "Trust creation requires EA — but persistent. Blends with legitimate trust setup.",
    },
    "FOREST_MSSQL_CROSSFOREST_LINK": {
        "name": "Cross-Forest MSSQL Linked Server Chain",
        "mitre_id": "T1210", "cve": None, "tier": 2, "severity": "HIGH",
        "attack_steps": [
            "Identify SQL Server with linked server configured to cross-forest SQL instance",
            "Execute xp_cmdshell via linked server chain",
            "Pivot through SQL chain to reach forest-boundary systems",
        ],
        "remediation_steps": [
            "Disable cross-forest SQL Server linked servers",
            "Disable xp_cmdshell on all instances",
        ],
        "opsec_notes": "SQL linked server chains can span multiple forests invisibly. Map with Get-SQLServerLinkCrawl.",
    },
    "FOREST_PRINTNIGHTMARE_CROSS": {
        "name": "Cross-Forest PrintNightmare Exploitation",
        "mitre_id": "T1068", "cve": "CVE-2021-34527", "tier": 2, "severity": "HIGH",
        "attack_steps": [
            "Identify Print Spooler service running on cross-forest reachable server",
            "Load malicious DLL via AddPrinterDriver from source forest",
            "Code executes as SYSTEM on target forest boundary server",
        ],
        "remediation_steps": [
            "Disable Print Spooler on all boundary servers",
            "Apply KB5004945",
        ],
        "opsec_notes": "Cross-forest DLL load requires UNC path reachable across trust — ensure network path exists.",
    },
    "FOREST_HIVENIGHTMARE_CROSS": {
        "name": "HiveNightmare Cross-Forest Hash Extraction",
        "mitre_id": "T1003.002", "cve": "CVE-2021-36934", "tier": 2, "severity": "HIGH",
        "attack_steps": [
            "Gain non-admin shell on cross-forest boundary machine (unpatched)",
            "Read SAM/SYSTEM hives from VSS shadow copies",
            "Extract local admin hash and use for cross-forest PTH to other boundary machines",
        ],
        "remediation_steps": [
            "Apply KB5005010",
            "Remove unnecessary VSS shadow copies",
        ],
        "opsec_notes": "File reads from VSS are virtually silent. No privilege escalation needed.",
    },
    "FOREST_NOPAC_CROSS": {
        "name": "noPac Cross-Forest Privilege Escalation",
        "mitre_id": "T1558.001", "cve": "CVE-2021-42278 / CVE-2021-42287", "tier": 3, "severity": "CRITICAL",
        "attack_steps": [
            "Identify unpatched DC in target forest accessible via trust",
            "Create machine account in target forest (via cross-trust rights)",
            "Spoof sAMAccountName as target DC name",
            "Request TGT, then TGS — KDC impersonates DC",
            "DCSync target forest",
        ],
        "remediation_steps": [
            "Apply November 2021 patches on all forest DCs",
            "Set MachineAccountQuota to 0 across all forest domains",
        ],
        "opsec_notes": "Cross-forest noPac requires machine account creation rights in target forest — rare but high impact.",
    },
    "FOREST_CERTIFRIED_CROSS": {
        "name": "Certifried Cross-Forest dNSHostName Spoof",
        "mitre_id": "T1649", "cve": "CVE-2022-26923", "tier": 3, "severity": "HIGH",
        "attack_steps": [
            "Identify unpatched CA in target forest",
            "Modify dNSHostName of source machine to match target forest DC",
            "Enroll Machine template certificate — CA issues cert for spoofed DC name",
            "PKINIT TGT as target forest DC → DCSync",
        ],
        "remediation_steps": [
            "Apply May 2022 updates across all forest CAs",
            "Restrict dNSHostName modification",
        ],
        "opsec_notes": "Requires machine account or dNSHostName write access. Target unpatched CAs in forests with weak certificate governance.",
    },
}


def build_forest_graph(trusts: list[dict], entities: list[dict]) -> dict:
    domains = set()
    for t in trusts:
        if t.get("name"):
            domains.add(t["name"])
    for e in entities:
        if e.get("domain"):
            domains.add(e["domain"])

    domain_list = sorted(domains)
    n = len(domain_list)
    nodes = []
    for i, domain in enumerate(domain_list):
        angle = (2 * math.pi * i / max(n, 1))
        cx, cy = 300, 300
        r = min(200, 50 * n)
        x = cx + r * math.cos(angle)
        y = cy + r * math.sin(angle)

        has_adcs = any(
            e.get("domain", "").upper() == domain.upper() and
            e.get("entity_type") in ("CA", "CERTIFICATE_TEMPLATE")
            for e in entities
        )
        nodes.append({
            "id": domain,
            "label": domain,
            "x": round(x, 1),
            "y": round(y, 1),
            "has_adcs": has_adcs,
        })

    edges = []
    for t in trusts:
        risk = "HIGH" if not t.get("sid_filtering") else "MEDIUM"
        if t.get("forest_trust") and not t.get("sid_filtering"):
            risk = "CRITICAL"
        edges.append({
            "source": t.get("name", ""),
            "target": t.get("partner", t.get("name", "")),
            "direction": t.get("direction", "Bidirectional"),
            "transitive": t.get("transitive", True),
            "risk": risk,
            "sid_filtering": t.get("sid_filtering", False),
        })

    return {"nodes": nodes, "edges": edges}


def detect_forest_techniques(
    trusts: list[dict],
    entities: list[dict],
    edges: list[dict],
) -> list[dict]:
    results: list[dict] = []
    edge_types = {e.get("edge_type", "") for e in edges}
    for trust in trusts:
        forest_trust = trust.get("forest_trust", False)
        sid_filtering = trust.get("sid_filtering", False)
        trust_type = trust.get("trust_type", "")
        transitive = trust.get("transitive", True)
        quarantine = trust.get("quarantine", False)
        name = trust.get("name", "")

        if forest_trust and not sid_filtering:
            results.append(_forest_hit("FOREST_TRUST_KEY_FORGERY", trust=name))
            results.append(_forest_hit("FOREST_ADCS_ESC1_CROSS", trust=name))

        if transitive and forest_trust:
            results.append(_forest_hit("FOREST_TRANSITIVE_HOP", trust=name))

        if forest_trust and sid_filtering and not quarantine:
            results.append(_forest_hit("FOREST_SID_FILTER_PARTIAL", trust=name))

        if "mit" in trust_type.lower() or "non-windows" in trust_type.lower():
            results.append(_forest_hit("FOREST_MIT_NO_FILTER", trust=name))

        if trust.get("is_pam_trust"):
            results.append(_forest_hit("FOREST_SHADOW_PRINCIPAL_PAM", trust=name))

    # ADCS cross-forest
    if "ADCS_ESC1" in edge_types or "ADCS_ESC8" in edge_types:
        results.append(_forest_hit("FOREST_ADCS_ESC1_CROSS"))

    # AADConnect multi-forest
    if "AADCONNECT_SYNC" in edge_types:
        results.append(_forest_hit("FOREST_AADCONNECT_CLOUD_PIVOT"))

    # Exchange
    has_exchange = any(
        e.get("entity_type") in ("EXCHANGE_SERVER", "EXCHANGE") or
        "exchange" in str(e.get("attributes", {}).get("services", [])).lower()
        for e in entities
    )
    if has_exchange:
        results.append(_forest_hit("FOREST_EXCHANGE_WRITEDACL"))

    # CVE chains
    if "CVE_CHAIN" in edge_types:
        results.append(_forest_hit("FOREST_NOPAC_CROSS"))
        results.append(_forest_hit("FOREST_CERTIFRIED_CROSS"))

    # Coercion primitives detected
    coercion_types = {"PETITPOTAM", "PRINTSPOOLER", "SHADOWCOERCE", "DFSCOERCE"}
    if coercion_types & edge_types:
        results.append(_forest_hit("FOREST_PRINTNIGHTMARE_CROSS"))

    # SQL linked servers
    if "MSSQL_LINKED" in edge_types:
        results.append(_forest_hit("FOREST_MSSQL_CROSSFOREST_LINK"))

    # Deduplicate
    seen: set[str] = set()
    deduped: list[dict] = []
    for r in results:
        if r["technique_id"] not in seen:
            seen.add(r["technique_id"])
            deduped.append(r)

    return deduped


def compute_pivot_paths(trusts: list[dict]) -> list[dict]:
    trust_map: dict[str, list[str]] = {}
    for t in trusts:
        name = t.get("name", "")
        partner = t.get("partner", "")
        if name and partner:
            trust_map.setdefault(name, []).append(partner)
            direction_val = t.get("direction_val", 3)
            if direction_val in (1, 3):
                trust_map.setdefault(partner, []).append(name)

    paths: list[dict] = []
    all_domains = set(trust_map.keys())

    for start in all_domains:
        visited = {start}
        queue = [(start, [start])]
        while queue:
            current, path = queue.pop(0)
            for neighbor in trust_map.get(current, []):
                if neighbor not in visited:
                    visited.add(neighbor)
                    new_path = path + [neighbor]
                    if len(new_path) > 1:
                        paths.append({
                            "path": new_path,
                            "hops": len(new_path) - 1,
                            "start": start,
                            "end": neighbor,
                        })
                    if len(new_path) < 5:
                        queue.append((neighbor, new_path))

    return paths


def _forest_hit(technique_id: str, **kwargs) -> dict:
    cat = FOREST_TECHNIQUE_CATALOGUE.get(technique_id, {})
    return {
        "technique_id": technique_id,
        "name": cat.get("name", technique_id),
        "mitre_id": cat.get("mitre_id"),
        "cve": cat.get("cve"),
        "tier": cat.get("tier", 2),
        "severity": cat.get("severity", "HIGH"),
        "attack_steps": cat.get("attack_steps", []),
        "remediation_steps": cat.get("remediation_steps", []),
        "opsec_notes": cat.get("opsec_notes", ""),
        **kwargs,
    }


class ForestPivotAnalyzer:
    def __init__(self, trusts: list[dict], entities: list[dict], edges: list[dict]):
        self._trusts = trusts
        self._entities = entities
        self._edges = edges

    def analyze(self) -> dict:
        techniques = detect_forest_techniques(self._trusts, self._entities, self._edges)
        pivot_paths = compute_pivot_paths(self._trusts)
        graph = build_forest_graph(self._trusts, self._entities)

        return {
            "techniques": techniques,
            "pivot_paths": pivot_paths,
            "graph": graph,
            "summary": {
                "total_techniques": len(techniques),
                "critical_count": sum(1 for t in techniques if t["severity"] == "CRITICAL"),
                "high_count": sum(1 for t in techniques if t["severity"] == "HIGH"),
                "forest_count": len(self._trusts),
                "pivot_paths_count": len(pivot_paths),
            },
        }
