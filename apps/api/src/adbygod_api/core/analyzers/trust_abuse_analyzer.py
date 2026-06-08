from __future__ import annotations

import logging
from typing import Any

log = logging.getLogger(__name__)

_SEVERITY: dict[str, str] = {
    "SID_HISTORY_INJECTION":        "CRITICAL",
    "EXTRASID_GOLDEN_TICKET":       "CRITICAL",
    "PAM_TRUST_ABUSE":              "CRITICAL",
    "TRUST_KEY_EXTRACTION_FORGERY": "CRITICAL",
    "SAPPHIRE_DIAMOND_TICKET":      "CRITICAL",
    "AADCONNECT_SYNC":              "CRITICAL",
    "TRANSITIVE_DELEGATION":        "HIGH",
    "TRUST_ESCALATION_CHAIN":       "HIGH",
    "RC4_TRUST_DOWNGRADE":          "HIGH",
    "TRUST_PASSWORD_OVERLAP_WINDOW":"HIGH",
    "SELECTIVE_AUTH_BYPASS":        "HIGH",
    "CROSS_TRUST_KERBEROASTING":    "HIGH",
    "CROSS_TRUST_ASREP_ROASTING":   "HIGH",
    "CROSS_TRUST_ADCS_ESC1_ESC8":   "CRITICAL",
    "CROSS_TRUST_SHADOW_CREDENTIALS":"HIGH",
    "BRONZE_BIT_CROSS_TRUST":       "HIGH",
    "TDO_MANIPULATION":             "HIGH",
    "PAC_VALIDATION_BYPASS":        "CRITICAL",
    "RODC_CROSS_TRUST_CACHE":       "MEDIUM",
    "SID_FILTER_PARTIAL_BYPASS":    "HIGH",
    "MIT_KERBEROS_REALM_TRUST":     "HIGH",
    "NOPAC_CROSS_TRUST":            "CRITICAL",
    "FAST_ARMORING_BYPASS":         "MEDIUM",
}

TECHNIQUE_CATALOGUE: dict[str, dict[str, Any]] = {
    "SID_HISTORY_INJECTION": {
        "name": "SID History Injection",
        "mitre_id": "T1134.005", "cve": None, "tier": 1,
        "attack_steps": [
            "Enumerate inbound/bidirectional trust with no SID filtering",
            "Compromise account in trusted domain",
            "Inject privileged SID (e.g. Enterprise Admins S-1-5-21-...-519) into SID history",
            "Request TGT in trusted domain — PAC includes injected SID",
            "Use TGT to access trusting domain resources as Enterprise Admin",
        ],
        "remediation_steps": [
            "Enable SID Filtering on all inbound trusts: netdom trust /EnableSIDFilteringAll",
            "Audit SID history attributes: Get-ADUser -Filter * -Properties SIDHistory",
            "Enable Protected Users group for sensitive accounts",
        ],
        "opsec_notes": "RC4 tickets are noisier than AES — request TGT with /crypto:aes256 to reduce SIEM hits. Ticket injection via Rubeus avoids touching LSASS directly.",
    },
    "EXTRASID_GOLDEN_TICKET": {
        "name": "ExtraSID Golden Ticket (Cross-Forest)",
        "mitre_id": "T1558.001", "cve": None, "tier": 1,
        "attack_steps": [
            "DCSync krbtgt hash from forest root DC",
            "Identify target forest's Enterprise Admins SID",
            "Forge golden ticket with extra SID for target forest EA group",
            "Use ticket to access resources in target forest",
        ],
        "remediation_steps": [
            "Enable SID Filtering on forest trusts",
            "Rotate krbtgt twice to invalidate forged tickets",
            "Monitor for ticket lifetimes > domain policy maximum",
        ],
        "opsec_notes": "Use diamond ticket (clone legit PAC) instead of golden ticket to evade PAC validation anomaly detection.",
    },
    "PAM_TRUST_ABUSE": {
        "name": "PAM Trust Exploitation",
        "mitre_id": "T1134.001", "cve": None, "tier": 1,
        "attack_steps": [
            "Identify PAM trust (msDS-IsParentOf / shadow principal configuration)",
            "Enumerate shadow principals mapped to privileged accounts",
            "Compromise account with shadow principal mapping in bastion forest",
            "Leverage elevated access window to pivot into production forest",
        ],
        "remediation_steps": [
            "Audit shadow principal mappings regularly",
            "Implement time-limited just-in-time access windows",
            "Monitor PAM trust authentication events (Event 4768/4769 cross-domain)",
        ],
        "opsec_notes": "Access window is time-limited — must operate within the JIT window. Shadow principal auth generates normal Kerberos tickets — low noise.",
    },
    "TRANSITIVE_DELEGATION": {
        "name": "Unconstrained Delegation Across Trust",
        "mitre_id": "T1558.001", "cve": None, "tier": 1,
        "attack_steps": [
            "Identify machine with unconstrained delegation in trusting domain",
            "Coerce DC from trusted domain to authenticate to that machine (PrintSpooler/PetitPotam)",
            "Capture TGT of trusted domain DC from LSASS on the delegation machine",
            "Use captured TGT for DCSync against trusted domain",
        ],
        "remediation_steps": [
            "Eliminate unconstrained delegation: replace with constrained or resource-based constrained",
            "Enable 'Account is sensitive and cannot be delegated' on tier-0 accounts",
        ],
        "opsec_notes": "Use Rubeus monitor /interval:5 to capture TGTs in real time. Coercion over MS-EFSR is quieter than SpoolSS.",
    },
    "TRUST_ESCALATION_CHAIN": {
        "name": "Chained Trust Escalation",
        "mitre_id": "T1078", "cve": None, "tier": 1,
        "attack_steps": [
            "Map all transitive trust relationships from current domain",
            "Identify weakest link in chain (lowest-risk domain with trust path to target)",
            "Compromise weakest domain first",
            "Use trust ticket to hop toward high-value target domain",
        ],
        "remediation_steps": [
            "Enforce non-transitive trusts where full transitivity is not required",
            "Segment trust topology — avoid hub-and-spoke trust designs",
        ],
        "opsec_notes": "Each hop generates cross-realm TGT requests — spread timing across sessions to avoid correlation.",
    },
    "TRUST_KEY_EXTRACTION_FORGERY": {
        "name": "Trust Key Extraction → Inter-Realm TGT Forgery",
        "mitre_id": "T1558.001", "cve": None, "tier": 2,
        "attack_steps": [
            "DCSync the trust account object (e.g. TRUSTED$ in trusting domain)",
            "Extract RC4 (NT hash) or AES keys of trust account",
            "Forge inter-realm TGT signed with trust key — no krbtgt needed",
            "Use forged ticket to authenticate in trusted domain as arbitrary user",
        ],
        "remediation_steps": [
            "Monitor DCSync events for trust account objects (Event 4662)",
            "Restrict DCSync rights to Domain Controllers only",
            "Rotate trust passwords more frequently than default 30-day cycle",
        ],
        "opsec_notes": "More stealthy than golden ticket — uses trust key not krbtgt, evades some golden ticket detections. Use AES256 key if available.",
    },
    "RC4_TRUST_DOWNGRADE": {
        "name": "RC4 Encryption Downgrade on Trust",
        "mitre_id": "T1558.001", "cve": None, "tier": 2,
        "attack_steps": [
            "Detect USES_RC4_ENCRYPTION flag on trust attributes (trustAttributes & 0x080)",
            "Request cross-realm TGT using RC4 encryption type",
            "Captured RC4-encrypted ticket is crackable offline",
            "Crack RC4 trust key → forge tickets without needing DCSync",
        ],
        "remediation_steps": [
            "Clear USES_RC4_ENCRYPTION flag from all trust objects",
            "Set msDS-SupportedEncryptionTypes to require AES256 (0x18)",
            "Enforce AES via GPO: Network Security: Configure encryption types allowed for Kerberos",
        ],
        "opsec_notes": "RC4 requests still blend with legacy traffic in mixed environments.",
    },
    "TRUST_PASSWORD_OVERLAP_WINDOW": {
        "name": "Trust Password Overlap Window Exploitation",
        "mitre_id": "T1134.005", "cve": None, "tier": 2,
        "attack_steps": [
            "Identify trust with whenChanged < 30 days (password recently rotated)",
            "Previous trust password still valid for up to 30 days after rotation",
            "Extract previous trust password from trust account pwdHistory via DCSync with history",
            "Forge tickets using previous password — KDC accepts within overlap window",
        ],
        "remediation_steps": [
            "Force trust password rotation twice in quick succession to eliminate overlap",
            "Monitor for authentication using old trust credentials post-rotation",
        ],
        "opsec_notes": "Low detection surface — old password auth looks identical to new password auth in standard logs.",
    },
    "SELECTIVE_AUTH_BYPASS": {
        "name": "Selective Authentication Bypass via Broad Group Grant",
        "mitre_id": "T1078", "cve": None, "tier": 2,
        "attack_steps": [
            "Enumerate Allowed-to-Authenticate permission on target trust resources",
            "Identify if Domain Users or Authenticated Users has the permission (misconfiguration)",
            "Any domain account can now authenticate cross-trust without selective auth restriction",
            "Use any compromised domain account to access trust resources",
        ],
        "remediation_steps": [
            "Restrict Allowed-to-Authenticate to specific groups/accounts only",
            "Audit selective auth configuration: Get-ADTrust | Select SelectiveAuthentication",
        ],
        "opsec_notes": "Normal Kerberos auth — no anomalous ticket properties. Virtually silent.",
    },
    "CROSS_TRUST_KERBEROASTING": {
        "name": "Cross-Trust Kerberoasting",
        "mitre_id": "T1558.003", "cve": None, "tier": 2,
        "attack_steps": [
            "Enumerate SPNs in trusted domain from trusting domain context",
            "Request TGS cross-realm for target SPN using cross-realm TGT",
            "Extract RC4/AES TGS from memory",
            "Crack offline with hashcat -m 13100 (RC4) or -m 19700 (AES256)",
        ],
        "remediation_steps": [
            "Use Managed Service Accounts (MSA/gMSA) for all service accounts",
            "Enforce AES-only encryption on service accounts",
            "Audit cross-realm TGS requests in partner domain event logs",
        ],
        "opsec_notes": "Use /nowrap flag in Rubeus to avoid log truncation. AES TGS cracking is significantly slower — target RC4 first.",
    },
    "CROSS_TRUST_ASREP_ROASTING": {
        "name": "Cross-Trust AS-REP Roasting",
        "mitre_id": "T1558.004", "cve": None, "tier": 2,
        "attack_steps": [
            "Enumerate accounts with pre-auth disabled in trusted domain",
            "Send AS-REQ cross-realm for each account (no credentials required)",
            "Capture AS-REP encrypted with account's key",
            "Crack offline with hashcat -m 18200",
        ],
        "remediation_steps": [
            "Enable Kerberos pre-authentication on all accounts",
            "Use Protected Users security group to force pre-auth requirement",
        ],
        "opsec_notes": "AS-REQ to remote domain DC — ensure routing allows port 88 to partner DC. Spread requests over time.",
    },
    "CROSS_TRUST_ADCS_ESC1_ESC8": {
        "name": "Cross-Trust ADCS ESC1/ESC8 Certificate Enrollment",
        "mitre_id": "T1649", "cve": None, "tier": 2,
        "attack_steps": [
            "Identify CA in trusted domain accepting enrollment from trusting domain principals",
            "Find ESC1-vulnerable template (enrollee supplies SAN, no manager approval)",
            "Enroll certificate with SAN set to DA UPN in trusted domain",
            "Use certificate for PKINIT TGT request as DA",
        ],
        "remediation_steps": [
            "Restrict cross-domain enrollment rights on all CAs",
            "Disable EDITF_ATTRIBUTESUBJECTALTNAME2 flag on all CAs",
        ],
        "opsec_notes": "Certificate request via certreq.exe blends with normal PKI operations. ESC8 relay via ntlmrelayx -t http://ca/certsrv/certfnsh.asp.",
    },
    "CROSS_TRUST_SHADOW_CREDENTIALS": {
        "name": "Cross-Trust Shadow Credentials",
        "mitre_id": "T1558.004", "cve": None, "tier": 2,
        "attack_steps": [
            "Identify account in trusted domain with msDS-KeyCredentialLink writable from trusting domain",
            "Add KeyCredential blob to target account's msDS-KeyCredentialLink",
            "Request TGT via PKINIT using generated certificate",
            "Use TGT for access in trusted domain",
        ],
        "remediation_steps": [
            "Audit msDS-KeyCredentialLink write permissions cross-domain",
            "Enable LDAP signing and channel binding to prevent relay-based writes",
        ],
        "opsec_notes": "LDAP modification — ensure LDAPS or signed LDAP. Whisker tool for KeyCredential blob generation.",
    },
    "BRONZE_BIT_CROSS_TRUST": {
        "name": "Bronze Bit S4U2Proxy Bypass Cross-Trust",
        "mitre_id": "T1558.001", "cve": "CVE-2020-17049", "tier": 2,
        "attack_steps": [
            "Identify constrained delegation principal configured across domain boundary",
            "Obtain TGS for target service on behalf of victim (S4U2Self)",
            "Flip the 'forwardable' flag in the TGS using Bronze Bit technique",
            "Use modified TGS with S4U2Proxy to access service in target domain",
        ],
        "remediation_steps": [
            "Apply KB4598347 and related Kerberos patches on all DCs",
            "Audit constrained delegation configurations that span domain boundaries",
        ],
        "opsec_notes": "Requires unpatched DCs. Rubeus s4u /bronzebit flag. Ticket modification is detectable by PAC validation on patched systems.",
    },
    "SAPPHIRE_DIAMOND_TICKET": {
        "name": "Sapphire/Diamond Ticket (PAC Clone)",
        "mitre_id": "T1558.001", "cve": None, "tier": 3,
        "attack_steps": [
            "Obtain AS-REP for legitimate account (real ticket with valid PAC)",
            "Decrypt PAC using extracted krbtgt key",
            "Modify PAC SID list to include privileged SIDs (or ExtraSIDs)",
            "Re-encrypt PAC — produces diamond ticket that passes PAC validation",
        ],
        "remediation_steps": [
            "Protect krbtgt with AES256 and frequent rotation",
            "Deploy Microsoft Defender for Identity to detect PAC anomalies",
        ],
        "opsec_notes": "Diamond ticket evades PAC validation–based detections that catch golden tickets. Indistinguishable from legitimate ticket at KDC level.",
    },
    "TDO_MANIPULATION": {
        "name": "Trusted Domain Object (TDO) Manipulation",
        "mitre_id": "T1484", "cve": None, "tier": 3,
        "attack_steps": [
            "Obtain write access to trustedDomain object in CN=System,DC=domain",
            "Modify trustAuthIncoming/trustAuthOutgoing to inject attacker-controlled trust key",
            "Forge cross-realm tickets using injected key — undetected by standard tooling",
        ],
        "remediation_steps": [
            "Restrict write access to CN=System container",
            "Monitor changes to trustedDomain objects (Event 4739, 5136)",
        ],
        "opsec_notes": "Extremely stealthy — no new trust created, existing trust key replaced. Changes replicate silently.",
    },
    "PAC_VALIDATION_BYPASS": {
        "name": "PAC Validation Bypass (MS14-068)",
        "mitre_id": "T1558.001", "cve": "MS14-068", "tier": 3,
        "attack_steps": [
            "Identify unpatched Windows Server 2003/2008 DC in trusted domain",
            "Forge PAC without knowing krbtgt key using MD5 checksum bypass",
            "Submit forged PAC in TGT — unpatched DC accepts it",
            "Achieve DA-level access using domain user account",
        ],
        "remediation_steps": [
            "Apply MS14-068 patch (KB3011780) on all DCs",
            "Upgrade Windows Server 2003/2008 to supported versions",
        ],
        "opsec_notes": "Only works against unpatched DCs. PyKEK / goldenPac exploit. Detection: Event 4769 with unusual privilege attributes.",
    },
    "RODC_CROSS_TRUST_CACHE": {
        "name": "RODC Cross-Trust Cache Attack",
        "mitre_id": "T1558", "cve": None, "tier": 2,
        "attack_steps": [
            "Identify RODC (Read-Only DC) with trust path to another domain",
            "Coerce RODC to cache credentials for privileged accounts via Kerberos pre-auth",
            "Extract cached credentials from RODC NTDS.dit (partial)",
            "Use credentials for cross-trust lateral movement",
        ],
        "remediation_steps": [
            "Configure msDS-RevealOnDemandGroup to restrict which accounts RODC can cache",
            "Add privileged accounts to msDS-NeverRevealGroup on all RODCs",
        ],
        "opsec_notes": "RODC caching is covert — no direct event for cache population. Extraction requires RODC compromise first.",
    },
    "SID_FILTER_PARTIAL_BYPASS": {
        "name": "SID Filter Partial Bypass (RID < 1000)",
        "mitre_id": "T1134.005", "cve": None, "tier": 3,
        "attack_steps": [
            "Identify forest trust where SID filtering is enabled but quarantine is not",
            "Note that SID filtering only blocks RIDs >= 1000 by default in some configs",
            "Inject well-known privileged SIDs (RID < 1000) if not explicitly blocked",
            "Use injected SID for elevated access cross-forest",
        ],
        "remediation_steps": [
            "Enable full quarantine (SID filter quarantine) on all forest trusts",
            "Use netdom trust /quarantine:yes for complete SID filtering",
        ],
        "opsec_notes": "Rare misconfiguration but high impact when present. Check using: Get-ADTrust | fl *",
    },
    "MIT_KERBEROS_REALM_TRUST": {
        "name": "MIT Kerberos Realm Trust Exploitation",
        "mitre_id": "T1558", "cve": None, "tier": 3,
        "attack_steps": [
            "Identify MIT Kerberos realm trust with no SID filtering (MIT realms have no SID concept)",
            "Obtain Kerberos TGT from MIT realm KDC",
            "Use cross-realm ticket to access AD forest resources",
            "MIT realm has no SID filtering — arbitrary AD resource access possible",
        ],
        "remediation_steps": [
            "Avoid creating MIT Kerberos realm trusts unless strictly necessary",
            "If required, implement application-level authorization on all resources",
        ],
        "opsec_notes": "MIT Kerberos trusts bypass SID filtering entirely — they are unconditionally dangerous.",
    },
    "NOPAC_CROSS_TRUST": {
        "name": "noPac Cross-Trust Privilege Escalation",
        "mitre_id": "T1558.001", "cve": "CVE-2021-42278 / CVE-2021-42287", "tier": 3,
        "attack_steps": [
            "Obtain machine account creation privileges (default: any domain user can create up to 10)",
            "Create machine account with sAMAccountName spoofing target DC name (without $)",
            "Request TGT for the machine account",
            "Rename back and use S4U2Self to obtain TGS as target DC — then DCSync",
            "Repeat cross-trust for target domain DCs if trust allows TGS forwarding",
        ],
        "remediation_steps": [
            "Apply November 2021 KB patches on all DCs (CVE-2021-42278 + CVE-2021-42287)",
            "Set MachineAccountQuota to 0 for all non-privileged users",
        ],
        "opsec_notes": "Patched in Nov 2021 — only effective against unpatched environments. Use noPac tool (cube0x0).",
    },
    "FAST_ARMORING_BYPASS": {
        "name": "FAST Armoring Bypass via Unclaimed Claim",
        "mitre_id": "T1558", "cve": None, "tier": 3,
        "attack_steps": [
            "Identify environment using FAST (Flexible Authentication Secure Tunneling) Kerberos armoring",
            "Find claim type that is checked but not enforced on older DCs",
            "Forge claim in Kerberos ticket using modified PAC structure",
            "Bypass FAST armoring requirement to perform ticket-based attacks",
        ],
        "remediation_steps": [
            "Ensure all DCs enforce FAST armoring uniformly",
            "Set 'Always provide claims' on all domain controllers via GPO",
        ],
        "opsec_notes": "Highly technical — requires deep Kerberos knowledge. Low detection risk as it exploits legitimate protocol features.",
    },
}


def score_technique_severity(technique_id: str) -> str:
    return _SEVERITY.get(technique_id, "MEDIUM")


def detect_trust_techniques(
    trusts: list[dict],
    entities: list[dict],
    edges: list[dict],
) -> list[dict]:
    results: list[dict] = []

    trusted_domains = {t["name"].upper() for t in trusts}

    for trust in trusts:
        name = trust.get("name", "")
        direction_val = trust.get("direction_val", 0)
        attrs_raw = trust.get("attrs_raw", 0)
        sid_filtering = trust.get("sid_filtering", False)
        forest_trust = trust.get("forest_trust", False)
        transitive = trust.get("transitive", True)
        trust_type = trust.get("trust_type", "")
        when_changed_days = trust.get("when_changed_days", 999)

        inbound = direction_val in (1, 3)
        bidirectional = direction_val == 3

        # SID History Injection: inbound trust without SID filtering
        if inbound and not sid_filtering:
            results.append(_hit("SID_HISTORY_INJECTION", trust=name))

        # ExtraSID Golden Ticket: forest trust without SID filtering
        if forest_trust and not sid_filtering:
            results.append(_hit("EXTRASID_GOLDEN_TICKET", trust=name))

        # RC4 Downgrade: USES_RC4_ENCRYPTION flag set (trustAttributes & 0x080)
        if attrs_raw & 0x080:
            results.append(_hit("RC4_TRUST_DOWNGRADE", trust=name))

        # Trust Password Overlap Window: recently changed (< 30 days)
        if when_changed_days < 30:
            results.append(_hit("TRUST_PASSWORD_OVERLAP_WINDOW", trust=name))

        # Transitive trust chain detection (2+ transitive trusts)
        if transitive and bidirectional:
            results.append(_hit("TRUST_ESCALATION_CHAIN", trust=name))

        # MIT Kerberos realm trust
        if "mit" in trust_type.lower() or "non-windows" in trust_type.lower():
            results.append(_hit("MIT_KERBEROS_REALM_TRUST", trust=name))

        # RODC cross-trust cache: RODC-type trust indicators
        if trust.get("is_rodc_involved"):
            results.append(_hit("RODC_CROSS_TRUST_CACHE", trust=name))

        # Trust key forgery: bidirectional trust (can DCSync trust account)
        if bidirectional:
            results.append(_hit("TRUST_KEY_EXTRACTION_FORGERY", trust=name))

        # PAM trust detection
        if trust.get("is_pam_trust"):
            results.append(_hit("PAM_TRUST_ABUSE", trust=name))

        # SID Filter partial bypass: forest trust with SID filtering but no quarantine
        if forest_trust and sid_filtering and not trust.get("quarantine"):
            results.append(_hit("SID_FILTER_PARTIAL_BYPASS", trust=name))

    # Cross-trust Kerberoasting: entities with SPNs in trusted domains
    spn_domains = set()
    for entity in entities:
        if entity.get("entity_type") == "USER":
            domain = entity.get("domain", "").upper()
            spns = entity.get("attributes", {}).get("spns", [])
            if spns and domain in trusted_domains:
                spn_domains.add(domain)

    if spn_domains:
        results.append(_hit("CROSS_TRUST_KERBEROASTING", affected_domains=list(spn_domains)))

    # Cross-trust AS-REP Roasting: accounts with pre-auth disabled in trusted domains
    asrep_domains = set()
    for entity in entities:
        if entity.get("entity_type") == "USER":
            domain = entity.get("domain", "").upper()
            if entity.get("attributes", {}).get("asrep_roastable") and domain in trusted_domains:
                asrep_domains.add(domain)

    if asrep_domains:
        results.append(_hit("CROSS_TRUST_ASREP_ROASTING", affected_domains=list(asrep_domains)))

    # Cross-trust ADCS: edges with ADCS_ESC1 or ADCS_ESC8 edge types
    lm_edge_types = {e.get("edge_type", "") for e in edges}
    if "ADCS_ESC1" in lm_edge_types or "ADCS_ESC8" in lm_edge_types:
        results.append(_hit("CROSS_TRUST_ADCS_ESC1_ESC8"))

    # Shadow credentials: ADD_KEY_CREDENTIAL_LINK edge in cross-domain context
    if "ADD_KEY_CREDENTIAL_LINK" in lm_edge_types:
        results.append(_hit("CROSS_TRUST_SHADOW_CREDENTIALS"))

    # Transitive delegation: unconstrained delegation + coercion edge
    if "COERCION" in lm_edge_types or "PETITPOTAM" in lm_edge_types or "PRINTSPOOLER" in lm_edge_types:
        results.append(_hit("TRANSITIVE_DELEGATION"))

    # Sapphire/Diamond ticket: golden ticket + EXTRASID edges
    if "GOLDEN_TICKET" in lm_edge_types or "EXTRASID" in lm_edge_types:
        results.append(_hit("SAPPHIRE_DIAMOND_TICKET"))

    # CVE chains
    if "CVE_CHAIN" in lm_edge_types:
        results.append(_hit("NOPAC_CROSS_TRUST"))
        results.append(_hit("PAC_VALIDATION_BYPASS"))

    # Deduplicate by technique_id
    seen: set[str] = set()
    deduped: list[dict] = []
    for r in results:
        if r["technique_id"] not in seen:
            seen.add(r["technique_id"])
            deduped.append(r)

    return deduped


def _hit(technique_id: str, **kwargs) -> dict:
    cat = TECHNIQUE_CATALOGUE.get(technique_id, {})
    return {
        "technique_id": technique_id,
        "name": cat.get("name", technique_id),
        "mitre_id": cat.get("mitre_id"),
        "cve": cat.get("cve"),
        "tier": cat.get("tier", 2),
        "severity": score_technique_severity(technique_id),
        "attack_steps": cat.get("attack_steps", []),
        "remediation_steps": cat.get("remediation_steps", []),
        "opsec_notes": cat.get("opsec_notes", ""),
        **kwargs,
    }


class TrustAbuseAnalyzer:
    def __init__(self, trusts: list[dict], entities: list[dict], edges: list[dict]):
        self._trusts = trusts
        self._entities = entities
        self._edges = edges

    def analyze(self) -> dict:
        techniques = detect_trust_techniques(self._trusts, self._entities, self._edges)
        chains = self._detect_chains(techniques)
        return {
            "techniques": techniques,
            "chains": chains,
            "summary": {
                "total_techniques": len(techniques),
                "critical_count": sum(1 for t in techniques if t["severity"] == "CRITICAL"),
                "high_count": sum(1 for t in techniques if t["severity"] == "HIGH"),
                "medium_count": sum(1 for t in techniques if t["severity"] == "MEDIUM"),
                "chains_detected": len(chains),
            },
        }

    def _detect_chains(self, techniques: list[dict]) -> list[dict]:
        technique_ids = {t["technique_id"] for t in techniques}
        chains = []

        if {"SID_HISTORY_INJECTION", "EXTRASID_GOLDEN_TICKET"}.issubset(technique_ids):
            chains.append({
                "chain_id": "FULL_TRUST_COMPROMISE",
                "name": "Full Forest Trust Compromise",
                "steps": ["SID_HISTORY_INJECTION", "EXTRASID_GOLDEN_TICKET"],
                "severity": "CRITICAL",
            })

        if {"TRANSITIVE_DELEGATION", "TRUST_KEY_EXTRACTION_FORGERY"}.issubset(technique_ids):
            chains.append({
                "chain_id": "COERCE_THEN_FORGE",
                "name": "Coercion → Trust Key Forgery Chain",
                "steps": ["TRANSITIVE_DELEGATION", "TRUST_KEY_EXTRACTION_FORGERY"],
                "severity": "CRITICAL",
            })

        if {"CROSS_TRUST_ADCS_ESC1_ESC8", "EXTRASID_GOLDEN_TICKET"}.issubset(technique_ids):
            chains.append({
                "chain_id": "ADCS_TO_FOREST_PIVOT",
                "name": "ADCS ESC8 → ExtraSID Forest Pivot",
                "steps": ["CROSS_TRUST_ADCS_ESC1_ESC8", "EXTRASID_GOLDEN_TICKET"],
                "severity": "CRITICAL",
            })

        return chains
