#!/usr/bin/env python3
"""
AdByG0d Platform — Canonical Output Model v1.0
Converts raw module findings into the platform's canonical JSON schema.
This schema is consumed by the API's ingest endpoint.

All collectors (Linux remote, Windows local) must produce this format.
"""

import json
import uuid
from datetime import datetime, timezone
from dataclasses import dataclass, field, asdict
from typing import Optional, List, Dict, Any


SCHEMA_VERSION = "1.0"
TOOL_NAME = "AdByG0d"
COLLECTOR_VERSION = "1.0.0"


# ─────────────────────────────────────────────────────────────────
# Entity types (must match platform schema)
# ─────────────────────────────────────────────────────────────────

ENTITY_TYPES = {
    "user": "USER",
    "group": "GROUP",
    "computer": "COMPUTER",
    "domain": "DOMAIN",
    "forest": "FOREST",
    "ou": "OU",
    "gpo": "GPO",
    "serviceaccount": "SERVICE_ACCOUNT",
    "gmsa": "GMSA",
    "dmsa": "DMSA",
    "ca": "CA",
    "certtemplate": "CERT_TEMPLATE",
    "trust": "TRUST",
    "site": "SITE",
    "dc": "DC",
}

# UAC flag constants
UAC_ACCOUNTDISABLE = 0x0002
UAC_PASSWD_NOTREQD = 0x0020
UAC_TRUSTED_FOR_DELEGATION = 0x00080000
UAC_NOT_DELEGATED = 0x00100000
UAC_USE_DES_KEY_ONLY = 0x00200000
UAC_DONT_REQUIRE_PREAUTH = 0x00400000
UAC_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION = 0x01000000
UAC_SERVER_TRUST_ACCOUNT = 0x2000  # DC


@dataclass
class CanonicalEntity:
    """Platform-normalized AD entity."""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    entity_type: str = "USER"
    distinguished_name: Optional[str] = None
    object_sid: Optional[str] = None
    sam_account_name: Optional[str] = None
    display_name: Optional[str] = None
    dns_hostname: Optional[str] = None
    domain: Optional[str] = None
    is_enabled: bool = True
    is_admin_count: bool = False
    is_sensitive: bool = False
    is_protected_user: bool = False
    tier: Optional[int] = None
    is_crown_jewel: bool = False
    business_tags: List[str] = field(default_factory=list)
    attributes: Dict[str, Any] = field(default_factory=dict)
    # Timestamps (ISO format strings)
    object_created: Optional[str] = None
    object_modified: Optional[str] = None
    last_logon: Optional[str] = None
    password_last_set: Optional[str] = None


@dataclass
class CanonicalEdge:
    """Directed relationship between two canonical entities."""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    source_id: str = ""
    target_id: str = ""
    edge_type: str = "HAS_CONTROL"
    provenance: Optional[str] = None
    inheritance_root: Optional[str] = None
    risk_weight: float = 1.0
    attributes: Dict[str, Any] = field(default_factory=dict)


@dataclass
class CanonicalEvidence:
    """Raw evidence record from collection."""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    source_type: str = "ldap"  # ldap, smb, registry, kerberos, dns, local
    source_host: Optional[str] = None
    source_port: Optional[int] = None
    collection_method: Optional[str] = None
    raw_data: Optional[Dict[str, Any]] = None
    confidence: float = 1.0


@dataclass
class CanonicalFinding:
    """Platform-normalized security finding."""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    finding_type: str = "UNKNOWN"
    module: str = "Unknown"
    title: str = ""
    description: str = ""
    severity: str = "INFO"
    confidence: float = 1.0
    affected_count: int = 0
    affected_objects: List[str] = field(default_factory=list)
    root_cause: str = ""
    causal_chain: List[str] = field(default_factory=list)
    remediation: str = ""
    remediation_steps: List[str] = field(default_factory=list)
    fix_complexity: str = "medium"
    references: List[str] = field(default_factory=list)
    # Scoring hints for the API to use
    technical_severity: float = 5.0
    reachability: float = 0.5
    asset_criticality: float = 0.5
    on_crown_jewel_path: bool = False
    is_tier0_direct: bool = False
    evidence_ids: List[str] = field(default_factory=list)


@dataclass
class CanonicalCertTemplate:
    """Certificate template data."""
    name: str = ""
    distinguished_name: Optional[str] = None
    ca_name: Optional[str] = None
    enrollee_supplies_subject: bool = False
    requires_manager_approval: bool = False
    authorized_signatures_required: int = 0
    validity_period: Optional[str] = None
    ekus: List[str] = field(default_factory=list)
    enrollment_rights: List[str] = field(default_factory=list)
    write_rights: List[str] = field(default_factory=list)
    esc1_vulnerable: bool = False
    esc2_vulnerable: bool = False
    esc3_vulnerable: bool = False
    esc4_vulnerable: bool = False
    attributes: Dict[str, Any] = field(default_factory=dict)


class CanonicalOutput:
    """
    Builds the canonical output payload from raw module data.
    Usage:
        output = CanonicalOutput(domain="corp.local", dc_ip="10.10.10.1")
        output.add_entity(...)
        output.add_finding(...)
        payload = output.to_dict()
        output.save("output.json")
        output.upload_to_api("http://localhost:8000", assessment_id)
    """

    def __init__(
        self,
        domain: str,
        dc_ip: Optional[str] = None,
        collection_mode: str = "LINUX_REMOTE",
    ):
        self.domain = domain
        self.dc_ip = dc_ip
        self.collection_mode = collection_mode
        self.collected_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        self.modules_run: List[str] = []
        self.entities: List[CanonicalEntity] = []
        self.edges: List[CanonicalEdge] = []
        self.evidence: List[CanonicalEvidence] = []
        self.findings: List[CanonicalFinding] = []
        self.cert_templates: List[CanonicalCertTemplate] = []
        self.metadata: Dict[str, Any] = {}
        self._entity_index: Dict[str, str] = {}  # distinguishedName/SID → id

    def set_domain_info(self, domain_info: dict):
        self.metadata["domain_info"] = domain_info

    def set_password_policy(self, policy: dict):
        self.metadata["password_policy"] = policy

    def set_trusts(self, trusts: list):
        self.metadata["trusts"] = trusts

    def add_entity(self, entity: CanonicalEntity) -> str:
        """Add entity and return its ID."""
        # Deduplicate by DN or SID
        key = entity.distinguished_name or entity.object_sid or entity.sam_account_name
        if key and key in self._entity_index:
            return self._entity_index[key]
        self.entities.append(entity)
        if key:
            self._entity_index[key] = entity.id
        return entity.id

    def get_entity_id(self, key: str) -> Optional[str]:
        return self._entity_index.get(key)

    def add_edge(self, edge: CanonicalEdge):
        self.edges.append(edge)

    def add_evidence(self, evidence: CanonicalEvidence) -> str:
        self.evidence.append(evidence)
        return evidence.id

    def add_finding(self, finding: CanonicalFinding):
        self.findings.append(finding)

    def add_cert_template(self, template: CanonicalCertTemplate):
        self.cert_templates.append(template)

    def add_module(self, module_name: str):
        if module_name not in self.modules_run:
            self.modules_run.append(module_name)

    def from_legacy_reporter(self, reporter):
        """
        Convert existing Reporter findings to canonical format.
        Bridges the legacy module output to the canonical schema.
        """
        self.modules_run = reporter.modules_run
        for f in reporter.findings:
            sev = f.severity.upper()
            # Map severity to scoring hints
            sev_score_map = {
                "CRITICAL": (9.5, 0.9),
                "HIGH": (7.5, 0.7),
                "MEDIUM": (5.5, 0.5),
                "LOW": (3.5, 0.3),
                "INFO": (2.0, 0.1),
            }
            tech_sev, reach = sev_score_map.get(sev, (5.0, 0.5))

            canonical = CanonicalFinding(
                finding_type=_infer_finding_type(f.title),
                module=f.module,
                title=f.title,
                description=f.description or "",
                severity=sev,
                confidence=1.0,
                affected_count=len(f.affected) if f.affected else 0,
                affected_objects=list(f.affected[:50]) if f.affected else [],
                root_cause="",
                causal_chain=[],
                remediation=f.remediation or "",
                remediation_steps=[],
                fix_complexity="medium",
                references=list(f.references) if f.references else [],
                technical_severity=tech_sev,
                reachability=reach,
            )
            self.findings.append(canonical)

    def to_dict(self) -> dict:
        return {
            "schema_version": SCHEMA_VERSION,
            "tool": TOOL_NAME,
            "collector_version": COLLECTOR_VERSION,
            "collection_mode": self.collection_mode,
            "domain": self.domain,
            "dc_ip": self.dc_ip,
            "collected_at": self.collected_at,
            "modules_run": self.modules_run,
            "entities": [asdict(e) for e in self.entities],
            "edges": [asdict(e) for e in self.edges],
            "evidence": [asdict(e) for e in self.evidence],
            "findings": [asdict(f) for f in self.findings],
            "cert_templates": [asdict(t) for t in self.cert_templates],
            "metadata": self.metadata,
        }

    def save(self, path: str):
        with open(path, 'w') as f:
            json.dump(self.to_dict(), f, indent=2, default=str)
        print(f"[+] Canonical output saved to {path}")

    def upload_to_api(self, api_base: str, assessment_id: str) -> bool:
        """Upload canonical output to the platform API."""
        try:
            import urllib.request
            import urllib.error
            data = json.dumps(self.to_dict()).encode('utf-8')
            url = f"{api_base}/api/v1/ingest/{assessment_id}"
            req = urllib.request.Request(
                url, data=data,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=60) as resp:
                result = json.loads(resp.read())
                print(f"[+] Uploaded to API: {result}")
                return True
        except Exception as e:
            print(f"[-] API upload failed: {e}")
            return False

    def summary(self) -> str:
        sev_counts = {}
        for f in self.findings:
            sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1
        parts = [
            f"Domain: {self.domain}",
            f"Entities: {len(self.entities)}",
            f"Edges: {len(self.edges)}",
            f"Evidence records: {len(self.evidence)}",
            f"Findings: {len(self.findings)}",
        ]
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            if sev in sev_counts:
                parts.append(f"  {sev}: {sev_counts[sev]}")
        return "\n".join(parts)


def _infer_finding_type(title: str) -> str:
    """Attempt to infer a canonical finding_type from a legacy title string."""
    title_lower = title.lower()
    patterns = {
        "ESC1": ["esc1", "san misconfig", "enrollee supplies subject"],
        "ESC2": ["esc2", "any purpose eku"],
        "ESC3": ["esc3", "enrollment agent"],
        "ESC4": ["esc4", "template acl", "writedacl on template"],
        "UNCONSTRAINED_DELEGATION": ["unconstrained delegation"],
        "CONSTRAINED_DELEGATION": ["constrained delegation"],
        "RBCD": ["resource-based constrained delegation", "rbcd"],
        "ASREP_ROASTABLE": ["as-rep roast", "asrep roast", "pre-authentication disabled", "pre-auth disabled"],
        "KERBEROASTABLE": ["kerberoast", "kerberoastable"],
        "KERBEROASTABLE_ADMIN": ["kerberoastable admin", "admin.*kerberoastable"],
        "NO_LOCKOUT_POLICY": ["no.*lockout", "lockout.*not configured"],
        "WEAK_PASSWORD_LENGTH": ["minimum password length", "weak.*password"],
        "PASSWD_NOTREQD": ["passwd_notreqd", "password not required"],
        "NO_LAPS": ["laps not deployed", "laps.*not.*configured"],
        "MACHINE_ACCOUNT_QUOTA": ["machineaccountquota", "machine account quota"],
        "TRUST_NO_SID_FILTERING": ["sid filter", "no sid filter"],
        "DCSYNC": ["dcsync", "dc sync"],
        "SHADOW_CREDS": ["shadow credential"],
        "SID_HISTORY": ["sid history"],
        "DNSADMINS": ["dnsadmins"],
        "GPP_CREDS": ["gpp password", "group policy preference.*password"],
        "LEGACY_OS": ["legacy os", "end-of-life os", "eol os", "2008", "2003"],
        "EXCESSIVE_DA": ["excessive.*domain admin", "domain admin.*member"],
    }
    for ftype, patterns_list in patterns.items():
        import re
        for pat in patterns_list:
            if re.search(pat, title_lower):
                return ftype
    return "GENERIC_" + title_lower[:20].upper().replace(" ", "_").strip("_")
