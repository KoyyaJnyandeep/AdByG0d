from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from uuid import UUID, uuid4

from typing import Any

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import delete, insert, select
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from adbygod_api.database import AsyncSessionLocal, engine, get_db
from adbygod_api.models import (
    Assessment,
    AssessmentStatus,
    CertTemplate,
    CollectionMode,
    DataOrigin,
    EdgeType,
    Entity,
    EntityType,
    EvidenceRecord,
    Finding,
    FindingEvidence,
    FindingStatus,
    GraphEdge,
    PlatformUser,
    SeverityLevel,
)
from adbygod_api.schemas import CollectorIngest
from adbygod_api.core.collection.adcs import (
    certutil_has_editf_altsubjectname,
    esc6_enabled,
    parse_int,
    parse_certutil_edit_flags,
)
from adbygod_api.core.analyzers.rule_engine import RuleEngine, RuleMatch
from adbygod_api.core.analyzers.scoring_service import RiskScoringService
from adbygod_api.core.security.authorization import require_assessment_write_access
from adbygod_api.routes.auth import get_current_user
# move jobs.emit import to module level; importing inside _process_ingest
# created a circular import that failed when ingest.py was loaded before jobs.py.
from adbygod_api.routes import jobs as _jobs_module

log = logging.getLogger(__name__)
router = APIRouter(prefix="/ingest", tags=["ingest"])
rule_engine = RuleEngine()
scoring_service = RiskScoringService()

_BULK_CHUNK = 500
# Detect dialect once at startup — avoids deprecated get_bind() on async sessions
_DB_DIALECT: str = ""


def _get_dialect() -> str:
    global _DB_DIALECT
    if not _DB_DIALECT:
        _DB_DIALECT = engine.dialect.name
    return _DB_DIALECT


def _utcnow_naive() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _coerce_datetime(value: object) -> datetime | None:
    """Normalize FILETIME, Unix epoch, milliseconds, or ISO strings to naive UTC."""
    if value in (None, "", 0, "0", "None", "null"):
        return None
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc).replace(tzinfo=None) if value.tzinfo else value
    raw = str(value).strip()
    try:
        numeric = float(raw)
    except (TypeError, ValueError):
        try:
            dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        except ValueError:
            return None
        return dt.astimezone(timezone.utc).replace(tzinfo=None) if dt.tzinfo else dt
    try:
        if numeric >= 100_000_000_000_000:
            unix_seconds = (numeric - 116444736000000000) / 10_000_000
        elif numeric >= 1_000_000_000_000:
            unix_seconds = numeric / 1000
        else:
            unix_seconds = numeric
        if unix_seconds <= 0:
            return None
        return datetime.fromtimestamp(unix_seconds, tz=timezone.utc).replace(tzinfo=None)
    except (OverflowError, OSError, ValueError):
        return None


def _enqueue_projection_after_ingest(assessment_id: str) -> None:
    """Enqueue a Neo4j re-projection after ingest commits (Postgres is source of truth)."""
    from adbygod_api.core.tasks.graph_projection import enqueue
    enqueue(assessment_id)


def _pick_datetime(raw: dict, attrs: dict, *keys: str) -> datetime | None:
    for key in keys:
        if key in raw:
            parsed = _coerce_datetime(raw.get(key))
            if parsed:
                return parsed
        if key in attrs:
            parsed = _coerce_datetime(attrs.get(key))
            if parsed:
                return parsed
    return None


def _extract_evidence_refs(raw_finding: dict) -> list[str]:
    refs = raw_finding.get("evidence_ids") or raw_finding.get("evidence_refs") or []
    if not isinstance(refs, list):
        return []
    unique_refs: list[str] = []
    seen: set[str] = set()
    for ref in refs:
        ref_str = str(ref).strip()
        if ref_str and ref_str not in seen:
            seen.add(ref_str)
            unique_refs.append(ref_str)
    return unique_refs


_RULE_EVIDENCE_TYPES: dict[str, tuple[str, ...]] = {
    "NO_LOCKOUT_POLICY": ("domains",),
    "WEAK_PASSWORD_LENGTH": ("domains",),
    "NO_PASSWORD_COMPLEXITY": ("domains",),
    "WEAK_PASSWORD_HISTORY": ("domains",),
    "MACHINE_ACCOUNT_QUOTA": ("domains",),
    "LOW_DOMAIN_FUNCTIONAL_LEVEL": ("domains",),
    "KRBTGT_STALE": ("domains", "users"),
    "REVERSIBLE_ENCRYPTION_ENABLED": ("domains", "users"),
    "LARGE_SPRAY_SURFACE": ("users",),
    "PASSWD_NOTREQD": ("users",),
    "ASREP_ROASTABLE": ("users",),
    "KERBEROASTABLE_ADMIN": ("users",),
    "KERBEROASTABLE_SERVICES": ("users",),
    "ADMIN_PWD_NEVER_EXPIRES": ("users",),
    "STALE_ADMIN_ACCOUNT": ("users",),
    "DEFAULT_ADMIN_ENABLED": ("users",),
    "ADMIN_NOT_PROTECTED_USERS": ("users", "groups"),
    "SID_HISTORY_POPULATED": ("users",),
    "KERBEROAST_RC4_ONLY": ("users",),
    "SERVICE_ACCOUNTS_NO_GMSA": ("users",),
    "UNCONSTRAINED_DELEGATION": ("computers",),
    "COMPUTERS_NO_LAPS": ("computers",),
    "NO_LAPS": ("computers", "domains"),
    "RBCD_CONFIGURED": ("computers",),
    "CONSTRAINED_DELEGATION_ANY_PROTOCOL": ("users", "computers"),
    "CONSTRAINED_DELEGATION_KCD": ("users", "computers"),
    "TRUST_NO_SID_FILTERING": ("domains",),
    "BIDIRECTIONAL_EXTERNAL_TRUST": ("domains",),
    "ESC1": ("certtemplates",),
    "ESC2": ("certtemplates",),
    "ESC3": ("certtemplates",),
    "ESC4": ("certtemplates",),
    "ESC6_CA_SAN_FLAG_ENABLED": ("enterprisecas", "certtemplates"),
    "ESC8": ("enterprisecas", "certtemplates"),
    "DCSYNC_RIGHTS": ("domains", "users", "groups"),
    "GENERIC_ALL_TIER0": ("users", "groups", "computers", "domains"),
    "WRITE_DACL_ON_USERS": ("users", "groups"),
    "WRITE_OWNER_TIER0": ("users", "groups", "computers", "domains"),
    "ADD_MEMBER_GROUP_TAKEOVER": ("groups", "users"),
    "DANGEROUS_GPO_DELEGATION": ("gpos", "groups", "users"),
    "ADMINSDHOLDER_ORPHAN": ("users", "groups"),
    "ADMINSDHOLDER_DRIFT": ("users", "groups"),
    "SYSVOL_GPP_CPASSWORD": ("gpos",),
    "ESC5_PKI_OBJECT_CONTROL": ("enterprisecas", "certtemplates"),
    "ESC7_CA_PERMISSION_ABUSE": ("enterprisecas",),
    "ESC9_WEAK_SECURITY_EXTENSION_MAPPING": ("certtemplates", "enterprisecas"),
    "ESC10_WEAK_CERTIFICATE_MAPPING": ("enterprisecas",),
    "ESC11_RPC_ENROLLMENT_RELAY": ("enterprisecas",),
    "ESC13_ISSUANCE_POLICY_GROUP_LINK": ("certtemplates",),
    "ESC16_CA_DISABLES_SID_EXTENSION": ("enterprisecas",),
    "LAPS_PASSWORD_READABLE": ("computers", "groups", "users"),
    "GMSA_PASSWORD_READABLE": ("users", "groups"),
    "WRITE_SPN_ABUSE_PATH": ("users", "groups"),
    "ADD_KEY_CREDENTIAL_LINK_ABUSE_PATH": ("users", "groups", "computers"),
    "WRITE_GP_LINK_ABUSE_PATH": ("ous", "domains", "gpos"),
    "WRITE_ACCOUNT_RESTRICTIONS_ABUSE_PATH": ("users", "computers"),
    "SQL_ADMIN_ATTACK_PATH": ("computers", "users"),
    "CA_PRIVATE_KEY_CONTROL": ("enterprisecas",),
    "GOLDEN_CERTIFICATE_RISK": ("enterprisecas",),
    "DNSADMINS_RISKY_MEMBERSHIP": ("groups", "users"),
    "NULL_SESSION_SMB_EXPOSURE": ("computers",),
    "LEGACY_EOL_OPERATING_SYSTEMS": ("computers",),
    "DES_ONLY_KERBEROS_ACCOUNT": ("users", "computers"),
    "ACCOUNT_DESCRIPTION_SECRET": ("users", "computers"),
    "PRIVILEGED_PRIMARY_GROUP_ID": ("users",),
    "USER_ACCOUNT_DOLLAR_SUFFIX": ("users",),
    "TREAT_AS_EXTERNAL_TRUST": ("domains",),
}

_RULE_EDGE_TYPES: dict[str, tuple[str, ...]] = {
    "DCSYNC_RIGHTS": ("DCSYNC",),
    "GENERIC_ALL_TIER0": ("GENERIC_ALL", "WRITE_DACL", "WRITE_OWNER", "OWNS"),
    "WRITE_DACL_ON_USERS": ("WRITE_DACL",),
    "WRITE_OWNER_TIER0": ("WRITE_OWNER", "OWNS"),
    "ADD_MEMBER_GROUP_TAKEOVER": ("ADD_MEMBER",),
    "DANGEROUS_GPO_DELEGATION": ("GENERIC_ALL", "WRITE_DACL", "WRITE_OWNER", "OWNS", "HAS_CONTROL"),
    "RBCD_CONFIGURED": ("ALLOWED_TO_ACT",),
    "CONSTRAINED_DELEGATION_KCD": ("ALLOWED_TO_DELEGATE",),
    "CONSTRAINED_DELEGATION_ANY_PROTOCOL": ("ALLOWED_TO_DELEGATE",),
    "ESC5_PKI_OBJECT_CONTROL": ("GENERIC_ALL", "WRITE_DACL", "WRITE_OWNER", "HAS_CONTROL", "CA_PRIVATE_KEY_CONTROL", "GOLDEN_CERT"),
    "ESC7_CA_PERMISSION_ABUSE": ("MANAGE_CA", "MANAGE_CERTIFICATES"),
    "LAPS_PASSWORD_READABLE": ("READ_LAPS_PASSWORD",),
    "GMSA_PASSWORD_READABLE": ("READ_GMSA_PASSWORD",),
    "WRITE_SPN_ABUSE_PATH": ("WRITE_SPN",),
    "ADD_KEY_CREDENTIAL_LINK_ABUSE_PATH": ("ADD_KEY_CREDENTIAL_LINK",),
    "WRITE_GP_LINK_ABUSE_PATH": ("WRITE_GP_LINK",),
    "WRITE_ACCOUNT_RESTRICTIONS_ABUSE_PATH": ("WRITE_ACCOUNT_RESTRICTIONS",),
    "SQL_ADMIN_ATTACK_PATH": ("SQL_ADMIN",),
    "CA_PRIVATE_KEY_CONTROL": ("CA_PRIVATE_KEY_CONTROL",),
    "GOLDEN_CERTIFICATE_RISK": ("GOLDEN_CERT",),
    "DNSADMINS_RISKY_MEMBERSHIP": ("MEMBER_OF",),
}

# Finding types whose primary evidence comes from cert templates
_CERT_TEMPLATE_RULE_TYPES: frozenset[str] = frozenset({
    "ESC1", "ESC2", "ESC3", "ESC4",
    "ESC9_WEAK_SECURITY_EXTENSION_MAPPING",
    "ESC13_ISSUANCE_POLICY_GROUP_LINK",
})

# Finding types whose primary evidence comes from domain/password policy
_POLICY_RULE_TYPES: frozenset[str] = frozenset({
    "NO_LOCKOUT_POLICY", "WEAK_PASSWORD_LENGTH", "NO_PASSWORD_COMPLEXITY",
    "WEAK_PASSWORD_HISTORY", "MACHINE_ACCOUNT_QUOTA", "LOW_DOMAIN_FUNCTIONAL_LEVEL",
    "KRBTGT_STALE", "REVERSIBLE_ENCRYPTION_ENABLED",
})

# Finding types whose primary evidence comes from trust objects
_TRUST_RULE_TYPES: frozenset[str] = frozenset({
    "TRUST_NO_SID_FILTERING", "BIDIRECTIONAL_EXTERNAL_TRUST", "SID_HISTORY_POPULATED",
    "TREAT_AS_EXTERNAL_TRUST",
})


def _evidence_payload_type(raw: dict) -> str:
    raw_data = raw.get("raw_data") or {}
    payload_type = str(raw_data.get("type") or "").strip().lower()
    if payload_type:
        return payload_type
    method = str(raw.get("collection_method") or "").lower()
    if "/" in method:
        return method.rsplit("/", 1)[-1]
    return method


def _cert_template_source_refs(match: "RuleMatch", rule_data: dict[str, Any], limit: int = 10) -> list[dict[str, Any]]:
    """Extract structured cert template refs for ADCS findings."""
    if match.finding_type not in _CERT_TEMPLATE_RULE_TYPES:
        return []
    esc_flag = match.finding_type.lower() + "_vulnerable"
    refs: list[dict[str, Any]] = []
    for template in rule_data.get("cert_templates", []) or []:
        if not template.get(esc_flag):
            continue
        attrs = template.get("attributes") or {}
        refs.append({
            "ref_type": "cert_template",
            "template_name": template.get("name"),
            "ca_name": template.get("ca_name") or ", ".join(attrs.get("published_by", []) or []) or None,
            "distinguished_name": template.get("distinguished_name"),
            "enrollee_supplies_subject": bool(
                attrs.get("ct_flag_enrollee_supplies_subject")
                or template.get("enrollee_supplies_subject")
            ),
            "ekus": (template.get("ekus") or [])[:4],
            "enrollment_rights": (template.get("enrollment_rights") or [])[:5],
            "write_rights": (template.get("write_rights") or [])[:5],
            "esc_flag": match.finding_type,
        })
        if len(refs) >= limit:
            break
    return refs


def _policy_source_refs(match: "RuleMatch", rule_data: dict[str, Any]) -> list[dict[str, Any]]:
    """Extract structured domain/password policy attribute refs for policy findings."""
    if match.finding_type not in _POLICY_RULE_TYPES:
        return []
    policy = rule_data.get("password_policy") or {}
    domain_info = rule_data.get("domain_info") or {}
    ref: dict[str, Any] = {"ref_type": "policy", "finding_type": match.finding_type}
    if match.finding_type == "NO_LOCKOUT_POLICY":
        ref["lockout_threshold"] = policy.get("lockout_threshold", 0)
    elif match.finding_type == "WEAK_PASSWORD_LENGTH":
        ref["min_password_length"] = policy.get("min_password_length")
        ref["min_password_length_recommended"] = 14
    elif match.finding_type == "NO_PASSWORD_COMPLEXITY":
        ref["complexity_enabled"] = policy.get("complexity_enabled", False)
        ref["pwd_properties"] = policy.get("pwd_properties")
    elif match.finding_type == "WEAK_PASSWORD_HISTORY":
        ref["pwd_history_length"] = policy.get("pwd_history_length")
    elif match.finding_type == "MACHINE_ACCOUNT_QUOTA":
        ref["machine_account_quota"] = domain_info.get("machine_account_quota")
        ref["attribute"] = "ms-DS-MachineAccountQuota"
    elif match.finding_type == "LOW_DOMAIN_FUNCTIONAL_LEVEL":
        ref["domain_functional_level"] = domain_info.get("domain_functional_level")
        ref["attribute"] = "domainFunctionality"
    elif match.finding_type == "KRBTGT_STALE":
        ref["krbtgt_password_age_days"] = domain_info.get("krbtgt_password_age_days")
        ref["attribute"] = "pwdLastSet on krbtgt"
    elif match.finding_type == "REVERSIBLE_ENCRYPTION_ENABLED":
        ref["reversible_encryption"] = policy.get("reversible_encryption_enabled") or policy.get("reversible_encryption")
        ref["attribute"] = "ADS_UF_ENCRYPTED_TEXT_PASSWORD_ALLOWED"
    return [ref]


def _trust_source_refs(match: "RuleMatch", rule_data: dict[str, Any], limit: int = 10) -> list[dict[str, Any]]:
    """Extract structured trust object refs for trust findings."""
    if match.finding_type not in _TRUST_RULE_TYPES:
        return []
    tokens = _affected_tokens(match)
    refs: list[dict[str, Any]] = []
    for trust in rule_data.get("trusts", []) or []:
        if not isinstance(trust, dict):
            continue
        partner = str(
            trust.get("partner") or trust.get("target_domain")
            or trust.get("TargetDomainName") or trust.get("flat_name") or ""
        )
        if tokens and partner and partner.lower() not in tokens:
            continue
        # Use explicit None-checks so that False (SID filtering disabled) is preserved
        # through the lookup chain — Python `or` would swallow a False value.
        def _first_non_none(*values: Any) -> Any:
            for v in values:
                if v is not None:
                    return v
            return None

        sid_filter = _first_non_none(
            trust.get("sid_filtering"),
            trust.get("sid_filtering_enabled"),
            trust.get("SidFilteringEnabled"),
        )
        selective = _first_non_none(
            trust.get("selective_auth"),
            trust.get("SelectiveAuthentication"),
        )
        refs.append({
            "ref_type": "trust",
            "partner": partner or None,
            "target_domain": trust.get("target_domain") or trust.get("TargetDomainName") or partner or None,
            "trust_type": trust.get("trust_type") or trust.get("TrustType") or "TRUST",
            "direction": trust.get("direction") or trust.get("trust_direction") or trust.get("TrustDirection"),
            "sid_filtering": sid_filter,
            "selective_auth": selective,
        })
        if len(refs) >= limit:
            break
    return refs


def _build_evidence_catalog(payload: CollectorIngest, evidence_id_map: dict[str, UUID]) -> list[dict[str, Any]]:
    catalog: list[dict[str, Any]] = []
    for raw in payload.evidence:
        raw_id = str(raw.get("id") or "").strip()
        evidence_id = evidence_id_map.get(raw_id)
        if not evidence_id:
            continue
        catalog.append({
            "id": evidence_id,
            "raw_id": raw_id,
            "payload_type": _evidence_payload_type(raw),
            "source_type": str(raw.get("source_type") or "").lower(),
            "collection_method": str(raw.get("collection_method") or "").lower(),
            "raw_data": raw.get("raw_data") or {},
        })
    return catalog


def _evidence_for_types(catalog: list[dict[str, Any]], payload_types: tuple[str, ...]) -> list[dict[str, Any]]:
    wanted = {item.lower() for item in payload_types}
    matches = [
        item for item in catalog
        if item["payload_type"] in wanted
        or any(f"/{wanted_type}" in item["collection_method"] for wanted_type in wanted)
    ]
    return matches or catalog[:1]


def _affected_tokens(match: RuleMatch) -> set[str]:
    tokens: set[str] = set()
    for item in match.affected_objects or []:
        if isinstance(item, dict):
            for key in (
                "id", "entity_id", "object_sid", "object_id", "template_id",
                "template_name", "name", "sam_account_name", "display_name",
                "dns_hostname", "target_domain", "partner",
            ):
                value = item.get(key)
                if value:
                    tokens.add(str(value).strip().lower())
        elif item is not None:
            tokens.add(str(item).strip().lower())
    return {token for token in tokens if token}


def _entity_source_refs(match: "RuleMatch", rule_data: dict[str, Any], limit: int = 20) -> list[dict[str, Any]]:
    tokens = _affected_tokens(match)
    refs: list[dict[str, Any]] = []
    for entity in rule_data.get("entities", []) or []:
        attrs = entity.get("attributes") or {}
        values = {
            str(entity.get("id") or "").lower(),
            str(entity.get("object_sid") or "").lower(),
            str(entity.get("sam_account_name") or "").lower(),
            str(entity.get("display_name") or "").lower(),
            str(entity.get("dns_hostname") or "").lower(),
            str(attrs.get("object_sid") or "").lower(),
        }
        if tokens and not (tokens & values):
            continue
        refs.append({
            "ref_type": "entity",
            "entity_id": entity.get("id"),
            "entity_type": entity.get("entity_type"),
            "object_sid": entity.get("object_sid") or attrs.get("object_sid"),
            "sam_account_name": entity.get("sam_account_name"),
            "display_name": entity.get("display_name"),
            "distinguished_name": entity.get("distinguished_name"),
            "dns_hostname": entity.get("dns_hostname"),
        })
        if len(refs) >= limit:
            break
    return refs


def _edge_source_refs(match: "RuleMatch", rule_data: dict[str, Any], limit: int = 20) -> list[dict[str, Any]]:
    wanted_edge_types = set(_RULE_EDGE_TYPES.get(match.finding_type, ()))
    if not wanted_edge_types:
        return []
    # Build entity name/SID map for enriching edge endpoints
    entity_names: dict[str, str] = {}
    entity_sids: dict[str, str] = {}
    for entity in rule_data.get("entities", []) or []:
        eid = str(entity.get("id") or "")
        if eid:
            entity_names[eid] = (
                entity.get("sam_account_name")
                or entity.get("display_name")
                or entity.get("dns_hostname")
                or eid
            )
            if entity.get("object_sid"):
                entity_sids[eid] = str(entity.get("object_sid"))

    # Scope edges to those whose source appears in the finding's affected objects.
    # When affected_objects contains composite strings (e.g. "src -> tgt"), no source
    # matches — fall back to all edges of the wanted type so those findings still get refs.
    affected_tokens = _affected_tokens(match)
    all_typed = [
        edge for edge in rule_data.get("edges", []) or []
        if str(edge.get("edge_type") or "") in wanted_edge_types
    ]
    if affected_tokens:
        scoped = [
            edge for edge in all_typed
            if entity_names.get(str(edge.get("source_id") or ""), "").lower() in affected_tokens
            or str(edge.get("source_id") or "").lower() in affected_tokens
            or str(edge.get("source_ref") or "").lower() in affected_tokens
        ]
        candidate_edges = scoped if scoped else all_typed
    else:
        candidate_edges = all_typed

    refs: list[dict[str, Any]] = []
    for edge in candidate_edges:
        edge_type = str(edge.get("edge_type") or "")
        src_db = str(edge.get("source_id") or "")
        tgt_db = str(edge.get("target_id") or "")
        source_entity = next((e for e in rule_data.get("entities", []) or [] if str(e.get("id") or "") == src_db), {})
        target_entity = next((e for e in rule_data.get("entities", []) or [] if str(e.get("id") or "") == tgt_db), {})
        refs.append({
            "ref_type": "edge",
            "edge_type": edge_type,
            # raw imported identifiers (SID/name/DN from source payload)
            "source_id": edge.get("source_ref") or edge.get("source_id"),
            "target_id": edge.get("target_ref") or edge.get("target_id"),
            # normalized DB entity UUIDs
            "source_entity_id": src_db or None,
            "target_entity_id": tgt_db or None,
            # human-readable names resolved from entity map
            "source_name": entity_names.get(src_db),
            "target_name": entity_names.get(tgt_db),
            "source_sid": entity_sids.get(src_db),
            "target_sid": entity_sids.get(tgt_db),
            "source_entity_type": source_entity.get("entity_type") or "UNKNOWN",
            "target_entity_type": target_entity.get("entity_type") or "UNKNOWN",
            "ace_right": (edge.get("attributes") or {}).get("ace_right"),
            "rights": (edge.get("attributes") or {}).get("rights"),
            "derived_from": (edge.get("attributes") or {}).get("derived_from"),
            "provenance": edge.get("provenance"),
        })
        if len(refs) >= limit:
            break
    return refs


def _attack_path_from_rule_match(match: "RuleMatch", rule_data: dict[str, Any]) -> list[dict[str, Any]]:
    """Build a compact per-finding path from edge-level rule evidence.

    Full graph path computation remains in `/graph/{assessment_id}/paths`; this
    gives finding detail pages a direct source → target abuse edge when the rule
    was triggered by an edge-backed condition.
    """
    edge_refs = _edge_source_refs(match, rule_data, limit=1)
    if not edge_refs:
        return []
    ref = edge_refs[0]
    source_id = str(ref.get("source_entity_id") or ref.get("source_id") or "")
    target_id = str(ref.get("target_entity_id") or ref.get("target_id") or "")
    source_label = str(ref.get("source_name") or ref.get("source_id") or "Source")
    target_label = str(ref.get("target_name") or ref.get("target_id") or "Target")
    edge_type = str(ref.get("edge_type") or "")
    return [
        {
            "entity_id": source_id,
            "entity_label": source_label,
            "entity_type": ref.get("source_entity_type") or "UNKNOWN",
            "edge_type": edge_type or None,
            "provenance": ref.get("provenance"),
            "explanation": f"{source_label} has {edge_type.replace('_', ' ').lower()} over {target_label}" if edge_type else "",
        },
        {
            "entity_id": target_id,
            "entity_label": target_label,
            "entity_type": ref.get("target_entity_type") or "UNKNOWN",
            "edge_type": None,
            "provenance": ref.get("provenance"),
            "explanation": match.title,
        },
    ]


def _evidence_strength(source_refs: list[dict[str, Any]]) -> str:
    """Classify the quality level of evidence support for a finding-evidence link."""
    ref_types = {r.get("ref_type") for r in source_refs}
    if "edge" in ref_types:
        return "edge_level"
    if ref_types & {"cert_template", "policy", "trust"}:
        return "object_level"
    if "entity" in ref_types:
        return "object_level"
    return "payload_level_fallback"


def _build_relevance_text(
    match: "RuleMatch",
    source_refs: list[dict[str, Any]],
    evidence_item: dict[str, Any],
) -> str:
    """Generate a precise, human-readable relevance description for an evidence link.

    Prioritises edge-level > object-level (cert template, policy, trust, entity)
    > payload-level. Uses imported identifiers where available so the text is
    forensically traceable to actual source records.
    """
    method = evidence_item.get("collection_method") or evidence_item.get("source_type") or "imported evidence"

    edge_refs = [r for r in source_refs if r.get("ref_type") == "edge"]
    cert_refs = [r for r in source_refs if r.get("ref_type") == "cert_template"]
    policy_refs = [r for r in source_refs if r.get("ref_type") == "policy"]
    trust_refs = [r for r in source_refs if r.get("ref_type") == "trust"]
    entity_refs = [r for r in source_refs if r.get("ref_type") == "entity"]

    if edge_refs:
        ref = edge_refs[0]
        edge_type = ref.get("edge_type", "UNKNOWN_EDGE")
        src = ref.get("source_name") or ref.get("source_id") or "?"
        tgt = ref.get("target_name") or ref.get("target_id") or "?"
        rights_part = ""
        ace = ref.get("ace_right") or ref.get("rights")
        if ace:
            rights_part = f" [{ace}]"
        extra = ""
        if len(edge_refs) > 1:
            extra = f" (+{len(edge_refs) - 1} additional {edge_type} edge(s))"
        return (
            f"Derived from ACL/graph edge {edge_type}{rights_part}: "
            f"{src} → {tgt}{extra}; "
            f"via {method}"
        )

    if cert_refs:
        ref = cert_refs[0]
        tpl = ref.get("template_name") or "?"
        ca = ref.get("ca_name")
        ca_part = f" on {ca}" if ca else ""
        attrs: list[str] = []
        if ref.get("enrollee_supplies_subject"):
            attrs.append("enrollee-supplied SAN")
        ekus = ref.get("ekus") or []
        if ekus:
            attrs.append(f"EKU: {', '.join(str(e) for e in ekus[:2])}")
        if ref.get("write_rights"):
            attrs.append("write ACL configured")
        attr_part = f" ({', '.join(attrs)})" if attrs else ""
        extra = f" (+{len(cert_refs) - 1} more template(s))" if len(cert_refs) > 1 else ""
        return (
            f"Derived from cert template {tpl}{ca_part}{attr_part}{extra}; "
            f"via {method}"
        )

    if policy_refs:
        ref = policy_refs[0]
        attrs = []
        for key, label in (
            ("lockout_threshold", "lockoutThreshold"),
            ("min_password_length", "minPwdLength"),
            ("complexity_enabled", "pwdProperties.complexity"),
            ("pwd_history_length", "pwdHistoryLength"),
            ("machine_account_quota", "ms-DS-MachineAccountQuota"),
            ("domain_functional_level", "domainFunctionality"),
            ("krbtgt_password_age_days", "krbtgt pwdLastSet age"),
            ("reversible_encryption", "ADS_UF_ENCRYPTED_TEXT_PASSWORD_ALLOWED"),
        ):
            val = ref.get(key)
            if val is not None:
                attrs.append(f"{label}={val}")
        attr_part = f" ({', '.join(attrs)})" if attrs else ""
        return f"Derived from domain policy evidence{attr_part}; via {method}"

    if trust_refs:
        ref = trust_refs[0]
        partner = ref.get("partner") or ref.get("target_domain") or "?"
        attrs = []
        sid_filter = ref.get("sid_filtering")
        if sid_filter is False:
            attrs.append("SID filtering disabled")
        direction = ref.get("direction")
        if direction:
            attrs.append(f"direction={direction}")
        trust_type = ref.get("trust_type")
        if trust_type and trust_type != "TRUST":
            attrs.append(f"type={trust_type}")
        attr_part = f" ({', '.join(attrs)})" if attrs else ""
        extra = f" (+{len(trust_refs) - 1} more trust(s))" if len(trust_refs) > 1 else ""
        return (
            f"Derived from trust relationship with {partner}{attr_part}{extra}; "
            f"via {method}"
        )

    if entity_refs:
        names = []
        for r in entity_refs[:3]:
            name = (
                r.get("sam_account_name")
                or r.get("display_name")
                or r.get("dns_hostname")
                or r.get("object_sid")
                or r.get("entity_id")
            )
            if name:
                names.append(str(name))
        if names:
            name_str = ", ".join(names)
            if len(entity_refs) > 3:
                name_str += f" (+{len(entity_refs) - 3} more)"
            return f"Derived from {match.module} evidence for {name_str}; via {method}"

    # Fallback: payload-level only
    return f"Detected via {method} ({match.rule_name})"


def _rule_match_evidence_links(
    match: "RuleMatch",
    finding_id: UUID,
    rule_data: dict[str, Any],
    catalog: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    explicit_refs = {str(ref).strip() for ref in match.evidence_refs or [] if str(ref).strip()}
    if explicit_refs:
        evidence_items = [
            item for item in catalog
            if item["raw_id"] in explicit_refs or str(item["id"]) in explicit_refs
        ]
    else:
        evidence_items = _evidence_for_types(catalog, _RULE_EVIDENCE_TYPES.get(match.finding_type, ()))
    if not evidence_items:
        return []

    # Gather source refs from all evidence families — most specific first
    edge_refs = _edge_source_refs(match, rule_data)
    cert_refs = _cert_template_source_refs(match, rule_data)
    policy_refs = _policy_source_refs(match, rule_data)
    trust_refs = _trust_source_refs(match, rule_data)
    entity_refs = _entity_source_refs(match, rule_data)

    # Compose: specialised refs first, entity refs last (de-prioritised)
    source_refs = edge_refs + cert_refs + policy_refs + trust_refs + entity_refs

    strength = _evidence_strength(source_refs)

    # relation_type: "derived_from" when we have real object/edge refs; "supports" as fallback
    relation_type = "derived_from" if source_refs else "supports"

    source_ref = {
        "rule_id": match.rule_id,
        "rule_name": match.rule_name,
        "finding_type": match.finding_type,
        "module": match.module,
        "affected_objects": match.affected_objects[:20],
        "source_refs": source_refs[:30],
        "confidence": match.confidence,
        "provenance": "rule_engine",
        "evidence_strength": strength,
    }

    rows: list[dict[str, Any]] = []
    seen: set[UUID] = set()
    for item in evidence_items[:6]:
        evidence_id = item["id"]
        if evidence_id in seen:
            continue
        seen.add(evidence_id)
        relevance = _build_relevance_text(match, source_refs, item)
        rows.append({
            "id": uuid4(),
            "finding_id": finding_id,
            "evidence_id": evidence_id,
            "relation_type": relation_type,
            "evidence_strength": strength,
            "relevance": relevance,
            "source_ref": source_ref,
        })
    return rows


def _origin_from_value(value: str | None, fallback: DataOrigin) -> DataOrigin:
    if value:
        try:
            return DataOrigin(str(value).strip().upper())
        except ValueError:
            pass
    return fallback


def _payload_default_origin(payload: CollectorIngest) -> DataOrigin:
    try:
        collection_mode = CollectionMode(payload.collection_mode)
    except ValueError:
        collection_mode = None
    return DataOrigin.IMPORTED if collection_mode == CollectionMode.IMPORT else DataOrigin.COLLECTED


async def _bulk_insert(db: AsyncSession, model, rows: list[dict]) -> None:
    if not rows:
        return
    dialect_name = _get_dialect()
    if dialect_name == "postgresql":
        stmt = pg_insert(model)
    elif dialect_name == "sqlite":
        stmt = sqlite_insert(model)
    else:
        stmt = insert(model)
    for i in range(0, len(rows), _BULK_CHUNK):
        chunk_stmt = stmt.values(rows[i : i + _BULK_CHUNK])
        if hasattr(chunk_stmt, "on_conflict_do_nothing"):
            chunk_stmt = chunk_stmt.on_conflict_do_nothing()
        await db.execute(chunk_stmt)


@router.post("/{assessment_id}", status_code=status.HTTP_202_ACCEPTED)
async def ingest_collector_data(
    assessment_id: UUID,
    payload: CollectorIngest,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    current_user: PlatformUser = Depends(get_current_user),
):
    assessment = await require_assessment_write_access(assessment_id, db, current_user)

    result = await db.execute(
        select(Assessment).where(Assessment.id == assessment_id).with_for_update()
    )
    locked_assessment = result.scalars().first()
    if not locked_assessment:
        raise HTTPException(status_code=404, detail="Assessment not found")

    if locked_assessment.status == AssessmentStatus.RUNNING:
        raise HTTPException(
            status_code=409,
            detail="Assessment is currently RUNNING — please wait for it to finish",
        )

    locked_assessment.status = AssessmentStatus.RUNNING
    locked_assessment.started_at = _utcnow_naive()
    locked_assessment.modules_run = payload.modules_run
    locked_assessment.error_message = None
    await db.commit()

    background_tasks.add_task(_process_ingest, assessment_id=assessment_id, payload=payload)
    return {"message": "Ingest queued", "assessment_id": str(assessment.id)}


def _normalise_trust_direction(value: object) -> str:
    if isinstance(value, int):
        return {1: "INBOUND", 2: "OUTBOUND", 3: "BIDIRECTIONAL"}.get(value, str(value))
    text = str(value or "").strip()
    if text.isdigit():
        return {"1": "INBOUND", "2": "OUTBOUND", "3": "BIDIRECTIONAL"}.get(text, text)
    return text or "UNKNOWN"


def _materialize_trust_metadata(payload: CollectorIngest) -> None:
    trusts = payload.metadata.get("trusts", []) if isinstance(payload.metadata, dict) else []
    if not isinstance(trusts, list) or not trusts:
        return

    domain_entity = next(
        (entity for entity in payload.entities if str(entity.get("entity_type", "")).upper() == "DOMAIN"),
        None,
    )
    if not domain_entity:
        return
    domain_id = str(domain_entity.get("id") or "").strip()
    if not domain_id:
        return

    existing_entity_ids = {str(entity.get("id") or "").strip() for entity in payload.entities}
    existing_edges = {
        (
            str(edge.get("source_id") or "").strip(),
            str(edge.get("target_id") or "").strip(),
            str(edge.get("edge_type") or "").strip(),
        )
        for edge in payload.edges
    }

    for index, trust in enumerate(trusts):
        if not isinstance(trust, dict):
            continue
        target_domain = str(
            trust.get("target_domain")
            or trust.get("partner")
            or trust.get("TargetDomainName")
            or trust.get("flat_name")
            or trust.get("FlatName")
            or ""
        ).strip()
        target_sid = str(
            trust.get("partner_sid")
            or trust.get("target_domain_sid")
            or trust.get("TargetDomainSid")
            or ""
        ).strip()
        if not target_domain and not target_sid:
            continue

        trust_id_suffix = target_sid or target_domain.lower().replace(" ", "-") or str(index)
        trust_id = f"trust:{payload.domain}:{trust_id_suffix}"
        trust_type = str(trust.get("trust_type") or trust.get("TrustType") or "TRUST")
        direction = _normalise_trust_direction(
            trust.get("direction") or trust.get("trust_direction") or trust.get("TrustDirection")
        )
        transitive = bool(trust.get("transitive", trust.get("IsTransitive", True)))
        sid_filtering = bool(
            trust.get(
                "sid_filtering",
                trust.get("sid_filtering_enabled", trust.get("SidFilteringEnabled", True)),
            )
        )
        selective_auth = bool(trust.get("selective_auth", trust.get("SelectiveAuthentication", False)))

        if trust_id not in existing_entity_ids:
            payload.entities.append({
                "id": trust_id,
                "entity_type": "TRUST",
                "object_sid": target_sid or None,
                "sam_account_name": target_domain or target_sid,
                "display_name": target_domain or target_sid,
                "domain": payload.domain,
                "is_enabled": True,
                "is_admin_count": False,
                "is_sensitive": not sid_filtering,
                "is_protected_user": False,
                "is_crown_jewel": False,
                "tier": None,
                "business_tags": ["Trust Relationship"],
                "attributes": {
                    "target_domain": target_domain or target_sid,
                    "target_sid": target_sid or None,
                    "partner": target_domain or target_sid,
                    "trust_type": trust_type,
                    "direction": direction,
                    "transitive": transitive,
                    "sid_filtering": sid_filtering,
                    "selective_auth": selective_auth,
                    "trust_attributes": trust.get("trust_attributes") or trust.get("TrustAttributes"),
                    "source": "metadata/trusts",
                },
            })
            existing_entity_ids.add(trust_id)

        edge_key = (domain_id, trust_id, "TRUSTS")
        if edge_key not in existing_edges:
            payload.edges.append({
                "source_id": domain_id,
                "target_id": trust_id,
                "edge_type": "TRUSTS",
                "risk_weight": 0.90 if not sid_filtering else 0.60,
                "provenance": "Ingest trust metadata",
                "attributes": {
                    "target_domain": target_domain or target_sid,
                    "trust_type": trust_type,
                    "direction": direction,
                    "sid_filtering": sid_filtering,
                    "transitive": transitive,
                },
            })
            existing_edges.add(edge_key)


def _normalise_attrs(attrs: dict) -> dict:
    out = dict(attrs or {})
    mappings = {
        "dont_require_preauth": "uac_dont_require_preauth",
        "passwd_notreqd": "uac_passwd_notreqd",
        "trusted_for_delegation": "uac_trusted_for_delegation",
        "is_dc": "uac_is_dc",
        "has_spn": "has_spn",
        "has_laps": "laps_installed",
        "hasLAPS": "laps_installed",
        "pwdneverexpires": "pwd_never_expires",
        "passwordneverexpires": "pwd_never_expires",
        "trustedtoauth": "constrained_delegation_any_protocol",
        "uac_trusted_to_auth_for_delegation": "constrained_delegation_any_protocol",
    }
    for src_key, dst_key in mappings.items():
        if src_key in out and dst_key not in out:
            out[dst_key] = out[src_key]
    return out

def _build_rule_data(
    entity_rows: list[dict],
    raw_edges: list,
    cert_rows: list[dict],
    entity_id_map: dict[str, UUID],
    payload: CollectorIngest,
) -> dict:
    """Pure CPU work — safe to run in a thread pool."""
    entities_dicts = [
        {
            "id": str(row["id"]),
            "entity_type": row["entity_type"].value,
            "sam_account_name": row["sam_account_name"],
            "display_name": row["display_name"],
            "dns_hostname": row.get("dns_hostname"),
            "distinguished_name": row.get("distinguished_name"),
            "object_sid": row.get("object_sid"),
            "domain": row.get("domain"),
            "is_enabled": row["is_enabled"],
            "is_admin_count": row["is_admin_count"],
            "is_crown_jewel": row["is_crown_jewel"],
            "tier": row["tier"],
            "attributes": _normalise_attrs(row["attributes"] or {}),
        }
        for row in entity_rows
    ]
    cert_template_dicts = [
        {
            "name": row["name"],
            "distinguished_name": row.get("distinguished_name"),
            "ca_name": row.get("ca_name"),
            "ekus": row.get("ekus", []),
            "enrollment_rights": row.get("enrollment_rights", []),
            "write_rights": row.get("write_rights", []),
            "attributes": row.get("raw_attributes", {}),
            "esc1_vulnerable": row["esc1_vulnerable"],
            "esc2_vulnerable": row["esc2_vulnerable"],
            "esc3_vulnerable": row["esc3_vulnerable"],
            "esc4_vulnerable": row["esc4_vulnerable"],
        }
        for row in cert_rows
    ]
    rule_edges = []
    for raw_edge in raw_edges:
        src_db = entity_id_map.get(raw_edge.get("source_id"))
        tgt_db = entity_id_map.get(raw_edge.get("target_id"))
        if src_db and tgt_db:
            rule_edges.append({
                "source_id": str(src_db),
                "target_id": str(tgt_db),
                "source_ref": raw_edge.get("source_id"),
                "target_ref": raw_edge.get("target_id"),
                "edge_type": raw_edge.get("edge_type", ""),
                "provenance": raw_edge.get("provenance"),
                "attributes": raw_edge.get("attributes", {}),
            })
    return {
        "entities": entities_dicts,
        "edges": rule_edges,
        "evidence": [
            {
                "id": raw.get("id"),
                "source_type": raw.get("source_type", "ldap"),
                "source_host": raw.get("source_host"),
                "collection_method": raw.get("collection_method"),
                "raw_data": raw.get("raw_data", {}),
                "confidence": raw.get("confidence", 1.0),
            }
            for raw in payload.evidence
        ],
        "cert_templates": cert_template_dicts,
        "ca_flags": payload.ca_flags,
        "adcs_ca_configs": payload.metadata.get("adcs_ca_configs", []),
        "ca_configs": payload.metadata.get("ca_configs", []),
        "pki_objects": payload.metadata.get("pki_objects", []),
        "domain_info": payload.metadata.get("domain_info", {}),
        "password_policy": payload.metadata.get("password_policy", {}),
        "trusts": payload.metadata.get("trusts", []),
        "network_config": payload.metadata.get("network_config", {}),
    }


def _build_rule_finding_rows(rule_matches: list, assessment_id: UUID, rule_data: dict[str, Any] | None = None) -> list[dict]:
    """Pure CPU work — safe to run in a thread pool."""
    rows: list[dict] = []
    for match in rule_matches:
        try:
            severity = SeverityLevel(match.severity.upper())
        except ValueError:
            severity = SeverityLevel.INFO
        scored = scoring_service.score_finding({
            "technical_severity": match.technical_severity,
            "reachability": match.reachability,
            "confidence": match.confidence,
            "affected_count": match.affected_count,
            "on_crown_jewel_path": match.on_crown_jewel_path,
            "is_tier0_direct": match.is_tier0_direct,
        })
        rows.append({
            "id": uuid4(),
            "assessment_id": assessment_id,
            "finding_type": match.finding_type,
            "module": match.module,
            "title": match.title,
            "description": match.description,
            "origin": DataOrigin.INFERRED,
            "severity": severity,
            "technical_severity": match.technical_severity,
            "reachability_score": match.reachability,
            "confidence": match.confidence,
            "affected_count": match.affected_count,
            "affected_objects": match.affected_objects,
            "root_cause": match.root_cause,
            "causal_chain": match.causal_chain,
            "attack_path": _attack_path_from_rule_match(match, rule_data) if rule_data else [],
            "remediation": match.remediation,
            "remediation_steps": match.remediation_steps,
            "fix_complexity": match.fix_complexity,
            "references": match.references,
            "cve_ids": getattr(match, "cve_ids", []) or [],
            "mitre_attack_ids": getattr(match, "mitre_attack_ids", []) or [],
            "composite_score": scored["composite_score"],
            "status": FindingStatus.OPEN,
            "drift_status": "new",
        })
    return rows


async def _process_ingest(assessment_id: UUID, payload: CollectorIngest, job_id: str | None = None) -> bool:
    assessment: Assessment | None = None

    async def _update_progress(msg: str, pct: int):
        log.info("[%s] %s (%d%%)", assessment_id, msg, pct)
        if job_id:
            await _jobs_module.emit(job_id, {"phase": "ingest", "message": msg, "pct": pct, "level": "INFO"})

        # PostgreSQL can safely publish these status writes through a second
        # session. SQLite holds a database-level writer lock while the ingest
        # transaction is open; a second writer blocks for the busy timeout and
        # the progress update is then dropped. Keep SQLite progress in the main
        # transaction and rely on SSE for live updates.
        if _get_dialect() == "sqlite":
            if assessment is not None:
                assessment.progress_pct = pct
                assessment.last_message = msg
            return

        try:
            async with AsyncSessionLocal() as prog_db:
                from sqlalchemy import update
                await prog_db.execute(
                    update(Assessment)
                    .where(Assessment.id == assessment_id)
                    .values(progress_pct=pct, last_message=msg)
                )
                await prog_db.commit()
        except Exception:
            log.warning("Failed to update progress for assessment %s", assessment_id, exc_info=True)

    async with AsyncSessionLocal() as db:
        try:
            result = await db.execute(select(Assessment).where(Assessment.id == assessment_id))
            assessment = result.scalars().first()
            if not assessment:
                return False

            log.info(
                "Processing ingest for %s: %s entities, %s edges, %s evidence records",
                assessment_id,
                len(payload.entities),
                len(payload.edges),
                len(payload.evidence),
            )
            payload_origin = _payload_default_origin(payload)
            _materialize_trust_metadata(payload)

            # Clear any previous ingest data for this assessment to avoid duplicates
            # FindingEvidence has no assessment_id — delete via finding_id FK
            finding_ids_q = select(Finding.id).where(Finding.assessment_id == assessment_id)
            await db.execute(delete(FindingEvidence).where(FindingEvidence.finding_id.in_(finding_ids_q)))
            for model in (GraphEdge, EvidenceRecord, Finding, Entity, CertTemplate):
                await db.execute(delete(model).where(model.assessment_id == assessment_id))
            # No flush here! Keep deletes uncommitted until inserts are ready.

            # ── Entities (bulk) ────────────────────────────────────────────
            entity_id_map: dict[str, UUID] = {}  # any alias → db uuid
            seen_primary: set[str] = set()
            entity_rows: list[dict] = []
            skipped_entities = 0

            for raw in payload.entities:
                try:
                    entity_type = EntityType(raw.get("entity_type", "USER"))
                except ValueError:
                    log.warning(
                        "Skipping entity with unknown entity_type=%r (sam=%r)",
                        raw.get("entity_type"),
                        raw.get("sam_account_name"),
                    )
                    skipped_entities += 1
                    continue

                ent_id = uuid4()
                raw_id = raw.get("id") or ""
                dn = raw.get("distinguished_name") or ""
                sam = raw.get("sam_account_name") or ""
                sid = raw.get("object_sid") or ""
                primary_key = raw_id or dn or sam or str(ent_id)
                if primary_key in seen_primary:
                    log.warning("Duplicate entity key %r in ingest payload; skipping insert", primary_key)
                    skipped_entities += 1
                    continue

                seen_primary.add(primary_key)
                # Register all aliases so edges can reference entities by id, DN, SAM, or SID
                for alias in filter(None, [raw_id, dn, sam, sid]):
                    entity_id_map[alias] = ent_id
                raw_attrs = raw.get("attributes", {}) or {}
                entity_rows.append({
                    "id": ent_id,
                    "assessment_id": assessment_id,
                    "entity_type": entity_type,
                    "distinguished_name": raw.get("distinguished_name"),
                    "object_sid": raw.get("object_sid"),
                    "sam_account_name": raw.get("sam_account_name"),
                    "display_name": raw.get("display_name"),
                    "dns_hostname": raw.get("dns_hostname"),
                    "domain": raw.get("domain") or payload.domain,
                    "is_enabled": raw.get("is_enabled", True),
                    "is_admin_count": raw.get("is_admin_count", False),
                    "is_sensitive": raw.get("is_sensitive", False),
                    "is_protected_user": raw.get("is_protected_user", False),
                    "tier": raw.get("tier"),
                    "is_crown_jewel": raw.get("is_crown_jewel", False),
                    "business_tags": raw.get("business_tags", []),
                    "attributes": raw_attrs,
                    "object_created": _pick_datetime(raw, raw_attrs, "object_created", "whencreated"),
                    "object_modified": _pick_datetime(raw, raw_attrs, "object_modified", "whenchanged"),
                    "last_logon": _pick_datetime(raw, raw_attrs, "last_logon", "last_logon_timestamp", "lastlogon", "lastlogontimestamp"),
                    "password_last_set": _pick_datetime(raw, raw_attrs, "password_last_set", "pwdlastset"),
                })

            if skipped_entities:
                log.warning("Skipped %s entities with unrecognised entity_type", skipped_entities)

            await _bulk_insert(db, Entity, entity_rows)
            await db.flush()

            # ── Edges (bulk) ───────────────────────────────────────────────
            edge_rows: list[dict] = []
            for raw in payload.edges:
                src_db_id = entity_id_map.get(raw.get("source_id"))
                tgt_db_id = entity_id_map.get(raw.get("target_id"))
                if not src_db_id or not tgt_db_id:
                    continue
                try:
                    edge_type = EdgeType(raw.get("edge_type", "HAS_CONTROL"))
                except ValueError:
                    edge_type = EdgeType.HAS_CONTROL

                edge_rows.append({
                    "id": uuid4(),
                    "assessment_id": assessment_id,
                    "source_id": src_db_id,
                    "target_id": tgt_db_id,
                    "edge_type": edge_type,
                    "provenance": raw.get("provenance"),
                    "risk_weight": raw.get("risk_weight", 1.0),
                    "attributes": raw.get("attributes", {}),
                })

            await _bulk_insert(db, GraphEdge, edge_rows)
            await db.flush()

            # ── Evidence (bulk) ────────────────────────────────────────────
            evidence_id_map: dict[str, UUID] = {}
            evidence_rows: list[dict] = []
            for raw in payload.evidence:
                evidence_id = uuid4()
                raw_id = str(raw.get("id") or evidence_id)
                evidence_id_map[raw_id] = evidence_id
                evidence_rows.append({
                    "id": evidence_id,
                    "assessment_id": assessment_id,
                    "source_type": raw.get("source_type", "ldap"),
                    "source_host": raw.get("source_host"),
                    "source_port": raw.get("source_port"),
                    "collection_method": raw.get("collection_method"),
                    "origin": _origin_from_value(raw.get("origin"), payload_origin),
                    "raw_data": raw.get("raw_data"),
                    "confidence": raw.get("confidence", 1.0),
                })

            await _bulk_insert(db, EvidenceRecord, evidence_rows)
            await db.flush()

            # ── Cert templates (bulk) ──────────────────────────────────────
            cert_rows = [
                {
                    "id": uuid4(),
                    "assessment_id": assessment_id,
                    "name": raw.get("name"),
                    "distinguished_name": raw.get("distinguished_name"),
                    "ca_name": raw.get("ca_name"),
                    "enrollee_supplies_subject": raw.get("enrollee_supplies_subject", False),
                    "requires_manager_approval": raw.get("requires_manager_approval", False),
                    "authorized_signatures_required": raw.get("authorized_signatures_required", 0),
                    "ekus": raw.get("ekus", []),
                    "enrollment_rights": raw.get("enrollment_rights", []),
                    "write_rights": raw.get("write_rights", []),
                    "esc1_vulnerable": raw.get("esc1_vulnerable", False),
                    "esc2_vulnerable": raw.get("esc2_vulnerable", False),
                    "esc3_vulnerable": raw.get("esc3_vulnerable", False),
                    "esc4_vulnerable": raw.get("esc4_vulnerable", False),
                    "raw_attributes": raw.get("attributes", {}),
                }
                for raw in payload.cert_templates
            ]
            await _bulk_insert(db, CertTemplate, cert_rows)
            await db.flush()

            # ── Payload findings (bulk) ────────────────────────────────────
            finding_rows: list[dict] = []
            finding_evidence_pairs: list[tuple[UUID, UUID, str, str, dict[str, Any]]] = []
            linked_pairs: set[tuple[UUID, UUID]] = set()

            for raw in payload.findings:
                try:
                    severity = SeverityLevel(raw.get("severity", "INFO").upper())
                except ValueError:
                    severity = SeverityLevel.INFO

                scored = scoring_service.score_finding({
                    "technical_severity": raw.get("technical_severity", 5.0),
                    "reachability": raw.get("reachability", 0.5),
                    "confidence": raw.get("confidence", 1.0),
                    "asset_criticality": raw.get("asset_criticality", 0.5),
                    "affected_count": raw.get("affected_count", 1),
                    "on_crown_jewel_path": raw.get("on_crown_jewel_path", False),
                    "is_tier0_direct": raw.get("is_tier0_direct", False),
                })

                finding_id = uuid4()
                finding_rows.append({
                    "id": finding_id,
                    "assessment_id": assessment_id,
                    "finding_type": raw.get("finding_type", raw.get("type", "UNKNOWN")),
                    "module": raw.get("module", "Unknown"),
                    "title": raw.get("title", ""),
                    "description": raw.get("description", ""),
                    "origin": _origin_from_value(raw.get("origin"), payload_origin),
                    "severity": severity,
                    "technical_severity": raw.get("technical_severity"),
                    "reachability_score": raw.get("reachability"),
                    "confidence": raw.get("confidence", 1.0),
                    "affected_count": raw.get("affected_count", 0),
                    "affected_objects": raw.get("affected_objects", raw.get("affected", [])),
                    "root_cause": raw.get("root_cause", ""),
                    "causal_chain": raw.get("causal_chain", []),
                    "attack_path": raw.get("attack_path", []),
                    "remediation": raw.get("remediation", ""),
                    "remediation_steps": raw.get("remediation_steps", []),
                    "fix_complexity": raw.get("fix_complexity", "medium"),
                    "references": raw.get("references", []),
                    "cve_ids": raw.get("cve_ids", []),
                    "mitre_attack_ids": raw.get("mitre_attack_ids", []),
                    "composite_score": scored["composite_score"],
                    "status": FindingStatus.OPEN,
                    "drift_status": "new",
                })

                for evidence_ref in _extract_evidence_refs(raw):
                    evidence_id = evidence_id_map.get(evidence_ref)
                    if not evidence_id:
                        continue
                    pair = (finding_id, evidence_id)
                    if pair not in linked_pairs:
                        linked_pairs.add(pair)
                        finding_evidence_pairs.append((
                            finding_id,
                            evidence_id,
                            raw.get("evidence_relevance") or "Collector-reported supporting evidence",
                            raw.get("evidence_relation_type") or "supports",
                            raw.get("source_ref") or {},
                        ))

            await _bulk_insert(db, Finding, finding_rows)
            await db.flush()

            finding_evidence_rows = [
                {
                    "id": uuid4(),
                    "finding_id": fid,
                    "evidence_id": eid,
                    "relation_type": relation_type,
                    "relevance": rel,
                    "source_ref": source_ref,
                }
                for fid, eid, rel, relation_type, source_ref in finding_evidence_pairs
            ]
            await _bulk_insert(db, FindingEvidence, finding_evidence_rows)
            await db.flush()

            # ── Rule engine — offloaded to thread pool (CPU-bound) ─────────
            rule_data = await asyncio.to_thread(
                _build_rule_data, entity_rows, payload.edges, cert_rows, entity_id_map, payload
            )
            # ── Analysis Phase ────────────────────────────────────────────
            await _update_progress("Running security rule engine analysis…", 85)
            rule_matches = await asyncio.to_thread(rule_engine.evaluate_all, rule_data)
            await _update_progress(f"Rule engine complete — found {len(rule_matches)} potential issues", 92)
            log.info("Rule engine produced %s findings for %s", len(rule_matches), assessment_id)

            # ── Rule-engine findings (bulk) — scored in thread pool ────────
            rule_finding_rows = await asyncio.to_thread(
                _build_rule_finding_rows, rule_matches, assessment_id, rule_data
            )

            await _bulk_insert(db, Finding, rule_finding_rows)
            await db.flush()

            evidence_catalog = _build_evidence_catalog(payload, evidence_id_map)
            rule_finding_evidence_rows: list[dict[str, Any]] = []
            for match, row in zip(rule_matches, rule_finding_rows, strict=False):
                rule_finding_evidence_rows.extend(
                    _rule_match_evidence_links(match, row["id"], rule_data, evidence_catalog)
                )
            await _bulk_insert(db, FindingEvidence, rule_finding_evidence_rows)
            await db.flush()

            # ── Finalise assessment — scores computed from in-memory rows ──
            all_finding_rows = finding_rows + rule_finding_rows
            exposure_score = scoring_service.compute_exposure_score(all_finding_rows)

            sev_count: dict[str, int] = {s.value: 0 for s in SeverityLevel}
            for r in all_finding_rows:
                sev_count[r["severity"].value] = sev_count.get(r["severity"].value, 0) + 1

            assessment.status = AssessmentStatus.COMPLETED
            assessment.completed_at = _utcnow_naive()
            assessment.progress_pct = 100
            assessment.last_message = "Ingest and analysis complete"
            assessment.modules_run = payload.modules_run
            assessment.exposure_score = exposure_score
            assessment.stats = {
                "total_findings": len(all_finding_rows),
                "critical": sev_count.get("CRITICAL", 0),
                "high": sev_count.get("HIGH", 0),
                "medium": sev_count.get("MEDIUM", 0),
                "low": sev_count.get("LOW", 0),
                "info": sev_count.get("INFO", 0),
                "total_entities": len(entity_rows),
                "total_edges": len(edge_rows),
            }

            await db.commit()

            # Re-project the assessment graph into Neo4j (source of truth = Postgres)
            _enqueue_projection_after_ingest(str(assessment_id))

            log.info(
                "Assessment %s completed. Score: %s, Findings: %s",
                assessment_id,
                exposure_score,
                len(all_finding_rows),
            )
            return True

        except Exception as exc:
            log.error("Ingest failed for %s: %s", assessment_id, exc, exc_info=True)
            # use a FRESH session to mark the assessment failed.
            # The existing `db` session may be in a dirty/broken state (partially
            # written rows, failed flush, etc.).  Re-using it can silently succeed
            # with stale identity-map data or raise IntegrityError on re-commit.
            try:
                async with AsyncSessionLocal() as err_db:
                    err_result = await err_db.execute(select(Assessment).where(Assessment.id == assessment_id))
                    failed_assessment = err_result.scalars().first()
                    if failed_assessment:
                        failed_assessment.status = AssessmentStatus.FAILED
                        failed_assessment.error_message = str(exc)
                        await err_db.commit()
            except Exception as mark_exc:
                log.error("Failed to mark assessment %s as FAILED: %s", assessment_id, mark_exc)
            return False


# ── CA Flags sub-ingest ────────────────────────────────────────────────────────

class CAFlagsIngest(BaseModel):
    """Payload from Collect-AdByG0d-ADCS-CAFlags.ps1 or any Windows CA collector."""

    ca_flags: list[dict[str, Any]]


@router.post("/{assessment_id}/ca-flags")
async def ingest_ca_flags(
    assessment_id: UUID,
    payload: CAFlagsIngest,
    db: AsyncSession = Depends(get_db),
    current_user: PlatformUser = Depends(get_current_user),
):
    """Ingest CA EditFlags evidence from Windows collector without re-running full ingest.

    Accepts the JSON output of Collect-AdByG0d-ADCS-CAFlags.ps1.
    Upserts ESC6_CA_SAN_FLAG_ENABLED findings for any CA with EDITF_ATTRIBUTESUBJECTALTNAME2 set.
    Does NOT clear or modify other findings, entities, or evidence.
    """
    await require_assessment_write_access(assessment_id, db, current_user)

    result = await db.execute(select(Assessment).where(Assessment.id == assessment_id))
    assessment = result.scalars().first()
    if not assessment:
        raise HTTPException(status_code=404, detail="Assessment not found")
    if assessment.status not in (AssessmentStatus.COMPLETED, AssessmentStatus.RUNNING):
        raise HTTPException(
            status_code=409,
            detail="CA flags can only be imported into a COMPLETED or RUNNING assessment",
        )

    if not payload.ca_flags:
        raise HTTPException(status_code=422, detail="ca_flags list is empty")

    # Normalise and evaluate each CA flag entry
    normalised: list[dict] = []
    for ca in payload.ca_flags:
        ca_name = str(ca.get("ca_name") or "")
        edit_flags_raw = ca.get("edit_flags", 0)
        editf_direct = ca.get("editf_attribute_subject_alt_name_2")
        certutil_out = ca.get("certutil_output") or ""

        # Accept int, hex string, decimal string, or LDAP-style list/wrapper values.
        ef_int = parse_int(edit_flags_raw)

        # Also try to parse from certutil output if no direct value
        if ef_int == 0 and certutil_out:
            parsed = parse_certutil_edit_flags(certutil_out)
            if parsed is not None:
                ef_int = parsed

        flag_set = (
            bool(editf_direct)
            or esc6_enabled(ef_int)
            or certutil_has_editf_altsubjectname(certutil_out)
        )
        normalised.append({
            "ca_name": ca_name,
            "hostname": ca.get("hostname") or ca.get("host") or "",
            "edit_flags": ef_int,
            "edit_flags_hex": ca.get("edit_flags_hex") or hex(ef_int),
            "editf_attribute_subject_alt_name_2": flag_set,
            "registry_path": ca.get("registry_path") or "",
            "certutil_output": certutil_out,
            "collection_method": ca.get("collection_method") or "windows_ca_flags",
        })

    # Store as evidence record
    evidence_id = uuid4()
    evidence_row = {
        "id": evidence_id,
        "assessment_id": assessment_id,
        "source_type": "windows_registry",
        "source_host": normalised[0]["hostname"] if normalised else None,
        "source_port": None,
        "collection_method": "windows_ca_flags",
        "origin": DataOrigin.IMPORTED,
        "raw_data": {"ca_flags": normalised},
        "confidence": 1.0,
    }
    await _bulk_insert(db, EvidenceRecord, [evidence_row])
    await db.flush()

    # Remove existing ESC6 findings and insert fresh ones atomically
    try:
        esc6_ids_q = (
            select(Finding.id)
            .where(Finding.assessment_id == assessment_id)
            .where(Finding.finding_type == "ESC6_CA_SAN_FLAG_ENABLED")
        )
        await db.execute(delete(FindingEvidence).where(FindingEvidence.finding_id.in_(esc6_ids_q)))
        await db.execute(
            delete(Finding)
            .where(Finding.assessment_id == assessment_id)
            .where(Finding.finding_type == "ESC6_CA_SAN_FLAG_ENABLED")
        )
        await db.flush()

        # Evaluate ESC6 rule
        rule_data = {"ca_flags": normalised, "entities": [], "cert_templates": []}
        rule_matches = await asyncio.to_thread(rule_engine.evaluate_all, rule_data)
        esc6_matches = [m for m in rule_matches if m.finding_type == "ESC6_CA_SAN_FLAG_ENABLED"]

        finding_rows = await asyncio.to_thread(_build_rule_finding_rows, esc6_matches, assessment_id)

        # Link findings → evidence
        finding_evidence_rows = []
        for row in finding_rows:
            finding_evidence_rows.append({
                "id": uuid4(),
                "finding_id": row["id"],
                "evidence_id": evidence_id,
                "relation_type": "supports",
                "relevance": "Windows CA registry EditFlags evidence",
                "source_ref": {
                    "finding_type": row.get("finding_type"),
                    "source_refs": [
                        {"ref_type": "ca", "ca_name": item.get("ca_name"), "host": item.get("hostname")}
                        for item in normalised[:20]
                    ],
                    "provenance": "ca_flags_ingest",
                },
            })

        await _bulk_insert(db, Finding, finding_rows)
        await db.flush()
        await _bulk_insert(db, FindingEvidence, finding_evidence_rows)
        await db.commit()
    except Exception as exc:
        await db.rollback()
        log.error("ESC6 ingest failed for assessment %s, rolled back: %s", assessment_id, exc)
        raise HTTPException(status_code=500, detail="CA flags ingest failed") from exc

    log.info(
        "CA flags ingested for %s: %s CAs evaluated, %s ESC6 findings created",
        assessment_id,
        len(normalised),
        len(finding_rows),
    )
    return {
        "cas_evaluated": len(normalised),
        "esc6_findings_created": len(finding_rows),
        "evidence_id": str(evidence_id),
    }
