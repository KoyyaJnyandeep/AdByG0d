import io
import json
import logging
import zipfile
from datetime import datetime, timezone
from typing import Any

log = logging.getLogger(__name__)

_BH_ZIP_MAX_MEMBERS = 256
_BH_ZIP_MAX_UNCOMPRESSED_BYTES = 256 * 1024 * 1024  # 256 MB
_BH_ZIP_MAX_RATIO = 100

MAX_MEMBER_BYTES = 128 * 1024 * 1024   # 128 MB per ZIP entry (decompressed)
MAX_OBJECTS_PER_TYPE = 500_000         # items per data list


def _validate_bloodhound_zip_members(members: list[zipfile.ZipInfo]) -> None:
    if len(members) > _BH_ZIP_MAX_MEMBERS:
        raise ValueError(
            f"ZIP contains too many BloodHound members ({len(members)} > {_BH_ZIP_MAX_MEMBERS})"
        )

    total_uncompressed = sum(member.file_size for member in members)
    if total_uncompressed > _BH_ZIP_MAX_UNCOMPRESSED_BYTES:
        raise ValueError(
            f"ZIP total uncompressed size {total_uncompressed} exceeds limit {_BH_ZIP_MAX_UNCOMPRESSED_BYTES}"
        )

    for member in members:
        if member.compress_size == 0 and member.file_size > 0:
            raise ValueError(
                f"ZIP member {member.filename!r} has zero compressed size but non-zero uncompressed size "
                f"({member.file_size}) — malformed entry rejected"
            )
        if member.compress_size > 0 and member.file_size / member.compress_size > _BH_ZIP_MAX_RATIO:
            raise ValueError(
                f"ZIP member {member.filename!r} has suspicious compression ratio "
                f"({member.file_size}/{member.compress_size})"
            )

_ACE_TO_EDGE: dict[str, str] = {
    "GenericAll": "GENERIC_ALL", "GenericWrite": "HAS_CONTROL",
    "WriteProperty": "HAS_CONTROL",
    "WriteOwner": "WRITE_OWNER", "WriteDacl": "WRITE_DACL",
    "AllExtendedRights": "HAS_CONTROL", "AddMember": "ADD_MEMBER",
    "AddSelf": "ADD_MEMBER", "ForceChangePassword": "FORCE_CHANGE_PASSWORD",
    "ReadLAPSPassword": "HAS_CONTROL", "ReadGMSAPassword": "HAS_CONTROL",
    "Owns": "OWNS", "DCSync": "DCSYNC",
    "AllowedToDelegate": "ALLOWED_TO_DELEGATE",
    "AllowedToAct": "ALLOWED_TO_ACT", "AdminTo": "ADMIN_TO",
    "CanRDP": "CAN_RDP", "CanPSRemote": "CAN_WINRM",
    "ExecuteDCOM": "HAS_CONTROL", "HasSIDHistory": "HAS_CONTROL",
    "SQLAdmin": "ADMIN_TO",
}

_TYPE_MAP: dict[str, str] = {
    "User": "USER", "Group": "GROUP", "Computer": "COMPUTER",
    "Domain": "DOMAIN", "GPO": "GPO", "OU": "OU", "Container": "OU",
    "CertTemplate": "CERT_TEMPLATE", "EnterpriseCA": "CA",
    "AIACA": "CA", "RootCA": "CA", "IssuancePolicy": "CERT_TEMPLATE",
    "NTAuthStore": "CA", "DC": "DC", "Trust": "TRUST",
}

_FILE_TYPES: dict[str, str] = {
    "users": "User", "groups": "Group", "computers": "Computer",
    "domains": "Domain", "gpos": "GPO", "ous": "OU",
    "containers": "OU", "certtemplates": "CertTemplate",
    "enterprisecas": "EnterpriseCA",
}

_HVG: frozenset[str] = frozenset([
    "DOMAIN ADMINS", "ENTERPRISE ADMINS", "SCHEMA ADMINS",
    "ADMINISTRATORS", "DOMAIN CONTROLLERS", "READ-ONLY DOMAIN CONTROLLERS",
    "GROUP POLICY CREATOR OWNERS", "PROTECTED USERS", "CERT PUBLISHERS",
    "ACCOUNT OPERATORS", "BACKUP OPERATORS", "PRINT OPERATORS",
    "SERVER OPERATORS", "REMOTE MANAGEMENT USERS",
])

_CLIENT_AUTH_EKUS: frozenset[str] = frozenset([
    "1.3.6.1.5.5.7.3.2", "1.3.6.1.4.1.311.20.2.2",
    "1.3.6.1.5.2.3.4", "2.5.29.37.0",
])

_HIGH_RISK_EDGES: frozenset[str] = frozenset(["GENERIC_ALL", "WRITE_DACL", "DCSYNC"])
_DCSYNC_COMPONENT_RIGHTS: frozenset[str] = frozenset(["GetChanges", "GetChangesAll"])

_ESC4_CONTROL_RIGHTS: frozenset[str] = frozenset([
    "Owns", "GenericAll", "GenericWrite", "WriteProperty", "WriteOwner", "WriteDacl",
])
_LOW_PRIV_SIDS: frozenset[str] = frozenset([
    "S-1-1-0",       # Everyone
    "S-1-5-11",      # Authenticated Users
    "S-1-5-32-545",  # BUILTIN\Users
])
_LOW_PRIV_DOMAIN_RIDS: frozenset[str] = frozenset(["513", "515"])
_PRIVILEGED_SIDS: frozenset[str] = frozenset([
    "S-1-5-18", "S-1-5-9", "S-1-5-32-544",
])
_PRIVILEGED_DOMAIN_RIDS: frozenset[str] = frozenset(["512", "516", "518", "519", "520"])
_LOW_PRIV_NAME_MARKERS: tuple[str, ...] = (
    "everyone", "authenticated users", "domain users", "domain computers", "builtin\\users",
)
_PRIVILEGED_NAME_MARKERS: tuple[str, ...] = (
    "domain admins", "enterprise admins", "schema admins", "administrators",
    "system", "domain controllers", "enterprise domain controllers",
)


def _is_high_value_group(name: str) -> bool:
    n = name.upper()
    return any(h in n for h in _HVG)


def _base_ent(sid: str, etype: str, name: str, props: dict, **overrides) -> dict[str, Any]:
    name = str(name or "")
    props = _as_dict(props)
    e: dict[str, Any] = {
        "id": sid, "entity_type": etype, "object_sid": sid,
        "sam_account_name": props.get("samaccountname") or name.split("@")[0],
        "display_name": props.get("displayname") or name,
        "distinguished_name": props.get("distinguishedname", ""),
        "domain": props.get("domain", ""),
        "is_enabled": True, "is_admin_count": False,
        "is_sensitive": False, "is_protected_user": False,
        "is_crown_jewel": False, "tier": None,
        "attributes": props, "business_tags": [],
    }
    e.update(overrides)
    return e


def _ace_principal_sid(ace: dict) -> str:
    return str(ace.get("PrincipalSID") or ace.get("PrincipalObjectIdentifier") or "").strip()


def _is_low_privileged_template_principal(principal_sid: str, principal_name: str | None) -> bool:
    sid = str(principal_sid or "").strip().upper()
    name = str(principal_name or "").strip().lower()
    rid = sid.rsplit("-", 1)[-1] if "-" in sid else ""
    if sid in _PRIVILEGED_SIDS or rid in _PRIVILEGED_DOMAIN_RIDS:
        return False
    if any(marker in name for marker in _PRIVILEGED_NAME_MARKERS):
        return False
    if sid in _LOW_PRIV_SIDS or rid in _LOW_PRIV_DOMAIN_RIDS:
        return True
    return any(marker in name for marker in _LOW_PRIV_NAME_MARKERS)



def _has_low_priv_template_enrollment(enrollment_rights: list[Any] | None) -> bool:
    """Return True only when BloodHound enrollment data proves broad enrollment."""
    for right in enrollment_rights or []:
        if isinstance(right, dict):
            if bool(right.get("is_low_privileged", False)):
                return True
            sid = str(right.get("principal_sid") or right.get("sid") or right.get("PrincipalSID") or "").strip()
            name = str(right.get("principal_name") or right.get("name") or right.get("principal") or "").strip()
            if _is_low_privileged_template_principal(sid, name):
                return True
            continue
        if _is_low_privileged_template_principal("", str(right or "")):
            return True
    return False


def _typed_principal_sid(principal: dict | None) -> str:
    principal = _as_dict(principal)
    return str(principal.get("ObjectIdentifier") or principal.get("SID") or "").strip()


def _as_dict(value: Any) -> dict:
    return value if isinstance(value, dict) else {}


def _as_list(value: Any) -> list:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple | set):
        return list(value)
    return [value]


def _as_int(value: Any, default: int = 0) -> int:
    try:
        if isinstance(value, list | tuple | set):
            value = next(iter(value), default)
        return int(str(value), 0)
    except (TypeError, ValueError):
        return default


def _as_bool(value: Any, default: bool = False) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, int | float):
        return bool(value)
    text = str(value).strip().lower()
    if text in {"true", "yes", "y", "1", "enabled"}:
        return True
    if text in {"false", "no", "n", "0", "disabled", ""}:
        return False
    return default


def _timestamp_to_datetime(value: Any) -> datetime | None:
    """Return a naive UTC datetime for BloodHound FILETIME, epoch, or ISO strings."""
    if value in (None, "", 0, "0", "None", "null"):
        return None
    if isinstance(value, datetime):
        dt = value
        return dt.astimezone(timezone.utc).replace(tzinfo=None) if dt.tzinfo else dt

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
        # Windows FILETIME: 100ns intervals since 1601-01-01.
        if numeric >= 100_000_000_000_000:
            unix_seconds = (numeric - 116444736000000000) / 10_000_000
        # Unix epoch in milliseconds.
        elif numeric >= 1_000_000_000_000:
            unix_seconds = numeric / 1000
        else:
            unix_seconds = numeric
        if unix_seconds <= 0:
            return None
        return datetime.fromtimestamp(unix_seconds, tz=timezone.utc).replace(tzinfo=None)
    except (OverflowError, OSError, ValueError):
        return None


def _days_since(value: Any) -> int | None:
    dt = _timestamp_to_datetime(value)
    if not dt:
        return None
    delta = datetime.now(timezone.utc).replace(tzinfo=None) - dt
    return max(0, delta.days)


def _principal_name_key(value: object) -> str:
    text = str(value or "").strip().lower()
    if "\\" in text:
        text = text.rsplit("\\", 1)[-1]
    if "@" in text:
        text = text.split("@", 1)[0]
    return text


def _enrollment_right_parts(right: object) -> tuple[str, str]:
    if isinstance(right, dict):
        sid = str(right.get("principal_sid") or right.get("sid") or right.get("ObjectIdentifier") or "").strip()
        name = str(right.get("principal_name") or right.get("name") or right.get("principal") or "").strip()
        return sid, name
    return "", str(right or "").strip()


def _days_since_windows_filetime(value: Any) -> int:
    """Return whole days since an AD FILETIME timestamp, or 0 when unavailable."""
    try:
        filetime = int(value or 0)
    except (TypeError, ValueError):
        return 0
    if filetime <= 0:
        return 0
    try:
        unix_seconds = (filetime / 10_000_000) - 11_644_473_600
        last_seen = datetime.fromtimestamp(unix_seconds, tz=timezone.utc)
    except (OverflowError, OSError, ValueError):
        return 0
    age_days = (datetime.now(timezone.utc) - last_seen).days
    return max(0, int(age_days))


class BloodHoundParser:
    def __init__(self):
        self._entities: list[dict] = []
        self._edges: list[dict] = []
        self._evidence: list[dict] = []
        self._findings: list[dict] = []
        self._cert_templates: list[dict] = []
        self._domain_info: dict = {}
        self._password_policy: dict = {}
        self._trusts: list[dict] = []
        self._sid_map: dict[str, dict] = {}
        self._protected_user_member_sids: set[str] = set()
        self._dcsync_component_rights: dict[tuple[str, str], set[str]] = {}
        self._gpo_change_edge_keys: set[tuple[str, str, str]] = set()
        # monotonic counter keeps evidence IDs unique across multiple ZIP entries
        self._evidence_seq: int = 0

    def parse_zip(self, data: bytes) -> dict:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            for info in zf.infolist():
                if info.file_size > MAX_MEMBER_BYTES:
                    raise ValueError(
                        f"ZIP member '{info.filename}' declared decompressed size "
                        f"{info.file_size} exceeds {MAX_MEMBER_BYTES} byte limit"
                    )
            _validate_bloodhound_zip_members(zf.infolist())
            for name in zf.namelist():
                if not name.endswith(".json"):
                    continue
                log.info(f"Parsing BloodHound zip entry: {name}")
                try:
                    self._dispatch(json.loads(zf.read(name)), name)
                except Exception as exc:
                    log.warning(f"Failed to parse {name}: {exc}")
        return self._build_result()

    def parse_json(self, data: bytes) -> dict:
        raw = json.loads(data)
        if not isinstance(raw, dict):
            raise ValueError("BloodHound JSON root must be an object")
        self._dispatch(raw, "")
        return self._build_result()

    def _dispatch(self, raw: dict, filename: str):
        if not isinstance(raw, dict):
            log.debug("BloodHound payload root is not an object — skipping")
            return
        meta = _as_dict(raw.get("meta", {}))
        obj_type = str(meta.get("type", "") or "").lower()
        if not obj_type:
            fname = filename.lower()
            for key in _FILE_TYPES:
                if key in fname:
                    obj_type = key
                    break

        handler = {
            "users": self._parse_users, "groups": self._parse_groups,
            "computers": self._parse_computers, "domains": self._parse_domains,
            "gpos": self._parse_gpos, "ous": self._parse_ous,
            "containers": self._parse_ous, "certtemplates": self._parse_cert_templates,
            "enterprisecas": self._parse_enterprise_cas, "rootcas": self._parse_enterprise_cas,
        }.get(obj_type)

        data_list = raw.get("data", [])
        if not isinstance(data_list, list):
            log.debug("BloodHound type=%r has non-list data — skipping", obj_type)
            return
        if len(data_list) > MAX_OBJECTS_PER_TYPE:
            raise ValueError(
                f"BloodHound type={obj_type!r} has {len(data_list)} objects, "
                f"exceeding limit of {MAX_OBJECTS_PER_TYPE}"
            )
        if handler and data_list:
            handler(data_list)
            self._evidence.append({
                "id": f"bh-{obj_type}-{self._evidence_seq}",
                "source_type": "bloodhound",
                "collection_method": f"sharphound/{obj_type}",
                "origin": "IMPORTED",
                "raw_data": {"type": obj_type, "count": len(data_list), "version": meta.get("version")},
                "confidence": 1.0,
            })
            self._evidence_seq += 1
        else:
            log.debug(f"No handler for BloodHound type={obj_type!r} — skipping")

    def _props(self, obj: dict) -> dict:
        obj = _as_dict(obj)
        return _as_dict(obj.get("Properties", obj.get("props", {})))

    def _sid(self, obj: dict) -> str:
        obj = _as_dict(obj)
        return str(obj.get("ObjectIdentifier", obj.get("SID", "")) or "").strip()

    def _parse_users(self, items: list):
        for obj in items:
            obj = _as_dict(obj)
            props = self._props(obj)
            sid = self._sid(obj)
            if not sid:
                continue
            name = str(props.get("name", "") or "")
            sam = props.get("samaccountname") or name.split("@")[0]
            is_admin = _as_bool(props.get("admincount", False))
            spns = _as_list(props.get("serviceprincipalnames"))
            has_spn = _as_bool(props.get("hasspn", False)) or bool(spns)
            is_service_account = has_spn
            trusted_to_auth = _as_bool(
                props.get("trustedtoauth", False)
            ) or _as_bool(
                props.get("trustedtoauthfordelegation", False)
            )
            delegate_targets = [
                _typed_principal_sid(target)
                for target in _as_list(obj.get("AllowedToDelegate"))
                if _typed_principal_sid(target)
            ]
            sid_history = _as_list(props.get("sidhistory"))
            has_sid_history = bool(sid_history or obj.get("HasSIDHistory"))
            last_logon_value = props.get("lastlogontimestamp") or props.get("lastlogon")
            last_logon_dt = _timestamp_to_datetime(last_logon_value)
            password_last_set_dt = _timestamp_to_datetime(props.get("pwdlastset"))
            days_since_last_logon = _days_since(last_logon_value)

            attrs: dict[str, Any] = {
                "uac_dont_require_preauth": _as_bool(props.get("dontreqpreauth", False)),
                "uac_passwd_notreqd": _as_bool(props.get("passwordnotreqd", False)),
                "uac_trusted_for_delegation": _as_bool(props.get("unconstraineddelegation", False)),
                "uac_trusted_to_auth_for_delegation": trusted_to_auth,
                "constrained_delegation_any_protocol": trusted_to_auth,
                "allowed_to_delegate_to": delegate_targets,
                "has_spn": has_spn,
                "spns": spns,
                "object_sid": sid,
                "last_logon_timestamp": last_logon_value,
                "password_last_set": props.get("pwdlastset"),
                "pwd_never_expires": _as_bool(props.get("passwordneverexpires", False)) or _as_bool(props.get("pwdneverexpires", False)),
                "sid_history": [str(item) for item in sid_history],
                "has_sid_history": has_sid_history,
                "description": props.get("description"),
                "email": props.get("email"),
                "title": props.get("title"),
                "department": props.get("department"),
                "admincount": is_admin,
                "sensitive": _as_bool(props.get("sensitive", False)),
                # Password-expiry flags are unrelated to Protected Users membership.
                # Preserve explicit exporter hints when present, then enrich from
                # Protected Users group membership during _build_result().
                "protected_users": bool(
                    _as_bool(props.get("isprotecteduser", False))
                    or _as_bool(props.get("protecteduser", False))
                    or _as_bool(props.get("protected", False))
                ),
            }
            if days_since_last_logon is not None:
                attrs["days_since_last_logon"] = days_since_last_logon
            ent = _base_ent(
                sid,
                "SERVICE_ACCOUNT" if is_service_account else "USER",
                name,
                props,
                sam_account_name=sam,
                is_enabled=_as_bool(props.get("enabled", True), True),
                is_admin_count=is_admin,
                is_sensitive=attrs["sensitive"],
                is_protected_user=attrs["protected_users"],
                tier=0 if is_admin else None,
                attributes=attrs,
                last_logon=last_logon_dt.isoformat() if last_logon_dt else None,
                password_last_set=password_last_set_dt.isoformat() if password_last_set_dt else None,
            )
            self._entities.append(ent)
            self._sid_map[sid] = {"entity_type": ent["entity_type"], "sam": sam}
            for target in _as_list(obj.get("AllowedToDelegate")):
                target_sid = _typed_principal_sid(target)
                if target_sid and target_sid != sid:
                    target_dict = _as_dict(target)
                    self._edges.append({
                        "source_id": sid,
                        "target_id": target_sid,
                        "edge_type": "ALLOWED_TO_DELEGATE",
                        "risk_weight": 0.95,
                        "provenance": "BloodHound user AllowedToDelegate",
                        "attributes": {
                            "source_field": "AllowedToDelegate",
                            "target_type": target_dict.get("ObjectType"),
                        },
                    })
            for ace in _as_list(obj.get("Aces")):
                self._add_ace_edge(sid, ace)
        log.info(f"Parsed {len(items)} users")

    def _parse_groups(self, items: list):
        for obj in items:
            obj = _as_dict(obj)
            props = self._props(obj)
            sid = self._sid(obj)
            if not sid:
                continue
            name = str(props.get("name", "") or "")
            is_hvg = _is_high_value_group(name)
            is_admin = _as_bool(props.get("admincount", False))
            ent = _base_ent(sid, "GROUP", name, props,
                is_admin_count=is_admin,
                is_crown_jewel=is_hvg,
                tier=0 if is_hvg else None,
                attributes={"object_sid": sid, "domain": props.get("domain", "")})
            self._entities.append(ent)
            self._sid_map[sid] = {"entity_type": "GROUP", "sam": ent["sam_account_name"]}
            is_protected_users_group = "protected users" in name.lower()
            for member in _as_list(obj.get("Members")):
                member_dict = _as_dict(member)
                msid = member_dict.get("ObjectIdentifier", "")
                if msid:
                    if is_protected_users_group:
                        self._protected_user_member_sids.add(msid)
                    self._edges.append({"source_id": msid, "target_id": sid, "edge_type": "MEMBER_OF", "risk_weight": 0.4, "provenance": "BloodHound group membership"})
            for ace in _as_list(obj.get("Aces")):
                self._add_ace_edge(sid, ace)
        log.info(f"Parsed {len(items)} groups")

    def _parse_computers(self, items: list):
        for obj in items:
            obj = _as_dict(obj)
            props = self._props(obj)
            sid = self._sid(obj)
            if not sid:
                continue
            name = str(props.get("name", "") or "")
            is_dc = _as_bool(props.get("isdc", False))
            unconst = _as_bool(props.get("unconstraineddelegation", False))
            trusted_to_auth = _as_bool(props.get("trustedtoauth", False)) or _as_bool(props.get("trustedtoauthfordelegation", False))
            delegate_targets = [
                _typed_principal_sid(target)
                for target in _as_list(obj.get("AllowedToDelegate"))
                if _typed_principal_sid(target)
            ]
            rbcd_principals = [
                _typed_principal_sid(principal)
                for principal in _as_list(obj.get("AllowedToAct"))
                if _typed_principal_sid(principal)
            ]
            last_logon_value = props.get("lastlogontimestamp") or props.get("lastlogon")
            last_logon_dt = _timestamp_to_datetime(last_logon_value)
            attrs: dict[str, Any] = {
                "uac_trusted_for_delegation": unconst and not is_dc,
                "uac_trusted_to_auth_for_delegation": trusted_to_auth,
                "constrained_delegation_any_protocol": trusted_to_auth,
                "allowed_to_delegate_to": delegate_targets,
                "rbcd_configured": bool(rbcd_principals),
                "rbcd_principals": rbcd_principals,
                "uac_is_dc": is_dc,
                "object_sid": sid,
                "os": props.get("operatingsystem"),
                "os_version": props.get("operatingsystemversion"),
                "last_logon": last_logon_value,
                "enabled": props.get("enabled", True),
                "unconstraineddelegation": unconst,
                "description": props.get("description"),
            }
            if "haslaps" in props:
                laps_enabled = _as_bool(props.get("haslaps"))
                attrs["hasLAPS"] = laps_enabled
                attrs["has_laps"] = laps_enabled
                attrs["laps_installed"] = laps_enabled
            ent = _base_ent(
                sid,
                "DC" if is_dc else "COMPUTER",
                name,
                props,
                dns_hostname=props.get("dnshostname") or name,
                is_enabled=_as_bool(props.get("enabled", True), True),
                is_sensitive=is_dc,
                is_crown_jewel=is_dc,
                tier=0 if is_dc else (1 if unconst else None),
                attributes=attrs,
                business_tags=["Domain Controller"] if is_dc else [],
                last_logon=last_logon_dt.isoformat() if last_logon_dt else None,
            )
            self._entities.append(ent)
            self._sid_map[sid] = {"entity_type": ent["entity_type"], "sam": ent["sam_account_name"]}
            for ace in _as_list(obj.get("Aces")):
                self._add_ace_edge(sid, ace)
            for la in _as_list(_as_dict(obj.get("LocalAdmins", {})).get("Results")):
                la_sid = _as_dict(la).get("ObjectIdentifier")
                if la_sid:
                    self._edges.append({
                        "source_id": la_sid,
                        "target_id": sid,
                        "edge_type": "ADMIN_TO",
                        "risk_weight": 0.8,
                        "provenance": "BloodHound local admin",
                    })
            for target in _as_list(obj.get("AllowedToDelegate")):
                target_sid = _typed_principal_sid(target)
                if target_sid and target_sid != sid:
                    target_dict = _as_dict(target)
                    self._edges.append({
                        "source_id": sid,
                        "target_id": target_sid,
                        "edge_type": "ALLOWED_TO_DELEGATE",
                        "risk_weight": 0.95,
                        "provenance": "BloodHound computer AllowedToDelegate",
                        "attributes": {
                            "source_field": "AllowedToDelegate",
                            "target_type": target_dict.get("ObjectType"),
                        },
                    })
            for principal in _as_list(obj.get("AllowedToAct")):
                principal_sid = _typed_principal_sid(principal)
                if principal_sid and principal_sid != sid:
                    principal_dict = _as_dict(principal)
                    self._edges.append({
                        "source_id": principal_sid,
                        "target_id": sid,
                        "edge_type": "ALLOWED_TO_ACT",
                        "risk_weight": 0.95,
                        "provenance": "BloodHound computer AllowedToAct",
                        "attributes": {
                            "source_field": "AllowedToAct",
                            "principal_type": principal_dict.get("ObjectType"),
                        },
                    })
        log.info(f"Parsed {len(items)} computers")

    def _add_gpo_change_edges(self, gpo_changes: dict | None, scope_type: str) -> None:
        changes = _as_dict(gpo_changes)
        affected_computers = [
            _typed_principal_sid(computer)
            for computer in _as_list(changes.get("AffectedComputers"))
        ]
        affected_computers = [computer for computer in affected_computers if computer]
        if not affected_computers:
            return

        edge_specs = (
            ("LocalAdmins", "ADMIN_TO", 0.80, "BloodHound GPOLocalGroup local admin"),
            ("RemoteDesktopUsers", "CAN_RDP", 0.45, "BloodHound GPOLocalGroup RDP"),
            ("DcomUsers", "HAS_CONTROL", 0.70, "BloodHound GPOLocalGroup DCOM"),
            ("PSRemoteUsers", "CAN_WINRM", 0.50, "BloodHound GPOLocalGroup PSRemote"),
        )
        for source_field, edge_type, risk_weight, provenance in edge_specs:
            for principal in _as_list(changes.get(source_field)):
                principal_sid = _typed_principal_sid(principal)
                if not principal_sid:
                    continue
                principal_dict = _as_dict(principal)
                for computer_sid in affected_computers:
                    if principal_sid == computer_sid:
                        continue
                    key = (principal_sid, computer_sid, edge_type)
                    if key in self._gpo_change_edge_keys:
                        continue
                    self._gpo_change_edge_keys.add(key)
                    self._edges.append({
                        "source_id": principal_sid,
                        "target_id": computer_sid,
                        "edge_type": edge_type,
                        "risk_weight": risk_weight,
                        "provenance": provenance,
                        "attributes": {
                            "derived_from": "bloodhound/gpo_changes",
                            "source_field": source_field,
                            "scope_type": scope_type,
                            "principal_type": principal_dict.get("ObjectType"),
                        },
                    })

    def _parse_domains(self, items: list):
        for obj in items:
            obj = _as_dict(obj)
            props = self._props(obj)
            sid = self._sid(obj)
            name = str(props.get("name", "") or "")
            if not sid:
                continue
            attrs: dict[str, Any] = {
                "functional_level": props.get("functionallevel"),
                "domain_functional_level": props.get("functionallevel"),
                "domain_sid": sid,
            }
            if "machineaccountquota" in props:
                attrs["machine_account_quota"] = props.get("machineaccountquota")
            ent = _base_ent(
                sid,
                "DOMAIN",
                name,
                props,
                sam_account_name=name,
                domain=name,
                is_sensitive=True,
                is_crown_jewel=True,
                tier=0,
                attributes=attrs,
                business_tags=["Domain Root"],
            )
            self._entities.append(ent)
            self._sid_map[sid] = {"entity_type": "DOMAIN", "sam": name}
            self._domain_info.update({
                "domain": name,
                "domain_sid": sid,
                "functional_level": props.get("functionallevel"),
                "domain_functional_level": props.get("functionallevel"),
                "total_computers": 0,
                "total_users": 0,
            })
            if "machineaccountquota" in props:
                self._domain_info["machine_account_quota"] = props.get("machineaccountquota")
            for trust in _as_list(obj.get("Trusts")):
                trust = _as_dict(trust)
                trust_entry = {
                    "partner": trust.get("TargetDomainName", ""),
                    "trust_type": trust.get("TrustType", ""),
                    "transitive": _as_bool(trust.get("IsTransitive", False)),
                    "partner_sid": trust.get("TargetDomainSid", ""),
                }
                direction = trust.get("TrustDirection") or trust.get("Direction")
                if direction not in (None, ""):
                    trust_entry["trust_direction"] = direction
                if "SidFilteringEnabled" in trust:
                    trust_entry["sid_filtering_enabled"] = trust.get("SidFilteringEnabled")
                self._trusts.append(trust_entry)
            for link in _as_list(obj.get("Links")):
                link = _as_dict(link)
                gpo_id = link.get("GUID") or link.get("ObjectIdentifier", "")
                if gpo_id:
                    self._edges.append({
                        "source_id": gpo_id,
                        "target_id": sid,
                        "edge_type": "APPLIES_GPO",
                        "risk_weight": 0.3,
                        "provenance": "BloodHound domain GPO link",
                        "attributes": {"enforced": _as_bool(link.get("IsEnforced", False)), "scope_type": "DOMAIN"},
                    })
            for child in _as_list(obj.get("ChildObjects")):
                child = _as_dict(child)
                child_id = child.get("ObjectIdentifier", "")
                if child_id:
                    self._edges.append({
                        "source_id": sid,
                        "target_id": child_id,
                        "edge_type": "CONTAINS",
                        "risk_weight": 0.2,
                        "provenance": "BloodHound domain containment",
                        "attributes": {"child_type": child.get("ObjectType"), "scope_type": "DOMAIN"},
                    })
            self._add_gpo_change_edges(_as_dict(obj.get("GPOChanges")), "DOMAIN")
            self._password_policy.update(_as_dict(props.get("passwordpolicy", {})))
            for ace in _as_list(obj.get("Aces")):
                self._add_ace_edge(sid, ace)

    def _parse_gpos(self, items: list):
        for obj in items:
            obj = _as_dict(obj)
            props = self._props(obj)
            sid = self._sid(obj)
            name = str(props.get("name", "") or "")
            if not sid:
                continue
            ent = _base_ent(sid, "GPO", name, props,
                # Enforced is a link property, not a GPO enabled/disabled state.
                is_enabled=_as_bool(props.get("enabled", True), True), attributes=props)
            self._entities.append(ent)
            self._sid_map[sid] = {"entity_type": "GPO", "sam": name}
            for ace in _as_list(obj.get("Aces")):
                self._add_ace_edge(sid, ace)
            for link in _as_list(obj.get("Links")):
                link = _as_dict(link)
                target = link.get("GUID") or link.get("ObjectIdentifier", "")
                if target:
                    self._edges.append({
                        "source_id": sid, "target_id": target, "edge_type": "APPLIES_GPO",
                        "risk_weight": 0.3, "provenance": "BloodHound GPO link",
                        "attributes": {"enforced": _as_bool(link.get("IsEnforced", False)), "scope_type": "LEGACY_GPO_LINK"},
                    })

    def _parse_ous(self, items: list):
        for obj in items:
            obj = _as_dict(obj)
            props = self._props(obj)
            sid = self._sid(obj)
            name = str(props.get("name", "") or "")
            if not sid:
                continue
            self._entities.append(_base_ent(sid, "OU", name, props, attributes=props))
            self._sid_map[sid] = {"entity_type": "OU", "sam": name}
            for link in _as_list(obj.get("Links")):
                link = _as_dict(link)
                gpo_id = link.get("GUID") or link.get("ObjectIdentifier", "")
                if gpo_id:
                    self._edges.append({
                        "source_id": gpo_id, "target_id": sid, "edge_type": "APPLIES_GPO",
                        "risk_weight": 0.3, "provenance": "BloodHound OU GPO link",
                        "attributes": {"enforced": _as_bool(link.get("IsEnforced", False)), "scope_type": "OU"},
                    })
            for child in _as_list(obj.get("ChildObjects")):
                child = _as_dict(child)
                child_id = child.get("ObjectIdentifier", "")
                if child_id:
                    self._edges.append({
                        "source_id": sid, "target_id": child_id, "edge_type": "CONTAINS",
                        "risk_weight": 0.2, "provenance": "BloodHound OU containment",
                        "attributes": {"child_type": child.get("ObjectType"), "scope_type": "OU"},
                    })
            self._add_gpo_change_edges(_as_dict(obj.get("GPOChanges")), "OU")
            for ace in _as_list(obj.get("Aces")):
                self._add_ace_edge(sid, ace)

    def _parse_cert_templates(self, items: list):
        for obj in items:
            obj = _as_dict(obj)
            props = self._props(obj)
            sid = self._sid(obj)
            name = str(props.get("name", "") or "")
            if not sid:
                continue
            ekus = _as_list(props.get("ekus") or props.get("certificatetemplateekus"))
            client_auth = any(e in _CLIENT_AUTH_EKUS for e in ekus)
            no_approval = not _as_bool(props.get("requiresmanagerapproval", False))
            auth_sig_count = _as_int(props.get("authorizedsignaturesrequired", 0))
            no_sigs = auth_sig_count == 0
            published = bool(props.get("caname", ""))
            enrollment_rights = _as_list(props.get("enrollmentrights"))
            low_priv_enrollment = _has_low_priv_template_enrollment(enrollment_rights)
            has_publication_telemetry = "caname" in props
            has_enrollment_telemetry = "enrollmentrights" in props
            inferred_exposure_context = (
                published and low_priv_enrollment
                if has_publication_telemetry or has_enrollment_telemetry
                else True
            )
            esc1 = (
                published
                and low_priv_enrollment
                and _as_bool(props.get("enrolleesuppliessubject", False))
                and client_auth
                and no_approval
                and no_sigs
            )
            esc2 = (
                inferred_exposure_context
                and (not ekus or "2.5.29.37.0" in ekus)
                and no_approval
                and no_sigs
            )
            esc3 = (
                inferred_exposure_context
                and "1.3.6.1.4.1.311.20.2.1" in ekus
                and no_approval
                and no_sigs
            )
            template_write_rights: list[dict[str, Any]] = [
                right for right in _as_list(props.get("writerights")) if isinstance(right, dict)
            ]
            for ace in _as_list(obj.get("Aces")):
                ace = _as_dict(ace)
                right = ace.get("RightName") or ace.get("AceType", "")
                principal_sid = _ace_principal_sid(ace)
                if right in _ESC4_CONTROL_RIGHTS and principal_sid:
                    template_write_rights.append({
                        "principal_sid": principal_sid,
                        "principal_type": ace.get("PrincipalType"),
                        "right": right,
                        "is_inherited": _as_bool(ace.get("IsInherited", False)),
                    })
            template: dict[str, Any] = {
                "object_sid": sid,
                "name": name,
                "distinguished_name": props.get("distinguishedname", ""),
                "ca_name": props.get("caname", ""),
                "enrollee_supplies_subject": _as_bool(props.get("enrolleesuppliessubject", False)),
                "requires_manager_approval": _as_bool(props.get("requiresmanagerapproval", False)),
                "authorized_signatures_required": auth_sig_count,
                "validity_period": props.get("validityperiod"),
                "renewal_period": props.get("renewalperiod"),
                "ekus": ekus,
                "enrollment_rights": enrollment_rights,
                "write_rights": template_write_rights,
                "esc1_vulnerable": esc1,
                "esc2_vulnerable": esc2,
                "esc3_vulnerable": esc3,
                "esc4_vulnerable": False,
                "attributes": props,
            }
            self._cert_templates.append(template)
            tags = (["ESC1"] if esc1 else []) + (["ESC2"] if esc2 else []) + (["ESC3"] if esc3 else [])
            ent = _base_ent(
                sid,
                "CERT_TEMPLATE",
                name,
                props,
                is_enabled=published,
                is_sensitive=esc1 or esc2 or esc3,
                is_crown_jewel=esc1,
                attributes=props,
                business_tags=tags,
            )
            self._entities.append(ent)
            self._sid_map[sid] = {"entity_type": "CERT_TEMPLATE", "sam": name}
            for ace in _as_list(obj.get("Aces")):
                self._add_ace_edge(sid, ace)

    def _parse_enterprise_cas(self, items: list):
        for obj in items:
            obj = _as_dict(obj)
            props = self._props(obj)
            sid = self._sid(obj)
            name = str(props.get("name", "") or "")
            if not sid:
                continue
            ent = _base_ent(sid, "CA", name, props,
                is_sensitive=True, is_crown_jewel=True, tier=0,
                attributes=props, business_tags=["Certificate Authority"])
            self._entities.append(ent)
            self._sid_map[sid] = {"entity_type": "CA", "sam": name}
            for ace in _as_list(obj.get("Aces")):
                self._add_ace_edge(sid, ace)

    def _add_ace_edge(self, target_sid: str, ace: dict):
        ace = _as_dict(ace)
        principal_sid = ace.get("PrincipalSID") or ace.get("PrincipalObjectIdentifier", "")
        right = ace.get("RightName") or ace.get("AceType", "")
        if right in _DCSYNC_COMPONENT_RIGHTS:
            target_meta = self._sid_map.get(target_sid, {})
            if target_meta.get("entity_type") == "DOMAIN" and principal_sid and principal_sid != target_sid:
                self._dcsync_component_rights.setdefault((principal_sid, target_sid), set()).add(right)
            return
        edge_type = _ACE_TO_EDGE.get(right)
        if not edge_type or not principal_sid or principal_sid == target_sid:
            if principal_sid and not edge_type and right:
                log.debug("[BH] Unmapped ACE right %r on target %s — no edge created", right, target_sid)
            elif not principal_sid and edge_type:
                log.debug("[BH] ACE right %r on target %s missing principal SID — edge dropped", right, target_sid)
            return
        is_inherited = _as_bool(ace.get("IsInherited", False))
        risk = 1.0 if edge_type in _HIGH_RISK_EDGES else (0.5 if is_inherited else 0.85)
        self._edges.append({
            "source_id": principal_sid, "target_id": target_sid,
            "edge_type": edge_type, "risk_weight": risk,
            "provenance": f"ACE: {right} ({'inherited' if is_inherited else 'direct'})",
            "attributes": {"ace_right": right, "is_inherited": is_inherited},
        })

    def _build_result(self) -> dict:
        for (principal_sid, target_sid), rights in self._dcsync_component_rights.items():
            if not _DCSYNC_COMPONENT_RIGHTS.issubset(rights):
                continue
            self._edges.append({
                "source_id": principal_sid,
                "target_id": target_sid,
                "edge_type": "DCSYNC",
                "risk_weight": 1.0,
                "provenance": "BloodHound combined GetChanges + GetChangesAll",
                "attributes": {
                    "ace_rights": sorted(rights),
                    "derived_from": "bloodhound/replication_rights",
                },
            })

        # Enrollment-right strings from BloodHound (e.g. CORP\Domain Users)
        # are resolved to imported principals when possible so graph ADCS pages
        # can show CAN_ENROLL edges instead of an empty enrollee list.
        principal_name_index: dict[str, str] = {}
        for entity in self._entities:
            entity_id = str(entity.get("id") or "").strip()
            if not entity_id:
                continue
            for candidate in (
                entity.get("sam_account_name"),
                entity.get("display_name"),
                entity.get("object_sid"),
            ):
                key = _principal_name_key(candidate)
                if key:
                    principal_name_index.setdefault(key, entity_id)
        for template in self._cert_templates:
            template_id = str(template.get("object_sid") or "").strip()
            if not template_id:
                continue
            for right in template.get("enrollment_rights", []) or []:
                principal_sid, principal_name = _enrollment_right_parts(right)
                source_id = principal_sid or principal_name_index.get(_principal_name_key(principal_name), "")
                if source_id and source_id != template_id:
                    self._edges.append({
                        "source_id": source_id,
                        "target_id": template_id,
                        "edge_type": "CAN_ENROLL",
                        "risk_weight": 0.55,
                        "provenance": "BloodHound certificate template enrollment right",
                        "attributes": {
                            "principal_name": principal_name or None,
                            "principal_sid": principal_sid or None,
                            "derived_from": "bloodhound/enrollmentrights",
                        },
                    })

        for template in self._cert_templates:
            esc4 = bool(template.get("esc4_vulnerable", False))
            for right in _as_list(template.get("write_rights")):
                if not isinstance(right, dict):
                    continue
                principal_sid = str(right.get("principal_sid") or right.get("sid") or "").strip()
                principal_meta = self._sid_map.get(principal_sid, {})
                principal_name = right.get("principal_name") or principal_meta.get("sam") or right.get("name")
                right["principal_sid"] = principal_sid
                if principal_name:
                    right["principal_name"] = principal_name
                if right.get("principal_type") is None and principal_meta.get("entity_type"):
                    right["principal_type"] = principal_meta.get("entity_type")
                is_low_priv = _as_bool(right.get("is_low_privileged", False)) or _is_low_privileged_template_principal(principal_sid, principal_name)
                right["is_low_privileged"] = is_low_priv
                esc4 = esc4 or is_low_priv
            template["esc4_vulnerable"] = esc4
            if esc4:
                template_sid = template.get("object_sid")
                for entity in self._entities:
                    if entity.get("id") != template_sid:
                        continue
                    entity["is_sensitive"] = True
                    tags = list(entity.get("business_tags") or [])
                    if "ESC4" not in tags:
                        tags.append("ESC4")
                    entity["business_tags"] = tags
                    break

        if self._protected_user_member_sids:
            for entity in self._entities:
                if entity.get("id") not in self._protected_user_member_sids:
                    continue
                entity["is_protected_user"] = True
                attrs = entity.setdefault("attributes", {})
                attrs["protected_users"] = True
                attrs["protected_users_source"] = "bloodhound/group_membership"

        user_count = sum(1 for e in self._entities if e["entity_type"] in ("USER", "SERVICE_ACCOUNT"))
        comp_entities = [e for e in self._entities if e["entity_type"] in ("COMPUTER", "DC")]
        comp_count = len(comp_entities)
        dc_count = sum(1 for e in self._entities if e["entity_type"] == "DC")
        laps_known = [
            e for e in comp_entities
            if "laps_installed" in (e.get("attributes") or {})
        ]
        self._domain_info.update({
            "total_users": user_count,
            "total_computers": comp_count,
            "total_dcs": dc_count,
            "total_entities": len(self._entities),
        })
        if laps_known:
            laps_count = sum(1 for e in laps_known if (e.get("attributes") or {}).get("laps_installed"))
            self._domain_info["laps_deployed"] = laps_count > 0
            self._domain_info["laps_coverage_pct"] = int((laps_count / len(laps_known)) * 100)
        else:
            self._domain_info.pop("laps_deployed", None)
            self._domain_info.pop("laps_coverage_pct", None)

        seen: set[tuple] = set()
        deduped = []
        for edge in self._edges:
            if not isinstance(edge, dict):
                continue
            key = (edge.get("source_id"), edge.get("target_id"), edge.get("edge_type"))
            if not all(key):
                continue
            if key in seen:
                continue
            seen.add(key)
            deduped.append(edge)
        self._domain_info["total_edges"] = len(deduped)
        modules_run = list({e.get("collection_method", "").split("/")[0] for e in self._evidence})
        return {
            "schema_version": "4.0",
            "tool": "BloodHound",
            "collection_mode": "IMPORT",
            "domain": self._domain_info.get("domain", "unknown"),
            "dc_ip": None,
            "collected_at": "imported",
            "collector_version": "sharphound/unknown",
            "modules_run": modules_run or ["Domain Enumeration"],
            "entities": self._entities,
            "edges": deduped,
            "evidence": self._evidence,
            "findings": self._findings,
            "cert_templates": self._cert_templates,
            "metadata": {
                "domain_info": self._domain_info,
                "password_policy": self._password_policy,
                "trusts": self._trusts,
                "imported_from": "bloodhound",
            },
        }
