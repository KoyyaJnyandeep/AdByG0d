from __future__ import annotations

import asyncio
import logging
import random
import time
from datetime import datetime, timezone
from typing import Any

from ldap3 import BASE, Connection, NTLM, SAFE_SYNC, Server, SUBTREE, ANONYMOUS, SIMPLE
from ldap3.protocol.microsoft import security_descriptor_control

from adbygod_api.core.crypto_compat import ensure_hashlib_md4
from adbygod_api.core.collection.adcs import build_adcs_result
from adbygod_api.core.connectivity.transport import ProxyTransport

log = logging.getLogger(__name__)
ensure_hashlib_md4()

# ── LDAP constants ────────────────────────────────────────────────
UAC_ACCOUNTDISABLE = 0x0002
UAC_PASSWD_NOTREQD = 0x0020
UAC_SERVER_TRUST = 0x2000
UAC_DONT_EXPIRE_PASSWD = 0x10000
UAC_SMARTCARD_REQUIRED = 0x40000
UAC_TRUSTED_FOR_DELEGATION = 0x80000
UAC_NOT_DELEGATED = 0x100000
UAC_DONT_REQ_PREAUTH = 0x400000
UAC_TRUSTED_TO_AUTH_FOR_DELEGATION = 0x1000000

USER_ATTRS = [
    "sAMAccountName", "userPrincipalName", "distinguishedName",
    "objectSid", "userAccountControl", "adminCount",
    "servicePrincipalName", "memberOf", "lastLogonTimestamp",
    "pwdLastSet", "badPwdCount", "badPasswordTime",
    "description", "displayName", "mail", "title", "department",
    "whenCreated", "whenChanged", "msDS-GroupMSAMembership",
    "msDS-AllowedToDelegateTo", "msDS-AllowedToActOnBehalfOfOtherIdentity",
    "msDS-KeyCredentialLink", "sIDHistory", "msDS-SupportedEncryptionTypes",
]

COMPUTER_ATTRS = [
    "sAMAccountName", "dNSHostName", "distinguishedName",
    "objectSid", "userAccountControl", "adminCount",
    "operatingSystem", "operatingSystemVersion",
    "lastLogonTimestamp", "whenCreated", "memberOf",
    "msDS-AllowedToDelegateTo",
    "msDS-AllowedToActOnBehalfOfOtherIdentity",
    "ms-Mcs-AdmPwdExpirationTime",
    "msLAPS-PasswordExpirationTime",
    "description",
]

GROUP_ATTRS = [
    "sAMAccountName", "distinguishedName", "objectSid",
    "member", "adminCount", "description", "whenCreated",
    "groupType", "managedBy",
]

DOMAIN_ATTRS = [
    "dc", "distinguishedName", "objectSid",
    "minPwdLength", "lockoutThreshold", "lockoutDuration",
    "maxPwdAge", "minPwdAge", "pwdHistoryLength",
    "lockoutObservationWindow", "ms-DS-MachineAccountQuota",
    "msDS-Behavior-Version", "ntPwdHistory", "pwdProperties",
]

TRUST_ATTRS = [
    "name", "distinguishedName", "trustPartner",
    "trustDirection", "trustType", "trustAttributes",
    "flatName", "securityIdentifier",
]

GPO_ATTRS = [
    "displayName", "distinguishedName", "name", "cn",
    "gPCFileSysPath", "gPCMachineExtensionNames",
    "gPCUserExtensionNames", "whenCreated", "whenChanged",
]

OU_ATTRS = [
    "distinguishedName", "objectSid", "gPLink", "gPOptions", "name",
]

_GPO_LINK_RE = __import__("re").compile(r"\[LDAP://([^;]+);(\d+)\]", __import__("re").IGNORECASE)


class LDAPCollector:
    def __init__(
        self,
        dc_ip: str,
        domain: str,
        username: str = "",
        password: str = "",
        auth_method: str = "NTLM",
        use_ssl: bool = False,
        port: int = 0,
        enum_adcs: bool = True,
        enum_trusts: bool = True,
        enum_gpos: bool = True,
        enum_acls: bool = True,
        enum_gpo_acls: bool = True,
        scan_sysvol: bool = False,
        check_adcs_web: bool = True,
        check_esc6: bool = True,
        acl_include_inherited: bool = True,
        acl_max_objects: int = 5_000,
        pipeline_plan: "Any | None" = None,  # CommandPlan — injected by collection route
        proxy_transport: "ProxyTransport | None" = None,
    ):
        self.dc_ip = dc_ip.strip() if dc_ip else ""
        self.domain = domain.strip() if domain else ""
        self.username = username.strip() if username else ""
        self.password = password if password else None
        self.auth_method = auth_method.upper()
        self.use_ssl = use_ssl
        self.port = port or (636 if use_ssl else 389)
        self.enum_adcs = enum_adcs
        self.enum_trusts = enum_trusts
        self.enum_gpos = enum_gpos
        self.enum_acls = enum_acls
        self.enum_gpo_acls = enum_gpo_acls
        self.scan_sysvol = scan_sysvol
        self.check_adcs_web = check_adcs_web
        self.check_esc6 = check_esc6
        self.acl_include_inherited = acl_include_inherited
        self.acl_max_objects = acl_max_objects
        self._conn: Connection | None = None
        self._base_dn: str = ""
        self._progress_cb: Any = None
        # Pipeline integration — None means legacy direct-execution mode
        self._plan = pipeline_plan
        self._proxy: ProxyTransport | None = proxy_transport

    def set_progress_callback(self, cb):
        self._progress_cb = cb

    def _emit(self, message: str, pct: int, level: str = "INFO"):
        if self._progress_cb:
            self._progress_cb(message, pct, level)
        log.info("[LDAP:%s] %s", self.domain, message)

    # ── pipeline helpers ──────────────────────────────────────────────

    @property
    def _opsec_shuffle(self) -> bool:
        return bool(self._plan and getattr(self._plan, "opsec_shuffle_attrs", False))

    @property
    def _opsec_jitter_ms(self) -> int:
        return int(self._plan.opsec_jitter_ms) if self._plan else 0

    @property
    def _obfuscation_enabled(self) -> bool:
        return bool(self._plan and getattr(self._plan, "obfuscation_enabled", False))

    def _shuffle_attrs(self, attrs: list) -> list:
        """Randomise attribute order for OPSEC if plan requests it."""
        if not self._opsec_shuffle:
            return attrs
        shuffled = list(attrs)
        random.shuffle(shuffled)
        return shuffled

    def _maybe_jitter(self) -> None:
        """Apply per-query jitter for remote LDAP obfuscation/OPSEC."""
        jitter_ms = self._opsec_jitter_ms
        if jitter_ms <= 0:
            return
        time.sleep(random.randint(0, jitter_ms) / 1000.0)

    def _obfuscate_filter(self, search_filter: str) -> str:
        """
        Preserve LDAP semantics while changing wire-visible query shape.

        ldap3 direct queries cannot be PowerShell-obfuscated. Remote OBFSC for
        this collector pads each filter with a universal objectClass clause and
        combines it through AND. AD objects always carry objectClass, so results
        stay equivalent while filter bytes differ from raw catalog filters.
        """
        if not self._obfuscation_enabled:
            return search_filter
        filt = search_filter.strip()
        if not filt.startswith("("):
            return search_filter
        return f"(&{filt}(objectClass=*))"

    def _obfuscation_metadata(self) -> dict[str, Any]:
        return {
            "enabled": self._obfuscation_enabled,
            "scope": "remote_ldap",
            "technique": getattr(self._plan, "obfuscation_technique", "auto") if self._plan else "auto",
            "query_filter_padding": self._obfuscation_enabled,
            "attribute_shuffle": self._opsec_shuffle,
            "jitter_ms": self._opsec_jitter_ms,
            "note": "ldap3 direct LDAP has no PowerShell surface; OBFSC mutates LDAP query shape and timing.",
        }

    def _connect(self):
        self._emit(f"Connecting to {self.dc_ip}:{self.port} (auth={self.auth_method})…", 2)
        import contextlib
        _ctx = self._proxy.patched_socket() if self._proxy else contextlib.nullcontext()
        with _ctx:
            import socket as _sock
            try:
                with _sock.create_connection((self.dc_ip, self.port), timeout=5):
                    pass
            except Exception as exc:
                raise ConnectionError(
                    f"DC Unreachable: Could not connect to {self.dc_ip}:{self.port} ({exc})"
                ) from exc

            server = Server(self.dc_ip, port=self.port, use_ssl=self.use_ssl, get_info="ALL", connect_timeout=5)

            user_in = self.username or ""
            if self.auth_method == "NTLM":
                if "\\" in user_in:
                    creds_user = user_in
                elif "@" in user_in:
                    u_part, d_part = user_in.split("@", 1)
                    creds_user = f"{d_part}\\{u_part}"
                else:
                    creds_user = f"{self.domain}\\{user_in}" if user_in else None
            else:
                if "\\" in user_in:
                    d_part, u_part = user_in.split("\\", 1)
                    creds_user = f"{u_part}@{d_part}"
                elif "@" not in user_in and user_in != "":
                    creds_user = f"{user_in}@{self.domain}"
                else:
                    creds_user = user_in or None

            auth_map = {
                "NTLM": NTLM,
                "SIMPLE": SIMPLE,
                "ANONYMOUS": ANONYMOUS,
            }
            self._conn = Connection(
                server,
                user=creds_user,
                password=self.password or None,
                authentication=auth_map.get(self.auth_method, NTLM),
                client_strategy=SAFE_SYNC,
                auto_bind=True,
                read_only=True,
                receive_timeout=15,
            )
        try:
            self._base_dn = server.info.other.get("defaultNamingContext", [""])[0]
            if not self._base_dn:
                 log.debug("defaultNamingContext is empty, trying rootDomainNamingContext")
                 self._base_dn = server.info.other.get("rootDomainNamingContext", [""])[0]

            if not self._base_dn:
                 raise ValueError("No naming context found in RootDSE")
        except Exception:
            log.debug("Failed to read naming context from RootDSE, falling back to domain parts", exc_info=True)
            self._base_dn = ",".join(f"DC={part}" for part in self.domain.split("."))
        self._emit(f"Connected — base DN: {self._base_dn}", 5)

    def _disconnect(self):
        if self._conn:
            try:
                self._conn.unbind()
            except Exception:
                pass

    def _search(self, search_filter: str, attributes: list[str], search_base: str | None = None) -> list[dict]:
        base = search_base or self._base_dn
        # OPSEC: shuffle attribute order so LDAP traffic pattern varies per query
        active_attrs = self._shuffle_attrs(list(attributes))
        active_filter = self._obfuscate_filter(search_filter)
        self._maybe_jitter()
        while True:
            response_entries: list[Any] = []
            try:
                cookie = None
                while True:
                    search_result = self._conn.search(
                        search_base=base,
                        search_filter=active_filter,
                        search_scope=SUBTREE,
                        attributes=active_attrs,
                        paged_size=500,
                        paged_cookie=cookie,
                    )
                    if search_result is False:
                        error = self._conn.last_error or "Unknown LDAP error"
                        if "invalid attribute" in error.lower() or "unsupported attribute" in error.lower():
                             raise Exception(error)

                        # Check for specific AD errors like 'Size Limit Exceeded' or 'Operations Error'
                        if "size limit exceeded" in error.lower():
                            log.warning("LDAP size limit exceeded for query: %s", active_filter)
                            # We don't raise here, we just return what we have
                            break

                        raise Exception(f"LDAP Search failed: {error}")
                    if isinstance(search_result, tuple):
                        _ok, result, response, _request = search_result
                        response_entries.extend(
                            item for item in response if item.get("type") == "searchResEntry"
                        )
                        cookie = (
                            result.get("controls", {})
                            .get("1.2.840.113556.1.4.319", {})
                            .get("value", {})
                            .get("cookie")
                        )
                    else:
                        response_entries = list(self._conn.entries)
                        cookie = None
                    if not cookie:
                        break
                break
            except Exception as exc:
                message = str(exc).lower()
                if "invalid attribute type" not in message and "unsupported attribute" not in message:
                    raise
                invalid_attrs = [attr for attr in active_attrs if attr.lower() in message]
                if not invalid_attrs:
                    raise
                active_attrs = [attr for attr in active_attrs if attr not in invalid_attrs]
                self._emit(
                    f"Skipping unsupported LDAP attribute(s): {', '.join(invalid_attrs)}",
                    0,
                    "WARN",
                )
        results: list[dict] = []
        for entry in response_entries:
            obj: dict[str, Any] = {}
            if isinstance(entry, dict):
                entry_attrs = entry.get("attributes", {})
                for attr in active_attrs:
                    if attr not in entry_attrs:
                        continue
                    raw = entry_attrs[attr]
                    if isinstance(raw, list):
                        obj[attr] = [str(v) for v in raw]
                    elif raw is not None:
                        obj[attr] = raw
                results.append(obj)
                continue
            for attr in active_attrs:
                val = getattr(entry, attr, None)
                if val is None:
                    continue
                raw = val.value
                if isinstance(raw, list):
                    obj[attr] = [str(v) for v in raw]
                elif raw is not None:
                    obj[attr] = raw
            results.append(obj)
        return results

    def _search_with_sd(self, search_filter: str, attributes: list[str], search_base: str, search_scope=SUBTREE) -> list[dict]:
        """LDAP search that also returns raw nTSecurityDescriptor bytes for AD CS ACL checks."""
        controls = security_descriptor_control(sdflags=0x04)
        active_attrs = self._shuffle_attrs(list(dict.fromkeys([*attributes, "nTSecurityDescriptor"])))
        active_filter = self._obfuscate_filter(search_filter)
        self._maybe_jitter()
        rows: list[dict[str, Any]] = []
        cookie = None
        while True:
            result = self._conn.search(
                search_base=search_base,
                search_filter=active_filter,
                search_scope=search_scope,
                attributes=active_attrs,
                controls=controls,
                paged_size=200,
                paged_cookie=cookie,
            )
            if result is False:
                raise Exception(f"LDAP Search failed: {self._conn.last_error or 'Unknown LDAP error'}")

            if isinstance(result, tuple):
                _ok, ldap_result, response, _request = result
                entries = [item for item in response if item.get("type") == "searchResEntry"]
                for entry in entries:
                    attrs = entry.get("attributes", {})
                    raw_attrs = entry.get("raw_attributes", {})
                    row: dict[str, Any] = {"distinguishedName": entry.get("dn", attrs.get("distinguishedName", ""))}
                    for attr in active_attrs:
                        if attr == "nTSecurityDescriptor":
                            raw_values = raw_attrs.get(attr, [])
                            row[attr] = raw_values[0] if raw_values else attrs.get(attr)
                            continue
                        if attr in attrs:
                            value = attrs[attr]
                            row[attr] = [str(v) for v in value] if isinstance(value, list) else value
                    rows.append(row)
                cookie = (
                    ldap_result.get("controls", {})
                    .get("1.2.840.113556.1.4.319", {})
                    .get("value", {})
                    .get("cookie")
                )
            else:
                for entry in self._conn.entries:
                    row = {}
                    for attr in active_attrs:
                        val = getattr(entry, attr, None)
                        if val is None:
                            continue
                        if attr == "nTSecurityDescriptor":
                            raw_values = val.raw_values
                            row[attr] = raw_values[0] if raw_values else None
                        else:
                            raw = val.value
                            row[attr] = [str(v) for v in raw] if isinstance(raw, list) else raw
                    rows.append(row)
                cookie = None
            if not cookie:
                break
        return rows

    def _enum_users(self) -> list[dict]:
        self._emit("Enumerating user accounts…", 10)
        raw = self._search("(&(objectCategory=person)(objectClass=user))", USER_ATTRS)

        # Collect Protected Users group members for cross-reference
        protected_users_dns: set[str] = set()
        try:
            pu_raw = self._search(
                "(&(objectClass=group)(sAMAccountName=Protected Users))",
                ["member"],
            )
            if pu_raw:
                members = pu_raw[0].get("member", [])
                if isinstance(members, str):
                    members = [members]
                protected_users_dns = {str(m).lower() for m in members}
        except Exception:
            log.debug("Failed to parse Protected Users group", exc_info=True)
            pass

        now = datetime.now(timezone.utc)
        entities = []
        for r in raw:
            uac = int(r.get("userAccountControl") or 0)
            spns = r.get("servicePrincipalName", [])
            if isinstance(spns, str):
                spns = [spns]
            sam = str(r.get("sAMAccountName", ""))
            sid = str(r.get("objectSid", ""))
            dn = str(r.get("distinguishedName", ""))
            enabled = not bool(uac & UAC_ACCOUNTDISABLE)
            is_trusted_to_auth = bool(uac & UAC_TRUSTED_TO_AUTH_FOR_DELEGATION)

            # Calculate days since last logon
            days_since_last_logon = 0
            raw_logon = r.get("lastLogonTimestamp")
            if raw_logon and str(raw_logon) not in ("", "0", "None"):
                try:
                    if isinstance(raw_logon, datetime):
                        logon_dt = raw_logon.replace(tzinfo=timezone.utc) if raw_logon.tzinfo is None else raw_logon
                        days_since_last_logon = (now - logon_dt).days
                except Exception:
                    log.debug("Failed to parse lastLogonTimestamp", exc_info=True)
                    pass

            key_cred = r.get("msDS-KeyCredentialLink", [])
            if isinstance(key_cred, str):
                key_cred = [key_cred]
            sid_history = r.get("sIDHistory", [])
            if isinstance(sid_history, str):
                sid_history = [sid_history]
            enc_types = int(r.get("msDS-SupportedEncryptionTypes") or 0)

            attrs: dict[str, Any] = {
                "uac_value": uac,
                "uac_dont_require_preauth": bool(uac & UAC_DONT_REQ_PREAUTH),
                "uac_passwd_notreqd": bool(uac & UAC_PASSWD_NOTREQD),
                "uac_trusted_for_delegation": bool(uac & UAC_TRUSTED_FOR_DELEGATION),
                "uac_trusted_to_auth_for_delegation": is_trusted_to_auth,
                "uac_dont_expire_passwd": bool(uac & UAC_DONT_EXPIRE_PASSWD),
                "uac_smartcard_required": bool(uac & UAC_SMARTCARD_REQUIRED),
                "uac_is_dc": False,
                # Aliases expected by rule engine
                "pwd_never_expires": bool(uac & UAC_DONT_EXPIRE_PASSWD),
                "constrained_delegation_any_protocol": is_trusted_to_auth,
                "has_spn": len(spns) > 0,
                "spns": spns,
                "object_sid": sid,
                "allowed_to_delegate_to": r.get("msDS-AllowedToDelegateTo", []),
                "rbcd_configured": bool(r.get("msDS-AllowedToActOnBehalfOfOtherIdentity")),
                "member_of": r.get("memberOf", []),
                "last_logon": str(raw_logon or ""),
                "days_since_last_logon": days_since_last_logon,
                "password_last_set": str(r.get("pwdLastSet", "")),
                "bad_pwd_count": int(r.get("badPwdCount") or 0),
                "description": str(r.get("description", "")),
                "shadow_credentials": len(key_cred) > 0,
                "sid_history": [str(s) for s in sid_history],
                "has_sid_history": len(sid_history) > 0,
                "supported_encryption_types": enc_types,
                "rc4_only": enc_types != 0 and not bool(enc_types & 0x18),  # AES128=0x8, AES256=0x10
            }
            is_admin = bool(r.get("adminCount"))
            is_protected = dn.lower() in protected_users_dns
            entities.append({
                "id": sid or sam,
                "entity_type": "SERVICE_ACCOUNT" if spns else "USER",
                "object_sid": sid,
                "sam_account_name": sam,
                "display_name": str(r.get("displayName") or sam),
                "distinguished_name": dn,
                "domain": self.domain,
                "is_enabled": enabled,
                "is_admin_count": is_admin,
                "is_sensitive": bool(uac & UAC_NOT_DELEGATED),
                "is_protected_user": is_protected,
                "is_crown_jewel": False,
                "tier": 0 if is_admin else None,
                "attributes": attrs,
                "business_tags": [],
            })
        self._emit(f"Enumerated {len(entities)} users", 22)
        return entities

    def _enum_computers(self) -> list[dict]:
        self._emit("Enumerating computer accounts…", 25)
        raw = self._search("(objectClass=computer)", COMPUTER_ATTRS)
        entities = []
        for r in raw:
            uac = int(r.get("userAccountControl") or 0)
            sam = str(r.get("sAMAccountName", ""))
            sid = str(r.get("objectSid", ""))
            is_dc = bool(uac & UAC_SERVER_TRUST)
            enabled = not bool(uac & UAC_ACCOUNTDISABLE)
            has_laps = bool(r.get("ms-Mcs-AdmPwdExpirationTime") or r.get("msLAPS-PasswordExpirationTime"))
            is_trusted_to_auth = bool(uac & UAC_TRUSTED_TO_AUTH_FOR_DELEGATION)
            rbcd_configured = bool(r.get("msDS-AllowedToActOnBehalfOfOtherIdentity"))
            attrs: dict[str, Any] = {
                "uac_value": uac,
                "uac_trusted_for_delegation": bool(uac & UAC_TRUSTED_FOR_DELEGATION) and not is_dc,
                "uac_trusted_to_auth_for_delegation": is_trusted_to_auth,
                "uac_is_dc": is_dc,
                "has_laps": has_laps,
                "laps_installed": has_laps,
                "constrained_delegation_any_protocol": is_trusted_to_auth,
                "rbcd_configured": rbcd_configured,
                "os": str(r.get("operatingSystem", "")),
                "os_version": str(r.get("operatingSystemVersion", "")),
                "allowed_to_delegate_to": r.get("msDS-AllowedToDelegateTo", []),
                "object_sid": sid,
                "description": str(r.get("description", "")),
            }
            entities.append({
                "id": sid or sam,
                "entity_type": "DC" if is_dc else "COMPUTER",
                "object_sid": sid,
                "sam_account_name": sam,
                "dns_hostname": str(r.get("dNSHostName") or sam),
                "display_name": sam,
                "distinguished_name": str(r.get("distinguishedName", "")),
                "domain": self.domain,
                "is_enabled": enabled,
                "is_admin_count": False,
                "is_sensitive": is_dc,
                "is_protected_user": False,
                "is_crown_jewel": is_dc,
                "tier": 0 if is_dc else (1 if attrs["uac_trusted_for_delegation"] else None),
                "attributes": attrs,
                "business_tags": ["Domain Controller"] if is_dc else [],
            })
        self._emit(f"Enumerated {len(entities)} computers", 38)
        return entities

    def _enum_groups(self) -> tuple[list[dict], list[dict]]:
        self._emit("Enumerating groups…", 40)
        raw = self._search("(objectClass=group)", GROUP_ATTRS)
        entities = []
        edges = []
        for r in raw:
            sam = str(r.get("sAMAccountName", ""))
            sid = str(r.get("objectSid", ""))
            members = r.get("member", [])
            if isinstance(members, str):
                members = [members]
            is_admin = bool(r.get("adminCount"))
            entities.append({
                "id": sid or sam,
                "entity_type": "GROUP",
                "object_sid": sid,
                "sam_account_name": sam,
                "display_name": sam,
                "distinguished_name": str(r.get("distinguishedName", "")),
                "domain": self.domain,
                "is_enabled": True,
                "is_admin_count": is_admin,
                "is_sensitive": False,
                "is_protected_user": False,
                "is_crown_jewel": _is_high_value_group(sam),
                "tier": 0 if _is_high_value_group(sam) else None,
                "attributes": {"object_sid": sid},
                "business_tags": [],
            })
            for member_dn in members:
                edges.append({
                    "source_id": member_dn,
                    "target_id": sid or sam,
                    "edge_type": "MEMBER_OF",
                    "risk_weight": 0.4,
                    "provenance": "LDAP group membership",
                    "attributes": {"member_dn": member_dn},
                })
        self._emit(f"Enumerated {len(entities)} groups and {len(edges)} membership edges", 52)
        return entities, edges

    def _enum_domain_policy(self) -> dict:
        self._emit("Reading domain password policy…", 55)
        raw = self._search("(objectClass=domain)", DOMAIN_ATTRS, search_base=self._base_dn)
        policy: dict[str, Any] = {}
        if raw:
            r = raw[0]
            pwd_props = int(r.get("pwdProperties") or 0)
            functional_level = int(r.get("msDS-Behavior-Version") or 0)
            history_count = int(r.get("pwdHistoryLength") or 0)
            policy = {
                "min_password_length": int(r.get("minPwdLength") or 0),
                "lockout_threshold": int(r.get("lockoutThreshold") or 0),
                "lockout_duration": str(r.get("lockoutDuration", "")),
                "max_pwd_age": str(r.get("maxPwdAge", "")),
                "min_pwd_age": str(r.get("minPwdAge", "")),
                "pwd_history_length": history_count,
                "password_history_count": history_count,
                "machine_account_quota": int(r.get("ms-DS-MachineAccountQuota") or 10),
                "functional_level": functional_level,
                "domain_functional_level": functional_level,
                "complexity_enabled": bool(pwd_props & 0x1),
                "reversible_encryption_enabled": bool(pwd_props & 0x10),
            }
        self._emit("Read domain policy", 60)
        return policy

    def _get_krbtgt_password_age(self) -> int:
        try:
            raw = self._search(
                "(sAMAccountName=krbtgt)",
                ["pwdLastSet"],
            )
            if not raw:
                return 0
            pwd_last_set = raw[0].get("pwdLastSet")
            if not pwd_last_set or str(pwd_last_set) in ("", "0", "None"):
                return 0
            if isinstance(pwd_last_set, datetime):
                dt = pwd_last_set.replace(tzinfo=timezone.utc) if pwd_last_set.tzinfo is None else pwd_last_set
                return (datetime.now(timezone.utc) - dt).days
        except Exception:
            log.debug("Failed to get krbtgt password age", exc_info=True)
            pass
        return 0

    def _check_network_exposure(self) -> dict[str, Any]:
        """Fast TCP reachability checks used by network posture rules."""
        import socket

        ports = {
            53: "dns",
            88: "kerberos",
            135: "rpc",
            389: "ldap",
            445: "smb",
            464: "kpasswd",
            636: "ldaps",
            3268: "global_catalog",
            3269: "global_catalog_ldaps",
            5985: "winrm_http",
            5986: "winrm_https",
        }
        open_ports: list[int] = []
        for port in ports:
            try:
                with socket.create_connection((self.dc_ip, port), timeout=1.5):
                    open_ports.append(port)
            except OSError:
                continue

        winrm_ports = [port for port in open_ports if port in (5985, 5986)]
        return {
            "open_ports": open_ports,
            "open_services": [ports[port] for port in open_ports],
            "winrm_open": bool(winrm_ports),
            "winrm_hosts": [f"{self.dc_ip}:{port}" for port in winrm_ports],
        }

    def _enum_trusts(self) -> list[dict]:
        self._emit("Enumerating domain trusts…", 62)
        raw = self._search(
            "(objectClass=trustedDomain)",
            TRUST_ATTRS,
            search_base=f"CN=System,{self._base_dn}",
        )
        trusts = []
        for r in raw:
            attrs = int(r.get("trustAttributes") or 0)
            trusts.append({
                "partner": str(r.get("trustPartner", "")),
                "trust_type": int(r.get("trustType") or 0),
                "trust_direction": int(r.get("trustDirection") or 0),
                "trust_attributes": attrs,
                "sid_filtering_enabled": bool(attrs & 0x4),
                "flat_name": str(r.get("flatName", "")),
            })
        self._emit(f"Enumerated {len(trusts)} trusts", 68)
        return trusts

    def _enum_gpos(self) -> list[dict]:
        self._emit("Enumerating Group Policy Objects…", 70)
        raw = self._search("(objectClass=groupPolicyContainer)", GPO_ATTRS)
        entities = []
        for r in raw:
            name = str(r.get("displayName") or r.get("name", ""))
            dn = str(r.get("distinguishedName", ""))
            guid = str(r.get("cn", ""))
            entities.append({
                "id": dn,
                "entity_type": "GPO",
                "sam_account_name": name,
                "display_name": name,
                "distinguished_name": dn,
                "domain": self.domain,
                "is_enabled": True,
                "is_admin_count": False,
                "is_sensitive": False,
                "is_protected_user": False,
                "is_crown_jewel": False,
                "tier": None,
                "attributes": {
                    "path": str(r.get("gPCFileSysPath", "")),
                    "gpo_guid": guid,
                },
                "business_tags": [],
            })
        self._emit(f"Enumerated {len(entities)} GPOs", 78)
        return entities

    def _enum_ous(self) -> list[dict]:
        """Enumerate OUs — needed for entity map and gPLink parsing."""
        self._emit("Enumerating OUs…", 71)
        raw = self._search("(objectClass=organizationalUnit)", OU_ATTRS)
        entities = []
        for r in raw:
            dn = str(r.get("distinguishedName", ""))
            sid = str(r.get("objectSid", ""))
            name = str(r.get("name", ""))
            entities.append({
                "id": dn,
                "entity_type": "OU",
                "object_sid": sid,
                "sam_account_name": name,
                "display_name": name,
                "distinguished_name": dn,
                "domain": self.domain,
                "is_enabled": True,
                "is_admin_count": False,
                "is_sensitive": False,
                "is_protected_user": False,
                "is_crown_jewel": False,
                "tier": None,
                "attributes": {
                    "gp_link": str(r.get("gPLink", "")),
                    "gp_options": int(r.get("gPOptions") or 0),
                },
                "business_tags": [],
            })
        self._emit(f"Enumerated {len(entities)} OUs", 72)
        return entities

    def _enum_domain_entity(self) -> dict | None:
        """Create domain root as a graph entity (needed for DCSYNC edges)."""
        raw = self._search("(objectClass=domain)", ["objectSid", "distinguishedName"],
                           search_base=self._base_dn)
        if not raw:
            return None
        r = raw[0]
        sid = str(r.get("objectSid", ""))
        dn = str(r.get("distinguishedName", self._base_dn))
        return {
            "id": sid or dn,
            "entity_type": "DOMAIN",
            "object_sid": sid,
            "sam_account_name": self.domain,
            "display_name": self.domain,
            "distinguished_name": dn,
            "domain": self.domain,
            "is_enabled": True,
            "is_admin_count": False,
            "is_sensitive": True,
            "is_protected_user": False,
            "is_crown_jewel": True,
            "tier": 0,
            "attributes": {"object_sid": sid},
            "business_tags": ["Domain Root"],
        }

    def _enum_gpo_links(self, gpo_entities: list[dict]) -> list[dict]:
        """
        Parse gPLink attributes on domain root and OUs.
        Returns APPLIES_GPO edges: source=GPO entity, target=OU/domain DN.
        """
        # Build GPO DN → entity id map (case-insensitive)
        gpo_map: dict[str, str] = {}
        for gpo in gpo_entities:
            dn = gpo.get("distinguished_name", "")
            if dn:
                gpo_map[dn.lower()] = gpo.get("id", dn)

        containers = self._search(
            "(|(objectClass=domain)(objectClass=organizationalUnit))",
            ["distinguishedName", "gPLink", "gPOptions"],
        )
        edges: list[dict] = []
        for c in containers:
            container_dn = str(c.get("distinguishedName", ""))
            gp_link = str(c.get("gPLink") or "")
            if not gp_link:
                continue
            gp_options = int(c.get("gPOptions") or 0)
            block_inherit = bool(gp_options & 1)
            for match in _GPO_LINK_RE.finditer(gp_link):
                gpo_dn = match.group(1).strip()
                link_opts = int(match.group(2))
                disabled = bool(link_opts & 0x01)
                enforced = bool(link_opts & 0x02)
                if disabled:
                    continue
                gpo_id = gpo_map.get(gpo_dn.lower())
                if not gpo_id:
                    continue
                edges.append({
                    "source_id": gpo_id,
                    "target_id": container_dn,
                    "edge_type": "APPLIES_GPO",
                    "risk_weight": 0.6 if enforced else 0.3,
                    "provenance": f"GPO linked {'(enforced) ' if enforced else ''}to {container_dn}",
                    "attributes": {
                        "enforced": enforced,
                        "block_inheritance": block_inherit,
                        "gpo_dn": gpo_dn,
                        "target_dn": container_dn,
                    },
                })
        self._emit(f"Found {len(edges)} GPO link edges", 73)
        return edges

    def _build_entity_map(self, entities: list[dict]) -> dict[str, str]:
        """Build multi-key lookup: SID/DN/SAM/id → entity id."""
        entity_map: dict[str, str] = {}
        for e in entities:
            eid = e.get("id", "")
            if not eid:
                continue
            entity_map[eid] = eid
            for key in filter(None, [
                e.get("object_sid", ""),
                e.get("distinguished_name", ""),
                e.get("sam_account_name", ""),
                e.get("dns_hostname", ""),
            ]):
                if key not in entity_map:
                    entity_map[key] = eid
        return entity_map

    def _run_acl_collection(self, entities: list[dict]) -> tuple[list[dict], list[dict], list[dict]]:
        """Run DACL enumeration. Returns (edges, placeholder_entities, evidence)."""
        from adbygod_api.core.collection.acl_collector import AclCollector
        entity_map = self._build_entity_map(entities)
        acl = AclCollector(
            conn=self._conn,
            base_dn=self._base_dn,
            entity_map=entity_map,
            include_inherited=self.acl_include_inherited,
            max_objects=self.acl_max_objects,
            progress_cb=self._progress_cb,
        )
        return acl.collect()

    def _run_sysvol_scan(self) -> tuple[list[dict], list[dict]]:
        """Scan SYSVOL for GPP cpassword. Returns (findings, evidence)."""
        from adbygod_api.core.collection.sysvol_scanner import SysvolScanner
        scanner = SysvolScanner(
            dc_ip=self.dc_ip,
            domain=self.domain,
            username=self.username,
            password=self.password or "",
            auth_method=self.auth_method,
            progress_cb=self._progress_cb,
        )
        return scanner.scan()

    def _enum_adcs(self, entities: list[dict]) -> tuple[list[dict], list[dict], list[dict], list[dict], list[dict], dict]:
        self._emit("Enumerating AD CS (PKI) infrastructure…", 80)
        config_base = f"CN=Configuration,{self._base_dn}"
        template_attrs = [
            "cn", "displayName", "name", "distinguishedName", "objectGUID",
            "pKIExtendedKeyUsage", "msPKI-Certificate-Application-Policy",
            "msPKI-Certificate-Name-Flag", "msPKI-Enrollment-Flag",
            "msPKI-Private-Key-Flag", "msPKI-RA-Signature",
            "msPKI-Minimal-Key-Size", "flags",
        ]
        ca_attrs = [
            "cn", "name", "distinguishedName", "objectClass", "dNSHostName", "certificateTemplates",
            "cACertificateDN", "msPKI-Enrollment-Servers",
        ]
        template_rows = self._search_with_sd(
            "(objectClass=pKICertificateTemplate)",
            template_attrs,
            search_base=f"CN=Certificate Templates,CN=Public Key Services,CN=Services,{config_base}",
        )
        ca_rows = self._search_with_sd(
            "(objectClass=pKIEnrollmentService)",
            ca_attrs,
            search_base=f"CN=Enrollment Services,CN=Public Key Services,CN=Services,{config_base}",
        )
        pki_object_rows: list[dict] = []
        pki_object_attrs = ["cn", "name", "distinguishedName", "objectClass"]
        for dn in [
            f"CN=Public Key Services,CN=Services,{config_base}",
            f"CN=Certificate Templates,CN=Public Key Services,CN=Services,{config_base}",
            f"CN=NTAuthCertificates,CN=Public Key Services,CN=Services,{config_base}",
            f"CN=AIA,CN=Public Key Services,CN=Services,{config_base}",
            f"CN=CDP,CN=Public Key Services,CN=Services,{config_base}",
        ]:
            try:
                pki_object_rows.extend(self._search_with_sd(
                    "(objectClass=*)",
                    pki_object_attrs,
                    search_base=dn,
                    search_scope=BASE,
                ))
            except Exception as exc:
                log.debug("Skipping optional PKI object ACL read for %s: %s", dn, exc)
        ca_entities, template_entities, templates, findings, evidence, coverage = build_adcs_result(
            domain=self.domain,
            dc_ip=self.dc_ip,
            entities=entities,
            template_rows=template_rows,
            ca_rows=ca_rows,
            pki_object_rows=pki_object_rows,
            include_inherited=self.acl_include_inherited,
            check_adcs_web=self.check_adcs_web,
            check_esc6=self.check_esc6,
        )
        esc_counts = coverage.get("esc_counts", {})
        self._emit(f"Enumerated {len(ca_entities)} CAs and {len(templates)} certificate templates", 88)
        self._emit(
            "AD CS: templates=%d CAs=%d published=%d ESC1=%d ESC2=%d ESC3=%d ESC4=%d ESC5=%d ESC6 checked=false ESC8 endpoints=%d"
            % (
                len(templates), len(ca_entities), coverage.get("published_templates_resolved", 0),
                esc_counts.get("esc1", 0), esc_counts.get("esc2", 0),
                esc_counts.get("esc3", 0), esc_counts.get("esc4", 0),
                coverage.get("esc5_findings", 0),
                coverage.get("esc8_endpoints_checked", 0),
            ),
            89,
        )
        return ca_entities, template_entities, templates, findings, evidence, coverage

    def _run_collection(self) -> dict:
        self._connect()
        try:
            if self._obfuscation_enabled:
                self._emit(
                    "Remote OBFSC active — ldap3 queries use filter padding, attribute shuffle, and jitter",
                    6,
                )
            entities: list[dict] = []
            edges: list[dict] = []
            evidence: list[dict] = []
            cert_templates: list[dict] = []
            findings: list[dict] = []
            adcs_coverage: dict[str, Any] = {}
            trusts: list[dict] = []
            gpos: list[dict] = []
            acl_edge_count = 0
            gpo_link_count = 0
            sysvol_findings: list[dict] = []
            modules_run: list[str] = ["Directory Inventory", "Password Policy", "Privilege and Control Paths", "Exposure Quick Checks"]

            # Domain root entity (needed as DCSYNC target)
            domain_entity = self._enum_domain_entity()
            if domain_entity:
                entities.append(domain_entity)

            users = self._enum_users()
            entities.extend(users)
            self._emit(f"Enumerated {len(users)} user accounts", 20)
            evidence.append({
                "id": "ldap-users",
                "source_type": "ldap",
                "source_host": self.dc_ip,
                "collection_method": "ldap/users",
                "origin": "COLLECTED",
                "raw_data": {"count": len(users)},
                "confidence": 1.0,
            })

            computers = self._enum_computers()
            entities.extend(computers)
            self._emit(f"Enumerated {len(computers)} computer accounts", 35)
            evidence.append({
                "id": "ldap-computers",
                "source_type": "ldap",
                "source_host": self.dc_ip,
                "collection_method": "ldap/computers",
                "origin": "COLLECTED",
                "raw_data": {"count": len(computers)},
                "confidence": 1.0,
            })

            groups, group_edges = self._enum_groups()
            entities.extend(groups)
            edges.extend(group_edges)
            self._emit(f"Enumerated {len(groups)} groups and {len(group_edges)} memberships", 50)
            evidence.append({
                "id": "ldap-groups",
                "source_type": "ldap",
                "source_host": self.dc_ip,
                "collection_method": "ldap/groups",
                "origin": "COLLECTED",
                "raw_data": {"count": len(groups)},
                "confidence": 1.0,
            })

            # OUs (needed for entity map + GPO link targets)
            ous = self._enum_ous()
            entities.extend(ous)

            pwd_policy = self._enum_domain_policy()
            krbtgt_age = self._get_krbtgt_password_age()
            network_config = self._check_network_exposure()
            evidence.append({
                "id": "network-exposure",
                "source_type": "network",
                "source_host": self.dc_ip,
                "collection_method": "network/tcp_ports",
                "origin": "COLLECTED",
                "raw_data": network_config,
                "confidence": 0.95,
            })

            if self.enum_gpos:
                gpos = self._enum_gpos()
                entities.extend(gpos)
                evidence.append({
                    "id": "ldap-gpos",
                    "source_type": "ldap",
                    "source_host": self.dc_ip,
                    "collection_method": "ldap/gpos",
                    "origin": "COLLECTED",
                    "raw_data": {"count": len(gpos)},
                    "confidence": 1.0,
                })
                modules_run.append("Group Policy Coverage")

                if self.enum_gpo_acls:
                    gpo_link_edges = self._enum_gpo_links(gpos)
                    edges.extend(gpo_link_edges)
                    gpo_link_count = len(gpo_link_edges)
                    evidence.append({
                        "id": "ldap-gpo-links",
                        "source_type": "ldap",
                        "source_host": self.dc_ip,
                        "collection_method": "ldap/gpo_links",
                        "origin": "COLLECTED",
                        "raw_data": {"count": gpo_link_count},
                        "confidence": 1.0,
                    })

            if self.enum_trusts:
                trusts = self._enum_trusts()
                evidence.append({
                    "id": "ldap-trusts",
                    "source_type": "ldap",
                    "source_host": self.dc_ip,
                    "collection_method": "ldap/trusts",
                    "origin": "COLLECTED",
                    "raw_data": {"count": len(trusts)},
                    "confidence": 1.0,
                })
                modules_run.append("Topology and Trusts")

            if self.enum_adcs:
                ca_entities, template_entities, cert_templates, adcs_findings, adcs_evidence, adcs_coverage = self._enum_adcs(entities)
                entities.extend(ca_entities)
                entities.extend(template_entities)
                evidence.extend(adcs_evidence)
                findings.extend(adcs_findings)
                modules_run.append("Certificate Services Posture")

            # ACL collection — runs after all entities are known so entity_map is complete
            if self.enum_acls:
                self._emit("Running DACL enumeration…", 60)
                acl_edges, placeholder_entities, acl_evidence = self._run_acl_collection(entities)
                edges.extend(acl_edges)
                entities.extend(placeholder_entities)
                evidence.extend(acl_evidence)
                acl_edge_count = len(acl_edges)
                modules_run.append("ACL / Permission Analysis")
                self._emit(f"ACL: {acl_edge_count} permission edges, {len(placeholder_entities)} unresolved SIDs", 75)

            # SYSVOL GPP cpassword scan
            if self.scan_sysvol:
                self._emit("Scanning SYSVOL for GPP cpassword…", 85)
                sysvol_raw, sysvol_evidence = self._run_sysvol_scan()
                # Raw file-location dicts go into sysvol_evidence["raw_data"]["findings"]
                # where the ACL-008 rule engine rule reads them. Do NOT add to findings
                # list — they are not proper finding dicts (no finding_type/severity/title).
                evidence.extend(sysvol_evidence)
                modules_run.append("SYSVOL / GPP Exposure")
                self._emit(f"SYSVOL: {len(sysvol_raw)} cpassword file(s) found", 88)

            for ent in entities:
                attrs = ent.get("attributes", {})
                if attrs.get("uac_trusted_for_delegation") and not attrs.get("uac_is_dc"):
                    edges.append({
                        "source_id": ent["id"],
                        "target_id": f"domain:{self.domain}",
                        "edge_type": "ALLOWED_TO_DELEGATE",
                        "risk_weight": 0.9,
                        "provenance": "Unconstrained delegation (LDAP)",
                        "attributes": {"delegation_type": "unconstrained"},
                    })
                for target_spn in attrs.get("allowed_to_delegate_to", []):
                    edges.append({
                        "source_id": ent["id"],
                        "target_id": target_spn,
                        "edge_type": "ALLOWED_TO_DELEGATE",
                        "risk_weight": 0.7,
                        "provenance": f"Constrained delegation to {target_spn}",
                        "attributes": {"delegation_type": "constrained", "target_spn": target_spn},
                    })

            self._emit("Collection complete. Building result…", 95, "SUCCESS")
            dc_count = sum(1 for e in entities if e["entity_type"] == "DC")
            user_count = sum(1 for e in entities if e["entity_type"] in ("USER", "SERVICE_ACCOUNT"))
            comp_count = sum(1 for e in entities if e["entity_type"] in ("COMPUTER", "DC"))
            laps_count = sum(1 for e in entities if e.get("attributes", {}).get("has_laps"))
            domain_info = {
                "domain": self.domain,
                "dc_ip": self.dc_ip,
                "total_users": user_count,
                "total_computers": comp_count,
                "total_dcs": dc_count,
                "laps_deployed": laps_count > 0,
                "laps_count": laps_count,
                "machine_account_quota": pwd_policy.get("machine_account_quota", 10),
                "functional_level": pwd_policy.get("functional_level", 0),
                "domain_functional_level": pwd_policy.get("functional_level", 0),
                "krbtgt_password_age_days": krbtgt_age,
                "open_ports": network_config.get("open_ports", []),
            }
            metadata_modules = [
                "domain_policy",
                "users",
                "computers",
                "groups",
                "ous",
                "network_exposure",
            ]
            if self.enum_gpos:
                metadata_modules.append("gpos")
            if self.enum_gpo_acls and self.enum_gpos:
                metadata_modules.append("gpo_links")
            if self.enum_trusts:
                metadata_modules.append("trusts")
            if self.enum_adcs:
                metadata_modules.append("adcs")
            if self.enum_acls:
                metadata_modules.append("acls")
            if self.scan_sysvol:
                metadata_modules.append("sysvol")

            self._emit(f"Collection complete: {len(entities)} entities, {len(edges)} edges", 100)
            return {
                "schema_version": "1.0",
                "tool": "AdByG0d LDAP Collector",
                "collection_mode": "LINUX_REMOTE",
                "domain": self.domain,
                "dc_ip": self.dc_ip,
                "collected_at": "live",
                "collector_version": "ldap3/live",
                "modules_run": modules_run,
                "entities": entities,
                "edges": edges,
                "evidence": evidence,
                "findings": findings,
                "cert_templates": cert_templates,
                "metadata": {
                    "domain_info": domain_info,
                    "password_policy": pwd_policy,
                    "trusts": trusts,
                    "network_config": network_config,
                    "collected_modules": metadata_modules,
                    "enum_flags": {
                        "enum_gpos": self.enum_gpos,
                        "enum_trusts": self.enum_trusts,
                        "enum_adcs": self.enum_adcs,
                        "enum_acls": self.enum_acls,
                        "enum_gpo_acls": self.enum_gpo_acls,
                        "scan_sysvol": self.scan_sysvol,
                        "check_adcs_web": self.check_adcs_web,
                        "check_esc6": self.check_esc6,
                    },
                    "coverage": {
                        "acl_edges": acl_edge_count,
                        "gpo_link_edges": gpo_link_count,
                        "sysvol_cpassword_files": len(sysvol_findings),
                        "adcs": adcs_coverage,
                    },
                    "obfuscation": self._obfuscation_metadata(),
                },
            }
        finally:
            self._disconnect()

    async def collect(self) -> dict:
        return await asyncio.to_thread(self._run_collection)


def _is_high_value_group(name: str) -> bool:
    n = name.upper()
    return any(
        marker in n
        for marker in [
            "DOMAIN ADMINS", "ENTERPRISE ADMINS", "SCHEMA ADMINS",
            "ADMINISTRATORS", "DOMAIN CONTROLLERS", "READ-ONLY DOMAIN CONTROLLERS",
            "GROUP POLICY CREATOR OWNERS", "ACCOUNT OPERATORS",
            "BACKUP OPERATORS", "PRINT OPERATORS", "SERVER OPERATORS",
        ]
    )
