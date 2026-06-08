"""
Live LDAP ACL collector — read-only, DACL-only.

Emits graph edges:
  DCSYNC      DS-Replication-Get-Changes + Get-Changes-All on domain root
  GENERIC_ALL GenericAll / FullControl on any object
  HAS_CONTROL GenericWrite on any object
  WRITE_DACL  WriteDACL on any object
  WRITE_OWNER WriteOwner on any object
  ADD_MEMBER  WriteProperty(member) on group objects
"""
from __future__ import annotations

import logging
import struct
from typing import Any

from ldap3 import BASE, SUBTREE
from ldap3.protocol.microsoft import security_descriptor_control

log = logging.getLogger(__name__)

# ── Access mask bit constants ─────────────────────────────────────────────────
MASK_GENERIC_ALL   = 0x10000000
MASK_GENERIC_WRITE = 0x40000000
MASK_WRITE_DACL    = 0x00040000
MASK_WRITE_OWNER   = 0x00080000
MASK_EXT_RIGHT     = 0x00000100  # ADS_RIGHT_DS_CONTROL_ACCESS
MASK_WRITE_PROP    = 0x00000020  # ADS_RIGHT_DS_WRITE_PROP
MASK_FULL_CONTROL  = 0x000F01FF  # Object-specific full-control bits

# ── ACE type constants ────────────────────────────────────────────────────────
ACE_ALLOW        = 0x00
ACE_ALLOW_OBJECT = 0x05

# ── Inheritance flag ──────────────────────────────────────────────────────────
INHERITED_ACE = 0x10

# ── Object ACE flag: ObjectType field present ─────────────────────────────────
OBJ_TYPE_PRESENT = 0x01

# ── DCSync extended-right GUIDs (lowercase, dash-separated) ──────────────────
DC_SYNC_GET_CHANGES          = "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"
DC_SYNC_GET_CHANGES_ALL      = "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"
DC_SYNC_GET_CHANGES_FILTERED = "89e95b76-444d-4c62-991a-0facbeda640c"
DCSYNC_GUIDS = frozenset([DC_SYNC_GET_CHANGES, DC_SYNC_GET_CHANGES_ALL,
                           DC_SYNC_GET_CHANGES_FILTERED])

# ── member attribute schemaIDGUID ─────────────────────────────────────────────
MEMBER_ATTR_GUID = "bf9679c0-0de6-11d0-a285-00aa003049e2"

# ── Trustee SIDs that are safe to suppress globally ───────────────────────────
# Broad principals such as Everyone / Authenticated Users must NOT be dropped:
# if they receive GenericAll, WriteDACL, AddMember, etc., that is a real finding.
_SKIP_SIDS = frozenset([
    "S-1-5-18",   # SYSTEM
])

_WELL_KNOWN: dict[str, str] = {
    "S-1-1-0":      "Everyone",
    "S-1-5-2":      "Network",
    "S-1-5-3":      "Batch",
    "S-1-5-6":      "Service",
    "S-1-5-7":      "Anonymous Logon",
    "S-1-5-9":      "Enterprise Domain Controllers",
    "S-1-5-11":     "Authenticated Users",
    "S-1-5-18":     "SYSTEM",
    "S-1-5-32-544": "BUILTIN\\Administrators",
    "S-1-5-32-548": "BUILTIN\\Account Operators",
    "S-1-5-32-549": "BUILTIN\\Server Operators",
    "S-1-5-32-550": "BUILTIN\\Print Operators",
    "S-1-5-32-551": "BUILTIN\\Backup Operators",
    "S-1-5-32-552": "BUILTIN\\Replicator",
}


def _bytes_to_guid(b: bytes) -> str:
    """Convert 16-byte Windows GUID (mixed-endian) → lowercase dash-string."""
    if not b or len(b) < 16:
        return ""
    p1 = struct.unpack_from("<I", b, 0)[0]
    p2 = struct.unpack_from("<H", b, 4)[0]
    p3 = struct.unpack_from("<H", b, 6)[0]
    p4 = b[8:10].hex()
    p5 = b[10:16].hex()
    return f"{p1:08x}-{p2:04x}-{p3:04x}-{p4}-{p5}"


def parse_sd_aces(raw: bytes) -> list:
    """Parse raw nTSecurityDescriptor → list of impacket ACE objects. Empty list on failure."""
    if not raw:
        return []
    try:
        from impacket.ldap.ldaptypes import SR_SECURITY_DESCRIPTOR
        sd = SR_SECURITY_DESCRIPTOR(data=raw)
        if not sd["OffsetDacl"]:
            return []
        dacl = sd["Dacl"]
        return list(dacl.aces)
    except Exception as exc:
        log.debug("SD parse failed: %s", exc)
        return []


class AclCollector:
    """
    Read-only LDAP ACL collector.

    Accepts an already-open ldap3 Connection and a pre-built entity_map,
    then enumerates nTSecurityDescriptor on domain root, users, groups,
    computers, OUs, GPO containers, and AdminSDHolder.

    Returns (edges, placeholder_entities, evidence_records).
    """

    def __init__(
        self,
        conn,
        base_dn: str,
        entity_map: dict[str, str],
        include_inherited: bool = True,
        max_objects: int = 5_000,
        progress_cb: Any = None,
    ):
        self.conn = conn
        self.base_dn = base_dn
        self.entity_map: dict[str, str] = dict(entity_map)
        self.include_inherited = include_inherited
        self.max_objects = max_objects
        self._cb = progress_cb

        self._edges: list[dict] = []
        self._edge_keys: set[tuple] = set()
        self._placeholders: list[dict] = []
        self._placeholder_sids: set[str] = set()
        self._dcsync: dict[str, set[str]] = {}  # trustee_sid → set of DCSync GUIDs seen

    # ──────────────────────────────────────────────────────────────────────────
    # Internal helpers
    # ──────────────────────────────────────────────────────────────────────────

    def _log(self, msg: str, pct: int = 0) -> None:
        log.info("[ACL] %s", msg)
        if self._cb:
            try:
                self._cb(msg, pct)
            except Exception:
                pass

    def _search_sd(self, search_filter: str, search_base: str | None = None,
                   scope=SUBTREE) -> list[dict]:
        """Return list of {dn, sid, sd_raw} dicts with DACL bytes."""
        base = search_base or self.base_dn
        controls = security_descriptor_control(sdflags=0x04)
        results: list[dict] = []

        def append_entries(entries) -> None:
            for entry in entries:
                if isinstance(entry, dict):
                    dn = entry.get("dn", "")
                    raw_attrs = entry.get("raw_attributes", {})
                    proc_attrs = entry.get("attributes", {})

                    sd_list = raw_attrs.get("nTSecurityDescriptor", [])
                    sd_raw = sd_list[0] if sd_list else None
                    if not sd_raw:
                        sd_raw = proc_attrs.get("nTSecurityDescriptor")

                    sid = proc_attrs.get("objectSid", "")
                    if isinstance(sid, (list, tuple)):
                        sid = sid[0] if sid else ""
                    results.append({"dn": str(dn), "sid": str(sid or ""), "sd_raw": sd_raw})
                else:
                    try:
                        dn = entry.entry_dn
                        sd_raw_vals = entry["nTSecurityDescriptor"].raw_values
                        sd_raw = sd_raw_vals[0] if sd_raw_vals else None
                        sid = str(entry["objectSid"].value) if "objectSid" in entry else ""
                        results.append({"dn": str(dn), "sid": sid, "sd_raw": sd_raw})
                    except Exception:
                        pass

        try:
            cookie = None
            while True:
                res = self.conn.search(
                    search_base=base,
                    search_filter=search_filter,
                    search_scope=scope,
                    attributes=["distinguishedName", "objectSid", "nTSecurityDescriptor"],
                    controls=controls,
                    paged_size=200,
                    paged_cookie=cookie,
                )

                if isinstance(res, tuple):
                    _ok, result, response, _req = res
                    append_entries([e for e in response if e.get("type") == "searchResEntry"])
                    cookie = (
                        result.get("controls", {})
                        .get("1.2.840.113556.1.4.319", {})
                        .get("value", {})
                        .get("cookie")
                    )
                else:
                    append_entries(list(self.conn.entries))
                    cookie = None

                if not cookie:
                    break
        except Exception as exc:
            log.warning("[ACL] search error filter=%r: %s", search_filter, exc)
            return results

        return results

    def _resolve(self, sid: str, dn: str = "") -> str | None:
        for key in filter(None, [sid, dn]):
            v = self.entity_map.get(key)
            if v:
                return v
        return None

    def _placeholder(self, sid: str) -> str:
        if sid in self.entity_map:
            return self.entity_map[sid]
        if sid not in self._placeholder_sids:
            self._placeholder_sids.add(sid)
            name = _WELL_KNOWN.get(sid, sid)
            self._placeholders.append({
                "id": sid,
                "entity_type": "UNKNOWN",
                "object_sid": sid,
                "sam_account_name": name,
                "display_name": name,
                "distinguished_name": "",
                "domain": "",
                "is_enabled": True,
                "is_admin_count": False,
                "is_sensitive": False,
                "is_protected_user": False,
                "is_crown_jewel": False,
                "tier": None,
                "attributes": {"object_sid": sid, "placeholder": True},
                "business_tags": [],
            })
            self.entity_map[sid] = sid
        return sid

    def _add_edge(self, src: str, tgt: str, etype: str, risk: float,
                  prov: str, attrs: dict) -> None:
        key = (src, tgt, etype)
        if key in self._edge_keys:
            return
        self._edge_keys.add(key)
        self._edges.append({
            "source_id": src,
            "target_id": tgt,
            "edge_type": etype,
            "risk_weight": risk,
            "provenance": prov,
            "attributes": attrs,
        })

    # ──────────────────────────────────────────────────────────────────────────
    # ACE processing
    # ──────────────────────────────────────────────────────────────────────────

    def _process_ace(self, ace, target_id: str, target_dn: str,
                     target_type: str, is_domain_root: bool) -> None:

        ace_type = ace["AceType"]
        if ace_type not in (ACE_ALLOW, ACE_ALLOW_OBJECT):
            return

        try:
            ace_flags = ace["AceFlags"]
            is_inherited = bool(ace_flags & INHERITED_ACE)
            if is_inherited and not self.include_inherited:
                return

            inner = ace["Ace"]
            mask = inner["Mask"]["Mask"]
            trustee = inner["Sid"].formatCanonical()
        except Exception:
            return

        if trustee in _SKIP_SIDS or trustee == target_id:
            return

        src = self._resolve(trustee)
        if src is None:
            src = self._placeholder(trustee)

        conf = 0.9 if is_inherited else 1.0
        base = {
            "trustee_sid": trustee,
            "is_inherited": is_inherited,
            "confidence": conf,
            "target_dn": target_dn,
            "target_type": target_type,
            "collection_method": "ldap/acl",
        }
        inh_label = "inherited" if is_inherited else "direct"

        # ── Object ACE: check GUID-scoped rights ───────────────────────────
        if ace_type == ACE_ALLOW_OBJECT:
            try:
                flags = inner["Flags"]
                obj_guid = ""
                if flags & OBJ_TYPE_PRESENT:
                    obj_guid = _bytes_to_guid(bytes(inner["ObjectType"]))
            except Exception:
                obj_guid = ""

            if obj_guid:
                # DCSync extended rights on domain root
                if is_domain_root and obj_guid in DCSYNC_GUIDS and (mask & MASK_EXT_RIGHT):
                    self._dcsync.setdefault(trustee, set()).add(obj_guid)
                    return  # edge emitted in _flush_dcsync

                # WriteProperty(member) on group → AddMember
                if obj_guid == MEMBER_ATTR_GUID and (mask & MASK_WRITE_PROP):
                    self._add_edge(src, target_id, "ADD_MEMBER", 0.85 * conf,
                                   f"WriteProperty(member) (LDAP ACL, {inh_label})",
                                   {**base, "right": "AddMember", "guid": obj_guid,
                                    "impact": "group_takeover"})
                    return

        # ── Standard mask checks ───────────────────────────────────────────
        # GenericAll / FullControl — supersedes all others
        if (mask & MASK_GENERIC_ALL) or ((mask & MASK_FULL_CONTROL) == MASK_FULL_CONTROL):
            self._add_edge(src, target_id, "GENERIC_ALL", conf,
                           f"GenericAll (LDAP ACL, {inh_label})",
                           {**base, "right": "GenericAll", "raw_mask": hex(mask),
                            "impact": "account_takeover"})
            return  # GenericAll implies all others — skip redundant edges

        if mask & MASK_WRITE_DACL:
            self._add_edge(src, target_id, "WRITE_DACL", min(0.95, conf + 0.05),
                           f"WriteDACL (LDAP ACL, {inh_label})",
                           {**base, "right": "WriteDACL", "raw_mask": hex(mask),
                            "impact": "account_takeover"})

        if mask & MASK_WRITE_OWNER:
            self._add_edge(src, target_id, "WRITE_OWNER", 0.9 * conf,
                           f"WriteOwner (LDAP ACL, {inh_label})",
                           {**base, "right": "WriteOwner", "raw_mask": hex(mask),
                            "impact": "account_takeover"})

        if mask & MASK_GENERIC_WRITE:
            self._add_edge(src, target_id, "HAS_CONTROL", 0.85 * conf,
                           f"GenericWrite (LDAP ACL, {inh_label})",
                           {**base, "right": "GenericWrite", "raw_mask": hex(mask),
                            "impact": "account_takeover"})

    def _process_object(self, obj: dict, target_type: str,
                        is_domain_root: bool = False) -> None:
        dn = obj.get("dn", "")
        sid = obj.get("sid", "")
        sd_raw = obj.get("sd_raw")
        if not sd_raw:
            return

        target_id = self._resolve(sid, dn)
        if not target_id:
            return

        for ace in parse_sd_aces(sd_raw):
            try:
                self._process_ace(ace, target_id, dn, target_type, is_domain_root)
            except Exception as exc:
                log.debug("[ACL] ACE error on %r: %s", dn, exc)

    def _flush_dcsync(self, domain_target_id: str) -> None:
        """Emit DCSYNC edges only when both replication rights are present."""
        required = {DC_SYNC_GET_CHANGES, DC_SYNC_GET_CHANGES_ALL}
        for trustee_sid, guids in self._dcsync.items():
            if not required.issubset(guids):
                continue
            src = self.entity_map.get(trustee_sid, trustee_sid)
            self._add_edge(
                src, domain_target_id, "DCSYNC", 1.0,
                "DS-Replication-Get-Changes + Get-Changes-All (LDAP ACL)",
                {
                    "trustee_sid": trustee_sid,
                    "right": "DCSync",
                    "guids": sorted(guids),
                    "confidence": 1.0,
                    "has_both_rights": True,
                    "collection_method": "ldap/acl",
                    "impact": "domain_compromise",
                },
            )

    # ──────────────────────────────────────────────────────────────────────────
    # Main collection entry point
    # ──────────────────────────────────────────────────────────────────────────

    def collect(self) -> tuple[list[dict], list[dict], list[dict]]:
        """
        Run DACL enumeration.

        Returns:
            edges              — graph edge dicts ready for ldap_collector output
            placeholder_entities — UNKNOWN entities created for unresolved SIDs
            evidence           — evidence record list
        """
        self._edges = []
        self._edge_keys = set()
        self._placeholders = []
        self._placeholder_sids = set()
        self._dcsync = {}

        scanned = 0

        # 1. Domain root — home of DCSync rights
        self._log("ACL: domain root…", 72)
        domain_objs = self._search_sd("(objectClass=domain)",
                                       search_base=self.base_dn, scope=BASE)
        domain_target_id = ""
        for obj in domain_objs:
            if not domain_target_id:
                domain_target_id = self._resolve(obj["sid"], obj["dn"]) or obj["dn"]
            self._process_object(obj, "DOMAIN", is_domain_root=True)
        scanned += len(domain_objs)

        # 2. AdminSDHolder
        ash_dn = f"CN=AdminSDHolder,CN=System,{self.base_dn}"
        self._log("ACL: AdminSDHolder…", 73)
        for obj in self._search_sd("(objectClass=*)", search_base=ash_dn, scope=BASE):
            obj["dn"] = ash_dn  # ensure DN is set
            self._process_object(obj, "ADMIN_SD_HOLDER")
            scanned += 1

        # 3. Users, Groups, Computers
        batches = [
            ("(&(objectCategory=person)(objectClass=user))", "USER",     74),
            ("(objectClass=group)",                          "GROUP",    78),
            ("(objectClass=computer)",                       "COMPUTER", 82),
        ]
        for flt, obj_type, pct in batches:
            if scanned >= self.max_objects:
                self._log(f"ACL: max_objects={self.max_objects} — stopping", pct)
                break
            self._log(f"ACL: {obj_type} objects…", pct)
            for obj in self._search_sd(flt):
                if scanned >= self.max_objects:
                    break
                self._process_object(obj, obj_type)
                scanned += 1

        # 4. OUs
        if scanned < self.max_objects:
            self._log("ACL: OUs…", 85)
            for obj in self._search_sd("(objectClass=organizationalUnit)"):
                if scanned >= self.max_objects:
                    break
                self._process_object(obj, "OU")
                scanned += 1

        # 5. GPO containers
        if scanned < self.max_objects:
            self._log("ACL: GPO containers…", 87)
            gpo_base = f"CN=Policies,CN=System,{self.base_dn}"
            for obj in self._search_sd("(objectClass=groupPolicyContainer)",
                                        search_base=gpo_base):
                if scanned >= self.max_objects:
                    break
                self._process_object(obj, "GPO")
                scanned += 1

        # Emit DCSync edges
        if domain_target_id:
            self._flush_dcsync(domain_target_id)

        n_edges = len(self._edges)
        self._log(f"ACL: scanned {scanned} objects → {n_edges} abuse edges", 89)

        evidence = [{
            "id": "ldap-acls",
            "source_type": "ldap",
            "collection_method": "ldap/acl",
            "origin": "COLLECTED",
            "raw_data": {
                "objects_scanned": scanned,
                "abuse_edges": n_edges,
                "dcsync_principals": len(self._dcsync),
                "unresolved_sids": len(self._placeholders),
            },
            "confidence": 1.0,
        }]

        return self._edges, self._placeholders, evidence
