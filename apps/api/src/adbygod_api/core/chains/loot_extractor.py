"""
Parse raw impacket output lines and extract structured loot:
NT hashes, Kerberos hashes, cleartext passwords, ccache paths, SIDs.
"""
from __future__ import annotations

import logging
import re
from typing import Any

log = logging.getLogger(__name__)

# ─── Regex patterns ────────────────────────────────────────────────────────

# secretsdump: DOMAIN\user:RID:LMhash:NThash:::
_NTLM_RE = re.compile(
    r"^(?P<domain>[^\\:\n]+)\\(?P<user>[^:]+):(?P<rid>\d+):"
    r"(?P<lm>[0-9a-fA-F]{32}):(?P<nt>[0-9a-fA-F]{32}):::",
    re.MULTILINE,
)

# secretsdump: user:CLEARTEXT:password (LSA secrets)
_CLEARTEXT_RE = re.compile(
    r"^(?P<domain>[^\\:\n]+)\\(?P<user>[^:]+):CLEARTEXT:(?P<password>.+)$",
    re.MULTILINE,
)

# secretsdump: $MACHINE.ACC or DPAPI etc
_MACHINE_ACC_RE = re.compile(
    r"^\$(?P<service>[A-Z_\.]+)\.ACC\s*:\s*(?P<hash>[0-9a-fA-F]{32}:[0-9a-fA-F]{32})$",
    re.MULTILINE,
)

# Kerberoast TGS hash
_KRB5TGS_RE = re.compile(
    r"(\$krb5tgs\$\d+\$\*[^\$*]+\*\$[0-9a-fA-F\$]+)",
    re.IGNORECASE,
)

# AS-REP hash
_KRB5ASREP_RE = re.compile(
    r"(\$krb5asrep\$\d+\$[^\s]+)",
    re.IGNORECASE,
)

# ccache file path
_CCACHE_RE = re.compile(
    r"[Ss]aving (?:ticket|TGT|TGS) in\s+(?:file\s+)?['\"]?([^\s'\"]+\.ccache)['\"]?",
)

# Domain SID
_SID_RE = re.compile(
    r"Domain SID[:\s]+(?P<sid>S-\d-\d-\d+(?:-\d+)+)",
    re.IGNORECASE,
)

# krbtgt hash line from dcsync / secretsdump
_KRBTGT_RE = re.compile(
    r"krbtgt[:\\s]+\d+:[0-9a-fA-F]{32}:(?P<nt>[0-9a-fA-F]{32}):::",
    re.IGNORECASE | re.MULTILINE,
)

# Domain admin hash (look for Administrator specifically)
_DA_HASH_RE = re.compile(
    r"(?:Administrator|Admin)[:\\s]+\d+:[0-9a-fA-F]{32}:(?P<nt>[0-9a-fA-F]{32}):::",
    re.IGNORECASE | re.MULTILINE,
)


class LootExtractor:

    def extract(self, output_lines: list[str], technique_id: str) -> dict[str, Any]:
        """
        Parse all output lines for a completed step and return structured loot.
        """
        text = "\n".join(output_lines)
        loot: dict[str, Any] = {"technique": technique_id, "raw_count": len(output_lines)}

        # NT hashes
        nt_hashes = self._extract_nt_hashes(text)
        if nt_hashes:
            loot["nt_hashes"] = nt_hashes
            loot["nt_hash_count"] = len(nt_hashes)
            # Check specifically for DA hash
            da = next((h for h in nt_hashes if str(h.get("user", "")).lower() in ("administrator", "admin")), None)
            if da:
                loot["da_hash"] = f"aad3b435b51404eeaad3b435b51404ee:{da.get('nt', '')}"
                loot["da_user"] = da.get("user", "Administrator")
                loot["da_domain"] = da.get("domain", "")
            # krbtgt
            krbtgt = next((h for h in nt_hashes if str(h.get("user", "")).lower() == "krbtgt"), None)
            if krbtgt:
                loot["krbtgt_hash"] = krbtgt.get("nt", "")

        # Cleartext passwords
        cleartext = self._extract_cleartext(text)
        if cleartext:
            loot["cleartext_creds"] = cleartext

        # Kerberoast hashes
        kerb_hashes = _KRB5TGS_RE.findall(text)
        if kerb_hashes:
            loot["kerberos_hashes"] = kerb_hashes
            loot["kerberos_hash_count"] = len(kerb_hashes)

        # AS-REP hashes
        asrep_hashes = _KRB5ASREP_RE.findall(text)
        if asrep_hashes:
            loot["asrep_hashes"] = asrep_hashes
            loot["asrep_hash_count"] = len(asrep_hashes)

        # ccache tickets
        ccaches = _CCACHE_RE.findall(text)
        if ccaches:
            loot["ccache_tickets"] = ccaches
            loot["ccache_path"] = ccaches[0]

        # Domain SID
        sid_match = _SID_RE.search(text)
        if sid_match:
            loot["domain_sid"] = sid_match.group("sid")

        # krbtgt NT hash (for golden ticket)
        krbtgt_match = _KRBTGT_RE.search(text)
        if krbtgt_match:
            loot["krbtgt_hash"] = krbtgt_match.group("nt")

        return loot

    def _extract_nt_hashes(self, text: str) -> list[dict]:
        hashes = []
        seen = set()
        for m in _NTLM_RE.finditer(text):
            key = f"{m.group('domain')}\\{m.group('user')}"
            if key not in seen:
                seen.add(key)
                hashes.append({
                    "domain": m.group("domain"),
                    "user": m.group("user"),
                    "rid": int(m.group("rid")),
                    "lm": m.group("lm"),
                    "nt": m.group("nt"),
                    "hash": f"aad3b435b51404eeaad3b435b51404ee:{m.group('nt')}",
                })
        return hashes

    def _extract_cleartext(self, text: str) -> list[dict]:
        creds = []
        seen = set()
        for m in _CLEARTEXT_RE.finditer(text):
            key = f"{m.group('domain')}\\{m.group('user')}"
            if key not in seen:
                seen.add(key)
                creds.append({
                    "domain": m.group("domain"),
                    "user": m.group("user"),
                    "password": m.group("password").strip(),
                })
        return creds

    def forward_creds(self, loot: dict, current_params: dict) -> dict:
        """
        Given accumulated loot from previous steps, update params for the next step.
        Priority: DA hash > any NT hash > cleartext > original creds.
        """
        params = dict(current_params)

        # Best case: we have a DA hash
        if loot.get("da_hash"):
            params["hashes"] = loot["da_hash"]
            params["username"] = loot.get("da_user", "Administrator")
            params.pop("password", None)
            log.info("Forwarding DA hash to next step")
            return params

        # NT hash from secretsdump
        nt_hashes = [h for h in loot.get("nt_hashes", []) or [] if isinstance(h, dict)]
        if nt_hashes:
            # Prefer enabled accounts, not machine accounts
            best = next(
                (h for h in nt_hashes
                 if not str(h.get("user", "")).endswith("$") and h.get("nt") != "31d6cfe0d16ae931b73c59d7e0c089c0"),
                None,
            )
            if best:
                params["hashes"] = best.get("hash", "")
                params["username"] = best.get("user", "")
                params.pop("password", None)
                log.info("Forwarding NT hash for %s\\%s", best.get("domain", ""), best.get("user", ""))
                return params

        # Cleartext from LSA
        cleartext = [c for c in loot.get("cleartext_creds", []) or [] if isinstance(c, dict)]
        if cleartext:
            best = cleartext[0]
            params["username"] = best.get("user", "")
            params["password"] = best.get("password", "")
            params.pop("hashes", None)
            log.info("Forwarding cleartext creds for %s\\%s", best.get("domain", ""), best.get("user", ""))

        # ccache ticket
        if loot.get("ccache_path"):
            params["ccache"] = loot["ccache_path"]
            params["use_kerberos"] = "true"

        return params


_extractor = LootExtractor()


def extract_loot(lines: list[str], technique_id: str) -> dict[str, Any]:
    return _extractor.extract(lines, technique_id)


def forward_creds(accumulated_loot: dict, params: dict) -> dict:
    return _extractor.forward_creds(accumulated_loot, params)
