from __future__ import annotations

_EXPECTED_DCSYNC_NAMES = frozenset({
    "domain controllers",
    "enterprise domain controllers",
    "domain admins",
    "enterprise admins",
    "schema admins",
    "administrators",
    "replicator",
})
_SYNC_LIKE_PATTERNS = (
    "adsync",
    "aadsync",
    "azure_sync",
    "azuread_",
    "msol_",
    "aad_",
    "dirsync",
)


def classify_dcsync_principal(meta: dict | None) -> str:
    """Classify a DCSync edge source as expected, sync-like, or suspicious."""
    principal = meta or {}
    entity_type = str(
        principal.get("type") or principal.get("entity_type") or ""
    ).upper()
    if entity_type == "DC":
        return "expected"

    attrs = principal.get("attributes") or {}
    raw_name = str(
        principal.get("sam_account_name")
        or principal.get("display_name")
        or ""
    ).strip().lower()
    candidate_names = {
        raw_name,
        raw_name.split("@", 1)[0],
        raw_name.rsplit("\\", 1)[-1],
    }
    if candidate_names & _EXPECTED_DCSYNC_NAMES:
        return "expected"

    sid = str(
        principal.get("object_sid") or attrs.get("object_sid") or ""
    ).strip().lower()
    if sid == "s-1-5-9" or sid.startswith("s-1-5-32-"):
        return "expected"

    if any(pattern in raw_name for pattern in _SYNC_LIKE_PATTERNS):
        return "sync_like"

    return "suspicious"
