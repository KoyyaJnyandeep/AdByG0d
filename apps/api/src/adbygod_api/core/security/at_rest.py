"""Small at-rest protection helpers for sensitive operational data.

The API still needs plaintext in memory while a scan or chain executes, but
passwords, hashes, loot blobs, and raw offensive output should not sit in the
DB as cleartext.  These helpers provide transparent Fernet wrapping for the
SQLAlchemy TypeDecorators in ``models.py`` and a conservative redactor for API
responses that should never echo stored secrets back to the browser.
"""
from __future__ import annotations

import base64
import hashlib
import json
from functools import lru_cache
from typing import Any

from cryptography.fernet import Fernet, InvalidToken

from adbygod_api.config import settings

_JSON_WRAPPER_KEY = "__adbygod_encrypted_json_v1__"
_TEXT_PREFIX = "adg0d+fernet:v1:"
_REDACTED = "<redacted>"

# Match exact field names and common secret-bearing variants.  This is used for
# browser/API redaction only; DB protection encrypts the whole sensitive JSON
# payload, so a missed redaction key does not mean a missed at-rest encryption.
_SECRET_KEY_PARTS = (
    "password",
    "passwd",
    "secret",
    "token",
    "hash",
    "nthash",
    "lmhash",
    "ccache",
    "ticket",
    "private_key",
    "private-key",
    "pfx",
    "certificate",
    "api_key",
    "api-key",
    "auth_key",
    "credential",
)


def _secret_material() -> str:
    secret = (settings.SECRET_KEY or "").strip()
    if not secret:
        raise RuntimeError("SECRET_KEY must be configured before sensitive data can be persisted")
    return secret


@lru_cache(maxsize=16)
def _fernet_for_secret(secret: str) -> Fernet:
    digest = hashlib.sha256(secret.encode("utf-8")).digest()
    key = base64.urlsafe_b64encode(digest)
    return Fernet(key)


def _fernet() -> Fernet:
    return _fernet_for_secret(_secret_material())


def protect_json_for_db(value: Any) -> Any:
    """Encrypt a whole JSON value while keeping the DB column JSON-typed.

    Legacy plaintext rows are accepted on reads and get protected the next time
    they are written.  Values already in the wrapper form are preserved so bulk
    migrations can safely be re-run.
    """
    if value is None:
        return None
    if isinstance(value, dict) and isinstance(value.get(_JSON_WRAPPER_KEY), str):
        return value
    serialized = json.dumps(value, separators=(",", ":"), sort_keys=True, ensure_ascii=False, default=str)
    token = _fernet().encrypt(serialized.encode("utf-8")).decode("ascii")
    return {_JSON_WRAPPER_KEY: token}


def reveal_json_from_db(value: Any) -> Any:
    if not isinstance(value, dict):
        return value
    token = value.get(_JSON_WRAPPER_KEY)
    if not isinstance(token, str):
        return value
    try:
        plaintext = _fernet().decrypt(token.encode("ascii"))
    except (InvalidToken, ValueError, TypeError) as exc:
        raise RuntimeError("Encrypted JSON payload could not be decrypted; verify SECRET_KEY consistency") from exc
    try:
        return json.loads(plaintext.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError("Encrypted JSON payload is corrupted") from exc


def protect_text_for_db(value: Any) -> Any:
    if value is None:
        return None
    text = str(value)
    if text.startswith(_TEXT_PREFIX):
        return text
    token = _fernet().encrypt(text.encode("utf-8")).decode("ascii")
    return f"{_TEXT_PREFIX}{token}"


def reveal_text_from_db(value: Any) -> Any:
    if value is None:
        return None
    text = str(value)
    if not text.startswith(_TEXT_PREFIX):
        return text
    token = text[len(_TEXT_PREFIX):]
    try:
        return _fernet().decrypt(token.encode("ascii")).decode("utf-8")
    except (InvalidToken, ValueError, TypeError, UnicodeDecodeError) as exc:
        raise RuntimeError("Encrypted text payload could not be decrypted; verify SECRET_KEY consistency") from exc


def _looks_secret_key(key: str) -> bool:
    lowered = key.strip().lower()
    normalized = lowered.replace("-", "_")
    return any(part in lowered or part.replace("-", "_") in normalized for part in _SECRET_KEY_PARTS)


def redact_sensitive_mapping(value: Any, *, replacement: str = _REDACTED) -> Any:
    """Recursively remove secret-looking values from a response payload."""
    if isinstance(value, dict):
        redacted: dict[Any, Any] = {}
        for key, item in value.items():
            key_text = str(key)
            if _looks_secret_key(key_text) and item not in (None, "", [], {}):
                redacted[key] = replacement
            else:
                redacted[key] = redact_sensitive_mapping(item, replacement=replacement)
        return redacted
    if isinstance(value, list):
        return [redact_sensitive_mapping(item, replacement=replacement) for item in value]
    if isinstance(value, tuple):
        return tuple(redact_sensitive_mapping(item, replacement=replacement) for item in value)
    return value


__all__ = [
    "protect_json_for_db",
    "reveal_json_from_db",
    "protect_text_for_db",
    "reveal_text_from_db",
    "redact_sensitive_mapping",
]
