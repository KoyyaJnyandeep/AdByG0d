"""Tests that sensitive values are redacted from outputs."""
from __future__ import annotations


from adbygod_api.core.reports.report_builder import redact_sensitive


class TestRedaction:
    def test_redacts_password_key(self):
        data = {"password": "secret123", "name": "test"}
        result = redact_sensitive(data)
        assert result["password"] == "[REDACTED:SENSITIVE]"
        assert result["name"] == "test"

    def test_redacts_api_key(self):
        data = {"api_key": "sk-proj-abc123xyz", "status": "ok"}
        result = redact_sensitive(data)
        assert result["api_key"] == "[REDACTED:SENSITIVE]"

    def test_redacts_token(self):
        data = {"access_token": "eyJhbGci...", "type": "bearer"}
        result = redact_sensitive(data)
        # "token" is a sensitive key token; access_token contains "token"
        assert result["access_token"] == "[REDACTED:SENSITIVE]"

    def test_redacts_secret_key(self):
        data = {"secret_key": "my-secret", "other": "safe"}
        result = redact_sensitive(data)
        assert result["secret_key"] == "[REDACTED:SENSITIVE]"

    def test_does_not_redact_safe_fields(self):
        data = {"username": "alice", "domain": "corp.local", "status": "active"}
        result = redact_sensitive(data)
        assert result["username"] == "alice"
        assert result["domain"] == "corp.local"

    def test_redacts_nested_password(self):
        data = {"target": {"password": "hunter2", "ip": "10.0.0.1"}}
        result = redact_sensitive(data)
        assert result["target"]["password"] == "[REDACTED:SENSITIVE]"
        assert result["target"]["ip"] == "10.0.0.1"

    def test_redacts_cpassword(self):
        # "cpassword" contains the substring "password" from _SENSITIVE_KEY_TOKENS
        data = {"cpassword": "AES_ENCRYPTED_VALUE"}
        result = redact_sensitive(data)
        assert result["cpassword"] == "[REDACTED:SENSITIVE]"

    def test_redacts_ntlm_hash(self):
        # "ntlm_hash" contains "hash" which is in _SENSITIVE_KEY_TOKENS
        data = {"ntlm_hash": "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0"}
        result = redact_sensitive(data)
        assert result["ntlm_hash"] == "[REDACTED:SENSITIVE]"

    def test_handles_none_values(self):
        data = {"password": None, "name": "test"}
        result = redact_sensitive(data)
        # Key is sensitive so the value (None) is replaced regardless
        assert result is not None
        assert result["password"] == "[REDACTED:SENSITIVE]"

    def test_handles_list_with_sensitive_dicts(self):
        data = [{"password": "secret"}, {"name": "safe"}]
        # redact_sensitive handles dict input; wrapping list in a dict
        result = redact_sensitive({"items": data})
        assert result is not None
        # The list items are redacted at the child level since key "items" is not sensitive
        items = result["items"]
        assert isinstance(items, list)
        assert items[0]["password"] == "[REDACTED:SENSITIVE]"
        assert items[1]["name"] == "safe"

    def test_safe_key_exceptions_not_redacted(self):
        # hash_type, hashcat_mode, etc. are in _SAFE_KEY_EXCEPTIONS
        data = {
            "hash_type": "ntlm",
            "hashcat_mode": 1000,
            "john_format": "nt",
            "evidence_hash": "sha256:abc",
            "policy_hash": "sha256:def",
        }
        result = redact_sensitive(data)
        assert result["hash_type"] == "ntlm"
        assert result["hashcat_mode"] == 1000
        assert result["john_format"] == "nt"
        assert result["evidence_hash"] == "sha256:abc"
        assert result["policy_hash"] == "sha256:def"

    def test_redacts_authorization_header(self):
        data = {"authorization": "Bearer eyJhbGci..."}
        result = redact_sensitive(data)
        assert result["authorization"] == "[REDACTED:SENSITIVE]"

    def test_redacts_cleartext_credential(self):
        data = {"cleartext_password": "P@ssw0rd!"}
        result = redact_sensitive(data)
        assert result["cleartext_password"] == "[REDACTED:SENSITIVE]"

    def test_handles_bytes_value(self):
        # bytes values should be summarised, not crash
        data = {"raw_data": b"\x00\x01\x02\x03"}
        result = redact_sensitive(data)
        assert result is not None
        assert isinstance(result["raw_data"], str)
        assert "BINARY" in result["raw_data"]

    def test_depth_truncation(self):
        # Objects nested beyond depth 4 should be summarised, not crash
        deep = {"a": {"b": {"c": {"d": {"e": "deep_value"}}}}}
        result = redact_sensitive(deep)
        assert result is not None

    def test_large_dict_truncated(self):
        # Dicts with more than 20 keys should include a truncation marker
        data = {f"field_{i}": f"value_{i}" for i in range(25)}
        result = redact_sensitive(data)
        assert "__truncated_keys__" in result
        assert result["__truncated_keys__"] == 5

    def test_large_list_truncated(self):
        # Lists with more than 15 items should include a truncation marker
        data = {"items": list(range(20))}
        result = redact_sensitive(data)
        rendered = result["items"]
        assert len(rendered) == 16  # 15 items + 1 truncation marker string
        assert isinstance(rendered[-1], str)
        assert "TRUNCATED" in rendered[-1]
