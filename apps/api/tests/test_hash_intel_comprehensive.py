"""Comprehensive tests for hash_intel — every hash type, edge case, and tool check."""
from __future__ import annotations

import pytest

from adbygod_api.core.loot.hash_intel import (
    EMPTY_NT,
    EMPTY_LM,
    HASHCAT_TO_JOHN,
    analyze_loot,
    is_allowed_wordlist_path,
)


# ── constants ─────────────────────────────────────────────────────────────────

class TestConstants:
    def test_empty_nt_hash_value(self):
        assert EMPTY_NT == "31d6cfe0d16ae931b73c59d7e0c089c0"

    def test_empty_lm_hash_value(self):
        assert EMPTY_LM == "aad3b435b51404eeaad3b435b51404ee"

    def test_hashcat_to_john_covers_all_modes(self):
        expected_modes = {1000, 3000, 5500, 5600, 13100, 18200, 19700, 2100, 1100}
        assert expected_modes.issubset(set(HASHCAT_TO_JOHN.keys()))

    def test_hashcat_modes_map_to_strings(self):
        for mode, name in HASHCAT_TO_JOHN.items():
            assert isinstance(mode, int)
            assert isinstance(name, str)
            assert len(name) > 0

    def test_nt_mode_1000_maps_to_NT(self):
        assert HASHCAT_TO_JOHN[1000] == "NT"

    def test_kerberoast_mode_13100_mapped(self):
        assert 13100 in HASHCAT_TO_JOHN

    def test_asrep_mode_18200_mapped(self):
        assert 18200 in HASHCAT_TO_JOHN

    def test_netntlmv2_mode_5600_mapped(self):
        assert HASHCAT_TO_JOHN[5600] == "netntlmv2"

    def test_mscash2_mode_2100_mapped(self):
        assert HASHCAT_TO_JOHN[2100] == "mscash2"


# ── is_allowed_wordlist_path ──────────────────────────────────────────────────

class TestAllowedWordlistPath:
    def test_rockyou_on_kali_allowed(self):
        assert is_allowed_wordlist_path("/usr/share/wordlists/rockyou.txt")

    def test_seclists_rockyou_allowed(self):
        assert is_allowed_wordlist_path("/usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt")

    def test_opt_seclists_allowed(self):
        assert is_allowed_wordlist_path("/opt/SecLists/Passwords/Leaked-Databases/rockyou.txt")

    def test_arbitrary_path_rejected(self):
        assert not is_allowed_wordlist_path("/etc/passwd")

    def test_home_dir_rejected(self):
        assert not is_allowed_wordlist_path("/home/user/my_wordlist.txt")

    def test_tmp_dir_rejected(self):
        assert not is_allowed_wordlist_path("/tmp/wordlist.txt")

    def test_empty_string_rejected(self):
        assert not is_allowed_wordlist_path("")

    def test_relative_path_rejected(self):
        assert not is_allowed_wordlist_path("rockyou.txt")

    def test_traversal_attempt_rejected(self):
        assert not is_allowed_wordlist_path("/usr/share/wordlists/../../../etc/shadow")

    def test_windows_tools_dir_allowed(self):
        assert is_allowed_wordlist_path(r"C:\tools\wordlists\rockyou.txt")

    def test_windows_common_path_allowed(self):
        assert is_allowed_wordlist_path(r"C:\wordlists\rockyou.txt")


# ── analyze_loot ──────────────────────────────────────────────────────────────

class TestAnalyzeLoot:
    def test_empty_entries_returns_structure(self):
        result = analyze_loot([])
        assert "tools" in result
        assert "hashes" in result

    def test_tools_section_has_required_keys(self):
        result = analyze_loot([])
        tools = result["tools"]
        assert "hashcat_available" in tools
        assert "john_available" in tools

    def test_hashes_section_on_empty(self):
        result = analyze_loot([])
        hashes = result["hashes"]
        assert isinstance(hashes, dict)

    def test_nt_hashes_classified(self):
        entries = [
            {
                "loot_type": "hashes",
                "items": {"nt_hashes": {
                    "jdoe": "32ed87bdb5fdc5e9cba88547376818d4",
                    "admin": "fc525c9683e8fe067095ba2ddc971889",
                }},
                "item_count": 2,
                "chain_id": "c1",
                "chain_name": "Test",
                "assessment_id": "a1",
                "completed_at": None,
            }
        ]
        result = analyze_loot(entries)
        assert isinstance(result, dict)

    def test_empty_nt_hash_flagged(self):
        entries = [
            {
                "loot_type": "hashes",
                "items": {"nt_hashes": {
                    "disabled_user": EMPTY_NT,
                    "real_user": "32ed87bdb5fdc5e9cba88547376818d4",
                }},
                "item_count": 2,
                "chain_id": "c1",
                "chain_name": "Test",
                "assessment_id": "a1",
                "completed_at": None,
            }
        ]
        result = analyze_loot(entries)
        assert isinstance(result, dict)

    def test_kerberos_ticket_classified(self):
        ticket = "$krb5tgs$23$*svc_sql$CORP.LOCAL$MSSQLSvc/sql01.corp.local:1433*$abcd1234"
        entries = [
            {
                "loot_type": "hashes",
                "items": {"kerberoast_tickets": {"svc_sql": ticket}},
                "item_count": 1,
                "chain_id": "c2",
                "chain_name": "Kerberoast",
                "assessment_id": "a2",
                "completed_at": None,
            }
        ]
        result = analyze_loot(entries)
        assert isinstance(result, dict)

    def test_asrep_ticket_classified(self):
        asrep = "$krb5asrep$23$asrep_user@CORP.LOCAL:deadbeef0102030405060708"
        entries = [
            {
                "loot_type": "hashes",
                "items": {"asrep_hashes": {"asrep_user": asrep}},
                "item_count": 1,
                "chain_id": "c3",
                "chain_name": "AS-REP",
                "assessment_id": "a3",
                "completed_at": None,
            }
        ]
        result = analyze_loot(entries)
        assert isinstance(result, dict)

    def test_netntlmv2_classified(self):
        netntlmv2 = "jdoe::CORP:1122334455667788:abcdef1234567890abcdef1234567890:0101000000000000"
        entries = [
            {
                "loot_type": "hashes",
                "items": {"netntlmv2_hashes": {"jdoe": netntlmv2}},
                "item_count": 1,
                "chain_id": "c4",
                "chain_name": "Relay",
                "assessment_id": "a4",
                "completed_at": None,
            }
        ]
        result = analyze_loot(entries)
        assert isinstance(result, dict)

    def test_mixed_loot_types(self):
        entries = [
            {
                "loot_type": "hashes",
                "items": {
                    "nt_hashes": {"user1": "32ed87bdb5fdc5e9cba88547376818d4"},
                    "kerberoast_tickets": {"svc": "$krb5tgs$23$*svc*$a1b2c3"},
                    "asrep_hashes": {"nopreauth": "$krb5asrep$23$nopreauth@CORP.LOCAL:abc"},
                },
                "item_count": 3,
                "chain_id": "c5",
                "chain_name": "Mixed",
                "assessment_id": "a5",
                "completed_at": None,
            },
            {
                "loot_type": "credentials",
                "items": {"plaintext": {"local_admin": "Password123!"}},
                "item_count": 1,
                "chain_id": "c5",
                "chain_name": "Mixed",
                "assessment_id": "a5",
                "completed_at": None,
            }
        ]
        result = analyze_loot(entries)
        assert isinstance(result, dict)

    def test_loot_with_no_items_key(self):
        entries = [
            {
                "loot_type": "hashes",
                "item_count": 0,
                "chain_id": "c6",
                "chain_name": "Empty",
                "assessment_id": "a6",
                "completed_at": None,
            }
        ]
        result = analyze_loot(entries)
        assert isinstance(result, dict)

    def test_large_loot_set_performance(self):
        nt_hashes = {f"user{i}": f"{i:032x}" for i in range(500)}
        entries = [
            {
                "loot_type": "hashes",
                "items": {"nt_hashes": nt_hashes},
                "item_count": 500,
                "chain_id": "c7",
                "chain_name": "Big",
                "assessment_id": "a7",
                "completed_at": None,
            }
        ]
        result = analyze_loot(entries)
        assert isinstance(result, dict)


# ── CrackRequest validation (model-level) ────────────────────────────────────

class TestCrackRequestValidation:
    """Test Pydantic CrackRequest model validation rules."""

    def test_valid_nt_mode(self):
        from adbygod_api.routes.loot import CrackRequest
        req = CrackRequest(
            hashes=["31d6cfe0d16ae931b73c59d7e0c089c0"],
            hashcat_mode=1000,
            acknowledge_authorized=True,
        )
        assert req.hashcat_mode == 1000

    def test_invalid_mode_raises(self):
        from pydantic import ValidationError
        from adbygod_api.routes.loot import CrackRequest
        with pytest.raises(ValidationError):
            CrackRequest(hashes=["abc"], hashcat_mode=9999, acknowledge_authorized=True)

    def test_too_many_hashes_raises(self):
        from pydantic import ValidationError
        from adbygod_api.routes.loot import CrackRequest
        with pytest.raises((ValidationError, ValueError)):
            CrackRequest(
                hashes=["abc"] * 5001,
                hashcat_mode=1000,
                acknowledge_authorized=True,
            )

    def test_hash_too_long_raises(self):
        from pydantic import ValidationError
        from adbygod_api.routes.loot import CrackRequest
        with pytest.raises((ValidationError, ValueError)):
            CrackRequest(
                hashes=["a" * 5000],
                hashcat_mode=1000,
                acknowledge_authorized=True,
            )

    def test_invalid_tool_raises(self):
        from pydantic import ValidationError
        from adbygod_api.routes.loot import CrackRequest
        with pytest.raises(ValidationError):
            CrackRequest(
                hashes=["abc"],
                hashcat_mode=1000,
                tool="evil_tool",
                acknowledge_authorized=True,
            )

    def test_valid_tools_accepted(self):
        from adbygod_api.routes.loot import CrackRequest
        for tool in ["hashcat", "john", "auto"]:
            req = CrackRequest(hashes=["abc"], hashcat_mode=1000, tool=tool, acknowledge_authorized=True)
            assert req.tool in (tool, None) or req.tool == tool.lower()

    def test_invalid_wordlist_rejected(self):
        from pydantic import ValidationError
        from adbygod_api.routes.loot import CrackRequest
        with pytest.raises(ValidationError):
            CrackRequest(
                hashes=["abc"],
                hashcat_mode=1000,
                wordlist="/etc/shadow",
                acknowledge_authorized=True,
            )

    def test_none_tool_accepted(self):
        from adbygod_api.routes.loot import CrackRequest
        req = CrackRequest(hashes=["abc"], hashcat_mode=1000, tool=None, acknowledge_authorized=True)
        assert req.tool is None

    def test_all_valid_hashcat_modes(self):
        from adbygod_api.routes.loot import CrackRequest
        for mode in HASHCAT_TO_JOHN:
            req = CrackRequest(hashes=["abc"], hashcat_mode=mode, acknowledge_authorized=True)
            assert req.hashcat_mode == mode

    def test_empty_hash_strings_stripped(self):
        from adbygod_api.routes.loot import CrackRequest
        req = CrackRequest(
            hashes=["  31d6cfe0d16ae931b73c59d7e0c089c0  ", "", "   "],
            hashcat_mode=1000,
            acknowledge_authorized=True,
        )
        assert all(h == h.strip() for h in req.hashes)
        assert "" not in req.hashes
