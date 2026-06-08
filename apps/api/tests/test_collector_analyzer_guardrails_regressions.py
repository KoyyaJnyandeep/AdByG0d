from __future__ import annotations

from adbygod_api.core.analyzers.collector_analyzer import (
    _parse_domain_info,
    _parse_net_accounts,
    _parse_users,
)


def test_native_password_policy_parser_does_not_fabricate_bad_defaults() -> None:
    parsed = _parse_net_accounts("Minimum password length: unavailable\nLockout threshold: ???")
    assert "min_password_length" not in parsed
    assert "lockout_threshold" not in parsed


def test_native_domain_parser_does_not_fabricate_machine_account_quota() -> None:
    parsed = _parse_domain_info("ms-DS-MachineAccountQuota : not-collected")
    assert "machine_account_quota" not in parsed


def test_native_spn_user_is_service_account_and_delegation_is_normalized() -> None:
    output = """
SamAccountName : svc_web
SID : S-1-5-21-1-2-3-1101
Enabled : True
ServicePrincipalName : HTTP/web.lab.local
TrustedToAuthForDelegation : True
msDS-AllowedToDelegateTo : HTTP/sql.lab.local
msDS-SupportedEncryptionTypes : 4
PasswordNeverExpires : True
LastLogonDate : 01/01/2024 12:00:00 AM

"""
    entity = _parse_users(output)[0]
    attrs = entity["attributes"]
    assert entity["entity_type"] == "SERVICE_ACCOUNT"
    assert attrs["constrained_delegation_any_protocol"] is True
    assert attrs["allowed_to_delegate_to"] == ["HTTP/sql.lab.local"]
    assert attrs["rc4_only"] is True
    assert attrs["days_since_last_logon"] > 0
