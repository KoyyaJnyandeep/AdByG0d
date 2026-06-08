from __future__ import annotations

import io
import json
import zipfile

import pytest


def _make_collector_zip(manifest_override: dict | None = None, extra_files: dict | None = None) -> bytes:
    manifest = {
        "version": "1.0",
        "generator": "AdByGod-Native-Collector",
        "domain": "corp.local",
        "dc_ip": "10.0.0.1",
        "collected_at": "2026-05-08T12:00:00+00:00",
        "modules": ["enum", "topology"],
    }
    if manifest_override:
        manifest.update(manifest_override)

    enum_data = {
        "module_id": "enum",
        "commands": [
            {"id": "net-user-domain", "title": "List domain users", "output": "Administrator", "error": None, "duration_ms": 42},
        ],
    }

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("manifest.json", json.dumps(manifest))
        zf.writestr("enum.json", json.dumps(enum_data))
        if extra_files:
            for name, content in extra_files.items():
                zf.writestr(name, content)
    buf.seek(0)
    return buf.read()


def test_make_collector_zip_is_valid():
    data = _make_collector_zip()
    zf = zipfile.ZipFile(io.BytesIO(data))
    assert "manifest.json" in zf.namelist()
    manifest = json.loads(zf.read("manifest.json"))
    assert manifest["generator"] == "AdByGod-Native-Collector"


def test_parse_collector_zip_extracts_manifest_and_modules():
    from adbygod_api.routes.import_data import _parse_collector_zip

    data = _make_collector_zip()
    manifest, modules = _parse_collector_zip(data)

    assert manifest["domain"] == "corp.local"
    assert manifest["generator"] == "AdByGod-Native-Collector"
    assert "enum" in modules
    assert modules["enum"]["module_id"] == "enum"
    assert len(modules["enum"]["commands"]) == 1


def test_parse_collector_zip_rejects_missing_manifest():
    from adbygod_api.routes.import_data import _parse_collector_zip

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("enum.json", "{}")
    with pytest.raises(ValueError, match="manifest.json"):
        _parse_collector_zip(buf.getvalue())


def test_parse_collector_zip_rejects_wrong_generator():
    from adbygod_api.routes.import_data import _parse_collector_zip

    data = _make_collector_zip(manifest_override={"generator": "SharpHound"})
    with pytest.raises(ValueError, match="AdByGod-Native-Collector"):
        _parse_collector_zip(data)


def test_parse_collector_zip_skips_manifest_in_module_dict():
    from adbygod_api.routes.import_data import _parse_collector_zip

    data = _make_collector_zip()
    _, modules = _parse_collector_zip(data)
    assert "manifest" not in modules


def test_parse_collector_zip_rejects_path_traversal_entries():
    from adbygod_api.routes.import_data import _parse_collector_zip

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("manifest.json", json.dumps({
            "version": "1.0",
            "generator": "AdByGod-Native-Collector",
            "domain": "corp.local",
            "modules": ["enum"],
        }))
        zf.writestr("../../evil.json", json.dumps({"module_id": "evil"}))
        zf.writestr("enum.json", json.dumps({"module_id": "enum", "commands": []}))
    with pytest.raises(ValueError, match="unsafe path"):
        _parse_collector_zip(buf.getvalue())


def test_collector_analyzer_uses_high_fidelity_windows_zip_fields():
    from adbygod_api.core.analyzers.collector_analyzer import build_rule_data_from_collector

    modules = {
        "enum": {
            "module_id": "enum",
            "commands": [
                {
                    "id": "get-aduser-all",
                    "output": """
SamAccountName              : svc_sql
SID                         : S-1-5-21-1-2-3-1101
Name                        : SQL Service
Enabled                     : True
AdminCount                  : 1
ServicePrincipalName        : MSSQLSvc/sql.lab.local:1433
UserAccountControl          : 4260384
PasswordNeverExpires        : True
DoesNotRequirePreAuth       : True
TrustedForDelegation        : False
TrustedToAuthForDelegation  : False
DistinguishedName           : CN=svc_sql,CN=Users,DC=lab,DC=local
msDS-SupportedEncryptionTypes : 0

SamAccountName              : bob
SID                         : S-1-5-21-1-2-3-1102
Name                        : Bob
Enabled                     : True
AdminCount                  : 0
UserAccountControl          : 32
DistinguishedName           : CN=bob,CN=Users,DC=lab,DC=local
""",
                },
                {
                    "id": "get-adcomputer-all",
                    "output": """
Name                        : APP01
SamAccountName              : APP01$
SID                         : S-1-5-21-1-2-3-2101
Enabled                     : True
DNSHostName                 : app01.lab.local
UserAccountControl          : 528384
DistinguishedName           : CN=APP01,CN=Computers,DC=lab,DC=local
ms-Mcs-AdmPwdExpirationTime : 

Name                        : DC01
SamAccountName              : DC01$
SID                         : S-1-5-21-1-2-3-1000
Enabled                     : True
DNSHostName                 : dc01.lab.local
UserAccountControl          : 532480
DistinguishedName           : OU=Domain Controllers,DC=lab,DC=local
ms-Mcs-AdmPwdExpirationTime : 133431984000000000
""",
                },
                {
                    "id": "get-addomain",
                    "output": """
DNSRoot                     : lab.local
NetBIOSName                 : LAB
DomainMode                  : Windows2016Domain
ms-DS-MachineAccountQuota   : 10
""",
                },
                {
                    "id": "get-adtrust",
                    "output": """
Name                        : legacy.local
TrustType                   : External
Direction                   : Bidirectional
SIDFilteringQuarantined     : False
TrustAttributes             : 0
""",
                },
            ],
        },
        "exposure_quick_checks": {
            "module_id": "exposure_quick_checks",
            "commands": [
                {
                    "id": "quick-reg-smb-signing",
                    "output": "RequireSecuritySignature    REG_DWORD    0x0",
                },
                {
                    "id": "quick-reg-ldap-signing",
                    "output": "LDAPServerIntegrity    REG_DWORD    0x1",
                },
                {
                    "id": "quick-reg-ldap-channel-binding",
                    "output": "LdapEnforceChannelBinding    REG_DWORD    0x0",
                },
                {
                    "id": "quick-reg-lmcompat",
                    "output": "LmCompatibilityLevel    REG_DWORD    0x3",
                },
                {
                    "id": "quick-winrm-service",
                    "output": "Service\n    AllowUnencrypted = false\n    Auth\n        Basic = false",
                },
            ],
        },
    }

    data = build_rule_data_from_collector(modules)

    svc = next(e for e in data["entities"] if e["sam_account_name"] == "svc_sql")
    bob = next(e for e in data["entities"] if e["sam_account_name"] == "bob")
    app = next(e for e in data["entities"] if e["sam_account_name"] == "APP01$")

    assert svc["is_admin_count"] is True
    assert svc["attributes"]["has_spn"] is True
    assert svc["attributes"]["uac_dont_require_preauth"] is True
    assert svc["attributes"]["pwd_never_expires"] is True
    assert bob["attributes"]["uac_passwd_notreqd"] is True
    assert app["attributes"]["uac_trusted_for_delegation"] is True
    assert data["domain_info"]["machine_account_quota"] == 10
    assert data["domain_info"]["laps_deployed"] is True
    assert data["domain_info"]["laps_coverage_pct"] == 50
    assert data["trusts"][0]["sid_filtering_enabled"] is False
    assert data["network_config"]["smb_signing_required"] is False
    assert data["network_config"]["ldap_signing"] == "disabled"
    assert data["network_config"]["ldap_channel_binding"] is False
    assert data["network_config"]["ntlm_lm_compat_level"] == 3
    assert data["network_config"]["winrm_open"] is True


def test_collector_rule_data_to_ingest_passes_through_evidence_and_findings():
    """Evidence and findings from rule_data must not be silently dropped."""
    from adbygod_api.routes.import_data import _collector_rule_data_to_ingest

    manifest = {
        "version": "1.0",
        "generator": "AdByGod-Native-Collector",
        "domain": "corp.local",
        "dc_ip": "10.0.0.1",
        "collected_at": "2026-05-08T12:00:00+00:00",
        "modules": ["enum"],
    }
    rule_data = {
        "entities": [],
        "edges": [],
        "evidence": [{"id": "ev-1", "source_type": "ldap", "confidence": 0.9}],
        "findings": [{"id": "fi-1", "title": "Test finding", "severity": "HIGH"}],
        "cert_templates": [],
        "ca_flags": [],
    }

    result = _collector_rule_data_to_ingest(manifest, ["enum"], rule_data)

    assert len(result.evidence) == 1, "evidence must be passed through, not dropped"
    assert result.evidence[0]["id"] == "ev-1"
    assert len(result.findings) == 1, "findings must be passed through, not dropped"
    assert result.findings[0]["id"] == "fi-1"
