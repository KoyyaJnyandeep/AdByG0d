from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
COLLECTOR_SRC = ROOT / "collectors" / "linux_remote" / "src"
if str(COLLECTOR_SRC) not in sys.path:
    sys.path.insert(0, str(COLLECTOR_SRC))

from adbygod_collector.modules.enumeration import EnumerationModule
from adbygod_collector.modules.passwords import PasswordModule


class _Entry:
    def __init__(self, **attrs):
        self._attrs = attrs

    def __getattr__(self, name):
        if name in self._attrs:
            return self._attrs[name]
        raise AttributeError(name)

    def __getitem__(self, name):
        return self._attrs.get(name)


class _Reporter:
    def __init__(self):
        self.calls: list[dict] = []
        self.modules_run: list[str] = []

    def add(self, module, severity, title, description, **kwargs):
        self.calls.append({
            "module": module,
            "severity": severity,
            "title": title,
            "description": description,
            **kwargs,
        })


class _PasswordConnector:
    def __init__(self):
        self.requests: list[tuple[str, list[str]]] = []

    def ldap_search(self, search_filter, attributes, **kwargs):
        self.requests.append((search_filter, list(attributes)))
        return [
            _Entry(
                sAMAccountName="WINLAPS01$",
                **{"msLAPS-PasswordExpirationTime": "133431984000000000"},
            ),
            _Entry(sAMAccountName="NOLAPS01$"),
        ]


class _EnumerationConnector:
    base_dn = "DC=lab,DC=local"

    def __init__(self):
        self.requests: list[tuple[str, list[str]]] = []

    def ldap_search(self, search_filter, attributes, **kwargs):
        self.requests.append((search_filter, list(attributes)))
        if search_filter == "(objectCategory=computer)":
            return [
                _Entry(
                    cn="WINLAPS01",
                    operatingSystem="Windows 11",
                    userAccountControl="4096",
                    **{"msLAPS-PasswordExpirationTime": "133431984000000000"},
                ),
                _Entry(cn="NOLAPS01", operatingSystem="Windows 11", userAccountControl="4096"),
            ]
        if "lDAPDisplayName=msLAPS-PasswordExpirationTime" in search_filter:
            return [_Entry(cn="ms-LAPS-Password-Expiration-Time")]
        if "msLAPS-PasswordExpirationTime=*" in search_filter:
            return [_Entry(cn="WINLAPS01")]
        return []


def test_password_module_counts_windows_laps_without_reading_password_values() -> None:
    connector = _PasswordConnector()
    reporter = _Reporter()

    PasswordModule(connector, reporter).check_laps_coverage()

    assert connector.requests
    requested = connector.requests[0][1]
    assert "ms-Mcs-AdmPwd" not in requested
    assert "msLAPS-Password" not in requested
    assert "msLAPS-PasswordExpirationTime" in requested
    assert reporter.calls[0]["details"]["laps_managed"] == 1
    assert reporter.calls[0]["affected"] == ["NOLAPS01$"]


def test_enumeration_module_counts_windows_laps_expiration_metadata() -> None:
    connector = _EnumerationConnector()
    reporter = _Reporter()
    module = EnumerationModule(connector, reporter)

    module.enum_computers()

    assert module.domain_info["total_computers"] == 2
    assert module.domain_info["laps_computers"] == 1
    requested = connector.requests[0][1]
    assert "msLAPS-PasswordExpirationTime" in requested
    assert "ms-Mcs-AdmPwd" not in requested


def test_enumeration_laps_schema_and_deployment_support_windows_laps() -> None:
    connector = _EnumerationConnector()
    reporter = _Reporter()
    module = EnumerationModule(connector, reporter)
    module.domain_info["total_computers"] = 2

    module.enum_laps()

    filters = [search_filter for search_filter, _ in connector.requests]
    assert any("lDAPDisplayName=msLAPS-PasswordExpirationTime" in search_filter for search_filter in filters)
    assert any("msLAPS-PasswordExpirationTime=*" in search_filter for search_filter in filters)
    assert reporter.calls[0]["details"]["LAPS Deployed"] == 1
