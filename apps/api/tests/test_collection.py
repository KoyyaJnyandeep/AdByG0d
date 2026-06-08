from __future__ import annotations

import asyncio
import hashlib

from ldap3.core.exceptions import LDAPAttributeError
from ldap3.utils.ntlm import NtlmClient

from adbygod_api.models import AssessmentStatus
from adbygod_api.routes import collection as collection_routes
from adbygod_api.routes import jobs as job_routes
from adbygod_api.core import crypto_compat
from adbygod_api.core.collection.ldap_collector import LDAPCollector
from adbygod_api.core.pipeline import CommandPlan


def _collection_payload() -> dict:
    return {
        "schema_version": "1.0",
        "tool": "LDAP Collector",
        "collection_mode": "LINUX_REMOTE",
        "domain": "corp.local",
        "dc_ip": "10.0.0.1",
        "collected_at": "live",
        "collector_version": "test",
        "modules_run": ["Directory Inventory"],
        "entities": [],
        "edges": [],
        "evidence": [],
        "findings": [],
        "cert_templates": [],
        "metadata": {},
    }


def test_md4_fallback_supports_ntlm_when_hashlib_disables_md4(monkeypatch):
    original_new = hashlib.new

    def fake_new(name: str, data: bytes = b"", **kwargs):
        if name.lower() == "md4":
            raise ValueError("unsupported hash type MD4")
        return original_new(name, data, **kwargs)

    monkeypatch.setattr(crypto_compat, "_PATCHED", False)
    monkeypatch.setattr(hashlib, "new", fake_new)

    crypto_compat.ensure_hashlib_md4()

    digest = hashlib.new("md4", "Password".encode("utf-16le")).hexdigest()
    assert digest == "a4f49c406510bdcab6824ee7c30fd852"

    response_key = NtlmClient("LAB", "scanner", "Password").ntowf_v2()
    assert response_key.hex() == "8419f0599f06e911aa57605e31337825"


def test_ldap_search_retries_without_schema_unsupported_attributes():
    class Attr:
        def __init__(self, value):
            self.value = value

    class Entry:
        sAMAccountName = Attr("DC01$")

    class FakeConnection:
        def __init__(self):
            self.calls = []
            self.entries = []

        def search(self, **kwargs):
            attrs = kwargs["attributes"]
            self.calls.append(list(attrs))
            if "ms-Mcs-AdmPwdExpirationTime" in attrs:
                raise LDAPAttributeError("invalid attribute type ms-Mcs-AdmPwdExpirationTime")
            self.entries = [Entry()]

    collector = LDAPCollector(dc_ip="10.0.0.1", domain="lab.local")
    collector._conn = FakeConnection()
    collector._base_dn = "DC=lab,DC=local"

    rows = collector._search(
        "(objectClass=computer)",
        ["sAMAccountName", "ms-Mcs-AdmPwdExpirationTime"],
    )

    assert rows == [{"sAMAccountName": "DC01$"}]
    assert collector._conn.calls == [
        ["sAMAccountName", "ms-Mcs-AdmPwdExpirationTime"],
        ["sAMAccountName"],
    ]


def test_ldap_collector_preserves_password_whitespace():
    collector = LDAPCollector(
        dc_ip="10.0.0.1",
        domain="lab.local",
        username="scanner",
        password="  pass with spaces  ",
    )

    assert collector.password == "  pass with spaces  "


def test_remote_obfsc_changes_ldap_query_shape_and_metadata(monkeypatch):
    class FakeConnection:
        def __init__(self):
            self.calls = []

        def search(self, **kwargs):
            self.calls.append(kwargs)
            return True

        @property
        def entries(self):
            return []

    monkeypatch.setattr("time.sleep", lambda _seconds: None)

    plan = CommandPlan(
        obfuscation_enabled=True,
        obfuscation_technique="auto",
        opsec_jitter_ms=250,
        opsec_shuffle_attrs=True,
    )
    collector = LDAPCollector(dc_ip="10.0.0.1", domain="lab.local", pipeline_plan=plan)
    collector._conn = FakeConnection()
    collector._base_dn = "DC=lab,DC=local"

    collector._search("(objectClass=computer)", ["sAMAccountName", "dNSHostName"])

    call = collector._conn.calls[0]
    assert call["search_filter"] == "(&(objectClass=computer)(objectClass=*))"
    assert sorted(call["attributes"]) == ["dNSHostName", "sAMAccountName"]
    assert collector._obfuscation_metadata() == {
        "enabled": True,
        "scope": "remote_ldap",
        "technique": "auto",
        "query_filter_padding": True,
        "attribute_shuffle": True,
        "jitter_ms": 250,
        "note": "ldap3 direct LDAP has no PowerShell surface; OBFSC mutates LDAP query shape and timing.",
    }


def test_collection_route_constructor_and_progress_events(test_app, monkeypatch):
    db = test_app["db"]
    client = test_app["client"]
    user = db.run(db.create_user("collector", "collector@example.invalid", is_superadmin=True))
    assessment = db.run(db.create_assessment("Collect", "corp.local", workspace_id=None))

    class FakeCollector:
        last_kwargs = None

        def __init__(self, **kwargs):
            FakeCollector.last_kwargs = kwargs
            self.kwargs = kwargs
            self.callback = None

        def set_progress_callback(self, callback):
            self.callback = callback

        async def collect(self):
            await asyncio.to_thread(lambda: self.callback("threaded progress", 33, "INFO"))
            return _collection_payload()

    async def fake_process_ingest(assessment_id, payload):
        return None

    monkeypatch.setattr(collection_routes, "LDAPCollector", FakeCollector)
    monkeypatch.setattr(collection_routes, "_process_ingest", fake_process_ingest)

    response = client.post(
        f"/api/v1/collection/ldap/{assessment.id}",
        headers=test_app["headers_for"](user),
        json={
            "dc_ip": "10.0.0.1",
            "domain": "corp.local",
            "username": "user",
            "password": "pass",
            "enum_adcs": False,
            "enum_trusts": False,
            "enum_gpos": False,
            "obfuscation_enabled": True,
            "obfuscation_technique": "auto",
        },
    )
    assert response.status_code in (200, 202)
    body = response.json()
    assert body["stream_token"]

    job = job_routes.get_job(body["job_id"])
    assert job is not None
    drained = list(job.history)
    assert any(event.get("message") == "threaded progress" for event in drained)
    assert FakeCollector.last_kwargs["pipeline_plan"].obfuscation_enabled is True
    assert FakeCollector.last_kwargs["pipeline_plan"].opsec_shuffle_attrs is True
    assert FakeCollector.last_kwargs["pipeline_plan"].opsec_jitter_ms == 250
    assert any("remote LDAP obfuscation active" in event.get("message", "") for event in drained)


def test_ldap_collection_request_validation_rejects_bad_inputs(test_app):
    db = test_app["db"]
    client = test_app["client"]
    user = db.run(db.create_user("collector-validation", "collector-validation@example.invalid", is_superadmin=True))
    assessment = db.run(db.create_assessment("Collect validation", "corp.local", workspace_id=None))
    headers = test_app["headers_for"](user)
    base = {
        "dc_ip": "10.0.0.1",
        "domain": "corp.local",
        "username": "user",
        "password": "pass",
    }

    invalid_cases = [
        {"port": 0},
        {"port": 70000},
        {"acl_max_objects": 50001},
        {"auth_method": "KERBEROS"},
        {"domain": ".corp.local"},
        {"domain": "corp..local"},
        {"password": ""},
    ]

    for override in invalid_cases:
        payload = {**base, **override}
        response = client.post(f"/api/v1/collection/ldap/{assessment.id}", headers=headers, json=payload)
        assert response.status_code == 422, override


def test_collection_enum_flags_skip_optional_modules(monkeypatch):
    collector = LDAPCollector(
        dc_ip="10.0.0.1",
        domain="corp.local",
        username="user",
        password="pass",
        enum_adcs=False,
        enum_trusts=False,
        enum_gpos=False,
    )
    called = {"gpos": 0, "trusts": 0, "adcs": 0}

    monkeypatch.setattr(collector, "_connect", lambda: None)
    monkeypatch.setattr(collector, "_disconnect", lambda: None)
    monkeypatch.setattr(collector, "_emit", lambda *args, **kwargs: None)
    monkeypatch.setattr(collector, "_enum_users", lambda: [])
    monkeypatch.setattr(collector, "_enum_computers", lambda: [])
    monkeypatch.setattr(collector, "_enum_groups", lambda: ([], []))
    monkeypatch.setattr(collector, "_enum_domain_policy", lambda: {})
    monkeypatch.setattr(collector, "_get_krbtgt_password_age", lambda: 0)
    monkeypatch.setattr(collector, "_enum_domain_entity", lambda: None)
    monkeypatch.setattr(collector, "_enum_ous", lambda: [])
    monkeypatch.setattr(collector, "_run_acl_collection", lambda entities: ([], [], []))
    monkeypatch.setattr(collector, "_run_sysvol_scan", lambda: ([], []))
    monkeypatch.setattr(collector, "_enum_gpos", lambda: called.__setitem__("gpos", called["gpos"] + 1) or [])
    monkeypatch.setattr(collector, "_enum_trusts", lambda: called.__setitem__("trusts", called["trusts"] + 1) or [])
    monkeypatch.setattr(collector, "_enum_adcs", lambda: called.__setitem__("adcs", called["adcs"] + 1) or ([], []))

    payload = collector._run_collection()
    assert called == {"gpos": 0, "trusts": 0, "adcs": 0}
    assert payload["metadata"]["enum_flags"]["enum_gpos"] is False
    assert payload["metadata"]["enum_flags"]["enum_trusts"] is False
    assert payload["metadata"]["enum_flags"]["enum_adcs"] is False
    assert "domain_policy" in payload["metadata"]["collected_modules"]
    assert "ous" in payload["metadata"]["collected_modules"]


def test_failed_collection_marks_assessment_failed(test_app, monkeypatch):
    db = test_app["db"]
    client = test_app["client"]
    user = db.run(db.create_user("collector", "collector2@example.invalid", is_superadmin=True))
    assessment = db.run(db.create_assessment("Collect", "corp.local", workspace_id=None))

    class FakeCollector:
        def __init__(self, **kwargs):
            self.callback = None

        def set_progress_callback(self, callback):
            self.callback = callback

        async def collect(self):
            raise RuntimeError("bind failed")

    monkeypatch.setattr(collection_routes, "LDAPCollector", FakeCollector)

    response = client.post(
        f"/api/v1/collection/ldap/{assessment.id}",
        headers=test_app["headers_for"](user),
        json={
            "dc_ip": "10.0.0.1",
            "domain": "corp.local",
            "username": "user",
            "password": "pass",
        },
    )
    assert response.status_code in (200, 202)

    refreshed = db.run(db.get_assessment(assessment.id))
    assert refreshed.status == AssessmentStatus.FAILED
    assert "bind failed" in (refreshed.error_message or "")
