from __future__ import annotations

import asyncio
import hashlib
import json
from uuid import UUID

import pytest
from sqlalchemy import text

from adbygod_api import config
from adbygod_api.core.connectivity import process_manager
from adbygod_api.core.connectivity.probe import multi_probe
from adbygod_api.core.connectivity.transport import ProxyTransport
from adbygod_api.models import AssessmentStatus, ConnectivityProfile
from adbygod_api.routes import collection as collection_routes


def test_connectivity_profile_crud_redacts_sensitive_config(test_app):
    db = test_app["db"]
    client = test_app["client"]
    user = db.run(db.create_user("netadmin", "netadmin@example.invalid", is_superadmin=True))
    headers = test_app["headers_for"](user)

    create = client.post(
        "/api/v1/connectivity/profiles",
        headers=headers,
        json={
            "name": "Pivot",
            "mode": "CHISEL",
            "config": {
                "server_port": 8080,
                "socks_port": 1080,
                "auth_token": "secret-token",
                "client_cmd": "chisel client secret-token@host",
                "server_pid": 1234,
            },
        },
    )

    assert create.status_code == 201
    created = create.json()
    assert created["config"]["auth_token"] == "***REDACTED***"
    assert created["config"]["client_cmd"] == "***REDACTED***"
    assert created["config"]["server_pid"] == "***REDACTED***"

    profile_id = created["id"]
    get_one = client.get(f"/api/v1/connectivity/profiles/{profile_id}", headers=headers)
    list_all = client.get("/api/v1/connectivity/profiles", headers=headers)
    update = client.patch(
        f"/api/v1/connectivity/profiles/{profile_id}",
        headers=headers,
        json={"config": {"auth_token": "new-token", "client_cmd": "new cmd", "server_pid": 5678}},
    )
    deleted = client.delete(f"/api/v1/connectivity/profiles/{profile_id}", headers=headers)

    assert get_one.json()["config"]["auth_token"] == "***REDACTED***"
    assert list_all.json()[0]["config"]["client_cmd"] == "***REDACTED***"
    assert update.json()["config"]["server_pid"] == "***REDACTED***"
    assert deleted.status_code == 204


def test_redacted_secret_update_preserves_existing_config_and_merges(test_app):
    db = test_app["db"]
    client = test_app["client"]
    user = db.run(db.create_user("secret-editor", "secret-editor@example.invalid", is_superadmin=True))
    headers = test_app["headers_for"](user)

    created = client.post(
        "/api/v1/connectivity/profiles",
        headers=headers,
        json={
            "name": "Chisel",
            "mode": "CHISEL",
            "config": {
                "server_port": 8080,
                "socks_port": 1080,
                "auth_token": "real-secret",
                "target_domain": "lab.local",
                "dc_ip": "192.168.56.10",
            },
        },
    ).json()

    updated = client.patch(
        f"/api/v1/connectivity/profiles/{created['id']}",
        headers=headers,
        json={
            "config": {
                "auth_token": "***REDACTED***",
                "socks_port": 1081,
                "dc_hostname": "dc01.lab.local",
            }
        },
    )

    assert updated.status_code == 200
    assert updated.json()["config"]["auth_token"] == "***REDACTED***"
    assert updated.json()["config"]["socks_port"] == 1081
    assert updated.json()["config"]["target_domain"] == "lab.local"

    async def _load_config():
        async with test_app["session_maker"]() as session:
            profile = await session.get(ConnectivityProfile, UUID(created["id"]))
            return profile.config

    stored = db.run(_load_config())
    assert stored["auth_token"] == "real-secret"
    assert stored["server_port"] == 8080
    assert stored["socks_port"] == 1081
    assert stored["dc_hostname"] == "dc01.lab.local"


def test_chisel_template_uses_token_placeholder_and_clear_removes_secret(test_app):
    db = test_app["db"]
    client = test_app["client"]
    user = db.run(db.create_user("chisel-clear", "chisel-clear@example.invalid", is_superadmin=True))
    headers = test_app["headers_for"](user)

    created = client.post(
        "/api/v1/connectivity/profiles",
        headers=headers,
        json={
            "name": "Chisel",
            "mode": "CHISEL",
            "config": {"server_port": 8080, "socks_port": 1080, "auth_token": "real-secret"},
        },
    ).json()

    from adbygod_api.core.connectivity.process_manager import ChiselServerManager

    mgr = ChiselServerManager(port=8080, socks_port=1080, auth_token="real-secret")
    template = mgr.client_cmd_template()
    assert "<TOKEN>@" in template
    assert "real-secret" not in template

    cleared = client.patch(
        f"/api/v1/connectivity/profiles/{created['id']}",
        headers=headers,
        json={"config": {"auth_token": None}},
    )
    assert cleared.status_code == 200
    assert "auth_token" not in cleared.json()["config"]

    async def _load_config():
        async with test_app["session_maker"]() as session:
            profile = await session.get(ConnectivityProfile, UUID(created["id"]))
            return profile.config

    stored = db.run(_load_config())
    assert "auth_token" not in stored


def test_profile_config_validation_rejects_invalid_mode_fields(test_app):
    db = test_app["db"]
    client = test_app["client"]
    user = db.run(db.create_user("validator", "validator@example.invalid", is_superadmin=True))
    headers = test_app["headers_for"](user)

    bad_socks = client.post(
        "/api/v1/connectivity/profiles",
        headers=headers,
        json={"name": "Bad SOCKS", "mode": "SOCKS5", "config": {"proxy_host": "127.0.0.1", "proxy_port": 70000}},
    )
    bad_cidr = client.post(
        "/api/v1/connectivity/profiles",
        headers=headers,
        json={"name": "Bad CIDR", "mode": "DIRECT", "config": {"target_subnets": ["not-a-cidr"]}},
    )
    bad_relay = client.post(
        "/api/v1/connectivity/profiles",
        headers=headers,
        json={"name": "Bad Relay", "mode": "RELAY_AGENT", "config": {"relay_host": "", "relay_port": 1080}},
    )

    assert bad_socks.status_code == 422
    assert bad_cidr.status_code == 422
    assert bad_relay.status_code == 422


def test_probe_target_restricted_for_non_superadmin(test_app, monkeypatch):
    db = test_app["db"]
    client = test_app["client"]
    user = db.run(db.create_user("probe-user", "probe-user@example.invalid", is_superadmin=False))
    workspace = db.run(db.create_workspace("Probe Workspace"))
    db.run(db.add_workspace_user(workspace.id, user.id, role="analyst"))
    headers = test_app["headers_for"](user)

    profile = client.post(
        "/api/v1/connectivity/profiles",
        headers=headers,
        json={
            "name": "Direct Lab",
            "mode": "DIRECT",
            "config": {
                "dc_ip": "192.168.56.10",
                "dc_hostname": "dc01.lab.local",
                "target_subnets": ["192.168.56.0/24"],
            },
        },
    ).json()

    async def fake_probe(target_host, transport):
        return {
            "success": True,
            "status": "ONLINE",
            "latency_ms": 1,
            "probes": {},
            "capabilities": {"ldap_collection": True},
            "readiness_pct": 25,
            "open_ports": [389],
        }

    monkeypatch.setattr("adbygod_api.routes.connectivity.multi_probe", fake_probe)

    denied = client.post(
        f"/api/v1/connectivity/profiles/{profile['id']}/test",
        headers=headers,
        json={"target_host": "10.0.0.99"},
    )
    allowed_dc = client.post(
        f"/api/v1/connectivity/profiles/{profile['id']}/test",
        headers=headers,
        json={"target_host": "192.168.56.10"},
    )
    allowed_subnet = client.post(
        f"/api/v1/connectivity/profiles/{profile['id']}/test",
        headers=headers,
        json={"target_host": "192.168.56.44"},
    )

    assert denied.status_code == 403
    assert allowed_dc.status_code == 200
    assert allowed_dc.json()["status"] == "ONLINE"
    assert allowed_subnet.status_code == 200


def test_probe_target_blocks_localhost_for_non_superadmin(test_app, monkeypatch):
    db = test_app["db"]
    client = test_app["client"]
    user = db.run(db.create_user("probe-local-user", "probe-local-user@example.invalid", is_superadmin=False))
    workspace = db.run(db.create_workspace("Probe Local Workspace"))
    db.run(db.add_workspace_user(workspace.id, user.id, role="analyst"))
    headers = test_app["headers_for"](user)

    profile = client.post(
        "/api/v1/connectivity/profiles",
        headers=headers,
        json={
            "name": "Direct Wildcard",
            "mode": "DIRECT",
            "config": {"dc_ip": "192.168.56.10", "target_subnets": ["0.0.0.0/0"]},
        },
    ).json()

    async def fake_probe(target_host, transport):
        raise AssertionError("localhost probe must be rejected before multi_probe")

    monkeypatch.setattr("adbygod_api.routes.connectivity.multi_probe", fake_probe)
    denied = client.post(
        f"/api/v1/connectivity/profiles/{profile['id']}/test",
        headers=headers,
        json={"target_host": "127.0.0.1"},
    )
    assert denied.status_code == 403


def test_tunnel_binary_requires_configured_absolute_path_and_sha(tmp_path, monkeypatch):
    binary = tmp_path / "chisel"
    binary.write_bytes(b"fake chisel")
    binary.chmod(0o755)
    digest = hashlib.sha256(binary.read_bytes()).hexdigest()

    monkeypatch.setattr(config.settings, "TUNNEL_MANAGEMENT_BINARY_ALLOWLIST", "chisel")
    monkeypatch.setattr(config.settings, "CHISEL_BINARY_PATH", str(binary))
    monkeypatch.setattr(config.settings, "CHISEL_BINARY_SHA256", digest)

    assert process_manager._verified_binary("chisel") == str(binary)

    monkeypatch.setattr(config.settings, "CHISEL_BINARY_SHA256", "0" * 64)
    with pytest.raises(RuntimeError, match="SHA256 mismatch"):
        process_manager._verified_binary("chisel")

    monkeypatch.setattr(config.settings, "CHISEL_BINARY_PATH", "chisel")
    monkeypatch.setattr(config.settings, "CHISEL_BINARY_SHA256", digest)
    with pytest.raises(RuntimeError, match="absolute"):
        process_manager._verified_binary("chisel")


def test_probe_status_online_degraded_offline(monkeypatch):
    async def fake_tcp_probe(host, port, transport, timeout=3.0):
        if port in fake_tcp_probe.open_ports:
            return {"success": True, "latency_ms": 1, "error": None, "host": host, "port": port}
        return {"success": False, "latency_ms": None, "error": "closed", "host": host, "port": port}

    monkeypatch.setattr("adbygod_api.core.connectivity.probe.tcp_probe", fake_tcp_probe)
    transport = ProxyTransport(mode="DIRECT")

    fake_tcp_probe.open_ports = {389}
    online = asyncio.run(multi_probe("dc.lab.local", transport))
    assert online["status"] == "ONLINE"
    assert online["success"] is True
    assert online["capabilities"]["ldap_collection"] is True

    fake_tcp_probe.open_ports = {88}
    degraded = asyncio.run(multi_probe("dc.lab.local", transport))
    assert degraded["status"] == "DEGRADED"
    assert degraded["success"] is False

    fake_tcp_probe.open_ports = set()
    offline = asyncio.run(multi_probe("dc.lab.local", transport))
    assert offline["status"] == "OFFLINE"
    assert offline["success"] is False


def test_socks_transport_patches_raw_socket_for_ldap3_style_connects():
    import socket

    transport = ProxyTransport(mode="SOCKS5", proxy_host="127.0.0.1", proxy_port=1080)
    original_socket = socket.socket
    original_create_connection = socket.create_connection

    with transport.patched_socket():
        assert socket.socket is not original_socket
        assert socket.create_connection is not original_create_connection

    assert socket.socket is original_socket
    assert socket.create_connection is original_create_connection


def test_assessment_creation_resolves_target_from_connectivity_profile(test_app):
    db = test_app["db"]
    client = test_app["client"]
    user = db.run(db.create_user("creator", "creator@example.invalid", is_superadmin=True))
    headers = test_app["headers_for"](user)

    profile_resp = client.post(
        "/api/v1/connectivity/profiles",
        headers=headers,
        json={
            "name": "Lab SOCKS",
            "mode": "SOCKS5",
            "config": {
                "proxy_host": "127.0.0.1",
                "proxy_port": 1080,
                "target_domain": "lab.local",
                "dc_ip": "192.168.56.10",
                "dc_hostname": "dc01.lab.local",
                "dns_server": "192.168.56.10",
                "base_dn": "DC=lab,DC=local",
                "target_subnets": ["192.168.56.0/24"],
            },
        },
    )
    profile_id = profile_resp.json()["id"]

    assessment_resp = client.post(
        "/api/v1/assessments",
        headers=headers,
        json={
            "name": "Resolved Lab",
            "domain": "placeholder.local",
            "dc_ip": "10.0.0.1",
            "connectivity_profile_id": profile_id,
            "collection_config": {"target": {"username": "scanner"}},
        },
    )

    assert assessment_resp.status_code == 201
    body = assessment_resp.json()
    assert body["domain"] == "lab.local"
    assert body["dc_ip"] == "192.168.56.10"

    loaded = db.run(db.get_assessment(UUID(body["id"])))
    assert loaded.connectivity_profile_id == UUID(profile_id)
    assert loaded.collection_config["resolved_target"]["base_dn"] == "DC=lab,DC=local"
    assert loaded.collection_config["resolved_target"]["transport_mode"] == "SOCKS5"
    assert loaded.collection_config["target"]["username"] == "scanner"


def test_assessment_list_falls_back_to_requested_modules_when_modules_run_empty(test_app):
    db = test_app["db"]
    client = test_app["client"]
    user = db.run(db.create_user("module-card", "module-card@example.invalid", is_superadmin=True))
    headers = test_app["headers_for"](user)

    created = client.post(
        "/api/v1/assessments",
        headers=headers,
        json={
            "name": "Module Card",
            "domain": "lab.local",
            "collection_config": {"modules": ["directory", "adcs"]},
        },
    )
    assert created.status_code == 201
    assert created.json()["modules_run"] == []

    listed = client.get("/api/v1/assessments", headers=headers)
    assert listed.status_code == 200
    row = next(item for item in listed.json() if item["id"] == created.json()["id"])
    assert row["modules_run"] == ["directory", "adcs"]


def test_assessment_list_skips_undecryptable_collection_config(test_app):
    db = test_app["db"]
    client = test_app["client"]
    user = db.run(db.create_user("stale-secret-list", "stale-secret-list@example.invalid", is_superadmin=True))
    headers = test_app["headers_for"](user)

    created = client.post(
        "/api/v1/assessments",
        headers=headers,
        json={
            "name": "Stale Secret",
            "domain": "lab.local",
            "collection_config": {"modules": ["directory"]},
        },
    )
    assert created.status_code == 201
    assessment_id = created.json()["id"]

    async def _corrupt_config():
        async with test_app["session_maker"]() as session:
            await session.execute(
                text("UPDATE assessments SET collection_config = :config WHERE id = :id"),
                {
                    "id": assessment_id,
                    "config": json.dumps({"__adbygod_encrypted_json_v1__": "not-a-valid-fernet-token"}),
                },
            )
            await session.commit()

    db.run(_corrupt_config())

    listed = client.get("/api/v1/assessments", headers=headers)
    assert listed.status_code == 200
    row = next(item for item in listed.json() if item["id"] == assessment_id)
    assert row["modules_run"] == []


def test_assessment_delete_skips_undecryptable_collection_config(test_app):
    db = test_app["db"]
    client = test_app["client"]
    user = db.run(db.create_user("stale-secret-delete", "stale-secret-delete@example.invalid", is_superadmin=True))
    headers = test_app["headers_for"](user)

    created = client.post(
        "/api/v1/assessments",
        headers=headers,
        json={
            "name": "Delete Stale Secret",
            "domain": "lab.local",
            "collection_config": {"modules": ["directory"]},
        },
    )
    assert created.status_code == 201
    assessment_id = created.json()["id"]

    async def _corrupt_config():
        async with test_app["session_maker"]() as session:
            await session.execute(
                text("UPDATE assessments SET collection_config = :config WHERE id = :id"),
                {
                    "id": assessment_id,
                    "config": json.dumps({"__adbygod_encrypted_json_v1__": "not-a-valid-fernet-token"}),
                },
            )
            await session.commit()

    db.run(_corrupt_config())

    deleted = client.delete(f"/api/v1/assessments/{assessment_id}", headers=headers)
    assert deleted.status_code == 204


def test_collection_uses_resolved_profile_target(test_app, monkeypatch):
    db = test_app["db"]
    client = test_app["client"]
    user = db.run(db.create_user("collector-profile", "collector-profile@example.invalid", is_superadmin=True))
    headers = test_app["headers_for"](user)

    profile = client.post(
        "/api/v1/connectivity/profiles",
        headers=headers,
        json={
            "name": "Direct Lab",
            "mode": "DIRECT",
            "config": {"target_domain": "lab.local", "dc_ip": "192.168.56.10"},
        },
    ).json()
    assessment = client.post(
        "/api/v1/assessments",
        headers=headers,
        json={
            "name": "Collect Resolved",
            "domain": "placeholder.local",
            "dc_ip": "10.0.0.1",
            "connectivity_profile_id": profile["id"],
        },
    ).json()

    class FakeCollector:
        last_kwargs = None

        def __init__(self, **kwargs):
            FakeCollector.last_kwargs = kwargs

        def set_progress_callback(self, callback):
            self.callback = callback

        async def collect(self):
            return {
                "schema_version": "1.0",
                "tool": "LDAP Collector",
                "collection_mode": "LINUX_REMOTE",
                "domain": "lab.local",
                "dc_ip": "192.168.56.10",
                "collected_at": "live",
                "collector_version": "test",
                "modules_run": ["Directory Inventory"],
                "entities": [{"id": "domain:lab.local", "entity_type": "DOMAIN"}],
                "edges": [],
                "evidence": [],
                "findings": [],
                "cert_templates": [],
                "metadata": {},
            }

    async def fake_process_ingest(assessment_id, payload, job_id=None):
        return None

    monkeypatch.setattr(collection_routes, "LDAPCollector", FakeCollector)
    monkeypatch.setattr(collection_routes, "_process_ingest", fake_process_ingest)

    response = client.post(
        f"/api/v1/collection/ldap/{assessment['id']}",
        headers=headers,
        json={
            "dc_ip": "10.0.0.1",
            "domain": "placeholder.local",
            "username": "scanner",
            "password": "pass",
        },
    )

    assert response.status_code in (200, 202)
    assert FakeCollector.last_kwargs["dc_ip"] == "192.168.56.10"
    assert FakeCollector.last_kwargs["domain"] == "lab.local"
    loaded = db.run(db.get_assessment(UUID(assessment["id"])))
    assert loaded.status == AssessmentStatus.COMPLETED


def test_connectivity_stats_returns_aggregate(test_app):
    db = test_app["db"]
    client = test_app["client"]
    user = db.run(db.create_user("statsadmin", "stats@example.invalid", is_superadmin=True))
    headers = test_app["headers_for"](user)

    # Create two profiles
    r1 = client.post("/api/v1/connectivity/profiles", headers=headers,
        json={"name": "P1", "mode": "DIRECT", "config": {}})
    r2 = client.post("/api/v1/connectivity/profiles", headers=headers,
        json={"name": "P2", "mode": "SOCKS5", "config": {"proxy_host": "10.0.0.1", "proxy_port": 1080}})
    assert r1.status_code == 201
    assert r2.status_code == 201

    resp = client.get("/api/v1/connectivity/stats", headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] >= 2
    assert "online" in data
    assert "modes_used" in data
    assert isinstance(data["modes_used"], list)


def test_clone_profile_copies_without_sensitive_fields(test_app):
    db = test_app["db"]
    client = test_app["client"]
    user = db.run(db.create_user("cloneadmin", "clone@example.invalid", is_superadmin=True))
    headers = test_app["headers_for"](user)

    create = client.post("/api/v1/connectivity/profiles", headers=headers,
        json={"name": "Original", "mode": "CHISEL", "config": {
            "server_port": 8080, "socks_port": 1080, "auth_token": "secret",
        }})
    assert create.status_code == 201
    pid = create.json()["id"]

    clone = client.post(f"/api/v1/connectivity/profiles/{pid}/clone", headers=headers)
    assert clone.status_code == 201
    c = clone.json()
    assert "(copy)" in c["name"]
    assert c["id"] != pid
    assert c["is_default"] is False
    # auth_token was in SENSITIVE_CONFIG_KEYS so stripped or redacted
    assert "auth_token" not in c["config"] or c["config"]["auth_token"] == "***REDACTED***"


def test_probe_history_accumulates(test_app, monkeypatch):
    """Calling test endpoint twice should store up to 20 history entries."""

    async def _fake_multi_probe(host, transport):
        return {
            "success": True, "status": "ONLINE", "latency_ms": 10,
            "probes": {}, "capabilities": {"ldap_collection": True},
            "readiness_pct": 100, "open_ports": [389],
        }

    monkeypatch.setattr("adbygod_api.routes.connectivity.multi_probe", _fake_multi_probe)

    db = test_app["db"]
    client = test_app["client"]
    user = db.run(db.create_user("histadmin", "hist@example.invalid", is_superadmin=True))
    headers = test_app["headers_for"](user)

    create = client.post("/api/v1/connectivity/profiles", headers=headers,
        json={"name": "HistProf", "mode": "DIRECT", "config": {"dc_ip": "10.0.0.1"}})
    pid = create.json()["id"]

    for _ in range(3):
        r = client.post(f"/api/v1/connectivity/profiles/{pid}/test", headers=headers,
            json={"target_host": "10.0.0.1"})
        assert r.status_code == 200

    prof = client.get(f"/api/v1/connectivity/profiles/{pid}", headers=headers).json()
    history = prof["config"].get("probe_history", [])
    assert len(history) == 3
    assert history[0]["status"] == "ONLINE"
