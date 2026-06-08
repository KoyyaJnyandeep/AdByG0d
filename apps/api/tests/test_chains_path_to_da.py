import asyncio
import sys
import types

from adbygod_api.core.chains.path_resolver import ALL_PATHS, get_paths_for_situation, resolve_path_to_steps
from adbygod_api.core.workers.impacket_worker import SUPPORTED_TECHNIQUES, ImpacketWorker, _certipy_user, _display_cmd
from adbygod_api.routes import chains as chain_routes
from adbygod_api import models
from adbygod_api.config import settings


def _auth_headers(test_app, username: str = "chain-user") -> dict[str, str]:
    user = test_app["db"].run(
        test_app["db"].create_user(
            username,
            f"{username}@example.test",
            is_superadmin=True,
        )
    )
    return test_app["headers_for"](user)


def test_domain_user_auto_select_uses_curated_viable_path_order():
    paths = get_paths_for_situation("DOMAIN_USER")
    assert paths[0].id == "adcs_esc1_cert_da"
    assert "golden_ticket" != paths[0].id

    steps, _nodes, meta, _graph_paths = resolve_path_to_steps(
        None,
        "192.168.56.10",
        "lab.local",
        {"username": "scanner@lab.local", "password": "secret", "dc_ip": "192.168.56.10"},
        "DOMAIN_USER",
    )

    assert meta[0]["id"] == "adcs_esc1_cert_da"
    assert [step["technique_id"] for step in steps[:3]] == ["certipy_find", "certipy_req", "certipy_auth"]


def test_supported_situations_do_not_default_to_late_stage_golden_ticket():
    assert get_paths_for_situation("ANON")[0].id != "zerologon_cve_2020_1472"
    assert get_paths_for_situation("HASH_ONLY")[0].id == "pth_direct_dcsync"
    assert get_paths_for_situation("TRUST")[0].id == "trust_escalation_extrasid"


def test_chain_endpoint_is_closed_when_feature_flag_is_off(test_app, monkeypatch):
    monkeypatch.setattr(settings, "ENABLE_CHAIN_BUILDER", False)

    response = test_app["client"].get("/api/v1/chains/situations")

    assert response.status_code == 503
    assert response.json()["detail"] == "Under development"


def test_impacket_command_display_redacts_passwords_and_hashes():
    rendered = _display_cmd([
        "impacket-secretsdump",
        "lab.local/scanner@lab.local:Sc@nner-Lab#2026!@192.168.56.10",
        "-hashes",
        ":0123456789abcdef0123456789abcdef",
    ])

    assert "Sc@nner-Lab#2026!" not in rendered
    assert "0123456789abcdef0123456789abcdef" not in rendered
    assert "<redacted>" in rendered
    assert "192.168.56.10" in rendered


def test_certipy_user_normalization_does_not_double_domain_suffix():
    assert _certipy_user("scanner@lab.local", "lab.local") == "scanner@lab.local"
    assert _certipy_user("LAB\\scanner", "lab.local") == "scanner@lab.local"
    assert _certipy_user("scanner", "lab.local") == "scanner@lab.local"


def test_certipy_find_captures_ca_and_vulnerable_template(monkeypatch):
    worker = ImpacketWorker()
    emitted = []
    captured_cmd = {}

    async def fake_capture(cmd, emit, env=None, cwd=None):
        captured_cmd["cmd"] = cmd
        return 0, [
            "    CA Name                             : LAB-DC01-CA",
            "    Template Name                       : ADG0D-ESC1-SupplySAN",
            "      ESC1                              : Enrollee supplies subject and template allows client authentication.",
        ]

    async def emit(data):
        emitted.append(data)

    monkeypatch.setattr(worker, "_stream_subprocess_capture", fake_capture)

    rc = asyncio.run(worker._run_certipy_find("job-1", {
        "target": "192.168.56.10",
        "dc_ip": "192.168.56.10",
        "domain": "lab.local",
        "username": "scanner@lab.local",
        "password": "secret",
    }, emit))

    assert rc == 0
    assert captured_cmd["cmd"][3] == "scanner@lab.local"
    assert any(item.get("loot_type") == "ca_name" and item.get("data") == "LAB-DC01-CA" for item in emitted)
    assert any(item.get("loot_type") == "vulnerable_template" and item.get("data") == "ADG0D-ESC1-SupplySAN" for item in emitted)


def test_certipy_req_treats_certipy_error_output_as_failure(monkeypatch):
    worker = ImpacketWorker()
    emitted = []

    async def fake_capture(cmd, emit, env=None, cwd=None):
        return 0, ["[-] Got error: 'NoneType' object is not subscriptable"]

    async def emit(data):
        emitted.append(data)

    monkeypatch.setattr(worker, "_stream_subprocess_capture", fake_capture)

    rc = asyncio.run(worker._run_certipy_req("job-1", {
        "target": "192.168.56.10",
        "dc_ip": "192.168.56.10",
        "domain": "lab.local",
        "username": "scanner@lab.local",
        "password": "secret",
        "template": "User",
        "upn": "Administrator@lab.local",
    }, emit))

    assert rc == 1
    assert any("Certipy request failed" in item.get("line", "") for item in emitted)


def test_certipy_req_reports_unsupported_template_cleanly(monkeypatch):
    worker = ImpacketWorker()
    emitted = []

    async def fake_capture(cmd, emit, env=None, cwd=None):
        return 0, [
            "[-] Got error while requesting certificate: code: 0x80094800 - CERTSRV_E_UNSUPPORTED_CERT_TYPE - The requested certificate template is not supported by this CA.",
        ]

    async def emit(data):
        emitted.append(data)

    monkeypatch.setattr(worker, "_stream_subprocess_capture", fake_capture)

    rc = asyncio.run(worker._run_certipy_req("job-1", {
        "target": "192.168.56.10",
        "dc_ip": "192.168.56.10",
        "domain": "lab.local",
        "username": "scanner@lab.local",
        "password": "secret",
        "ca": "LAB-DC01-CA",
        "template": "ADG0D-ESC1-SupplySAN",
        "upn": "Administrator@lab.local",
    }, emit))

    assert rc == 1
    assert any("rejected template 'ADG0D-ESC1-SupplySAN' as unsupported" in item.get("line", "") for item in emitted)


def test_certipy_template_uses_v5_flags_and_fails_on_permission_error(monkeypatch):
    worker = ImpacketWorker()
    emitted = []
    captured_cmd = {}

    async def fake_capture(cmd, emit, env=None, cwd=None):
        captured_cmd["cmd"] = cmd
        return 0, ["[-] User 'SCANNER' doesn't have permission to update these attributes"]

    async def emit(data):
        emitted.append(data)

    monkeypatch.setattr(worker, "_stream_subprocess_capture", fake_capture)

    rc = asyncio.run(worker._run_certipy_template("job-1", {
        "domain": "lab.local",
        "username": "scanner@lab.local",
        "password": "secret",
        "dc_ip": "192.168.56.10",
        "template": "ADG0D-ESC4-WeakTemplateACL",
    }, emit))

    assert rc == 1
    assert "-write-default-configuration" in captured_cmd["cmd"]
    assert "-save-old" not in captured_cmd["cmd"]
    assert any("template modification failed" in item.get("line", "") for item in emitted)


def test_every_path_library_technique_has_worker_support():
    technique_ids = {step.technique_id for path in ALL_PATHS for step in path.steps if not step.is_manual}
    assert technique_ids - SUPPORTED_TECHNIQUES == set()


def test_ldap_bind_uses_base_object_probe_not_rootdse_attribute(monkeypatch):
    captured = {}

    class FakeServer:
        def __init__(self, *args, **kwargs):
            pass

    class FakeConnection:
        def __init__(self, *args, **kwargs):
            self.entries = ["base"]

        def search(self, search_base, search_filter, **kwargs):
            captured["search_base"] = search_base
            captured["search_filter"] = search_filter
            captured["kwargs"] = kwargs
            return True

        def unbind(self):
            return True

    monkeypatch.setitem(
        sys.modules,
        "ldap3",
        types.SimpleNamespace(ALL="ALL", Server=FakeServer, Connection=FakeConnection),
    )

    result = chain_routes._ldap_bind_sync(
        "ldap://192.168.56.10:389",
        "scanner@lab.local",
        "secret",
        "DC=lab,DC=local",
    )

    assert result["ok"] is True
    assert captured["search_base"] == "DC=lab,DC=local"
    assert captured["kwargs"]["attributes"] == ["objectClass"]
    assert captured["kwargs"]["search_scope"] == "BASE"


def test_chain_preflight_reports_ports_and_ldap_bind(test_app, monkeypatch):
    async def fake_check_tcp(host: str, port: int, timeout: float = 2.0):
        return port, port != 445, "No route to host" if port == 445 else None

    def fake_ldap_bind(ldap_url: str, username: str, password: str, base_dn: str):
        return {"ok": True, "user": username, "base_dn": base_dn, "entries_seen": 1}

    monkeypatch.setattr(chain_routes, "_check_tcp", fake_check_tcp)
    monkeypatch.setattr(chain_routes, "_ldap_bind_sync", fake_ldap_bind)

    response = test_app["client"].post(
        "/api/v1/chains/preflight",
        headers=_auth_headers(test_app),
        json={
            "target": "192.168.56.10",
            "dc_ip": "192.168.56.10",
            "domain": "lab.local",
            "username": "scanner@lab.local",
            "password": "secret",
            "ports": [389, 445],
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["ok"] is False
    assert body["ports"] == {"389": True, "445": False}
    assert body["ldap_bind"]["ok"] is True
    assert "192.168.56.10:445 unreachable" in body["errors"][0]


def _inaccessible_chain_assessment(test_app):
    db = test_app["db"]

    owner = db.run(
        db.create_user(
            "chain-private-owner",
            "chain-private-owner@example.test",
            is_superadmin=False,
        )
    )
    outsider = db.run(
        db.create_user(
            "chain-private-outsider",
            "chain-private-outsider@example.test",
            is_superadmin=False,
        )
    )

    workspace = db.run(db.create_workspace("Private Chain Workspace"))
    db.run(db.add_workspace_user(workspace.id, owner.id, role="analyst"))

    assessment = db.run(
        db.create_assessment(
            "Private Chain Assessment",
            "private.lab",
            workspace_id=workspace.id,
            created_by=owner.id,
        )
    )

    return outsider, assessment


def _chain_payload(assessment_id: str) -> dict:
    return {
        "assessment_id": assessment_id,
        "target": "192.168.56.10",
        "domain": "private.lab",
        "username": "scanner",
        "password": "secret",
        "dc_ip": "192.168.56.10",
        "situation": "DOMAIN_USER",
    }


def test_chain_resolve_rejects_inaccessible_assessment(test_app):
    outsider, assessment = _inaccessible_chain_assessment(test_app)

    response = test_app["client"].post(
        "/api/v1/chains/resolve",
        headers=test_app["headers_for"](outsider),
        json=_chain_payload(str(assessment.id)),
    )

    assert response.status_code == 403
    assert response.json()["detail"] == "Workspace access denied"


def test_chain_create_rejects_inaccessible_assessment(test_app):
    outsider, assessment = _inaccessible_chain_assessment(test_app)

    response = test_app["client"].post(
        "/api/v1/chains",
        headers=test_app["headers_for"](outsider),
        json=_chain_payload(str(assessment.id)),
    )

    assert response.status_code == 403
    assert response.json()["detail"] == "Workspace access denied"



def _create_attack_chain(test_app, owner, *, steps=None):
    steps = steps or [{"technique_id": "kerberoast", "target": "192.168.56.10", "params": {}}]

    async def _insert():
        async with test_app["session_maker"]() as session:
            chain = models.AttackChain(
                owner_user_id=owner.id,
                name="Execution Gate Test",
                status=models.ChainStatus.PENDING,
                target="192.168.56.10",
                domain="lab.local",
                path_nodes=[],
                steps=steps,
                current_step=0,
                loot={},
                job_ids=[],
                params={"opsec_profile": "BALANCED"},
            )
            session.add(chain)
            await session.commit()
            await session.refresh(chain)
            return chain

    return test_app["db"].run(_insert())


def test_chain_preflight_requires_superadmin(test_app):
    user = test_app["db"].run(
        test_app["db"].create_user(
            "chain-preflight-regular",
            "chain-preflight-regular@example.test",
            is_superadmin=False,
        )
    )

    response = test_app["client"].post(
        "/api/v1/chains/preflight",
        headers=test_app["headers_for"](user),
        json={"target": "192.168.56.10", "ports": [389]},
    )

    assert response.status_code == 403
    assert response.json()["detail"] == "Superadmin access required"


def test_chain_start_requires_superadmin(test_app):
    user = test_app["db"].run(
        test_app["db"].create_user(
            "chain-start-regular",
            "chain-start-regular@example.test",
            is_superadmin=False,
        )
    )
    chain = _create_attack_chain(test_app, user)

    response = test_app["client"].post(
        f"/api/v1/chains/{chain.id}/start",
        headers=test_app["headers_for"](user),
    )

    assert response.status_code == 403
    assert response.json()["detail"] == "Superadmin access required"


def test_chain_start_respects_global_kill_switch(test_app):
    admin = test_app["db"].run(
        test_app["db"].create_user(
            "chain-start-disabled-admin",
            "chain-start-disabled-admin@example.test",
            is_superadmin=True,
        )
    )
    chain = _create_attack_chain(test_app, admin)

    response = test_app["client"].post(
        f"/api/v1/chains/{chain.id}/start",
        headers=test_app["headers_for"](admin),
    )

    assert response.status_code == 403
    assert response.json()["detail"] == "Command execution is disabled by default"


def test_chain_start_requires_allowlisted_steps(test_app, monkeypatch):
    admin = test_app["db"].run(
        test_app["db"].create_user(
            "chain-start-allowlist-admin",
            "chain-start-allowlist-admin@example.test",
            is_superadmin=True,
        )
    )
    chain = _create_attack_chain(test_app, admin)
    monkeypatch.setattr(chain_routes.settings, "ENABLE_COMMAND_EXECUTION", True)
    monkeypatch.setattr(chain_routes.settings, "COMMAND_EXECUTION_ALLOWLIST", "")

    response = test_app["client"].post(
        f"/api/v1/chains/{chain.id}/start",
        headers=test_app["headers_for"](admin),
    )

    assert response.status_code == 403
    assert "not allowlisted" in response.json()["detail"]
