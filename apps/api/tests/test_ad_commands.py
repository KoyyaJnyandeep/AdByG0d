from __future__ import annotations

import json
from importlib import reload

from adbygod_api.data.ad_commands import AD_COMMANDS
import adbygod_api.data.ad_commands as ad_commands_data
from adbygod_api.routes import ad_commands as routes
import adbygod_api.services.command_execution as cmd_svc


def _auth_headers(test_app, username: str = "adcmd-user", *, is_superadmin: bool = False) -> dict[str, str]:
    db = test_app["db"]
    user = db.run(db.create_user(username, f"{username}@example.invalid", is_superadmin=is_superadmin))
    return test_app["headers_for"](user)


def test_category_counts_include_linux_and_both_platforms(test_app, monkeypatch):
    monkeypatch.setattr(routes, "AD_CATEGORIES", ["Test"])
    monkeypatch.setattr(routes, "AD_CATEGORY_DESCRIPTIONS", {"Test": "desc"})
    monkeypatch.setattr(
        routes,
        "AD_COMMANDS",
        [
            {
                "id": "linux-tech",
                "category": "Test",
                "title": "Linux",
                "tool": "bloodhound-python",
                "platform": "linux",
                "executable_on_linux": False,
                "description": "",
                "commands": [],
            },
            {
                "id": "both-tech",
                "category": "Test",
                "title": "Both",
                "tool": "openssl",
                "platform": "both",
                "executable_on_linux": False,
                "description": "",
                "commands": [],
            },
            {
                "id": "win-tech",
                "category": "Test",
                "title": "Windows",
                "tool": "powerview",
                "platform": "windows",
                "executable_on_linux": False,
                "description": "",
                "commands": [],
            },
        ],
    )

    response = test_app["client"].get(
        "/api/v1/ad-commands/categories",
        headers=_auth_headers(test_app),
    )

    assert response.status_code == 200
    assert response.json()[0]["linux_executable_count"] == 2


def test_legacy_list_endpoint_returns_requested_techniques_in_order(test_app, monkeypatch):
    monkeypatch.setattr(
        routes,
        "AD_COMMANDS",
        [
            {
                "id": "one",
                "category": "Test",
                "title": "One",
                "tool": "ldapsearch",
                "platform": "linux",
                "executable_on_linux": True,
                "description": "first",
                "commands": [],
            },
            {
                "id": "two",
                "category": "Test",
                "title": "Two",
                "tool": "nmap",
                "platform": "linux",
                "executable_on_linux": True,
                "description": "second",
                "commands": [],
            },
        ],
    )

    response = test_app["client"].get(
        "/api/v1/ad-commands/list",
        params={"ids": "two,missing,one"},
        headers=_auth_headers(test_app, "legacy-list-user"),
    )

    assert response.status_code == 200
    assert [item["id"] for item in response.json()] == ["two", "one"]


def test_execute_rejects_negative_command_index(test_app, monkeypatch):
    monkeypatch.setattr(routes.settings, "ENABLE_COMMAND_EXECUTION", True)
    monkeypatch.setattr(routes.settings, "COMMAND_EXECUTION_ALLOWLIST", "linux-tech")
    monkeypatch.setattr(routes.shutil, "which", lambda binary: f"/usr/bin/{binary}")
    monkeypatch.setattr(
        routes,
        "AD_COMMANDS",
        [
            {
                "id": "linux-tech",
                "category": "Test",
                "title": "Linux",
                "tool": "bloodhound-python",
                "platform": "linux",
                "executable_on_linux": True,
                "description": "",
                "commands": [{"label": "One", "command": "echo ok", "params": []}],
            }
        ],
    )

    response = test_app["client"].post(
        "/api/v1/ad-commands/execute/linux-tech",
        headers=_auth_headers(test_app, "negative-index-user", is_superadmin=True),
        json={"command_index": -1, "params": {}},
    )

    assert response.status_code == 400
    assert "out of range" in response.json()["detail"]


def test_execute_is_disabled_by_default(test_app, monkeypatch):
    monkeypatch.setattr(routes.settings, "ENABLE_COMMAND_EXECUTION", False)
    monkeypatch.setattr(routes.settings, "COMMAND_EXECUTION_ALLOWLIST", "linux-tech")
    monkeypatch.setattr(
        routes,
        "AD_COMMANDS",
        [
            {
                "id": "linux-tech",
                "category": "Test",
                "title": "Linux",
                "tool": "openssl",
                "platform": "linux",
                "executable_on_linux": True,
                "description": "",
                "commands": [{"label": "Echo", "command": "echo ok", "params": []}],
            }
        ],
    )

    response = test_app["client"].post(
        "/api/v1/ad-commands/execute/linux-tech",
        headers=_auth_headers(test_app, "disabled-user", is_superadmin=True),
        json={"command_index": 0, "params": {}},
    )

    assert response.status_code == 403
    assert response.json()["detail"] == "Command execution is disabled by default"


def test_execute_requires_allowlisted_technique(test_app, monkeypatch):
    monkeypatch.setattr(routes.settings, "ENABLE_COMMAND_EXECUTION", True)
    monkeypatch.setattr(routes.settings, "COMMAND_EXECUTION_ALLOWLIST", "")
    monkeypatch.setattr(
        routes,
        "AD_COMMANDS",
        [
            {
                "id": "linux-tech",
                "category": "Test",
                "title": "Linux",
                "tool": "openssl",
                "platform": "linux",
                "executable_on_linux": True,
                "description": "",
                "commands": [{"label": "Echo", "command": "echo ok", "params": []}],
            }
        ],
    )

    response = test_app["client"].post(
        "/api/v1/ad-commands/execute/linux-tech",
        headers=_auth_headers(test_app, "allowlist-user", is_superadmin=True),
        json={"command_index": 0, "params": {}},
    )

    assert response.status_code == 403
    assert response.json()["detail"] == "Technique is not allowlisted for execution"


def test_execute_requires_superadmin(test_app, monkeypatch):
    monkeypatch.setattr(routes.settings, "ENABLE_COMMAND_EXECUTION", True)
    monkeypatch.setattr(routes.settings, "COMMAND_EXECUTION_ALLOWLIST", "linux-tech")
    monkeypatch.setattr(
        routes,
        "AD_COMMANDS",
        [
            {
                "id": "linux-tech",
                "category": "Test",
                "title": "Linux",
                "tool": "openssl",
                "platform": "linux",
                "executable_on_linux": True,
                "description": "",
                "commands": [{"label": "Echo", "command": "echo ok", "params": []}],
            }
        ],
    )

    response = test_app["client"].post(
        "/api/v1/ad-commands/execute/linux-tech",
        headers=_auth_headers(test_app, "regular-user", is_superadmin=False),
        json={"command_index": 0, "params": {}},
    )

    assert response.status_code == 403


def test_execute_uses_structured_argv_and_redacts_sensitive_params(test_app, monkeypatch):
    captured: dict[str, object] = {}

    class FakeProc:
        returncode = 0

        async def communicate(self):
            return b"ok", b""

    async def fake_exec(*argv, stdout=None, stderr=None):
        captured["argv"] = list(argv)
        return FakeProc()

    monkeypatch.setattr(routes.settings, "ENABLE_COMMAND_EXECUTION", True)
    monkeypatch.setattr(routes.settings, "COMMAND_EXECUTION_ALLOWLIST", "linux-tech")
    monkeypatch.setattr(
        routes,
        "AD_COMMANDS",
        [
            {
                "id": "linux-tech",
                "category": "Test",
                "title": "Linux",
                "tool": "openssl",
                "platform": "linux",
                "executable_on_linux": True,
                "description": "",
                "commands": [{"label": "Echo", "command": "echo {Value} {Password}", "params": ["Value", "Password"]}],
            }
        ],
    )
    monkeypatch.setattr(cmd_svc.asyncio, "create_subprocess_exec", fake_exec)
    monkeypatch.setattr(routes.shutil, "which", lambda binary: f"/usr/bin/{binary}")
    monkeypatch.setattr(cmd_svc.shutil, "which", lambda binary: f"/usr/bin/{binary}")
    monkeypatch.setattr(cmd_svc, "AD_COMMANDS", routes.AD_COMMANDS)

    response = test_app["client"].post(
        "/api/v1/ad-commands/execute/linux-tech",
        headers=_auth_headers(test_app, "structured-argv-user", is_superadmin=True),
        json={"command_index": 0, "params": {"Value": "foo;touch /tmp/pwned", "Password": "hunter2"}},
    )

    assert response.status_code == 200
    assert captured["argv"] == ["echo", "foo;touch /tmp/pwned", "hunter2"]
    assert response.json()["execution_mode"] == "argv"
    assert response.json()["rendered_command"].startswith("echo ")
    assert "hunter2" not in response.json()["rendered_command"]
    assert "[REDACTED]" in response.json()["rendered_command"]


def test_execute_uses_case_insensitive_tool_lookup(test_app, monkeypatch):
    class FakeProc:
        returncode = 0

        async def communicate(self):
            return b"ok", b""

    async def fake_exec(*argv, stdout=None, stderr=None):
        return FakeProc()

    seen: list[str] = []

    def fake_which(binary: str):
        seen.append(binary)
        if binary in {"GetUserSPNs.py", "echo"}:
            return f"/usr/bin/{binary}"
        return None

    monkeypatch.setattr(
        routes,
        "AD_COMMANDS",
        [
            {
                "id": "linux-tech",
                "category": "Test",
                "title": "Linux",
                "tool": "Impacket-GetUserSPNs",
                "platform": "linux",
                "executable_on_linux": True,
                "description": "",
                "commands": [{"label": "Echo", "command": "echo ok", "params": []}],
            }
        ],
    )
    monkeypatch.setattr(routes.settings, "ENABLE_COMMAND_EXECUTION", True)
    monkeypatch.setattr(routes.settings, "COMMAND_EXECUTION_ALLOWLIST", "linux-tech")
    monkeypatch.setattr(cmd_svc.asyncio, "create_subprocess_exec", fake_exec)
    monkeypatch.setattr(routes.shutil, "which", fake_which)
    monkeypatch.setattr(cmd_svc.shutil, "which", fake_which)
    monkeypatch.setattr(cmd_svc, "AD_COMMANDS", routes.AD_COMMANDS)

    response = test_app["client"].post(
        "/api/v1/ad-commands/execute/linux-tech",
        headers=_auth_headers(test_app, "tool-lookup-user", is_superadmin=True),
        json={"command_index": 0, "params": {}},
    )

    assert response.status_code == 200
    assert response.json()["tool_available"] is True
    assert "echo" in seen


def test_catalog_listing_includes_execution_mode(test_app, monkeypatch):
    monkeypatch.setattr(routes.settings, "ENABLE_COMMAND_EXECUTION", False)
    monkeypatch.setattr(
        routes,
        "AD_COMMANDS",
        [
            {
                "id": "linux-tech",
                "category": "Test",
                "title": "Linux",
                "tool": "echo",
                "platform": "linux",
                "executable_on_linux": True,
                "description": "",
                "commands": [
                    {"label": "safe", "command": "echo ok", "params": []},
                    {"label": "manual", "command": "echo ok | tee out", "params": []},
                ],
            }
        ],
    )

    response = test_app["client"].get(
        "/api/v1/ad-commands/techniques/linux-tech",
        headers=_auth_headers(test_app, "catalog-mode-user", is_superadmin=True),
    )

    assert response.status_code == 200
    commands = response.json()["commands"]
    assert commands[0]["execution_mode"] == "argv"
    assert commands[1]["execution_mode"] == "manual"


def test_execute_rejects_manual_only_command(test_app, monkeypatch):
    monkeypatch.setattr(routes.settings, "ENABLE_COMMAND_EXECUTION", True)
    monkeypatch.setattr(routes.settings, "COMMAND_EXECUTION_ALLOWLIST", "linux-tech")
    monkeypatch.setattr(routes.shutil, "which", lambda binary: f"/usr/bin/{binary}")
    monkeypatch.setattr(
        routes,
        "AD_COMMANDS",
        [
            {
                "id": "linux-tech",
                "category": "Test",
                "title": "Linux",
                "tool": "echo",
                "platform": "linux",
                "executable_on_linux": True,
                "description": "",
                "commands": [{"label": "Manual", "command": "echo ok | tee out", "params": []}],
            }
        ],
    )

    response = test_app["client"].post(
        "/api/v1/ad-commands/execute/linux-tech",
        headers=_auth_headers(test_app, "manual-only-user", is_superadmin=True),
        json={"command_index": 0, "params": {}},
    )

    assert response.status_code == 400
    assert "manual-only" in response.json()["detail"]


def test_execute_validates_actual_argv0_not_logical_tool(test_app, monkeypatch):
    monkeypatch.setattr(routes.settings, "ENABLE_COMMAND_EXECUTION", True)
    monkeypatch.setattr(routes.settings, "COMMAND_EXECUTION_ALLOWLIST", "linux-tech")
    monkeypatch.setattr(routes.shutil, "which", lambda binary: None if binary == "missing-binary" else f"/usr/bin/{binary}")
    monkeypatch.setattr(
        routes,
        "AD_COMMANDS",
        [
            {
                "id": "linux-tech",
                "category": "Test",
                "title": "Linux",
                "tool": "echo",
                "platform": "linux",
                "executable_on_linux": True,
                "description": "",
                "commands": [{"label": "Missing", "command": "missing-binary --version", "params": []}],
            }
        ],
    )

    response = test_app["client"].post(
        "/api/v1/ad-commands/execute/linux-tech",
        headers=_auth_headers(test_app, "missing-argv-user", is_superadmin=True),
        json={"command_index": 0, "params": {}},
    )

    assert response.status_code == 409
    assert response.json()["detail"] == "Required executable is not installed: missing-binary"


def test_execute_rejects_empty_rendered_command(test_app, monkeypatch):
    monkeypatch.setattr(routes.settings, "ENABLE_COMMAND_EXECUTION", True)
    monkeypatch.setattr(routes.settings, "COMMAND_EXECUTION_ALLOWLIST", "linux-tech")
    monkeypatch.setattr(
        routes,
        "AD_COMMANDS",
        [
            {
                "id": "linux-tech",
                "category": "Test",
                "title": "Linux",
                "tool": "echo",
                "platform": "linux",
                "executable_on_linux": True,
                "description": "",
                "commands": [{"label": "Empty", "command": "", "params": []}],
            }
        ],
    )

    response = test_app["client"].post(
        "/api/v1/ad-commands/execute/linux-tech",
        headers=_auth_headers(test_app, "empty-render-user", is_superadmin=True),
        json={"command_index": 0, "params": {}},
    )

    assert response.status_code == 400


def test_execute_hides_internal_errors(test_app, monkeypatch):
    async def fake_exec(*argv, stdout=None, stderr=None):
        raise RuntimeError("secret internal path")

    monkeypatch.setattr(routes.settings, "ENABLE_COMMAND_EXECUTION", True)
    monkeypatch.setattr(routes.settings, "COMMAND_EXECUTION_ALLOWLIST", "linux-tech")
    monkeypatch.setattr(
        routes,
        "AD_COMMANDS",
        [
            {
                "id": "linux-tech",
                "category": "Test",
                "title": "Linux",
                "tool": "openssl",
                "platform": "linux",
                "executable_on_linux": True,
                "description": "",
                "commands": [{"label": "Echo", "command": "echo ok", "params": []}],
            }
        ],
    )
    monkeypatch.setattr(cmd_svc.asyncio, "create_subprocess_exec", fake_exec)
    monkeypatch.setattr(routes.shutil, "which", lambda binary: f"/usr/bin/{binary}")
    monkeypatch.setattr(cmd_svc.shutil, "which", lambda binary: f"/usr/bin/{binary}")
    monkeypatch.setattr(cmd_svc, "AD_COMMANDS", routes.AD_COMMANDS)

    response = test_app["client"].post(
        "/api/v1/ad-commands/execute/linux-tech",
        headers=_auth_headers(test_app, "error-hide-user", is_superadmin=True),
        json={"command_index": 0, "params": {}},
    )

    assert response.status_code == 500
    assert response.json()["detail"] == "Command execution failed"


def test_catalog_has_unique_ids_and_project_relevant_entries():
    ids = [entry["id"] for entry in AD_COMMANDS]

    assert len(ids) == len(set(ids))
    assert "enum-adbygod-collector" in ids
    assert "enum-ldapsearch-linux" in ids
    assert "enum-windapsearch-linux" in ids
    assert "enum-smb-shares-linux" in ids
    assert "enum-rpc-net-linux" in ids
    assert "enum-adidnsdump-linux" in ids
    assert "enum-nmap-ad-linux" in ids
    assert "privesc-impacket-acl-edit" in ids
    assert "privesc-impacket-rbcd" in ids


def test_catalog_fixes_known_broken_commands():
    commands = "\n".join(
        cmd["command"]
        for entry in AD_COMMANDS
        for cmd in entry.get("commands", [])
    )

    assert "Get-ADUser -Filter * -Identity" not in commands
    assert "Enter-PSSession -Sessions" not in commands
    assert "Invoke-BloodHound -CollectionMethod All --LdapUsername" not in commands
    assert "IdentinyReferenceName" not in commands
    assert "'{Domain}\\\\{Username}' -y {PasswordFile}" not in commands


def test_ldapsearch_templates_support_upn_simple_bind():
    ldapsearch = next(entry for entry in AD_COMMANDS if entry["id"] == "enum-ldapsearch-linux")

    for cmd in ldapsearch["commands"]:
        assert "-D {Username}" in cmd["command"]
        assert "-w {Password}" in cmd["command"]
        assert "LDAPUrl" in cmd["params"]
        assert "PasswordFile" not in cmd["params"]


def test_overlay_commands_load_from_environment(tmp_path, monkeypatch):
    overlay = tmp_path / "ad_commands.local.json"
    overlay.write_text(
        json.dumps(
            {
                "category_descriptions": {
                    "Private Lab Playbooks": "Local only",
                },
                "commands": [
                    {
                        "id": "local-test-command",
                        "category": "Private Lab Playbooks",
                        "title": "Local Test Command",
                        "tool": "python3",
                        "platform": "linux",
                        "executable_on_linux": False,
                        "description": "Local command overlay",
                        "commands": [
                            {
                                "label": "Run local",
                                "command": "python3 local.py --target {Target}",
                                "params": ["Target"],
                                "platform": "linux",
                            }
                        ],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("AD_COMMANDS_OVERLAY_PATH", str(overlay))

    reloaded = reload(ad_commands_data)

    assert any(entry["id"] == "local-test-command" for entry in reloaded.AD_COMMANDS)
    assert "Private Lab Playbooks" in reloaded.AD_CATEGORIES
    assert reloaded.AD_CATEGORY_DESCRIPTIONS["Private Lab Playbooks"] == "Local only"

    monkeypatch.delenv("AD_COMMANDS_OVERLAY_PATH", raising=False)
    reload(ad_commands_data)
