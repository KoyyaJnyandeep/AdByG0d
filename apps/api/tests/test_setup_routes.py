"""Tests for /api/v1/setup endpoints (dev-only)."""
from __future__ import annotations


def test_setup_status_no_operator(test_app):
    """Fresh DB → setup_complete=False, profile=None."""
    client = test_app["client"]
    resp = client.get("/api/v1/setup/status")
    assert resp.status_code == 200
    data = resp.json()
    assert data["setup_complete"] is False
    assert data["profile"] is None


def test_setup_init_creates_operator(test_app, tmp_path, monkeypatch):
    """POST /setup/init creates a superadmin and profile file."""
    import adbygod_api.config as config_mod
    import adbygod_api.routes.setup as setup_mod
    monkeypatch.setattr(config_mod.settings, "ALLOW_DEV_BOOTSTRAP", True)
    monkeypatch.setattr(config_mod.settings, "DEBUG", True)
    monkeypatch.setattr(setup_mod, "DEV_PROFILE_PATH", tmp_path / ".dev-profile.json")

    client = test_app["client"]
    resp = client.post("/api/v1/setup/init", json={"callsign": "tester", "passphrase": "SuperSecret99!"})
    assert resp.status_code == 201
    data = resp.json()
    assert data["callsign"] == "tester"
    assert (tmp_path / ".dev-profile.json").exists()


def test_setup_status_after_init(test_app, tmp_path, monkeypatch):
    """After init, setup_complete=True and profile returned."""
    import adbygod_api.config as config_mod
    import adbygod_api.routes.setup as setup_mod
    monkeypatch.setattr(config_mod.settings, "ALLOW_DEV_BOOTSTRAP", True)
    monkeypatch.setattr(config_mod.settings, "DEBUG", True)
    monkeypatch.setattr(setup_mod, "DEV_PROFILE_PATH", tmp_path / ".dev-profile.json")

    client = test_app["client"]
    client.post("/api/v1/setup/init", json={"callsign": "tester2", "passphrase": "SuperSecret99!"})

    resp = client.get("/api/v1/setup/status")
    assert resp.status_code == 200
    data = resp.json()
    assert data["setup_complete"] is True
    assert data["profile"]["callsign"] == "tester2"


def test_setup_init_conflict(test_app, tmp_path, monkeypatch):
    """Double init returns 409."""
    import adbygod_api.config as config_mod
    import adbygod_api.routes.setup as setup_mod
    monkeypatch.setattr(config_mod.settings, "ALLOW_DEV_BOOTSTRAP", True)
    monkeypatch.setattr(config_mod.settings, "DEBUG", True)
    monkeypatch.setattr(setup_mod, "DEV_PROFILE_PATH", tmp_path / ".dev-profile.json")

    client = test_app["client"]
    client.post("/api/v1/setup/init", json={"callsign": "tester3", "passphrase": "SuperSecret99!"})
    resp = client.post("/api/v1/setup/init", json={"callsign": "tester3b", "passphrase": "SuperSecret99!"})
    assert resp.status_code == 409


def test_setup_update_callsign(test_app, tmp_path, monkeypatch):
    """PUT /setup/profile updates callsign."""
    import adbygod_api.config as config_mod
    import adbygod_api.routes.setup as setup_mod
    monkeypatch.setattr(setup_mod, "DEV_PROFILE_PATH", tmp_path / ".dev-profile.json")
    monkeypatch.setattr(config_mod.settings, "ALLOW_DEV_BOOTSTRAP", True)
    monkeypatch.setattr(config_mod.settings, "DEBUG", True)

    client = test_app["client"]
    client.post("/api/v1/setup/init", json={"callsign": "old_name", "passphrase": "SuperSecret99!"})
    # Authenticate as the newly created superadmin before updating profile
    client.post("/api/v1/auth/login", json={"username": "old_name", "password": "SuperSecret99!"})

    resp = client.put(
        "/api/v1/setup/profile",
        json={"callsign": "new_name"},
        headers={"X-Requested-With": "XMLHttpRequest"},
    )
    assert resp.status_code == 200
    assert resp.json()["callsign"] == "new_name"


def test_setup_delete_wipes_operator(test_app, tmp_path, monkeypatch):
    """DELETE /setup/profile removes operator and profile file."""
    import adbygod_api.config as config_mod
    import adbygod_api.routes.setup as setup_mod
    monkeypatch.setattr(setup_mod, "DEV_PROFILE_PATH", tmp_path / ".dev-profile.json")
    monkeypatch.setattr(config_mod.settings, "ALLOW_DEV_BOOTSTRAP", True)
    monkeypatch.setattr(config_mod.settings, "DEBUG", True)

    client = test_app["client"]
    client.post("/api/v1/setup/init", json={"callsign": "todelete", "passphrase": "SuperSecret99!"})
    # Authenticate as the newly created superadmin before deleting profile
    client.post("/api/v1/auth/login", json={"username": "todelete", "password": "SuperSecret99!"})

    resp = client.delete(
        "/api/v1/setup/profile",
        headers={"X-Requested-With": "XMLHttpRequest"},
    )
    assert resp.status_code == 204
    assert not (tmp_path / ".dev-profile.json").exists()

    status_resp = client.get("/api/v1/setup/status")
    assert status_resp.json()["setup_complete"] is False


def test_setup_init_blocked_without_bootstrap_flags(test_app, monkeypatch):
    """Bootstrap must be blocked when ALLOW_DEV_BOOTSTRAP is not set, even with an empty DB."""
    import adbygod_api.config as config_mod
    monkeypatch.setattr(config_mod.settings, "ALLOW_DEV_BOOTSTRAP", False)
    monkeypatch.setattr(config_mod.settings, "DEBUG", False)

    client = test_app["client"]
    resp = client.post(
        "/api/v1/setup/init",
        json={"callsign": "attacker", "passphrase": "SuperSecret99!"},
    )
    assert resp.status_code in (401, 403, 404), (
        f"Expected 401/403/404, got {resp.status_code}: {resp.text}"
    )


def test_setup_init_allowed_with_bootstrap_flags(test_app, monkeypatch, tmp_path):
    """Bootstrap succeeds when DEBUG=true and ALLOW_DEV_BOOTSTRAP=true."""
    import adbygod_api.config as config_mod
    import adbygod_api.routes.setup as setup_mod
    monkeypatch.setattr(config_mod.settings, "ALLOW_DEV_BOOTSTRAP", True)
    monkeypatch.setattr(config_mod.settings, "DEBUG", True)
    monkeypatch.setattr(setup_mod, "DEV_PROFILE_PATH", tmp_path / ".dev-profile.json")

    client = test_app["client"]
    resp = client.post(
        "/api/v1/setup/init",
        json={"callsign": "developer", "passphrase": "SuperSecret99!"},
    )
    assert resp.status_code == 201
