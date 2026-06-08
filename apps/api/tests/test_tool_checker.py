"""Tests for tool checker probe."""
import pytest
from adbygod_api.core.tool_checker.probe import probe_tool, ToolSpec, TOOL_CATALOG


@pytest.mark.asyncio
async def test_probe_tool_always_installed():
    spec = ToolSpec("python3", "python3", "apt install python3", [0])
    result = await probe_tool(spec)
    assert result.available is True
    assert result.name == "python3"


@pytest.mark.asyncio
async def test_probe_tool_missing():
    spec = ToolSpec("definitely-not-real-xyz", "definitely-not-real-xyz", "install it", [0])
    result = await probe_tool(spec)
    assert result.available is False
    assert result.version is None


def test_tool_catalog_no_duplicates():
    binaries = [t.binary for t in TOOL_CATALOG]
    assert len(binaries) == len(set(binaries)), "Duplicate binaries in catalog"


def test_tool_catalog_has_required_tools():
    binaries = {t.binary for t in TOOL_CATALOG}
    for required in ["nmap", "nxc", "python3", "hashcat"]:
        assert required in binaries, f"{required} missing from catalog"


def test_scan_requires_superadmin(test_app):
    """Non-superadmin must get 403 on POST /tool-checker/scan."""
    db = test_app["db"]
    client = test_app["client"]

    user = db.run(db.create_user("tc_analyst", "tc_analyst@test.com", is_superadmin=False))
    login = client.post("/api/v1/auth/login", json={"username": user.username, "password": "password123!"})
    token = login.cookies.get("adbygod_session")

    resp = client.post(
        "/api/v1/tool-checker/scan",
        cookies={"adbygod_session": token},
        headers={"x-requested-with": "XMLHttpRequest"},
    )
    assert resp.status_code == 403


def test_results_requires_superadmin(test_app):
    """Non-superadmin must get 403 on GET /tool-checker/results."""
    db = test_app["db"]
    client = test_app["client"]

    user = db.run(db.create_user("tc_analyst2", "tc_analyst2@test.com", is_superadmin=False))
    login = client.post("/api/v1/auth/login", json={"username": user.username, "password": "password123!"})
    token = login.cookies.get("adbygod_session")

    resp = client.get(
        "/api/v1/tool-checker/results",
        cookies={"adbygod_session": token},
    )
    assert resp.status_code == 403


def test_scan_superadmin_allowed(test_app):
    """Superadmin can POST /tool-checker/scan."""
    db = test_app["db"]
    client = test_app["client"]

    admin = db.run(db.create_user("tc_admin", "tc_admin@test.com", is_superadmin=True))
    login = client.post("/api/v1/auth/login", json={"username": admin.username, "password": "password123!"})
    token = login.cookies.get("adbygod_session")

    resp = client.post(
        "/api/v1/tool-checker/scan",
        cookies={"adbygod_session": token},
        headers={"x-requested-with": "XMLHttpRequest"},
    )
    assert resp.status_code == 200
