"""Tests: credential cracking/collection requires ENABLE_COMMAND_EXECUTION + superadmin.
Before the fix, /loot/crack/start and /loot/collect bypassed the CREDENTIAL_HANDLING policy."""
from __future__ import annotations

import pytest
from unittest.mock import MagicMock

_DA_MODULE = "adbygod_api.core.privileged_operations"


# ── loot route: /loot/crack/start ────────────────────────────────────────────

def test_crack_start_403_when_flag_disabled(test_app):
    client = test_app["client"]
    factory = test_app["db"]
    import asyncio

    user = asyncio.run(factory.create_user("cracker1", "c1@corp.local", is_superadmin=True))
    headers = test_app["headers_for"](user)

    import adbygod_api.config as cfg
    old = cfg.settings.ENABLE_COMMAND_EXECUTION
    try:
        cfg.settings.ENABLE_COMMAND_EXECUTION = False
        resp = client.post("/api/v1/loot/crack/start", json={
            "hashes": ["aad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0"],
            "hashcat_mode": 1000,
            "acknowledge_authorized": True,
            "wordlist": "/usr/share/wordlists/rockyou.txt",
        }, headers=headers)
    finally:
        cfg.settings.ENABLE_COMMAND_EXECUTION = old

    assert resp.status_code == 403


def test_crack_start_403_for_non_superadmin(test_app):
    client = test_app["client"]
    factory = test_app["db"]
    import asyncio

    regular = asyncio.run(factory.create_user("cracker2", "c2@corp.local", is_superadmin=False))
    headers = test_app["headers_for"](regular)

    import adbygod_api.config as cfg
    old = cfg.settings.ENABLE_COMMAND_EXECUTION
    try:
        cfg.settings.ENABLE_COMMAND_EXECUTION = True
        resp = client.post("/api/v1/loot/crack/start", json={
            "hashes": ["aad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0"],
            "hashcat_mode": 1000,
            "acknowledge_authorized": True,
            "wordlist": "/usr/share/wordlists/rockyou.txt",
        }, headers=headers)
    finally:
        cfg.settings.ENABLE_COMMAND_EXECUTION = old

    assert resp.status_code == 403


# ── loot route: /loot/collect ────────────────────────────────────────────────

_COLLECT_BODY = {
    "techniques": ["secretsdump"],
    "target": "dc01.corp.local",
    "domain": "corp.local",
    "username": "admin",
    "password": "Password1",
    "dc_ip": "10.0.0.1",
}


def test_collect_403_when_flag_disabled(test_app):
    client = test_app["client"]
    factory = test_app["db"]
    import asyncio

    user = asyncio.run(factory.create_user("collector1", "col1@corp.local", is_superadmin=True))
    headers = test_app["headers_for"](user)

    import adbygod_api.config as cfg
    old = cfg.settings.ENABLE_COMMAND_EXECUTION
    try:
        cfg.settings.ENABLE_COMMAND_EXECUTION = False
        resp = client.post("/api/v1/loot/collect", json=_COLLECT_BODY, headers=headers)
    finally:
        cfg.settings.ENABLE_COMMAND_EXECUTION = old

    assert resp.status_code == 403


def test_collect_403_for_non_superadmin(test_app):
    client = test_app["client"]
    factory = test_app["db"]
    import asyncio

    regular = asyncio.run(factory.create_user("collector2", "col2@corp.local", is_superadmin=False))
    headers = test_app["headers_for"](regular)

    import adbygod_api.config as cfg
    old = cfg.settings.ENABLE_COMMAND_EXECUTION
    try:
        cfg.settings.ENABLE_COMMAND_EXECUTION = True
        resp = client.post("/api/v1/loot/collect", json=_COLLECT_BODY, headers=headers)
    finally:
        cfg.settings.ENABLE_COMMAND_EXECUTION = old

    assert resp.status_code == 403


# ── AI operator: approve crack_hashes must check flag ─────────────────────────

def test_ai_approve_crack_hashes_blocked_when_flag_disabled(test_app):
    """Approving crack_hashes via AI operator must be blocked when flag off."""
    client = test_app["client"]
    factory = test_app["db"]
    import asyncio

    user = asyncio.run(factory.create_user("ai_approver1", "ai1@corp.local", is_superadmin=True))
    headers = test_app["headers_for"](user)

    import adbygod_api.config as cfg
    old = cfg.settings.ENABLE_COMMAND_EXECUTION

    # Inject a pending approval for crack_hashes
    from adbygod_api.core.ai_operator.approval_store import get_approval_store
    store = get_approval_store()
    req_id = store.create(
        "crack_hashes",
        {"hashes": ["abc"], "hashcat_mode": 1000},
        "Crack hashes",
        "HIGH",
        "Credential cracking",
        user_id=str(user.id),
    )

    try:
        cfg.settings.ENABLE_COMMAND_EXECUTION = False
        resp = client.post(f"/api/v1/ai-operator/approve/{req_id}", headers=headers)
    finally:
        cfg.settings.ENABLE_COMMAND_EXECUTION = old

    assert resp.status_code == 403


# ── exec_tools._crack_hashes internal policy check ───────────────────────────

@pytest.mark.asyncio
async def test_crack_hashes_tool_blocked_for_non_superadmin():
    from adbygod_api.core.ai_operator.tools.exec_tools import HANDLERS
    import adbygod_api.config as cfg

    ctx = MagicMock()
    ctx.current_user = MagicMock(is_superadmin=False)

    old = cfg.settings.ENABLE_COMMAND_EXECUTION
    try:
        cfg.settings.ENABLE_COMMAND_EXECUTION = True
        result = await HANDLERS["crack_hashes"](
            {"hashes": ["abc123"], "hashcat_mode": 1000}, ctx
        )
    finally:
        cfg.settings.ENABLE_COMMAND_EXECUTION = old

    assert result.get("blocked") is True


@pytest.mark.asyncio
async def test_crack_hashes_tool_blocked_when_flag_disabled():
    from adbygod_api.core.ai_operator.tools.exec_tools import HANDLERS
    import adbygod_api.config as cfg

    ctx = MagicMock()
    ctx.current_user = MagicMock(is_superadmin=True)

    old = cfg.settings.ENABLE_COMMAND_EXECUTION
    try:
        cfg.settings.ENABLE_COMMAND_EXECUTION = False
        result = await HANDLERS["crack_hashes"](
            {"hashes": ["abc123"], "hashcat_mode": 1000}, ctx
        )
    finally:
        cfg.settings.ENABLE_COMMAND_EXECUTION = old

    assert result.get("blocked") is True
