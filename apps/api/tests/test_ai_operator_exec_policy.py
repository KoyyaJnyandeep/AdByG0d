"""
Tests for the shared command_execution service policy enforcement.

All subprocess calls and shutil.which are mocked — no real processes are spawned.
"""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

import adbygod_api.config as config_module
from adbygod_api.services.command_execution import execute_technique


# ── Helpers ───────────────────────────────────────────────────────────────────

def _superadmin():
    user = MagicMock()
    user.is_superadmin = True
    user.id = "user-super-1"
    return user


def _normal_user():
    user = MagicMock()
    user.is_superadmin = False
    user.id = "user-normal-1"
    return user


# A minimal catalog technique that is auto-executable (no execution_mode = manual)
_CATALOG_TECHNIQUE = {
    "id": "T001",
    "category": "Reconnaissance & OSINT",
    "title": "Test Technique",
    "tool": "dig",
    "platform": "linux",
    "executable_on_linux": True,
    "commands": [
        {
            "label": "test command",
            "command": "dig {Domain} ANY",
            "params": ["Domain"],
            "platform": "linux",
            # no execution_mode key → defaults to ""  → not blocked
        }
    ],
}

_CATALOG_MANUAL = {
    "id": "T002",
    "category": "Reconnaissance & OSINT",
    "title": "Manual Technique",
    "tool": "powershell",
    "platform": "windows",
    "executable_on_linux": False,
    "commands": [
        {
            "label": "manual cmd",
            "command": "powershell Get-ADUser",
            "execution_mode": "manual",
        }
    ],
}

_FAKE_CATALOG = [_CATALOG_TECHNIQUE, _CATALOG_MANUAL]


# ── Tests ─────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_normal_user_cannot_execute():
    """Non-superadmin is always blocked regardless of flags."""
    with patch.object(config_module.settings, "ENABLE_COMMAND_EXECUTION", True):
        result = await execute_technique(
            technique_id="T001",
            current_user=_normal_user(),
        )
    assert result.blocked is True
    assert "superadmin" in (result.error or "").lower()


@pytest.mark.asyncio
async def test_superadmin_blocked_when_flag_disabled():
    """ENABLE_COMMAND_EXECUTION=false blocks even superadmins."""
    with patch.object(config_module.settings, "ENABLE_COMMAND_EXECUTION", False):
        result = await execute_technique(
            technique_id="T001",
            current_user=_superadmin(),
        )
    assert result.blocked is True
    assert "disabled" in (result.error or "").lower()


@pytest.mark.asyncio
async def test_technique_not_in_allowlist_blocked():
    """technique_id not in explicit allowlist is blocked."""
    with (
        patch.object(config_module.settings, "ENABLE_COMMAND_EXECUTION", True),
        patch(
            "adbygod_api.services.command_execution.AD_COMMANDS",
            _FAKE_CATALOG,
        ),
    ):
        result = await execute_technique(
            technique_id="T002",
            current_user=_superadmin(),
            allowlist=["T001"],
        )
    assert result.blocked is True
    assert "allowlist" in (result.error or "").lower()


@pytest.mark.asyncio
async def test_technique_not_in_catalog_blocked():
    """Unknown technique_id returns blocked."""
    with (
        patch.object(config_module.settings, "ENABLE_COMMAND_EXECUTION", True),
        patch(
            "adbygod_api.services.command_execution.AD_COMMANDS",
            _FAKE_CATALOG,
        ),
    ):
        result = await execute_technique(
            technique_id="UNKNOWN-XYZ",
            current_user=_superadmin(),
            allowlist=["UNKNOWN-XYZ"],  # pass allowlist so we don't get blocked there
        )
    assert result.blocked is True
    assert "not found" in (result.error or "").lower()


@pytest.mark.asyncio
async def test_manual_only_technique_blocked():
    """Technique with execution_mode=manual cannot be auto-executed."""
    with (
        patch.object(config_module.settings, "ENABLE_COMMAND_EXECUTION", True),
        patch(
            "adbygod_api.services.command_execution.AD_COMMANDS",
            _FAKE_CATALOG,
        ),
    ):
        result = await execute_technique(
            technique_id="T002",
            current_user=_superadmin(),
            allowlist=["T002"],
        )
    assert result.blocked is True
    assert "manual" in (result.error or "").lower()


@pytest.mark.asyncio
async def test_executable_not_found_blocked():
    """If shutil.which returns None, execution is blocked."""
    with (
        patch.object(config_module.settings, "ENABLE_COMMAND_EXECUTION", True),
        patch(
            "adbygod_api.services.command_execution.AD_COMMANDS",
            _FAKE_CATALOG,
        ),
        patch("adbygod_api.services.command_execution.shutil.which", return_value=None),
    ):
        result = await execute_technique(
            technique_id="T001",
            current_user=_superadmin(),
            allowlist=["T001"],
            params={"Domain": "example.com"},
        )
    assert result.blocked is True
    assert "not found" in (result.error or "").lower()


@pytest.mark.asyncio
async def test_output_is_capped():
    """Subprocess output larger than caps is truncated."""
    big_stdout = b"A" * 100_000
    big_stderr = b"B" * 100_000

    mock_proc = MagicMock()
    mock_proc.returncode = 0
    mock_proc.communicate = AsyncMock(return_value=(big_stdout, big_stderr))

    with (
        patch.object(config_module.settings, "ENABLE_COMMAND_EXECUTION", True),
        patch(
            "adbygod_api.services.command_execution.AD_COMMANDS",
            _FAKE_CATALOG,
        ),
        patch("adbygod_api.services.command_execution.shutil.which", return_value="/usr/bin/dig"),
        patch(
            "adbygod_api.services.command_execution.asyncio.create_subprocess_exec",
            return_value=mock_proc,
        ),
    ):
        result = await execute_technique(
            technique_id="T001",
            current_user=_superadmin(),
            allowlist=["T001"],
            params={"Domain": "example.com"},
        )

    assert result.blocked is False
    assert result.error is None
    from adbygod_api.services.command_execution import _STDOUT_CAP, _STDERR_CAP
    assert len(result.stdout) <= _STDOUT_CAP
    assert len(result.stderr) <= _STDERR_CAP


@pytest.mark.asyncio
async def test_output_is_redacted():
    """Subprocess output containing password=... is redacted."""
    sensitive_stdout = b"Connected: password=mysecret token=abc123"
    clean_stderr = b""

    mock_proc = MagicMock()
    mock_proc.returncode = 0
    mock_proc.communicate = AsyncMock(return_value=(sensitive_stdout, clean_stderr))

    with (
        patch.object(config_module.settings, "ENABLE_COMMAND_EXECUTION", True),
        patch(
            "adbygod_api.services.command_execution.AD_COMMANDS",
            _FAKE_CATALOG,
        ),
        patch("adbygod_api.services.command_execution.shutil.which", return_value="/usr/bin/dig"),
        patch(
            "adbygod_api.services.command_execution.asyncio.create_subprocess_exec",
            return_value=mock_proc,
        ),
    ):
        result = await execute_technique(
            technique_id="T001",
            current_user=_superadmin(),
            allowlist=["T001"],
            params={"Domain": "example.com"},
        )

    assert result.blocked is False
    assert "mysecret" not in result.stdout
    assert "abc123" not in result.stdout
    assert "[REDACTED]" in result.stdout


@pytest.mark.asyncio
async def test_audit_event_created_on_block():
    """audit_fn is called with a blocked event when execution is blocked."""
    audit_fn = AsyncMock()

    with patch.object(config_module.settings, "ENABLE_COMMAND_EXECUTION", False):
        result = await execute_technique(
            technique_id="T001",
            current_user=_superadmin(),
            audit_fn=audit_fn,
        )

    assert result.blocked is True
    # audit_fn should have been called
    audit_fn.assert_called()
    # The call should carry the blocked audit event
    call_args = audit_fn.call_args_list
    events = [c.args[0] if c.args else c.kwargs.get("event") for c in call_args]
    assert any("blocked" in str(e) for e in events)


@pytest.mark.asyncio
async def test_audit_event_created_on_success():
    """audit_fn is called with execution.completed on a successful run."""
    audit_fn = AsyncMock()

    mock_proc = MagicMock()
    mock_proc.returncode = 0
    mock_proc.communicate = AsyncMock(return_value=(b"ok output", b""))

    with (
        patch.object(config_module.settings, "ENABLE_COMMAND_EXECUTION", True),
        patch(
            "adbygod_api.services.command_execution.AD_COMMANDS",
            _FAKE_CATALOG,
        ),
        patch("adbygod_api.services.command_execution.shutil.which", return_value="/usr/bin/dig"),
        patch(
            "adbygod_api.services.command_execution.asyncio.create_subprocess_exec",
            return_value=mock_proc,
        ),
    ):
        result = await execute_technique(
            technique_id="T001",
            current_user=_superadmin(),
            allowlist=["T001"],
            params={"Domain": "example.com"},
            audit_fn=audit_fn,
        )

    assert result.blocked is False
    assert result.exit_code == 0
    # audit_fn called at least twice: execution.started + execution.completed
    assert audit_fn.call_count >= 2
    all_events = [c.args[0] for c in audit_fn.call_args_list if c.args]
    assert "execution.completed" in all_events
