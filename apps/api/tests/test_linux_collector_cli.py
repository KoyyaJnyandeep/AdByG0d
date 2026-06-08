from __future__ import annotations

import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[3]
COLLECTOR_SRC = ROOT / "collectors" / "linux_remote" / "src"
if str(COLLECTOR_SRC) not in sys.path:
    sys.path.insert(0, str(COLLECTOR_SRC))

from adbygod_collector import cli as collector_cli


def test_list_modules_does_not_require_target_args(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["collect.py", "--list-modules"])

    args = collector_cli.parse_args()

    assert args.list_modules is True
    assert args.domain is None
    assert args.dc_ip is None


def test_password_is_loaded_from_environment(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["collect.py", "-d", "corp.local", "-dc-ip", "10.0.0.1", "-u", "alice"])
    monkeypatch.setenv("ADBYGOD_PASSWORD", "from-env")

    args = collector_cli.parse_args()

    assert collector_cli._resolve_password(args) == "from-env"


def test_password_is_loaded_from_file(monkeypatch, tmp_path):
    password_file = tmp_path / "collector-password.txt"
    password_file.write_text("from-file\n", encoding="utf-8")
    monkeypatch.setattr(
        sys,
        "argv",
        ["collect.py", "-d", "corp.local", "-dc-ip", "10.0.0.1", "-u", "alice", "--password-file", str(password_file)],
    )

    args = collector_cli.parse_args()

    assert collector_cli._resolve_password(args) == "from-file"


def test_no_prompt_password_exits_when_password_missing(monkeypatch):
    monkeypatch.setattr(
        sys,
        "argv",
        ["collect.py", "-d", "corp.local", "-dc-ip", "10.0.0.1", "-u", "alice", "--no-prompt-password"],
    )
    monkeypatch.delenv("ADBYGOD_PASSWORD", raising=False)

    args = collector_cli.parse_args()

    with pytest.raises(SystemExit) as exc:
        collector_cli._resolve_password(args)

    assert exc.value.code == 1
