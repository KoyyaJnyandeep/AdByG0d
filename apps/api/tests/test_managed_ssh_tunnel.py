from __future__ import annotations

import socket
from unittest.mock import patch


# ── pick_free_port ─────────────────────────────────────────────────────────────

def test_pick_free_port_returns_in_range():
    from adbygod_api.core.connectivity.ssh_tunnel import pick_free_port
    port = pick_free_port(41000, 49000)
    assert 41000 <= port <= 49000


def test_pick_free_port_skips_used_ports():
    from adbygod_api.core.connectivity.ssh_tunnel import pick_free_port

    call_count = 0
    original_bind = socket.socket.bind

    def fake_bind(self, addr):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            raise OSError("address in use")
        return original_bind(self, addr)

    with patch.object(socket.socket, "bind", fake_bind):
        port = pick_free_port(41000, 49000)
    assert 41000 <= port <= 49000
    assert call_count >= 2


# ── _build_ssh_cmd ─────────────────────────────────────────────────────────────

def test_build_ssh_cmd_returns_list_not_string():
    from adbygod_api.core.connectivity.ssh_tunnel import _build_ssh_cmd
    cmd = _build_ssh_cmd(
        binary="/usr/bin/ssh",
        local_port=42000,
        jumpbox_host="10.0.0.5",
        jumpbox_port=22,
        username="operator",
        auth_method="ssh_key",
        ssh_key_path="/home/op/.ssh/id_rsa",
    )
    assert isinstance(cmd, list)
    assert all(isinstance(arg, str) for arg in cmd)


def test_build_ssh_cmd_socks_binds_localhost_only():
    from adbygod_api.core.connectivity.ssh_tunnel import _build_ssh_cmd
    cmd = _build_ssh_cmd(
        binary="/usr/bin/ssh",
        local_port=42000,
        jumpbox_host="10.0.0.5",
        jumpbox_port=22,
        username="operator",
        auth_method="ssh_key",
        ssh_key_path=None,
    )
    # Must be -D 127.0.0.1:port, never 0.0.0.0
    assert "-D" in cmd
    d_idx = cmd.index("-D")
    assert cmd[d_idx + 1].startswith("127.0.0.1:")
    assert "0.0.0.0" not in " ".join(cmd)


def test_build_ssh_cmd_no_shell_string():
    from adbygod_api.core.connectivity.ssh_tunnel import _build_ssh_cmd
    cmd = _build_ssh_cmd(
        binary="/usr/bin/ssh",
        local_port=42000,
        jumpbox_host="10.0.0.5",
        jumpbox_port=22,
        username="operator",
        auth_method="ssh_key",
        ssh_key_path=None,
    )
    # No shell metacharacters
    full = " ".join(cmd)
    for char in [";", "&&", "||", "|", "`", "$("]:
        assert char not in full, f"Shell metacharacter {char!r} found in command"


def test_build_ssh_cmd_key_auth_adds_i_flag():
    from adbygod_api.core.connectivity.ssh_tunnel import _build_ssh_cmd
    cmd = _build_ssh_cmd(
        binary="/usr/bin/ssh",
        local_port=42000,
        jumpbox_host="10.0.0.5",
        jumpbox_port=22,
        username="operator",
        auth_method="ssh_key",
        ssh_key_path="/home/op/.ssh/id_rsa",
    )
    assert "-i" in cmd
    i_idx = cmd.index("-i")
    assert cmd[i_idx + 1] == "/home/op/.ssh/id_rsa"


def test_sanitized_cmd_preview_redacts_key_path():
    from adbygod_api.core.connectivity.ssh_tunnel import _sanitized_cmd_preview
    cmd = ["/usr/bin/ssh", "-i", "/home/op/.ssh/id_rsa", "-N", "-D", "127.0.0.1:42000", "operator@10.0.0.5"]
    preview = _sanitized_cmd_preview(cmd)
    assert "/home/op/.ssh/id_rsa" not in preview
    assert "<KEY_PATH_REDACTED>" in preview
    assert "operator@10.0.0.5" in preview  # non-sensitive parts kept


def test_sshpass_args_do_not_contain_password():
    from adbygod_api.core.connectivity.ssh_tunnel import _build_sshpass_args
    ssh_cmd = ["/usr/bin/ssh", "-N", "-D", "127.0.0.1:42000", "op@host"]
    sshpass_args, _ = _build_sshpass_args(ssh_cmd, password="s3cr3t", read_fd=7)
    full = " ".join(sshpass_args)
    assert "s3cr3t" not in full
