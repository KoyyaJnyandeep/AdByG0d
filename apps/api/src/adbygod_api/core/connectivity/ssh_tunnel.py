from __future__ import annotations

import asyncio
import logging
import os
import random
import shutil
import socket

from adbygod_api.config import settings

log = logging.getLogger(__name__)


def pick_free_port(min_port: int = 41000, max_port: int = 49000) -> int:
    """Return a free localhost port in [min_port, max_port]. Raises RuntimeError if none found."""
    candidates = list(range(min_port, max_port + 1))
    random.shuffle(candidates)
    for port in candidates[:200]:  # try up to 200 random candidates
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind(("127.0.0.1", port))
                return port
        except OSError:
            continue
    raise RuntimeError(f"No free port available in range {min_port}-{max_port}")


def _build_ssh_cmd(
    *,
    binary: str,
    local_port: int,
    jumpbox_host: str,
    jumpbox_port: int,
    username: str,
    auth_method: str,
    ssh_key_path: str | None,
) -> list[str]:
    """Build SSH argument list. No secrets included. shell=False safe."""
    cmd = [
        binary,
        "-N",
        "-D", f"127.0.0.1:{local_port}",
        "-p", str(jumpbox_port),
        "-o", "ExitOnForwardFailure=yes",
        "-o", "ServerAliveInterval=30",
        "-o", "ServerAliveCountMax=3",
        "-o", "StrictHostKeyChecking=accept-new",
    ]
    if auth_method == "ssh_key" and ssh_key_path:
        cmd += ["-i", ssh_key_path, "-o", "BatchMode=yes"]
    else:
        # password_dev mode — no -i flag, BatchMode=no so sshpass can work
        cmd += ["-o", "BatchMode=no"]
    cmd.append(f"{username}@{jumpbox_host}")
    return cmd


async def is_local_tcp_listener(host: str, port: int, timeout: float = 0.75) -> bool:
    """Return True only if host:port accepts a TCP connection."""
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
        writer.close()
        await writer.wait_closed()
        return True
    except Exception:
        return False


def _sanitized_cmd_preview(cmd: list[str]) -> str:
    """Return a loggable/storable command representation with key path redacted."""
    sanitized = []
    skip_next = False
    for arg in cmd:
        if skip_next:
            sanitized.append("<KEY_PATH_REDACTED>")
            skip_next = False
        elif arg == "-i":
            sanitized.append(arg)
            skip_next = True
        else:
            sanitized.append(arg)
    return " ".join(sanitized)


def _build_sshpass_args(
    ssh_cmd: list[str],
    *,
    password: str,
    read_fd: int,
) -> tuple[list[str], bytes]:
    """
    Returns (full_cmd_list, password_bytes).
    Caller must: os.write(write_fd, password_bytes); os.close(write_fd).
    full_cmd_list uses sshpass -d <read_fd> and contains no plaintext password.
    """
    full_cmd = ["sshpass", "-d", str(read_fd)] + ssh_cmd
    return full_cmd, (password + "\n").encode()


async def _verify_socks_port(port: int, timeout: float = 8.0) -> None:
    """Wait for SSH SOCKS listener on 127.0.0.1:port. Raises RuntimeError on timeout."""
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while loop.time() < deadline:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection("127.0.0.1", port), timeout=1.0
            )
            writer.close()
            await writer.wait_closed()
            return
        except (ConnectionRefusedError, OSError, asyncio.TimeoutError):
            await asyncio.sleep(0.5)
    raise RuntimeError(f"SOCKS port 127.0.0.1:{port} did not become available within {timeout}s")


class ManagedSshSocksManager:
    """Manages one SSH SOCKS5 tunnel subprocess per profile."""

    def __init__(
        self,
        *,
        jumpbox_host: str,
        jumpbox_port: int,
        username: str,
        auth_method: str,
        ssh_key_path: str | None = None,
    ):
        self.jumpbox_host = jumpbox_host
        self.jumpbox_port = jumpbox_port
        self.username = username
        self.auth_method = auth_method
        self.ssh_key_path = ssh_key_path
        self.local_port: int | None = None
        self._proc: asyncio.subprocess.Process | None = None

    @property
    def pid(self) -> int | None:
        return self._proc.pid if self._proc else None

    @property
    def running(self) -> bool:
        return self._proc is not None and self._proc.returncode is None

    async def start(self, password: str | None = None) -> int:
        """Start SSH tunnel. Returns local_port. Raises on failure."""
        if self.running:
            assert self.local_port is not None
            return self.local_port

        self.local_port = pick_free_port(
            settings.MANAGED_TUNNEL_PORT_MIN,
            settings.MANAGED_TUNNEL_PORT_MAX,
        )

        binary = settings.MANAGED_SSH_BINARY
        if not shutil.which(binary) and not (os.path.isabs(binary) and os.path.isfile(binary)):
            raise RuntimeError(f"SSH binary not found: {binary}")
        if self.auth_method == "password_dev" and not shutil.which("sshpass"):
            raise RuntimeError("password_dev auth requires sshpass to be installed")

        ssh_cmd = _build_ssh_cmd(
            binary=binary,
            local_port=self.local_port,
            jumpbox_host=self.jumpbox_host,
            jumpbox_port=self.jumpbox_port,
            username=self.username,
            auth_method=self.auth_method,
            ssh_key_path=self.ssh_key_path,
        )

        if self.auth_method == "password_dev":
            if password is None:
                raise ValueError("password required for password_dev auth_method")
            read_fd, write_fd = os.pipe()
            try:
                full_cmd, pw_bytes = _build_sshpass_args(ssh_cmd, password=password, read_fd=read_fd)
                os.write(write_fd, pw_bytes)
                os.close(write_fd)
                write_fd = -1  # mark closed
                self._proc = await asyncio.create_subprocess_exec(
                    *full_cmd,
                    stdin=asyncio.subprocess.DEVNULL,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    pass_fds=(read_fd,),
                )
            except Exception:
                if write_fd != -1:
                    try:
                        os.close(write_fd)
                    except OSError:
                        pass
                raise
            finally:
                try:
                    os.close(read_fd)
                except OSError:
                    pass
        else:
            self._proc = await asyncio.create_subprocess_exec(
                *ssh_cmd,
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

        log.info("[ssh_tunnel] started pid=%s port=%s host=%s", self.pid, self.local_port, self.jumpbox_host)
        try:
            await _verify_socks_port(self.local_port)
        except Exception:
            await self.stop()
            raise
        return self.local_port

    async def stop(self) -> None:
        if self._proc and self._proc.returncode is None:
            self._proc.terminate()
            try:
                await asyncio.wait_for(self._proc.wait(), timeout=5)
            except asyncio.TimeoutError:
                self._proc.kill()
                try:
                    await asyncio.wait_for(self._proc.wait(), timeout=2)
                except asyncio.TimeoutError:
                    log.warning("[ssh_tunnel] process did not exit after SIGKILL pid=%s", self.pid)
        self._proc = None
        log.info("[ssh_tunnel] stopped host=%s", self.jumpbox_host)

    async def log_lines(self, max_lines: int = 100) -> list[str]:
        lines: list[str] = []
        if not self._proc or not self._proc.stderr:
            return lines
        try:
            for _ in range(max_lines):
                line = await asyncio.wait_for(self._proc.stderr.readline(), timeout=0.05)
                if not line:
                    break
                lines.append(line.decode(errors="replace").rstrip())
        except asyncio.TimeoutError:
            pass
        return lines

    def sanitized_command_preview(self) -> str:
        binary = settings.MANAGED_SSH_BINARY
        if not shutil.which(binary) and not (os.path.isabs(binary) and os.path.isfile(binary)):
            raise RuntimeError(f"SSH binary not found: {binary}")
        if self.auth_method == "password_dev" and not shutil.which("sshpass"):
            raise RuntimeError("password_dev auth requires sshpass to be installed")

        ssh_cmd = _build_ssh_cmd(
            binary=binary,
            local_port=self.local_port or 0,
            jumpbox_host=self.jumpbox_host,
            jumpbox_port=self.jumpbox_port,
            username=self.username,
            auth_method=self.auth_method,
            ssh_key_path=self.ssh_key_path,
        )
        return _sanitized_cmd_preview(ssh_cmd)


# Module-level registry keyed by profile_id string
_ssh_managers: dict[str, ManagedSshSocksManager] = {}
_ssh_manager_locks: dict[str, asyncio.Lock] = {}


def _get_lock(profile_id: str) -> asyncio.Lock:
    if profile_id not in _ssh_manager_locks:
        _ssh_manager_locks[profile_id] = asyncio.Lock()
    return _ssh_manager_locks[profile_id]


async def start_tunnel(profile_id: str, manager: ManagedSshSocksManager, password: str | None = None) -> int:
    """Acquire per-profile lock and start tunnel. Use this instead of manager.start() directly."""
    async with _get_lock(profile_id):
        return await manager.start(password=password)


def get_ssh_manager(
    profile_id: str,
    *,
    jumpbox_host: str = "",
    jumpbox_port: int = 22,
    username: str = "",
    auth_method: str = "ssh_key",
    ssh_key_path: str | None = None,
) -> ManagedSshSocksManager:
    if profile_id not in _ssh_managers or not _ssh_managers[profile_id].running:
        _ssh_managers[profile_id] = ManagedSshSocksManager(
            jumpbox_host=jumpbox_host,
            jumpbox_port=jumpbox_port,
            username=username,
            auth_method=auth_method,
            ssh_key_path=ssh_key_path,
        )
    return _ssh_managers[profile_id]
