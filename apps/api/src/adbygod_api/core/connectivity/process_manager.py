from __future__ import annotations

import asyncio
import hashlib
import logging
from pathlib import Path

from adbygod_api.config import settings

log = logging.getLogger(__name__)


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _verified_binary(kind: str) -> str:
    allowlist = settings.tunnel_management_binary_allowlist
    binary_name = "chisel" if kind == "chisel" else "ligolo-proxy"
    configured_path = settings.CHISEL_BINARY_PATH if kind == "chisel" else settings.LIGOLO_PROXY_BINARY_PATH
    expected_sha = settings.CHISEL_BINARY_SHA256 if kind == "chisel" else settings.LIGOLO_PROXY_BINARY_SHA256

    if binary_name not in allowlist:
        raise RuntimeError(f"{binary_name} is not enabled in TUNNEL_MANAGEMENT_BINARY_ALLOWLIST")
    if not configured_path:
        raise RuntimeError(f"{binary_name} requires configured absolute path")

    path = Path(configured_path)
    if not path.is_absolute():
        raise RuntimeError(f"{binary_name} path must be absolute: {configured_path}")
    if not path.is_file():
        raise RuntimeError(f"{binary_name} binary not found: {configured_path}")
    if (path.stat().st_mode & 0o111) == 0:
        raise RuntimeError(f"{binary_name} binary is not executable: {configured_path}")
    if not expected_sha:
        raise RuntimeError(f"{binary_name} requires SHA256 pin")

    actual_sha = _sha256_file(path)
    if actual_sha.lower() != expected_sha.lower():
        raise RuntimeError(f"{binary_name} SHA256 mismatch")
    return str(path)


class ChiselServerManager:
    """Manages a chisel server subprocess for SOCKS5 tunnel establishment."""

    def __init__(self, port: int = 8080, socks_port: int = 1080, auth_token: str | None = None):
        self.port = port
        self.socks_port = socks_port
        self.auth_token = auth_token
        self._proc: asyncio.subprocess.Process | None = None

    @property
    def pid(self) -> int | None:
        return self._proc.pid if self._proc else None

    @property
    def running(self) -> bool:
        return self._proc is not None and self._proc.returncode is None

    async def start(self) -> str:
        """Start chisel server. Returns a safe client command template."""
        if self.running:
            return self.client_cmd_template()

        binary = _verified_binary("chisel")

        cmd = [binary, "server", "--reverse", "--socks5", f"--port={self.port}"]
        if self.auth_token:
            cmd += [f"--auth={self.auth_token}"]

        self._proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        log.info("[chisel] server started pid=%s port=%s", self._proc.pid, self.port)
        await asyncio.sleep(0.3)
        if not self.running:
            lines = await self.log_lines(20)
            self._proc = None
            tail = (" :: " + " | ".join(lines[-5:])) if lines else ""
            raise RuntimeError(f"chisel server exited during startup{tail}")
        return self.client_cmd_template()

    async def stop(self) -> None:
        if self._proc and self._proc.returncode is None:
            self._proc.terminate()
            try:
                await asyncio.wait_for(self._proc.wait(), timeout=5)
            except asyncio.TimeoutError:
                self._proc.kill()
                await self._proc.wait()
        self._proc = None
        log.info("[chisel] server stopped")

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

    def client_cmd_template(self) -> str:
        import socket
        server_ip = socket.gethostbyname(socket.gethostname())
        auth_prefix = "<TOKEN>@" if self.auth_token else ""
        return (
            f"chisel client {auth_prefix}{server_ip}:{self.port} "
            f"R:{self.socks_port}:socks"
        )


class LigoloProxyManager:
    """Manages a ligolo-ng proxy subprocess for TUN-based routing."""

    def __init__(self, port: int = 11601, tun_interface: str = "ligolo"):
        self.port = port
        self.tun_interface = tun_interface
        self._proc: asyncio.subprocess.Process | None = None
        self._routes: list[str] = []

    @property
    def pid(self) -> int | None:
        return self._proc.pid if self._proc else None

    @property
    def running(self) -> bool:
        return self._proc is not None and self._proc.returncode is None

    async def start(self) -> None:
        if self.running:
            return

        binary = _verified_binary("ligolo-proxy")

        cmd = [binary, "-selfcert", f"-laddr=0.0.0.0:{self.port}"]
        self._proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        log.info("[ligolo] proxy started pid=%s port=%s", self._proc.pid, self.port)
        await asyncio.sleep(0.3)
        if not self.running:
            lines = await self.log_lines(20)
            self._proc = None
            tail = (" :: " + " | ".join(lines[-5:])) if lines else ""
            raise RuntimeError(f"ligolo proxy exited during startup{tail}")

    async def stop(self) -> None:
        for cidr in list(self._routes):
            try:
                await self.remove_route(cidr)
            except Exception:
                log.warning("[ligolo] failed to remove route %s during stop", cidr, exc_info=True)
        if self._proc and self._proc.returncode is None:
            self._proc.terminate()
            try:
                await asyncio.wait_for(self._proc.wait(), timeout=5)
            except asyncio.TimeoutError:
                self._proc.kill()
                await self._proc.wait()
        self._proc = None
        self._routes = []
        log.info("[ligolo] proxy stopped")

    async def add_route(self, cidr: str) -> None:
        proc = await asyncio.create_subprocess_exec(
            "ip", "route", "add", cidr, "dev", self.tun_interface,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        _, stderr = await proc.communicate()
        if proc.returncode != 0:
            err = stderr.decode(errors="replace").strip()
            if "File exists" not in err:
                raise RuntimeError(f"ip route add failed: {err}")
        if cidr not in self._routes:
            self._routes.append(cidr)
        log.info("[ligolo] route added %s via %s", cidr, self.tun_interface)

    async def remove_route(self, cidr: str) -> None:
        proc = await asyncio.create_subprocess_exec(
            "ip", "route", "del", cidr, "dev", self.tun_interface,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        await proc.communicate()
        self._routes = [r for r in self._routes if r != cidr]

    @property
    def routes(self) -> list[str]:
        return list(self._routes)

    async def log_lines(self, max_lines: int = 100) -> list[str]:
        lines: list[str] = []
        if not self._proc or not self._proc.stdout:
            return lines
        try:
            for _ in range(max_lines):
                line = await asyncio.wait_for(self._proc.stdout.readline(), timeout=0.05)
                if not line:
                    break
                lines.append(line.decode(errors="replace").rstrip())
        except asyncio.TimeoutError:
            pass
        return lines


_chisel_managers: dict[str, ChiselServerManager] = {}
_ligolo_managers: dict[str, LigoloProxyManager] = {}


def get_chisel_manager(profile_id: str, port: int = 8080, socks_port: int = 1080, auth_token: str | None = None) -> ChiselServerManager:
    if profile_id not in _chisel_managers:
        _chisel_managers[profile_id] = ChiselServerManager(port=port, socks_port=socks_port, auth_token=auth_token)
    mgr = _chisel_managers[profile_id]
    if not mgr.running:
        mgr.port = port
        mgr.socks_port = socks_port
        mgr.auth_token = auth_token
    return mgr


def get_ligolo_manager(profile_id: str, port: int = 11601, tun_interface: str = "ligolo") -> LigoloProxyManager:
    if profile_id not in _ligolo_managers:
        _ligolo_managers[profile_id] = LigoloProxyManager(port=port, tun_interface=tun_interface)
    mgr = _ligolo_managers[profile_id]
    if not mgr.running:
        mgr.port = port
        mgr.tun_interface = tun_interface
    return mgr
