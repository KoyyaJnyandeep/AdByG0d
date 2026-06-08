from __future__ import annotations

import os
import socket
import threading
from contextlib import contextmanager
from dataclasses import dataclass
from typing import TYPE_CHECKING, Iterator

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

_SOCKET_PATCH_LOCK = threading.RLock()


@dataclass
class ProxyTransport:
    """Immutable description of how to reach the target network segment."""

    mode: str  # ConnectivityMode value
    proxy_host: str | None = None
    proxy_port: int | None = None
    via_tun: bool = False  # True for ligolo — kernel routes traffic, no SOCKS needed

    @property
    def proxy_url(self) -> str | None:
        if self.proxy_host and self.proxy_port:
            return f"socks5h://{self.proxy_host}:{self.proxy_port}"
        return None

    def subprocess_env(self, base: dict | None = None) -> dict:
        """Return env dict suitable for asyncio.create_subprocess_exec."""
        env = {**os.environ, **(base or {})}
        if self.proxy_url:
            env["ALL_PROXY"] = self.proxy_url
            env["all_proxy"] = self.proxy_url
            env["SOCKS5_PROXY"] = self.proxy_url
        return env

    @contextmanager
    def patched_socket(self) -> Iterator[None]:
        """
        Context manager: patches socket.create_connection to route through
        SOCKS5 proxy. Used by ldap3 which opens raw sockets directly.
        Safe to nest — restores original on exit.
        """
        if not (self.proxy_host and self.proxy_port) or self.via_tun:
            yield
            return

        try:
            import socks as pysocks
        except ImportError as exc:
            raise RuntimeError("PySocks not installed — run: pip install PySocks") from exc

        proxy_host = self.proxy_host
        proxy_port = self.proxy_port

        def _socks_create(address, timeout=socket._GLOBAL_DEFAULT_TIMEOUT, source_address=None):
            s = pysocks.socksocket()
            s.set_proxy(pysocks.SOCKS5, proxy_host, proxy_port)
            if timeout is not socket._GLOBAL_DEFAULT_TIMEOUT:
                s.settimeout(timeout)
            s.connect(address)
            return s

        with _SOCKET_PATCH_LOCK:
            _orig_create_connection = socket.create_connection
            _orig_socket = socket.socket
            _orig_default_proxy = pysocks.get_default_proxy()
            pysocks.set_default_proxy(pysocks.SOCKS5, proxy_host, proxy_port)
            socket.create_connection = _socks_create
            socket.socket = pysocks.socksocket
            try:
                yield
            finally:
                socket.socket = _orig_socket
                socket.create_connection = _orig_create_connection
                pysocks.set_default_proxy(*_orig_default_proxy) if _orig_default_proxy else pysocks.set_default_proxy()


# ── Factory helpers ───────────────────────────────────────────────────────────

def direct_transport() -> ProxyTransport:
    return ProxyTransport(mode="DIRECT")


def socks5_transport(host: str, port: int) -> ProxyTransport:
    return ProxyTransport(mode="SOCKS5", proxy_host=host, proxy_port=port)


def chisel_transport(socks_port: int) -> ProxyTransport:
    """Chisel server exposes SOCKS5 on localhost."""
    return ProxyTransport(mode="CHISEL", proxy_host="127.0.0.1", proxy_port=socks_port)


def ligolo_transport() -> ProxyTransport:
    """Ligolo routes via TUN — no SOCKS needed, just direct."""
    return ProxyTransport(mode="LIGOLO", via_tun=True)


def from_profile(mode: str, config: dict) -> ProxyTransport:
    """Build a ProxyTransport from a ConnectivityProfile's mode + config dict."""
    if mode == "DIRECT":
        return direct_transport()
    if mode == "SOCKS5":
        return socks5_transport(config["proxy_host"], int(config["proxy_port"]))
    if mode == "CHISEL":
        socks_port = int(config.get("socks_port", 1080))
        return chisel_transport(socks_port)
    if mode == "LIGOLO":
        return ligolo_transport()
    if mode == "RELAY_AGENT":
        host = config.get("relay_host", "127.0.0.1")
        port = int(config.get("relay_port", 1080))
        return socks5_transport(host, port)
    raise RuntimeError(f"Unsupported connectivity transport mode: {mode}")


async def resolve_transport(profile, db: "AsyncSession") -> ProxyTransport:
    """
    Async transport resolver. For MANAGED_SSH_SOCKS, query the live
    TunnelSession and require a reachable local SOCKS listener. Missing or
    broken managed tunnels fail closed instead of silently routing direct.
    For all other modes: delegates to from_profile().
    """
    from sqlalchemy import select
    from adbygod_api.core.connectivity.ssh_tunnel import is_local_tcp_listener
    from adbygod_api.models import TunnelSession, TunnelSessionStatus

    mode = profile.mode.value if hasattr(profile.mode, "value") else profile.mode

    if mode != "MANAGED_SSH_SOCKS":
        cfg = profile.config if isinstance(profile.config, dict) else {}
        return from_profile(mode, cfg)

    # Find latest active TunnelSession for this profile
    result = await db.execute(
        select(TunnelSession)
        .where(
            TunnelSession.profile_id == profile.id,
            TunnelSession.status == TunnelSessionStatus.ACTIVE,
        )
        .order_by(TunnelSession.started_at.desc())
        .limit(1)
    )
    session = result.scalar_one_or_none()
    if session is None:
        raise RuntimeError("Managed SSH SOCKS tunnel has no active session")
    if not session.local_host or not session.local_port:
        raise RuntimeError("Managed SSH SOCKS tunnel session has no usable local endpoint")
    if not await is_local_tcp_listener(session.local_host, int(session.local_port)):
        raise RuntimeError("Managed SSH SOCKS tunnel listener is not reachable")
    return socks5_transport(session.local_host, int(session.local_port))
