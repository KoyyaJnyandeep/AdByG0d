from __future__ import annotations

import logging
import subprocess
from typing import Any, Callable

log = logging.getLogger(__name__)


class SMBCollector:
    """Collect SMB share, session, and service data from a Windows target."""

    def __init__(
        self,
        target: str,
        domain: str,
        username: str = "",
        password: str = "",
        hashes: str = "",
    ):
        self.target = target
        self.domain = domain
        self.username = username
        self.password = password
        self.hashes = hashes
        self._progress_cb: Callable | None = None

    def set_progress_callback(self, cb: Callable) -> None:
        self._progress_cb = cb

    def _emit(self, message: str, pct: int, level: str = "INFO") -> None:
        if self._progress_cb:
            self._progress_cb(message, pct, level)
        log.info("[SMB:%s] %s", self.target, message)

    def _creds(self, with_target: bool = True) -> list[str]:
        if self.hashes:
            base = f"{self.domain}/{self.username}@{self.target}" if with_target else f"{self.domain}/{self.username}"
            return [base, "-hashes", self.hashes]
        base = f"{self.domain}/{self.username}:{self.password}@{self.target}" if with_target else f"{self.domain}/{self.username}:{self.password}"
        return [base]

    def _run(self, cmd: list[str], timeout: int = 30) -> str:
        log.debug("SMBCollector running: %s", " ".join(cmd))
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            return (r.stdout or "") + (r.stderr or "")
        except subprocess.TimeoutExpired:
            return "[!] Command timed out"
        except Exception as exc:
            return f"[!] Error: {exc}"

    def collect_shares(self) -> dict[str, Any]:
        self._emit("Enumerating shares via impacket-smbclient", 10)
        raw = self._run(["impacket-smbclient", *self._creds(), "-c", "shares"])
        shares = []
        for line in raw.splitlines():
            stripped = line.strip()
            if stripped and not stripped.startswith(("Impacket", "Type", "----", "#")):
                shares.append(stripped)
        return {"raw": raw, "shares": shares}

    def collect_sessions(self) -> dict[str, Any]:
        self._emit("Enumerating active sessions via impacket-netview", 30)
        raw = self._run(["impacket-netview", *self._creds(with_target=False), "-target", self.target], timeout=20)
        return {"raw": raw}

    def collect_rpcdump(self) -> dict[str, Any]:
        self._emit("Dumping RPC endpoints", 50)
        raw = self._run(["impacket-rpcdump", *self._creds()])
        endpoints = []
        for line in raw.splitlines():
            if "uuid" in line.lower() or "Protocol" in line:
                endpoints.append(line.strip())
        return {"raw": raw, "endpoints": endpoints}

    def collect_services(self) -> dict[str, Any]:
        self._emit("Listing services", 70)
        raw = self._run(["impacket-services", *self._creds(), "list"])
        return {"raw": raw}

    def collect_reg(self, key: str = r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa") -> dict[str, Any]:
        self._emit(f"Registry query: {key}", 85)
        raw = self._run(["impacket-reg", *self._creds(), "query", key, "/s"])
        return {"raw": raw, "key": key}

    def collect_all(self) -> dict[str, Any]:
        self._emit(f"Starting full SMB collection against {self.target}", 0)
        result: dict[str, Any] = {
            "target": self.target,
            "domain": self.domain,
            "username": self.username,
        }
        result["shares"] = self.collect_shares()
        result["sessions"] = self.collect_sessions()
        result["rpcdump"] = self.collect_rpcdump()
        result["services"] = self.collect_services()
        self._emit("SMB collection complete", 100)
        return result
