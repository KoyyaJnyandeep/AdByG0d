from __future__ import annotations

import logging
import shutil
import subprocess
from typing import Any, Callable

log = logging.getLogger(__name__)

AD_PORTS = "53,88,135,139,389,445,464,593,636,3268,3269,5985,5986,9389"
SMB_VULN_SCRIPTS = "smb-vuln-ms17-010,smb-vuln-ms08-067,smb2-security-mode"


class NmapCollector:
    """Network scanning and AD service fingerprinting via nmap."""

    def __init__(self, target: str, timing: str = "T4"):
        self.target = target
        self.timing = timing
        self._progress_cb: Callable | None = None

    def set_progress_callback(self, cb: Callable) -> None:
        self._progress_cb = cb

    def _emit(self, message: str, pct: int, level: str = "INFO") -> None:
        if self._progress_cb:
            self._progress_cb(message, pct, level)
        log.info("[Nmap:%s] %s", self.target, message)

    def _available(self) -> bool:
        return shutil.which("nmap") is not None

    def _run(self, args: list[str], timeout: int = 120) -> str:
        if not self._available():
            return "[!] nmap not found in PATH"
        cmd = ["nmap", f"-{self.timing}", "--open"] + args
        log.debug("NmapCollector: %s", " ".join(cmd))
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            return (r.stdout or "") + (r.stderr or "")
        except subprocess.TimeoutExpired:
            return "[!] nmap timed out"
        except Exception as exc:
            return f"[!] Error: {exc}"

    def host_discovery(self) -> dict[str, Any]:
        self._emit(f"Host discovery on {self.target}", 10)
        raw = self._run(["-sn", self.target])
        hosts = [
            line.split("for ")[-1].strip()
            for line in raw.splitlines()
            if "Nmap scan report for" in line
        ]
        return {"raw": raw, "hosts_up": hosts}

    def ad_service_scan(self, host: str | None = None) -> dict[str, Any]:
        tgt = host or self.target.split("/")[0]
        self._emit(f"AD service scan on {tgt}", 40)
        raw = self._run(["-sV", "-sC", "-p", AD_PORTS, tgt], timeout=60)
        open_ports: list[str] = []
        for line in raw.splitlines():
            if "/tcp" in line and "open" in line:
                open_ports.append(line.strip())
        return {"raw": raw, "open_ports": open_ports}

    def smb_vuln_scan(self, host: str | None = None) -> dict[str, Any]:
        tgt = host or self.target.split("/")[0]
        self._emit(f"SMB vulnerability scripts on {tgt}", 70)
        raw = self._run(["--script", SMB_VULN_SCRIPTS, "-p", "445", tgt], timeout=60)
        vulns: list[str] = []
        for line in raw.splitlines():
            if "VULNERABLE" in line or "ms17-010" in line.lower() or "ms08-067" in line.lower():
                vulns.append(line.strip())
        return {"raw": raw, "vulnerabilities": vulns}

    def collect_all(self) -> dict[str, Any]:
        self._emit(f"Starting full nmap collection against {self.target}", 0)
        result: dict[str, Any] = {"target": self.target}
        result["host_discovery"] = self.host_discovery()
        host = self.target.split("/")[0]
        result["ad_services"] = self.ad_service_scan(host)
        result["smb_vulns"] = self.smb_vuln_scan(host)
        self._emit("Nmap collection complete", 100)
        return result
