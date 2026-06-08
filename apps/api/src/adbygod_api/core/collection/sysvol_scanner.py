"""
SYSVOL GPP cpassword scanner — read-only, SMB-based.

Scans \\DC_IP\\SYSVOL\\<domain>\\Policies recursively for XML preference
files that contain cpassword attributes (Group Policy Preferences passwords).

Redacts the cpassword value in all stored output. Does not decrypt.
"""
from __future__ import annotations

import io
import logging
import ntpath
import re
from typing import Any

log = logging.getLogger(__name__)

CPASSWORD_RE = re.compile(r'\bcpassword="([^"]+)"', re.IGNORECASE)

GPP_TARGET_FILES = frozenset([
    "Groups.xml",
    "Services.xml",
    "ScheduledTasks.xml",
    "DataSources.xml",
    "Printers.xml",
    "Drives.xml",
])

REMEDIATION = (
    "Remove legacy GPP password XML files from SYSVOL. "
    "Rotate all credentials that may have been exposed. "
    "Use LAPS, gMSA, or modern credential management instead of GPP passwords."
)


class SysvolScanner:
    """
    Read-only SYSVOL scanner using impacket SMBConnection.

    Parameters
    ----------
    dc_ip : str
        Domain controller IP address.
    domain : str
        Fully qualified domain name (e.g. lab.local).
    username : str
        SAMAccountName or UPN for SMB authentication.
    password : str
        Plaintext password (used only in memory, never stored).
    auth_method : str
        "NTLM" (default) or "SIMPLE". SIMPLE falls back to NTLM for SMB.
    max_files : int
        Stop after this many files read (safety limit).
    progress_cb : callable
        Optional progress callback(message, pct).
    """

    def __init__(
        self,
        dc_ip: str,
        domain: str,
        username: str,
        password: str,
        auth_method: str = "NTLM",
        max_files: int = 500,
        progress_cb: Any = None,
    ):
        self.dc_ip = dc_ip
        self.domain = domain.lower()
        self.username = username
        self.password = password
        self.auth_method = auth_method.upper()
        self.max_files = max_files
        self._cb = progress_cb

    def _log(self, msg: str, pct: int = 0) -> None:
        log.info("[SYSVOL] %s", msg)
        if self._cb:
            try:
                self._cb(msg, pct)
            except Exception:
                pass

    def _connect(self):
        from impacket.smbconnection import SMBConnection
        conn = SMBConnection(self.dc_ip, self.dc_ip, timeout=10)
        if self.auth_method == "NTLM":
            ntlm_domain = self.domain.split(".")[0].upper()
            conn.login(self.username, self.password, ntlm_domain)
        else:
            conn.login(self.username, self.password, "")
        return conn

    def _list_dir(self, conn, path: str) -> list:
        """List directory entries, returning SharedFile objects."""
        try:
            return conn.listPath("SYSVOL", path + "\\*")
        except Exception as exc:
            log.debug("[SYSVOL] listPath failed for %r: %s", path, exc)
            return []

    def _read_file(self, conn, path: str) -> bytes | None:
        buf = io.BytesIO()
        try:
            conn.getFile("SYSVOL", path, buf.write)
            return buf.getvalue()
        except Exception as exc:
            log.debug("[SYSVOL] getFile failed for %r: %s", path, exc)
            return None

    def _scan_dir(self, conn, path: str, findings: list[dict],
                  files_read: list[int]) -> None:
        """Recursively scan directory for GPP XML files."""
        if files_read[0] >= self.max_files:
            return

        entries = self._list_dir(conn, path)
        for entry in entries:
            name = entry.get_longname()
            if name in (".", ".."):
                continue
            full_path = ntpath.join(path, name)

            if entry.is_directory():
                self._scan_dir(conn, full_path, findings, files_read)
            elif name in GPP_TARGET_FILES:
                files_read[0] += 1
                if files_read[0] > self.max_files:
                    return
                content = self._read_file(conn, full_path)
                if content:
                    self._check_cpassword(content, full_path, name, findings)

    def _check_cpassword(self, content: bytes, path: str, filename: str,
                         findings: list[dict]) -> None:
        try:
            text = content.decode("utf-8", errors="replace")
        except Exception:
            return

        matches = CPASSWORD_RE.findall(text)
        if not matches:
            return

        # Redact — do NOT store the actual encrypted value
        redacted_text = CPASSWORD_RE.sub('cpassword="***REDACTED***"', text)

        gpo_guid = ""
        parts = path.replace("\\", "/").split("/")
        for part in parts:
            if part.startswith("{") and part.endswith("}"):
                gpo_guid = part
                break

        log.warning("[SYSVOL] cpassword found in %s (GPO: %s)", path, gpo_guid or "unknown")
        findings.append({
            "file_path": path,
            "filename": filename,
            "gpo_guid": gpo_guid,
            "cpassword_count": len(matches),
            "redacted_content_preview": redacted_text[:500],
        })

    def scan(self) -> tuple[list[dict], list[dict]]:
        """
        Scan SYSVOL for GPP cpassword exposure.

        Returns
        -------
        findings : list[dict]
            One dict per file containing cpassword.
        evidence_records : list[dict]
            EvidenceRecord-compatible dicts.
        """
        self._log("SYSVOL: connecting…", 90)
        findings: list[dict] = []
        evidence: list[dict] = []

        try:
            conn = self._connect()
        except Exception as exc:
            log.warning("[SYSVOL] Connection failed: %s", exc)
            evidence.append({
                "id": "sysvol-scan",
                "source_type": "smb",
                "collection_method": "sysvol/gpp",
                "origin": "COLLECTED",
                "raw_data": {"error": str(exc), "scanned": False},
                "confidence": 0.0,
            })
            return findings, evidence

        policies_path = f"\\{self.domain}\\Policies"
        self._log(f"SYSVOL: scanning {policies_path}…", 91)
        files_read = [0]

        try:
            self._scan_dir(conn, policies_path, findings, files_read)
        except Exception as exc:
            log.warning("[SYSVOL] Scan error: %s", exc)
        finally:
            try:
                conn.logoff()
            except Exception:
                pass

        self._log(f"SYSVOL: {files_read[0]} files read, {len(findings)} cpassword files", 92)

        evidence.append({
            "id": "sysvol-scan",
            "source_type": "smb",
            "source_host": self.dc_ip,
            "collection_method": "sysvol/gpp",
            "origin": "COLLECTED",
            "raw_data": {
                "files_read": files_read[0],
                "cpassword_files": len(findings),
                "policies_path": policies_path,
                "findings": [
                    {
                        "file_path": f["file_path"],
                        "filename": f["filename"],
                        "gpo_guid": f["gpo_guid"],
                        "cpassword_count": f["cpassword_count"],
                    }
                    for f in findings
                ],
            },
            "confidence": 1.0,
        })

        return findings, evidence
