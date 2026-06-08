"""
PipelineExecutor — runs a (possibly obfuscated) CommandPlan step by step.

Step routing:
  PS_REMOTE   → PowerShell one-liner via asyncio subprocess (powershell.exe or pwsh)
  PS_LOCAL    → write to temp file, execute locally  (COMMAND_PLAN dry-run mode)
  LDAP_QUERY  → ldap3 execute (caller passes a live connection)
  SUBPROCESS  → asyncio.create_subprocess_exec (impacket, certipy, etc.)
  NOOP        → skip

OPSEC jitter (plan.opsec_jitter_ms > 0) adds a random sleep between steps.
"""
from __future__ import annotations

import asyncio
import logging
import random
import tempfile
import os
from datetime import datetime, timezone
from typing import Callable, Awaitable, Any

from .command_plan import CommandPlan, CommandStep, StepTechnique

log = logging.getLogger(__name__)


def _ts() -> str:
    return datetime.now(timezone.utc).isoformat()


EmitFn = Callable[[dict], Awaitable[None]]


async def _noop_emit(data: dict) -> None:
    pass


class PipelineExecutor:
    """
    Executes all steps in a CommandPlan sequentially.
    Writes results back onto each CommandStep (stdout_lines, return_code, error).
    """

    def __init__(
        self,
        ldap_conn: Any | None = None,   # ldap3 Connection, used for LDAP_QUERY steps
        ps_binary: str = "powershell",  # powershell / pwsh
    ):
        self._ldap_conn = ldap_conn
        self._ps_binary = ps_binary

    async def run(
        self,
        plan: CommandPlan,
        emit: EmitFn = _noop_emit,
    ) -> CommandPlan:
        """Execute all steps; returns the same plan with results filled in."""
        total = len(plan.steps)
        for idx, step in enumerate(plan.steps, start=1):
            if step.technique == StepTechnique.NOOP:
                continue

            await emit({
                "phase": "execute",
                "step": step.id,
                "module": step.module,
                "index": idx,
                "total": total,
                "obfsc": step.obfsc_command is not None,
            })

            try:
                await self._run_step(step, emit)
            except Exception as exc:
                step.error = str(exc)
                step.return_code = -1
                log.warning("[pipeline] step=%s error=%s", step.id, exc)
                await emit({"step": step.id, "error": str(exc), "ts": _ts()})

            # OPSEC jitter between steps
            if plan.opsec_jitter_ms > 0:
                jitter = random.randint(0, plan.opsec_jitter_ms) / 1000.0
                if jitter > 0:
                    await asyncio.sleep(jitter)

        return plan

    # ── step routing ──────────────────────────────────────────────────

    async def _run_step(self, step: CommandStep, emit: EmitFn) -> None:
        if step.technique == StepTechnique.PS_REMOTE:
            await self._run_ps_remote(step, emit)
        elif step.technique == StepTechnique.PS_LOCAL:
            await self._run_ps_local(step, emit)
        elif step.technique == StepTechnique.LDAP_QUERY:
            await self._run_ldap(step, emit)
        elif step.technique == StepTechnique.SUBPROCESS:
            await self._run_subprocess(step, emit)
        else:
            log.debug("[pipeline] unknown technique %s for step %s", step.technique, step.id)

    # ── PS_REMOTE ─────────────────────────────────────────────────────

    async def _run_ps_remote(self, step: CommandStep, emit: EmitFn) -> None:
        cmd_str = step.effective_command
        if not isinstance(cmd_str, str):
            cmd_str = " ".join(str(c) for c in cmd_str)

        argv = [self._ps_binary, "-NoP", "-NonI", "-W", "Hidden", "-C", cmd_str]
        await self._stream_subprocess(step, argv, emit)

    # ── PS_LOCAL ──────────────────────────────────────────────────────

    async def _run_ps_local(self, step: CommandStep, emit: EmitFn) -> None:
        cmd = step.effective_command
        if isinstance(cmd, str):
            script_content = cmd
        else:
            script_content = "\n".join(str(c) for c in cmd)

        fd, path = tempfile.mkstemp(suffix=".ps1", prefix="abg_")
        try:
            with os.fdopen(fd, "w") as f:
                f.write(script_content)
            argv = [self._ps_binary, "-NoP", "-NonI", "-W", "Hidden", "-File", path]
            await self._stream_subprocess(step, argv, emit)
        finally:
            try:
                os.unlink(path)
            except OSError:
                pass

    # ── LDAP_QUERY ────────────────────────────────────────────────────

    async def _run_ldap(self, step: CommandStep, emit: EmitFn) -> None:
        if self._ldap_conn is None:
            step.error = "No LDAP connection provided to PipelineExecutor"
            step.return_code = -1
            await emit({"step": step.id, "error": step.error, "ts": _ts()})
            return

        spec = step.effective_command
        if not isinstance(spec, dict):
            step.error = "LDAP_QUERY step.effective_command must be a dict"
            step.return_code = -1
            return

        base    = spec.get("base", "")
        filter_ = spec.get("filter", "(objectClass=*)")
        attrs   = spec.get("attrs", ["*"])
        scope   = spec.get("scope", "SUBTREE")

        # OPSEC: shuffle attribute ordering if requested
        if step.metadata.get("opsec_shuffle_attrs"):
            attrs = list(attrs)
            random.shuffle(attrs)

        from ldap3 import SUBTREE as LDAP_SUBTREE, BASE as LDAP_BASE, LEVEL as LDAP_LEVEL
        scope_map = {"SUBTREE": LDAP_SUBTREE, "BASE": LDAP_BASE, "LEVEL": LDAP_LEVEL}
        ldap_scope = scope_map.get(scope.upper(), LDAP_SUBTREE)

        try:
            loop = asyncio.get_running_loop()
            conn = self._ldap_conn

            def _search():
                conn.search(
                    search_base=base,
                    search_filter=filter_,
                    search_scope=ldap_scope,
                    attributes=attrs,
                )
                return list(conn.response or [])

            entries = await loop.run_in_executor(None, _search)
            step.stdout_lines = [str(e) for e in entries]
            step.return_code = 0
            await emit({
                "step": step.id, "phase": "ldap",
                "entries": len(entries), "ts": _ts(),
            })
        except Exception as exc:
            step.error = str(exc)
            step.return_code = -1
            raise

    # ── SUBPROCESS ────────────────────────────────────────────────────

    async def _run_subprocess(self, step: CommandStep, emit: EmitFn) -> None:
        cmd = step.effective_command
        if isinstance(cmd, str):
            import shlex
            argv = shlex.split(cmd)
        else:
            argv = [str(c) for c in cmd]
        await self._stream_subprocess(step, argv, emit)

    # ── helpers ───────────────────────────────────────────────────────

    async def _stream_subprocess(
        self,
        step: CommandStep,
        argv: list[str],
        emit: EmitFn,
    ) -> None:
        proc = await asyncio.create_subprocess_exec(
            *argv,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=step.env,
        )

        async def drain(stream, stream_name: str):
            assert stream is not None
            async for raw in stream:
                line = raw.decode("utf-8", errors="replace").rstrip()
                if not line:
                    continue
                if step.capture_output:
                    if stream_name == "stdout":
                        step.stdout_lines.append(line)
                    else:
                        step.stderr_lines.append(line)
                await emit({"stream": stream_name, "line": line, "step": step.id, "ts": _ts()})

        try:
            await asyncio.wait_for(
                asyncio.gather(drain(proc.stdout, "stdout"), drain(proc.stderr, "stderr")),
                timeout=step.timeout,
            )
        except asyncio.TimeoutError:
            proc.kill()
            step.error = f"step {step.id} timed out after {step.timeout}s"
            await emit({"step": step.id, "error": step.error, "ts": _ts()})

        await proc.wait()
        step.return_code = proc.returncode or 0
