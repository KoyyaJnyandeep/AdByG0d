"""
OutputNormalizer — strips obfuscation artefacts from executor output.

After the Executor runs obfuscated PS steps the raw stdout may contain
decode-time noise (base64 prefix echoes, variable dumps, etc.).  This layer
cleans it so the Parser sees plain structured output regardless of which
obfuscation technique was used.

For SUBPROCESS steps (impacket) output is already structured — normalizer
just applies standard whitespace / colour-code stripping.
"""
from __future__ import annotations

import re
from typing import Sequence

from .command_plan import CommandPlan, CommandStep

# ANSI colour codes
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")

# Lines that are artefacts from obfsc decode stages we want to discard
_OBFSC_NOISE_PATTERNS: list[re.Pattern] = [
    re.compile(r"^\$_[a-z]+="),                        # internal obfsc vars echoed
    re.compile(r"^&\(\["),                             # scriptblock invocation echo
    re.compile(r"^\[System\."),                        # .NET type echo
    re.compile(r"^pOwErShElL\s+-", re.IGNORECASE),    # obfsc powershell invocation echo
    re.compile(r"^\s*$"),                              # blank lines
]

# Standard noise from impacket / certipy tools
_TOOL_NOISE_PATTERNS: list[re.Pattern] = [
    re.compile(r"^\[?\*\]?\s+Protocol Client"),
    re.compile(r"^Impacket\s+v"),
    re.compile(r"^\s+\[#\]"),
    re.compile(r"^ServicePrincipalName\s+Name\s+MemberOf"),  # kerberoast header dupe
]


def _strip_ansi(line: str) -> str:
    return _ANSI_RE.sub("", line)


def _is_obfsc_noise(line: str) -> bool:
    return any(p.search(line) for p in _OBFSC_NOISE_PATTERNS)


def _is_tool_noise(line: str) -> bool:
    return any(p.search(line) for p in _TOOL_NOISE_PATTERNS)


class OutputNormalizer:
    """
    Process a completed CommandPlan: clean each step's output lines in-place.

    strip_obfsc_noise  — remove lines that are artefacts of the obfsc wrapper
    strip_tool_noise   — remove boilerplate from impacket/certipy tool headers
    strip_ansi         — remove ANSI colour codes
    """

    def __init__(
        self,
        strip_obfsc_noise: bool = True,
        strip_tool_noise: bool = True,
        strip_ansi: bool = True,
    ):
        self._strip_obfsc = strip_obfsc_noise
        self._strip_tool  = strip_tool_noise
        self._strip_ansi  = strip_ansi

    def process(self, plan: CommandPlan) -> CommandPlan:
        """Normalise all steps in plan in-place.  Returns same plan."""
        for step in plan.steps:
            step.stdout_lines = self._clean(step.stdout_lines, step)
            step.stderr_lines = self._clean(step.stderr_lines, step)
        return plan

    def clean_lines(
        self,
        lines: Sequence[str],
        obfsc_active: bool = False,
    ) -> list[str]:
        """Standalone helper — clean a list of lines without a full plan."""
        cleaned = []
        for line in lines:
            if self._strip_ansi:
                line = _strip_ansi(line)
            if self._strip_obfsc and obfsc_active and _is_obfsc_noise(line):
                continue
            if self._strip_tool and _is_tool_noise(line):
                continue
            cleaned.append(line)
        return cleaned

    # ── internals ─────────────────────────────────────────────────────

    def _clean(self, lines: list[str], step: CommandStep) -> list[str]:
        obfsc_active = step.obfsc_command is not None
        return self.clean_lines(lines, obfsc_active=obfsc_active)
