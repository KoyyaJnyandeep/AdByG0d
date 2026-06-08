"""
CommandPlan — structured representation of what to execute.

A plan is built by a module (LDAPCollector, ImpacketWorker, etc.) BEFORE
any execution starts.  The ObfscTransformer then optionally rewrites the
steps, and PipelineExecutor runs them.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class StepTechnique(str, Enum):
    # Server-side Python — obfsc doesn't apply to these
    LDAP_QUERY     = "ldap_query"       # ldap3 Python query
    SUBPROCESS     = "subprocess"       # generic subprocess (impacket CLI, certipy, etc.)
    # PS execution sent to remote Windows — obfsc applies here
    PS_REMOTE      = "ps_remote"        # PowerShell sent via WinRM / wmiexec / smbexec
    PS_LOCAL       = "ps_local"         # PowerShell invoked locally (COMMAND_PLAN export)
    # Meta
    NOOP           = "noop"             # placeholder / disabled step


@dataclass
class CommandStep:
    """One atomic execution unit inside a CommandPlan."""
    id: str                              = field(default_factory=lambda: str(uuid.uuid4())[:8])
    module: str                          = ""         # e.g. "kerberos", "acl", "ldap_enum"
    technique: StepTechnique             = StepTechnique.SUBPROCESS
    # raw_command: the original, un-obfuscated command
    #   str  → PS / shell one-liner
    #   list → argv list (subprocess)
    #   dict → LDAP query spec {base, filter, attrs, scope}
    raw_command: str | list[str] | dict  = field(default_factory=str)
    # obfsc_command: filled in by ObfscTransformer; None means "use raw_command"
    obfsc_command: str | list[str] | dict | None = None
    env: dict[str, str] | None           = None
    timeout: int                         = 120       # seconds
    capture_output: bool                 = False     # True → accumulate lines for parser
    metadata: dict[str, Any]             = field(default_factory=dict)

    # ── runtime fields (filled by executor) ──────────────────────────
    stdout_lines: list[str]              = field(default_factory=list, repr=False)
    stderr_lines: list[str]              = field(default_factory=list, repr=False)
    return_code: int | None              = None
    error: str | None                    = None

    @property
    def effective_command(self) -> str | list[str] | dict:
        """Return obfsc_command if set, else raw_command."""
        return self.obfsc_command if self.obfsc_command is not None else self.raw_command

    @property
    def is_ps(self) -> bool:
        return self.technique in (StepTechnique.PS_REMOTE, StepTechnique.PS_LOCAL)

    @property
    def is_ldap(self) -> bool:
        return self.technique == StepTechnique.LDAP_QUERY


@dataclass
class CommandPlan:
    """
    Full ordered execution plan for one collection/operation.

    Lifecycle:
        1. Module builds the plan (steps with raw_command filled).
        2. ObfscTransformer.transform(plan) rewrites steps if enabled.
        3. PipelineExecutor.run(plan, emit) executes each step.
        4. OutputNormalizer.process(plan) cleans results.
    """
    plan_id: str                     = field(default_factory=lambda: str(uuid.uuid4()))
    assessment_id: str               = ""
    operation: str                   = ""        # e.g. "ldap_collection", "kerberoast"
    steps: list[CommandStep]         = field(default_factory=list)

    # ── obfuscation config ────────────────────────────────────────────
    obfuscation_enabled: bool        = False
    # technique: 0-13 matching frontend TechniqueId, or "auto" (picks best fit per step)
    obfuscation_technique: int | str = "auto"

    # ── OPSEC config (for LDAP OPSEC hardening) ──────────────────────
    opsec_jitter_ms: int             = 0         # 0 = disabled; random delay per step
    opsec_shuffle_attrs: bool        = False     # randomise LDAP attribute ordering

    metadata: dict[str, Any]        = field(default_factory=dict)

    # ── convenience ──────────────────────────────────────────────────
    def add_step(self, **kwargs) -> CommandStep:
        step = CommandStep(**kwargs)
        self.steps.append(step)
        return step

    def ps_steps(self) -> list[CommandStep]:
        return [s for s in self.steps if s.is_ps]

    def ldap_steps(self) -> list[CommandStep]:
        return [s for s in self.steps if s.is_ldap]

    def subprocess_steps(self) -> list[CommandStep]:
        return [s for s in self.steps if s.technique == StepTechnique.SUBPROCESS]
