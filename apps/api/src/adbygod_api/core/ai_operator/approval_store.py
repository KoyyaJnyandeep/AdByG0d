from __future__ import annotations
import asyncio
import hashlib
import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone


@dataclass
class PendingApproval:
    request_id: str
    user_id: str
    tool_name: str
    args: dict
    description: str
    opsec_rating: str
    opsec_note: str
    # Binding context
    assessment_id: str = ""
    workspace_id: str = ""
    session_id: str = ""
    # Timestamps
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    # Resolution metadata
    approved_by: str = ""
    approved_at: datetime | None = None
    status: str = "pending"  # pending | approved | rejected | expired
    # Action integrity
    action_hash: str = ""  # SHA-256 of tool_name + sorted args
    # Internal async primitive
    _event: asyncio.Event = field(default_factory=asyncio.Event)
    approved: bool | None = None

    _SENSITIVE_KEYS = frozenset({"password", "secret", "token", "key", "credential"})

    def as_event_dict(self) -> dict:
        scrubbed_args = {
            k: "[REDACTED]" if k.lower() in self._SENSITIVE_KEYS else v
            for k, v in self.args.items()
        }
        return {
            "type": "approval_required",
            "request_id": self.request_id,
            "tool": self.tool_name,
            "args": scrubbed_args,
            "description": self.description,
            "opsec_rating": self.opsec_rating,
            "opsec_note": self.opsec_note,
            "expires_at": self.expires_at.isoformat(),
        }


class ApprovalStore:
    def __init__(self, ttl_seconds: float = 300.0):
        self._pending: dict[str, PendingApproval] = {}
        self._ttl = ttl_seconds

    def create(
        self,
        tool_name: str,
        args: dict,
        description: str,
        opsec_rating: str = "MEDIUM",
        opsec_note: str = "",
        user_id: str = "",
        assessment_id: str = "",
        workspace_id: str = "",
        session_id: str = "",
    ) -> str:
        request_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc)
        action_hash = hashlib.sha256(
            f"{tool_name}:{json.dumps(args, sort_keys=True)}".encode()
        ).hexdigest()
        self._pending[request_id] = PendingApproval(
            request_id=request_id,
            user_id=user_id,
            tool_name=tool_name,
            args=args,
            description=description,
            opsec_rating=opsec_rating,
            opsec_note=opsec_note,
            assessment_id=assessment_id,
            workspace_id=workspace_id,
            session_id=session_id,
            created_at=now,
            expires_at=now + timedelta(seconds=self._ttl),
            action_hash=action_hash,
        )
        return request_id

    def get(self, request_id: str) -> PendingApproval | None:
        return self._pending.get(request_id)

    def resolve(
        self,
        request_id: str,
        approved: bool,
        user_id: str = "",
        expected_tool_name: str | None = None,
        expected_action_hash: str | None = None,
    ) -> tuple[bool, str]:
        """
        Validate and resolve a pending approval request.

        Returns (success, reason).  success=False if any guard fails.

        Reason codes:
          ok                – resolved successfully
          request_not_found – unknown request_id
          already_resolved  – status is not 'pending' (replay prevention)
          expired           – request TTL has elapsed
          user_mismatch     – approver is not the request owner
          action_mismatch   – expected_action_hash does not match stored hash
          tool_mismatch     – expected_tool_name does not match stored tool
        """
        pending = self._pending.get(request_id)
        if not pending:
            return False, "request_not_found"

        # Replay prevention: already resolved
        if pending.status != "pending":
            return False, "already_resolved"

        # Expiry check
        if datetime.now(timezone.utc) > pending.expires_at:
            pending.status = "expired"
            return False, "expired"

        # User binding: approver must match the request owner
        if user_id and pending.user_id and pending.user_id != user_id:
            return False, "user_mismatch"

        # Action hash validation (optional)
        if expected_action_hash and pending.action_hash != expected_action_hash:
            return False, "action_mismatch"

        # Tool name validation (optional)
        if expected_tool_name and pending.tool_name != expected_tool_name:
            return False, "tool_mismatch"

        # All checks passed — resolve
        pending.approved = approved
        pending.status = "approved" if approved else "rejected"
        pending.approved_by = user_id
        pending.approved_at = datetime.now(timezone.utc)
        pending._event.set()
        return True, "ok"

    async def wait(self, request_id: str, timeout: float | None = None) -> bool | None:
        pending = self._pending.get(request_id)
        if not pending:
            return None
        ttl = timeout if timeout is not None else self._ttl
        try:
            await asyncio.wait_for(pending._event.wait(), timeout=ttl)
            return pending.approved
        except asyncio.TimeoutError:
            return None
        finally:
            self._pending.pop(request_id, None)

    def cleanup_expired(self) -> None:
        now = datetime.now(timezone.utc)
        expired = [rid for rid, p in self._pending.items() if now > p.expires_at]
        for rid in expired:
            self._pending.pop(rid, None)


_store = ApprovalStore()


def get_approval_store() -> ApprovalStore:
    return _store
