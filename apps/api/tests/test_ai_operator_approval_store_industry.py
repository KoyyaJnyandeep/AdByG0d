"""
Industry hardening tests for ApprovalStore.

Guards validated:
- cross-user approval prevention
- expiry enforcement
- replay prevention (already approved or already rejected)
- action hash mismatch
- tool name mismatch
- approved_by / approved_at population
- assessment_id binding
- as_event_dict() sensitive-arg scrubbing
- request_not_found on unknown ID
"""
from __future__ import annotations

import time


from adbygod_api.core.ai_operator.approval_store import ApprovalStore


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_store(ttl: float = 300.0) -> ApprovalStore:
    return ApprovalStore(ttl_seconds=ttl)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_user_cannot_approve_other_user_request():
    """User B must not be able to approve a request owned by user A."""
    store = make_store()
    req_id = store.create(
        "execute_technique", {"technique_id": "T1003"}, "DCSync", user_id="user-A"
    )
    ok, reason = store.resolve(req_id, approved=True, user_id="user-B")
    assert ok is False
    assert reason == "user_mismatch"


def test_expired_request_rejected():
    """A request whose TTL has elapsed must be rejected with 'expired'."""
    store = make_store(ttl=0.001)  # 1 ms TTL
    req_id = store.create("execute_technique", {}, "desc", user_id="user-A")
    # Busy-wait until the TTL has definitely elapsed
    time.sleep(0.05)
    ok, reason = store.resolve(req_id, approved=True, user_id="user-A")
    assert ok is False
    assert reason == "expired"


def test_already_approved_cannot_replay():
    """Approving a request that was already approved must fail with 'already_resolved'."""
    store = make_store()
    req_id = store.create("execute_technique", {}, "desc", user_id="user-A")
    ok1, reason1 = store.resolve(req_id, approved=True, user_id="user-A")
    assert ok1 is True
    assert reason1 == "ok"

    ok2, reason2 = store.resolve(req_id, approved=True, user_id="user-A")
    assert ok2 is False
    assert reason2 == "already_resolved"


def test_rejected_request_cannot_approve_later():
    """A rejected request cannot later be approved (already_resolved)."""
    store = make_store()
    req_id = store.create("execute_technique", {}, "desc", user_id="user-A")
    ok1, _ = store.resolve(req_id, approved=False, user_id="user-A")
    assert ok1 is True

    ok2, reason2 = store.resolve(req_id, approved=True, user_id="user-A")
    assert ok2 is False
    assert reason2 == "already_resolved"


def test_action_hash_mismatch_rejected():
    """Passing a wrong expected_action_hash must reject with 'action_mismatch'."""
    store = make_store()
    req_id = store.create(
        "execute_technique", {"technique_id": "T1003"}, "desc", user_id="user-A"
    )
    ok, reason = store.resolve(
        req_id,
        approved=True,
        user_id="user-A",
        expected_action_hash="deadbeef" * 8,  # 64-char hex but wrong value
    )
    assert ok is False
    assert reason == "action_mismatch"


def test_tool_mismatch_rejected():
    """Passing a wrong expected_tool_name must reject with 'tool_mismatch'."""
    store = make_store()
    req_id = store.create(
        "execute_technique", {}, "desc", user_id="user-A"
    )
    ok, reason = store.resolve(
        req_id,
        approved=True,
        user_id="user-A",
        expected_tool_name="run_shell_command",  # not what was stored
    )
    assert ok is False
    assert reason == "tool_mismatch"


def test_approval_stores_approved_by_and_at():
    """After a successful approve, approved_by and approved_at must be populated."""
    store = make_store()
    req_id = store.create("execute_technique", {}, "desc", user_id="user-A")
    ok, reason = store.resolve(req_id, approved=True, user_id="user-A")
    assert ok is True
    assert reason == "ok"

    pending = store.get(req_id)
    assert pending is not None
    assert pending.approved_by == "user-A"
    assert pending.approved_at is not None
    assert pending.status == "approved"


def test_assessment_id_stored_in_request():
    """Assessment ID passed to create() must be retrievable from the pending record."""
    store = make_store()
    assessment_id = "assess-99"
    req_id = store.create(
        "execute_technique",
        {},
        "desc",
        user_id="user-A",
        assessment_id=assessment_id,
        workspace_id="ws-1",
        session_id="sess-abc",
    )
    pending = store.get(req_id)
    assert pending is not None
    assert pending.assessment_id == assessment_id
    assert pending.workspace_id == "ws-1"
    assert pending.session_id == "sess-abc"


def test_as_event_dict_scrubs_sensitive_args():
    """Sensitive arg keys must appear as [REDACTED] in the SSE payload."""
    store = make_store()
    req_id = store.create(
        "execute_technique",
        {
            "password": "s3cr3t!",
            "token": "eyJhbGci...",
            "technique_id": "T1558",
            "key": "rsa-private",
            "secret": "top-secret",
            "credential": "NTLM-hash",
            "normal_param": "value",
        },
        "desc",
    )
    pending = store.get(req_id)
    d = pending.as_event_dict()

    assert d["args"]["password"] == "[REDACTED]"
    assert d["args"]["token"] == "[REDACTED]"
    assert d["args"]["key"] == "[REDACTED]"
    assert d["args"]["secret"] == "[REDACTED]"
    assert d["args"]["credential"] == "[REDACTED]"
    assert d["args"]["technique_id"] == "T1558"
    assert d["args"]["normal_param"] == "value"
    # expires_at must be present
    assert "expires_at" in d


def test_request_not_found_returns_false():
    """Resolving a completely unknown request_id must return (False, 'request_not_found')."""
    store = make_store()
    ok, reason = store.resolve("00000000-0000-0000-0000-000000000000", approved=True)
    assert ok is False
    assert reason == "request_not_found"
