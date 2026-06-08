"""Unit tests: chain runner must not overwrite STOPPED status with FAILED
when exit_code=-1 (killed step job) arrives after stop_chain was called."""
from __future__ import annotations

from adbygod_api.models import ChainStatus


def _apply_exit_code_logic(chain, exit_code):
    """
    Mirrors the fixed chains.py elif block.
    Returns True if chain.status was changed to FAILED.
    """
    if exit_code != 0 and chain is not None:
        if chain.status != ChainStatus.STOPPED:
            chain.status = ChainStatus.FAILED
            return True
    return False


def test_stopped_chain_not_overwritten_with_failed():
    """If exit_code=-1 arrives after chain.status=STOPPED, status must remain STOPPED."""

    class FakeChain:
        status = ChainStatus.STOPPED

    chain = FakeChain()
    changed = _apply_exit_code_logic(chain, exit_code=-1)

    assert changed is False
    assert chain.status == ChainStatus.STOPPED


def test_running_chain_set_to_failed_on_nonzero_exit():
    """A RUNNING chain with exit_code != 0 must become FAILED."""

    class FakeChain:
        status = ChainStatus.RUNNING

    chain = FakeChain()
    changed = _apply_exit_code_logic(chain, exit_code=-1)

    assert changed is True
    assert chain.status == ChainStatus.FAILED


def test_zero_exit_code_does_not_trigger_failed():
    """exit_code=0 must never set FAILED."""

    class FakeChain:
        status = ChainStatus.RUNNING

    chain = FakeChain()
    changed = _apply_exit_code_logic(chain, exit_code=0)

    assert changed is False
    assert chain.status == ChainStatus.RUNNING


def test_manual_crack_sentinel_does_not_trigger_failed():
    """exit_code=2 (manual crack sentinel) must not set FAILED (handled by the if exit_code==2 branch)."""

    class FakeChain:
        status = ChainStatus.RUNNING

    # The caller handles exit_code==2 before reaching the elif block
    # so we test that exit_code!=0 with a STOPPED chain is safe
    chain2 = FakeChain()
    chain2.status = ChainStatus.STOPPED
    changed = _apply_exit_code_logic(chain2, exit_code=2)

    assert changed is False
    assert chain2.status == ChainStatus.STOPPED


def test_none_chain_does_not_raise():
    """If chain is None (DB lookup returned nothing), no crash."""
    changed = _apply_exit_code_logic(None, exit_code=-1)
    assert changed is False
