import pytest
from pydantic import ValidationError

from adbygod_api.routes.loot import CrackRequest
from adbygod_api.core.loot.hash_intel import start_crack_job


def test_crack_request_rejects_invalid_tool():
    with pytest.raises(ValidationError):
        CrackRequest(hashes=["a" * 32], hashcat_mode=1000, tool="evil", acknowledge_authorized=True)


def test_crack_request_rejects_unapproved_wordlist():
    with pytest.raises(ValidationError):
        CrackRequest(hashes=["a" * 32], hashcat_mode=1000, wordlist="/etc/passwd", acknowledge_authorized=True)


@pytest.mark.asyncio
async def test_start_crack_job_rejects_invalid_tool_before_tool_lookup():
    with pytest.raises(ValueError):
        await start_crack_job("user", ["a" * 32], 1000, "/usr/share/wordlists/rockyou.txt", tool="evil")
