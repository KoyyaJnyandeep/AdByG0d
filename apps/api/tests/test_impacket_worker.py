import pytest
from adbygod_api.core.workers.impacket_worker import ImpacketWorker, SUPPORTED_TECHNIQUES


def test_supported_techniques_includes_kerberoast():
    assert "kerberoast" in SUPPORTED_TECHNIQUES
    assert "asreproast" in SUPPORTED_TECHNIQUES
    assert "dcsync" in SUPPORTED_TECHNIQUES


def test_impacket_worker_instantiates():
    w = ImpacketWorker()
    assert w is not None


def test_unknown_technique_raises():
    import asyncio
    w = ImpacketWorker()
    results = []

    async def run():
        async def emit(d): results.append(d)
        await w.execute("job-1", {"technique": "nonexistent", "target": "1.2.3.4"}, emit)

    asyncio.run(run())
    assert any("error" in r or r.get("exit_code", 0) != 0 for r in results)


def test_display_cmd_redacts_domain_user_password():
    from adbygod_api.core.workers.impacket_worker import _display_cmd

    shown = _display_cmd(["impacket-wmiexec", "LAB/user:Secret123", "-target", "10.0.0.1"])

    assert "Secret123" not in shown
    assert "LAB/user:<redacted>" in shown


def test_safe_nmap_flags_reject_output_and_script_flags():
    from adbygod_api.core.workers.impacket_worker import _safe_nmap_flags

    with pytest.raises(ValueError):
        _safe_nmap_flags("-sV -oN /tmp/out")
    with pytest.raises(ValueError):
        _safe_nmap_flags("--script vuln")
    assert _safe_nmap_flags("-sV -sC -T4 --open") == ["-sV", "-sC", "-T4", "--open"]
