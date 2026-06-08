from __future__ import annotations
from adbygod_api.core.kill_chain.tracker import (
    PHASES, compute_phase_coverage_sync, suggest_next_techniques,
)


def test_phases_has_9_entries():
    assert len(PHASES) == 9
    assert PHASES[0].phase_id == 0
    assert PHASES[0].label == "Reconnaissance"
    assert PHASES[8].phase_id == 8


def test_compute_phase_coverage_empty():
    results = compute_phase_coverage_sync(recon_findings=[], techniques_run=[])
    assert len(results) == 9
    assert all(r["status"] == "not_started" for r in results)
    assert all(r["completion_pct"] == 0 for r in results)


def test_compute_phase0_with_recon_findings():
    results = compute_phase_coverage_sync(
        recon_findings=[{"type": "ldap_exposure"}, {"type": "smb_null"}],
        techniques_run=[],
    )
    phase0 = next(r for r in results if r["phase_id"] == 0)
    assert phase0["status"] in ("partial", "complete")
    assert phase0["completion_pct"] > 0


def test_compute_phase1_with_ia_techniques():
    results = compute_phase_coverage_sync(
        recon_findings=[],
        techniques_run=["ia-responder-capture", "ia-ntlm-relay", "ia-amsi-bypass"],
    )
    phase1 = next(r for r in results if r["phase_id"] == 1)
    assert "ia-responder-capture" in phase1["techniques_run"]
    assert phase1["status"] in ("partial", "complete")


def test_suggest_anon_ldap_recommends_rid_cycling():
    suggestions = suggest_next_techniques(
        recon_findings=[{"finding_type": "ANONYMOUS_LDAP_ENABLED", "type": "ldap_exposure"}],
        techniques_run=[],
        graph_signals={},
    )
    ids = [s["technique_id"] for s in suggestions]
    assert "recon-rid-cycling" in ids


def test_suggest_timeroast_finding_recommends_ia():
    suggestions = suggest_next_techniques(
        recon_findings=[{"finding_type": "TIMEROAST_EXPOSURE", "type": "timeroast_exposure"}],
        techniques_run=[],
        graph_signals={},
    )
    ids = [s["technique_id"] for s in suggestions]
    assert any(tid in ids for tid in ["ia-timeroast", "ia-pre2k-detect"])


def test_suggest_empty_recommends_phase0_start():
    suggestions = suggest_next_techniques(
        recon_findings=[],
        techniques_run=[],
        graph_signals={},
    )
    assert len(suggestions) > 0
    assert suggestions[0]["phase_id"] == 0
