"""Unit tests for lateral movement analyzer."""
from __future__ import annotations
from adbygod_api.core.analyzers.lateral_movement_analyzer import (
    detect_lm_techniques,
    match_chains,
    summarise_lm,
    LM_TECHNIQUE_CATALOGUE,
)


def _edge(edge_type: str, src="HOST1", dst="HOST2"):
    return {"edge_type": edge_type, "src": src, "dst": dst}


def test_pth_detected():
    edges = [_edge("PASS_THE_HASH")]
    results = detect_lm_techniques(edges, [])
    ids = [t["technique_id"] for t in results]
    assert "PTH" in ids


def test_petitpotam_detected():
    edges = [_edge("PETITPOTAM"), _edge("ADCS_ESC8")]
    results = detect_lm_techniques(edges, [])
    ids = [t["technique_id"] for t in results]
    assert "PETITPOTAM_ADCS_ESC8" in ids


def test_shadow_credentials_detected():
    edges = [_edge("ADD_KEY_CREDENTIAL_LINK")]
    results = detect_lm_techniques(edges, [])
    ids = [t["technique_id"] for t in results]
    assert "SHADOW_CREDENTIALS_CHAIN" in ids


def test_nopac_detected():
    edges = [_edge("CVE_CHAIN"), _edge("MACHINE_ACCOUNT")]
    results = detect_lm_techniques(edges, [])
    ids = [t["technique_id"] for t in results]
    assert "NOPAC" in ids


def test_chain_matching_petitpotam():
    techniques = [{"technique_id": "PETITPOTAM_ADCS_ESC8"}]
    chains = match_chains(techniques)
    chain_ids = [c["chain_id"] for c in chains]
    assert "PETITPOTAM_ESC8_DA" in chain_ids


def test_chain_not_matched_when_missing_technique():
    techniques = [{"technique_id": "PTH"}]
    chains = match_chains(techniques)
    chain_ids = [c["chain_id"] for c in chains]
    assert "WEBCLIENT_RBCD_LM" not in chain_ids


def test_summarise_lm_structure():
    edges = [_edge("PASS_THE_HASH"), _edge("PETITPOTAM")]
    summary = summarise_lm(edges, [])
    assert "total_paths" in summary
    assert "techniques_detected" in summary
    assert "chains" in summary
    assert summary["techniques_detected"] >= 1


def test_no_false_positives_on_empty_edges():
    results = detect_lm_techniques([], [])
    assert results == []


def test_deduplication():
    edges = [_edge("PASS_THE_HASH"), _edge("PASS_THE_HASH"), _edge("PASS_THE_HASH")]
    results = detect_lm_techniques(edges, [])
    ids = [t["technique_id"] for t in results]
    assert ids.count("PTH") == 1


def test_catalogue_completeness():
    expected_ids = {
        "PTH", "PTT", "PKINIT_CERT", "OVERPASS_THE_HASH", "SHADOW_CREDENTIALS_CHAIN",
        "S4U_DELEGATION", "LAPS_PASSWORD_READ", "GMSA_PASSWORD_READ",
        "PETITPOTAM_ADCS_ESC8", "WEBCLIENT_NTLM_RELAY", "NOPAC", "AADCONNECT_PWSYNC",
        "ADCS_ESC1_CERT_ABUSE", "ADCS_ESC8_RELAY", "GPO_EXEC",
    }
    assert expected_ids.issubset(set(LM_TECHNIQUE_CATALOGUE.keys()))
