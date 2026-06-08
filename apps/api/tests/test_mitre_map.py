from __future__ import annotations
from adbygod_api.core.kill_chain.mitre_map import get_mitre, suggest_cvss, ALL_TECHNIQUE_IDS


def test_known_recon_technique():
    r = get_mitre("recon-rid-cycling")
    assert r["mitre_id"] == "T1087.002"
    assert r["tactic"] == "reconnaissance"
    assert isinstance(r["cvss"], float)


def test_known_ia_technique():
    r = get_mitre("ia-responder-capture")
    assert r["mitre_id"] == "T1557.001"
    assert r["tactic"] == "credential_access"


def test_known_existing_technique():
    r = get_mitre("privesc-kerberoast-impacket")
    assert r["mitre_id"] == "T1558.003"


def test_unknown_technique_returns_none():
    assert get_mitre("not-a-real-id") is None


def test_suggest_cvss_critical():
    score = suggest_cvss("CRITICAL")
    assert score >= 9.0


def test_suggest_cvss_low():
    score = suggest_cvss("LOW")
    assert score < 5.0


def test_all_technique_ids_is_list():
    assert isinstance(ALL_TECHNIQUE_IDS, list)
    assert "recon-rid-cycling" in ALL_TECHNIQUE_IDS
    assert "ia-amsi-bypass" in ALL_TECHNIQUE_IDS
