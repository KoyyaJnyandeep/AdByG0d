"""Unit tests for TrustAbuseAnalyzer detection logic."""
from __future__ import annotations
from adbygod_api.core.analyzers.trust_abuse_analyzer import (
    detect_trust_techniques,
    score_technique_severity,
    TECHNIQUE_CATALOGUE,
)


def _trust(name="CORP.LOCAL", direction_val=3, attrs_raw=0, sid_filtering=False,
           forest_trust=False, transitive=True, trust_type="Uplevel (AD)",
           when_changed_days=60):
    return {
        "name": name, "direction_val": direction_val, "attrs_raw": attrs_raw,
        "sid_filtering": sid_filtering, "forest_trust": forest_trust,
        "transitive": transitive, "trust_type": trust_type,
        "when_changed_days": when_changed_days, "direction": "Bidirectional",
        "attribute_flags": [],
    }


def test_sid_history_injection_detected():
    trusts = [_trust(sid_filtering=False, direction_val=1)]
    results = detect_trust_techniques(trusts, entities=[], edges=[])
    ids = [t["technique_id"] for t in results]
    assert "SID_HISTORY_INJECTION" in ids


def test_extrasid_detected_on_forest_trust_no_sid_filter():
    trusts = [_trust(forest_trust=True, sid_filtering=False, direction_val=3)]
    results = detect_trust_techniques(trusts, entities=[], edges=[])
    ids = [t["technique_id"] for t in results]
    assert "EXTRASID_GOLDEN_TICKET" in ids


def test_rc4_downgrade_detected():
    trusts = [_trust(attrs_raw=0x080)]
    results = detect_trust_techniques(trusts, entities=[], edges=[])
    ids = [t["technique_id"] for t in results]
    assert "RC4_TRUST_DOWNGRADE" in ids


def test_trust_password_overlap_detected():
    trusts = [_trust(when_changed_days=10)]
    results = detect_trust_techniques(trusts, entities=[], edges=[])
    ids = [t["technique_id"] for t in results]
    assert "TRUST_PASSWORD_OVERLAP_WINDOW" in ids


def test_cross_trust_kerberoasting_detected():
    entities = [{"entity_type": "USER", "domain": "TRUSTED.LOCAL", "attributes": {"spns": ["MSSQLSvc/db.trusted.local:1433"]}}]
    trusts = [_trust(name="TRUSTED.LOCAL", direction_val=2)]
    results = detect_trust_techniques(trusts, entities=entities, edges=[])
    ids = [t["technique_id"] for t in results]
    assert "CROSS_TRUST_KERBEROASTING" in ids


def test_cross_trust_asrep_detected():
    entities = [{"entity_type": "USER", "domain": "TRUSTED.LOCAL", "attributes": {"asrep_roastable": True}}]
    trusts = [_trust(name="TRUSTED.LOCAL", direction_val=2)]
    results = detect_trust_techniques(trusts, entities=entities, edges=[])
    ids = [t["technique_id"] for t in results]
    assert "CROSS_TRUST_ASREP_ROASTING" in ids


def test_severity_scoring_critical_for_sid_injection():
    assert score_technique_severity("SID_HISTORY_INJECTION") == "CRITICAL"


def test_technique_catalogue_has_all_expected_ids():
    expected = {
        "SID_HISTORY_INJECTION", "EXTRASID_GOLDEN_TICKET", "PAM_TRUST_ABUSE",
        "TRANSITIVE_DELEGATION", "TRUST_ESCALATION_CHAIN", "TRUST_KEY_EXTRACTION_FORGERY",
        "RC4_TRUST_DOWNGRADE", "TRUST_PASSWORD_OVERLAP_WINDOW", "SELECTIVE_AUTH_BYPASS",
        "CROSS_TRUST_KERBEROASTING", "CROSS_TRUST_ASREP_ROASTING",
        "CROSS_TRUST_ADCS_ESC1_ESC8", "CROSS_TRUST_SHADOW_CREDENTIALS",
        "BRONZE_BIT_CROSS_TRUST", "SAPPHIRE_DIAMOND_TICKET",
        "TDO_MANIPULATION", "PAC_VALIDATION_BYPASS", "RODC_CROSS_TRUST_CACHE",
        "SID_FILTER_PARTIAL_BYPASS", "MIT_KERBEROS_REALM_TRUST",
        "NOPAC_CROSS_TRUST", "FAST_ARMORING_BYPASS",
    }
    assert expected.issubset(set(TECHNIQUE_CATALOGUE.keys()))


def test_no_false_positives_on_clean_trust():
    trusts = [_trust(sid_filtering=True, direction_val=2, attrs_raw=0, when_changed_days=90)]
    results = detect_trust_techniques(trusts, entities=[], edges=[])
    # SID filtering on + no RC4 + no recent change = no Tier 1/2 hits
    tier1_2 = [t for t in results if t["tier"] <= 2]
    assert len(tier1_2) == 0


def test_deduplication_no_double_hits():
    trusts = [_trust(sid_filtering=False, direction_val=1), _trust(name="EXTRA.LOCAL", sid_filtering=False, direction_val=1)]
    results = detect_trust_techniques(trusts, entities=[], edges=[])
    ids = [t["technique_id"] for t in results]
    assert len(ids) == len(set(ids))
