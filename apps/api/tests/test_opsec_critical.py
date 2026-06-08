from adbygod_api.core.ai_operator.opsec_advisor import get_opsec_rating
from adbygod_api.core.ai_operator.critical_monitor import scan_for_critical

def test_dcsync_is_loud_or_critical():
    rating = get_opsec_rating("dcsync-domain")
    assert rating.level in ("LOUD", "CRITICAL")
    assert isinstance(rating.event_ids, list)

def test_ldap_enum_is_quiet_or_medium():
    rating = get_opsec_rating("ldap-full-enum")
    assert rating.level in ("QUIET", "MEDIUM")

def test_unknown_technique_returns_default():
    rating = get_opsec_rating("totally-unknown-technique-xyz")
    assert rating.level in ("QUIET", "MEDIUM", "LOUD", "CRITICAL")
    assert isinstance(rating.note, str)

def test_opsec_rating_is_dataclass():
    rating = get_opsec_rating("kerberoast-spns")
    assert hasattr(rating, "level")
    assert hasattr(rating, "event_ids")
    assert hasattr(rating, "note")

def test_critical_monitor_detects_ntlm_hash():
    result = [
        {"hash_type": "NTLM", "pth_ready": True, "note": "NTLM for administrator account"},
    ]
    alerts = scan_for_critical("get_credential_intel", result)
    assert len(alerts) > 0
    assert any(a["severity"] == "CRITICAL" for a in alerts)

def test_critical_monitor_detects_esc1():
    result = [{"title": "ESC1 Vulnerable Template — WebEnrollment", "module": "ADCS ESC1", "severity": "CRITICAL"}]
    alerts = scan_for_critical("list_findings", result)
    assert any("ESC1" in a["title"] for a in alerts)

def test_critical_monitor_detects_unconstrained_delegation():
    result = [{"title": "Unconstrained Delegation on EXCH01", "module": "delegation", "severity": "HIGH"}]
    alerts = scan_for_critical("list_findings", result)
    assert len(alerts) > 0

def test_no_false_positives_on_normal_graph_summary():
    result = {"entity_count": 100, "attack_path_count": 5, "summary": "100 entities"}
    alerts = scan_for_critical("get_graph_summary", result)
    assert alerts == []

def test_critical_monitor_returns_list():
    result = []
    alerts = scan_for_critical("list_findings", result)
    assert isinstance(alerts, list)
