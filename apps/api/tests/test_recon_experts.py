from __future__ import annotations
from unittest.mock import MagicMock
from adbygod_api.core.validation.contracts import ExpertVerdict
from adbygod_api.core.validation.experts.pre2k_exposure import Pre2kExposureExpert
from adbygod_api.core.validation.experts.recon_exposure import ReconExposureExpert


def _ctx(findings=None, entities=None, evidence=None):
    ctx = MagicMock()
    ctx.findings = findings or []
    ctx.entities = entities or []
    ctx.evidence = evidence or []
    ctx.has_entities = bool(entities)
    ctx.has_findings = bool(findings)
    return ctx


def _finding(finding_type: str, title: str = ""):
    f = MagicMock()
    f.finding_type = finding_type
    f.title = title
    return f


def test_anon_ldap_finding_triggers_support():
    ctx = _ctx(findings=[_finding("ANONYMOUS_LDAP_ENABLED")])
    expert = ReconExposureExpert()
    result = expert.evaluate("recon_exposure", ctx)
    assert result.verdict == ExpertVerdict.SUPPORTS_EXPOSURE
    assert result.score_delta > 0


def test_smb_null_finding_triggers_support():
    ctx = _ctx(findings=[_finding("SMB_NULL_SESSION")])
    expert = ReconExposureExpert()
    result = expert.evaluate("recon_exposure", ctx)
    assert result.verdict == ExpertVerdict.SUPPORTS_EXPOSURE


def test_no_relevant_findings_neutral():
    ctx = _ctx(findings=[_finding("KERBEROASTING")])
    expert = ReconExposureExpert()
    result = expert.evaluate("recon_exposure", ctx)
    assert result.verdict in (ExpertVerdict.NEUTRAL, ExpertVerdict.INSUFFICIENT_DATA)


def test_mitre_tags_present():
    ctx = _ctx(findings=[_finding("ANONYMOUS_LDAP_ENABLED")])
    expert = ReconExposureExpert()
    result = expert.evaluate("recon_exposure", ctx)
    assert any("T1087" in t for t in result.mitre_techniques)



def _computer_entity(sam: str, uac_flags: int = 0):
    e = MagicMock()
    e.entity_type = "COMPUTER"
    e.sam_account_name = sam
    e.attributes = {"userAccountControl": uac_flags}
    e.id = "test-id-" + sam
    return e


def test_pre2k_passwd_notreqd_triggers():
    computer = _computer_entity("OLDPC$", uac_flags=0x20)
    ctx = _ctx(entities=[computer])
    ctx.has_entities = True
    expert = Pre2kExposureExpert()
    result = expert.evaluate("pre2k_exposure", ctx)
    assert result.verdict == ExpertVerdict.SUPPORTS_EXPOSURE
    assert result.score_delta > 0


def test_pre2k_normal_computer_neutral():
    computer = _computer_entity("DC01$", uac_flags=0x1000)
    ctx = _ctx(entities=[computer])
    ctx.has_entities = True
    expert = Pre2kExposureExpert()
    result = expert.evaluate("pre2k_exposure", ctx)
    assert result.verdict in (ExpertVerdict.NEUTRAL, ExpertVerdict.INSUFFICIENT_DATA)


def test_pre2k_no_entities():
    ctx = _ctx()
    expert = Pre2kExposureExpert()
    result = expert.evaluate("pre2k_exposure", ctx)
    assert result.verdict == ExpertVerdict.INSUFFICIENT_DATA
