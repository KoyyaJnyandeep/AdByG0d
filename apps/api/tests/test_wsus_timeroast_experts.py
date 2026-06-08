from __future__ import annotations
from unittest.mock import MagicMock
from adbygod_api.core.validation.contracts import ExpertVerdict
from adbygod_api.core.validation.experts.timeroast_exposure import TimeroastExposureExpert
from adbygod_api.core.validation.experts.wsus_exposure import WSUSExposureExpert


def _ctx(findings=None, evidence=None, entities=None):
    ctx = MagicMock()
    ctx.findings = findings or []
    ctx.evidence = evidence or []
    ctx.entities = entities or []
    ctx.has_entities = bool(entities)
    ctx.has_evidence = bool(evidence)
    return ctx


def _recon_evidence(probe_type: str, hashes: int = 3):
    ev = MagicMock()
    ev.collection_method = "recon_engine"
    ev.raw_data = {"probe_type": probe_type, "hashes_found": hashes}
    return ev


def test_timeroast_evidence_triggers():
    ctx = _ctx(evidence=[_recon_evidence("ntp_sntp_probe")])
    result = TimeroastExposureExpert().evaluate("timeroast_exposure", ctx)
    assert result.verdict == ExpertVerdict.SUPPORTS_EXPOSURE


def test_timeroast_no_evidence_insufficient():
    ctx = _ctx()
    result = TimeroastExposureExpert().evaluate("timeroast_exposure", ctx)
    assert result.verdict == ExpertVerdict.INSUFFICIENT_DATA


def test_wsus_evidence_triggers():
    ev = MagicMock()
    ev.collection_method = "recon_engine"
    ev.raw_data = {"probe_type": "wsus_http_probe", "port": 8530, "server": "10.0.0.5"}
    ctx = _ctx(evidence=[ev])
    result = WSUSExposureExpert().evaluate("wsus_exposure", ctx)
    assert result.verdict == ExpertVerdict.SUPPORTS_EXPOSURE
    assert result.score_delta >= 0.8


def test_wsus_no_evidence_insufficient():
    ctx = _ctx()
    result = WSUSExposureExpert().evaluate("wsus_exposure", ctx)
    assert result.verdict == ExpertVerdict.INSUFFICIENT_DATA
