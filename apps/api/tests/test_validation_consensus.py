"""
Validation Consensus Engine — 23 test cases.
Expert unit tests use mock ValidationAssessmentContext + ADGraphAnalyzer.load_from_dicts().
API integration tests use the test_app fixture (SQLite in-memory).
"""
from __future__ import annotations

import sys
import uuid
from pathlib import Path
from types import SimpleNamespace


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from adbygod_api.core.graph.graph_service import ADGraphAnalyzer
from adbygod_api.core.validation.context import ValidationAssessmentContext
from adbygod_api.core.validation.contracts import ExpertVerdict, FinalVerdict
from adbygod_api.core.validation.experts.dcsync import DCSyncExpert, _classify_principal
from adbygod_api.core.validation.experts.kerberos import KerberosExpert
from adbygod_api.core.validation.experts.acl import ACLExpert
from adbygod_api.core.validation.experts.ntlm_relay import NTLMRelayExpert
from adbygod_api.core.validation.experts.trust import TrustExpert
from adbygod_api.core.validation.experts.evidence_quality import compute_evidence_quality
from adbygod_api.core.validation.scoring import ConsensusArbitrator


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_entity(eid: str, sam: str = "", entity_type: str = "USER", **kwargs) -> SimpleNamespace:
    """Lightweight ORM-like entity stub."""
    ns = SimpleNamespace(
        id=eid,
        sam_account_name=sam,
        display_name=sam,
        entity_type=entity_type,
        is_enabled=kwargs.get("is_enabled", True),
        is_admin_count=kwargs.get("is_admin_count", False),
        is_sensitive=kwargs.get("is_sensitive", False),
        is_protected_user=kwargs.get("is_protected_user", False),
        attributes=kwargs.get("attributes", {}),
    )
    return ns


def _make_evidence(eid: str, origin: str = "COLLECTED", confidence: float = 0.9,
                   is_corroborated: bool = False, source_type: str | None = "LDAP") -> SimpleNamespace:
    return SimpleNamespace(
        id=eid,
        origin=origin,
        confidence=confidence,
        is_corroborated=is_corroborated,
        source_type=source_type,
    )


def _make_finding(fid: str, finding_type: str = "TEST", title: str = "Test",
                  module: str = "kerberos") -> SimpleNamespace:
    return SimpleNamespace(id=fid, finding_type=finding_type, title=title, module=module)


def _make_ctx(
    entities: list | None = None,
    edges: list | None = None,
    entity_dicts: list | None = None,
    edge_dicts: list | None = None,
    findings: list | None = None,
    evidence: list | None = None,
    assessment_id: str | None = None,
) -> ValidationAssessmentContext:
    """Build a ValidationAssessmentContext from raw dicts using ADGraphAnalyzer.load_from_dicts."""
    analyzer = ADGraphAnalyzer()
    e_dicts = entity_dicts or []
    ed_dicts = edge_dicts or []
    analyzer.load_from_dicts(e_dicts, ed_dicts)

    ent_objs = entities or [
        _make_entity(
            d["id"],
            sam=d.get("sam_account_name", ""),
            entity_type=d.get("entity_type", "USER"),
            is_enabled=d.get("is_enabled", True),
            is_admin_count=d.get("is_admin_count", False),
            attributes=d.get("attributes", {}),
        )
        for d in e_dicts
    ]

    ev_list = evidence or []
    dist: dict[str, int] = {}
    for ev in ev_list:
        dist[ev.origin] = dist.get(ev.origin, 0) + 1

    ctx = ValidationAssessmentContext(
        assessment_id=assessment_id or str(uuid.uuid4()),
        domain="TEST.LOCAL",
        collection_mode="FULL",
        entities=ent_objs,
        entity_index={str(e.id): e for e in ent_objs},
        edges=ed_dicts,
        edge_type_index=analyzer._edge_type_index,
        findings=findings or [],
        finding_index={},
        module_findings={},
        evidence=ev_list,
        evidence_index={},
        cert_templates=[],
        exposure_paths=[],
        analyzer=analyzer,
        has_entities=bool(ent_objs),
        has_edges=bool(ed_dicts),
        has_findings=bool(findings),
        has_evidence=bool(ev_list),
        origin_distribution=dist,
        module_coverage={},
    )
    return ctx


# ---------------------------------------------------------------------------
# Test 6: DCSync DC principal → not scary (CONTRADICTS or low verdict)
# ---------------------------------------------------------------------------
def test_dcsync_dc_principal_not_scary():
    dc_id = str(uuid.uuid4())
    t0_id = str(uuid.uuid4())
    ctx = _make_ctx(
        entity_dicts=[
            {"id": dc_id, "entity_type": "DC", "sam_account_name": "DC01$", "tier": 0, "is_crown_jewel": True},
            {"id": t0_id, "entity_type": "DOMAIN", "sam_account_name": "TEST.LOCAL"},
        ],
        edge_dicts=[{"source_id": dc_id, "target_id": t0_id, "edge_type": "DCSYNC", "risk_weight": 0.9}],
    )
    result = DCSyncExpert().evaluate("dcsync", ctx)
    # DC principals should be classified expected — verdict CONTRADICTS or no SUPPORTS
    assert result.verdict != ExpertVerdict.SUPPORTS_EXPOSURE, (
        f"DC principal should not trigger SUPPORTS_EXPOSURE, got {result.verdict}"
    )


# ---------------------------------------------------------------------------
# Test 7: DCSync DA/EA/Admins → suppressed
# ---------------------------------------------------------------------------
def test_dcsync_da_ea_admins_suppressed():
    for sam in ("domain admins", "enterprise admins", "administrators"):
        classification = _classify_principal({"sam_account_name": sam, "type": "GROUP"})
        assert classification == "expected", f"{sam!r} should be expected, got {classification!r}"


# ---------------------------------------------------------------------------
# Test 8: DCSync non-default principal at domain-root → SUPPORTS_EXPOSURE
# ---------------------------------------------------------------------------
def test_dcsync_nondefault_principal_supports_exposure():
    attacker_id = str(uuid.uuid4())
    t0_id = str(uuid.uuid4())
    ctx = _make_ctx(
        entity_dicts=[
            {"id": attacker_id, "entity_type": "USER", "sam_account_name": "evil_svc", "tier": 1},
            {"id": t0_id, "entity_type": "DOMAIN", "sam_account_name": "TEST.LOCAL", "is_crown_jewel": True},
        ],
        edge_dicts=[{"source_id": attacker_id, "target_id": t0_id, "edge_type": "DCSYNC", "risk_weight": 0.9}],
    )
    result = DCSyncExpert().evaluate("dcsync", ctx)
    assert result.verdict == ExpertVerdict.SUPPORTS_EXPOSURE, (
        f"Non-default DCSync right should give SUPPORTS_EXPOSURE, got {result.verdict}"
    )


# ---------------------------------------------------------------------------
# Test 9: DCSync sync-like account → legitimacy review (WEAK_SUPPORT)
# ---------------------------------------------------------------------------
def test_dcsync_sync_like_account_legitimacy_review():
    sync_id = str(uuid.uuid4())
    t0_id = str(uuid.uuid4())
    ctx = _make_ctx(
        entity_dicts=[
            {"id": sync_id, "entity_type": "USER", "sam_account_name": "msol_connector", "tier": 1},
            {"id": t0_id, "entity_type": "DOMAIN", "sam_account_name": "TEST.LOCAL", "is_crown_jewel": True},
        ],
        edge_dicts=[{"source_id": sync_id, "target_id": t0_id, "edge_type": "DCSYNC", "risk_weight": 0.9}],
    )
    result = DCSyncExpert().evaluate("dcsync", ctx)
    assert result.verdict in (ExpertVerdict.WEAK_SUPPORT, ExpertVerdict.NEUTRAL), (
        f"Sync-like account should get WEAK_SUPPORT or NEUTRAL legitimacy review, got {result.verdict}"
    )
    # Sync-like accounts should not be classified as suspicious
    classification = _classify_principal({"sam_account_name": "msol_connector", "type": "USER"})
    assert classification == "sync_like"


# ---------------------------------------------------------------------------
# Test 10: Kerberos enabled preauth-disabled user → strong signal
# ---------------------------------------------------------------------------
def test_kerberos_enabled_preauth_disabled_strong_signal():
    uid = str(uuid.uuid4())
    entity = _make_entity(uid, is_enabled=True)
    ctx = _make_ctx(
        entities=[entity],
        entity_dicts=[{
            "id": uid, "entity_type": "USER", "sam_account_name": "victim",
            "attributes": {"uac_dont_require_preauth": True},
        }],
    )
    result = KerberosExpert().evaluate("kerberos", ctx)
    assert result.verdict == ExpertVerdict.SUPPORTS_EXPOSURE
    assert result.telemetry["asrep_enabled"] >= 1


# ---------------------------------------------------------------------------
# Test 11: Kerberos disabled preauth-disabled user → does not overinflate
# ---------------------------------------------------------------------------
def test_kerberos_disabled_preauth_does_not_overinflate():
    uid = str(uuid.uuid4())
    entity = _make_entity(uid, is_enabled=False)
    ctx = _make_ctx(
        entities=[entity],
        entity_dicts=[{
            "id": uid, "entity_type": "USER", "sam_account_name": "disabled_victim",
            "is_enabled": False, "attributes": {"uac_dont_require_preauth": True},
        }],
    )
    result = KerberosExpert().evaluate("kerberos", ctx)
    # Disabled account → should NOT produce SUPPORTS_EXPOSURE for AS-REP
    assert result.telemetry.get("asrep_enabled", 0) == 0, "Disabled account must not count as enabled ASREP"
    assert result.telemetry.get("asrep_disabled", 0) >= 1


# ---------------------------------------------------------------------------
# Test 12: Kerberos SPN + admin_count → CRITICAL severity
# ---------------------------------------------------------------------------
def test_kerberos_spn_admin_escalated_severity():
    uid = str(uuid.uuid4())
    entity = _make_entity(uid, is_enabled=True, is_admin_count=True)
    ctx = _make_ctx(
        entities=[entity],
        entity_dicts=[{
            "id": uid, "entity_type": "SERVICE_ACCOUNT", "sam_account_name": "svc_priv",
            "is_admin_count": True, "attributes": {"has_spn": True},
        }],
    )
    result = KerberosExpert().evaluate("kerberos", ctx)
    assert result.verdict == ExpertVerdict.SUPPORTS_EXPOSURE
    assert result.severity_hint == "CRITICAL"


# ---------------------------------------------------------------------------
# Test 13: ACL GenericAll on tier-0 → SUPPORTS_EXPOSURE CRITICAL
# ---------------------------------------------------------------------------
def test_acl_genericall_to_tier0_strong_exposure():
    attacker_id = str(uuid.uuid4())
    t0_id = str(uuid.uuid4())
    ctx = _make_ctx(
        entity_dicts=[
            {"id": attacker_id, "entity_type": "USER", "sam_account_name": "lowuser", "tier": 2},
            {"id": t0_id, "entity_type": "GROUP", "sam_account_name": "domain admins", "is_crown_jewel": True},
        ],
        edge_dicts=[{"source_id": attacker_id, "target_id": t0_id, "edge_type": "GENERIC_ALL", "risk_weight": 1.0}],
    )
    result = ACLExpert().evaluate("acl", ctx)
    assert result.verdict == ExpertVerdict.SUPPORTS_EXPOSURE
    assert result.severity_hint == "CRITICAL"


# ---------------------------------------------------------------------------
# Test 14: ACL no path to sensitive target → reduced verdict
# ---------------------------------------------------------------------------
def test_acl_no_path_to_sensitive_target_reduced_verdict():
    a_id = str(uuid.uuid4())
    b_id = str(uuid.uuid4())
    ctx = _make_ctx(
        entity_dicts=[
            {"id": a_id, "entity_type": "USER", "sam_account_name": "user1", "tier": 2},
            {"id": b_id, "entity_type": "USER", "sam_account_name": "user2", "tier": 2},
        ],
        edge_dicts=[{"source_id": a_id, "target_id": b_id, "edge_type": "GENERIC_ALL", "risk_weight": 0.5}],
    )
    result = ACLExpert().evaluate("acl", ctx)
    assert result.verdict != ExpertVerdict.SUPPORTS_EXPOSURE or result.severity_hint not in ("CRITICAL",), (
        "ACL with no tier-0 path should not produce CRITICAL exposure"
    )


# ---------------------------------------------------------------------------
# Test 15: Relay SMB + coercion + ADCS signals → higher confidence
# ---------------------------------------------------------------------------
def test_relay_smb_coercion_higher_confidence():
    finding1 = _make_finding(str(uuid.uuid4()), "SMB_SIGNING_DISABLED", "SMB Signing Disabled", "ntlm_relay")
    finding2 = _make_finding(str(uuid.uuid4()), "COERCION_VULNERABLE", "Coercion surface", "ntlm_relay")
    finding3 = _make_finding(str(uuid.uuid4()), "ADCS_ESC8", "ESC8 relay attack path", "ntlm_relay")
    ctx = _make_ctx(findings=[finding1, finding2, finding3])
    result = NTLMRelayExpert().evaluate("ntlm_relay", ctx)
    assert result.verdict in (ExpertVerdict.SUPPORTS_EXPOSURE, ExpertVerdict.WEAK_SUPPORT)
    assert result.confidence >= 0.5


# ---------------------------------------------------------------------------
# Test 16: Relay no evidence → INSUFFICIENT_DATA
# ---------------------------------------------------------------------------
def test_relay_no_evidence_insufficient_data():
    ctx = _make_ctx()  # empty context
    result = NTLMRelayExpert().evaluate("ntlm_relay", ctx)
    assert result.verdict == ExpertVerdict.INSUFFICIENT_DATA


# ---------------------------------------------------------------------------
# Test 17: Trust object exists, no risky indicators → low confidence
# ---------------------------------------------------------------------------
def test_trust_no_risky_indicators_low_confidence():
    trust_id = str(uuid.uuid4())
    domain_id = str(uuid.uuid4())
    ctx = _make_ctx(
        entity_dicts=[
            {"id": trust_id, "entity_type": "TRUST", "sam_account_name": "partnerdomain.local"},
            {"id": domain_id, "entity_type": "DOMAIN", "sam_account_name": "TEST.LOCAL"},
        ],
        edge_dicts=[{"source_id": domain_id, "target_id": trust_id, "edge_type": "TRUSTS", "risk_weight": 0.3}],
    )
    result = TrustExpert().evaluate("trust", ctx)
    # Trust exists but no risky attributes → should be WEAK_SUPPORT or NEUTRAL, low confidence
    assert result.verdict in (ExpertVerdict.WEAK_SUPPORT, ExpertVerdict.NEUTRAL, ExpertVerdict.INSUFFICIENT_DATA)
    assert result.confidence <= 0.65, f"Expected low confidence, got {result.confidence}"


# ---------------------------------------------------------------------------
# Test 18: Trust cross-boundary risky + pathing → higher support
# ---------------------------------------------------------------------------
def test_trust_risky_pathing_higher_support():
    trust_id = str(uuid.uuid4())
    domain_id = str(uuid.uuid4())
    ctx = _make_ctx(
        entity_dicts=[
            {
                "id": trust_id, "entity_type": "TRUST", "sam_account_name": "evil.corp",
                "attributes": {"sid_filtering": False, "is_transitive": True, "trust_type": "EXTERNAL"},
            },
            {"id": domain_id, "entity_type": "DOMAIN", "sam_account_name": "TEST.LOCAL", "is_crown_jewel": True},
        ],
        edge_dicts=[{"source_id": domain_id, "target_id": trust_id, "edge_type": "TRUSTS", "risk_weight": 0.9}],
        findings=[_make_finding(str(uuid.uuid4()), "SID_FILTER_DISABLED", "SID filtering disabled", "trust")],
    )
    result = TrustExpert().evaluate("trust", ctx)
    # Risky trust indicators should elevate verdict
    assert result.verdict in (ExpertVerdict.SUPPORTS_EXPOSURE, ExpertVerdict.WEAK_SUPPORT)


# ---------------------------------------------------------------------------
# Test 19: Corroborated collected evidence > single imported
# ---------------------------------------------------------------------------
def test_evidence_corroborated_collected_beats_imported():
    ev_collected = [
        _make_evidence(str(uuid.uuid4()), origin="COLLECTED", is_corroborated=True),
        _make_evidence(str(uuid.uuid4()), origin="COLLECTED", is_corroborated=True),
    ]
    ev_imported = [_make_evidence(str(uuid.uuid4()), origin="IMPORTED", is_corroborated=False)]

    ctx_strong = _make_ctx(evidence=ev_collected)
    ctx_weak = _make_ctx(evidence=ev_imported)

    score_strong, band_strong, _ = compute_evidence_quality(ctx_strong)
    score_weak, band_weak, _ = compute_evidence_quality(ctx_weak)

    assert score_strong > score_weak, (
        f"Corroborated COLLECTED ({score_strong}) should beat single IMPORTED ({score_weak})"
    )


# ---------------------------------------------------------------------------
# Test 20: Contradiction can cap final confidence
# ---------------------------------------------------------------------------
def test_contradiction_can_cap_final_confidence():
    from adbygod_api.core.validation.contracts import ExpertDecision

    # Build a set of decisions: strong support but FRAGILE evidence quality
    support_decision = ExpertDecision(
        expert_id="dcsync_expert", expert_name="DCSync Expert", module_id="dcsync",
        verdict=ExpertVerdict.SUPPORTS_EXPOSURE, score_delta=0.9, confidence=0.9,
        summary="DCSync rights found",
    )
    fragile_eq = ExpertDecision(
        expert_id="evidence_quality_expert", expert_name="Evidence Quality Expert", module_id="dcsync",
        verdict=ExpertVerdict.CONTRADICTS_EXPOSURE, score_delta=-0.5, confidence=0.3,
        summary="Evidence quality: FRAGILE",
    )
    contradiction = ExpertDecision(
        expert_id="contradiction_expert", expert_name="Contradiction Expert", module_id="dcsync",
        verdict=ExpertVerdict.CONTRADICTS_EXPOSURE, score_delta=-0.4, confidence=0.75,
        summary="All principals expected",
        contradicting_signals=["All DCSYNC principals are expected built-ins."],
    )

    ctx = _make_ctx()  # empty
    result = ConsensusArbitrator().fuse([support_decision, fragile_eq, contradiction], ctx, "dcsync")

    # With two strong contradictions + fragile evidence, final verdict must NOT be LIKELY_EXPOSED
    assert result.final_verdict != FinalVerdict.LIKELY_EXPOSED, (
        f"Strong contradictions should prevent LIKELY_EXPOSED, got {result.final_verdict}"
    )
    # Confidence should be reduced
    assert result.confidence < 70, f"Expected confidence < 70, got {result.confidence}"


# ============================================================================
# API / Integration tests
# ============================================================================

def _login(client, username, password):
    resp = client.post("/api/v1/auth/login", json={"username": username, "password": password})
    assert resp.status_code == 200
    return resp.json()["access_token"]


def _auth(client, username, password="password123!"):
    token = _login(client, username, password)
    return {"Authorization": f"Bearer {token}"}


def _setup_assessment(db):
    """Create workspace + user + assessment, return dict with ids."""
    import asyncio
    import adbygod_api.models as models

    async def _go():
        ws = await db.create_workspace("Test WS")
        user = await db.create_user("testuser_consensus", "consensus@test.com")
        await db.add_workspace_user(ws.id, user.id, "analyst")
        assessment = await db.create_assessment(
            "CONSENSUS Test", "TEST.LOCAL", workspace_id=ws.id, created_by=user.id,
            status=models.AssessmentStatus.RUNNING,
        )
        return ws, user, assessment

    return asyncio.run(_go())


# ---------------------------------------------------------------------------
# Test 5: Invalid module returns 400
# ---------------------------------------------------------------------------
def test_invalid_module_returns_400(test_app):
    client = test_app["client"]
    db = test_app["db"]
    headers_for = test_app["headers_for"]
    import asyncio
    import adbygod_api.models as models

    async def _setup():
        ws = await db.create_workspace("ws5")
        user = await db.create_user("user5", "u5@test.com")
        await db.add_workspace_user(ws.id, user.id)
        a = await db.create_assessment("A5", "X.LOCAL", workspace_id=ws.id, created_by=user.id,
                                        status=models.AssessmentStatus.RUNNING)
        return user, a

    user, assessment = asyncio.run(_setup())
    headers = headers_for(user)
    resp = client.post(
        f"/api/v1/validation/simulate/invalid_module/{assessment.id}",
        json={"target": "TEST.LOCAL"},
        headers=headers,
    )
    assert resp.status_code == 400


# ---------------------------------------------------------------------------
# Test 4: Cross-workspace access blocked
# ---------------------------------------------------------------------------
def test_cross_workspace_access_blocked(test_app):
    client = test_app["client"]
    db = test_app["db"]
    headers_for = test_app["headers_for"]
    import asyncio
    import adbygod_api.models as models

    async def _setup():
        ws1 = await db.create_workspace("ws_a")
        ws2 = await db.create_workspace("ws_b")
        owner = await db.create_user("owner4", "owner4@test.com")
        outsider = await db.create_user("outsider4", "out4@test.com")
        await db.add_workspace_user(ws1.id, owner.id)
        await db.add_workspace_user(ws2.id, outsider.id)
        assessment = await db.create_assessment("Private", "P.LOCAL", workspace_id=ws1.id, created_by=owner.id,
                                                 status=models.AssessmentStatus.RUNNING)
        return outsider, assessment

    outsider, assessment = asyncio.run(_setup())
    headers = headers_for(outsider)
    resp = client.post(
        f"/api/v1/validation/simulate/kerberos/{assessment.id}",
        json={"target": "P.LOCAL"},
        headers=headers,
    )
    assert resp.status_code in (403, 404)


# ---------------------------------------------------------------------------
# Test 22: Route still works with same call pattern (backward compat)
# ---------------------------------------------------------------------------
def test_route_works_with_same_call_pattern(test_app):
    client = test_app["client"]
    db = test_app["db"]
    headers_for = test_app["headers_for"]
    import asyncio
    import adbygod_api.models as models

    async def _setup():
        ws = await db.create_workspace("ws22")
        user = await db.create_user("user22", "u22@test.com")
        await db.add_workspace_user(ws.id, user.id)
        a = await db.create_assessment("A22", "X.LOCAL", workspace_id=ws.id, created_by=user.id,
                                        status=models.AssessmentStatus.RUNNING)
        return user, a

    user, assessment = asyncio.run(_setup())
    headers = headers_for(user)
    resp = client.post(
        f"/api/v1/validation/simulate/kerberos/{assessment.id}",
        json={"target": "X.LOCAL", "mode": "simulation"},
        headers=headers,
    )
    assert resp.status_code == 200
    data = resp.json()
    # Backward-compatible fields must exist
    assert "risk_score" in data
    assert "confidence" in data
    assert "operator_brief" in data
    assert "safeguards" in data


# ---------------------------------------------------------------------------
# Test 21: Frontend types backward compatible + new fields present
# ---------------------------------------------------------------------------
def test_frontend_types_backward_compatible(test_app):
    client = test_app["client"]
    db = test_app["db"]
    headers_for = test_app["headers_for"]
    import asyncio
    import adbygod_api.models as models

    async def _setup():
        ws = await db.create_workspace("ws21")
        user = await db.create_user("user21", "u21@test.com")
        await db.add_workspace_user(ws.id, user.id)
        a = await db.create_assessment("A21", "X.LOCAL", workspace_id=ws.id, created_by=user.id,
                                        status=models.AssessmentStatus.RUNNING)
        return user, a

    user, assessment = asyncio.run(_setup())
    headers = headers_for(user)
    resp = client.post(
        f"/api/v1/validation/simulate/dcsync/{assessment.id}",
        json={"target": "X.LOCAL"},
        headers=headers,
    )
    assert resp.status_code == 200
    data = resp.json()

    # Old fields preserved
    for field in ("risk_score", "confidence", "operator_brief", "impact", "blast_radius",
                  "safeguards", "recommended_actions"):
        assert field in data, f"Missing backward-compat field: {field}"

    # New consensus fields
    for field in ("run_id", "final_verdict", "confidence_band", "consensus_score",
                  "evidence_quality_score", "evidence_quality_band", "expert_decisions",
                  "evidence_summary", "counts", "logs"):
        assert field in data, f"Missing new consensus field: {field}"

    # Safety labels
    assert data["simulated"] is True
    assert data["origin"] == "SIMULATED"
    assert data["execution_mode"] == "SIMULATION_CONSENSUS"


# ---------------------------------------------------------------------------
# Test 1+2+3: Run persisted, expert decisions persisted, correct labels
# ---------------------------------------------------------------------------
def test_run_and_decisions_persisted_with_correct_labels(test_app):
    client = test_app["client"]
    db = test_app["db"]
    headers_for = test_app["headers_for"]
    session_maker = test_app["session_maker"]
    import asyncio
    import adbygod_api.models as models
    from sqlalchemy import select

    async def _setup():
        ws = await db.create_workspace("ws123")
        user = await db.create_user("user123", "u123@test.com")
        await db.add_workspace_user(ws.id, user.id)
        a = await db.create_assessment("A123", "X.LOCAL", workspace_id=ws.id, created_by=user.id,
                                        status=models.AssessmentStatus.RUNNING)
        return user, a

    user, assessment = asyncio.run(_setup())
    headers = headers_for(user)
    resp = client.post(
        f"/api/v1/validation/simulate/acl/{assessment.id}",
        json={"target": "X.LOCAL"},
        headers=headers,
    )
    assert resp.status_code == 200
    data = resp.json()
    run_id = data["run_id"]

    # Verify run persisted in DB (Test 1)
    async def _verify():
        async with session_maker() as session:
            run = await session.get(models.ValidationRun, uuid.UUID(run_id))
            assert run is not None, "ValidationRun must be persisted"
            assert run.status == "COMPLETED"
            assert run.execution_mode == "SIMULATION_CONSENSUS"  # Test 3
            assert run.simulated is True
            assert run.origin == "SIMULATED"
            # Expert decisions persisted (Test 2)
            decisions_q = await session.execute(
                select(models.ValidationExpertDecision)
                .where(models.ValidationExpertDecision.validation_run_id == run.id)
            )
            decisions = decisions_q.scalars().all()
            assert len(decisions) > 0, "Expert decisions must be persisted"
            return run, decisions

    run, decisions = asyncio.run(_verify())
    assert run.final_verdict is not None
    assert all(d.expert_id for d in decisions)


# ---------------------------------------------------------------------------
# Test 23: New overview / runs endpoints return valid shapes
# ---------------------------------------------------------------------------
def test_overview_and_runs_endpoints_return_valid_shapes(test_app):
    client = test_app["client"]
    db = test_app["db"]
    headers_for = test_app["headers_for"]
    import asyncio
    import adbygod_api.models as models

    async def _setup():
        ws = await db.create_workspace("ws23")
        user = await db.create_user("user23", "u23@test.com")
        await db.add_workspace_user(ws.id, user.id)
        a = await db.create_assessment("A23", "X.LOCAL", workspace_id=ws.id, created_by=user.id,
                                        status=models.AssessmentStatus.RUNNING)
        return user, a

    user, assessment = asyncio.run(_setup())
    headers = headers_for(user)

    # Run one simulation first
    client.post(
        f"/api/v1/validation/simulate/kerberos/{assessment.id}",
        json={"target": "X.LOCAL"},
        headers=headers,
    )

    # Test overview endpoint
    overview_resp = client.get(f"/api/v1/validation/overview/{assessment.id}", headers=headers)
    assert overview_resp.status_code == 200
    overview = overview_resp.json()
    assert "modules" in overview
    assert "total_modules" in overview
    assert isinstance(overview["modules"], list)
    assert len(overview["modules"]) > 0
    for m in overview["modules"]:
        assert "module_id" in m
        assert "has_run" in m

    # Test runs endpoint
    runs_resp = client.get(f"/api/v1/validation/runs/{assessment.id}", headers=headers)
    assert runs_resp.status_code == 200
    runs_data = runs_resp.json()
    assert "runs" in runs_data
    assert "total" in runs_data
    assert runs_data["total"] >= 1

    # Test run detail endpoint
    run_id = runs_data["runs"][0]["run_id"]
    detail_resp = client.get(f"/api/v1/validation/runs/detail/{run_id}", headers=headers)
    assert detail_resp.status_code == 200
    detail = detail_resp.json()
    assert "expert_decisions" in detail
    assert "final_verdict" in detail
    assert isinstance(detail["expert_decisions"], list)
