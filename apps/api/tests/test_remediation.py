"""Tests for /api/v1/remediation/* endpoints."""
from __future__ import annotations




def _setup(db, name_prefix=""):
    user = db.run(db.create_user(f"{name_prefix}analyst", f"{name_prefix}a@example.com"))
    ws = db.run(db.create_workspace(f"{name_prefix}ws"))
    db.run(db.add_workspace_user(ws.id, user.id))
    asmt = db.run(db.create_assessment(f"{name_prefix}asmt", "lab.local", workspace_id=ws.id, created_by=user.id))
    return user, asmt


# ── /candidates/{assessment_id} ───────────────────────────────────────────────

def test_candidates_empty_assessment(test_app):
    db = test_app["db"]
    client = test_app["client"]
    headers_for = test_app["headers_for"]
    user, asmt = _setup(db, "cand_empty_")
    r = client.get(f"/api/v1/remediation/candidates/{asmt.id}", headers=headers_for(user))
    assert r.status_code == 200
    assert r.json() == []


def test_candidates_returns_open_findings(test_app):
    db = test_app["db"]
    client = test_app["client"]
    headers_for = test_app["headers_for"]
    user, asmt = _setup(db, "cand_open_")
    db.run(db.create_finding(asmt.id, title="Kerberoast", composite_score=80.0))
    db.run(db.create_finding(asmt.id, title="ACL Abuse", composite_score=70.0))
    r = client.get(f"/api/v1/remediation/candidates/{asmt.id}", headers=headers_for(user))
    assert r.status_code == 200
    data = r.json()
    assert len(data) == 2
    titles = {c["title"] for c in data}
    assert "Kerberoast" in titles
    assert "ACL Abuse" in titles


def test_candidates_response_schema(test_app):
    db = test_app["db"]
    client = test_app["client"]
    headers_for = test_app["headers_for"]
    user, asmt = _setup(db, "cand_schema_")
    db.run(db.create_finding(asmt.id, title="Schema Finding"))
    r = client.get(f"/api/v1/remediation/candidates/{asmt.id}", headers=headers_for(user))
    assert r.status_code == 200
    for c in r.json():
        assert set(c.keys()) >= {"finding_id", "title", "severity", "score", "effort", "impact"}
        assert isinstance(c["score"], (int, float))
        assert c["severity"] in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}


def test_candidates_excludes_closed_findings(test_app):
    db = test_app["db"]
    client = test_app["client"]
    headers_for = test_app["headers_for"]
    user, asmt = _setup(db, "cand_closed_")
    import asyncio
    from adbygod_api import models as m

    async def _close_finding(finding_id, session_maker):
        async with session_maker() as db_s:
            f = await db_s.get(m.Finding, finding_id)
            f.status = m.FindingStatus.REMEDIATED
            await db_s.commit()

    _ = db.run(db.create_finding(asmt.id, title="OpenFinding"))
    closed_f = db.run(db.create_finding(asmt.id, title="ClosedFinding"))
    asyncio.run(_close_finding(closed_f.id, test_app["session_maker"]))

    r = client.get(f"/api/v1/remediation/candidates/{asmt.id}", headers=headers_for(user))
    assert r.status_code == 200
    titles = {c["title"] for c in r.json()}
    assert "OpenFinding" in titles
    assert "ClosedFinding" not in titles


def test_candidates_requires_assessment_access(test_app):
    db = test_app["db"]
    client = test_app["client"]
    headers_for = test_app["headers_for"]
    user, asmt = _setup(db, "cand_access_")
    other_user = db.run(db.create_user("cand_other", "cand_other@example.com"))
    r = client.get(f"/api/v1/remediation/candidates/{asmt.id}", headers=headers_for(other_user))
    assert r.status_code in {403, 404}


# ── /simulate ─────────────────────────────────────────────────────────────────

def test_simulate_returns_result_schema(test_app):
    db = test_app["db"]
    client = test_app["client"]
    headers_for = test_app["headers_for"]
    user, asmt = _setup(db, "sim_schema_")
    f = db.run(db.create_finding(asmt.id, title="SimFinding", composite_score=60.0))
    r = client.post(
        "/api/v1/remediation/simulate",
        json={"assessment_id": str(asmt.id), "finding_ids": [str(f.id)]},
        headers=headers_for(user),
    )
    assert r.status_code == 200
    data = r.json()
    assert set(data.keys()) >= {
        "assessment_id", "paths_eliminated", "paths_remaining",
        "findings_resolved", "risk_reduction_pct", "operational_impact", "fix_order"
    }


def test_simulate_empty_finding_list(test_app):
    db = test_app["db"]
    client = test_app["client"]
    headers_for = test_app["headers_for"]
    user, asmt = _setup(db, "sim_empty_")
    r = client.post(
        "/api/v1/remediation/simulate",
        json={"assessment_id": str(asmt.id), "finding_ids": []},
        headers=headers_for(user),
    )
    assert r.status_code == 200
    data = r.json()
    assert data["risk_reduction_pct"] == 0.0
    assert data["paths_eliminated"] == 0
    assert data["findings_resolved"] == []


def test_simulate_risk_reduction_clamped_at_95(test_app):
    db = test_app["db"]
    client = test_app["client"]
    headers_for = test_app["headers_for"]
    user, asmt = _setup(db, "sim_clamp_")
    finding_ids = []
    for i in range(10):
        f = db.run(db.create_finding(asmt.id, title=f"HighRisk{i}", composite_score=99.0))
        finding_ids.append(str(f.id))
    r = client.post(
        "/api/v1/remediation/simulate",
        json={"assessment_id": str(asmt.id), "finding_ids": finding_ids},
        headers=headers_for(user),
    )
    assert r.status_code == 200
    assert r.json()["risk_reduction_pct"] <= 95.0


def test_simulate_fix_order_has_required_fields(test_app):
    db = test_app["db"]
    client = test_app["client"]
    headers_for = test_app["headers_for"]
    user, asmt = _setup(db, "sim_fix_")
    f1 = db.run(db.create_finding(asmt.id, title="FixOrder1", composite_score=80.0))
    f2 = db.run(db.create_finding(asmt.id, title="FixOrder2", composite_score=50.0))
    r = client.post(
        "/api/v1/remediation/simulate",
        json={"assessment_id": str(asmt.id), "finding_ids": [str(f1.id), str(f2.id)]},
        headers=headers_for(user),
    )
    assert r.status_code == 200
    for item in r.json()["fix_order"]:
        assert set(item.keys()) >= {"finding_id", "title", "priority", "effort", "impact"}
        assert isinstance(item["priority"], int)


def test_simulate_requires_assessment_access(test_app):
    db = test_app["db"]
    client = test_app["client"]
    headers_for = test_app["headers_for"]
    user, asmt = _setup(db, "sim_access_")
    outsider = db.run(db.create_user("sim_outsider", "sim_outsider@example.com"))
    r = client.post(
        "/api/v1/remediation/simulate",
        json={"assessment_id": str(asmt.id), "finding_ids": []},
        headers=headers_for(outsider),
    )
    assert r.status_code in {403, 404}


def test_simulate_includes_operational_impact_disclaimer(test_app):
    db = test_app["db"]
    client = test_app["client"]
    headers_for = test_app["headers_for"]
    user, asmt = _setup(db, "sim_disc_")
    r = client.post(
        "/api/v1/remediation/simulate",
        json={"assessment_id": str(asmt.id), "finding_ids": []},
        headers=headers_for(user),
    )
    assert r.status_code == 200
    impact = r.json()["operational_impact"]
    assert isinstance(impact, list) and len(impact) > 0
    # Simulation should clearly label itself
    combined = " ".join(impact).lower()
    assert "simulation" in combined or "simulated" in combined
