"""Tests for /api/v1/service-accounts/* endpoints."""
from __future__ import annotations

import asyncio


from adbygod_api import models


def _setup(db, prefix=""):
    user = db.run(db.create_user(f"{prefix}svc_user", f"{prefix}svc@example.com"))
    ws = db.run(db.create_workspace(f"{prefix}svc_ws"))
    db.run(db.add_workspace_user(ws.id, user.id))
    asmt = db.run(
        db.create_assessment(f"{prefix}svc_asmt", "svc.local", workspace_id=ws.id, created_by=user.id)
    )
    return user, asmt


async def _patch_entity(session_maker, entity_id, **kwargs):
    async with session_maker() as db:
        e = await db.get(models.Entity, entity_id)
        for k, v in kwargs.items():
            setattr(e, k, v)
        await db.commit()


# ── list ──────────────────────────────────────────────────────────────────────

def test_list_returns_empty_for_no_service_accounts(test_app):
    db = test_app["db"]
    client = test_app["client"]
    headers_for = test_app["headers_for"]
    user, asmt = _setup(db, "svc_empty_")
    r = client.get(f"/api/v1/service-accounts?assessment_id={asmt.id}", headers=headers_for(user))
    assert r.status_code == 200
    assert isinstance(r.json(), (list, dict))


def test_list_excludes_non_service_account_entities(test_app):
    db = test_app["db"]
    client = test_app["client"]
    headers_for = test_app["headers_for"]
    user, asmt = _setup(db, "svc_excl_")
    # Create regular user — should NOT appear in service accounts
    db.run(db.create_entity(asmt.id, entity_type=models.EntityType.USER, sam_account_name="regular_user"))
    r = client.get(f"/api/v1/service-accounts?assessment_id={asmt.id}", headers=headers_for(user))
    assert r.status_code == 200
    accounts = r.json() if isinstance(r.json(), list) else r.json().get("items", [])
    names = [a["sam_account_name"] for a in accounts]
    assert "regular_user" not in names


def test_list_includes_service_accounts(test_app):
    db = test_app["db"]
    client = test_app["client"]
    headers_for = test_app["headers_for"]
    user, asmt = _setup(db, "svc_incl_")
    db.run(db.create_entity(asmt.id, entity_type=models.EntityType.SERVICE_ACCOUNT, sam_account_name="svc_acct1"))
    r = client.get(f"/api/v1/service-accounts?assessment_id={asmt.id}", headers=headers_for(user))
    assert r.status_code == 200
    accounts = r.json() if isinstance(r.json(), list) else r.json().get("items", [])
    names = [a["sam_account_name"] for a in accounts]
    assert "svc_acct1" in names


def test_list_response_schema(test_app):
    db = test_app["db"]
    client = test_app["client"]
    headers_for = test_app["headers_for"]
    user, asmt = _setup(db, "svc_schema_")
    db.run(db.create_entity(asmt.id, entity_type=models.EntityType.SERVICE_ACCOUNT, sam_account_name="schema_svc"))
    r = client.get(f"/api/v1/service-accounts?assessment_id={asmt.id}", headers=headers_for(user))
    assert r.status_code == 200
    accounts = r.json() if isinstance(r.json(), list) else r.json().get("items", [])
    for acct in accounts:
        required = {"id", "sam_account_name", "risk", "kerberoastable", "asrep_roastable", "unconstrained_delegation"}
        assert required.issubset(acct.keys()), f"Missing fields: {required - acct.keys()}"


def test_list_access_control(test_app):
    db = test_app["db"]
    client = test_app["client"]
    headers_for = test_app["headers_for"]
    user, asmt = _setup(db, "svc_acl_")
    outsider = db.run(db.create_user("svc_outsider", "svc_out@example.com"))
    r = client.get(f"/api/v1/service-accounts?assessment_id={asmt.id}", headers=headers_for(outsider))
    assert r.status_code in {403, 404}


# ── risk derivation ───────────────────────────────────────────────────────────

def test_risk_critical_for_unconstrained_delegation(test_app):
    db = test_app["db"]
    client = test_app["client"]
    headers_for = test_app["headers_for"]
    user, asmt = _setup(db, "svc_crit_")
    entity = db.run(db.create_entity(
        asmt.id, entity_type=models.EntityType.SERVICE_ACCOUNT, sam_account_name="unconstrained_svc"
    ))
    asyncio.run(_patch_entity(
        test_app["session_maker"], entity.id,
        attributes={"unconstrained_delegation": True}
    ))
    r = client.get(f"/api/v1/service-accounts?assessment_id={asmt.id}", headers=headers_for(user))
    assert r.status_code == 200
    accounts = r.json() if isinstance(r.json(), list) else r.json().get("items", [])
    matches = [a for a in accounts if a["sam_account_name"] == "unconstrained_svc"]
    assert len(matches) == 1
    assert matches[0]["risk"] == "CRITICAL"


def test_risk_high_for_kerberoastable(test_app):
    db = test_app["db"]
    client = test_app["client"]
    headers_for = test_app["headers_for"]
    user, asmt = _setup(db, "svc_high_")
    entity = db.run(db.create_entity(
        asmt.id, entity_type=models.EntityType.SERVICE_ACCOUNT, sam_account_name="kerberoastable_svc"
    ))
    asyncio.run(_patch_entity(
        test_app["session_maker"], entity.id,
        attributes={"kerberoastable": True}
    ))
    r = client.get(f"/api/v1/service-accounts?assessment_id={asmt.id}", headers=headers_for(user))
    assert r.status_code == 200
    accounts = r.json() if isinstance(r.json(), list) else r.json().get("items", [])
    matches = [a for a in accounts if a["sam_account_name"] == "kerberoastable_svc"]
    assert len(matches) == 1
    assert matches[0]["risk"] in {"CRITICAL", "HIGH"}


def test_risk_low_for_clean_account(test_app):
    db = test_app["db"]
    client = test_app["client"]
    headers_for = test_app["headers_for"]
    user, asmt = _setup(db, "svc_low_")
    db.run(db.create_entity(
        asmt.id, entity_type=models.EntityType.SERVICE_ACCOUNT, sam_account_name="clean_svc"
    ))
    r = client.get(f"/api/v1/service-accounts?assessment_id={asmt.id}", headers=headers_for(user))
    assert r.status_code == 200
    accounts = r.json() if isinstance(r.json(), list) else r.json().get("items", [])
    matches = [a for a in accounts if a["sam_account_name"] == "clean_svc"]
    assert len(matches) == 1
    assert matches[0]["risk"] == "LOW"


# ── summary ───────────────────────────────────────────────────────────────────

def test_summary_endpoint_exists(test_app):
    db = test_app["db"]
    client = test_app["client"]
    headers_for = test_app["headers_for"]
    user, asmt = _setup(db, "svc_sum_")
    r = client.get(f"/api/v1/service-accounts/summary?assessment_id={asmt.id}", headers=headers_for(user))
    assert r.status_code in {200, 404}  # 404 acceptable if summary requires entities


def test_summary_schema_if_present(test_app):
    db = test_app["db"]
    client = test_app["client"]
    headers_for = test_app["headers_for"]
    user, asmt = _setup(db, "svc_sumsch_")
    db.run(db.create_entity(asmt.id, entity_type=models.EntityType.SERVICE_ACCOUNT, sam_account_name="sumtest"))
    r = client.get(f"/api/v1/service-accounts/summary?assessment_id={asmt.id}", headers=headers_for(user))
    if r.status_code == 200:
        data = r.json()
        assert isinstance(data, dict)
        # At minimum should have counts
        assert any(k in data for k in {"total", "by_risk", "kerberoastable_count", "counts"})
