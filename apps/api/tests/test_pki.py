"""PKI/ADCS ESC scoring pipeline tests."""
from __future__ import annotations

import asyncio
from uuid import UUID

import pytest

from adbygod_api import models


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _make_cert_template(assessment_id: UUID, session_maker, **kwargs) -> models.CertTemplate:
    defaults = dict(
        assessment_id=assessment_id,
        name="TestTemplate",
        ca_name="LAB-CA",
        esc1_vulnerable=False,
        esc2_vulnerable=False,
        esc3_vulnerable=False,
        esc4_vulnerable=False,
        enrollee_supplies_subject=False,
        requires_manager_approval=False,
        authorized_signatures_required=0,
        ekus=[],
        enrollment_rights=[],
        write_rights=[],
    )
    defaults.update(kwargs)

    async def _create():
        async with session_maker() as db:
            t = models.CertTemplate(**defaults)
            db.add(t)
            await db.commit()
            await db.refresh(t)
            return t

    return asyncio.run(_create())


# ---------------------------------------------------------------------------
# fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def pki_setup(test_app):
    client = test_app["client"]
    db = test_app["db"]
    headers_for = test_app["headers_for"]
    session_maker = test_app["session_maker"]

    admin = asyncio.run(db.create_user("pki_admin", "pki_admin@test.local", is_superadmin=True))
    analyst = asyncio.run(db.create_user("pki_analyst", "pki_analyst@test.local"))
    other = asyncio.run(db.create_user("pki_other", "pki_other@test.local"))

    ws = asyncio.run(db.create_workspace("pki-ws"))
    asyncio.run(db.add_workspace_user(ws.id, analyst.id, role="analyst"))

    assessment = asyncio.run(db.create_assessment("PKI Audit", "lab.local", workspace_id=ws.id, created_by=analyst.id))

    return dict(
        client=client,
        session_maker=session_maker,
        assessment_id=assessment.id,
        admin_headers=headers_for(admin),
        analyst_headers=headers_for(analyst),
        other_headers=headers_for(other),
    )


# ---------------------------------------------------------------------------
# /pki/templates
# ---------------------------------------------------------------------------

def test_templates_empty_returns_list(pki_setup):
    r = pki_setup["client"].get(
        "/api/v1/pki/templates",
        params={"assessment_id": str(pki_setup["assessment_id"])},
        headers=pki_setup["analyst_headers"],
    )
    assert r.status_code == 200
    assert r.json() == []


def test_templates_all_returned(pki_setup):
    aid = pki_setup["assessment_id"]
    sm = pki_setup["session_maker"]
    _make_cert_template(aid, sm, name="T-ESC1", esc1_vulnerable=True)
    _make_cert_template(aid, sm, name="T-Clean")

    r = pki_setup["client"].get(
        "/api/v1/pki/templates",
        params={"assessment_id": str(aid)},
        headers=pki_setup["analyst_headers"],
    )
    assert r.status_code == 200
    names = {t["name"] for t in r.json()}
    assert {"T-ESC1", "T-Clean"} == names


def test_templates_vulnerable_only_filter(pki_setup):
    aid = pki_setup["assessment_id"]
    sm = pki_setup["session_maker"]
    _make_cert_template(aid, sm, name="V-ESC2", esc2_vulnerable=True)
    _make_cert_template(aid, sm, name="V-ESC3", esc3_vulnerable=True)
    _make_cert_template(aid, sm, name="V-Safe")

    r = pki_setup["client"].get(
        "/api/v1/pki/templates",
        params={"assessment_id": str(aid), "vulnerable_only": "true"},
        headers=pki_setup["analyst_headers"],
    )
    assert r.status_code == 200
    names = {t["name"] for t in r.json()}
    assert "V-ESC2" in names
    assert "V-ESC3" in names
    assert "V-Safe" not in names


def test_templates_vulnerable_only_includes_esc4(pki_setup):
    aid = pki_setup["assessment_id"]
    sm = pki_setup["session_maker"]
    _make_cert_template(aid, sm, name="V-ESC4", esc4_vulnerable=True)

    r = pki_setup["client"].get(
        "/api/v1/pki/templates",
        params={"assessment_id": str(aid), "vulnerable_only": "true"},
        headers=pki_setup["analyst_headers"],
    )
    assert r.status_code == 200
    assert any(t["name"] == "V-ESC4" for t in r.json())


def test_templates_schema_fields(pki_setup):
    aid = pki_setup["assessment_id"]
    sm = pki_setup["session_maker"]
    _make_cert_template(
        aid, sm, name="FieldCheck",
        ca_name="MYCA",
        esc1_vulnerable=True,
        enrollee_supplies_subject=True,
        ekus=["1.3.6.1.5.5.7.3.2"],
    )

    r = pki_setup["client"].get(
        "/api/v1/pki/templates",
        params={"assessment_id": str(aid)},
        headers=pki_setup["analyst_headers"],
    )
    assert r.status_code == 200
    t = next(item for item in r.json() if item["name"] == "FieldCheck")
    assert t["ca_name"] == "MYCA"
    assert t["esc1_vulnerable"] is True
    assert t["esc2_vulnerable"] is False
    assert t["enrollee_supplies_subject"] is True
    assert "1.3.6.1.5.5.7.3.2" in t["ekus"]


def test_templates_access_control_no_workspace(pki_setup):
    aid = pki_setup["assessment_id"]
    r = pki_setup["client"].get(
        "/api/v1/pki/templates",
        params={"assessment_id": str(aid)},
        headers=pki_setup["other_headers"],
    )
    assert r.status_code in (403, 404)


# ---------------------------------------------------------------------------
# /pki/summary
# ---------------------------------------------------------------------------

def test_summary_empty_assessment(pki_setup):
    r = pki_setup["client"].get(
        "/api/v1/pki/summary",
        params={"assessment_id": str(pki_setup["assessment_id"])},
        headers=pki_setup["analyst_headers"],
    )
    assert r.status_code == 200
    data = r.json()
    assert data["total_templates"] == 0
    assert data["vulnerable_templates"] == 0
    assert data["esc1_count"] == 0
    assert data["esc2_count"] == 0
    assert data["esc3_count"] == 0
    assert data["esc4_count"] == 0
    assert data["ca_names"] == []


def test_summary_counts_by_esc_type(pki_setup):
    aid = pki_setup["assessment_id"]
    sm = pki_setup["session_maker"]
    _make_cert_template(aid, sm, name="S-ESC1a", esc1_vulnerable=True)
    _make_cert_template(aid, sm, name="S-ESC1b", esc1_vulnerable=True)
    _make_cert_template(aid, sm, name="S-ESC2", esc2_vulnerable=True)
    _make_cert_template(aid, sm, name="S-ESC3", esc3_vulnerable=True, esc1_vulnerable=True)
    _make_cert_template(aid, sm, name="S-ESC4", esc4_vulnerable=True)
    _make_cert_template(aid, sm, name="S-Clean")

    r = pki_setup["client"].get(
        "/api/v1/pki/summary",
        params={"assessment_id": str(aid)},
        headers=pki_setup["analyst_headers"],
    )
    assert r.status_code == 200
    data = r.json()
    assert data["esc1_count"] == 3  # ESC1a + ESC1b + ESC3 (also has esc1=True)
    assert data["esc2_count"] == 1
    assert data["esc3_count"] == 1
    assert data["esc4_count"] == 1
    assert data["vulnerable_templates"] == 5  # all except S-Clean
    assert data["total_templates"] == 6


def test_summary_ca_names_aggregated(pki_setup):
    aid = pki_setup["assessment_id"]
    sm = pki_setup["session_maker"]
    _make_cert_template(aid, sm, name="CA-T1", ca_name="CORP-CA1", esc1_vulnerable=True)
    _make_cert_template(aid, sm, name="CA-T2", ca_name="CORP-CA1", esc2_vulnerable=True)
    _make_cert_template(aid, sm, name="CA-T3", ca_name="CORP-CA2")

    r = pki_setup["client"].get(
        "/api/v1/pki/summary",
        params={"assessment_id": str(aid)},
        headers=pki_setup["analyst_headers"],
    )
    assert r.status_code == 200
    ca_names = set(r.json()["ca_names"])
    assert "CORP-CA1" in ca_names
    assert "CORP-CA2" in ca_names
    assert len(ca_names) == 2


def test_summary_access_control(pki_setup):
    r = pki_setup["client"].get(
        "/api/v1/pki/summary",
        params={"assessment_id": str(pki_setup["assessment_id"])},
        headers=pki_setup["other_headers"],
    )
    assert r.status_code in (403, 404)


def test_summary_admin_can_access(pki_setup):
    r = pki_setup["client"].get(
        "/api/v1/pki/summary",
        params={"assessment_id": str(pki_setup["assessment_id"])},
        headers=pki_setup["admin_headers"],
    )
    assert r.status_code == 200


def test_summary_assessment_id_in_response(pki_setup):
    r = pki_setup["client"].get(
        "/api/v1/pki/summary",
        params={"assessment_id": str(pki_setup["assessment_id"])},
        headers=pki_setup["analyst_headers"],
    )
    assert r.status_code == 200
    assert r.json()["assessment_id"] == str(pki_setup["assessment_id"])


def test_templates_vulnerable_only_false_returns_all(pki_setup):
    aid = pki_setup["assessment_id"]
    sm = pki_setup["session_maker"]
    _make_cert_template(aid, sm, name="ALL-ESC1", esc1_vulnerable=True)
    _make_cert_template(aid, sm, name="ALL-Safe")

    r = pki_setup["client"].get(
        "/api/v1/pki/templates",
        params={"assessment_id": str(aid), "vulnerable_only": "false"},
        headers=pki_setup["analyst_headers"],
    )
    assert r.status_code == 200
    names = {t["name"] for t in r.json()}
    assert "ALL-ESC1" in names
    assert "ALL-Safe" in names
