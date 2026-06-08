"""Deep tests for assessment lifecycle, entity routes, finding routes, and graph routes."""
from __future__ import annotations

import uuid

from adbygod_api import models


# ── helpers ───────────────────────────────────────────────────────────────────

def _setup(db, prefix=""):
    user = db.run(db.create_user(f"{prefix}user", f"{prefix}@x.local"))
    ws = db.run(db.create_workspace(f"{prefix}ws"))
    db.run(db.add_workspace_user(ws.id, user.id, role="owner"))
    asmt = db.run(db.create_assessment(
        f"{prefix}asmt", f"{prefix}.corp.local",
        workspace_id=ws.id, created_by=user.id
    ))
    return user, ws, asmt


def _populate_domain(db, asmt_id):
    """Add a realistic set of entities and edges."""
    dc = db.run(db.create_entity(asmt_id, entity_type=models.EntityType.DC, sam_account_name="DC01$", tier=0))
    domain = db.run(db.create_entity(asmt_id, entity_type=models.EntityType.DOMAIN, sam_account_name="corp.local", tier=0))
    da_group = db.run(db.create_entity(asmt_id, entity_type=models.EntityType.GROUP, sam_account_name="Domain Admins", tier=0))
    admin = db.run(db.create_entity(asmt_id, entity_type=models.EntityType.USER, sam_account_name="Administrator", tier=0, is_crown_jewel=True))
    jdoe = db.run(db.create_entity(asmt_id, entity_type=models.EntityType.USER, sam_account_name="jdoe"))
    ws1 = db.run(db.create_entity(asmt_id, entity_type=models.EntityType.COMPUTER, sam_account_name="WORKSTATION01$"))
    svc = db.run(db.create_entity(asmt_id, entity_type=models.EntityType.SERVICE_ACCOUNT, sam_account_name="svc_sql"))
    ca = db.run(db.create_entity(asmt_id, entity_type=models.EntityType.CA, sam_account_name="CORP-CA", tier=0))

    edges = [
        (admin.id, da_group.id, models.EdgeType.MEMBER_OF, 0.9),
        (jdoe.id,  da_group.id, models.EdgeType.MEMBER_OF, 0.9),
        (jdoe.id,  admin.id,    models.EdgeType.GENERIC_ALL, 0.95),
        (svc.id,   domain.id,   models.EdgeType.DCSYNC, 1.0),
        (jdoe.id,  ws1.id,      models.EdgeType.ADMIN_TO, 0.85),
        (jdoe.id,  ws1.id,      models.EdgeType.CAN_RDP, 0.7),
        (admin.id, ca.id,       models.EdgeType.MANAGE_CA, 0.95),
    ]
    for src, tgt, etype, rw in edges:
        db.run(db.create_edge(asmt_id, src, tgt, edge_type=etype, risk_weight=rw))

    return dc, domain, da_group, admin, jdoe, ws1, svc, ca


def _populate_findings(db, asmt_id):
    findings = []
    specs = [
        ("AS-REP Roasting", "Kerberos", models.SeverityLevel.HIGH, 78.0),
        ("DCSync Rights", "Kerberos", models.SeverityLevel.CRITICAL, 95.0),
        ("LAPS Not Deployed", "Configuration", models.SeverityLevel.MEDIUM, 45.0),
        ("Unconstrained Delegation", "Kerberos", models.SeverityLevel.CRITICAL, 92.0),
        ("Weak Password Policy", "Password", models.SeverityLevel.LOW, 22.0),
        ("Shadow Admin Detected", "ACL", models.SeverityLevel.HIGH, 81.0),
        ("ESC1 Template Abuse", "AD CS", models.SeverityLevel.CRITICAL, 98.0),
        ("RBCD Misconfiguration", "Delegation", models.SeverityLevel.HIGH, 76.0),
    ]
    for title, module, sev, score in specs:
        f = db.run(db.create_finding(
            asmt_id, title=title, module=module, severity=sev, composite_score=score
        ))
        findings.append(f)
    return findings


# ── assessment CRUD ───────────────────────────────────────────────────────────

class TestAssessmentCRUD:
    def test_create_assessment(self, test_app):
        client = test_app["client"]
        db = test_app["db"]
        headers_for = test_app["headers_for"]
        user, ws, _ = _setup(db, "acrud_")
        r = client.post(
            "/api/v1/assessments",
            json={"name": "New Assessment", "domain": "test.local", "workspace_id": str(ws.id)},
            headers=headers_for(user),
        )
        assert r.status_code == 201
        data = r.json()
        assert data["name"] == "New Assessment"
        assert data["domain"] == "test.local"

    def test_list_assessments(self, test_app):
        client = test_app["client"]
        db = test_app["db"]
        headers_for = test_app["headers_for"]
        user, ws, asmt = _setup(db, "alist_")
        r = client.get("/api/v1/assessments", headers=headers_for(user))
        assert r.status_code == 200
        ids = [a["id"] for a in r.json()]
        assert str(asmt.id) in ids

    def test_get_assessment_by_id(self, test_app):
        client = test_app["client"]
        db = test_app["db"]
        headers_for = test_app["headers_for"]
        user, ws, asmt = _setup(db, "aget_")
        r = client.get(f"/api/v1/assessments/{asmt.id}", headers=headers_for(user))
        assert r.status_code == 200
        assert r.json()["id"] == str(asmt.id)

    def test_get_assessment_404(self, test_app):
        client = test_app["client"]
        db = test_app["db"]
        headers_for = test_app["headers_for"]
        user, _, _ = _setup(db, "a404_")
        r = client.get(f"/api/v1/assessments/{uuid.uuid4()}", headers=headers_for(user))
        assert r.status_code in (403, 404)

    def test_update_assessment_name(self, test_app):
        client = test_app["client"]
        db = test_app["db"]
        headers_for = test_app["headers_for"]
        user, ws, asmt = _setup(db, "aupd_")
        r = client.patch(
            f"/api/v1/assessments/{asmt.id}",
            json={"name": "Updated Name"},
            headers=headers_for(user),
        )
        assert r.status_code == 200
        assert r.json()["name"] == "Updated Name"

    def test_delete_assessment(self, test_app):
        client = test_app["client"]
        db = test_app["db"]
        headers_for = test_app["headers_for"]
        user, ws, asmt = _setup(db, "adel_")
        r = client.delete(f"/api/v1/assessments/{asmt.id}", headers=headers_for(user))
        assert r.status_code == 204
        r2 = client.get(f"/api/v1/assessments/{asmt.id}", headers=headers_for(user))
        assert r2.status_code in (403, 404)

    def test_assessment_requires_auth(self, test_app):
        r = test_app["client"].get("/api/v1/assessments")
        assert r.status_code == 401

    def test_create_assessment_invalid_missing_domain(self, test_app):
        client = test_app["client"]
        db = test_app["db"]
        headers_for = test_app["headers_for"]
        user, ws, _ = _setup(db, "ainv_")
        r = client.post(
            "/api/v1/assessments",
            json={"name": "No Domain"},
            headers=headers_for(user),
        )
        assert r.status_code == 422

    def test_assessment_stats(self, test_app):
        client = test_app["client"]
        db = test_app["db"]
        headers_for = test_app["headers_for"]
        user, ws, asmt = _setup(db, "astats_")
        _populate_findings(db, asmt.id)
        r = client.get(f"/api/v1/assessments/{asmt.id}/stats", headers=headers_for(user))
        assert r.status_code == 200

    def test_assessment_dashboard(self, test_app):
        client = test_app["client"]
        db = test_app["db"]
        headers_for = test_app["headers_for"]
        user, ws, asmt = _setup(db, "adash_")
        _populate_domain(db, asmt.id)
        _populate_findings(db, asmt.id)
        r = client.get(f"/api/v1/assessments/{asmt.id}/dashboard", headers=headers_for(user))
        assert r.status_code == 200

    def test_workspace_isolation(self, test_app):
        client = test_app["client"]
        db = test_app["db"]
        headers_for = test_app["headers_for"]
        user1, _, asmt1 = _setup(db, "iso1_")
        user2 = db.run(db.create_user("iso_outsider2", "iso2@x.local"))
        r = client.get(f"/api/v1/assessments/{asmt1.id}", headers=headers_for(user2))
        assert r.status_code in (403, 404)


# ── entity routes ─────────────────────────────────────────────────────────────

class TestEntityRoutes:
    def test_list_entities_empty(self, test_app):
        client = test_app["client"]
        db = test_app["db"]
        headers_for = test_app["headers_for"]
        user, ws, asmt = _setup(db, "ent_empty_")
        r = client.get(
            "/api/v1/entities/",
            params={"assessment_id": str(asmt.id)},
            headers=headers_for(user),
        )
        assert r.status_code == 200
        assert isinstance(r.json(), list)

    def test_list_entities_with_data(self, test_app):
        client = test_app["client"]
        db = test_app["db"]
        headers_for = test_app["headers_for"]
        user, ws, asmt = _setup(db, "ent_list_")
        _populate_domain(db, asmt.id)
        r = client.get(
            "/api/v1/entities/",
            params={"assessment_id": str(asmt.id)},
            headers=headers_for(user),
        )
        assert r.status_code == 200
        entities = r.json()
        assert len(entities) >= 6
        types_found = {e["entity_type"] for e in entities}
        assert "USER" in types_found
        assert "COMPUTER" in types_found

    def test_entity_type_summary(self, test_app):
        client = test_app["client"]
        db = test_app["db"]
        headers_for = test_app["headers_for"]
        user, ws, asmt = _setup(db, "ent_sum_")
        _populate_domain(db, asmt.id)
        r = client.get(
            "/api/v1/entities/summary",
            params={"assessment_id": str(asmt.id)},
            headers=headers_for(user),
        )
        assert r.status_code == 200

    def test_entity_intelligence(self, test_app):
        client = test_app["client"]
        db = test_app["db"]
        headers_for = test_app["headers_for"]
        user, ws, asmt = _setup(db, "ent_intel_")
        dc, domain, da, admin, jdoe, ws1, svc, ca = _populate_domain(db, asmt.id)
        r = client.get(
            "/api/v1/entities/intelligence",
            params={"assessment_id": str(asmt.id), "entity_id": str(jdoe.id)},
            headers=headers_for(user),
        )
        assert r.status_code == 200

    def test_get_single_entity(self, test_app):
        client = test_app["client"]
        db = test_app["db"]
        headers_for = test_app["headers_for"]
        user, ws, asmt = _setup(db, "ent_get_")
        dc, domain, da, admin, jdoe, ws1, svc, ca = _populate_domain(db, asmt.id)
        r = client.get(f"/api/v1/entities/{jdoe.id}", headers=headers_for(user))
        assert r.status_code == 200
        assert r.json()["sam_account_name"] == "jdoe"

    def test_list_entities_filter_by_type(self, test_app):
        client = test_app["client"]
        db = test_app["db"]
        headers_for = test_app["headers_for"]
        user, ws, asmt = _setup(db, "ent_filt_")
        _populate_domain(db, asmt.id)
        r = client.get(
            "/api/v1/entities/",
            params={"assessment_id": str(asmt.id), "entity_type": "USER"},
            headers=headers_for(user),
        )
        assert r.status_code == 200
        for e in r.json():
            assert e["entity_type"] == "USER"

    def test_entity_access_control(self, test_app):
        client = test_app["client"]
        db = test_app["db"]
        headers_for = test_app["headers_for"]
        user, ws, asmt = _setup(db, "ent_acl_")
        outsider = db.run(db.create_user("ent_outsider", "ent_out@x.local"))
        r = client.get(
            "/api/v1/entities/",
            params={"assessment_id": str(asmt.id)},
            headers=headers_for(outsider),
        )
        assert r.status_code in (403, 404)


# ── finding routes ────────────────────────────────────────────────────────────

class TestFindingRoutes:
    def test_list_findings_empty(self, test_app):
        client = test_app["client"]
        db = test_app["db"]
        headers_for = test_app["headers_for"]
        user, ws, asmt = _setup(db, "find_empty_")
        r = client.get(
            "/api/v1/findings/",
            params={"assessment_id": str(asmt.id)},
            headers=headers_for(user),
        )
        assert r.status_code == 200
        data = r.json()
        assert "items" in data
        assert data["total"] == 0

    def test_list_findings_with_data(self, test_app):
        client = test_app["client"]
        db = test_app["db"]
        headers_for = test_app["headers_for"]
        user, ws, asmt = _setup(db, "find_list_")
        _populate_findings(db, asmt.id)
        r = client.get(
            "/api/v1/findings/",
            params={"assessment_id": str(asmt.id), "page_size": 50},
            headers=headers_for(user),
        )
        assert r.status_code == 200
        data = r.json()
        assert data["total"] == 8
        assert len(data["items"]) == 8

    def test_list_findings_filter_by_severity(self, test_app):
        client = test_app["client"]
        db = test_app["db"]
        headers_for = test_app["headers_for"]
        user, ws, asmt = _setup(db, "find_sev_")
        _populate_findings(db, asmt.id)
        r = client.get(
            "/api/v1/findings/",
            params={"assessment_id": str(asmt.id), "severity": "CRITICAL"},
            headers=headers_for(user),
        )
        assert r.status_code == 200
        for f in r.json()["items"]:
            assert f["severity"] == "CRITICAL"

    def test_get_single_finding(self, test_app):
        client = test_app["client"]
        db = test_app["db"]
        headers_for = test_app["headers_for"]
        user, ws, asmt = _setup(db, "find_get_")
        findings = _populate_findings(db, asmt.id)
        r = client.get(f"/api/v1/findings/{findings[0].id}", headers=headers_for(user))
        assert r.status_code == 200
        assert r.json()["id"] == str(findings[0].id)

    def test_findings_return_attack_metadata(self, test_app):
        client = test_app["client"]
        db = test_app["db"]
        headers_for = test_app["headers_for"]
        user, ws, asmt = _setup(db, "find_meta_")
        finding = db.run(db.create_finding(
            asmt.id,
            title="DCSync path",
            module="ACL",
            severity=models.SeverityLevel.CRITICAL,
            composite_score=95.0,
        ))

        async def enrich():
            async with db.session_maker() as session:
                stored = await session.get(models.Finding, finding.id)
                stored.cve_ids = ["CVE-2025-0001"]
                stored.mitre_attack_ids = ["T1003.006"]
                stored.attack_path = [
                    {
                        "entity_id": "user-1",
                        "entity_label": "svc_sync",
                        "entity_type": "USER",
                        "edge_type": "DCSYNC",
                        "explanation": "svc_sync can replicate directory secrets",
                    },
                    {
                        "entity_id": "domain-1",
                        "entity_label": "corp.local",
                        "entity_type": "DOMAIN",
                        "explanation": "Domain secrets target",
                    },
                ]
                await session.commit()

        db.run(enrich())

        list_resp = client.get(
            "/api/v1/findings/",
            params={"assessment_id": str(asmt.id), "page_size": 50},
            headers=headers_for(user),
        )
        assert list_resp.status_code == 200
        item = list_resp.json()["items"][0]
        assert item["cve_ids"] == ["CVE-2025-0001"]
        assert item["mitre_attack_ids"] == ["T1003.006"]
        assert item["attack_path"][0]["edge_type"] == "DCSYNC"

        detail_resp = client.get(f"/api/v1/findings/{finding.id}", headers=headers_for(user))
        assert detail_resp.status_code == 200
        detail = detail_resp.json()
        assert detail["cve_ids"] == ["CVE-2025-0001"]
        assert detail["mitre_attack_ids"] == ["T1003.006"]
        assert detail["attack_path"][1]["entity_type"] == "DOMAIN"

    def test_update_finding_status(self, test_app):
        client = test_app["client"]
        db = test_app["db"]
        headers_for = test_app["headers_for"]
        user, ws, asmt = _setup(db, "find_upd_")
        findings = _populate_findings(db, asmt.id)
        r = client.patch(
            f"/api/v1/findings/{findings[0].id}",
            json={"status": "IN_REVIEW"},
            headers=headers_for(user),
        )
        assert r.status_code == 200
        assert r.json()["status"] == "IN_REVIEW"

    def test_update_finding_all_statuses(self, test_app):
        client = test_app["client"]
        db = test_app["db"]
        headers_for = test_app["headers_for"]
        user, ws, asmt = _setup(db, "find_allstat_")
        findings = _populate_findings(db, asmt.id)
        statuses = ["IN_REVIEW", "REMEDIATED", "ACCEPTED", "FALSE_POSITIVE", "OPEN"]
        for status_val in statuses:
            r = client.patch(
                f"/api/v1/findings/{findings[0].id}",
                json={"status": status_val},
                headers=headers_for(user),
            )
            assert r.status_code == 200, f"Status {status_val} failed: {r.text}"
            assert r.json()["status"] == status_val

    def test_finding_module_summary(self, test_app):
        client = test_app["client"]
        db = test_app["db"]
        headers_for = test_app["headers_for"]
        user, ws, asmt = _setup(db, "find_modsm_")
        _populate_findings(db, asmt.id)
        r = client.get(
            "/api/v1/findings/modules/summary",
            params={"assessment_id": str(asmt.id)},
            headers=headers_for(user),
        )
        assert r.status_code == 200

    def test_list_findings_module_filter_accepts_aliases(self, test_app):
        client = test_app["client"]
        db = test_app["db"]
        headers_for = test_app["headers_for"]
        user, ws, asmt = _setup(db, "find_modalias_")
        db.run(db.create_finding(
            asmt.id,
            title="ESC1 template",
            module="AD CS",
            severity=models.SeverityLevel.CRITICAL,
            composite_score=96.0,
        ))
        db.run(db.create_finding(
            asmt.id,
            title="Forest trust issue",
            module="Domain and Forest Trust Analysis",
            severity=models.SeverityLevel.HIGH,
            composite_score=81.0,
        ))

        adcs = client.get(
            "/api/v1/findings/",
            params={"assessment_id": str(asmt.id), "module": "adcs"},
            headers=headers_for(user),
        )
        assert adcs.status_code == 200
        assert adcs.json()["total"] == 1
        assert adcs.json()["items"][0]["module"] == "AD CS"

        trusts = client.get(
            "/api/v1/findings/",
            params={"assessment_id": str(asmt.id), "module": "trust"},
            headers=headers_for(user),
        )
        assert trusts.status_code == 200
        assert trusts.json()["total"] == 1
        assert trusts.json()["items"][0]["module"] == "Domain and Forest Trust Analysis"

    def test_finding_access_control(self, test_app):
        client = test_app["client"]
        db = test_app["db"]
        headers_for = test_app["headers_for"]
        user, ws, asmt = _setup(db, "find_acl_")
        _populate_findings(db, asmt.id)
        outsider = db.run(db.create_user("find_out", "findout@x.local"))
        r = client.get(
            "/api/v1/findings/",
            params={"assessment_id": str(asmt.id)},
            headers=headers_for(outsider),
        )
        assert r.status_code in (403, 404)

    def test_finding_not_found(self, test_app):
        client = test_app["client"]
        db = test_app["db"]
        headers_for = test_app["headers_for"]
        user, _, _ = _setup(db, "find404_")
        r = client.get(f"/api/v1/findings/{uuid.uuid4()}", headers=headers_for(user))
        assert r.status_code in (403, 404)


# ── graph routes ──────────────────────────────────────────────────────────────

class TestGraphRoutes:
    def test_graph_data_empty(self, test_app):
        client = test_app["client"]
        db = test_app["db"]
        headers_for = test_app["headers_for"]
        user, ws, asmt = _setup(db, "gr_empty_")
        r = client.get(f"/api/v1/graph/{asmt.id}/data", headers=headers_for(user))
        assert r.status_code == 200
        data = r.json()
        assert "nodes" in data
        assert "edges" in data

    def test_graph_data_with_entities(self, test_app):
        client = test_app["client"]
        db = test_app["db"]
        headers_for = test_app["headers_for"]
        user, ws, asmt = _setup(db, "gr_data_")
        _populate_domain(db, asmt.id)
        r = client.get(f"/api/v1/graph/{asmt.id}/data", headers=headers_for(user))
        assert r.status_code == 200
        data = r.json()
        assert len(data["nodes"]) >= 6
        assert len(data["edges"]) >= 5

    def test_graph_paths(self, test_app):
        client = test_app["client"]
        db = test_app["db"]
        headers_for = test_app["headers_for"]
        user, ws, asmt = _setup(db, "gr_paths_")
        _populate_domain(db, asmt.id)
        r = client.get(f"/api/v1/graph/{asmt.id}/paths", headers=headers_for(user))
        assert r.status_code == 200

    def test_graph_blast_radius(self, test_app):
        client = test_app["client"]
        db = test_app["db"]
        headers_for = test_app["headers_for"]
        user, ws, asmt = _setup(db, "gr_blast_")
        _populate_domain(db, asmt.id)
        r = client.get(f"/api/v1/graph/{asmt.id}/blast-radius", headers=headers_for(user))
        assert r.status_code == 200

    def test_graph_simulate_removal(self, test_app):
        client = test_app["client"]
        db = test_app["db"]
        headers_for = test_app["headers_for"]
        user, ws, asmt = _setup(db, "gr_sim_")
        dc, domain, da, admin, jdoe, ws1, svc, ca = _populate_domain(db, asmt.id)
        # EdgeRemoval uses "source" and "target" (string IDs)
        r = client.post(
            f"/api/v1/graph/{asmt.id}/simulate-removal",
            json=[{"source": str(jdoe.id), "target": str(da.id)}],
            headers=headers_for(user),
        )
        assert r.status_code == 200
        data = r.json()
        assert "before" in data or "metric" in data

    def test_graph_categories(self, test_app):
        client = test_app["client"]
        db = test_app["db"]
        headers_for = test_app["headers_for"]
        user, ws, asmt = _setup(db, "gr_cat_")
        _populate_domain(db, asmt.id)
        r = client.get(f"/api/v1/graph/{asmt.id}/categories", headers=headers_for(user))
        assert r.status_code == 200

    def test_graph_choke_points(self, test_app):
        client = test_app["client"]
        db = test_app["db"]
        headers_for = test_app["headers_for"]
        user, ws, asmt = _setup(db, "gr_choke_")
        _populate_domain(db, asmt.id)
        r = client.get(f"/api/v1/graph/{asmt.id}/choke-points", headers=headers_for(user))
        assert r.status_code == 200

    def test_graph_access_control(self, test_app):
        client = test_app["client"]
        db = test_app["db"]
        headers_for = test_app["headers_for"]
        user, ws, asmt = _setup(db, "gr_acl_")
        outsider = db.run(db.create_user("gr_outsider", "grout@x.local"))
        r = client.get(f"/api/v1/graph/{asmt.id}/data", headers=headers_for(outsider))
        assert r.status_code in (403, 404)

    def test_attack_flow_chains_returns_data(self, test_app):
        client = test_app["client"]
        db = test_app["db"]
        headers_for = test_app["headers_for"]
        user, _, _ = _setup(db, "atfl_")
        r = client.get("/api/v1/graph/attack-flow-chains", headers=headers_for(user))
        assert r.status_code == 200
        # Returns a dict with categories and chains
        data = r.json()
        assert isinstance(data, (list, dict))


class TestAssessmentBackedEndpointSurface:
    def test_assessment_result_endpoints_return_current_assessment_data(self, test_app):
        client = test_app["client"]
        db = test_app["db"]
        headers_for = test_app["headers_for"]
        user, ws, asmt = _setup(db, "surface_")
        dc, domain, da, admin, jdoe, ws1, svc, ca = _populate_domain(db, asmt.id)
        findings = _populate_findings(db, asmt.id)
        trust = db.run(db.create_entity(asmt.id, entity_type=models.EntityType.TRUST, sam_account_name="legacy.local"))

        async def enrich_surface_data():
            async with db.session_maker() as session:
                stored_svc = await session.get(models.Entity, svc.id)
                stored_svc.attributes = {"spns": ["MSSQLSvc/sql.corp.local"], "kerberoastable": True}
                stored_trust = await session.get(models.Entity, trust.id)
                stored_trust.domain = "corp.local"
                stored_trust.attributes = {
                    "target_domain": "legacy.local",
                    "trust_type": "FOREST",
                    "direction": "BIDIRECTIONAL",
                    "sid_filtering": False,
                    "selective_auth": False,
                    "transitive": True,
                }
                stored_finding = await session.get(models.Finding, findings[0].id)
                stored_finding.cve_ids = ["CVE-2026-0002"]
                stored_finding.mitre_attack_ids = ["T1558.004"]
                stored_finding.attack_path = [
                    {"entity_id": str(jdoe.id), "entity_label": "jdoe", "entity_type": "USER", "edge_type": "GENERIC_ALL"},
                    {"entity_id": str(admin.id), "entity_label": "Administrator", "entity_type": "USER"},
                ]
                session.add(models.CertTemplate(
                    id=uuid.uuid4(),
                    assessment_id=asmt.id,
                    name="UserESC1",
                    ca_name="CORP-CA",
                    enrollee_supplies_subject=True,
                    esc1_vulnerable=True,
                    ekus=["Client Authentication"],
                    enrollment_rights=["Domain Users"],
                    write_rights=[],
                    raw_attributes={},
                ))
                session.add(models.ExposurePath(
                    id=uuid.uuid4(),
                    assessment_id=asmt.id,
                    source_entity_id=jdoe.id,
                    target_entity_id=admin.id,
                    path_steps=stored_finding.attack_path,
                    hop_count=1,
                    path_score=91.0,
                    target_tier=0,
                    path_type="acl_abuse",
                    explanation="jdoe controls Administrator",
                ))
                await session.commit()

        db.run(enrich_surface_data())

        endpoints = [
            ("GET", f"/api/v1/assessments/{asmt.id}/stats", None),
            ("GET", f"/api/v1/assessments/{asmt.id}/dashboard", None),
            ("GET", "/api/v1/findings", {"assessment_id": str(asmt.id), "page_size": 50}),
            ("GET", "/api/v1/findings/modules/summary", {"assessment_id": str(asmt.id)}),
            ("GET", f"/api/v1/findings/{findings[0].id}", None),
            ("GET", f"/api/v1/findings/{findings[0].id}/evidence", None),
            ("GET", "/api/v1/entities/", {"assessment_id": str(asmt.id)}),
            ("GET", "/api/v1/entities/summary", {"assessment_id": str(asmt.id)}),
            ("GET", "/api/v1/entities/intelligence", {"assessment_id": str(asmt.id)}),
            ("GET", f"/api/v1/entities/{jdoe.id}", None),
            ("GET", f"/api/v1/graph/{asmt.id}/data", None),
            ("GET", f"/api/v1/graph/{asmt.id}/paths", None),
            ("GET", f"/api/v1/graph/{asmt.id}/blast-radius", None),
            ("GET", f"/api/v1/graph/{asmt.id}/categories", None),
            ("GET", f"/api/v1/graph/{asmt.id}/choke-points", None),
            ("GET", "/api/v1/pki/templates", {"assessment_id": str(asmt.id)}),
            ("GET", "/api/v1/pki/summary", {"assessment_id": str(asmt.id)}),
            ("GET", "/api/v1/service-accounts", {"assessment_id": str(asmt.id)}),
            ("GET", "/api/v1/service-accounts/summary", {"assessment_id": str(asmt.id)}),
            ("GET", "/api/v1/trusts", {"assessment_id": str(asmt.id)}),
            ("GET", "/api/v1/trusts/summary", {"assessment_id": str(asmt.id)}),
            ("GET", "/api/v1/trusts/abuse", {"assessment_id": str(asmt.id)}),
            ("GET", "/api/v1/trusts/abuse/techniques", {"assessment_id": str(asmt.id)}),
            ("GET", "/api/v1/trusts/forest-pivot", {"assessment_id": str(asmt.id)}),
            ("GET", "/api/v1/trusts/forest-pivot/paths", {"assessment_id": str(asmt.id)}),
            ("GET", "/api/v1/lateral-movement/summary", {"assessment_id": str(asmt.id)}),
            ("GET", "/api/v1/lateral-movement/techniques", {"assessment_id": str(asmt.id)}),
            ("GET", "/api/v1/lateral-movement/paths", {"assessment_id": str(asmt.id)}),
            ("GET", "/api/v1/lateral-movement/chains", {"assessment_id": str(asmt.id)}),
            ("GET", f"/api/v1/remediation/candidates/{asmt.id}", None),
            ("GET", f"/api/v1/validation/global-score/{asmt.id}", None),
            ("GET", f"/api/v1/validation/overview/{asmt.id}", None),
            ("GET", f"/api/v1/validation/runs/{asmt.id}", None),
            ("GET", f"/api/v1/arsenal/target-from-assessment/{asmt.id}", None),
            ("GET", f"/api/v1/reports/preview/{asmt.id}", None),
        ]
        for method, path, params in endpoints:
            response = client.request(method, path, params=params, headers=headers_for(user))
            assert response.status_code == 200, f"{method} {path} failed: {response.text}"

        simulate = client.post(
            "/api/v1/remediation/simulate",
            headers=headers_for(user),
            json={"assessment_id": str(asmt.id), "finding_ids": [str(findings[0].id)]},
        )
        assert simulate.status_code == 200

        trust_sim = client.post(
            "/api/v1/trusts/simulate",
            params={"assessment_id": str(asmt.id)},
            headers=headers_for(user),
            json={"overrides": [{"trust_name": "legacy.local", "sid_filtering": True}]},
        )
        assert trust_sim.status_code == 200


# ── validation routes ─────────────────────────────────────────────────────────

class TestValidationRoutes:
    def test_list_modules(self, test_app):
        client = test_app["client"]
        db = test_app["db"]
        headers_for = test_app["headers_for"]
        user, _, _ = _setup(db, "val_mods_")
        r = client.get("/api/v1/validation/modules", headers=headers_for(user))
        assert r.status_code == 200
        modules = r.json()
        assert isinstance(modules, list)
        assert len(modules) > 0
        for m in modules:
            assert "id" in m
            assert "name" in m

    def test_synthetic_presets(self, test_app):
        client = test_app["client"]
        db = test_app["db"]
        headers_for = test_app["headers_for"]
        user, _, _ = _setup(db, "val_pre_")
        r = client.get("/api/v1/validation/synthetic/presets", headers=headers_for(user))
        assert r.status_code == 200

    def test_global_score_empty_assessment(self, test_app):
        client = test_app["client"]
        db = test_app["db"]
        headers_for = test_app["headers_for"]
        user, ws, asmt = _setup(db, "val_gs_")
        r = client.get(f"/api/v1/validation/global-score/{asmt.id}", headers=headers_for(user))
        assert r.status_code == 200
        data = r.json()
        assert "score" in data
        assert data["score"] == 0

    def test_global_score_with_findings(self, test_app):
        client = test_app["client"]
        db = test_app["db"]
        headers_for = test_app["headers_for"]
        user, ws, asmt = _setup(db, "val_gsfind_")
        _populate_domain(db, asmt.id)
        _populate_findings(db, asmt.id)
        r = client.get(f"/api/v1/validation/global-score/{asmt.id}", headers=headers_for(user))
        assert r.status_code == 200
        data = r.json()
        assert data["score"] > 0
        assert "rating" in data
        assert "factors" in data

    def test_validation_overview(self, test_app):
        client = test_app["client"]
        db = test_app["db"]
        headers_for = test_app["headers_for"]
        user, ws, asmt = _setup(db, "val_ov_")
        _populate_findings(db, asmt.id)
        r = client.get(f"/api/v1/validation/overview/{asmt.id}", headers=headers_for(user))
        assert r.status_code == 200

    def test_validation_runs_empty(self, test_app):
        client = test_app["client"]
        db = test_app["db"]
        headers_for = test_app["headers_for"]
        user, ws, asmt = _setup(db, "val_runs_")
        r = client.get(f"/api/v1/validation/runs/{asmt.id}", headers=headers_for(user))
        assert r.status_code == 200
        data = r.json()
        # returns either list or dict with "runs" key
        assert isinstance(data, list) or "runs" in data

    def test_posture_timeline(self, test_app):
        client = test_app["client"]
        db = test_app["db"]
        headers_for = test_app["headers_for"]
        user, ws, asmt = _setup(db, "val_tl_")
        _populate_findings(db, asmt.id)
        r = client.get(f"/api/v1/validation/posture-timeline/{asmt.id}", headers=headers_for(user))
        assert r.status_code == 200


# ── loot routes ────────────────────────────────────────────────────────────────

class TestLootRoutes:
    def test_list_loot_empty(self, test_app):
        client = test_app["client"]
        db = test_app["db"]
        headers_for = test_app["headers_for"]
        user, _, _ = _setup(db, "loot_empty_")
        r = client.get("/api/v1/loot", headers=headers_for(user))
        assert r.status_code == 200
        assert isinstance(r.json(), list)

    def test_loot_summary_empty(self, test_app):
        client = test_app["client"]
        db = test_app["db"]
        headers_for = test_app["headers_for"]
        user, _, _ = _setup(db, "loot_sum_")
        r = client.get("/api/v1/loot/summary", headers=headers_for(user))
        assert r.status_code == 200
        data = r.json()
        assert "total_entries" in data
        assert data["total_entries"] == 0

    def test_hash_intel_empty(self, test_app):
        client = test_app["client"]
        db = test_app["db"]
        headers_for = test_app["headers_for"]
        user, _, _ = _setup(db, "loot_hi_")
        r = client.get("/api/v1/loot/hash-intel", headers=headers_for(user))
        assert r.status_code == 200
        data = r.json()
        assert "tools" in data
        assert "hashes" in data

    def test_export_loot_json(self, test_app):
        client = test_app["client"]
        db = test_app["db"]
        headers_for = test_app["headers_for"]
        user, _, _ = _setup(db, "loot_exp_")
        r = client.get("/api/v1/loot/export", headers=headers_for(user))
        assert r.status_code == 200
        assert "application/json" in r.headers.get("content-type", "")

    def test_crack_job_requires_acknowledgement(self, test_app):
        import adbygod_api.config as cfg
        client = test_app["client"]
        db = test_app["db"]
        headers_for = test_app["headers_for"]
        # Must be superadmin with ENABLE_COMMAND_EXECUTION=True to reach the ack check.
        user = db.run(db.create_user("crack_ack_user", "crack_ack@x.local", is_superadmin=True))
        old_flag = cfg.settings.ENABLE_COMMAND_EXECUTION
        try:
            cfg.settings.ENABLE_COMMAND_EXECUTION = True
            r = client.post(
                "/api/v1/loot/crack/start",
                json={
                    "hashes": ["aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0"],
                    "hashcat_mode": 1000,
                    "acknowledge_authorized": False,
                },
                headers=headers_for(user),
            )
        finally:
            cfg.settings.ENABLE_COMMAND_EXECUTION = old_flag
        assert r.status_code == 400

    def test_crack_job_invalid_mode(self, test_app):
        client = test_app["client"]
        db = test_app["db"]
        headers_for = test_app["headers_for"]
        user, _, _ = _setup(db, "crack_mode_")
        r = client.post(
            "/api/v1/loot/crack/start",
            json={
                "hashes": ["aad3b435b51404eeaad3b435b51404ee"],
                "hashcat_mode": 9999999,
                "acknowledge_authorized": True,
            },
            headers=headers_for(user),
        )
        assert r.status_code == 422

    def test_crack_job_not_found(self, test_app):
        client = test_app["client"]
        db = test_app["db"]
        headers_for = test_app["headers_for"]
        user, _, _ = _setup(db, "crack_nf_")
        r = client.get("/api/v1/loot/crack/nonexistent-job-id", headers=headers_for(user))
        assert r.status_code == 404

    def test_crack_too_many_hashes(self, test_app):
        client = test_app["client"]
        db = test_app["db"]
        headers_for = test_app["headers_for"]
        user, _, _ = _setup(db, "crack_many_")
        r = client.post(
            "/api/v1/loot/crack/start",
            json={
                "hashes": ["31d6cfe0d16ae931b73c59d7e0c089c0"] * 5001,
                "hashcat_mode": 1000,
                "acknowledge_authorized": True,
            },
            headers=headers_for(user),
        )
        assert r.status_code == 422

    def test_loot_requires_auth(self, test_app):
        r = test_app["client"].get("/api/v1/loot")
        assert r.status_code == 401


# ── report routes ──────────────────────────────────────────────────────────────

class TestReportRoutes:
    def test_export_json_with_findings(self, test_app):
        client = test_app["client"]
        db = test_app["db"]
        headers_for = test_app["headers_for"]
        user, ws, asmt = _setup(db, "rpt_json_")
        _populate_domain(db, asmt.id)
        _populate_findings(db, asmt.id)
        r = client.post(
            "/api/v1/reports/export",
            json={"assessment_id": str(asmt.id), "format": "json", "sections": []},
            headers=headers_for(user),
        )
        assert r.status_code == 200
        data = r.json()
        assert data["mime_type"] == "application/json"
        import json
        import base64
        content = base64.b64decode(data["content"]) if data.get("encoding") == "base64" else data["content"]
        if isinstance(content, str):
            payload = json.loads(content)
            assert "assessment" in payload or "findings" in payload

    def test_export_csv_format(self, test_app):
        client = test_app["client"]
        db = test_app["db"]
        headers_for = test_app["headers_for"]
        user, ws, asmt = _setup(db, "rpt_csv_")
        _populate_findings(db, asmt.id)
        r = client.post(
            "/api/v1/reports/export",
            json={"assessment_id": str(asmt.id), "format": "csv", "sections": []},
            headers=headers_for(user),
        )
        assert r.status_code == 200
        data = r.json()
        assert data["mime_type"] == "text/csv"
        assert data["filename"].endswith(".csv")

    def test_export_html_format(self, test_app):
        client = test_app["client"]
        db = test_app["db"]
        headers_for = test_app["headers_for"]
        user, ws, asmt = _setup(db, "rpt_html_")
        _populate_findings(db, asmt.id)
        r = client.post(
            "/api/v1/reports/export",
            json={"assessment_id": str(asmt.id), "format": "html", "sections": []},
            headers=headers_for(user),
        )
        assert r.status_code == 200
        data = r.json()
        assert data["mime_type"] == "text/html"

    def test_export_pdf_format(self, test_app):
        client = test_app["client"]
        db = test_app["db"]
        headers_for = test_app["headers_for"]
        user, ws, asmt = _setup(db, "rpt_pdf_")
        _populate_findings(db, asmt.id)
        r = client.post(
            "/api/v1/reports/export",
            json={"assessment_id": str(asmt.id), "format": "pdf", "sections": []},
            headers=headers_for(user),
        )
        assert r.status_code == 200
        data = r.json()
        assert data["mime_type"] == "application/pdf"

    def test_export_invalid_format(self, test_app):
        client = test_app["client"]
        db = test_app["db"]
        headers_for = test_app["headers_for"]
        user, ws, asmt = _setup(db, "rpt_inv_")
        r = client.post(
            "/api/v1/reports/export",
            json={"assessment_id": str(asmt.id), "format": "docx", "sections": []},
            headers=headers_for(user),
        )
        assert r.status_code in (400, 422)

    def test_preview_with_rich_data(self, test_app):
        client = test_app["client"]
        db = test_app["db"]
        headers_for = test_app["headers_for"]
        user, ws, asmt = _setup(db, "rpt_prev_")
        _populate_domain(db, asmt.id)
        _populate_findings(db, asmt.id)
        r = client.get(f"/api/v1/reports/preview/{asmt.id}", headers=headers_for(user))
        assert r.status_code == 200

    def test_all_report_sections_in_json_export(self, test_app):
        client = test_app["client"]
        db = test_app["db"]
        headers_for = test_app["headers_for"]
        user, ws, asmt = _setup(db, "rpt_secs_")
        _populate_domain(db, asmt.id)
        _populate_findings(db, asmt.id)
        caps = client.get("/api/v1/reports/capabilities", headers=headers_for(user)).json()
        sections = [s["id"] for s in caps.get("sections", [])]
        r = client.post(
            "/api/v1/reports/export",
            json={"assessment_id": str(asmt.id), "format": "json", "sections": sections},
            headers=headers_for(user),
        )
        assert r.status_code == 200
