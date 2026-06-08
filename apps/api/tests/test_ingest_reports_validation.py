from __future__ import annotations

import base64

from sqlalchemy import select

from adbygod_api.core.analyzers.scoring_service import RiskScoringService
from adbygod_api.core.graph.graph_service import ADGraphAnalyzer
from adbygod_api.core.analyzers.rule_engine import RuleMatch
from adbygod_api.core.validation.catalog import VALIDATION_MODULE_INDEX
from adbygod_api.schemas import CollectorIngest
from adbygod_api.models import DataOrigin, EdgeType, EntityType, EvidenceRecord, Finding, FindingEvidence, SeverityLevel
from adbygod_api.routes import ingest as ingest_routes
from adbygod_api.routes import public as public_routes


def _ingest_payload() -> dict:
    return {
        "schema_version": "1.0",
        "tool": "test",
        "collection_mode": "IMPORT",
        "domain": "corp.local",
        "dc_ip": None,
        "collected_at": "2026-04-12T00:00:00Z",
        "collector_version": "test",
        "modules_run": ["Import"],
        "entities": [
            {
                "id": "u1",
                "entity_type": "USER",
                "sam_account_name": "alice",
                "display_name": "Alice",
                "domain": "corp.local",
                "attributes": {},
            }
        ],
        "edges": [],
        "evidence": [
            {"id": "ev-1", "source_type": "ldap", "collection_method": "ldap/users", "raw_data": {"k": "v"}, "confidence": 1.0}
        ],
        "findings": [
            {
                "finding_type": "TEST_FINDING",
                "module": "Kerberos",
                "title": "Collector linked finding",
                "severity": "HIGH",
                "technical_severity": 8.0,
                "reachability": 0.6,
                "confidence": 1.0,
                "affected_count": 1,
                "evidence_refs": ["ev-1", "ev-1", "missing"],
            }
        ],
        "cert_templates": [],
        "metadata": {},
    }


def test_ingest_links_evidence_and_ignores_invalid_duplicates(test_app, monkeypatch):
    db = test_app["db"]
    client = test_app["client"]
    user = db.run(db.create_user("ingest", "ingest@example.invalid", is_superadmin=True))
    assessment = db.run(db.create_assessment("Ingest", "corp.local", workspace_id=None, created_by=user.id))

    monkeypatch.setattr(ingest_routes.rule_engine, "evaluate_all", lambda payload: [])

    response = client.post(
        f"/api/v1/ingest/{assessment.id}",
        headers=test_app["headers_for"](user),
        json=_ingest_payload(),
    )
    assert response.status_code in (200, 202)

    findings_response = client.get(
        "/api/v1/findings",
        headers=test_app["headers_for"](user),
        params={"assessment_id": str(assessment.id)},
    )
    finding_id = findings_response.json()["items"][0]["id"]

    evidence_response = client.get(
        f"/api/v1/findings/{finding_id}/evidence",
        headers=test_app["headers_for"](user),
    )
    assert evidence_response.status_code == 200
    evidence_items = evidence_response.json()
    assert len(evidence_items) == 1
    assert evidence_items[0]["source_type"] == "ldap"
    assert evidence_items[0]["origin"] == DataOrigin.IMPORTED.value
    assert findings_response.json()["items"][0]["origin"] == DataOrigin.IMPORTED.value

    async def _count_links():
        async with test_app["session_maker"]() as session:
            result = await session.execute(select(FindingEvidence))
            return len(result.scalars().all())

    assert db.run(_count_links()) == 1


def test_ingest_rule_engine_findings_are_labeled_inferred(test_app, monkeypatch):
    db = test_app["db"]
    client = test_app["client"]
    user = db.run(db.create_user("infer", "infer@example.invalid", is_superadmin=True))
    assessment = db.run(db.create_assessment("Infer", "corp.local", workspace_id=None, created_by=user.id))

    monkeypatch.setattr(
        ingest_routes.rule_engine,
        "evaluate_all",
        lambda payload: [
            RuleMatch(
                rule_id="rule-hit",
                rule_name="Rule Hit",
                finding_type="RULE_HIT",
                module="Graph",
                title="Rule-derived path",
                description="Derived from rule-engine correlation.",
                severity="HIGH",
                technical_severity=7.5,
                reachability=0.8,
                confidence=0.9,
                affected_count=1,
                affected_objects=["alice"],
                root_cause="graph relationship",
                causal_chain=[],
                remediation="Review derived path.",
                remediation_steps=["Review path"],
                fix_complexity="medium",
                references=[],
                on_crown_jewel_path=False,
                is_tier0_direct=False,
            )
        ],
    )

    response = client.post(
        f"/api/v1/ingest/{assessment.id}",
        headers=test_app["headers_for"](user),
        json=_ingest_payload(),
    )
    assert response.status_code in (200, 202)

    async def _origins():
        async with test_app["session_maker"]() as session:
            result = await session.execute(select(Finding.origin).where(Finding.assessment_id == assessment.id))
            return [item.value if hasattr(item, "value") else str(item) for item in result.scalars().all()]

    assert DataOrigin.IMPORTED.value in db.run(_origins())
    assert DataOrigin.INFERRED.value in db.run(_origins())


def test_rule_engine_findings_link_to_imported_evidence_and_report_quality(test_app):
    db = test_app["db"]
    client = test_app["client"]
    user = db.run(db.create_user("trace", "trace@example.invalid", is_superadmin=True))
    assessment = db.run(db.create_assessment("Traceability", "corp.local", workspace_id=None, created_by=user.id))

    payload = _ingest_payload()
    payload["findings"] = []
    payload["entities"] = [
        {
            "id": "S-1-5-21-1-1000",
            "entity_type": "USER",
            "object_sid": "S-1-5-21-1-1000",
            "sam_account_name": "svc-sql",
            "display_name": "svc-sql",
            "domain": "corp.local",
            "is_enabled": True,
            "is_admin_count": True,
            "attributes": {"uac_dont_require_preauth": True, "has_spn": True, "object_sid": "S-1-5-21-1-1000"},
        },
        {
            "id": "S-1-5-21-1-1001",
            "entity_type": "USER",
            "object_sid": "S-1-5-21-1-1001",
            "sam_account_name": "syncsvc",
            "display_name": "syncsvc",
            "domain": "corp.local",
            "is_enabled": True,
            "attributes": {"object_sid": "S-1-5-21-1-1001"},
        },
        {
            "id": "S-1-5-21-1",
            "entity_type": "DOMAIN",
            "object_sid": "S-1-5-21-1",
            "sam_account_name": "CORP.LOCAL",
            "display_name": "CORP.LOCAL",
            "domain": "corp.local",
            "is_crown_jewel": True,
            "tier": 0,
            "attributes": {"machine_account_quota": 10, "functional_level": "2008"},
        },
    ]
    payload["edges"] = [
        {
            "source_id": "S-1-5-21-1-1001",
            "target_id": "S-1-5-21-1",
            "edge_type": "DCSYNC",
            "risk_weight": 1.0,
            "provenance": "test dcsync ace",
            "attributes": {"ace_right": "DCSync"},
        }
    ]
    payload["evidence"] = [
        {"id": "bh-users-0", "source_type": "bloodhound", "collection_method": "sharphound/users", "origin": "IMPORTED", "raw_data": {"type": "users", "count": 2}, "confidence": 1.0},
        {"id": "bh-domains-1", "source_type": "bloodhound", "collection_method": "sharphound/domains", "origin": "IMPORTED", "raw_data": {"type": "domains", "count": 1}, "confidence": 1.0},
        {"id": "bh-certtemplates-2", "source_type": "bloodhound", "collection_method": "sharphound/certtemplates", "origin": "IMPORTED", "raw_data": {"type": "certtemplates", "count": 1}, "confidence": 1.0},
    ]
    payload["cert_templates"] = [
        {
            "name": "ESC1User",
            "distinguished_name": "CN=ESC1User,CN=Certificate Templates,CN=Public Key Services",
            "ca_name": "CORP-CA",
            "enrollee_supplies_subject": True,
            "ekus": ["1.3.6.1.5.5.7.3.2"],
            "enrollment_rights": ["CORP\\Domain Users"],
            "write_rights": [],
            "esc1_vulnerable": True,
            "attributes": {"object_sid": "template-esc1"},
        }
    ]
    payload["metadata"] = {
        "domain_info": {"machine_account_quota": 10, "functional_level": "2008"},
        "password_policy": {"lockout_threshold": 0, "min_password_length": 8},
        "trusts": [{"partner": "legacy.local", "sid_filtering_enabled": False}],
    }

    assert db.run(ingest_routes._process_ingest(assessment.id, CollectorIngest(**payload))) is True

    async def _link_summary():
        async with test_app["session_maker"]() as session:
            findings = (await session.execute(select(Finding).where(Finding.assessment_id == assessment.id))).scalars().all()
            links = (await session.execute(select(FindingEvidence))).scalars().all()
            return findings, links

    findings, links = db.run(_link_summary())
    assert findings
    assert len(links) >= len(findings)
    assert {link.relation_type for link in links} <= {"supports", "derived_from", "corroborates", "fallback_payload_support"}
    assert any((link.source_ref or {}).get("source_refs") for link in links)

    response = client.post(
        "/api/v1/reports/export",
        headers=test_app["headers_for"](user),
        json={"assessment_id": str(assessment.id), "format": "json", "sections": ["coverage_assurance", "data_quality", "finding_register", "detailed_findings"]},
    )
    assert response.status_code == 200
    payload = response.json()["payload"]
    assert len(payload["coverage_assurance"]["findings_without_linked_evidence"]) == 0
    assert payload["data_quality"]["finding_evidence_linkage_pct"] == 100.0
    assert all(item["evidence_count"] > 0 for item in payload["findings_register"])
    assert all(item["evidence"] for item in payload["finding_details"])


def test_process_ingest_persists_modules_run_for_live_collection(test_app, monkeypatch):
    db = test_app["db"]
    user = db.run(db.create_user("live-modules", "live-modules@example.invalid", is_superadmin=True))
    assessment = db.run(db.create_assessment("Live Modules", "corp.local", workspace_id=None, created_by=user.id))

    monkeypatch.setattr(ingest_routes.rule_engine, "evaluate_all", lambda payload: [])

    payload_dict = _ingest_payload()
    payload_dict["modules_run"] = ["Directory Inventory", "Certificate Services Posture"]
    db.run(ingest_routes._process_ingest(assessment.id, CollectorIngest(**payload_dict)))

    refreshed = db.run(db.get_assessment(assessment.id))
    assert refreshed.modules_run == ["Directory Inventory", "Certificate Services Posture"]


def test_rule_engine_input_preserves_sysvol_evidence():
    payload_dict = _ingest_payload()
    payload_dict["evidence"] = [{
        "id": "sysvol-scan",
        "source_type": "smb",
        "collection_method": "sysvol/gpp",
        "raw_data": {
            "cpassword_files": 1,
            "findings": [{"file_path": "\\\\lab.local\\SYSVOL\\lab.local\\Policies\\{GUID}\\Machine\\Groups.xml"}],
        },
        "confidence": 1.0,
    }]
    payload = CollectorIngest(**payload_dict)

    rule_data = ingest_routes._build_rule_data([], [], [], {}, payload)

    assert rule_data["evidence"][0]["collection_method"] == "sysvol/gpp"
    assert rule_data["evidence"][0]["raw_data"]["cpassword_files"] == 1


def test_report_exports_match_supported_formats_and_use_graph_backed_score(test_app):
    db = test_app["db"]
    client = test_app["client"]
    user = db.run(db.create_user("reporter", "reporter@example.invalid", is_superadmin=True))
    assessment = db.run(db.create_assessment("Report", "corp.local", workspace_id=None, created_by=user.id))
    source = db.run(db.create_entity(assessment.id, entity_type=EntityType.USER, sam_account_name="alice"))
    tier0 = db.run(db.create_entity(assessment.id, entity_type=EntityType.GROUP, sam_account_name="Domain Admins", tier=0, is_crown_jewel=True))
    db.run(db.create_edge(assessment.id, source.id, tier0.id, edge_type=EdgeType.MEMBER_OF, risk_weight=1.0))
    finding = db.run(db.create_finding(assessment.id, title="Tier0 path", severity=SeverityLevel.CRITICAL, composite_score=90.0))

    async def _enrich_finding_metadata():
        async with test_app["session_maker"]() as session:
            stored = await session.get(Finding, finding.id)
            stored.cve_ids = ["CVE-2026-0001"]
            stored.mitre_attack_ids = ["T1003.006"]
            stored.attack_path = [
                {
                    "entity_id": str(source.id),
                    "entity_label": "alice",
                    "entity_type": "USER",
                    "edge_type": "MEMBER_OF",
                },
                {
                    "entity_id": str(tier0.id),
                    "entity_label": "Domain Admins",
                    "entity_type": "GROUP",
                },
            ]
            await session.commit()

    db.run(_enrich_finding_metadata())

    json_response = client.post(
        "/api/v1/reports/export",
        headers=test_app["headers_for"](user),
        json={"assessment_id": str(assessment.id), "format": "json", "sections": ["summary", "top_findings"]},
    )
    csv_response = client.post(
        "/api/v1/reports/export",
        headers=test_app["headers_for"](user),
        json={"assessment_id": str(assessment.id), "format": "csv", "sections": ["summary", "top_findings", "detailed_findings"]},
    )
    html_response = client.post(
        "/api/v1/reports/export",
        headers=test_app["headers_for"](user),
        json={"assessment_id": str(assessment.id), "format": "html", "sections": ["summary", "top_findings", "detailed_findings"]},
    )

    assert json_response.status_code == 200
    assert csv_response.status_code == 200
    assert html_response.status_code == 200
    assert json_response.json()["filename"].endswith(".json")
    assert csv_response.json()["filename"].endswith(".csv")
    assert html_response.json()["filename"].endswith(".html")

    async def _expected_score():
        async with test_app["session_maker"]() as session:
            from adbygod_api.models import Entity, Finding, GraphEdge

            entities = (await session.execute(select(Entity).where(Entity.assessment_id == assessment.id))).scalars().all()
            edges = (await session.execute(select(GraphEdge).where(GraphEdge.assessment_id == assessment.id))).scalars().all()
            findings = (await session.execute(select(Finding).where(Finding.assessment_id == assessment.id))).scalars().all()
            analyzer = ADGraphAnalyzer()
            analyzer.load_from_db(entities, edges)
            scorer = RiskScoringService(analyzer)
            return scorer.calculate_global_score(findings)["score"]

    payload = json_response.json()["payload"]
    assert payload["risk_analysis"]["graph_backed"] is True
    assert payload["assessment"]["exposure_score"] == db.run(_expected_score())
    assert payload["exposure"]["origin_counts"][DataOrigin.INFERRED.value] == 1
    assert payload["top_findings"][0]["origin"] == DataOrigin.INFERRED.value
    assert payload["top_findings"][0]["cve_ids"] == ["CVE-2026-0001"]
    assert payload["top_findings"][0]["mitre_attack_ids"] == ["T1003.006"]
    assert payload["finding_details"][0]["attack_path"][0]["edge_type"] == "MEMBER_OF"
    csv_content = csv_response.json()["content"]
    html_content = html_response.json()["content"]
    assert "mitre_attack_ids" in csv_content.splitlines()[0]
    assert "T1003.006" in csv_content
    assert "MITRE ATT&CK" in html_content
    assert "CVE-2026-0001" in html_content


def test_validation_response_is_clearly_labeled_simulation(test_app):
    db = test_app["db"]
    client = test_app["client"]
    user = db.run(db.create_user("validator", "validator@example.invalid", is_superadmin=True))
    assessment = db.run(db.create_assessment("Validate", "corp.local", workspace_id=None, created_by=user.id))

    response = client.post(
        f"/api/v1/validation/simulate/kerberos/{assessment.id}",
        headers=test_app["headers_for"](user),
        json={"target": "corp.local", "mode": "simulation"},
    )
    assert response.status_code in (200, 202)
    body = response.json()
    assert body["execution_mode"] in ("SIMULATION", "SIMULATION_CONSENSUS")
    assert body["origin"] == DataOrigin.SIMULATED.value
    assert body["simulated"] is True
    assert body["logs"][0]["message"].startswith("[SIMULATION")


def test_graph_export_prioritizes_direct_control_edge_endpoints():
    analyzer = ADGraphAnalyzer()
    entities = [
        {
            "id": "tier0",
            "entity_type": "GROUP",
            "sam_account_name": "Domain Admins",
            "tier": 0,
            "attributes": {},
        },
        {
            "id": "operator",
            "entity_type": "GROUP",
            "sam_account_name": "ADG0D-GenericAll-Testers",
            "tier": 2,
            "attributes": {},
        },
        {
            "id": "target",
            "entity_type": "USER",
            "sam_account_name": "ADG0D_TARGET_SVC1",
            "tier": 3,
            "attributes": {},
        },
        *[
            {
                "id": f"filler-{idx}",
                "entity_type": "USER",
                "sam_account_name": f"FILLER_{idx:03d}",
                "tier": 2,
                "attributes": {},
            }
            for idx in range(20)
        ],
    ]
    edges = [
        {
            "source_id": "operator",
            "target_id": "target",
            "edge_type": "GENERIC_ALL",
            "risk_weight": 1.0,
            "provenance": "GenericAll (LDAP ACL, direct)",
        }
    ]

    analyzer.load_from_dicts(entities, edges)
    graph_data = analyzer.export_for_frontend(max_nodes=3)

    labels = {node["label"] for node in graph_data["nodes"]}
    assert "Domain Admins" in labels
    assert "ADG0D-GenericAll-Testers" in labels
    assert "ADG0D_TARGET_SVC1" in labels
    assert graph_data["edges"][0]["edge_type"] == "GENERIC_ALL"


def test_validation_modules_endpoint_matches_supported_simulation_ids(test_app):
    db = test_app["db"]
    client = test_app["client"]
    user = db.run(db.create_user("catalog", "catalog@example.invalid", is_superadmin=True))
    assessment = db.run(db.create_assessment("Catalog", "corp.local", workspace_id=None, created_by=user.id))

    modules_response = client.get(
        "/api/v1/validation/modules",
        headers=test_app["headers_for"](user),
    )
    assert modules_response.status_code == 200
    module_ids = {module["id"] for module in modules_response.json()}
    assert module_ids == set(VALIDATION_MODULE_INDEX)

    invalid_response = client.post(
        f"/api/v1/validation/simulate/not-real/{assessment.id}",
        headers=test_app["headers_for"](user),
        json={"target": "corp.local", "mode": "simulation"},
    )
    assert invalid_response.status_code == 400


def _seed_public_summary_fixture(test_app):
    db = test_app["db"]
    user = db.run(db.create_user("public-summary", "public-summary@example.invalid", is_superadmin=True))
    assessment = db.run(db.create_assessment("Public AD", "lab.local", workspace_id=None, created_by=user.id, exposure_score=89.3))
    tier0 = db.run(db.create_entity(assessment.id, entity_type=EntityType.DOMAIN, sam_account_name="lab.local", tier=0, is_crown_jewel=True))
    operator = db.run(db.create_entity(assessment.id, entity_type=EntityType.USER, sam_account_name="operator"))
    db.run(db.create_edge(assessment.id, operator.id, tier0.id, edge_type=EdgeType.GENERIC_ALL, risk_weight=1.0))
    db.run(db.create_finding(
        assessment.id,
        title="1 admin-level account is Kerberoastable",
        module="Kerberos",
        severity=SeverityLevel.CRITICAL,
        composite_score=96.0,
    ))


def test_public_assessment_summary_is_disabled_by_default(test_app):
    _seed_public_summary_fixture(test_app)
    response = test_app["client"].get("/api/v1/public/assessment-summary")

    assert response.status_code in (200, 202)
    body = response.json()
    assert body["has_data"] is False
    assert body["assessment_id"] is None
    assert body["name"] is None
    assert body["domain"] is None
    assert body["coverage"]["kerberos"] == 0
    assert body["coverage"]["graph"] == 0


def test_public_assessment_summary_can_be_explicitly_enabled(test_app, monkeypatch):
    _seed_public_summary_fixture(test_app)
    monkeypatch.setattr(public_routes.settings, "ENABLE_PUBLIC_ASSESSMENT_SUMMARY", True)

    response = test_app["client"].get("/api/v1/public/assessment-summary")

    assert response.status_code in (200, 202)
    body = response.json()
    assert body["has_data"] is True
    assert body["name"] == "Public AD"
    assert body["domain"] == "lab.local"
    assert body["exposure_score"] == 89.3
    assert body["total_findings"] == 1
    assert body["critical_findings"] == 1
    assert body["total_entities"] == 2
    assert body["total_edges"] == 1
    assert body["tier0_assets"] == 1
    assert body["crown_jewels"] == 1
    assert body["analysis_tracks"] == 1
    assert body["zero_day_refs"] == 0
    assert body["coverage"]["kerberos"] == 100
    assert body["coverage"]["graph"] == 100


def test_pdf_report_export_and_direct_file_download_are_real_pdf_and_redact_evidence(test_app):
    db = test_app["db"]
    client = test_app["client"]
    user = db.run(db.create_user("pdf-reporter", "pdf-reporter@example.invalid", is_superadmin=True))
    assessment = db.run(db.create_assessment("PDF Report", "corp.local", workspace_id=None, created_by=user.id))
    finding = db.run(db.create_finding(assessment.id, title="Sensitive evidence should be redacted", severity=SeverityLevel.CRITICAL, composite_score=96.0))

    async def _seed_evidence():
        async with test_app["session_maker"]() as session:
            evidence = EvidenceRecord(
                assessment_id=assessment.id,
                source_type="ldap",
                collection_method="ldap/users",
                raw_data={"password": "never-print", "hash": "012345", "hash_type": "NTLM", "nested": {"api_token": "abc"}},
                confidence=1.0,
                origin=DataOrigin.COLLECTED,
            )
            session.add(evidence)
            await session.flush()
            session.add(FindingEvidence(finding_id=finding.id, evidence_id=evidence.id, relevance="primary proof"))
            await session.commit()

    db.run(_seed_evidence())

    request = {
        "assessment_id": str(assessment.id),
        "format": "pdf",
        "sections": ["exec_summary", "finding_register", "detailed_findings", "evidence_appendix"],
    }
    wrapped = client.post("/api/v1/reports/export", headers=test_app["headers_for"](user), json=request)
    assert wrapped.status_code == 200
    body = wrapped.json()
    assert body["filename"].endswith(".pdf")
    assert body["mime_type"] == "application/pdf"
    assert body["content_encoding"] == "base64"
    raw_pdf = base64.b64decode(body["content"])
    assert raw_pdf.startswith(b"%PDF")
    assert body["byte_length"] == len(raw_pdf)

    record = body["payload"]["evidence_appendix"]["records"][0]["raw_data_redacted"]
    assert record["password"] == "[REDACTED:SENSITIVE]"
    assert record["hash"] == "[REDACTED:SENSITIVE]"
    assert record["hash_type"] == "NTLM"
    assert record["nested"]["api_token"] == "[REDACTED:SENSITIVE]"

    direct = client.post("/api/v1/reports/export/file", headers=test_app["headers_for"](user), json=request)
    assert direct.status_code == 200
    assert direct.headers["content-type"].startswith("application/pdf")
    assert "attachment;" in direct.headers["content-disposition"]
    assert direct.content.startswith(b"%PDF")


def test_report_assurance_reconciles_every_finding_and_surfaces_quality_gaps(test_app):
    db = test_app["db"]
    client = test_app["client"]
    user = db.run(db.create_user("assurance-reporter", "assurance-reporter@example.invalid", is_superadmin=True))
    assessment = db.run(db.create_assessment("Assurance Report", "corp.local", workspace_id=None, created_by=user.id))
    adcs_finding = db.run(db.create_finding(
        assessment.id,
        title="ESC1 certificate template permits arbitrary subject",
        module="ADCS",
        severity=SeverityLevel.CRITICAL,
        composite_score=97.0,
    ))
    db.run(db.create_finding(
        assessment.id,
        title="DCSync replication rights granted to unexpected principal",
        module="ACL",
        severity=SeverityLevel.HIGH,
        composite_score=84.0,
    ))

    async def _seed_evidence():
        async with test_app["session_maker"]() as session:
            evidence = EvidenceRecord(
                assessment_id=assessment.id,
                source_type="ldap",
                collection_method="acl/domain-root",
                raw_data={"proof": "linked"},
                confidence=1.0,
                origin=DataOrigin.COLLECTED,
                is_corroborated=True,
            )
            session.add(evidence)
            await session.flush()
            session.add(FindingEvidence(finding_id=adcs_finding.id, evidence_id=evidence.id, relevance="direct proof"))
            await session.commit()

    db.run(_seed_evidence())

    response = client.post(
        "/api/v1/reports/export",
        headers=test_app["headers_for"](user),
        json={
            "assessment_id": str(assessment.id),
            "format": "json",
            "sections": [
                "exec_summary",
                "coverage_assurance",
                "risk_themes",
                "priority_action_board",
                "data_quality",
                "finding_register",
                "detailed_findings",
            ],
        },
    )
    assert response.status_code in (200, 202)
    payload = response.json()["payload"]
    coverage = payload["coverage_assurance"]
    assert coverage["integrity_status"] == "PASS"
    assert coverage["all_findings_present_in_payload"] is True
    assert coverage["finding_count_reconciliation"]["stored_findings"] == 2
    assert coverage["finding_count_reconciliation"]["finding_register_rows"] == 2
    assert coverage["finding_count_reconciliation"]["detailed_finding_rows"] == 2
    assert coverage["finding_count_reconciliation"]["unreported_payload_rows"] == 0
    assert len(coverage["findings_without_linked_evidence"]) == 1

    themes = payload["risk_theme_summary"]
    theme_names = {theme["theme"] for theme in themes["themes"]}
    assert "AD CS / Certificate Abuse" in theme_names
    assert "Replication / DCSync" in theme_names
    assert payload["priority_action_board"]["total_actions"] == 2
    assert payload["priority_action_board"]["immediate_actions"] >= 1
    assert payload["data_quality"]["readiness_grade"] in {"A", "B", "C", "D"}
    assert all(item["risk_themes"] for item in payload["findings_register"])


def test_report_html_csv_and_capabilities_expose_assurance_upgrade(test_app):
    db = test_app["db"]
    client = test_app["client"]
    user = db.run(db.create_user("report-polish", "report-polish@example.invalid", is_superadmin=True))
    assessment = db.run(db.create_assessment("Polished Report", "corp.local", workspace_id=None, created_by=user.id))
    db.run(db.create_finding(
        assessment.id,
        title="Kerberoastable privileged service account",
        module="Kerberos",
        severity=SeverityLevel.HIGH,
        composite_score=88.0,
    ))
    request = {
        "assessment_id": str(assessment.id),
        "sections": ["coverage_assurance", "risk_themes", "priority_action_board", "data_quality", "finding_register"],
    }
    html_response = client.post(
        "/api/v1/reports/export",
        headers=test_app["headers_for"](user),
        json={**request, "format": "html"},
    )
    csv_response = client.post(
        "/api/v1/reports/export",
        headers=test_app["headers_for"](user),
        json={**request, "format": "csv"},
    )
    capabilities = client.get("/api/v1/reports/capabilities", headers=test_app["headers_for"](user))

    assert html_response.status_code == 200
    html = html_response.json()["content"]
    assert "Finding Coverage Assurance" in html
    assert "Risk Themes" in html
    assert "Priority Action Board" in html
    assert "Data Quality and Confidence" in html

    assert csv_response.status_code == 200
    csv_header = csv_response.json()["content"].splitlines()[0]
    assert "risk_themes" in csv_header

    assert capabilities.status_code == 200
    body = capabilities.json()
    section_ids = {section["id"] for section in body["sections"]}
    assert {"coverage_assurance", "risk_themes", "priority_action_board", "data_quality"}.issubset(section_ids)
    assert body["assurance"]["finding_payload_reconciliation"] is True


# ── Phase 2: Evidence Traceability Deep Tests ─────────────────────────────────

def _full_traceability_payload() -> dict:
    """Rich ingest payload covering all evidence families for traceability tests."""
    return {
        "schema_version": "1.0",
        "tool": "test",
        "collection_mode": "IMPORT",
        "domain": "corp.local",
        "dc_ip": None,
        "collected_at": "2026-05-01T00:00:00Z",
        "collector_version": "test",
        "modules_run": ["BloodHound Import"],
        "entities": [
            {
                "id": "S-1-5-21-1",
                "entity_type": "DOMAIN",
                "object_sid": "S-1-5-21-1",
                "sam_account_name": "CORP.LOCAL",
                "display_name": "CORP.LOCAL",
                "domain": "corp.local",
                "is_crown_jewel": True,
                "tier": 0,
                "attributes": {},
            },
            {
                "id": "S-1-5-21-1-500",
                "entity_type": "USER",
                "object_sid": "S-1-5-21-1-500",
                "sam_account_name": "Administrator",
                "display_name": "Administrator",
                "domain": "corp.local",
                "is_enabled": True,
                "is_admin_count": True,
                "attributes": {"has_spn": True, "pwd_never_expires": True},
            },
            {
                "id": "S-1-5-21-1-1102",
                "entity_type": "USER",
                "object_sid": "S-1-5-21-1-1102",
                "sam_account_name": "syncsvc",
                "display_name": "syncsvc",
                "domain": "corp.local",
                "is_enabled": True,
                "is_admin_count": False,
                "attributes": {"object_sid": "S-1-5-21-1-1102"},
            },
            {
                "id": "S-1-5-21-1-1200",
                "entity_type": "USER",
                "object_sid": "S-1-5-21-1-1200",
                "sam_account_name": "svc_kerberoast",
                "display_name": "svc_kerberoast",
                "domain": "corp.local",
                "is_enabled": True,
                "is_admin_count": False,
                "attributes": {"has_spn": True, "uac_dont_require_preauth": True},
            },
            {
                "id": "S-1-5-21-1-1201",
                "entity_type": "USER",
                "object_sid": "S-1-5-21-1-1201",
                "sam_account_name": "svc2",
                "display_name": "svc2",
                "domain": "corp.local",
                "is_enabled": True,
                "attributes": {"has_spn": True},
            },
            {
                "id": "S-1-5-21-1-1202",
                "entity_type": "USER",
                "object_sid": "S-1-5-21-1-1202",
                "sam_account_name": "svc3",
                "display_name": "svc3",
                "domain": "corp.local",
                "is_enabled": True,
                "attributes": {"has_spn": True},
            },
            {
                "id": "S-1-5-21-1-1100",
                "entity_type": "USER",
                "object_sid": "S-1-5-21-1-1100",
                "sam_account_name": "gpo_delegate",
                "display_name": "gpo_delegate",
                "domain": "corp.local",
                "is_enabled": True,
                "is_admin_count": False,
                "attributes": {},
            },
            {
                "id": "gpo-test-1",
                "entity_type": "GPO",
                "sam_account_name": "Default Domain Policy",
                "display_name": "Default Domain Policy",
                "domain": "corp.local",
                "attributes": {},
            },
        ],
        "edges": [
            {
                "source_id": "S-1-5-21-1-1102",
                "target_id": "S-1-5-21-1",
                "edge_type": "DCSYNC",
                "risk_weight": 1.0,
                "provenance": "sharphound/domains",
                "attributes": {"ace_right": "DCSync"},
            },
            {
                "source_id": "S-1-5-21-1-1100",
                "target_id": "gpo-test-1",
                "edge_type": "GENERIC_ALL",
                "risk_weight": 0.9,
                "provenance": "sharphound/gpos",
                "attributes": {"ace_right": "GenericAll"},
            },
        ],
        "evidence": [
            {
                "id": "ev-users",
                "source_type": "bloodhound",
                "collection_method": "sharphound/users",
                "origin": "IMPORTED",
                "raw_data": {"type": "users", "count": 5},
                "confidence": 1.0,
            },
            {
                "id": "ev-domains",
                "source_type": "bloodhound",
                "collection_method": "sharphound/domains",
                "origin": "IMPORTED",
                "raw_data": {"type": "domains", "count": 1},
                "confidence": 1.0,
            },
            {
                "id": "ev-gpos",
                "source_type": "bloodhound",
                "collection_method": "sharphound/gpos",
                "origin": "IMPORTED",
                "raw_data": {"type": "gpos", "count": 1},
                "confidence": 1.0,
            },
            {
                "id": "ev-certtemplates",
                "source_type": "bloodhound",
                "collection_method": "sharphound/certtemplates",
                "origin": "IMPORTED",
                "raw_data": {"type": "certtemplates", "count": 1},
                "confidence": 1.0,
            },
        ],
        "findings": [],
        "cert_templates": [
            {
                "name": "ESC1-UserCert",
                "distinguished_name": "CN=ESC1-UserCert,CN=Certificate Templates",
                "ca_name": "CORP-CA-01",
                "enrollee_supplies_subject": True,
                "ekus": ["1.3.6.1.5.5.7.3.2"],
                "enrollment_rights": ["CORP\\Domain Users"],
                "write_rights": [],
                "esc1_vulnerable": True,
                "esc2_vulnerable": False,
                "esc3_vulnerable": False,
                "esc4_vulnerable": False,
                "attributes": {
                    "ct_flag_enrollee_supplies_subject": True,
                    "published_by": ["CORP-CA-01"],
                },
            }
        ],
        "metadata": {
            "domain_info": {
                "machine_account_quota": 10,
                "domain_functional_level": 3,
                "krbtgt_password_age_days": 400,
            },
            "password_policy": {
                "lockout_threshold": 0,
                "min_password_length": 7,
                "pwd_history_length": 5,
                "complexity_enabled": False,
            },
            "trusts": [
                {
                    "partner": "legacy.local",
                    "target_domain": "legacy.local",
                    "sid_filtering_enabled": False,
                    "direction": "BIDIRECTIONAL",
                    "trust_type": "EXTERNAL",
                }
            ],
            "network_config": {},
        },
    }


def test_evidence_links_created_at_ingest_not_at_report_time(test_app):
    """Evidence links must exist in the DB before any report is generated."""
    db = test_app["db"]
    assessment = db.run(db.create_assessment("EvidenceLinksEarly", "corp.local", workspace_id=None, created_by=None))
    payload = CollectorIngest(**_full_traceability_payload())
    assert db.run(ingest_routes._process_ingest(assessment.id, payload)) is True

    async def _links_before_report():
        async with test_app["session_maker"]() as session:
            links = (await session.execute(
                select(FindingEvidence).join(Finding, FindingEvidence.finding_id == Finding.id)
                .where(Finding.assessment_id == assessment.id)
            )).scalars().all()
            return links

    links = db.run(_links_before_report())
    assert links, "Evidence links must be persisted during ingest, not fabricated at report time"


def test_no_backfill_label_in_fresh_import(test_app):
    """A freshly imported assessment must not show 'Backfilled report traceability' text."""
    db = test_app["db"]
    assessment = db.run(db.create_assessment("NoBackfill", "corp.local", workspace_id=None, created_by=None))
    payload = CollectorIngest(**_full_traceability_payload())
    assert db.run(ingest_routes._process_ingest(assessment.id, payload)) is True

    async def _link_relevances():
        async with test_app["session_maker"]() as session:
            links = (await session.execute(
                select(FindingEvidence).join(Finding, FindingEvidence.finding_id == Finding.id)
                .where(Finding.assessment_id == assessment.id)
            )).scalars().all()
            return [link.relevance or "" for link in links]

    relevances = db.run(_link_relevances())
    assert relevances, "Expect evidence links to exist"
    for text in relevances:
        assert "Backfilled report traceability" not in text, (
            f"Fresh import produced backfill text: {text!r}"
        )


def test_edge_level_evidence_for_dcsync_finding(test_app):
    """DCSync finding must produce edge_level evidence with source/target refs."""
    db = test_app["db"]
    assessment = db.run(db.create_assessment("DCSyncEdge", "corp.local", workspace_id=None, created_by=None))
    payload = CollectorIngest(**_full_traceability_payload())
    assert db.run(ingest_routes._process_ingest(assessment.id, payload)) is True

    async def _dcsync_links():
        async with test_app["session_maker"]() as session:
            findings = (await session.execute(
                select(Finding).where(
                    Finding.assessment_id == assessment.id,
                    Finding.finding_type == "DCSYNC_RIGHTS",
                )
            )).scalars().all()
            if not findings:
                return [], []
            links = (await session.execute(
                select(FindingEvidence).where(
                    FindingEvidence.finding_id.in_([f.id for f in findings])
                )
            )).scalars().all()
            return findings, links

    findings, links = db.run(_dcsync_links())
    assert findings, "DCSYNC_RIGHTS finding must be produced"
    assert links, "DCSYNC_RIGHTS finding must have evidence links"

    edge_links = [
        link for link in links
        if (link.source_ref or {}).get("source_refs")
        and any(r.get("ref_type") == "edge" for r in (link.source_ref or {}).get("source_refs", []))
    ]
    assert edge_links, "DCSYNC_RIGHTS must have at least one edge-level source ref"

    for link in edge_links:
        assert link.evidence_strength == "edge_level", (
            f"DCSYNC edge link must be edge_level, got {link.evidence_strength!r}"
        )
        assert link.relation_type == "derived_from"
        assert link.relevance and "DCSYNC" in link.relevance, (
            f"DCSYNC relevance must mention edge type, got: {link.relevance!r}"
        )


def test_cert_template_source_refs_for_esc1_finding(test_app):
    """ESC1 finding must link to specific cert template with template name/CA/EKU."""
    db = test_app["db"]
    assessment = db.run(db.create_assessment("ESC1Refs", "corp.local", workspace_id=None, created_by=None))
    payload = CollectorIngest(**_full_traceability_payload())
    assert db.run(ingest_routes._process_ingest(assessment.id, payload)) is True

    async def _esc1_links():
        async with test_app["session_maker"]() as session:
            findings = (await session.execute(
                select(Finding).where(
                    Finding.assessment_id == assessment.id,
                    Finding.finding_type == "ESC1",
                )
            )).scalars().all()
            if not findings:
                return [], []
            links = (await session.execute(
                select(FindingEvidence).where(
                    FindingEvidence.finding_id.in_([f.id for f in findings])
                )
            )).scalars().all()
            return findings, links

    findings, links = db.run(_esc1_links())
    assert findings, "ESC1 finding must be produced"
    assert links, "ESC1 finding must have evidence links"

    template_links = [
        link for link in links
        if any(
            r.get("ref_type") == "cert_template"
            for r in (link.source_ref or {}).get("source_refs", [])
        )
    ]
    assert template_links, "ESC1 must have at least one cert_template source ref"

    for link in template_links:
        assert link.evidence_strength == "object_level"
        ref = next(
            r for r in link.source_ref["source_refs"] if r.get("ref_type") == "cert_template"
        )
        assert ref.get("template_name") == "ESC1-UserCert", f"Expected template name, got {ref!r}"
        assert ref.get("ca_name"), "ESC1 cert template ref must include CA name"
        assert link.relevance and "ESC1-UserCert" in link.relevance, (
            f"ESC1 relevance must mention template name: {link.relevance!r}"
        )


def test_policy_source_refs_for_lockout_and_weak_password(test_app):
    """Password policy findings must carry exact attribute values in source_refs."""
    db = test_app["db"]
    assessment = db.run(db.create_assessment("PolicyRefs", "corp.local", workspace_id=None, created_by=None))
    payload = CollectorIngest(**_full_traceability_payload())
    assert db.run(ingest_routes._process_ingest(assessment.id, payload)) is True

    async def _policy_links():
        async with test_app["session_maker"]() as session:
            findings = (await session.execute(
                select(Finding).where(
                    Finding.assessment_id == assessment.id,
                    Finding.finding_type.in_(["NO_LOCKOUT_POLICY", "WEAK_PASSWORD_LENGTH"]),
                )
            )).scalars().all()
            if not findings:
                return [], []
            links = (await session.execute(
                select(FindingEvidence).where(
                    FindingEvidence.finding_id.in_([f.id for f in findings])
                )
            )).scalars().all()
            return findings, links

    findings, links = db.run(_policy_links())
    assert findings, "Password policy findings must be produced"
    assert links

    policy_links = [
        link for link in links
        if any(r.get("ref_type") == "policy" for r in (link.source_ref or {}).get("source_refs", []))
    ]
    assert policy_links, "Policy findings must have policy source refs"

    lockout_links = [
        link for link in policy_links
        if any(
            r.get("lockout_threshold") is not None
            for r in (link.source_ref or {}).get("source_refs", [])
        )
    ]
    assert lockout_links, "NO_LOCKOUT_POLICY must record lockout_threshold=0 in source_refs"
    for link in lockout_links:
        ref = next(r for r in link.source_ref["source_refs"] if r.get("ref_type") == "policy")
        assert ref.get("lockout_threshold") == 0
        assert link.relevance and "lockoutThreshold=0" in link.relevance


def test_trust_source_refs_for_sid_filtering_finding(test_app):
    """Trust finding must carry partner name and sid_filtering=False in source_refs."""
    db = test_app["db"]
    assessment = db.run(db.create_assessment("TrustRefs", "corp.local", workspace_id=None, created_by=None))
    payload = CollectorIngest(**_full_traceability_payload())
    assert db.run(ingest_routes._process_ingest(assessment.id, payload)) is True

    async def _trust_links():
        async with test_app["session_maker"]() as session:
            findings = (await session.execute(
                select(Finding).where(
                    Finding.assessment_id == assessment.id,
                    Finding.finding_type == "TRUST_NO_SID_FILTERING",
                )
            )).scalars().all()
            if not findings:
                return [], []
            links = (await session.execute(
                select(FindingEvidence).where(
                    FindingEvidence.finding_id.in_([f.id for f in findings])
                )
            )).scalars().all()
            return findings, links

    findings, links = db.run(_trust_links())
    assert findings, "TRUST_NO_SID_FILTERING finding must be produced"
    assert links

    trust_refs_present = any(
        r.get("ref_type") == "trust"
        for link in links
        for r in (link.source_ref or {}).get("source_refs", [])
    )
    assert trust_refs_present, "Trust finding must have trust source refs"

    for link in links:
        tr = next(
            (r for r in (link.source_ref or {}).get("source_refs", []) if r.get("ref_type") == "trust"),
            None,
        )
        if tr:
            assert tr.get("sid_filtering") is False, f"Trust ref must record sid_filtering=False: {tr!r}"
            assert link.relevance and "legacy.local" in link.relevance, (
                f"Trust relevance must mention partner: {link.relevance!r}"
            )


def test_all_findings_have_evidence_links_and_no_missing_evidence_in_report(test_app):
    """Full traceability: 100% evidence linked, no missing evidence, no backfill text."""
    db = test_app["db"]
    client = test_app["client"]
    user = db.run(db.create_user("full-trace", "full-trace@example.invalid", is_superadmin=True))
    assessment = db.run(db.create_assessment("FullTrace", "corp.local", workspace_id=None, created_by=user.id))
    payload = CollectorIngest(**_full_traceability_payload())
    assert db.run(ingest_routes._process_ingest(assessment.id, payload)) is True

    response = client.post(
        "/api/v1/reports/export",
        headers=test_app["headers_for"](user),
        json={
            "assessment_id": str(assessment.id),
            "format": "json",
            "sections": ["coverage_assurance", "data_quality", "finding_register", "detailed_findings"],
        },
    )
    assert response.status_code == 200
    rpt = response.json()["payload"]

    assert rpt["coverage_assurance"]["findings_without_linked_evidence"] == [], (
        "All findings must have linked evidence"
    )
    assert rpt["data_quality"]["finding_evidence_linkage_pct"] == 100.0

    for item in rpt["findings_register"]:
        assert item["evidence_count"] > 0, f"Finding {item.get('finding_type')} has no evidence"

    for item in rpt["finding_details"]:
        assert item["evidence"], f"Finding detail {item.get('finding_type')} has empty evidence"
        for ev in item["evidence"]:
            assert "Backfilled report traceability" not in (ev.get("relevance") or ""), (
                f"Fresh import must not use backfill label: {ev.get('relevance')!r}"
            )
            assert ev.get("relation_type") in ("supports", "derived_from", "corroborates", "fallback_payload_support")
            assert ev.get("evidence_strength") in (
                "edge_level", "object_level", "aggregate_level", "payload_level_fallback"
            )


def test_evidence_strength_classified_correctly_per_rule_family(test_app):
    """edge-level rules get edge_level strength; policy/template rules get object_level."""
    db = test_app["db"]
    assessment = db.run(db.create_assessment("Strength", "corp.local", workspace_id=None, created_by=None))
    payload = CollectorIngest(**_full_traceability_payload())
    assert db.run(ingest_routes._process_ingest(assessment.id, payload)) is True

    async def _strength_map():
        async with test_app["session_maker"]() as session:
            rows = (await session.execute(
                select(Finding.finding_type, FindingEvidence.evidence_strength)
                .join(FindingEvidence, FindingEvidence.finding_id == Finding.id)
                .where(Finding.assessment_id == assessment.id)
            )).all()
            return {ft: strength for ft, strength in rows}

    strength_map = db.run(_strength_map())

    if "DCSYNC_RIGHTS" in strength_map:
        assert strength_map["DCSYNC_RIGHTS"] == "edge_level", (
            f"DCSYNC_RIGHTS must be edge_level, got {strength_map['DCSYNC_RIGHTS']!r}"
        )
    if "ESC1" in strength_map:
        assert strength_map["ESC1"] == "object_level", (
            f"ESC1 must be object_level, got {strength_map['ESC1']!r}"
        )
    if "NO_LOCKOUT_POLICY" in strength_map:
        assert strength_map["NO_LOCKOUT_POLICY"] == "object_level", (
            f"NO_LOCKOUT_POLICY must be object_level, got {strength_map['NO_LOCKOUT_POLICY']!r}"
        )
    if "TRUST_NO_SID_FILTERING" in strength_map:
        assert strength_map["TRUST_NO_SID_FILTERING"] == "object_level"


def test_report_does_not_fabricate_evidence_links(test_app):
    """Report generation must only render persisted evidence links, never invent them."""
    db = test_app["db"]
    client = test_app["client"]
    user = db.run(db.create_user("no-fab", "no-fab@example.invalid", is_superadmin=True))
    assessment = db.run(db.create_assessment("NoFabricate", "corp.local", workspace_id=None, created_by=user.id))

    # Ingest with NO findings (rule engine disabled) and NO collector findings
    bare_payload = {
        "schema_version": "1.0",
        "tool": "test",
        "collection_mode": "IMPORT",
        "domain": "corp.local",
        "dc_ip": None,
        "collected_at": "2026-05-01T00:00:00Z",
        "collector_version": "test",
        "modules_run": ["Test"],
        "entities": [],
        "edges": [],
        "evidence": [
            {"id": "bare-ev", "source_type": "ldap", "collection_method": "ldap/users",
             "raw_data": {}, "confidence": 1.0},
        ],
        "findings": [],
        "cert_templates": [],
        "metadata": {},
    }
    from unittest.mock import patch
    with patch.object(ingest_routes.rule_engine, "evaluate_all", return_value=[]):
        assert db.run(ingest_routes._process_ingest(assessment.id, CollectorIngest(**bare_payload))) is True

    async def _db_link_count():
        async with test_app["session_maker"]() as session:
            links = (await session.execute(
                select(FindingEvidence).join(Finding, FindingEvidence.finding_id == Finding.id)
                .where(Finding.assessment_id == assessment.id)
            )).scalars().all()
            return len(links)

    db_links = db.run(_db_link_count())
    assert db_links == 0, "No findings → no evidence links in DB"

    # Report must agree with DB state
    response = client.post(
        "/api/v1/reports/export",
        headers=test_app["headers_for"](user),
        json={
            "assessment_id": str(assessment.id),
            "format": "json",
            "sections": ["coverage_assurance", "data_quality"],
        },
    )
    assert response.status_code == 200
    rpt = response.json()["payload"]
    assert rpt["coverage_assurance"]["linked_evidence_findings"] == 0
    assert rpt["data_quality"]["findings_with_linked_evidence"] == 0


def test_regression_evidence_not_zero_after_bloodhound_import(test_app):
    """Regression: report must not show 'Evidence 0' for all findings after BloodHound import."""
    db = test_app["db"]
    client = test_app["client"]
    user = db.run(db.create_user("regression-ev", "regression-ev@example.invalid", is_superadmin=True))
    assessment = db.run(db.create_assessment("Regression", "corp.local", workspace_id=None, created_by=user.id))
    payload = CollectorIngest(**_full_traceability_payload())
    assert db.run(ingest_routes._process_ingest(assessment.id, payload)) is True

    response = client.post(
        "/api/v1/reports/export",
        headers=test_app["headers_for"](user),
        json={"assessment_id": str(assessment.id), "format": "json", "sections": ["coverage_assurance", "data_quality", "finding_register"]},
    )
    assert response.status_code == 200
    rpt = response.json()["payload"]

    missing_evidence = rpt["coverage_assurance"]["findings_without_linked_evidence"]
    total_findings = rpt["coverage_assurance"]["finding_count_reconciliation"]["stored_findings"]
    assert missing_evidence != total_findings or total_findings == 0, (
        "All findings must not be evidence-less — original regression reproduced"
    )
    assert rpt["data_quality"]["finding_evidence_linkage_pct"] == 100.0, (
        "Evidence linkage must be 100% after import with full evidence payload"
    )
