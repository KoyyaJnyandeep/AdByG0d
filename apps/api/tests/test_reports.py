"""Tests for /api/v1/reports/* endpoints."""
from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from pathlib import Path


from adbygod_api.core.reports.renderers import compact_rows_for_pdf, render_pdf_report


def _setup(db, prefix=""):
    user = db.run(db.create_user(f"{prefix}rpt_user", f"{prefix}rpt@example.com"))
    ws = db.run(db.create_workspace(f"{prefix}rpt_ws"))
    db.run(db.add_workspace_user(ws.id, user.id))
    asmt = db.run(
        db.create_assessment(f"{prefix}rpt_asmt", "rpt.local", workspace_id=ws.id, created_by=user.id)
    )
    return user, asmt


# ── /capabilities ─────────────────────────────────────────────────────────────

def test_capabilities_returns_formats(test_app):
    client = test_app["client"]
    db = test_app["db"]
    headers_for = test_app["headers_for"]
    user, _ = _setup(db, "caps_")
    r = client.get("/api/v1/reports/capabilities", headers=headers_for(user))
    assert r.status_code == 200
    data = r.json()
    format_ids = {f["id"] for f in data["formats"]}
    assert format_ids == {"pdf", "html", "json", "csv"}


def test_capabilities_returns_sections(test_app):
    client = test_app["client"]
    db = test_app["db"]
    headers_for = test_app["headers_for"]
    user, _ = _setup(db, "capsec_")
    r = client.get("/api/v1/reports/capabilities", headers=headers_for(user))
    assert r.status_code == 200
    assert isinstance(r.json()["sections"], list)
    assert len(r.json()["sections"]) > 0


# ── /preview ──────────────────────────────────────────────────────────────────

def test_preview_requires_auth(test_app):
    client = test_app["client"]
    import uuid
    r = client.get(f"/api/v1/reports/preview/{uuid.uuid4()}")
    assert r.status_code == 401


def test_preview_returns_report_structure(test_app):
    client = test_app["client"]
    db = test_app["db"]
    headers_for = test_app["headers_for"]
    user, asmt = _setup(db, "prev_")
    r = client.get(f"/api/v1/reports/preview/{asmt.id}", headers=headers_for(user))
    assert r.status_code == 200
    data = r.json()
    assert "assessment" in data
    assert "report_meta" in data or "sections" in data or "findings" in data


def test_preview_access_control(test_app):
    client = test_app["client"]
    db = test_app["db"]
    headers_for = test_app["headers_for"]
    user, asmt = _setup(db, "prev_acl_")
    outsider = db.run(db.create_user("rpt_outsider", "rpt_out@example.com"))
    r = client.get(f"/api/v1/reports/preview/{asmt.id}", headers=headers_for(outsider))
    assert r.status_code in {403, 404}


# ── /export ───────────────────────────────────────────────────────────────────

def test_export_json_format(test_app):
    client = test_app["client"]
    db = test_app["db"]
    headers_for = test_app["headers_for"]
    user, asmt = _setup(db, "exp_json_")
    r = client.post(
        "/api/v1/reports/export",
        json={"assessment_id": str(asmt.id), "format": "json", "sections": []},
        headers=headers_for(user),
    )
    assert r.status_code == 200
    data = r.json()
    assert data["mime_type"] == "application/json"
    assert "content" in data
    assert "filename" in data
    assert data["filename"].endswith(".json")
    # Content should be valid JSON
    json.loads(data["content"])


def test_export_csv_format(test_app):
    client = test_app["client"]
    db = test_app["db"]
    headers_for = test_app["headers_for"]
    user, asmt = _setup(db, "exp_csv_")
    db.run(db.create_finding(asmt.id, title="CSVFinding"))
    r = client.post(
        "/api/v1/reports/export",
        json={"assessment_id": str(asmt.id), "format": "csv", "sections": []},
        headers=headers_for(user),
    )
    assert r.status_code == 200
    data = r.json()
    assert data["mime_type"] == "text/csv"
    assert data["filename"].endswith(".csv")


def test_export_html_format(test_app):
    client = test_app["client"]
    db = test_app["db"]
    headers_for = test_app["headers_for"]
    user, asmt = _setup(db, "exp_html_")
    r = client.post(
        "/api/v1/reports/export",
        json={"assessment_id": str(asmt.id), "format": "html", "sections": []},
        headers=headers_for(user),
    )
    assert r.status_code == 200
    data = r.json()
    assert data["mime_type"] == "text/html"
    assert data["filename"].endswith(".html")
    assert "<html" in data["content"].lower() or "<!doctype" in data["content"].lower()


def test_export_invalid_format_rejected(test_app):
    client = test_app["client"]
    db = test_app["db"]
    headers_for = test_app["headers_for"]
    user, asmt = _setup(db, "exp_bad_")
    r = client.post(
        "/api/v1/reports/export",
        json={"assessment_id": str(asmt.id), "format": "xlsx", "sections": []},
        headers=headers_for(user),
    )
    assert r.status_code == 422  # Pydantic pattern validation


def test_export_access_control(test_app):
    client = test_app["client"]
    db = test_app["db"]
    headers_for = test_app["headers_for"]
    user, asmt = _setup(db, "exp_acl_")
    outsider = db.run(db.create_user("rpt_exp_outsider", "rpt_exp_out@example.com"))
    r = client.post(
        "/api/v1/reports/export",
        json={"assessment_id": str(asmt.id), "format": "json", "sections": []},
        headers=headers_for(outsider),
    )
    assert r.status_code in {403, 404}


def test_export_response_has_byte_length(test_app):
    client = test_app["client"]
    db = test_app["db"]
    headers_for = test_app["headers_for"]
    user, asmt = _setup(db, "exp_bytes_")
    r = client.post(
        "/api/v1/reports/export",
        json={"assessment_id": str(asmt.id), "format": "json", "sections": []},
        headers=headers_for(user),
    )
    assert r.status_code == 200
    data = r.json()
    assert isinstance(data["byte_length"], int)
    assert data["byte_length"] > 0


def test_export_technique_compatibility_endpoint_accepts_card_payload(test_app):
    client = test_app["client"]
    db = test_app["db"]
    headers_for = test_app["headers_for"]
    user, _ = _setup(db, "exp_tech_")
    r = client.post(
        "/api/v1/reports/export-technique",
        json={
            "technique_id": "T1003.006",
            "title": "DCSync",
            "mitre_id": "T1003.006",
            "risk_level": "HIGH",
            "description": "Replicate directory secrets",
        },
        headers=headers_for(user),
    )
    assert r.status_code == 200
    assert r.json()["status"] == "accepted"
    assert r.json()["technique_id"] == "T1003.006"


def test_pdf_compaction_helper_keeps_small_sections_complete():
    rows = [[f"row-{idx}", idx] for idx in range(5)]
    compacted = compact_rows_for_pdf(
        "unit",
        rows,
        limits={"unit": {"threshold": 10, "max_rows": 3, "label": "unit rows"}},
    )
    assert compacted["rows"] == rows
    assert compacted["displayed_count"] == 5
    assert compacted["omitted_count"] == 0
    assert compacted["is_compacted"] is False
    assert compacted["disclosure"] == ""


def test_pdf_compaction_helper_caps_large_sections_with_disclosure():
    rows = [["low", 1], ["critical", 10], ["medium", 5]]
    compacted = compact_rows_for_pdf(
        "unit",
        rows,
        sort_key=lambda row: -row[1],
        limits={"unit": {"threshold": 2, "max_rows": 2, "label": "unit rows"}},
    )
    assert compacted["rows"] == [["critical", 10], ["medium", 5]]
    assert compacted["displayed_count"] == 2
    assert compacted["total_count"] == 3
    assert compacted["omitted_count"] == 1
    assert compacted["is_compacted"] is True
    assert "Showing 2 of 3 unit rows" in compacted["disclosure"]
    assert "Rows omitted from PDF: 1" in compacted["disclosure"]


def _report_payload(*, pki_count=0, trust_count=0, service_count=0, finding_count=37):
    severities = ["CRITICAL"] * 12 + ["HIGH"] * 17 + ["MEDIUM"] * 8
    findings = [
        {
            "id": f"finding-{idx}",
            "finding_type": "TEST",
            "module": "Kerberos",
            "title": f"Finding {idx}",
            "severity": severities[idx % len(severities)] if idx < len(severities) else "LOW",
            "status": "OPEN",
            "origin": "INFERRED",
            "composite_score": 90 - idx,
            "confidence": 1.0,
            "affected_count": 1,
            "evidence_count": 1,
            "risk_themes": ["Kerberos / Credential Exposure"],
            "first_seen": "2026-05-19T00:00:00",
            "last_seen": "2026-05-19T00:00:00",
            "created_at": "2026-05-19T00:00:00",
            "updated_at": "2026-05-19T00:00:00",
        }
        for idx in range(finding_count)
    ]
    details = [
        {
            **finding,
            "description": "Rule-derived finding with linked evidence.",
            "root_cause": "Assessment telemetry proved the condition.",
            "affected_objects": [f"object-{finding['id']}"],
            "remediation": "Apply the recommended hardening action.",
            "remediation_steps": ["Review", "Fix", "Verify"],
            "causal_chain": [],
            "attack_path": [],
            "references": [],
            "cve_ids": [],
            "evidence": [
                {
                    "origin": "IMPORTED",
                    "source_type": "bloodhound",
                    "collection_method": "sharphound/users",
                    "confidence": 1.0,
                    "relevance": "supporting source payload",
                }
            ],
        }
        for finding in findings
    ]
    pki_templates = [
        {
            "name": f"Template-{idx:04d}",
            "ca_name": f"CA-{idx % 10}",
            "esc_flags": ["ESC1"] if idx % 2 == 0 else [],
            "vulnerable": idx % 2 == 0,
        }
        for idx in range(pki_count)
    ]
    trusts = [
        {
            "source": "corp.local",
            "target": f"trust-{idx:04d}.local",
            "trust_type": "EXTERNAL" if idx % 2 else "FOREST",
            "risk": "CRITICAL" if idx % 5 == 0 else "HIGH",
            "sid_filtering": idx % 3 != 0,
            "selective_auth": idx % 4 != 0,
        }
        for idx in range(trust_count)
    ]
    accounts = [
        {
            "risk": "CRITICAL" if idx % 7 == 0 else ("HIGH" if idx % 3 == 0 else "MEDIUM"),
            "sam_account_name": f"svc-{idx:05d}",
            "entity_type": "SERVICE_ACCOUNT",
            "kerberoastable": idx % 2 == 0,
            "asrep_roastable": idx % 11 == 0,
            "unconstrained_delegation": idx % 13 == 0,
            "password_age_days": 30 + idx,
            "in_privileged_group": idx % 17 == 0,
        }
        for idx in range(service_count)
    ]
    return {
        "report_meta": {
            "generator": "AdByG0d Reporting Engine",
            "generator_version": "test",
            "generated_at": "2026-05-19T00:00:00Z",
            "sections": {"included": [
                "exec_summary", "scope_methodology", "risk_posture", "coverage_assurance",
                "risk_themes", "priority_action_board", "data_quality", "finding_register",
                "detailed_findings", "attack_paths", "graph_posture", "identity_inventory",
                "pki_posture", "trust_posture", "service_accounts", "validation",
                "remediation_plan", "evidence_appendix", "execution_summary",
            ]},
            "provenance_policy": "Provenance preserved.",
            "redaction_policy": "Sensitive values redacted.",
        },
        "assessment": {
            "id": "assessment-1",
            "name": "NIGHTMARE_MAX synthetic",
            "domain": "corp.local",
            "status": "COMPLETED",
            "collection_mode": "IMPORT",
            "exposure_score": 95.0,
            "modules_run": ["BloodHound Import"],
        },
        "risk_analysis": {"rating": "CRITICAL"},
        "exposure": {
            "total_findings": finding_count,
            "severity_counts": {"CRITICAL": 12, "HIGH": 17, "MEDIUM": 8, "LOW": 0, "INFO": 0},
            "origin_counts": {"INFERRED": finding_count},
        },
        "module_breakdown": [{"module": "Kerberos", "total": finding_count}],
        "coverage_assurance": {
            "integrity_status": "PASS",
            "coverage_statement": "All findings present.",
            "finding_count_reconciliation": {
                "stored_findings": finding_count,
                "finding_register_rows": finding_count,
                "detailed_finding_rows": finding_count,
                "unreported_payload_rows": 0,
            },
            "module_coverage": [{"module": "Kerberos", "findings": finding_count, "critical_high": 29, "evidence_linked": finding_count, "remediation_ready": finding_count}],
            "findings_without_linked_evidence": [],
            "findings_without_remediation": [],
            "modules_run_without_findings": [],
        },
        "data_quality": {
            "readiness_grade": "A",
            "readiness_score": 93.5,
            "finding_evidence_linkage_pct": 100.0,
            "average_finding_confidence": 1.0,
            "corroborated_evidence_pct": 0.0,
            "quality_flags": {"missing_evidence": 0, "missing_description": 0, "missing_root_cause": 0, "missing_remediation": 0},
            "scoring_note": "Ready.",
        },
        "risk_theme_summary": {"classification_policy": "Themes.", "themes": [{"theme": "Kerberos / Credential Exposure", "finding_count": finding_count, "critical_high_count": 29, "max_score": 95, "top_findings": findings[:3]}]},
        "priority_action_board": {"planning_note": "Prioritized.", "immediate_actions": 12, "near_term_actions": 17, "planned_actions": 8, "total_actions": finding_count, "items": [{"wave": "Immediate", "priority": idx + 1, "severity": findings[idx]["severity"], "score": findings[idx]["composite_score"], "title": findings[idx]["title"], "estimated_effort": "medium"} for idx in range(finding_count)]},
        "top_findings": findings[:12],
        "findings_register": findings,
        "finding_details": details,
        "attack_paths": {"total_paths": 0, "top_paths": []},
        "graph_posture": {"node_count": service_count + trust_count, "edge_count": 0, "high_risk_edge_count": 0, "average_edge_risk_weight": 0, "edge_type_counts": {}},
        "identity_inventory": {"total_entities": service_count + trust_count, "tier0_entities": 0, "crown_jewels": 0, "admin_count_entities": 0, "entity_counts": {"SERVICE_ACCOUNT": service_count, "TRUST": trust_count}, "tier0_examples": []},
        "pki_posture": {"total_templates": pki_count, "vulnerable_templates": sum(1 for item in pki_templates if item["vulnerable"]), "esc1_count": sum(1 for item in pki_templates if "ESC1" in item["esc_flags"]), "esc2_count": 0, "esc3_count": 0, "esc4_count": 0, "templates": pki_templates},
        "trust_posture": {"total_trusts": trust_count, "sid_filtering_off": sum(1 for item in trusts if not item["sid_filtering"]), "selective_auth_off": sum(1 for item in trusts if not item["selective_auth"]), "forest_trusts": sum(1 for item in trusts if item["trust_type"] == "FOREST"), "critical_risk": sum(1 for item in trusts if item["risk"] == "CRITICAL"), "high_risk": sum(1 for item in trusts if item["risk"] == "HIGH"), "trusts": trusts},
        "service_account_posture": {"total": service_count, "privileged": sum(1 for item in accounts if item["in_privileged_group"]), "kerberoastable": sum(1 for item in accounts if item["kerberoastable"]), "asrep_roastable": sum(1 for item in accounts if item["asrep_roastable"]), "unconstrained_delegation": sum(1 for item in accounts if item["unconstrained_delegation"]), "stale_password": sum(1 for item in accounts if item["password_age_days"] > 180), "by_risk": {"CRITICAL": sum(1 for item in accounts if item["risk"] == "CRITICAL"), "HIGH": sum(1 for item in accounts if item["risk"] == "HIGH"), "MEDIUM": sum(1 for item in accounts if item["risk"] == "MEDIUM"), "LOW": 0}, "accounts": accounts},
        "validation_posture": {"total_runs": 0, "runs": []},
        "remediation_plan": {"actionable_findings": finding_count, "items": [{"priority": idx + 1, "severity": findings[idx]["severity"], "status": "OPEN", "score": findings[idx]["composite_score"], "title": findings[idx]["title"], "estimated_effort": "medium"} for idx in range(finding_count)]},
        "evidence_appendix": {"redaction_policy": "Redacted.", "records": [{"origin": "IMPORTED", "source_type": "bloodhound", "collection_method": "sharphound/users", "confidence": 1.0, "is_corroborated": False, "raw_data_redacted": {"type": "users", "count": service_count}}]},
        "execution_summary": {"redaction_notice": "Omitted.", "status_counts": {}, "loot_item_counts_by_type": {}},
    }


def test_large_pdf_posture_sections_are_bounded():
    payload = _report_payload(pki_count=2000, trust_count=500, service_count=10006)
    pdf = render_pdf_report(payload)
    assert pdf.startswith(b"%PDF")
    if shutil.which("pdfinfo") or shutil.which("pdftotext"):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "nightmare.pdf"
            path.write_bytes(pdf)
            if shutil.which("pdfinfo"):
                info = subprocess.check_output(["pdfinfo", str(path)], text=True)
                pages = int(next(line.split(":", 1)[1].strip() for line in info.splitlines() if line.startswith("Pages:")))
                assert pages <= 120
            if shutil.which("pdftotext"):
                text = subprocess.check_output(["pdftotext", str(path), "-"], text=True)
                assert "Showing 25 of 2,000 certificate templates" in text
                assert "Showing 25 of 500 trust relationships" in text
                assert "Showing 30 of 10,006 service accounts" in text
                assert "Rows omitted from PDF: 9,976" in text


def test_small_pdf_posture_sections_remain_untruncated():
    pki_rows = [[f"Template-{idx}", "CA", "ESC1", "Yes"] for idx in range(5)]
    trust_rows = [["corp.local", f"trust-{idx}.local", "EXTERNAL", "HIGH", "No", "No"] for idx in range(5)]
    service_rows = [["HIGH", f"svc-{idx}", "SERVICE_ACCOUNT", "Yes", "No", "No", 100] for idx in range(5)]
    assert compact_rows_for_pdf("pki_posture", pki_rows)["rows"] == pki_rows
    assert compact_rows_for_pdf("trust_posture", trust_rows)["rows"] == trust_rows
    assert compact_rows_for_pdf("service_accounts", service_rows)["rows"] == service_rows


# ── /export/file ──────────────────────────────────────────────────────────────

def test_export_file_returns_content_disposition(test_app):
    client = test_app["client"]
    db = test_app["db"]
    headers_for = test_app["headers_for"]
    user, asmt = _setup(db, "expf_")
    r = client.post(
        "/api/v1/reports/export/file",
        json={"assessment_id": str(asmt.id), "format": "json", "sections": []},
        headers=headers_for(user),
    )
    assert r.status_code == 200
    assert "content-disposition" in r.headers
    assert "attachment" in r.headers["content-disposition"]
    assert r.headers["content-type"].startswith("application/json")


# ── CSV formula injection tests ────────────────────────────────────────────────


def test_csv_report_sanitizes_formula_characters():
    """CSV cells starting with formula characters must be prefixed with a single quote."""
    from adbygod_api.core.reports.renderers import render_csv_report
    import csv
    import io

    payload = {
        "findings_register": [
            {
                "id": "f1",
                "severity": "High",
                "composite_score": 8.5,
                "status": "open",
                "origin": "automated",
                "risk_themes": ["=HYPERLINK exploit"],
                "module": "+module",
                "finding_type": "-type",
                "title": "=HYPERLINK(\"https://evil.com\",\"click\")",
                "affected_count": 1,
                "confidence": "high",
                "technical_severity": "@severe",
                "reachability_score": 1.0,
                "evidence_count": 1,
                "fix_complexity": "low",
                "estimated_effort": "1h",
                "first_seen": "2026-01-01",
                "last_seen": "2026-01-02",
            }
        ],
        "finding_details": [
            {
                "id": "f1",
                "description": "+description formula",
                "root_cause": "\tcaught by tab prefix",
                "remediation": "safe text",
                "remediation_steps": [],
                "cve_ids": [],
                "mitre_attack_ids": [],
                "references": [],
            }
        ],
    }

    csv_text = render_csv_report(payload)
    reader = csv.DictReader(io.StringIO(csv_text))
    row = next(reader)

    assert row["title"].startswith("'"), f"title not sanitized: {row['title']!r}"
    assert row["technical_severity"].startswith("'"), f"technical_severity not sanitized: {row['technical_severity']!r}"
    assert row["description"].startswith("'"), f"description not sanitized: {row['description']!r}"
    assert row["root_cause"].startswith("'"), f"root_cause not sanitized: {row['root_cause']!r}"


def test_csv_report_safe_text_unchanged():
    """Normal text in CSV cells must not be modified."""
    from adbygod_api.core.reports.renderers import render_csv_report
    import csv
    import io

    payload = {
        "findings_register": [
            {
                "id": "f2",
                "severity": "Low",
                "composite_score": 2.0,
                "status": "open",
                "origin": "manual",
                "risk_themes": [],
                "module": "recon",
                "finding_type": "info",
                "title": "Normal finding title",
                "affected_count": 0,
                "confidence": "low",
                "technical_severity": "low",
                "reachability_score": 0.1,
                "evidence_count": 0,
                "fix_complexity": "none",
                "estimated_effort": "0",
                "first_seen": None,
                "last_seen": None,
            }
        ],
        "finding_details": [],
    }

    csv_text = render_csv_report(payload)
    reader = csv.DictReader(io.StringIO(csv_text))
    row = next(reader)
    assert row["title"] == "Normal finding title"
