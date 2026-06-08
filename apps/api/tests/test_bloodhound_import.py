from __future__ import annotations


from adbygod_api.routes import import_data as import_routes
from adbygod_api.models import AssessmentStatus


def _collector_payload() -> dict:
    return {
        "schema_version": "1.0",
        "tool": "BloodHound",
        "collection_mode": "IMPORT",
        "domain": "corp.local",
        "dc_ip": None,
        "collected_at": "2026-04-12T00:00:00Z",
        "collector_version": "test",
        "modules_run": ["BloodHound Import"],
        "entities": [],
        "edges": [],
        "evidence": [{"id": "bh-users-0", "source_type": "bloodhound", "collection_method": "sharphound/users", "origin": "IMPORTED", "raw_data": {"type": "users", "count": 1}, "confidence": 1.0}],
        "findings": [],
        "cert_templates": [],
        "metadata": {},
    }


def test_zip_import_success(test_app, monkeypatch):
    db = test_app["db"]
    assessment = db.run(db.create_assessment("Import", "corp.local", workspace_id=None))
    calls: list[str] = []

    class FakeParser:
        def parse_zip(self, data: bytes):
            calls.append(f"zip:{data.decode()}")
            return _collector_payload()

        def parse_json(self, data: bytes):
            raise AssertionError("json parser should not be used for zip input")

    async def fake_process_ingest(assessment_id, payload, **_kwargs):
        return True

    monkeypatch.setattr(import_routes, "BloodHoundParser", FakeParser)
    monkeypatch.setattr(import_routes, "_process_ingest", fake_process_ingest)

    db.run(import_routes._run_import("job-zip", assessment.id, b"zip-data", "sample.zip"))
    assert calls == ["zip:zip-data"]


def test_json_import_success(test_app, monkeypatch):
    db = test_app["db"]
    assessment = db.run(db.create_assessment("Import", "corp.local", workspace_id=None))
    calls: list[str] = []

    class FakeParser:
        def parse_zip(self, data: bytes):
            raise AssertionError("zip parser should not be used for json input")

        def parse_json(self, data: bytes):
            calls.append(f"json:{data.decode()}")
            return _collector_payload()

    async def fake_process_ingest(assessment_id, payload, **_kwargs):
        return True

    monkeypatch.setattr(import_routes, "BloodHoundParser", FakeParser)
    monkeypatch.setattr(import_routes, "_process_ingest", fake_process_ingest)

    db.run(import_routes._run_import("job-json", assessment.id, b"{}", "sample.json"))
    assert calls == ["json:{}"]


def test_import_parser_failure_marks_assessment_failed(test_app, monkeypatch):
    db = test_app["db"]
    assessment = db.run(db.create_assessment("Import", "corp.local", workspace_id=None))

    class FakeParser:
        def parse_zip(self, data: bytes):
            raise RuntimeError("parser exploded")

        def parse_json(self, data: bytes):
            raise RuntimeError("parser exploded")

    monkeypatch.setattr(import_routes, "BloodHoundParser", FakeParser)

    db.run(import_routes._run_import("job-fail", assessment.id, b"bad", "sample.zip"))
    refreshed = db.run(db.get_assessment(assessment.id))
    assert refreshed.status == AssessmentStatus.FAILED
    assert "parser exploded" in (refreshed.error_message or "")


def test_import_missing_assessment_returns_404(test_app):
    db = test_app["db"]
    client = test_app["client"]
    user = db.run(db.create_user("importer", "importer@example.invalid", is_superadmin=True))

    response = client.post(
        "/api/v1/import/00000000-0000-0000-0000-000000000123/bloodhound",
        headers=test_app["headers_for"](user),
        files={"file": ("sample.zip", b"zip-bytes", "application/zip")},
    )
    assert response.status_code == 404


def test_import_running_assessment_conflict(test_app):
    db = test_app["db"]
    client = test_app["client"]
    user = db.run(db.create_user("importer", "importer@example.invalid", is_superadmin=True))
    assessment = db.run(db.create_assessment("Import", "corp.local", workspace_id=None, status=AssessmentStatus.RUNNING))

    response = client.post(
        f"/api/v1/import/{assessment.id}/bloodhound",
        headers=test_app["headers_for"](user),
        files={"file": ("sample.zip", b"zip-bytes", "application/zip")},
    )
    assert response.status_code == 409


def test_auto_import_detects_renamed_native_collector_zip(test_app, monkeypatch):
    db = test_app["db"]
    client = test_app["client"]
    user = db.run(db.create_user("nativeauto", "nativeauto@example.invalid", is_superadmin=True))
    captured: dict[str, object] = {}

    def fake_parse_collector_zip(_data: bytes):
        return (
            {
                "generator": "AdByGod-Native-Collector",
                "domain": "renamed.local",
                "dc_ip": "10.10.10.10",
                "collected_at": "2026-05-17T00:00:00Z",
                "modules": ["enum"],
            },
            {"enum": {"commands": []}},
        )

    async def fake_run_collector_import(**kwargs):
        captured.update(kwargs)

    monkeypatch.setattr(import_routes, "_parse_collector_zip", fake_parse_collector_zip)
    monkeypatch.setattr(import_routes, "_run_collector_import", fake_run_collector_import)

    response = client.post(
        "/api/v1/import/bloodhound/auto",
        headers=test_app["headers_for"](user),
        files={"file": ("renamed-output.zip", b"native-zip", "application/zip")},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["message"] == "Native collector zip detected and import queued"
    assert captured["manifest"]["domain"] == "renamed.local"
    assert captured["module_data"] == {"enum": {"commands": []}}
