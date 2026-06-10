from __future__ import annotations

from adbygod_api.routes import ingest as ingest_routes


def test_enqueue_helper_exists_and_delegates(monkeypatch):
    captured = {}

    # Patch the Celery task's delay so nothing is actually enqueued.
    import adbygod_api.core.tasks.graph_projection as gp
    monkeypatch.setattr(gp.project_assessment, "delay",
                        lambda aid: captured.setdefault("aid", aid))

    assert hasattr(ingest_routes, "_enqueue_projection_after_ingest")
    ingest_routes._enqueue_projection_after_ingest("abc-123")
    assert captured["aid"] == "abc-123"
