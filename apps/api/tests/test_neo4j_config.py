from __future__ import annotations
import sys
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from adbygod_api.config import Settings


def test_neo4j_settings_have_defaults():
    # Assert declared defaults (not a constructed Settings()) so a developer's
    # local .env cannot mask the real default values — matches the pattern in
    # test_config_validation.py.
    fields = Settings.model_fields
    assert fields["NEO4J_URI"].default == "bolt://localhost:7687"
    assert fields["NEO4J_USER"].default == "neo4j"
    assert fields["NEO4J_PASSWORD"].default == ""
    assert fields["NEO4J_DATABASE"].default == "neo4j"
    assert fields["GRAPH_QUERY_TIMEOUT_SECONDS"].default == 30
    assert fields["GRAPH_PROJECT_BATCH_SIZE"].default == 10000


def test_neo4j_settings_env_override(monkeypatch):
    monkeypatch.setenv("NEO4J_URI", "bolt://neo4j:7687")
    monkeypatch.setenv("NEO4J_PASSWORD", "s3cret")
    s = Settings()
    assert s.NEO4J_URI == "bolt://neo4j:7687"
    assert s.NEO4J_PASSWORD == "s3cret"


def test_production_requires_neo4j_password():
    # Neo4j is a hard dependency with no fallback, so production must refuse to
    # start without a password — mirroring the SECRET_KEY guard.
    import pytest

    s = Settings(
        ENVIRONMENT="production",
        SECRET_KEY="x" * 40,
        DEBUG=False,
        DATABASE_URL="postgresql+asyncpg://u:p@db/adbygod",
        AUTH_COOKIE_SECURE=True,
        NEO4J_PASSWORD="",
    )
    with pytest.raises(RuntimeError, match="NEO4J_PASSWORD"):
        s.validate_runtime()
