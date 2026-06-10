"""Tests that production config rejects unsafe settings."""
from __future__ import annotations

import pytest

from adbygod_api.config import Settings


# A fully valid production config that should pass validate_runtime().
# Used as the baseline; individual tests override one field at a time.
BASE_SAFE_PROD_CONFIG = {
    "ENVIRONMENT": "production",
    "SECRET_KEY": "a" * 48,
    "DATABASE_URL": "postgresql+asyncpg://user:pass@localhost/db",
    "ALLOWED_ORIGINS": "https://example.com",
    "AUTH_COOKIE_SECURE": True,
    "DEBUG": False,
    # Neo4j is a hard production dependency (no NetworkX fallback), so a valid
    # production config must set NEO4J_PASSWORD — see Settings.validate_runtime.
    "NEO4J_PASSWORD": "prod-neo4j-secret",
}


class TestProductionConfig:
    def test_dev_config_works(self):
        # A development config is allowed when DEBUG=True and no dangerous
        # feature flags are enabled. We explicitly set ENABLE_COMMAND_EXECUTION
        # and ALLOW_DEV_BOOTSTRAP to False so the .env file's value is
        # overridden (pydantic-settings gives kwargs higher precedence than
        # the env file).
        s = Settings(
            SECRET_KEY="a" * 48,
            DEBUG=True,
            ENVIRONMENT="development",
            ENABLE_COMMAND_EXECUTION=False,
            ALLOW_DEV_BOOTSTRAP=False,
        )
        s.validate_runtime()  # Should not raise

    def test_production_weak_secret_fails(self):
        # A short key should fail even in production when no dangerous feature is
        # toggled — the weak-secret guard fires unconditionally when DEBUG=False.
        with pytest.raises(RuntimeError, match="SECRET_KEY"):
            s = Settings(**{**BASE_SAFE_PROD_CONFIG, "SECRET_KEY": "short"})
            s.validate_runtime()

    def test_production_wildcard_cors_fails(self):
        with pytest.raises(RuntimeError, match="wildcard"):
            s = Settings(**{**BASE_SAFE_PROD_CONFIG, "ALLOWED_ORIGINS": "*"})
            s.validate_runtime()

    def test_production_debug_fails(self):
        with pytest.raises(RuntimeError):
            s = Settings(**{**BASE_SAFE_PROD_CONFIG, "DEBUG": True})
            s.validate_runtime()

    def test_production_sqlite_fails(self):
        with pytest.raises(RuntimeError, match="SQLite"):
            s = Settings(
                **{**BASE_SAFE_PROD_CONFIG, "DATABASE_URL": "sqlite:///./test.db"}
            )
            s.validate_runtime()

    def test_production_insecure_cookie_fails(self):
        with pytest.raises(RuntimeError, match="AUTH_COOKIE_SECURE"):
            s = Settings(**{**BASE_SAFE_PROD_CONFIG, "AUTH_COOKIE_SECURE": False})
            s.validate_runtime()

    def test_production_valid_config_passes(self):
        s = Settings(**BASE_SAFE_PROD_CONFIG)
        s.validate_runtime()  # Should not raise

    def test_command_execution_disabled_by_default(self):
        # Verify the *class-level default* for the dangerous flag is False.
        # We check pydantic model_fields so the test is insulated from any
        # local .env overrides that a developer may have enabled.
        default = Settings.model_fields["ENABLE_COMMAND_EXECUTION"].default
        assert default is False

    def test_tunnel_management_disabled_by_default(self):
        default = Settings.model_fields["ENABLE_TUNNEL_MANAGEMENT"].default
        assert default is False

    def test_chain_builder_disabled_by_default(self):
        default = Settings.model_fields["ENABLE_CHAIN_BUILDER"].default
        assert default is False

    def test_ai_arbitrary_shell_disabled_by_default(self):
        field = Settings.model_fields.get("ENABLE_AI_ARBITRARY_SHELL")
        if field is None:
            # Field doesn't exist on this Settings class — that's also safe.
            return
        assert field.default is False


class TestPaginationLimits:
    """Verify endpoint configuration constants have reasonable caps."""

    def test_max_crack_hashes_cap(self):
        from adbygod_api.routes.loot import _MAX_CRACK_HASHES

        assert _MAX_CRACK_HASHES <= 10000

    def test_max_upload_bytes_cap(self):
        from adbygod_api.routes.import_data import MAX_UPLOAD_BYTES

        assert MAX_UPLOAD_BYTES <= 512 * 1024 * 1024  # 512 MB max
