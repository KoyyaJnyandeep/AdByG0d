from __future__ import annotations

import json
import tempfile
from functools import lru_cache
from pathlib import Path
from typing import Any

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


DEFAULT_SQLITE_PATH = (Path(__file__).resolve().parents[2] / "adbygod.db").as_posix()
DEFAULT_JOB_WORKSPACE = str(Path(tempfile.gettempdir()) / "adbygod_jobs")
WEAK_DEFAULT_ADMIN_PASSWORDS = {"password", "admin", "changeme", "change-me", "default", "letmein", "123456"}


class Settings(BaseSettings):
    # App
    APP_NAME: str = "AdByG0d Platform"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = False
    SECRET_KEY: str = ""
    ENVIRONMENT: str = "development"
    LOG_LEVEL: str = "INFO"
    SQL_ECHO: bool = False
    AUTO_CREATE_TABLES: bool = True

    # Database
    # Default to a fixed app-local SQLite file so runtime cwd does not silently
    # change which database the API and bootstrap scripts use.
    DATABASE_URL: str = f"sqlite+aiosqlite:///{DEFAULT_SQLITE_PATH}"

    # Redis
    REDIS_URL: str = "redis://localhost:6379/0"

    # Graph engine (Neo4j) — required in all environments, no NetworkX fallback
    NEO4J_URI: str = "bolt://localhost:7687"
    NEO4J_USER: str = "neo4j"
    NEO4J_PASSWORD: str = ""
    NEO4J_DATABASE: str = "neo4j"
    GRAPH_QUERY_TIMEOUT_SECONDS: int = 30
    GRAPH_PROJECT_BATCH_SIZE: int = 10000

    # Celery — broker and result backend
    # Defaults to a separate Redis DB so job results don't collide with pub/sub.
    CELERY_BROKER_URL: str = "redis://localhost:6379/1"
    CELERY_RESULT_BACKEND: str = "redis://localhost:6379/1"

    # Per-job subprocess workspace (platform-safe default via tempfile.gettempdir())
    JOB_WORKSPACE_BASE: str = DEFAULT_JOB_WORKSPACE
    # Set true in debug environments to keep workspaces on failure for inspection.
    JOB_WORKSPACE_RETAIN_ON_FAILURE: bool = False

    # Auth
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    STREAM_TOKEN_EXPIRE_MINUTES: int = 5
    ALGORITHM: str = "HS256"
    AUTH_COOKIE_NAME: str = "adbygod_session"
    AUTH_COOKIE_SECURE: bool = False
    AUTH_COOKIE_SAMESITE: str = "lax"
    STRICT_COOKIE_ORIGIN_CHECK: bool = True
    ALLOW_DEV_BOOTSTRAP: bool = False
    DEFAULT_ADMIN_USERNAME: str = ""
    DEFAULT_ADMIN_PASSWORD: str = ""
    DEFAULT_ADMIN_EMAIL: str = ""
    DEFAULT_ADMIN_FULL_NAME: str = ""
    LOGIN_RATE_LIMIT_ATTEMPTS: int = 5
    LOGIN_RATE_LIMIT_WINDOW_SECONDS: int = 300

    # CORS
    ALLOWED_ORIGINS: str = "http://localhost:3000,http://localhost:3001,http://127.0.0.1:3000"

    # Collection
    MAX_SCAN_DURATION_HOURS: int = 24
    EVIDENCE_RETENTION_DAYS: int = 365

    # Public UI telemetry. Keep disabled unless you intentionally want the login
    # page to disclose the latest assessment's aggregate posture.
    ENABLE_PUBLIC_ASSESSMENT_SUMMARY: bool = False

    # AI Provider Configuration
    # Set the default provider: "claude" | "openai" | "ollama"
    AI_DEFAULT_PROVIDER: str = "claude"
    # API keys — also read from environment by the providers directly
    ANTHROPIC_API_KEY: str = ""
    OPENAI_API_KEY: str = ""
    OPENAI_BASE_URL: str = "https://api.openai.com/v1"
    # Ollama local server
    OLLAMA_BASE_URL: str = "http://localhost:11434"
    OLLAMA_DEFAULT_MODEL: str = "llama3.2"

    # Dangerous feature controls
    ENABLE_COMMAND_EXECUTION: bool = False
    COMMAND_EXECUTION_ALLOWLIST: str = ""
    # When false (default), run_shell_command AI tool is blocked even with approval
    ENABLE_AI_ARBITRARY_SHELL: bool = False
    COMMAND_EXECUTION_TIMEOUT_SECONDS: int = 60
    ENABLE_CHAIN_BUILDER: bool = False
    ENABLE_TUNNEL_MANAGEMENT: bool = False
    TUNNEL_MANAGEMENT_BINARY_ALLOWLIST: str = "chisel,ligolo-proxy"
    CHISEL_BINARY_PATH: str = ""
    CHISEL_BINARY_SHA256: str = ""
    LIGOLO_PROXY_BINARY_PATH: str = ""
    LIGOLO_PROXY_BINARY_SHA256: str = ""
    MANAGED_SSH_BINARY: str = "ssh"  # resolved via PATH; /usr/bin/ssh on Linux, ssh.exe on Windows
    MANAGED_TUNNEL_PORT_MIN: int = 41000
    MANAGED_TUNNEL_PORT_MAX: int = 49000
    MANAGED_TUNNEL_MAX_LIFETIME_MINUTES: int = 240

    model_config = SettingsConfigDict(env_file=".env", case_sensitive=True, extra="ignore")

    @field_validator("DEBUG", mode="before")
    @classmethod
    def parse_debug(cls, value: Any) -> Any:
        if isinstance(value, bool) or value is None:
            return value
        if isinstance(value, str):
            normalized = value.strip().lower()
            if normalized in {"1", "true", "yes", "on", "debug", "dev", "development"}:
                return True
            if normalized in {"0", "false", "no", "off", "release", "prod", "production"}:
                return False
        return value

    @property
    def allowed_origins_list(self) -> list[str]:
        cleaned = self.ALLOWED_ORIGINS.strip()
        if not cleaned:
            return []
        if cleaned.startswith("["):
            try:
                parsed = json.loads(cleaned)
                if isinstance(parsed, list):
                    return [str(item).strip() for item in parsed if str(item).strip()]
            except json.JSONDecodeError:
                pass
        return [item.strip() for item in cleaned.split(",") if item.strip()]

    @property
    def dev_bootstrap_enabled(self) -> bool:
        return bool(self.DEBUG and self.ALLOW_DEV_BOOTSTRAP)

    @property
    def is_production(self) -> bool:
        return self.ENVIRONMENT.strip().lower() in {"prod", "production"}

    @property
    def command_execution_allowlist(self) -> set[str]:
        return {
            item.strip()
            for item in self.COMMAND_EXECUTION_ALLOWLIST.split(",")
            if item.strip()
        }

    @property
    def tunnel_management_binary_allowlist(self) -> set[str]:
        return {
            item.strip()
            for item in self.TUNNEL_MANAGEMENT_BINARY_ALLOWLIST.split(",")
            if item.strip()
        }

    def validate_runtime(self) -> None:
        secret = (self.SECRET_KEY or "").strip()
        database_url = self.DATABASE_URL.strip().lower()
        weak_secret_markers = {
            "change-me",
            "changeme",
            "example",
            "placeholder",
            "secret",
            "dev-only",
            "default",
        }

        if not secret:
            raise RuntimeError("SECRET_KEY must be set before the API starts")

        if self.is_production and self.DEBUG:
            raise RuntimeError("DEBUG must be false when ENVIRONMENT=production")

        if self.is_production and database_url.startswith("sqlite"):
            raise RuntimeError("Production deployments must use an external database, not local SQLite")

        if self.is_production and "*" in self.allowed_origins_list:
            raise RuntimeError("Production deployments must not allow wildcard CORS origins")

        if self.is_production and not self.AUTH_COOKIE_SECURE:
            raise RuntimeError(
                "AUTH_COOKIE_SECURE must be true in production to prevent session token "
                "transmission over insecure connections."
            )

        if self.is_production and not self.NEO4J_PASSWORD.strip():
            raise RuntimeError(
                "NEO4J_PASSWORD must be set in production; the graph engine is a hard "
                "dependency with no fallback."
            )

        lowered = secret.lower()
        if len(secret) < 32 or any(marker in lowered for marker in weak_secret_markers):
            if (not self.DEBUG) or self.ENABLE_COMMAND_EXECUTION or self.ALLOW_DEV_BOOTSTRAP:
                raise RuntimeError(
                    "SECRET_KEY is missing, placeholder, or too weak for this runtime mode. "
                    "Set a unique random 32+ character secret before starting the API."
                )

        default_admin_password = (self.DEFAULT_ADMIN_PASSWORD or "").strip()
        if self.ALLOW_DEV_BOOTSTRAP and default_admin_password.lower() in WEAK_DEFAULT_ADMIN_PASSWORDS:
            raise RuntimeError(
                "DEFAULT_ADMIN_PASSWORD is weak/default and cannot be used with ALLOW_DEV_BOOTSTRAP=true"
            )

        if self.ENABLE_COMMAND_EXECUTION:
            unknown = self.unknown_command_execution_allowlist_ids()
            if unknown:
                raise RuntimeError(
                    "COMMAND_EXECUTION_ALLOWLIST contains unknown AD command IDs: "
                    + ", ".join(sorted(unknown))
                )

    def known_command_ids(self) -> set[str]:
        from adbygod_api.data.ad_commands import AD_COMMANDS

        return {str(command.get("id", "")).strip() for command in AD_COMMANDS if str(command.get("id", "")).strip()}

    def unknown_command_execution_allowlist_ids(self) -> set[str]:
        allowlist = self.command_execution_allowlist
        if not allowlist:
            return set()
        return allowlist - self.known_command_ids()

    def cookie_secure(self) -> bool:
        # Production must always use Secure cookies. In local/staging development,
        # honor AUTH_COOKIE_SECURE so http://localhost login works when it is false.
        return True if self.is_production else bool(self.AUTH_COOKIE_SECURE)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
