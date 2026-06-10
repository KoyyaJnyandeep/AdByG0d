from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
import logging
import time

import re
import uuid

from fastapi import Depends, FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware

from adbygod_api.config import settings
from adbygod_api.database import Base, engine, AsyncSessionLocal
from adbygod_api import models  # noqa: F401 - imports model metadata
from adbygod_api.routes import (
    ad_commands,
    ai_operator,
    arsenal,
    assessments,
    audit,
    auth,
    chains,
    collection,
    connectivity,
    entities,
    findings,
    graph,
    import_data,
    ingest,
    jobs,
    lateral_movement,
    loot,
    ops,
    pki,
    public,
    remediation,
    reports,
    search,
    service_accounts,
    trusts,
    users,
    validation,
    recon,
    kill_chain,
    session,
    setup,
    tool_checker,
    security,
)
from adbygod_api.routes.graph_ws import router as graph_ws_router
from adbygod_api.core.commands.catalog import get_collection_modules
from adbygod_api.core.commands.architecture_catalog import ARCHITECTURE_ATTACK_MODULES, merge_architecture_modules
from adbygod_api.core.commands.exposure_catalog import EXPOSURE_QUICK_CHECK_MODULES, merge_exposure_modules
from adbygod_api.core.workers.pool import init_pool
from adbygod_api.core.graph import neo4j_client

logging.basicConfig(
    level=getattr(logging, settings.LOG_LEVEL.upper(), logging.DEBUG if settings.DEBUG else logging.INFO),
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
)
log = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    settings.validate_runtime()
    if settings.AUTO_CREATE_TABLES:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
    else:
        log.info("Automatic table creation disabled; expecting migrations to be applied")
    await auth.ensure_default_admin_user()
    init_pool(max_workers=10)
    from adbygod_api.core.loot.hash_intel import recover_crack_jobs
    await recover_crack_jobs()
    log.info("Database tables verified — %s", settings.APP_VERSION)
    await neo4j_client.connect()
    await neo4j_client.ensure_schema()
    yield
    await neo4j_client.close()


async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    if not settings.DEBUG:
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


async def request_logging(request: Request, call_next):
    start = time.perf_counter()
    response = await call_next(request)
    if settings.DEBUG:
        elapsed_ms = (time.perf_counter() - start) * 1000
        log.debug("%s %s -> %s (%.2f ms)", request.method, request.url.path, response.status_code, elapsed_ms)
    return response


async def api_health():
    return {"ok": True, "version": settings.APP_VERSION}


async def root():
    return {
        "ok": True,
        "service": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "author": "White0xdi3",
        "message": "AdByG0d API is running. Open the Web UI on port 3000, or open API docs at /api/docs.",
        "web_ui": "http://127.0.0.1:3000",
        "api_docs": "/api/docs",
        "health": "/api/health",
        "api_prefix": API_PREFIX,
    }


async def health():
    return {"ok": True, "version": settings.APP_VERSION}


async def collection_modules(_user=Depends(auth.get_current_user)):
    return {"modules": merge_architecture_modules(merge_exposure_modules(get_collection_modules()))}


async def architecture_modules(_user=Depends(auth.get_current_user)):
    return {"modules": ARCHITECTURE_ATTACK_MODULES}


async def exposure_modules(_user=Depends(auth.get_current_user)):
    return {"modules": EXPOSURE_QUICK_CHECK_MODULES}


# Paths to skip for audit logging (read-only, health, public, docs)
_AUDIT_SKIP_PREFIXES = (
    "/api/docs", "/api/redoc", "/api/openapi.json", "/api/health", "/health",
    "/api/v1/public/",
)
_AUDIT_SKIP_METHODS = {"GET", "HEAD", "OPTIONS"}

# Map URL path fragments → human-readable resource types
_RESOURCE_MAP = [
    (r"/assessments",      "assessment"),
    (r"/findings",         "finding"),
    (r"/import",           "import"),
    (r"/ingest",           "ingest"),
    (r"/entities",         "entity"),
    (r"/graph",            "graph"),
    (r"/loot",             "loot"),
    (r"/reports",          "report"),
    (r"/validation",       "validation"),
    (r"/auth/",            "auth"),
    (r"/users",            "user"),
    (r"/connectivity",     "connectivity"),
    (r"/collection",       "collection"),
    (r"/chains",           "chain"),
    (r"/ops",              "operation"),
    (r"/pki",              "pki"),
    (r"/remediation",      "remediation"),
    (r"/search",           "search"),
    (r"/setup",            "setup"),
    (r"/tool-checker",     "tool"),
]

_UUID_RE = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.I)


def _resource_type(path: str) -> str:
    for fragment, rtype in _RESOURCE_MAP:
        if fragment in path:
            return rtype
    return "unknown"


def _resource_id(path: str) -> str | None:
    m = _UUID_RE.search(path)
    return m.group(0) if m else None


def _action(method: str, path: str, status: int) -> str:
    verb = {
        "POST":   "create",
        "PUT":    "update",
        "PATCH":  "update",
        "DELETE": "delete",
    }.get(method, method.lower())
    rtype = _resource_type(path)
    outcome = "ok" if status < 400 else "fail"
    return f"{rtype}.{verb}.{outcome}"


async def audit_middleware(request: Request, call_next):
    response = await call_next(request)

    method = request.method
    path   = request.url.path

    if method in _AUDIT_SKIP_METHODS:
        return response
    if any(path.startswith(p) for p in _AUDIT_SKIP_PREFIXES):
        return response

    # Best-effort: read user_id from the session cookie / JWT without blocking
    user_id: uuid.UUID | None = None
    try:
        from adbygod_api.routes.auth import get_current_user_from_request
        user = await get_current_user_from_request(request)
        if user:
            user_id = user.id
    except Exception:
        pass

    entry = models.AuditLog(
        user_id=user_id,
        action=_action(method, path, response.status_code),
        resource_type=_resource_type(path),
        resource_id=_resource_id(path),
        details={"method": method, "path": path, "status": response.status_code},
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
    )
    try:
        async with AsyncSessionLocal() as db:
            db.add(entry)
            await db.commit()
    except Exception as exc:
        log.debug("audit write failed: %s", exc)

    return response


API_PREFIX = "/api/v1"


def create_app() -> FastAPI:
    application = FastAPI(
        title=settings.APP_NAME,
        version=settings.APP_VERSION,
        contact={"name": "White0xdi3"},
        docs_url="/api/docs",
        redoc_url="/api/redoc",
        openapi_url="/api/openapi.json",
        lifespan=lifespan,
    )

    application.add_middleware(
        CORSMiddleware,
        allow_origins=settings.allowed_origins_list,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    application.middleware("http")(audit_middleware)
    application.middleware("http")(request_logging)
    application.middleware("http")(security_headers)

    application.get("/")(root)
    application.get("/api/health")(api_health)
    application.get("/health")(health)
    application.get(f"{API_PREFIX}/modules")(collection_modules)
    application.get(f"{API_PREFIX}/modules/architecture")(architecture_modules)
    application.get(f"{API_PREFIX}/modules/exposure")(exposure_modules)

    application.include_router(auth.router, prefix=API_PREFIX)
    application.include_router(assessments.router, prefix=API_PREFIX)
    application.include_router(findings.router, prefix=API_PREFIX)
    application.include_router(entities.router, prefix=API_PREFIX)
    application.include_router(graph.router, prefix=API_PREFIX)
    application.include_router(ingest.router, prefix=API_PREFIX)
    application.include_router(import_data.router, prefix=API_PREFIX)
    application.include_router(collection.router, prefix=API_PREFIX)
    application.include_router(jobs.router, prefix=API_PREFIX)
    application.include_router(pki.router, prefix=API_PREFIX)
    application.include_router(public.router, prefix=API_PREFIX)
    application.include_router(remediation.router, prefix=API_PREFIX)
    application.include_router(reports.router, prefix=API_PREFIX)
    application.include_router(search.router, prefix=API_PREFIX)
    application.include_router(validation.router, prefix=API_PREFIX)
    application.include_router(audit.router, prefix=API_PREFIX)
    application.include_router(ad_commands.router, prefix=API_PREFIX)
    application.include_router(ops.router, prefix=API_PREFIX)
    application.include_router(chains.router, prefix=API_PREFIX)
    application.include_router(trusts.router, prefix=API_PREFIX)
    application.include_router(lateral_movement.router, prefix=API_PREFIX)
    application.include_router(service_accounts.router, prefix=API_PREFIX)
    application.include_router(loot.router, prefix=API_PREFIX)
    application.include_router(users.router, prefix=API_PREFIX)
    application.include_router(arsenal.router, prefix=API_PREFIX)
    application.include_router(connectivity.router, prefix=API_PREFIX)
    application.include_router(recon.router, prefix=API_PREFIX)
    application.include_router(kill_chain.router, prefix=API_PREFIX)
    application.include_router(session.router, prefix=API_PREFIX)
    application.include_router(tool_checker.router, prefix=API_PREFIX)
    application.include_router(security.router, prefix=API_PREFIX)
    application.include_router(setup.router, prefix=API_PREFIX)
    application.include_router(ai_operator.router, prefix=API_PREFIX)
    application.include_router(graph_ws_router, prefix=API_PREFIX)

    return application


app = create_app()
