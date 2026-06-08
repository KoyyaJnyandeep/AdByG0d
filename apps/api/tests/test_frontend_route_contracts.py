from __future__ import annotations

from fastapi.routing import APIRoute, APIWebSocketRoute

from adbygod_api.main import app


HTTP_ROUTE_CONTRACTS = [
    ("POST", "/api/v1/auth/login"),
    ("GET", "/api/v1/auth/me"),
    ("POST", "/api/v1/auth/logout"),
    ("GET", "/api/v1/assessments"),
    ("POST", "/api/v1/assessments"),
    ("GET", "/api/v1/assessments/workspaces"),
    ("GET", "/api/v1/assessments/{assessment_id}"),
    ("PATCH", "/api/v1/assessments/{assessment_id}"),
    ("DELETE", "/api/v1/assessments/{assessment_id}"),
    ("GET", "/api/v1/assessments/{assessment_id}/stats"),
    ("GET", "/api/v1/assessments/{assessment_id}/dashboard"),
    ("GET", "/api/v1/findings"),
    ("GET", "/api/v1/findings/modules/summary"),
    ("GET", "/api/v1/findings/{finding_id}"),
    ("PATCH", "/api/v1/findings/{finding_id}"),
    ("GET", "/api/v1/findings/{finding_id}/evidence"),
    ("GET", "/api/v1/entities"),
    ("GET", "/api/v1/entities/summary"),
    ("GET", "/api/v1/entities/intelligence"),
    ("GET", "/api/v1/entities/{entity_id}"),
    ("GET", "/api/v1/graph/attack-flow-chains"),
    ("GET", "/api/v1/graph/{assessment_id}/data"),
    ("GET", "/api/v1/graph/{assessment_id}/paths"),
    ("GET", "/api/v1/graph/{assessment_id}/blast-radius"),
    ("POST", "/api/v1/graph/{assessment_id}/simulate-removal"),
    ("POST", "/api/v1/graph/{assessment_id}/compute-paths"),
    ("GET", "/api/v1/graph/{assessment_id}/categories"),
    ("GET", "/api/v1/graph/{assessment_id}/choke-points"),
    ("GET", "/api/v1/pki/templates"),
    ("GET", "/api/v1/pki/summary"),
    ("GET", "/api/v1/reports/capabilities"),
    ("GET", "/api/v1/reports/preview/{assessment_id}"),
    ("POST", "/api/v1/reports/export"),
    ("POST", "/api/v1/reports/export-technique"),
    ("GET", "/api/v1/remediation/candidates/{assessment_id}"),
    ("POST", "/api/v1/remediation/simulate"),
    ("GET", "/api/v1/modules"),
    ("GET", "/api/v1/validation/modules"),
    ("GET", "/api/v1/validation/global-score/{assessment_id}"),
    ("POST", "/api/v1/validation/simulate/{module_id}/{assessment_id}"),
    ("GET", "/api/v1/validation/overview/{assessment_id}"),
    ("GET", "/api/v1/validation/runs/{assessment_id}"),
    ("GET", "/api/v1/validation/runs/detail/{run_id}"),
    ("GET", "/api/v1/validation/stream/{module_id}/{assessment_id}"),
    ("GET", "/api/v1/validation/stream-all/{assessment_id}"),
    ("POST", "/api/v1/validation/synthetic/generate"),
    ("GET", "/api/v1/validation/synthetic/presets"),
    ("POST", "/api/v1/validation/simulate-synthetic/{module_id}/{preset_name}"),
    ("POST", "/api/v1/validation/simulate-all/{assessment_id}"),
    ("GET", "/api/v1/validation/analytics/{run_id}"),
    ("GET", "/api/v1/validation/kill-chains/{run_id}"),
    ("GET", "/api/v1/validation/blast-radius/{run_id}/{entity_id}"),
    ("GET", "/api/v1/validation/comparison/{run_id_a}/{run_id_b}"),
    ("GET", "/api/v1/validation/export/{run_id}/json"),
    ("GET", "/api/v1/validation/posture-timeline/{assessment_id}"),
    ("GET", "/api/v1/audit"),
    ("POST", "/api/v1/import/{assessment_id}/bloodhound"),
    ("POST", "/api/v1/import/bloodhound/auto"),
    ("POST", "/api/v1/import/collector-zip"),
    ("POST", "/api/v1/collection/ldap/{assessment_id}"),
    ("GET", "/api/v1/collection/capabilities"),
    ("GET", "/api/v1/jobs/status/{job_id}"),
    ("GET", "/api/v1/jobs/stream/{job_id}"),
    ("GET", "/api/v1/search"),
    ("GET", "/api/v1/ad-commands/categories"),
    ("GET", "/api/v1/ad-commands/techniques"),
    ("GET", "/api/v1/ad-commands/list"),
    ("GET", "/api/v1/ad-commands/techniques/{technique_id}"),
    ("GET", "/api/v1/ad-commands/tools/available"),
    ("POST", "/api/v1/ad-commands/execute/{technique_id}"),
    ("GET", "/api/v1/trusts"),
    ("GET", "/api/v1/trusts/summary"),
    ("GET", "/api/v1/trusts/abuse"),
    ("GET", "/api/v1/trusts/abuse/techniques"),
    ("POST", "/api/v1/trusts/simulate"),
    ("GET", "/api/v1/trusts/forest-pivot"),
    ("GET", "/api/v1/trusts/forest-pivot/paths"),
    ("GET", "/api/v1/service-accounts"),
    ("GET", "/api/v1/service-accounts/summary"),
    ("GET", "/api/v1/loot"),
    ("GET", "/api/v1/loot/summary"),
    ("GET", "/api/v1/loot/hash-intel"),
    ("POST", "/api/v1/loot/crack/start"),
    ("GET", "/api/v1/loot/crack/{job_id}"),
    ("GET", "/api/v1/loot/export"),
    ("DELETE", "/api/v1/loot/{chain_id}"),
    ("POST", "/api/v1/loot/hash/manual"),
    ("POST", "/api/v1/loot/collect"),
    ("GET", "/api/v1/users"),
    ("GET", "/api/v1/users/me"),
    ("PATCH", "/api/v1/users/{user_id}"),
    ("POST", "/api/v1/users/{user_id}/deactivate"),
    ("POST", "/api/v1/users/{user_id}/activate"),
    ("GET", "/api/v1/lateral-movement/summary"),
    ("GET", "/api/v1/lateral-movement/paths"),
    ("GET", "/api/v1/lateral-movement/techniques"),
    ("GET", "/api/v1/lateral-movement/chains"),
    ("GET", "/api/v1/connectivity/profiles"),
    ("POST", "/api/v1/connectivity/profiles"),
    ("GET", "/api/v1/connectivity/profiles/{profile_id}"),
    ("PATCH", "/api/v1/connectivity/profiles/{profile_id}"),
    ("DELETE", "/api/v1/connectivity/profiles/{profile_id}"),
    ("POST", "/api/v1/connectivity/profiles/{profile_id}/test"),
    ("POST", "/api/v1/connectivity/profiles/{profile_id}/clone"),
    ("POST", "/api/v1/connectivity/profiles/{profile_id}/chisel/start"),
    ("POST", "/api/v1/connectivity/profiles/{profile_id}/chisel/stop"),
    ("GET", "/api/v1/connectivity/profiles/{profile_id}/chisel/status"),
    ("GET", "/api/v1/connectivity/profiles/{profile_id}/chisel/logs"),
    ("POST", "/api/v1/connectivity/profiles/{profile_id}/ligolo/start"),
    ("POST", "/api/v1/connectivity/profiles/{profile_id}/ligolo/stop"),
    ("POST", "/api/v1/connectivity/profiles/{profile_id}/ligolo/route"),
    ("GET", "/api/v1/connectivity/profiles/{profile_id}/ligolo/status"),
    ("GET", "/api/v1/connectivity/profiles/{profile_id}/ligolo/logs"),
    ("POST", "/api/v1/connectivity/profiles/{profile_id}/tunnel/start"),
    ("POST", "/api/v1/connectivity/profiles/{profile_id}/tunnel/stop"),
    ("GET", "/api/v1/connectivity/profiles/{profile_id}/tunnel/status"),
    ("GET", "/api/v1/connectivity/profiles/{profile_id}/tunnel/logs"),
    ("GET", "/api/v1/connectivity/stats"),
    ("POST", "/api/v1/chains/resolve"),
    ("POST", "/api/v1/chains/preflight"),
    ("POST", "/api/v1/chains"),
    ("GET", "/api/v1/chains"),
    ("GET", "/api/v1/chains/situations"),
    ("GET", "/api/v1/chains/library"),
    ("GET", "/api/v1/chains/{chain_id}"),
    ("POST", "/api/v1/chains/{chain_id}/start"),
    ("POST", "/api/v1/chains/{chain_id}/stop"),
    ("POST", "/api/v1/ops/execute"),
    ("GET", "/api/v1/ops/jobs"),
    ("GET", "/api/v1/ops/jobs/{job_id}/output"),
    ("DELETE", "/api/v1/ops/jobs/{job_id}"),
    ("GET", "/api/v1/ops/profile"),
    ("PUT", "/api/v1/ops/profile"),
    ("GET", "/api/v1/ai-operator/providers"),
    ("GET", "/api/v1/ai-operator/providers/{provider_id}"),
    ("POST", "/api/v1/ai-operator/suggest"),
    ("POST", "/api/v1/ai-operator/playbook"),
    ("POST", "/api/v1/ai-operator/auto-run"),
    ("GET", "/api/v1/ai-operator/status"),
    ("POST", "/api/v1/ai-operator/stop"),
    ("GET", "/api/v1/ai-operator/history"),
    ("POST", "/api/v1/ai-operator/providers/{provider_id}/test"),
    ("POST", "/api/v1/ai-operator/chat"),
    ("POST", "/api/v1/ai-operator/analyze"),
    ("POST", "/api/v1/ai-operator/explain"),
    ("POST", "/api/v1/ai-operator/generate-report"),
    ("POST", "/api/v1/ai-operator/analyze-bloodhound"),
    ("POST", "/api/v1/ai-operator/approve/{request_id}"),
    ("POST", "/api/v1/ai-operator/reject/{request_id}"),
    ("GET", "/api/v1/ai-operator/memory/{assessment_id}"),
    ("DELETE", "/api/v1/ai-operator/memory/{assessment_id}"),
    ("GET", "/api/v1/ai-operator/playbooks"),
    ("GET", "/api/v1/ai-operator/target-card/{assessment_id}"),
    ("GET", "/api/v1/arsenal/cves"),
    ("GET", "/api/v1/arsenal/cves/{cve_id}"),
    ("GET", "/api/v1/arsenal/stats"),
    ("POST", "/api/v1/arsenal/check"),
    ("POST", "/api/v1/arsenal/check-batch"),
    ("GET", "/api/v1/arsenal/jobs/{job_id}"),
    ("GET", "/api/v1/arsenal/assessments-list"),
    ("GET", "/api/v1/arsenal/target-from-assessment/{assessment_id}"),
    ("GET", "/api/v1/arsenal/stream/{job_id}"),
    ("POST", "/api/v1/recon/scan"),
    ("GET", "/api/v1/recon/scan/{scan_id}"),
    ("GET", "/api/v1/recon/scans"),
    ("GET", "/api/v1/kill-chain"),
    ("GET", "/api/v1/session"),
    ("POST", "/api/v1/session/update"),
    ("POST", "/api/v1/session/reset"),
    ("POST", "/api/v1/tool-checker/scan"),
    ("GET", "/api/v1/tool-checker/results"),
    ("GET", "/api/v1/public/assessment-summary"),
]

WEBSOCKET_ROUTE_CONTRACTS = [
    "/api/v1/chains/ws/{chain_id}",
    "/api/v1/ops/ws/jobs/{job_id}",
]


def _route_table() -> tuple[set[tuple[str, str]], set[str]]:
    http_routes: set[tuple[str, str]] = set()
    websocket_routes: set[str] = set()
    for route in app.routes:
        if isinstance(route, APIRoute):
            for method in route.methods or set():
                if method in {"HEAD", "OPTIONS"}:
                    continue
                http_routes.add((method, route.path))
        elif isinstance(route, APIWebSocketRoute):
            websocket_routes.add(route.path)
    return http_routes, websocket_routes


def _with_optional_trailing_slash(path: str) -> set[str]:
    if path == "/":
        return {path}
    return {path.rstrip("/"), f"{path.rstrip('/')}/"}


def test_frontend_http_api_routes_exist() -> None:
    http_routes, _ = _route_table()
    missing = [
        (method, path)
        for method, path in HTTP_ROUTE_CONTRACTS
        if not any((method, candidate) in http_routes for candidate in _with_optional_trailing_slash(path))
    ]
    assert missing == []


def test_frontend_websocket_api_routes_exist() -> None:
    _, websocket_routes = _route_table()
    missing = [
        path
        for path in WEBSOCKET_ROUTE_CONTRACTS
        if not any(candidate in websocket_routes for candidate in _with_optional_trailing_slash(path))
    ]
    assert missing == []


def test_synthetic_validation_contract_uses_post_not_get() -> None:
    http_routes, _ = _route_table()
    path = "/api/v1/validation/simulate-synthetic/{module_id}/{preset_name}"
    assert ("POST", path) in http_routes
    assert ("GET", path) not in http_routes
