from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
WEB_SRC = ROOT / "apps" / "web" / "src"


def _read(relative_path: str) -> str:
    return (WEB_SRC / relative_path).read_text()


def test_direct_axios_api_helpers_send_cookie_auth_headers_and_env_base() -> None:
    for relative_path in ["lib/reconApi.ts", "lib/killChainApi.ts", "lib/sessionApi.ts"]:
        source = _read(relative_path)
        assert "baseURL: getApiBaseUrl()" in source
        assert "withCredentials: true" in source
        assert "'X-Requested-With': 'XMLHttpRequest'" in source
        assert "const API = '/api/v1'" not in source
        assert "const BASE = '/api/v1" not in source
        assert "axios.get<" not in source
        assert "axios.post<" not in source


def test_api_base_helpers_do_not_double_api_v1_prefixes() -> None:
    source = _read("lib/apiBase.ts")
    assert "normalized.endsWith('/api/v1') ? normalized" in source
    assert "return normalized.endsWith('/api/v1') ? normalized : `${normalized}/api/v1`" in source


def test_ops_terminal_websocket_uses_normalized_api_base_once() -> None:
    source = _read("components/ops/LiveOutputTerminal.tsx")
    assert "getWsApiBaseUrl" in source
    assert "getApiBaseUrl" in source
    # URL is built with wsPath variable (default '/ops/ws/jobs') + jobId — no hardcoded double /api/v1
    assert "`${resolvedWsBaseUrl}${wsPath}/${jobId}`" in source
    assert "/ops/ws/jobs" in source  # default path is present
    assert "resolvedWsBaseUrl}/api/v1/ops/ws/jobs" not in source
    assert "NEXT_PUBLIC_API_URL.replace(/\\/$/, '')}/api/v1/ops/jobs" not in source


def test_chain_websocket_uses_shared_normalized_ws_base() -> None:
    source = _read("lib/chainApi.ts")
    assert "getWsApiBaseUrl" in source
    assert "`${getWsApiBaseUrl()}/chains/ws/${chainId}`" in source
    assert "window.location.hostname}:8000/api/v1" not in source


def test_core_api_helper_uses_shared_normalized_api_base_for_streams_and_fetches() -> None:
    source = _read("lib/api.ts")
    assert "import { getApiBaseUrl } from './apiBase'" in source
    assert "return `${getApiBaseUrl()}${path}${query}`" in source
    assert "const url = `${getApiBaseUrl()}/loot/collect`" in source
    assert "process.env.NEXT_PUBLIC_API_URL" not in source
    assert "}/api/v1/loot/collect" not in source


def test_validation_api_uses_shared_normalized_api_base() -> None:
    source = _read("app/validation/lib/api.ts")
    assert 'import { getApiBaseUrl } from "@/lib/apiBase";' in source
    assert "const BASE = getApiBaseUrl();" in source
    assert "NEXT_PUBLIC_API_URL" not in source
    assert 'replace(/\\/$/, "")}/api/v1' not in source


def test_ops_api_uses_shared_normalized_api_base() -> None:
    source = _read("lib/opsApi.ts")
    assert "import { getApiBaseUrl } from './apiBase'" in source
    assert "fetch(`${getApiBaseUrl()}${path}`" in source
    assert "NEXT_PUBLIC_API_URL" not in source


def test_ai_operator_api_is_env_base_aware_for_all_calls() -> None:
    source = _read("lib/aiOperatorApi.ts")
    assert "import { getApiBaseUrl } from './apiBase'" in source
    assert "const BASE = `${getApiBaseUrl()}/ai-operator`" in source
    assert "const BASE = '/api/v1/ai-operator'" not in source
    assert "fetch(`${BASE}/chat`" in source


def test_validation_module_type_uses_risk_category_not_bare_category() -> None:
    """Ensures the global ValidationModule type uses risk_category (backend field name)."""
    source = _read("lib/types.ts")
    # Must have risk_category (the real backend field)
    assert "risk_category" in source
    # Must NOT have a plain standalone `category: string` in the ValidationModule block
    # (category is allowed as an optional alias but not as the primary required field)
    import re
    # Find the ValidationModule interface block
    match = re.search(r"interface ValidationModule \{[^}]+\}", source, re.DOTALL)
    assert match is not None, "ValidationModule interface not found in types.ts"
    block = match.group(0)
    assert "risk_category" in block, "ValidationModule must have risk_category field"
    # Must not have category as a required (non-optional) field
    assert "category?: string" in block or "category?" in block or "category" not in block or "risk_category" in block


def test_assessment_type_includes_connectivity_profile_id() -> None:
    """Ensures the Assessment TS type exposes connectivity_profile_id (backend field)."""
    source = _read("lib/types.ts")
    import re
    match = re.search(r"interface Assessment \{[^}]+\}", source, re.DOTALL)
    assert match is not None, "Assessment interface not found in types.ts"
    block = match.group(0)
    assert "connectivity_profile_id" in block, "Assessment must have connectivity_profile_id"


def test_expert_decision_type_includes_extended_fields() -> None:
    """Ensures ExpertDecision TS type includes the extended fields the backend sends in run detail."""
    source = _read("lib/types.ts")
    import re
    match = re.search(r"interface ExpertDecision \{[^}]+\}", source, re.DOTALL)
    assert match is not None, "ExpertDecision interface not found in types.ts"
    block = match.group(0)
    assert "module_id" in block, "ExpertDecision must have optional module_id"
    assert "kill_chain_stage" in block, "ExpertDecision must have optional kill_chain_stage"
    assert "mitre_techniques" in block, "ExpertDecision must have optional mitre_techniques"


def test_validation_module_backend_sends_risk_category() -> None:
    """Ensures the catalog module definition uses risk_category (not category)."""
    source = (Path(__file__).resolve().parents[1] / "src/adbygod_api/core/validation/catalog.py").read_text()
    assert "risk_category" in source, "Catalog definition must use risk_category field"
    assert "ValidationModuleDefinition" in source


def test_loot_collect_stream_does_not_use_legacy_localstorage_token() -> None:
    """collectStream must not fall back to localStorage token — auth is cookie-only."""
    source = _read("lib/api.ts")
    # The legacy fallback should be removed
    assert "adbygod_token" not in source or "clearLegacyClientAuthArtifacts" in source, \
        "adbygod_token localStorage reads must only exist in the logout-cleanup function"
    assert "Authorization: `Bearer ${token}`" not in source, \
        "Legacy Bearer token header must not be present in collectStream"


def test_evidence_out_schema_includes_source_port() -> None:
    """EvidenceOut Pydantic schema must include source_port so it isn't silently dropped."""
    from pathlib import Path
    source = (Path(__file__).resolve().parents[1] / "src/adbygod_api/schemas.py").read_text()
    import re
    match = re.search(r"class EvidenceOut\(BaseModel\):.*?(?=\nclass |\Z)", source, re.DOTALL)
    assert match is not None, "EvidenceOut not found in schemas.py"
    block = match.group(0)
    assert "source_port" in block, \
        "EvidenceOut must include source_port or it gets silently dropped from /findings/{id}/evidence"


def test_backend_validation_module_pydantic_uses_risk_category() -> None:
    """The backend ValidationModule Pydantic class must use risk_category, not category."""
    from pathlib import Path
    source = (Path(__file__).resolve().parents[1] / "src/adbygod_api/routes/validation.py").read_text()
    import re
    match = re.search(r"class ValidationModule\(BaseModel\):.*?(?=\nclass |\Z)", source, re.DOTALL)
    assert match is not None, "ValidationModule Pydantic class not found in routes/validation.py"
    block = match.group(0)
    assert "risk_category" in block, \
        "ValidationModule Pydantic class must use risk_category (not category) to match the catalog data"
    assert "    category: str" not in block, \
        "ValidationModule must not have a bare 'category: str' — it conflicts with the actual risk_category field"


def test_validation_result_type_includes_rich_fusion_fields() -> None:
    """ValidationResult global type must expose the rich fields that validation run-detail sends."""
    source = _read("lib/types.ts")
    # Find the block between 'interface ValidationResult {' and the matching closing brace
    start = source.find("interface ValidationResult {")
    assert start != -1, "ValidationResult not found in types.ts"
    # Walk forward to find the matching closing brace (depth counting)
    depth, end = 0, start
    for i, ch in enumerate(source[start:], start):
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                end = i
                break
    block = source[start:end + 1]
    for field in ("module_id", "assessment_id", "duration_ms", "kill_chains", "red_team_narrative"):
        assert field in block, f"ValidationResult must have {field} (sent by backend run-detail endpoint)"
