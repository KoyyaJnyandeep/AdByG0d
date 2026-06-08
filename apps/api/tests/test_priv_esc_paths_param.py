"""Contract test: priv-esc page must send max_paths (the backend's param name),
not limit (which the backend ignores for path queries)."""
from __future__ import annotations

from pathlib import Path

_WEB = Path(__file__).resolve().parents[3] / "apps" / "web" / "src"


def _read(rel: str) -> str:
    return (_WEB / rel).read_text()


def test_priv_esc_page_sends_max_paths_not_limit() -> None:
    source = _read("app/priv-esc/page.tsx")
    assert "max_paths: 200" in source, "priv-esc page must send max_paths: 200 to match backend param"
    assert "limit: 200" not in source, "priv-esc page must not send 'limit' — backend ignores it for path queries"


def test_graph_api_type_allows_max_paths() -> None:
    source = _read("lib/api.ts")
    assert "max_paths?" in source, "getPaths type must include optional max_paths param"
