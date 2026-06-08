# Testing Guide

This document covers how the AdByG0d test suite is structured, how to run it, and how to write new tests.

**Author:** White0xdi3  
**Project:** AdByG0d — Active Directory Security Assessment Platform

---

## Test suite overview

| Component | Framework | Location | Count |
|---|---|---|---|
| Backend (Python) | pytest + asyncio | `apps/api/tests/` | 100+ tests |
| Linting (Python) | ruff | `apps/api/src/`, `apps/api/tests/` | — |
| Syntax check | compileall | `apps/api/src/`, `collectors/` | — |
| Frontend lint | ESLint | `apps/web/src/` | — |
| Frontend types | TypeScript compiler | `apps/web/src/` | — |
| Frontend build | Next.js | `apps/web/` | — |

---

## Running the full verification sequence

Run this sequence from the repository root before opening a pull request:

```bash
# 1. Python syntax check
python -m compileall -q apps/api/src collectors/linux_remote/src

# 2. Python linting
python -m ruff check apps/api/src collectors/linux_remote/src apps/api/tests

# 3. Backend tests
python -m pytest apps/api/tests -q

# 4. Frontend lint
npm --prefix apps/web run lint

# 5. Frontend type-check
npm --prefix apps/web run type-check -- --pretty false

# 6. Frontend production build
npm --prefix apps/web run build
```

### Required environment variables for backend tests

```bash
export SECRET_KEY=test-key-not-real-1234567890abcdef
export DEBUG=true
export ENVIRONMENT=development
```

These can be set in your shell, in a `.env` file in `apps/api/`, or passed directly to pytest:

```bash
SECRET_KEY=test-key-not-real-1234567890abcdef \
DEBUG=true \
ENVIRONMENT=development \
python -m pytest apps/api/tests -q
```

---

## Running specific tests

```bash
# Run a single test file
python -m pytest apps/api/tests/test_collector_import.py -v

# Run a specific test by name
python -m pytest apps/api/tests/test_import_security_boundaries.py::test_zip_path_traversal_rejected -v

# Run tests matching a keyword
python -m pytest apps/api/tests -k "bloodhound" -v

# Run tests in parallel (requires pytest-xdist)
python -m pytest apps/api/tests -n auto -q

# Run with 24 parallel workers
python -m pytest apps/api/tests -n 24 -q

# Run with verbose output and no capture
python -m pytest apps/api/tests -v -s
```

---

## Test infrastructure

### Database isolation

Each test that requires database access gets its own in-memory SQLite database, created and torn down by the `test_app` fixture in `conftest.py`. Tests are fully isolated — they cannot share or corrupt each other's data. There is no dependency on an external database server.

The `test_app` fixture:
1. Creates a temporary SQLite database in memory
2. Runs all Alembic migrations against it
3. Overrides the FastAPI dependency injection to use this isolated database
4. Creates a test HTTP client pointing at the isolated app instance
5. Tears everything down when the test completes

### Authentication in tests

The `test_app` fixture returns a configured `AsyncClient`. Tests that require an authenticated session use the `authenticate` helper to log in:

```python
async def test_something(test_app):
    client, override_db = test_app
    # Log in as a test user
    response = await client.post("/api/auth/login", json={
        "username": "testadmin",
        "password": "testpassword"
    })
    assert response.status_code == 200
    # Subsequent requests use the cookie automatically
    response = await client.get("/api/assessments/")
    assert response.status_code == 200
```

### `TestDataFactory`

The `TestDataFactory` class provides async helpers for generating test data:

```python
from tests.conftest import TestDataFactory

async def test_with_entities(test_app):
    client, session_factory = test_app
    async with session_factory() as session:
        factory = TestDataFactory(session)
        assessment = await factory.create_assessment(name="Test Assessment")
        user = await factory.create_user(username="analyst", role="analyst")
        finding = await factory.create_finding(assessment_id=assessment.id)
        entity = await factory.create_entity(assessment_id=assessment.id)
```

### Asyncio mode

All tests use `asyncio` mode (`asyncio_mode = "auto"` in pytest configuration). Test functions declared with `async def` are run by pytest-asyncio automatically.

---

## Test files and what they cover

| File | Coverage area |
|---|---|
| `test_authz_isolation.py` | Role-based access control across endpoints |
| `test_bloodhound_import_pipeline.py` | BloodHound ZIP import end-to-end |
| `test_chain_stop_not_failed.py` | Operation chain state machine transitions |
| `test_collector_import.py` | Collector ZIP parsing and module summary |
| `test_credential_policy_enforcement.py` | Privileged operation access gates |
| `test_graph_ws_delta_broadcast.py` | WebSocket graph delta streaming |
| `test_import_security_boundaries.py` | ZIP security: path traversal, bombs, adversarial inputs |
| `test_laps_coverage_regressions.py` | LAPS and gMSA validation rule regressions |
| `test_large_scale_domain_import.py` | High-volume entity and edge import performance |
| `test_linux_collector_cli.py` | Linux remote collector CLI invocation |
| `test_plan_attack_phase_matching.py` | Kill chain phase assignment |
| `test_reports.py` | Report generation (PDF, DOCX) |
| `test_validation_consensus.py` | Multi-expert validation agreement |
| `test_ai_operator_integration.py` | AI operator integration (mock provider) |
| `test_ai_operator_provider_contract.py` | AI provider contract tests |
| `test_operator_tools_e2e.py` | Operator tool end-to-end (requires AI config) |
| `test_qwen_ollama_accuracy.py` | Ollama provider accuracy (requires Ollama) |

### AI and Ollama tests

`test_qwen_ollama_accuracy.py` and `test_operator_tools_e2e.py` require a running Ollama or AI provider instance. They are excluded from the standard CI run. To run them locally:

```bash
python -m pytest apps/api/tests/test_qwen_ollama_accuracy.py -v
python -m pytest apps/api/tests/test_operator_tools_e2e.py -v
```

---

## Import security test levels

`test_import_security_boundaries.py` has six escalating test levels:

| Level | Description |
|---|---|
| 1 | Happy-path: valid ZIP parses, summarizes, and imports |
| 2 | Boundary conditions: preview truncation at `_RAW_PREVIEW_CHARS`, member count limits |
| 3 | Adversarial: path traversal `../`, nested ZIPs, zero-compressed-size entries, non-ZIP content |
| 4 | State machine enforcement: duplicate import (409 conflict), bulk entity creation, completed import replay |
| 5 | Compound cascades: corrupt module, delete-during-import, null output fields |
| 6 | Real ZIP round-trips: store/deflate/bzip2/lzma compression methods, empty ZIPs, 256-member performance |

---

## Writing new tests

### Test file naming

Name test files after what they test, not after the mechanism:

- `test_bloodhound_import_pipeline.py` — good
- `test_import_integration.py` — acceptable
- `test_thing.py` — not acceptable

### Test function naming

Use full descriptive names that read as specifications:

```python
# Good
async def test_zip_path_traversal_rejected():
async def test_import_fails_with_409_when_already_running():
async def test_analyst_cannot_access_user_management():

# Not good
async def test_zip():
async def test_import_409():
async def test_access():
```

### What to test

- The behavior described in the function name, nothing more
- Boundary conditions and error paths, not just the happy path
- The HTTP response status code and response body structure
- That the database state after the operation matches the expected state

### What not to test

- Implementation details (internal function signatures, private class attributes)
- Framework behavior (FastAPI's own routing, SQLAlchemy session management)
- External services without mocking (network calls, real domain controllers)

### Synthetic test data only

All test data must be synthetic. Do not use real domain names, real SIDs, real usernames from actual environments. Use the `TestDataFactory` for generating entities and assessments.

### Example test pattern

```python
import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_finding_requires_authentication(test_app):
    client, _ = test_app
    # No authentication — should be rejected
    response = await client.get("/api/findings/")
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_analyst_can_create_finding(test_app, analyst_client):
    client = analyst_client
    response = await client.post("/api/findings/", json={
        "assessment_id": 1,
        "title": "Kerberoastable SPN account",
        "severity": "HIGH",
        "category": "kerberoasting"
    })
    assert response.status_code == 201
    data = response.json()
    assert data["title"] == "Kerberoastable SPN account"
    assert data["severity"] == "HIGH"
```

---

## CI pipeline

GitHub Actions runs the full verification sequence on every push and pull request:

```
CI
├── backend
│   ├── Python syntax check (compileall)
│   ├── Ruff lint
│   └── pytest
├── frontend
│   ├── ESLint
│   ├── TypeScript type-check
│   └── Next.js production build
└── release-hygiene
    ├── Tracked sensitive file check
    ├── Tracked secret pattern check
    └── Release archive safety
```

All three jobs must pass before a pull request can be merged. The CI configuration is in `.github/workflows/ci.yml`.

---

## Linting

Ruff is the Python linter. Configuration is in `apps/api/pyproject.toml`.

```bash
# Check only
python -m ruff check apps/api/src apps/api/tests

# Auto-fix safe issues
python -m ruff check --fix apps/api/src apps/api/tests
```

Per-file ignores are documented in `pyproject.toml`. Test files that manipulate `sys.path` before imports are allowed to use `E402` (module import not at top of file).

---

## Dependency notes

| Package | Purpose |
|---|---|
| `pytest` | Test runner |
| `pytest-asyncio` | asyncio test support |
| `pytest-xdist` | Parallel test execution (`-n 24`) |
| `pytest-timeout` | Per-test timeout enforcement |
| `httpx` | Async HTTP client for TestClient |
| `aiosqlite` | Async SQLite driver for in-memory test databases |
| `ruff` | Python linter |

Install all test dependencies with:

```bash
pip install -r apps/api/requirements.txt
```

The test dependencies are included in the main requirements file.

---

*Maintained by [White0xdi3](https://github.com/White0xdi3) — AdByG0d project*
