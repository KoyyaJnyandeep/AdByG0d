# Contributing to AdByG0d

Thank you for taking the time to contribute to AdByG0d. This document explains how to get your development environment set up, how to run the test suite, and what is expected of contributions before they are reviewed.

**Author:** White0xdi3  
**Project:** AdByG0d — Active Directory Security Assessment Platform

---

## Before you start

- Read [SECURITY.md](SECURITY.md). Security vulnerabilities must be reported privately, not as public issues or pull requests.
- Read [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md). All contributors are expected to follow it.
- Do not include real credentials, client data, domain captures, hashes from real environments, private keys, or any raw engagement evidence anywhere in your contribution — issues, PRs, test data, fixtures, or commit messages.
- Use synthetic data only. See `data/samples/` for examples of what is acceptable.

---

## Development environment

### System requirements

| Requirement | Minimum version |
|---|---|
| Python | 3.12 |
| Node.js | 20 |
| npm | 10 |
| Redis | 7 |
| Git | 2.40 |

PostgreSQL is only required for production deployments. SQLite is used automatically for local development and all tests.

### Clone and set up

```bash
git clone https://github.com/White0xdi3/AdByG0d.git
cd AdByG0d
```

### Backend setup

```bash
cd apps/api

python3 -m venv .venv
source .venv/bin/activate

pip install --upgrade pip
pip install -r requirements.txt

cp .env.example .env
# Edit .env — set SECRET_KEY to any long random string for local development
```

Run database migrations:

```bash
PYTHONPATH=src alembic upgrade head
```

Start the API:

```bash
PYTHONPATH=src uvicorn adbygod_api.main:app --reload --host 0.0.0.0 --port 8000
```

### Frontend setup

```bash
cd apps/web

npm install

cp .env.example .env.local
# Default values point the frontend at http://localhost:8000

npm run dev
```

### Celery worker (required for async jobs)

```bash
cd apps/api
source .venv/bin/activate

PYTHONPATH=src celery -A adbygod_api.core.celery_app:celery_app worker \
  --loglevel=info \
  --queues=offensive_jobs \
  --concurrency=4
```

---

## Running the test suite

The minimum environment variables required to run the backend tests:

```bash
export SECRET_KEY=test-key-not-real-1234567890abcdef
export DEBUG=true
export ENVIRONMENT=development
```

### Full verification sequence

Run this before opening a pull request:

```bash
# Python syntax check
python -m compileall -q apps/api/src collectors/linux_remote/src

# Python linting
python -m ruff check apps/api/src collectors/linux_remote/src apps/api/tests

# Backend tests
python -m pytest apps/api/tests -q

# Frontend lint
npm --prefix apps/web run lint

# Frontend type-check
npm --prefix apps/web run type-check -- --pretty false

# Frontend production build
npm --prefix apps/web run build
```

### Running specific tests

```bash
# Run a single test file
python -m pytest apps/api/tests/test_collector_import.py -v

# Run a specific test
python -m pytest apps/api/tests/test_import_security_boundaries.py::test_zip_path_traversal_rejected -v

# Run with parallelism for speed (requires pytest-xdist)
python -m pytest apps/api/tests -n auto -q
```

### Test data

Use synthetic fixtures only. The `data/samples/` directory contains example payloads. The `apps/api/tests/conftest.py` `TestDataFactory` class provides async helpers for generating entities, findings, assessments, and users in test-isolated SQLite databases.

Do not write tests that depend on external services, real domain controllers, or network access. Every test must run fully offline.

---

## What to work on

Check the open issues for things labeled `bug`, `enhancement`, or `good first issue`. If you want to work on something not already tracked, open an issue first to discuss the approach before writing code — this avoids duplicate effort and ensures the change aligns with the project direction.

---

## Code standards

### Python

- Target Python 3.12
- Use async/await throughout — do not use synchronous database or I/O calls in FastAPI route handlers
- Run `ruff check` before committing — the CI pipeline enforces zero lint errors
- Keep route handlers thin: business logic belongs in `core/`, not in `routes/`
- Do not add error handling for states that cannot occur — trust internal invariants
- Write tests for new features and bug fixes using the existing `conftest.py` infrastructure

### TypeScript / Next.js

- Target TypeScript strict mode
- Follow the existing App Router conventions — `page.tsx` and `loading.tsx` are framework conventions and must not be renamed
- Use `@/lib/` and `@/components/` path aliases consistently
- Do not use `any` without a type assertion comment explaining why it is unavoidable
- Run `npm run lint` and `npm run type-check` before committing

### General

- Prefer editing existing files over adding new ones
- Do not introduce abstractions beyond what the immediate change requires
- Keep comments limited to non-obvious constraints, invariants, or workarounds — do not comment on what the code does
- Match the surrounding code style in any file you touch

---

## Commit messages

Use the imperative mood in the subject line:

```
feat: add ESC14 template misconfiguration check
fix: prevent zip path traversal on collector import
docs: document ROUTE_SECURITY_MATRIX admin endpoints
```

Types: `feat`, `fix`, `docs`, `test`, `refactor`, `chore`

Keep the subject under 72 characters. Add a body if the motivation is not obvious from the subject alone.

---

## Pull request process

1. Fork the repository and create your branch from `main`
2. Make your changes on a focused branch (one feature or fix per PR)
3. Ensure the full verification sequence passes locally
4. Fill out the pull request template — every checklist item is required
5. Do not include real credentials, client data, or sensitive content anywhere in the PR
6. Request review — the maintainer will review and provide feedback

Pull requests that fail CI or include real sensitive data will not be merged.

---

## Security contributions

If your contribution touches authentication, authorization, input validation, archive handling, secret management, or any dangerous capability flag, include a security review note in the PR body explaining what attack surfaces were considered and what mitigations are in place.

See [docs/SECURITY_MODEL.md](docs/SECURITY_MODEL.md) and [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) for the security architecture context.

---

## License

By contributing to AdByG0d, you agree that your contributions will be licensed under the MIT License that covers this project.

---

*Maintained by [White0xdi3](https://github.com/White0xdi3)*
