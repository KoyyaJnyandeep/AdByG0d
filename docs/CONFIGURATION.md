# Configuration Reference

AdByG0d is configured entirely through environment variables. This document is the authoritative reference for every variable the application reads.

**Author:** White0xdi3  
**Project:** AdByG0d — Active Directory Security Assessment Platform

---

## How configuration is loaded

The API reads environment variables at startup. Variables can be set:
- In a `.env` file in `apps/api/` (development)
- In a `.env` file in the repository root when using Docker Compose
- Directly in the process environment (production, CI)

The application validates critical variables at startup and refuses to start if production requirements are not met.

---

## Critical variables

These must be set before the application will start in any environment.

### `SECRET_KEY`

Signs and verifies all JWT tokens. If this value is exposed or guessed, an attacker can forge authentication tokens for any user including superadmins.

- **Required:** yes
- **Minimum length:** 32 characters (64+ recommended)
- **Generate with:** `python3 -c "import secrets; print(secrets.token_urlsafe(48))"`
- **Production check:** The application rejects startup if this matches any known weak or default value
- **Rotation:** Rotating this key immediately invalidates all active sessions

### `DATABASE_URL`

SQLAlchemy async connection string.

- **Required:** yes (or omit to use SQLite automatically in development)
- **Development default:** SQLite — `sqlite+aiosqlite:///./adbygod_dev.db`
- **Production required format:** `postgresql+asyncpg://user:password@host:port/dbname`
- **Production check:** The application rejects SQLite in production mode

### `REDIS_URL`

Redis connection for real-time pub-sub and job output streaming.

- **Required:** yes in production
- **Default:** `redis://localhost:6379/0`
- **Example:** `redis://:password@redis.internal:6379/0`

### `CELERY_BROKER_URL`

Redis connection for the Celery task queue. Should use a separate database index from `REDIS_URL`.

- **Required:** yes for async job execution
- **Default:** `redis://localhost:6379/1`
- **Example:** `redis://:password@redis.internal:6379/1`

---

## Authentication and session

### `AUTH_COOKIE_SECURE`

Controls the `Secure` attribute on the authentication cookie. Must be `true` in any deployment behind HTTPS.

- **Values:** `true` / `false`
- **Default:** `false`
- **Production check:** The application rejects startup if this is `false` in production mode

### `AUTH_COOKIE_SAMESITE`

SameSite policy for the authentication cookie.

- **Values:** `strict` / `lax` / `none`
- **Default:** `lax`

### `ACCESS_TOKEN_EXPIRE_MINUTES`

Lifetime of the JWT access token in minutes.

- **Default:** `60`
- **Recommendation:** Keep short (30–120 minutes). Refresh tokens are not implemented — the user re-authenticates after expiry.

---

## CORS and origins

### `ALLOWED_ORIGINS`

Comma-separated list of origins permitted by the CORS policy. The API rejects cross-origin requests from any origin not in this list.

- **Required:** yes in production
- **Example:** `https://adbygod.example.com`
- **Production check:** The application rejects wildcard `*` origins in production mode
- **Docker development default:** `http://localhost:3000`

Do not include a trailing slash. Origins must exactly match the scheme, host, and port of the frontend.

---

## Runtime environment

### `ENVIRONMENT`

Selects the runtime mode. Controls startup validation strictness, debug endpoint availability, and logging verbosity.

- **Values:** `development` / `production`
- **Default:** `development`

### `DEBUG`

Enables the interactive OpenAPI docs endpoint (`/docs`), detailed exception tracebacks in API responses, and verbose logging.

- **Values:** `true` / `false`
- **Default:** `false`
- **Never enable in production**

### `API_PREFIX`

URL path prefix for all API routes.

- **Default:** `/api`
- **Example:** If set to `/api/v1`, all routes become `/api/v1/assessments`, `/api/v1/findings`, etc.

---

## Dangerous capability flags

All dangerous capabilities are **off by default**. They require explicit opt-in through environment variables. These flags must not be set in any deployment that is not isolated, authorized, and under direct operator control.

See [docs/DANGEROUS_FEATURES.md](DANGEROUS_FEATURES.md) for the complete description of what each flag enables, its attack surface, and the required deployment controls.

### `ENABLE_COMMAND_EXECUTION`

Enables the AD command catalog execution API. Allows running pre-built Active Directory commands against the target domain from the web interface.

- **Values:** `true` / `false`
- **Default:** `false`

### `ENABLE_AI_ARBITRARY_SHELL`

Enables the AI operator shell tool, which allows the AI to execute arbitrary shell commands on the assessment host. Requires `ENABLE_COMMAND_EXECUTION` to also be `true`.

- **Values:** `true` / `false`
- **Default:** `false`

### `ENABLE_CHAIN_BUILDER`

Enables multi-step operation chain workflows with automatic sequencing.

- **Values:** `true` / `false`
- **Default:** `false`

### `ENABLE_TUNNEL_MANAGEMENT`

Enables Chisel and ligolo-proxy tunnel lifecycle management from the web interface.

- **Values:** `true` / `false`
- **Default:** `false`

---

## AI operator

### `AI_PROVIDER`

Selects the AI provider. The AI operator is disabled entirely if this is not set.

- **Values:** `anthropic` / `openai` / `ollama`
- **Default:** unset (disabled)

### `ANTHROPIC_API_KEY`

Anthropic API key. Required when `AI_PROVIDER=anthropic`.

### `OPENAI_API_KEY`

OpenAI API key. Required when `AI_PROVIDER=openai`.

### `OLLAMA_BASE_URL`

Base URL for the Ollama server. Required when `AI_PROVIDER=ollama`.

- **Example:** `http://localhost:11434`

### `AI_MODEL`

Model identifier to use. Defaults vary by provider.

- **Anthropic default:** `claude-sonnet-4-6`
- **OpenAI default:** `gpt-4o`
- **Ollama default:** `qwen2.5:14b`

---

## Job execution

### `CELERY_RESULT_BACKEND`

Backend for Celery task result storage.

- **Default:** Uses `REDIS_URL` value
- **Example:** `redis://localhost:6379/2`

### `JOB_OUTPUT_MAX_BYTES`

Maximum bytes of job output stored per job before truncation.

- **Default:** `10485760` (10 MB)

### `JOB_TIMEOUT_SECONDS`

Maximum wall-clock seconds a single job is allowed to run before it is terminated.

- **Default:** `3600` (1 hour)

---

## Collector and import

### `ZIP_MAX_MEMBERS`

Maximum number of files inside a collector ZIP archive before the import is rejected.

- **Default:** `256`

### `ZIP_MAX_UNCOMPRESSED_BYTES`

Maximum total uncompressed size in bytes of a collector ZIP archive.

- **Default:** `268435456` (256 MB)

### `ZIP_MAX_RATIO`

Maximum compression ratio (uncompressed ÷ compressed) before the archive is rejected as a potential ZIP bomb.

- **Default:** `100`

### `RAW_PREVIEW_CHARS`

Maximum number of characters of raw module output preserved in the import summary preview.

- **Default:** `2048`

---

## Reporting

### `REPORT_OUTPUT_DIR`

Directory where generated report files are written before being streamed to the client.

- **Default:** `/tmp/adbygod_reports`

---

## Frontend (`apps/web`)

The Next.js frontend reads these variables at build time or runtime via `NEXT_PUBLIC_` prefix.

### `NEXT_PUBLIC_API_URL`

Base URL the browser uses to reach the API.

- **Development default:** `http://localhost:8000`
- **Production example:** `https://api.adbygod.example.com`

### `NEXT_PUBLIC_WS_URL`

Base WebSocket URL for live streaming connections.

- **Development default:** `ws://localhost:8000`
- **Production example:** `wss://api.adbygod.example.com`

---

## Docker Compose variable files

| File | Purpose |
|---|---|
| `.env.docker.example` | Template for Docker Compose deployments |
| `apps/api/.env.example` | Template for manual local backend setup |
| `apps/web/.env.example` | Template for manual local frontend setup |

Copy the relevant example file and fill in the values before starting any service. Never commit a populated `.env` file.

---

## Production startup validation

When `ENVIRONMENT=production`, the API validates configuration at startup and refuses to start if any of the following conditions are detected:

- `SECRET_KEY` is shorter than 32 characters or matches a known weak value
- `DATABASE_URL` is a SQLite connection string
- `AUTH_COOKIE_SECURE` is `false`
- `ALLOWED_ORIGINS` contains a wildcard `*`
- `DEBUG` is `true`

These checks exist to prevent misconfigured deployments from reaching production traffic.

---

*Maintained by [White0xdi3](https://github.com/White0xdi3) — AdByG0d project*
