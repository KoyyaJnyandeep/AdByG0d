# Security Model

This document describes the security architecture of AdByG0d: what the platform protects, how it is protected, and what is out of scope.

**Author:** White0xdi3  
**Project:** AdByG0d — Active Directory Security Assessment Platform

---

## What AdByG0d protects

AdByG0d handles sensitive material: Active Directory evidence, credential hashes, assessment findings, and — when privileged capabilities are enabled — live execution output from offensive tools. The platform is designed to protect this material from:

1. Unauthorized access by users without a valid session
2. Privilege escalation within the platform (a read-only user gaining analyst or admin access)
3. Input-based attacks (injection, path traversal, archive bombs) from untrusted imported data
4. Accidental exposure of dangerous capabilities that are off by default

The platform does not protect against:
- A compromised assessment host operating system
- A compromised superadmin account
- Attackers with physical or hypervisor-level access to the host
- Misconfigured network infrastructure (exposed Redis, exposed PostgreSQL)

These are deployer responsibilities, documented in [INSTALLATION.md](INSTALLATION.md).

---

## Authentication

### Mechanism

Authentication uses JWT tokens signed with HMAC-SHA256 using `SECRET_KEY`. Tokens are transported exclusively as httpOnly cookies, which prevents JavaScript from reading them and blocks a class of XSS-based session theft.

Tokens carry:
- `sub` — user ID
- `exp` — expiry timestamp (default: 60 minutes, configurable)
- `role` — role at time of issuance

Token issuance happens at `POST /api/auth/login`. Tokens are not refreshed — the user re-authenticates when the token expires.

### Session termination

`POST /api/auth/logout` records a per-user `tokens_invalidated_at` timestamp, clears the httpOnly cookie, and evicts the token from the in-process authentication cache. Any token issued at or before that timestamp is rejected on later use.

If all tokens must be invalidated immediately (for example, after `SECRET_KEY` exposure), rotate `SECRET_KEY`. That invalidates every signed token for every user simultaneously.

### Production requirements

| Requirement | Enforcement |
|---|---|
| `SECRET_KEY` minimum length 32 characters | Startup validation, rejects on failure |
| `AUTH_COOKIE_SECURE=true` when `ENVIRONMENT=production` | Startup validation, rejects on failure |
| HTTPS required for Secure cookie transport | Deployer responsibility |

---

## Authorization

### Role model

| Role | Permissions |
|---|---|
| `superadmin` | All operations including user management and dangerous capability execution |
| `analyst` | Create and manage assessments, trigger jobs, import data, use AI operator |
| `readonly` | Read-only access to assessments and findings they are granted access to |

### Enforcement

Authorization is checked at the route handler level using FastAPI dependency injection. Every route that requires authentication declares a dependency on `get_current_user()`, which extracts and validates the JWT from the cookie. Routes that require a specific role declare an additional dependency on `require_role(role)`.

The route security matrix documenting the auth requirements of every endpoint is maintained in [apps/api/docs/ROUTE_SECURITY_MATRIX.md](../apps/api/docs/ROUTE_SECURITY_MATRIX.md).

### Dangerous capability gate

Dangerous capabilities (`ENABLE_COMMAND_EXECUTION`, `ENABLE_AI_ARBITRARY_SHELL`, `ENABLE_CHAIN_BUILDER`, `ENABLE_TUNNEL_MANAGEMENT`) are checked at the route handler level in addition to authentication. If the corresponding environment variable is `false`, the endpoint returns `403 Forbidden` regardless of the caller's role.

---

## Input validation

### Archive import

Collector ZIP archives pass through four validation gates before extraction:

1. **Magic byte check** — The file must begin with a valid ZIP magic byte sequence (`PK\x03\x04`). Non-ZIP files are rejected before any extraction attempt.
2. **Member count limit** — Archives with more than `ZIP_MAX_MEMBERS` (default: 256) entries are rejected. This prevents ZIP bombs with many small files.
3. **Uncompressed size limit** — The total uncompressed size across all members must be below `ZIP_MAX_UNCOMPRESSED_BYTES` (default: 256 MB). This prevents ZIP bombs that expand to fill disk.
4. **Compression ratio limit** — Any individual member with a compression ratio exceeding `ZIP_MAX_RATIO` (default: 100:1) causes the entire archive to be rejected.
5. **Path traversal check** — Any archive member whose extracted path contains `..` or begins with `/` is rejected. This prevents writing files outside the intended extraction directory.

These checks happen in `_parse_collector_zip` before any member content is read or stored.

### JSON payloads

All API request bodies are validated by Pydantic models with strict typing. Unknown fields are silently ignored. String fields are length-bounded. Enum fields reject values not in the defined enum.

### SQL injection

All database queries use SQLAlchemy's parameterized query interface. Raw SQL strings are not used in application code. SQLAlchemy's async engine handles parameter binding.

### Cross-site scripting

The API returns JSON. HTML rendering happens entirely in the Next.js frontend, which uses React's automatic escaping. The API does not render HTML templates or return HTML content from user-controlled data.

### CORS

The API enforces CORS using the `ALLOWED_ORIGINS` list. Requests from any origin not in this list are rejected at the CORS middleware layer before reaching the route handler. Wildcard origins are rejected in production mode.

---

## Secret handling

### Application secrets

`SECRET_KEY` is the primary cryptographic secret the application manages directly. It signs JWTs and derives the Fernet key used by the database at-rest protection helpers. It must be generated uniquely per deployment, stored outside source control, and rotated after any suspected exposure.

### Database at-rest protection

Sensitive operational fields use SQLAlchemy type decorators backed by Fernet helpers:
- `EncryptedJSON` wraps JSON columns in an encrypted JSON envelope before persistence
- `EncryptedText` stores text values with a versioned encrypted prefix
- Legacy plaintext rows are still readable and are protected the next time they are written

These helpers protect configured sensitive columns such as connectivity profile config, assessment collection config, offensive job steps, job loot, job params, operator approval params, and streamed job output lines. They do not replace host disk encryption, database access controls, or careful backup handling.

### Credential data

Assessment operations may involve domain credentials (usernames and passwords for LDAP, Kerberos, SMB connections). These are:
- Not stored in the database — they are passed through the API to the execution layer at runtime
- Not logged in application logs at INFO level or above
- Never included in job output streaming by design

### Hashes

Credential hashes collected during assessments are stored in the loot module. They are:
- Stored in the database and accessible only to authenticated users
- Classified by hash type (NTLM, Kerberos, NetNTLMv2, etc.)
- Associated with the assessment they were collected during

The application does not perform hash cracking directly — it provides integration points for external tools (Hashcat).

### AI provider keys

`ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, and other provider credentials are read from environment variables and passed directly to the provider SDK. They are not stored in the database, logged, or included in API responses.

---

## Transport security

The API communicates over HTTP when running locally. In production:
- All traffic must be behind a TLS-terminating reverse proxy
- The `AUTH_COOKIE_SECURE=true` setting ensures the session cookie is only transmitted over HTTPS
- WebSocket connections (`wss://`) are required in production

The deployer is responsible for TLS configuration, certificate management, and HTTP-to-HTTPS redirects.

---

## Audit logging

All write operations and all dangerous capability invocations are recorded in the audit log, including:
- User authentication events (login, logout, failed login)
- Assessment creation, modification, and deletion
- Job creation, start, and stop
- Command execution events (when `ENABLE_COMMAND_EXECUTION` is enabled)
- AI operator shell invocations (when `ENABLE_AI_ARBITRARY_SHELL` is enabled)
- User management operations

The audit log is accessible at `GET /api/audit/` and requires superadmin role. Log entries are immutable — they cannot be modified or deleted through the API.

---

## Production startup validation

When `ENVIRONMENT=production`, the application validates the following at startup and terminates with a descriptive error if any check fails:

| Check | Failure condition |
|---|---|
| Secret key strength | `SECRET_KEY` is shorter than 32 characters |
| Secret key default check | `SECRET_KEY` matches any known weak or default value |
| Database type | `DATABASE_URL` is a SQLite connection string |
| Cookie security | `AUTH_COOKIE_SECURE` is `false` |
| CORS policy | `ALLOWED_ORIGINS` contains `*` |
| Debug mode | `DEBUG=true` |

These checks prevent common deployment misconfigurations from reaching production traffic.

---

## Known limitations

- **No distributed token revocation cache** — logout invalidation is persisted per user and the current process cache is evicted, but multi-process deployments may accept a recently cached token until each process refreshes it or the JWT expires. Rotate `SECRET_KEY` for immediate global invalidation after compromise.
- **No rate limiting on all endpoints** — only authentication endpoints are rate limited; internal API endpoints rely on authentication for access control
- **At-rest protection is column-scoped** — selected sensitive operational JSON/text columns are encrypted with Fernet-derived helpers, but not every database field is encrypted. Host disk encryption, database access control, and encrypted backups remain deployer responsibilities
- **SQLite is not safe for production** — the startup validation enforces this, but SQLite provides no access control and no network isolation

---

## Reporting security issues

Follow the process in [SECURITY.md](../SECURITY.md). Do not open public issues for vulnerabilities.

---

*Maintained by [White0xdi3](https://github.com/White0xdi3) — AdByG0d project*
