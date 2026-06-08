<p align="center">
  <img src="docs/screenshots/banner.jpg" alt="AdByG0d" width="100%" />
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.12-3572A5?style=flat-square&logo=python&logoColor=white" alt="Python" />
  <img src="https://img.shields.io/badge/Platform-Linux%20%7C%20Docker-166534?style=flat-square&logo=linux&logoColor=white" alt="Platform" />
  <img src="https://img.shields.io/badge/Expert%20Modules-25%2B-7c3aed?style=flat-square" alt="Expert Modules" />
  <img src="https://img.shields.io/badge/Kill--Chain-9%20Phases-ea580c?style=flat-square" alt="Kill-Chain" />
  <img src="https://img.shields.io/badge/AD%20Commands-752%20Entries-c2410c?style=flat-square" alt="AD Commands" />
  <img src="https://img.shields.io/badge/License-MIT-ca8a04?style=flat-square" alt="License" />
</p>
<p align="center">
  <img src="https://img.shields.io/badge/Author-White0xdi3-0891b2?style=flat-square" alt="Author" />
</p>

---

> **Authorized use only.** Run AdByG0d only against domains and systems you own or have explicit written permission to assess. You are fully responsible for legal compliance, protecting any evidence you collect, and handling credentials and secrets safely.

## Screenshots

<p align="center">
  <img src="docs/screenshots/launch-screen.png" alt="Launch Screen" width="49%" />
  <img src="docs/screenshots/dashboard.png" alt="Dashboard" width="49%" />
</p>
<p align="center">
  <img src="docs/screenshots/findings.png" alt="Findings" width="49%" />
  <img src="docs/screenshots/identity-graph.png" alt="Identity Graph" width="49%" />
</p>

---

## Features

### Evidence ingestion
- Import BloodHound CE ZIPs, legacy BloodHound JSON bundles, and native collector ZIPs
- Import output from the Linux remote collector (Python, LDAP/SMB/Kerberos) or Windows local collector (PowerShell)
- Manual entity and finding entry for evidence collected outside the platform
- Entity and edge deduplication with conflict resolution on re-import
- Bulk insertion with chunked processing (500-item batches)
- Evidence quality scoring: FRAGILE → WEAK → MODERATE → STRONG
- Evidence type tracking: COLLECTED, IMPORTED, INFERRED, SIMULATED
- Provenance badge per finding showing which sources corroborate each conclusion

### Validation engine — 25+ expert modules
- **Kerberoasting** — SPN accounts with RC4 encryption, unconstrained delegation, stale service accounts, weak password policy
- **AS-REP roasting** — pre-authentication disabled, no-preauth enumeration exposure
- **ADCS ESC paths** — ESC1–ESC16 template and CA misconfigurations; enrollment right and write right analysis; CA flag exposure
- **Delegation abuse** — unconstrained, constrained, and resource-based constrained delegation; delegation chain traversal; machine account quota exploitation
- **DCSync rights** — non-standard replication ACEs on domain and NC roots
- **ACL abuse** — GenericAll, WriteDacl, WriteOwner, GenericWrite, AddMember, ForceChangePassword; AdminSDHolder analysis; ownership abuse
- **GPO abuse** — writable GPOs, GPP cpassword in SYSVOL, machine vs. user scope gaps, scheduled task injection via GPO
- **LAPS exposure** — readable LAPS passwords, coverage gaps, expiry risks
- **gMSA exposure** — readable managed service account passwords
- **Shadow credentials** — msDS-KeyCredentialLink alternate-credential abuse
- **SID history** — legacy SID entries enabling shadow privilege across trust boundaries
- **Trust relationships** — cross-domain and cross-forest trust posture; SID filtering and selective authentication; transitive trust chains; forest pivot vectors
- **NTLM relay paths** — unsigned SMB, LDAP without channel binding, coercion surface enumeration
- **Password policy** — reversible encryption, no complexity requirement, excessive lockout threshold, fine-grained policy gaps
- **Network posture** — tier separation analysis, network segmentation and segregation assessment
- **Service account privilege** — over-privileged service accounts, delegation risks, stale principals
- **Recon exposure** — information disclosure scoring, anonymous binding, unauthenticated enumeration surface
- **Pre-2000 machine exposure** — legacy machine account vulnerability analysis
- **Domain configuration** — functional level assessment, security baseline gaps
- **Timeroasting** — service principal enumeration risk via timestamp abuse
- **WSUS exposure** — WSUS misconfiguration abuse vectors
- Consensus fusion: expert decisions aggregated with confidence bands and contradiction detection
- Remediation playbook and MITRE technique mapping generated per finding

### Graph engine
- Interactive force-directed graph with support for 400+ entities and edges
- Attack-path computation with shortest-path queries and timeout protection
- Choke point identification — critical junctions that collapse multiple paths
- Blast-radius scoring from any owned node (reachable computers, DCs, domains, groups, users)
- Domain dominance detection — tier-0 node reachability analysis
- Alternative path detection after simulated remediation steps
- Monte Carlo path success probability simulation
- Edge removal and path re-computation for counterfactual analysis
- Graph layout persistence (save and restore node positions)
- Assessment snapshot diffing — compare two graph states over time
- Fullscreen mode, streaming updates, and LRU-cached graph rendering

### Kill chain & attack progression
- 9-phase MITRE ATT&CK kill chain tracker: Reconnaissance through Exfiltration
- Phase completion percentage and technique coverage metrics
- Technique execution history with timestamps
- Finding alignment to kill chain phase
- Next-technique suggestions based on coverage gaps
- Multi-step attack chain construction and execution (feature-gated)
- OPSEC profile selection per chain: BALANCED, AGGRESSIVE, STEALTH
- WebSocket progress streaming for live chain execution

### Loot & credential management
- Hash vault: NTLM, LM, Kerberos TGT/TGS, MSCash2, NetNTLMv1/v2, DPAPI, LAPS, gMSA
- Live hash collection via DCSync, Secretsdump, NTDS VSS, AS-REP Roast, Kerberoast
- Manual hash ingest with automatic type classification
- Integrated cracking: Hashcat and John the Ripper with automatic tool selection
- Wordlist support: rockyou.txt and custom wordlists with path allowlist enforcement
- Distributed crack job queue with Redis backing and result persistence
- PTH readiness assessment — flags which hashes can be used directly for lateral movement
- Credential export with sensitive value redaction for reports

### Offensive operations (feature-gated)
- 100+ offensive technique IDs mapped to impacket, certipy, Rubeus, and custom tools
- **Reconnaissance**: LDAP enum, SMB enum, rpcdump, nmap, lookupsid, samrdump, NetView, ACL enum, GPO enum, delegation enum
- **Kerberos attacks**: Kerberoast, AS-REP Roast, TGT/TGS acquisition, ticket forging, Rubeus monitoring
- **Credential access**: DCSync, Secretsdump, registry query, LAPS dump, gMSA dump
- **Lateral movement / execution**: SMBExec, WMIExec, ATExec, PSExec
- **Coercion and relay**: PrinterBug, PetitPotam, DFSCoercion, NTLMRelayx (SMB and ADCS modes)
- **Certificate abuse**: Certipy find/request/auth/template, shadow credential write
- **Object abuse**: DACLEdit, RBCD write, Whisker
- **Persistence**: AddComputer, ChangePassword, machine rename
- **SCCM**: SCCM enumeration, NAA credential extraction
- **GPO injection**: Scheduled task injection via Group Policy
- **CVE exploits**: Zerologon (CVE-2020-1472) with safe restore path
- All jobs streamed live via SSE with per-step output capture

### AD command catalog
- 752 AD exploitation commands across Reconnaissance, Lateral Movement, Privilege Escalation, Persistence, and Defense Evasion
- Full syntax reference with Linux and Windows platform variants
- Tunnel-aware execution (direct or through SOCKS5 / chisel / ligolo)

### Obfuscation & OPSEC
- 14 obfuscation variants: attribute ordering randomization, Base64 encoding, timing jitter, LDAP query permutation, and more
- Configurable 0–10 000 ms random inter-step jitter
- OPSEC advisor integration per technique and chain
- Command plan generation with step-by-step preview before execution

### Tunneling & connectivity
- SSH tunnel orchestration with connection tracking
- Chisel reverse proxy deployment and server status monitoring
- Ligolo-proxy agent management
- Multi-hop tunnel chains with port allocation
- SOCKS5 proxy configuration for tool routing
- Connectivity profile modes: DIRECT, SSH, LIGOLO, CHISEL
- Connectivity test with multi-probe verification

### Collectors
- **Linux remote collector** — Python, runs from any Linux host with network access:
  - Full domain enumeration: users, groups, computers, OUs, GPOs, trusts, DCs, DNS, LAPS
  - ACL abuse enumeration (GenericAll, WriteDacl, WriteOwner, GenericWrite, AddMember)
  - ADCS template discovery and ESC exposure detection
  - Kerberos posture: Kerberoastable accounts, AS-REP roastable, delegation types
  - Credential discovery: LAPS passwords, gMSA, fine-grained password policies
  - SMB signing, encryption, and relay surface checks
  - Coercion surface detection: PrinterBug, PetitPotam, DFSCoercion
  - Persistence indicator enumeration: shadow admins, hidden groups, Backup Operators
  - Auth methods: NTLM, SIMPLE, ANONYMOUS
- **Windows local collector** — PowerShell, runs on a domain-joined host:
  - Full AD collection output as importable ZIP
  - ADCS CA flags and certificate template enumeration

### Reporting & export
- Multi-format export: PDF dossier, HTML briefing, JSON evidence pack, CSV register
- 19+ configurable report sections: executive summary, technical findings, evidence pack, remediation roadmap, MITRE coverage matrix, threat actor alignment, kill chain progression, risk themes, priority action board, control effectiveness, validation history, and more
- Evidence redaction — loot values and plaintext credentials stripped from exported reports
- Report readiness scoring before generation
- Provenance labeling per data point

### Remediation planning
- Ranked remediation candidate list by composite risk score
- Wave-based fix sequencing with dependency detection
- Simulated remediation impact — path elimination estimate without making live changes
- Risk reduction percentage and blast-radius reduction projection per fix
- Operational impact assessment per remediation action

### Assessment management
- Multi-assessment workspace with full lifecycle: QUEUED → RUNNING → COMPLETED / FAILED
- Collection mode support: PASSIVE, DIRECT, REMEDIATE
- Module coverage tracking — which validation modules ran per assessment
- Assessment diffing — compare two snapshots to surface regressions or improvements
- Dashboard aggregation: entity counts, severity distribution, coverage heatmap

### Operations and reporting
- Live job output streaming via SSE and WebSocket
- Celery-backed async job execution with queue isolation
- Kill chain tracker with phase progression
- Loot management with hash classification and cracking workflow integration

### AI operator (optional)
- Provider support: Claude (Anthropic), OpenAI, and Ollama (local)
- Next-step technique suggestion scoped to current MITRE kill chain phase
- Automated playbook generation from active findings
- Tool output analysis and technique explanation
- BloodHound graph interpretation and narrative generation
- Persistent engagement memory store across operator sessions
- Approval workflow — dangerous actions require explicit human sign-off before execution
- Campaign orchestration for multi-step autonomous operation
- OPSEC advisor integration — flags high-noise or risky suggestions
- Full audit log of every AI action for compliance review
- Disabled entirely unless API keys and execution flags are explicitly configured
- Arbitrary shell and auto-execution require explicit flags and human approval

### User management & access control
- Role-based access: operator and superadmin tiers
- Assessment-scoped workspace isolation
- JWT authentication with token revocation and 60-second cache TTL
- Cookie-based and Bearer token auth support
- CSRF protection via Origin/Referer validation
- In-memory login rate limiting (5 attempts per 300 s window, per IP and identifier)
- Password hashing with pbkdf2_sha256 and bcrypt

### Audit & compliance
- Full audit trail: authentication events, data mutations, validation runs, report actions
- IP address and user agent capture per event
- Resource-level action logging (resource type, resource ID, action detail)
- All dangerous execution actions logged with user, timestamp, and context
- Encryption-at-rest for sensitive JSON fields with key rotation support

---

## Architecture

```
AdByG0d/
├── apps/
│   ├── api/                        FastAPI backend
│   │   ├── src/adbygod_api/
│   │   │   ├── core/
│   │   │   │   ├── ai_operator/    AI operator engine, tools, campaign, approval workflow
│   │   │   │   ├── analyzers/      Rule engine, lateral movement, trust, ACL, GPO, scoring
│   │   │   │   ├── arsenal/        CVE database and exploit catalog
│   │   │   │   ├── chains/         Attack chain builder and execution
│   │   │   │   ├── collection/     LDAP/SMB direct collection modules
│   │   │   │   ├── commands/       AD command catalog (752 entries)
│   │   │   │   ├── connectivity/   Tunnel and pivoting layer (SSH, Chisel, Ligolo)
│   │   │   │   ├── graph/          Attack path engine, blast radius, choke points
│   │   │   │   ├── kill_chain/     MITRE ATT&CK phase tracker
│   │   │   │   ├── loot/           Hash vault, cracking jobs, credential management
│   │   │   │   ├── parsers/        BloodHound ZIP/JSON, collector output parsers
│   │   │   │   ├── pipeline/       Ingestion pipeline, obfuscation transformer
│   │   │   │   ├── recon/          Recon scan engine
│   │   │   │   ├── reports/        PDF/HTML/JSON/CSV report generation
│   │   │   │   ├── security/       Auth, CSRF, rate limiting, privilege checks
│   │   │   │   └── validation/     25+ expert modules, consensus engine, scoring
│   │   │   ├── routes/             35+ API route groups (REST + WebSocket + SSE)
│   │   │   ├── services/           Cross-cutting service layer
│   │   │   └── data/               AD command definitions
│   │   ├── alembic/                Database migrations (20 versions)
│   │   ├── tests/                  Backend test suite (110+ tests)
│   │   └── scripts/                Admin bootstrap and seed utilities
│   └── web/                        Next.js 15 frontend
│       └── src/app/                37 pages — dashboard, graph, findings, loot,
│                                   ops, kill-chain, validation, paths, pki,
│                                   trusts, recon, enumeration, arsenal, loot,
│                                   remediation, reports, audit, ai-operator, settings
├── collectors/
│   ├── linux_remote/               Python collector — LDAP, Kerberos, SMB, ADCS,
│   │                               ACL abuse, coercion, persistence indicators
│   └── windows_local/              PowerShell collector — full AD + ADCS CA flags
├── data/samples/                   Synthetic BloodHound fixtures for testing
├── docs/                           Setup, configuration, and security docs
└── scripts/                        Dev environment, start/stop, release helpers
```

**Backend:** Python 3.12, FastAPI, SQLAlchemy 2, Alembic, Celery, Redis  
**Frontend:** Next.js 15, React 19, TypeScript, Tailwind CSS  
**Database:** SQLite (local dev only), PostgreSQL 15+ (production required)  
**Deployment:** Docker Compose (dev and production variants)  
**Real-time:** WebSocket + SSE for job streaming, graph updates, and chain execution

---

## Quick start with Docker

The fastest way to run AdByG0d locally:

```bash
git clone <repo-url> AdByG0d
cd AdByG0d

# Copy the example env file
cp .env.docker.example .env

# Generate a strong secret key and set it in .env
python3 -c "import secrets; print(secrets.token_urlsafe(48))"
# Edit .env and paste the output as the value of SECRET_KEY

# Build and start all services
docker compose up --build
```

This starts four services: Redis, the API, the Celery worker, and the Next.js frontend.

| Service | URL |
|---|---|
| Web UI | http://localhost:3000 |
| API | http://localhost:8000 |
| API docs (dev only) | http://localhost:8000/docs |

On first run, create an admin account using the bootstrap script:

```bash
docker compose exec api python scripts/bootstrap_admin.py
```

---

## Manual local setup

### Prerequisites

| Requirement | Version |
|---|---|
| Python | 3.12 or later |
| Node.js | 20 or later |
| npm | 10 or later |
| Redis | 7 or later |
| PostgreSQL | 15 or later (production only) |

SQLite is used automatically for local development — no database setup required.

---

### Backend

```bash
cd apps/api

# Create and activate a virtual environment
python3 -m venv .venv
source .venv/bin/activate        # Linux/macOS
# .venv\Scripts\activate         # Windows

# Install dependencies
pip install --upgrade pip
pip install -r requirements.txt

# Copy and configure the environment file
cp .env.example .env

# Generate a secret key
python3 -c "import secrets; print(secrets.token_urlsafe(48))"
# Paste the output into SECRET_KEY in .env

# Run database migrations
PYTHONPATH=src alembic upgrade head

# Start the API server
PYTHONPATH=src uvicorn adbygod_api.main:app --reload --host 0.0.0.0 --port 8000
```

The API is now running at http://localhost:8000. Interactive docs are available at http://localhost:8000/docs when `DEBUG=true`.

---

### Celery worker

Async jobs (command execution, report generation, hash cracking) require the worker. Start it in a second terminal:

```bash
cd apps/api
source .venv/bin/activate

PYTHONPATH=src celery -A adbygod_api.core.celery_app:celery_app worker \
  --loglevel=info \
  --queues=offensive_jobs \
  --concurrency=4
```

Make sure Redis is running before starting the worker. The worker connects to the URL in `CELERY_BROKER_URL`.

---

### Frontend

```bash
cd apps/web

# Install dependencies
npm install

# Copy and configure the environment file
cp .env.example .env.local
# Default config points the frontend at http://localhost:8000

# Start the development server
npm run dev
```

The frontend is now running at http://localhost:3000.

---

### Create the first admin account

With the API running:

```bash
cd apps/api
source .venv/bin/activate
PYTHONPATH=src python scripts/bootstrap_admin.py
```

Follow the prompts to set a username, email, and password. This account gets the superadmin role and can create additional users through the settings page.

---

## Production deployment

### Docker production setup

```bash
cp .env.docker.example .env
```

Edit `.env` and set these before deploying:

```bash
SECRET_KEY=<generate with: python3 -c "import secrets; print(secrets.token_urlsafe(48))">
POSTGRES_PASSWORD=<strong unique password>
ALLOWED_ORIGINS=https://your-domain.com
NEXT_PUBLIC_API_URL=https://api.your-domain.com
ENVIRONMENT=production
DEBUG=false
AUTH_COOKIE_SECURE=true
```

Then start the production stack:

```bash
docker compose -f docker-compose.prod.yml up --build -d
```

### Production requirements

- Run the API and frontend behind a TLS-terminating reverse proxy (nginx, Caddy, Traefik)
- PostgreSQL is required in production — SQLite will be rejected at startup
- Do not expose Redis or PostgreSQL ports publicly
- Set `ALLOWED_ORIGINS` to your exact frontend origin — no wildcards
- Set `AUTH_COOKIE_SECURE=true` — required when running behind HTTPS

---

## Environment variables

### Critical variables (must set before running)

| Variable | Purpose | Example |
|---|---|---|
| `SECRET_KEY` | Signs all JWT tokens — rotate immediately if exposed | `python3 -c "import secrets; print(secrets.token_urlsafe(48))"` |
| `DATABASE_URL` | SQLAlchemy connection string | `postgresql+asyncpg://adbygod:password@localhost:5432/adbygod` |
| `REDIS_URL` | Redis pub-sub and job streams | `redis://localhost:6379/0` |
| `CELERY_BROKER_URL` | Celery task queue | `redis://localhost:6379/1` |
| `ALLOWED_ORIGINS` | Comma-separated CORS origins | `https://adbygod.example.com` |
| `AUTH_COOKIE_SECURE` | HTTPS-only cookie enforcement | `true` (required in production) |

### Dangerous capability flags (all off by default)

| Variable | What it enables |
|---|---|
| `ENABLE_COMMAND_EXECUTION` | Command execution from the AD command catalog |
| `ENABLE_AI_ARBITRARY_SHELL` | AI operator shell tool (requires ENABLE_COMMAND_EXECUTION) |
| `ENABLE_CHAIN_BUILDER` | Multi-step operation workflows |
| `ENABLE_TUNNEL_MANAGEMENT` | Chisel/ligolo-proxy tunnel process management |

Enable these only in isolated, authorized environments. See [docs/DANGEROUS_FEATURES.md](docs/DANGEROUS_FEATURES.md).

Full reference: [docs/CONFIGURATION.md](docs/CONFIGURATION.md)

---

## Database migrations

```bash
cd apps/api

# Apply all pending migrations
PYTHONPATH=src alembic upgrade head

# Check current migration version
PYTHONPATH=src alembic current

# View migration history
PYTHONPATH=src alembic history
```

The Docker image runs `alembic upgrade head` automatically before the API starts.

---

## Running the test suite

Run from the repository root:

```bash
# Python syntax check
python -m compileall -q apps/api/src collectors/linux_remote/src

# Linting
python -m ruff check apps/api/src collectors/linux_remote/src apps/api/tests

# Backend tests
python -m pytest apps/api/tests -q

# Frontend lint and type check
npm --prefix apps/web run lint
npm --prefix apps/web run type-check -- --pretty false

# Full build verification
npm --prefix apps/web run build
```

Minimum environment for backend tests:

```bash
export SECRET_KEY=test-key-not-real-1234567890abcdef
export DEBUG=true
export ENVIRONMENT=development
```

See [docs/TESTING.md](docs/TESTING.md) for CI notes and dependency details.

---

## Collectors

### Linux remote collector

The Python collector runs from any Linux host with network access to the target domain:

```bash
cd collectors/linux_remote
pip install -r requirements.txt   # or use the included venv
python -m adbygod_collector --help
```

Supports LDAP, Kerberos, SMB, ADCS, coercion surface detection, and ACL collection.

### Windows local collector

Run from a domain-joined Windows host:

```powershell
# Full collection
.\Collect-AdByG0d.ps1

# ADCS CA flags collection
.\Collect-AdByG0d-ADCS-CAFlags.ps1
```

Output is a ZIP archive that imports directly into AdByG0d via the web interface.

---

## Security

- All dangerous execution features are off by default and require explicit environment flags
- The API validates production settings at startup and refuses to start with weak configuration
- Imported archives are validated for size and path traversal before extraction
- See [docs/SECURITY_MODEL.md](docs/SECURITY_MODEL.md) for the full security model
- Report vulnerabilities per [SECURITY.md](SECURITY.md)

---

## Limitations

- Validation quality depends directly on the completeness of imported evidence — missing data means missing findings
- Some checks require domain reachability and specific tooling (impacket, certipy, BloodHound) to be installed on the assessment host
- The AI operator makes mistakes and must not run unattended or without human review of each suggested action
- Production hardening — TLS, database access control, Redis network isolation, host security — is the deployer's responsibility

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Do not submit real credentials, client data, screenshots with sensitive content, hashes from real environments, or raw engagement evidence.

## License

MIT — see [LICENSE](LICENSE)
