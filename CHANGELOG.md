# Changelog

All notable changes to AdByG0d are documented here.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.0.0] — 2026-06-08

**Author:** White0xdi3  
**Project:** AdByG0d — Active Directory Security Assessment Platform

Initial public release.

### Added

#### Core platform
- FastAPI backend with async SQLAlchemy 2 and Alembic migrations (20 versions)
- Next.js 15 / React 19 frontend with TypeScript and Tailwind CSS
- Docker Compose development and production configurations
- Celery + Redis async job execution with dedicated queue isolation
- JWT authentication with httpOnly cookie transport and role-based access control
- Superadmin, analyst, and read-only role tiers

#### Evidence ingestion
- BloodHound CE ZIP import pipeline with path traversal protection and ZIP bomb limits
- Legacy BloodHound JSON bundle import
- Native AdByG0d collector ZIP import
- Linux remote collector output import (LDAP, Kerberos, SMB, ADCS)
- Windows local PowerShell collector output import
- Manual entity and finding entry
- Collector ZIP module summary with configurable output preview truncation
- Import job state machine: PENDING → RUNNING → COMPLETED / FAILED

#### Validation engine (16 check categories)
- Kerberoasting — SPN accounts with RC4 encryption and unconstrained delegation
- AS-REP roasting — accounts with pre-authentication disabled
- ADCS ESC paths — ESC1 through ESC16 template and CA misconfiguration detection
- Delegation abuse — unconstrained, constrained, and resource-based constrained delegation
- DCSync rights — non-standard replication ACEs on domain NC roots
- GPO abuse — writable GPOs, dangerous privilege settings, missing scope coverage
- LAPS and gMSA exposure — readable managed passwords and weak access control
- NTLM relay paths — unsigned SMB, unsigned LDAP, LDAP without channel binding
- SID history — legacy SID entries providing shadow privilege escalation paths
- Shadow credentials — msDS-KeyCredentialLink abuse vector detection
- Trust relationships — cross-domain and cross-forest trust posture mapping
- Password policy — reversible encryption, no complexity, excessive lockout thresholds
- ACL analysis — WriteDACL, GenericAll, GenericWrite, AddMember exposure
- Privileged group membership — tier-0 group enumeration
- Service account exposure — weak SPNs, over-privileged accounts
- Cloud interface — Azure AD Connect, AD FS, and hybrid-join surface identification

#### Graph engine
- Attack-path analysis with shortest-path queries across EntityType and EdgeType enum space
- Blast-radius scoring from any owned node
- Domain dominance detection with tier-0 node reachability
- MITRE ATT&CK technique mapping (TA0003, TA0004, TA0006, TA0008)
- Graph layout persistence, community detection, and centrality scoring
- WebSocket-based live graph delta broadcast
- Monte Carlo simulation for path probability scoring
- Choke-point and neighborhood queries
- Snapshot diffing across assessment runs

#### Operations
- Live job output streaming via SSE and WebSocket
- AD command catalog with pre-built queries across 20+ categories
- Kill chain tracker with phase progression and annotation
- Loot management with hash classification and Hashcat integration
- Tunnel management — Chisel and ligolo-proxy lifecycle control
- Recon surface mapping — coercion targets, relay paths, exposed services
- Lateral movement path enumeration
- Playbook export with phase sequencing
- Synthetic evidence generation for training and capability testing

#### Reporting
- PDF and DOCX report generation with severity breakdown
- Assessment comparison diffing across time
- Posture timeline visualization
- Global risk scoring per assessment
- Evidence export in JSON and ZIP formats

#### AI operator (optional, off by default)
- Claude, OpenAI, and Ollama provider support
- Technique suggestions, target card generation, output analysis, playbook generation
- Arbitrary shell execution gated behind explicit environment flags and human approval
- Provider capability negotiation and health testing

#### Security controls
- ZIP archive validation: 256-member limit, 256 MB uncompressed limit, 100:1 compression ratio limit
- Production startup validation — rejects weak `SECRET_KEY`, SQLite, insecure CORS, and cookie config
- Audit log for all write operations and dangerous capability invocations
- Rate limiting on authentication endpoints
- Dangerous capability flags — all off by default, require explicit environment variable enablement

#### Developer tooling
- pytest test suite with 100+ tests and asyncio + SQLite in-memory test isolation
- pytest-xdist parallel execution support
- Ruff linting configuration
- GitHub Actions CI pipeline — backend, frontend, and release hygiene checks
- Release archive safety check — blocks tracked secrets and sensitive file patterns
- Synthetic AD domain fixture generator (users, computers, groups, GPOs, cert templates, findings)

### Security

- All dangerous execution capabilities are disabled by default
- See [SECURITY.md](SECURITY.md) for the vulnerability reporting policy

---

## [Unreleased]

No unreleased changes at this time.

---

*Maintained by [White0xdi3](https://github.com/White0xdi3)*
