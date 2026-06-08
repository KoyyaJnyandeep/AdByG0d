# Route Security Matrix

This document maps every API endpoint to its authentication requirement, minimum role, and any additional capability flags required.

**Author:** White0xdi3  
**Project:** AdByG0d — Active Directory Security Assessment Platform

All routes are mounted under the `API_PREFIX` (default: `/api`). A full path example: `GET /api/assessments/`.

---

## Legend

| Symbol | Meaning |
|---|---|
| `none` | No authentication required |
| `any` | Valid JWT required, any role |
| `analyst` | Analyst or superadmin role required |
| `superadmin` | Superadmin role required |
| `flag:X` | Additional capability flag must be `true` |
| `setup` | Only available when initial setup is incomplete |

---

## Public endpoints

No authentication required.

| Method | Path | Notes |
|---|---|---|
| `GET` | `/api/public/health` | Health check — returns environment and status |
| `GET` | `/api/public/assessment-summary` | Aggregate counts across all assessments |
| `GET` | `/api/public/assessments-list` | List of assessment names and IDs |

---

## Authentication (`/api/auth/`)

| Method | Path | Auth | Notes |
|---|---|---|---|
| `POST` | `/api/auth/login` | `none` | Issues JWT cookie |
| `POST` | `/api/auth/logout` | `any` | Clears JWT cookie |
| `GET` | `/api/auth/me` | `any` | Returns current user details |
| `PUT` | `/api/auth/profile` | `any` | Update own display name |

---

## Initial setup (`/api/setup/`)

| Method | Path | Auth | Notes |
|---|---|---|---|
| `GET` | `/api/setup/status` | `none` | Returns whether initial setup is complete |
| `POST` | `/api/setup/init` | `setup` | Create first superadmin — blocked after setup completes |
| `PUT` | `/api/setup/update` | `any` | Update own account profile |
| `DELETE` | `/api/setup/reset` | `any` | Delete own account |

---

## User management (`/api/users/`)

All user management requires superadmin role.

| Method | Path | Auth | Notes |
|---|---|---|---|
| `GET` | `/api/users/` | `superadmin` | List all users |
| `POST` | `/api/users/` | `superadmin` | Create user |
| `GET` | `/api/users/{user_id}` | `superadmin` | Get user details |
| `PUT` | `/api/users/{user_id}` | `superadmin` | Update user (role, active status) |
| `POST` | `/api/users/{user_id}/activate` | `superadmin` | Activate a deactivated user |
| `POST` | `/api/users/{user_id}/deactivate` | `superadmin` | Deactivate a user |

---

## Assessments (`/api/assessments/`)

| Method | Path | Auth | Notes |
|---|---|---|---|
| `GET` | `/api/assessments/` | `any` | List assessments accessible to the current user |
| `POST` | `/api/assessments/` | `analyst` | Create assessment |
| `GET` | `/api/assessments/{assessment_id}` | `any` | Get assessment details |
| `PUT` | `/api/assessments/{assessment_id}` | `analyst` | Update assessment |
| `DELETE` | `/api/assessments/{assessment_id}` | `analyst` | Delete assessment and all associated data |
| `GET` | `/api/assessments/{assessment_id}/dashboard` | `any` | Dashboard summary metrics |
| `GET` | `/api/assessments/{assessment_id}/stats` | `any` | Finding statistics |

---

## Findings (`/api/findings/`)

| Method | Path | Auth | Notes |
|---|---|---|---|
| `GET` | `/api/findings/` | `any` | List findings (filter by assessment) |
| `POST` | `/api/findings/` | `analyst` | Create finding |
| `GET` | `/api/findings/{finding_id}` | `any` | Get finding details |
| `PUT` | `/api/findings/{finding_id}` | `analyst` | Update finding |
| `DELETE` | `/api/findings/{finding_id}` | `analyst` | Delete finding |
| `POST` | `/api/findings/{finding_id}/evidence` | `analyst` | Attach evidence to finding |

---

## Entities (`/api/entities/`)

| Method | Path | Auth | Notes |
|---|---|---|---|
| `GET` | `/api/entities/` | `any` | List entities (filter by assessment) |
| `POST` | `/api/entities/` | `analyst` | Create entity |
| `GET` | `/api/entities/{entity_id}` | `any` | Get entity details |
| `PUT` | `/api/entities/{entity_id}` | `analyst` | Update entity |
| `DELETE` | `/api/entities/{entity_id}` | `analyst` | Delete entity |

---

## Graph engine (`/api/graph/`)

| Method | Path | Auth | Notes |
|---|---|---|---|
| `GET` | `/api/graph/{assessment_id}` | `any` | Get full graph for assessment |
| `GET` | `/api/graph/{assessment_id}/paths` | `any` | Attack path enumeration |
| `POST` | `/api/graph/{assessment_id}/compute-paths` | `analyst` | Trigger path computation job |
| `GET` | `/api/graph/{assessment_id}/blast-radius` | `any` | Blast-radius from owned nodes |
| `GET` | `/api/graph/{assessment_id}/centrality` | `any` | Node centrality scores |
| `GET` | `/api/graph/{assessment_id}/communities` | `any` | Community detection |
| `GET` | `/api/graph/{assessment_id}/choke-points` | `any` | Choke-point analysis |
| `GET` | `/api/graph/{assessment_id}/anomalies` | `any` | Structural anomaly detection |
| `POST` | `/api/graph/{assessment_id}/monte-carlo` | `analyst` | Monte Carlo path probability |
| `GET` | `/api/graph/{assessment_id}/simulate-removal` | `any` | Simulate node removal impact |
| `GET` | `/api/graph/{assessment_id}/neighborhood/{node_id}` | `any` | Node neighborhood query |
| `POST` | `/api/graph/{assessment_id}/nl-query` | `analyst` | Natural language graph query |
| `POST` | `/api/graph/{assessment_id}/narrate-path` | `analyst` | AI-generated path narrative |
| `GET` | `/api/graph/{assessment_id}/snapshot` | `any` | Current graph snapshot |
| `GET` | `/api/graph/{assessment_id}/snapshots` | `any` | Historical snapshot list |
| `GET` | `/api/graph/{assessment_id}/diff` | `any` | Graph diff between snapshots |
| `GET` | `/api/graph/{assessment_id}/diff-assessment` | `any` | Graph diff across assessments |
| `GET` | `/api/graph/{assessment_id}/layout` | `any` | Get saved layout |
| `PUT` | `/api/graph/{assessment_id}/layout/{layout_name}` | `analyst` | Save layout |
| `DELETE` | `/api/graph/{assessment_id}/layout/{layout_name}` | `analyst` | Delete layout |
| `GET` | `/api/graph/{assessment_id}/views` | `any` | Saved graph views |
| `POST` | `/api/graph/{assessment_id}/views` | `analyst` | Save graph view |
| `DELETE` | `/api/graph/{assessment_id}/views/{view_id}` | `analyst` | Delete graph view |
| `GET` | `/api/graph/{assessment_id}/markings` | `any` | Node markings (owned, controlled) |
| `PUT` | `/api/graph/{assessment_id}/markings` | `analyst` | Update node markings |
| `WS` | `/api/graph/ws/{chain_id}` | `any` | WebSocket graph delta stream |

---

## Data ingest (`/api/ingest/`)

| Method | Path | Auth | Notes |
|---|---|---|---|
| `POST` | `/api/ingest/collector-zip` | `analyst` | Upload and parse a collector ZIP |
| `GET` | `/api/ingest/modules` | `any` | List parsed modules from an import |
| `GET` | `/api/ingest/modules/summary` | `any` | Module output summaries |

---

## Data import (`/api/import/`)

| Method | Path | Auth | Notes |
|---|---|---|---|
| `POST` | `/api/import/` | `analyst` | Start import from parsed collector data |
| `GET` | `/api/import/{assessment_id}` | `any` | Import status for an assessment |
| `POST` | `/api/import/analyze-bloodhound` | `analyst` | Analyze a BloodHound ZIP before import |
| `GET` | `/api/import/{assessment_id}/bloodhound` | `any` | BloodHound import details |

---

## Collection (`/api/collection/`)

| Method | Path | Auth | Notes |
|---|---|---|---|
| `POST` | `/api/collection/collect` | `analyst` | Trigger remote Linux collector |
| `GET` | `/api/collection/scans` | `any` | List collection scans |
| `GET` | `/api/collection/scan/{scan_id}` | `any` | Scan details and status |
| `GET` | `/api/collection/scan/{scan_id}/output` | `any` | Streaming scan output |
| `WS` | `/api/collection/ws/scan/{scan_id}` | `any` | WebSocket scan output stream |

---

## Jobs (`/api/jobs/`)

| Method | Path | Auth | Notes |
|---|---|---|---|
| `GET` | `/api/jobs/` | `any` | List all jobs |
| `GET` | `/api/jobs/{job_id}` | `any` | Job details and status |
| `GET` | `/api/jobs/{job_id}/output` | `any` | Job output (paginated) |
| `POST` | `/api/jobs/{job_id}/stop` | `analyst` | Cancel running job |
| `GET` | `/api/jobs/stream/{job_id}` | `any` | SSE job output stream |
| `WS` | `/api/jobs/ws/jobs/{job_id}` | `any` | WebSocket job output stream |

---

## Validation engine (`/api/validation/`)

| Method | Path | Auth | Notes |
|---|---|---|---|
| `POST` | `/api/validation/simulate/{module_id}/{assessment_id}` | `analyst` | Run a validation module |
| `POST` | `/api/validation/simulate-all/{assessment_id}` | `analyst` | Run all validation modules |
| `GET` | `/api/validation/stream/{module_id}/{assessment_id}` | `any` | SSE validation output stream |
| `GET` | `/api/validation/stream-all/{assessment_id}` | `any` | SSE all-modules output stream |
| `GET` | `/api/validation/runs/{assessment_id}` | `any` | Validation run history |
| `GET` | `/api/validation/runs/detail/{run_id}` | `any` | Validation run details |
| `GET` | `/api/validation/results` | `any` | Validation results |
| `GET` | `/api/validation/analytics/{run_id}` | `any` | Run analytics |
| `GET` | `/api/validation/comparison/{run_id_a}/{run_id_b}` | `any` | Compare two validation runs |
| `GET` | `/api/validation/simulate-synthetic/{module_id}/{preset_name}` | `analyst` | Synthetic preset simulation |
| `GET` | `/api/validation/synthetic/presets` | `any` | Available synthetic presets |
| `POST` | `/api/validation/synthetic/generate` | `analyst` | Generate synthetic validation data |

---

## ADCS and PKI (`/api/pki/`)

| Method | Path | Auth | Notes |
|---|---|---|---|
| `GET` | `/api/pki/templates` | `any` | Certificate template list |
| `GET` | `/api/pki/cves` | `any` | Known ADCS CVEs |
| `GET` | `/api/pki/cves/{cve_id}` | `any` | CVE details |
| `GET` | `/api/pki/overview/{assessment_id}` | `any` | ADCS exposure overview |
| `GET` | `/api/pki/preview/{assessment_id}` | `any` | ADCS finding preview |
| `GET` | `/api/pki/{assessment_id}/ca-flags` | `any` | CA security flag analysis |

---

## Graph (WebSocket only, `/api/graph/`)

| Method | Path | Auth | Notes |
|---|---|---|---|
| `WS` | `/api/graph/ws/{chain_id}` | `any` | Live graph delta broadcast |

---

## Kill chain (`/api/kill-chain/`)

| Method | Path | Auth | Notes |
|---|---|---|---|
| `GET` | `/api/kill-chain/kill-chains/{run_id}` | `any` | Kill chain phases for a run |
| `GET` | `/api/kill-chain/blast-radius/{run_id}/{entity_id}` | `any` | Blast-radius from entity |
| `GET` | `/api/kill-chain/attack-flow-chains` | `any` | Attack flow chain list |

---

## Trusts (`/api/trusts/`)

| Method | Path | Auth | Notes |
|---|---|---|---|
| `GET` | `/api/trusts/` | `any` | List domain trusts |
| `GET` | `/api/trusts/forest-pivot` | `any` | Forest pivot opportunities |
| `GET` | `/api/trusts/forest-pivot/paths` | `any` | Paths through trust relationships |

---

## Lateral movement (`/api/lateral-movement/`)

| Method | Path | Auth | Notes |
|---|---|---|---|
| `GET` | `/api/lateral-movement/paths` | `any` | Lateral movement path enumeration |
| `GET` | `/api/lateral-movement/candidates/{assessment_id}` | `any` | Lateral movement target candidates |

---

## Service accounts (`/api/service-accounts/`)

| Method | Path | Auth | Notes |
|---|---|---|---|
| `GET` | `/api/service-accounts/` | `any` | List service accounts |
| `GET` | `/api/service-accounts/summary` | `any` | Service account exposure summary |

---

## Loot (`/api/loot/`)

| Method | Path | Auth | Notes |
|---|---|---|---|
| `GET` | `/api/loot/list` | `analyst` | List all collected hashes and credentials |
| `POST` | `/api/loot/hash/manual` | `analyst` | Manually add a hash |
| `GET` | `/api/loot/hash-intel` | `analyst` | Hash intelligence (type classification) |
| `POST` | `/api/loot/crack/start` | `analyst` | Submit hashes to cracking workflow |
| `GET` | `/api/loot/crack/{job_id}` | `analyst` | Cracking job status |

---

## AD command catalog (`/api/ad-commands/`)

| Method | Path | Auth | Notes |
|---|---|---|---|
| `GET` | `/api/ad-commands/` | `analyst` | List command categories |
| `GET` | `/api/ad-commands/categories` | `analyst` | Command categories |
| `GET` | `/api/ad-commands/techniques` | `analyst` | All techniques |
| `GET` | `/api/ad-commands/techniques/{technique_id}` | `analyst` | Technique details |
| `POST` | `/api/ad-commands/execute/{technique_id}` | `analyst` + `flag:ENABLE_COMMAND_EXECUTION` | Execute a catalog technique |
| `GET` | `/api/ad-commands/history` | `analyst` | Execution history |

---

## Operation chains (`/api/chains/`)

Requires `ENABLE_CHAIN_BUILDER=true`.

| Method | Path | Auth | Notes |
|---|---|---|---|
| `GET` | `/api/chains/chains` | `analyst` + `flag:ENABLE_CHAIN_BUILDER` | List chains |
| `POST` | `/api/chains/chains` | `analyst` + `flag:ENABLE_CHAIN_BUILDER` | Create chain |
| `GET` | `/api/chains/{chain_id}` | `analyst` + `flag:ENABLE_CHAIN_BUILDER` | Chain details |
| `PUT` | `/api/chains/{chain_id}` | `analyst` + `flag:ENABLE_CHAIN_BUILDER` | Update chain |
| `DELETE` | `/api/chains/{chain_id}` | `analyst` + `flag:ENABLE_CHAIN_BUILDER` | Delete chain |
| `POST` | `/api/chains/{chain_id}/start` | `analyst` + `flag:ENABLE_CHAIN_BUILDER` | Start chain execution |
| `POST` | `/api/chains/{chain_id}/stop` | `analyst` + `flag:ENABLE_CHAIN_BUILDER` | Stop chain execution |

---

## Arsenal (`/api/arsenal/`)

| Method | Path | Auth | Notes |
|---|---|---|---|
| `GET` | `/api/arsenal/` | `analyst` | List arsenal techniques |
| `GET` | `/api/arsenal/techniques` | `analyst` | Technique library |
| `GET` | `/api/arsenal/techniques/{technique_id}` | `analyst` | Technique details with MITRE mapping |
| `POST` | `/api/arsenal/execute` | `analyst` + `flag:ENABLE_COMMAND_EXECUTION` | Execute arsenal technique |
| `GET` | `/api/arsenal/playbook` | `analyst` | Generated playbook |
| `GET` | `/api/arsenal/playbooks` | `analyst` | Saved playbooks |
| `POST` | `/api/arsenal/export-technique` | `analyst` | Export technique as script |

---

## Recon (`/api/recon/`)

| Method | Path | Auth | Notes |
|---|---|---|---|
| `GET` | `/api/recon/` | `analyst` | Recon surface overview |
| `GET` | `/api/recon/scan` | `analyst` | Current scan status |
| `POST` | `/api/recon/scan` | `analyst` | Initiate recon scan |
| `GET` | `/api/recon/abuse` | `analyst` | Abuse surface enumeration |
| `GET` | `/api/recon/abuse/techniques` | `analyst` | Applicable abuse techniques |
| `GET` | `/api/recon/situations` | `analyst` | Situational awareness summary |
| `GET` | `/api/recon/intelligence` | `analyst` | Intelligence summary |
| `POST` | `/api/recon/analyze` | `analyst` | Trigger recon analysis |
| `GET` | `/api/recon/target-card/{assessment_id}` | `analyst` | Target card generation |
| `GET` | `/api/recon/target-from-assessment/{assessment_id}` | `analyst` | Target data from assessment |
| `GET` | `/api/recon/memory/{assessment_id}` | `analyst` | AI operator memory for assessment |
| `GET` | `/api/recon/ldap/{assessment_id}` | `analyst` | LDAP attribute summary |
| `GET` | `/api/recon/posture-timeline/{assessment_id}` | `analyst` | Security posture over time |
| `GET` | `/api/recon/global-score/{assessment_id}` | `any` | Global risk score |

---

## Operations (`/api/ops/`)

| Method | Path | Auth | Notes |
|---|---|---|---|
| `GET` | `/api/ops/` | `analyst` | Ops dashboard |
| `GET` | `/api/ops/status` | `analyst` | Ops service status |
| `GET` | `/api/ops/stats` | `analyst` | Ops statistics |
| `GET` | `/api/ops/jobs` | `analyst` | All ops jobs |
| `GET` | `/api/ops/jobs/{job_id}` | `analyst` | Ops job details |
| `GET` | `/api/ops/status/{job_id}` | `analyst` | Job status |
| `POST` | `/api/ops/auto-run` | `analyst` + `flag:ENABLE_COMMAND_EXECUTION` | Automated operation run |
| `POST` | `/api/ops/approve/{request_id}` | `superadmin` | Approve a human-in-the-loop request |
| `POST` | `/api/ops/reject/{request_id}` | `superadmin` | Reject a human-in-the-loop request |

---

## Reports (`/api/reports/`)

| Method | Path | Auth | Notes |
|---|---|---|---|
| `POST` | `/api/reports/generate-report` | `analyst` | Generate PDF or DOCX report |
| `GET` | `/api/reports/export` | `any` | Export assessment data |
| `GET` | `/api/reports/export/file` | `any` | Download export file |
| `GET` | `/api/reports/export/{run_id}/json` | `any` | Export validation run as JSON |
| `GET` | `/api/reports/{assessment_id}/export-playbook` | `analyst` | Export playbook for assessment |

---

## Remediation (`/api/remediation/`)

| Method | Path | Auth | Notes |
|---|---|---|---|
| `GET` | `/api/remediation/` | `any` | Remediation item list |
| `GET` | `/api/remediation/suggest` | `any` | AI-generated remediation suggestions |
| `GET` | `/api/remediation/simulate` | `analyst` | Simulate remediation impact |
| `GET` | `/api/remediation/resolve` | `analyst` | Mark remediation resolved |
| `GET` | `/api/remediation/categories` | `any` | Remediation categories |

---

## Search (`/api/search/`)

| Method | Path | Auth | Notes |
|---|---|---|---|
| `GET` | `/api/search/` | `any` | Full-text search across assessments |

---

## Tunnel management (`/api/ops/profiles/`)

Requires `ENABLE_TUNNEL_MANAGEMENT=true`.

| Method | Path | Auth | Notes |
|---|---|---|---|
| `GET` | `/api/ops/profiles` | `analyst` + `flag:ENABLE_TUNNEL_MANAGEMENT` | List tunnel profiles |
| `POST` | `/api/ops/profiles` | `analyst` + `flag:ENABLE_TUNNEL_MANAGEMENT` | Create tunnel profile |
| `GET` | `/api/ops/profiles/{profile_id}` | `analyst` + `flag:ENABLE_TUNNEL_MANAGEMENT` | Profile details |
| `PUT` | `/api/ops/profiles/{profile_id}` | `analyst` + `flag:ENABLE_TUNNEL_MANAGEMENT` | Update profile |
| `DELETE` | `/api/ops/profiles/{profile_id}` | `analyst` + `flag:ENABLE_TUNNEL_MANAGEMENT` | Delete profile |
| `POST` | `/api/ops/profiles/{profile_id}/clone` | `analyst` + `flag:ENABLE_TUNNEL_MANAGEMENT` | Clone profile |
| `POST` | `/api/ops/profiles/{profile_id}/test` | `analyst` + `flag:ENABLE_TUNNEL_MANAGEMENT` | Test connectivity |
| `POST` | `/api/ops/profiles/{profile_id}/chisel/start` | `analyst` + `flag:ENABLE_TUNNEL_MANAGEMENT` | Start Chisel tunnel |
| `POST` | `/api/ops/profiles/{profile_id}/chisel/stop` | `analyst` + `flag:ENABLE_TUNNEL_MANAGEMENT` | Stop Chisel tunnel |
| `GET` | `/api/ops/profiles/{profile_id}/chisel/status` | `analyst` + `flag:ENABLE_TUNNEL_MANAGEMENT` | Chisel status |
| `GET` | `/api/ops/profiles/{profile_id}/chisel/logs` | `analyst` + `flag:ENABLE_TUNNEL_MANAGEMENT` | Chisel logs |
| `POST` | `/api/ops/profiles/{profile_id}/ligolo/start` | `analyst` + `flag:ENABLE_TUNNEL_MANAGEMENT` | Start ligolo-proxy |
| `POST` | `/api/ops/profiles/{profile_id}/ligolo/stop` | `analyst` + `flag:ENABLE_TUNNEL_MANAGEMENT` | Stop ligolo-proxy |
| `GET` | `/api/ops/profiles/{profile_id}/ligolo/status` | `analyst` + `flag:ENABLE_TUNNEL_MANAGEMENT` | ligolo-proxy status |
| `GET` | `/api/ops/profiles/{profile_id}/ligolo/logs` | `analyst` + `flag:ENABLE_TUNNEL_MANAGEMENT` | ligolo-proxy logs |
| `POST` | `/api/ops/profiles/{profile_id}/ligolo/route` | `analyst` + `flag:ENABLE_TUNNEL_MANAGEMENT` | Add routing rule |
| `GET` | `/api/ops/profiles/{profile_id}/tunnel/status` | `analyst` + `flag:ENABLE_TUNNEL_MANAGEMENT` | Active tunnel status |
| `POST` | `/api/ops/profiles/{profile_id}/tunnel/start` | `analyst` + `flag:ENABLE_TUNNEL_MANAGEMENT` | Start tunnel |
| `POST` | `/api/ops/profiles/{profile_id}/tunnel/stop` | `analyst` + `flag:ENABLE_TUNNEL_MANAGEMENT` | Stop tunnel |
| `GET` | `/api/ops/profiles/{profile_id}/tunnel/logs` | `analyst` + `flag:ENABLE_TUNNEL_MANAGEMENT` | Tunnel logs |

---

## AI operator (`/api/ai-operator/`)

| Method | Path | Auth | Notes |
|---|---|---|---|
| `POST` | `/api/ai-operator/chat` | `analyst` | Send message to AI operator |
| `GET` | `/api/ai-operator/providers` | `analyst` | List configured providers |
| `GET` | `/api/ai-operator/providers/{provider_id}` | `analyst` | Provider details |
| `POST` | `/api/ai-operator/providers/{provider_id}/test` | `analyst` | Test provider connectivity |
| `GET` | `/api/ai-operator/capabilities` | `analyst` | AI operator tool capabilities |
| `GET` | `/api/ai-operator/tools/available` | `analyst` | Available operator tools |
| `GET` | `/api/ai-operator/workspaces` | `analyst` | Operator workspaces |

---

## Security controls (`/api/security/`)

| Method | Path | Auth | Notes |
|---|---|---|---|
| `GET` | `/api/security/` | `superadmin` | Security control status |
| `GET` | `/api/security/check` | `superadmin` | Run security checks |
| `GET` | `/api/security/check-batch` | `superadmin` | Batch security checks |
| `GET` | `/api/security/explain` | `superadmin` | Explain security posture |

---

## Tool checker (`/api/tool-checker/`)

| Method | Path | Auth | Notes |
|---|---|---|---|
| `GET` | `/api/tool-checker/` | `analyst` | Check installed tool availability |
| `GET` | `/api/tool-checker/capabilities` | `analyst` | Tool capability matrix |
| `GET` | `/api/tool-checker/preflight` | `analyst` | Pre-flight checks for execution |
| `GET` | `/api/tool-checker/stop` | `analyst` | Stop a running tool check |
| `GET` | `/api/tool-checker/update` | `superadmin` | Update tool definitions |

---

## Connectivity check (`/api/connectivity/`)

| Method | Path | Auth | Notes |
|---|---|---|---|
| `GET` | `/api/connectivity/` | `analyst` | Run connectivity probe |
| `GET` | `/api/connectivity/status` | `analyst` | Connectivity status |

---

## Audit log (`/api/audit/`)

| Method | Path | Auth | Notes |
|---|---|---|---|
| `GET` | `/api/audit/` | `superadmin` | Query audit log |

---

## Session (`/api/session/`)

| Method | Path | Auth | Notes |
|---|---|---|---|
| `GET` | `/api/session/` | `any` | Current session info |

---

## Notes on WebSocket endpoints

WebSocket connections use cookie-based authentication. The JWT cookie must be present when the WebSocket handshake is initiated. WebSocket connections that fail authentication are closed with code 4001.

## Notes on SSE endpoints

Server-Sent Event streaming endpoints (`/stream/`, `/stream-all/`) require a valid JWT cookie. Authentication is checked before the stream opens. Unauthenticated requests receive a `401` HTTP response before any streaming begins.

---

*Maintained by [White0xdi3](https://github.com/White0xdi3) — AdByG0d project*
