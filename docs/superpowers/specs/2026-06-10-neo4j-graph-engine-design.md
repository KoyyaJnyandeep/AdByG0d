# Neo4j Graph Engine — Design

**Date:** 2026-06-10
**Status:** Draft for review
**Author:** brainstormed with the AdByG0d maintainer

## 1. Background & current state

AdByG0d is a BloodHound-style Active Directory exposure platform. The backend is:

- **`apps/api`** — Python FastAPI, SQLAlchemy 2.0 async. **PostgreSQL** in prod (`asyncpg`), **SQLite** (`aiosqlite`) in dev. Entities and edges are relational rows scoped by `assessment_id` (`entities`, `graph_edges` tables in `models.py`).
- **Graph compute** — On first request for an assessment, every entity + edge row is loaded into an **in-memory NetworkX `DiGraph`** (`ADGraphAnalyzer` in `core/graph/graph_service.py`, ~2,300 lines, ~70 public methods). Path-finding uses `nx.shortest_path`, `all_shortest_paths`, `all_simple_paths`, `dijkstra_path`; analytics use `python-louvain` (communities) and NetworkX centrality.
- **Caching** — An in-process LRU dict (`_graph_cache` in `routes/graph.py`, max 50 analyzers, lock-guarded) holds built analyzers; invalidated on ingest via `invalidate_graph_cache(assessment_id)`.
- **`apps/web`** — Next.js 15 / React 19, renders the graph with `d3-force`. Consumes the JSON shaped by `ADGraphAnalyzer.export_for_frontend(...)`.

### Why this hits a wall at scale

The maintainer targets **enterprise scale: 100k+ nodes, millions of edges** (full-forest / BloodHound-enterprise), and chose **"whatever performs best"** over minimizing operational cost. The current design's limits there:

1. **Memory** — the whole per-assessment graph lives in one Python process; up to 50 cached. A full forest is multiple GB of NetworkX objects, *per uvicorn/gunicorn worker* (the cache is per-process, so memory multiplies with workers).
2. **`all_simple_paths` is exponential** on dense control graphs — the classic BloodHound-scale failure mode.
3. **Cold-start** — first query per assessment rebuilds the graph from SQL (O(N+E)); a latency spike that grows with size.
4. **No horizontal scale** — because each worker holds its own in-memory graph, you cannot cheaply add API replicas.

## 2. Goals & non-goals

### Goals

- Move heavy graph traversal and analytics to **Neo4j** (with the **GDS** — Graph Data Science — plugin) so path-finding and centrality scale to 100k+ nodes / millions of edges.
- Preserve the existing **HTTP API contract** and the **frontend data shape** — `routes/graph.py`, `routes/chains.py`, and `apps/web` should need minimal or no change.
- Migrate **method-by-method** behind an abstraction, with parity tests against the current NetworkX implementation — never a big-bang rewrite.
- Keep a **lightweight dev path** (SQLite + NetworkX) available behind a config flag.

### Non-goals

- Rewriting ingestion, dedup, or conflict-resolution (it stays on Postgres and is unchanged).
- Replacing Postgres. It remains the system-of-record for assessments, entities, edges, findings, users, audit, jobs.
- Changing collectors or import formats.
- UI/visual redesign.

## 3. Decisions captured from brainstorming

| Question | Decision |
|---|---|
| Target scale | Enterprise: 100k+ nodes, millions of edges |
| Operational appetite | "Whatever performs best" — operational cost & licensing secondary |
| Sync model | **Option A — Projection.** Postgres is source of truth; Neo4j is a derived, rebuildable read-model |

## 4. Architecture — hybrid (Postgres source of truth + Neo4j graph engine)

```
                 ingest / import (unchanged)
                          │
                          ▼
                 ┌──────────────────┐         project (bulk UNWIND, batched)
   Postgres ◄────┤  entities/edges  ├────────────────────────────────────►  Neo4j  (+ GDS)
 (source of      │   (system of     │                                       (derived read-model,
  truth)         │     record)      │   ◄── reproject endpoint rebuilds ──   per-assessment subgraph)
                 └──────────────────┘
                          ▲                                                       ▲
                          │ relational reads (findings, users, audit…)            │ Cypher / GDS reads
                          │                                                       │ (paths, blast radius,
                   FastAPI routes ──────── GraphBackend abstraction ──────────────┘  communities, centrality)
                          │
                          ▼
                  Next.js / d3-force  (unchanged JSON contract)
```

- **Postgres** stays authoritative. All existing ingest/dedup/finding logic is untouched.
- **Neo4j** is a **derived read-model**: it can be wiped and rebuilt from Postgres at any time. After each ingest the affected assessment is **projected** into Neo4j (batched). A `reproject` operation rebuilds an assessment's subgraph from scratch.
- All **graph queries** (traversal + analytics) run on Neo4j/GDS. Relational/metadata reads stay on Postgres.
- A **`GraphBackend` abstraction** sits between the routes and the engine, with two implementations: `NetworkXBackend` (current behavior, dev/fallback) and `Neo4jBackend` (new, prod default). Selected by `GRAPH_BACKEND` config.

## 5. Data model mapping

Each assessment's subgraph is isolated in Neo4j by an `assessment_id` property on every node and relationship (plus a per-assessment composite index). Single shared database; isolation by property + index. (Neo4j multi-database is an Enterprise feature; we stay on Community + property scoping.)

### Entity → `(:Entity)` node

Carry the fields the analyzer and frontend actually use:

| Postgres column | Neo4j node property | Notes |
|---|---|---|
| `id` (UUID) | `id` (string) | node key, indexed; `entity_type` also set as a **label** (e.g. `:User`, `:Computer`, `:Group`, `:Domain`, `:GPO`, `:CertTemplate`) for fast `MATCH` |
| `assessment_id` | `assessment_id` | scope key, indexed |
| `entity_type` | `entity_type` + label | |
| `object_sid` / `sam_account_name` / `distinguished_name` / `dns_hostname` / `domain` / `display_name` | same | drive `lookup_by_sid/sam/dn` |
| `is_enabled`, `is_admin_count`, `is_sensitive`, `is_protected_user`, `is_crown_jewel`, `tier` | same | tier/crown-jewel drive Tier-0 / high-value queries |
| `attributes` (JSON) | flattened to scalar props used by detectors (e.g. `unconstrained_delegation`, `has_spn`, `dont_req_preauth`) | Neo4j props must be primitives; nested JSON stays in Postgres |

### GraphEdge → `[:<EDGE_TYPE>]` relationship

| Postgres column | Neo4j relationship | Notes |
|---|---|---|
| `edge_type` (EdgeType enum) | **relationship type** (`MEMBER_OF`, `GENERIC_ALL`, `DCSYNC`, …) | enables typed Cypher patterns |
| `source_id` → `target_id` | `(src)-[r]->(tgt)` direction | |
| `risk_weight` | `r.risk_weight` | edge cost for weighted/Dijkstra paths |
| `edge_confidence`, `edge_provenance_type`, `provenance`, `edge_key` | same | provenance & dedup |
| `assessment_id` | `r.assessment_id` | scope |

### Indexes / constraints (created on startup / first projection)

- `CONSTRAINT entity_id IF NOT EXISTS ... (n:Entity) REQUIRE (n.id) IS UNIQUE`
- `INDEX ... FOR (n:Entity) ON (n.assessment_id)`
- `INDEX ... FOR (n:Entity) ON (n.object_sid)`, `(n.sam_account_name)`, `(n.distinguished_name)` — back the lookup helpers
- Relationship index `ON (r.assessment_id)` where supported

## 6. Components

### 6.1 `GraphBackend` abstraction (`core/graph/backends/`)

A `Protocol` (or ABC) declaring the methods the routes actually consume — the subset of `ADGraphAnalyzer`'s ~70 methods that are reachable from `routes/` and `core/analyzers/`. Two implementations:

- **`NetworkXBackend`** — wraps today's `ADGraphAnalyzer` unchanged. Default when `GRAPH_BACKEND=networkx`. Keeps SQLite-only dev a pure `pip install`.
- **`Neo4jBackend`** — backed by the Neo4j async driver; each method is a Cypher/GDS query scoped by `assessment_id`. Default when `GRAPH_BACKEND=neo4j`.

`routes/graph.py`'s `_get_analyzer(assessment_id, db)` becomes `_get_backend(assessment_id, db)` returning the configured backend. For Neo4j the per-process `_graph_cache` of in-memory graphs is **removed** (Neo4j is the shared cache); a small LRU of *driver sessions / GDS projection handles* may remain.

> **Method-by-method migration:** `Neo4jBackend` may initially delegate un-ported methods to `NetworkXBackend` (lazy-loading that assessment's graph) so we ship value incrementally. The phase plan ports the highest-value traversal/analytics methods first.

### 6.2 Neo4j driver & lifecycle (`core/graph/neo4j_client.py`)

- Single shared `neo4j.AsyncDriver` (async, connection-pooled) created at app startup, closed at shutdown (FastAPI lifespan).
- Config: `NEO4J_URI`, `NEO4J_USER`, `NEO4J_PASSWORD`, `NEO4J_DATABASE`.
- Health check surfaced in the existing ops/health route; startup ensures constraints/indexes exist.

### 6.3 Projection service (`core/graph/projection.py`)

- **Full project / reproject(assessment_id):** delete that assessment's nodes+rels in Neo4j, then bulk-load from Postgres in **batches** (`UNWIND $rows AS row MERGE …`, ~10k rows/tx). Runs as a **Celery task** (Redis broker already present) so large forests don't block the request.
- **Incremental project:** hook where `invalidate_graph_cache(assessment_id)` is called today (`routes/ingest.py:1399`, `core/ai_operator/tools/write_tools.py:228`). After ingest commits, enqueue a projection refresh for that assessment instead of (or in addition to) cache invalidation.
- **Endpoint:** `POST /assessments/{id}/graph/reproject` → enqueues a reproject job; status via the existing jobs API. Also exposes per-assessment projection state (`last_projected_at`, row counts, drift) so the UI can show "graph is rebuilding".

### 6.4 Cypher / GDS query layer

- **Paths:** `shortestPath` / `allShortestPaths` for unweighted; GDS Dijkstra / Yen's k-shortest for weighted (`risk_weight`) and `find_k_shortest_paths`. Bounded variable-length patterns replace `all_simple_paths` with explicit hop caps + result limits.
- **Reachability / neighborhood:** variable-length `MATCH` with `assessment_id` scope and hop/size caps (`get_reachable_from`, `get_can_reach`, `get_neighborhood`, `export_attack_subgraph`).
- **Analytics via GDS:** PageRank, betweenness centrality, Louvain communities, degree — over a named in-memory **GDS graph projection** per assessment (replaces NetworkX centrality + `python-louvain`). Choke points / critical nodes derive from betweenness.
- **Detectors:** the `detect_*` methods (kerberoastable, AS-REP, ADCS ESC, shadow admins, DCSync, delegation, LAPS/gMSA) become Cypher `MATCH` patterns on typed relationships + node props — generally a direct and faster translation.
- **Simulation:** `simulate_edge_removal` / `simulate_node_hardening` run inside a transaction that mutates a GDS in-memory projection (or a tx rolled back), recompute affected metrics, and return deltas — no mutation of the persisted graph.
- **Frontend export:** `export_for_frontend` returns the **same JSON shape** as today, just sourced from Cypher. This is a parity-tested boundary.

### 6.5 Config additions (`config.py`)

```
GRAPH_BACKEND: str = "networkx"          # "neo4j" | "networkx"
NEO4J_URI: str = "bolt://localhost:7687"
NEO4J_USER: str = "neo4j"
NEO4J_PASSWORD: str = ""
NEO4J_DATABASE: str = "neo4j"
GRAPH_QUERY_TIMEOUT_SECONDS: int = 30
GRAPH_PROJECT_BATCH_SIZE: int = 10000
```

Prod (`docker-compose.prod.yml`, `.env.docker.example`) defaults `GRAPH_BACKEND=neo4j`; local dev defaults to `networkx`.

### 6.6 Deployment (`docker-compose.yml` / `.prod.yml`)

Add a `neo4j` service (Community + GDS plugin), e.g. `neo4j:5-community` with `NEO4J_PLUGINS=["graph-data-science"]`, a named volume, heap/pagecache sized for the target graph, healthcheck, and `api`/`worker` depending on it. Add `neo4j` Python driver to `requirements.txt`.

## 7. Data flow

1. **Ingest** (unchanged) writes entities/edges to Postgres, commits.
2. Post-commit hook **enqueues a projection** (Celery) for that `assessment_id`.
3. Worker **projects** Postgres rows → Neo4j (batched UNWIND/MERGE), updates `last_projected_at`.
4. **Query** requests hit `routes/graph.py` → `Neo4jBackend` → Cypher/GDS scoped by `assessment_id` → JSON in the existing shape → frontend.
5. **Reproject** (manual or on detected drift) rebuilds an assessment's subgraph from Postgres.

## 8. Migration / phasing strategy

Behind the `GraphBackend` abstraction, port in priority order; each phase keeps NetworkX parity tests green and can ship independently:

- **Phase 0 — Scaffolding:** Neo4j service in compose, driver/lifecycle, config, constraints/indexes, `GraphBackend` Protocol with `NetworkXBackend` wrapping current code (no behavior change).
- **Phase 1 — Projection:** projection service + Celery task + reproject endpoint + ingest hook. Neo4j now mirrors Postgres.
- **Phase 2 — Core traversal:** shortest / all-shortest / k-shortest paths, reachability, neighborhood, `export_for_frontend`. These cover the hot Graph Explorer + Attack Paths views.
- **Phase 3 — Analytics (GDS):** centrality, communities, blast radius, choke points, critical nodes, domain dominance.
- **Phase 4 — Detectors:** `detect_*` pattern queries.
- **Phase 5 — Simulation:** edge-removal / node-hardening / remediation ranking.
- **Phase 6 — Default flip & cleanup:** prod default `GRAPH_BACKEND=neo4j`; NetworkX retained as dev/fallback.

## 9. Error handling & consistency

- **Projection lag:** Neo4j may briefly trail Postgres after ingest. The UI shows projection state; queries are best-effort against the latest projection. Acceptable per Option A.
- **Neo4j unavailable:** graph routes return a clear `503` with a "graph engine unavailable / projecting" signal (frontend already has a "no data / rebuilding" state). Optionally fall back to `NetworkXBackend` for an assessment if configured — explicit, not silent.
- **Reproject is idempotent:** delete-then-load scoped by `assessment_id`; safe to re-run.
- **Query timeouts:** `GRAPH_QUERY_TIMEOUT_SECONDS` enforced via Cypher tx timeout; mirrors the existing `_run_path_with_timeout` guard so a pathological query can't hang a worker.
- **Drift detection:** compare Postgres vs Neo4j row counts per assessment; expose a "reproject needed" flag.

## 10. Testing

- **Parity tests:** golden AD fixtures (small + medium) run through both `NetworkXBackend` and `Neo4jBackend`; assert identical results for paths, detectors, and `export_for_frontend` (order-normalized). This is the core safety net for the migration.
- **Neo4j in tests:** ephemeral Neo4j via `testcontainers` (or a CI service container); skipped when unavailable so the existing pytest suite still runs without Neo4j locally.
- **Projection tests:** ingest → project → query round-trip; reproject idempotency; incremental refresh after re-import.
- **Scale smoke test:** synthetic 100k-node / 1M-edge generator; assert path/centrality queries complete within target latency and bounded memory.
- Existing `apps/api/tests` continue to pass with `GRAPH_BACKEND=networkx` (default in CI unless the Neo4j job is selected).

## 11. Performance considerations

- Per-assessment `assessment_id` index + `Entity.id` uniqueness constraint are mandatory before large loads.
- Bulk projection uses batched `UNWIND` (configurable `GRAPH_PROJECT_BATCH_SIZE`), `MERGE` on keys; consider `apoc.periodic.iterate` for very large loads.
- GDS analytics run on a **named in-memory projection** per assessment, created on demand and released after use / on a TTL, to bound Neo4j heap.
- Size Neo4j `pagecache` to hold the working set; `dbms.memory.*` tuned in compose for the target forest size.
- Bounded variable-length traversals (explicit hop caps + `LIMIT`) prevent the `all_simple_paths` blow-up.

## 12. Licensing note (recorded, deprioritized per decision)

- **Neo4j Community Edition is GPLv3**; this repo is **MIT**. The **`neo4j` Python driver is Apache-2.0** (safe to depend on). **GDS Community** has its own license terms. Shipping the Neo4j server in `docker-compose` means operators pull a GPLv3 service alongside the MIT app. The maintainer chose "whatever performs best," accepting this; recorded here so it's a conscious, documented choice (and to revisit if the project's distribution model changes). BloodHound made the same Neo4j-based call.

## 13. Risks

- **Large surface (~70 analyzer methods):** mitigated by the abstraction + phased port + delegation to NetworkX for un-ported methods.
- **Dual-store drift:** mitigated by reproject + drift detection; Postgres remains source of truth.
- **GDS memory pressure** at full-forest scale: mitigated by on-demand named projections with TTL/release and tuned heap/pagecache.
- **Operational weight** (new stateful JVM service): explicitly accepted.

## 14. Open questions

1. **Dev fallback retained?** Plan keeps `NetworkXBackend` for SQLite-only dev behind `GRAPH_BACKEND`. Confirm you want this, or go Neo4j-only everywhere (simpler code, heavier dev setup).
2. **Neo4j version pin** — target `neo4j:5-community` (with GDS) unless you have a reason to pin `4.x`.
3. **GDS vs. hand-written Cypher** for centrality/communities — plan uses GDS for scale; acceptable to add the GDS plugin dependency.
