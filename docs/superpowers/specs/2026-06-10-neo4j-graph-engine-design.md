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
- Migrate **method-by-method** behind a single internal seam, validated by golden-fixture tests — never a big-bang rewrite.
- **Neo4j everywhere, including dev.** Ship a lightweight `docker-compose.dev.yml` (Neo4j + GDS) so local and prod run identical code paths. No SQLite/NetworkX runtime fallback.

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
| Dev/prod parity | **Neo4j-only everywhere.** Drop the SQLite/NetworkX runtime fallback; ship `docker-compose.dev.yml` with Neo4j so dev == prod. Avoids Python↔Cypher behavior drift across ~70 methods |
| Neo4j version | **`neo4j:5-community` + GDS plugin**, pinned. v5's memory management and bulk `UNWIND`/`apoc` throughput suit the projection model; no 4.x |
| Analytics engine | **GDS library** for centrality & community detection — keeps heavy analytics off the transactional engine. CE's 4-core cap is sufficient at 100k-node scale |

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
                   FastAPI routes ──────── Neo4jGraphService ────────────────────┘  communities, centrality)
                          │
                          ▼
                  Next.js / d3-force  (unchanged JSON contract)
```

- **Postgres** stays authoritative. All existing ingest/dedup/finding logic is untouched.
- **Neo4j** is a **derived read-model**: it can be wiped and rebuilt from Postgres at any time. After each ingest the affected assessment is **projected** into Neo4j (batched). A `reproject` operation rebuilds an assessment's subgraph from scratch.
- All **graph queries** (traversal + analytics) run on Neo4j/GDS. Relational/metadata reads stay on Postgres.
- A single **`Neo4jGraphService`** sits between the routes and the engine — one runtime implementation, no NetworkX fallback. Dev and prod run identical code (Neo4j in both via `docker-compose.dev.yml`).

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

### 6.1 `Neo4jGraphService` (`core/graph/neo4j_graph_service.py`)

A **single** service class exposing the methods the routes actually consume — the subset of `ADGraphAnalyzer`'s ~70 methods reachable from `routes/` and `core/analyzers/`. Each method is a Cypher/GDS query scoped by `assessment_id`, backed by the shared async driver. There is **no second implementation and no `GRAPH_BACKEND` switch** — Neo4j runs in dev and prod alike.

`routes/graph.py`'s `_get_analyzer(assessment_id, db)` becomes `_get_service(assessment_id)` returning the Neo4j-backed service. The per-process `_graph_cache` of in-memory NetworkX graphs is **removed** (Neo4j is the shared store); a small LRU of *GDS named-projection handles* may remain to avoid re-projecting for back-to-back analytics calls.

> **Method-by-method migration:** because there is no NetworkX fallback at runtime, the feature branch is built up in phases (see §8) and is not merged until the core query phases are functional. The retired `graph_service.py` (NetworkX) is kept **out of the runtime** and used only as a one-time **golden-fixture generator** for tests (see §10), then removed once parity fixtures are frozen.

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
NEO4J_URI: str = "bolt://localhost:7687"
NEO4J_USER: str = "neo4j"
NEO4J_PASSWORD: str = ""
NEO4J_DATABASE: str = "neo4j"
GRAPH_QUERY_TIMEOUT_SECONDS: int = 30
GRAPH_PROJECT_BATCH_SIZE: int = 10000
```

No `GRAPH_BACKEND` flag — Neo4j is required in every environment. `.env.docker.example` documents the `NEO4J_*` vars.

### 6.6 Deployment (`docker-compose.yml` / `.prod.yml` / new `docker-compose.dev.yml`)

Add a `neo4j` service pinned to **`neo4j:5-community`** with `NEO4J_PLUGINS=["graph-data-science"]`, a named volume, heap/pagecache sized for the target graph, a healthcheck, and `api`/`worker` depending on it (healthy). Add the **`neo4j`** Python driver to `requirements.txt`.

A new **`docker-compose.dev.yml`** brings up a lightweight Neo4j (smaller heap/pagecache) alongside the dev API/worker so local dev runs the **same Neo4j code path** as prod — no SQLite/NetworkX divergence. (Postgres can still be SQLite-on-disk for *relational* dev data; the graph engine is always Neo4j.)

v5 is chosen for its memory management and bulk `UNWIND`/`apoc` throughput, which the projection model leans on heavily.

## 7. Data flow

1. **Ingest** (unchanged) writes entities/edges to Postgres, commits.
2. Post-commit hook **enqueues a projection** (Celery) for that `assessment_id`.
3. Worker **projects** Postgres rows → Neo4j (batched UNWIND/MERGE), updates `last_projected_at`.
4. **Query** requests hit `routes/graph.py` → `Neo4jGraphService` → Cypher/GDS scoped by `assessment_id` → JSON in the existing shape → frontend.
5. **Reproject** (manual or on detected drift) rebuilds an assessment's subgraph from Postgres.

## 8. Migration / phasing strategy

The work lands on the `feat/neo4j-graph-engine` branch and is **not merged until Phase 2 is functional** (there is no NetworkX fallback, so graph routes must work on Neo4j before merge). Each phase is validated by golden-fixture tests:

- **Phase 0 — Scaffolding:** Neo4j service in `docker-compose*.yml` (incl. new `docker-compose.dev.yml`), `neo4j` driver dependency, driver/lifecycle, config (`NEO4J_*`), startup constraints/indexes, empty `Neo4jGraphService` skeleton.
- **Phase 1 — Projection:** projection service + Celery task + reproject endpoint + ingest hook. Neo4j now mirrors Postgres.
- **Phase 2 — Core traversal (merge gate):** shortest / all-shortest / k-shortest paths, reachability, neighborhood, `export_for_frontend`. Covers the hot Graph Explorer + Attack Paths views. Routes switch from `_get_analyzer` to `_get_service`; `_graph_cache` removed.
- **Phase 3 — Analytics (GDS):** centrality, communities, blast radius, choke points, critical nodes, domain dominance.
- **Phase 4 — Detectors:** `detect_*` pattern queries.
- **Phase 5 — Simulation:** edge-removal / node-hardening / remediation ranking.
- **Phase 6 — Cleanup:** delete the runtime NetworkX `graph_service.py` (after its outputs are frozen as test fixtures), `python-louvain`/NetworkX deps where no longer used, and the old cache plumbing.

## 9. Error handling & consistency

- **Projection lag:** Neo4j may briefly trail Postgres after ingest. The UI shows projection state; queries are best-effort against the latest projection. Acceptable per Option A.
- **Neo4j unavailable:** Neo4j is a hard dependency (no fallback). Graph routes return a clear `503` with a "graph engine unavailable / projecting" signal (frontend already has a "no data / rebuilding" state); health/ops route reports Neo4j status.
- **Reproject is idempotent:** delete-then-load scoped by `assessment_id`; safe to re-run.
- **Query timeouts:** `GRAPH_QUERY_TIMEOUT_SECONDS` enforced via Cypher tx timeout; mirrors the existing `_run_path_with_timeout` guard so a pathological query can't hang a worker.
- **Drift detection:** compare Postgres vs Neo4j row counts per assessment; expose a "reproject needed" flag.

## 10. Testing

- **Golden-fixture tests:** run the *retired* NetworkX `graph_service.py` **once** over small + medium AD fixtures to snapshot expected outputs (paths, detectors, `export_for_frontend`, order-normalized). The `Neo4jGraphService` is then asserted against these **frozen fixtures** — no dual runtime, no live drift, and the NetworkX reference can be deleted afterward (§8 Phase 6).
- **Neo4j in tests:** ephemeral Neo4j (+GDS) via `testcontainers` (or a CI service container). Graph tests **require** Neo4j; the non-graph suite (auth, ingest, findings, etc.) still runs without it.
- **Projection tests:** ingest → project → query round-trip; reproject idempotency; incremental refresh after re-import.
- **Scale smoke test:** synthetic 100k-node / 1M-edge generator; assert path/centrality queries complete within target latency and bounded Neo4j heap/pagecache.
- CI gains a Neo4j service for the graph-test job; the rest of `apps/api/tests` runs as today.

## 11. Performance considerations

- Per-assessment `assessment_id` index + `Entity.id` uniqueness constraint are mandatory before large loads.
- Bulk projection uses batched `UNWIND` (configurable `GRAPH_PROJECT_BATCH_SIZE`), `MERGE` on keys; consider `apoc.periodic.iterate` for very large loads.
- GDS analytics run on a **named in-memory projection** per assessment, created on demand and released after use / on a TTL, to bound Neo4j heap.
- Size Neo4j `pagecache` to hold the working set; `dbms.memory.*` tuned in compose for the target forest size.
- Bounded variable-length traversals (explicit hop caps + `LIMIT`) prevent the `all_simple_paths` blow-up.

## 12. Licensing note (recorded, deprioritized per decision)

- **Neo4j Community Edition is GPLv3**; this repo is **MIT**. The **`neo4j` Python driver is Apache-2.0** (safe to depend on). **GDS runs on Community Edition with a 4-core (concurrency) cap** under its own license terms — accepted as sufficient at 100k-node scale. Shipping the Neo4j server in `docker-compose` means operators pull a GPLv3 service alongside the MIT app. The maintainer chose "whatever performs best," accepting this; recorded here so it's a conscious, documented choice (and to revisit if the project's distribution model changes). BloodHound made the same Neo4j-based call.

## 13. Risks

- **Large surface (~70 analyzer methods):** mitigated by the phased port (§8) on an unmerged branch + golden-fixture parity tests frozen from the NetworkX reference. No runtime dual-implementation, so no live Python↔Cypher drift.
- **No runtime fallback:** if Neo4j is down, graph features are down. Accepted (Neo4j-only decision); surfaced via health checks and `503`s, mitigated operationally (healthchecks, restart policy).
- **Dual-store drift:** mitigated by reproject + drift detection; Postgres remains source of truth.
- **GDS memory pressure** at full-forest scale: mitigated by on-demand named projections with TTL/release and tuned heap/pagecache.
- **Operational weight** (new stateful JVM service): explicitly accepted.

## 14. Resolved decisions

All brainstorming open questions are now closed (see §3):

1. **Dev fallback?** ❌ Dropped. **Neo4j-only everywhere**; ship `docker-compose.dev.yml`. One runtime code path, no Python↔Cypher drift.
2. **Neo4j version?** ✅ Pinned **`neo4j:5-community` + GDS**. No 4.x.
3. **GDS for analytics?** ✅ Yes. GDS for centrality & community detection; CE 4-core cap accepted at 100k-node scale.
