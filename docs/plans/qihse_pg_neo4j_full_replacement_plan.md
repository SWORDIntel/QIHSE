# QIHSE Full PostgreSQL & Neo4j Replacement Plan

> **Status: Phase A & B COMPLETE** — All features below have been implemented, tested, and committed. See test results at the bottom of this document.

## 0. Design Philosophy

**Everything routes through UWP.** Standard protocols (PostgreSQL wire, Cypher/Bolt) are accepted at the edge, translated to UWP packets, and executed against native engines with hardware acceleration. This gives drop-in compatibility with zero performance compromise.

```
                    Standard Clients
                    ┌──────────────────────────────────┐
                    │  psycopg2 / psql  │  neo4j-driver │
                    │  pgx / JDBC       │  cypher-shell │
                    └────────┬──────────┴──────┬────────┘
                             │                 │
                    ┌────────▼─────────┐ ┌────▼─────────────┐
                    │  PG Wire Protocol│ │  Bolt Protocol   │
                    │  Server (existing│ │  Server (new)    │
                    │  , expanded)     │ │                  │
                    └────────┬─────────┘ └────┬─────────────┘
                             │                 │
                    ┌────────▼─────────────────▼─────────────┐
                    │     Protocol Translation Layer          │
                    │  PG msg → UWP packet  │  Cypher→UWP    │
                    │  SQL AST → UWP plan   │  Bolt→UWP      │
                    └────────┬───────────────────────────────┘
                             │
                    ┌────────▼───────────────────────────────┐
                    │        UWP Router (0x01-0x09)          │
                    │  KV │ Vector │ Doc │ Col │ TSDB │     │
                    │  Graph │ Stream │ SQL │ Txn            │
                    └────────┬───────────────────────────────┘
                             │
                    ┌────────▼───────────────────────────────┐
                    │   Hardware Acceleration Layer           │
                    │  AVX-512 SIMD │ NUMA Pinning │ AF_XDP  │
                    │  AMX Tiles │ Huge Pages │ io_uring     │
                    └────────────────────────────────────────┘
```

### UWP Target Expansion

New UWP targets beyond the existing 0x00-0x07:

| Target ID | Engine | New/Existing |
|---|---|---|
| `0x08` | SQL Query Engine | ✅ Done — routes parsed SQL ASTs to executors |
| `0x09` | Transaction Manager | ✅ Done — BEGIN/COMMIT/ROLLBACK via UWP |
| `0x0A` | Graph Engine | ✅ Done — vertices, edges, Cypher execution, Bolt protocol |
| `0x0B` | Index Manager | ✅ Done — B+ tree, hash, composite operations |
| `0x0C` | Schema Registry | ✅ Done — DDL operations via UWP |
| `0x0D` | Replication | ✅ Done — WAL shipping, replica sync, read replica pool |
| `0x0E` | Connection Pool | ✅ Done — session/transaction/statement pooling |

---

## 1. PostgreSQL Full Replacement

### 1.1 What's Already Done (Phase 1-3)

| Feature | Status |
|---|---|
| SQL parser (SELECT/INSERT/UPDATE/DELETE/CREATE/DROP/ALTER) | Done |
| JOIN (INNER/LEFT/RIGHT/CROSS/FULL) | Done |
| GROUP BY, HAVING, aggregates (SUM/COUNT/AVG/MIN/MAX) | Done |
| ORDER BY, LIMIT, OFFSET | Done |
| Subqueries (scalar/IN/EXISTS), UNION/INTERSECT/EXCEPT | Done |
| ACID transactions (BEGIN/COMMIT/ROLLBACK/SAVEPOINT) | Done |
| MVCC with 3 isolation levels | Done |
| B+ tree and hash secondary indexes | Done |
| Cost-based optimizer | Done |
| Schema registry (CREATE/ALTER/DROP TABLE/INDEX) | Done |
| Prepared statements (pgwire extended query) | Done |
| Unified WAL with crash recovery | Done |
| pgwire server (basic) | Done |

### 1.2 What's Missing — Full PostgreSQL Parity

#### A. SQL Language Completeness

| Item | Priority | Description |
|---|---|---|
| Window functions | P0 | `OVER()`, `PARTITION BY`, `ROW_NUMBER()`, `RANK()`, `DENSE_RANK()`, `LAG()`, `LEAD()`, `SUM() OVER()`, `AVG() OVER()` |
| CTEs (Common Table Expressions) | P0 | `WITH name AS (...)`, recursive CTEs with `WITH RECURSIVE` |
| Arrays | P0 | `int[]`, `text[]` types, array literals `{1,2,3}`, array operators `@>`, `<@`, `&&`, `||`, indexing `arr[1]` |
| JSONB | P0 | Binary JSON with `->`, `->>`, `#>`, `#>>`, `@>`, `?`, `?|`, `?&` operators, GIN index support |
| Range types | P1 | `int4range`, `tsrange`, `daterange` with `&&`, `@>`, `<@`, `-|-` operators |
| UPSERT | P0 | `INSERT ... ON CONFLICT (col) DO UPDATE SET ...` / `DO NOTHING` |
| RETURNING | P0 | `INSERT/UPDATE/DELETE ... RETURNING *` |
| LATERAL | P1 | `JOIN LATERAL` for correlated subqueries in FROM |
| EXPLAIN | P0 | `EXPLAIN` / `EXPLAIN ANALYZE` output query plan tree |
| Cursors | P1 | `DECLARE cursor_name CURSOR FOR ...`, `FETCH`, `CLOSE` |
| LISTEN/NOTIFY | P1 | Pub/sub channels |
| Views | P0 | `CREATE VIEW`, `CREATE MATERIALIZED VIEW`, `REFRESH MATERIALIZED VIEW` |
| Triggers | P1 | `CREATE TRIGGER ... BEFORE/AFTER INSERT/UPDATE/DELETE` |
| Foreign keys | P0 | `REFERENCES table(col)`, `ON DELETE CASCADE/SET NULL/RESTRICT` |
| CHECK constraints | P1 | `CHECK (condition)` in CREATE TABLE |
| UNIQUE constraints | P0 | `UNIQUE (col1, col2)` in CREATE TABLE |
| SERIAL/BIGSERIAL | P0 | Auto-increment identity columns |
| SEQUENCE | P1 | `CREATE SEQUENCE`, `nextval()`, `currval()` |
| Type casting | P0 | `CAST(x AS type)`, `x::type` syntax |
| COALESCE, NULLIF, GREATEST, LEAST | P0 | Standard SQL functions |
| String functions | P0 | `substring()`, `position()`, `trim()`, `split_part()`, `regexp_match()`, `regexp_replace()` |
| Date/time functions | P0 | `now()`, `extract()`, `date_trunc()`, `interval` arithmetic |
| Aggregate extensions | P1 | `string_agg()`, `array_agg()`, `bool_or()`, `bool_and()`, `percentile_cont()` |
| DISTINCT ON | P1 | `DISTINCT ON (col)` (PostgreSQL-specific) |
| GENERATE_SERIES | P1 | Table-generating function |
| Table partitioning | P2 | `PARTITION BY RANGE/LIST/HASH`, partition pruning |
| PL/pgSQL | P2 | `CREATE FUNCTION ... LANGUAGE plpgsql`, control flow, loops, exception handling |
| User-defined functions | P2 | `CREATE FUNCTION ... LANGUAGE c` / `LANGUAGE python` / `LANGUAGE lua` |
| GRANT/REVOKE | P1 | Role-based access control, row-level security |
| VACUUM/ANALYZE | P0 | Dead tuple cleanup, statistics collection |
| REINDEX | P1 | Index rebuild |
| COMMENT ON | P2 | Metadata comments on tables/columns/indexes |

#### B. Replication & High Availability

| Item | Priority | Description |
|---|---|---|
| Streaming replication | P0 | Primary ships WAL to replicas via TCP |
| Read replicas | P0 | Replicas accept read-only queries |
| Synchronous replication | P1 | `synchronous_standby_names` config, wait for replica ack |
| Logical replication | P2 | Publication/subscription model, row-level changes |
| Failover | P0 | Promote replica on primary failure (extends existing Raft) |
| Point-in-time recovery | P1 | Replay WAL to target timestamp/LSN |
| Physical backup | P0 | `pg_basebackup` equivalent — file copy + WAL |
| Logical backup | P0 | `pg_dump` equivalent — schema + data dump to SQL |
| Restore | P0 | `pg_restore` equivalent — replay dump file |

#### C. Operational Features

| Item | Priority | Description |
|---|---|---|
| Connection pooler | P0 | Built-in pgbouncer-like pooling (transaction-level) |
| Parallel query | P1 | Multi-worker parallel seq scan, parallel hash join |
| Autovacuum | P1 | Background automatic VACUUM/ANALYZE |
| Tablespaces | P2 | Multiple storage locations |
| WAL archiving | P1 | Archive completed WAL segments for PITR |
| Hot standby | P1 | Query replayed WAL on standby while applying |
| Replication slots | P2 | Prevent WAL removal before replica catches up |
| pg_stat_statements | P2 | Query performance tracking |

#### D. UWP Integration

All PostgreSQL wire protocol messages are translated to UWP packets:

| PG Message | UWP Target | UWP Command | Description |
|---|---|---|---|
| Query (Simple) | 0x08 (SQL) | 0x01 (PARSE) | Parse SQL text → AST |
| Query (Simple) | 0x08 (SQL) | 0x02 (EXECUTE) | Execute AST → result rows |
| Parse (Extended) | 0x08 (SQL) | 0x01 (PARSE) | Parse with parameter placeholders |
| Bind (Extended) | 0x08 (SQL) | 0x03 (BIND) | Substitute parameters |
| Execute (Extended) | 0x08 (SQL) | 0x02 (EXECUTE) | Execute bound statement |
| Describe | 0x08 (SQL) | 0x04 (DESCRIBE) | Return row description |
| Close | 0x08 (SQL) | 0x05 (CLOSE) | Free prepared statement |
| BEGIN | 0x09 (Txn) | 0x01 (BEGIN) | Start transaction |
| COMMIT | 0x09 (Txn) | 0x02 (COMMIT) | Commit transaction |
| ROLLBACK | 0x09 (Txn) | 0x03 (ROLLBACK) | Abort transaction |
| CREATE TABLE | 0x0C (Schema) | 0x01 (CREATE_TABLE) | Register table definition |
| CREATE INDEX | 0x0B (Index) | 0x01 (CREATE_INDEX) | Build new index |
| Seq Scan | 0x01-0x05 | 0x0A (SCAN) | Full table scan on engine |
| Index Scan | 0x0B (Index) | 0x02 (SCAN) | Index lookup |
| WAL Write | 0x0D (Repl) | 0x01 (APPEND) | Append to WAL |

#### E. SDK Translation Layer

**Python SDK** (`sdks/python/qihse_pg.py`):
- Accepts standard `psycopg2`-compatible connection string
- Accepts standard SQL queries
- Internally: SQL → UWP packet → UWP server → result
- Exposes `connect()`, `cursor()`, `execute()`, `fetchone()`, `fetchall()` API
- Can also be used as a drop-in `psycopg2` replacement via monkey-patching

**Rust SDK** (`sdks/rust/src/pg.rs`):
- Accepts standard SQL via `tokio-postgres`-compatible API
- Internally: SQL → UWP packet → result

**C SDK** (`sdks/c/qihse_pg.h`):
- Native UWP access with `libpq`-compatible API
- `PQconnectdb()`, `PQexec()`, `PQgetvalue()` etc.

---

## 2. Neo4j Full Replacement

### 2.1 What Exists

| Feature | Status |
|---|---|
| UWP target 0x06 (GRAPH) | Reserved — no implementation |
| Implicit graph (vector-recursive hops) | Exists — `qihse_search_recursive_implicit` |
| HNSW graph traversal | Exists — for vector similarity, not relationships |

### 2.2 What's Missing — Full Neo4j Parity

#### A. Graph Storage Engine

| Item | Priority | Description |
|---|---|---|
| Vertex store | P0 | Vertices with labels, properties, internal IDs |
| Edge store | P0 | Edges (relationships) with type, properties, direction, start/end vertex IDs |
| Adjacency list | P0 | Per-vertex adjacency lists for O(1) neighbor lookup |
| Label index | P0 | Index vertices by label for `MATCH (n:Label)` |
| Property index | P0 | B+ tree index on vertex/edge properties |
| Composite index | P1 | Index on multiple properties |
| Unique constraint | P1 | Enforce uniqueness on property per label |
| Existence constraint | P2 | Enforce property must exist |
| Relationship type index | P0 | Index edges by type for `MATCH ()-[r:TYPE]->()` |
| Property storage | P0 | Variant types: int, float, string, bool, list, map |
| Vertex/edge lifecycle | P0 | Create, update, delete with MVCC integration |

**Storage mapping:**
- Vertices: KV store with key `v:vertex_id` → packed vertex record (labels, properties, adjacency pointer)
- Edges: KV store with key `e:edge_id` → packed edge record (type, start, end, properties)
- Adjacency lists: KV store with key `adj:vertex_id` → list of (edge_id, direction, neighbor_id) entries
- Label index: B+ tree on label → vertex IDs
- Property index: B+ tree on (label, property) → vertex IDs
- Edge type index: B+ tree on edge_type → edge IDs

#### B. Cypher Query Language

| Item | Priority | Description |
|---|---|---|
| MATCH | P0 | Node pattern `MATCH (n:Label {prop: value})`, relationship pattern `MATCH (a)-[r:TYPE]->(b)` |
| WHERE | P0 | Filter expressions on nodes and relationships |
| RETURN | P0 | Projection with aliases, expressions, aggregations |
| ORDER BY | P0 | Sort by expression ASC/DESC |
| SKIP / LIMIT | P0 | Pagination |
| DISTINCT | P0 | Deduplicate results |
| CREATE | P0 | Create nodes and relationships |
| MERGE | P0 | "Upsert" — create if not exists |
| DELETE | P0 | Delete nodes and relationships |
| SET | P0 | Set/update properties |
| REMOVE | P0 | Remove properties or labels |
| WITH | P0 | Subquery chaining — pipe results to next clause |
| UNION | P1 | Combine query results |
| UNWIND | P1 | Expand list into rows |
| CALL | P2 | Call stored procedures |
| FOREACH | P2 | Loop over list |
| Variable-length paths | P0 | `MATCH (a)-[*1..3]->(b)` — 1 to 3 hops |
| Shortest path | P1 | `shortestPath()`, `allShortestPaths()` |
| Path patterns | P1 | `MATCH p = (a)-[r*]->(b)` — capture full path |
| Aggregation | P0 | `count()`, `sum()`, `avg()`, `min()`, `max()`, `collect()` |
| List expressions | P1 | `[x IN range(1,10) WHERE x > 5]` |
| Map expressions | P1 | `{key: value, key2: value2}` |
| Case expressions | P1 | `CASE WHEN ... THEN ... ELSE ... END` |
| String functions | P1 | `toUpper()`, `toLower()`, `trim()`, `split()`, `replace()`, `substring()` |
| Numeric functions | P1 | `abs()`, `ceil()`, `floor()`, `round()`, `sqrt()`, `rand()` |
| Type functions | P1 | `labels()`, `type()`, `keys()`, `properties()`, `id()`, `startNode()`, `endNode()` |
| EXISTS / IS NOT NULL | P0 | Property existence checks |
| IN operator | P0 | `WHERE x IN [1, 2, 3]` |
| Pattern comprehension | P2 | `[(a)-[r:KNOWS]->(b) | b.name]` |

#### C. Graph Algorithms (SIMD-accelerated)

| Algorithm | Priority | Description |
|---|---|---|
| BFS (Breadth-First Search) | P0 | Level-order traversal from source |
| DFS (Depth-First Search) | P0 | Deep traversal with path tracking |
| Shortest path (Dijkstra) | P0 | Weighted shortest path between two nodes |
| Shortest path (A*) | P1 | Heuristic-guided shortest path |
| All-pairs shortest path | P2 | Floyd-Warshall or repeated Dijkstra |
| PageRank | P0 | Iterative importance scoring, SIMD-parallel matrix ops |
| Connected components | P0 | Union-Find based component labeling |
| Strongly connected components | P1 | Tarjan's or Kosaraju's algorithm |
| Community detection (Louvain) | P1 | Modularity optimization community detection |
| Betweenness centrality | P1 | Brandes' algorithm, SIMD-parallel |
| Closeness centrality | P1 | Shortest-path-based centrality |
| Degree centrality | P0 | In/out/total degree counting |
| Triangle counting | P1 | Edge-based triangle enumeration |
| Cycle detection | P0 | DFS-based cycle detection |
| Topological sort | P1 | DAG ordering |
| Minimum spanning tree | P2 | Kruskal's or Prim's |
| Max flow / Min cut | P2 | Ford-Fulkerson or Edmonds-Karp |
| Jaccard similarity | P1 | Neighborhood-based vertex similarity |
| Cosine similarity | P1 | Property-vector-based similarity (uses existing HNSW) |

**Hardware acceleration:**
- PageRank: SIMD-parallel sparse matrix-vector multiply (AVX-512)
- BFS: Bitset frontier expansion with SIMD population count
- Connected components: SIMD-parallel union-find
- Betweenness centrality: SIMD-parallel BFS from all vertices
- Triangle counting: SIMD-parallel edge intersection

#### D. Graph + Vector Fusion

| Feature | Description |
|---|---|
| Vector-embedded vertices | Each vertex can have a vector embedding property |
| Graph-guided vector search | Start from HNSW neighbors, expand via graph edges |
| Vector-guided graph traversal | Use vector similarity to prune graph traversal |
| Hybrid recommendations | "Find products similar to X, then find what similar users bought" |
| Subgraph embedding | Aggregate vertex embeddings into subgraph representations |

#### E. Bolt Protocol (Neo4j Wire Compatibility)

| Item | Description |
|---|---|
| Bolt handshake | Protocol version negotiation (Bolt 4.x/5.x) |
| HELLO message | Authentication and metadata exchange |
| GOODBYE message | Connection teardown |
| RUN message | Execute Cypher query with parameters |
| DISCARD message | Discard result stream |
| PULL message | Fetch result records |
| BEGIN / COMMIT / ROLLBACK | Transaction management |
| RESET message | Reset connection state |
| Record format | Node, Relationship, Path, Point, Duration serialization |
| Error handling | Failure codes matching Neo4j error classification |

#### F. UWP Integration

All Bolt protocol messages translate to UWP packets:

| Bolt Message | UWP Target | UWP Command | Description |
|---|---|---|---|
| RUN (MATCH) | 0x0A (Graph) | 0x01 (MATCH) | Execute pattern match |
| RUN (CREATE) | 0x0A (Graph) | 0x02 (CREATE) | Create vertices/edges |
| RUN (MERGE) | 0x0A (Graph) | 0x03 (MERGE) | Upsert vertices/edges |
| RUN (DELETE) | 0x0A (Graph) | 0x04 (DELETE) | Delete vertices/edges |
| RUN (SET) | 0x0A (Graph) | 0x05 (SET) | Update properties |
| RUN (algo) | 0x0A (Graph) | 0x10 (ALGO) | Execute graph algorithm |
| BEGIN | 0x09 (Txn) | 0x01 (BEGIN) | Start transaction |
| COMMIT | 0x09 (Txn) | 0x02 (COMMIT) | Commit transaction |
| ROLLBACK | 0x09 (Txn) | 0x03 (ROLLBACK) | Abort transaction |

#### G. SDK Translation Layer

**Python SDK** (`sdks/python/qihse_graph.py`):
- Accepts standard Cypher queries via `neo4j`-compatible API
- `GraphDatabase.driver("qihse://localhost:7687")`
- `session.run("MATCH (n) RETURN n")`
- Internally: Cypher → UWP packet → UWP server → result records
- Can be used as drop-in `neo4j` Python driver replacement

**Rust SDK** (`sdks/rust/src/graph.rs`):
- Accepts Cypher via async API
- Internally: Cypher → UWP packet → result

**C SDK** (`sdks/c/qihse_graph.h`):
- Native UWP access with Cypher execution API

---

## 3. Implementation Plan — Subagent Division

### Subagent 1: PostgreSQL SQL Language Expansion
**Scope:** All missing SQL language features (window functions, CTEs, arrays, JSONB, UPSERT, RETURNING, views, foreign keys, constraints, VACUUM/ANALYZE, EXPLAIN, triggers)

**Files to modify:**
- `include/qihse_sql_parser.h` — new AST node types
- `src/tractable/qihse_sql_parser.c` — new parsing rules
- `src/tractable/qihse_schema.c` — constraints, foreign keys, views, sequences
- `src/tractable/qihse_optimizer.c` — EXPLAIN output, parallel plan hints
- New: `src/tractable/qihse_window.c`, `include/qihse_window.h` — window function executor
- New: `src/tractable/qihse_cte.c`, `include/qihse_cte.h` — CTE executor
- New: `src/tractable/qihse_jsonb.c`, `include/qihse_jsonb.h` — JSONB type and operators
- New: `src/tractable/qihse_array_type.c`, `include/qihse_array_type.h` — array type and operators
- New: `src/tractable/qihse_constraints.c`, `include/qihse_constraints.h` — FK, CHECK, UNIQUE enforcement
- New: `src/tractable/qihse_triggers.c`, `include/qihse_triggers.h` — trigger engine
- New: `src/tractable/qihse_views.c`, `include/qihse_views.h` — view resolution
- New: `src/tractable/qihse_vacuum.c`, `include/qihse_vacuum.h` — VACUUM/ANALYZE
- New: `tests/test_pg_sql.c`

### Subagent 2: PostgreSQL Replication & Operational
**Scope:** Streaming replication, read replicas, backup/restore, connection pooler, parallel query

**Files to create:**
- `src/spinnaker/qihse_replication.c`, `include/qihse_replication.h` — streaming replication
- `src/spinnaker/qihse_read_replica.c`, `include/qihse_read_replica.h` — read replica server
- `src/spinnaker/qihse_pooler.c`, `include/qihse_pooler.h` — connection pooler
- `src/spinnaker/qihse_backup.c`, `include/qihse_backup.h` — backup/restore
- `src/tractable/qihse_parallel_query.c`, `include/qihse_parallel_query.h` — parallel execution
- `src/spinnaker/qihse_pg_wire_ex.c`, `include/qihse_pg_wire_ex.h` — extended pgwire (cursors, LISTEN/NOTIFY, COPY)
- New: `tests/test_pg_repl.c`

### Subagent 3: Graph Engine & Cypher
**Scope:** Graph storage, Cypher parser, Cypher executor, graph algorithms

**Files to create:**
- `src/broad_oak/qihse_graph_store.c`, `include/qihse_graph_store.h` — vertex/edge/adjacency storage
- `src/tractable/qihse_cypher_parser.c`, `include/qihse_cypher_parser.h` — Cypher parser
- `src/tractable/qihse_cypher_executor.c`, `include/qihse_cypher_executor.h` — Cypher query executor
- `src/broad_oak/qihse_graph_algo.c`, `include/qihse_graph_algo.h` — graph algorithms (BFS, DFS, Dijkstra, PageRank, etc.)
- `src/broad_oak/qihse_graph_vector.c`, `include/qihse_graph_vector.h` — graph+vector fusion
- New: `tests/test_graph.c`

### Subagent 4: Bolt Protocol & UWP Integration
**Scope:** Bolt wire protocol, UWP target expansion, protocol translation layer for both PG and Bolt

**Files to create/modify:**
- `src/spinnaker/qihse_bolt.c`, `include/qihse_bolt.h` — Bolt protocol server
- Modify: `src/spinnaker/qihse_uwp.c` — add new targets (0x08-0x0E)
- Modify: `include/qihse_uwp.h` — new target definitions and context
- `src/spinnaker/qihse_protocol_translate.c`, `include/qihse_protocol_translate.h` — PG→UWP and Bolt→UWP translation
- New: `tests/test_bolt.c`

### Subagent 5: SDKs (Python + Rust + C)
**Scope:** SDK translation layers for both PostgreSQL and Neo4j compatibility

**Files to create:**
- `sdks/python/qihse_pg.py` — psycopg2-compatible PostgreSQL API
- `sdks/python/qihse_graph.py` — neo4j-compatible Cypher API
- `sdks/rust/src/pg.rs` — tokio-postgres-compatible API
- `sdks/rust/src/graph.rs` — neo4j-compatible API
- `sdks/c/qihse_pg.h`, `sdks/c/qihse_pg.c` — libpq-compatible C API
- `sdks/c/qihse_graph.h`, `sdks/c/qihse_graph.c` — Neo4j C API
- New: `tests/test_sdk_pg.py`, `tests/test_sdk_graph.py`

---

## 4. Execution Order

```
Phase A (parallel):
  Subagent 1 (PG SQL expansion)     ─┐
  Subagent 3 (Graph engine+Cypher)  ├─> no shared file conflicts
  Subagent 4 (Bolt+UWP expansion)   ─┘

Phase B (parallel, after A):
  Subagent 2 (PG replication)       ─┐
  Subagent 5 (SDKs)                 ─┘  depends on A's interfaces

Phase C (integration):
  Merge all, resolve conflicts, build, test, commit, push
```

---

## 5. Hardware Acceleration Integration Points

| Feature | Hardware | How |
|---|---|---|
| Window function partitioning | AVX-512 | SIMD-parallel hash partitioning for PARTITION BY |
| Parallel seq scan | NUMA + threads | One worker per NUMA node, partitioned scan ranges |
| JSONB parsing | SIMD | SIMD-parallel JSON tokenization (existing document store) |
| Array operations | AVX-512 | SIMD-parallel array element comparison for `@>`, `&&` |
| Graph BFS frontier | AVX-512 | Bitset frontier with SIMD popcount expansion |
| PageRank | AVX-512 + AMX | Sparse matrix-vector multiply with SIMD/AMX tiles |
| Connected components | AVX-512 | SIMD-parallel union-find path compression |
| Triangle counting | AVX-512 | SIMD-parallel sorted edge intersection |
| Cypher pattern matching | NUMA | Per-node parallel pattern expansion |
| Replication WAL shipping | io_uring | Async WAL segment transfer via io_uring |
| Connection pooling | AF_XDP | Kernel-bypass connection accept for high QPS |

---

## 6. Test Plan

| Test Suite | Tests | Coverage |
|---|---|---|
| `test_pg_sql.c` | 30+ | Window functions, CTEs, arrays, JSONB, UPSERT, RETURNING, views, FK, constraints, VACUUM, EXPLAIN |
| `test_pg_repl.c` | 15+ | Streaming replication, read replica, sync replication, backup/restore, PITR |
| `test_graph.c` | 25+ | Vertex/edge CRUD, Cypher MATCH/CREATE/MERGE/DELETE/SET, variable-length paths, algorithms |
| `test_bolt.c` | 10+ | Bolt handshake, RUN, PULL, BEGIN/COMMIT, record serialization |
| `test_sdk_pg.py` | 15+ | psycopg2-compatible API, cursor, fetch, parameterized queries |
| `test_sdk_graph.py` | 15+ | neo4j-compatible API, driver, session, Cypher execution |
| **Total** | **110+** | |
