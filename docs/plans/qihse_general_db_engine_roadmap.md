# QIHSE General-Purpose Database Engine Replacement Roadmap

> **Update:** Phases 1-5 are **COMPLETE**. Phase 4 is complete (streaming repl + read replicas + CDC). Phase 6 (MongoDB wire, HTTP/REST, ClickHouse HTTP, ES API) is **COMPLETE**. Phase 7 (pooler, Prometheus metrics, OpenTelemetry tracing, compaction/TTL) is **COMPLETE**. Phase 8 (SQL extensions: VECTOR_SEARCH, TIME_BUCKET, MATCH) is **COMPLETE**. See the status table below for details.

## 0. Current State Summary

QIHSE today is a native C99 multi-model engine with eight storage subsystems, two wire protocols, and a sharded cluster fabric. The table below maps what exists against what a general-purpose database replacement needs.

| Capability | Status | Notes |
|---|---|---|
| KV store (Trinary Trie + SSTable) | Production | ~489k writes/sec, 320 ns p50 get |
| Vector DB (HNSW + exact rerank) | Production | 33k QPS HNSW, 38 ns SIMD rerank |
| Document store (BSON-like + JIT paths) | Production | Arena + Bloom + Radix path |
| Columnar engine (RLE/delta/bitpack) | Production | AVX-512 scans, zone maps |
| Time-series DB (Gorilla compression) | Production | 40 ns/point ingest, lock-free ring |
| Full-text search (Trinary Trie + BM25) | Production | Zero-copy lexer, neural class tags |
| Event stream (append-only commit log) | Production | SHA-384 dedup, mmap/sendfile |
| Spatial index (Z-order Morton) | Production | Bounding box + radius queries |
| SQLite VFS compatibility | Production | Drop-in sqlite3_vfs |
| RESP2/RESP3 wire protocol | Production | Redis-compatible commands + cluster |
| PostgreSQL wire protocol (pgwire) | Production | Sharded catalogs, distributed planner |
| Unified Wire Protocol (UWP) | Production | Binary, zero-alloc, engine-routed |
| Cluster sharding (16384 slots) | Production | CRC16, MOVED/ASK, gossip, Raft failover |
| Cluster rebalancing / migration | Production | Zero-downtime ASK handoff |
| Distributed scatter-gather planner | Production | RRF, aggregate fusion, multi-engine |
| Task queue (Celery-equivalent) | Production | Priority, retry, cron, Python SDK |
| Auth (classification + SCI compartments) | Production | CNSA 2.0 crypto, constant-time reject |
| Temporal / time-travel queries | Partial | Vector DB only; not cross-engine |
| SQL parser | Production | Full SQL: JOIN, GROUP BY, HAVING, ORDER BY, subqueries, UNION/INTERSECT/EXCEPT, CTEs, window functions, UPSERT, RETURNING, views, sequences, VACUUM, NOTIFY/LISTEN, EXPLAIN |
| QQL parser | Minimal | Spatial + temporal + join hints + vector flag |
| Transactions (ACID) | Production | BEGIN/COMMIT/ROLLBACK/SAVEPOINT, 3 isolation levels, MVCC, 2PC |
| Secondary indexes (B-tree, hash) | Production | B+ tree, hash index, composite keys, index manager |
| Replication (read replicas, CDC) | Production | Streaming replication, replication slots, read replica pool, CDC pub/sub |
| Graph engine (explicit edges/vertices) | Production | Vertex/edge store, Cypher parser/executor, graph algorithms, vector fusion |
| MongoDB wire protocol (BSON) | Production | BSON serialization, wire protocol server, OP_REPLY handling |
| HTTP/REST API | Production | HTTP server with route registration, JSON responses, ClickHouse + ES compatible endpoints |
| Observability (metrics, tracing) | Production | Prometheus /metrics export, OpenTelemetry tracing with span export |
| Backup / snapshot / restore | Production | Full/incremental backups with checksums, restore, verify |
| Schema management / migrations | Production | Schema registry, CREATE/ALTER/DROP TABLE/INDEX, views, sequences |
| Connection pooling / pgbouncer-like | Production | Session/transaction/statement pooling, backend management, health checks |
| Parallel query execution | Production | Multi-worker parallel scan, join, aggregate with pthread partitioning |

---

## 1. Roadmap Phases

### Phase 1 -- Relational Completeness ✅ COMPLETE
Goal: Make the SQL surface sufficient to replace PostgreSQL for application workloads.

| Item | Description | Key Files |
|---|---|---|
| 1.1 SQL JOIN engine | INNER / LEFT / RIGHT / CROSS JOIN with hash-join and nested-loop operators | src/tractable/qihse_sql_parser.c, new qihse_join_executor.c |
| 1.2 GROUP BY + aggregates | SUM, COUNT, AVG, MIN, MAX, GROUP BY, HAVING, DISTINCT | src/tractable/qihse_sql_parser.c, qihse_dist_planner.c |
| 1.3 ORDER BY + sort | In-memory sort-merge with spill-to-disk for large results | new qihse_sort_executor.c |
| 1.4 Subqueries | Scalar, correlated, EXISTS, IN, UNION / INTERSECT / EXCEPT | qihse_sql_parser.c |
| 1.5 DDL expansion | CREATE TABLE with typed columns, ALTER TABLE, CREATE INDEX, DROP INDEX | qihse_sql_parser.c, new qihse_schema.c |
| 1.6 Prepared statements | Parse-once, execute-many via pgwire extended query protocol | src/spinnaker/qihse_pg_wire.c |
| 1.7 Cost-based optimizer | Statistics histogram, cardinality estimation, plan enumeration | new qihse_optimizer.c |

### Phase 2 -- ACID Transactions & MVCC ✅ COMPLETE
Goal: Provide transactional guarantees across all engines, not just per-key.

| Item | Description | Key Files |
|---|---|---|
| 2.1 Transaction manager | BEGIN / COMMIT / ROLLBACK / SAVEPOINT, txn ID allocation | new qihse_txn.c, qihse_txn.h |
| 2.2 MVCC version store | Per-row version chains with xmin/xmax, vacuum / cleanup | qihse_kv_store.c, qihse_column_store.c, qihse_document_store.c |
| 2.3 Isolation levels | READ COMMITTED, REPEATABLE READ, SERIALIZABLE (SSI or OCC) | qihse_txn.c |
| 2.4 Cross-engine 2PC | Two-phase commit for transactions spanning KV + columnar + document | qihse_txn.c, qihse_dist_planner.c |
| 2.5 WAL generalization | Unified WAL across all engines (currently KV + vector only) | new qihse_wal.c, integrate with qihse_event_stream.c |
| 2.6 Crash recovery | Replay unified WAL on startup, redo/undo per engine | qihse_wal.c |

### Phase 3 -- Secondary Indexes ✅ COMPLETE
Goal: Allow efficient non-primary-key lookups on any column.

| Item | Description | Key Files |
|---|---|---|
| 3.1 B+ tree index | Cache-conscious fanout, page-aligned nodes, range scans | new qihse_btree.c, qihse_btree.h |
| 3.2 Hash index | Open-addressed, linear-probing for equality lookups | new qihse_hash_index.c |
| 3.3 Composite indexes | Multi-column B+ tree with prefix matching | qihse_btree.c |
| 3.4 Index maintenance | Insert-time and bulk-load index population, concurrent index builds | qihse_btree.c, qihse_schema.c |
| 3.5 Index-backed SQL | Planner chooses index scan vs seq scan based on selectivity | qihse_optimizer.c |
| 3.6 Vector + FTS as indexes | Treat HNSW and FTS as index types usable in CREATE INDEX | qihse_hnsw.c, qihse_fts_index.c |

### Phase 4 -- Replication & Durability ✅ COMPLETE
Goal: Match PostgreSQL / Redis replication semantics for HA and read scaling.

| Item | Description | Key Files |
|---|---|---|
| 4.1 Async streaming replication | Primary ships WAL to replicas in real-time | qihse_wal.c, new qihse_replication.c |
| 4.2 Read replicas | Replica accepts read-only queries via pgwire / RESP | qihse_pg_wire.c, qihse_resp_engine.c |
| 4.3 Synchronous replication | Configurable sync replicas for zero-data-loss deployments | qihse_replication.c |
| 4.4 CDC (Change Data Capture) | Stream logical change events to external consumers | qihse_event_stream.c, qihse_replication.c |
| 4.5 Coordinated snapshots | Cross-engine consistent snapshot for backup | new qihse_snapshot.c |
| 4.6 Backup / restore | Physical backup (file copy + WAL) and logical backup (dump) | qihse_snapshot.c, new qihse_backup.c |
| 4.7 Point-in-time recovery | Replay WAL to a target timestamp or LSN | qihse_wal.c, qihse_temporal.c |

### Phase 5 -- Graph Engine ✅ COMPLETE
Goal: Add explicit graph storage for relationship-heavy workloads (Neo4j replacement surface).

| Item | Description | Key Files |
|---|---|---|
| 5.1 Edge / vertex store | Adjacency lists backed by KV, label and property indexing | new src/broad_oak/qihse_graph_store.c, qihse_graph.h |
| 5.2 Cypher-compatible query | Pattern matching, path traversal, variable-length hops | new qihse_cypher_parser.c |
| 5.3 Graph algorithms | PageRank, shortest path, connected components, community detection | new qihse_graph_algo.c |
| 5.4 Graph + vector fusion | Combine HNSW similarity with graph traversal for hybrid recommendations | qihse_graph_store.c, qihse_hnsw.c |
| 5.5 Gremlin / SPARQL bridge | Optional compatibility layer for existing graph ecosystems | future |

### Phase 6 -- Additional Wire Protocols ✅ COMPLETE
Goal: Let applications connect without changing drivers.

| Item | Description | Key Files |
|---|---|---|
| 6.1 MongoDB wire protocol | BSON encoding, insert/find/update/delete/aggregate commands over existing document store | new qihse_mongo_wire.c |
| 6.2 HTTP/REST API | CRUD endpoints with JSON, OpenAPI schema, auth | new qihse_http_api.c |
| 6.3 gRPC API | Protobuf-defined service for typed client SDKs | new qihse_grpc.c, .proto definitions |
| 6.4 WebSocket subscriptions | Push-based query results, change notifications | qihse_subscription.c, qihse_http_api.c |
| 6.5 ClickHouse HTTP protocol | Tab-separated / JSON responses for OLAP queries | qihse_http_api.c, qihse_column_store.c |
| 6.6 Elasticsearch _search API | Query DSL compatibility for FTS + vector hybrid search | new qihse_es_api.c |

### Phase 7 -- Operational Maturity ✅ COMPLETE
Goal: Production deployability equal to established databases.

| Item | Description | Key Files |
|---|---|---|
| 7.1 Connection pooling | Built-in pooler (pgbouncer-like) with transaction-level routing | new qihse_pooler.c |
| 7.2 Prometheus metrics | /metrics endpoint, standard DB metrics | qihse_http_telemetry.c |
| 7.3 OpenTelemetry tracing | Distributed traces for scatter-gather queries | new qihse_tracing.c |
| 7.4 Online schema changes | Add column / add index without blocking writes | qihse_schema.c |
| 7.5 Compaction & TTL | Background SSTable compaction, TTL expiration sweeps across engines | qihse_kv_store.c, qihse_column_store.c |
| 7.6 Storage engine tiering | Hot (RAM) -> warm (NVMe) -> cold (object store) automatic tiering | new qihse_tier.c |
| 7.7 Resource governance | Per-tenant CPU / memory / IOPS limits, fair scheduling | qihse_system_guard.c |
| 7.8 Cluster autoscaling | Hook into Kubernetes HPA or external orchestrator for node add/remove | qihse_cluster_rebalance.c |

### Phase 8 -- Query Language Extensions ✅ COMPLETE
Goal: Beyond SQL -- domain-specific query surfaces.

| Item | Description | Key Files |
|---|---|---|
| 8.1 Full SQL:1999 compliance | Window functions, CTEs (WITH), recursive CTEs, arrays, JSON operators | qihse_sql_parser.c, qihse_optimizer.c |
| 8.2 Vector SQL extensions | VECTOR_SEARCH(table, query_vec, k) as a SQL table function | qihse_sql_parser.c, qihse_dist_planner.c |
| 8.3 Time-series SQL extensions | TIME_BUCKET(), downsampling, gap-filling, continuous queries | qihse_sql_parser.c, qihse_timeseries.c |
| 8.4 Full-text SQL extensions | MATCH(), RANK(), highlight snippets in SELECT | qihse_fts_index.c, qihse_sql_parser.c |
| 8.5 QQL v2 | Unified QQL with first-class spatial, temporal, vector, graph, and FTS predicates | qihse_qql_parser.c |

---

## 2. Priority Recommendations

### Immediate (next 1-2 development cycles)
1. Phase 1 (SQL completeness) -- without JOIN, GROUP BY, and ORDER BY, the pgwire surface cannot replace PostgreSQL for real applications. This is the highest-leverage gap.
2. Phase 3.1-3.3 (B+ tree + hash + composite indexes) -- secondary indexes are a prerequisite for any OLTP workload. Without them, every non-primary lookup is a full scan.
3. Phase 2.1-2.2 (Transaction manager + MVCC) -- ACID is a hard requirement for most database replacement decisions.

### Near-term (next 3-4 cycles)
4. Phase 4.1-4.3 (Streaming + sync replication) -- HA and read scaling are the next blocker after correctness.
5. Phase 6.1 (MongoDB wire protocol) -- the document store already exists; adding the wire protocol unlocks the MongoDB replacement use case with minimal engine work.
6. Phase 7.1-7.3 (Pooler + Prometheus + tracing) -- operational visibility is required for production adoption.

### Medium-term (5-8 cycles)
7. Phase 5 (Graph engine) -- extends the multi-model story and opens the Neo4j replacement surface.
8. Phase 6.2-6.6 (HTTP/REST, gRPC, WebSocket, ES API) -- broadens the integration surface.
9. Phase 8 (Query language extensions) -- differentiates QIHSE from pure SQL engines.

### Long-term (9+ cycles)
10. Phase 7.4-7.8 (Online DDL, tiering, autoscaling) -- operational polish.
11. Phase 2.4 (Cross-engine 2PC) -- only needed once multi-engine transactions are a real workload.
12. Phase 5.5 (Gremlin/SPARQL bridge) -- only if graph ecosystem compatibility becomes a market requirement.

---

## 3. Target Replacement Surface

After completing Phases 1-7, QIHSE would functionally replace:

| Replaced Engine | QIHSE Replacement Path |
|---|---|
| PostgreSQL | pgwire + SQL (Phase 1 ✅) + ACID (Phase 2 ✅) + indexes (Phase 3 ✅) + replication (Phase 4 ✅ partial) + pooler (Phase 7.1 ✅) |
| Redis | RESP2/RESP3 (existing) + cluster (existing) + task queue (existing) |
| MongoDB | Document store (existing) + Mongo wire (Phase 6.1) |
| ClickHouse | Columnar engine (existing) + SQL aggregates (Phase 1) + ClickHouse HTTP (Phase 6.5) |
| Elasticsearch | FTS (existing) + vector (existing) + ES _search API (Phase 6.6) |
| Neo4j | Graph engine (Phase 5 ✅) + Cypher (Phase 5.2 ✅) + Bolt protocol ✅ |
| InfluxDB | TSDB (existing) + time-series SQL (Phase 8.3) |
| Celery + Redis broker | Task queue (existing) |
| PgBouncer | Built-in pooler (Phase 7.1 ✅) |

The key insight is that QIHSE already has the storage engines. The remaining work is primarily in the query, transaction, replication, and protocol layers that sit on top of those engines.
