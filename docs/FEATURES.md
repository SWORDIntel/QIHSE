# QIHSE Features

> **Status: partial.** This is a feature map, and per-engine verification
> varies. Engines with CI-wired tests include the event stream, document store,
> column store, time-series, FTS, graph, vector DB and routing persistence.
> SQL, transactions and secondary indexes are covered by
> `tests/test_sql_completeness.c`, `tests/test_sql_dml_exec.c`,
> `tests/test_txn.c`, `tests/test_mvcc_delete.c` and `tests/test_indexes.c` —
> an earlier revision of this document said those test files did not exist, and
> that is no longer true. Read the per-area status lines in
> `tests/gold/pack.v1.gold` and in [architecture/](architecture/) for the
> specific gaps that remain (SQL INSERT does not yet populate the mutable row
> store that UPDATE/DELETE execute against, and the Bolt adapter does not
> return query results to a driver).

This document is the detailed feature map for QIHSE. The [root README](../README.md) intentionally stays higher level.

QIHSE is a native-C, multi-model database system built around a shared memory, execution, persistence, and protocol layer. The goal is not to bolt unrelated databases together; it is to expose different data models through one runtime.

## Core data engines

| Engine | Primary use | Core implementation |
|---|---|---|
| **Vector** | Similarity search and retrieval | Exact `float32` reranking, trinary `qtri`/`qmag` filtering, HNSW, FP16/FP8/INT8/INT4 candidate representations |
| **Key-value** | Low-latency keyed state | Trinary trie, LSM/SSTable persistence, WAL-backed durability |
| **Document** | JSON-like records | Native document storage with compiled access/query paths |
| **Time-series** | Telemetry and ordered numeric data | Lock-free ingress and Gorilla-style XOR/delta compression |
| **Columnar** | OLAP and analytical scans | SIMD-accelerated column scans, aligned storage, RLE paths |
| **Graph** | Relationship traversal | Vertex/edge store, Cypher parser/executor, graph algorithms, vector+graph fusion |
| **Full-text** | Lexical search | Native tokenization and BM25 scoring |
| **Event stream** | Append-only event/log workloads | Memory-mapped/sendfile-oriented append path and deduplication |

QIHSE also includes a SQLite VFS integration path and a distributed task queue/scheduler.

## Relational layer

QIHSE includes a relational query layer over the native storage engines.

Major components include:

- SQL parsing and execution
- sequential and index scans
- hash and nested-loop joins
- aggregation and sorting
- window functions
- a cost-based optimizer
- schema/catalog management
- prepared statements
- ACID transactions
- MVCC row versions and snapshot visibility
- unified WAL and crash recovery
- B+ tree and hash indexes
- two-phase commit interfaces
- parallel query execution

Key implementation documents:

- [SQL engine](architecture/sql_engine.md)
- [Transactions and MVCC](architecture/transactions_mvcc.md)
- [Secondary indexes](architecture/secondary_indexes.md)
- [Distributed query planner](architecture/distributed_query_planner.md)

## Graph layer

The graph subsystem provides:

- vertex and edge storage
- label and property indexes
- Cypher parsing and execution
- BFS and DFS
- Dijkstra and A*
- PageRank
- strongly connected components
- centrality calculations
- triangle counting
- graph/vector hybrid search

See [Graph engine](architecture/graph_engine.md) and [Bolt protocol](architecture/bolt_protocol.md).

## Persistence and recovery

QIHSE uses native persistence rather than delegating durability to an external database.

The persistence stack includes:

- LSM/SSTable storage paths
- write-ahead logging
- checkpoint and replay
- crash recovery
- full backup and restore, plus a real incremental (delta) export: the KV store
  stamps a store-global change sequence, and `qihse_backup_incremental_user()`
  writes a `BACKUP_INCREMENTAL` container of only the delta above a cursor
  (see [Replication and backup](architecture/replication_backup.md))
- replication slots and WAL shipping
- replica-side WAL apply into a bound store
- read-replica routing
- background compaction
- TTL expiration
- encrypted `.qdb` containers where configured

See:

- [Routing and persistence](architecture/routing_persistence.md)
- [Replication and backup](architecture/replication_backup.md)
- [SQLite VFS plan](qihse_sqlite_vfs_plan.md)

## Hardware-aware execution

QIHSE detects the available CPU instruction set and selects the appropriate implementation at build/runtime boundaries.

Supported execution paths include combinations of:

- scalar fallback
- SSE4.2 / AVX-class paths where available
- AVX2 + FMA
- AVX-512
- AVX-VNNI
- AMX on supported hosts

The codebase also contains heterogeneous compute paths for GPU/NPU experimentation and memory-topology-aware placement.

The important design point is graceful fallback: the system should remain buildable on older hosts while using wider SIMD when the machine supports it.

## Networking and protocol ingress

QIHSE's Unified Wire Protocol (UWP) provides a binary target-routing layer across database engines. The codebase also includes AF_XDP/eBPF paths for low-overhead ingress on supported Linux hosts.

UWP targets cover authentication plus database and operational services including KV, vector, document, columnar, time-series, graph, stream, SQL, transactions, indexes, schema, replication, and pooling.

See [Operational protocols](architecture/operational_protocols.md) and the [AF_XDP operational guide](manual/deployment/AF_XDP_OPERATIONAL_GUIDE.md).

## Federation data plane

The federation layer turns a cluster of QIHSE instances into a
partition-aware data plane without making local operation depend on global
quorum. Landed and tested:

- scoped consensus for strong namespaces (`include/qihse_consensus.h`):
  persistent term/voted-for/fencing state, log matching, majority+current-term
  commit, log compaction with snapshot install, single-server membership
  changes — deliberately not called Raft; boundaries stated in the header
  (`tests/test_consensus.c`, `make test-consensus`)
- signed backup containers (v3: `[ header 464 ][ signature ][ data ][ WAL ]`,
  ML-DSA over the header, classification-preserving WAL replay, v1/v2
  retired) and a verify-only entry point (`tests/test_backup_auth.c`,
  `tests/test_federation_backup.c`)
- node-side CRL consumption composing with KV revocation state, plus the
  out-of-process federation CA tool (`make federation-ca`)
  (`tests/test_federation_crl.c`, `tests/test_federation_ca.c`)
- controller SDKs over the `FEDERATION.*` RESP surface: C reference client
  (`include/qihse_controller.h`), Python (`python/qihse/controller.py`,
  `python/tests/test_controller_sdk.py`) and Rust
  (`rust/qihse-rs/src/controller.rs`, `tests/controller_sdk.rs`)
- incremental export from the KV change sequence, authorization-filtered with
  a no-leak resume point (`tests/test_incremental_export.c`)

See [Federation overview](architecture/federation_overview.md).

## Operations

The operational layer includes:

- streaming replication
- read replicas
- full backup and restore with incremental (delta) export — see above
- parallel query execution
- connection pooling
- change data capture
- Prometheus-format metrics
- OpenTelemetry-style tracing
- background compaction and TTL
- SQL extensions such as vector search, time bucketing, and full-text matching

## Task queue and scheduler

QIHSE includes a native distributed task queue with:

- multiple priority levels
- worker pools
- retries
- asynchronous dispatch
- periodic scheduling
- Python-facing task APIs

See [Task queue plan](plans/qihse_task_queue_plan.md).

## Security-related capabilities

Security functionality includes:

- authentication on protocol entry points
- per-object authorization/ACL handling
- rate limiting and account lockout paths
- bounded frame handling
- TLS 1.3 support for UWP deployments configured with certificates
- ChaCha20-Poly1305 AEAD fallback mode for selected trusted/development deployments
- connection and idle limits
- protocol metrics and audit paths
- sanitizer, fuzz, and concurrency regression coverage
- post-quantum cryptographic primitives in configured `.qdb` container workflows
- CNSA 2.0 key generation (ML-KEM-1024 + ML-DSA-87) via native C keygen
- optional operator password binding via FIPS YubiKey/HSM PIV slot 9c
- operator key stored securely in `~/.ssh/qihse_operator_key` (chmod 600)
- `.ssh` directory enforced at chmod 700
- normal operator-only mode requires no manually configured password
- five-second builder HSM prompt defaults to skip for noninteractive operation
- first-class tenancy: tenant-scoped principals (`t:<id>/` namespaces enforced
  deny-by-default at the engine boundary), delegated creation floored to the
  lowest rank, operator-set clearance/SCI at creation or via modification,
  per-tenant quotas, and immediate mid-session revocation
- content-addressed blob store with per-blob tenant/tag/classification binding
- session-bundle compose and chunked RESP delivery with fresh per-session
  ML-KEM-1024 session keys and a commons-poisoning sanity gate
- closed-schema PII-free telemetry ingest gate for the `t:*/tlm/…` namespace
- fleet-wide killswitch pub/sub channel (tenant-readable, system-publish-only)
- tenant-subset export artifacts, background expiry sweeps, delivery metrics

See [Session-delivery subsystem](architecture/session_delivery.md).

Security claims and limitations are documented separately because they change faster than the architectural overview. See [Security](security/README.md), [UWP cryptographic design](security/UWP_CRYPTO_DESIGN.md), and the [August 2026 UWP audit](security/UWP_AUDIT_2026-08.md).

## External database compatibility

QIHSE contains compatibility layers for existing database clients and protocols, including PostgreSQL, Redis, MongoDB, Neo4j/Bolt, Elasticsearch-style HTTP APIs, ClickHouse-style HTTP APIs, InfluxDB-style APIs, and PgBouncer-like pooling/admin behavior.

Those interfaces are described in [Compatibility](COMPATIBILITY.md).

## SDKs

SDKs and compatibility bindings are grouped under [`sdks/`](../sdks/):

- [`sdks/python/`](../sdks/python/) — Python bindings and compatibility clients
- [`sdks/rust/`](../sdks/rust/) — Rust bindings
- [`sdks/c/`](../sdks/c/) — C compatibility interfaces

The federation controller SDKs are separate from the compatibility set: the C
reference client (`include/qihse_controller.h`), the Python SDK
([`python/qihse/controller.py`](../python/qihse/controller.py)) and the Rust
SDK ([`rust/qihse-rs/src/controller.rs`](../rust/qihse-rs/src/controller.rs)).

## Benchmarks

Benchmark results are kept out of the root README because performance claims only make sense with workload and hardware context.

See [`docs/benchmarks/`](benchmarks/) for methodology, test conditions, regression procedures, and recorded results.
