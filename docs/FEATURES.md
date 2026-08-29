# QIHSE Features

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
- full and incremental backup
- replication slots and WAL shipping
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

## Operations

The operational layer includes:

- streaming replication
- read replicas
- full/incremental backup and restore
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

Security claims and limitations are documented separately because they change faster than the architectural overview. See [Security](security/README.md), [UWP cryptographic design](security/UWP_CRYPTO_DESIGN.md), and the [August 2026 UWP audit](security/UWP_AUDIT_2026-08.md).

## External database compatibility

QIHSE contains compatibility layers for existing database clients and protocols, including PostgreSQL, Redis, MongoDB, Neo4j/Bolt, Elasticsearch-style HTTP APIs, ClickHouse-style HTTP APIs, InfluxDB-style APIs, and PgBouncer-like pooling/admin behavior.

Those interfaces are described in [Compatibility](COMPATIBILITY.md).

## SDKs

SDKs and compatibility bindings are grouped under [`sdks/`](../sdks/):

- [`sdks/python/`](../sdks/python/) — Python bindings and compatibility clients
- [`sdks/rust/`](../sdks/rust/) — Rust bindings
- [`sdks/c/`](../sdks/c/) — C compatibility interfaces

## Benchmarks

Benchmark results are kept out of the root README because performance claims only make sense with workload and hardware context.

See [`docs/benchmarks/`](benchmarks/) for methodology, test conditions, regression procedures, and recorded results.
