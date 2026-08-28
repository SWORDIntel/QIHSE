# QIHSE System Architecture & Engine Overview

QIHSE is a native C99 multi-model database engine designed for high-throughput, low-latency workloads. It unifies eight distinct storage engines under a single process space and memory hierarchy, eliminating the operational overhead of managing fragmented database infrastructure.

---

## 1. Storage Engine Surface

QIHSE provides eight specialized storage engines alongside an integrated SQLite VFS compatibility layer:

| Engine | Primary Abstraction | Implementation Details |
|---|---|---|
| **Vector DB** | Dense vector search | Exact `float32` reranking with Trinary signature (`qtri`/`qmag`) filtering, multi-precision quantization (`FP16`, `FP8`, `INT8`, `INT4`), and HNSW graph traversal. |
| **Key-Value Store** | $O(k)$ key-value indexing | Trinary Trie in-memory index backed by LSM-Tree memtables and SSTable disk persistence. |
| **Document Store** | JSON document storage | JIT-compiled path evaluators translating frequent access patterns directly into bytecode. |
| **Time-Series DB** | Append-only telemetry | Lock-free ingress ring buffers with Gorilla XOR delta-of-delta bit-packing. |
| **Columnar Engine** | Vectorized OLAP | AVX2/AVX-512 accelerated columnar scans with Run-Length Encoding (RLE) and dictionary compression. |
| **Graph Engine** | Multi-hop relationships | Dual Anchor and HNSW traversal for fast path resolution across large relational graphs. |
| **Full-Text Search** | Lexical indexing | Zero-copy tokenization with native BM25 relevance scoring. |
| **Event Stream** | Append-only commit log | Kernel-bypass DMA I/O via `mmap` and `sendfile` with SHA-384 frame deduplication. |
| **SQLite VFS** | Relational compatibility | Drop-in `sqlite3_vfs` backend utilizing the Black Hole KV store and Marmalade Event Stream. |

---

## 2. Query & Transaction Layer

QIHSE provides a full relational query and transaction layer on top of the storage engines:

### 2.1 SQL Engine

The SQL parser (`src/tractable/qihse_sql_parser.c`) supports the full SQL surface needed for application workloads:

- **DML**: SELECT, INSERT, UPDATE, DELETE
- **DDL**: CREATE TABLE with typed columns (INT, BIGINT, FLOAT, DOUBLE, VARCHAR, TEXT, BOOL, TIMESTAMP, VECTOR), ALTER TABLE (ADD/DROP/RENAME COLUMN), CREATE INDEX, DROP INDEX, DROP TABLE
- **JOIN**: INNER, LEFT, RIGHT, CROSS, FULL OUTER with ON clauses
- **Aggregation**: GROUP BY, HAVING, SUM, COUNT, AVG, MIN, MAX, COUNT(*), DISTINCT
- **Sorting**: ORDER BY with ASC/DESC, multi-column sort keys
- **Subqueries**: Scalar subqueries in SELECT list, IN/EXISTS in WHERE, correlated subqueries
- **Set operations**: UNION, INTERSECT, EXCEPT
- **Pagination**: LIMIT and OFFSET
- **Prepared statements**: Parse-once, execute-many via pgwire extended query protocol (Parse/Bind/Execute/Describe/Close/Sync)

### 2.2 Query Executors

| Executor | File | Description |
|---|---|---|
| **Join Executor** | `src/tractable/qihse_join_executor.c` | Hash-join (build/probe with hash table on join key) and nested-loop join operators with generic row stream abstraction |
| **Aggregate Executor** | `src/tractable/qihse_aggregate_executor.c` | Hash-based aggregation with group-by, distinct tracking, accumulator state for SUM/COUNT/AVG/MIN/MAX |
| **Sort Executor** | `src/tractable/qihse_sort_executor.c` | In-memory sort-merge with configurable spill-to-disk for large result sets, multi-key numeric/string comparison |
| **Index Scan** | `src/tractable/qihse_index_scan.c` | EQ, RANGE, and PREFIX predicate scans over B+ tree and hash indexes |

### 2.3 Cost-Based Optimizer

The optimizer (`src/tractable/qihse_optimizer.c`) provides:

- Per-column statistics with histograms and most-common-value tracking
- Cardinality estimation for filter conditions (equality, range)
- Selectivity-based plan enumeration: seq scan vs index scan
- Join algorithm selection: hash join vs nested loop based on cardinality estimates
- Plan tree output that executors follow

### 2.4 Schema Registry

The schema registry (`src/tractable/qihse_schema.c`) maintains:

- Table definitions with typed columns
- Index metadata (index name, columns, index type)
- ALTER TABLE operations (ADD COLUMN, DROP COLUMN, RENAME COLUMN, RENAME TABLE)
- CREATE/DROP INDEX operations

---

## 3. Transaction & MVCC Layer

### 3.1 Transaction Manager

The transaction manager (`src/tractable/qihse_txn.c`) provides full ACID transaction support:

- **BEGIN / COMMIT / ROLLBACK / SAVEPOINT**: Full transaction lifecycle with savepoint stacks for partial rollback
- **Transaction ID allocation**: Monotonic 64-bit IDs, thread-safe with mutex
- **Transaction registry**: Tracks all active, committed, and aborted transactions
- **Isolation levels**:
  - **READ COMMITTED**: Fresh snapshot per statement
  - **REPEATABLE READ**: Snapshot held for entire transaction
  - **SERIALIZABLE**: Optimistic concurrency control (OCC) with read-set/write-set tracking and conflict validation at commit time
- **Two-phase commit (2PC)**: Coordinator interface with participant callbacks (prepare, commit, abort) for cross-engine distributed transactions

### 3.2 MVCC Version Store

The MVCC store (`src/tractable/qihse_mvcc.c`) implements per-row version chains:

- **Version metadata**: Each version records `xmin` (creating txn ID) and `xmax` (deleting/superseding txn ID)
- **Visibility check**: A version is visible to a transaction if `xmin <= snapshot` AND (`xmax` is unset OR `xmax > snapshot`)
- **Garbage collection**: Dead versions (not visible to any active transaction) are collected by vacuum
- **Multi-engine support**: Version chains work across KV, document, columnar, vector, and event stream engines via engine ID tagging

### 3.3 Unified WAL

The Write-Ahead Log (`src/tractable/qihse_wal.c`) provides durability across all engines:

- **Record format**: LSN (8 bytes), txn_id (8 bytes), engine_id (1 byte), op_type (1 byte), key/value with lengths, CRC32 checksum
- **Segment rotation**: Configurable segment size (default 64 MB), automatic rotation
- **Durability modes**: none (no fsync), fdatasync per commit, group commit (batch fsync)
- **Checkpoint**: Flush all engine state, record checkpoint LSN, truncate old WAL segments

### 3.4 Crash Recovery

The recovery module (`src/tractable/qihse_recovery.c`) implements three-phase recovery:

1. **Analysis phase**: Scan WAL, build transaction status table (active/committed/aborted)
2. **Redo phase**: Re-apply all committed mutations to the MVCC store
3. **Undo phase**: Mark uncommitted transactions as aborted in the transaction manager

---

## 4. Secondary Index Layer

### 4.1 B+ Tree Index

The B+ tree (`src/frieze/qihse_btree.c`) provides:

- **Page-aligned (4 KB) nodes** for TLB efficiency
- **Configurable fanout** (default 128 for int64 keys)
- **Key types**: int32, int64, float64, variable-length strings
- **Composite keys**: Sort-preserving serialization for multi-column indexes with prefix matching
- **Range scans**: Leaf node linked list for efficient range iteration
- **Thread-safe**: Per-tree pthread rwlock

### 4.2 Hash Index

The hash index (`src/frieze/qihse_hash_index.c`) provides:

- **Open-addressed** with linear probing for cache efficiency
- **Dynamic resizing**: Grows when load factor exceeds 0.7
- **Key types**: int64 and string keys
- **Tombstone markers** for deletions with reuse on subsequent inserts
- **Thread-safe**: Per-index pthread rwlock

### 4.3 Index Manager

The index manager (`src/frieze/qihse_index_manager.c`) provides:

- **Index types**: BTREE, HASH, VECTOR_HNSW, FTS_INVERTED
- **Per-table index tracking**: Multiple indexes per table, lookup by name
- **Synchronous insert-time updates**: Indexes updated atomically with data writes
- **Bulk-load support**: Sort-then-build for initial index creation on existing data
- **HNSW/FTS wrappers**: Existing vector and full-text indexes can be registered as index types via vtable

---

## 5. Unified Wire Protocol (UWP)

The Unified Wire Protocol (UWP) is a binary, memory-aligned protocol that routes network packets directly into engine-specific C data structures with zero intermediate allocations.

```
+-------------------+-------------------+-----------------------------------+
| Target ID (1 Byte)| Command (1 Byte)  | Payload (Aligned struct / bytes)  |
+-------------------+-------------------+-----------------------------------+
```

### Protocol Target Mapping

| Target ID | Target Engine | Operations |
|---|---|---|
| `0x01` | Key-Value Store | Set, Get, Delete, Expire |
| `0x02` | Vector DB | Upsert, Search, Delete, Flush |
| `0x03` | Document Store | Insert JSON, Query, Update |
| `0x04` | Columnar Engine | Append Column, Batch Scan |
| `0x05` | Time-Series DB | Insert Points, Range Query |
| `0x06` | Graph Engine | Insert Edge, Multi-Hop Traverse |
| `0x07` | Event Stream | Append Record, Stream Replay |

---

## 6. Wire Protocol Compatibility

QIHSE supports multiple wire protocols for drop-in compatibility with existing applications:

| Protocol | File | Compatibility |
|---|---|---|
| **RESP2/RESP3** | `src/spinnaker/qihse_resp_engine.c` | Redis-compatible commands, cluster routing (MOVED/ASK), TASK.* and SCHEDULE.* extensions |
| **PostgreSQL Wire** | `src/spinnaker/qihse_pg_wire.c` | PostgreSQL wire protocol with sharded catalogs, distributed planner, prepared statements (extended query protocol) |
| **UWP** | `src/spinnaker/qihse_uwp.c` | Native binary protocol with zero-copy engine routing |

---

## 7. Hardware Acceleration & Dynamic Dispatch

QIHSE uses runtime CPUID capability detection to select the most efficient vector math implementation without requiring separate compilation targets:

- **AVX-512 / VNNI / AMX**: Selected automatically on modern Intel/AMD architectures for high-throughput distance calculations and columnar scans.
- **AVX2 / FMA**: Selected on systems with 256-bit SIMD support.
- **AVX1 / SSE4.2**: Graceful fallback on older x86_64 host hardware.
- **Scalar / Portable**: Guaranteed bit-exact fallback on non-x86 or constrained virtualized environments.

Memory maintenance operates across both Unified Memory Architectures (UMA) and Heterogeneous Memory Architectures (HMA) with automatic tiering based on access temperature (`vectors.qtier`).

---

## 8. Security & Access Control

For defense and intelligence installations requiring cell-level access controls:

- **Compartmented Access**: Optional classification level and SCI compartment bitmasks on individual keys and vectors.
- **Constant-Time Rejection**: Unauthorized access requests execute algorithmic paths indistinguishable from missing keys to prevent timing analysis.
- **CNSA 2.0 Aligned Cryptography (In Progress):** Optional transparent page-level encryption via AES-256-GCM, ML-KEM-1024 key encapsulation, and ML-DSA-87 signature validation (data at rest). Transport encryption (ChaCha20-Poly1305 AEAD) is implemented and opt-in via ctx->tls_ctx; cleartext is the default.
- **Audit Hash Chains**: Append-only cryptographic ledger tracking access modifications and security events.

---

## 9. Cluster & Distribution

QIHSE provides a full clustered deployment model:

- **16,384 hash slots** with CRC16 slot mapping (Redis-compatible)
- **MOVED / ASK redirection** for cluster routing
- **UDP gossip bus** for cluster topology propagation
- **Raft-based failover** with replica promotion
- **Zero-downtime slot migration** with ASK handoff
- **Distributed scatter-gather planner** with RRF fusion and aggregate reduction
- **NUMA-pinned workers** for cluster operations

---

## 10. Task Queue & Scheduler

QIHSE includes a Celery-equivalent distributed task queue:

- **4 priority levels**: CRITICAL, HIGH, NORMAL, LOW
- **Dedicated worker pool**: NUMA-aware thread binding, pause/resume, dynamic worker count
- **Retry with exponential backoff** and jitter
- **Dead-letter/dead state** after exhausted retries
- **Periodic cron scheduling**: 10ms timing wheel, TSDB persistence, cron parser
- **Python SDK**: `@task` decorator, `.delay()`, `.apply_async()`, `AsyncResult.get()`
- **RESP commands**: TASK.SUBMIT, TASK.RESULT, TASK.STATUS, TASK.CANCEL, TASK.RETRY, TASK.DELETE, TASK.QUEUE, TASK.STATS, TASK.WORKERS, SCHEDULE.ADD/REMOVE/LIST/ENABLE/DISABLE/NEXT

---

## 11. Architectural Topology

For the complete standalone, full-page subsystem schematic detailing kernel-bypass ingress, engine routing, and disk persistence layers, refer to:

> **[View the Full Subsystem Architecture Diagram](../diagrams/subsystem_architecture.md)**
