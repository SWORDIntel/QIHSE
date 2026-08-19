# QIHSE Performance Benchmarks & Hot-Path Profiling Report

QIHSE treats data retrieval as a low-level systems problem. Rather than acting as a traditional managed dashboard or heavy intermediary application, QIHSE acts as a native memory overlay with SIMD-accelerated execution pipelines.

To validate sub-microsecond retrieval across diverse storage paradigms, QIHSE provides a dedicated profiling harness (`make bench-hotpath`) measuring latency percentiles (mean, p50, p95, p99, max) and transaction throughput across all core engines.

---

## 1. Full-System Hot-Path Benchmark Results

**Host Environment:** Intel Xeon E5-2407 (8 cores @ 2.20GHz), 96 GB Physical RAM, AVX1 execution mode, Linux 6.8 kernel.

### Subsystem Latency & Throughput Summary

```
=======================================================================
  QIHSE FULL-SYSTEM ARCHITECTURAL BENCHMARK & HOT-PATH PROFILING       
=======================================================================
```

#### A. Vector Database Engine (Exact SIMD Math)
*Dataset: 10,000 unit vectors × 128 dimensions*
| Metric / Distance Function | Mean Latency | p50 (Median) | p95 Latency | p99 Latency | Max Latency |
| :--- | :--- | :--- | :--- | :--- |
| **Exact Dot-Product Rerank** | `0.04 μs` (40 ns) | **`38 ns`** | `40 ns` | `50 ns` | `90 ns` |
| **Exact L2 Euclidean Distance** | `0.04 μs` (40 ns) | **`38 ns`** | `40 ns` | `40 ns` | `70 ns` |
| **Exact Cosine Distance Rerank** | `0.07 μs` (70 ns) | **`40 ns`** | `50 ns` | `60 ns` | `5.22 μs` |

---

#### B. Key-Value Subsystem & Trinary Trie
*Dataset: 50,000 keys (Trinary Trie Indexing, LSM MemTable & WAL)*
| Engine Layer & Access Mode | Throughput | Mean Latency | p50 (Median) | p99 Latency |
| :--- | :--- | :--- | :--- | :--- |
| **Raw Trinary Trie Search** | **`5,864,436 queries/sec`** | `170.52 ns` | **`150 ns`** | `311 ns` |
| **In-Memory Trie Set** | **`971,596 writes/sec`** | `0.65 μs` | **`290 ns`** | `3.80 μs` |
| **KV Set (Buffered WAL Ingress)** | **`489,089 writes/sec`** | `1.76 μs` | **`550 ns`** | `56.43 μs` |
| **KV Point Get (CNSA 2.0 Guarded)** | **`418,143 reads/sec`** | `2.20 μs` | **`320 ns`** | `550 ns` |

---

#### C. SQLite VFS Engine
*Dataset: 10,000 records (Batch Transaction) & 1,000 Point Selects*
| Operation | Metric | Benchmark Result |
| :--- | :--- | :--- |
| **Bulk Transaction Insert** | Throughput | **`116,259 rows/sec`** (`10k rows in 86 ms`) |
| **Indexed Point Select (VFS Cached)** | p50 Latency | **`7.42 μs`** |
| **Indexed Point Select (VFS Cached)** | p95 Latency | **`8.37 μs`** |
| **Cache Hit Mode** | Layer | Served directly from QIHSE 64MB LRU Page Cache |

---

#### D. Time-Series Telemetry (Gorilla XOR Engine)
*Dataset: 20,000 temporal data points*
| Operation | Metric | Benchmark Result |
| :--- | :--- | :--- |
| **Point Ingestion Rate** | Throughput | **`4,796,298 points/sec`** |
| **Per-Point Ingestion Latency** | p50 (Median) | **`40 ns`** (`0.13 μs` mean) |
| **Range Average Scan** | Latency | **`876.15 μs`** (for 20,000 points) |

---

#### E. Columnar OLAP Engine
*Dataset: 50,000 float32 elements*
| Operation | Metric | Benchmark Result |
| :--- | :--- | :--- |
| **SIMD Sum Aggregation** | Latency | **`297.28 μs`** |
| **Vector Scan Bandwidth** | Throughput | Continuous L1/L2 streamed aggregation |

---

## 2. Hot-Path Optimizations & Architectural Analysis

### Optimization 1: $O(N)$ Parallel Array Elimination in Key-Value Engine
* **The Bottleneck**: Point retrieval (`qihse_kv_get_user`) and insertion previously maintained a secondary dynamically resized array `store->keys` to track security classification tags and expiration metadata. Every `get` and `set` performed an $O(N)$ linear `strcmp` scan across all $N$ keys. At 50k keys, this caused **40.8 μs** latency per lookup.
* **The Solution**: Replaced the parallel array with **in-node trie payloads** (`kv_payload_t`), embedding `classification`, `sci_compartment`, and `expire_time_ms` directly alongside the value bytes in the Trinary Trie leaf nodes.
* **Result**: Lookup latency dropped from **`40.8 μs` to `320 ns`** (a **~67x speedup**), with point queries executing in $O(\text{key\_len})$ time directly from cache.

### Optimization 2: 64KB Buffered WAL Logging
* **The Bottleneck**: `qihse_kv_set()` previously called `fflush(store->wal_fd)` synchronously on every write operation, creating 50,000 blocking filesystem syscalls and limiting write throughput to `29.8k ops/sec`.
* **The Solution**: Introduced a **64KB write buffer threshold** with automated flushing on block boundaries, MemTable rotation, and database close.
* **Result**: Write throughput jumped from **`29,823 writes/sec` to `489,089–509,358 writes/sec`** (a **~16.4x speedup**), reducing write latency to **`550 ns` p50**.

### Optimization 3: Writable Data Directory Fallback
* **The Solution**: Added automated resolution to `./data/qihse/` when `/var/lib/qihse/` is unprivileged, enabling non-root applications and automated CI/CD harnesses to execute durable LSM-Tree SSTable persistence and WAL crash recovery seamlessly.

---

## 3. Before vs. After Optimization Matrix

| Subsystem & Metric | Baseline (Pre-Optimization) | Optimized Engine | Performance Multiplier |
| :--- | :--- | :--- | :--- |
| **KV Point Get Latency (p50)** | `40.01 μs` (40,010 ns) | **`0.32 μs` (320 ns)** | **67x Faster** 🚀 |
| **KV Point Get Throughput** | `24,333 reads/sec` | **`418,143–1,629,212 reads/sec`** | **17x–67x Higher** 🚀 |
| **KV Write Ingress Throughput** | `29,823 writes/sec` | **`489,089–509,358 writes/sec`** | **16.4x Higher** 🚀 |
| **KV Write Latency (p50)** | `25.93 μs` | **`0.55 μs` (550 ns)** | **47x Faster** 🚀 |
| **Raw Trinary Trie Traversal** | `150 ns` p50 | **`150 ns` p50** | Hardware Wire Speed |
| **Gorilla XOR Ingestion** | `40 ns` p50 | **`40 ns` p50** | `4.80M–5.10M pts/sec` |

---

## 4. Competitive Architectural Advantage

| Feature / Metric | Conventional Databases (Redis / Chroma / Postgres) | QIHSE Native Engine |
| :--- | :--- | :--- |
| **Vector Similarity Math** | 200–500 μs (network IPC + serial serialization) | **38–40 ns** (zero-copy direct SIMD registers) |
| **Multi-Modal Concurrency** | Single-threaded event loop blocking or heavy B-Tree lock contention | Disjoint lockless memory structures per engine plane |
| **Time-Series Ingestion** | 50k–200k points/sec (JSON / SQL parse overhead) | **4.8M–5.1M points/sec** (Gorilla XOR bit-packing) |
| **Memory Architecture** | Unmanaged virtual memory / Garbage collected heap | NUMA-aware, HugePage-aligned UMA/HMA tiering |
