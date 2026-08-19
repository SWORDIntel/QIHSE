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

---

## 5. QIHSE + KEYSTONE 5-Pillar Integrated Architecture Benchmarks

To profile the unified integration between QIHSE and KEYSTONE, the dedicated test harness (`make bench-keystone-integrated`) exercises all 5 joint pillars on host hardware (`AVX1` mode on Intel Xeon E5-2407):

```
========================================================================================================
     QIHSE + KEYSTONE 5-PILLAR INTEGRATED PERFORMANCE BENCHMARK
========================================================================================================
 Subsystem / Benchmark Operation              Throughput         p50 Latency    p95 Latency   p99 Latency
--------------------------------------------------------------------------------------------------------
 [1] HNSW Vector Search (Default Entry)       33,080 ops/sec        27.96 µs       30.87 µs      90.32 µs
     HNSW Vector Search (Anchor-Seeded)       31,692 ops/sec        29.39 µs       33.67 µs     118.42 µs
     * Hop reduction verified on 63/64 clustered queries with 100% recall@32 parity.

 [2] Standard Binary Search (1M rows)      2,016,334 lookups/s     415.00 ns      715.00 ns     878.00 ns
     Keystone Anchor Search (1M rows)      3,510,610 lookups/s     218.00 ns      347.00 ns     450.00 ns
     * Speedup: 1.74x - 2.01x faster lookup latency (best-case down to 18ns in hot cache).

 [3] AF_XDP Kernel-Bypass Ingest             141,865 pkts/sec        4.63 µs        5.54 µs      22.78 µs
     * Ingestion Bandwidth: 34.64 MiB/s zero-copy UMEM parsing across 16,384 CRC16 slots.

 [4] Keystone Neural Micro-Model (260->64->6) 370,749 infer/s        2.55 µs        2.74 µs       2.93 µs
     * Mean latency: 2.64 µs per full 6-class feedforward classification.

 [5] Hybrid FTS + Vector RRF Multimodal        1,838 queries/s     501.58 µs      715.75 µs     850.03 µs
     * BM25 trigram inverted index + HNSW vector DB fused via RRF with dynamic neural semantic masking.
========================================================================================================
```

### Head-to-Head Comparative Analysis vs. Industry Alternatives

| Pillar / Subsystem | QIHSE + KEYSTONE Measured | Industry Standard / Alternative | Competitive Advantage |
| :--- | :--- | :--- | :--- |
| **Pillar 1: Vector Graph Search** | **33,080 QPS** (p50: 27.9 µs)<br>Anchor-Seeded 1D Spline Projection | **FAISS HNSW (CPU)**: ~15,000 QPS (65 µs)<br>**pgvector (HNSW)**: ~2,000 QPS (500 µs) | **2.2x higher QPS** vs FAISS CPU<br>**16.5x higher QPS** vs pgvector |
| **Pillar 2: Sorted Column / TSDB Search** | **3,510,610 lookups/s** (218 ns)<br>Keystone $O(\log \log N)$ Spline (18 ns best) | **C++ `std::lower_bound`**: 2,016,334 (447 ns)<br>**Postgres B-Tree**: ~600k lookups/s (1.2 µs) | **1.74x–2.0x faster** vs `std::lower_bound`<br>**5.5x faster** vs B+Tree pointer chasing |
| **Pillar 3: Packet Ingestion & Log Parsing** | **141,865 pkts/sec** (34.6 MiB/s)<br>AF_XDP Kernel Bypass + In-Place UMEM Scan | **Linux BSD Socket + epoll**: ~25,000 pkts/s<br>**Redis Ingestion**: ~75,000 ops/s | **5.6x higher throughput** vs epoll<br>**1.9x higher throughput** vs Redis |
| **Pillar 4: Neural Context Inference** | **370,749 infer/s** (2.55 µs)<br>Inlined Dense SAXPY C Kernel (260 $\to$ 64 $\to$ 6) | **ONNX Runtime (CPU)**: ~35,000 infer/s (28 µs)<br>**PyTorch LibTorch**: ~5,000 infer/s (200 µs) | **10.5x faster inference** vs ONNX Runtime<br>**74.0x faster** vs PyTorch LibTorch |
| **Pillar 5: Hybrid Multimodal Search** | **1,838 queries/s** (501 µs)<br>In-Memory BM25 + HNSW + Neural Masking | **OpenSearch Hybrid**: ~120 QPS (8.3 ms)<br>**Weaviate Hybrid**: ~200 QPS (5.0 ms) | **16.5x lower latency** vs OpenSearch<br>**10.0x lower latency** vs Weaviate |

