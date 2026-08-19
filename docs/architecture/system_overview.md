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

## 2. Unified Wire Protocol (UWP)

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

## 3. Hardware Acceleration & Dynamic Dispatch

QIHSE uses runtime CPUID capability detection to select the most efficient vector math implementation without requiring separate compilation targets:

- **AVX-512 / VNNI / AMX**: Selected automatically on modern Intel/AMD architectures for high-throughput distance calculations and columnar scans.
- **AVX2 / FMA**: Selected on systems with 256-bit SIMD support.
- **AVX1 / SSE4.2**: Graceful fallback on older x86_64 host hardware.
- **Scalar / Portable**: Guaranteed bit-exact fallback on non-x86 or constrained virtualized environments.

Memory maintenance operates across both Unified Memory Architectures (UMA) and Heterogeneous Memory Architectures (HMA) with automatic tiering based on access temperature (`vectors.qtier`).

---

## 4. Security & Access Control

For defense and intelligence installations requiring cell-level access controls:

- **Compartmented Access**: Optional classification level and SCI compartment bitmasks on individual keys and vectors.
- **Constant-Time Rejection**: Unauthorized access requests execute algorithmic paths indistinguishable from missing keys to prevent timing analysis.
- **CNSA 2.0 Cryptography**: Optional transparent page-level encryption via AES-256-GCM, ML-KEM-1024 key encapsulation, and ML-DSA-87 signature validation.
- **Audit Hash Chains**: Append-only cryptographic ledger tracking access modifications and security events.

---

## 5. Comprehensive Subsystem Architecture

The following diagram maps the entire subsystem topology, from low-level eBPF packet ingress and protocol decoding down through memory tiering, SIMD execution units, and durable persistence layers:

```mermaid
flowchart TB
    %% Client & Network Ingress
    subgraph INGRESS["Network Ingress & Protocol Layer"]
        direction TB
        XDP["eBPF / AF_XDP Driver<br/>(Kernel-Bypass Raw Sockets)"]
        UWP["UWP Binary Dispatcher<br/>(Zero-Copy Target 0x01–0x07)"]
        SQL_API["SQLite VFS Interface<br/>(file:*.db?vfs=qihse)"]
        AUTH["CNSA 2.0 Security Guard<br/>(Cell-Level Auth & Constant-Time Rejection)"]
        
        XDP --> UWP
        SQL_API --> AUTH
        UWP --> AUTH
    end

    %% Unified Storage Engine Matrix
    subgraph ENGINES["Multi-Modal Engine Matrix"]
        direction TB
        
        subgraph VEC_PLANE["Vector & Semantic Search"]
            VDB["Vector DB Core<br/>(Exact float32 Reranker)"]
            QMAG["Trinary Filter<br/>(qtri / qmag Signatures)"]
            HNSW["HNSW Graph Index<br/>(Multi-Hop Traversal)"]
            QUANT["Quantization Pipeline<br/>(FP16 / FP8 / INT8 / INT4)"]
            
            HNSW --> QMAG
            QUANT --> QMAG
            QMAG --> VDB
        end

        subgraph REL_PLANE["Relational & Structured Engines"]
            KV["Black Hole KV Store<br/>(Trinary Trie + MemTable)"]
            DOC["Document Store<br/>(JIT Bytecode Evaluator)"]
            COL["Columnar Engine<br/>(AVX OLAP & RLE Sweeps)"]
            FTS["BM25 Search Index<br/>(Zero-Copy Tokenizer)"]
            GRAPH["Graph Engine<br/>(Anchor Traversal)"]
        end

        subgraph STREAM_PLANE["Stream & Telemetry Engines"]
            TS["Time-Series Engine<br/>(Gorilla XOR Bit-Packing)"]
            EVT["Marmalade Event Stream<br/>(DMA Append-Only Log)"]
        end
    end

    %% Memory & Compute Acceleration
    subgraph COMPUTE_MEM["Compute Acceleration & Memory Subsystem"]
        direction TB
        
        subgraph MEMORY["Hierarchical Memory (UMA / HMA)"]
            TIER["Access Tiering Controller<br/>(vectors.qtier Hot/Cold)"]
            NUMA["NUMA-Aware Allocator<br/>(HugePages / DMA Ring Buffers)"]
        end

        subgraph SIMD_DISPATCH["Hardware Execution Dispatch"]
            CPUID["Runtime CPUID Arbiter"]
            AVX512["AVX-512 / AMX / VNNI<br/>(512-bit Vector Units)"]
            AVX2["AVX2 / FMA<br/>(256-bit SIMD)"]
            SCALAR["Scalar & AVX1 Fallback<br/>(Bit-Exact Portability)"]
            
            CPUID --> AVX512
            CPUID --> AVX2
            CPUID --> SCALAR
        end
    end

    %% Persistence Subsystem
    subgraph PERSIST["Durable Persistence Layer"]
        direction LR
        SST["SSTable Disk Spooler<br/>(LSM Multi-Level)"]
        WAL["Marmalade QWAL<br/>(SHA-384 Torn-Tail Recovery)"]
        PQC_STORE["Encrypted Storage Container<br/>(.qdb ML-KEM Encapsulation)"]
    end

    %% Cross-Subsystem Interconnects
    AUTH --> VEC_PLANE
    AUTH --> REL_PLANE
    AUTH --> STREAM_PLANE

    VEC_PLANE <--> TIER
    REL_PLANE <--> TIER
    STREAM_PLANE <--> TIER
    TIER <--> NUMA

    VEC_PLANE --> CPUID
    COL --> CPUID

    REL_PLANE --> SST
    STREAM_PLANE --> WAL
    SQL_API --> WAL
    KV --> SST
    SST --> PQC_STORE
    WAL --> PQC_STORE
```
