# QIHSE Subsystem Architecture Diagram

A full-page schematic mapping the QIHSE database topology from kernel-bypass network ingress down to memory tiering, runtime SIMD dispatch arbiters, and durable persistence layers.

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

---

[← Return to System Overview](../architecture/system_overview.md) | [← Return to README](../../README.md)
