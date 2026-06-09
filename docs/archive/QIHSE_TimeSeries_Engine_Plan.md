# QIHSE Time-Series Engine Architecture Plan

## Overview
The Time-Series Engine is designed to store high-frequency telemetry data with extreme memory efficiency while supporting fast aggregations and automatic eviction of stale data.

## Core Mechanisms
1. **Ring Buffer Ingestion**
   Data arrives via DPDK or standard socket pathways and lands in a lock-free, cache-line padded ring buffer (`qihse_tsdb_insert`). This allows for nanosecond-level insertion latency.

2. **Gorilla Compression (Chunking)**
   Once the in-memory ring buffer has accumulated enough samples, they are flushed asynchronously into page-aligned chunks (`qihse_tsdb_chunk_t`).
   - **Timestamps** are compressed using a Delta-of-Delta approach, yielding 1 to ~32 bits per timestamp.
   - **Floating Point Values** are compressed via XOR against the previous value. If the XOR'd value has similar leading and trailing zeros as the prior sequence, it compactly encodes just the meaningful bits.

3. **Time-To-Live (TTL) / Window Expiry**
   The time-series chunks act as a linked list sorted by time. The Engine exposes `qihse_tsdb_trim` which takes a `current_ts` and efficiently evicts chunks whose `end_timestamp` precedes the configured `ttl_ms` window.

## Usage
Data is queried efficiently using vectorizable window functions such as `qihse_tsdb_average_range()`, which decompresses the underlying chunk stream only for data bounded by the search range.
