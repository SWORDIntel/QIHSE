# CodeGraph redesign verification

> **Roadmap authority:** [ROADMAP.md](../../ROADMAP.md) is the sole authority for delivery status, remaining work, sequencing and acceptance. This file retains supporting design, acceptance criteria and dated evidence; historical status labels below are not an independent current checklist. Consolidated 2026-11-07.

Scope: the native CodeGraph import, query-generation lifetime, and source-freshness subprocesses. This review uses source inspection and isolated synthetic graphs; it does not inspect live CodeGraph data. Supplied speedup or memory-reduction figures are hypotheses until reproduced.

## Findings

| Proposal | Verified current behavior | Bounded action |
| --- | --- | --- |
| Use KV bulk mode while importing | JSONL import calls authenticated setters without bulk mode. Normal writes append WAL records and flush the memtable above 512 KiB. | Benchmark a bounded import variant separately. Bulk mode suppresses automatic SST flushing as well as WAL traffic, so it increases the amount retained in RAM. |
| Release decoded KV after constructing a query graph | Query requests use copied node metadata, native graph properties/adjacency, and parsed manifest metadata. The decoded KV remains allocated throughout the generation. | Release it only after successful graph construction for query, context, impact, review and serve. Keep it for import, migration, GC and stats. |
| The graph occupies exactly three copies in RAM | There are multiple overlapping representations: serialized KV records, the CLI node table, and native graph structures. They do not contain identical data or occupy equal space. | Measure resident memory; do not describe the representation count as a measured 3x multiplier. |
| Parallelize Git subprocesses | Freshness currently captures bounded Git results sequentially and hashes them in a fixed order. Queries verify freshness before and after producing results. | Keep correctness and timeout behavior. Parallel capture requires fixed digest ordering, bounded aggregate buffers, sibling cancellation and deterministic cleanup. |
| Replace nonblocking child reaping with one blocking wait | Git can close stdout while continuing to run. The existing reap loop still enforces its deadline and kills the process group. | A blocking wait without a separate deadline mechanism can hang indefinitely. |

## Read-only generation ownership

`nodes_from_kv` duplicates the file, name and kind strings. `qihse_graph_vertex_create` and `qihse_graph_edge_create` copy their labels, property keys and string values. The native graph and CLI node indexes therefore do not borrow record payloads from the KV store.

The `read_only_graph` flag is enabled explicitly for graph query commands and `serve`. `load_snapshot_unlocked` releases the KV only after the complete native graph has passed node counts, edge counts, unresolved counts and authoritative-endpoint validation. `clear_generation` already tolerates a null KV and preserves the flag; a resident refresh loads and validates a replacement before releasing its decoded KV again. Invalid replacement manifests still clear the previous graph and deny queries.

Authentication remains required when loading every record and on each resident request. The authenticated principal belongs to the isolated authentication realm, not to the KV allocation. Releasing the decoded KV does not disable the existing principal or capability checks. No new data-access primitive is introduced. On glibc, a single `malloc_trim(0)` after this release returns eligible allocator pages to the operating system. Other allocators use their normal free behavior. Trimming occurs during generation construction, never on each warm query.

## Bulk-mode tradeoff

`qihse_kv_bulk_load_begin` and `qihse_kv_bulk_load_end` are storage-mode controls; they do not bypass `set_user_preflight` or classified-record export checks. End clears the flag and flushes existing WAL bytes; it does not automatically write the accumulated memtable to SST storage. A failed import can destroy its private staging store with bulk mode still enabled: destruction closes the WAL and frees the trie; there is no committed generation to recover from that staging store.

An unconditional toggle would retain the entire JSONL import in memory, potentially up to the native graph capacity limits. A file-size bound limits input bytes but does not equal a bound on trie/node/property overhead. Any adoption needs measured peak memory and an explicit bounded policy or opt-in. It does not make each published graph smaller because the same authenticated records are ultimately encoded.

## Measurement

The experiment compiles the captured baseline and candidate with the same GCC `-O2` flags, storage codec sources and shared QIHSE library. The fixture has 16,000 nodes and 48,000 edges. Each measurement starts a fresh one-worker resident process and samples `smaps_rollup` after the same context query. Two pairs alternate baseline/candidate order against one immutable snapshot; refresh, corrupt-manifest invalidation, restoration and capability-revocation checks run after the measurements. Host workloads remain active and page cache is not dropped. The controlled receipt is `benchmarks/codegraph_readonly_reference.json`; the reproducible harness is `benchmarks/codegraph_readonly_compare.py`.

| Metric | Baseline | Release decoded KV and trim |
| --- | ---: | ---: |
| First resident RSS pair (KiB) | 317,908 | 66,792 |
| Second resident RSS pair (KiB) | 317,784 | 66,784 |
| Median resident RSS (KiB) | 317,846 | 66,788 |
| Cold query peak RSS, one sample (KiB) | 315,168 | 314,228 |
| Cold query wall time, one sample (seconds) | 19.627 | 19.159 |

Median resident RSS fell 79.0% on this fixture. Cold context output parity, valid-generation refresh, malformed-manifest denial, recovery and capability revocation passed. The single cold samples establish no speed or peak-memory improvement.

The release-only candidate initially measured 317,904 KiB against 317,732 KiB for the packed snapshot: glibc retained the freed pages. This motivated the separately measured trim call. These results apply to this synthetic fixture and allocator, and do not establish the supplied general 4x/8x claims. Resident RSS and cold peak RSS are distinct: freeing KV after construction can reduce steady-state memory without reducing the peak required to decode and build the graph. Allocator behavior can also retain freed pages.

The bulk-mode variant was prepared as an isolated experiment but not integrated or benchmarked during this pass. Its source-level tradeoff above is verified; no bulk speedup is claimed.

A focused 800-node/2,400-edge ASan/UBSan run passed cold query parity, resident refresh, corrupt-manifest denial/recovery and capability revocation with no sanitizer error. CLI and codec sources were instrumented; the shared QIHSE library was not, and leak detection was disabled. This is partial memory-safety coverage, not an instrumented full-engine or leak check. The receipt is `benchmarks/codegraph_readonly_sanitizer.json`.
# Experimental dictionary format (historical checkpoint)

The prototype below was subsequently integrated as [packed-v3](codegraph_compact_references.md). Its original integration requirements describe that earlier checkpoint, not current missing work.

The isolated `codegraph-columnar` worktree, commit `eb5004b`, contains a complete
QCGP0003 prototype. It interns binary digests and exact quoted strings while
preserving the original KV stream bytes, unknown JSON and security metadata.
It is not linked into the native CLI or enabled for repository graphs.

| Nodes / edges | Packed-v2 bytes | Prototype bytes | Reduction |
| --- | ---: | ---: | ---: |
| 8 / 24 | 2,715 | 2,688 | 0.99% |
| 800 / 2,400 | 182,355 | 177,806 | 2.50% |
| 8,000 / 24,000 | 1,974,079 | 1,686,048 | 14.59% |

On the smallest fixture, current automatic selection already chooses Zstandard at
2,688 bytes, so the prototype provides no improvement over that selected format.
These are single-run synthetic size comparisons, not evidence for the supplied
fourfold reduction or a general speedup.

Normal tests, ASan/UBSan, exact reconstruction, record fingerprints,
authorization negatives and 256 malformed-token mutations passed. Review found a
stale-stdio-buffer integrity defect in the first prototype; its regression fails
that initial implementation and passes the hardened decoder. The decoder now
hashes and parses the same private copy obtained with `pread`, with source
descriptor stability checks. Independent targeted rereview passed.

The experimental worktree contains the format specification and durable benchmark
and validation receipts. Production promotion requires loader/migration integration
and the new adapter's negative tests in CI.
