# CodeGraph completion results

This report covers disposable synthetic fixtures only. No live CodeGraph was read, converted, or rebuilt. The authoritative delivery status is in `ROADMAP.md`.

## Implemented

- `packed-v4` stores exact KV exports in typed, independently compressed bounded chunks. `auto` compares all four codecs and publishes the smallest verified candidate. Exact record bytes, labels, SCI, expiry, sequence, unknown fields, and unresolved relationships are retained.
- `generations-v1` stores immutable per-file blocks and a small parent. The current and previous parents share unchanged blocks; authenticated GC removes only unreferenced blocks. A query index never hides a missing or damaged referenced block.
- An optional persisted query index stores node/search/adjacency data and loads evidence blocks on demand. The canonical snapshot remains authoritative. Cache keys bind the checksum, storage format, principal, tenant, and labels; expiry and malformed evidence prevent cache use or partial success.
- Explicit Git, filesystem, and editor-overlay source identities have independent pre/post freshness checks. The producer writes private exports from one SQLite read snapshot, updates changed files when dependency evidence is sufficient, and falls back to a full build otherwise. The wrapper reports actual byte/record progress and keys ETA samples by mode.
- Query startup releases transient KV spill files after constructing the resident graph. Space accounting reports canonical sections and authorized current/previous/shared generation usage without revealing protected blocks.

Guest disk totals deliberately omit the CodeGraph root directory inode: its size can reveal the number of excluded classified snapshot entries. Such totals are marked incomplete. Operator accounting may include that inode.

## Measurements

| Synthetic workload | Before | After | Trade-off |
|---|---:|---:|---|
| 40k nodes, 120k edges, exact export; Zstd versus packed-v4 | 9,172,486 B | 7,956,752 B | Three encode medians: 4.631 s versus 4.238 s; decode 0.367 s versus 2.575 s and peak decode RSS 30,684 versus 49,120 KiB. |
| 100-file graph, current plus previous after one edit; whole Zstd versus shared generations | 2,312,364 B | 1,265,073 B | Standalone generation encode 1.265 s versus whole Zstd 0.534 s; raw-export staging and publication are excluded. |
| 8k nodes, 24k edges, fresh CLI process; canonical versus optional query index | 7.622 s, 163,884 KiB peak RSS | 6.032 s, 25,640 KiB | Adds 651,365 B to a 1,518,671 B snapshot; cold lazy traversal 0.111 to 1.409 ms. Three shuffled pairs with warm OS cache. |
| 105,047,610 B export, 150,010 edges; active decoded KV spill after query handoff | 118,287,991 B | 0 B | Audit and lease files remain; no snapshot bytes are removed. |

These are different fixtures and stages, so their ratios must not be multiplied. The persisted-index CLI receipt predates the final in-memory compressed-tail trim; the trim's separate component test reduced owned bytes from 2,129,852 to 1,865,764 on an 8k-node fixture. There is no claim that every repository becomes smaller or faster.

Reproduce with the scoped `make test-codegraph` target. Benchmark drivers and complete methodology are in `benchmarks/codegraph_chunked_reference.json`, `benchmarks/codegraph_generations_reference.json`, `benchmarks/codegraph_query_index_native_reference.json`, `benchmarks/codegraph_runtime_spills_reference.json`, and the corresponding scripts in `benchmarks/` or `tests/`. The installed native binary and pipx producer passed disposable Git cold and unchanged reindex, filesystem, and unsaved-overlay smoke runs with the optional query index; receipts are `benchmarks/codegraph_installed_git_reference.json` and `benchmarks/codegraph_installed_filesystem_reference.json`. The full QIHSE suite was stopped at the user's request; this report does not claim a full-suite pass.
