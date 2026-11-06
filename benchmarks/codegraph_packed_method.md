# CodeGraph packed-format comparison method

This benchmark extends the synthetic P0 baseline in
[`codegraph_p0_method.md`](codegraph_p0_method.md). It compares format
encoders against the **same authenticated, in-memory QIHSE KV store**. Its
graph input contains duplicate symbol names, long paths, high-degree callers,
unresolved edges and opaque extension fields. All state is created beneath a
temporary directory; no live CodeGraph storage is read.

The comparison has two separate correctness gates:

1. For each backend, reopen its snapshot with an explicit authenticated
   principal and compare a canonical multiset digest over all materialized
   keys and values, record counts, public metadata and public label behavior.
   Include a protected synthetic record and verify that a low-clearance
   principal cannot open or enumerate it. The operator must still open it.
   Exercise malformed/truncated inputs in the codec's focused tests.
2. Once the native CLI opens packed snapshots using its verified-load API and
   a trusted expected SHA-256, compare exact `query`,
   `context` and `impact` responses across all three backends. Generation
   identifiers and timing fields are allowed to differ. A direct caller/test
   case must preserve IDs; a high-degree case may truncate and must report
   that condition. Record parity alone does not establish query parity.

The current `qihse_kv_save_user` contract serializes live records; it does not
promise to preserve dead rows. The benchmark will not claim tombstone parity
unless the production format and test fixture explicitly include it.

For timing, run each backend in a fresh process and alternate backend order
across repetitions. Report encode and authenticated load wall/CPU time,
per-process peak RSS, apparent and allocated snapshot bytes, and source/binary
hashes. Logical writes are not captured in this harness. Keep fixture creation
and authentication startup separate from encode/load stage timings. Retain
the OS page cache and label the result as such. Do not derive live-corpus space
recovery from apparent-byte ratios or a synthetic fixture.

Packed encoding consumes an already exported raw stream. Its comparable
end-to-end save time is `raw_export_ms + encode_ms`; the legacy and Zstd save
functions perform export internally, so their `encode_ms` already includes it.
The harness reports `production_equivalent_encode_ms` using this definition.
Every process also exports the source graph to raw KV bytes, and the harness
requires the hash of that export to match across all backend runs.

The benchmark should include at least a small fixture for fast correctness
checks and a medium fixture with enough duplicate strings and edges to make
storage overhead measurable. Only paired measurements made without a known
concurrent QIHSE build/test should be used in timing comparisons. Any shared
host activity is reported, and no performance gain is claimed without
repeatable evidence.
