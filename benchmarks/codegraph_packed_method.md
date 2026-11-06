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

## Initial packed codec result

The first `QCGP0002` candidate is recorded in
[`codegraph_packed_reference.json`](codegraph_packed_reference.json). On the
deterministic 800-node/2400-edge fixture, three paired runs passed exact raw
re-export, 3,202-record fingerprint equality and low-clearance denial. Median
apparent bytes were 1,825,299 for legacy KV, 187,857 for current Zstd level 9,
and 306,505 for the initial packed codec. Packed was 63.2% larger than current
Zstd. Median production-equivalent encode times were 21.2, 128.1 and 143.6 ms;
authenticated loads were 91.1, 95.4 and 98.5 ms, respectively. Per-process
peak RSS was 36,696, 38,620 and 38,404 KiB. These are synthetic, warm-cache
results from a coordinated quiet window; unrelated host activity was not
controlled. The initial packed codec does not meet the space objective.

The first native packed import of this same fixture failed its complete-export
verification because the source KV store and the opened memory snapshot can
serialize identical records in a different order. Importing Zstd then migrating
to packed succeeded. The verifier was changed to compare an order-insensitive
digest over **complete authenticated serialized records**, retaining header,
key, value, labels, expiry, flags and sequence. Direct packed import and
Zstd-to-packed migration then both passed exact native query parity against
legacy and Zstd snapshots on the medium fixture. The four cases cover shared
names, high-degree bounded context, direct caller/test IDs, and absent symbols.
The two receipts are [`codegraph_packed_queries_reference.json`](codegraph_packed_queries_reference.json)
and [`codegraph_packed_migrate_queries_reference.json`](codegraph_packed_migrate_queries_reference.json).

## Revised literal-key codec

The codec revision preserves literal digest keys so Zstd can reuse long ID
sequences inside JSON values. Its paired medium receipt is
[`codegraph_packed_literal_reference.json`](codegraph_packed_literal_reference.json),
with the small correctness fixture in
[`codegraph_packed_literal_small_reference.json`](codegraph_packed_literal_small_reference.json).
On the same authenticated medium raw export (SHA-256 recorded in both receipts),
revised packed is 182,355 apparent bytes versus 187,857 for current Zstd level
9: 5,502 bytes or 2.93% smaller. Its 48-byte outer header is followed by a
7,897-byte compressed label/header frame and 174,410-byte compressed body
frame. All three formats reproduced the same 3,202 live records and exact raw
export, and a low-clearance principal was denied without decoded output. The
small 16-node/24-edge fixture is 3,249 packed bytes versus 3,216 Zstd bytes,
so packed is 33 bytes larger there.

The revised medium medians were 153.5 ms production-equivalent packed save
versus 152.0 ms current Zstd save, 94.9 versus 113.7 ms authenticated load,
and 37,944 versus 38,484 KiB whole-process peak RSS. These timings are short,
shared-host samples and do not establish a speed or memory advantage. Direct
native imports measured 182,323 packed versus 187,971 Zstd bytes; migration
measured 184,708 packed bytes. Those CLI paths can have different live record
metadata and are query-parity evidence, not a same-export codec size pair.
