# CodeGraph P0 synthetic baseline

Run from a checkout after building the native CLI:

```sh
python3 benchmarks/codegraph_p0_baseline.py \
  --binary ./qihse-codegraph --nodes 800 --edges 2400 --repeats 3 \
  --output benchmarks/codegraph_p0_reference.json
```

The script creates a temporary Git repository and a deterministic JSONL graph.
It includes long repeated paths, two symbols with the same display name, one
high-degree caller, a direct test relationship, unresolved edges, and opaque
extension fields. It imports that source through the native CodeGraph CLI,
then uses the authenticated QIHSE SDK fixture to serialize an equivalent
legacy KV generation. No live graph storage is read.

The native CLI validates both generations and runs exact `query`, `context`
and `impact` cases. The script compares the entire response apart from the
expected generation identifier and timing fields. It also checks ground-truth
IDs for the duplicate names, caller, target and test. The high-degree `context`
case must report truncation; the separate target `impact` case checks direct
caller/test recall without relying on the truncated result. Results from a resident
authenticated socket reader must match the one-shot answers.

The JSON receipt records apparent and allocated bytes for *synthetic temporary*
snapshot files. Apparent bytes are not physical space reclaimed, and allocated
bytes can depend on the temporary filesystem. Its `input_jsonl_field_value_bytes`
breakdown sums JSONL value, key and punctuation bytes **before** KV encoding or
Zstandard; it is not a physical section breakdown of either snapshot format.

Each one-shot query runs in a fresh process. The first process may encounter a
cold OS page cache, but the benchmark does not drop caches or claim a cold-cache
comparison. Alternating compact/legacy calls controls some order bias. Native
`--timings` separates auth, load, freshness and query stages. Resident timings
contain a first request and repeated requests against an already loaded reader.

`peak_rss_kib` is Linux `wait4` per-process RSS. `observed_wchar_lower_bound`
samples the process's `/proc/PID/io` write-character counter every 5 ms; it may
miss final writes and includes stdout/stderr. `filesystem_output_blocks` is the
process's reported output-block count, not bytes reclaimed on the host. CPU and
wall timings include any concurrent host load recorded in `methodology`.

This fixture tests format and query equivalence. It does not measure live-corpus
compression, cross-language retrieval recall, or total QIHSE directory cleanup.

The committed 800-node, 2,400-edge reference receipt measured 1,825,299 bytes
for legacy KV and 187,976 bytes for the current level-9 container (89.7% fewer
apparent bytes on this synthetic fixture). Allocated bytes were 1,826,816 and
188,416. The pre-KV JSONL input was 1,547,957 bytes, including 515,136 bytes
of serialized ID values and 361,232 bytes of serialized path values. Zstandard
already compresses this repetition, so these shares do not predict additional
packed-format savings. Four query shapes matched exactly across formats. Median
one-shot wall times were roughly 6.2–6.5 seconds on this host, with authentication
dominating; native `query_ms` medians ranged from about 0.1 to 1.6 ms. Repeated
resident requests were about 65–73 ms, including source freshness checks.

The receipt records the benchmark script and binary hashes, platform and CPU,
three alternating pairs, and the fact that ambient host activity was not fully
controlled. These measurements do not establish a live-repository ratio or a
speed advantage for either snapshot format.
