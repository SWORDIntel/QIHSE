# CodeGraph search: measured costs and deployment

## Delivered architecture

The existing native QIHSE reader retains a validated immutable KV generation, native adjacency,
dense node metadata and sorted name/file lookup arrays. The CLI can connect to that reader;
direct one-shot commands still work. CRG remains the sole parser/exporter and KEYSTONE retains
its lexical/trigram role. There is no new database, daemon, parser, watcher, vector lookup or
LLM-based retrieval stage.

Four fixed workers overlap independent freshness work. Graph API operations remain serialized
because iterator thread safety is not promised. A generation read lease spans response assembly;
replacement takes an exclusive lease and old memory is reclaimed only after readers finish.
The queue is bounded to 16; `serve --workers 1` retains serial diagnostic operation.

Exact lookup uses the sorted native index. Prefix, substring and file-qualified matching preserve
ambiguity; qualification cannot invent namespace metadata absent from the canonical export.
Batched context has one node/token budget, flat deduplicated nodes/relations and per-symbol
correspondence. Closest-hop nodes rank first, then stable identity; requested roots outrank optional
neighbors. Retained relations have both stable endpoint IDs retained. Truncation is explicit.

## Reproducible input and binary identity

All headline comparisons use the same real CRG source clone and byte-identical dual-digest export:

- Source commit: `e162ebcd79623e670eab721954eb142842c12e89`.
- 8,361 nodes; 76,358 exported relations; 28,562 traversable and 47,796 unresolved/non-traversable.
- Export SHA256: `2b218a690d52c9f504ab4a45788f6bd9c3822541048ee060daa97112d415de1b`.
- Original CLI SHA256: `59bf1b1adf82fe6971d8f7048e556d37487a6db46fe03473225d05af66175854`.
- Final CLI SHA256: `072c99019a094fbc2d7fc77bc9ca909d043ca63fd02acf71c75d855d34318feb`.
- Final native source SHA256: `a50a8493c6c0d1a71a0379c0aae57affb26b157c3e1258e8c70fcbe0aa0406e4`.
- Frozen original library SHA256:
  `e5a0c8fb178c923e3065be73de057ea995806483dab808e736e396e427e5be9c`.

Both binaries use the frozen library, excluding concurrent, unrelated KV batch API development.
The final pin is `/tmp/codegraph-delivery-final-n3hc00nf`; the machine-local input root is
`/tmp/codegraph-search-measured-s6y5js4s`. Temporary paths are reproduction receipts, not deployment
configuration. `benchmarks/codegraph_search_delivery_manifest.json` records the pin and hashes.
Do not substitute a subsequently rebuilt live library and call the comparison identical.

The original accepts the legacy `worktree` digest; the candidate requires the stronger
`worktree_v2` digest in the same export. The latter includes status, binary HEAD diff, staged
index and untracked bytes/symlink targets. Git trust flags cause freshness refusal. CRG checks
stored source hashes against bytes before and after export, preventing stale facts from being
relabeled with current Git identity.

## Final latency and throughput

All values below are milliseconds. Warm runs have 100 measured samples **per case and concurrency**,
after warmup. Cold runs have three samples; their interpolated p95/p99 are descriptive, not reliable
tail estimates. Cold means a new process and graph reconstruction, not eviction of filesystem
caches. Timed phases ran sequentially without our heavy test suites running concurrently.

| Path, unique depth-2 context | p50 | p95 | p99 | Throughput/s |
| --- | ---: | ---: | ---: | ---: |
| Original cold, one client | 14,040.70 | 14,100.49 | 14,105.81 | 0.07 |
| Final cold, one client | 14,119.54 | 14,627.90 | 14,673.09 | 0.07 |
| Original resident, one client | 226.89 | 256.72 | 268.95 | 4.36 |
| Final resident socket, one client | 84.83 | 89.91 | 93.65 | 11.06 |
| Original resident, four clients | 833.95 | 931.17 | 940.58 | 4.74 |
| Final resident socket, four clients | 102.93 | 116.82 | 127.54 | 36.37 |
| Final CLI-to-reader, one client | 129.27 | 143.22 | 150.69 | 7.36 |
| Final CLI-to-reader, four clients | 124.07 | 135.59 | 136.94 | 30.17 |

At p95, final socket context is 156.8x faster than original cold reconstruction and 2.86x faster
than the original resident reader. Fast CLI is 98.5x faster than original cold. The >=10x repeated
query objective is met without weakening auth or freshness. Cold reconstruction itself is not
materially faster: authentication, authorized KV restore and graph construction remain startup
costs. Final socket startup was 14,485.59 ms; the first authenticated status query took 87.17 ms.
The original already supported residency: its cold-to-warm gain is not a newly invented feature.

| Final socket case | Clients | p50 | p95 | p99 |
| --- | ---: | ---: | ---: | ---: |
| Unique depth-1 | 1 | 86.56 | 92.88 | 95.02 |
| Unique depth-1 | 4 | 98.77 | 111.48 | 113.34 |
| Ambiguous name | 1 | 93.40 | 113.79 | 131.04 |
| Ambiguous name | 4 | 98.07 | 108.05 | 114.04 |
| High-degree query | 1 | 90.69 | 106.28 | 111.97 |
| High-degree query | 4 | 103.71 | 120.54 | 127.53 |

Sub-100 ms p95 is achieved for the representative single-client exact/context cases, not all
requests or transports. Four-reader contention, ambiguous queries and process-launched CLI calls
can exceed it. Git/content verification remains the dominant cost; no event cache claims freshness
without reading the relevant content.

The workload covers 19 cases: depth 1/2/3/5, narrow depth 1..5, ambiguity, missing seeds, valid and
mixed batches, high-degree query/impact and test-oriented query/impact. Socket batches are native
shared-budget operations. CLI/cold batch measurements are ordered individual commands, **not**
the same amount of output work, so their ratios are not presented as batch-equivalence speedups.
The mixed batch deliberately includes a missing third seed. Old socket query/impact commands were
unsupported; their fast error responses are not performance baselines.

## CPU, memory, allocations and output

For unique depth-2 at one client:

| Path | Median CPU ms | Median peak RSS KiB | Median response bytes |
| --- | ---: | ---: | ---: |
| Original cold | 14,050 | 295,448 | 13,724 |
| Final cold | 14,110 | 295,844 | 14,231 |
| Original resident | 230 | 296,472 | 13,724 |
| Final socket | 80 | 297,908 | 14,190 |
| Final CLI-to-reader | 115 | 298,020 | 14,189 |

Cold CPU includes the command and waited children. Resident CPU samples the server and waited Git
children; CLI measurements also include client CPU. Concurrent requests share CPU, so there is no
fabricated per-request CPU attribution at concurrency four. Resident process accounting excludes
transient live-child RSS; raw reports include phase resources and separate CLI client resources.

The final instrumented warm allocation probe used 20 `GraphStore` contexts, depth 2, limit 80,
4,000 tokens, with the same interposed glibc probe as the original. Original: 1,466 calls and
408,135 requested bytes/query. Final: 1,511 calls and 631,938 requested bytes/query. This is a 3.1%
call-count and 54.8% requested-byte **increase**, not an allocation improvement: stronger freshness
inventory and bounded request buffers have a cost. These are requested bytes, not live/peak heap;
interposition is diagnostic and its timings are not headline latency results.

Cold Valgrind final: 5,001,312 allocations, 1,026,333,595 requested bytes, zero errors and zero
bytes definitely/indirectly/possibly lost; 110,589 bytes remain reachable in library globals.
Original: 5,001,175 allocations, 1,025,781,110 requested bytes, the same reachable total and no
errors/lost bytes. Residency avoids repeating roughly five million startup allocations per query;
it does not eliminate them from startup. See the final Valgrind log and allocation JSON receipt.

Final normal responses are slightly larger because they expose planner/ambiguity/timing metadata.
Single-query node identities and relation evidence remain identical to the original. Batch
contracts intentionally differ: full repeated reports become flat deduplicated records.
The allocation probe separately measured client JSON decode: median 0.484 ms, maximum 0.870 ms
for 13,762-byte real responses (20 samples). Headline socket wall time covers connect, request,
server work and response transfer, but excludes subsequent client JSON decoding. No claim is made
that this round trip isolates network transfer alone.

## Stage attribution and implementation choices

Final median unique depth-2 socket stages, one client:

| Stage | ms |
| --- | ---: |
| Capability authorization | 0.0070 |
| Loaded-generation check | 0.0643 |
| Pre-query freshness | 41.0073 |
| Seed lookup/planning | 0.0160 |
| Traversal/assembly | 1.1322 |
| Serialization | 0.2598 |
| Post-query freshness | 41.4915 |
| Reported total | 83.8384 |

Stage medians are independent and need not sum exactly. The external wall median is 84.83 ms;
the difference includes transport, scheduling and other work, not just byte transfer.
Warm KV load, snapshot verification and graph construction are zero because the generation is
resident. At four clients freshness medians rise to about 48 ms each.

Original selective profiling found ~1.119 ms lookup, ~2.795 ms traversal/assembly, ~0.288 ms
serialization and ~0.027 ms stdio transfer per context. Six Git subprocesses per query dominated
freshness (~293 ms in that diagnostic run). The fix uses `posix_spawnp` rather than forking the
large resident address space and combines stage-index/trust-flag inventory without changing the
reconstructed index bytes. Sorted lookup removes the name scan. Measured adjacency cost did not
justify replacing the native graph or adding KEYSTONE to exact lookup.

Original cold instrumentation attributed seconds to auth/PBKDF2, authorized KV loading and graph
construction, versus ~0.35 s snapshot hashing. Those diagnostic runs overlapped other tests and
are stage evidence, not substitutes for the sequential headline measurements.

## Correctness and verification

`codegraph_search_delivery_correctness.json` audits all final raw rows: 66 cold command requests,
3,800 socket requests and 4,400 CLI requests. All are fresh, outputs are deterministic for each
case, and there are **zero unexpected errors**. Expected missing-seed results remain explicit.
All bounded cold single-query node sets and relation evidence match the untouched original.
Full-envelope content hashes can differ because planner/timing metadata changed; they are not
misrepresented as semantic fact changes.

Verified final checks:

- `make -C /opt/QIHSE qihse-codegraph test-graph test-codegraph`: passed; 19 graph unit checks.
- Root native fixture against the final pin and frozen library: passed, including real cross-UID
  `SO_PEERCRED` denial. The non-root run explicitly skips that one peer test.
- Native `-fanalyzer -Wall -Wextra -Werror` and clang-format: passed.
- Full QIHSE suite on the frozen library earlier in this implementation: 161 targets passed,
  including W12/TurboQuant/TLS. The final native-only edits were subsequently covered by the final
  native contracts; this is not a claim that the changing shared checkout was fully retested.
- CRG exporter/format/CLI/visualization checks: 75 passed, 71 optional-format skips; Ruff passed.
- HAX focused `result_cache`, `tools/codegraph_reader`, `tools/graph`, `tools/code_context`: passed.
- HAX lint: passed. Actual HAX-to-reader integration passed after final cache hardening.
- Final native cold Valgrind: exit 0, zero errors and no lost allocations.

Native fault coverage includes tracked/staged/untracked-byte freshness, Git trust flags, source
and generation changes mid-query, corrupt replacement rollback, interrupted import, publication
ENOSPC/rename/fsync failures, restart, disconnects, total frame deadlines, queue overload, bounded
thread count, process-group Git timeout, revocation during a blocked query, commit-aware token
rotation, rank-preserved batch roots and relation endpoints. Expanding a previously imported small
untracked file to a 1 TiB sparse file verifies the aggregate hash deadline returns nonfresh/no facts
within eight seconds and recovers after reimport. It does not skip bytes and assert freshness.

The final full HAX run after all scoped edits had 252/254 successes: failures in
`execution_journal` and `tool_router`, with no timeouts. The selected failure logs are retained in
`codegraph_search_delivery_hax_suite.json`. Earlier shared runs also had `e2e/aimem_capture`
failures and agent/task timeouts. These are outside this scoped change and were not suppressed or
patched. The shared checkout continues receiving unrelated edits, so whole-workspace verification
fingerprints can change during successful checks. No repository-wide clean promotion or production
deployment is claimed.

## Real source-grounded consumer example

`codegraph_search_delivery_hax_integration.json` drives HAX with a scripted LLM provider but real
CRG facts, real native CLI/socket, authentication and source files. It repeats two-seed context
and executes graph query/impact/review, checking fresh JSON, one generation and exact source spans.
The returned graph citation includes `code_review_graph/graph.py:1177-1185`, `get_all_nodes`:

```python
def get_all_nodes(self, exclude_files: bool = True) -> list[GraphNode]:
    """Return all nodes, optionally excluding File nodes."""
```

The source body selects non-File nodes when requested, otherwise all nodes, and maps rows with
`_row_to_node`. Stable ID:
`c5c6e85160fc9333fd2a86e41f553b7c7773fff506ae6c67b1dc7c44a930abb1`.
The same receipt also checks `get_all_edges` at lines 3569–3572. This is executable integration
evidence, not a proposed transcript or a fake graph backend.

## Reproduction, activation and fallback

From `/opt/QIHSE`, with the pinned binary/library pair and paired snapshot available:

```sh
python3 benchmarks/codegraph_search.py \
  --root /tmp/codegraph-search-measured-s6y5js4s \
  --binary /tmp/codegraph-delivery-final-n3hc00nf/qihse-codegraph \
  --state-home /tmp/codegraph-search-measured-s6y5js4s/state-paired-after \
  --export /tmp/codegraph-search-measured-s6y5js4s/repo/.code-review-graph/graph.paired.qihse.jsonl \
  --output /tmp/codegraph-repeated.json \
  --mode resident --transport socket --samples 100 --concurrency 1 4 --timings
```

Use `--transport cli` for fast CLI, or `--mode cold --samples 3 --concurrency 1` for cold commands.
`--prepare SOURCE_REPO --crg CRG` prepares a new real clone/export when the temporary input no
longer exists. Such a run is new input, not the exact published comparison. The allocation runner
is `benchmarks/codegraph_search_allocations.py`; it accepts `--binary`, `--repo`, `--state-home`
and `--output` and compiles the adjacent interposition source in private temporary storage.

Final evidence is named `codegraph_search_delivery_*`. The `paired_before*` files are the original
baseline. Earlier `paired_after*`, `final_warm` and older pins are historical, not final acceptance:
one intermediate concurrency run exposed a JSON-C shared serialization-buffer race, fixed with
read-only structural manifest comparison before these final zero-error runs.

Build the native tool and HAX, then reexport/import with v2 provenance before starting a reader.
A running HAX binary needs restarting to use rebuilt consumer code. No user-owned processes were
restarted by this work; integration cleanup targeted only exact test-owned reader PIDs. HAX context
can activate its existing reader integration; generic graph commands reuse an active reader and
do not create one merely for a short query. Use a private owner-only runtime directory.

The same binary supports one-shot operation. `--fallback oneshot` is explicit and only applies to
unavailable transport; auth, stale, malformed and deadline errors must not silently take a cold
path. Use `--fallback error` to require the reader. HAX supports only the exact known legacy
unsupported-command response as compatibility fallback, not substring-matched errors.
Do not downgrade freshness to get a green flag. Retained immutable generations are not
automatically garbage-collected; cross-process lifetime safety takes precedence over disk cleanup.
Generation rebuilding takes an exclusive lease, and changes detected around a query reject rather
than emit unverifiable facts. Filesystem/OS reads themselves can still stall below userspace;
this is not a real-time filesystem guarantee. Broad cross-language semantic impact accuracy and
token savings versus lexical lookup plus targeted reads are not established by this benchmark.
