# W12.0 baseline audit: kernels and full-engine synthetic comparison

> **Roadmap authority:** [ROADMAP.md](../../ROADMAP.md) is the sole authority for delivery status, remaining work, sequencing and acceptance. This file retains supporting design, acceptance criteria and dated evidence; historical status labels below are not an independent current checklist. Consolidated 2026-11-07.

Status: **in progress, not a completed W12.0 gate** (2026-11-06).
Source audit pinned to `d298f725278d35be4279506f5753b163ee8eb904`.
Parent design: [TurboQuant plan](qihse_turboquant_vector_index_plan.md).

The first increment changed no production query mode, public C structure, default,
credential, persistence format, or authorization behavior. It adds a reproducible
benchmark-only exhaustive search loop over generated fixtures, using the actual
production scalar and runtime-dispatched FP32 distance kernels. That kernel
run was **not** a full VectorDB/AIMEM benchmark, an authorization test, or a
TurboQuant codec. The second increment below adds a synthetic full VectorDB run.

## Second increment: full VectorDB synthetic baseline

The new engine driver in benchmarks/scripts/qihse_w12_engine_baseline.py
builds a benchmark-only C probe and calls the public VectorDB create, add,
flush, sidecar build, and search APIs. Every search has an explicit authenticated
operator principal. The driver creates a fresh private QIHSE_DATA_DIR per
route and only inserts generated unclassified vectors; it does not read the
configured QIHSE store. It compares returned IDs against a separate binary64
exhaustive oracle over the same binary32 values.

Reproduce after building libqihse.so in this checkout:

    make -j16 libqihse.so
    python3 benchmarks/scripts/qihse_w12_engine_baseline_test.py
    python3 benchmarks/scripts/qihse_w12_engine_baseline.py --rows 256 --dimensions 128 --queries 8 --repeats 3 --output build/w12/engine-baseline.json

The default fixture is xorshift32 seed 0x1200, isotropic, 256 rows x 128
dimensions, 8 queries, top 10, candidate pool 64, all three metrics, one
warmup plus three timed repetitions. The checked-in artifact at
benchmarks/scripts/qihse_w12_engine_pilot.json includes fixture SHA-256,
library/probe hashes, compiler command, host CPU flags/allowed CPUs, raw latency
samples, first-repeat result IDs, recall, build time, FP32 resident bytes,
graph topology bytes, and complete qdb container bytes. It marks total
allocator RAM, sidecar disk bytes, AIMEM, real corpus, PQ and TurboQuant as
unmeasured. The C probe requires little-endian IEEE binary32.

Observed first full-engine run on the current host (2026-11-06, 8 queries x
3 repeats per metric, p50 from 24 warm samples):

| Wired route | Cosine recall@10 vs FP64 | Cosine p50 (us) | qdb bytes |
| --- | ---: | ---: | ---: |
| Exact FP32 | 1.000 | 97 | 191,516 |
| Trinary scalar + rerank | 0.925 | 141 | 191,516 |
| Trinary magnitude + rerank | 1.000 | 155 | 191,516 |
| Trinary magnitude bypass | 0.900 | 141 | 191,516 |
| Graph traversal + rerank | 0.975 | 128 | 228,432 |
| INT8 candidates + rerank | 0.888 | 51 | 225,344 |
| FP16 selector (FP32 alias) | 1.000 | 56 | 191,516 |
| Explicit FP32 selector (FP32 alias) | 1.000 | 57 | 191,516 |
| FP8 selector (FP32 alias) | 1.000 | 58 | 191,516 |
| FP4 selector (FP32 alias) | 1.000 | 57 | 191,516 |
| INT4 selector (FP32 alias) | 1.000 | 57 | 191,516 |
| Binary candidates + rerank | 0.300 | 35 | 191,516 |

The FP32 resident count was 131,072 bytes for every mode. Graph reported
114,352 additional in-process topology bytes; index_bytes reports graph
topology only. Container size is measured after post-build flush and is not
the byte size of every in-memory sidecar. In particular, binary and trinary
container sizes were unchanged from exact FP32 here. The five FP16/FP32/FP8/
FP4/INT4 selectors are exact FP32 scan aliases, so their timings are repeated
FP32 measurements, not evidence of compressed scoring. The current candidate
routes select globally before complete authorization, as audited below; these
unclassified results do not qualify a classified deployment. The sample is
too small and process ordering too variable for speedup claims.

Remaining W12.0 gate: run a declared real, authorized corpus and multiple
dimensions/seeds with controlled CPU affinity and order; capture total
sidecar/storage RAM and disk, build/update costs, latency distributions and
recall; establish scope-first candidate authorization and low-clearance
high-data negative tests before any approximate route is promoted. TurboQuant
is still a standalone codec, not a VectorDB search route.

## Actual wired alternatives

Line references below are to the pinned revision. `VDB` means
`src/broad_oak/qihse_vector_db.c`; `AIMEM` means
`src/spinnaker/qihse_ai_memory.c`.

| Alternative | Actual implementation | W12 qualification |
| --- | --- | --- |
| FLOAT32 (0) | Public search → dispatched exact scan (`VDB:6325–6343,6426–6432,6761–6820`) | Authorization precedes scoring. This increment measures its distance kernels, not the full route. |
| Graph (4) | HNSW construction exports level-0 adjacency; custom flat traversal (`1973–2076,6190–6322`) | Call it the VectorDB graph path. Traversal uses L2 even when final scores use cosine/dot; candidate authorization gate unresolved. |
| Trinary scalar (1) | Sign selection then FP32 rerank (`6871–6997`) | Pool ≥ physical row count bypasses quantized scoring (`6919–6920`). Global selection precedes auth. |
| Trinary magnitude (2) | Magnitude candidates then FP32 rerank (`7504–7679`) | Policy can fall back to FP32 (`7556–7569`); explicit pools and route receipts needed. |
| Magnitude bypass (3) | Direct quantized results (`7350–7497`) | Different score semantics; no FP32 rerank; metadata filter absent from output loop. |
| INT8 (5) | Quantized dot candidate selection (`2477–2602`) | Global selection precedes auth; rerank stops after K accepted rows, not after the whole pool. |
| FP16 / explicit FP32 / FP8 / FP4 / INT4 (7–11) | Check sidecar VALID, then call the same canonical FP32 exact scan (`6387–6410`) | **Not five independently wired compressed scoring routes.** No compressed-search speed/recall claim is justified. |
| Binary (12) | Hamming selection and partial FP32 rerank (`2841–2999`) | Existing row-authorization blocker below. |
| PQ | Library source (`Makefile:104–107`), standalone `qihse_pq.h:20–28` | Not a native VectorDB query mode. L2-squared, global `rand()` initialization (`qihse_pq.c:7–18,31–34,105–112`). |

No unmeasured route is reported as a successful comparison. The JSON artifact
contains an explicit `unmeasured` map instead of invented measurements.

## Security and integration blockers

These are **source-confirmed findings**, not runtime exploit reproductions. They
must not be inherited by a new codec/index adapter. Fixing them is separate work
from this benchmark-only increment.

- Graph (`VDB:6234–6288`), INT8 (`2516–2562`), trinary scalar
  (`6936–6945`), magnitude (`7618–7629`) and sparse (`3997–4080`)
  select globally before their later row authorization checks. The main public
  `qihse_vector_db_search` checks non-NULL user, but that does not prevent hidden
  rows consuming candidate capacity. Its declaration is in
  `include/qihse_vector_db.h:733–738`.
- Binary candidate selection (`2889–2935`) and rerank (`2955–2995`)
  contain no row auth check. The shared insertion helper (`6685–6758`)
  does not authorize either. Public native
  `qihse_vector_db_search_binary_candidates` (`header:1093–1099`,
  `VDB:3010–3015`) enters this helper directly; the main mode-12 route
  checks only non-NULL user (`6341,6411–6421`). This is public C exposure,
  not merely an unused static helper. Rust also accepts the raw mode. No direct
  binary RESP route was found.
- Graph *does* have a public RESP route: VECSEARCH/VECSCATTER propagate session
  identity (`qihse_resp_engine.c:2792–2805,2872–2878`), but cannot repair
  filtering after candidate selection in the engine.
- Native rows have classification/SCI but no first-class tenant/project/owner
  (`persistence/qihse_vector_store.h:30–39`). Optional metadata filters
  are not a replacement for mandatory authenticated scope.
- Cache keys omit mode, pool, threshold and metadata filter
  (`VDB:3056–3092`); hits return cached IDs/scores without live materialization
  authorization (`3127–3145`). Benchmark cache hits can conceal path/recall
  differences; future scoped search must also handle revocation and scope.
- The context-free direct-ID compatibility wrapper passes NULL (`5809–5815`),
  but the shared auth function denies classified/SCI access for NULL
  (`core/qihse_auth.c:1406–1412`). This audit does **not** claim classified
  disclosure through that wrapper.

AIMEM is a separate substrate: it contains no VectorDB calls. Its scoped entry is
`qihse_ai_memory_recall_scoped` (`AIMEM:1977–2035`), called by RESP
RECALL-SCOPED with session user (`qihse_resp_engine.c:7009–7027`). It enumerates
user-authorized tenant-prefixed KV records and applies scope/owner/kind before
embedding/ranking (`AIMEM:1919–1969,2031–2035`); materialization rereads
canonical records with user context (`2066–2075`). QH-05 `query_begin`
(`3197–3244`) builds authorized scoped rows (`3067–3108`) before ranking
(`3124–3194`), and cursor continuation rechecks visibility (`3247–3264`).
W12.3 needs a real scoped adapter, stable ID mapping and generation boundary,
not simply another native enum value.

## Mutation and persisted generation map

| Operation | Actual path / source |
| --- | --- |
| Insert | public add → WAL ADD when file-backed → apply_add → append_row (`VDB:5572–5620,4391–4438,4341–4388`) |
| Delete | public wrapper → delete_by_ids → WAL DELETE → tombstone → finish generation (`5758–5771,5818–5893`); explicit graph edges can return EBUSY |
| Update | WAL UPDATE → old-row tombstone → append same external ID (`6045–6074`) |
| Upsert | WAL UPSERT → existing-ID tombstone → append → finish generation (`6145–6173`) |
| Compaction | copy live rows, change physical ordinals, invalidate qtri/qmag, flush (`7809–7949`) |
| Flush | rebuild qtri/qmag → authoritative snapshot → vector-store flush (`7684–7752`) → truncate WAL / committed generation (`7753–7767`) |
| Reopen | snapshot → WAL replay → graph/INT8/tier load (`5493–5533`) |

The actual store uses sections inside one `.qdb` container, despite legacy
`vectors.qtri`/`vectors.qmag` wording. Container `QIHSEQDB` version 1;
qtri/qmag/graph/INT8/tier/edges section IDs are `0x0007` through `0x000C`
(`persistence/qihse_container.h:34–47`). Current manifest 192 bytes, legacy
128 bytes, index rows 48 bytes, manifest/index/idmap version 1
(`qihse_vector_store.c:23–32`); authoritative FLOAT32 encoding version 1
(`qihse_vector_store.h:22–23`). qtri/qmag payload metadata resides in the manifest,
not independent codec headers (`header:58–81`, `.c:594–675`). Graph writes
`QIHSEQGR` v2 and reads v1/v2 (`VDB:848–850,919–920`). INT8 writes
`QIHSEQI8` v1 (`1181–1183`); its loader validates generation/size/checksum,
but not the version field (`1240–1257`). WAL `QHWAL01` v1; edges `QIHSEEDG` v1
(`65–78`).

**Do not copy the existing lifecycle gaps:** mutation invalidation and compaction
mark qtri/qmag stale, not graph/INT8/binary (`1756–1773,7931–7938`); graph
load ignores its generation (`924–927`); flush can resave a VALID old graph under
a new generation without rebuilding (`7792–7795`). Container publication already
has temporary-file fsync, rename, directory fsync
(`qihse_container.c:894–930`), but reusing it requires a separately reviewed
section/schema design. No migration is attempted here.

## ABI and native FP32 comparison contract

- Existing mode values **0–12** and metrics **0–2** are pinned by compile-time
  tests. Append future enum values; do not renumber. Query/result structures have
  no size/version negotiation (`qihse_vector_db.h:271–278,338–353`); adding
  fields is not automatically ABI-safe. Result structures have no generation.
- Python hardcodes default FP32/cosine and forwards `current_user`
  (`sdks/python/qihse.c:264–274`). Rust exposes explicit User and raw mode
  (`rust/qihse-rs/src/lib.rs:264–301`). Revisit generated bindings/initializers
  before any layout change. RESP has no general mode selector in the inspected
  VECSEARCH grammar; any new adapter requires low-clearance/high-data CI tests.
- Native unrestricted comparison must use `max_results == K`, since the default
  path uses max_results rather than query.top_k (`VDB:6432`), and
  `similarity_threshold = -FLT_MAX`, since zero excludes negative scores (`6812`).
- Equal scores retain physical scan order (`6697–6703`), not external-ID order.
  Compaction may change that order. This pilot uses row ordinals as synthetic IDs.
- Open can auto-enable cache from config (`5536–5542`); `enable_cache(vdb, 0)`
  rejects EINVAL (`8343–8345`). Future native runs need controlled empty config
  and explicit cache clearing, with clear cost declared separately.
- `index_bytes` counts HNSW topology only (`8430–8435`), and memory usage exposes
  FP32 resident counters (`8424–8426`), not total sidecars/rows/maps/cache/allocator
  costs. Public add initializes unclassified/no-SCI rows (`4366–4375`), so a
  synthetic success is not an authorization proof.

## Reproducible first baseline

Run from the repository root, requiring a C99 compiler and Python 3 (standard
library only):

```sh
make test-w12-fp32
make test-w12-fp32-sanitize
make bench-w12-fp32 W12_ARGS='--rows 256 --queries 8 --repeats 3 --dimensions 128 384 768 1536 --corpora isotropic anisotropic clustered duplicates high-dynamic-range sparse-sign --output build/w12/fp32-pilot.json'
```

`W12_CC` selects the compiler for Make targets; `CC` does so for the Python
script directly. Sanitizer target defaults to leak detection. In a ptrace
sandbox where LeakSanitizer refuses to run, use
`ASAN_OPTIONS=detect_leaks=0 make test-w12-fp32-sanitize` and explicitly report
that **leak detection was not verified**. This is not a production workaround.

The generated fixtures use versioned xorshift32 integer state and binary
fractions, then round to IEEE binary32. There is no corpus download, real user
data ingestion, authentication bootstrap, or persistent store. Dimensions
128/384/768/1536 are predeclared; all six synthetic families are retained.
The scalar production path is the exhaustive FP32 baseline. An independent
Python binary64 `math.fsum` oracle scores **all selected rows**, ranks by score
then row ordinal, and provides numerical/ranking reference evidence. The native
scalar/dispatched paths are not required to be bitwise identical: FP32
accumulation, reduction order and FMA can disagree near ties. Pilot score
contract is `abs(score-reference) <= 2e-5 * max(1, abs(reference))`; exact row-set
recall reports every disagreement rather than hiding it behind a tie tolerance.
Zero-norm cosine is 0; L2 similarity is `1/(1+distance)`; negative similarities
are included. Nonfinite selected inputs, raw distances and FP32 computed scores fail.
In particular, overflowing L2 distance is rejected before conversion can hide
infinity as a zero similarity.

Kernel top-K buffers are reused; selection precedes validation/scoring.
The selection mask is a **synthetic test fixture**, not a production auth API.
C/ABI checks and Python tests cover exact scores, negative scores, ties, empty
selection, zero norms, nonfinite values, overflow, wrong shapes, reproducible
corpora, odd SIMD tails, recall/statistics and report semantics.

Timing includes the C validation + exhaustive scan + top-K and one ctypes call;
Python fixture preparation, FP64 truth and warmup are excluded. This is not
full-engine latency or a pure dot-kernel microbenchmark. Reports retain compiler,
flags, source hashes, Git SHA/dirty state, host, seed, fixture hash, all raw warm
latency samples, result rows, p50/p95/p99, throughput, approximate normal mean CI,
selected-top-K score error and scalar/reference recall. Score error is measured
for returned rows, not every scanned row. Repeated warm queries are correlated;
8 unique queries and 24 timing samples do not establish tail-latency significance.
Vector/query/auxiliary array byte counts are labeled separately and exclude
Python objects, duplicate fixture buffers and runtime/allocator overhead; engine resident
and sidecar disk bytes remain **null**, not guessed. No speedup or compression
promotion decision is made from this pilot.

## W12.1 readiness: independently implement the paper, not INT4

Primary reference: [ICLR 2026 paper, Algorithms 1–2](https://proceedings.iclr.cc/paper_files/paper/2026/file/5c802ef38ab6e366c2ea06eee554c088-Paper-Conference.pdf).
This is a contract for a later codec, **not implemented by this increment**.

1. For `x`, preserve `rho = ||x||`, normalize `u = x/rho`; construct a Haar
   orthogonal rotation from Gaussian QR with the diagonal sign convention. Use
   independent RNG streams for rotation and residual projection.
2. Use dimension-aware scalar centroid tables for the spherical marginal
   `f_d(t) proportional to (1-t*t)^((d-3)/2)` on `[-1,1]`, keyed by dimension and
   bit width. Lloyd boundaries are centroid midpoints. Do not silently use
   Gaussian tables for all dimensions or renormalize centroid reconstruction.
3. For MSE k bits, encode rotated coordinates; reconstruct
   `u_hat = transpose(Pi) * centroids`. MSE score is
   `rho * dot(Pi*q, centroids)`.
4. For product total b bits, use k=b-1 MSE bits and residual signs:
   `r=u-u_hat`, `gamma=||r||`, independent `S_ij ~ N(0,1)`, `s=sign(S*r)`.
   The dot correction is
   `rho * gamma * sqrt(pi/2)/d * dot(S*q, s)`.
   Sketch the **residual**, not the original vector, and handle rho/gamma zero
   exactly. Use true norms for cosine and L2, not decoded-vector norms.
5. Dense reference transforms may be O(d²); report setup/encode costs honestly.
   Share rotation/projection/tables per profile and prepare query transforms once.
   A fast Hadamard substitute is not the same distribution or unbiasedness
   guarantee; treat it as a separately justified experimental profile.
6. FP64 norm/residual handling avoids overflow on finite FP32 inputs. For an
   initial reference profile, packed MSE payload plus FP64 norm costs
   `ceil(k*d/8)+8` bytes/row; corrected payload plus both norms costs
   `ceil((b-1)*d/8)+ceil(d/8)+16`, before IDs/metadata/alignment. Two shared dense
   FP64 matrices cost `16*d*d` bytes (36 MiB at d=1536). If authoritative FP32
   stays resident, adding a sidecar **increases** total RAM; code-only compression
   ratio is not whole-store reduction.
7. Unbiasedness tests require independent projection seeds with fixed residual
   and query, including self/negative/orthogonal cases. Seed alone does not
   guarantee bitwise QR/Gaussian agreement across libm/platforms. Persist exact
   parameters or explicitly bound determinism to a pinned implementation profile.
   Malformed packed inputs, exact lengths/padding, fuzzing and sanitizers remain
   mandatory. No third-party implementation is copied; review licenses before
   any future code/data reuse.

The mathematical contract is sufficiently specified to plan a standalone scalar
reference next. **The W12.0 promotion gate remains open:** no declared real
semantic corpus, full authorized engine comparison, effective resident-index
accounting, target hardware repetition, or security/crash integration gate has
passed. W12.1 work must not be mistaken for permission to integrate or optimize
an unsafe global candidate path. W12.3 is blocked on pre-top-K scoped auth,
complete candidate reranking, generation-bound IDs, cache isolation and negative
regression tests.
