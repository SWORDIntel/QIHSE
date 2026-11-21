# QIHSE Core Search: Engineering Reference

> **Status: source contract with targeted regression checks (2026-11-15).**
> This page replaces the earlier core-search examples and complexity claims.
> The authoritative API inventory is [docs/API_REFERENCE.md](../../API_REFERENCE.md),
> including its separately labelled core-math addendum (§8.14). An earlier
> shared-library symbol inventory does not certify the new source changes.

## Core lookup

```c
not_stisla_result_t qihse_search(
    const void* data,
    size_t n,
    const void* query,
    not_stisla_anchor_table_t* table,
    const qihse_config_t* config
);
```

The function returns a matching original-record index or
`NOT_STISLA_NOT_FOUND`. Compare with that macro, not a signed integer literal:
`not_stisla_result_t` is `size_t`. Invalid arguments and resource failures also
return the sentinel; inspect `errno` according to the source contract.

For numeric records, a signed random-Fourier-feature inner product proposes a
candidate. Every returned index is checked against the original typed record.
In the default exact/fallback configuration, a failed candidate triggers a
complete equality search. Approximate feature scores cannot turn an absent
value into a successful lookup. Integer conversion to double can collide above
2^53, but final equality compares original integer values.

The scalar numeric scorer performs O(nD) work and uses O(D) kernel/feature
scratch, where D is the selected feature dimension. Exact fallback adds O(n)
comparisons. There is no O(sqrt(n)) search guarantee. The streaming core creates
neither a per-record complex state nor a Grover simulation, and does not
promise a hardware speedup. Direct typed search remains a necessary baseline.

For STRING, BINARY, STRUCT and CUSTOM records, the caller supplies a fixed record
width in `type_descriptor.element_size`. STRING uses NUL-terminated slots;
BINARY/STRUCT use byte equality; CUSTOM requires `compare_fn`. The descriptor
is a record contract, not an arbitrary pointer to variable-length storage. See
the current headers for comparator signatures and record equality details.

The descriptor-free compatibility verifiers `qihse_verify_result` and
`qihse_verify_search_result` support INT64, UINT64 and DOUBLE only. Use the
descriptor-aware main search for the non-numeric types above.

The anchor-table argument remains in the API but is not used by this streaming
path. Experimental amplification, heterogeneous device APIs and parallel
pipeline APIs remain separate; their configuration fields do not enable them
inside this exact lookup.

### Numeric example

```c
#include "qihse.h"
#include <stdint.h>
#include <stdio.h>

int main(void) {
    const int64_t data[] = {1, 7, 42, 100};
    const int64_t query = 42;
    const size_t n = sizeof(data) / sizeof(data[0]);
    qihse_config_t config;
    if (qihse_config_init(&config, QIHSE_TYPE_INT64, n) != 0) return 1;
    not_stisla_result_t result = qihse_search(data, n, &query, NULL, &config);
    if (result == NOT_STISLA_NOT_FOUND) return 2;
    printf("Found at index: %zu\n", (size_t)result);
    return data[result] == query ? 0 : 3;
}
```

## Configuration

Use the `qihse_config_t` declaration in `include/qihse.h`; do not copy an older
struct definition into a consumer. Initialize with:

```c
int qihse_config_init(qihse_config_t* config,
                      qihse_data_type_t data_type,
                      size_t array_size);
```

It returns zero on success and a negative error on invalid input. Numeric
configurations receive the appropriate record width. Non-numeric record width
and any custom comparator remain caller responsibilities.

| Field | Initial value or meaning |
|---|---|
| `rff_gamma` | 1.0; must remain finite and positive |
| `random_seed` | 42; zero is also a valid deterministic seed |
| `auto_dimensions` | true |
| `min_dimensions`, `max_dimensions` | 64, 2048 |
| `fixed_dimensions` | 256; used when `auto_dimensions=false` |
| `verification` | Exact mode with classical fallback |
| `enable_profiling` | false |
| `use_heterogeneous`, `enable_acceleration` | false; the streaming lookup uses its CPU path |

The automatic dimension choice is a bounded size heuristic. It does not measure
entropy, effective rank or an achieved accuracy percentage. Unmeasured
statistics are marked unavailable rather than populated with invented values.
Compatibility fields such as timeout/backend/pipeline choices must not be read
as guarantees that the scalar path enforces or dispatches them.
In particular, neither `timeout_ms` nor
`verification.max_verification_time_us` is an enforced deadline.

## Batch lookup

```c
size_t qihse_batch_search(
    const void* data, size_t n,
    const void* queries, size_t num_queries,
    not_stisla_result_t* results,
    not_stisla_anchor_table_t* table,
    const qihse_config_t* config
);
```

`queries` contains fixed-width records using the same descriptor stride as
`data`; `results` has at least `num_queries` entries. The return value is the
number of queries found. A batch now creates one phase-cosine basis and shares
streamed row projections across tiles of up to 16 queries. Missing queries
retain the not-found sentinel. This does not retain an n-by-D feature matrix or
dispatch parallel devices.

### Choose the methodology explicitly

Use `qihse_search_ex` or `qihse_batch_search_ex` for versioned method options and
per-call measurements. They return 0 on success, including absence, or -1 with
`errno` on failure. Results carry the matching index or not-found sentinel.

| Method | Meaning |
|---|---|
| `QIHSE_SEARCH_EXACT` | Direct original-record equality scan with no feature allocation. |
| `QIHSE_SEARCH_RFF_COSINE` | Existing random-phase cosine map, with D real coordinates. |
| `QIHSE_SEARCH_RFF_PAIRED` | D/2 frequencies and interleaved cosine/sine pairs, with D real coordinates. D must be even. |

All three preserve original typed equality. The default is phase-cosine RFF;
method choice is explicit rather than inferred from benchmark results. Initialize
options and optional metrics with their size-aware helpers:

```c
qihse_search_options_t options;
qihse_search_metrics_t metrics;
if (qihse_search_options_init(&options, sizeof(options)) != 0) return 1;
if (qihse_search_metrics_init(&metrics, sizeof(metrics)) != 0) return 1;
config.auto_dimensions = false;
config.fixed_dimensions = 128; /* Even D, within the initialized 64..2048 bounds. */
options.method = QIHSE_SEARCH_RFF_PAIRED;
options.tile_size = 16;
if (qihse_batch_search_ex(data, n, queries, num_queries, results, NULL,
                          &config, &options, &metrics) != 0) return 1;
```

Tile sizes are 1–64. For finite numeric data, Q finite queries and no projection failures,
row projections fall from `n*Q` at tile 1 to `n*ceil(Q/T)` at tile T. Query
projections remain Q; dot products remain O(nQD). Scratch is O(TD) and does not
grow with n. The implementation clamps the active tile size to Q. Exact mode
reports zero dimensions, tile size 1 and zero owned heap scratch. These counters
make the computation saved by batching observable without implying a different
asymptotic lookup bound.

## Numerical primitives

### RFF kernel

```c
qihse_rff_kernel_t* qihse_rff_create(size_t input_dims, size_t output_dims,
                                    double gamma, uint64_t seed);
void qihse_rff_project(const qihse_rff_kernel_t* kernel,
                       const double* input, double* output);
void qihse_rff_destroy(qihse_rff_kernel_t* kernel);
```

The basis is `sqrt(2/D)*cos(omega*x+b)`, with Gaussian frequency variance
`2*gamma`, approximating `exp(-gamma*||x-y||^2)`. Gamma and dimensions must be
positive; gamma must be finite. Allocation products are checked before use.
Kernel-local random state includes a deterministic seed-zero case and does not
consume the process-global C RNG. Seed reproduction is limited to the same
implementation/math platform; it is not a cross-version persisted-basis promise.

For a selectable feature method, use the opaque `qihse_rff_map_t` API. The
`QIHSE_RFF_COSINE_PHASE` method preserves the formula above;
`QIHSE_RFF_PAIRED_SINCOS` uses D/2 frequencies and
`[cos(w0.x),sin(w0.x),...]/sqrt(D/2)`. Its ideal self-kernel is one and its ideal
dot product depends only on x−y; floating-point rounding still matters.
`qihse_rff_map_project` returns status and rejects nonfinite inputs or a
nonfinite projection. Do not consume its output after failure.

Use `qihse_rff_map_get_descriptor` to obtain basis version, method, both
dimensions, gamma and seed. All fields must agree between data and query
features. Serialize fields explicitly. The old kernel struct and creation API
retain their phase-cosine meaning; selecting paired features does not reinterpret
old projected vectors.

AVX2 construction still rounds its output dimension to a multiple of eight and
casts the canonical basis to float. Compare CPU variants using the actual
rounded dimension and their stated floating-point precision. Correct CPU tails
and strides do not establish any untested GPU/NPU equivalence.

### Floating-point helper functions

`qihse_math_fast_exp`, `qihse_math_fast_log`, `qihse_math_fast_sqrt` and
`qihse_math_fast_sincos` retain their precision-selector arguments for
compatibility. Every selector currently uses libm. No separate approximation
error or speedup is implied by the names FULL/HIGH/MEDIUM/LOW/FAST.

### State fidelity and vector verification

RFF, superposition, amplification and vector-verification layouts are defined
once in `include/qihse_math_types.h`. Private translation units must not add
fields to those public structures.

The typed `qihse_superposition_state_fidelity(a,b)` computes normalized squared
complex overlap. The existing four-argument
`qihse_superposition_fidelity(a,b,n,out)` remains the raw-float compatibility
entry; its output is also bounded normalized squared overlap. Fidelity is not a
calibrated search success probability.

The legacy `qihse_adaptive_amplify` entry returns `-ENOTSUP`, while the void
`qihse_apply_oracle` sets `errno=ENOTSUP` without changing the state. Their
signatures do not establish a query-to-state marking rule. For explicit state
experiments, use `qihse_amplify` with target indices.
The separately named `qihse_amplify_internal` and
`qihse_amplify_fixed_point` return `-1` with `errno=ENOTSUP`.

Vector verification uses explicit lengths through
`qihse_verify_result_advanced_sized` and `qihse_verify_batch_sized`. The old
unsized entry points return -1 with `errno=ENOTSUP`, because neither a query
pointer nor a verification mode safely describes a vector's length. Required
ground truth and result-lifecycle rules are specified in
`algorithms/qihse_verification.h`. These numeric helpers do not authorize reads
from a database.

Sized EXACT verification requires elementwise equality. Sized PRECISION checks
every absolute difference against `config.tolerance`; the other supported
similarity modes report bounded cosine scores. Ground truth is mandatory,
inputs must be finite and nonempty, and NONE is unsupported. Destroy a populated
verification result before reuse to release any owned error message.

## Profiling and evidence

Prefer a per-call `qihse_search_metrics_t` with the `_ex` APIs. It records actual
candidate hits, fallback queries/hits, direct queries, unprojected queries,
successful query/row projections, projection failures, original-record
comparisons, basis builds, tiles and peak owned heap scratch. Stage timings
include instrumentation overhead. Caller buffers, stack and allocator metadata
are excluded from scratch bytes.

For the legacy global report, set `config.enable_profiling=true`, then call
`qihse_get_performance_stats`. Timing fields for stages that do not run
must not be treated as evidence of executed amplification or device work.
No recorded score or hardcoded hit-rate value establishes an algorithmic speedup.
`avg_confidence` is the verified-match fraction, not a probability estimate;
`classical_fallbacks` now counts actual fallback queries. `total_operations`
remains an uninstrumented compatibility field.

Run the actual core benchmark with an exact baseline:

```sh
scripts/run-core-methods-bench.sh > core-methods.jsonl
scripts/run-core-methods-bench.sh --method paired --tile 1,16 --dimensions 128 --dataset nearby_double --format csv > paired-nearby.csv
```

The quick default compares all three methods on present, absent, duplicate,
nearby-double and large-integer fixtures. It runs one warmup and three timed
repeats, at 512 records, 32 queries, 64/128 real coordinates, tiles 1/16, seed 42
and gamma 1. Flags select each of these choices. JSONL/CSV records actual CPU
and wall batch times, per-call stage times, correctness and counters. Validation
against a separate original-type oracle is outside the timed region; any
mismatch makes the command fail. The amortized ns/query field is batch time
divided by Q, not a single-request latency distribution. Setup is included in
each timed public call.

Compare against an independent exact baseline and record source revision,
compiler flags, input/query distributions, setup cost, steady-state latency,
bytes, candidate recall and fallback work. Run the full repository gate with:

```sh
make test TEST_JOBS=32
```

Focused regression checks and the synthetic paired-feature experiment are
separate evidence. Proposed small optimizations and more unusual feature maps
are in [Core feature experiments](../../plans/qihse_core_experiments.md).
The single [migration note](../../API_REFERENCE.md#migration-note) records
compatibility changes, feature regeneration and the rebuild command.
The [validation follow-up](../../plans/qihse_core_validation.md) records later
shared-library integration and the full-suite outcome separately from the
original synthetic benchmark.

## VectorDB boundary

The modern VectorDB dispatcher is separate from the original scalar lookup.
Its INT8 and binary selectors exact-score every admitted candidate, retaining
the requested top-k by the exact metric. Approximate candidate omission is
still possible; complete reranking is not exhaustive search over omitted rows.
Both selectors restrict clearance/SCI before candidate admission and recheck
during exact reranking, so an excluded row cannot displace an authorized row
from a bounded pool. The direct binary candidate entry requires an explicit user.

For database authorization, federation, transport, installed SDK contracts and
other public runtime surfaces, use [the main API reference](../../API_REFERENCE.md)
and the relevant current header. This core correction makes no new claim about
Intel oneAPI, Fortran, CUDA or NPU integration.
