# QIHSE Core Search: Engineering Reference

> **Status: source contract with targeted regression checks (2026-11-14).**
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
number of queries found. The implementation currently calls the scalar search
for each query. It does not share an embedded data matrix or promise SIMD
batching or parallel execution. Missing queries retain the not-found sentinel.

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

Set `config.enable_profiling=true` to collect timings from the streaming core,
then call `qihse_get_performance_stats`. Timing fields for stages that do not run
must not be treated as evidence of executed amplification or device work.
No recorded score or hardcoded hit-rate value establishes an algorithmic speedup.
`avg_confidence` is a verified-hit indicator (zero or one), while
`classical_fallbacks` and `total_operations` remain uninstrumented compatibility
fields. Their zero values do not establish that no fallback or work occurred.

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

## VectorDB boundary

The modern VectorDB dispatcher is separate from the original scalar lookup.
Its INT8 and binary selectors exact-score every admitted candidate, retaining
the requested top-k by the exact metric. Approximate candidate omission is
still possible; complete reranking is not exhaustive search over omitted rows.
The binary selector requires an explicit user, restricts clearance/SCI before
candidate admission, and rechecks before payload materialization.

For database authorization, federation, transport, installed SDK contracts and
other public runtime surfaces, use [the main API reference](../../API_REFERENCE.md)
and the relevant current header. This core correction makes no new claim about
Intel oneAPI, Fortran, CUDA or NPU integration.
