# CodeGraph immutable CSR projection

> **Roadmap authority:** [ROADMAP.md](../../ROADMAP.md) is the sole authority for delivery status, remaining work, sequencing and acceptance. This file retains supporting design, acceptance criteria and dated evidence; historical status labels below are not an independent current checklist. Consolidated 2026-11-07.

The native CodeGraph CLI now builds a private compressed sparse row (CSR) query
projection instead of duplicating nodes and edge properties into the general
mutable graph engine. Authenticated KV records remain authoritative and retain
all original fields, including unresolved relations and unknown metadata. This
change reduces resident query memory; it does not change persisted snapshot
formats or discard graph facts.

`tools/qihse_codegraph_csr.c` owns dense edge records, two incident-index arrays,
and shared string blocks. It retains stable insertion order in each adjacency.
Node file/name/kind strings share those blocks. The temporary string hash index
is freed when construction finishes. Generation replacement destroys the
projection and its strings together while holding the existing generation lease.

The handle inherits an explicit authenticated `qihse_user_t *`; construction and
all accessors fail closed for missing or revoked principals. The authenticated
snapshot loader and validated public-record schema still reject classified
records before building this projection. No context-free graph read API is
introduced. The principal must outlive the projection.

Queries preserve incoming self-loop exclusion and the existing 2,048 matching
neighbors per direction, with type filtering before that bound. A shared budget
also limits each query to 65,536 examined edges, including rejected types and
self-loops. Exhaustion sets `truncated` and suppresses test-gap hints whose
relations could not be examined. Batched requests apply this bound independently
to each of their at most 32 queries, bounding the entire batch to 2,097,152
examined edges. The complete underlying graph is retained.

## Measurement

The existing `benchmarks/codegraph_readonly_compare.py` harness compared current
main (already including readonly KV release and `malloc_trim`) to this CSR
candidate. Both binaries linked the same real `libqihse`, with the same compiler
settings. Every memory pair used the exact same immutable packed-v2 generation
of 16,000 nodes and 48,000 edges. Alternating run order was before/after then
after/before. Other host work continued and page caches were not dropped.

| Measurement | Current main | CSR candidate |
|---|---:|---:|
| Resident RSS pair 1 (KiB) | 66,736 | 28,964 |
| Resident RSS pair 2 (KiB) | 66,800 | 28,892 |
| Median resident RSS (MiB) | 65.20 | 28.25 |
| Single cold context wall time (seconds) | 11.083 | 10.814 |
| Single cold process peak RSS (KiB) | 316,492 | 279,036 |

Median resident memory fell **56.7%**, or **2.31 times smaller**. The single cold
measurements are diagnostic, not a reliable latency benchmark. Import/snapshot
validation still needs the full authenticated KV representation, so peak memory
remains substantially larger than steady state. This does not substantiate the
archive's different synthetic component benchmark as an end-to-end speedup.

The receipt is `benchmarks/codegraph_csr_reference.json`, including binary,
CLI source, CSR source, shared-library, and CLI-delta hashes. The baseline is the
captured CLI immediately before this projection patch, with the earlier automatic
format selection, staging, retention, and readonly release changes included.

Example reproduction with independently built binaries:

```sh
python3 benchmarks/codegraph_readonly_compare.py \
  --baseline "$BASELINE_BIN" --candidate "$CANDIDATE_BIN" \
  --library-dir "$PROJECT_ROOT" --nodes 16000 --edges 48000 --pairs 2 \
  --output ./codegraph-csr-result.json
```

The same harness verifies cold query parity, valid generation refresh, corrupt
manifest denial and recovery, and capability revocation after all memory pairs.
Dedicated projection tests additionally cover self-loop ordering, late filtered
test relations, and high-degree scan exhaustion. The C unit test uses real
authentication and checks revoked-principal access and concurrent immutable
readers. Existing CLI storage tests exercise low-clearance reads of classified
legacy and packed snapshots. Sanitizer validation instruments the CLI and codecs;
the linked shared QIHSE library is not instrumented.

## Focused validation receipt

The controlled harness passed cold query parity, valid daemon generation
refresh, invalid-manifest denial/recovery, and capability revocation. The
dedicated Python projection regression passed with 4,099 edges (baseline
query/context/impact/review equivalence, self-loops and late TESTED_BY filtering)
and 65,537 self-loop edges (bounded scan, truthful truncation, no unverified
test-gap hint).

The same cold/refresh/revocation harness passed with AddressSanitizer and
UndefinedBehaviorSanitizer on an 800-node/2,400-edge fixture. Leak detection was
disabled because the linked shared runtime is not instrumented. Sanitizer RSS
is diagnostic only and is not comparable to the production memory result;
the receipt is `benchmarks/codegraph_csr_sanitizer.json`.

`tests/test_codegraph_storage.py` passed against the candidate, including
low-clearance rejection of protected legacy and packed snapshots, authenticated
storage accounting, migration, corruption handling, deduplication and GC.

`tests/test_codegraph_native.py` also passed against the candidate, including
concurrent daemon replacement, bounded Git subprocess cleanup, stale-source
denial, capability rotation failure, and revocation races. The cross-UID
SO_PEERCRED negative check was skipped because the harness was not running as
root; its other authorization checks ran. The parent integration still requires
the repository's full `make test TEST_JOBS=32` gate.
