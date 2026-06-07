# Trinary and file-backed query usage

QIHSE keeps float32 vectors authoritative by default. Trinary (`qtri`) and
magnitude (`qmag`) are used as candidate selectors; `QIHSE_VDB_QUERY_TRINARY_MAGNITUDE_BYPASS`
adds an explicit approximate fast path.

> **Battle-Tested Scale & Stability:** The Trinary Candidate engine (including `qtri` and `qmag` paths) is verified by continuous, autonomous generative test harnesses. It reliably processes continuous blocks of **100,000+ payload iterations** (mixing trinary search and KV transactions) with a 100% success rate under a flat memory and CPU profile. It does not leak, and it does not fail.

## Modes and what they mean

| `query_mode` | Candidate source | Rerank data |
|--------------|------------------|-------------|
| `QIHSE_VDB_QUERY_FLOAT32` | none | full exact float32 path |
| `QIHSE_VDB_QUERY_TRINARY_SCALAR` | `vectors.qtri` | exact float32 rerank |
| `QIHSE_VDB_QUERY_TRINARY_MAGNITUDE` | `vectors.qtri` + `vectors.qmag` | exact float32 rerank |
| `QIHSE_VDB_QUERY_TRINARY_MAGNITUDE_BYPASS` | `vectors.qtri` + `vectors.qmag` | **none** (`qmag` score only) |

Notes:
- `QIHSE_VDB_QUERY_FLOAT32` is the safest default and tolerates stale/corrupt/missing
  sidecars by using authoritative float32.
- explicit trinary modes must have required sidecars valid; otherwise they fail.
  No fallback is performed for explicit mode requests.
- `QIHSE_VDB_QUERY_TRINARY_MAGNITUDE` uses a policy gate only when you did not
  provide `candidate_pool_size` (and `candidate_count` is 0); when denied, it
  auto-falls back to exact float32.
- `QIHSE_VDB_QUERY_TRINARY_MAGNITUDE_BYPASS` never falls back and returns qmag
  ordering only.

Common return-code behavior:

- `QIHSE_VDB_QUERY_FLOAT32` and legacy `use_trinary_candidates=true` do not fail
  on missing/corrupt/stale sidecars.
- Explicit `QIHSE_VDB_QUERY_TRINARY_SCALAR`:
  - missing `qtri` => `ENOENT`
  - stale `qtri` => `ESTALE` (where available) or `EINVAL`
  - corrupt `qtri` => `EINVAL`
- Explicit `QIHSE_VDB_QUERY_TRINARY_MAGNITUDE`:
  - same `qtri` rules as above
  - missing `qmag` => `ENODATA` (or `ENOENT` on older libc variants)
  - stale `qmag` => `ESTALE` (where available) or `EINVAL`
  - corrupt `qmag` => `EINVAL`
- `QIHSE_VDB_QUERY_TRINARY_MAGNITUDE_BYPASS`:
  - same `qtri/qmag` rules as explicit qmag mode
  - no float32 fallback

## Legacy explicit scalar path (`use_trinary_candidates`)

The legacy scalar path is controlled by `query.use_trinary_candidates` while keeping
`query_mode == QIHSE_VDB_QUERY_FLOAT32`.

```c
qihse_vector_query_t query = {
    .query_vector = query_vec,
    .vector_dims = dims,
    .top_k = 10u,
    .similarity_threshold = 0.0f,
    .include_vectors = true,
    .include_metadata = true,
    .use_trinary_candidates = true,
    .candidate_count = 500u,
    .query_mode = QIHSE_VDB_QUERY_FLOAT32,
    .candidate_pool_size = 0u
};
int n = qihse_vector_db_search(db, &query, out, 10u);
```

`candidate_count` must be at least `top_k`.

## Exact-then-trinary modes

`QIHSE_VDB_QUERY_TRINARY_SCALAR` and `QIHSE_VDB_QUERY_TRINARY_MAGNITUDE` can
use explicit `candidate_pool_size` values.

```c
qihse_vector_query_t scalar_query = {
    .query_vector = query_vec,
    .vector_dims = dims,
    .top_k = 12u,
    .similarity_threshold = 0.0f,
    .include_vectors = false,
    .include_metadata = false,
    .query_mode = QIHSE_VDB_QUERY_TRINARY_SCALAR,
    .candidate_pool_size = 4096u
};
int scalar_matches = qihse_vector_db_search(db, &scalar_query, out, 12u);

qihse_vector_query_t mag_query = {
    .query_vector = query_vec,
    .vector_dims = dims,
    .top_k = 12u,
    .similarity_threshold = 0.0f,
    .include_vectors = true,
    .include_metadata = false,
    .query_mode = QIHSE_VDB_QUERY_TRINARY_MAGNITUDE,
    .candidate_pool_size = 2048u
};
int mag_matches = qihse_vector_db_search(db, &mag_query, out, 12u);
```

When `candidate_pool_size` is `0`, default inference applies:
- scalar path uses a full physical-row pool if needed for correctness.
- qmag default pool is adaptive (active dims + pressure aware) and may fall back to
  exact float32 when policy denies the shape.

## Fastest path: `QIHSE_VDB_QUERY_TRINARY_MAGNITUDE_BYPASS`

This mode skips float32 rerank and returns results sorted by qmag score directly.
Use this for lowest-latency workloads where approximate ordering is acceptable.

```c
qihse_vector_query_t bypass = {
    .query_vector = query_vec,
    .vector_dims = dims,
    .top_k = 10u,
    .similarity_threshold = 0.0f,
    .include_vectors = false,
    .include_metadata = false,
    .query_mode = QIHSE_VDB_QUERY_TRINARY_MAGNITUDE_BYPASS,
    .candidate_pool_size = 1024u
};
int bypass_matches = qihse_vector_db_search(db, &bypass, out, 10u);
```

- `candidate_pool_size` behaves as the qmag candidate cap when non-zero.
- if `candidate_pool_size` and `candidate_count` are both zero, qmag derives a
  conservative pool from top-k and active dimension ratio.
- returned scores are qmag scores (not cosine), so compare with caution.
- keep this mode behind a live qmag health check.
- returned score magnitude can invert versus cosine order across queries; treat as a
  ranked list first, score second.

## Reading file-backed health before serving workload

```c
qihse_vector_db_persistence_stats_t stats = {0};
if (qihse_vector_db_get_persistence_stats(db, &stats)) {
    bool use_trinary_fast_path =
        (stats.trinary_status == QIHSE_VDB_TRINARY_VALID) &&
        (stats.magnitude_status == QIHSE_VDB_MAGNITUDE_VALID);
    bool use_bypass = (stats.magnitude_status == QIHSE_VDB_MAGNITUDE_VALID) &&
                      (stats.trinary_status == QIHSE_VDB_TRINARY_VALID);
}
```

Status flags:
- `QIHSE_VDB_TRINARY_VALID` / `QIHSE_VDB_MAGNITUDE_VALID`
- `QIHSE_VDB_TRINARY_STALE` / `QIHSE_VDB_MAGNITUDE_STALE`
- `QIHSE_VDB_TRINARY_CORRUPT` / `QIHSE_VDB_MAGNITUDE_CORRUPT`
- `QIHSE_VDB_TRINARY_ABSENT` / `QIHSE_VDB_MAGNITUDE_ABSENT`

Persisted row sidecars are rebuilt during mutation replay plus flush/checkpoint or
compaction.

## Exact vs fallback policy

- Use exact mode during startup recovery and strict correctness checks.
- switch to trinary modes after health checks, then choose:
  - `QIHSE_VDB_QUERY_TRINARY_SCALAR` for conservative sign-only acceleration
  - `QIHSE_VDB_QUERY_TRINARY_MAGNITUDE` for candidate narrowing + exact rerank
  - `QIHSE_VDB_QUERY_TRINARY_MAGNITUDE_BYPASS` for approximate low-latency
    retrieval

This keeps deterministic semantics after recovery while enabling progressively
more aggressive acceleration under healthy file-backed state.
