# QMAG Default Policy Guidance

This note captures the result-driven policy from the 100-case qmag sweep and
the dimension-mapped default heuristic.

## Sweep outcome

The qmag losses were not uniform. They clustered around four shapes:

- Small row counts, where qmag setup and shortlist pressure dominate any candidate-selection benefit.
- Dense or high-active-dimension queries, where most dimensions participate and magnitude sidecar scoring loses selectivity.
- High `top_k` requests, especially when `top_k` consumes a large share of live rows.
- High rerank pressure, where the default qmag pool approaches exact-search work while still risking shortlist loss.

## Default behavior

Default-pool qmag is a performance policy, not a correctness dependency. When a query shape matches the loss clusters above, the default qmag path should fall back to exact float32 search and return exact-equivalent IDs and ordering.

Default qmag first maps the non-zero query dimensions into the runtime
dimension-major qmag cache, then picks a candidate pool from active-dimension
pressure:

- `active_query_dims/vector_dims <= 1/16`: `top_k * 8`
- `active_query_dims/vector_dims <= 1/8`: `top_k * 10`
- Otherwise: `top_k * 12`

The pool is capped to live rows before the policy gate. The fast path is allowed
only when all default gates pass:

- `live_rows >= 512`
- `active_query_dims/vector_dims <= 1/4`
- `top_k/live_rows <= 3/128`
- `effective_candidate_pool/live_rows <= 9/32`

When allowed, qmag scores candidates through the dimension-mapped cache and
reranks the shortlist with exact float32 rows. When rejected, the query uses the
exact float32 path.

## Explicit qmag pools

Caller-provided qmag pools are explicit opt-ins. If the caller sets a non-zero `candidate_pool_size`, qmag should execute after normal sidecar and pool validation even when the default policy would have fallen back.

Use explicit pools only when the caller accepts qmag shortlist behavior. For correctness-first queries, leave `candidate_pool_size` at zero and rely on the conservative default policy.

## Regression coverage

The persistence regression suite covers these 100-case loss patterns:

- Small-row default qmag returns exact-equivalent results through fallback.
- Dense/high-active default qmag returns exact-equivalent results through fallback.
- Sparse low-pressure default qmag remains exact-equivalent.
- Explicit qmag pools still execute when the default policy would fall back.
- Low-active, low-`top_k` defaults exercise the qmag fast path.
- High-`top_k` defaults fall back to exact float32.
