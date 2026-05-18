# QMAG Default Policy Guidance

This note captures the result-driven policy from the 100-case qmag sweep.

## Sweep outcome

The qmag losses were not uniform. They clustered around four shapes:

- Small row counts, where qmag setup and shortlist pressure dominate any candidate-selection benefit.
- Dense or high-active-dimension queries, where most dimensions participate and magnitude sidecar scoring loses selectivity.
- High `top_k` requests, especially when `top_k` consumes a large share of live rows.
- High rerank pressure, where the default qmag pool approaches exact-search work while still risking shortlist loss.

## Default behavior

Default-pool qmag is a performance policy, not a correctness dependency. When a query shape matches the loss clusters above, the default qmag path should fall back to exact float32 search and return exact-equivalent IDs and ordering.

The default qmag path remains appropriate for sparse, low-pressure searches:

- Live-row counts are large enough for candidate selection to amortize.
- Active query dimensions are low relative to stored dimensions.
- `top_k` is small relative to live rows.
- The default candidate pool leaves enough room for exact rerank without dominating the query.

## Explicit qmag pools

Caller-provided qmag pools are explicit opt-ins. If the caller sets a non-zero `candidate_pool_size`, qmag should execute after normal sidecar and pool validation even when the default policy would have fallen back.

Use explicit pools only when the caller accepts qmag shortlist behavior. For correctness-first queries, leave `candidate_pool_size` at zero and rely on the conservative default policy.

## Regression coverage

The persistence regression suite covers these 100-case loss patterns:

- Small-row default qmag returns exact-equivalent results through fallback.
- Dense/high-active default qmag returns exact-equivalent results through fallback.
- Sparse low-pressure default qmag remains exact-equivalent.
- Explicit qmag pools still execute when the default policy would fall back.
