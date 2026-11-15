# Core feature experiments

The selectable core methods below are implemented; the later experiments are
research candidates. [ROADMAP.md](../../ROADMAP.md) remains the delivery-status
authority. Compare each change with typed exact search before adopting it. The
existing VectorDB routes are separate from scalar Hilbert lookup, and TurboQuant
remains an experimental numeric/sidecar implementation.

## Available method comparison

`qihse_batch_search_ex` now selects direct exact scan, phase-cosine RFF, or paired
sine/cosine RFF. Its options also select tiles of 1–64 queries; each tile shares
one streamed row projection. A batch builds one basis and retains O(tile*D)
scratch. Exact mode allocates no projection scratch. Existing calls keep the
phase-cosine map, with legacy batches using tiles of 16. There is no automatic
selection based on a benchmark winner.

Run the actual core implementation, with an independent typed equality oracle:

```sh
scripts/run-core-methods-bench.sh > core-methods.jsonl
scripts/run-core-methods-bench.sh --method phase --dimensions 128 --tile 1,16 --dataset present --repeats 9 --format csv > phase-tiles.csv
scripts/run-core-methods-bench.sh --method paired --dimensions 128 --tile 16 --dataset nearby_double --seed 0 > paired-nearby.jsonl
```

The default is a quick 45-case sweep: 512 records, 32 queries, 64/128 real
coordinates, tiles 1/16, five datasets, seed 42, gamma 1, one warmup and three
timed repeats. Datasets include present, absent, duplicate, adjacent
representable-double and large-integer queries. Non-exact method selections
still include exact scan. Every measured call validates original-type equality;
any mismatch makes the command fail. Equal duplicate indices are all valid.

JSONL or CSV records actual process CPU and wall batch times, setup/scoring/
verification times, candidate hits, fallback work, comparisons, projections,
basis builds and scratch bytes. Counts sum timed repeats; scratch is their peak.
Fixture construction, the independent oracle and result checking are outside
timing. Basis construction and metrics collection are inside each timed call.
Data and queries remain resident and are reused after warmup. The amortized
ns/query field does not measure individual-request latency, and three repeats
do not establish p99 behavior. Sanitizer builds are correctness checks only.

The projection-count benefit is testable without a timing claim: for finite
inputs, n=512 and Q=32, tile 16 needs 1,024 row projections per batch instead
of 16,384 at tile 1. The remaining nQD dot products still run. This benefit
does not imply that either RFF method beats direct scalar equality search.

The checked-in [2026-11-15 reference](../../benchmarks/results/core_methods/README.md)
contains the 45-case JSONL run and its exact source/header hash manifest. On that
unpinned, instrumented synthetic run, direct scan was fastest in every fixture;
tiling reduced RFF projections as predicted. Treat those timings as observations
for that build and workload, not promotion thresholds.

## Small experiments first

1. **Precompute and reuse the real feature map.** Keep data features immutable
   for a source generation and embed only queries. Compare direct feature dot
   products against any complex/phase representation at identical scoring
   semantics. Include source generation, preprocessing, gamma, seed/matrix and
   dimensions in profile identity. Report setup cost separately and calculate
   query-count break-even; reject a cache whose refresh cost outweighs savings.
   Tiled reuse is now implemented above; retaining features across calls remains
   a separate experiment. A persistent cache needs explicit source-generation
   invalidation and a measured break-even against both tiled and direct search.

2. **Evaluate the implemented paired map on real workloads.** For m frequencies use
   `z(x)=(cos(w1.x),sin(w1.x),...,cos(wm.x),sin(wm.x))/sqrt(m)`.
   Its dot product is `mean(cos(wj.(x-y)))`; its self-kernel is one, and common
   translation preserves the finite map up to rounding. This removes the
   random-phase cosine map's extra diagonal noise. Compare **2m real output
   coordinates against 2m real coordinates**, not unequal storage budgets.
   [Sutherland and Schneider](https://www.cs.cmu.edu/~dsutherl/papers/rff_uai15.pdf)
   analyze the lower Gaussian-kernel variance. The new opaque map API exposes a
   versioned descriptor for this reason; do not silently mix maps in persisted
   features and queries. Lower kernel-estimation error does not establish better
   exact-equality candidate recall for nearly indistinguishable scalar values.

   The portable synthetic probe requires NumPy:

   ```sh
   python3 benchmarks/scripts/qihse_rff_pairing_experiment.py
   python3 benchmarks/scripts/qihse_rff_pairing_experiment.py --features 256 --trials 4096 --output pairing.json
   ```

   It writes JSON to stdout and only writes a file when `--output` is supplied.
   Default seed 20261114, gamma 0.5, 128 real coordinates and 4096 trials gave
   RMSE 0.06197 versus 0.005379 at scalar separation 0.25; self-kernel RMSE was
   0.06171 versus 0. These are formula experiments, **not QIHSE execution,
   throughput or production recall measurements**. Recheck on actual queries.

3. **Grow feature blocks only when rankings are ambiguous.** Compare fixed
   dimensions with blocks of 32, 64, 128, ... and calibrate score-gap uncertainty
   against independent exact scores. Use independent validation seeds and a
   held-out corpus. [RFF error estimation](https://proceedings.mlr.press/v206/yao23a.html)
   supplies an adaptive-computation starting point. Record candidate recall,
   fallback rate and p99 latency; confidence-based pruning belongs to an
   approximate mode unless a valid bound establishes exactness.

4. **Center before phase evaluation.** The paired map's ideal score depends on
   x−y, but evaluating very large phases or resolving adjacent doubles can lose
   useful precision. Experiment with a shared, versioned center and scale before
   projection. For integers above 2^53, subtract in a checked original integer
   representation before conversion; converting both operands first can already
   discard the difference. Measure candidate hits and range-reduction cost on
   the large-integer and nearby-double fixtures, preserving exact fallback. The
   transform belongs in feature identity and must not silently change the target
   kernel or equality semantics.

## More unusual, bounded trials

- **Structured frequencies:** compare properly radially scaled
  [ORF/SORF](https://proceedings.neurips.cc/paper/2016/hash/53adaf494dc89ef7196d73636eb2451b-Abstract.html)
  and [Fastfood](https://proceedings.mlr.press/v28/le13.html) against dense RFF.
  A bare QR rotation changes the spectral distribution; structured Hadamard
  transforms are not the exact Haar reference used by TurboQuant. This is useful
  for genuine multidimensional input, not an assumed acceleration for d=1.

- **Quantization with residual bounds:** store an upper bound
  `epsilon >= ||x-xhat||`; then `|q.x-q.xhat| <= ||q||*epsilon` for an exact query.
  Use upper bounds to decide which candidates need authoritative scoring.
  This proposed Cauchy–Schwarz screening can preserve exact top-k if arithmetic
  bounds are conservative and every remaining candidate is covered. TurboQuant's
  residual norms are a useful prototype input. Bounds on random features alone
  do not remove their separate approximation error relative to the original
  vectors. Measure fewer vector reads and total latency, including worst case.

- **Learn where to spend dimensions:** compare a few labelled spectral groups
  ([A la Carte](https://proceedings.mlr.press/v38/yang15b.html)) or representative
  [Nyström landmarks](https://papers.nips.cc/paper_files/paper/2015/hash/03e0704b5690a2dee1861dc3ad3316c9-Abstract.html)
  at equal bytes and latency. Include training, updates and distribution drift.
  A mixture of purely radial Gaussian kernels remains monotone in Euclidean
  distance, so changing bandwidths alone does not improve exact Euclidean
  nearest-neighbour ordering. Meaningful field structure or task labels must
  justify a different similarity.

- **Actual tensor interactions:** test degree 2/3
  [TensorSketch](https://arxiv.org/abs/2505.08146) over meaningful feature groups,
  such as opcode category and operand shape, instead of position-dependent
  phase decoration. First compare with a small exact tensor-product oracle;
  then measure labelled retrieval improvement against concatenation and RFF
  at a fixed memory/latency budget. This changes similarity semantics explicitly.

## Common acceptance conditions

Freeze corpus, query set, feature profile, source SHA and seeds. Measure build
time, update/rebuild cost, p50/p95/p99 latency, total bytes/RSS, candidate recall
and final recall. Use a separate exact-score oracle. Include absent values,
duplicates, permutations, near ties, large/small finite inputs and zero vectors.
Report fallback work separately. Do not claim a simulated amplitude's magnitude
is a calibrated success probability.

The INT8 and binary selectors now exact-score their whole admitted candidate
pool and retain the requested top-k. Their selection geometry remains approximate:
raw min/max integer dot products and binary Hamming distance need not preserve
DOT/COSINE/L2 rankings. Exact reranking cannot recover omitted candidates.
Future metric-aware screening should precompute query-side scale/offset terms
and establish separate cosine/L2 contracts; it is not part of this narrow fix.
