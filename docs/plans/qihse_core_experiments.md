# Core feature experiments

These are research candidates, not promotion claims. [ROADMAP.md](../../ROADMAP.md)
remains the delivery-status authority. Establish a correct typed exact-search
baseline before evaluating feature transforms. The existing VectorDB routes are
separate from the original scalar Hilbert search, and TurboQuant remains an
experimental numeric/sidecar implementation.

## Small experiments first

1. **Precompute and reuse the real feature map.** Keep data features immutable
   for a source generation and embed only queries. Compare direct feature dot
   products against any complex/phase representation at identical scoring
   semantics. Include source generation, preprocessing, gamma, seed/matrix and
   dimensions in profile identity. Report setup cost separately and calculate
   query-count break-even; reject a cache whose refresh cost outweighs savings.
   A smaller first step is a tiled batch: reuse one kernel and each streamed
   row projection across, for example, 16 query feature vectors. Compare it with
   the current repeated scalar calls and a direct typed batch baseline; measure
   p50/p99, scratch bytes and batch-size break-even. This can avoid a persistent
   n-by-D cache, but has no measured engine speedup yet and needs no new public
   API until the experiment establishes a useful contract.

2. **Pair sine and cosine.** For m frequencies use
   `z(x)=(cos(w1.x),sin(w1.x),...,cos(wm.x),sin(wm.x))/sqrt(m)`.
   Its dot product is `mean(cos(wj.(x-y)))`; its self-kernel is one, and common
   translation preserves the finite map up to rounding. This removes the
   random-phase cosine map's extra diagonal noise. Compare **2m real output
   coordinates against 2m real coordinates**, not unequal storage budgets.
   [Sutherland and Schneider](https://www.cs.cmu.edu/~dsutherl/papers/rff_uai15.pdf)
   analyze the lower Gaussian-kernel variance. A different map needs an explicit
   versioned profile; do not silently change persisted features or their queries.

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
