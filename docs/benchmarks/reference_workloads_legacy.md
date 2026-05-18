# QIHSE Reference Workloads: Commercial Validation Suite

## Benchmark Design for Enterprise-Grade Validation

**Purpose:** Establish credible performance claims through standardized, reproducible benchmarks that reflect real-world usage patterns.

---

## Workload Categories

### 1. Vector Search (ANN/Top-K) - 40% of Use Cases

#### Trinary Candidate Calibration

The persisted trinary path is an opt-in candidate generator followed by exact
float32 reranking.

Current calibration rule:

- Exact float32 remains the default unless a query opts into trinary mode.
- Legacy `use_trinary_candidates` keeps using `candidate_count` exactly as
  supplied.
- `qtri` defaults to a full-row exact rerank after sidecar validation because
  sign-only matching can collapse dense non-negative vectors into large
  equal-score buckets. With no explicit candidate pool, the effective pool and
  reranked row count are the full row count.
- `qmag` uses row-side magnitude buckets plus signs, then reranks against the
  authoritative float32 vectors. The intended acceleration layout keeps an
  in-memory, dimension-major QIHSE qmag cache decoded from the row-side qmag
  data so each query dimension can scan contiguous magnitude/sign bytes across
  rows. Mutations invalidate this derived cache; delete, update, upsert, and
  compact must rebuild or refresh it before any opt-in qmag candidate search can
  use it. With no explicit candidate pool, `qmag` is the default fast trinary
  candidate path and reports the inferred effective pool separately from the
  requested query pool. The persisted format remains the authoritative row-side
  vector snapshot and qmag data; no persisted dimension-major transposed qmag
  sidecar is assumed or required. The benchmark runner labels this as
  QIHSE dimension-mapped trinary+magnitude candidate scoring followed by exact
  float32 rerank; the label is script-inferred from query mode, not a C ABI
  field.

Calibration gate:

- Do not change default candidate-pool policy for synthetic-only cases.
- Add production-shaped reference workloads first, then compare recall,
  latency, and rerank cost across exact float32, scalar `qtri`, and `qmag`.
- Only adjust defaults when a reference workload shows a stable improvement
  across repeated runs.

Sweep policy analysis:

- Analyze the 100-case sweep with actual qmag effective pools using:
  `python3 benchmarks/scripts/qihse_qmag_policy_analyzer.py results/sweep100/summary.json --results-dir results/sweep100 --top 20`
- The analyzer prints ranked candidate policies plus a concise C-threshold
  block. The C block rationalizes the best active-dimension and pool-pressure
  findings to integer-friendly thresholds such as `1/4`, `1/32`, and `19/64`,
  then reports expected selected cases, false positives, false negatives,
  precision, recall, and mean selected qmag speedup if those thresholds are
  used as the default qmag auto-policy.

Tracked workload manifest:

- `benchmarks/reference_workloads.json` is the current source of truth for
  calibration workloads.
- `make bench-reference-workloads` validates the manifest and prints the
  benchmark plan.
- External workloads are intentionally file-backed but not bundled. Use
  `python3 benchmarks/scripts/qihse_reference_workloads.py --root . --check-files`
  to verify local dataset availability before using them as tuning evidence.
- Add `--inspect-files` to validate external vector dimensions and row counts
  against the manifest before accepting a dataset as calibration evidence.
- `make sample-vxug-pdf-workload` builds the `vxug-pdf-sample` workload from
  the local FRAMEWERX VXUG PDF path and validates only that workload.
- `make validate-reference-workflow` runs the manifest plan, the generated
  `fvecs`/`ivecs` smoke workload, the VXUG benchmark gate, and persistence
  tests sequentially.
- `sift1m-fallback` rejects non-zero mismatches so scalar sign-collapse
  regressions fail immediately.
- `sparse-active-256x16` and `sparse-active-768x32` cover deterministic
  sparse-query trinary/qmag workloads with 2048 rows, 128 queries, `top_k=10`,
  and exact active query dimension counts of 16 and 32 respectively.

Execution plan:

1. `make bench-vxug-pdf-workload` loads
   `data/vxug_pdf_sample/base.f32`, `query.f32`, and `ground_truth.u32` into
   a file-backed QIHSE vector database.
2. Run the same queries through exact float32, scalar `qtri`, and `qmag`.
   Record recall@10, latency, requested candidate pool, effective candidate
   pool, reranked rows, active query dimensions, candidate policy/path label,
   and mismatches.
3. Store benchmark outputs under `results/` as generated artifacts outside git
   by default. Only promote summarized results into docs after the runner is
   repeatable. `qihse_reference_result_summary.py` reads those generated JSON
   files and applies the manifest recall floor for each mode.
4. Add one larger SIFT-style workload with `fvecs` base/query vectors and
   `ivecs` ground truth. Use it as the first dataset large enough to justify
   any candidate-pool default change.
5. Treat QIHSE GitHub as the upstream working repository. FRAMEWERX should
   import or mirror QIHSE after upstream changes land, not become the long-term
   source of truth for QIHSE benchmark policy.

Latest local VXUG sample result:

- `float32`: recall@10 `1.0000`
- `qtri`: recall@10 `0.9812`
- `qmag`: recall@10 `1.0000`

The first result supports the existing policy: `qmag` is the preferred fast
trinary path for magnitude-sensitive text-derived vectors, while scalar `qtri`
keeps correctness by defaulting to a full-row rerank unless a caller provides an
explicit candidate pool.

#### Sparse-Active Trinary/QMAG Fixtures

The sparse-active fixtures make the temporary sparse sweeps reproducible without
ad hoc scripts. They generate deterministic `f32_matrix` base/query files and
`u32_matrix` ground truth under `data/sparse_active/`.

Representative manifest workloads:

- `sparse-active-256x16`: 256 dimensions, 16 active query dimensions, 2048
  rows, 128 queries, `top_k=10`.
- `sparse-active-768x32`: 768 dimensions, 32 active query dimensions, 2048
  rows, 128 queries, `top_k=10`.

Generate and validate the fixtures:

```bash
python3 benchmarks/scripts/qihse_generate_sparse_active_fixture.py --force
python3 benchmarks/scripts/qihse_reference_workloads.py --root . \
  --workload sparse-active-256x16 \
  --workload sparse-active-768x32 \
  --inspect-files --plan
```

Run the benchmark modes through the existing manifest-backed runner:

```bash
make bench-reference-workload REFERENCE_WORKLOAD=sparse-active-256x16
make bench-reference-workload REFERENCE_WORKLOAD=sparse-active-768x32
```

Each run compares exact float32, scalar `qtri`, and `qmag`, reports active query
dimensions, candidate policy/path labels, reranked rows, recall@10, latency, and
mismatch counts, and writes generated JSON under `results/<workload>/latest.json`.

#### SIFT1M Benchmark (Computer Vision)
```python
# Dataset: 1M SIFT descriptors (128 dimensions)
# Queries: 10K random vectors
# Ground truth: Exact k-NN for recall calculation

workload_sift1m = {
    "name": "SIFT1M",
    "dataset_size": 1_000_000,
    "dimensions": 128,
    "queries": 10_000,
    "k_values": [1, 10, 100],
    "metrics": ["recall@1", "recall@10", "recall@100", "qps", "latency_p99"]
}
```

The manifest already declares the SIFT-style file paths and formats. Once the
files are present under `data/sift1m/`, run `make bench-sift1m-workload` to use
the same exact float32/scalar `qtri`/`qmag` runner and write generated JSON
under `results/sift1m/`.

If full 1M data is unavailable, `make bench-sift1m-workload` now falls back to
`sift1m-fallback`, reading deterministic vectors and ground truth from
`data/sift1m/fallback/*`. The fallback gate keeps the same recall floor as the
full SIFT workload and rejects non-zero mismatches.

To refresh the staged fallback fixture:

```bash
python3 benchmarks/scripts/qihse_generate_sift1m_fixture.py --force
```

`make bench-reference-runner-smoke` covers the generic `fvecs`/`ivecs` parser
path with a tiny generated workload when full SIFT data is not present.

#### GIST1M Benchmark (Semantic Search)
```python
# Dataset: 1M GIST descriptors (960 dimensions)
# Queries: 1K semantic search queries
# Use case: Content-based image retrieval

workload_gist1m = {
    "name": "GIST1M",
    "dataset_size": 1_000_000,
    "dimensions": 960,
    "queries": 1_000,
    "metric": "cosine",
    "expected_recall": 0.95  # At reasonable latency
}
```

#### Text Embedding Benchmarks
```python
# Dataset: MS MARCO passage embeddings (768 dimensions)
# Use case: Document retrieval, QA systems

workload_text_embeddings = {
    "name": "MSMARCO-Passage",
    "dataset_size": 8_800_000,
    "dimensions": 768,
    "queries": 6_980,
    "evaluation": "MRR@10",  # Mean Reciprocal Rank
}
```

#### VXUG PDF Text Sample
```python
# Dataset: local FRAMEWERX VXUG PDF text extraction
# Default source: ../exploits/vxunderground/VXUG-Papers/Hells Gate/HellsGate.pdf
# Generated files: data/vxug_pdf_sample/{base.f32,query.f32,ground_truth.u32}

workload_vxug_pdf_sample = {
    "name": "vxug-pdf-sample",
    "dataset_size": 256,
    "dimensions": 256,
    "queries": 16,
    "top_k": 10,
  "metrics": [
    "recall_at_10",
    "latency_p95_us",
    "active_query_dims",
    "requested_candidate_pool",
    "effective_candidate_pool",
    "candidate_policy",
    "candidate_path_label",
    "reranked_rows"
  ]
}
```

### 2. Graph Search - 30% of Use Cases

#### Social Network Analysis
```python
# Dataset: LiveJournal social graph
# Operations: Shortest path, connected components, centrality

workload_social_graph = {
    "name": "LiveJournal",
    "nodes": 4_800_000,
    "edges": 69_000_000,
    "operations": ["bfs", "pagerank", "connected_components"],
    "metrics": ["time_to_solution", "memory_usage", "scalability"]
}
```

#### Knowledge Graph Traversal
```python
# Dataset: Freebase knowledge graph subset
# Use case: Entity linking, relation extraction

workload_knowledge_graph = {
    "name": "Freebase-10M",
    "triples": 10_000_000,
    "entities": 2_000_000,
    "queries": ["1-hop", "2-hop", "3-hop", "entity_linking"],
    "metrics": ["precision", "recall", "query_time"]
}
```

#### Recommendation Graph
```python
# Dataset: MovieLens 25M ratings as bipartite graph
# Use case: Collaborative filtering, recommendations

workload_recommendation = {
    "name": "MovieLens-25M",
    "users": 162_000,
    "items": 62_000,
    "interactions": 25_000_000,
    "evaluation": "NDCG@10",  # Normalized Discounted Cumulative Gain
}
```

### 3. Constraint Search - 20% of Use Cases

#### Combinatorial Optimization
```python
# Problem: Traveling Salesman Problem variants
# Dataset: TSPLIB instances (up to 10K cities)

workload_tsp = {
    "name": "TSPLIB-Varied",
    "problem_sizes": [100, 500, 1000, 5000, 10000],
    "constraints": ["triangle_inequality", "euclidean_distance"],
    "objectives": ["min_distance", "min_time"],
    "baselines": ["LKH_solver", "Concorde"]
}
```

#### Scheduling Optimization
```python
# Problem: Job shop scheduling
# Dataset: Taillard benchmark instances

workload_job_shop = {
    "name": "Taillard-JobShop",
    "jobs": [10, 15, 20],
    "machines": [5, 10, 15],
    "time_horizon": 1000,
    "constraints": ["precedence", "resource_limits"],
    "metrics": ["makespan", "solution_quality", "time_to_best"]
}
```

#### Resource Allocation
```python
# Problem: Knapsack variants with complex constraints
# Use case: Portfolio optimization, resource planning

workload_knapsack = {
    "name": "MultiDimensional-Knapsack",
    "items": [100, 500, 1000, 5000],
    "dimensions": [2, 5, 10],
    "constraints": ["capacity_limits", "dependency_constraints"],
    "objectives": ["max_value", "min_cost"]
}
```

### 4. Hybrid Workloads - 10% of Use Cases

#### Multi-Modal Retrieval
```python
# Dataset: MS COCO (images + text)
# Use case: Cross-modal retrieval

workload_multimodal = {
    "name": "MSCOCO-CrossModal",
    "images": 123_000,
    "captions": 600_000,
    "image_features": 2048,
    "text_features": 768,
    "tasks": ["image_to_text", "text_to_image"],
    "metrics": ["recall@1", "recall@5", "recall@10"]
}
```

#### Structured Search
```python
# Dataset: Product catalog with structured metadata
# Use case: E-commerce search with filters

workload_structured = {
    "name": "ProductCatalog-Structured",
    "products": 10_000_000,
    "attributes": ["price", "category", "brand", "rating", "availability"],
    "queries": ["faceted_search", "range_queries", "boolean_filters"],
    "metrics": ["precision", "recall", "query_time"]
}
```

---

## Benchmark Execution Framework

### Standardized Test Harness

```c
// qihse/benchmarks/benchmark_runner.h

typedef struct {
    const char* workload_name;
    qihse_workload_type_t type;
    qihse_dataset_t dataset;
    qihse_query_set_t queries;
    qihse_ground_truth_t ground_truth;
    qihse_metrics_config_t metrics;
    qihse_baseline_config_t baselines;
} qihse_benchmark_config_t;

// Automated benchmark execution
qihse_error_t qihse_run_benchmark(
    const qihse_benchmark_config_t* config,
    qihse_benchmark_results_t* results
);
```

### Performance Profiling

```c
// Comprehensive performance capture
typedef struct {
    // Throughput metrics
    double qps;                    // Queries per second
    double latency_p50;           // Median latency (μs)
    double latency_p95;           // 95th percentile latency
    double latency_p99;           // 99th percentile latency

    // Accuracy metrics
    double recall_at_1;           // Recall@1
    double recall_at_10;          // Recall@10
    double ndcg_at_10;            // NDCG@10

    // Resource metrics
    size_t peak_memory_mb;        // Peak memory usage
    double avg_cpu_percent;       // Average CPU utilization
    double avg_power_watts;       // Average power consumption

    // Correctness metrics
    double correctness_score;     // 0.0-1.0 (verification success rate)
    uint64_t verification_failures; // Number of failed verifications
} qihse_performance_metrics_t;
```

---

## Validation Methodology

### 1. Correctness Validation

#### Deterministic Verification
```c
// Verify against known ground truth
qihse_error_t qihse_validate_correctness(
    const qihse_benchmark_results_t* results,
    const qihse_ground_truth_t* ground_truth,
    double* correctness_score
);
```

#### Probabilistic Verification
```c
// Statistical correctness for approximate methods
qihse_error_t qihse_validate_probabilistic(
    const qihse_benchmark_results_t* results,
    double confidence_level,  // e.g., 0.99 for 99% confidence
    double* correctness_score
);
```

### 2. Performance Regression Detection

#### Statistical Process Control
```c
// Detect performance regressions
typedef struct {
    double baseline_mean;
    double baseline_stddev;
    double control_limit_sigma;  // e.g., 3.0 for 99.7% confidence
    uint32_t min_samples;       // Minimum samples for stable baseline
} qihse_regression_detector_t;

qihse_regression_status_t qihse_detect_regression(
    const qihse_performance_metrics_t* current,
    const qihse_regression_detector_t* detector
);
```

### 3. Comparative Analysis

#### Baseline Comparisons
```c
// Compare against reference implementations
qihse_error_t qihse_compare_baselines(
    const qihse_benchmark_results_t* qihse_results,
    const qihse_baseline_results_t* baseline_results,
    qihse_comparison_report_t* report
);
```

---

## Commercial Validation Criteria

### Performance Thresholds

| Workload Type | Minimum QPS | Maximum P99 Latency | Minimum Accuracy |
|---------------|-------------|---------------------|------------------|
| Vector Search (ANN) | 10,000 | 10ms | 95% recall@10 |
| Graph Search | 1,000 | 100ms | 100% correctness |
| Constraint Search | 100 | 1s | Optimal solution |
| Hybrid Search | 5,000 | 50ms | 90% recall@10 |

### Resource Efficiency Targets

- **Memory Usage:** < 2x dataset size in memory
- **CPU Utilization:** < 80% average during steady state
- **Power Consumption:** < 200W for workstation deployment
- **Storage Overhead:** < 50% for indices/metadata

### Correctness Guarantees

- **Exact Methods:** 100% correctness on all test cases
- **Approximate Methods:** >99% correctness with confidence bounds
- **Verification:** All results verifiable within 10% of query time

---

## Benchmark Maintenance

### Dataset Versioning
```json
{
  "dataset": {
    "name": "SIFT1M",
    "version": "1.0.0",
    "sha256": "abc123...",
    "download_url": "https://...",
    "validation_hash": "def456..."
  }
}
```

### Continuous Validation
- **Weekly Regression Tests:** All benchmarks run automatically
- **Performance Trending:** Historical performance tracking
- **Platform Coverage:** Linux, macOS, Windows validation
- **Hardware Diversity:** Testing on different CPU/GPU configurations

### Community Benchmarks
- **Open Dataset Initiative:** Publish benchmark datasets for third-party validation
- **Standardized Metrics:** Align with ANN-Benchmarks, BIGANN communities
- **Reproducibility:** Containerized benchmark execution

---

## Implementation Roadmap

### Phase 1: Core Benchmarks (Month 1)
- [ ] Implement SIFT1M and GIST1M vector benchmarks
- [ ] Basic graph search benchmarks
- [ ] Correctness validation framework

### Phase 2: Enterprise Features (Month 2)
- [ ] Constraint optimization benchmarks
- [ ] Hybrid workload benchmarks
- [ ] Performance regression detection

### Phase 3: Production Validation (Month 3)
- [ ] Full benchmark suite automation
- [ ] Comparative analysis tools
- [ ] Commercial validation reports

---

## Risk Assessment

### Technical Risks
- **Dataset Bias:** Benchmarks may not reflect real customer workloads
- **Hardware Variance:** Performance varies significantly across hardware
- **Measurement Noise:** Micro-benchmarking can be unreliable

### Mitigation Strategies
- **Diverse Datasets:** Include both synthetic and real-world data
- **Statistical Rigor:** Use proper statistical methods for significance testing
- **Hardware Normalization:** Report performance relative to baseline hardware

### Business Risks
- **Competitive Claims:** Rivals may dispute benchmark relevance
- **Implementation Differences:** "Apples-to-apples" comparison challenges

### Mitigation Strategies
- **Transparent Methodology:** Publish complete benchmark implementations
- **Third-Party Validation:** Independent audit of benchmark correctness
- **Standard Alignment:** Follow industry-standard benchmarking practices

---

## Success Metrics

### Technical Success
- ✅ **Benchmark Coverage:** 95% of target workloads implemented
- ✅ **Reproducibility:** <5% variance across identical hardware
- ✅ **Correctness:** 100% verification success rate

### Business Success
- ✅ **Competitive Positioning:** 2-5x performance advantage demonstrated
- ✅ **Customer Validation:** Benchmarks correlate with real customer performance
- ✅ **Industry Recognition:** Benchmarks accepted by relevant communities

---

This benchmark suite provides the empirical foundation for QIHSE's performance claims and ensures commercial credibility through rigorous, reproducible validation.

---

**Document Version:** 1.0
**Last Updated:** December 27, 2025
**Next Review:** January 2026 (post-implementation)
