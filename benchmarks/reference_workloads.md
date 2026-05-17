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
- `qtri` uses a wider default candidate pool than `qmag` because it only sees
  sign information.
- `qmag` uses row-side magnitude buckets plus signs, then reranks against the
  authoritative float32 vectors.

Calibration gate:

- Do not change default candidate-pool multipliers for synthetic-only cases.
- Add production-shaped reference workloads first, then compare recall,
  latency, and rerank cost across exact float32, scalar `qtri`, and `qmag`.
- Only adjust defaults when a reference workload shows a stable improvement
  across repeated runs.

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
    "metrics": ["recall_at_10", "latency_p95_us", "rerank_candidates"]
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
