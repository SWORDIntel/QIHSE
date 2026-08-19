# QIHSE Distributed Scatter-Gather SQL/QQL Multi-Engine Planner

## 1. Executive Summary

QIHSE incorporates a native **Distributed Scatter-Gather Query Planner** (`include/qihse_dist_planner.h`) designed to orchestrate complex composite SQL and QQL statements across sharded cluster nodes and multi-model storage backends.

The planner integrates **CRC16 Hash Slot Partitioning**, **SIMD Vector Distance Search**, **Gorilla Block-Compressed Time-Series Aggregation**, **Columnar Analytical Scans**, and **Reciprocal Rank Fusion (RRF)** into a unified execution pipeline.

---

## 2. Architecture & Query Lifecycle

```
       Incoming SQL / QQL Query (e.g., SELECT * FROM {device_4096} WHERE vector_search(...) AND AVG(temp) > 75)
                                          │
                                          ▼
                      ┌───────────────────────────────────────┐
                      │    QIHSE Distributed Query Planner    │
                      │  - AST Decomposition                  │
                      │  - Entity / Hash Tag Extraction       │
                      │  - Engine Target Classification       │
                      └───────────────────┬───────────────────┘
                                          │
                  ┌───────────────────────┴───────────────────────┐
                  ▼                                               ▼
     ┌────────────────────────┐                      ┌────────────────────────┐
     │   Single-Shard Scoped  │                      │   Multi-Shard Scatter  │
     │      (Hash Tag {...})  │                      │        (Unscoped)      │
     │  - CRC16 slot lookup   │                      │  - Dispatched to all   │
     │  - Direct O(1) route   │                      │    cluster nodes       │
     └────────────┬───────────┘                      └────────────┬───────────┘
                  │                                               │
                  └───────────────────────┬───────────────────────┘
                                          │
                                          ▼
                         ┌─────────────────────────────────┐
                         │   Multi-Engine Task Execution   │
                         │   - SIMD Vector DB (Exact F32)  │
                         │   - Gorilla TSDB (Time Range)   │
                         │   - Columnar Store (Sum / Min)  │
                         │   - Black Hole KV Store (Get)   │
                         └────────────────┬────────────────┘
                                          │
                                          ▼
                         ┌─────────────────────────────────┐
                         │    Result Fusion & Reduction    │
                         │  - Reciprocal Rank Fusion (RRF) │
                         │  - Top-K Candidate Merge        │
                         │  - Scalar Aggregate Reduction   │
                         └────────────────┬────────────────┘
                                          │
                                          ▼
                                Formatted Output Rows
```

---

## 3. Query Partitioning Strategies

### 3.1 Scoped Point & Range Execution ($O(1)$)
When a query targets an entity tagged with braces (e.g., `SELECT * FROM {device_4096} WHERE ...` or `MATCH (n:{sensor:77}) ...`), the planner extracts the tag and hashes it via `qihse_cluster_key_slot()`:

$$\text{Slot} = \text{CRC16}(\text{tag}) \pmod{16384}$$

The planner routes the single sub-task directly to the node owning that slot, avoiding global cluster fan-out.

### 3.2 Global Multi-Shard Scatter-Gather
When a query contains no partition tags or requires global analytics (e.g., `MATCH (n:Sensor) WHERE ts_range(telemetry, 0, 1000000) AND AVG(cpu_temp) > 80.0 RETURN n`), the planner builds a parallel scatter-gather execution plan with sub-tasks distributed across all active cluster nodes.

---

## 4. Multi-Engine Sub-Task Dispatch

| Task Type (`qihse_dist_task_type_t`) | Storage Engine Target | Execution Function |
|---|---|---|
| `QIHSE_TASK_VECTOR_SEARCH` | Broad Oak Vector DB | `qihse_vector_db_search()` |
| `QIHSE_TASK_TS_RANGE` | Marmalade Gorilla TSDB | `qihse_tsdb_average_range_user()` |
| `QIHSE_TASK_COL_SCAN` | Frieze Columnar Store | `qihse_column_sum_float32_user()` |
| `QIHSE_TASK_KV_POINT` | Black Hole KV Store | `qihse_kv_get_user()` |
| `QIHSE_TASK_DOC_FILTER` | Frieze Document Store | `qihse_doc_store_get()` |

---

## 5. Result Fusion & Reduction

* **Reciprocal Rank Fusion (RRF)**: For multi-shard vector searches, candidate matches from different shard nodes are normalized and ranked using:
  $$\text{RRF\_Score}(d) = \sum_{m \in M} \frac{1}{k + r_m(d)}$$
  where $k=60$ and $r_m(d)$ is the rank position of document $d$ in model result $m$.
* **Scalar Reduction**: Aggregate metrics across shards (`AVG`, `SUM`, `MIN`, `MAX`) are accumulated and reduced across all completed shard tasks.
* **Nanosecond Profiling**: Each result structure captures exact hardware timing (`res->execution_time_ns`) using monotonic timestamp registers.

---

## 6. API Reference

```c
// Initialize planner with cluster topology
qihse_dist_planner_t* planner = qihse_dist_planner_create(topo);

// Deconstruct and plan composite SQL/QQL statement
qihse_dist_plan_t* plan = qihse_dist_plan_query(planner, query_str, user);

// Execute plan across local engines and gather results
qihse_dist_query_result_t* res = qihse_dist_execute_plan(
    planner, plan, kv_store, vector_db, tsdb, column_store, doc_store, user
);

// Process results and free resources
qihse_dist_query_result_free(res);
qihse_dist_plan_free(plan);
qihse_dist_planner_destroy(planner);
```
