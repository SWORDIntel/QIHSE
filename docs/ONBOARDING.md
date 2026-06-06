# QIHSE Onboarding Guide

This guide gives the fastest path to use QIHSE with the most important runtime
flows: multi-modal DB lifecycle (Vector, KV, Columnar, Time-Series, Document, Event Stream, Graph, FTS), Unified Wire Protocol (UWP) networking, trinary-backed search behavior, persistence recovery, caller-driven maintenance loops, and validation workflows.

## 1) Runtime stack and file-backed vector DB lifecycle

Use this sequence for first-time setup:

```c
#include "core/qihse_abi.h"
#include "memory/include/qihse_memory.h"
#include "qihse_vector_db.h"

qihse_context_t ctx = NULL;
qihse_memory_manager_t memory_manager = NULL;
qihse_uma_manager_t uma = NULL;
qihse_vector_db_t db = NULL;

qihse_context_create(NULL, &ctx);
memory_manager = qihse_memory_manager_create(ctx, "uma");
uma = qihse_uma_create(memory_manager, QIHSE_UMA_MIGRATE_ON_ACCESS);

// Create or open:
db = qihse_vector_db_create(QIHSE_VECTOR_DB_INMEMORY, uma, "/var/lib/qihse/my-index");
// or reopen existing:
db = qihse_vector_db_open(QIHSE_VECTOR_DB_INMEMORY, uma, "/var/lib/qihse/my-index",
                          QIHSE_VDB_OPEN_FILE_BACKED);
```

Key flags:
- `QIHSE_VDB_OPEN_FILE_BACKED` → durability enabled
- `QIHSE_VDB_OPEN_READ_ONLY` → query-only open
- `QIHSE_VDB_OPEN_MMAP` → query-only memory-mapped mode (only with read-only)
- `QIHSE_VDB_OPEN_TRUNCATE` → reset existing store before open (destructive)

Mutations:

```c
uint64_t ids[] = {101, 102};
const float vecs[] = {
    1.0f, 0.0f, 0.0f,
    0.0f, 1.0f, 0.0f,
};
qihse_vector_db_add_vectors(db, vecs, 2, 3, ids, NULL, NULL);

qihse_vector_db_delete_by_id(db, 101);
qihse_vector_db_update_by_id(db, 102, vecs + 3, 3, NULL, 0);
uint64_t upsert_ids[] = {102, 999};
float upsert_vecs[] = {0.2f, 0.1f, 0.3f, 0.4f, 0.6f, 0.8f};
qihse_vector_db_upsert_by_ids(db, upsert_ids, upsert_vecs, 2, 3, NULL, NULL, NULL, NULL);
```

Durability hygiene:

```c
qihse_vector_db_persistence_stats_t s = {0};
qihse_vector_db_get_persistence_stats(db, &s);
if (s.needs_flush) qihse_vector_db_flush(db);
qihse_vector_db_checkpoint(db);
qihse_vector_db_close(db);  // closes and flushes if writable
```

Cleanup:

```c
qihse_uma_destroy(uma);
qihse_memory_manager_destroy(memory_manager);
qihse_context_destroy(ctx);
```

## 2) Unified Wire Protocol (UWP) Server

To run QIHSE over the network utilizing its zero-copy DMA and memory-aligned multiplexer, spin up the UWP server:

```c
#include "qihse_uwp.h"

qihse_uwp_server_t* server = qihse_uwp_server_create(db, 8080, "0.0.0.0");
qihse_uwp_server_start(server);
```

The UWP implementation uses detached pthreads and native socket timeouts to mitigate DoS (Slowloris) attacks, while bounding all metadata strings to strict array limits.

## 3) Trinary / qmag search usage

QIHSE keeps float32 authoritative. Trinary sidecars are for candidate filtering only.

```c
qihse_vector_query_t q = {
  .query_vector = query_vec,
  .vector_dims = dims,
  .top_k = 10,
  .similarity_threshold = 0.0f,
  .include_vectors = true,
  .include_metadata = true,
  .use_trinary_candidates = false,
  .candidate_count = 0,
  .query_mode = QIHSE_VDB_QUERY_FLOAT32
};
int n = qihse_vector_db_search(db, &q, out, 10);
```

- `QIHSE_VDB_QUERY_FLOAT32` is exact and tolerant if sidecars are missing/stale/corrupt.
- `QIHSE_VDB_QUERY_TRINARY_SCALAR` uses `vectors.qtri` candidates.
- `QIHSE_VDB_QUERY_TRINARY_MAGNITUDE` uses `vectors.qtri + vectors.qmag`.
- `QIHSE_VDB_QUERY_TRINARY_MAGNITUDE_BYPASS` skips float32 rerank and returns qmag
  ordering directly.

Legacy explicit scalar path:

```c
qihse_vector_query_t scalar = {
  .query_vector = query_vec, .vector_dims = dims, .top_k = 10,
  .similarity_threshold = 0.0f,
  .include_vectors = false, .include_metadata = false,
  .use_trinary_candidates = true,
  .candidate_count = 500, .query_mode = QIHSE_VDB_QUERY_FLOAT32,
  .candidate_pool_size = 0
};
```

Targeted qmag bypass:

```c
qihse_vector_query_t bypass = {
  .query_vector = query_vec, .vector_dims = dims, .top_k = 10,
  .similarity_threshold = 0.0f,
  .include_vectors = false, .include_metadata = false,
  .query_mode = QIHSE_VDB_QUERY_TRINARY_MAGNITUDE_BYPASS,
  .candidate_pool_size = 1024
};
```

- `candidate_count >= top_k` is required on this path.
- Explicit `candidate_pool_size` works on `QIHSE_VDB_QUERY_TRINARY_*`:
  - `candidate_pool_size = 0` enables default inference with safe policy fallback.

Check sidecar health before enabling fast paths:

```c
qihse_vector_db_get_persistence_stats(db, &s);
bool fast_ok = (s.trinary_status == QIHSE_VDB_TRINARY_VALID) &&
               (s.magnitude_status == QIHSE_VDB_MAGNITUDE_VALID);
```

## 3) Persistence recovery runbook

After startup, treat query mode as exact first:

```c
qihse_vector_db_open(QIHSE_VECTOR_DB_INMEMORY, uma, "/var/lib/qihse/my-index",
                     QIHSE_VDB_OPEN_FILE_BACKED | QIHSE_VDB_OPEN_READ_ONLY);

qihse_vector_db_persistence_stats_t rs = {0};
qihse_vector_db_get_persistence_stats(db, &rs);
```

Recovery behavior:
- exact mode still works when sidecars are missing/corrupt/stale.
- explicit trinary/qmag modes may fail with invalid sidecars.

If sidecars are invalid:

```c
if (rs.trinary_status != QIHSE_VDB_TRINARY_VALID ||
    rs.magnitude_status != QIHSE_VDB_MAGNITUDE_VALID) {
    qihse_vector_db_flush(db);
    qihse_vector_db_checkpoint(db);
    qihse_vector_db_compact(db);
}
```

## 4) Caller-owned memory maintenance loop

QIHSE does not spawn background maintenance threads; caller runs the maintenance pass.

```c
#include "memory/include/qihse_memory_migration_scheduler.h"

qihse_memory_migration_scheduler_t scheduler = {0};
qihse_memory_migration_scheduler_config_t config = {0};
qihse_memory_migration_task_t tasks[256];
qihse_memory_migration_scheduler_default_config(&config);
qihse_memory_migration_scheduler_init(&scheduler, tasks, 256, &config);

qihse_memory_maintenance_start(manager, &scheduler);
qihse_memory_maintenance_snapshot(manager, &scheduler, QIHSE_DEVICE_GPU, 64);
qihse_memory_maintenance_step(manager, &scheduler, 16);
```

Optional per-pass inspection:

```c
const qihse_memory_migration_task_t* top = qihse_memory_migration_scheduler_peek(&scheduler);
if (top) {
  qihse_memory_migration_decision_t d = {0};
  qihse_memory_migration_decision_inspect(top->buffer, top->target_device, top->target_type, &d);
}
```

## 5) Validation and benchmark onboarding

Quick checks:

```bash
make test-persist
make bench-reference-workloads
make bench-reference-runner-smoke
make validate-reference-workflow
```

Targeted workload runs:

```bash
make bench-reference-workload REFERENCE_WORKLOAD=sparse-active-256x16
make bench-reference-workload REFERENCE_WORKLOAD=sparse-active-768x32
make bench-vxug-pdf-workload
make bench-sift1m-workload
```

## 6) Useful docs

- [docs/usage/README.md] for modular how-to pages.
- [docs/persistence/README.md] for persistence mechanics.
- [docs/qmag-policy.md] for qmag candidate policy rationale.
- [docs/benchmarks/reference_workloads.md] for benchmark methodology.
