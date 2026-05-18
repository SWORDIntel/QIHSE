# Vector DB lifecycle and mutation usage

This page is the practical baseline for opening and mutating QIHSE vector stores.

## 1) Build a runtime stack once

```c
#include "core/qihse_abi.h"
#include "memory/include/qihse_memory.h"
#include "qihse_vector_db.h"

qihse_context_t ctx = NULL;
qihse_memory_manager_t memory_manager = NULL;
qihse_uma_manager_t uma = NULL;
qihse_vector_db_t db = NULL;

if (qihse_context_create(NULL, &ctx) != QIHSE_OK) {
    /* handle error */
}

memory_manager = qihse_memory_manager_create(ctx, "uma");
if (!memory_manager) {
    /* handle error */
}

uma = qihse_uma_create(memory_manager, QIHSE_UMA_MIGRATE_ON_ACCESS);
if (!uma) {
    /* handle error */
}
```

## 2) Create, open, and size-check a file-backed vector DB

```c
// New file-backed index (creates directory and writes on first snapshot/checkpoint)
db = qihse_vector_db_create(QIHSE_VECTOR_DB_INMEMORY, uma, "/var/lib/qihse/my-index");

// Open existing file-backed DB in read-write mode
db = qihse_vector_db_open(
    QIHSE_VECTOR_DB_INMEMORY,
    uma,
    "/var/lib/qihse/my-index",
    QIHSE_VDB_OPEN_FILE_BACKED
);

// Open existing DB read-only + memory-mapped query mode
db = qihse_vector_db_open(
    QIHSE_VECTOR_DB_INMEMORY,
    uma,
    "/var/lib/qihse/my-index",
    QIHSE_VDB_OPEN_FILE_BACKED | QIHSE_VDB_OPEN_READ_ONLY | QIHSE_VDB_OPEN_MMAP
);

qihse_vector_db_persistence_stats_t stats = {0};
if (qihse_vector_db_get_persistence_stats(db, &stats)) {
    if (stats.trinary_status == QIHSE_VDB_TRINARY_VALID) {
        /* vectors.qtri is usable for candidate modes */
    }
    if (stats.magnitude_status == QIHSE_VDB_MAGNITUDE_VALID) {
        /* vectors.qmag is usable for magnitude modes */
    }
}
```

Important:
- file-backed means `db_path` is non-NULL and passed with
  `QIHSE_VDB_OPEN_FILE_BACKED`.
- `QIHSE_VDB_OPEN_MMAP` is only valid with `QIHSE_VDB_OPEN_READ_ONLY`.

## 3) Mutate rows with append-only semantics

All successful mutation APIs append to a log-backed store and keep previous WAL
records durable until checkpoint.

```c
float vectors[] = {
    0.12f, -0.17f, 0.93f, 0.21f,  // row 0
    0.34f, 0.02f, -0.77f, 0.11f,  // row 1
};
uint64_t ids[] = {101, 102};
const char* meta0 = "blue,shard=us-east-1";
const char* meta1 = "red,shard=eu-west-1";
const void* metadata[] = {meta0, meta1};
size_t metadata_sizes[] = {strlen(meta0), strlen(meta1)};

qihse_vector_db_add_vectors(
    db,
    vectors,
    2u,
    4u,
    ids,
    metadata,
    metadata_sizes
);
```

```c
uint64_t ids_to_delete[] = {101};
size_t deleted_count = 0u;

qihse_vector_db_delete_by_ids(db, ids_to_delete, 1u, &deleted_count);

float replacement[4] = {0.02f, 0.41f, -0.33f, 0.20f};
const char* replacement_meta = "red-updated";
qihse_vector_db_update_by_id(
    db,
    102,
    replacement,
    4u,
    replacement_meta,
    strlen(replacement_meta)
);

uint64_t upsert_ids[] = {102, 999};
float upsert_vectors[] = {
    0.30f, 0.40f, 0.50f, 0.60f, // id 102 exists -> update
    0.70f, 0.80f, 0.90f, 1.00f  // id 999 absent -> insert
};
qihse_vector_db_upsert_by_ids(db, upsert_ids, upsert_vectors, 2u, 4u, NULL, NULL, NULL, NULL);
```

## 4) Exact query path (default)

```c
float query_vector[4] = {0.11f, -0.04f, 0.99f, 0.00f};
qihse_vector_query_t query = {
    .query_vector = query_vector,
    .vector_dims = 4u,
    .top_k = 10u,
    .similarity_threshold = 0.0f,
    .include_vectors = true,
    .include_metadata = true,
    .query_mode = QIHSE_VDB_QUERY_FLOAT32
};

qihse_vector_result_t results[10];
int found = qihse_vector_db_search(db, &query, results, 10u);
```

`QIHSE_VDB_QUERY_FLOAT32` is authoritative and exact; trinary sidecars are
allowed to exist but are ignored unless you opt into trinary modes.

## 5) Shutdown, durability, and recovery hygiene

```c
qihse_vector_db_persistence_stats_t end_stats = {0};
if (qihse_vector_db_get_persistence_stats(db, &end_stats) && end_stats.needs_flush) {
    qihse_vector_db_flush(db); // writes dirty WAL snapshot candidate
}

qihse_vector_db_checkpoint(db);  // publish checkpoint and trim WAL windows
qihse_vector_db_close(db);       // flush (if needed) + destroy handle
```

If durability windows must be small, prefer periodic:
`qihse_vector_db_flush()` after mutation batches and less frequent
`qihse_vector_db_checkpoint()` during maintenance windows.

Cleanup:

```c
qihse_uma_destroy(uma);
qihse_memory_manager_destroy(memory_manager);
qihse_context_destroy(ctx);
```

