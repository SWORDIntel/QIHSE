# QIHSE — Quantum-Inspired Hilbert Space Expansion

[![License: AGPL v3](https://img.shields.io/badge/License-AGPL%20v3-black.svg)](LICENSE)
![Build: CI-Ready](https://img.shields.io/badge/Build-CI%20Ready-brightgreen.svg)

QIHSE is a C-first vector search runtime with exact float32 correctness by default and
optional trinary/qmag acceleration where that is safe.

## Build

```bash
git clone https://github.com/SWORDIntel/QIHSE.git
cd QIHSE
make all
```

## Code showcase: one-file integration pattern

```c
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>

#include "qihse_vector_db.h"

int main(void) {
    const char* db_path = "data/qihse_db";
    const size_t dims = 128;
    const size_t batch = 4;
    float vectors[] = {
        /* 2 * 128 values */
        0.0f, 1.0f,
        /* ... fill all dims * batch values */
    };
    float query[] = {
        /* 128 query floats */
        0.1f,
        /* ... */
    };
    uint64_t ids[] = {1001, 1002, 1003, 1004};
    qihse_vector_result_t results[10];

    qihse_vector_db_t db = qihse_vector_db_open(
        QIHSE_VECTOR_DB_AUTO,
        NULL,  // UMA can be wired in when you need cross-device placement.
        db_path,
        QIHSE_VDB_OPEN_CREATE | QIHSE_VDB_OPEN_FILE_BACKED
    );
    if (!db) {
        perror("qihse_vector_db_open");
        return 1;
    }

    if (!qihse_vector_db_add_vectors(db, vectors, batch, dims, ids, NULL, NULL)) {
        perror("qihse_vector_db_add_vectors");
        qihse_vector_db_close(db);
        return 1;
    }

    qihse_vector_query_t q = {
        .query_vector = query,
        .vector_dims = dims,
        .top_k = 3,
        .similarity_threshold = 0.0f,
        .include_vectors = true,
        .include_metadata = false,
        .use_trinary_candidates = false,
        .candidate_count = 0,
        .query_mode = QIHSE_VDB_QUERY_FLOAT32,
        .candidate_pool_size = 0
    };

    int got = qihse_vector_db_search(db, &q, results, 10);
    if (got < 0) {
        perror("qihse_vector_db_search");
        qihse_vector_db_close(db);
        return 1;
    }

    for (int i = 0; i < got; ++i) {
        printf("id=%llu score=%0.4f\n",
               (unsigned long long)results[i].id,
               results[i].score);
    }

    if (!qihse_vector_db_flush(db)) {
        perror("qihse_vector_db_flush");
    }
    if (!qihse_vector_db_checkpoint(db)) {
        perror("qihse_vector_db_checkpoint");
    }
    if (!qihse_vector_db_compact(db)) {
        perror("qihse_vector_db_compact");
    }

    qihse_vector_db_close(db);
    return 0;
}
```

## Code showcase: trinary and magnitude modes

```c
qihse_vector_query_t fast = {
    .query_vector = query,
    .vector_dims = 128,
    .top_k = 20,
    .query_mode = QIHSE_VDB_QUERY_TRINARY_MAGNITUDE,
    .candidate_pool_size = 640,
    .candidate_count = 640,
    .similarity_threshold = 0.25f,
    .include_vectors = false,
    .include_metadata = false,
    .use_trinary_candidates = false
};

int fast_found = qihse_vector_db_search(db, &fast, results, 20);
```

```c
qihse_vector_query_t scalar_only = {
    .query_vector = query,
    .vector_dims = 128,
    .top_k = 16,
    .query_mode = QIHSE_VDB_QUERY_TRINARY_SCALAR,
    .include_vectors = false,
    .include_metadata = false,
    .use_trinary_candidates = false
};

int scalar_candidates = qihse_vector_db_search_trinary_candidates(
    db,
    &scalar_only,
    400,    // must be >= top_k
    results,
    16
);
```

Use these modes deliberately. Missing/stale/corrupt trinary artifacts fail explicitly rather than silently masking results.

## Code showcase: batch mutation API patterns

```c
uint64_t del_ids[] = {1001, 1003};
size_t deleted = 0;
if (!qihse_vector_db_delete_by_ids(db, del_ids, 2, &deleted)) {
    perror("delete_by_ids");
}
printf("deleted=%zu\n", deleted);

float updated[] = {
    /* updated vector 1 */
    0.5f, 0.6f,
    /* ... */
};
uint64_t upd_ids[] = {1002};
if (!qihse_vector_db_update_by_id(db, 1002, updated, 128, NULL, 0)) {
    perror("update_by_id");
}

uint64_t up_ids[] = {2001, 2002, 1004};
float up_vectors[] = {
    /* three x 128 vectors */
};
qihse_vector_result_t* metas = NULL;
size_t meta_sizes[] = {0, 0, 0};
size_t inserted = 0, updated_count = 0;
if (!qihse_vector_db_upsert_by_ids(
        db,
        up_ids,
        up_vectors,
        3,
        128,
        NULL,
        meta_sizes,
        &inserted,
        &updated_count)) {
    perror("upsert_by_ids");
}
printf("upsert inserted=%zu updated=%zu\n", inserted, updated_count);
```

## Code showcase: read runtime persistence state

```c
qihse_vector_db_persistence_stats_t st = {0};
if (qihse_vector_db_get_persistence_stats(db, &st)) {
    printf("storage_mode=%d\n", (int)st.storage_mode);
    printf("encoding=0x%x\n", (unsigned)st.encoding_id);
    printf("committed=%llu rows=%llu live=%llu\n",
           (unsigned long long)st.committed_generation,
           (unsigned long long)st.total_vectors,
           (unsigned long long)st.live_vectors);
    printf("trinary=%d qmag=%d\n",
           (int)st.trinary_status,
           (int)st.magnitude_status);
    printf("wal_records_replayed=%llu wal_pending=%llu\n",
           (unsigned long long)st.wal_records_replayed,
           (unsigned long long)st.wal_bytes_pending);
}
```

## Code showcase: controlled warm-up preloading

```c
if (!qihse_vector_db_preload_similar(
        db,
        query,
        128,
        0.85f)) {
    perror("preload_similar");
}
```

## Validation commands (copy/paste)

```bash
make test-persist
make test-trinary-codec
make bench-trinary-search-path
make bench-trinary-search-sweep
make bench-reference-workloads
make benchmark
```

## Key API surface

- `qihse_vector_db_open`
- `qihse_vector_db_add_vectors`
- `qihse_vector_db_update_by_id`
- `qihse_vector_db_update_by_ids`
- `qihse_vector_db_delete_by_id`
- `qihse_vector_db_delete_by_ids`
- `qihse_vector_db_upsert_by_ids`
- `qihse_vector_db_search`
- `qihse_vector_db_search_trinary_candidates`
- `qihse_vector_db_preload_similar`
- `qihse_vector_db_flush`
- `qihse_vector_db_checkpoint`
- `qihse_vector_db_compact`
- `qihse_vector_db_get_persistence_stats`
- `qihse_vector_db_close`
- `qihse_vector_db_destroy`

## Documentation pointers

- [docs/ONBOARDING.md](docs/ONBOARDING.md)
- [docs/persistence/README.md](docs/persistence/README.md)
- [docs/qmag-policy.md](docs/qmag-policy.md)
- [docs/usage/](docs/usage/)
- [docs/deployment/](docs/deployment/)
- [docs/security/](docs/security/)

## License

This project is AGPL-3.0-or-later. See [LICENSE](LICENSE).
