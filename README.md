# QIHSE — Vector Search Engine for Fast, Correct, Persistent ANN

[![License: AGPL v3](https://img.shields.io/badge/License-AGPL%20v3-black.svg)](LICENSE)

QIHSE is a C runtime that combines exact ANN correctness with optional trinary
candidate acceleration, deterministic persistence, and a direct persistence model
you can integrate in production code.

## Why this project

- Exact float32 search is always the authority.
- Trinary and magnitude artifacts are performance helpers, not correctness
  shortcuts.
- File-backed persistence is crash-aware through checkpoint + WAL replay.
- Hardware path options are explicit in build and configuration.

## Build in 30 seconds

```bash
git clone https://github.com/SWORDIntel/QIHSE.git
cd QIHSE
make all
```

## 60-second integration sketch

```c
qihse_vector_db_t db = qihse_vector_db_open(
    QIHSE_VECTOR_DB_AUTO,
    NULL,
    "data/qihse_db",
    QIHSE_VDB_OPEN_CREATE | QIHSE_VDB_OPEN_FILE_BACKED
);

qihse_vector_query_t q = {
    .query_vector = query,
    .vector_dims = 128,
    .top_k = 10,
    .query_mode = QIHSE_VDB_QUERY_FLOAT32
};

int got = qihse_vector_db_search(db, &q, results, 10);
qihse_vector_db_flush(db);
qihse_vector_db_checkpoint(db);
qihse_vector_db_close(db);
```

## What “fast mode” looks like

Use trinary modes only when sidecars exist:
- `QIHSE_VDB_QUERY_TRINARY_SCALAR`
- `QIHSE_VDB_QUERY_TRINARY_MAGNITUDE`

Both still rerank with float32 for final result correctness.

## Developer-facing API surface

- `qihse_vector_db_open`
- `qihse_vector_db_add_vectors`
- `qihse_vector_db_update_by_id`
- `qihse_vector_db_delete_by_id`
- `qihse_vector_db_upsert_by_ids`
- `qihse_vector_db_search`
- `qihse_vector_db_search_trinary_candidates`
- `qihse_vector_db_preload_similar`
- `qihse_vector_db_get_persistence_stats`
- `qihse_vector_db_flush`
- `qihse_vector_db_checkpoint`
- `qihse_vector_db_compact`
- `qihse_vector_db_close`

## Production checks

- `make test-persist` validates persistence and WAL replay.
- `make test-trinary-codec` validates codec and sidecar expectations.
- `make benchmark` runs reference workload checks.
- `make bench-vxug-pdf-workload` runs a practical end-to-end sample.

## Runtime posture

- Exact mode default, trinary mode opt-in.
- Sidecar problems surface as explicit query failures.
- Maintenance and migration controls are caller-driven.
- Built for reproducibility over magic behavior.

## Documentation

- [docs/ONBOARDING.md](docs/ONBOARDING.md)
- [docs/persistence/README.md](docs/persistence/README.md)
- [docs/usage/](docs/usage/)
- [docs/qmag-policy.md](docs/qmag-policy.md)
- [docs/security/](docs/security/)
- [docs/deployment/](docs/deployment/)

## License

AGPL-3.0-or-later. See [LICENSE](LICENSE).
