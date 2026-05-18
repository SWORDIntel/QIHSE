# QIHSE — Quantum-Inspired Hilbert Space Expansion

[![License: AGPL v3](https://img.shields.io/badge/License-AGPL%20v3-black.svg)](LICENSE)

QIHSE is a C runtime for vector search with exact float32 results by default and
optional trinary acceleration (`qtri`/`qmag`) for candidate reduction.

## Build

```bash
git clone https://github.com/SWORDIntel/QIHSE.git
cd QIHSE
make all
```

## Quick start

```c
qihse_vector_db_t db = qihse_vector_db_open(
    QIHSE_VECTOR_DB_AUTO,
    NULL,
    "data/qihse_db",
    QIHSE_VDB_OPEN_CREATE | QIHSE_VDB_OPEN_FILE_BACKED
);

qihse_vector_query_t q = {
    .query_vector = query,
    .vector_dims = dims,
    .top_k = 10,
    .query_mode = QIHSE_VDB_QUERY_FLOAT32
};
int got = qihse_vector_db_search(db, &q, results, 10);
```

## Trinary mode note

Use `QIHSE_VDB_QUERY_TRINARY_SCALAR` or
`QIHSE_VDB_QUERY_TRINARY_MAGNITUDE` when sidecar candidates are present.
These modes are explicit opt-ins and still return exact reranked float32 results.

## Core API surface

- `qihse_vector_db_open`
- `qihse_vector_db_add_vectors`
- `qihse_vector_db_update_by_id`, `qihse_vector_db_delete_by_id`
- `qihse_vector_db_upsert_by_ids`
- `qihse_vector_db_search`, `qihse_vector_db_search_trinary_candidates`
- `qihse_vector_db_flush`, `qihse_vector_db_checkpoint`, `qihse_vector_db_compact`
- `qihse_vector_db_get_persistence_stats`, `qihse_vector_db_close`

## Runtime checks

- Exact float32 search is the default and authoritative path.
- File-backed opens load checkpoint + replay WAL before serving reads.
- Trinary failures are explicit when sidecars are missing, stale, or corrupt.
- Makefile targets:
  - `make test-persist`
  - `make test-trinary-codec`
  - `make benchmark`

## Docs

- [docs/ONBOARDING.md](docs/ONBOARDING.md)
- [docs/persistence/README.md](docs/persistence/README.md)
- [docs/usage/](docs/usage/)
- [docs/qmag-policy.md](docs/qmag-policy.md)

## License

AGPL-3.0-or-later. See [LICENSE](LICENSE).
