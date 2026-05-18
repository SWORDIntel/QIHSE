# QIHSE — Quantum-Inspired Hilbert Space Expansion

[![License: AGPL v3](https://img.shields.io/badge/License-AGPL%20v3-black.svg)](LICENSE)
![Build: CI-Ready](https://img.shields.io/badge/Build-CI%20Ready-brightgreen.svg)

QIHSE is a C runtime focused on high-throughput vector search with
**exact-result-first semantics** and **optional trinary acceleration**.

It is built as a practical platform:
- deterministic persistence pipeline
- vector-only mutation APIs with explicit durability controls
- optional hardware-aware execution scaffolding
- reproducible benchmark and validation targets

## What it does well today

- **Correct first**: exact float32 search remains the default and always
  produces authoritative results.
- **Faster where it is safe**: trinary candidate search (`qtri`, `qmag`) can
  route to a smaller candidate set and still rerank against float32 data.
- **Restart-friendly persistence**: file-backed stores, WAL replay, checkpoints,
  and compact cycles are implemented in the vector DB layer.
- **Operational visibility**: persistence status, trinary health, and migration
  helpers are exposed through dedicated APIs.

## Core stack

- Core search API in `qihse_search.*` and `qihse_vector_db.*`
- UMA/HMA memory control in `memory/`
- Trinary codec and sidecars in `codecs/` and `persistence/`
- Device execution backends in `backends/` and orchestration in `orchestration/`
- Benchmark and workflow scripts in `benchmarks/` and `benchmarks/scripts/`

## Quick start

```bash
git clone https://github.com/SWORDIntel/QIHSE.git
cd QIHSE
make all
```

Build artifacts:
- `libqihse.so` shared library
- command-line and test executables from `make test` targets

## Minimal usage pattern (vector DB persistence)

```c
#include "qihse_vector_db.h"

qihse_vector_db_t db = qihse_vector_db_open(
    QIHSE_VECTOR_DB_AUTO,
    NULL,                         // UMA manager is optional for simple local test flows
    "/var/lib/qihse/db",
    QIHSE_VDB_OPEN_CREATE | QIHSE_VDB_OPEN_FILE_BACKED
);

// Add vectors
qihse_vector_db_add_vectors(db, vectors, num_vectors, dims, ids, NULL, NULL);

// Query exact results (safe default)
qihse_vector_query_t q = {
    .query_vector = query,
    .vector_dims = dims,
    .top_k = 10,
    .include_vectors = true,
    .include_metadata = true,
    .query_mode = QIHSE_VDB_QUERY_FLOAT32
};
qihse_vector_db_search(db, &q, results, 10);

// Persist and compact
qihse_vector_db_flush(db);
qihse_vector_db_checkpoint(db);
qihse_vector_db_compact(db);

qihse_vector_db_close(db);
```

For optional acceleration, set `query_mode` to trinary modes:
- `QIHSE_VDB_QUERY_TRINARY_SCALAR`
- `QIHSE_VDB_QUERY_TRINARY_MAGNITUDE`

Both use trinary/qmag as candidate selectors and still return exact reranked
float32 results.

## Performance and validation surface

- `make test-persist`
  - file-backed persistence tests and WAL recovery checks
- `make test-trinary-codec`
  - codec correctness
- `make benchmark`
  - reference workloads and persistence validation in one flow
- `make bench-vxug-pdf-workload`
  - sample VXUG-based end-to-end benchmark
- `make bench-trinary-search-path`, `make bench-trinary-search-sweep`
  - trinary mode behavior exploration

## Runtime contract highlights

- **Trinary sidecar behavior is explicit and strict**:
  missing/stale/corrupt sidecars fail explicit trinary paths instead of silently
  degrading query correctness.
- **File-backed runs are replay-safe**:
  durable state is rebuilt from snapshot + WAL before serving queries.
- **Maintenance is caller-driven**:
  migration and maintenance hooks are available without hidden always-on worker threads.
- **No accidental lock-in**:
  all major behavior knobs stay in C APIs and Makefile targets.

## Documentation

- [docs/README.md](docs/README.md)
- [docs/architecture/](docs/architecture/)
- [docs/usage/](docs/usage/)
- [docs/persistence/README.md](docs/persistence/README.md)
- [docs/qmag-policy.md](docs/qmag-policy.md)
- [docs/security/](docs/security/)
- [docs/deployment/](docs/deployment/)
- [docs/ONBOARDING.md](docs/ONBOARDING.md)

## Security notes

QIHSE includes security-oriented primitives and configuration pathways for
controlled environments. If you deploy for sensitive workloads, follow:
- `docs/security/` for controls
- platform-specific hardening in deployment docs

## Build matrix note

Targeted hardware flags are controlled by Make variables:
- `make QIHSE_ENABLE_AVX2=1`
- `make QIHSE_ENABLE_AVX512=1`

Builds run with conservative defaults and can be expanded as needed.

## License

This project is licensed under the GNU Affero General Public License v3.0
or later — see [LICENSE](LICENSE).

## Contributing

See [docs/development/CONTRIBUTING.md](docs/development/CONTRIBUTING.md) and
follow the existing docs-first contribution workflow.
