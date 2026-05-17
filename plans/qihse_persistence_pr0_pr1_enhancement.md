# QIHSE Persistence Enhancement Plan: Current Checkpoint

## Purpose

This enhancement records the landed native persistence slice and the reboot-safe continuation path from it.

The existing plan is directionally correct, but it now contains several future tracks: durable persistence, WAL recovery, mmap, trinary codec execution, Python bindings, and native anchor-search integration. PR-0/PR-1 are complete. PR-2 has landed ADD/COMMIT WAL records, previous-record offsets, and writable torn-tail truncation. PR-3 and PR-5 candidate slices have started: clean read-only mmap now covers vectors, metadata, ID map, and validated `index.qidx` rows; the standalone trinary tryte codec now has deterministic top-k candidate selection plus a benchmark target.

Target outcome:

- `qihse_vector_db_create(..., db_path)` creates a durable native file-backed database.
- Insert, close, reopen, and search works without export/import.
- Sparse external vector IDs no longer corrupt vector or metadata hydration.
- QIHSE is treated as its own standalone native program, not as a Framewerx feature, plugin, ingestion helper, or downstream application component.
- `not_stisla` is integrated only where it fits: scalar ID lookup over sorted keys.
- The on-disk layout owns `vectors.qtri` now as a rebuildable tryte sidecar derived from authoritative float32 vectors.
- WAL replay, read-only mmap reopen, ADD/COMMIT WAL records, previous-record offsets, and writable torn-tail truncation are part of the native persistence slice; Python storage remains out of scope.

## Resume Checkpoint

Last updated: 2026-05-17.

Use this section first after a reboot or context reset.

Current implementation state:

- PR-0 anchor-search integration is implemented.
- PR-1 native file-backed vector DB persistence is implemented.
- PR-2 WAL/recovery hardening is implemented for ADD/COMMIT records, previous-record offsets, committed-batch replay, and writable torn-tail truncation.
- PR-3 candidate work has started: read-only mmap mode maps `vectors.qvec`, `metadata.qmeta`, validated `idmap.qid`, and validated direct `index.qidx` rows for clean snapshots.
- PR-4 physical compaction is present: delete/update/upsert API symbols write committed WAL records, replay committed mutation batches newer than the snapshot, writable open truncates torn/uncommitted mutation tails, and `compact()` rewrites live rows only before publishing the regenerated snapshot/sidecars.
- PR-4 compaction fixture coverage now enforces row/index/live/idmap counts after physical pruning, high unsigned IDs, valid `vectors.qtri` after compact, and stale/corrupt derived sidecar rebuild.
- PR-5 search-path benchmark scaffolding is present: standalone tryte top-k exists with `make bench-trinary-codec`, DB-backed candidate generation plus exact float32 rerank exists with `make bench-trinary-db-candidate`, and `make bench-trinary-search-path` compares full float32 DB search against trinary candidates plus rerank with recall/order/latency reporting.
- Latest pushed checkpoint before this slice: `7df0e3e` on `codex/qihse-file-persistence`.
- `qihse/qihse_vector_db.c` was restored after a disk-full truncation and now contains the native persistence implementation.
- `qihse_vector_db_create(..., db_path)` opens a file-backed native database.
- `qihse_vector_db_open()` supports ephemeral, file-copy, read-only, and read-only mmap modes.
- `qihse_vector_db_add_vectors()` appends a WAL ADD record and explicit COMMIT record before accepting file-backed writes.
- `qihse_vector_db_flush()`, `checkpoint()`, and `compact()` rewrite the snapshot, regenerate `idmap.qid`, generate `vectors.qtri`, and clear `wal.qwal`.
- Open replays valid committed WAL batches newer than the committed snapshot generation.
- Writable open truncates torn or uncommitted WAL tails back to the last committed WAL boundary.
- `vectors.qvec` remains authoritative; `vectors.qtri` is a derived tryte sidecar for the trinary path.
- Missing or corrupt `vectors.qtri` does not block `FLOAT32` database open/search.
- Read-only mmap works only for clean snapshots without pending WAL.
- The top-level `not_stisla/` subsystem is intentionally removed. Do not resurrect it; useful code now lives under `qihse/algorithms/`.

Expected important files:

```text
qihse/qihse_vector_db.c
qihse/qihse_vector_db.h
qihse/codecs/qihse_trinary_tryte_codec.c
qihse/codecs/qihse_trinary_tryte_codec.h
qihse/persistence/qihse_file.h
qihse/persistence/qihse_file_posix.c
qihse/persistence/qihse_persist_format.h
qihse/persistence/qihse_persist_format.c
qihse/persistence/qihse_vector_store.h
qihse/persistence/qihse_vector_store.c
qihse/tests/qihse_vector_db_persistence_test.c
qihse/tests/qihse_trinary_codec_test.c
qihse/benchmarks/qihse_trinary_candidate_bench.c
qihse/benchmarks/qihse_trinary_db_candidate_bench.c
qihse/algorithms/qihse_anchor_search.c
qihse/algorithms/qihse_anchor_search.h
qihse/algorithms/qihse_anchor_search_UPSTREAM.txt
```

Expected generated or transient files:

- `qihse/libqihse.so` is rebuilt by `make test-persist` and may show as modified.
- `qihse/tests/qihse_vector_db_persistence_test` is a generated test binary. It should not be committed.
- `qihse/tests/qihse_trinary_codec_test` is a generated test binary. It should not be committed.

First commands after reboot:

```bash
cd /home/john/FRAMEWERX/SWORDIntel_QIHSE
df -h .
git status --short
cd qihse
make test-persist
make test-trinary-codec
make bench-trinary-codec
make bench-trinary-db-candidate
make bench-trinary-search-path
rm -f tests/qihse_vector_db_persistence_test tests/qihse_trinary_codec_test
```

Expected verification result:

```text
PASS all qihse vector DB persistence tests
PASS: top-k candidate selection
PASS: top-k invalid tryte rejection
rows=2048 dims=64 row_bytes=13 topk=8 iterations=64
trinary_db_candidate_bench rows=2048 dims=64 qtri_row_bytes=13 candidates=64 topk=8 iterations=32
trinary_search_path_bench rows=2048 dims=64 qtri_row_bytes=13 candidates=64 topk=8 iterations=32
```

If the build fails after reboot, inspect these areas first:

- `qihse/qihse_vector_db.c`: WAL ADD/COMMIT replay, torn-tail truncation, read-only mmap open for vectors/metadata/idmap/index, and trinary sidecar generation.
- `qihse/codecs/qihse_trinary_tryte_codec.*`: tryte packing, validation, scalar scoring, and top-k candidate selection.
- `qihse/benchmarks/qihse_trinary_candidate_bench.c`: standalone trinary candidate timing and reference-result validation.
- `qihse/benchmarks/qihse_trinary_db_candidate_bench.c`: DB-backed `vectors.qtri` candidate selection and exact float32 rerank validation.
- `qihse/persistence/`: snapshot file load/flush helpers and little-endian/checksum helpers.
- `qihse/Makefile`: explicit `SRCS_BASE` must include the persistence helpers and `algorithms/qihse_anchor_search.c`.
- Disk space: the previous interruption happened when the filesystem hit 100% and truncated `qihse/qihse_vector_db.c`.

## Program Boundary

QIHSE must be developed and tested as an independent native program.

Rules:

- The persistence contract belongs to QIHSE, not Framewerx.
- `db_path` names a QIHSE database, not a Framewerx workspace artifact.
- Native C owns the storage format, recovery behavior, indexing, and codec layout.
- Framewerx, RAG, ingestion scripts, commercial docs, and external app workflows are clients at most; they are not part of the QIHSE database contract.
- Build and verification commands for this work should run from `qihse/`.
- New storage files must live under `qihse/` source ownership, with tests under `qihse/tests/`.
- Python may wrap native QIHSE APIs later, but must not define persistence semantics.
- No persistence code should rely on Framewerx-specific directory layout, environment variables, service lifecycle, or configuration.

## Current-State Findings

- `qihse/qihse_vector_db.c` now implements native file-backed persistence for `db_path`.
- `qihse_vector_db_search()` hydrates results from internal row offsets instead of using caller-visible IDs as array indexes.
- `qihse/Makefile` now builds NOT_STISLA-derived anchor search natively as `qihse/algorithms/qihse_anchor_search.c`.
- `qihse/qihse_search.c` now calls the native anchor-search implementation for suitable `QIHSE_TYPE_INT64` hybrid searches.
- The repo uses an explicit Makefile source list, so any new persistence `.c` files must be added to `SRCS_BASE` or a guarded source list.
- Persistence helper files now live under `qihse/persistence/` and are built by the native QIHSE Makefile.
- `not_stisla/` is no longer an independent top-level subsystem; the useful anchor-search implementation is integrated under `qihse/algorithms/`.

## Scope

### In Scope

- Remove the `not_stisla_search` stub from QIHSE hybrid int64 search.
- Build the NOT_STISLA-derived anchor-search implementation as native QIHSE algorithm code.
- Add native vector DB open, flush, close, compact, and checkpoint API stubs.
- Make `qihse_vector_db_create(..., db_path)` delegate to file-backed open mode.
- Replace the vector DB parallel arrays with a canonical row table.
- Fix sparse-ID result hydration by separating external vector ID from internal row index.
- Add snapshot-style durable file-backed copy mode.
- Add WAL append/replay for accepted adds that have not yet been checkpointed into a snapshot.
- Add read-only mmap reopen for clean vector files.
- Add a rebuildable `idmap.qid` sidecar for `vector_id -> row_index` lookup.
- Generate and validate optional `vectors.qtri` tryte sidecar bytes while keeping `vectors.qvec` authoritative.
- Add persistence tests and a `make test-persist` target.

### Out of Scope

- Writable mmap and mmap WAL replay.
- Trinary scoring kernels, recall benchmarks, and pure trinary-authoritative storage.
- Quantized vector sidecars.
- Python persistence format.
- Framewerx-specific persistence integration.
- Persisted `not_stisla` anchors.
- Distributed or multi-writer coordination beyond a basic single-writer lock.

## PR-0: Real NOT_STISLA Integration

PR-0 must land before persistence code relies on `not_stisla`.

### Code Changes

Patch `qihse/qihse_search.c`:

- Include the native QIHSE anchor-search header.
- Remove the normal-path stub print.
- In `qihse_execute_hybrid_search()`, call `not_stisla_search()` only for `QIHSE_TYPE_INT64`.
- Keep fallback behavior when inputs, table, config, or type are unsuitable.

Expected behavior:

- `qihse_search()` remains the primary QIHSE path.
- `not_stisla_search()` supplies the anchor result for sorted `int64_t` search.
- No core search path prints during normal operation.

Patch `qihse/Makefile`:

```make
SRCS_BASE += algorithms/qihse_anchor_search.c
```

NOT_STISLA's useful anchor-search code is now integrated into QIHSE's algorithm layer, not carried as a top-level sibling or independent vendored subsystem.

### PR-0 Validation

Commands:

```bash
cd qihse
grep -R "Stubbing call to not_stisla_search" -n .
make clean
make
nm -D libqihse.so | grep -E "not_stisla_search|qihse_execute_hybrid_search"
```

Expected:

- `grep` returns no stubbed call path.
- Build succeeds from `qihse/`.
- Hybrid search can resolve an `int64_t` key through `not_stisla_search()`.

## PR-1: Durable File-Backed Copy Mode

PR-1 delivers native durability, WAL replay for accepted adds, read-only mmap reopen for clean snapshots, and a generated trinary sidecar in the stable file layout.

### Public API Additions

Patch `qihse/qihse_vector_db.h`:

```c
typedef enum qihse_vector_db_storage_mode_e {
    QIHSE_VDB_STORAGE_EPHEMERAL = 0,
    QIHSE_VDB_STORAGE_FILE_COPY = 1,
    QIHSE_VDB_STORAGE_FILE_MMAP = 2
} qihse_vector_db_storage_mode_t;

typedef enum qihse_vector_db_open_flags_e {
    QIHSE_VDB_OPEN_CREATE      = 1u << 0,
    QIHSE_VDB_OPEN_READ_ONLY   = 1u << 1,
    QIHSE_VDB_OPEN_TRUNCATE    = 1u << 2,
    QIHSE_VDB_OPEN_FILE_BACKED = 1u << 3,
    QIHSE_VDB_OPEN_MMAP        = 1u << 4
} qihse_vector_db_open_flags_t;

qihse_vector_db_t qihse_vector_db_open(
    qihse_vector_db_backend_t backend,
    qihse_uma_manager_t uma,
    const char* db_path,
    uint32_t flags
);

bool qihse_vector_db_flush(qihse_vector_db_t vdb);
bool qihse_vector_db_checkpoint(qihse_vector_db_t vdb);
bool qihse_vector_db_compact(qihse_vector_db_t vdb);
bool qihse_vector_db_close(qihse_vector_db_t vdb);
```

Compatibility rule:

- `db_path == NULL`: keep ephemeral in-memory behavior.
- `db_path != NULL`: open or create durable file-backed copy mode.
- `qihse_vector_db_destroy()` remains valid and should call close/free cleanup internally.

### Internal Row Model

Add a canonical row table:

```c
#define QIHSE_ROW_F_LIVE      0x00000001u
#define QIHSE_ROW_F_TOMBSTONE 0x00000002u

typedef struct qihse_index_row_s {
    uint64_t vector_id;
    uint64_t vector_offset;
    uint64_t metadata_offset;
    uint64_t metadata_size;
    uint64_t commit_generation;
    uint32_t row_flags;
    uint32_t reserved;
} qihse_index_row_t;
```

Replace authoritative use of:

- `vector_ids`
- `vector_offsets`
- `metadata_offsets`
- `metadata_sizes`

with:

- `rows`
- `rows_capacity`
- `vector_bytes_used`
- `metadata_bytes_used`

Temporary compatibility arrays are allowed during refactor only if `rows[]` is the source of truth.

### Sparse-ID Search Fix

Add a hit type:

```c
typedef struct qihse_vector_hit_s {
    uint64_t vector_id;
    size_t row_index;
    float score;
} qihse_vector_hit_t;
```

Search loop:

- Scan rows by internal row index.
- Skip non-live rows.
- Store `vector_id` and `row_index` in hits.
- Sort hits by score.
- Hydrate vectors and metadata through `row_index`, not `result.id`.

This must be completed before persistence files are trusted.

### File Layout

PR-1 creates:

```text
<db_path>/
  MANIFEST
  vectors.qvec
  vectors.qtri
  metadata.qmeta
  index.qidx
  idmap.qid
  LOCK
```

Authoritative files:

- `MANIFEST`
- `vectors.qvec`
- `metadata.qmeta`
- `index.qidx`

Derived files:

- `idmap.qid`
- `vectors.qtri`

`idmap.qid` must be rebuildable from `index.qidx`; corruption of `idmap.qid` must not prevent normal vector DB open/search.

`vectors.qtri` is optional in PR-1. `vectors.qvec` remains authoritative. If `vectors.qtri` is absent, stale, or corrupt, open must still succeed and mark the trinary sidecar unavailable. This keeps the layout stable without making trinary search part of the first durable release.

### Persistence Modules

Add:

```text
qihse/persistence/qihse_file.h
qihse/persistence/qihse_file_posix.c
qihse/persistence/qihse_persist_format.h
qihse/persistence/qihse_persist_format.c
qihse/persistence/qihse_vector_store.h
qihse/persistence/qihse_vector_store.c
```

Responsibilities:

- `qihse_file.*`: POSIX open, pread, pwrite, fsync, rename, lock, directory fsync helpers.
- `qihse_persist_format.*`: little-endian field encoding, header validation, checksum helpers, checked arithmetic helpers, trinary sidecar header validation.
- `qihse_vector_store.*`: load/flush snapshot files, manifest slot selection, idmap load/rebuild, trinary sidecar status handling.

Do not write native structs directly as the disk format. Serialize explicit little-endian fields.

### Snapshot Durability

PR-1 uses two-slot manifest snapshot durability, not WAL.

Flush sequence:

1. Write `vectors.qvec.tmp`.
2. Write `vectors.qtri.tmp` if the trinary sidecar is enabled or already exists.
3. Write `metadata.qmeta.tmp`.
4. Write `index.qidx.tmp`.
5. Build and write `idmap.qid.tmp`.
6. `fsync` all tmp files.
7. Rename tmp files into place.
8. Write the inactive manifest slot with generation + 1.
9. `fsync` `MANIFEST`.
10. `fsync` the database directory.
11. Mark `dirty = false`.

Open sequence:

1. Open or create database directory.
2. Acquire `LOCK` unless read-only.
3. Read both manifest slots.
4. Select the highest valid generation.
5. Validate file sizes and checksums.
6. Load `index.qidx` into `rows[]`.
7. Allocate UMA vector storage and read `vectors.qvec`.
8. Validate `vectors.qtri` if present and record sidecar status.
9. Allocate UMA metadata storage and read `metadata.qmeta`.
10. Load `idmap.qid` if valid.
11. Rebuild `idmap.qid` if missing, stale, or corrupt.

### ID Map Sidecar

Use `not_stisla` for sparse scalar lookup:

```text
external vector_id -> sortable int64 key -> not_stisla lookup -> row_index
```

Do not use `not_stisla` inside vector similarity scoring.

Unsigned ID transform:

```c
static inline int64_t qihse_u64_to_sortable_i64(uint64_t id) {
    return (int64_t)(id ^ 0x8000000000000000ULL);
}

static inline uint64_t qihse_sortable_i64_to_u64(int64_t key) {
    return ((uint64_t)key) ^ 0x8000000000000000ULL;
}
```

In-memory ID map:

```c
typedef struct qihse_idmap_s {
    int64_t* keys;
    uint64_t* row_indices;
    size_t count;
    size_t capacity;
    not_stisla_anchor_table_t* anchors;
    bool dirty;
    uint64_t generation;
} qihse_idmap_t;
```

Build rules:

- Include live rows only.
- Sort by transformed key.
- Reject duplicate vector IDs in PR-1.
- Set ID map generation to manifest generation.
- Rebuild from `index.qidx` if sidecar validation fails.

### Trinary Layout Reservation

Trinary belongs in the file layout from PR-1 because it affects manifest compatibility and sidecar generation rules. The first durable release should reserve and validate the sidecar contract without routing vector search through trinary scoring yet.

Encoding IDs:

```c
typedef enum qihse_vector_encoding_e {
    QIHSE_ENCODING_FLOAT32 = 0x00000001u,
    QIHSE_ENCODING_FLOAT32_TRINARY_2BIT = 0x00010001u,
    QIHSE_ENCODING_FLOAT32_TRINARY_TRYTE = 0x00010002u,
    QIHSE_ENCODING_TRINARY_TRYTE = 0x00010003u
} qihse_vector_encoding_t;
```

PR-1 behavior:

- `QIHSE_ENCODING_FLOAT32` is the only authoritative storage mode.
- `QIHSE_ENCODING_FLOAT32_TRINARY_2BIT` is reserved for a quick prototype sidecar.
- `QIHSE_ENCODING_FLOAT32_TRINARY_TRYTE` is layout-reserved as an optional derived sidecar.
- `QIHSE_ENCODING_TRINARY_TRYTE` is reserved but must fail open/create until pure trinary correctness and recovery tests exist.
- Manifest records must include `encoding_id`, `encoding_version`, `trinary_generation`, `trinary_row_bytes`, `trinary_rows`, `trinary_crc64`, and `trinary_flags`.
- `vectors.qtri` is a raw tryte payload whose size, generation, and checksum are governed by `MANIFEST`.
- Tryte rows use `trytes_per_row = (dims + 4) / 5`.
- Padding trits are zero.
- Valid packed bytes are `0..242`; bytes `243..255` are invalid.
- A corrupt or stale `vectors.qtri` marks the sidecar unavailable, but does not fail DB open while `vectors.qvec` is authoritative.
- PR-1 search continues to use `vectors.qvec`; trinary candidate generation is a follow-on implementation.

This gives trinary a stable on-disk home early while keeping recall, scoring kernels, and hybrid rerank benchmarks out of the first persistence landing.

### Read-Only Mode

`QIHSE_VDB_OPEN_READ_ONLY` must:

- Open existing database.
- Avoid writer lock where practical.
- Allow search and ID lookup.
- Reject `qihse_vector_db_add_vectors()`.
- Reject flush, compact, and checkpoint mutations.

For PR-1, `checkpoint()` and `compact()` can return true no-op for ephemeral mode and false or not-supported for read-only/file-backed mode until their real phases land. Document the behavior in comments.

## Tests

Add:

```text
qihse/tests/qihse_vector_db_persistence_test.c
```

Add Makefile target:

```make
.PHONY: test-persist

test-persist: lib
	$(CC) $(CFLAGS) -o tests/qihse_vector_db_persistence_test \
	    tests/qihse_vector_db_persistence_test.c \
	    -L. -lqihse $(LDFLAGS)
	LD_LIBRARY_PATH=. ./tests/qihse_vector_db_persistence_test
```

Required test cases:

1. Create, insert, close, reopen, search.
2. Sparse IDs hydrate the correct vector and metadata.
3. Binary metadata survives restart byte-for-byte.
4. `db_path == NULL` stays ephemeral.
5. WAL replays an accepted add before snapshot flush.
6. Torn WAL tail is ignored and truncated on writable open.
7. Read-only mmap reopen searches mapped vector file.
8. Corrupt `vectors.qvec` magic fails open cleanly.
9. Truncated `index.qidx` fails open cleanly.
10. Read-only open can search but cannot mutate.
11. Duplicate vector ID is rejected.
12. Corrupt `idmap.qid` rebuilds without blocking vector search, including IDs above `INT64_MAX`.
13. Missing `vectors.qtri` is accepted for `FLOAT32` databases.
14. Corrupt `vectors.qtri` marks the sidecar unavailable but does not block open/search.

Developer command:

```bash
cd qihse
make clean
make
make test-persist
```

## Acceptance Criteria

PR-0 is complete when:

- QIHSE no longer prints or hardcodes the `not_stisla_search` stub.
- QIHSE builds cleanly with the native anchor-search algorithm integrated into `qihse/algorithms`.
- Hybrid `int64_t` search calls the real `not_stisla_search()`.

PR-1 is complete when:

- `qihse_vector_db_create(..., db_path)` creates durable native files.
- Insert, close, reopen, and search works with no export step.
- The implementation builds and tests as QIHSE from `qihse/`, without depending on Framewerx runtime behavior.
- Sparse vector IDs never act as row indexes.
- Metadata survives restart exactly.
- `idmap.qid` is generated from `index.qidx`.
- `idmap.qid` corruption triggers rebuild rather than DB open failure.
- `vectors.qtri` is part of the file layout as an optional derived sidecar.
- `vectors.qtri` absence or corruption does not block `FLOAT32` database open/search.
- Manifest fields reserve trinary encoding and sidecar generation state.
- Duplicate IDs are rejected cleanly.
- Read-only open can search but cannot mutate.
- Native persistence diagnostics report generation, storage mode, ID-map rebuild state, and trinary sidecar status.
- Python has not implemented any storage format.
- Writable mmap, production vector DB trinary acceleration, pure trinary storage, compaction crash fixtures, and anchor persistence are still deferred.

## Follow-On Phases

After the current checkpoint:

- PR-3: harden mmap compatibility and corruption tests now that read-only `vectors.qvec`, `metadata.qmeta`, `idmap.qid`, and `index.qidx` mapping are present for clean snapshots.
- PR-4: public delete/update/upsert API behavior, mutation WAL replay/truncation, and physical tombstone compaction are implemented and covered by persistence tests. Compaction crash/recovery fixtures remain.
- PR-5: DB-backed candidate generation, exact rerank, and search-path benchmark scaffolding are present; production search-path acceleration, broader recall measurement, and optional pure trinary storage remain.
- PR-6: optional persisted anchor hints and optimizer statistics as rebuildable sidecars.

## PR-4: Mutation and Compaction Plan

PR-4 should make mutation explicit without changing QIHSE's program boundary. The public contract belongs to native QIHSE; Framewerx and other callers remain clients.

Status: the public delete/update/upsert declarations are staged in `qihse/qihse_vector_db.h` and the native implementation is present in `qihse/qihse_vector_db.c`. Executable tests now cover delete, update, upsert, read-only rejection, compact-after-mutation search correctness, unflushed mutation WAL replay, and physical compact row pruning.

### Public API

The explicit external-ID mutation APIs are staged in `qihse/qihse_vector_db.h`:

```c
bool qihse_vector_db_delete_by_id(
    qihse_vector_db_t vdb,
    uint64_t vector_id
);

bool qihse_vector_db_delete_by_ids(
    qihse_vector_db_t vdb,
    const uint64_t* vector_ids,
    size_t count,
    size_t* deleted_count
);

bool qihse_vector_db_update_by_id(
    qihse_vector_db_t vdb,
    uint64_t vector_id,
    const float* vector,
    size_t dims,
    const void* metadata,
    size_t metadata_size
);

bool qihse_vector_db_update_by_ids(
    qihse_vector_db_t vdb,
    const uint64_t* vector_ids,
    const float* vectors,
    size_t count,
    size_t dims,
    const void* const* metadata,
    const size_t* metadata_sizes,
    size_t* updated_count
);

bool qihse_vector_db_upsert_by_ids(
    qihse_vector_db_t vdb,
    const uint64_t* vector_ids,
    const float* vectors,
    size_t count,
    size_t dims,
    const void* const* metadata,
    const size_t* metadata_sizes,
    size_t* inserted_count,
    size_t* updated_count
);

bool qihse_vector_db_compact(qihse_vector_db_t vdb);
```

Semantics:

- Delete marks a live row tombstoned by external `vector_id`; missing IDs return false for single-ID delete and are skipped in batch delete.
- Update is replace-by-ID: tombstone the old live row and append a new live row with the same external ID, vector bytes, metadata bytes, and a higher commit generation.
- Upsert updates existing live IDs and appends new IDs in one committed batch.
- Batch APIs are atomic at the WAL commit boundary: after crash recovery, either the committed batch is replayed or the uncommitted tail is ignored/truncated.
- Read-only and read-only mmap opens reject all mutation APIs.

### Row Flags and ID Map

Use fixed row flags consistently in memory and on disk:

```c
#define QIHSE_ROW_F_LIVE       0x00000001u
#define QIHSE_ROW_F_TOMBSTONE  0x00000002u
#define QIHSE_ROW_F_SUPERSEDED 0x00000004u
```

Rules:

- Exactly one latest live row may exist per external `vector_id`.
- Delete clears `QIHSE_ROW_F_LIVE` and sets `QIHSE_ROW_F_TOMBSTONE`.
- Update clears `QIHSE_ROW_F_LIVE` and sets `QIHSE_ROW_F_TOMBSTONE | QIHSE_ROW_F_SUPERSEDED` on the old row, then appends a new `QIHSE_ROW_F_LIVE` row.
- Search scans only live rows.
- `idmap.qid` includes only live rows and maps each external ID to the latest live row index.
- Duplicate live IDs are invalid on open; older tombstoned duplicates are legal until compaction.

### WAL Records

Extend `wal.qwal` record types without weakening the current ADD/COMMIT model:

```c
QIHSE_WAL_DELETE_BATCH = 7,
QIHSE_WAL_UPDATE_BATCH = 8,
QIHSE_WAL_UPSERT_BATCH = 9,
QIHSE_WAL_COMPACT_BEGIN = 10,
QIHSE_WAL_COMPACT_COMMIT = 11
```

Payload requirements:

- DELETE stores the batch count and external IDs.
- UPDATE stores old row indexes, external IDs, vector bytes, metadata sizes, metadata bytes, and new row descriptors.
- UPSERT stores the same payload as UPDATE plus an operation flag per row: insert or replace.
- Each mutation batch is followed by the existing COMMIT record with previous-record offset and payload checksum.
- Replay applies only fully committed batches newer than the manifest generation.
- Writable open truncates torn or uncommitted mutation tails exactly like ADD tails.

### Compaction

`qihse_vector_db_compact()` should rewrite authoritative snapshot files into a new generation:

1. Take the write mutex and require non-read-only file-backed mode.
2. Build a live-row remap from old row index to new compact row index.
3. Copy only live vector rows into new `vectors.qvec.tmp`.
4. Copy only live metadata blobs into new `metadata.qmeta.tmp`.
5. Write compact `index.qidx.tmp` with live rows only, preserving external IDs and assigning fresh offsets.
6. Rebuild `idmap.qid.tmp` from compact rows.
7. Regenerate `vectors.qtri.tmp` from compact float32 vectors when the sidecar is enabled or already present.
8. Write a new manifest generation only after all tmp files are fsynced and renamed.
9. Clear checkpointed WAL bytes and mark persistence stats clean.

Crash rule: if compaction crashes before manifest publication, the old generation remains authoritative. If it crashes after manifest publication, open validates the new generation and derived sidecars, rebuilding only rebuildable files when needed.

### Required Tests

The persistence test file carries a compile-safe TODO backlog for these cases. Convert the backlog to executable tests only after `qihse_vector_db.c` exports the mutation symbols:

1. Delete-by-ID removes a row from search and survives close/reopen.
2. Delete of a missing ID does not corrupt the database.
3. Update-by-ID replaces vector and metadata, preserves external ID, and survives reopen.
4. Batch delete/update/upsert has correct counts and rejects duplicate live IDs inside the same committed batch.
5. WAL replays committed delete/update/upsert batches after crash before checkpoint.
6. Torn delete/update/upsert WAL tails are ignored and truncated on writable open.
7. `idmap.qid` rebuild after delete/update maps only the latest live rows.
8. Compaction removes tombstoned/superseded rows, preserves search results, metadata bytes, high external IDs, and generation ordering.
9. Read-only and read-only mmap opens reject delete/update/upsert/compact.
10. Corrupt derived `idmap.qid` or `vectors.qtri` after compaction does not block float32 open/search.

### Migration Notes

- Existing PR-1/PR-2 databases contain only live rows; open should treat absent tombstone/superseded bits as live rows.
- No format break is needed if `row_flags` and `commit_generation` are already persisted; new flag values are forward-compatible.
- If an older database has duplicate live IDs because of a prior bug, PR-4 open should fail clearly rather than guessing which row wins.
- Compaction should be opt-in at first. Automatic compaction can be added later using tombstone ratio and metadata waste thresholds exposed through persistence stats.

## 3-Agent Continuation Split

Use this split when resuming the remaining plan with multiple agents. QIHSE remains its own native program; none of these tasks should introduce Framewerx-specific persistence behavior.

Agent 1: PR-4 compaction crash fixtures.

- Add tmp-file and manifest-publication crash/recovery fixtures around compact.
- Verify old generation remains authoritative when compact publication is incomplete.
- Verify derived sidecars rebuild after compact interruption.
- Keep compaction manual until stats-driven thresholds exist.

Agent 2: PR-4 WAL-plus-compaction fixtures.

- Add WAL-plus-compaction interaction tests.
- Verify committed mutation WAL replay before compact, compact clearing checkpointed WAL, and no resurrection of pruned rows.
- Fix any recovery bugs exposed by those tests.
- Keep derived sidecar rebuild behavior explicit.

Agent 3: PR-5 search-path trinary acceleration.

- Use the search-path benchmark to guide optional vector DB search acceleration.
- Add broader recall/performance datasets beyond the synthetic fixture.
- Keep reporting speed honestly; the current benchmark proves recall/order but not consistent speedup.
- Keep `vectors.qvec` authoritative until pure trinary storage has recovery, migration, and recall tests.
- Update plan state after production search-path acceleration lands.
