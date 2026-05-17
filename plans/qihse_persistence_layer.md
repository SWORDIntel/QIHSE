# QIHSE Native File-Backed Persistence Plan

## 0. Current Checkpoint and Reboot Resume

Last updated: 2026-05-17.

QIHSE is being developed here as its own standalone native program. Framewerx, RAG, ingestion scripts, and external applications are clients at most; they do not define the QIHSE persistence contract.

Current landed state:

- PR-0 is complete: NOT_STISLA-derived anchor-search usefulness is integrated as native QIHSE algorithm code under `qihse/algorithms/`; the independent top-level subsystem should not be restored.
- PR-1 is complete: `db_path` creates a native file-backed vector database with durable snapshot files, row-index-correct hydration, `idmap.qid`, derived `vectors.qtri`, diagnostics, read-only reopen, and read-only mmap of clean vector snapshots.
- PR-2 is complete for the planned WAL structure: file-backed adds write ADD and COMMIT WAL records, records carry previous-record offsets, open replays committed batches newer than the snapshot, and writable open truncates torn or uncommitted WAL tails.
- PR-3 candidate work has started: read-only mmap mode maps `vectors.qvec`, `metadata.qmeta`, and validated `idmap.qid`; read-only mmap of `index.qidx` remains.
- PR-5 candidate work has started: a standalone native tryte codec exists with deterministic top-k candidate selection; vector DB trinary candidate generation, exact rerank, recall benchmarks, and pure trinary storage remain.

Resume commands:

```bash
cd /home/john/FRAMEWERX/SWORDIntel_QIHSE
git status --short
cd qihse
make test-persist
make test-trinary-codec
rm -f tests/qihse_vector_db_persistence_test tests/qihse_trinary_codec_test
```

Expected result:

```text
PASS all qihse vector DB persistence tests
PASS: top-k candidate selection
PASS: top-k invalid tryte rejection
```

Post-PR-2 continuation:

- PR-3: extend mmap from read-only `vectors.qvec` into `index.qidx`, `metadata.qmeta`, and `idmap.qid` where mapping improves open/search/hydration behavior. Vector, metadata, and ID-map mmap are present; index mmap remains.
- PR-4: public delete/update/upsert API declarations are staged; tombstone behavior, mutation WAL replay, batch semantics, and real compaction remain.
- PR-5: move trinary sidecar behavior behind a native codec module, then add tryte scoring, candidate generation, exact rerank, recall benchmarks, and optional pure trinary storage. Standalone tryte encoding/scoring/top-k is present; database search integration, exact rerank, and benchmarks remain.
- PR-6: add persisted anchor hints and optimizer statistics only as rebuildable, explicit-format sidecars.

Recommended 3-agent split:

- Agent 1 owns PR-3 mmap extension, continuing after vector/metadata/ID-map mmap with index mmap.
- Agent 2 owns PR-5 trinary DB integration and benchmarks, starting from the standalone tryte codec and top-k selector.
- Agent 3 owns PR-4 plus the remaining PR-5/PR-6 database sidecar and compaction work.

## 1. Background

QIHSE should be treated as a standalone native database engine, not as an in-memory helper for a downstream application. This plan started because the original vector DB implementation accepted `db_path` in `qihse_vector_db_create` but kept vector and metadata state in process memory. PR-1 corrected that oversight with native file-backed persistence.

The persistence layer is therefore native C and file-backed by design. `db_path` is an actual on-disk database, with ongoing work focused on broader memory mapping, explicit mutation semantics, codec execution, and sidecar hardening.

## 2. Design Goals

- Make QIHSE usable as a standalone durable vector database.
- Store vectors, IDs, metadata, dimensions, capacity, feature flags, and layout state on disk.
- Support fast startup by mapping existing database files instead of rebuilding indexes.
- Preserve the current in-memory API while adding a durable file-backed mode.
- Keep all core persistence in native C; Python bindings should call native APIs only.
- Detect corruption, incompatible versions, partial writes, and torn commits.
- Allow future zero-copy search over mapped vector pages where UMA placement permits it.
- Support experimental vector encodings behind stable format/version gates.
- Make experimental modes measurable, reversible, and optional.

## 3. Non-Goals

- Do not make Framewerx, RAG, or any ingestion script part of the QIHSE persistence contract.
- Do not depend on FAISS, Chroma, Qdrant, SQLite, RocksDB, LMDB, or another database engine for the core format.
- Do not implement distributed replication in the first file-backed release.
- Do not optimize compression before the durable file format and recovery model are stable.
- Do not expose a separate Python `.npz` or JSON persistence format.
- Do not make trinary, quantized, or compressed vector layouts the only storage mode before `float32` persistence is proven correct.

## 4. Code Targets

Primary files:

- `qihse/qihse_vector_db.h`
- `qihse/qihse_vector_db.c`
- `qihse/qihse_vector_codec.h`
- `qihse/qihse_vector_codec.c`
- `qihse/codecs/qihse_codec_trinary.c`
- `qihse/memory/include/qihse_uma.h`
- `qihse/memory/src/qihse_uma.c`
- `qihse/python/qihse.py`
- `qihse/tests/qihse_test.c` or a new `qihse/tests/qihse_vector_db_persistence_test.c`

The existing implementation stores vectors in UMA-managed memory through `qihse_uma_allocate_superposition`. The file-backed design should integrate with that model instead of bypassing it: mapped pages can be represented as a persistent memory tier or copied into UMA as a compatibility path.

## 5. Storage Model

Use a directory-backed database at `db_path`:

```text
<db_path>/
  MANIFEST
  vectors.qvec
  vectors.qtri
  metadata.qmeta
  index.qidx
  wal.qwal
  LOCK
```

File roles:

- `MANIFEST`: database identity, format version, active generation, dimensions, metric, feature flags, and file sizes.
- `vectors.qvec`: fixed-width `float32` vector pages.
- `vectors.qtri`: optional packed trinary sidecar pages for experimental codecs.
- `metadata.qmeta`: append-only metadata byte arena.
- `index.qidx`: vector ID table, vector offsets, metadata offsets, metadata sizes, tombstone flags, and commit generation.
- `wal.qwal`: write-ahead log for crash recovery.
- `LOCK`: advisory single-writer lock file.

This layout is more database-like than a single snapshot file. It supports incremental writes, recovery, compaction, and future mapped search without rewriting the full database after each ingest batch.

## 6. File Format

All persistent files should use explicit fixed-width little-endian fields. Never persist native C structs directly unless every field is fixed-width, padded intentionally, and validated.

Common header:

```c
typedef struct qihse_file_header_s {
    uint8_t magic[8];
    uint32_t format_version;
    uint32_t header_size;
    uint64_t file_generation;
    uint64_t logical_size;
    uint64_t checksum;
    uint8_t reserved[64];
} qihse_file_header_t;
```

Magic values:

- `QHMANFST` for `MANIFEST`
- `QHVECTOR` for `vectors.qvec`
- `QHTRIT01` for `vectors.qtri`
- `QHMETA01` for `metadata.qmeta`
- `QHINDEX1` for `index.qidx`
- `QHWAL001` for `wal.qwal`

The manifest should include:

- Database UUID
- Format version
- QIHSE library version that created the database
- Vector dimensions
- Vector scalar type, initially `float32`
- Vector encoding: raw `float32`, quantized, trinary, or future custom encodings
- Encoding parameters offset and length
- Distance metric, initially cosine
- Total live vectors
- Allocated vector capacity
- Metadata arena size
- Current commit generation
- Backend mode: in-memory, file-backed copy, or file-backed mmap
- Feature flags: Hilbert, quantization, parallel, superposition

Encoding metadata should be versioned separately from the database format. That lets QIHSE add experimental layouts without forcing a full database format migration for every encoding experiment.

Index row layout:

```c
typedef struct qihse_index_row_disk_s {
    uint64_t vector_id;
    uint64_t vector_offset;
    uint64_t metadata_offset;
    uint64_t metadata_size;
    uint64_t commit_generation;
    uint32_t row_flags;
    uint32_t reserved;
} qihse_index_row_disk_t;
```

Rules:

- `vector_id` is the caller-visible ID.
- The row number is the internal storage slot.
- `vector_offset` points into `vectors.qvec`.
- `metadata_offset` and `metadata_size` point into `metadata.qmeta`.
- `row_flags` reserves bits for tombstone, pending, compacted, and checksum-present.
- Search results must carry both row number and external vector ID internally.

## 7. Native API

Extend `qihse/qihse_vector_db.h` with explicit open, flush, checkpoint, and close behavior.

```c
typedef enum qihse_vector_db_open_flags_e {
    QIHSE_VDB_OPEN_CREATE = 1 << 0,
    QIHSE_VDB_OPEN_READ_ONLY = 1 << 1,
    QIHSE_VDB_OPEN_FILE_BACKED = 1 << 2,
    QIHSE_VDB_OPEN_MMAP = 1 << 3,
    QIHSE_VDB_OPEN_TRUNCATE = 1 << 4
} qihse_vector_db_open_flags_t;

qihse_vector_db_t qihse_vector_db_open(
    qihse_uma_manager_t uma,
    const char* db_path,
    uint32_t flags
);

bool qihse_vector_db_flush(qihse_vector_db_t vdb);
bool qihse_vector_db_checkpoint(qihse_vector_db_t vdb);
bool qihse_vector_db_compact(qihse_vector_db_t vdb);
bool qihse_vector_db_close(qihse_vector_db_t vdb);
```

Keep `qihse_vector_db_create` for compatibility, but make its behavior explicit:

- `db_path == NULL`: create an ephemeral in-memory DB.
- `db_path != NULL`: open or create a file-backed DB through `qihse_vector_db_open`.
- Existing callers should not need to change to gain persistence.

Optional export/import snapshot APIs can exist later, but they should not be the primary persistence mechanism.

## 8. Write Path

For `qihse_vector_db_add_vectors` in file-backed mode:

1. Validate dimensions and capacity.
2. Append an intent record to `wal.qwal`.
3. `fsync` the WAL before exposing the mutation as committed.
4. Append metadata bytes to `metadata.qmeta`.
5. Write vector pages to `vectors.qvec`.
6. Update index entries in `index.qidx`.
7. Advance the manifest commit generation atomically.
8. Optionally truncate or checkpoint the WAL after all data files are durable.

The first implementation can batch steps 2-7 per `add_vectors` call. Later releases can add transaction handles for larger ingest batches.

WAL record types:

- `BEGIN_ADD_BATCH`
- `VECTOR_PAGE_WRITE`
- `METADATA_APPEND`
- `INDEX_ROW_WRITE`
- `COMMIT_BATCH`
- `CHECKPOINT`

Every WAL record should include record length, record type, generation, payload checksum, and previous-record offset. That gives recovery enough structure to walk backward from the last valid record if the tail is torn.

## 9. Read/Search Path

File-backed mode should support two strategies:

- `FILE_BACKED_COPY`: load persistent vectors into UMA memory on open. This is simplest and preserves current search code.
- `FILE_BACKED_MMAP`: map `vectors.qvec`, `metadata.qmeta`, and `index.qidx` and search directly over mapped vector pages.

Implement `FILE_BACKED_COPY` first if needed, but design the file format and internal handles so `FILE_BACKED_MMAP` can become the default for large immutable indexes.

Search must ignore tombstoned rows and must use logical index slots rather than assuming `result.id` is always an array offset. The current search code indexes metadata by `results[i].id`; persistence work should correct this by tracking both external vector ID and internal row index.

Search should route through an encoding-aware dispatch table:

```c
typedef struct qihse_vector_codec_s {
    uint32_t encoding_id;
    uint32_t encoding_version;
    uint32_t codec_flags;
    size_t (*params_size)(const void* params);
    bool (*validate_params)(const void* params, size_t params_size);
    bool (*encode_batch)(const float* input, size_t count, size_t dims,
                         const void* params, void* output);
    bool (*encode_query)(const float* query, size_t dims,
                         const void* params, void* encoded_query);
    bool (*decode_row)(const void* encoded, size_t row, float* output);
    bool (*validate_row)(const void* encoded_row, size_t dims);
    float (*similarity)(const void* encoded_row, const void* encoded_query,
                        size_t dims);
    size_t (*similarity_batch)(const void* encoded_rows, size_t row_count,
                               const void* encoded_query, size_t dims,
                               float* scores);
    size_t (*encoded_row_bytes)(size_t dims, const void* params);
} qihse_vector_codec_t;
```

The default codec is raw `float32`. Experimental codecs can be compiled in and selected at database creation time, but the database must record the selected codec and reject opens when the codec is unavailable.

## 10. Crash Recovery

On open:

1. Acquire `LOCK` unless opened read-only.
2. Read and validate `MANIFEST`.
3. Validate file headers and size bounds.
4. Replay committed WAL records newer than the manifest generation.
5. Roll back incomplete WAL records.
6. Rebuild any derived in-memory state from `index.qidx`.
7. Refuse to open if checksums, dimensions, or file sizes are inconsistent.

Recovery should never trust file size alone. Every offset and byte count must be bounds-checked before use.

## 11. Durability and Atomicity

Minimum durability requirements:

- Use `pwrite`/`pread` or mapped writes with explicit `msync`.
- Use `fsync` for WAL and manifest updates.
- Use two manifest slots or a generation-stamped manifest write so a torn manifest can be recovered.
- Update the manifest only after vector, metadata, and index writes are durable.
- Support read-only open without taking the writer lock.
- Treat `qihse_vector_db_flush` as "all accepted writes are durable".
- Treat `qihse_vector_db_checkpoint` as "WAL replay is no longer required for generations at or before this checkpoint".

For portability, isolate OS-specific file operations behind a small internal module, for example:

- `qihse_file_open`
- `qihse_file_pread_exact`
- `qihse_file_pwrite_exact`
- `qihse_file_fsync`
- `qihse_file_mmap`
- `qihse_file_munmap`
- `qihse_file_lock`

## 12. Concurrency Model

Start with single-writer, multi-reader semantics:

- One writer process holds an exclusive advisory lock through `LOCK`.
- Read-only opens do not block each other.
- Readers map or load only committed generations.
- The writer publishes new generations by advancing the manifest.
- Readers that need repeatable results keep their opened generation until close.

Threading inside one process:

- Mutating APIs take the vector DB write mutex.
- Search APIs take a read lock or operate on an immutable generation view.
- Compaction takes the write mutex and publishes a new generation only after the replacement files are complete.

This is enough for a real embedded database while avoiding premature distributed coordination.

## 13. Growth and Compaction

The file-backed database needs predictable growth behavior:

- Grow `vectors.qvec` geometrically, matching `max_vectors`.
- Append metadata to `metadata.qmeta`.
- Store tombstones in `index.qidx` for future delete/update support.
- Implement `qihse_vector_db_compact` to rewrite live metadata and remove tombstoned rows.
- Keep compaction generation-based so a crash during compaction leaves the old files usable.

Even if delete/update APIs are added later, reserving tombstone and generation fields now avoids a format break.

### PR-4 Mutation and Compaction Plan

PR-4 turns reserved tombstone fields into real database behavior. This is native QIHSE work only; Framewerx and application layers remain clients.

Status: `qihse/qihse_vector_db.h` now stages the public delete/update/upsert declarations. `qihse_vector_db.c` does not implement them yet, so executable mutation tests remain gated behind the next implementation slice.

Public API additions staged in `qihse/qihse_vector_db.h`:

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
```

Mutation semantics:

- Delete marks the latest live row for an external `vector_id` tombstoned.
- Update is append-only replacement: tombstone the old live row, append a new live row with the same external ID and new vector/metadata bytes.
- Upsert updates existing IDs and inserts missing IDs in one committed batch.
- Batch APIs expose counts and use one WAL commit boundary per batch.
- Read-only and read-only mmap opens reject delete, update, upsert, and compact.

Row flag behavior:

```c
#define QIHSE_ROW_F_LIVE       0x00000001u
#define QIHSE_ROW_F_TOMBSTONE  0x00000002u
#define QIHSE_ROW_F_SUPERSEDED 0x00000004u
```

Rules:

- Search only scans rows with `QIHSE_ROW_F_LIVE`.
- `idmap.qid` includes only live rows and maps each external ID to the latest live row index.
- Delete clears live and sets tombstone.
- Update clears live and sets tombstone plus superseded on the old row, then appends a new live row.
- Duplicate live IDs are invalid; duplicate tombstoned historical IDs are allowed until compaction.

WAL implications:

```c
QIHSE_WAL_DELETE_BATCH = 7,
QIHSE_WAL_UPDATE_BATCH = 8,
QIHSE_WAL_UPSERT_BATCH = 9,
QIHSE_WAL_COMPACT_BEGIN = 10,
QIHSE_WAL_COMPACT_COMMIT = 11
```

- DELETE payload stores count and external IDs.
- UPDATE payload stores old row indexes, external IDs, vector bytes, metadata sizes, metadata bytes, and replacement row descriptors.
- UPSERT payload stores the same data plus a per-row insert-or-replace operation flag.
- Every mutation batch must still be followed by the existing COMMIT record with previous-record offset and payload checksum.
- Recovery replays only fully committed mutation batches newer than the manifest generation.
- Writable open truncates torn or uncommitted mutation tails just as it does for ADD.

Compaction behavior:

1. Require file-backed, non-read-only mode and take the write mutex.
2. Build an old-row to compact-row remap from live rows only.
3. Rewrite live vector rows into `vectors.qvec.tmp`.
4. Rewrite live metadata into `metadata.qmeta.tmp`.
5. Rewrite `index.qidx.tmp` with live rows only and fresh offsets.
6. Rebuild `idmap.qid.tmp` from compact rows.
7. Regenerate `vectors.qtri.tmp` from compact authoritative float32 vectors when the sidecar is enabled or already present.
8. Fsync tmp files, rename them into place, then publish a new manifest generation.
9. Clear checkpointed WAL bytes and update persistence stats.

Compaction must be generation-safe: a crash before manifest publication leaves the old generation authoritative; a crash after manifest publication opens the new generation or fails cleanly on authoritative-file corruption.

Required PR-4 tests:

The persistence test file currently records this as a compile-safe TODO backlog. Enable real calls only after the mutation symbols are implemented.

- Delete-by-ID removes a row from search and survives reopen.
- Missing-ID delete is a clean no-op/failure and does not corrupt state.
- Update-by-ID replaces vector and metadata while preserving the external ID.
- Batch delete/update/upsert returns correct counts and rejects duplicate live IDs inside one batch.
- WAL replays committed delete/update/upsert batches after crash before checkpoint.
- Torn mutation WAL tails are ignored and truncated on writable open.
- `idmap.qid` rebuild after mutation maps only latest live rows.
- Compaction removes tombstoned/superseded rows and preserves live search results, metadata, high external IDs, generation order, and trinary sidecar status.
- Read-only and read-only mmap opens reject all mutation and compaction APIs.

Migration notes:

- Existing PR-1/PR-2 databases contain only live rows; absent tombstone/superseded bits remain valid live rows.
- If `row_flags` and `commit_generation` are already persisted, PR-4 should not require a format break.
- Open should fail clearly on duplicate live IDs rather than selecting a winner.
- Automatic compaction should wait for stats-driven thresholds; PR-4 should expose manual compaction first.

## 14. UMA Integration

Add a persistent-file memory placement path to UMA:

- For copy mode, UMA owns normal allocated memory populated from disk.
- For mmap mode, UMA wraps mapped ranges and tags them as file-backed.
- Superposition state can describe residency: mapped-cold, mapped-warm, copied-hot, pinned-hot.
- `qihse_uma_free` must not call `free` on mapped pages; it should unmap or release the wrapper.

This keeps the persistence layer aligned with QIHSE's architecture instead of creating a parallel memory subsystem.

## 15. Experimental Vector Encodings

QIHSE can support experimental encodings as first-class native storage modes once the file-backed base is correct. The most promising initial experiment is trinary vector storage.

The reference model for this experiment is the balanced ternary logic in the Triton Lua modules under `/home/john/Fast26/edge/modules/core/`. The useful ideas for QIHSE are mathematical, storage-oriented, and validation-oriented:

- Balanced trits use the domain `{-1, 0, +1}`.
- K3-style ternary operations can be table-driven with compact lookup tables.
- Branchless ternary selection can be implemented with arithmetic masks.
- Five balanced trits can be packed into one byte because `3^5 = 243`.
- Multi-trit buffers support conversion, addition, multiplication, comparison, and copy operations.
- Register/state serialization shows a simple restart model: persist compact numeric state, restore it deterministically, then resume from validated state.
- The Lua-T compiler enforces termination with an explicit halt instruction on all generated paths; QIHSE codecs should adopt the same attitude by enforcing bounded decode/scan loops and rejecting malformed encoded rows.
- The generated program tables keep opcode values explicit and stable; QIHSE should do the same for codec IDs, WAL record types, and manifest feature flags.

QIHSE should not port the Lua VM or its operational behavior. It should port the small, testable encoding and validation ideas into native C vector codecs.

Relevant Triton source roles:

- `triton.lua`: balanced trit math, K3 lookup tables, branchless trit selection, tryte packing.
- `triton_luac.lua`: compiler invariants, explicit opcode table, auto-termination pattern.
- `triton_brain.lua`: deterministic save/restore of compact state.
- `triton_brain_program.lua`: stable table-driven instruction representation.

Concrete QIHSE improvements to port:

- Use explicit numeric IDs for codecs and WAL records, mirroring Triton's stable opcode tables.
- Build compile-time LUTs for ternary operations instead of branching per dimension.
- Precompute packed-tryte decode and score tables at codec initialization.
- Persist codec parameters as a validated manifest blob with its own version and checksum.
- Encode queries once per search and reuse the encoded query for every row.
- Validate encoded rows with bounded loops derived from `dims` and `encoded_row_bytes`.
- Keep restart state compact: manifest generation, codec ID/version, codec parameter checksum, and committed row count are enough to reconstruct codec state.

### Trinary Vector Mode

Trinary encoding maps each vector dimension to one of three states:

- `-1`: negative contribution
- `0`: neutral or below threshold
- `+1`: positive contribution

Why it may fit QIHSE:

- It maps naturally to sign/phase-style vector behavior.
- It can reduce storage from `32 * dims` bits to roughly `2 * dims` bits before packing overhead.
- Similarity can use fast integer popcount-style kernels rather than full floating-point dot products.
- It gives QIHSE a path toward very large resident indexes with lower memory bandwidth pressure.

Proposed packed layout:

```text
trit_data: 5 trits per byte, tryte-packed
scale_data: optional per-row or per-block scale
threshold_data: optional per-database threshold parameters
```

The earlier 2-bit-per-dimension layout is simpler, but the Triton-style tryte layout is denser:

- 2-bit packing stores 4 trits per byte and wastes one representable state.
- Tryte packing stores 5 trits per byte and uses 243 of 256 byte values.
- 2-bit packing may be faster for SIMD prototypes.
- Tryte packing is the better file-backed storage candidate once encode/decode kernels are optimized.

Tryte row sizing:

```text
trytes_per_row = (dims + 4) / 5
padding_trits = (5 - (dims % 5)) % 5
padding value = 0
```

Valid packed bytes are `0..242`. Bytes `243..255` are invalid and should cause validation failure unless the row belongs to an uncommitted WAL record being rolled back.

Initial trinary encoding:

```text
value < -threshold -> -1
abs(value) <= threshold -> 0
value > threshold -> +1
```

Candidate similarity kernels:

- Trinary dot approximation: count matching signs, subtract opposite signs, ignore zeroes.
- Query-sign kernel: encode query to trinary at search time and compare packed trits.
- Hybrid rerank: use trinary search for candidate generation, then rerank top-K from stored `float32` sidecar vectors where configured.
- LUT kernel: precompute small score tables for packed trit groups and sum table results per row.
- Branchless mask kernel: use arithmetic masks for positive, neutral, and negative query states to avoid unpredictable branches.

The first trinary implementation should be optional and benchmarked against raw `float32`, not assumed superior.

Fast tryte scoring design:

```c
/* 243 valid tryte states. score[a][b] is the 5-trit dot contribution. */
int8_t qihse_tryte_score_lut[243][243];

/* 256 entries so invalid byte checks are branch-light. */
bool qihse_tryte_valid_lut[256];
int8_t qihse_tryte_decode_lut[243][5];
```

Search flow:

1. Encode the query once into packed trytes.
2. For each row, validate only if the database was not already validated on open.
3. Sum `qihse_tryte_score_lut[row_tryte][query_tryte]` for each tryte.
4. Apply optional row scale/norm correction.
5. Return candidates to exact rerank when `FLOAT32_TRINARY` mode is active.

Native C sketch for tryte packing:

```c
static uint8_t qihse_pack_5trits(const int8_t trits[5]) {
    uint32_t value = 0;
    uint32_t pow3 = 1;
    for (size_t i = 0; i < 5; i++) {
        uint32_t u = (uint32_t)(trits[i] + 1); /* -1,0,+1 -> 0,1,2 */
        value += u * pow3;
        pow3 *= 3;
    }
    return (uint8_t)value;
}

static void qihse_unpack_5trits(uint8_t byte, int8_t trits[5]) {
    uint32_t value = byte;
    for (size_t i = 0; i < 5; i++) {
        trits[i] = (int8_t)((value % 3) - 1);
        value /= 3;
    }
}
```

Native C sketch for branchless ternary selection:

```c
static float qihse_trit_select(int8_t trit, float pos, float zero, float neg) {
    float m_pos = (float)(trit * (trit + 1)) * 0.5f;
    float m_neg = (float)(trit * (trit - 1)) * 0.5f;
    float m_zero = 1.0f - (float)(trit * trit);
    return pos * m_pos + zero * m_zero + neg * m_neg;
}
```

### Encoding Modes

Support these database creation modes:

- `QIHSE_ENCODING_FLOAT32 = 0x00000001`: authoritative raw vectors, fastest to implement, baseline correctness.
- `QIHSE_ENCODING_FLOAT32_TRINARY_2BIT = 0x00010001`: raw vectors plus simple trinary sidecar for prototype kernels.
- `QIHSE_ENCODING_FLOAT32_TRINARY_TRYTE = 0x00010002`: raw vectors plus Triton-style tryte sidecar for candidate search and exact rerank.
- `QIHSE_ENCODING_TRINARY_TRYTE = 0x00010003`: packed trinary-only high-density mode.
- `QIHSE_ENCODING_INT8 = 0x00020001`: future quantized mode for hardware-friendly approximate search.

The hybrid `FLOAT32_TRINARY` mode is the safest experimental path: it lets QIHSE test trinary speed while preserving exact rerank and easy migration.

Hybrid sidecar rule:

- `vectors.qvec` remains authoritative for inserts, recovery, and exact rerank.
- `vectors.qtri` is a derived acceleration structure.
- If `vectors.qtri` is missing or fails validation, QIHSE can rebuild it from `vectors.qvec`.
- Pure trinary mode is allowed only when the manifest explicitly marks raw-vector recovery as unavailable.

### Codec Selection Recommendation

Build the experimental path in this order:

1. `FLOAT32` file-backed baseline.
2. `FLOAT32_TRINARY_2BIT` prototype for simple kernels and quick measurement.
3. `FLOAT32_TRINARY_TRYTE` storage codec based on the Triton 5-trit packing model.
4. Pure `TRINARY_TRYTE` only after recall, latency, and recovery behavior are proven.

That gives QIHSE room to experiment aggressively while keeping a reliable database path available at every step.

### Experimental Guardrails

- Experimental encodings must be selected explicitly at create time.
- The manifest must mark experimental encodings clearly.
- Open should fail with a clear error if the binary lacks the required codec.
- Tests must compare experimental search recall against `float32` baseline.
- Benchmarks must report ingest speed, disk size, open latency, search latency, and recall.
- Experimental files must remain recoverable through the same WAL and manifest rules as raw vectors.
- Codec decode loops must be bounded by manifest dimensions and encoded row byte length.
- Codec IDs and parameters must be explicit numeric values, not implicit enum ordering.
- Encoded rows must have validation tests equivalent to compiler "all paths halt" checks: malformed rows fail quickly and cannot produce unbounded scans.
- Tryte rows must reject invalid byte values `243..255`.
- Every codec must define whether it is authoritative storage or a rebuildable sidecar.
- Recall benchmarks must include both candidate recall before rerank and final recall after rerank.

## 16. Performance Strategy

The persistence work should be fast by construction, not just durable.

Immediate performance choices:

- Use contiguous vector pages sized for sequential writes and SIMD-friendly reads.
- Align vector rows to at least 64 bytes for CPU cache-line behavior.
- Prefer `pwrite` batching over many small writes.
- Batch WAL records for `add_vectors` calls while preserving commit boundaries.
- Separate metadata from vectors so search does not page in metadata unless requested.
- Keep index rows fixed-width for direct offset math and mmap search.
- Implement trinary scoring as portable scalar LUT summation first.
- Add AVX2/AVX-512 kernels only after scalar LUT correctness and recall are locked down.
- Validate `vectors.qtri` once at open/checkpoint time, then skip per-row validation on hot search paths.

Benchmark targets for the first usable release:

- Open existing `float32` file-backed DB without re-ingestion.
- Search reopened DB with no measurable correctness difference from in-memory mode.
- Ingest should be I/O-bound for large batches, not syscall-bound on per-vector writes.
- File-backed copy mode should be within a reasonable factor of current in-memory search.
- Mmap mode should reduce startup time for large indexes significantly versus full load.
- Hybrid trinary candidate generation should report candidate recall before exact rerank.
- Tryte sidecar size should be close to `ceil(dims / 5) * rows` plus header/alignment overhead.
- Sidecar rebuild from `vectors.qvec` should be measured separately from normal open latency.

## 17. Observability and Diagnostics

Expose native diagnostics so persistence failures are debuggable:

- Last persistence error code and message.
- Open mode: in-memory, file-backed copy, or file-backed mmap.
- Current committed generation.
- WAL bytes pending checkpoint.
- Live vector count and tombstone count.
- Vector file bytes, metadata file bytes, and index file bytes.
- Recovery action taken during open.
- Active codec ID/version and codec parameter checksum.
- Trinary sidecar status: absent, valid, rebuilt, stale, or corrupt.
- Sidecar rebuild time and rows rebuilt.
- Candidate recall and rerank recall in benchmark mode.

Add a C API such as:

```c
bool qihse_vector_db_get_persistence_stats(
    qihse_vector_db_t vdb,
    qihse_vector_db_persistence_stats_t* stats
);
```

## 18. Python Binding

After the native API is stable, extend `qihse/python/qihse.py`.

Python should expose:

- `open_vector_db(path, create=True, read_only=False, mmap=False)`
- `flush()`
- `checkpoint()`
- `compact()`
- `close()`

Python must not implement its own storage format. It should be a ctypes wrapper around the native file-backed database.

## 19. Implementation Phases

### Phase 1: Native File Abstraction and Format Headers

- Add internal file I/O helpers.
- Define file headers, manifest records, and validation helpers.
- Add checked arithmetic for all offset and size calculations.
- Define the vector codec registry with `float32` as the only required codec.
- Add unit tests for malformed headers and size overflow.

### Phase 2: File-Backed Copy Mode

- Make `db_path` create/open a directory-backed database.
- Persist vectors, metadata, and index rows during `add_vectors`.
- Load persisted data into UMA memory on open.
- Preserve current search behavior while fixing row-index vs vector-ID handling.

### Phase 3: WAL and Recovery

- Add WAL intent and commit records.
- Replay WAL on open.
- Add torn-write and crash-simulation tests.
- Add manifest generation validation.
- Add single-writer lock handling and read-only open behavior.

### Phase 4: Mapped Search

- Map vector and index files directly.
- Search over mapped vector pages where alignment and scalar type permit.
- Add fallback to copy mode when the platform does not support the mapping requirements.
- Add generation-stable read views so mapped readers are not invalidated by writer growth or compaction.

### Phase 5: Maintenance Operations

- Add checkpoint and compaction.
- Add read-only open.
- Add optional snapshot export for portable backups.
- Add format compatibility tests across release fixtures.
- Add persistence stats and diagnostic APIs.

### Phase 6: Experimental Encodings

- Add trinary codec behind an explicit create flag.
- Add packed trit storage and similarity kernels.
- Add hybrid `FLOAT32_TRINARY` mode for exact reranking.
- Add recall and performance benchmarks against raw `float32`.
- Keep the format recoverable through the same WAL and manifest path.

## 20. Verification

Native tests should cover:

- Create, close, reopen, and search a file-backed DB.
- Reopen with no explicit save call.
- Metadata bytes survive restart exactly.
- Vector IDs are preserved even when they are sparse or non-contiguous.
- Results before close match results after reopen.
- Read-only open can search but cannot mutate.
- Corrupt magic/version/header/manifest is rejected.
- Truncated vector, metadata, index, and WAL files are rejected.
- Simulated crash before manifest commit does not expose partial writes.
- Simulated crash after manifest commit recovers committed writes.
- `db_path == NULL` remains ephemeral.
- Concurrent read-only opens can search the same committed generation.
- Writer lock prevents two mutating processes from opening the same database.
- Sparse vector IDs do not corrupt metadata lookup.
- Compaction preserves live vector IDs and metadata.
- Experimental codec manifest entries reject opens when the codec is unavailable.
- Trinary or hybrid mode passes recovery tests and recall benchmarks before being marked usable.

Expected command path:

```bash
cmake --build build
ctest --test-dir build --output-on-failure
```

If this repository's current CMake setup does not register tests with CTest, add the persistence tests to the existing native test binary and document the exact binary invocation.

## 21. Acceptance Criteria

- `qihse_vector_db_create(..., db_path)` produces a durable database at `db_path`.
- A process can insert vectors, exit without an export step, reopen the same `db_path`, and search the existing vectors.
- Core persistence lives in native C, not Python.
- Python bindings use the native file-backed database.
- Corrupt or partial files fail cleanly without undefined behavior.
- Existing in-memory users are not forced to use disk persistence.
- The design supports broader `mmap` search without changing the public persistence contract.
- The implementation has an explicit recovery story for every persistent file.
- The on-disk format is versioned and suitable for compatibility fixtures in future releases.
- Experimental encodings can be added without weakening the durability contract.
- Trinary mode remains optional until benchmarks prove it is both fast and accurate enough for target workloads.

## 22. Post-PR-2 Continuation Plan

The plan no longer starts from an in-memory-only database. PR-0, PR-1, and PR-2 are implemented. Continue from the native QIHSE persistence layer that already has durable `db_path`, snapshot files, `idmap.qid`, derived `vectors.qtri`, read-only mmap for clean vector snapshots, ADD/COMMIT WAL records, previous-record offsets, committed-batch replay, and writable torn-tail truncation.

The remaining work should be split into focused native QIHSE PRs:

- PR-3: mmap/zero-copy extension for index, metadata, and ID-map files.
- PR-4: implement staged tombstone/delete/update/upsert APIs, mutation WAL records, batch semantics, and compaction.
- PR-5: native trinary codec module, scoring, candidate generation, exact rerank, recall benchmarks, and optional pure trinary storage.
- PR-6: persisted anchor hints and optimizer statistics as rebuildable sidecars.

Use a 3-agent split:

- Agent 1: PR-3 mmap extension.
- Agent 2: PR-5 trinary codec module and benchmarks.
- Agent 3: remaining PR-4/PR-5/PR-6 database semantics, compaction, and sidecars.

Historical PR-1 objective: make `db_path` actually durable.

Make this work:

qihse_vector_db_t db = qihse_vector_db_create(
    QIHSE_VECTOR_DB_INMEMORY,
    uma,
    "/tmp/my.qihse"
);

qihse_vector_db_add_vectors(db, vectors, n, dims, ids, metadata, metadata_sizes);
qihse_vector_db_destroy(db);

/* New process or same process later */
qihse_vector_db_t db2 = qihse_vector_db_create(
    QIHSE_VECTOR_DB_INMEMORY,
    uma,
    "/tmp/my.qihse"
);

qihse_vector_db_search(db2, &query, results, max_results);

No export step. No Python storage. No `.npz`. No JSON. WAL is now part of native QIHSE recovery and should be kept in the C persistence layer.

1. Add persistence as storage mode, not backend

Current backend enum mixes external systems like FAISS, Chroma, Qdrant, and in-memory, but implementation falls back to in-memory for non-native backends. File persistence should be a storage mode, not another backend.

Add to qihse/qihse_vector_db.h:

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

Then preserve existing API:

qihse_vector_db_t qihse_vector_db_create(
    qihse_vector_db_backend_t backend,
    qihse_uma_manager_t uma,
    const char* db_path
) {
    uint32_t flags = 0;

    if (db_path) {
        flags |= QIHSE_VDB_OPEN_CREATE | QIHSE_VDB_OPEN_FILE_BACKED;
    }

    return qihse_vector_db_open(backend, uma, db_path, flags);
}

db_path == NULL remains ephemeral. db_path != NULL becomes durable.

2. Fix sparse-ID search before writing disk code

This is the first real blocker.

Current search stores external IDs into results, then later uses results[i].id as an array index for vector/metadata lookup. That only works when external IDs are dense row indexes. It breaks for sparse caller IDs.

Add internal hit structure:

typedef struct qihse_vector_hit_s {
    uint64_t vector_id;   /* caller-visible ID */
    size_t row_index;     /* internal storage row */
    float score;
} qihse_vector_hit_t;

During search:

hits[found].vector_id = internal->rows[i].vector_id;
hits[found].row_index = i;
hits[found].score = similarity;
found++;

During hydration:

size_t row = hits[i].row_index;

results[i].id = hits[i].vector_id;
results[i].score = hits[i].score;
results[i].vector_dims = query->vector_dims;

if (query->include_vectors) {
    memcpy(results[i].vector,
           (char*)storage_ptr + internal->rows[row].vector_offset,
           query->vector_dims * sizeof(float));
}

if (query->include_metadata && internal->rows[row].metadata_size > 0) {
    memcpy(results[i].metadata,
           (char*)meta_ptr + internal->rows[row].metadata_offset,
           internal->rows[row].metadata_size);
}

This also prepares the disk index format, because disk rows will use row slot as internal identity and vector_id as caller-visible identity.

3. Replace parallel arrays with canonical row table

Current internal state has parallel arrays:

uint64_t* vector_ids;
size_t* vector_offsets;
size_t* metadata_offsets;
size_t* metadata_sizes;

That is fragile once persistence exists. Use one canonical row table.

Add:

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

Then internal DB state becomes:

typedef struct qihse_vector_db_internal_s {
    qihse_vector_db_backend_t backend;
    qihse_vector_db_storage_mode_t storage_mode;
    qihse_uma_manager_t uma_manager;

    char* db_path;
    bool read_only;
    bool dirty;

    size_t vector_dims;
    size_t vector_row_bytes;
    size_t total_vectors;
    size_t live_vectors;
    size_t max_vectors;

    uint64_t committed_generation;

    qihse_uma_address_t* vector_storage;
    qihse_uma_address_t* metadata_storage;

    qihse_index_row_t* rows;
    size_t rows_capacity;

    uint64_t vector_bytes_used;
    uint64_t metadata_bytes_used;

    int lock_fd;
    int manifest_fd;
    int vectors_fd;
    int metadata_fd;
    int index_fd;

    bool hilbert_enabled;
    bool quantization_enabled;
    bool parallel_enabled;

    bool superposition_enabled;
    qihse_memory_superposition_state_t superposition_state;

    double avg_search_time_ms;
    double preload_hit_rate;
    double memory_efficiency;

    qihse_uma_address_t** preloaded_vectors;
    size_t preloaded_count;
    size_t max_preloaded;
} qihse_vector_db_internal_t;

Keep compatibility arrays only temporarily if needed, but do not make them authoritative.

4. Add actual persistence files

Add:

qihse/persistence/qihse_file.h
qihse/persistence/qihse_file_posix.c
qihse/persistence/qihse_persist_format.h
qihse/persistence/qihse_persist_format.c
qihse/persistence/qihse_vector_store.h
qihse/persistence/qihse_vector_store.c
qihse/tests/qihse_vector_db_persistence_test.c

Update qihse/Makefile. The repo currently builds libqihse.so from an explicit SRCS_BASE, so new .c files must be listed there.

Example:

SRCS_BASE=core/qihse.c qihse_search.c qihse_math.c qihse_instr.c qihse_hetero.c \
     qihse_vector_db.c qihse_exports.c \
     persistence/qihse_file_posix.c \
     persistence/qihse_persist_format.c \
     persistence/qihse_vector_store.c \
     core/qihse_helpers.c core/qihse_plugin.c \
     ...

Do not hide missing persistence symbols inside qihse_exports.c. That file currently provides stub/missing symbols for wrapper expectations, not real database logic.

5. Landed PR-1/PR-2 disk layout

The implemented layout includes authoritative float32 vectors, metadata, row index, ID map, WAL, and a derived trinary sidecar:

<db_path>/
  MANIFEST
  vectors.qvec
  vectors.qtri
  metadata.qmeta
  index.qidx
  idmap.qid
  wal.qwal
  LOCK

`vectors.qvec`, `metadata.qmeta`, and `index.qidx` are authoritative. `idmap.qid` and `vectors.qtri` are rebuildable sidecars. `wal.qwal` is authoritative only for committed batches newer than the snapshot generation.

6. File format for PR-1

Use explicit little-endian encoding. Do not write native C structs directly as disk format.

Common header
#define QIHSE_VDB_FORMAT_VERSION 1u

#define QIHSE_MANIFEST_MAGIC "QHMANF1"
#define QIHSE_VECTOR_MAGIC   "QHVEC01"
#define QIHSE_META_MAGIC     "QHMETA1"
#define QIHSE_INDEX_MAGIC    "QHIDX01"

typedef struct qihse_file_header_s {
    uint8_t  magic[8];
    uint32_t format_version;
    uint32_t header_size;
    uint64_t generation;
    uint64_t logical_size;
    uint64_t payload_crc64;
    uint8_t  reserved[32];
} qihse_file_header_t;

But on disk, encode manually:

bool qihse_write_u32le(uint8_t* p, size_t n, uint32_t v);
bool qihse_write_u64le(uint8_t* p, size_t n, uint64_t v);
bool qihse_read_u32le(const uint8_t* p, size_t n, uint32_t* out);
bool qihse_read_u64le(const uint8_t* p, size_t n, uint64_t* out);
Manifest record
typedef struct qihse_manifest_s {
    uint8_t db_uuid[16];

    uint32_t format_version;
    uint32_t manifest_version;

    uint64_t generation;

    uint64_t vector_dims;
    uint64_t vector_row_bytes;
    uint64_t total_vectors;
    uint64_t live_vectors;

    uint64_t vector_bytes_used;
    uint64_t metadata_bytes_used;
    uint64_t index_rows_used;

    uint32_t scalar_type;      /* float32 initially */
    uint32_t distance_metric;  /* cosine initially */
    uint32_t storage_mode;     /* copy or mmap */
    uint32_t feature_flags;

    uint64_t vectors_crc64;
    uint64_t metadata_crc64;
    uint64_t index_crc64;
} qihse_manifest_t;
7. Manifest and snapshot flush

The snapshot path should keep generation-stamped manifest validation so torn manifest writes are rejected or bypassed.

MANIFEST:
  slot0
  slot1

Each slot includes:

magic
format_version
generation
manifest_payload
payload_crc64
slot_crc64

Open logic:

1. Read slot0.
2. Read slot1.
3. Validate magic/version/checksum.
4. Select highest valid generation.
5. Validate file sizes against manifest.
6. Load vectors/metadata/index.

Flush logic:

1. Write vectors.qvec.tmp.
2. Write metadata.qmeta.tmp.
3. Write index.qidx.tmp.
4. fsync all tmp files.
5. rename tmp files into place.
6. write inactive manifest slot with generation + 1.
7. fsync MANIFEST.
8. fsync db directory.
9. dirty = false.

This gives atomic snapshot behavior alongside WAL recovery for committed batches not yet checkpointed into the snapshot.

8. File-backed copy mode first

The current UMA API owns heap-like allocations and exposes qihse_uma_allocate, qihse_uma_free, qihse_uma_access, and related memory functions. Do not force mmap into that model yet.

PR-1 open path:

1. Open db directory.
2. Read valid manifest.
3. Read index rows into internal->rows.
4. Allocate UMA vector buffer.
5. Read vectors.qvec payload into UMA buffer.
6. Allocate UMA metadata buffer.
7. Read metadata.qmeta payload into UMA buffer.
8. Set total_vectors/live_vectors/vector_dims/bytes_used.
9. Search normally using UMA access.

PR-1 write path:

1. Validate input.
2. Reject mutation if read_only.
3. Set vector_dims on first insert.
4. Enforce dims on later inserts.
5. Grow rows[].
6. Grow UMA vector buffer.
7. Grow UMA metadata buffer.
8. Copy vector bytes into UMA vector buffer.
9. Copy metadata bytes into UMA metadata buffer.
10. Fill qihse_index_row_t.
11. Mark dirty.

Write to disk only on flush()/close() for PR-1.

9. Add checked arithmetic before offsets

Add helpers:

static bool qihse_checked_mul_size(size_t a, size_t b, size_t* out) {
    if (a != 0 && b > SIZE_MAX / a) return false;
    *out = a * b;
    return true;
}

static bool qihse_checked_add_size(size_t a, size_t b, size_t* out) {
    if (b > SIZE_MAX - a) return false;
    *out = a + b;
    return true;
}

Use for:

vector_dims * sizeof(float)
num_vectors * vector_row_bytes
total_vectors + num_vectors
row_index * vector_row_bytes
metadata_offset + metadata_size
header_size + payload_size

This prevents malformed files and large ingests from corrupting offset math.

PR-1 test plan

Add qihse/tests/qihse_vector_db_persistence_test.c.

Required tests
1. Create → insert → close → reopen → search
/* Create */
db = qihse_vector_db_create(QIHSE_VECTOR_DB_INMEMORY, uma, tmp_path);

/* Insert */
qihse_vector_db_add_vectors(db, vectors, 3, dims, ids, metadata, metadata_sizes);

/* Close */
qihse_vector_db_close(db);

/* Reopen */
db2 = qihse_vector_db_create(QIHSE_VECTOR_DB_INMEMORY, uma, tmp_path);

/* Search */
n = qihse_vector_db_search(db2, &query, results, 3);

assert(n > 0);
assert(results[0].id == expected_id);
2. Sparse IDs
ids[0] = 42;
ids[1] = 999999;
ids[2] = 123456789;

Expected:

result.id == 999999
result.vector == original row 1 vector
result.metadata == original row 1 metadata
3. Metadata exact survival

Use binary metadata, not strings only:

uint8_t meta0[] = {0x00, 0x01, 0xff, 0x7f};

Expected after reopen:

memcmp(result.metadata, meta0, sizeof(meta0)) == 0
4. db_path == NULL stays ephemeral
db = qihse_vector_db_create(QIHSE_VECTOR_DB_INMEMORY, uma, NULL);

Expected:

no directory created
no persistence files created
search works in-process
5. Corrupt header rejected

Mutate vectors.qvec magic.

Expected:

open returns NULL or explicit error
no undefined behavior
6. Truncated index rejected

Truncate index.qidx mid-row.

Expected:

open fails cleanly
7. Read-only open blocks mutation
db = qihse_vector_db_open(
    QIHSE_VECTOR_DB_INMEMORY,
    uma,
    tmp_path,
    QIHSE_VDB_OPEN_READ_ONLY | QIHSE_VDB_OPEN_FILE_BACKED
);

Expected:

qihse_vector_db_search(...) works
qihse_vector_db_add_vectors(...) == false
Makefile test target

Because the repo currently uses a Makefile path rather than a visible CTest setup, add this first:

.PHONY: test-persist

test-persist: lib
	$(CC) $(CFLAGS) -o tests/qihse_vector_db_persistence_test \
	    tests/qihse_vector_db_persistence_test.c \
	    -L. -lqihse $(LDFLAGS)
	LD_LIBRARY_PATH=. ./tests/qihse_vector_db_persistence_test

Expected developer command:

cd qihse
make clean
make
make test-persist

PR-2: WAL and crash recovery.

Status: implemented after PR-1. The WAL now has ADD and COMMIT records, previous-record offsets, committed-batch replay, and writable torn-tail truncation.

Implemented file: `wal.qwal`.

WAL record header:
typedef enum qihse_wal_record_type_e {
    QIHSE_WAL_BEGIN_ADD_BATCH = 1,
    QIHSE_WAL_VECTOR_BYTES    = 2,
    QIHSE_WAL_METADATA_BYTES  = 3,
    QIHSE_WAL_INDEX_ROWS      = 4,
    QIHSE_WAL_COMMIT_BATCH    = 5,
    QIHSE_WAL_CHECKPOINT      = 6
} qihse_wal_record_type_t;

typedef struct qihse_wal_record_header_s {
    uint32_t magic;
    uint16_t version;
    uint16_t type;
    uint64_t generation;
    uint64_t prev_record_offset;
    uint64_t payload_size;
    uint64_t payload_crc64;
    uint64_t header_crc64;
} qihse_wal_record_header_t;
WAL write path
1. Write the ADD payload record for the accepted batch.
2. fsync `wal.qwal`.
3. Write the COMMIT record that seals the batch.
4. fsync `wal.qwal`.
5. Apply the accepted mutation to the in-memory view.
6. Publish data files on flush/checkpoint and clear checkpointed WAL bytes.
WAL recovery path
1. Load highest valid manifest slot.
2. Scan WAL forward from manifest generation.
3. Stop at first invalid/torn record.
4. Replay only batches with valid COMMIT_BATCH.
5. Ignore incomplete tail on read-only open.
6. Truncate incomplete tail on writable open.

Crash tests:

crash before COMMIT_BATCH -> no new vectors visible
crash after COMMIT_BATCH before manifest -> vectors recovered
crash during manifest write -> older valid manifest slot used
crash during checkpoint -> old data + WAL still recoverable
PR-3: mmap mode

Continue here after PR-2.

Add UMA allocation kind. Current UMA address type has pointer, size, device, and residency metadata, but no allocation kind or file mapping ownership.

Extend:

typedef enum qihse_uma_allocation_kind_e {
    QIHSE_UMA_ALLOC_HEAP = 0,
    QIHSE_UMA_ALLOC_MMAP = 1,
    QIHSE_UMA_ALLOC_EXTERNAL = 2
} qihse_uma_allocation_kind_t;

Add fields to qihse_uma_address_t:

qihse_uma_allocation_kind_t allocation_kind;
int backing_fd;
uint64_t backing_offset;
void* mapping_base;
size_t mapping_size;

Update free logic:

switch (address->allocation_kind) {
    case QIHSE_UMA_ALLOC_HEAP:
        free(address->ptr);
        break;

    case QIHSE_UMA_ALLOC_MMAP:
        munmap(address->mapping_base, address->mapping_size);
        close(address->backing_fd);
        break;

    case QIHSE_UMA_ALLOC_EXTERNAL:
        break;
}

Then add:

qihse_uma_address_t* qihse_uma_wrap_mmap(
    qihse_uma_manager_t uma,
    int fd,
    uint64_t offset,
    size_t size,
    int prot
);

Search should support:

FILE_BACKED_COPY  -> current UMA copy path
FILE_BACKED_MMAP  -> mapped vectors/index/metadata
Trinary continues as a post-PR-2 codec path

The trinary direction is useful, and the derived `vectors.qtri` sidecar now has an on-disk home. The next step is making it a native codec module with scoring and benchmarks, not making it authoritative by default.

Correct order:

1. FLOAT32 durable file-backed copy mode
2. Sparse-ID correctness
3. Two-slot manifest
4. Reopen/search tests
5. WAL/recovery
6. mmap
7. FLOAT32_TRINARY sidecar
8. Pure TRINARY only after recall benchmarks

When trinary lands, use hybrid first:

vectors.qvec = authoritative float32
vectors.qtri = rebuildable acceleration sidecar

If vectors.qtri is corrupt or missing:

open DB
mark sidecar stale
rebuild from vectors.qvec
continue

Do not make trinary authoritative until exact recall/latency/recovery tests exist.

Python binding comes last

Current Python wrapper loads libqihse.so and exposes only basic metadata/search calls through ctypes.

After native PR-1/PR-2 are stable, add:

class QIHSEVectorDB:
    def __init__(self, path, create=True, read_only=False, mmap=False):
        ...

    def add_vectors(self, vectors, ids=None, metadata=None):
        ...

    def search(self, query, top_k=10, include_vectors=False, include_metadata=False):
        ...

    def flush(self):
        ...

    def checkpoint(self):
        ...

    def compact(self):
        ...

    def close(self):
        ...

Python must remain a wrapper. Native C owns storage.

Final build sequence
Step 1
cd qihse
mkdir -p persistence tests
Step 2

Add files:

persistence/qihse_file.h
persistence/qihse_file_posix.c
persistence/qihse_persist_format.h
persistence/qihse_persist_format.c
persistence/qihse_vector_store.h
persistence/qihse_vector_store.c
tests/qihse_vector_db_persistence_test.c
Step 3

Patch:

qihse_vector_db.h
qihse_vector_db.c
Makefile
Step 4

Build:

make clean
make
Step 5

Run persistence test:

make test-persist
Done means

PR-1 is complete only when all of these are true:

qihse_vector_db_create(..., db_path) creates durable files
insert -> close -> reopen -> search works
sparse external IDs do not break vector/metadata hydration
metadata survives restart byte-for-byte
db_path == NULL remains in-memory only
corrupt magic fails open
truncated index fails open
read-only open can search but cannot mutate
Python has not implemented storage
WAL/mmap/trinary are not mixed into PR-1

This is the shortest path to real QIHSE persistence without burying the work under generalized database architecture.
SITREP

not_stisla should be incorporated, but not as a replacement for QIHSE vector similarity. It is a sorted int64_t search accelerator: anchor-based interpolation, bounded anchor learning, SIMD paths, batch search, huge-page hints, and workload-specific tuning. That maps directly to persistent ID/offset/generation indexes, not to raw high-dimensional vector scoring.

The native persistence plan remains valid: db_path becomes a real directory-backed database with manifest, vectors, metadata, index, WAL, and recovery semantics. The change is that not_stisla becomes the acceleration layer for ordered scalar indexes inside that database.

Important current-state finding: QIHSE now builds NOT_STISLA-derived anchor search directly as qihse/algorithms/qihse_anchor_search.c, but the QIHSE hybrid path still prints that not_stisla_search is stubbed and returns NOT_STISLA_NOT_FOUND. That is the first integration bug to fix.

Core decision
Incorporate not_stisla into persistence as:
1. vector_id -> row_index accelerator
2. metadata_offset lookup accelerator
3. WAL generation / commit-generation lookup helper
4. batch external-ID lookup path
5. optional telemetry/event/timestamp secondary-index engine
Do not incorporate it as:
1. primary vector similarity engine
2. replacement for cosine/L2/dot-product search
3. replacement for trinary/quantized vector codecs
4. authoritative persistence format
5. mandatory dependency for database correctness

Reason: not_stisla_search() works on sorted int64_t arrays. The API is explicitly built around sorted int64_t search, anchor tables, tolerance windows, batch items, and workload-specific integer/timestamp/offset searches. QIHSE vector search still needs row-index-correct vector scoring over float32, mmap, trinary sidecars, or future ANN structures.

Revised persistence plan
PR-0: fix current not_stisla integration before persistence work

This is now a prerequisite.

Problem

not_stisla is present and linked into the QIHSE build, but QIHSE’s hybrid path still has a stubbed call path:

printf("INFO: Stubbing call to not_stisla_search as its definition is missing.\n");
r.anchor_result = NOT_STISLA_NOT_FOUND;

That means the repo has build-level inclusion, but not reliable runtime integration.

Patch

In qihse/qihse_search.c, replace the stub with a real call for QIHSE_TYPE_INT64:

#include "qihse_anchor_search.h"

qihse_hybrid_result_t qihse_execute_hybrid_search(
    const void* data,
    size_t n,
    const void* query,
    not_stisla_anchor_table_t* table,
    const qihse_config_t* config
) {
    qihse_hybrid_result_t r = {0};
    r.used_hybrid = true;

    r.quantum_result = qihse_search(data, n, query, table, config);

    r.anchor_result = NOT_STISLA_NOT_FOUND;

    if (data && query && table && config && config->data_type == QIHSE_TYPE_INT64) {
        const int64_t key = *(const int64_t*)query;
        const size_t tol = config->anchor_config.tolerance
            ? config->anchor_config.tolerance
            : 8;

        r.anchor_result = not_stisla_search(
            (const int64_t*)data,
            n,
            key,
            table,
            tol
        );
    }

    if (r.quantum_result != NOT_STISLA_NOT_FOUND &&
        r.anchor_result != NOT_STISLA_NOT_FOUND) {
        r.final_result = r.quantum_result;
        r.final_confidence = (r.quantum_result == r.anchor_result) ? 0.95 : 0.70;
    } else if (r.quantum_result != NOT_STISLA_NOT_FOUND) {
        r.final_result = r.quantum_result;
        r.final_confidence = 0.80;
    } else if (r.anchor_result != NOT_STISLA_NOT_FOUND) {
        r.final_result = r.anchor_result;
        r.final_confidence = 0.75;
    } else {
        r.final_result = NOT_STISLA_NOT_FOUND;
        r.final_confidence = 0.0;
    }

    return r;
}

Also remove the stub print entirely. A core search path must not print during normal operation.

Build validation
cd qihse
grep -R "Stubbing call to not_stisla_search" -n .
make clean
make
nm -D libqihse.so | grep -E "not_stisla_search|qihse_execute_hybrid_search"

Expected:

grep returns nothing
libqihse.so exports or contains not_stisla_search linkage
qihse_execute_hybrid_search no longer hardcodes NOT_FOUND
PR-1 change: add persistent ID-map support

The previous PR-1 durable snapshot plan should now add a derived scalar index:

<db_path>/
  MANIFEST
  vectors.qvec
  metadata.qmeta
  index.qidx
  idmap.qid       <-- new derived native anchor-search lookup file
  LOCK

idmap.qid is not the authoritative source of truth. index.qidx remains authoritative. idmap.qid is a rebuildable acceleration sidecar.

Why this matters

The earlier persistence plan already required fixing sparse external IDs because vector result IDs must not be reused as row indexes. not_stisla gives QIHSE a fast native path for the missing reverse lookup:

external vector_id -> internal row_index

This supports:

dedupe before insert
future upsert
future delete/tombstone
get-by-id
metadata-by-id
batch ID lookup
WAL replay validation
compaction remapping
ID map format
Disk row
typedef struct qihse_idmap_row_disk_s {
    int64_t  sortable_key;       /* transformed uint64 vector_id */
    uint64_t vector_id;          /* caller-visible original ID */
    uint64_t row_index;          /* internal row in index.qidx */
    uint64_t commit_generation;
    uint32_t row_flags;
    uint32_t reserved;
} qihse_idmap_row_disk_t;
In-memory accelerator
typedef struct qihse_idmap_s {
    int64_t*  keys;              /* sorted transformed IDs */
    uint64_t* row_indices;       /* parallel row indexes */
    size_t    count;
    size_t    capacity;

    not_stisla_anchor_table_t* anchors;
    bool dirty;
    uint64_t generation;
} qihse_idmap_t;
Add to vector DB internals
typedef struct qihse_vector_db_internal_s {
    ...
    qihse_index_row_t* rows;
    size_t rows_capacity;

    qihse_idmap_t idmap;

    bool idmap_enabled;
    bool idmap_valid;
    ...
} qihse_vector_db_internal_t;
Correct uint64_t handling

not_stisla searches int64_t, but QIHSE vector IDs are uint64_t. Do not cast blindly. Use an order-preserving transform:

static inline int64_t qihse_u64_to_sortable_i64(uint64_t id) {
    return (int64_t)(id ^ 0x8000000000000000ULL);
}

static inline uint64_t qihse_sortable_i64_to_u64(int64_t key) {
    return ((uint64_t)key) ^ 0x8000000000000000ULL;
}

This preserves unsigned ordering under signed comparison.

Test it with:

0
1
42
UINT64_MAX / 2
UINT64_MAX

Expected sorted unsigned order must match sorted transformed signed order.

ID lookup path
bool qihse_vector_db_find_row_by_id(
    qihse_vector_db_t vdb,
    uint64_t vector_id,
    size_t* out_row
) {
    qihse_vector_db_internal_t* db = (qihse_vector_db_internal_t*)vdb;
    if (!db || !out_row || !db->idmap_valid) return false;

    int64_t key = qihse_u64_to_sortable_i64(vector_id);

    not_stisla_result_t pos = not_stisla_search(
        db->idmap.keys,
        db->idmap.count,
        key,
        db->idmap.anchors,
        8
    );

    if (pos == NOT_STISLA_NOT_FOUND) return false;

    *out_row = (size_t)db->idmap.row_indices[pos];
    return true;
}

This gives QIHSE a native fast path for sparse ID lookup while keeping the row table authoritative.

ID map build/rebuild
On flush/checkpoint
1. Allocate temporary idmap rows.
2. Walk index.qidx rows.
3. Include only live rows.
4. Convert vector_id -> sortable_key.
5. Sort by sortable_key.
6. Reject duplicate vector_id unless explicit upsert mode is enabled.
7. Write idmap.qid.tmp.
8. fsync idmap.qid.tmp.
9. rename to idmap.qid.
10. Mark idmap generation equal to manifest generation.
On open
1. Load MANIFEST.
2. Load authoritative index.qidx.
3. Try loading idmap.qid.
4. Validate header, generation, row count, checksum, sorted order.
5. If valid: use it.
6. If missing/corrupt/stale: rebuild from index.qidx.
7. Do not fail database open solely because idmap.qid is bad.

idmap.qid is derived. Corruption should cost rebuild time, not data loss.

PR-1 search behavior remains unchanged

For normal vector similarity search:

query vector -> scan/search vectors -> internal row hits -> hydrate result.id from rows[row].vector_id

Do not call not_stisla inside the hot vector similarity loop. It is not useful there.

For ID-oriented operations:

external vector_id -> not_stisla idmap lookup -> row_index -> vector/metadata/index row

That distinction keeps the design clean.

PR-1.5: add batch external-ID API

not_stisla already has batch-search support through not_stisla_batch_item_t and not_stisla_search_batch(). Use that for QIHSE batch ID operations.

Add:

size_t qihse_vector_db_get_rows_by_ids(
    qihse_vector_db_t vdb,
    const uint64_t* vector_ids,
    size_t count,
    size_t* out_rows,
    uint8_t* out_found
);

Implementation:

1. Convert vector_ids[] to sortable int64 keys.
2. Fill not_stisla_batch_item_t array.
3. Call not_stisla_search_batch() against idmap.keys.
4. Translate returned positions into row_indices.
5. Preserve caller order.

Use cases:

metadata fetch for many IDs
delete/tombstone batch
upsert conflict check
post-search hydration by external ID
future sparse vector joins
PR-2 WAL/recovery change

Do not WAL-log anchor tables.

Do not WAL-log idmap.qid as an authoritative file.

Instead:

WAL commits index.qidx rows.
idmap.qid is rebuilt from committed index.qidx after recovery.

Add manifest fields:

uint64_t idmap_generation;
uint64_t idmap_rows;
uint64_t idmap_crc64;
uint32_t idmap_flags; /* valid, stale, rebuilt, disabled */

Recovery path:

1. Recover authoritative vectors/metadata/index.
2. Validate manifest generation.
3. Validate idmap generation.
4. If idmap generation != index generation, rebuild.
5. If idmap checksum fails, rebuild.
6. If rebuild fails, DB can still open but ID lookup API reports unavailable.

This gives crash safety without coupling correctness to an adaptive search cache.

PR-3 mmap change

Map these as separate read-optimized arrays:

vectors.qvec
metadata.qmeta
index.qidx
idmap.qid

For idmap.qid, the mmap representation should expose:

const int64_t*  id_keys;
const uint64_t* id_rows;

Then not_stisla_search() can run directly over the mapped id_keys array.

Also use huge-page hints only where they make sense:

if (idmap_bytes >= 1024 * 1024) {
    madvise((void*)id_keys, idmap_bytes, MADV_HUGEPAGE);
    madvise((void*)id_keys, idmap_bytes, MADV_SEQUENTIAL);
}

not_stisla already includes a huge-page optimization helper for large arrays. For QIHSE, wrap that logic in the persistence file abstraction instead of calling it ad hoc from random paths.

PR-4 optional: persisted anchor sidecar

Only after ID map correctness and mmap are stable.

Optional file:

anchors.qanc

Purpose:

Persist learned not_stisla anchor hints for faster warm startup.

Rules:

anchors.qanc is never authoritative
missing anchors.qanc is fine
corrupt anchors.qanc is ignored
anchor generation must match idmap generation
anchor count must be bounded
anchors must be sorted and within idmap bounds

Do not put this in PR-1. Anchor learning is performance state, not database state.

Code hardening required before relying on not_stisla
1. Remove QIHSE stub

Already covered above. This is mandatory.

2. Do not enable OpenMP parallel path until clone is fixed

not_stisla_search_parallel() references not_stisla_anchor_table_clone(), but the clone implementation is inside #if 0. If _OPENMP is enabled, that path can break or need restoration.

Patch:

static not_stisla_anchor_table_t*
not_stisla_anchor_table_clone(const not_stisla_anchor_table_t* table)
{
    ...
}

Then test with:

make CFLAGS_EXTRA="-fopenmp"

Until that is fixed, use not_stisla_search_batch() without OpenMP for QIHSE persistence.

3. Avoid approximate anchor/quantum paths in persistence

The QIHSE native anchor-search compatibility path does exact sorted-key lookup. Quantum-enhanced or adaptive search paths add projection/fallback behavior and are not appropriate for deterministic persistence lookup. The persistence layer should use:

not_stisla_search()
not_stisla_search_batch()
not_stisla_anchor_table_create()
not_stisla_anchor_table_destroy()
not_stisla_anchor_table_get_stats()

Do not use:

quantum-enhanced anchor search
adaptive anchor search
approximate projection search

The quantum header defines local Hilbert-space constants and quantum-classical modes, but the persistence ID map needs exact deterministic sorted-key lookup, not approximate projection.

4. Make CPU detection one-time and thread-safe

The native QIHSE anchor-search module uses signal-based runtime CPU feature detection with a global jmp_buf. For QIHSE database code, call detection at process/library initialization or wrap it with pthread_once.

Add:

static pthread_once_t qihse_not_stisla_cpu_once = PTHREAD_ONCE_INIT;
static uint32_t qihse_not_stisla_cpu_features = 0;

static void qihse_not_stisla_detect_once(void) {
    qihse_not_stisla_cpu_features = not_stisla_detect_cpu_features();
}

Then:

pthread_once(&qihse_not_stisla_cpu_once, qihse_not_stisla_detect_once);
5. Do not copy native optimization-db persistence

qihse_save_optimization_db() currently writes native fields and structs directly with fwrite(). That is not acceptable for the new database persistence format. If optimization stats are persisted, define optimizer.qopt with explicit little-endian fields and checksums.

Updated file layout
PR-1 durable copy mode
<db_path>/
  MANIFEST
  vectors.qvec
  metadata.qmeta
  index.qidx
  idmap.qid
  LOCK
PR-2 WAL
<db_path>/
  MANIFEST
  vectors.qvec
  metadata.qmeta
  index.qidx
  idmap.qid
  wal.qwal
  LOCK
PR-3 mmap

Same files, but mapped:

vectors.qvec  -> vector scan/search
index.qidx    -> row table
metadata.qmeta -> lazy metadata hydration
idmap.qid     -> native anchor-search ID lookup
Later optional files
anchors.qanc      derived native anchor-search hints
vectors.qtri      derived trinary sidecar
optimizer.qopt    explicit-format optimization stats
Build plan update

Current Makefile builds algorithms/qihse_anchor_search.c directly as part of QIHSE.

Keep `algorithms/qihse_anchor_search.c` in the normal QIHSE source list. It is now native QIHSE algorithm code, not an optional sibling subsystem.

Build commands:

cd qihse
make clean
make
make QIHSE_ENABLE_AVX2=1
make QIHSE_ENABLE_AVX512=1

Do not make AVX2/AVX-512 required. Runtime feature detection and scalar fallback must remain valid.

Persistence tests to add
1. Sparse ID map survives restart
IDs:
42
999999
123456789
9223372036854775808
18446744073709551615

Expected:

insert -> flush -> close -> reopen
find_row_by_id(id) returns correct row
metadata for each ID matches original bytes
2. Duplicate ID behavior

Pick one policy:

reject duplicate vector_id

or:

upsert replaces old row with tombstone + new live row

For PR-1, choose rejection.

Expected:

second insert of same vector_id fails cleanly
idmap remains sorted
row table unchanged
3. Corrupt idmap.qid rebuilds

Test:

printf '\x00' | dd of="$DB/idmap.qid" bs=1 seek=0 count=1 conv=notrunc

Expected:

open succeeds
idmap is rebuilt from index.qidx
stats.idmap_rebuilt == true
search correctness unchanged
4. Stale generation rebuilds

Expected:

manifest generation > idmap generation
open marks idmap stale
rebuild happens
id lookup works
5. Batch lookup preserves caller order

Input:

[999999, 42, UINT64_MAX, missing_id]

Expected:

out_found = [1, 1, 1, 0]
out_rows correspond to original requested order
6. Vector similarity does not call ID map

Expected:

normal vector search works even with idmap disabled
idmap corruption does not affect vector search
7. Stub removal test
grep -R "Stubbing call to not_stisla_search" -n qihse

Expected:

no output
Benchmark targets

Use the repo’s own benchmark numbers as a reference, not as a guaranteed persistence result. One benchmark report shows not_stisla_search at about 7.98 ns/op versus binary search at 44.97 ns/op on a 1,000,000-element sorted int64_t dataset, with batch parallel at 6.48 ns/op. Another benchmark file has smaller measured gains for several array sizes and several “expected” large-array values, so QIHSE should benchmark its own ID-map workload rather than assume the largest advertised number.

Minimum QIHSE-specific benchmark:

Dataset:
1M live vector IDs
sparse uint64 IDs
random in-array lookups
random missing lookups
batch lookup sizes: 1, 8, 64, 1024

Compare:
linear scan
binary search
not_stisla_search
not_stisla_search_batch

Acceptance:

not_stisla single lookup faster than binary search after warmup
batch path faster than repeated single lookup
no correctness mismatch
no measurable vector-search regression
Updated phase order
Phase 0: real NOT_STISLA integration
remove QIHSE stub
make build flag explicit
add direct hybrid call for int64
avoid quantum path for persistence
add not_stisla unit tests to QIHSE test target
Phase 1: durable copy mode
MANIFEST
vectors.qvec
metadata.qmeta
index.qidx
idmap.qid as derived sidecar
row-index/result-ID fix
sparse ID tests
Phase 2: WAL/recovery
WAL protects authoritative files
idmap rebuilt after recovery
no WAL dependency on anchor tables
Phase 3: mmap
mmap vectors/index/metadata/idmap
not_stisla search over mapped id keys
huge-page hints through QIHSE file abstraction
Phase 4: maintenance
checkpoint
compact
rebuild idmap after compaction
batch external-ID APIs
persistence stats
Phase 5: experimental encodings
trinary sidecar
float32+trinary hybrid rerank
codec registry
recall benchmarks
Phase 6: optional learned sidecars
anchors.qanc
optimizer.qopt
generation-bound, checksum-protected, rebuildable
Final acceptance criteria update

Add these to the previous “done means” list:

QIHSE no longer stubs not_stisla_search
libqihse builds with native anchor search in qihse/algorithms
idmap.qid is generated from index.qidx
idmap.qid corruption does not prevent DB open
vector_id -> row_index lookup works for sparse uint64 IDs
duplicate vector IDs are rejected or handled by explicit upsert policy
batch ID lookup preserves caller order
normal vector search does not depend on idmap.qid
WAL recovery rebuilds idmap from authoritative index rows
mmap mode can search mapped id keys through native anchor search
anchor hints remain non-authoritative
approximate or quantum-enhanced search paths are not used for persistence lookup

This gives native anchor search a concrete role in the persistence architecture: fast scalar indexes for durable QIHSE, while keeping vector storage, recovery, and codec correctness under QIHSE’s own file-backed database contract.
