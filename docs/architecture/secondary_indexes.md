# QIHSE Secondary Index Architecture

> **Status: partial.** The B+ tree, hash index, index manager and index-scan
> executor all have real implementations under `src/frieze/` and
> `src/tractable/`, and `tests/test_indexes.c` (run via `make test-indexes`)
> exercises them. The API listings below have been corrected against
> `include/qihse_btree.h`, `include/qihse_hash_index.h`,
> `include/qihse_index_manager.h` and `include/qihse_index_scan.h`; the previous
> revision of this document listed function names that do not exist anywhere in
> the tree.
>
> Known limits, stated rather than glossed over:
>
> 1. **Key encoding is not uniform.** A single-column `INT64` *hash* index is
>    keyed by the raw eight bytes of the value, while every other index is keyed
>    by the sortable serialization from `qihse_btree_serialize_key()`. The scan
>    executor passes the key straight through, so an equality scan on an int64
>    hash index only matches when the caller supplies the raw key.
>    `tests/test_indexes.c` asserts this split explicitly.
> 2. **`qihse_index_manager_insert_row()` feeds every index on the manager and
>    requires the caller's column count to match every one of them.** A manager
>    holding indexes of different arity can therefore never be fed through it.
> 3. **`qihse_index_bulk_load()` on a non-BTREE handle dereferences
>    `idx->btree`, which is NULL for a hash index.** Only the BTREE path is
>    tested; the hash path is a latent crash.
> 4. **Nodes are 4 KB in size but not page-aligned.** `qihse_btree.c` allocates
>    leaves with `calloc(1, QIHSE_BTREE_PAGE_SIZE)`, which gives malloc's default
>    alignment, not an OS page boundary; the TLB claim below was never true of
>    the code.

## 1. Overview

QIHSE provides secondary index support beyond the primary key index (Trinary Trie in the KV store). The index layer consists of B+ tree and hash index implementations, an index manager, and an index scan executor that integrates with the query optimizer.

## 2. B+ Tree Index

**Files**: `include/qihse_btree.h`, `src/frieze/qihse_btree.c`

### Design

- **4 KB nodes**: Leaves are allocated in 4 KB blocks
  (`QIHSE_BTREE_PAGE_SIZE`) so a node fits a page, but they are *not* aligned to
  an OS page boundary — the TLB claim this bullet used to make was not true of
  the code. A leaf that overflows its block is reallocated larger.
- **Configurable fanout**: passed to `qihse_btree_create()`; the default for
  fixed-width int64 keys is 128
- **Leaf node linked list**: leaf nodes carry a `next_leaf` pointer, so a range
  scan needs one root-to-leaf descent followed by sequential leaf traversal
- **Thread-safe**: per-tree pthread rwlock (readers concurrent, writers
  exclusive)

### Key Types

| Type | Size | Serialization |
|---|---|---|
| int32 | 4 bytes | Direct little-endian |
| int64 | 8 bytes | Direct little-endian |
| float64 | 8 bytes | Bit-flipped for correct sort order |
| string | variable | Length-prefixed, byte-comparable |

### Composite Keys

Multi-column composite keys use sort-preserving serialization:

```c
qihse_btree_col_t composite[3] = {
    {QIHSE_BTREE_COL_INT64, &a, 0},
    {QIHSE_BTREE_COL_INT64, &b, 0},
    {QIHSE_BTREE_COL_STRING, str, strlen(str)},
};
void* buf = NULL;
size_t buf_len = 0;
qihse_btree_serialize_key_alloc(composite, 3, &buf, &buf_len);  /* caller frees buf */
```

`qihse_btree_serialize_key(cols, ncol, out_buf, &out_len)` writes into a
caller-supplied buffer (passing `out_buf == NULL` queries the required size, and
a too-small buffer returns -1 with `*out_len` set to the requirement). The
encoding is int32/int64 big-endian with the sign bit flipped, float64
sign-flipped with magnitude bits flipped for negatives, and strings raw UTF-8
followed by a 0x00 terminator.

Prefix matching: An index on `(a, b, c)` can be used for:
- `a = ?` (prefix length 1)
- `a = ? AND b = ?` (prefix length 2)
- `a = ? AND b = ? AND c = ?` (full key)

### API

```c
qihse_btree_t* qihse_btree_create(uint32_t fanout);   /* 0 => default 128 */
void qihse_btree_destroy(qihse_btree_t* tree);

// Insert or replace a key -> row_id mapping
bool qihse_btree_insert(qihse_btree_t* tree, const void* key, size_t key_len,
                        uint64_t row_id);

// Point lookup
bool qihse_btree_lookup(qihse_btree_t* tree, const void* key, size_t key_len,
                        uint64_t* out);

// Delete (row_id_out may be NULL)
bool qihse_btree_delete(qihse_btree_t* tree, const void* key, size_t key_len,
                        uint64_t* row_id_out);

// Range scan over [min_key, max_key]; either bound may be NULL/0.
// Returns NULL when the range is empty.
qihse_btree_cursor_t* qihse_btree_range_open(qihse_btree_t* tree,
    const void* min_key, size_t min_len,
    const void* max_key, size_t max_len);

// Prefix scan (composite index): keys beginning with prefix.
qihse_btree_cursor_t* qihse_btree_prefix_open(qihse_btree_t* tree,
    const void* prefix, size_t prefix_len);

// Cursor iteration
bool qihse_btree_cursor_get(const qihse_btree_cursor_t* cur,
                            const void** key_out, size_t* key_len_out,
                            uint64_t* row_id_out);
bool qihse_btree_cursor_next(qihse_btree_cursor_t* cur);
void qihse_btree_cursor_close(qihse_btree_cursor_t* cur);

size_t qihse_btree_size(const qihse_btree_t* tree);

// Persistence (format: magic, version, fanout, count, then key_len/row_id/key
// tuples in sorted order)
int             qihse_btree_save(const qihse_btree_t* tree, const char* path);
qihse_btree_t*  qihse_btree_load(const char* path);
```

## 3. Hash Index

**Files**: `include/qihse_hash_index.h`, `src/frieze/qihse_hash_index.c`

### Design

- **Open-addressed** with linear probing for cache-line efficiency
- **Dynamic resizing**: Table grows when load factor exceeds 0.7, typically doubling capacity
- **Tombstone markers**: Deleted entries are marked with a tombstone; probed past during lookups, reused during inserts
- **Thread-safe**: Per-index pthread rwlock

### Key Types
- int64 keys (8 bytes, hashed with FNV-1a)
- String keys (variable length, hashed with FNV-1a)

### API

```c
qihse_hash_index_t* qihse_hash_index_create(qihse_hash_key_type_t key_type,
                                            size_t initial_capacity); /* 0 => 1024 */
void qihse_hash_index_destroy(qihse_hash_index_t* idx);

bool qihse_hash_index_insert(qihse_hash_index_t* idx, const void* key,
                             size_t key_len, uint64_t row_id);
bool qihse_hash_index_lookup(qihse_hash_index_t* idx, const void* key,
                             size_t key_len, uint64_t* out);
bool qihse_hash_index_delete(qihse_hash_index_t* idx, const void* key,
                             size_t key_len, uint64_t* row_id_out);
size_t qihse_hash_index_size(const qihse_hash_index_t* idx);

int             qihse_hash_index_save(const qihse_hash_index_t* idx, const char* path);
qihse_hash_index_t* qihse_hash_index_load(const char* path);
```

`QIHSE_HASH_KEY_INT64` indexes hash the raw eight bytes of the value; string
indexes hash the byte string with its length, so `"bob"` and `"bob\0"` are
different keys.

## 4. Index Manager

**Files**: `include/qihse_index_manager.h`, `src/frieze/qihse_index_manager.c`

### Index Types

```c
typedef enum {
    QIHSE_INDEX_BTREE,        // B+ tree for range and point queries
    QIHSE_INDEX_HASH,         // Hash table for equality-only queries
    QIHSE_INDEX_VECTOR_HNSW,  // HNSW graph for vector similarity
    QIHSE_INDEX_FTS_INVERTED  // Inverted index for full-text search
} qihse_index_type_t;
```

### Per-Table Index Tracking

Each table can have multiple indexes. The index manager tracks:
- Index name (unique per table)
- Index type (BTREE, HASH, VECTOR_HNSW, FTS_INVERTED)
- Indexed columns
- Underlying index data structure (B+ tree handle, hash handle, or vtable for HNSW/FTS)

### Operations

```c
qihse_index_manager_t* qihse_index_manager_create(void);
void qihse_index_manager_destroy(qihse_index_manager_t* mgr);

// Register a B+ tree index (columns are described by name + type)
qihse_index_t* qihse_index_manager_add_btree(qihse_index_manager_t* mgr,
    const char* name, const qihse_idx_col_def_t* cols, size_t ncol,
    uint32_t fanout);

// Register a hash index
qihse_index_t* qihse_index_manager_add_hash(qihse_index_manager_t* mgr,
    const char* name, const qihse_idx_col_def_t* cols, size_t ncol,
    size_t initial_capacity);

// Register an existing HNSW or FTS index through a vtable
qihse_index_t* qihse_index_manager_add_wrapped(qihse_index_manager_t* mgr,
    const char* name, qihse_index_type_t type,
    const qihse_idx_col_def_t* cols, size_t ncol,
    const qihse_index_wrapper_vtbl_t* vtbl);

// Lookup / drop / count
qihse_index_t* qihse_index_manager_find(const qihse_index_manager_t* mgr,
                                        const char* name);
bool   qihse_index_manager_drop(qihse_index_manager_t* mgr, const char* name);
size_t qihse_index_manager_count(const qihse_index_manager_t* mgr);

// Insert a row into all indexes (requires ncol to match every index) or into one
bool qihse_index_manager_insert_row(qihse_index_manager_t* mgr, uint64_t row_id,
    const qihse_idx_col_type_t* col_types, const void* const* col_values,
    const size_t* col_lens, size_t ncol);
bool qihse_index_insert(qihse_index_t* idx, uint64_t row_id,
    const qihse_idx_col_type_t* col_types, const void* const* col_values,
    const size_t* col_lens, size_t ncol);
bool qihse_index_delete(qihse_index_t* idx, uint64_t row_id,
    const qihse_idx_col_type_t* col_types, const void* const* col_values,
    const size_t* col_lens, size_t ncol);
bool qihse_index_manager_delete_row(qihse_index_manager_t* mgr, uint64_t row_id,
    const qihse_idx_col_type_t* col_types, const void* const* col_values,
    const size_t* col_lens, size_t ncol);

// Bulk load (sort-then-build) — BTREE only in practice, see the status note
bool qihse_index_bulk_load(qihse_index_t* idx, const uint64_t* row_ids,
    const void* const* keys, const size_t* key_lens, size_t nrows);

// Accessors
qihse_index_type_t         qihse_index_type(const qihse_index_t* idx);
const char*                qihse_index_name(const qihse_index_t* idx);
size_t                     qihse_index_ncols(const qihse_index_t* idx);
const qihse_idx_col_def_t* qihse_index_cols(const qihse_index_t* idx);
qihse_btree_t*             qihse_index_btree(const qihse_index_t* idx);
qihse_hash_index_t*        qihse_index_hash(const qihse_index_t* idx);
void*                      qihse_index_wrapped_handle(const qihse_index_t* idx);
```

### HNSW / FTS Wrappers

Existing vector (HNSW) and full-text search indexes can be registered as index types via a vtable:

```c
typedef struct {
    void*  (*create_fn)(void);
    void   (*destroy_fn)(void* handle);
    bool   (*insert_fn)(void* handle, uint64_t row_id,
                        const void* data, size_t data_len);
    bool   (*delete_fn)(void* handle, uint64_t row_id);
} qihse_index_wrapper_vtbl_t;
```

This allows the optimizer to treat vector and FTS indexes uniformly with B+ tree and hash indexes.

## 5. Index Scan Executor

**Files**: `include/qihse_index_scan.h`, `src/tractable/qihse_index_scan.c`

The index scan executor provides a unified interface for reading from any index type:

```c
typedef enum {
    QIHSE_SCAN_EQ = 0,      // Equality lookup (BTREE and HASH)
    QIHSE_SCAN_RANGE = 1,   // Range scan (BTREE only)
    QIHSE_SCAN_PREFIX = 2   // Prefix match (composite BTREE only)
} qihse_scan_pred_kind_t;

typedef struct {
    qihse_scan_pred_kind_t kind;
    const void* eq_key;      size_t eq_key_len;      // EQ
    const void* min_key;     size_t min_len;         // RANGE (either bound may be NULL)
    const void* max_key;     size_t max_len;
    const void* prefix_key;  size_t prefix_len;      // PREFIX
} qihse_scan_pred_t;

// Returns NULL when the predicate matches nothing or is unsupported by the
// index type (e.g. RANGE on a hash index).
qihse_index_scan_t* qihse_index_scan_open(qihse_index_t* idx,
                                          const qihse_scan_pred_t* pred);

// Batched iteration into a caller-supplied buffer
bool qihse_index_scan_next(qihse_index_scan_t* scan, uint64_t* out_buf,
                           size_t cap, size_t* out_count);

// All matching row IDs at once (caller frees *out_buf)
bool qihse_index_scan_all(qihse_index_scan_t* scan, uint64_t** out_buf,
                          size_t* out_count);

void qihse_index_scan_close(qihse_index_scan_t* scan);

// One-shot equality lookup on a BTREE or HASH index
bool qihse_index_scan_eq(qihse_index_t* idx, const void* key, size_t key_len,
                         uint64_t* row_id_out);
```

Wrapped (HNSW/FTS) indexes open successfully but never yield row IDs: they are
not row-id predicate sources.

## 6. Testing

`tests/test_indexes.c` (run via `make test-indexes`) covers:

1. B+ tree insert/lookup over 100 keys at fanout=8 (forces node splits),
   including replace semantics and absent-key lookups.
2. B+ tree range scan: bounded range, open-ended lower bound, empty range.
3. B+ tree delete: row id out, idempotence, draining the tree to empty.
4. B+ tree string keys and a string range scan.
5. Composite key serialization: int64, float64 and string sort order, the
   sizing query, and the too-small-buffer error.
6. Composite prefix matching: `a=?` and `a=? AND b=?` on a 3-column index.
7. Hash index insert/lookup across a resize (500 keys from capacity 8).
8. Hash index string keys, including length sensitivity.
9. Hash index delete: tombstone probing, size accounting, slot reuse.
10. Index manager: add/find/count/drop, `insert_row`, per-index insert/delete,
    and the column-count refusal.
11. Index scan executor: EQ, RANGE and PREFIX on a B+ tree, EQ-only on a hash
    index, batched iteration, and "no match yields no scan handle".
12. Bulk load from an unsorted array, then ascending iteration.
13. Wrapped (HNSW/FTS) registration: vtable routing, payload delivery,
    destroy-on-drop, and the empty row-id result.

Not covered: `qihse_btree_save()`/`qihse_btree_load()` and
`qihse_hash_index_save()`/`qihse_hash_index_load()` persistence, the non-BTREE
branch of `qihse_index_bulk_load()` (a latent NULL dereference, see the status
note), and concurrent access under the per-tree rwlock.
