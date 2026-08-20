# QIHSE Secondary Index Architecture

## 1. Overview

QIHSE provides secondary index support beyond the primary key index (Trinary Trie in the KV store). The index layer consists of B+ tree and hash index implementations, an index manager, and an index scan executor that integrates with the query optimizer.

## 2. B+ Tree Index

**Files**: `include/qihse_btree.h`, `src/frieze/qihse_btree.c`

### Design

- **Page-aligned (4 KB) nodes**: Internal and leaf nodes are aligned to OS page size to eliminate TLB misses during traversal
- **Configurable fanout**: Default 128 for int64 keys, adjustable based on key size
- **Leaf node linked list**: Leaf nodes are linked for efficient range iteration without ascending to internal nodes
- **Thread-safe**: Per-tree pthread rwlock allows concurrent readers with exclusive writers

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
qihse_btree_key_t composite[3] = {
    {QIHSE_BTREE_KEY_INT64, &a, sizeof(int64_t)},
    {QIHSE_BTREE_KEY_INT64, &b, sizeof(int64_t)},
    {QIHSE_BTREE_KEY_STRING, str, strlen(str)},
};
qihse_btree_serialize_key(composite, 3, buffer, &buf_len);
```

Prefix matching: An index on `(a, b, c)` can be used for:
- `a = ?` (prefix length 1)
- `a = ? AND b = ?` (prefix length 2)
- `a = ? AND b = ? AND c = ?` (full key)

### API

```c
qihse_btree_t* qihse_btree_create(qihse_btree_key_type_t key_type, int fanout);

// Insert
int qihse_btree_insert(qihse_btree_t* tree, const void* key, size_t key_len, uint64_t row_id);

// Point lookup
bool qihse_btree_find(qihse_btree_t* tree, const void* key, size_t key_len, uint64_t* out_row_id);

// Delete
int qihse_btree_delete(qihse_btree_t* tree, const void* key, size_t key_len);

// Range scan
qihse_btree_cursor_t* qihse_btree_range_scan(qihse_btree_t* tree,
    const void* min_key, size_t min_len,
    const void* max_key, size_t max_len);

// Prefix scan (composite index)
qihse_btree_cursor_t* qihse_btree_prefix_scan(qihse_btree_t* tree,
    const void* prefix, size_t prefix_len);

// Cursor iteration
bool qihse_btree_cursor_next(qihse_btree_cursor_t* cursor, uint64_t* out_row_id);
void qihse_btree_cursor_close(qihse_btree_cursor_t* cursor);
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
qihse_hash_index_t* qihse_hash_index_create(qihse_hash_key_type_t key_type, size_t initial_capacity);

int qihse_hash_index_insert(qihse_hash_index_t* idx, const void* key, size_t key_len, uint64_t row_id);
bool qihse_hash_index_find(qihse_hash_index_t* idx, const void* key, size_t key_len, uint64_t* out_row_id);
int qihse_hash_index_delete(qihse_hash_index_t* idx, const void* key, size_t key_len);
```

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

// Create and register a B+ tree or hash index on a table
int qihse_index_manager_create_index(qihse_index_manager_t* mgr,
    const char* table_name, const char* index_name,
    qihse_index_type_t type, const char** columns, size_t num_columns);

// Register an existing HNSW or FTS as an index (vtable wrapper)
int qihse_index_manager_register_wrapper(qihse_index_manager_t* mgr,
    const char* table_name, const char* index_name,
    qihse_index_type_t type, qihse_index_vtable_t* vtable);

// Insert into all indexes for a table
int qihse_index_manager_insert(qihse_index_manager_t* mgr,
    const char* table_name, const void** keys, const size_t* key_lens,
    size_t num_keys, uint64_t row_id);

// Lookup via a specific index
qihse_index_handle_t* qihse_index_manager_find(qihse_index_manager_t* mgr,
    const char* index_name);

// Bulk load (sort-then-build)
int qihse_index_manager_bulk_load(qihse_index_manager_t* mgr,
    const char* index_name,
    const void** keys, const size_t* key_lens,
    const uint64_t* row_ids, size_t count);
```

### HNSW / FTS Wrappers

Existing vector (HNSW) and full-text search indexes can be registered as index types via a vtable:

```c
typedef struct qihse_index_vtable_s {
    int (*insert)(void* impl, const void* key, size_t key_len, uint64_t row_id);
    int (*delete)(void* impl, const void* key, size_t key_len);
    int (*find)(void* impl, const void* key, size_t key_len, uint64_t* out);
    void (*destroy)(void* impl);
} qihse_index_vtable_t;
```

This allows the optimizer to treat vector and FTS indexes uniformly with B+ tree and hash indexes.

## 5. Index Scan Executor

**Files**: `include/qihse_index_scan.h`, `src/tractable/qihse_index_scan.c`

The index scan executor provides a unified interface for reading from any index type:

```c
typedef enum {
    QIHSE_INDEX_SCAN_EQ,      // Equality lookup
    QIHSE_INDEX_SCAN_RANGE,   // Range scan (B+ tree only)
    QIHSE_INDEX_SCAN_PREFIX   // Prefix match (composite B+ tree)
} qihse_index_scan_type_t;

qihse_index_scan_t* qihse_index_scan_create(qihse_index_handle_t* idx,
    qihse_index_scan_type_t type,
    const void* start_key, size_t start_len,
    const void* end_key, size_t end_len);

// Get all matching row IDs at once
size_t qihse_index_scan_execute(qihse_index_scan_t* scan, uint64_t** out_row_ids);

// Or iterate one at a time
bool qihse_index_scan_next(qihse_index_scan_t* scan, uint64_t* out_row_id);
void qihse_index_scan_close(qihse_index_scan_t* scan);
```

## 6. Testing

Tests are in `tests/test_indexes.c` (14 tests):

1. B+ tree insert/lookup (forces splits with fanout=8)
2. B+ tree range scan with serialized keys
3. B+ tree delete
4. B+ tree string keys + range scan
5. Composite index prefix matching (a=? on 3-column index)
6. Composite index prefix matching (a=? AND b=?)
7. Hash index insert/lookup (triggers resize)
8. Hash index string keys
9. Hash index delete + tombstone reuse
10. Index manager: create, register, insert, lookup
11. Index manager: find by name
12. Index scan executor (range + equality)
13. Bulk load (sort-then-build)
14. Wrapped (HNSW/FTS) index type registration
