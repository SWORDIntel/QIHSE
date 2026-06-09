# qihse-rs

Safe Rust bindings for the [QIHSE](../../README.md) C database library.

## What's Exposed

| Rust type | C API prefix | Description |
|-----------|-------------|-------------|
| `KVStore` | `qihse_kv_*` | O(k) trinary trie + LSM key-value store |
| `TrinaryTrie` | `qihse_trinary_trie_*` | Raw trinary trie, byte-value key-value store |
| `VectorDB` | `qihse_vector_db_*` | Exact `float32` vector search with trinary / qmag acceleration |
| `TimeSeriesDB` | `qihse_tsdb_*` | Lock-free Gorilla-compressed time-series ingestion |
| `DocumentStore` | `qihse_doc_*` | JIT-compiled JSON document store |

All types implement `Drop` — C resources are freed automatically.

## Prerequisites

Build `libqihse.so` first:

```bash
# From the QIHSE repo root
make lib
```

## Build

```bash
cd rust/qihse-rs
LD_LIBRARY_PATH=../.. cargo build
```

## Examples

### Key-Value Store

```rust
use qihse_rs::KVStore;

let store = KVStore::new().unwrap();
store.set("key", "value", 0, 0);              // classification=0, sci=0 (unclassified)
assert_eq!(store.get("key"), Some("value".into()));
store.delete("key");
```

### Trinary Trie

```rust
use qihse_rs::TrinaryTrie;

let trie = TrinaryTrie::new().unwrap();
trie.insert("hello", b"world");
assert_eq!(trie.get("hello").as_deref(), Some(b"world".as_ref()));
trie.delete("hello");
```

### Vector Database

```rust
use qihse_rs::{VectorDB, ffi};

let db = VectorDB::new(ffi::qihse_vector_db_backend_e_QIHSE_VECTOR_DB_INMEMORY, None).unwrap();

let vectors = vec![1.0f32, 0.0, 0.0, 0.0];
let ids = vec![42u64];
db.add_vectors(&vectors, 4, Some(&ids));

let results = db.search(
    &[1.0, 0.0, 0.0, 0.0],
    10,
    ffi::qihse_vector_db_query_mode_e_QIHSE_VDB_QUERY_FLOAT32,
    ffi::qihse_distance_metric_e_QIHSE_DISTANCE_COSINE,
);
println!("top result: id={} score={}", results[0].id, results[0].score);
```

### Time-Series DB

```rust
use qihse_rs::TimeSeriesDB;

let db = TimeSeriesDB::new().unwrap();
db.insert(/*series_id=*/1, /*timestamp=*/1_000_000, /*value=*/42.0, 0, 0);
db.insert(1, 2_000_000, 58.0, 0, 0);
db.compress_flush();
let avg = db.average_range(0, 3_000_000);
println!("average: {avg}");
```

### Document Store

```rust
use qihse_rs::{KVStore, DocumentStore};

let kv = KVStore::new().unwrap();
let store = DocumentStore::new(&kv).unwrap();
store.insert_json(1, r#"{"name":"alice","role":"admin"}"#);
let ids = store.query("role = 'admin'");
println!("matched doc ids: {ids:?}");
```

## Security Note

`KVStore::set`, `TimeSeriesDB::insert`, and vector operations accept `classification` (u16)
and `sci_compartment` (u16) parameters. Pass `0` for unclassified data. Non-zero values
enable QIHSE's cell-level US/Five Eyes/SCI clearance enforcement — every read and write
checks clearance before any data is accessed.

## Running Tests

```bash
cd rust/qihse-rs
LD_LIBRARY_PATH=../.. cargo test
```
