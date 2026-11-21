# qihse-rs

Safe Rust bindings for the [QIHSE](../../README.md) C database library.

## What's Exposed

| Rust type | C API prefix | Description |
|-----------|-------------|-------------|
| `KVStore` | `qihse_kv_*` | O(k) trinary trie + LSM key-value store |
| `TrinaryTrie` | `qihse_trinary_trie_*` | Raw trinary trie, byte-value key-value store |
| `VectorDB` | `qihse_vector_db_*` | Exact `float32` vector search with trinary / qmag acceleration (authenticated reads) |
| `Auth` / `User` | `qihse_auth_*` | Authenticated principal handles for classified-capable reads |
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

Searches require an explicit authenticated principal (`Auth`/`User`) — the C
layer fails closed with `EACCES` for a NULL security context and never
substitutes a default one (repository invariant 1):

```rust
use qihse_rs::{Auth, User, VectorDB, ffi};

assert!(Auth::init());
let operator: User = Auth::authenticate_id(0, "at-least-12-char-password").unwrap();

let db = VectorDB::new(ffi::qihse_vector_db_backend_e_QIHSE_VECTOR_DB_INMEMORY, None).unwrap();

let vectors = vec![1.0f32, 0.0, 0.0, 0.0];
let ids = vec![42u64];
db.add_vectors(&vectors, 4, Some(&ids));

let results = db.search(
    &operator,
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

## Controller client (pure `std`, no FFI)

`qihse_rs::controller` is the Rust controller SDK (CITADEL v3 §25): a
synchronous RESP client over `std::net::TcpStream` mirroring the C reference
client (`include/qihse_controller.h` / `src/controller/qihse_controller.c`).
It adds no dependencies, contains no `unsafe`, and speaks the same command
vocabulary (`FEDERATION NODE.LIST`, `OBJECT.CAS`, `LEASE.ACQUIRE`,
`EVENT.APPEND`, `WATCH.*`, `PROV.*`, `SECURITY.*`, …) with the same reply
shapes.

### Connect with explicit credentials

Credentials are a connect-time parameter — there is no ambient credential
source, and the SDK confers no authority: authentication, scopes,
classification and replay are all enforced server-side. A denial surfaces as
`ControllerError::Server { class, message }` carrying the server's class
(`NOPERM`, `ERR`, …) verbatim.

```rust
use qihse_rs::controller::{ControllerClient, ControllerConfig, Credentials};

let config = ControllerConfig::new(
    "127.0.0.1",
    6380,
    Credentials::Password { username: "controller".into(), password: "…".into() },
);
let mut client = ControllerClient::connect(&config)?;
let nodes = client.node_list()?; // Reply::Array of [uuid, trust_state, kind]
```

`Credentials::Unauthenticated` connects without an `AUTH` round-trip; what
such a session may do is entirely the server's decision.

### Bounded decoder

Replies are decoded with the C client's hard caps, so a hostile or corrupt
peer cannot turn the client into a memory sink — violations are errors
(`ControllerError::OversizedBulk` / `TooManyItems` / `TooDeep`), never panics:

| Bound | Limit | Error |
|-------|-------|-------|
| bulk payload | `MAX_BULK` = 16 MiB | `OversizedBulk` |
| array items | `MAX_ITEMS` = 1 Mi items | `TooManyItems` |
| nesting depth | `MAX_DEPTH` = 32 | `TooDeep` |
| outbound command | 16 MiB encoded | `CommandTooLarge` (connection stays usable) |

Any transport failure, timeout, or bound violation marks the connection dead
(`is_connected() == false`); reconnect with `ControllerClient::connect` and
re-open watches with `Watch::reopen`.

### Object CAS and resumable watches

The CAS generation precondition is explicit in the type, and `Watch` carries
the journal cursor across reconnects (delivery is at-least-once: `reopen`
resumes from the last **acked** offset):

```rust
use qihse_rs::controller::CasPrecondition;

// Create-only, byte-exact value:
let created = client.object_cas("mgmt", "vm-7/desired", br#"{"cpu":4}"#,
                                CasPrecondition::CreateOnly)?;
// Swap only if currently at generation 3:
let swapped = client.object_cas("mgmt", "vm-7/desired", br#"{"cpu":8}"#,
                                CasPrecondition::IfGenerationIs(3))?;

let mut watch = client.watch_open(Some("vm-"))?;
while let Some(event) = watch.next(&mut client)? {
    // event.offset(), event_type(), resource_id(), payload() (byte-exact)
    watch.ack(&mut client)?; // server may drop the backlog to here
}
// After a reconnect:
let mut client = ControllerClient::connect(&config)?;
watch.reopen(&mut client)?; // WATCH.OPEN + WATCH.RESUME to the acked cursor
```

## Security Note

`KVStore::set` and `TimeSeriesDB::insert` accept `classification` (u16)
and `sci_compartment` (u16) parameters. Pass `0` for unclassified data. Non-zero values
enable QIHSE's cell-level US/Five Eyes/SCI clearance enforcement — every read and write
checks clearance before any data is accessed.

Classified-capable reads take an explicit authenticated context: `VectorDB::search`
requires a `User` obtained through `Auth` (bootstrap the operator, then authenticate).
A NULL security context is never an authorization bypass — the C layer fails closed
with `EACCES` (repository invariant 1).

## Running Tests

```bash
cd rust/qihse-rs
LD_LIBRARY_PATH=../.. cargo test
```

The controller-SDK tests (`tests/controller_sdk.rs` and the in-module tests in
`src/controller.rs`) need no running server: they drive the client against an
in-process mock controller bound to `127.0.0.1` ephemeral ports.

## Opt-in Python SDK port (partial)

`cargo test --manifest-path rust/qihse-rs/Cargo.toml --features python-port`
(from the repository root, after `make lib`; set `LD_LIBRARY_PATH=.` for native-linked tests).
The `python-port` feature exports `python_port` plus its separately named
`python_vector`, `python_storage`, `python_remote`, `python_browser`, and
`python_peripheral` modules. Default builds and the existing crate API remain
unchanged; Python remains active and the native C library still owns storage,
authorization, hardware profiling, and vector computation. `python_port` uses
`NativeVectorDB`/`StorageKv` names to avoid confusing these with legacy
`VectorDB`/`KVStore` wrappers. Its UWP codec does not open a socket.

Exact top-level `python/qihse/__init__.py` `__all__` inventory (in order),
with port status:

| Python exports | Rust coverage | Missing or different behavior |
|---|---|---|
| `VectorDB`, `VectorQuery`, `VectorResult`, `DistanceMetric`, `QueryMode` | partial (`NativeVectorDB`, `VectorQuery`, `VectorResult`, native FFI enums) | `VectorDB.open`, graph edges/build, quantization, metadata/result vectors, container, PG wire, and context manager; no Rust enum aliases |
| `KVStore`, `TimeSeriesDB`, `DocumentStore` | partial (`StorageKv`, `StorageTimeSeries`, `StorageDocument`) | Python method/signature parity not yet verified; use explicit authenticated `StorageUser` rather than legacy context-free reads |
| `EventStream`, `EventRecord`, `EventScope`, `Durability` | partial (`StorageEventStream`, `EventRecord`, `EventScope`, `Durability`) | Python stream lifecycle and schema method parity unverified |
| `UWPServer` | **missing** | TLS server launcher and TLS UWP client transport absent; `UwpCodec` supports only bounded framing and auth/error state, no verified socket |
| `NeuralClassifier`, `KeystoneClass`, `AnchorIndex` | implemented native-backed subset | Python type/signature parity needs fixture checks |
| `HardwareProfiler`, `HardwareProfile` | native C profiler implemented | Actual host CPU/cache values vary; compare stable fields and units |
| `FTSIndex`, `FTSResult` | partial native-backed | Python handle/context-manager interface absent |
| `MultimodalFusion`, `FusionResult` | **missing** | No Rust-side approximation of native fusion |
| `Controller`, `Reply`, `Watch`, `ControllerError`, `ControllerServerError` | partial (`controller` SDK) | error class and Python method parity not verified |
| `AIMEMClient`, `Scope`, `MemoryHit`, `DurableReceipt`, `KnowledgeVersion`, `KnowledgeRelation`, `KnowledgeProvenance`, `ExtendedKnowledgeVersion`, `DocumentSourceRef`, `Handoff`, `QueryHit`, `RecallMode` | first four and `RecallMode` partial (`python_remote`) | `KnowledgeVersion`, `KnowledgeRelation`, `KnowledgeProvenance`, `ExtendedKnowledgeVersion`, `DocumentSourceRef`, `Handoff`, `QueryHit` missing; remaining methods unverified; remote QKP/pinned peers unsupported by plaintext controller transport |
| `get_fleet_telemetry`, `collect_local_telemetry`, `publish_telemetry` | **missing** | Only `parse_ipmi`/`ThermalTelemetry` calculation exists; no CSV/IPMI process execution, fleet deadlines, JSON, TLS RESP publishing, or daemon |

`python/qihse/uwp.py` also defines a **non-`__all__`** `UWPClient`
(`connect`, `close`, `authenticate`, `send_command`, `kv_set`, `kv_get`,
`vector_upsert`, `doc_insert`, `tsdb_insert`, `is_authenticated`); none of these
network operations is implemented in Rust. `UwpCodec` is not a wire-client
substitute. It builds the Python-compatible 15-byte little-endian header and
rejects non-AUTH frame construction before an accepted auth reply; only a
caller-supplied verified TLS transport may carry its frames. No unverified
plain TCP fallback is offered.

`python/qihse/browser/__init__.py` `__all__` is **exactly** `keyslot`,
`SLOT_COUNT`, `NodeSpec`, `SessionFleet`. `python_port::browser` exports all
four names (Rust `SLOT_COUNT=16384`); the `SessionFleet` API is a *different,
read-only* authenticated subset. `browse`/`fetch` and `prepare_action` are
additional Rust helpers, not exports from Python's browser package root.
Python's fleet topology/snapshot/health methods and the HTTP/WebAuthn UI,
challenge verification, credential store, mutations, and CLI remain missing.

Conformance plan before any parity claim: (1) run matching Python/Rust fixtures
against the same native library for hardware units, vector/FTS scores, storage
labels and stream rows; (2) test low-clearance/high-data denial through *each*
Rust adapter, including direct-ID lookup, enumeration, batch/export and browser
read/slot-owner fallbacks, in CI; (3) use a mock TLS endpoint for UWP framed
AUTH, rejection, truncation, deadlines and retry behavior before implementing
any network client, and a real TLS test for the server launcher; (4) compare
all `__all__` method signatures/results and browser root exports across both
languages; (5) record missing methods and only promote individual rows after
negative auth and integration tests pass. The focused Rust checks do not
establish this conformance. The separate native extension in
`sdks/python/qihse.c` is another Python-facing surface; this table inventories
`python/qihse` only and does not establish parity with the extension.

Run the feature-gated peripheral checks with
`LD_LIBRARY_PATH=. cargo test --manifest-path rust/qihse-rs/Cargo.toml --features python-port --test python_peripheral -- --test-threads=1`
from the repository root. Omitting `--features python-port` runs **zero** tests
in that target, not a peripheral conformance check.

Upgrade: opt in with `--features python-port`, rebuild `make lib` then
`cargo build --manifest-path rust/qihse-rs/Cargo.toml --features python-port`.
No existing symbol is retired, no reindex is needed, and stored data needs no
migration.
