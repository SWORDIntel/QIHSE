#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

pub mod ffi {
    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}

// ============================================================================
// Controller client (pure-std protocol SDK — no FFI)
// ============================================================================

pub mod controller;

pub use controller::{
    CasPrecondition, ControllerClient, ControllerConfig, ControllerError, Credentials, Reply,
    Watch, WatchEvent, DEFAULT_TIMEOUT_MS, MAX_BULK, MAX_DEPTH, MAX_ITEMS,
};

use std::ffi::{CStr, CString};

// ============================================================================
// KVStore
// ============================================================================

/// Safe wrapper for the QIHSE Key-Value Store.
pub struct KVStore {
    ptr: *mut ffi::qihse_kv_store_t,
}

impl KVStore {
    /// Creates a new KVStore instance.
    pub fn new() -> Option<Self> {
        let ptr = unsafe { ffi::qihse_kv_store_create() };
        if ptr.is_null() { None } else { Some(Self { ptr }) }
    }

    /// Sets a key-value pair with optional cell-level security labels.
    pub fn set(&self, key: &str, value: &str, classification: u16, sci_compartment: u16) -> bool {
        let key_c = CString::new(key).expect("CString::new failed");
        let val_c = CString::new(value).expect("CString::new failed");
        unsafe { ffi::qihse_kv_set(self.ptr, key_c.as_ptr(), val_c.as_ptr(), classification, sci_compartment) }
    }

    /// Gets a value by key. Returns `None` if not found.
    pub fn get(&self, key: &str) -> Option<String> {
        let key_c = CString::new(key).expect("CString::new failed");
        let val_ptr = unsafe { ffi::qihse_kv_get_user(self.ptr, key_c.as_ptr(), std::ptr::null_mut()) };
        if val_ptr.is_null() {
            None
        } else {
            let val = unsafe { CStr::from_ptr(val_ptr).to_string_lossy().into_owned() };
            unsafe { libc::free(val_ptr as *mut libc::c_void) };
            Some(val)
        }
    }

    /// Deletes a key. Returns `true` if the key existed.
    pub fn delete(&self, key: &str) -> bool {
        let key_c = CString::new(key).expect("CString::new failed");
        unsafe { ffi::qihse_kv_del_user(self.ptr, key_c.as_ptr(), std::ptr::null_mut()) }
    }

    /// Returns `true` if the key exists.
    pub fn exists(&self, key: &str) -> bool {
        let key_c = CString::new(key).expect("CString::new failed");
        unsafe { ffi::qihse_kv_exists_user(self.ptr, key_c.as_ptr(), std::ptr::null_mut()) }
    }
}

impl Drop for KVStore {
    fn drop(&mut self) {
        unsafe { ffi::qihse_kv_store_destroy(self.ptr) };
    }
}

// ============================================================================
// TrinaryTrie
// ============================================================================

/// Safe wrapper for the QIHSE Trinary Trie (O(k) key-value store).
pub struct TrinaryTrie {
    ptr: *mut ffi::qihse_trinary_trie_t,
}

impl TrinaryTrie {
    /// Creates a new TrinaryTrie instance.
    pub fn new() -> Option<Self> {
        let ptr = unsafe { ffi::qihse_trinary_trie_create() };
        if ptr.is_null() { None } else { Some(Self { ptr }) }
    }

    /// Inserts a raw byte value under `key`. Returns `true` on success.
    pub fn insert(&self, key: &str, value: &[u8]) -> bool {
        let key_c = CString::new(key).expect("CString::new failed");
        unsafe {
            ffi::qihse_trinary_trie_insert(
                self.ptr,
                key_c.as_ptr(),
                value.as_ptr() as *mut _,
                value.len(),
            )
        }
    }

    /// Looks up `key` and returns the stored bytes, or `None` if not found.
    pub fn get(&self, key: &str) -> Option<Vec<u8>> {
        let key_c = CString::new(key).expect("CString::new failed");
        let mut out_size: usize = 0;
        let ptr = unsafe {
            ffi::qihse_trinary_trie_search(self.ptr, key_c.as_ptr(), &mut out_size)
        };
        if ptr.is_null() || out_size == 0 {
            None
        } else {
            let slice = unsafe { std::slice::from_raw_parts(ptr as *const u8, out_size) };
            Some(slice.to_vec())
        }
    }

    /// Deletes `key`. Returns `true` if the key existed.
    pub fn delete(&self, key: &str) -> bool {
        let key_c = CString::new(key).expect("CString::new failed");
        unsafe { ffi::qihse_trinary_trie_delete(self.ptr, key_c.as_ptr()) }
    }
}

impl Drop for TrinaryTrie {
    fn drop(&mut self) {
        unsafe { ffi::qihse_trinary_trie_destroy(self.ptr) };
    }
}

// ============================================================================
// Authenticated principal (explicit security context)
// ============================================================================

/// An authenticated QIHSE principal handle (`qihse_user_t*` from
/// `qihse_auth.h`).
///
/// The C auth layer keeps principals in a process-global table, so a `User`
/// is a borrowed, non-owning handle into that table: the C API exposes no
/// free function for it, it stays valid until the principal is destroyed,
/// and it is cheap to copy.
///
/// Classified-capable read primitives such as [`VectorDB::search`] demand an
/// explicit `User`: the C layer fails closed with `EACCES` for a NULL
/// security context and never substitutes a default principal (repository
/// invariant 1). This wrapper therefore has no unauthenticated fallback —
/// callers must obtain a principal through [`Auth`].
#[derive(Clone, Copy)]
pub struct User {
    ptr: *mut ffi::qihse_user_t,
}

impl User {
    /// Numeric user id (C `qihse_user_get_id`). User 0 is the system operator.
    pub fn id(&self) -> u32 {
        unsafe { ffi::qihse_user_get_id(self.ptr) }
    }

    /// Clearance level (C `qihse_user_get_classification`).
    pub fn classification(&self) -> u16 {
        unsafe { ffi::qihse_user_get_classification(self.ptr) }
    }
}

/// Process-global authentication subsystem (C `qihse_auth_*`).
pub struct Auth;

impl Auth {
    /// Initialise the global auth context (C `qihse_auth_init`).
    ///
    /// Note: the C implementation resets the principal table on every call,
    /// so initialise once per process before authenticating.
    pub fn init() -> bool {
        unsafe { ffi::qihse_auth_init() }
    }

    /// Bootstrap the system operator (user id 0) with `password`.
    ///
    /// The C layer requires a password of at least 12 characters and refuses
    /// to overwrite an already-configured operator verifier (for example one
    /// configured through the `QIHSE_OPERATOR_PASSWORD` environment
    /// variable); in that case authenticate with that password instead.
    pub fn bootstrap_operator(password: &str) -> bool {
        let pw = CString::new(password).expect("CString::new failed");
        unsafe { ffi::qihse_auth_bootstrap_operator(pw.as_ptr()) }
    }

    /// Authenticates `username` with `password`. Returns `None` on bad
    /// credentials or an interior NUL byte.
    pub fn authenticate(username: &str, password: &str) -> Option<User> {
        let name = CString::new(username).ok()?;
        let pw = CString::new(password).ok()?;
        let ptr = unsafe { ffi::qihse_auth_authenticate(name.as_ptr(), pw.as_ptr()) };
        if ptr.is_null() { None } else { Some(User { ptr }) }
    }

    /// Authenticates principal `user_id` (user 0 is the system operator) with
    /// `password`. Returns `None` on bad credentials or an interior NUL byte.
    pub fn authenticate_id(user_id: u32, password: &str) -> Option<User> {
        let pw = CString::new(password).ok()?;
        let ptr = unsafe { ffi::qihse_auth_authenticate_id(user_id, pw.as_ptr()) };
        if ptr.is_null() { None } else { Some(User { ptr }) }
    }
}

// ============================================================================
// VectorDB
// ============================================================================

/// A search result returned by [`VectorDB::search`].
#[derive(Debug, Clone)]
pub struct VectorResult {
    pub id: u64,
    pub score: f32,
}

/// Safe wrapper for the QIHSE Vector Database.
pub struct VectorDB {
    ptr: ffi::qihse_vector_db_t,
}

impl VectorDB {
    /// Creates a new Vector DB. `db_path` is `None` for an in-memory store.
    pub fn new(backend: ffi::qihse_vector_db_backend_e, db_path: Option<&str>) -> Option<Self> {
        let path_c = db_path.map(|s| CString::new(s).expect("CString::new failed"));
        let ptr = unsafe {
            ffi::qihse_vector_db_create(
                backend,
                std::ptr::null_mut(),
                path_c.as_ref().map_or(std::ptr::null(), |s| s.as_ptr()),
            )
        };
        if ptr.is_null() { None } else { Some(Self { ptr }) }
    }

    /// Adds `vectors` (flat row-major `f32` array, `dims` per vector).
    /// `ids` is optional; pass `None` for auto-assigned IDs.
    pub fn add_vectors(&self, vectors: &[f32], dims: usize, ids: Option<&[u64]>) -> bool {
        let num = if dims == 0 { 0 } else { vectors.len() / dims };
        let id_ptr = ids.map_or(std::ptr::null(), |s| s.as_ptr());
        unsafe {
            ffi::qihse_vector_db_add_vectors(
                self.ptr,
                vectors.as_ptr(),
                num,
                dims,
                id_ptr,
                std::ptr::null(),
                std::ptr::null(),
            )
        }
    }

    /// Searches for the `top_k` nearest neighbours of `query`, executed as
    /// the authenticated principal `user`.
    ///
    /// `user` is an explicit authenticated security context (repository
    /// invariant 1): the C layer fails closed with `EACCES` for a NULL
    /// context and returns no rows, so this wrapper requires a [`User`]
    /// handle and offers no unauthenticated fallback.
    pub fn search(
        &self,
        user: &User,
        query: &[f32],
        top_k: usize,
        mode: ffi::qihse_vector_db_query_mode_e,
        metric: ffi::qihse_distance_metric_e,
    ) -> Vec<VectorResult> {
        let mut raw_results: Vec<ffi::qihse_vector_result_t> = (0..top_k)
            .map(|_| ffi::qihse_vector_result_t {
                id: 0,
                score: 0.0,
                vector: std::ptr::null_mut(),
                vector_dims: 0,
                metadata: std::ptr::null_mut(),
                metadata_size: 0,
            })
            .collect();

        let q = ffi::qihse_vector_query_t {
            query_vector: query.as_ptr(),
            vector_dims: query.len(),
            top_k,
            similarity_threshold: 0.0,
            include_vectors: false,
            include_metadata: false,
            use_trinary_candidates: false,
            candidate_count: 0,
            query_mode: mode,
            candidate_pool_size: 0,
            distance_metric: metric,
            metadata_filter: None,
            metadata_filter_opaque: std::ptr::null_mut(),
            user: user.ptr,
        };

        let found = unsafe {
            ffi::qihse_vector_db_search(self.ptr, &q, raw_results.as_mut_ptr(), top_k)
        };

        if found <= 0 {
            return Vec::new();
        }

        raw_results[..found as usize]
            .iter()
            .map(|r| VectorResult { id: r.id, score: r.score })
            .collect()
    }

    /// Flush and close the database handle. Returns `true` on success.
    pub fn close(&mut self) -> bool {
        unsafe { ffi::qihse_vector_db_close(self.ptr) }
    }

    /// Trigger hierarchical memory maintenance (hot/cold tier promotion).
    pub fn maintenance(&self) -> bool {
        unsafe { ffi::qihse_vector_db_run_memory_maintenance(self.ptr) }
    }
}

impl Drop for VectorDB {
    fn drop(&mut self) {
        unsafe { ffi::qihse_vector_db_destroy(self.ptr) };
    }
}

// ============================================================================
// TimeSeriesDB
// ============================================================================

/// Safe wrapper for the QIHSE Time-Series Database.
pub struct TimeSeriesDB {
    ptr: *mut ffi::qihse_tsdb_t,
}

impl TimeSeriesDB {
    /// Creates a new TimeSeriesDB instance.
    pub fn new() -> Option<Self> {
        let ptr = unsafe { ffi::qihse_tsdb_create() };
        if ptr.is_null() { None } else { Some(Self { ptr }) }
    }

    /// Inserts a data point. `classification` and `sci_compartment` support
    /// cell-level security labels (pass `0` for unclassified data).
    pub fn insert(
        &self,
        series_id: u32,
        timestamp: u64,
        value: f64,
        classification: u16,
        sci_compartment: u16,
    ) -> bool {
        unsafe { ffi::qihse_tsdb_insert(self.ptr, series_id, timestamp, value, classification, sci_compartment) }
    }

    /// Returns the average of all values in `[start_ts, end_ts]`.
    pub fn average_range(&self, start_ts: u64, end_ts: u64) -> f64 {
        unsafe { ffi::qihse_tsdb_average_range_user(self.ptr, start_ts, end_ts, std::ptr::null_mut()) }
    }

    /// Flush buffered out-of-order data into compressed lanes.
    pub fn compress_flush(&self) {
        unsafe { ffi::qihse_tsdb_compress_flush(self.ptr) };
    }

    /// Set the TTL (in milliseconds) for old chunks.
    pub fn set_ttl(&self, ttl_ms: u64) {
        unsafe { ffi::qihse_tsdb_set_ttl(self.ptr, ttl_ms) };
    }

    /// Trim expired chunks older than `current_ts - ttl_ms`.
    pub fn trim(&self, current_ts: u64) {
        unsafe { ffi::qihse_tsdb_trim(self.ptr, current_ts) };
    }
}

impl Drop for TimeSeriesDB {
    fn drop(&mut self) {
        unsafe { ffi::qihse_tsdb_destroy(self.ptr) };
    }
}

// ============================================================================
// DocumentStore
// ============================================================================

/// Safe wrapper for the QIHSE Document Store.
pub struct DocumentStore {
    ptr: *mut ffi::qihse_document_store_t,
}

impl DocumentStore {
    /// Creates a new DocumentStore backed by `kv`. The `KVStore` must outlive
    /// this `DocumentStore`.
    pub fn new(kv: &KVStore) -> Option<Self> {
        let ptr = unsafe { ffi::qihse_doc_store_create(kv.ptr) };
        if ptr.is_null() { None } else { Some(Self { ptr }) }
    }

    /// Inserts a JSON document. Returns `true` on success.
    pub fn insert_json(&self, doc_id: u64, json: &str) -> bool {
        let json_c = CString::new(json).expect("CString::new failed");
        unsafe { ffi::qihse_doc_store_insert_json(self.ptr, doc_id, json_c.as_ptr()) }
    }

    /// Executes a WHERE-clause query and returns matching document IDs.
    pub fn query(&self, where_clause: &str) -> Vec<u64> {
        let clause_c = CString::new(where_clause).expect("CString::new failed");
        let result = unsafe {
            ffi::qihse_doc_store_query_user(self.ptr, clause_c.as_ptr(), std::ptr::null_mut())
        };
        if result.doc_ids.is_null() || result.count == 0 {
            return Vec::new();
        }
        let ids = unsafe { std::slice::from_raw_parts(result.doc_ids, result.count) }.to_vec();
        unsafe { libc::free(result.doc_ids as *mut libc::c_void) };
        ids
    }
}

impl Drop for DocumentStore {
    fn drop(&mut self) {
        unsafe { ffi::qihse_doc_store_destroy(self.ptr) };
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kv_store() {
        let store = KVStore::new().expect("Failed to create KV store");

        assert_eq!(store.exists("test_key"), false);
        assert!(store.set("test_key", "test_value", 0, 0));
        assert_eq!(store.exists("test_key"), true);
        let val = store.get("test_key");
        assert_eq!(val, Some("test_value".to_string()));
        assert!(store.delete("test_key"));
        assert_eq!(store.exists("test_key"), false);
    }

    #[test]
    fn test_trinary_trie() {
        let trie = TrinaryTrie::new().expect("Failed to create TrinaryTrie");

        assert!(trie.insert("hello", b"world"));
        let val = trie.get("hello");
        assert_eq!(val.as_deref(), Some(b"world".as_ref()));
        assert!(trie.delete("hello"));
        assert!(trie.get("hello").is_none());
    }

    /// Authenticated system operator for vector-search tests.
    ///
    /// Follows the C gold-workload pattern (`gold_security_null_context.c`):
    /// honour a pre-configured `QIHSE_OPERATOR_PASSWORD` verifier, otherwise
    /// bootstrap the operator with a fixed test password. The password must
    /// be at least 12 characters (C requirement).
    fn operator_for_search_tests() -> User {
        const PW: &str = "qihse-rs-vector-test-op";
        assert!(Auth::init(), "qihse_auth_init failed");
        if let Ok(env_pw) = std::env::var("QIHSE_OPERATOR_PASSWORD") {
            if !env_pw.is_empty() {
                if let Some(user) = Auth::authenticate_id(0, &env_pw) {
                    return user;
                }
            }
        }
        if Auth::authenticate_id(0, PW).is_none() {
            assert!(
                Auth::bootstrap_operator(PW),
                "operator bootstrap failed (verifier already configured?)"
            );
        }
        Auth::authenticate_id(0, PW).expect("no authenticated operator for vector search")
    }

    #[test]
    fn test_vector_db() {
        let operator = operator_for_search_tests();
        assert_eq!(operator.id(), 0);
        assert_eq!(operator.classification(), 0xFFFF);

        let db = VectorDB::new(
            ffi::qihse_vector_db_backend_e_QIHSE_VECTOR_DB_INMEMORY,
            None,
        )
        .expect("Failed to create VectorDB");

        let vectors: Vec<f32> = vec![1.0, 0.0, 0.0, 0.0];
        let ids: Vec<u64> = vec![42];
        assert!(db.add_vectors(&vectors, 4, Some(&ids)));

        let query: Vec<f32> = vec![1.0, 0.0, 0.0, 0.0];
        let results = db.search(
            &operator,
            &query,
            1,
            ffi::qihse_vector_db_query_mode_e_QIHSE_VDB_QUERY_FLOAT32,
            ffi::qihse_distance_metric_e_QIHSE_DISTANCE_COSINE,
        );
        assert!(!results.is_empty());
        assert_eq!(results[0].id, 42);
    }

    /// Invariant 1: a NULL security context must never become an
    /// authorization bypass. The safe API makes this unrepresentable
    /// (`VectorDB::search` demands a `User`); this probe pins the underlying
    /// C contract through the crate's public `ffi` surface the same way the
    /// C gold workload `gold_security_null_context.c` does: a NULL-user query
    /// returns no rows, writes no result bytes, and reports `EACCES`.
    ///
    /// (A low-clearance negative probe is not constructible here: the public
    /// C add API writes every row as UNCLASSIFIED, so there is no classified
    /// payload to withhold from a reduced principal.)
    #[test]
    fn test_vector_db_null_user_fails_closed() {
        let db = VectorDB::new(
            ffi::qihse_vector_db_backend_e_QIHSE_VECTOR_DB_INMEMORY,
            None,
        )
        .expect("Failed to create VectorDB");

        let vectors: Vec<f32> = vec![1.0, 0.0, 0.0, 0.0];
        let ids: Vec<u64> = vec![7];
        assert!(db.add_vectors(&vectors, 4, Some(&ids)));

        let query: Vec<f32> = vec![1.0, 0.0, 0.0, 0.0];
        let q = ffi::qihse_vector_query_t {
            query_vector: query.as_ptr(),
            vector_dims: query.len(),
            top_k: 1,
            similarity_threshold: 0.0,
            include_vectors: false,
            include_metadata: false,
            use_trinary_candidates: false,
            candidate_count: 0,
            query_mode: ffi::qihse_vector_db_query_mode_e_QIHSE_VDB_QUERY_FLOAT32,
            candidate_pool_size: 0,
            distance_metric: ffi::qihse_distance_metric_e_QIHSE_DISTANCE_COSINE,
            metadata_filter: None,
            metadata_filter_opaque: std::ptr::null_mut(),
            user: std::ptr::null_mut(), // the deliberately missing context
        };

        let mut raw = ffi::qihse_vector_result_t {
            id: 0,
            score: 0.0,
            vector: std::ptr::null_mut(),
            vector_dims: 0,
            metadata: std::ptr::null_mut(),
            metadata_size: 0,
        };

        let found = unsafe { ffi::qihse_vector_db_search(db.ptr, &q, &mut raw, 1) };
        let err = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);

        assert!(
            found <= 0,
            "NULL user context returned {found} rows; invariant 1 violated"
        );
        assert_eq!(err, libc::EACCES, "expected EACCES for NULL user context");
        assert_eq!(raw.id, 0, "fail-closed search must not write result bytes");
        assert_eq!(raw.score, 0.0, "fail-closed search must not write a score");
    }

    #[test]
    fn test_tsdb() {
        let db = TimeSeriesDB::new().expect("Failed to create TimeSeriesDB");

        assert!(db.insert(1, 1000, 10.0, 0, 0));
        assert!(db.insert(1, 2000, 20.0, 0, 0));
        db.compress_flush();
        let avg = db.average_range(0, 3000);
        assert!(avg > 0.0, "Expected non-zero average, got {avg}");
    }

    #[test]
    fn test_doc_store() {
        let kv = KVStore::new().expect("Failed to create KVStore");
        let store = DocumentStore::new(&kv).expect("Failed to create DocumentStore");

        assert!(store.insert_json(1, r#"{"name":"alice","age":30}"#));
    }
}
