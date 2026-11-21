//! Native-backed, deliberately partial port of the public Python vector APIs.
//!
//! This file is not yet exported by `lib.rs` (owned by another task). Until
//! integrated, tests include it with `#[path]`. C signatures missing from
//! `wrapper.h` are declared below against qihse_fts.h / qihse_keystone.h.
//!
//! Public API inventory (Python -> here):
//! - core.DistanceMetric / QueryMode: PARTIAL, use the native `ffi` constants
//!   instead of Rust enum aliases. VectorResult: PARTIAL (id/score, no vector).
//!   VectorQuery: PARTIAL (vector/top_k/mode/metric, no result-vector or
//!   metadata flags or similarity threshold). VectorDB.create, add_vectors,
//!   search, close: PARTIAL (`NativeVectorDB`, no metadata insertion/result,
//!   explicit principal). VectorDB.open: UNPORTED.
//!   VectorDB.add_edges, add_edge, replace_edge, remove_edge, neighbors,
//!   edge_records, build_graph, build_int8, build_fp8, build_fp4, build_int4,
//!   flush, run_memory_maintenance, set_memory_budget, get_memory_usage,
//!   dims, start_pg_wire: UNPORTED. Python context manager: UNPORTED.
//!   QIHSE_VDB_OPEN_* and QIHSE_CTR_* constants, Container.open_read,
//!   open_write, close, section_length, list_sections, read_section, flush,
//!   pack, unpack: UNPORTED.
//! - neural.KeystoneClass and NeuralClassifier.classify: PORTED.
//! - anchor.AnchorIndex.lower_bound/search: PORTED for sorted `&[i64]`.
//! - fts.FTSResult and FTSIndex.add_document/search/get_semantic_class/
//!   save/load/close: PORTED with mandatory authenticated principal. FTSIndex
//!   handle property and Python context manager: UNPORTED.
//! - fusion.FusionResult and MultimodalFusion.search: UNPORTED (needs native
//!   vector/FTS handle integration; no Python or Rust-side fallback).

use crate::ffi;
use std::ffi::{c_char, c_int, c_void, CStr, CString};
use std::ptr::NonNull;

#[derive(Debug, PartialEq, Eq)]
pub enum VectorError {
    InvalidInput(&'static str),
    Native(&'static str),
}

type Result<T> = std::result::Result<T, VectorError>;

#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeystoneClass {
    Unknown = 0,
    Financial = 1,
    Corporate = 2,
    Government = 3,
    Infrastructure = 4,
    Consumer = 5,
}

impl KeystoneClass {
    fn from_native(value: i32) -> Result<Self> {
        match value {
            0 => Ok(Self::Unknown),
            1 => Ok(Self::Financial),
            2 => Ok(Self::Corporate),
            3 => Ok(Self::Government),
            4 => Ok(Self::Infrastructure),
            5 => Ok(Self::Consumer),
            _ => Err(VectorError::Native("invalid native semantic class")),
        }
    }
}

// qihse_fts.h is not included by wrapper.h. These repr(C) declarations are
// matched to include/qihse_fts.h:12-18 and include/qihse_keystone.h:60-69.
#[repr(C)]
struct RawFtsResult {
    doc_id: u64,
    bm25_score: f32,
    semantic_class: c_int,
}

extern "C" {
    fn qihse_keystone_classify_context(text: *const c_char, len: usize, class: *mut c_int, confidence: *mut f32) -> c_int;
    fn qihse_keystone_class_name(class: c_int) -> *const c_char;
    fn qihse_keystone_anchor_lower_bound(arr: *const i64, n: usize, key: i64) -> usize;
    fn qihse_keystone_anchor_search(arr: *const i64, n: usize, key: i64) -> i64;
    fn qihse_fts_create() -> *mut c_void;
    fn qihse_fts_destroy(index: *mut c_void);
    fn qihse_fts_add_document_user(index: *mut c_void, doc_id: u64, text: *const c_char, len: usize, classification: u16, sci: u16, class: c_int, user: *mut ffi::qihse_user_t) -> bool;
    fn qihse_fts_search_user_filtered(index: *mut c_void, query: *const c_char, user: *mut ffi::qihse_user_t, results: *mut RawFtsResult, top_k: c_int, semantic_mask: u8) -> c_int;
    fn qihse_fts_get_doc_semantic_class_user(index: *mut c_void, doc_id: u64, user: *mut ffi::qihse_user_t) -> c_int;
    fn qihse_fts_save(index: *mut c_void, path: *const c_char, user: *mut ffi::qihse_user_t) -> bool;
    fn qihse_fts_load(path: *const c_char, user: *mut ffi::qihse_user_t) -> *mut c_void;
}

fn c_string(value: &str) -> Result<CString> {
    CString::new(value).map_err(|_| VectorError::InvalidInput("interior NUL byte"))
}

/// A non-owning, authenticated C principal. Auth must be initialized by the
/// embedding application; never infer an operator or use a NULL user on reads.
/// The native auth layer owns the handle and can revoke it independently.
/// It does not become safe to use merely because this Rust value is still alive.
pub struct Principal(NonNull<ffi::qihse_user_t>);

impl Principal {
    /// # Safety
    /// The caller must keep native auth initialized and prevent reset, shutdown,
    /// user deletion, or other invalidation of the returned C user for as long as
    /// it is used. Native auth mutations must not race authentication or its use.
    pub unsafe fn authenticate_id(user_id: u32, password: &str) -> Result<Self> {
        let password = c_string(password)?;
        let ptr = unsafe { ffi::qihse_auth_authenticate_id(user_id, password.as_ptr()) };
        NonNull::new(ptr).map(Self).ok_or(VectorError::Native("authentication failed"))
    }

    fn as_ptr(&self) -> *mut ffi::qihse_user_t { self.0.as_ptr() }
}

pub struct NeuralClassifier;

impl NeuralClassifier {
    pub fn classify(context: &str) -> Result<(KeystoneClass, String, f32)> {
        if context.is_empty() { return Err(VectorError::InvalidInput("empty context")); }
        let mut class = 0;
        let mut confidence = 0.0;
        let status = unsafe { qihse_keystone_classify_context(context.as_ptr().cast(), context.len(), &mut class, &mut confidence) };
        if status != 0 { return Err(VectorError::Native("classification failed")); }
        let class = KeystoneClass::from_native(class)?;
        let name = unsafe { qihse_keystone_class_name(class as c_int) };
        if name.is_null() { return Err(VectorError::Native("missing native class name")); }
        let name = unsafe { CStr::from_ptr(name) }.to_str().map_err(|_| VectorError::Native("invalid native class name"))?;
        Ok((class, name.to_owned(), confidence))
    }
}

pub struct AnchorIndex;

impl AnchorIndex {
    /// The caller must supply a sorted array, as for the Python API.
    pub fn lower_bound(sorted: &[i64], key: i64) -> usize {
        unsafe { qihse_keystone_anchor_lower_bound(sorted.as_ptr(), sorted.len(), key) }
    }

    pub fn search(sorted: &[i64], key: i64) -> Option<usize> {
        let index = unsafe { qihse_keystone_anchor_search(sorted.as_ptr(), sorted.len(), key) };
        if index < 0 { None } else { Some(index as usize) }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct FTSResult {
    pub doc_id: u64,
    pub score: f32,
    pub semantic_class: KeystoneClass,
}

/// Owned native index. Searches, metadata lookup, and export require the
/// explicit authenticated principal. Not Send/Sync: C has no such guarantee.
pub struct FTSIndex(NonNull<c_void>);

impl FTSIndex {
    pub fn new() -> Result<Self> {
        NonNull::new(unsafe { qihse_fts_create() }).map(Self).ok_or(VectorError::Native("FTS create failed"))
    }

    /// # Safety
    /// `user` must still refer to a live native auth user throughout this call;
    /// native auth reset, shutdown, deletion, and concurrent invalidation are forbidden.
    pub unsafe fn add_document(&mut self, user: &Principal, doc_id: u64, text: &str, classification: u16, sci: u16, class: KeystoneClass) -> Result<()> {
        // Length-delimited native call; text may contain NUL bytes.
        if unsafe { qihse_fts_add_document_user(self.0.as_ptr(), doc_id, text.as_ptr().cast(), text.len(), classification, sci, class as c_int, user.as_ptr()) } {
            Ok(())
        } else { Err(VectorError::Native("FTS add denied or failed")) }
    }

    /// # Safety
    /// `user` must still refer to a live native auth user throughout this call;
    /// native auth reset, shutdown, deletion, and concurrent invalidation are forbidden.
    pub unsafe fn search(&self, user: &Principal, query: &str, top_k: usize, semantic_mask: u8) -> Result<Vec<FTSResult>> {
        let query = c_string(query)?;
        let limit = c_int::try_from(top_k).map_err(|_| VectorError::InvalidInput("top_k exceeds native int"))?;
        if limit == 0 { return Ok(Vec::new()); }
        let mut rows = Vec::new();
        rows.try_reserve_exact(top_k).map_err(|_| VectorError::InvalidInput("top_k exceeds available memory"))?;
        rows.resize_with(top_k, || RawFtsResult { doc_id: 0, bm25_score: 0.0, semantic_class: 0 });
        let found = unsafe { qihse_fts_search_user_filtered(self.0.as_ptr(), query.as_ptr(), user.as_ptr(), rows.as_mut_ptr(), limit, semantic_mask) };
        if found < 0 || found > limit { return Err(VectorError::Native("FTS search failed")); }
        rows[..found as usize].iter().map(|row| Ok(FTSResult { doc_id: row.doc_id, score: row.bm25_score, semantic_class: KeystoneClass::from_native(row.semantic_class)? })).collect()
    }

    /// Native C returns UNKNOWN for missing or inaccessible documents.
    /// # Safety
    /// `user` must still refer to a live native auth user throughout this call;
    /// native auth reset, shutdown, deletion, and concurrent invalidation are forbidden.
    pub unsafe fn get_semantic_class(&self, user: &Principal, doc_id: u64) -> Result<KeystoneClass> {
        KeystoneClass::from_native(unsafe { qihse_fts_get_doc_semantic_class_user(self.0.as_ptr(), doc_id, user.as_ptr()) })
    }

    /// # Safety
    /// `user` must still refer to a live native auth user throughout this call;
    /// native auth reset, shutdown, deletion, and concurrent invalidation are forbidden.
    pub unsafe fn save(&self, user: &Principal, path: &str) -> Result<()> {
        let path = c_string(path)?;
        if unsafe { qihse_fts_save(self.0.as_ptr(), path.as_ptr(), user.as_ptr()) } { Ok(()) }
        else { Err(VectorError::Native("FTS export denied or failed")) }
    }

    /// # Safety
    /// `user` must still refer to a live native auth user throughout this call;
    /// native auth reset, shutdown, deletion, and concurrent invalidation are forbidden.
    pub unsafe fn load(user: &Principal, path: &str) -> Result<Self> {
        let path = c_string(path)?;
        NonNull::new(unsafe { qihse_fts_load(path.as_ptr(), user.as_ptr()) }).map(Self).ok_or(VectorError::Native("FTS load denied or failed"))
    }
}

impl Drop for FTSIndex {
    fn drop(&mut self) { unsafe { qihse_fts_destroy(self.0.as_ptr()) }; }
}

#[derive(Debug, Clone, PartialEq)]
pub struct VectorResult { pub id: u64, pub score: f32 }

/// Mirrors Python's query defaults except the principal is always explicit.
pub struct VectorQuery<'a> {
    pub vector: &'a [f32],
    pub top_k: usize,
    pub mode: ffi::qihse_vector_db_query_mode_e,
    pub metric: ffi::qihse_distance_metric_e,
}

/// Native-backed vector DB with no insecure Python or exact-search fallback.
pub struct NativeVectorDB { ptr: ffi::qihse_vector_db_t, closed: bool }

impl NativeVectorDB {
    pub fn create(path: Option<&str>) -> Result<Self> {
        let path = path.map(c_string).transpose()?;
        let ptr = unsafe { ffi::qihse_vector_db_create(ffi::qihse_vector_db_backend_e_QIHSE_VECTOR_DB_INMEMORY, std::ptr::null_mut(), path.as_ref().map_or(std::ptr::null(), |p| p.as_ptr())) };
        if ptr.is_null() { Err(VectorError::Native("vector DB create failed")) }
        else { Ok(Self { ptr, closed: false }) }
    }

    pub fn add_vectors(&mut self, vectors: &[f32], dims: usize, ids: Option<&[u64]>) -> Result<()> {
        if self.closed { return Err(VectorError::InvalidInput("database is closed")); }
        if dims == 0 || vectors.is_empty() || vectors.len() % dims != 0 || ids.is_some_and(|ids| ids.len() != vectors.len() / dims) {
            return Err(VectorError::InvalidInput("vector dimensions or id count mismatch"));
        }
        let ok = unsafe { ffi::qihse_vector_db_add_vectors(self.ptr, vectors.as_ptr(), vectors.len() / dims, dims, ids.map_or(std::ptr::null(), |v| v.as_ptr()), std::ptr::null(), std::ptr::null()) };
        if ok { Ok(()) } else { Err(VectorError::Native("vector add failed")) }
    }

    /// # Safety
    /// `user` must still refer to a live native auth user throughout this call;
    /// native auth reset, shutdown, deletion, and concurrent invalidation are forbidden.
    pub unsafe fn search(&self, user: &Principal, request: VectorQuery<'_>) -> Result<Vec<VectorResult>> {
        if self.closed { return Err(VectorError::InvalidInput("database is closed")); }
        if request.vector.is_empty() { return Err(VectorError::InvalidInput("empty vector query")); }
        if request.top_k == 0 { return Ok(Vec::new()); }
        let mut rows = Vec::new();
        rows.try_reserve_exact(request.top_k).map_err(|_| VectorError::InvalidInput("top_k exceeds available memory"))?;
        rows.resize_with(request.top_k, || ffi::qihse_vector_result_t { id: 0, score: 0.0, vector: std::ptr::null_mut(), vector_dims: 0, metadata: std::ptr::null_mut(), metadata_size: 0 });
        let query = ffi::qihse_vector_query_t {
            query_vector: request.vector.as_ptr(), vector_dims: request.vector.len(), top_k: request.top_k,
            similarity_threshold: 0.0, include_vectors: false, include_metadata: false,
            use_trinary_candidates: false, candidate_count: request.top_k.saturating_mul(2),
            query_mode: request.mode, candidate_pool_size: request.top_k.saturating_mul(20),
            distance_metric: request.metric, metadata_filter: None,
            metadata_filter_opaque: std::ptr::null_mut(), user: user.as_ptr(),
        };
        let found = unsafe { ffi::qihse_vector_db_search(self.ptr, &query, rows.as_mut_ptr(), request.top_k) };
        if found < 0 || found as usize > request.top_k { return Err(VectorError::Native("vector search failed")); }
        Ok(rows[..found as usize].iter().map(|row| VectorResult { id: row.id, score: row.score }).collect())
    }

    pub fn close(&mut self) -> Result<()> {
        if self.closed { return Ok(()); }
        // Native close flushes AND destroys the handle, even on flush failure.
        let ok = unsafe { ffi::qihse_vector_db_close(self.ptr) };
        self.closed = true;
        if ok { Ok(()) } else { Err(VectorError::Native("vector close failed")) }
    }
}

impl Drop for NativeVectorDB {
    fn drop(&mut self) {
        if !self.closed { unsafe { ffi::qihse_vector_db_destroy(self.ptr) }; }
    }
}
