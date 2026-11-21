//! Authenticated native-storage API corresponding to the Python KV, time-series,
//! document and scoped event-stream bindings. This module deliberately does not
//! expose the legacy context-free read paths.
//!
//! # Principal lifetime
//! Every `unsafe` principal operation requires the caller to keep the C auth
//! table and the referenced principal alive and unchanged for the entire call.
//! No auth reset, destruction, revocation or concurrent mutation may race it.
//! This module cannot enforce that invariant against process-global C auth.
use crate::ffi;
use std::ffi::{c_char, c_void, CStr, CString};
use std::marker::PhantomData;
use std::ptr;

fn text(value: &str) -> Option<CString> { CString::new(value).ok() }

/// A non-owning native principal returned by authentication; not a safe Rust
/// lifetime-bound or owned handle.
pub struct StorageUser { ptr: *mut ffi::qihse_user_t }
impl StorageUser {
    /// # Safety
    /// The returned principal must remain alive and unchanged throughout every
    /// subsequent use; never reset/destroy auth or revoke it while in use.
    pub unsafe fn authenticate_id(id: u32, password: &str) -> Option<Self> {
        let password = text(password)?;
        let ptr = unsafe { ffi::qihse_auth_authenticate_id(id, password.as_ptr()) };
        if ptr.is_null() { None } else { Some(Self { ptr }) }
    }
    /// # Safety
    /// The returned principal must remain alive and unchanged throughout every
    /// subsequent use; never reset/destroy auth or revoke it while in use.
    pub unsafe fn authenticate(username: &str, password: &str) -> Option<Self> {
        let username = text(username)?;
        let password = text(password)?;
        let ptr = unsafe { ffi::qihse_auth_authenticate(username.as_ptr(), password.as_ptr()) };
        if ptr.is_null() { None } else { Some(Self { ptr }) }
    }
    unsafe fn active(&self) -> bool { unsafe { ffi::qihse_auth_user_is_active(self.ptr) } }
    unsafe fn system_operator(&self) -> bool {
        self.active() && unsafe { ffi::qihse_user_get_role(self.ptr) == 0 && ffi::qihse_user_get_tenant_id(self.ptr) == 0 }
    }
    unsafe fn allows_key(&self, key: &str) -> bool {
        if !self.active() || key.is_empty() || key.as_bytes().contains(&0) { return false; }
        if self.system_operator() { return true; }
        let scoped = if let Some(rest) = key.strip_prefix("t:") {
            let Some((tenant, suffix)) = rest.split_once('/') else { return false; };
            if tenant.is_empty() || !tenant.bytes().all(|b| b.is_ascii_digit()) { return false; }
            suffix
        } else { key };
        if scoped.starts_with("aimem:") || scoped.starts_with("aimemv:") || scoped.starts_with("aimem-") { return false; }
        let tenant = unsafe { ffi::qihse_user_get_tenant_id(self.ptr) };
        tenant == 0 || key.starts_with(&format!("t:{tenant}/")) || key.starts_with("commons/")
    }
}

/// Native KV row labels and expiry (absolute Unix milliseconds, zero = none).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecordMeta { pub classification: u16, pub sci_compartment: u16, pub expire_time_ms: u64 }

pub struct BatchSet<'a> {
    pub key: &'a str, pub value: &'a str, pub expire_time_ms: u64,
    pub classification: u16, pub sci_compartment: u16,
}

pub struct StorageKv { ptr: *mut ffi::qihse_kv_store_t }
impl StorageKv {
    /// Authenticated open also authorizes all persisted rows before recovery.
    pub unsafe fn open(user: &StorageUser) -> Option<Self> {
        if !user.active() { return None; }
        let ptr = unsafe { ffi::qihse_kv_store_create_user(user.ptr) };
        if ptr.is_null() { None } else { Some(Self { ptr }) }
    }
    pub unsafe fn set(&self, user: &StorageUser, key: &str, value: &str, class: u16, sci: u16) -> bool {
        let (Some(key), Some(value)) = (text(key), text(value)) else { return false };
        if !user.allows_key(key.to_str().unwrap_or_default()) { return false; }
        unsafe { ffi::qihse_kv_set_user(self.ptr, key.as_ptr(), value.as_ptr(), class, sci, user.ptr) }
    }
    /// Returns None for missing, expired or unauthorized rows; the returned C
    /// allocation is copied before release.
    pub unsafe fn get(&self, user: &StorageUser, key: &str) -> Option<String> {
        let key = text(key)?;
        if !user.allows_key(key.to_str().unwrap_or_default()) { return None; }
        let raw = unsafe { ffi::qihse_kv_get_user(self.ptr, key.as_ptr(), user.ptr) };
        if raw.is_null() { return None; }
        let result = unsafe { CStr::from_ptr(raw).to_string_lossy().into_owned() };
        unsafe { libc::free(raw.cast()) };
        Some(result)
    }
    pub unsafe fn meta(&self, user: &StorageUser, key: &str) -> Option<RecordMeta> {
        let key = text(key)?;
        if !user.allows_key(key.to_str().unwrap_or_default()) { return None; }
        let mut meta: ffi::qihse_kv_record_meta_t = unsafe { std::mem::zeroed() };
        if !unsafe { ffi::qihse_kv_meta_user(self.ptr, key.as_ptr(), user.ptr, &mut meta) } { return None; }
        Some(RecordMeta { classification: meta.classification, sci_compartment: meta.sci_compartment, expire_time_ms: meta.expire_time_ms })
    }
    pub unsafe fn delete(&self, user: &StorageUser, key: &str) -> bool {
        let Some(key) = text(key) else { return false };
        user.allows_key(key.to_str().unwrap_or_default()) && unsafe { ffi::qihse_kv_del_user(self.ptr, key.as_ptr(), user.ptr) }
    }
    pub unsafe fn exists(&self, user: &StorageUser, key: &str) -> bool {
        let Some(key) = text(key) else { return false };
        user.allows_key(key.to_str().unwrap_or_default()) && unsafe { ffi::qihse_kv_exists_user(self.ptr, key.as_ptr(), user.ptr) }
    }
    pub unsafe fn expire(&self, user: &StorageUser, key: &str, ttl_ms: u64) -> bool {
        let Some(key) = text(key) else { return false };
        user.allows_key(key.to_str().unwrap_or_default()) && unsafe { ffi::qihse_kv_expire(self.ptr, key.as_ptr(), ttl_ms, user.ptr) }
    }
    /// Native filtering occurs before disclosure to the callback. A prefix is
    /// never emulated by unscoped enumeration.
    pub unsafe fn items(&self, user: &StorageUser, prefix: Option<&str>) -> Option<Vec<(String, String)>> {
        if !user.active() { return None; }
        let prefix = match prefix { Some(prefix) => Some(text(prefix)?), None => None };
        let mut items = (user, Vec::new());
        unsafe extern "C" fn collect(key: *const c_char, value: *const c_char, ctx: *mut c_void) -> bool {
            if key.is_null() || value.is_null() { return false; }
            let (user, items) = &mut *(ctx as *mut (&StorageUser, Vec<(String, String)>));
            let key = CStr::from_ptr(key).to_string_lossy().into_owned();
            if user.allows_key(&key) { items.push((key, CStr::from_ptr(value).to_string_lossy().into_owned())); }
            true
        }
        let ctx = (&mut items as *mut (&StorageUser, Vec<(String, String)>)).cast();
        let ok = unsafe { match prefix.as_ref() {
            Some(prefix) => ffi::qihse_kv_foreach_prefix_user(self.ptr, prefix.as_ptr(), user.ptr, Some(collect), ctx),
            None => ffi::qihse_kv_foreach_user(self.ptr, user.ptr, Some(collect), ctx),
        } };
        if ok { Some(items.1) } else { None }
    }
    pub unsafe fn keys(&self, user: &StorageUser, prefix: Option<&str>) -> Option<Vec<String>> {
        Some(self.items(user, prefix)?.into_iter().map(|(key, _)| key).collect())
    }
    pub unsafe fn size(&self, user: &StorageUser) -> Option<usize> { Some(self.items(user, None)?.len()) }
    pub unsafe fn get_shard(&self, user: &StorageUser, shard: &str) -> Option<String> {
        self.get(user, &format!("shard:{shard}"))
    }
    pub unsafe fn lookup_ip(&self, user: &StorageUser, ip: &str) -> bool {
        self.exists(user, &format!("ip:{ip}"))
    }
    /// Operator-only whole-store clear (an empty store and denied operation
    /// both return zero in the native ABI).
    pub unsafe fn clear(&self, user: &StorageUser) -> Option<usize> {
        if !user.system_operator() { return None; }
        Some(unsafe { ffi::qihse_kv_clear_user(self.ptr, user.ptr) })
    }
    /// Non-atomic on error; native failure can leave a recoverable WAL prefix.
    pub unsafe fn set_batch_durable(&self, user: &StorageUser, records: &[BatchSet<'_>]) -> bool {
        if !user.active() || records.is_empty() || records.len() > 4096 { return false; }
        let mut strings = Vec::with_capacity(records.len());
        let mut bytes = 0usize;
        for row in records {
            let (Some(key), Some(value)) = (text(row.key), text(row.value)) else { return false; };
            if !user.allows_key(key.to_str().unwrap_or_default()) { return false; }
            let Some(size) = bytes.checked_add(40).and_then(|n| n.checked_add(key.as_bytes().len())).and_then(|n| n.checked_add(value.as_bytes().len())) else { return false; };
            if size > 64 * 1024 * 1024 { return false; }
            bytes = size;
            strings.push((key, value));
        }
        let native: Vec<_> = records.iter().zip(&strings).map(|(row, (key, value))| ffi::qihse_kv_batch_set_record_t {
            key: key.as_ptr(), value: value.as_ptr(), expire_time_ms: row.expire_time_ms,
            classification: row.classification, sci_compartment: row.sci_compartment,
        }).collect();
        unsafe { ffi::qihse_kv_set_batch_durable_user(self.ptr, native.as_ptr(), native.len(), user.ptr) }
    }
    /// Operator-only native export; no raw snapshot fallback.
    pub unsafe fn save(&self, user: &StorageUser, path: &str) -> bool {
        let Some(path) = text(path) else { return false };
        user.system_operator() && unsafe { ffi::qihse_kv_save_user(self.ptr, path.as_ptr(), user.ptr) == 0 }
    }
    pub unsafe fn load(&self, user: &StorageUser, path: &str) -> bool {
        let Some(path) = text(path) else { return false };
        user.system_operator() && unsafe { ffi::qihse_kv_load_user(self.ptr, path.as_ptr(), user.ptr) == 0 }
    }
}
impl Drop for StorageKv { fn drop(&mut self) { unsafe { ffi::qihse_kv_store_destroy(self.ptr) } } }

pub struct StorageTimeSeries { ptr: *mut ffi::qihse_tsdb_t }
impl StorageTimeSeries {
    pub fn new() -> Option<Self> {
        let ptr = unsafe { ffi::qihse_tsdb_create() };
        if ptr.is_null() { None } else { Some(Self { ptr }) }
    }
    pub fn insert(&self, series_id: u32, timestamp: u64, value: f64, class: u16, sci: u16) -> bool {
        unsafe { ffi::qihse_tsdb_insert(self.ptr, series_id, timestamp, value, class, sci) }
    }
    pub fn flush(&self) { unsafe { ffi::qihse_tsdb_compress_flush(self.ptr) } }
    pub unsafe fn average_range(&self, user: &StorageUser, start: u64, end: u64) -> Option<f64> {
        if !user.active() || start > end { return None; }
        // Python's average_range spans *all* series and returns zero for an
        // empty authorized range; the per-series aggregate is not equivalent.
        Some(unsafe { ffi::qihse_tsdb_average_range_user(self.ptr, start, end, user.ptr) })
    }
    pub fn set_ttl(&self, ttl_ms: u64) { unsafe { ffi::qihse_tsdb_set_ttl(self.ptr, ttl_ms) } }
    pub fn trim(&self, current_ts: u64) { unsafe { ffi::qihse_tsdb_trim(self.ptr, current_ts) } }
}
impl Drop for StorageTimeSeries { fn drop(&mut self) { unsafe { ffi::qihse_tsdb_destroy(self.ptr) } } }

pub struct StorageDocument<'kv> { ptr: *mut ffi::qihse_document_store_t, _kv: PhantomData<&'kv StorageKv> }
impl<'kv> StorageDocument<'kv> {
    pub fn new(kv: &'kv StorageKv) -> Option<Self> {
        let ptr = unsafe { ffi::qihse_doc_store_create(kv.ptr) };
        if ptr.is_null() { None } else { Some(Self { ptr, _kv: PhantomData }) }
    }
    pub unsafe fn insert_json(&self, user: &StorageUser, id: u64, json: &str) -> bool {
        let Some(json) = text(json) else { return false };
        user.active() && unsafe { ffi::qihse_doc_store_insert_json_user(self.ptr, id, json.as_ptr(), user.ptr) }
    }
    pub unsafe fn get_json(&self, user: &StorageUser, id: u64) -> Option<String> {
        if !user.active() { return None; }
        let mut out = ptr::null_mut();
        if !unsafe { ffi::qihse_doc_store_get_json_user(self.ptr, id, user.ptr, &mut out) } || out.is_null() { return None; }
        let value = unsafe { CStr::from_ptr(out).to_string_lossy().into_owned() };
        unsafe { libc::free(out.cast()) };
        Some(value)
    }
    pub unsafe fn get_version_json(&self, user: &StorageUser, id: u64, version: u64) -> Option<String> {
        if !user.active() { return None; }
        let mut out = ptr::null_mut();
        if !unsafe { ffi::qihse_doc_store_get_version_json_user(self.ptr, id, version, user.ptr, &mut out) } || out.is_null() { return None; }
        let value = unsafe { CStr::from_ptr(out).to_string_lossy().into_owned() };
        unsafe { libc::free(out.cast()) };
        Some(value)
    }
    pub unsafe fn list(&self, user: &StorageUser, limit: usize) -> Vec<u64> {
        if !user.active() { return Vec::new(); }
        let result = unsafe { ffi::qihse_doc_store_list_user(self.ptr, user.ptr, limit.min(128)) };
        let ids = if result.doc_ids.is_null() || result.count == 0 { Vec::new() }
            else { unsafe { std::slice::from_raw_parts(result.doc_ids, result.count).to_vec() } };
        unsafe { libc::free(result.doc_ids.cast()) };
        ids
    }
}
impl Drop for StorageDocument<'_> { fn drop(&mut self) { unsafe { ffi::qihse_doc_store_destroy(self.ptr) } } }

/// Scoped V2 event identity; tenant is derived by the C layer from `StorageUser`.
#[derive(Debug, Clone, Copy)]
pub struct EventScope<'a> { pub topic: &'a str, pub classification: u16, pub sci: u16 }
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Durability { None, Fdatasync, Full }
#[derive(Debug, Clone)]
pub struct EventRecord {
    pub schema_id: u32, pub stream_offset: u64, pub prev_record_offset: u64,
    pub event_id: [u8; 48], pub flags: u32, pub payload: Vec<u8>,
}
impl EventRecord { pub fn is_committed(&self) -> bool { self.flags & 1 != 0 } pub fn is_corrupt(&self) -> bool { self.flags & 2 != 0 } }
#[derive(Debug, Clone, Copy)]
pub struct EventInput<'a> { pub schema_id: u32, pub event_id: Option<&'a [u8; 48]>, pub payload: &'a [u8] }
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AppendResult { pub stream_offset: u64, pub duplicate: bool }

fn native_scope(scope: EventScope<'_>) -> Option<(CString, ffi::qihse_es_scope_t)> {
    let topic = text(scope.topic)?;
    let raw = ffi::qihse_es_scope_t { topic: topic.as_ptr(), classification: scope.classification, sci: scope.sci };
    Some((topic, raw))
}
fn decode(row: &ffi::qihse_es_read_record_t) -> Option<EventRecord> {
    if row.payload_size > 16 * 1024 * 1024 || row.header.payload_size != row.payload_size as u64 || (row.payload_size != 0 && row.payload.is_null()) { return None; }
    let payload = if row.payload_size == 0 { Vec::new() } else { unsafe { std::slice::from_raw_parts(row.payload, row.payload_size).to_vec() } };
    Some(EventRecord { schema_id: row.header.schema_id, stream_offset: row.header.stream_offset,
        prev_record_offset: row.header.prev_record_offset, event_id: row.header.event_id, flags: row.header.flags, payload })
}

pub struct StorageEventStream { ptr: *mut ffi::qihse_event_stream_t, read_only: bool }
impl StorageEventStream {
    pub fn open(path: &str, durability: Durability, read_only: bool) -> Option<Self> {
        let path = text(path)?;
        let mode = match durability { Durability::None => 0, Durability::Fdatasync => 1, Durability::Full => 2 };
        let ptr = unsafe { ffi::qihse_event_stream_open(path.as_ptr(), mode, read_only) };
        if ptr.is_null() { None } else { Some(Self { ptr, read_only }) }
    }
    pub fn flush(&self) -> bool { unsafe { ffi::qihse_event_stream_flush(self.ptr) } }
    /// A failed batch may have committed a prefix; inspect durable state before retry.
    pub unsafe fn append_batch(&self, user: &StorageUser, scope: EventScope<'_>, records: &[EventInput<'_>]) -> Option<Vec<AppendResult>> {
        if self.read_only || !user.active() || records.is_empty() || records.len() > 1024 { return None; }
        let (_topic, scope) = native_scope(scope)?;
        let mut total = 0usize;
        let mut native = Vec::with_capacity(records.len());
        for row in records {
            if row.payload.len() > 16 * 1024 * 1024 { return None; }
            total = total.checked_add(row.payload.len())?;
            if total > 64 * 1024 * 1024 { return None; }
            native.push(ffi::qihse_es_batch_record_t { schema_id: row.schema_id,
                event_id: row.event_id.map_or(ptr::null(), |id| id.as_ptr()),
                payload: if row.payload.is_empty() { ptr::null() } else { row.payload.as_ptr() },
                payload_size: row.payload.len() });
        }
        let mut results = vec![ffi::qihse_es_batch_result_t { stream_offset: 0, duplicate: false }; native.len()];
        if !unsafe { ffi::qihse_event_stream_append_batch(self.ptr, user.ptr, &scope, native.as_ptr(), native.len(), results.as_mut_ptr()) } { return None; }
        Some(results.into_iter().map(|r| AppendResult { stream_offset: r.stream_offset, duplicate: r.duplicate }).collect())
    }
    /// `None` is a native read/authorization error; successful EOF is an empty page.
    pub unsafe fn read_batch(&self, user: &StorageUser, scope: EventScope<'_>, cursor: u64,
        capacity: usize, max_payload_bytes: usize) -> Option<(Vec<EventRecord>, u64)> {
        if !user.active() || !(1..=1024).contains(&capacity) || max_payload_bytes > 64 * 1024 * 1024 { return None; }
        let (_topic, scope) = native_scope(scope)?;
        let mut native: Vec<ffi::qihse_es_read_record_t> = (0..capacity).map(|_| unsafe { std::mem::zeroed() }).collect();
        let mut next = cursor;
        let mut count = 0usize;
        let ok = unsafe { ffi::qihse_event_stream_read_batch(self.ptr, user.ptr, &scope, &mut next, native.as_mut_ptr(), capacity, max_payload_bytes, &mut count) };
        if !ok || count > capacity { return None; }
        let result = native[..count].iter().map(decode).collect::<Option<Vec<_>>>();
        unsafe { ffi::qihse_event_stream_batch_free(native.as_mut_ptr(), count) };
        Some((result?, next))
    }
    pub fn compute_archive_id(archive: &[u8], scan_version: &str, schema: u32) -> Option<[u8; 48]> {
        let scan = text(scan_version)?;
        let mut out = [0; 48];
        let ptr = if archive.is_empty() { ptr::null() } else { archive.as_ptr() };
        if unsafe { ffi::qihse_event_stream_archive_id(ptr, archive.len(), scan.as_ptr(), schema, out.as_mut_ptr()) } { Some(out) } else { None }
    }
    pub fn compute_member_id(archive: &[u8; 48], member: &str, scan_version: &str, schema: u32) -> Option<[u8; 48]> {
        let member = text(member)?;
        let scan = text(scan_version)?;
        let mut out = [0; 48];
        if unsafe { ffi::qihse_event_stream_member_id(archive.as_ptr(), member.as_ptr(), scan.as_ptr(), schema, out.as_mut_ptr()) } { Some(out) } else { None }
    }
}
impl Drop for StorageEventStream { fn drop(&mut self) { unsafe { ffi::qihse_event_stream_destroy(self.ptr) } } }
