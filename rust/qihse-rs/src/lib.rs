#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

pub mod ffi {
    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}

use std::ffi::{CStr, CString};

/// Safe wrapper for QIHSE Key-Value Store
pub struct KVStore {
    ptr: *mut ffi::qihse_kv_store_t,
}

impl KVStore {
    /// Creates a new KVStore instance.
    pub fn new() -> Option<Self> {
        let ptr = unsafe { ffi::qihse_kv_store_create() };
        if ptr.is_null() {
            None
        } else {
            Some(Self { ptr })
        }
    }

    /// Sets a key-value pair.
    pub fn set(&self, key: &str, value: &str) -> bool {
        let key_c = CString::new(key).expect("CString::new failed");
        let val_c = CString::new(value).expect("CString::new failed");
        unsafe { ffi::qihse_kv_set(self.ptr, key_c.as_ptr(), val_c.as_ptr()) }
    }

    /// Gets a value by key.
    pub fn get(&self, key: &str) -> Option<String> {
        let key_c = CString::new(key).expect("CString::new failed");
        let val_ptr = unsafe { ffi::qihse_kv_get(self.ptr, key_c.as_ptr()) };
        if val_ptr.is_null() {
            None
        } else {
            let val = unsafe { CStr::from_ptr(val_ptr).to_string_lossy().into_owned() };
            unsafe { libc::free(val_ptr as *mut libc::c_void) };
            Some(val)
        }
    }

    /// Deletes a key.
    pub fn delete(&self, key: &str) -> bool {
        let key_c = CString::new(key).expect("CString::new failed");
        unsafe { ffi::qihse_kv_del(self.ptr, key_c.as_ptr()) }
    }

    /// Checks if a key exists.
    pub fn exists(&self, key: &str) -> bool {
        let key_c = CString::new(key).expect("CString::new failed");
        unsafe { ffi::qihse_kv_exists(self.ptr, key_c.as_ptr()) }
    }
}

impl Drop for KVStore {
    fn drop(&mut self) {
        unsafe { ffi::qihse_kv_store_destroy(self.ptr) };
    }
}

/// Safe wrapper for QIHSE Vector DB
pub struct VectorDB {
    ptr: ffi::qihse_vector_db_t,
}

impl VectorDB {
    /// Creates a new Vector DB instance.
    pub fn new(backend: ffi::qihse_vector_db_backend_e, db_path: Option<&str>) -> Option<Self> {
        let path_c = db_path.map(|s| CString::new(s).expect("CString::new failed"));
        let ptr = unsafe {
            ffi::qihse_vector_db_create(
                backend,
                std::ptr::null_mut(),
                path_c.as_ref().map_or(std::ptr::null(), |s| s.as_ptr()),
            )
        };
        if ptr.is_null() {
            None
        } else {
            Some(Self { ptr })
        }
    }
}

impl Drop for VectorDB {
    fn drop(&mut self) {
        unsafe { ffi::qihse_vector_db_destroy(self.ptr) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kv_store() {
        let store = KVStore::new().expect("Failed to create KV store");
        
        assert_eq!(store.exists("test_key"), false);
        
        assert!(store.set("test_key", "test_value"));
        assert_eq!(store.exists("test_key"), true);
        
        let val = store.get("test_key");
        assert_eq!(val, Some("test_value".to_string()));
        
        assert!(store.delete("test_key"));
        assert_eq!(store.exists("test_key"), false);
    }
}
