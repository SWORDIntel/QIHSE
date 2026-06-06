use std::ffi::{CStr, CString};
use std::os::raw::c_char;

// Opaque handles
pub enum QihseKvStore {}
pub enum QihseVectorDb {}

// FFI Bindings
extern "C" {
    fn qihse_kv_store_create() -> *mut QihseKvStore;
    fn qihse_kv_store_destroy(store: *mut QihseKvStore);
    fn qihse_kv_set(store: *mut QihseKvStore, key: *const c_char, val: *const c_char) -> bool;
    fn qihse_kv_get(store: *mut QihseKvStore, key: *const c_char) -> *mut c_char;
    fn qihse_parse_qql_to_ast(qql: *const c_char) -> *mut std::ffi::c_void;
}

pub struct Database {
    kv: *mut QihseKvStore,
}

impl Database {
    pub fn new() -> Self {
        unsafe {
            Database {
                kv: qihse_kv_store_create(),
            }
        }
    }

    pub fn kv_set(&self, key: &str, val: &str) {
        let c_key = CString::new(key).unwrap();
        let c_val = CString::new(val).unwrap();
        unsafe {
            qihse_kv_set(self.kv, c_key.as_ptr(), c_val.as_ptr());
        }
    }

    pub fn kv_get(&self, key: &str) -> Option<String> {
        let c_key = CString::new(key).unwrap();
        unsafe {
            let ptr = qihse_kv_get(self.kv, c_key.as_ptr());
            if ptr.is_null() {
                return None;
            }
            let val = CStr::from_ptr(ptr).to_string_lossy().into_owned();
            libc::free(ptr as *mut libc::c_void);
            Some(val)
        }
    }

    pub fn execute(&self, qql: &str) {
        let c_qql = CString::new(qql).unwrap();
        unsafe {
            qihse_parse_qql_to_ast(c_qql.as_ptr());
        }
    }
}

impl Drop for Database {
    fn drop(&mut self) {
        unsafe {
            qihse_kv_store_destroy(self.kv);
        }
    }
}
