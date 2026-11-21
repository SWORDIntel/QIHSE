// Until lib.rs exports the owned module, exercise the exact source as an
// integration module. The parent can add `pub mod python_storage;` at integration.
mod ffi { pub use qihse_rs::ffi::*; }
#[path = "../src/python_storage.rs"]
mod python_storage;
use python_storage::*;
use qihse_rs::Auth;

#[test]
fn native_storage_authorization_and_lifetimes() {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    let nonce = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join(format!(".qihse-rs-storage-{}-{nonce}", std::process::id()));
    std::fs::DirBuilder::new().mode(0o700).create(&dir).unwrap();
    assert_eq!(std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777, 0o700);
    std::env::set_var("QIHSE_DATA_DIR", &dir);
    assert!(Auth::init());
    let password = std::env::var("QIHSE_OPERATOR_PASSWORD").unwrap_or_default();
    let password = if password.is_empty() { "qihse-rs-storage-op" } else { &password };
    // SAFETY: this test owns its process auth table and never resets it while
    // either principal is used; native stores are dropped before audit shutdown.
    unsafe {
    if StorageUser::authenticate_id(0, password).is_none() {
        assert!(Auth::bootstrap_operator(password));
    }
    let operator = StorageUser::authenticate_id(0, password).unwrap();
    let guest_password = "qihse-rs-storage-guest";
    let guest = ffi::qihse_auth_create_user(
        ffi::qihse_auth_get_user(0), 57007, ffi::QIHSE_ROLE_GUEST as u16,
        0, 0, std::ffi::CString::new(guest_password).unwrap().as_ptr(), false,
    );
    assert!(!guest.is_null());
    let guest = StorageUser::authenticate_id(57007, guest_password).unwrap();

    let kv = StorageKv::open(&operator).expect("authenticated KV open");
    assert!(!kv.exists(&guest, "storage:high"));
    assert!(kv.set(&operator, "storage:high", "classified payload", 3, 1));
    assert!(kv.get(&guest, "storage:high").is_none());
    assert!(kv.meta(&guest, "storage:high").is_none());
    assert!(!kv.exists(&guest, "storage:high"));
    assert!(kv.get(&operator, "storage:high").unwrap().contains("classified"));
    assert_eq!(kv.meta(&operator, "storage:high").unwrap().classification, 3);
    assert_eq!(kv.meta(&operator, "storage:high").unwrap().sci_compartment, 1);
    assert!(kv.items(&guest, Some("storage:")).unwrap().is_empty());
    assert!(kv.keys(&operator, Some("storage:\0")).is_none());
    assert!(!kv.set(&guest, "aimem:direct", "forbidden", 0, 0));
    assert!(!kv.set(&guest, "t:42/aimem:direct", "forbidden", 0, 0));
    assert!(kv.get(&guest, "aimem:direct").is_none());
    assert!(!kv.save(&guest, dir.join("guest.qfs").to_str().unwrap()));
    assert!(kv.set(&operator, "storage:public", "", 0, 0));
    assert_eq!(kv.get(&guest, "storage:public").as_deref(), Some(""));
    assert!(kv.keys(&guest, Some("storage:")).unwrap().contains(&"storage:public".to_string()));
    assert!(kv.expire(&operator, "storage:public", 10_000));
    assert!(kv.delete(&operator, "storage:public"));
    assert_eq!(kv.get(&guest, "storage:public"), None);
    assert!(!kv.set_batch_durable(&guest, &[BatchSet {
        key: "storage:denied", value: "secret", expire_time_ms: 0,
        classification: 3, sci_compartment: 1,
    }]));
    assert!(kv.set_batch_durable(&operator, &[BatchSet {
        key: "storage:durable", value: "wal", expire_time_ms: 0,
        classification: 3, sci_compartment: 1,
    }]));
    assert_eq!(kv.get(&operator, "storage:durable").as_deref(), Some("wal"));
    assert!(kv.get(&guest, "storage:durable").is_none());
    assert!(kv.clear(&guest).is_none());

    let ts = StorageTimeSeries::new().unwrap();
    assert!(ts.insert(1, 1000, 12.0, 3, 1));
    assert!(ts.insert(2, 1000, 6.0, 0, 0));
    ts.flush();
    assert_eq!(ts.average_range(&guest, 0, 2000), Some(6.0));
    assert_eq!(ts.average_range(&operator, 0, 2000), Some(9.0));

    let doc = StorageDocument::new(&kv).unwrap();
    assert!(doc.insert_json(&operator, 91, r#"{"subject":"secret"}"#));
    assert!(doc.get_json(&operator, 91).unwrap().contains("secret"));
    assert_eq!(doc.get_json(&guest, 91), None);
    assert!(doc.list(&guest, 128).is_empty());
    drop(doc); // the native document store may not outlive its KV backing store

    let stream_dir = dir.join("events");
    let stream = StorageEventStream::open(stream_dir.to_str().unwrap(), Durability::Fdatasync, false).unwrap();
    let scope = EventScope { topic: "storage", classification: 3, sci: 1 };
    let record = EventInput { schema_id: 1, event_id: None, payload: b"event classified" };
    assert!(stream.append_batch(&guest, scope, &[record]).is_none());
    let result = stream.append_batch(&operator, scope, &[record]).unwrap();
    assert_eq!(result.len(), 1);
    assert_eq!(result[0].stream_offset, 0);
    assert!(stream.read_batch(&guest, scope, 0, 4, 1024).is_none());
    let (page, cursor) = stream.read_batch(&operator, scope, 0, 4, 1024).unwrap();
    assert_eq!(page.len(), 1);
    assert_eq!(page[0].payload, b"event classified");
    assert!(page[0].is_committed());
    assert!(cursor > 0);
    assert!(stream.read_batch(&operator, scope, cursor, 4, 1024).unwrap().0.is_empty());
    assert!(stream.flush());
    let readonly = StorageEventStream::open(stream_dir.to_str().unwrap(), Durability::Fdatasync, true).unwrap();
    assert!(readonly.append_batch(&operator, scope, &[record]).is_none());
    drop(readonly);
    drop(stream);
    drop(ts);
    drop(kv);
    unsafe extern "C" { fn qihse_audit_shutdown(); }
    qihse_audit_shutdown();
    }
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn malformed_principal_credentials_fail_closed() {
    // CString validation rejects these before touching C auth state or a principal.
    assert!(unsafe { StorageUser::authenticate_id(0, "bad\0password") }.is_none());
    assert!(unsafe { StorageUser::authenticate("bad\0user", "password") }.is_none());
}
