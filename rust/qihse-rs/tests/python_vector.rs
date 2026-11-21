//! Native FFI-focused tests for the partial Python vector API port.
//! `lib.rs` export belongs to a separate owner; include this source by path
//! until it is registered as a normal crate module.
#[path = "../src/python_vector.rs"]
mod python_vector;

use python_vector::{AnchorIndex, FTSIndex, KeystoneClass, NativeVectorDB, NeuralClassifier, Principal, VectorQuery};
pub use qihse_rs::ffi;
use std::ffi::CString;

#[test]
fn native_classifier_and_anchor_match_public_contract() {
    assert!(NeuralClassifier::classify("").is_err());
    let (class, name, confidence) = NeuralClassifier::classify("government infrastructure policy").unwrap();
    assert!(!name.is_empty());
    assert!((0.0..=1.0).contains(&confidence));
    assert!((class as i32) <= KeystoneClass::Consumer as i32);
    let sorted = [-5, 1, 1, 9];
    assert_eq!(AnchorIndex::lower_bound(&sorted, 1), 1);
    assert_eq!(AnchorIndex::lower_bound(&sorted, 2), 3);
    assert_eq!(AnchorIndex::search(&sorted, 9), Some(3));
    assert_eq!(AnchorIndex::search(&sorted, 2), None);
    assert_eq!(AnchorIndex::lower_bound(&[], 2), 0);
}

#[test]
fn native_vector_and_fts_are_principal_scoped() {
    // Separate audit/chain writer from other test binaries; no production path.
    let nonce = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
    let dir = std::env::current_dir().unwrap().join(format!("qihse-rs-vector-{}-{nonce}", std::process::id()));
    use std::os::unix::fs::DirBuilderExt;
    std::fs::DirBuilder::new().mode(0o700).create(&dir).unwrap();
    std::env::set_var("QIHSE_DATA_DIR", &dir);
    std::env::set_var("QIHSE_FIPS_MODE", "disabled");
    assert!(unsafe { ffi::qihse_auth_init() });
    let operator_password = "SecureOpPass1!";
    assert!(unsafe { ffi::qihse_auth_bootstrap_operator(CString::new(operator_password).unwrap().as_ptr()) });
    // SAFETY: This test owns native auth in its process; no reset, shutdown,
    // deletion, or concurrent auth mutation occurs while these principals are
    // used. Both principals and their index uses end before audit shutdown.
    let operator = unsafe { Principal::authenticate_id(0, operator_password) }.unwrap();
    let operator_handle = unsafe { ffi::qihse_auth_get_user(0) };
    let guest_password = CString::new("GuestPass123!").unwrap();
    assert!(!unsafe { ffi::qihse_auth_create_user(operator_handle, 7001, 2, 0, 0, guest_password.as_ptr(), false) }.is_null());
    let guest = unsafe { Principal::authenticate_id(7001, "GuestPass123!") }.unwrap();
    assert!(unsafe { Principal::authenticate_id(7001, "wrong password") }.is_err());

    let mut public = FTSIndex::new().unwrap();
    let mut mixed = FTSIndex::new().unwrap();
    unsafe { public.add_document(&operator, 20, "alpha bravo public", 0, 0, KeystoneClass::Unknown) }.unwrap();
    unsafe { mixed.add_document(&operator, 20, "alpha bravo public", 0, 0, KeystoneClass::Unknown) }.unwrap();
    assert!(unsafe { mixed.add_document(&guest, 21, "alpha alpha protected", 5, 0, KeystoneClass::Government) }.is_err());
    unsafe { mixed.add_document(&operator, 21, "alpha alpha protected", 5, 0, KeystoneClass::Government) }.unwrap();
    let baseline = unsafe { public.search(&guest, "alpha", 4, 0) }.unwrap();
    let visible = unsafe { mixed.search(&guest, "alpha", 4, 0) }.unwrap();
    assert_eq!(baseline, visible, "hidden rows must not affect BM25 corpus statistics");
    assert_eq!(unsafe { mixed.get_semantic_class(&guest, 21) }.unwrap(), KeystoneClass::Unknown);
    assert_eq!(unsafe { mixed.get_semantic_class(&operator, 21) }.unwrap(), KeystoneClass::Government);
    assert_eq!(unsafe { mixed.search(&operator, "alpha", 4, 1 << (KeystoneClass::Government as u8)) }.unwrap().len(), 1);
    assert!(unsafe { mixed.search(&guest, "al\0pha", 4, 0) }.is_err());

    let export = dir.join("classified.qfts");
    let export_path = export.to_str().unwrap();
    assert!(unsafe { mixed.save(&guest, export_path) }.is_err());
    assert!(!export.exists());
    unsafe { mixed.save(&operator, export_path) }.unwrap();
    assert!(unsafe { FTSIndex::load(&guest, export_path) }.is_err());
    let loaded = unsafe { FTSIndex::load(&operator, export_path) }.unwrap();
    assert_eq!(unsafe { loaded.search(&operator, "protected", 2, 0) }.unwrap()[0].doc_id, 21);

    let mut vectors = NativeVectorDB::create(None).unwrap();
    assert!(vectors.add_vectors(&[1.0, 0.0], 3, Some(&[22])).is_err());
    vectors.add_vectors(&[1.0, 0.0, 0.0, 1.0], 2, Some(&[22, 23])).unwrap();
    let nearest = unsafe { vectors.search(&guest, VectorQuery {
        vector: &[1.0, 0.0], top_k: 2,
        mode: ffi::qihse_vector_db_query_mode_e_QIHSE_VDB_QUERY_FLOAT32,
        metric: ffi::qihse_distance_metric_e_QIHSE_DISTANCE_COSINE,
    }) }.unwrap();
    assert_eq!(nearest.first().unwrap().id, 22);
    assert!(unsafe { vectors.search(&guest, VectorQuery {
        vector: &[1.0, 0.0], top_k: 2,
        mode: ffi::qihse_vector_db_query_mode_e_QIHSE_VDB_QUERY_TRINARY_MAGNITUDE_BYPASS,
        metric: ffi::qihse_distance_metric_e_QIHSE_DISTANCE_COSINE,
    }) }.is_err(), "missing opt-in sidecar must fail, not fall back to exact");
    vectors.close().unwrap();
    assert!(unsafe { vectors.search(&guest, VectorQuery {
        vector: &[1.0, 0.0], top_k: 2,
        mode: ffi::qihse_vector_db_query_mode_e_QIHSE_VDB_QUERY_FLOAT32,
        metric: ffi::qihse_distance_metric_e_QIHSE_DISTANCE_COSINE,
    }) }.is_err());
    drop(vectors);
    drop(loaded);
    drop(mixed);
    drop(public);
    unsafe extern "C" { fn qihse_audit_shutdown(); }
    unsafe { qihse_audit_shutdown(); }
    std::fs::remove_dir_all(&dir).unwrap();
}
