//! Opt-in facade for the implemented subset of `python/qihse/__init__.py`.
//! Module names distinguish native storage and vector types from legacy crate
//! APIs; imports here do not switch the Python package or any C data plane.
//! `StorageUser` is a non-owning C principal: authentication and every storage
//! operation taking it are unsafe until auth-table lifetime/epoch is enforced.

pub use crate::python_vector::{AnchorIndex, FTSIndex, FTSResult, KeystoneClass, NativeVectorDB, NeuralClassifier, Principal, VectorQuery, VectorResult};
pub use crate::python_storage::{Durability, EventRecord, EventScope, StorageDocument, StorageEventStream, StorageKv, StorageTimeSeries, StorageUser};
pub use crate::python_remote::{AIMEMClient, DurableReceipt, MemoryHit, RecallMode, Scope};
pub use crate::python_peripheral::{HardwareProfile, HardwareProfiler, ThermalTelemetry, UwpCodec, UwpError, parse_ipmi};

/// `python/qihse/browser/__init__.py` exposes keyslot, SLOT_COUNT, NodeSpec,
/// SessionFleet. The Rust browser slice also exposes authenticated read-only
/// helpers under its module path; it does NOT implement the HTTP/WebAuthn UI.
pub mod browser {
    pub use crate::python_browser::{keyslot, NodeSpec, SessionFleet};
    pub const SLOT_COUNT: usize = 16_384;
    pub use crate::python_browser::{browse, fetch, prepare_action, AuthenticatedFleet, BrowserError, KeyDetail, KeyEntry, KeyListing};
}
