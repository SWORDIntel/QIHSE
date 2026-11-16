//! Structural checks for a legacy CT1 recovery proposal.
//!
//! This crate does not authenticate QKP peers, inspect native WAL frames, write
//! data, authorize a suppressed apply, issue an ACK, mint authority, or expose
//! a C recovery capability. All evaluation entrypoints (including the
//! version/size-tagged fixed-width ABI) are strictly **structural** until
//! C-minted proof integration: inputs must first be established by the pinned
//! CT1 transport and rechecked by the native C executor under the store lock.
//! A successful structural evaluation is never permission to apply, suppress,
//! ACK, advance a cursor, or serve.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JournalProvenance {
    AuthenticatedSourceJournal,
    Other,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MutationKind {
    Set,
    Tombstone,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RowIdentity<'a> {
    pub key: &'a [u8],
    pub resource_tenant_id: u32,
    pub classification: u16,
    pub sci: u16,
}

/// Values supplied by the native authenticated CT1 transport, not by a client.
#[derive(Clone, Copy, Debug)]
pub struct Comparison<'a> {
    pub source_generation: &'a [u8; 16],
    pub target_generation: &'a [u8; 16],
    pub expected_baseline: &'a [u8; 32],
    pub target_baseline: &'a [u8; 32],
    pub original_frame_digest: &'a [u8; 32],
    pub observed_frame_digest: &'a [u8; 32],
    pub pending_position: u64,
    pub pending_record_count: u32,
    pub target_cursor: u64,
    pub pending_row_sequence: u64,
    pub pending_row: RowIdentity<'a>,
    pub pending_kind: MutationKind,
    pub deletion_position: u64,
    pub deletion_row_sequence: u64,
    pub deletion_row: RowIdentity<'a>,
    pub deletion_kind: MutationKind,
    pub deletion_provenance: JournalProvenance,
    pub latest_target_row: RowIdentity<'a>,
    pub latest_target_kind: MutationKind,
    pub latest_target_row_sequence: u64,
    pub target_highwater: u64,
    pub source_highwater: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Identity,
    Baseline,
    Frame,
    Position,
    Row,
    DeletionAuthority,
    Version,
    Exhausted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SequenceFloor {
    /// Minimum sequence the native allocator must *durably* allocate.
    pub minimum_next_sequence: u64,
}

/// Compares already-attested metadata. It does not attest that metadata.
pub fn compare(proof: &Comparison<'_>) -> Result<SequenceFloor, Error> {
    if proof.source_generation.iter().all(|&byte| byte == 0)
        || proof.source_generation != proof.target_generation
    {
        return Err(Error::Identity);
    }
    if proof.expected_baseline.iter().all(|&byte| byte == 0)
        || proof.expected_baseline != proof.target_baseline
    {
        return Err(Error::Baseline);
    }
    if proof.original_frame_digest.iter().all(|&byte| byte == 0)
        || proof.original_frame_digest != proof.observed_frame_digest
    {
        return Err(Error::Frame);
    }
    if proof.target_cursor.checked_add(1) != Some(proof.pending_position)
        || proof.deletion_position == 0
        || proof.deletion_position > proof.target_cursor
    {
        return Err(Error::Position);
    }
    if proof.pending_record_count != 1
        || proof.pending_row.key.is_empty()
        || proof.pending_row != proof.deletion_row
        || proof.pending_kind != MutationKind::Set
        || proof.deletion_kind != MutationKind::Tombstone
        || proof.latest_target_row != proof.deletion_row
        || proof.latest_target_kind != MutationKind::Tombstone
        || proof.latest_target_row_sequence != proof.deletion_row_sequence
    {
        return Err(Error::Row);
    }
    if proof.deletion_provenance != JournalProvenance::AuthenticatedSourceJournal {
        return Err(Error::DeletionAuthority);
    }
    if proof.pending_row_sequence == 0
        || proof.pending_row_sequence >= proof.deletion_row_sequence
        || proof.deletion_row_sequence > proof.target_highwater
    {
        return Err(Error::Version);
    }
    let minimum_next_sequence = proof
        .target_highwater
        .max(proof.source_highwater)
        .checked_add(1)
        .ok_or(Error::Exhausted)?;
    Ok(SequenceFloor {
        minimum_next_sequence,
    })
}

/// Fixed-width ABI version for [`EvidenceEvalRequestV1`] and [`EvidenceEvalOutputV1`].
pub const CT1_EVIDENCE_ABI_VERSION_1: u32 = 1;
/// Maximum native QKV6 key length represented by [`FixedRowIdentityV1`].
pub const CT1_MAX_KEY_BYTES: usize = 65535;
/// Maximum native CT codec frame byte length accepted for structural metadata checks.
pub const CT1_MAX_FRAME_BYTES: u32 = 64 * 1024 * 1024;

/// Fixed-width mutation kind tag for a SET record.
pub const CT1_MUTATION_SET: u32 = 1;
/// Fixed-width mutation kind tag for a TOMBSTONE record.
pub const CT1_MUTATION_TOMBSTONE: u32 = 2;

/// Only valid `requested_operation` value for [`EvidenceEvalRequestV1`]:
/// structural evaluation only (no apply, ACK, suppression, or capability minting).
pub const CT1_EVAL_OP_STRUCTURAL_ONLY: u32 = 1;

/// Output `structural_status` when all structural checks pass.
/// Explicitly unattested until C-minted proof integration.
pub const CT1_EVAL_STATUS_STRUCTURAL_CANDIDATE_UNATTESTED: u32 = 1;

/// Output `attestation_state`: always 0 (unverified / structural-only).
pub const CT1_ATTESTATION_NONE_STRUCTURAL_ONLY: u32 = 0;

/// Output `authorized_actions`: always 0 (never authorizes apply, ACK, suppress, or cursor advance).
pub const CT1_AUTHORIZED_ACTIONS_NONE: u32 = 0;

/// C ABI return codes for [`qihse_ct1_structural_evidence_evaluate_v1`].
pub const CT1_EVAL_OK: i32 = 0;
pub const CT1_EVAL_ERR_NULL_POINTER: i32 = -1;
pub const CT1_EVAL_ERR_INVALID_VERSION: i32 = -2;
pub const CT1_EVAL_ERR_INVALID_SIZE: i32 = -3;
pub const CT1_EVAL_ERR_UNSUPPORTED_OPERATION: i32 = -4;
pub const CT1_EVAL_ERR_NONZERO_RESERVED: i32 = -5;
pub const CT1_EVAL_ERR_IDENTITY: i32 = -6;
pub const CT1_EVAL_ERR_BASELINE: i32 = -7;
pub const CT1_EVAL_ERR_DIGEST: i32 = -8;
pub const CT1_EVAL_ERR_POSITION: i32 = -9;
pub const CT1_EVAL_ERR_FORGED_METADATA: i32 = -10;
pub const CT1_EVAL_ERR_STALE_ORDERING: i32 = -11;
pub const CT1_EVAL_ERR_OVERFLOW: i32 = -12;
pub const CT1_EVAL_ERR_PANIC: i32 = -13;

/// Fixed-width error taxonomy for the version/size-tagged structural evaluation ABI.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EvidenceAbiError {
    NullPointer,
    InvalidVersion,
    InvalidSize,
    UnsupportedOperation,
    NonZeroReserved,
    IdentityMismatch,
    BaselineMismatch,
    DigestMismatch,
    PositionOutOfRange,
    ForgedMetadata,
    StaleOrdering,
    Overflow,
    Panic,
}

impl EvidenceAbiError {
    pub const fn as_i32(self) -> i32 {
        match self {
            Self::NullPointer => CT1_EVAL_ERR_NULL_POINTER,
            Self::InvalidVersion => CT1_EVAL_ERR_INVALID_VERSION,
            Self::InvalidSize => CT1_EVAL_ERR_INVALID_SIZE,
            Self::UnsupportedOperation => CT1_EVAL_ERR_UNSUPPORTED_OPERATION,
            Self::NonZeroReserved => CT1_EVAL_ERR_NONZERO_RESERVED,
            Self::IdentityMismatch => CT1_EVAL_ERR_IDENTITY,
            Self::BaselineMismatch => CT1_EVAL_ERR_BASELINE,
            Self::DigestMismatch => CT1_EVAL_ERR_DIGEST,
            Self::PositionOutOfRange => CT1_EVAL_ERR_POSITION,
            Self::ForgedMetadata => CT1_EVAL_ERR_FORGED_METADATA,
            Self::StaleOrdering => CT1_EVAL_ERR_STALE_ORDERING,
            Self::Overflow => CT1_EVAL_ERR_OVERFLOW,
            Self::Panic => CT1_EVAL_ERR_PANIC,
        }
    }
}

/// Fixed-width, pointer-free row identity for the V1 structural evidence ABI.
///
/// Layout has no implicit padding. `key_digest` is SHA-256 of the raw key,
/// but this caller-supplied hash is not an attestation of that key.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FixedRowIdentityV1 {
    pub resource_tenant_id: u32,
    pub classification: u16,
    pub sci: u16,
    pub key_len: u32,
    pub reserved: u32,
    pub key_digest: [u8; 32],
}

impl FixedRowIdentityV1 {
    pub fn from_slice(
        key_bytes: &[u8],
        resource_tenant_id: u32,
        classification: u16,
        sci: u16,
    ) -> Result<Self, EvidenceAbiError> {
        if key_bytes.is_empty() {
            return Err(EvidenceAbiError::ForgedMetadata);
        }
        if key_bytes.len() > CT1_MAX_KEY_BYTES {
            return Err(EvidenceAbiError::Overflow);
        }
        let mut hasher = Sha256::new();
        hasher.update(key_bytes);
        Ok(Self {
            resource_tenant_id,
            classification,
            sci,
            key_len: key_bytes.len() as u32,
            reserved: 0,
            key_digest: hasher.finalize(),
        })
    }
}

/// Version/size-tagged, fixed-width structural evidence evaluation input (V1).
///
/// This struct intentionally contains **no** provenance enum, **no** `authenticated`
/// boolean, **no** QKP peer pin claim, and **no** C recovery capability handle.
/// Passing this struct proves structural consistency only; until C-minted proof
/// integration exists, it confers zero authority.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EvidenceEvalRequestV1 {
    pub version: u32,
    pub size: u32,
    pub requested_operation: u32,
    pub reserved: u32,

    pub source_generation: [u8; 16],
    pub target_generation: [u8; 16],
    pub expected_baseline_digest: [u8; 32],
    pub target_baseline_digest: [u8; 32],
    pub original_frame_digest: [u8; 32],
    pub observed_frame_digest: [u8; 32],

    pub expected_baseline_row_seq: u64,
    pub target_baseline_row_seq: u64,

    pub source_acknowledged_position: u64,
    pub source_durable_position: u64,
    pub pending_position: u64,
    pub target_cursor: u64,
    pub deletion_position: u64,

    pub pending_row_sequence: u64,
    pub deletion_row_sequence: u64,
    pub latest_target_row_sequence: u64,
    pub target_highwater: u64,
    pub source_highwater: u64,

    pub pending_record_count: u32,
    pub pending_kind: u32,
    pub deletion_kind: u32,
    pub latest_target_kind: u32,
    pub original_frame_len: u32,
    pub observed_frame_len: u32,
    pub flags: u32,
    pub reserved2: u32,

    pub pending_row: FixedRowIdentityV1,
    pub deletion_row: FixedRowIdentityV1,
    pub latest_target_row: FixedRowIdentityV1,
}

/// Version/size-tagged, fixed-width structural evaluation result (V1).
///
/// `attestation_state` is always [`CT1_ATTESTATION_NONE_STRUCTURAL_ONLY`] and
/// `authorized_actions` is always [`CT1_AUTHORIZED_ACTIONS_NONE`] until C-minted
/// proof integration. `transcript_digest` is a structural input binding, NOT a
/// cryptographic signature or peer attestation.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EvidenceEvalOutputV1 {
    pub version: u32,
    pub size: u32,
    pub structural_status: u32,
    pub attestation_state: u32,
    pub authorized_actions: u32,
    pub reserved: u32,
    pub minimum_next_row_seq: u64,
    pub transcript_digest: [u8; 32],
}

impl EvidenceEvalOutputV1 {
    pub const fn zeroed() -> Self {
        Self {
            version: 0,
            size: 0,
            structural_status: 0,
            attestation_state: 0,
            authorized_actions: 0,
            reserved: 0,
            minimum_next_row_seq: 0,
            transcript_digest: [0u8; 32],
        }
    }
}

fn validate_fixed_row(row: &FixedRowIdentityV1) -> Result<(), EvidenceAbiError> {
    if row.reserved != 0 {
        return Err(EvidenceAbiError::NonZeroReserved);
    }
    if row.key_len == 0 {
        return Err(EvidenceAbiError::ForgedMetadata);
    }
    if row.key_len as usize > CT1_MAX_KEY_BYTES {
        return Err(EvidenceAbiError::Overflow);
    }
    if is_all_zero(&row.key_digest) {
        return Err(EvidenceAbiError::ForgedMetadata);
    }
    Ok(())
}

fn is_all_zero(bytes: &[u8]) -> bool {
    bytes.iter().all(|&b| b == 0)
}

/// Evaluates fixed-width version/size-tagged recovery evidence **structurally**.
///
/// Does not mint authority, validate QKP pins, read WALs, or authorize any
/// apply, suppression, ACK, or cursor transition.
pub fn evaluate_structural_evidence_v1(
    req: &EvidenceEvalRequestV1,
) -> Result<EvidenceEvalOutputV1, EvidenceAbiError> {
    if req.version != CT1_EVIDENCE_ABI_VERSION_1 {
        return Err(EvidenceAbiError::InvalidVersion);
    }
    if req.size != core::mem::size_of::<EvidenceEvalRequestV1>() as u32 {
        return Err(EvidenceAbiError::InvalidSize);
    }
    if req.reserved != 0 || req.reserved2 != 0 || req.flags != 0 {
        return Err(EvidenceAbiError::NonZeroReserved);
    }
    if req.requested_operation != CT1_EVAL_OP_STRUCTURAL_ONLY {
        return Err(EvidenceAbiError::UnsupportedOperation);
    }

    validate_fixed_row(&req.pending_row)?;
    validate_fixed_row(&req.deletion_row)?;
    validate_fixed_row(&req.latest_target_row)?;

    if req.pending_record_count != 1
        || req.pending_kind != CT1_MUTATION_SET
        || req.deletion_kind != CT1_MUTATION_TOMBSTONE
        || req.latest_target_kind != CT1_MUTATION_TOMBSTONE
        || req.pending_row != req.deletion_row
        || req.latest_target_row != req.deletion_row
    {
        return Err(EvidenceAbiError::ForgedMetadata);
    }

    if req.original_frame_len == 0 || req.observed_frame_len == 0 {
        return Err(EvidenceAbiError::ForgedMetadata);
    }
    if req.original_frame_len > CT1_MAX_FRAME_BYTES || req.observed_frame_len > CT1_MAX_FRAME_BYTES
    {
        return Err(EvidenceAbiError::Overflow);
    }
    if req.original_frame_len != req.observed_frame_len {
        return Err(EvidenceAbiError::ForgedMetadata);
    }

    if is_all_zero(&req.source_generation)
        || is_all_zero(&req.target_generation)
        || req.source_generation != req.target_generation
    {
        return Err(EvidenceAbiError::IdentityMismatch);
    }

    if is_all_zero(&req.expected_baseline_digest)
        || is_all_zero(&req.target_baseline_digest)
        || req.expected_baseline_digest != req.target_baseline_digest
    {
        return Err(EvidenceAbiError::BaselineMismatch);
    }
    if req.expected_baseline_row_seq == 0 || req.target_baseline_row_seq == 0 {
        return Err(EvidenceAbiError::PositionOutOfRange);
    }
    if req.expected_baseline_row_seq != req.target_baseline_row_seq {
        return Err(EvidenceAbiError::BaselineMismatch);
    }

    if is_all_zero(&req.original_frame_digest)
        || is_all_zero(&req.observed_frame_digest)
        || req.original_frame_digest != req.observed_frame_digest
    {
        return Err(EvidenceAbiError::DigestMismatch);
    }

    if req.pending_position == 0
        || req.target_cursor == 0
        || req.deletion_position == 0
        || req.source_durable_position == 0
    {
        return Err(EvidenceAbiError::PositionOutOfRange);
    }
    let expected_pending_position = req
        .target_cursor
        .checked_add(1)
        .ok_or(EvidenceAbiError::Overflow)?;
    if expected_pending_position != req.pending_position
        || req.deletion_position > req.target_cursor
        || req.pending_position > req.source_durable_position
    {
        return Err(EvidenceAbiError::PositionOutOfRange);
    }
    if req.pending_position <= req.source_acknowledged_position {
        return Err(EvidenceAbiError::StaleOrdering);
    }

    if req.pending_row_sequence == 0
        || req.deletion_row_sequence == 0
        || req.latest_target_row_sequence == 0
    {
        return Err(EvidenceAbiError::PositionOutOfRange);
    }
    if req.pending_row_sequence >= req.deletion_row_sequence
        || req.latest_target_row_sequence != req.deletion_row_sequence
        || req.deletion_row_sequence > req.target_highwater
        || req.expected_baseline_row_seq > req.target_highwater
    {
        return Err(EvidenceAbiError::StaleOrdering);
    }

    let minimum_next_row_seq = req
        .target_highwater
        .max(req.source_highwater)
        .checked_add(1)
        .ok_or(EvidenceAbiError::Overflow)?;

    let transcript_digest = compute_transcript_digest_v1(req, minimum_next_row_seq);

    Ok(EvidenceEvalOutputV1 {
        version: CT1_EVIDENCE_ABI_VERSION_1,
        size: core::mem::size_of::<EvidenceEvalOutputV1>() as u32,
        structural_status: CT1_EVAL_STATUS_STRUCTURAL_CANDIDATE_UNATTESTED,
        attestation_state: CT1_ATTESTATION_NONE_STRUCTURAL_ONLY,
        authorized_actions: CT1_AUTHORIZED_ACTIONS_NONE,
        reserved: 0,
        minimum_next_row_seq,
        transcript_digest,
    })
}

/// Panic-safe, fixed-width C ABI entrypoint for structural evidence evaluation.
///
/// # Safety
/// - `input` must either be null (fails closed) or point to a valid, readable,
///   properly aligned [`EvidenceEvalRequestV1`] for the duration of the call.
/// - `out` must either be null (fails closed) or point to a valid, writable,
///   properly aligned [`EvidenceEvalOutputV1`] for the duration of the call.
/// - Neither region may be concurrently accessed or mutated by another thread;
///   overlapping input/output regions are rejected before an input reference is formed.
///
/// Failure zeroes `*out` when `out` is valid, non-null, and aligned.
/// This function does **not** mint a C recovery capability, verify QKP peers,
/// or authorize any store mutation or ACK.
#[no_mangle]
pub unsafe extern "C" fn qihse_ct1_structural_evidence_evaluate_v1(
    input: *const EvidenceEvalRequestV1,
    out: *mut EvidenceEvalOutputV1,
) -> i32 {
    if out.is_null() {
        return CT1_EVAL_ERR_NULL_POINTER;
    }
    if (out as usize) % core::mem::align_of::<EvidenceEvalOutputV1>() != 0 {
        return CT1_EVAL_ERR_FORGED_METADATA;
    }
    // Check byte ranges before creating a shared reference; even partial overlap
    // would invalidate it when the output is written.
    let out_start = out as usize;
    let Some(out_end) = out_start.checked_add(core::mem::size_of::<EvidenceEvalOutputV1>()) else {
        return CT1_EVAL_ERR_FORGED_METADATA;
    };
    let overlap = if input.is_null() {
        false
    } else {
        let input_start = input as usize;
        match input_start.checked_add(core::mem::size_of::<EvidenceEvalRequestV1>()) {
            Some(input_end) => input_start < out_end && out_start < input_end,
            None => true,
        }
    };
    // Fail closed even if the output aliases part of the input.
    core::ptr::write(out, EvidenceEvalOutputV1::zeroed());
    if overlap {
        return CT1_EVAL_ERR_FORGED_METADATA;
    }
    if input.is_null() {
        return CT1_EVAL_ERR_NULL_POINTER;
    }
    if (input as usize) % core::mem::align_of::<EvidenceEvalRequestV1>() != 0 {
        return CT1_EVAL_ERR_FORGED_METADATA;
    }

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let req = &*input;
        evaluate_structural_evidence_v1(req)
    }));

    match result {
        Ok(Ok(evaluated)) => {
            core::ptr::write(out, evaluated);
            CT1_EVAL_OK
        }
        Ok(Err(err)) => {
            core::ptr::write(out, EvidenceEvalOutputV1::zeroed());
            err.as_i32()
        }
        Err(_) => {
            core::ptr::write(out, EvidenceEvalOutputV1::zeroed());
            CT1_EVAL_ERR_PANIC
        }
    }
}

fn compute_transcript_digest_v1(
    req: &EvidenceEvalRequestV1,
    minimum_next_row_seq: u64,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"QIHSE-CT1-STRUCTURAL-EVIDENCE-V1\0");
    hasher.update(&req.version.to_le_bytes());
    hasher.update(&req.size.to_le_bytes());
    hasher.update(&req.requested_operation.to_le_bytes());
    hasher.update(&req.source_generation);
    hasher.update(&req.target_generation);
    hasher.update(&req.expected_baseline_digest);
    hasher.update(&req.target_baseline_digest);
    hasher.update(&req.original_frame_digest);
    hasher.update(&req.observed_frame_digest);
    hasher.update(&req.expected_baseline_row_seq.to_le_bytes());
    hasher.update(&req.target_baseline_row_seq.to_le_bytes());
    hasher.update(&req.source_acknowledged_position.to_le_bytes());
    hasher.update(&req.source_durable_position.to_le_bytes());
    hasher.update(&req.pending_position.to_le_bytes());
    hasher.update(&req.target_cursor.to_le_bytes());
    hasher.update(&req.deletion_position.to_le_bytes());
    hasher.update(&req.pending_row_sequence.to_le_bytes());
    hasher.update(&req.deletion_row_sequence.to_le_bytes());
    hasher.update(&req.latest_target_row_sequence.to_le_bytes());
    hasher.update(&req.target_highwater.to_le_bytes());
    hasher.update(&req.source_highwater.to_le_bytes());
    hasher.update(&req.pending_record_count.to_le_bytes());
    hasher.update(&req.pending_kind.to_le_bytes());
    hasher.update(&req.deletion_kind.to_le_bytes());
    hasher.update(&req.latest_target_kind.to_le_bytes());
    hasher.update(&req.original_frame_len.to_le_bytes());
    hasher.update(&req.observed_frame_len.to_le_bytes());
    hasher.update(&req.pending_row.resource_tenant_id.to_le_bytes());
    hasher.update(&req.pending_row.classification.to_le_bytes());
    hasher.update(&req.pending_row.sci.to_le_bytes());
    hasher.update(&req.pending_row.key_len.to_le_bytes());
    hasher.update(&req.pending_row.key_digest);
    hasher.update(&minimum_next_row_seq.to_le_bytes());
    hasher.finalize()
}

struct Sha256 {
    state: [u32; 8],
    len_bits: u64,
    buf: [u8; 64],
    buf_len: usize,
}

impl Sha256 {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];

    fn new() -> Self {
        Self {
            state: [
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
                0x5be0cd19,
            ],
            len_bits: 0,
            buf: [0u8; 64],
            buf_len: 0,
        }
    }

    fn update(&mut self, mut data: &[u8]) {
        self.len_bits = self
            .len_bits
            .wrapping_add((data.len() as u64).wrapping_mul(8));
        if self.buf_len > 0 {
            let need = 64 - self.buf_len;
            if data.len() < need {
                self.buf[self.buf_len..self.buf_len + data.len()].copy_from_slice(data);
                self.buf_len += data.len();
                return;
            }
            self.buf[self.buf_len..64].copy_from_slice(&data[..need]);
            let block = self.buf;
            self.compress(&block);
            self.buf_len = 0;
            data = &data[need..];
        }
        while data.len() >= 64 {
            let mut block = [0u8; 64];
            block.copy_from_slice(&data[..64]);
            self.compress(&block);
            data = &data[64..];
        }
        if !data.is_empty() {
            self.buf[..data.len()].copy_from_slice(data);
            self.buf_len = data.len();
        }
    }

    fn finalize(mut self) -> [u8; 32] {
        self.buf[self.buf_len] = 0x80;
        self.buf_len += 1;
        if self.buf_len > 56 {
            self.buf[self.buf_len..64].fill(0);
            let block = self.buf;
            self.compress(&block);
            self.buf_len = 0;
        }
        self.buf[self.buf_len..56].fill(0);
        self.buf[56..64].copy_from_slice(&self.len_bits.to_be_bytes());
        let block = self.buf;
        self.compress(&block);
        let mut out = [0u8; 32];
        for (chunk, word) in out.chunks_exact_mut(4).zip(self.state.iter()) {
            chunk.copy_from_slice(&word.to_be_bytes());
        }
        out
    }

    fn compress(&mut self, block: &[u8; 64]) {
        let mut w = [0u32; 64];
        for (i, chunk) in block.chunks_exact(4).enumerate() {
            w[i] = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = self.state;
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(Self::K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }
        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
        self.state[4] = self.state[4].wrapping_add(e);
        self.state[5] = self.state[5].wrapping_add(f);
        self.state[6] = self.state[6].wrapping_add(g);
        self.state[7] = self.state[7].wrapping_add(h);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GEN: [u8; 16] = [1; 16];
    const BASELINE: [u8; 32] = [2; 32];
    const FRAME: [u8; 32] = [3; 32];
    const ROW: RowIdentity<'static> = RowIdentity {
        key: b"fixture-key",
        resource_tenant_id: 7,
        classification: 4,
        sci: 2,
    };

    fn fixture() -> Comparison<'static> {
        Comparison {
            source_generation: &GEN,
            target_generation: &GEN,
            expected_baseline: &BASELINE,
            target_baseline: &BASELINE,
            original_frame_digest: &FRAME,
            observed_frame_digest: &FRAME,
            pending_position: 11111,
            pending_record_count: 1,
            target_cursor: 11110,
            pending_row_sequence: 5729448,
            pending_row: ROW,
            pending_kind: MutationKind::Set,
            deletion_position: 11103,
            deletion_row_sequence: 5729450,
            deletion_row: ROW,
            deletion_kind: MutationKind::Tombstone,
            deletion_provenance: JournalProvenance::AuthenticatedSourceJournal,
            latest_target_row: ROW,
            latest_target_kind: MutationKind::Tombstone,
            latest_target_row_sequence: 5729450,
            target_highwater: 5729457,
            source_highwater: 5729448,
        }
    }

    #[test]
    fn keeps_position_and_row_sequences_separate() {
        assert_eq!(compare(&fixture()).unwrap().minimum_next_sequence, 5729458);
        let mut proof = fixture();
        proof.source_highwater = 5729461;
        assert_eq!(compare(&proof).unwrap().minimum_next_sequence, 5729462);
    }

    #[test]
    fn rejects_wrong_binding_and_untrusted_deletion() {
        let mut proof = fixture();
        proof.target_generation = &[9; 16];
        assert_eq!(compare(&proof), Err(Error::Identity));
        proof = fixture();
        proof.source_generation = &[0; 16];
        proof.target_generation = &[0; 16];
        assert_eq!(compare(&proof), Err(Error::Identity));
        proof = fixture();
        proof.target_baseline = &[9; 32];
        assert_eq!(compare(&proof), Err(Error::Baseline));
        proof = fixture();
        proof.observed_frame_digest = &[9; 32];
        assert_eq!(compare(&proof), Err(Error::Frame));
        proof = fixture();
        proof.deletion_provenance = JournalProvenance::Other;
        assert_eq!(compare(&proof), Err(Error::DeletionAuthority));
    }

    #[test]
    fn rejects_mismatched_row_and_history() {
        let mut proof = fixture();
        proof.pending_record_count = 2;
        assert_eq!(compare(&proof), Err(Error::Row));
        proof = fixture();
        proof.deletion_row.classification = 5;
        assert_eq!(compare(&proof), Err(Error::Row));
        proof = fixture();
        proof.deletion_row.resource_tenant_id = 8;
        assert_eq!(compare(&proof), Err(Error::Row));
        proof = fixture();
        proof.deletion_row.key = b"other-key";
        assert_eq!(compare(&proof), Err(Error::Row));
        proof = fixture();
        proof.deletion_kind = MutationKind::Set;
        assert_eq!(compare(&proof), Err(Error::Row));
        proof = fixture();
        proof.latest_target_kind = MutationKind::Set;
        assert_eq!(compare(&proof), Err(Error::Row));
        proof = fixture();
        proof.latest_target_row_sequence += 1;
        assert_eq!(compare(&proof), Err(Error::Row));
        proof = fixture();
        proof.pending_kind = MutationKind::Tombstone;
        assert_eq!(compare(&proof), Err(Error::Row));
        proof = fixture();
        proof.deletion_position = proof.pending_position;
        assert_eq!(compare(&proof), Err(Error::Position));
        proof = fixture();
        proof.target_cursor = u64::MAX;
        assert_eq!(compare(&proof), Err(Error::Position));
        proof = fixture();
        proof.deletion_row_sequence = proof.pending_row_sequence;
        proof.latest_target_row_sequence = proof.deletion_row_sequence;
        assert_eq!(compare(&proof), Err(Error::Version));
        proof = fixture();
        proof.target_highwater = proof.deletion_row_sequence - 1;
        assert_eq!(compare(&proof), Err(Error::Version));
    }

    #[test]
    fn refuses_exhausted_allocator() {
        let mut proof = fixture();
        proof.source_highwater = u64::MAX;
        assert_eq!(compare(&proof), Err(Error::Exhausted));
    }

    fn abi_fixture() -> EvidenceEvalRequestV1 {
        let row = FixedRowIdentityV1::from_slice(b"fixture-key", 7, 4, 2).unwrap();
        EvidenceEvalRequestV1 {
            version: CT1_EVIDENCE_ABI_VERSION_1,
            size: core::mem::size_of::<EvidenceEvalRequestV1>() as u32,
            requested_operation: CT1_EVAL_OP_STRUCTURAL_ONLY,
            reserved: 0,
            source_generation: GEN,
            target_generation: GEN,
            expected_baseline_digest: BASELINE,
            target_baseline_digest: BASELINE,
            original_frame_digest: FRAME,
            observed_frame_digest: FRAME,
            expected_baseline_row_seq: 5729400,
            target_baseline_row_seq: 5729400,
            source_acknowledged_position: 11110,
            source_durable_position: 11111,
            pending_position: 11111,
            target_cursor: 11110,
            deletion_position: 11103,
            pending_row_sequence: 5729448,
            deletion_row_sequence: 5729450,
            latest_target_row_sequence: 5729450,
            target_highwater: 5729457,
            source_highwater: 5729448,
            pending_record_count: 1,
            pending_kind: CT1_MUTATION_SET,
            deletion_kind: CT1_MUTATION_TOMBSTONE,
            latest_target_kind: CT1_MUTATION_TOMBSTONE,
            original_frame_len: 128,
            observed_frame_len: 128,
            flags: 0,
            reserved2: 0,
            pending_row: row,
            deletion_row: row,
            latest_target_row: row,
        }
    }

    #[test]
    fn sha256_matches_fips_vector() {
        let mut h = Sha256::new();
        h.update(b"abc");
        assert_eq!(
            h.finalize(),
            [
                0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
                0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
                0xf2, 0x00, 0x15, 0xad,
            ]
        );
    }

    #[test]
    fn abi_layout_is_fixed_width_and_structural_only() {
        assert_eq!(core::mem::size_of::<FixedRowIdentityV1>(), 48);
        assert_eq!(core::mem::size_of::<EvidenceEvalRequestV1>(), 448);
        assert_eq!(core::mem::size_of::<EvidenceEvalOutputV1>(), 64);

        let req = abi_fixture();
        let out = evaluate_structural_evidence_v1(&req).unwrap();
        assert_eq!(out.version, CT1_EVIDENCE_ABI_VERSION_1);
        assert_eq!(out.size, 64);
        assert_eq!(
            out.structural_status,
            CT1_EVAL_STATUS_STRUCTURAL_CANDIDATE_UNATTESTED
        );
        assert_eq!(out.attestation_state, CT1_ATTESTATION_NONE_STRUCTURAL_ONLY);
        assert_eq!(out.authorized_actions, CT1_AUTHORIZED_ACTIONS_NONE);
        assert_eq!(out.reserved, 0);
        assert_eq!(out.minimum_next_row_seq, 5729458);
        assert_ne!(out.transcript_digest, [0u8; 32]);

        let mut req_alt = req;
        req_alt.source_highwater = 5729461;
        let out_alt = evaluate_structural_evidence_v1(&req_alt).unwrap();
        assert_eq!(out_alt.minimum_next_row_seq, 5729462);
        assert_ne!(out_alt.transcript_digest, out.transcript_digest);

        let alternate_row = FixedRowIdentityV1::from_slice(b"fixture-kez", 7, 4, 2).unwrap();
        req_alt = req;
        req_alt.pending_row = alternate_row;
        req_alt.deletion_row = alternate_row;
        req_alt.latest_target_row = alternate_row;
        assert_ne!(
            evaluate_structural_evidence_v1(&req_alt)
                .unwrap()
                .transcript_digest,
            out.transcript_digest
        );
        req_alt = req;
        req_alt.pending_row.key_len += 1;
        req_alt.deletion_row.key_len += 1;
        req_alt.latest_target_row.key_len += 1;
        assert_ne!(
            evaluate_structural_evidence_v1(&req_alt)
                .unwrap()
                .transcript_digest,
            out.transcript_digest
        );
    }

    #[test]
    fn rejects_malformed_version_size_and_reserved() {
        let mut req = abi_fixture();
        req.version = 0;
        assert_eq!(
            evaluate_structural_evidence_v1(&req),
            Err(EvidenceAbiError::InvalidVersion)
        );
        req.version = 2;
        assert_eq!(
            evaluate_structural_evidence_v1(&req),
            Err(EvidenceAbiError::InvalidVersion)
        );

        req = abi_fixture();
        req.size = 0;
        assert_eq!(
            evaluate_structural_evidence_v1(&req),
            Err(EvidenceAbiError::InvalidSize)
        );
        req = abi_fixture();
        req.size -= 1;
        assert_eq!(
            evaluate_structural_evidence_v1(&req),
            Err(EvidenceAbiError::InvalidSize)
        );
        req = abi_fixture();
        req.size += 4;
        assert_eq!(
            evaluate_structural_evidence_v1(&req),
            Err(EvidenceAbiError::InvalidSize)
        );

        req = abi_fixture();
        req.reserved = 1;
        assert_eq!(
            evaluate_structural_evidence_v1(&req),
            Err(EvidenceAbiError::NonZeroReserved)
        );
        req = abi_fixture();
        req.reserved2 = 1;
        assert_eq!(
            evaluate_structural_evidence_v1(&req),
            Err(EvidenceAbiError::NonZeroReserved)
        );
        req = abi_fixture();
        req.flags = 1;
        assert_eq!(
            evaluate_structural_evidence_v1(&req),
            Err(EvidenceAbiError::NonZeroReserved)
        );
        req = abi_fixture();
        req.pending_row.reserved = 1;
        assert_eq!(
            evaluate_structural_evidence_v1(&req),
            Err(EvidenceAbiError::NonZeroReserved)
        );

        req = abi_fixture();
        req.requested_operation = 2; // Attempt to request apply/ACK/non-structural op.
        assert_eq!(
            evaluate_structural_evidence_v1(&req),
            Err(EvidenceAbiError::UnsupportedOperation)
        );

        // C ABI boundary: null pointers and error output zeroing.
        let mut out = EvidenceEvalOutputV1 {
            version: 99,
            size: 99,
            structural_status: 99,
            attestation_state: 99,
            authorized_actions: 99,
            reserved: 99,
            minimum_next_row_seq: 99,
            transcript_digest: [0xff; 32],
        };
        unsafe {
            assert_eq!(
                qihse_ct1_structural_evidence_evaluate_v1(core::ptr::null(), &mut out),
                CT1_EVAL_ERR_NULL_POINTER
            );
            assert_eq!(out, EvidenceEvalOutputV1::zeroed());

            assert_eq!(
                qihse_ct1_structural_evidence_evaluate_v1(&req, core::ptr::null_mut()),
                CT1_EVAL_ERR_NULL_POINTER
            );

            assert_eq!(
                qihse_ct1_structural_evidence_evaluate_v1(&req, &mut out),
                CT1_EVAL_ERR_UNSUPPORTED_OPERATION
            );
            assert_eq!(out, EvidenceEvalOutputV1::zeroed());

            let mut bad_version = abi_fixture();
            bad_version.version += 1;
            out.version = 99;
            assert_eq!(
                qihse_ct1_structural_evidence_evaluate_v1(&bad_version, &mut out),
                CT1_EVAL_ERR_INVALID_VERSION
            );
            assert_eq!(out, EvidenceEvalOutputV1::zeroed());

            let mut bad_size = abi_fixture();
            bad_size.size -= 1;
            out.version = 99;
            assert_eq!(
                qihse_ct1_structural_evidence_evaluate_v1(&bad_size, &mut out),
                CT1_EVAL_ERR_INVALID_SIZE
            );
            assert_eq!(out, EvidenceEvalOutputV1::zeroed());

            let valid = abi_fixture();
            assert_eq!(
                qihse_ct1_structural_evidence_evaluate_v1(&valid, &mut out),
                CT1_EVAL_OK
            );
            assert_eq!(out.attestation_state, CT1_ATTESTATION_NONE_STRUCTURAL_ONLY);
            assert_eq!(out.authorized_actions, CT1_AUTHORIZED_ACTIONS_NONE);
            assert_eq!(out.minimum_next_row_seq, 5729458);
        }
    }

    #[test]
    fn rejects_forged_metadata() {
        let mut req = abi_fixture();
        req.source_generation = [0; 16];
        req.target_generation = [0; 16];
        assert_eq!(
            evaluate_structural_evidence_v1(&req),
            Err(EvidenceAbiError::IdentityMismatch)
        );

        req = abi_fixture();
        req.target_generation = [9; 16];
        assert_eq!(
            evaluate_structural_evidence_v1(&req),
            Err(EvidenceAbiError::IdentityMismatch)
        );

        req = abi_fixture();
        req.pending_record_count = 0;
        assert_eq!(
            evaluate_structural_evidence_v1(&req),
            Err(EvidenceAbiError::ForgedMetadata)
        );
        req.pending_record_count = 2;
        assert_eq!(
            evaluate_structural_evidence_v1(&req),
            Err(EvidenceAbiError::ForgedMetadata)
        );

        req = abi_fixture();
        req.pending_kind = 99;
        assert_eq!(
            evaluate_structural_evidence_v1(&req),
            Err(EvidenceAbiError::ForgedMetadata)
        );
        req = abi_fixture();
        req.pending_kind = CT1_MUTATION_TOMBSTONE;
        assert_eq!(
            evaluate_structural_evidence_v1(&req),
            Err(EvidenceAbiError::ForgedMetadata)
        );
        req = abi_fixture();
        req.deletion_kind = CT1_MUTATION_SET;
        assert_eq!(
            evaluate_structural_evidence_v1(&req),
            Err(EvidenceAbiError::ForgedMetadata)
        );
        req = abi_fixture();
        req.latest_target_kind = CT1_MUTATION_SET;
        assert_eq!(
            evaluate_structural_evidence_v1(&req),
            Err(EvidenceAbiError::ForgedMetadata)
        );

        // An empty key or an all-zero caller-supplied key digest is invalid.
        req = abi_fixture();
        req.pending_row.key_len = 0;
        assert_eq!(
            evaluate_structural_evidence_v1(&req),
            Err(EvidenceAbiError::ForgedMetadata)
        );
        req = abi_fixture();
        req.pending_row.key_digest = [0; 32];
        req.deletion_row.key_digest = [0; 32];
        req.latest_target_row.key_digest = [0; 32];
        assert_eq!(
            evaluate_structural_evidence_v1(&req),
            Err(EvidenceAbiError::ForgedMetadata)
        );

        // Mismatched row tenant / labels / key.
        req = abi_fixture();
        req.deletion_row.resource_tenant_id += 1;
        assert_eq!(
            evaluate_structural_evidence_v1(&req),
            Err(EvidenceAbiError::ForgedMetadata)
        );
        req = abi_fixture();
        req.latest_target_row.classification += 1;
        assert_eq!(
            evaluate_structural_evidence_v1(&req),
            Err(EvidenceAbiError::ForgedMetadata)
        );
        req = abi_fixture();
        req.deletion_row.key_digest[0] ^= 0xff;
        assert_eq!(
            evaluate_structural_evidence_v1(&req),
            Err(EvidenceAbiError::ForgedMetadata)
        );

        // Zero or mismatched frame lengths.
        req = abi_fixture();
        req.original_frame_len = 0;
        assert_eq!(
            evaluate_structural_evidence_v1(&req),
            Err(EvidenceAbiError::ForgedMetadata)
        );
        req = abi_fixture();
        req.observed_frame_len += 1;
        assert_eq!(
            evaluate_structural_evidence_v1(&req),
            Err(EvidenceAbiError::ForgedMetadata)
        );
    }

    #[test]
    fn rejects_zero_and_out_of_range_positions() {
        let mut req = abi_fixture();
        req.pending_position = 0;
        assert_eq!(
            evaluate_structural_evidence_v1(&req),
            Err(EvidenceAbiError::PositionOutOfRange)
        );

        req = abi_fixture();
        req.target_cursor = 0;
        assert_eq!(
            evaluate_structural_evidence_v1(&req),
            Err(EvidenceAbiError::PositionOutOfRange)
        );

        req = abi_fixture();
        req.deletion_position = 0;
        assert_eq!(
            evaluate_structural_evidence_v1(&req),
            Err(EvidenceAbiError::PositionOutOfRange)
        );

        req = abi_fixture();
        req.deletion_position = req.target_cursor + 1;
        assert_eq!(
            evaluate_structural_evidence_v1(&req),
            Err(EvidenceAbiError::PositionOutOfRange)
        );

        req = abi_fixture();
        req.pending_position = req.target_cursor + 2;
        assert_eq!(
            evaluate_structural_evidence_v1(&req),
            Err(EvidenceAbiError::PositionOutOfRange)
        );

        req = abi_fixture();
        req.source_durable_position = req.pending_position - 1;
        assert_eq!(
            evaluate_structural_evidence_v1(&req),
            Err(EvidenceAbiError::PositionOutOfRange)
        );

        req = abi_fixture();
        req.source_durable_position = 0;
        assert_eq!(
            evaluate_structural_evidence_v1(&req),
            Err(EvidenceAbiError::PositionOutOfRange)
        );

        req = abi_fixture();
        req.expected_baseline_row_seq = 0;
        req.target_baseline_row_seq = 0;
        assert_eq!(
            evaluate_structural_evidence_v1(&req),
            Err(EvidenceAbiError::PositionOutOfRange)
        );

        req = abi_fixture();
        req.pending_row_sequence = 0;
        assert_eq!(
            evaluate_structural_evidence_v1(&req),
            Err(EvidenceAbiError::PositionOutOfRange)
        );
    }

    #[test]
    fn rejects_digest_mismatch() {
        let mut req = abi_fixture();
        req.expected_baseline_digest = [0; 32];
        req.target_baseline_digest = [0; 32];
        assert_eq!(
            evaluate_structural_evidence_v1(&req),
            Err(EvidenceAbiError::BaselineMismatch)
        );

        req = abi_fixture();
        req.target_baseline_digest[0] ^= 1;
        assert_eq!(
            evaluate_structural_evidence_v1(&req),
            Err(EvidenceAbiError::BaselineMismatch)
        );

        req = abi_fixture();
        req.target_baseline_row_seq += 1;
        assert_eq!(
            evaluate_structural_evidence_v1(&req),
            Err(EvidenceAbiError::BaselineMismatch)
        );

        req = abi_fixture();
        req.original_frame_digest = [0; 32];
        req.observed_frame_digest = [0; 32];
        assert_eq!(
            evaluate_structural_evidence_v1(&req),
            Err(EvidenceAbiError::DigestMismatch)
        );

        req = abi_fixture();
        req.observed_frame_digest[31] ^= 1;
        assert_eq!(
            evaluate_structural_evidence_v1(&req),
            Err(EvidenceAbiError::DigestMismatch)
        );
    }

    #[test]
    fn rejects_stale_ordering() {
        let mut req = abi_fixture();
        req.pending_row_sequence = req.deletion_row_sequence;
        assert_eq!(
            evaluate_structural_evidence_v1(&req),
            Err(EvidenceAbiError::StaleOrdering)
        );

        req = abi_fixture();
        req.pending_row_sequence = req.deletion_row_sequence + 1;
        assert_eq!(
            evaluate_structural_evidence_v1(&req),
            Err(EvidenceAbiError::StaleOrdering)
        );

        req = abi_fixture();
        req.latest_target_row_sequence = req.deletion_row_sequence + 1;
        assert_eq!(
            evaluate_structural_evidence_v1(&req),
            Err(EvidenceAbiError::StaleOrdering)
        );

        req = abi_fixture();
        req.target_highwater = req.deletion_row_sequence - 1;
        assert_eq!(
            evaluate_structural_evidence_v1(&req),
            Err(EvidenceAbiError::StaleOrdering)
        );

        req = abi_fixture();
        req.source_acknowledged_position = req.pending_position;
        assert_eq!(
            evaluate_structural_evidence_v1(&req),
            Err(EvidenceAbiError::StaleOrdering)
        );

        req = abi_fixture();
        req.expected_baseline_row_seq = req.target_highwater + 1;
        req.target_baseline_row_seq = req.target_highwater + 1;
        assert_eq!(
            evaluate_structural_evidence_v1(&req),
            Err(EvidenceAbiError::StaleOrdering)
        );
    }

    #[test]
    fn rejects_overflow() {
        let mut req = abi_fixture();
        req.target_cursor = u64::MAX;
        assert_eq!(
            evaluate_structural_evidence_v1(&req),
            Err(EvidenceAbiError::Overflow)
        );

        req = abi_fixture();
        req.source_highwater = u64::MAX;
        assert_eq!(
            evaluate_structural_evidence_v1(&req),
            Err(EvidenceAbiError::Overflow)
        );

        req = abi_fixture();
        req.target_highwater = u64::MAX;
        assert_eq!(
            evaluate_structural_evidence_v1(&req),
            Err(EvidenceAbiError::Overflow)
        );

        req = abi_fixture();
        req.pending_row.key_len = (CT1_MAX_KEY_BYTES as u32) + 1;
        assert_eq!(
            evaluate_structural_evidence_v1(&req),
            Err(EvidenceAbiError::Overflow)
        );

        req = abi_fixture();
        req.pending_row.key_len = u32::MAX;
        assert_eq!(
            evaluate_structural_evidence_v1(&req),
            Err(EvidenceAbiError::Overflow)
        );

        req = abi_fixture();
        req.original_frame_len = CT1_MAX_FRAME_BYTES + 1;
        assert_eq!(
            evaluate_structural_evidence_v1(&req),
            Err(EvidenceAbiError::Overflow)
        );

        assert_eq!(
            FixedRowIdentityV1::from_slice(&[b'a'; CT1_MAX_KEY_BYTES + 1], 1, 1, 1),
            Err(EvidenceAbiError::Overflow)
        );
    }

    #[test]
    fn accepts_native_key_and_frame_boundaries_without_attesting_them() {
        let key = [b'a'; CT1_MAX_KEY_BYTES];
        let row = FixedRowIdentityV1::from_slice(&key, 7, 4, 2).unwrap();
        assert_eq!(row.key_len, 65535);
        let mut hasher = Sha256::new();
        hasher.update(&key);
        assert_eq!(row.key_digest, hasher.finalize());
        assert_ne!(
            row.key_digest,
            FixedRowIdentityV1::from_slice(b"a", 7, 4, 2)
                .unwrap()
                .key_digest
        );

        let mut req = abi_fixture();
        req.pending_row = row;
        req.deletion_row = row;
        req.latest_target_row = row;
        req.original_frame_len = CT1_MAX_FRAME_BYTES;
        req.observed_frame_len = CT1_MAX_FRAME_BYTES;
        let out = evaluate_structural_evidence_v1(&req).unwrap();
        assert_eq!(out.attestation_state, CT1_ATTESTATION_NONE_STRUCTURAL_ONLY);
        assert_eq!(out.authorized_actions, CT1_AUTHORIZED_ACTIONS_NONE);

        // A caller can forge a matching nonzero digest: this only checks structure.
        req.pending_row.key_digest = [9; 32];
        req.deletion_row.key_digest = [9; 32];
        req.latest_target_row.key_digest = [9; 32];
        let forged = evaluate_structural_evidence_v1(&req).unwrap();
        assert_ne!(forged.transcript_digest, out.transcript_digest);
        assert_eq!(
            forged.attestation_state,
            CT1_ATTESTATION_NONE_STRUCTURAL_ONLY
        );
        assert_eq!(forged.authorized_actions, CT1_AUTHORIZED_ACTIONS_NONE);
    }

    #[test]
    fn ffi_rejects_exact_and_partial_alias_before_reading_input() {
        let mut req = abi_fixture();
        let input = core::ptr::addr_of_mut!(req);
        let out = input.cast::<EvidenceEvalOutputV1>();
        unsafe {
            assert_eq!(
                qihse_ct1_structural_evidence_evaluate_v1(input, out),
                CT1_EVAL_ERR_FORGED_METADATA
            );
            assert_eq!(core::ptr::read(out), EvidenceEvalOutputV1::zeroed());
        }

        let mut req = abi_fixture();
        let input = core::ptr::addr_of_mut!(req);
        let out = unsafe { input.cast::<u8>().add(8).cast::<EvidenceEvalOutputV1>() };
        unsafe {
            assert_eq!(
                qihse_ct1_structural_evidence_evaluate_v1(input, out),
                CT1_EVAL_ERR_FORGED_METADATA
            );
            assert_eq!(core::ptr::read(out), EvidenceEvalOutputV1::zeroed());
        }
    }
}
