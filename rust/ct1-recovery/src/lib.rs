//! Structural checks for a legacy CT1 recovery proposal.
//!
//! This crate does not authenticate QKP peers, inspect native WAL frames, write
//! data, authorize a suppressed apply, or issue an ACK. Its inputs must first be
//! established by the pinned CT1 transport and rechecked by the native executor
//! under the store lock. A successful comparison is never permission to serve.

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
}
