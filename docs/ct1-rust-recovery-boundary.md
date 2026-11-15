# Rust-first CT1 recovery boundary (design, not a recovery procedure)

Status: design with a Rust-only structural comparison slice in
`rust/ct1-recovery`. B's legacy CT1 source remains stopped with original
pending position 11111; its successor is sealed at 11110. This crate neither
authenticates evidence nor has a C ABI or production call site. No operation
described here is implemented or authorized to advance that cursor. Do not
convert installed `--ct-role` pairs to CT group/lane mode.

## Existing split

The legacy CT1 store, QKV6 codec, SST compaction, persistence, RESP dispatch,
and QKP peer authentication remain in C. The existing `rust/qihse-rs` crate is a
client-side binding to `libqihse.so`; the `sdks/rust` crate is a PostgreSQL-wire
client. Neither is an in-process server-side recovery authority. Keep the new
recovery policy and typed control API in a separate Rust component, behind a
small, versioned C ABI, rather than presenting a new general-purpose SET/DEL
or allowing a client SDK to open a production data directory.

C owns verified server session handles, the native KV lock, sequence allocator,
WAL/SST writes, fsync, and recovery replay. Rust owns bounded parsing of a
recovery request, proof comparisons, state transitions and fail-closed decisions.
C must validate the live pinned QKP peer and Operator principal before passing a
request to Rust; Rust must require opaque verified-authority handles, not a
caller-supplied `authenticated` boolean or unauthenticated high-water number.
A decision is never by itself an ACK, a cursor update, or permission to serve
ordinary reads. The C executor must recheck generation, cursor, immutable frame
identity, row state and high-water while holding the KV lock immediately before
every durable transition; otherwise the Rust decision can race with the store.

## Proof and order

1. Require the exact pending group to have one SET row; reject multi-row
   groups. Bind the actual source frame (exact bytes and length), decoded row
   key, tenant, labels, actor, generation and position to a digest. Verify the
   current pinned target's sealed baseline and cursor and source-authored
   same-key deletion from the authenticated CT WAL. Recheck that this deletion
   is still the latest same-key physical record, including its version and
   labels; a later valid SET must not be overwritten. Source-only GET absence
   or an all-zero/unavailable TARGET STATUS is not proof.
2. Obtain target's actual durable row-sequence high-water in that authenticated
   session. Fenced source compensation must durably publish a floor above it,
   allocate a new sequence greater than the target's high-water and append a
   source-authored tombstone without allowing ordinary writes or reads.
3. A target outcome for the *original* group 11111 must remain non-visible
   across every crash cut, cold replay, tombstone compaction, WAL retirement
   and snapshot. Retain its exact provenance; never skip it in the source,
   replace the original frame, forge ACK/ABORT, or force a cursor. A separate
   durable suppression disposition or atomic two-group transaction is needed
   before any special receiver apply; the existing stale-SET guard stays on
   the ordinary path.
4. Apply and ACK the actual compensating group in order. Permit source
   RECONCILE only after the sealed target cursor equals source durable/ACK and
   the deletion remains effective through cold reopen. Duplicate requests
   after any lost reply must be idempotent or fail closed.

The Rust/C ABI must use fixed-width fields, explicit lengths and versioning;
reject nulls, oversize inputs, invalid UTF-8 where text is required, overflow,
wrong pins/generation/baseline, mismatched frame bytes or key/labels, missing
or non-source-authored tombstones, stale proof/cursor and insufficient sequence
floor. No FFI panic may unwind into C. The present public `Comparison` is
only a structural input, not an attestation: callers can fill every field.
Before any production call site exists, a verified-authority handle must be
unforgeable across the ABI, and C must recheck it under the lock.

## Release gates

Run `make test-ct-recovery-rust` for the current structural checks. Add Rust
unit tests for authenticated proof/state validation; C fault-injection tests for
allocation, WAL append, marker fsync, partial pair, ACK loss, compaction and
restart; real pinned-QKP CT1 daemon tests including negative authority; and
independent coherent B working-copy reopens. Package a labelled immutable
runtime including the Rust component and its dependency closure. Preserve the
original stores, journals, frozen copies, generation and routing; keep B owner
stopped until the gates pass. `b57774a`'s future tombstone-retention fix is not
an implementation of the recovery transaction and is not yet deployed.
