# Rust-first CT1 recovery boundary (design, not a recovery procedure)

Status: design with a Rust structural comparison slice in `rust/ct1-recovery`
and a read-only native C receiver-history check described below. B's legacy
CT1 source remains stopped with original
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

## Legacy receiver-history read API (first slice)

`qihse_kv_ct_receiver_history_v1` in `include/qihse_kv_store.h` is a
read-only native C query, not a Rust recovery control or production recovery
endpoint. The legacy RESP transport is `REPL.CT1 TARGET HISTORY-V1 generation
baseline_row_seq baseline_digest durable_cursor key resource_tenant_id
classification sci_compartment` (11 RESP arguments including command and
operation). It accepts only the configured successor's pinned source QKP peer
mapped to the exact active replication service principal; Operator QKP sessions
cannot bypass this gate. Source and target IDs come from server configuration,
not wire arguments. It returns exactly four decimal bulk fields:
`stream_position`, `row_change_seq`, `durable_cursor`, `row_seq_high_water`,
with no key, value, protected payload, ACK or state mutation.
It requires an active explicit replication/Operator principal, a versioned
request, exact current legacy receiver source/target/generation, sealed baseline
sequence and digest, current durable cursor, and one key, resource tenant and
classification/SCI pair. With the store read lock, it checks persisted CT state,
verifies the latest physical same-key tombstone via authorization-aware,
metadata-only row lookup, and decodes **all** retained receiver QKV6 frames
from position 1 to the current cursor with that principal and the receiver's
own tenant policy. Inaccessible frames, noncontiguous
positions, bad frames, wrong policy/mode/identity and trailing bytes fail closed.
A successful result contains only the tombstone's actual group position and row
version, receiver cursor and target row-sequence high-water; failures zero it.
A later same-key SET or changed latest version/labels invalidates the result.

The QKV6 SHA-256 checks frame bytes, **not** QKP peer identity or source
provenance. The group source ID and non-replica actor kind are persisted
metadata, not cryptographic peer attestation. The remote adapter pins the
authenticated source QKP service peer, but does not attest the original pending
source frame. Any future recovery controller must separately verify that frame
against trusted source evidence. This result is neither mutation authorization,
suppression, ACK, recovery admission nor a way to advance the source or receiver
cursor. It must be rechecked at any future
transition under the store lock; no such transition is supplied here.

Migration note: this is an additive native C ABI (version 1); existing callers
need no changes and stored data needs no migration or reindex. Consumers must
rebuild against the updated header and library (`make lib`), construct the
version/size-tagged request and check the boolean result before using any output.
Validate storage with `make test-ct-storage` and the pinned-QKP read-only
adapter with `python3 tests/test_ct_transfer.py Ct1RealDaemonTests -v`.
Neither check enables Rust FFI or production recovery use; original pending
frame attestation, recovery crash cuts and deployment gates remain unmet.

## Legacy retained source frame read API (second slice)

`qihse_kv_ct_source_retained_frame_v1` is a local, read-only native C query
for a currently retained, unacknowledged single-SET source group. Its remote
transport is `REPL.CT1 SOURCE FRAME-V1 generation baseline_row_seq
baseline_digest acknowledged_position durable_position stream_position key
resource_tenant_id classification sci_compartment row_change_seq` (14 RESP
arguments including command and operation). Only a live, active replication
service principal on the configured primary, authenticated as its exact pinned
successor QKP node **and public key**, can call this transport. The primary's
source and successor IDs come from local server configuration, never the wire;
Operator/admin sessions and other trusted peers have no access. All wire
fields are length/range bounded and compared against the current persisted
source state and retained WAL. Failed requests return one generic denial with
no frame or protected payload.

A successful reply has nine bulk fields: original bounded QKV6 frame bytes,
SHA-256 of those **exact bytes**, key, resource tenant ID, classification,
SCI compartment, stream position, row change sequence and expiry time in
milliseconds. The frame is captured during authorized decoding, not
re-serialized. The native query checks the whole retained WAL through clean
EOF and refuses inaccessible rows, bad identity/bounds, expired or ACKed
frames, multi-row groups and malformed data. The read does not mutate state,
ACK a group or establish cross-crash source authorship: QKV6's checksum and
the frame hash authenticate neither the historical QKP peer nor a recovery
decision. This endpoint grants no suppression, compensation, cursor advance,
reconciliation or recovery permission. Any future recovery executor needs
independent verified provenance and a fresh locked recheck; there is no
production recovery call here. Isolated real-daemon transport checks are in
`tests/test_ct_transfer.py` (`test_source_frame_v1_*`); native storage checks
are separately owned in `tests/test_ct_storage.c`.

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
