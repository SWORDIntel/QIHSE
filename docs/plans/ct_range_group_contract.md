# Range-group integration contract

Implementation is in progress. Completion is tracked only in
[ROADMAP.md](../../ROADMAP.md), CT.1 and CT.2. This contract describes the
interfaces shared by the storage, protocol, ownership and daemon changes.

## Scope and identities

A physical node can own SOURCE group C and receive group A simultaneously.
Each group has a stable ID, exact slot bitmap, generation, owner and successor.
SOURCE/RECEIVER belongs to the group, not the entire daemon. Promotion of A
must not demote or reset unrelated C. The metadata mesh elects a replaceable
consensus leader; that does not designate a permanent cluster data owner.

The common configured group map supplies initial owner/generation/successor.
The latest committed finalized promotion overrides those values. A source
node must not resolve a remote destination's generation from its local KV
contexts or infer a generation from a slot epoch. Empty configured destination
groups are valid. A failed authority query is not absence of a promotion.

All storage and protocol operations carry the actual authenticated control
and data contexts. System Operator is the existing control authority; these
changes introduce no user account or administrative CLI. Group replication
uses SYSTEM_ALL tenant policy with per-record class/SCI checks. Unsupported
exact-tenant group configuration is refused before persistence.

## Sequence domains

| Field | Meaning |
| --- | --- |
| Row `change_seq` | Source-local row/version sequence, not a group position |
| `baseline_row_seq` | Snapshot row watermark; may exceed the maximum selected row version |
| `baseline_stream_cut` | Group stream position captured by a full baseline |
| Transfer `source_cut` | Position at which the selected source slots were fenced |
| Transfer `target_cursor` | Target group's durable position bound by its typed receipt |

For PROMOTION claims, the historical `target_cursor` field instead binds the
fresh baseline's row watermark. The operation tag distinguishes it from a
TRANSFER's target stream cut; it is not the new generation's zero-based CT
position.

Zero is valid for an empty sealed stream or image. Explicit phase, sealed
baseline and proof distinguish empty from uninitialized state. Raw empty QFS
has zero bytes and a valid SHA-256 digest; no sentinel rows are added.

Outside-slot writes can advance a source group's current durable/ACK position
after a selected range is fenced. Export therefore requires its exact stored
cut to be acknowledged, not equality with the whole group's current position.

## Reservation and learned cuts

1. Resolve one admitted local SOURCE group for the interval's bitmap.
2. Reserve its expected committed ownership in the mesh. The transfer cut is
   initially unknown; the draft claim uses zero.
3. Persist INTENT, fence selected slots and learn the actual source cut.
4. Persist PREPARED with that cut. Rebuild the claim and store-bound proof
   using the actual cut before export or any target BEGIN.

The immutable reservation binds IDs, groups, generations, bitmap and grant.
The learned cut is checked against the actual frozen store. Export and import
compare it exactly, including zero. A nonzero caller-supplied fence cut must
match the actual cut. The final typed receipt binds all learned evidence.

## Transfer A to existing destination group C

The original grant names source owner A, target owner C, and C's successor D.
The source exports one exact image and stages it on both C and D.

| Local node | Source group A context | Target group C context |
| --- | --- | --- |
| C | Existing or temporary RECEIVER A | Existing SOURCE C |
| D | Existing or temporary RECEIVER A; possibly fenced SOURCE A if D is the old owner | Existing RECEIVER C |
| Old owner A | Fenced SOURCE A | May be absent; only present if A is C's successor |

An existing A receiver can cover more slots than the transfer. Installing a
selected subset preserves its full bitmap, global baseline and cursor. A new
unsealed temporary receiver whose complete bitmap is selected may initialize
its baseline/cursor from the image. All outside data and stream state remain.

The imported image is durably staged before its readiness seal is issued.
`range_digest` covers selected semantic rows; `image_digest` authenticates the
complete original QFS, including versions/tombstones/expired records. Their
composite checksum is the group transfer's activation checksum. Target-local
highwater can advance independently; incoming source row versions remain
usable for later source deltas. Removal of stale target rows can make its
physical QFS differ from the original source image.

C's GROUP-ACTIVATE independently queries pinned D's persisted readiness seal
over QKP before issuing the existing exact-tuple C activation receipt. A's
assertion that D is ready is insufficient. The inner D seal binds its issuer
separately from original target C. A legacy ACTIVATE cannot bypass the group
handler on a group-configured server.

After the common FINALIZE decision, local membership update removes only the
selected A bits and adds them to C contexts that actually exist locally.
C remains SOURCE on C and RECEIVER on D. Unselected bits/cursors remain.
An emptied temporary receiver can retire only when historical replay remains
possible. A durable phase-3 intent alone never authorizes membership; restart
revalidates the common decision and repeats finalization idempotently.

## Promotion and certificate recovery

Reserved promotion prepares the new SOURCE generation while ordinary reads,
writes and brain selection remain blocked by a persisted promotion-pending
gate. Replication baseline/certificate exchange may proceed. Baseline ACK
does not itself authorize ownership. The actual ready marker, original signed
certificate history and successor ACK precede common FINALIZE; an explicit
proof-verified admission step follows it.

Certificate logs can contain signed prepared/aborted attempts. Recovery pages
are original signed envelopes, not assertions re-signed by a later node.
The client verifies signatures and common FINAL decisions, filters other
attempts, checks the complete selected chain, then journals/applies links in
order. Network recovery runs on the proof worker outside the bus mutex.

Routing is reconciled from the authenticated committed mesh owner map after
common initialization and when decisions advance. This also repairs mixed
histories where CT2 changes a group's bitmap between promotions; promotion
certificates alone cannot describe that intervening transfer. Refresh checks
the entire selected map against trusted QKP identities before adoption and
preserves newer local epochs. It does not admit KV data or change group roles.
Historical journals/certificates cannot overwrite a newer committed map.

`REPL.CT1 CERTPAGE <lane> <after-sha256> <capacity>` returns one RESP bulk of
existing KV page records: BE32 length, SHA-256 digest, exact envelope. An
authenticated pinned observer can fetch authority metadata even if it is not
the current data successor. The requested canonical QCP2 event bounds recovery.

## WAL and retention

Historical replay validates actual labels and durable frame integrity; it
does not reauthorize past mutations using today's role, bitmap or generation.
Only current-generation frames advance the live stream cursor. Current
read/write admission remains separate from historical data reconstruction.

A bounded QKV7 reference frame commits an immutable authenticated baseline
image at its ordered WAL position before applying selected replacement. It
does not truncate other groups' recovery history. Per-group source logs retain
unacknowledged replication frames independently of the data WAL. ACK-prefix
collection follows durable SST publication; one stalled group must not retain
another group's acknowledged replication log. Restarts preserve persisted
cursor checkpoints and reconcile exact duplicate/newer durable frames.

Existing node-local namespaces retain native authenticated KV durability and
their existing replication contracts. They are not silently assigned to a
random group. Slot balancing does not implement AIMEM dataset sharding.
