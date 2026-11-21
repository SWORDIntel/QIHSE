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

## Baseline membership binding

Group `STATUS` appends the current slot-bitmap digest (14 fields). Group
`BASELINE STATUS` appends the immutable image's bitmap digest (8 fields).
The source captures that digest under the same KV lock as the snapshot bytes;
a later membership change cannot relabel an older image. Both replies retain
pinned transport identity and the explicit snapshot data principal.

Before replacing a receiver image, its worker requires both remote scope
digests to match its own persisted receiver bitmap digest. A mismatch waits
for the existing common-FINAL reconciliation. It does not derive membership
from the remote caller. This prevents a narrowed source baseline from
tombstoning rows that the receiver is about to serve in another SOURCE group.
Same-generation bitmap changes checkpoint historical shared WAL frames before
publishing the new bitmap; independent retained source logs preserve ACK work.

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
Phase 4 records completed local membership publication. Only that durable
completed state may be replaced by a different transfer; phase 3 must remain
retryable until its bitmap and cache changes finish. A distinct zero-cut INTENT
can be journaled and interrupted before replacing that old phase-4 descriptor.
Replay and explicit abort must treat the retained completion as historical, not
as the new INTENT's unresolved fence. They still require the exact common ABORT
and keep the old descriptor unchanged; same-ID or mismatching phase-1/2/3 state
is not discarded. `test-ct-lane-transfer` constructs a real completed descriptor,
then checks direct abort and automatic replay after separate durable INTENTs and
reopens, low-authority denial, exact descriptor preservation and a subsequent
native source fence/export. The regression fails at direct abort before the fix.
Completed same-ID retries must still return the original result. Adjacent
negative cases retain real native phase-1/2/3 descriptors and phase-4 same-ID or
nonzero-cut claims: rejected operations must not invoke common ABORT, alter the
descriptor/group state, advance row sequence or rewrite the rejected journal.
Authorized visibility is compared before/after rather than bypassing an
unadmitted or fenced lane to inspect rows; the unrelated source write is ACKed
before its positive read check. Negative-case journals are preserved separately
inside their own fresh fixture, never substituted for pre-existing history.
The phase-3 fixture already has common FINAL, so replay may legitimately finish
it; only its conflicting abort is a negative case, not that valid FINAL replay.

The converse is an actual same-ID native phase-1 source fence at cut zero, not
an unfenced INTENT alongside a different retained phase-4 completion.
[`zero_cut_case`](../../tests/test_ownership_lane_abort.c) in
`test-ownership-lane-abort` journals INTENT0, establishes that real fence and
verifies that its exact descriptor survives a clean store close/reopen while
the journal still contains only INTENT0. SOURCE admission is runtime state:
both SOURCE lanes are explicitly re-admitted with their authenticated peer
before ownership replay. Replay rebinds INTENT0 to same-ID PREPARED0 and leaves
it unresolved, without invoking common ABORT, discarding the fence or changing
lane state or row sequence. Zero alone is not evidence of an unfenced intent.
A valid SOURCE-scoped write and a low-authority abort are denied while the
fence, lanes, row sequence, journal, topology and authority counters remain
unchanged. An authenticated explicit abort obtains the exact common ABORT and
releases the fence; retries
and terminal replay recheck that decision idempotently without rewriting the
terminal journal. Both groups' state and row sequence are preserved through
abort; the unrelated group and both slots' topology owner/state/peer/epoch
remain unchanged even after a classified source write is ACKed and read by the
authorized principal. The low-clearance read remains denied. A distinct
reservation then acquires a real cut-1 fence, refuses an overwrite, and preserves
the classified row after exact common ABORT.

The same target now also runs a separate witnessed process-death case. A fresh
exec journals INTENT0 and returns from the real durable same-ID phase-1 fence,
checks the native descriptor and INTENT-only journal, writes an exact
`SOURCE_FENCED_PHASE1_INTENT0`/transfer-ID pipe witness, then receives SIGKILL
before any destructor or PREPARED append. The parent requires exact bytes, EOF
and direct SIGKILL; watchdog SIGALRM is failure. A second fresh exec opens the
same stores without rerunning SOURCE creation helpers. Before native open it
checks all three original lane-metadata/fence/journal file hashes and identities
against fixture-owned same-build expectations, never used as restore inputs.
Startup legitimately republishes lane metadata with SOURCE admission disarmed;
after open the descriptor/journal remain exact, while decoded lane state differs
only in runtime admission. Both SOURCE lanes are then explicitly reconciled from
their persisted baseline evidence before the existing PREPARED0/no-auto-ABORT,
fenced-write/low-abort denial, preservation, exact common ABORT release and
classified cut-1 progress assertions run. New crash fixtures and witness records
remain preserved. The original clean-reopen case remains exercised too.

Main verified normal `test-ownership-lane-abort`, its fixture/ownership/KV-TU
ASAN/fatal-UBSan/leak-detection target, and adjacent lane-transfer, staging
discovery, ownership abort/transfer and range-authority targets passed. These
are live-filesystem process-death checks with deterministic common-authority
hooks, not persistent-authentication, live-consensus, power-loss or physical
storage evidence. Full CT gates remain open; these focused results do not close
the recovery or failure matrix.

## Reservation-owned cancelled staging

Receiver preparation now writes private `QCTLN005` metadata. Only allocation of
an absent receiver, or reset of an empty non-admitted receiver bitmap, records
staging provenance: transfer ID, reservation index and SHA-256 binding of the
immutable reservation tuple plus lane identity, token, policy and bitmap, plus
the preparation-time source cut and an explicit known flag. Exact reuse of an
occupied unmarked receiver never acquires cleanup authority. `QCTLN002/003`
remain readable and upgrade as unmarked; 004 provenance retains an unknown cut,
not an inferred zero. Older binaries cannot read the new format. This is not an
in-place deployment or downgrade procedure.

An exact authenticated common ABORT may retire only matching temporary receiver
membership. It checkpoints historical shared WAL, durably publishes an empty
bitmap and invalid baseline, then removes the transfer descriptor. Rows, labels,
identity, token and cursors remain intact. Uncertain metadata publication fences
the handle until reopen; descriptor-removal failure retains retry evidence.
FINAL membership, explicit prune, admission and promotion invalidate staging
eligibility. Unmarked replicas, SOURCE contexts and differing occupied images
are not made disposable by an ABORT.

`test-ownership-lane-abort` reproduces the old `EBUSY` on disjoint reuse after a
real nonempty import/ABORT/reopen. It now checks reuse, preserved classified
source-target data, prepared-only native cancellation, missing/wrong proofs,
stale token/generation/reservation isolation, and failures before metadata rename,
after rename at parent fsync, and at descriptor unlink. Each fault is witnessed
by fixture-only exact-path/inode-guarded interception and reopened before retry.
Canonical 003 migration remains unmarked through exact prepare/import/ABORT.
A real completed phase-4 receipt also survives later prepared-only cancellation,
immediate retry and reopen byte-for-byte. Retired unowned rows remain excluded
from public snapshots; identical native reimport proves their retention without
bypassing that fence. `test-ownership-lane-abort-sanitize` instruments the fixture
and its directly compiled ownership and KV translation units with ASAN/UBSAN
(fatal undefined behavior) and leak detection against the rebuilt native library,
not a wholly instrumented library.

Ownership reconciliation now discovers marked pre-import candidates when no
descriptor exists, or beside a retained completed phase-4 receipt. An additive
Operator-only enumeration API supplies hints, never tokens or cleanup authority.
For a known cut, reconciliation resolves the provisioned topology/QKP map, obtains
the full common claim through the unchanged authority adapter, verifies an
already committed ABORT, and obtains the current native capability for cleanup.
It never creates a common ABORT. Unknown, RESERVED, FINALIZED, unavailable and
cut-unknown marked candidates are preserved and defer readiness; unmarked
receivers are not cleanup candidates. An earlier unresolved candidate does not
hide later committed cancellations. The scheduler
retries local pending/staged work every five one-second ticks even if the common
commit index is unchanged, without unconditional idle authority sweeps.

`test-ownership-staging-discovery` uses real KV prepare/close/reopen with nonzero
cuts, the actual range-authority adapter and a deterministic typed common log.
It discards transient claims/tokens before reopen, checks enumeration denial and
cleared outputs, unknown/reserved/final preservation, unavailable authority,
unchanged unrelated SOURCE/unmarked membership and labelled data, and repeated
reopen. A valid canonical FINAL control and a valid ABORT for a different source
cut are independently verified before testing preservation/rejection. Its 004
compatibility exec keeps cuts unknown through upgrade; explicit native cleanup
with a separately supplied exact common ABORT still works. A separate historical
ABORT replay has neither old capability and preserves a newer SOURCE incarnation,
its token, labelled row and newer routing epoch. Native no-op resolution does not
require an unrelated new token; actual staged retirement still does.
The retained-receipt wrapper test uses a deterministic authority fixture, not
that real-adapter common log; neither is a live consensus cancellation drill.
Unmarked historical cancellations remain conservative. These bounded local
results are not independent-node, power-loss, storage-controller or full CT
acceptance evidence.

## Promotion and certificate recovery

Reserved promotion prepares the new SOURCE generation while ordinary reads,
writes and brain selection remain blocked by a persisted promotion-pending
gate. Replication baseline/certificate exchange may proceed. Baseline ACK
does not itself authorize ownership. The actual ready marker, original signed
certificate history and successor ACK precede common FINALIZE; an explicit
proof-verified admission step follows it.

Applying FINAL also durably fences any local SOURCE context superseded by the
promotion before updating its routing view. Routing changes alone do not revoke
a KV writer token or an old-generation ACK path. A returned former owner can
become the new successor through the existing verified authority claim; its
stale persisted role must neither block that transition forever nor be reset
from the original CLI map. Unrelated local groups remain usable.

The daemon must keep scheduling an unfinished durable promotion even if common
FINAL already cleared the local `promotion_pending` flag and a later routing
refresh or FINALIZED append failed. SOURCE recovery selects the latest validated
PREPARED/COMMITTED lane journal record, binding the local topology/QKP identity,
exact generation/bitmap and recorded successor's explicit mapping/pin. Mutable
successor health or return of the old owner does not discard this retry; the
promotion resolver still verifies common authority and proof before acting.
Missing, unreadable, malformed, foreign or mismatching records are not permission
to start a new election. A FINALIZED record stops automatic retries.

`make test-ct-group-failover-tick` exercises the actual daemon scheduler with real
auth, topology, journal and promotion producer calls, using deterministic KV,
common-authority and transport boundary doubles. The pre-fix scheduler fails
after one injected post-FINAL routing-refresh failure; the fixed scheduler
recovers the same ID with pending cleared and stale successor health, appends
FINALIZED once, and leaves no-work/mismatched/unauthorized cases unchanged.
A fixed-size, scheduler-owned discovery cache now retains only the globally
unresolved promotion tuple permitted by the validated journal. It caches terminal
absence as well as pending work, preventing idle SOURCE lanes from re-parsing
history every second. Path, inode, size, ownership/mode/link metadata and
nanosecond mtime/ctime changes invalidate it; a failed or observably changing
replay drops every candidate and is retried. Live lane identity, principal,
generation, bitmap and successor pin are still checked per tick, and the real
producer still replays and verifies authority before acting. Metadata bracketing
is not an atomic snapshot proof or permission to skip producer validation.

The actual-tick test counts daemon replay calls: unchanged post-FINAL failures
retry without another discovery scan, terminal histories stay idle, and valid
append, equal-size inode replacement and same-size corruption (including
preserved mtime) invalidate the cache. It also forces FINALIZED-append failure
and verifies later recovery with pending already cleared. This is not a journal
lifecycle, resource/scale gate or whole-daemon stack bound. Adjacent loopback
`test-ct-multigroup-promotion` and `test-ct-group-admission-recovery` exercise the
rebuilt local daemon; bounded passes are not the full CT recovery/failure matrix.

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

## Interrupted SOURCE ACK recovery

SOURCE ACK metadata is durable before data-image sync and sidecar prefix GC.
An observed promotion-drill restart left metadata ACK/durable 2 with a valid
sidecar ACK 1/last 2 and matching WAL frame 2. The old startup path rejected that
legal split before reaching post-WAL reconciliation.

Only private recovery calls now permit a lagging sidecar ACK. They retain the
sidecar's own ACK for exact duplicate verification and contiguous reconstruction;
metadata ACK does not skip uncollected frames. Sidecar ACK ahead of metadata,
wrong duplicates, identity mismatches and unavailable/gapped suffixes still fail.
Normal append callers remain strict. Post-WAL reconciliation alone advances ACK
and collects the prefix; recovery does not GC first to make space.

`test-ct-lane-log` witnesses actual metadata-file and parent fsync followed by
SIGKILL before data sync/sidecar GC. Fresh exec checks the native WAL/checked
sidecar, reopens twice, verifies labelled rows and SOURCE re-admission fencing,
and preserves the unrelated lane sidecar byte-for-byte. Additional private
fixtures use valid checked headers or native-codec re-encoding: ACK-ahead,
byte-different duplicate and a missing stream-position suffix are rejected;
a complete WAL suffix reconstructs a shorter sidecar. Synthetic principals are
bootstrapped afresh for these execs; this does not establish identity durability.
The focused sanitizer target instruments the fixture and KV translation unit,
not the entire library. These live-filesystem process-death and synthetic-corruption
cases do not establish host/power-loss or full CT acceptance.

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
