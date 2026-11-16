# Rust-first CT1 recovery boundary (design, not a recovery procedure)

Status: **design only** beyond the structural `rust/ct1-recovery` `compare()`,
its fixed-width `qihse_ct1_structural_evidence_evaluate_v1` FFI-shaped
evaluator (not yet built or linked for C callers), and the pinned read-only
TARGET HISTORY-V1 / SOURCE FRAME-V1 C and RESP queries below. B's legacy CT1
source owner remains stopped, with its original pending SET group at position
11111; the successor is sealed at cursor 11110. Its source-authored same-key
tombstone is at 11103. The sample row sequences in the Rust fixture are
pending 5729448, tombstone 5729450, target high-water 5729457 and source
high-water 5729448; stream positions are **not** row sequences. These fixture
numbers illustrate the discrepancy, not a live read of B. Preserve the
original group, both stores, all journals, generation, seals and routing. The
structural-only ABI never attests its caller-supplied inputs and always returns
zero authorized actions; there is no C-minted verified capability, recovery
executor or production call site. No operation described here is implemented
or authorized to advance either cursor. Do not convert installed `--ct-role`
pairs to CT group/lane mode.

On 2026-11-16, the stopped B source's eight frozen native files matched both
its manifest and original; the successor's seven frozen native files matched
its manifest, while only five still matched its active, compacted store.
Manifest-only private working copies were verified before making separate
disposable clones. Local V1 queries on those disposable clones returned the
original 1644-byte source frame at 11111/5729448 and the target's physical
tombstone at 11103/5729450, sealed cursor 11110 and high-water 5729457.
These fixture-principal queries are **offline** checks: they provide neither
live pinned-QKP evidence nor historical source-authorship attestation. A store
open can write audit data and repair WAL tails; do not open the frozen evidence
or verified working copies to repeat the queries.

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

## Proposed next-stage verified-evidence capability ABI (not shipped)

This is an **internal, same-process** Rust/C ABI sketch, not a new RESP command
or authority for a client SDK. `include/qihse_kv_store.h:312-413` defines only
read-only V1 queries; `rust/ct1-recovery/src/lib.rs:30-124` defines public,
caller-manufacturable `Comparison` fields and a structural floor computation.
No `ct1_recovery_*` symbols below exist at `6b04d1f`. Define an internal C
factory accessible only after native daemon admission; it, **not Rust or wire
input**, mints and owns `ct1_recovery_cap_t` in a process-local registry. A C
pointer is a lookup key, never a serialized token, and is validated against
registry membership before dereference. No public constructor, pointer
round-trip through RESP, persisted capability, or authority based solely on a
`Comparison`/`authenticated` flag. Example ABI shape (names and layout
proposed, to be reviewed with implementers):

```c
typedef struct ct1_recovery_cap ct1_recovery_cap_t; /* C-owned, opaque */
typedef struct {
    uint32_t version;                 /* exactly 1 */
    uint32_t size;                    /* exactly sizeof this V1 struct */
    uint8_t generation[16];          /* decoded 32-hex CT generation */
    uint8_t baseline_digest[32];
    uint64_t baseline_row_seq;
    uint64_t expected_target_cursor; /* 11110 for B; selector, not proof */
    uint64_t pending_position;        /* 11111 for B; selector, not proof */
    uint32_t reserved;                /* zero; no unknown flags */
    uint32_t requested_operation;     /* exactly VERIFY, not APPLY/ACK */
} ct1_recovery_request_v1;
typedef struct {
    uint32_t version;                 /* exactly 1 */
    uint32_t size;                    /* exactly sizeof this V1 struct */
    uint32_t outcome;                 /* DENY / REVIEW_REQUIRED / CANDIDATE */
    uint32_t reserved;                /* zero */
    uint64_t minimum_next_row_seq;    /* max(target, source high-water)+1 */
    uint8_t evidence_digest[32];     /* transcript binding, NOT a signature */
} ct1_recovery_decision_v1;
/* Internal C admission obtains a live session/manifest and store evidence;
 * Rust only borrows the minted cap for comparison. */
int32_t ct1_recovery_evidence_open_v1(const ct1_recovery_request_v1 *,
                                      ct1_recovery_cap_t **);
int32_t ct1_recovery_compare_v1(const ct1_recovery_cap_t *,
                                ct1_recovery_decision_v1 *);
void ct1_recovery_evidence_close_v1(ct1_recovery_cap_t **);
```

All scalars crossing the boundary have fixed widths, arrays have fixed extent;
there is no `size_t`, `bool`, enum layout, `char *` string, host-order serialized
struct or variable-length unbounded pointer in the evidence payload. The only
pointers are process-local ABI arguments; no structure is written to disk or
sent on the wire. An owned, length-bounded copy of exact QKV6 frame bytes and
key, decoded tenant/labels/actor/expiry, source and target node IDs and pinned
public-key identities, generation, baseline, WAL extent, cursor, source ACK
and durable positions, deletion position/version, latest physical row/version
and both high-waters live **inside C's registry**. C controls frame allocation,
zeroization and lifetime; Rust borrows a checked, length-bounded view only
within `compare_v1`, does not store it, and cannot mint/clone an authority.
C validates the registry entry first, then passes a checked view to Rust; a
Rust FFI export must not dereference the opaque pointer independently.
Strict version/size, zero reserved bits, nonnull output, overflow and exact
key/frame/labels validation precede any access; failure zeros outputs and
returns a fixed-width error code. Close invalidates the cap and zeroizes its
protected buffers; invalidate on QKP disconnect/pin or principal change,
manifest change, generation/baseline or WAL change, cursor/high-water change,
expiry, store close/reopen, or failed recheck. Old, copied, cross-thread,
foreign-store or post-close handles fail registry and epoch checks; retire
handle addresses for the process lifetime (or use a validated generation-bearing
indirection) so allocator address reuse cannot revive a stale pointer. Rust
catches panics at the ABI boundary and never unwinds into C. Capability expiry
and single-use consumption are enforced in C, not by Rust's output.

Each server mints only its **own local** capability: source C verifies the
source WAL under its lock; target C verifies the receiver under its lock and
returns only a bounded, pinned-QKP authenticated, fence-epoch-bound receipt.
Source C validates that remote receipt against its configured target pin and
manifest before minting its combined local comparison view. B's ordinary owner
must stay stopped: a separately deployed recovery-only process with exclusive
ownership of a coherent B working copy may make offline evidence queries, but
cannot present that copy as the live pinned source. Any later live source
recovery process must exclusively own the original store and pinned identity,
boot control-only, and durably fence ordinary writes, ACKs, reads and automatic
reconciliation before accepting a QKP peer. Never run it alongside the stopped
owner's original service or expose a working copy on the production route.
No target pointer crosses a process boundary. Target C independently verifies
that same binding under its lock at commit; the receipt does not authorize
target mutation.
Minting requires **C-only** checks of a live authenticated QKP session: exact
configured node ID **and public-key pin** in each direction, active configured
non-Operator replication service principal with tenant/label access, and a
separately authenticated, scope-limited Operator approval/manifest for this
specific stopped B recovery. C validates the manifest's trusted issuer,
anti-replay epoch, source/target IDs and pins, generation, baseline sequence and
digest, pending group position, exact frame hash, row identity, allowed
operation and expiry against configuration and persisted local state. Never
accept these claims merely because a caller supplied them. C reads the
retained single-SET source WAL group and its **exact** frame under the source
store lock; C reads receiver history, latest physical tombstone at 11103,
row version and actual high-water under the target store lock. A locally
approved manifest and current pinned channel authenticate the **present**
controller's authority; SHA-256 of QKV6 bytes, persisted actor kind and the
read-only response cannot prove **historical cryptographic authorship** of
11111 or 11103. The target's 11103 row sequence 5729450 exceeding the
source's retained 11111 row sequence 5729448 is not evidence that 11103 is
present in the source's current WAL: ACK GC retired earlier source groups, and
the reopened source high-water fell behind the target. The frame query verifies
only the retained unacked tail; independently bind historical target groups,
source frozen manifests and prior source-authored deletions before using that
ordering as recovery evidence. Never relax codec sequence checks to infer
missing history. If historical cryptographic authorship is required, specify
an independently signed origin receipt/journal and trust root before permitting
a `CANDIDATE`; otherwise label the evidence as bounded local-WAL provenance,
not historical peer attestation. No read-only response or Rust decision grants suppression.

## Proposed crash-safe B transaction and cross-process fence (not shipped)

A single KV lock cannot freeze two server processes. The target's read-locked
HISTORY-V1 snapshot can be stale before the source publishes a floor, and the
source's FRAME-V1 result can be stale before target apply. The proposal needs
**two separately durable, owner-epoch-bound admission fences** and a narrowly
scoped protocol: while B owner remains stopped, acquire exclusive source
recovery ownership (normal owner/write admission denied) and persist a source
intent; acquire a target recovery fence that denies **all target row-sequence
allocation/writers** (including unrelated keys and background expiry), CT
apply/rebind, compaction of relevant proof, and ordinary reads for the
affected key until completion. Only a revalidated, transaction-bound executor
may make the specified target disposition and compensating apply transitions.
Fence installation must be durable and checked before any source sequence/floor
change. Each server takes only its **own** store lock for its transitions,
rechecking persisted CT state, WAL extent, peer/pin, manifest,
frame, generation/baseline, row/labels/version, high-water and cursor against
its capability; network calls happen **outside** either lock. A remote reply
is a comparison candidate, never a remote lock. The target fence must return
a fresh monotonically changing recovery epoch and cursor revision; the source
binds both to its intent. Target verify/apply must revalidate that epoch under
the target lock; if the cursor or row changed since the read, invalidate the
snapshot and abort **before** source append, or retain both fences and enter
read-denying repair after append. A TTL alone is unsafe: on timeout/restart,
the persisted fence must deny reads/apply until the committed transaction is
replayed or explicitly proven aborted. Every write path including replay,
expiry, compaction and snapshot installation must honor the fence/disposition.

Proposed durable ordering, with fsync failure treated as an uncertain commit
and replay before retry (never proceed on a guessed outcome):

1. Verify both persisted states and manifest through C as above. Target under
   its write lock durably records `PREPARED` fence/intent keyed by source,
   target, generation, original position **11111**, exact frame digest, key,
   labels, baseline, tombstone 11103/version, target cursor **11110** and
   high-water, then fsyncs WAL/intent and parent directory when creating or
   replacing files. Source independently records its owner fence/intent with
   the same binding and target fence epoch, fsyncs file and directory. Never
   treat an unattested prior HISTORY-V1 query as the prepared fence.
2. With both persisted fences verified, fetch fresh target high-water **under
   target lock** via the fenced QKP protocol **outside source lock**; reject if
   its revision/row or cursor changed. Under source lock, recheck the source
   fence, its persisted state and the target receipt/epoch; publish a durable
   sequence floor at least `max(current source high-water, observed target
   high-water)` (for the fixture at least 5729457), fsync its floor record and
   directory, and re-read it before allocating. `kv_change_seq_floor()` at
   `src/black_hole/qihse_kv_store.c:539-549` is **memory-only**; do not mistake
   it for that publication. Reject overflow/allocator exhaustion.
3. Under source lock allocate a **new** row sequence strictly above that floor
   (fixture minimum 5729458), append and fsync a source-authored same-key,
   same-label tombstone as a **new group after 11111**, with durable source CT
   position/retained WAL metadata and intent bound to exact frame and target
   epoch. Fsync the WAL, CT state/intent and required directory metadata in
   their recoverable commit order before exposing that group. Never rewrite,
   skip or ACK original 11111 to make room. If either fsync is uncertain,
   reread WAL/intent on reopen and continue only the same transaction.
4. Target atomically WAL-commits a `SUPPRESSED_ORIGINAL` disposition for the
   **exact** 11111 frame plus advancement of its cursor to 11111, with the
   original frame/provenance retained but **no SET row made visible**. Before
   ACK permits source GC, persist and verify that exact frame in the target
   disposition or a separately durable immutable archive, alongside the
   preserved frozen original source copy; a hash alone cannot retain payload
   and metadata. Do not rely on SOURCE FRAME-V1 after the final source ACK.
   Fsync that atomic transaction before acknowledging 11111; reject generic apply
   and any mismatched duplicate. An intent alone is not suppression. With
   target lock held, recheck its fence, current cursor, tombstone latest
   version/labels and high-water before commit. Source ACK for 11111, if sent,
   reflects only this durable non-visible target outcome, never an invented
   ACK/ABORT. Ordinary reads stay fenced while compensation is incomplete.
5. Target then applies the real later source tombstone group via normal
   sequence/identity checks and WAL-commits row + cursor atomically, fsyncs
   before ACK; lost replies are resolved from durable cursor, disposition and
   exact group digest, not by replaying an unsafe SET. Source durably records
   ACK positions in order; only after target cold-reopen confirms same-key
   absence and retained disposition (including after compaction/snapshot),
   target cursor equals source durable and ACK, and both fences still match,
   durably mark `COMPLETE` and release target read/writer fences only after
   verifying the disposition/archive. Existing pinned-peer RECONCILE clears
   primary `ct_control_only` on success; do not invoke it while the B source
   owner must remain fenced. A separately implemented recovery-only
   reconciliation must persist ACK/cursor equality without admitting ordinary
   owner reads or writes; any later admission requires its own explicit
   authenticated approval and recheck. Never auto-start B owner.

The disposition is a **permanent, generation-scoped negative apply fact**:
lookup and all replay, checkpoint, SST compaction, expiry scanning, WAL
retirement, snapshot/export/import, duplicate-apply and cold-open paths must
preserve and enforce it. If the disposition or its coupling to 11111/cursor is
missing/corrupt, deny service, not fall back to normal SET. During an
incomplete transaction the target stays read-denying, even if tombstone
compaction would remove the physical row; after completion, tombstone
retention or an equivalent durable absence barrier must prevent old 11111
from reappearing. `qihse_kv_apply_replica_record()` has an ordinary stale
source update guard (`src/black_hole/qihse_kv_store.c:8146-8149`), but it is
not a crash-persistent suppression disposition and does not authorize this
exception. A reset, ACK loss, snapshot or expired key must never promote the
stale SET to a visible row. Reconcile/discard of an aborted *uncommitted*
intent requires proof that neither source append nor target disposition/cursor
committed; after either commit, recovery must roll forward or fail closed.

| Durable cut | Restart / duplicate outcome (design requirement) |
| --- | --- |
| Before either fence, or after target fence but before source floor | No apply; validate/retire uncommitted intent only under both local locks; B stays stopped. |
| After source floor fsync, before append | Floor survives restart; no reuse of lower sequence; resume same fenced proof or fail closed. |
| During append / CT state fsync, or lost append reply | Recover exact group and position from source WAL; never append a conflicting compensation or rewrite 11111. |
| Before target disposition fsync / partial WAL | Cursor remains 11110 and reads fenced; no visibility of 11111; replay truncates/repairs only proven uncommitted tail. |
| After disposition + 11111 cursor fsync, before ACK or tombstone apply | Duplicate 11111 resolves suppressed, never SET; read fence remains; roll forward actual tombstone. |
| After tombstone + cursor fsync, before ACK / COMPLETE | Verify exact digest/cursor and same-key absence, retransmit ACK idempotently; keep disposition through compaction. |
| After COMPLETE / during snapshot, expiry or WAL retirement | Restore/checkpoint includes disposition and absence barrier; reopen must fail closed if either is absent. |

### Required test matrix for a future implementation

- Rust policy/FFI: wrong version/size, null/oversize/invalid-UTF-8 IDs,
  overflow, forged/reused/cross-store/expired handle, foreign thread and
  disconnect/rebind, panic containment, changed manifest/pins/principal,
  multi-row/expired source frame, wrong key/tenant/labels/actor, later SET,
  stale tombstone or generation/baseline and floor exhaustion. Caller-filled
  `Comparison` must remain non-authoritative; result cannot drive generic
  apply, ACK or read admission.
- Native storage with fault injection at **each** fence, floor file/write/fsync
  and directory fsync, allocator, source WAL append/CT state fsync, target
  disposition+cursor WAL append/fsync, tombstone+cursor fsync, source/target
  ACK and COMPLETE fsync; simulate torn writes, restart and duplicate calls at
  every row of the crash-cut table. Assert original bytes/group and all
  journals/generation unchanged except explicitly recorded new transaction
  artifacts, and the exact original frame retained in frozen evidence and
  durable disposition/archive even after expected source WAL retirement;
  verify monotone new row sequence, cursor continuity and permanent absence.
- Race and lifecycle: interleave target cursor/row/high-water change between
  V1 read and source floor, between source append and target disposition, QKP
  disconnect/manifest rotation, competing replica apply, expiry, compaction,
  snapshot/WAL retirement and ACK loss. Each must invalidate the capability,
  refuse before append or preserve fences and recover without serving stale
  data; cold reopen source and target independently under each cut.
- Real-daemon paired pinned-QKP positive and negative principal tests,
  authentic source WAL/manifest checks, high-clearance data vs low-clearance
  callers, B-like working-copy tests with 11103/11111 and an actual target
  high-water above source; inspect cursor, source group bytes, physical row
  and read visibility after cold reopen. Never test mutations on the preserved
  original B stores.

**Unresolved material decisions:** choose the authenticated recovery manifest's
issuer/trust root, expiry and anti-replay policy and whether historical
cryptographic origin receipts are mandatory (the existing V1 responses cannot
supply them). Specify the on-disk disposition/absence-barrier format and
retention semantics, and a durable cross-process fencing protocol capable of
blocking all target writers, before any executor or deployment is approved.
Until these are decided and crash cuts verified, `CANDIDATE` is not permission
to mutate or unstop B.

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
