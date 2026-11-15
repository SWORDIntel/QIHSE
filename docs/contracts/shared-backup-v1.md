# Local shared backup package v1

Status: implementation contract, not W11 acceptance or production restore readiness.
The API is `include/qihse_shared_backup.h`. Source handles and principal must stay
alive, and declared SQL/blob engine IDs must match registrations on the retained
coordinator. Sources are local durable stores; CT/distributed/replica snapshots
are unsupported. The format does not separately collect identity authority,
external private keys, ACL authority or service configuration. Native payloads
retain their authorized application data as-is; arbitrary stored data is not
silently filtered based on guessed semantics.

## Capture and publication

Require the live bootstrap Operator (role Operator, user 0, tenant 0), acquire a
scoped principal and retain its generation. Obtain **all four** native starting
checkpoints before any native export or protected output. Refuse pending state,
unhealthy/unsupported sources, equal SQL/blob engine IDs, exhausted receipt-ID
floors or a coordinator ID floor below a participant's required next ID.

Export in this order: KV, SQL, blob, coordinator. Use only authenticated native
APIs, including SQL decision sidecars, blob archive receipts and the coordinator's
expected-checkpoint export. Then obtain and compare all ending checkpoints and
revalidate principal generation. Rejection is whole-attempt, with no publication.
Only the native KV export has logical TTL filtering: the common visibility point
is its internal snapshot capture instant; other sources must remain unchanged
across their checkpoint intervals. Source mutations after the completed bracket
do not invalidate that earlier snapshot point.

Use one private sibling directory, member files mode 0600 and directories 0700.
Require an owned private destination parent. Remove only the SQL backup lock
artifact created inside this fresh stage; it is not a package member. Flush every
member and manifest, sync the stage, and publish once by atomic directory rename
with NOREPLACE. Unsupported no-replace semantics must fail closed. Parent-directory
sync failure after rename returns PUBLISHED_UNSYNCED and must not trigger removal
or blind retry. Existing destinations and unrelated files are never replaced.

On failure, only this attempt's unpublished stage may be cleaned up. Never follow
links or recursively delete unrelated trees. Failed test evidence is preserved.

## Payload membership

Mandatory members, exactly once:

- `kv.qbp`: native full KV container;
- `sql.qts`: native committed SQL snapshot;
- `blob.qba`: native blob archive v1/v2;
- `coordinator.qtj`: portable durable 2PC journal (may be empty).

Zero or more `sql.qts.decision.<16 lowercase hex digits>` members accompany the
SQL snapshot. IDs are nonzero, and each native decision sidecar is exactly 32
bytes. No other names, directories, links, traversal, duplicate names or hidden
files are accepted. The `manifest.qsb` file is additional to the payload list.
The coordinator member length must equal the authenticated journal-byte count.
Every participant ID referenced by its native membership records must be one of
the two declared SQL/blob engine IDs: v1 cannot claim replay coverage for another
participant whose store payload is absent. This is a supported-binding check,
not a substitute for native journal validation and engine replay during restore.

Payload members are sorted by bytewise ascending filename. Each is a regular
file owned by the process's effective UID, private (no group/other permissions),
with exactly one hard link. Directory inspection rejects extra entries. Payload
limits are 4096 members and 3 GiB total; the manifest is bounded to 1 MiB. Stream
hashing/copying uses one bounded heap chunk, never content-sized allocations.

## Canonical manifest

ASCII, lowercase hexadecimal, literal single spaces, LF line endings and no NUL
or trailing bytes. Brackets below indicate values, not literal brackets:

```
QIHSE-SHARED-BACKUP 1
KV [instance:16hex] [change_seq:16hex] [projection_epoch:16hex]
SQL [epoch:16hex]
BLOB [epoch:16hex]
COORD [epoch:16hex] [next_txn_id:16hex] [journal_bytes:16hex]
ENGINES [sql_engine_id:2hex] [blob_engine_id:2hex]
TOTAL [member_count:8hex] [payload_bytes:16hex]
FILE [name] [length:16hex] [sha384:96hex]
... exactly member_count FILE lines ...
MAC [hmac_sha384:96hex]
```

The HMAC authenticates every byte before the `MAC ` line, including the preceding
LF. Its key is exactly 48 caller-owned secret bytes. The key is never archived.
A distinct magic prefix separates this message from the blob archive. Hashes are
SHA-384 over exact member bytes. Checkpoint values are the equal before/after
values, not an inference from timestamps or content hashes. IDs/epochs that the
native checkpoint APIs refuse are invalid here, too.

Verify the MAC before decoding or returning protected manifest metadata. Parse
with bounded sizes and enforce canonical encoding (including exact widths and
reserved syntax), count, sorted unique membership, required files and total size.
Compare MACs in constant time. Native payload formats retain their own versions
and are additionally bound by the member hashes. The package is authenticated,
**not encrypted**; at-rest access remains restricted.

## Verification, unpacking and real restore

Verification authenticates package structure and exact member content, not a
successful native engine replay. Unpacking verifies first, copies native members
and manifest to a new private sibling stage, rehashes copied bytes against the
authenticated manifest, revalidates principal generation and publishes once with
the same no-replace and durability semantics. It never applies to live stores.
Concurrent source-member replacement or modification cannot publish bytes not
matching the pinned authenticated manifest. NULL/low/foreign/revoked principals
are denied before protected I/O; a correct HMAC key does not confer authority.

Keep the published package immutable. Native SQL restore creates a lock sidecar
beside its input, so first unpack into a separate private working directory and
run native restore from that copy. The working unpack may then contain operational
lock files and is no longer a canonical package; do not advertise or reverify it
as one. Copy the journal to a separate working file before opening a coordinator.

Common membership can include an engine whose PREPARE was never reached, or
failed before local staging. Its authoritative ABORT is an idempotent no-op when
no blob prepare/terminal record exists; it must not manufacture a blob receipt.
Unknown COMMIT and conflicting recorded decisions still fail. The authenticated
coordinator floor, not the blob archive alone, preserves unused coordinator IDs.
The focused restore fixture covers SQL ABORT receipt 5 with no blob receipt 5,
blob floor 4 and coordinator floor 6, repeated decision replay and a new native
SQL/blob commit at ID 6 after fresh unpack/restore.

A fresh-process restore must consume the native payloads through their own
authenticated restore APIs, register the manifest's engine IDs, and seed the new
manager with the maximum of `coordinator.next_txn_id` and the restored SQL/blob
required next IDs **before** recovery. Replay all common decisions before exposing
application state. Terminal receipts must not resurrect deleted objects or reset
current refs/pins. The raw journal does not include unjournaled allocated IDs or a
full one-phase MVCC registry; the authenticated next-ID floor is mandatory.

Focused tests must exercise a real SQL/blob common decision and fresh-process
restore/replay, low-authority denial with high data, mutation of each source and
prepare/abort ABA during export, malformed and tampered manifests/members, wrong
keys, no-replace publication, write/fsync/rename failures, visible-but-unsynced
results, and source changes during unpack. Fresh-exec children also receive
SIGKILL immediately before or after export and unpack publication rename. A
parent-observed pipe witness identifies the exact hook boundary, guarded by the
destination name and parent inode; unrelated early SIGKILL cannot pass. Before
rename, no destination is visible and a new attempt succeeds without deleting
the orphan stage. After rename, the visible package authenticates and restores
natively in another fresh process; the published package remains unchanged.
These are process-death tests on a live filesystem, not power-loss or storage
controller durability evidence. The sanitizer target keeps ASAN/UBSAN and leak
detection enabled; the focused stack target enforces a 16 KiB frame threshold.
No aggregate tests or production operations are authorized for this work.

### Actual filesystem capacity failure

`make test-shared-backup-enospc` uses `tests/run_shared_backup_enospc.sh` and
`tests/test_shared_backup.c --capacity` (unpack) and `--capacity-export` in
separate fresh rootless user/mount namespaces.
Only the new fixture's `limited` directory receives a private 4 MiB, 128-inode
`nodev,nosuid,noexec` tmpfs. Source stores, canonical package, logs, partial-member
evidence and native restore files remain on the backing filesystem. Namespace or
mount failure fails the target; there is no skip or injected-error fallback.

Real writes fill a fixture-owned file until kernel ENOSPC, then truncation of only
that filler releases 32 KiB. The unpack observer passes through actual `SYS_write`
results unchanged: the exercised blob member writes 32,768 bytes, returns a short
write and then ENOSPC with zero available blocks but spare inodes. It copies the
open partial member to backing evidence before the SDK removes its failed stage,
then verifies those bytes against the canonical archive prefix. ERROR leaves the
output-info sentinel and unrelated file bytes/mode/inode unchanged and publishes
no destination. Releasing only the filler permits retry at the same destination;
the retry authenticates and restores natively in a fresh exec, including the
manifest floor 5, original receipt/deletion/reference/pin invariants and a new
common transaction. Both canonical and retry packages remain authentic.

The native-export branch releases 64 KiB instead, allowing real KV/SQL native
export and SQL receipt sidecars to finish before the blob callback hits capacity.
The exercised 4 KiB-page tmpfs run leaves 20 KiB in those earlier members and
writes 45,056 blob-archive bytes before a real short write/ENOSPC, with zero free
blocks and 118 free inodes. Deterministic blob encoding permits exact comparison
with the earlier canonical archive prefix (the whole KV package need not be
byte-identical because its header contains capture time). After either failed
operation, all four authenticated source checkpoints must equal their starting
values. The native-export retry uses the same sources and destination, then the
same fresh-exec native restore and receipt/floor/ref/pin assertions. Both modes
run in the normal and sanitizer targets. This fresh source does not exercise
degraded-SSTable materialization or bound arbitrary native-export scratch usage.

The namespace supervisor copies remaining mounted contents to backing evidence
before unmount on ordinary exit, child failure or handled supervisor signals;
launcher-only HUP/INT/TERM is forwarded and the launcher waits for cleanup.
Copy/sync failure prints the namespace PID and stops that supervisor with the
original tmpfs still mounted; repair backing storage and explicitly send CONT
to retry capture. The target cannot return success, and unmount is not attempted
until a complete copy/sync succeeds. Unmount errors also fail the target. SIGKILL
of the launcher/supervisor/host is not a preservation guarantee. The separate
`test-shared-backup-enospc-sanitize` target
instruments the fixture and shared-backup translation unit with ASAN/fatal UBSan
and leak detection against the rebuilt remaining library. This is real kernel
byte exhaustion on volatile tmpfs, not physical disk/controller/power-loss or
full workload/scale/resource acceptance. The older synthetic ENOSPC injection
remains a separate fault case. The normal capacity case also requires the failed
stage to be absent before retry, not merely the final destination. Separate local
supervisor diagnostics verified preserved markers after child exit 42,
supervisor-only TERM, launcher-only TERM, and a refused evidence copy: the last
kept the original marker in the stopped mounted namespace, then copied it after
explicit CONT and still returned failure. Those diagnostics test supervisor
preservation, not SDK capacity-error provenance.
