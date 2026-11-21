# Bounded W11 native order-recovery fixture

`make test-w11-order-recovery` exercises a supported placement, not a production
checkout API or full W11 acceptance. Stock, orders, lines, operation ledger and
**event intent** live in one durable native SQL transaction. Blob evidence is
explicitly enlisted with SQL in common-manager 2PC. This does not enlist the
separate KV inventory counter, deliver an event, charge a payment or promise
external exactly-once behavior. Ordinary UWP COMMIT remains one-phase.

## Invariants and retry identity

Two products start with stock 10 and 9. Authenticated queries verify nonnegative
stock and `initial = remaining + sum(committed order quantities)` per product.
Each accepted operation has exactly one order, line, ledger row and event intent.
Their common transaction ID and SHA-384 cross-resolve to the exact classified
blob content, binding and reference count of one. The source accepts three
orders, including a pair of conflicting thread-owned SQL shadows. A fourth order
is committed on the independently restored stores and survives fresh reopen.

Retry identity is the persisted operation key plus its product/quantity and
expected evidence digest in the same SQL transaction, not a new general-purpose
request-retry API. Exact retries do not decrement stock or duplicate rows/blobs;
altered requests using the same operation key and insufficient stock are denied.
The SQL generation fence rejects the stale conflicting writer. READ grants are
explicit for the SQL tables: a matching-clearance/SCI Analyst positively reads
the labelled rows and exact blob. Separate low-classification and missing-SCI
Analysts retain those READ grants but cannot materialize high-data SQL rows or
blob bytes/metadata, so table-ACL denial cannot mask the label checks.

## Process and recovery boundaries

Fresh-exec children use real native participants. A parent-observed pipe witness
and exact SIGKILL status prove each intended crash; watchdog kills fail the test.

- After both PREPAREs, before a common decision: reopen durably chooses ABORT;
  stock and all order/event-intent tables remain unchanged and evidence invisible.
- After durable common COMMIT and SQL publication, before blob publication:
  reopen completes the original evidence receipt before fixture exposure. This
  explicitly tests recovery from partial participant publication, not atomic
  cross-engine read visibility during that interval.
- Repeated decision replay, exact/altered retries, a stale SQL PREPARE vote and a
  further fresh-process reopen preserve the same committed cohort and stock.

Recovery registers real participants and advances the manager above native
receipt ID floors before replay. An unattempted blob participant has no local
PREPARE: authoritative ABORT must be an idempotent no-op, not a fabricated blob
receipt or an ignored recovery error. Unknown COMMIT and conflicting recorded
terminal decisions remain denied. The coordinator journal remains the authority
for unused/aborted transaction allocation history. The adjacent SQL/blob test
also injects EIO into both index sync and rollback sync: absent ABORT stays denied
on the poisoned handle until reopen, and the failed reference increment is not
applied. Thus absent-state success does not suppress uncertain storage errors.

## Shared-package restore and durable progress

After the source conflict/reopen checks, the same retained SQL/blob/coordinator
handles and an authenticated application-KV origin marker are exported through
the shared package API. A deliberately allocated, rolled-back ID raises the
captured floor above participant receipts. The private synthetic 48-byte key
authenticates the package; it does not encrypt its classified payloads.

Fresh restore targets a separate sibling root, not the source stores. Native
SQL and receipts, blob v2 state and KV are restored from a private working unpack;
SQL's input lock and the working coordinator journal never modify the canonical
package. Every restart seeds the maximum of the authenticated manifest floor and
native receipt floors before common replay or application reads. The original
blob archive's four terminal receipts (one ABORT, three COMMITs) transfer exactly;
no receipt is invented for the blob participant never reached after SQL rejection.

After verifying that original snapshot, the restored controller commits order 24
(product 2, quantity 2) through real SQL/blob PREPARE and COMMIT at a safe new ID.
One inode-targeted blob COMMIT index-sync failure, followed by successful rollback
sync, leaves the common decision COMMITTING: SQL order and intent are visible,
blob bytes remain invisible, committed status is false, and ABORT plus shared
backup capture are refused. Retrying that same irreversible decision completes
publication without appending another common decision. Committed status becomes
true and a fresh shared backup succeeds at the previously absent destination.
This tests a recoverable local IO boundary, not cross-engine atomic read visibility
or external event delivery.

Repeated replay and exact/altered retries preserve four orders, lines, ledger rows,
event intents and evidence references. A final fresh reopen uses the newer native
receipt floors even when they exceed the original manifest floor. It verifies the
fifth real blob terminal receipt and all cohort invariants. The unchanged KV
marker identifies the original three-order snapshot, not a claim of KV/SQL atomic
progress or a current-order counter. Source package authentication stays valid
before and after all restore and new-transaction IO.

A second independent sibling, `<source>-restored-io`, exercises
`io-clone` → `io-kill` → `io-recover` → `io-reopen` without altering the normal
restored-progress branch. Clone and fresh pre-progress reopen both prove the
original manifest floor still exceeds native receipt floors. After the same
COMMIT EIO returns `EAGAIN`, the parent witnesses boundary `I` and SIGKILL before
any retry. Recovery reopens those exact files, without unpacking/restoring again.
Privileged pre-recovery inspection checks four durable SQL orders/intents against
the parent decision ID, hidden blob bytes, the actual pending native `T` record
and false committed status; checkpoint and `restart-package` export are refused.
Persisted common COMMIT replay must publish the complete cohort before direct
participant replay can repair anything. Exact replay and another fresh reopen
preserve receipts/refcounts without changing journal bytes. The previously absent
`restart-package` then exports and authenticates successfully. This remains a
live-filesystem process-death case, not host/power-loss proof.

Only private synthetic fixture principals and paths are used; failed trees stay
under `build/w11-order-*`. The test is registered for future serial CI, but no
aggregate target is needed or authorized here. Focused
`test-w11-order-recovery-sanitize` builds the fixture with ASAN/UBSAN and leak
detection enabled against the current native library; `check-w11-order-stack`
enforces a 16 KiB per-frame limit for the fixture. Wide-INSERT cast/quoted metadata
initialization is additionally covered by the native SQL parser regression.

## Adjacent SQL receipt uncertainty cases

`test-sql-receipt-recovery` uses the real SQL/blob participants in
`tests/test_sql_blob_txn_2pc.c` for independent COMMIT and ABORT branches. A
fixture-only TLS syscall guard observes the
successful receipt-file fsync, exact published receipt inode (native link/unlink
publication), and its parent directory before returning one `EIO` from parent
fsync. For COMMIT, SQL has published its snapshot and C receipt but retains
`.prepared` and poisons that handle. After durable common COMMIT, the coordinator
transaction remains COMMITTING/`EAGAIN`; ABORT, coordinator checkpoint and SQL backup are
refused.

The manager continues later callbacks: blob COMMIT publishes normally. This test
does not defer it with a mock or assert cross-engine atomic read visibility.
Only after the returned error and state/native-file assertions does the child
write the exact `S`/decision-ID witness and SIGKILL. The parent checks witness and
signal, preserving evidence in a separate parent so witness sync does not repair
the receipt directory's uncertain durability.

The ABORT branch instead publishes an A receipt, returns ABORTING/`EAGAIN`,
refuses COMMIT, and witnesses `A`/decision-ID before SIGKILL. SQL snapshot bytes
must equal the pre-PREPARE baseline and authorized row scans remain empty; the
prepared candidate is different and never published. Native blob ABORT proceeds
normally, leaves exact T/A records and keeps object bytes/metadata invisible.
Fresh common ABORT replay removes the SQL shadow without changing that baseline.
Both branches inspect native effects before any direct decision replay.

In the COMMIT branch, fresh exec opens the same files, seeds native participant
floors and inspects SQL snapshot/C receipt/pending shadow plus committed blob
before common recovery. Replay must remove the SQL shadow, expose committed
registry state and retain exactly one SQL row/blob reference **before** any direct
participant replay. In both branches, repeated matching decisions succeed and
opposite decisions fail; SQL epoch stays stable and journal bytes/SHA-384 remain
unchanged. SQL backup and the common checkpoint resume; another exec inspects the
absent shadow before replay.

`test-sql-receipt-recovery-sanitize` instruments the fixture and SQL table-store
translation unit with ASAN/fatal UBSan and leak detection; the rest of the rebuilt
library is not wholly instrumented. `check-sql-receipt-stack` enforces the 16 KiB
per-frame fixture bound. Private principals are bootstrapped/authenticated afresh
per exec, not recovered production identities. This closes one local coverage
gap without a production SQL change; it is not power-loss/storage-controller or
full W11 acceptance proof. The normal target is registered for future serial CI;
registration is not evidence that an aggregate was run.

Scale, broader node/partition/storage faults, prices/promotions, payment and
event-delivery workflows remain
outside this bounded regression, and all full acceptance gates remain open.
