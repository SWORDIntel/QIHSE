# CT1 and CT2 verification

[ROADMAP.md](../../ROADMAP.md) owns delivery status. The implementation and
configuration contract is in [Durable cluster transport](../plans/ct_transport_runtime.md).

Implementation entry points are the [KV storage and proof layer](../../src/black_hole/qihse_kv_store.c),
[RESP/QKP runtime](../../src/spinnaker/qihse_resp_engine.c),
[ownership journal and recovery](../../src/spinnaker/qihse_cluster_ownership.c),
[transfer manager](../../src/spinnaker/qihse_cluster_transfer.c),
[target staging](../../src/spinnaker/qihse_ct_target.c), and
[daemon configuration](../../tools/qihse_cluster_daemon.c).

## Real-process evidence

The CT1 daemon suite passes five pinned-QKP scenarios: acknowledged replication
and restart, wrong-generation/forged-peer denial, lost-ACK recovery, a second
32 KiB write after acknowledged-log GC, and lead failure followed by successor
promotion, a fresh successor baseline and stale-lead rejection. The native
protocol test also checks classified-data denial without payload disclosure.

The CT2 drill uses A→B and C→D as distinct CT1 primary/successor pairs, then
transfers from A to C. It verifies:

- A referenced classified row cannot be transferred through a low-clearance
  target identity; the source stays fenced and target status discloses no data.
- Durable partial staging survives target termination and restart; the same
  transfer ID resumes through the authenticated control path.
- Concurrent writes are refused while the range is fenced. Imported source
  rows survive, target-only rows inside the range are removed, and existing
  target data outside the range remains readable.
- Activation admits ordinary target reads before completion is returned.
- B and D independently adopt the verified new owner. Historical ACTIVATED
  receipts survive subsequent writes and another transfer.
- Completed same-ID retries have no transfer side effects. Both primaries can
  restart before a reverse transfer; 28- and 60-character IDs exercise the
  variable-length protocol contract.

These are real daemon and authenticated client operations. Storage tests also
exercise direct-writer fencing, classification/SCI/tenant denial, atomic
row-and-cursor recovery, expiry-preserving retry, transfer back and fault
injection. Source-status tests verify disarmed → reconciled → disarmed-on-reopen
admission independently of equal durable/acknowledged cursors.

## Reproduce

From the repository root:

```sh
make -j4 cluster-daemon
make test-ct-codec test-ct-codec-auth test-ct-storage test-ct-storage-crash \
     test-ct-transfer-storage test-cluster-transfer test-ct-target \
     test-ct-transport-protocol test-ct-transport-daemon test-ct-slot-transfer
make test TEST_JOBS=32
```

The focused gates pass. AddressSanitizer/UndefinedBehaviorSanitizer checks passed
for the storage/range-transfer paths and the target/manager test executables;
LeakSanitizer was disabled. Sanitizer coverage is limited to those focused
paths and executables; the complete repository suite uses the normal build.

The required complete `make test TEST_JOBS=32` run completed **198 targets with zero
failures**. Gold's **74 workloads in 11 areas** pass, including the real CT1/CT2
drills, with no declared transport coverage gaps. The serial scheduler regression
gate also confirms that both transport workloads run rather than being omitted.

## Bounds and operating mode

Transport is opt-in and uses provisioned identities, public-key pins and explicit
topology/QKP mappings. Manual CT1 promotion requires an authenticated system
Operator; automatic takeover still requires a genuine authority decision.
Legacy cleartext replication and unfenced ownership-changing paths remain
disabled. CT2 images are bounded to 4096 rows and 64 MiB; an oversized transfer
fails rather than truncating data. The source and isolated runtime fixtures are verified here. Live LAN rollout
conditions are tracked separately in [Current Issues](../AIMEM_CURRENT_ISSUES.md).
