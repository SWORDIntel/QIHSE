# Durable cluster transport

[ROADMAP.md](../../ROADMAP.md) owns delivery status. This document describes
the CT1 write-stream and CT2 ownership-transfer contracts; the presence of
an API or this document does not establish that the end-to-end drills pass.

## Write stream

CT mode is explicit. A primary binds one generation to an exact provisioned
QKP successor identity. Transport pins and topology node IDs are separate
namespaces and require an explicit trusted mapping. The legacy cleartext
`redundancy_peer` configuration remains rejected.

Daemon configuration uses `--ct-role primary|successor`, `--ct-peer HOST:PORT`,
`--ct-generation HEX32`, `--ct-log-limit BYTES` and `--ct-ack-timeout-ms N`.
It also requires an explicit replication principal, exact
`--replication-allowed-peer NODE_ID PUB_FILE` pins, QKP local identity and
`--topology-qkp-map TOPOLOGY_ID QKP_NODE_ID` mappings. Startup requires an
authenticated Operator; `qihse-cluster-daemon --help` lists the complete flags.

The KV mutation lock captures each committed mutation, including deletes,
expiry changes, expiry sweeps, batches, and delete-plus-receipt operations.
An atomic operation produces one QKV6 group, with tenant, classification,
SCI, absolute expiry, and actor provenance. A dense stream position orders
groups independently of the store's potentially noncontiguous change sequence.
Replication must not split an atomic group into independently applied rows.

The receiver validates every record before publication. Its mutation group
and cursor share one fsynced WAL frame. Identical retries are idempotent;
conflicting retries, position gaps, retired generations, and unauthorized
records are rejected. The source retains unacknowledged history and applies
backpressure at its configured log limit.

A successful write response requires the pinned successor's durable ACK.
The RESP dispatcher buffers the response, releases the outer KV lock, waits
for the durable stream position, then sends success. A timeout is an unresolved
outcome: the operation may be durable locally and must not be reported as
definitely absent. Ordinary source reads cannot disclose unacknowledged state.

A reopened primary starts disarmed. Before serving it must reconcile the
exact pinned successor, generation, baseline digest, and durable cursor.
Nonempty stores require an authenticated baseline; cursor zero alone is
insufficient evidence of equivalent data. Promotion retires the old receiver
generation durably. Automatic promotion additionally requires a genuine
authority decision; peer health counts alone are insufficient.

## Slot transfer

CT2 uses a durable source range fence, an authenticated bounded transfer image,
a target canonical seal, and a local ownership journal. Ordinary writer scopes
do not bypass a frozen or permanently moved range, including direct KV callers.

The opaque image receiver requires its provisioned system replication data
principal to cover the full classification and SCI range before accepting
image bytes. A lower-clearance service is refused without stage metadata or
payload disclosure. This is separate from the Operator control identity;
storage proofs and imports still receive the authenticated data principal.

The source records PREPARED before exporting or transmitting a range. The
target stages bounded chunks with a durable resume offset and verifies the
complete image before applying it. Import must preserve unrelated target keys
and the target's existing CT1 generation and successor. Its imported changes
enter its own durable write stream; a target seal cannot precede its required
successor ACK.

The source validates an opaque receipt obtained from the exact pinned target.
It binds both identity namespaces, transfer ID, generation, slots, source cut,
target durable cursor, and canonical range checksum. Caller-provided booleans,
unsigned checksums, and ordinary slot gossip are insufficient ownership proof.
Only then may the source journal COMMITTED and permanently fence its old
range. The target subsequently accepts an authenticated activation request,
persists its ownership transition, and releases its receive fence. The source
verifies the activated receipt before recording FINALIZED and publishing its
owner map. A sealed image alone does not authorize publication.

The activation acknowledgement also requires local recovery to have no
unresolved transition, the target's CT1 source to be admitted, and its pinned
successor to cover the imported cursor. It refreshes ordinary data admission before acknowledging;
a restarted target must not retain its startup control-only gate after the
source publishes the new owner.

Recovery must finish the same transition after a crash, without reopening
writes on the old source. An unresolved COMMITTED transfer still needs target
activation. FINALIZED records replay locally: a later legitimate target write
or another transfer must not make an already completed historical transition
depend on a mutable current seal. An uncertain network outcome keeps the
source fenced until explicit reconciliation or a proven abort.

An exact retry of a locally FINALIZED transfer returns completion from its
durable tuple without transmitting data or repeating activation. Reusing that
ID with another range or identity is rejected. Historical ACTIVATED receipts
use the durable finalized digest and cursor; full-scope, pinned observers must
also have a unique explicit topology/QKP mapping to verify those receipts.

The bounded range-image contract is at most 4096 live rows and 64 MiB; target
merge tombstones also count against the atomic-group bound. An over-limit range
must be refused before mutation, never truncated. Callers may divide a range
into smaller slot ranges; an individual oversized slot remains an explicit
unsupported transfer rather than losing records.

Peer ownership convergence requires independently resolving the authenticated
target receipt and persisting the transition locally. A bus notification is
a hint to perform this verification, never authority to adopt a new owner.

The bus periodically reannounces retained proof-bearing CT ownership events
because UDP delivery is not acknowledged. CT2 resend preserves each original
receipt-bound range while receivers apply only slots whose local epochs are
older. A single CT1 promotion frame carries its full authenticated slot bitmap,
even when that bitmap is disjoint; the receiver applies the full bitmap after
validating a maximal run. This repairs a missed announcement while a peer still
has a compatible predecessor view. It does not provide a proof chain for a peer
that missed A-to-B and later receives only B-to-C: such a peer must not replace
an unrelated current owner without authenticated evidence for the skipped
transition. Multi-hop missed-promotion recovery remains open.

## Operator commands

An authenticated system Operator on the successor may run:

```text
CLUSTER CT1 PROMOTE <failed-topology-node-id> <new-successor-topology-node-id>
```

The new successor must be trusted, healthy and slotless. Durable promotion
leaves the new primary control-only until that successor installs and confirms
the fresh generation baseline. The returned failure or `TRYAGAIN` must be
resolved against durable state rather than assumed to roll back promotion.

For an explicitly configured CT2 source and target:

```text
CLUSTER CT2 TRANSFER <target-topology-id> <first-last> <transfer-id>
```

Reuse the same transfer ID to reconcile a lost reply or interrupted transfer.
A pending result keeps an uncertain range fenced. A transfer ID is bound to its
identities, generation, range, configuration epoch and source cut; it cannot be
reused for a different operation. The old unfenced `MOVESLOTS` path stays
disabled.

## Verification

The focused gates are:

```sh
make test-ct-codec test-ct-codec-auth test-ct-storage test-ct-storage-crash \
     test-ct-transfer-storage test-cluster-transfer test-ct-target \
     test-ct-transport-protocol test-ct-transport-daemon test-ct-slot-transfer
```

They cover bounded framing, real registry authorization, exact grouped history,
durable cursor recovery, fault injection, target staging and actual pinned-QKP
daemon processes. Codec negative tests include low clearance, missing SCI,
wrong tenant, revoked principal, and NULL context with no payload output.

Runtime acceptance additionally requires real pinned-QKP processes: write on
the primary, wait for successor durability, kill the primary, promote, and
read the same data; restart the old primary and refuse stale authority. CT2
must copy to a target containing unrelated data, survive interrupted transfer,
reject concurrent direct writers, preserve labels and expiry, and converge
peer ownership through verified proof. A preseeded duplicate, a read-only
mirror, or a test-only substitute transport does not satisfy these drills.

The complete final repository check is `make test TEST_JOBS=32`. Gold coverage
gaps remain recorded until the corresponding runtime evidence passes.
