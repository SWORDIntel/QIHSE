# KP14 analysis artifact contract (v1, fail-closed preflight stage)

QIHSE owns the authoritative bytes, manifests and access decisions. KEYSTONE
may index a security-filtered projection of committed QIHSE manifests; its
index is rebuildable and must never become a second authority. Producers
(Angryier, radare3, METHRA, and future VEXEL) submit artifacts to QIHSE, not
directly to KEYSTONE.

`include/qihse_analysis_artifact.h` defines a bounded v1 manifest for binary,
disassembly, CFG, trace, solver, verdict and report artifacts. It records an
immutable SHA-384 artifact ID (canonical metadata hash), a SHA-384 payload
digest and byte length, tenant/classification/SCI binding, artifact schema,
producer and version, run ID/generation, source binary SHA-384, ISA/mode/address
width, optional ISANITY catalogue and VEXEL pack SHA-384 pins, up to eight
input artifact IDs, completion and fidelity. The payload
is a **reference**, not inline content. A manifest is no more than a few KiB;
the current blob tier limits one referenced payload to 64 MiB. Multi-part
artifacts will need a separate, explicit bundle contract.

`qihse_analysis_artifact_compute_id` hashes a domain-separated field stream
in declared order using big-endian integers, fixed zero-padded text fields,
the binary/catalogue/pack/payload digests, run/generation, input count and only the
occupied input slots. It does not hash C struct padding. `validate` rejects
malformed or tampered identities, duplicate/unused input slots, unbounded
strings, missing required inputs, invalid enum states and impossible
validated-but-partial status. These functions only validate a proposed
manifest already supplied by the caller; they perform no store lookup and do
**not** verify that a payload or its lineage exists. In particular, a
successful format validation is not authorization to retrieve or disclose
that manifest.

Cross-language v1 identity vector (`tests/test_analysis_artifact.c`): domain
bytes are ASCII `QIHSE/KP14/analysis-artifact/v1` **including one trailing
NUL**. Append, in order, big-endian `u16` version=1, kind=2,
completion=2, fidelity=1; big-endian `u32` tenant=77; big-endian `u16`
classification=2, SCI=1; 64-byte NUL-padded schema=`kp14.disassembly.v1`,
producer=`radare3`, producer_version=`0.1.0`; run ID=`77` repeated 16 bytes;
big-endian `u64` generation=1; binary digest=`d7` repeated 48 bytes;
32-byte NUL-padded ISA=`x86`, mode=`long64`; big-endian `u16`
address_bits=64; ISANITY catalogue digest=`e8` repeated 48 bytes; VEXEL pack
digest=48 zero bytes; big-endian `u64` payload_size=3; payload digest=`a5`
repeated 48 bytes; `u8` input_count=1; input artifact ID=`b6` repeated 48
bytes. The field stream is 579 bytes. Expected SHA-384 artifact ID:
`23e479429e43c1a8edb1137efc3366fa92243219aaa95f8f113cfd89fdaa63fd6ba5e7fdc7e1a9a2b7d2b0a8f13287f9`.

Derived artifacts require at least one input artifact ID and an explicit
nonzero address width; binary artifacts have no inputs and their binary digest
must equal the payload digest. Thus identical output bytes from different
inputs, run IDs, generations, profiles or catalogue/pack pins produce distinct
artifact IDs. A zero catalogue or pack digest explicitly means that authority
was not used, not that the version is unknown. The eventual ingest path must
verify that declaration against provenance and reject unsupported combinations.

The SHA-384 artifact ID and payload digest belong to QIHSE's manifest/blob
namespace. METHRA's existing BLAKE3 object and blob hashes are distinct
namespaces: equal-looking hex strings are not interchangeable identifiers.
A producer adapter must explicitly compute and verify the QIHSE SHA-384 digest
over the submitted bytes and record any METHRA BLAKE3 ID as separately typed
provenance. No implicit payload lookup by BLAKE3 is allowed.

`authorize_user` is the mandatory read/export visibility gate. It does not
authorize publishing, creating, or modifying artifacts; candidate-write
preflight uses a distinct role/scope-based authorization check. It
requires a live `qihse_user_t`, matching tenant (or a system-domain Operator),
sufficient classification clearance and SCI compartments. A system-domain
Analyst is not a cross-tenant bypass. NULL and
revoked identities fail closed. `make test-kp14-artifact-contract` exercises
low-clearance, missing-SCI, cross-tenant, NULL, revoked and tampered-manifest
denials using the real QIHSE authentication subsystem and removes its own
auth/audit fixture directory. The target is part of `make test` and its
build-and-test CI path; it is not yet a Gold workload.

`qihse_analysis_artifact_authorize_publisher` now provides that **separate
candidate-write gate**: an active tenant Analyst needs clearance, SCI and an
Operator-granted `QIHSE_ACL_WRITE` on namespace `KP14`, resource=tenant ID.
An Operator may publish across tenants; Guests and system-domain Analysts
cannot. A read-capable Analyst without that scope is denied. The API does not
grant write authority to a storage implementation automatically.

`qihse_analysis_artifact_preflight_user` streams a caller-supplied candidate
payload through a fixed 256 KiB buffer, bounded by the manifest's 64 MiB
ceiling. It first checks canonical identity and publisher scope; then it
checks exact byte length and SHA-384, and rechecks publisher authority after
the stream. A complete binary candidate returns `BINARY_VERIFIED`. Any
derived candidate returns `LINEAGE_UNRESOLVED` even when its input IDs are
well-formed: those IDs have not been authenticated against an immutable
manifest store. Digest/length mismatches and reader errors fail closed.
The preflight API writes **nothing**, retains no payload, assigns no durable
ID, and sends no KEYSTONE event. Repeating it has the same result but is not
a durable idempotency guarantee. Its denial tests ensure unauthorized calls
never invoke the payload reader; this stage exposes no artifact read or
metadata export path. `make test-kp14-artifact-contract` is wired into
`make test` for the canonical, auth and candidate-preflight cases.

## Not yet an ingest API

No manifest has been durably ingested, exported or indexed by this stage.
Do **not** publish this struct directly through `KEYSTONE.FEED.PUBLISH`, a
context-free METHRA KV path, or the best-effort fabric dispatcher. The secure
ingest gate must first:

1. Reserve a dedicated analysis-artifact blob tag without colliding with the
   existing replica-transaction tag; use authenticated streaming and compare
   complete SHA-384 digest, byte length and exact tenant/classification/SCI
   binding before commit.
2. Resolve every input ID through an authenticated, immutable manifest store;
   verify its tenant/security binding and reject cycles or dangling lineage.
3. Atomically persist the manifest and its referenced payload pin, with
   idempotent retry and crash recovery. Never advertise an uncommitted item.
4. Emit a bounded, versioned KEYSTONE feed projection only after commit.
   Map tenant/classification/SCI and object ID into the existing feed envelope;
   KEYSTONE's identity and consumer search must enforce those labels.
5. Expose authenticated read, direct-ID, enumeration, range export and backup
   APIs. Add low-clearance/high-data and missing-SCI negative tests through
   every new wire/SDK surface, including tests proving protected bytes never
   cross the wire.

The present in-memory C struct is **not** a wire format or serialization
contract. Wire encoding, durable persistence, provenance verification and
search-index delivery remain open gates.

Current blocker: `qihse_blob_put_expected_user` durably writes only a blob;
there is no artifact-specific tag/binding or atomic manifest+payload commit.
The blob refcount API is not a protected lineage pin: an authorized tenant
principal can call `qihse_blob_delete_user` enough times to remove a blob
referenced by a hypothetical manifest. A separate manifest log layered on
top of these calls would be able to crash or race between operations and
would falsely advertise durability. Resolve protected pin ownership,
authenticated lineage lookup, transaction/recovery ordering and explicit
feed-after-commit outbox semantics before adding a durable put/get or feed
ACK. No preflight result may be treated as a commit receipt.
