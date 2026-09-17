# QIHSE — Federation Database Layer Upgrade Design Brief

> **Status: planned.** The governing brief for the federation work. The stages
> it specifies that are built are recorded in
> [architecture/federation_overview.md](../architecture/federation_overview.md);
> the rest of this document describes intent, not the tree.

**Document type:** AI implementation brief  
**Target repository:** `SWORDIntel/QIHSE`  
**Role in system:** Distributed state, persistence, telemetry, event, and metadata substrate  
**Explicit non-role:** Hypervisor controller, scheduler, fencing decision-maker, or UI  
**Baseline inspected:** `main`, including recent cluster/failover/performance work through commit `1e889eab5e7f1c34314ecd7f0b8b8c7ec47f93a5`  
**Date:** 2026-09-15

---

## 0. Executive Directive

Upgrade QIHSE into a **partition-aware, security-first federation data plane** suitable for backing a multi-host hypervisor control system without making host operation dependent on global cluster quorum.

The governing architectural principle is:

> **Federation must enhance a node, never become a prerequisite for that node to remain locally operable.**

QIHSE remains the system of record for control-plane metadata, event history, telemetry, inventory, desired state, replicated configuration, audit records, and searchable operational history. A separate hypervisor controller consumes this state and performs privileged actions.

QIHSE must provide the primitives required for safe orchestration, but it must **not itself decide when to start, stop, migrate, fence, or promote a VM**.

---

# 1. Current Baseline

QIHSE already provides or is actively developing the majority of the required substrate:

- native C multi-model database runtime;
- KV, relational, document, graph, time-series, columnar, vector, full-text, and event-stream capabilities;
- WAL, MVCC, transactions, backup/restore, replication, CDC, metrics and tracing;
- authentication, authorization, object ACLs, tenant isolation and audited security boundaries;
- cluster sharding using 16,384 hash slots;
- cluster topology and per-node identity;
- UDP gossip with `MEET`, `PING`, `PONG`, `FAIL`, `SLOT_UPDATE`, and `NODE_UPDATE`;
- primary/replica roles and failover machinery;
- NUMA/hardware-aware execution;
- cross-node scatter/gather queries;
- task queue and scheduler primitives;
- QIHSE/KEYSTONE native integration.

The existing cluster implementation is useful, but its current failover semantics are **database-centric** and must not be reused unchanged as a hypervisor ownership mechanism.

The existing `qihse_cluster_failover` code can promote replicas and move slot ownership based on local cluster health/topology. That is acceptable for database shard management but is insufficient proof that a VM, disk, floating IP, or other exclusive infrastructure resource is safe to activate elsewhere.

---

# 2. System Boundary

The intended stack is:

```text
                 Management UI / CLI / API
                           |
                           v
               Hypervisor Control Program
             policy / scheduler / HA / fencing
                           |
              +------------+-------------+
              |                          |
              v                          v
         Host Agent(s)                QIHSE
       local hypervisor         state / events / DB
              |                          |
              v                          v
            Xen/KVM                  KEYSTONE
                                  indexing/intelligence
```

QIHSE owns **state**, including build coordination state and software-supply-chain provenance.

The hypervisor controller owns **execution authority**.

KEYSTONE owns **retrieval acceleration and optional intelligence**.

---

# 3. Hard Architectural Invariants

These are non-negotiable.

## 3.1 Local survivability

Loss of federation quorum, peer connectivity, or all remote QIHSE replicas must **not** prevent a surviving node from:

- reading its durable local state;
- appending local operational events;
- updating state in namespaces for which it has explicit local authority;
- serving local telemetry/history;
- recovering from its own WAL;
- continuing as an independently valid QIHSE database instance.

Global unavailability may block globally exclusive operations, but must not make the database globally read-only.

## 3.2 No global quorum gate on ordinary local writes

Do not reproduce a model equivalent to:

```text
cluster quorum lost
    -> entire distributed config database becomes read-only
```

Instead, write authorization is determined by **consistency class + namespace authority**, not global cluster status.

## 3.3 Execution decisions remain outside QIHSE

QIHSE may store:

- requested state;
- observed state;
- leases;
- epochs;
- fencing tokens;
- ownership claims;
- node health;
- attestation state.

QIHSE must not autonomously execute:

- VM start/stop;
- VM migration;
- host fencing;
- storage promotion;
- network ownership changes;
- hypervisor commands.

## 3.4 Fail closed for exclusive state

If QIHSE cannot determine that a globally exclusive state transition is valid, the relevant **transition** fails closed.

This must not prevent unrelated local-safe operations.

## 3.5 Every distributed mutation is attributable

Every federation mutation must include:

- authenticated principal;
- originating node UUID;
- request UUID;
- namespace/object ID;
- HLC timestamp;
- previous generation/version;
- new generation/version;
- policy/consistency class;
- cryptographic audit chain entry.

## 3.6 Never infer safety from absence

A missing heartbeat is not proof that another host is powered off.

A stale replica is not proof that the previous owner relinquished a resource.

QIHSE records evidence. The hypervisor controller performs fencing and decides whether activation is safe.


## 3.7 QIHSE is not a remote build executor

QIHSE may store build jobs, leases, worker capabilities, artifacts, test results, and provenance.

It must not expose a generic arbitrary-command execution primitive to build workers.

Citadel owns dispatch and execution policy.

## 3.8 Signing authority is external

QIHSE stores signing identities, signatures, and verification state but never requires repository/private signing keys to exist in the database process.

Build workers and QIHSE must be unable to promote an artifact solely by writing database state.

---

# 4. New Core Concept: Consistency Classes

Add explicit consistency semantics to QIHSE objects/namespaces.

Suggested enum:

```c
typedef enum {
    QIHSE_CONSISTENCY_LOCAL = 0,
    QIHSE_CONSISTENCY_EVENTUAL,
    QIHSE_CONSISTENCY_CAUSAL,
    QIHSE_CONSISTENCY_QUORUM,
    QIHSE_CONSISTENCY_LINEARIZABLE
} qihse_consistency_class_t;
```

## 4.1 `LOCAL`

Authoritative on one node.

Examples:

- live local CPU temperature;
- local VM runtime observation;
- local device discovery;
- host-local logs;
- pending local command journal.

Must remain writable during complete network isolation.

## 4.2 `EVENTUAL`

Multi-writer and convergent.

Examples:

- non-critical telemetry;
- historical annotations;
- inventory enrichment;
- cached search metadata;
- aggregated performance statistics.

Use deterministic conflict resolution and/or CRDT-compatible structures.

## 4.3 `CAUSAL`

Preserve causality but allow disconnected operation.

Examples:

- state transitions where event order matters but simultaneous disconnected updates can later be reconciled;
- operator annotations;
- desired-state edits not involving exclusive ownership.

Use HLC + causal metadata/version vectors.

## 4.4 `QUORUM`

Require configured replica acknowledgement.

Examples:

- durable cluster configuration;
- security-policy changes;
- node enrollment;
- trust-store changes.

Quorum scope must be **per replication group**, not necessarily whole federation.

## 4.5 `LINEARIZABLE`

Strict serialization for small, high-value namespaces only.

Examples:

- execution ownership epochs;
- exclusive resource lease records;
- cluster CA generation;
- revocation epochs;
- one-time migration handoff state.

Do not route bulk telemetry or ordinary VM metadata through this path.

---

# 5. Sovereign Node Architecture

Every QIHSE node has two simultaneous identities:

```text
LOCAL DATABASE
    authoritative for permitted local namespaces

FEDERATION MEMBER
    exchanges replicated/global state with peers
```

Required operating modes:

```text
CONNECTED
DEGRADED
ISOLATED
RECOVERING
FENCED
MAINTENANCE
```

Cluster state must be visible to clients, but must not be conflated with database usability.

Suggested status object:

```json
{
  "node_id": "uuid",
  "federation_state": "isolated",
  "local_database": "read-write",
  "strong_namespaces": "unavailable",
  "eventual_namespaces": "read-write",
  "pending_replication_events": 281,
  "last_peer_contact_hlc": "...",
  "reconciliation_required": true
}
```

---

# 6. Federation Metadata Model

Add first-class infrastructure entities.

## 6.1 Node

```text
federation/node/<uuid>
```

Fields:

- immutable node UUID;
- hostname/display name;
- hardware identity;
- platform;
- boot ID;
- trust state;
- enrollment epoch;
- certificate fingerprint;
- public keys;
- capabilities;
- current health;
- last HLC;
- software/build revision;
- local authority namespaces;
- runtime trust state;
- evidence bundle reference;
- root-image/package provenance references;
- hardening-audit generation.

## 6.2 Resource

```text
federation/resource/<type>/<uuid>
```

Types may include:

```text
vm
volume
network
ip
device
host
service-domain
template
snapshot
```

QIHSE stores metadata, not execution handles.

## 6.3 Ownership Record

```text
federation/ownership/<type>/<uuid>
```

Minimum fields:

```json
{
  "resource_id": "...",
  "owner_node": "...",
  "generation": 1831,
  "fencing_epoch": 92,
  "lease_id": "...",
  "lease_state": "granted",
  "issued_hlc": "...",
  "expires_hlc": "...",
  "controller_request_id": "...",
  "evidence": []
}
```

Important:

**QIHSE persists the ownership state. The controller decides whether it is safe to grant or consume it.**

## 6.4 Desired / Observed Split

Never overwrite observed runtime state with desired state.

Use separate records:

```text
workload/<id>/desired
workload/<id>/observed/<node>
```

Example:

```json
desired:
{
  "power": "running",
  "memory_mb": 16384,
  "placement_policy": "malware-domain",
  "generation": 121
}

observed:
{
  "node": "r730xd",
  "power": "running",
  "domain_id": 42,
  "observed_generation": 121,
  "boot_id": "...",
  "hlc": "..."
}
```

---

# 7. Versioning and Time

## 7.1 Hybrid Logical Clock

Implement an HLC and attach it to all federation mutations.

Required properties:

- monotonic on each node;
- mergeable on receive;
- tolerant of wall-clock skew;
- sortable;
- persisted across restart sufficiently to prevent backwards federation ordering.

Suggested logical representation:

```text
physical_ms : 48-64 bits
logical     : 16-32 bits
node_hash   : optional tie-breaker
```

## 7.2 Object Generation

Each mutable object has a 64-bit generation.

Updates should support CAS:

```text
UPDATE object
IF generation == N
SET generation = N + 1
```

Required native primitive:

```c
qihse_result_t qihse_compare_exchange_object(...);
```

Do not emulate critical CAS with read-then-write in client code.

## 7.3 Fencing Epoch

Fencing epochs must be monotonic and non-reusable.

They are separate from ordinary object generations.

A stale process holding epoch `81` must never be able to commit an exclusive-resource action once epoch `82` is authoritative.

---

# 8. Distributed Write Model

Introduce a mutation envelope:

```c
typedef struct {
    qihse_uuid_t request_id;
    qihse_uuid_t origin_node;
    qihse_uuid_t principal_id;
    qihse_hlc_t hlc;
    uint64_t expected_generation;
    uint64_t fencing_epoch;
    qihse_consistency_class_t consistency;
    uint32_t flags;
} qihse_federation_mutation_t;
```

Every cross-node write path must carry this structure or its wire equivalent.

Benefits:

- idempotency;
- replay protection;
- CAS;
- auditability;
- conflict detection;
- federation provenance.

---

# 9. Idempotency

Hypervisor orchestration generates retries.

QIHSE must make duplicate requests harmless.

Maintain a bounded request ledger:

```text
request_id -> result digest / generation / completion state
```

Requirements:

- configurable TTL;
- persistent for security-critical namespaces;
- deduplicate replayed mutation RPCs;
- exact response replay where practical;
- request ID collision detection.

---

# 10. Anti-Entropy and Reconciliation

Gossip is useful for liveness but is not sufficient as the only replication correctness mechanism.

Add explicit anti-entropy.

Recommended model:

```text
periodic peer reconciliation
    -> compare namespace/root summaries
    -> identify divergent ranges
    -> exchange generation/HLC digests
    -> transfer missing events/objects
    -> verify checksums
```

Possible structures:

- Merkle trees per namespace/shard;
- range hashes over sorted object IDs;
- WAL/event-segment hashes;
- manifest generation hashes.

Requirements:

- resumable;
- rate limited;
- checksum verified;
- crash safe;
- observable;
- capable of repairing a node offline for days;
- does not require full dataset retransmission.

---

# 11. Conflict Handling

Never silently overwrite irreconcilable control-plane conflicts.

Each namespace defines one policy:

```text
LWW_HLC
MERGE_SET
COUNTER
APPEND_ONLY
MANUAL
REJECT_CONFLICT
CUSTOM
```

For infrastructure state, default toward `REJECT_CONFLICT` rather than LWW.

Create:

```text
federation/conflicts/<uuid>
```

with:

- both versions;
- causal metadata;
- origin nodes;
- security principal;
- reason;
- resolution status;
- resolution event.

---

# 12. Event-Sourced Federation Journal

Add a canonical append-only control-plane event journal.

Event envelope:

```json
{
  "event_id": "...",
  "event_type": "workload.observed.running",
  "resource_id": "...",
  "node_id": "...",
  "principal_id": "...",
  "hlc": "...",
  "generation": 331,
  "fencing_epoch": 92,
  "payload": {},
  "previous_hash": "...",
  "hash": "..."
}
```

Use cases:

- audit;
- recovery;
- KEYSTONE indexing;
- UI real-time feed;
- incident reconstruction;
- state-machine replay;
- anomaly detection.

The event log should not replace compact materialized state. Maintain both:

```text
event journal -> authoritative transition history
materialized records -> fast current state
```

---

# 13. Subscription / Watch API

The controller must not poll the database continuously.

Implement watch streams:

```text
WATCH namespace/prefix FROM <cursor>
```

Requirements:

- resumable cursor;
- at-least-once delivery;
- event IDs for dedupe;
- bounded backlog;
- disconnect/reconnect;
- backpressure;
- ACL enforcement;
- prefix filtering;
- optional snapshot-then-watch.

Suggested interfaces:

```c
qihse_watch_open(...)
qihse_watch_next(...)
qihse_watch_ack(...)
qihse_watch_resume(...)
```

Expose equivalent Rust/Python SDKs.

---

# 14. Lease and Epoch Primitive

QIHSE should provide a generic, auditable atomic primitive.

It must **not** implement hypervisor HA policy.

Suggested operations:

```text
LEASE.CREATE
LEASE.RENEW
LEASE.RELEASE
LEASE.READ
LEASE.CAS
EPOCH.NEXT
```

Lease fields:

- owner;
- lease UUID;
- namespace/resource;
- expiry;
- epoch;
- request UUID;
- issuer;
- generation.

Requirements:

- strongly consistent namespace;
- monotonic epoch;
- stale renewals rejected;
- idempotent release;
- explicit clock-skew model;
- server-side expiry;
- audit event for all changes.

Controller policy decides when a lease may be acquired.

---

# 15. Quorum Must Be Scoped

Do not implement a single monolithic federation quorum.

Use **replication groups**.

Example:

```text
group/core-security
group/control-metadata
group/telemetry
group/site-a
group/site-b
```

An outage in one group must not stop unrelated groups.

Metadata:

```json
{
  "group_id": "...",
  "members": [],
  "voters": [],
  "witnesses": [],
  "consistency": "quorum",
  "term": 22
}
```

---

# 16. Consensus Scope

Consensus should be introduced only where semantics require it.

Use a well-defined consensus algorithm/library for strong namespaces rather than claiming "Raft" without full Raft safety mechanics.

Minimum requirements before labeling a component Raft:

- persistent term;
- voted-for persistence;
- log index/term;
- leader election;
- majority commitment;
- log matching;
- current-term commit rules;
- membership change semantics;
- snapshot/install-snapshot;
- crash/restart tests;
- network partition tests.

If the implementation is deliberately smaller, name it accurately.

---

# 17. Gossip Upgrade

Existing gossip should evolve into a signed membership/health plane.

Add:

- protocol version;
- sender node UUID, not only topology index;
- boot/session UUID;
- monotonic message sequence;
- HLC;
- replay window;
- authentication tag/signature;
- cluster/federation UUID;
- capability bitmap;
- health summary;
- protocol feature negotiation.

Never trust a UDP datagram merely because its source IP matches a configured peer.

---

# 18. Node Identity and Trust

Each node gets durable identity keys.

Enrollment flow:

```text
generate node key
    -> operator approves enrollment
    -> federation CA signs node identity
    -> node obtains scoped certificate
    -> QIHSE stores enrollment event
```

Use mTLS for all administrative/federation RPC.

Node identity must not equal:

```text
IP address
hostname
topology array index
```

Those are mutable attributes.

A valid node identity proves identity, not current trustworthiness.

Federation admission policy should additionally evaluate current runtime evidence such as:

```text
approved Citadel image
approved QIHSE artifact
valid SBOM/provenance
attestation state
hardening-audit state
revocation state
```

before granting voter or strong-write authority.


---

# 19. Authorization

Extend current QIHSE ACL model with infrastructure scopes.

Suggested permissions:

```text
FEDERATION_READ
FEDERATION_WRITE
NODE_ENROLL
NODE_REVOKE
POLICY_READ
POLICY_WRITE
LEASE_READ
LEASE_WRITE
SECURITY_ADMIN
AUDIT_READ
TELEMETRY_WRITE
```

Separate service identities:

```text
hypervisor-controller
host-agent
ui-api
keystone-indexer
backup-agent
operator
```

KEYSTONE must receive a read/index identity, not database-admin privileges.

---

# 20. Security Classification

Preserve existing QIHSE classification/SCI design for infrastructure objects.

Useful classes:

```text
PUBLIC
OPERATIONS
SECURITY
SECRET
HOST_LOCAL
MALWARE_LAB
CREDENTIAL
KEY_MATERIAL
```

Never place private keys directly in ordinary QIHSE records.

Store key references/handles where possible.

---

# 21. Data-at-Rest Model

Support encrypted datasets/namespaces with externally managed key material.

Requirements:

- envelope encryption;
- key IDs in metadata;
- rotation;
- read-old/write-new rotation phase;
- recovery procedure;
- encrypted backups;
- no secret keys written into ordinary WAL/audit logs.

---

# 22. Replication Transport

Separate logical replication protocol from transport.

Preferred abstraction:

```c
struct qihse_replication_transport_ops {
    connect();
    send();
    recv();
    close();
    peer_identity();
};
```

Initial transport may use:

- TLS/TCP;
- QUIC if later justified;
- local Unix socket for same-host components.

AF_XDP is a performance optimization, never a correctness dependency.

---

# 23. Snapshot and Backup Semantics

Add federation-consistent metadata snapshots.

Need two snapshot types:

## Local snapshot

Crash-consistent local database snapshot without federation coordination.

## Coordinated metadata snapshot

Captures selected replication groups at known committed indices/generations.

Backups must include:

- manifest;
- schema version;
- cluster/federation UUID;
- namespace generations;
- cryptographic checksums;
- encryption metadata;
- WAL continuation point.

---

# 24. Schema Evolution

Infrastructure software must support rolling upgrades.

Every wire object and persisted object needs:

```text
schema_id
schema_version
minimum_reader_version
feature_bits
```

Rules:

- unknown optional fields ignored;
- unknown mandatory feature bit rejects safely;
- downgrade behavior explicit;
- migrations resumable;
- no cluster-wide stop-the-world migration for ordinary schema changes.

---

# 25. Controller-Facing API

Create a narrow first-class federation API rather than making the controller pretend to be a Redis/PostgreSQL client.

Suggested high-level operations:

```text
Node.Register
Node.Get
Node.List
Node.PublishObservation

Object.Get
Object.CAS
Object.Watch

Desired.Set
Observed.Publish

Lease.Acquire
Lease.Renew
Lease.Release
Epoch.Next

Event.Append
Event.Subscribe

Conflict.List
Conflict.Resolve

Replication.Status
Federation.Status

Build.JobCreate
Build.JobGet
Build.JobTransition
Build.WorkerPublish
Build.HistoryQuery

Supply.ArtifactGet
Supply.Lineage
Supply.Impact
Supply.SBOMGet
Supply.AttestationGet
Supply.RepositorySnapshotGet
```

Native C API plus Rust SDK are highest priority.

---

# 26. KEYSTONE Feed

Provide a clean change stream for KEYSTONE.

KEYSTONE should index:

- immutable event IDs;
- node/resource metadata;
- telemetry summaries;
- logs where policy permits;
- security/audit events where explicitly permitted;
- package/source/build provenance;
- SBOM component relationships;
- repository snapshots;
- vulnerability observations;
- build-performance history.

Do not allow KEYSTONE to become authoritative.

Each indexed record must include:

```text
qihse_object_id
generation
hlc
classification
tenant/security context
tombstone state
```

This allows KEYSTONE to detect stale indexed documents.

---


# 27. Package Override and Source-Intake Registry

QIHSE should become the authoritative registry describing how Citadel obtains and overrides package sources.

The registry does **not** cause builds by itself. It stores policy and state consumed by Citadel.

Suggested namespace:

```text
supply/package/<name>
```

Example:

```yaml
package: libwebp
mode: overlay

upstream:
  distribution: debian
  suite: unstable
  source_package: libwebp

citadel:
  repository: hardened
  patchset: hardened/libwebp
  rebuild_on_upstream_change: true

policy:
  allowed_profiles:
    - media
  forbidden_profiles:
    - dom0
  hostile_input: true

build:
  reproducibility: required
  independent_builds: 2
```

Required package modes:

```text
UPSTREAM_BINARY
UPSTREAM_SOURCE_REBUILD
CITADEL_OVERLAY
CITADEL_FORK
FORBIDDEN
ISOLATED_EXCEPTION
```

QIHSE must preserve the reason and provenance for every override.

---

# 28. Federated Build Job State

QIHSE should provide durable coordination state for the Citadel Adaptive Federated Build Fabric.

QIHSE is responsible for:

- job state;
- requested build profile;
- source identity;
- builder capability metadata;
- lease state;
- historical performance;
- artifact references;
- verification state;
- audit trail.

QIHSE is **not** responsible for invoking compilers or executing arbitrary commands.

Suggested namespaces:

```text
build/jobs/<uuid>
build/workers/<node-uuid>
build/history/<package>/<build-id>
build/cache/<digest>
build/artifacts/<digest>
build/leases/<uuid>
build/toolchains/<id>
build/profiles/<id>
```

Build state machine:

```text
QUEUED
  |
  v
PLANNING
  |
  v
LEASED
  |
  v
BUILDING
  |
  v
TESTING
  |
  v
VERIFYING
  |
  v
SIGNING
  |
  v
PUBLISHED
```

Failure states:

```text
FAILED
RETRYABLE
QUARANTINED
CANCELLED
```

Every transition must use authenticated mutation envelopes and request IDs.

---

# 29. Builder Capability and Historical Performance Model

QIHSE stores normalized worker capability records so Citadel can select build nodes intelligently.

Example:

```yaml
node: r730xd
cpu_model: ...
cores_total: 32
cores_available: 19
ram_total_gb: 128
ram_available_gb: 74
scratch_available_gb: 340
isa:
  - sse4.2
  - avx
  - avx2
  - fma
load_1m: 3.2
thermal_headroom: 0.78
toolchain_cache:
  gcc: hot
  llvm: hot
source_cache:
  ffmpeg: present
trust_state: attested
build_queue_depth: 1
```

Historical build records should capture:

```text
package
source revision
build profile
toolchain
builder node
allocated cores
peak RAM
cache state
build duration
test duration
artifact size
success/failure
```

This allows Citadel/KEYSTONE to estimate completion time using real historical performance rather than nominal CPU specifications.

---

# 30. Build Lease and Idempotency Semantics

Build jobs should use QIHSE's generic lease and idempotency primitives.

A build lease should include:

```text
build_id
lease_id
owner_node
generation
issued_hlc
expires_hlc
request_id
```

Build jobs are retryable and should be naturally idempotent.

If a builder disappears:

```text
lease expiry
    |
    v
Citadel evaluates retry policy
    |
    v
job may be assigned elsewhere
```

Duplicate job submissions or retried state updates must not create duplicate authoritative artifacts.

Independent verification builds are represented as separate executions under one logical build request.

---

# 31. Supply-Chain Provenance Graph

QIHSE should become the authoritative provenance graph for Citadel software artifacts.

Core entity types:

```text
SOURCE_REPOSITORY
SOURCE_REVISION
SOURCE_ARCHIVE
PATCHSET
BUILD_RECIPE
BUILD_PROFILE
TOOLCHAIN
BUILD_DEPENDENCY
BUILDER_NODE
BUILD_WORKER_IMAGE
BUILD_JOB
TEST_RESULT
OUTPUT_ARTIFACT
DEB_PACKAGE
SBOM
ATTESTATION
APT_REPOSITORY_SNAPSHOT
ROOT_IMAGE
DEPLOYMENT
NODE
VULNERABILITY_OBSERVATION
```

Representative edges:

```text
DERIVED_FROM
PATCHED_BY
BUILT_WITH
BUILD_DEPENDS_ON
BUILT_ON
BUILT_IN
PRODUCES
DESCRIBED_BY
ATTESTED_BY
PUBLISHED_IN
CONTAINED_IN
DEPLOYED_TO
AFFECTED_BY
SUPERSEDES
VERIFIED_AGAINST
```

Example:

```text
Debian source revision
        |
        v
Citadel patchset
        |
        v
build recipe + toolchain
        |
        v
isolated worker image
        |
        v
build job
        |
        v
.deb artifact
        |
        +--> SBOM
        |
        +--> provenance attestation
        |
        v
APT repository snapshot
        |
        v
Citadel root image
        |
        v
node deployment
```

All artifact-bearing nodes must use cryptographic digests as stable identities where appropriate.

---

# 32. SBOM and Attestation Records

SBOM Z should write normalized supply-chain evidence into QIHSE.

QIHSE stores:

- canonical internal component graph;
- generated SPDX/CycloneDX document references;
- provenance attestation references;
- artifact digest bindings;
- signature metadata;
- verification result;
- attestation policy status.

QIHSE does not hold private signing keys.

Suggested namespaces:

```text
supply/sbom/<uuid>
supply/attestation/<uuid>
supply/artifact/<digest>
supply/repository-snapshot/<uuid>
supply/release/<uuid>
```

A signed SBOM/attestation record should include:

```text
artifact digest
SBOM digest
provenance digest
signing identity
signature algorithm
signature
signature timestamp/HLC
policy generation
verification status
```

External formats such as SPDX, CycloneDX, and in-toto/SLSA remain export/interoperability representations.

The QIHSE internal model should not be constrained to the lowest common denominator of any one external SBOM standard.

---

# 33. Immutable Vulnerability Observations

Vulnerability information must be modeled separately from immutable SBOM evidence.

Do not mutate a historical SBOM when scanner knowledge changes.

Use:

```text
VULNERABILITY_OBSERVATION
```

Fields:

```text
observation_id
scanner
scanner_version
vulnerability_db_revision
scan_hlc
artifact/component identity
advisory/CVE identity
matching rationale
severity/source
disposition
```

This permits:

```text
same signed SBOM
+ multiple vulnerability observations over time
```

and preserves forensic integrity.

QIHSE should support querying:

```text
all currently affected deployed nodes
all historical observations for artifact X
all artifacts built before advisory database revision Y
all patched/superseded artifacts
```

---

# 34. Repository Snapshot and Deployment Provenance

APT repository state must be represented as an immutable snapshot object.

Suggested entity:

```text
APT_REPOSITORY_SNAPSHOT
```

Fields:

```text
snapshot_uuid
suite/channel
Release/InRelease digest
package index digests
publication HLC
signing identity
parent snapshot
```

Root images reference the exact repository snapshot(s) from which their package closure was resolved.

Node deployments reference exact root-image and service-domain image generations.

This enables:

```text
node
  -> root image
  -> repository snapshot
  -> package
  -> artifact
  -> build
  -> source
```

and reverse traversal.

Required high-value queries:

```text
Which nodes contain artifact digest X?
Which images include source revision Y?
Which releases include outputs from builder Z?
Which deployed systems depend on vulnerable component C?
Which artifacts were built with toolchain digest T?
Which images were assembled from repository snapshot R?
```

KEYSTONE may accelerate these queries but must not become authoritative.

---



# 35. Evidence-Aware Federation Admission

QIHSE federation trust must not rely only on possession of a valid node certificate.

A node should present a machine-readable **runtime trust evidence bundle** containing, where available:

```text
node identity
boot/session UUID
Citadel release/image identity
root-image digest
QIHSE package/artifact digest
QIHSE SBOM digest
QIHSE provenance-attestation digest
policy generation
kernel/Xen image identities
Secure/Measured Boot state
TPM attestation reference
hardening-audit generation
```

QIHSE stores this evidence but does not fabricate or self-approve it.

Citadel/attestation components determine whether the evidence satisfies current federation policy.

Suggested trust states:

```text
TRUSTED
TRUSTED_DEGRADED
LOCAL_ONLY
QUARANTINED
REVOKED
UNKNOWN
```

Recommended semantics:

```text
TRUSTED
    may participate according to configured replication/consensus roles

TRUSTED_DEGRADED
    reads and selected replication allowed;
    strong-write/voter eligibility policy-dependent

LOCAL_ONLY
    local QIHSE remains usable;
    no authoritative federation voting or strong mutation rights

QUARANTINED
    federation data exchange heavily restricted;
    forensic/repair access only

REVOKED
    federation access denied
```

Critical principle:

> A failed provenance or attestation check must not unnecessarily destroy local availability, but it must be able to remove the node from trusted distributed authority.

Federation membership records should include:

```text
trust_state
trust_policy_generation
evidence_bundle_id
evidence_verified_hlc
verification_principal
verification_result
```

Changes in trust state must emit immutable audit events.

---

# 36. QIHSE Runtime Hardening Profile

QIHSE is a network-facing, state-authoritative component and requires its own explicit Citadel security profile.

The release profile should minimize ambient operating-system capability.

Default posture should include, where compatible with measured performance and required functionality:

```text
dedicated unprivileged service identity
no interactive shell requirement
no setuid requirement
no arbitrary device access
no raw block-device access unless explicitly configured
no arbitrary kernel module loading
no ptrace of unrelated processes
no unrestricted perf access
no unrestricted BPF access
restricted user namespaces
restricted filesystem write paths
restricted Unix/network socket families
restricted address families
bounded memory-lock capability
bounded file-descriptor limits
production core dumps disabled by default
```

Use systemd sandboxing, LSM policy, seccomp, capability dropping, namespace restrictions, and filesystem protections as appropriate.

Do not blindly disable interfaces that QIHSE demonstrably needs.

Instead maintain a **measured allowlist** per build/profile.

Potentially sensitive Linux interfaces to audit explicitly:

```text
AF_PACKET
AF_NETLINK
AF_ALG
raw sockets
io_uring
userfaultfd
perf_event_open
BPF
process_vm_readv/process_vm_writev
ptrace
keyrings
memfd
mount-related syscalls
```

For each interface classify:

```text
REQUIRED
OPTIONAL
FORBIDDEN
UNKNOWN
```

Unknown should fail CI hardening review for production builds.

QIHSE release packages should expose the intended syscall/capability profile as versioned metadata so runtime drift can be detected.

---

# 37. Network Exposure and Egress Policy

QIHSE network behavior should be explicit and minimal.

A production node should expose only configured QIHSE interfaces such as:

```text
federation/replication
client API
metrics/health
local Unix sockets
```

Each listener must have:

```text
defined bind address
defined authentication mode
defined authorization scope
defined protocol version
defined rate/size limits
```

No listener should bind to all interfaces merely for convenience unless the deployment policy explicitly permits it.

Outbound connectivity should also be policy-described.

QIHSE itself should not require unrestricted Internet egress.

Expected outbound classes may include:

```text
configured federation peers
configured backup target
configured telemetry sink
local Citadel services
```

Package/source fetching, CVE-database updates, and build dependency retrieval belong to dedicated update/build domains rather than the QIHSE process.

Represent network policy in QIHSE as data, but enforcement belongs to Citadel/sys-net/host policy.

Suggested metadata:

```text
security/runtime-network-profile/<service>/<version>
```

This allows the system to detect when the actual listening/egress surface diverges from the declared profile.

---

# 38. Time Integrity and Trusted Ordering

QIHSE already relies on HLC for distributed ordering; retain HLC as the correctness mechanism.

Wall-clock synchronization should nevertheless be hardened because timestamps affect:

```text
audit interpretation
certificate validity
build provenance
repository publication
operator incident analysis
lease expiry diagnostics
```

Citadel hosts should prefer authenticated time synchronization such as NTS where operationally available.

QIHSE must never assume wall-clock accuracy for consensus safety.

Rules:

```text
HLC/order correctness > wall clock
monotonic clock > wall clock for duration measurement
wall clock = human/audit context
```

QIHSE should detect and record significant clock anomalies:

```text
backward jump
large forward jump
peer skew beyond threshold
NTP/NTS sync loss
monotonic/wall-clock inconsistency
```

Suggested event types:

```text
time.sync_lost
time.sync_restored
time.wall_jump
time.peer_skew
```

These events may affect trust/diagnostic state but should not silently rewrite existing event timestamps.

---

# 39. QIHSE Hardening Self-Audit

QIHSE should expose a machine-readable security posture report for Citadel's global `citadel audit` mechanism.

Suggested API:

```text
Security.Audit
Security.RuntimeProfile
Security.TrustEvidence
```

Example report:

```json
{
  "qihse_build": "...",
  "artifact_digest": "...",
  "sbom_verified": true,
  "provenance_verified": true,
  "trust_state": "TRUSTED",
  "service_uid": 992,
  "core_dumps": false,
  "unexpected_capabilities": [],
  "unexpected_listeners": [],
  "runtime_profile_generation": 17,
  "federation_mtls": true,
  "gossip_replay_protection": true,
  "data_encryption_policy": "satisfied",
  "audit_chain": "valid"
}
```

The audit must verify actual runtime state rather than merely reading configuration files.

Checks should include, where practical:

```text
effective Linux capabilities
process UID/GID
open listening sockets
unexpected outbound connections
loaded runtime modules/plugins
writable filesystem paths
core-dump policy
seccomp/LSM state
binary/artifact digest
SBOM/provenance verification
node certificate validity
federation trust state
audit-chain continuity
WAL integrity state
backup encryption policy
```

Results should be versioned and stored as evidence objects:

```text
security/audit/<node>/<service>/<hlc>
```

A failed self-audit must not automatically erase local data or terminate the database.

Policy may:

```text
degrade federation trust
remove voter eligibility
block strong mutations
quarantine the node
alert the operator
```

according to severity.

This provides a continuously testable security posture rather than assuming that build-time hardening remains intact after deployment.

---


# 40. Performance Requirements

The federation work must not regress QIHSE's fast local paths.

Set explicit budgets.

Initial targets:

```text
LOCAL KV operation federation overhead:
    <5% p50
    <10% p99

Event append:
    >=100k events/s/node on modern server hardware target
    batchable

Watch delivery:
    <10 ms local propagation p50

Disconnected local write:
    no synchronous peer dependency

Reconciliation:
    bounded configurable bandwidth/CPU
```

Treat these as engineering targets, not benchmark claims.

---

# 41. Observability

Expose:

```text
federation_peer_state
replication_lag
unreplicated_bytes
anti_entropy_ranges_checked
anti_entropy_bytes_repaired
conflict_count
watch_subscribers
watch_backlog
lease_count
lease_expiry_failures
cas_failures
stale_epoch_rejections
auth_failures
audit_chain_status
runtime_trust_state
runtime_profile_drift
unexpected_listener_count
unexpected_capability_count
provenance_verification_state
clock_sync_state
peer_clock_skew
```

Metrics must be label-bounded to avoid cardinality explosions.

---

# 42. Failure-State Matrix

Required semantics:

| Failure | Local-safe writes | Eventual writes | Strong/global writes | Reads | Recovery |
|---|---:|---:|---:|---:|---|
| all peers reachable | yes | yes | yes | yes | normal |
| minority peers lost | yes | yes | depends group | yes | automatic |
| node fully isolated | yes | yes/queued | no unless explicitly local authority | yes | reconcile |
| local disk degraded | limited/fail closed | limited | no | best effort | storage repair |
| QIHSE process restart | after WAL | after WAL | after state recovery | yes | automatic |
| identity revoked | no federation writes | no | no | policy dependent | re-enroll |
| runtime provenance invalid | yes local | policy/local only | no strong authority | local reads yes | re-attest/rebuild |
| hardening audit critical failure | yes local | policy/local only | no strong authority | local reads yes | investigate/remediate |
| conflicting versions | unaffected namespaces yes | policy | reject | both available to resolver | explicit |

---

# 43. Reconciliation Safety

On rejoin:

1. authenticate peer;
2. compare federation UUID;
3. compare node boot/session UUID;
4. exchange HLC;
5. exchange namespace manifests;
6. identify divergent ranges;
7. transfer immutable events first;
8. apply conflict policy;
9. reconstruct materialized state;
10. verify range checksums;
11. mark reconciliation complete.

A rejoining node must not immediately publish stale exclusive ownership as authoritative.

---

# 44. Testing Requirements

## 31.1 Deterministic distributed simulation

Create a test transport capable of:

- packet loss;
- duplication;
- reordering;
- delay;
- partition;
- asymmetric partition;
- process crash;
- disk write failure;
- stale clock;
- restart from snapshot/WAL.

Run state-machine tests without real network timing.

## 31.2 Mandatory scenarios

At minimum:

```text
5 nodes -> isolate 1 -> local writes continue
5 nodes -> split 2/3 -> strong group elects exactly one leader
5 nodes -> split 2/2 + witness
complete isolation -> LOCAL namespace remains RW
rejoin after 24h divergent EVENTUAL writes -> deterministic merge
stale lease renewal -> rejected
stale fencing epoch -> rejected
duplicate request UUID -> no duplicate mutation
old boot UUID packet replay -> rejected
revoked node attempts replication -> rejected
node with valid cert but invalid provenance -> denied voter/strong-write authority
unexpected listener introduced -> hardening audit detects drift
unexpected Linux capability introduced -> hardening audit detects drift
core dump policy changed -> hardening audit detects drift
wall clock jumps backward -> HLC remains monotonic and event emitted
NTS/time sync loss -> recorded without corrupting ordering
mid-snapshot crash -> recoverable
schema N and N+1 mixed cluster -> supported
```

## 31.3 Fuzzing

Fuzz:

- federation frame parser;
- snapshot manifest;
- reconciliation manifests;
- mutation envelopes;
- schema decoder;
- gossip parser;
- watch cursor decoder;
- persisted lease records.

Continue ASan/UBSan and add TSan-capable concurrency jobs where practical.

---

# 45. Rollout Plan

## Phase 0 — Refactor boundaries

- define federation module;
- add UUID/HLC/version primitives;
- no behavior changes;
- document current cluster semantics.

## Phase 1 — Sovereign local state

- consistency class metadata;
- local-authority namespaces;
- eliminate global quorum dependency for local-safe writes;
- federation status API.

## Phase 2 — Event journal + watches

- immutable event envelope;
- resumable watch API;
- idempotent request IDs;
- controller SDK.

## Phase 3 — Replication correctness

- anti-entropy;
- manifests/range digests;
- conflict objects;
- resumable reconciliation.

## Phase 4 — Strong namespace

- scoped consensus group;
- CAS;
- monotonic epochs;
- lease primitive;
- explicit membership.

## Phase 5 — Trust plane

- node enrollment;
- mTLS;
- signed/replay-resistant gossip;
- revocation;
- security scopes.

## Phase 6 — Build and supply-chain substrate

- package override/source registry;
- build-job state machine;
- worker capability records;
- build leases/idempotency;
- provenance graph entities/edges;
- SBOM/attestation records;
- vulnerability observations;
- repository snapshot/deployment lineage;
- controller-facing build/supply APIs.

## Phase 7 — Runtime trust and hardening

- evidence-aware federation admission;
- runtime security profiles;
- network exposure/egress declarations;
- time-integrity events;
- QIHSE hardening self-audit;
- Citadel audit integration;
- trust-state effects on voter/strong-write eligibility.

## Phase 8 — Operational hardening

- rolling schema upgrades;
- backup/snapshot semantics;
- chaos test suite;
- performance regression suite;
- recovery tooling.

---

# 46. Acceptance Criteria

This upgrade is not complete until all are true:

1. A single isolated node can recover and service authorized `LOCAL` state without peer availability.
2. Loss of federation quorum does not globally force QIHSE read-only.
3. Strong/exclusive namespaces fail closed under insufficient consensus.
4. Stale fencing epochs are reliably rejected.
5. Duplicate mutation requests are idempotent.
6. A node offline for an extended period can reconcile without full rebuild.
7. Conflicts are explicit and inspectable.
8. Federation traffic is mutually authenticated and replay resistant.
9. KEYSTONE can consume resumable change streams without becoming authoritative.
10. The hypervisor controller can use native CAS/watch/lease primitives without embedding database consensus logic.
11. No database component directly executes hypervisor actions.
12. Existing QIHSE security regression suites continue to pass.
13. New partition/chaos tests pass deterministically.
14. Local query performance remains within defined regression budgets.
15. QIHSE can trace a deployed package back to source revision, patchset, build recipe, toolchain, worker image, builder node, and artifact digest.
16. QIHSE build records cannot directly invoke arbitrary commands on builders.
17. Build signing/private repository keys are not required inside QIHSE or build workers.
18. Duplicate/retried build state mutations remain idempotent.
19. Repository snapshots are immutable and queryable.
20. Historical signed SBOM records are never rewritten because vulnerability intelligence changes.
21. QIHSE can answer reverse-impact queries from vulnerable component/source/toolchain/builder to deployed nodes.
22. KEYSTONE may index supply-chain records without becoming authoritative for provenance.
23. A node with valid credentials but failed provenance can remain locally usable while being denied trusted federation authority.
24. QIHSE exposes a runtime hardening audit based on actual process/system state.
25. Unexpected listeners, capabilities, provenance drift, or runtime-profile drift are detectable.
26. QIHSE requires no unrestricted Internet egress.
27. Wall-clock anomalies do not break HLC ordering or consensus safety.
28. Production core-dump policy and sensitive kernel-interface policy are explicitly testable.

---

# 47. Explicit Non-Goals

Do **not** turn QIHSE into:

- Proxmox replacement UI;
- VM scheduler;
- Xen/libvirt wrapper;
- host fencing system;
- storage controller;
- SDN controller;
- secret vault;
- arbitrary remote shell;
- compiler/build executor;
- repository signing authority;
- monolithic cluster manager.

Provide the durable, secure primitives those systems require.

---

# 48. AI Implementation Instructions

When implementing this brief:

1. Inspect current code before modifying interfaces.
2. Preserve current public APIs unless an incompatibility is explicitly versioned.
3. Add functionality incrementally; do not rewrite working storage engines merely to fit the federation design.
4. Prefer explicit state machines over implicit boolean combinations.
5. Do not call a protocol "Raft" unless the required safety properties are actually implemented and tested.
6. Every new wire format must be versioned, length-bounded, authenticated, fuzzable, and documented.
7. Every persistent structure must have magic, version, bounds validation, checksums where appropriate, and safe failure behavior.
8. Every cross-node mutation must be idempotent and attributable.
9. Do not add hidden dependency on peer reachability to local paths.
10. Benchmark before/after changes and preserve scalar/reference correctness paths.
11. Security failures fail closed only for the affected authority domain; do not unnecessarily brick unrelated local functionality.
12. Keep QIHSE authoritative for persisted state, but not authoritative for physical-world facts that only a host agent can directly observe.

---

# 49. Deliverables Expected From the Implementing AI

Produce:

```text
docs/architecture/federation_overview.md
docs/architecture/consistency_classes.md
docs/architecture/sovereign_nodes.md
docs/architecture/federation_replication.md
docs/architecture/federation_security.md
docs/architecture/leases_epochs.md
docs/architecture/reconciliation.md
docs/architecture/controller_api.md
docs/architecture/build_coordination.md
docs/architecture/supply_chain_provenance.md
docs/architecture/sbom_attestation.md
docs/architecture/repository_snapshots.md
docs/architecture/runtime_trust.md
docs/architecture/runtime_hardening.md
docs/architecture/network_exposure.md
docs/architecture/time_integrity.md
docs/architecture/security_self_audit.md

include/qihse_federation.h
include/qihse_hlc.h
include/qihse_watch.h
include/qihse_lease.h
include/qihse_build.h
include/qihse_supply_chain.h
include/qihse_provenance.h
include/qihse_runtime_trust.h
include/qihse_security_audit.h

src/federation/*
src/build/*
src/supply_chain/*
tests/federation/*
tests/chaos/*
benchmarks/qihse_federation_bench.c
```

Also update:

```text
docs/README.md
docs/FEATURES.md
docs/COMPATIBILITY.md
README.md
```

only when the implementation genuinely supports the documented feature.

---

# 50. Final Architectural Statement

QIHSE should become a **secure federated data substrate composed of sovereign nodes**.

It should provide:

```text
local autonomy
+ replicated state
+ scoped strong consistency
+ explicit conflict handling
+ authenticated membership
+ resumable event streams
+ reconciliation
+ CAS / epochs / leases
+ build-job coordination
+ software-supply-chain provenance
+ SBOM/attestation state
+ immutable repository/deployment lineage
+ evidence-aware federation admission
+ runtime hardening verification
+ explicit network/time security posture
```

without coupling ordinary local operation to whole-cluster quorum.

That gives the future hypervisor controller a much better foundation than a conventional monolithic cluster database while keeping the database and execution-control security boundaries clean.
