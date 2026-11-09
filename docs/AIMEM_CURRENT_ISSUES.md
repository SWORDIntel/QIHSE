# AIMEM Current Issues

Status updated 2026-11-09. This note records verified blockers and risks; it contains no credential values.

## 1. Durable authentication authority migration is blocked

The last authenticated, read-only authority-capabilities query (2026-11-05) reported volatile legacy mode `0`, not ready, and no export, import, or checkpoint capability. `PRINCIPAL_MIGRATION.md` explicitly blocks activation while the LAN ownership/GC conflict remains unresolved.

On 2026-11-09, the Operator credential was recovered through the existing
`systemd-creds decrypt --user` launcher path. Authenticated
`AUTHORITY.CAPABILITIES` succeeded and confirmed legacy mode `0` with no durable
authority export/import/checkpoint support. The earlier capability rejection
used `AIMEM_SERVICE`, which is intentionally limited to AIMEM commands; it did
not establish an Operator permission failure.

The user authorized a local binary deployment while retaining that authority
mode, the same Operator and AIMEM service credentials, numeric service/tenant
IDs, KV directory, QKP pins, and ONNX model. The new isolated release was tested
on a separate port before replacing the user service's `current` link. The live
service then preserved a pre-upgrade durable canary; exact reads and the new
store/forget local-fsync receipts passed. The database key count was 2,270 both
before and after canary cleanup, with healthy SST indexes and the 30-second
sweeper running. This was a binary upgrade, not activation of durable principal
authority. Runtime-created accounts and transient sessions are not persisted by
legacy mode. A future durable authority migration still requires supported
state transfer; this limitation does not prevent ordinary upgrades that retain
the explicitly configured two-principal setup.

The subsequent HAX smoke exposed unavailable scoped semantic/hybrid recall:
the default build omitted the optional KEYSTONE projection. The final local
release enables `QIHSE_ENABLE_AIMEM_KEYSTONE=1`, loads its adjacent KEYSTONE
library, and uses a private derived projection cache. A bounded UUID plus
canonical-content SHA-256 vector cache retains completed inference across
invalidated cold generations; all publication marker, label and authorization
checks remain intact. A deterministic KV mutation during inference proved that
an invalidated generation retries without repeating completed inference.

The real HAX Python QKP client now passes durable store, exact read,
wrong-project denial, BM25/semantic/hybrid recall and local-fsync forget;
disposable smoke memories were cleaned up. The broader cluster rollout is
held: T320 is reachable again, but the three authenticated cluster views
disagree on slot ownership, T320 reports FAIL, and all maintenance gates are
OPEN. The historical rolling script also targets install paths overridden by
the running units' versioned release paths. No remote service was restarted.

## 2. QIHSE push is blocked by secret scanning

Local QIHSE commit `52765af` was rejected by GitHub push protection (GH013). Secret scanning identified credential-like environment values in these benchmark captures:

- `benchmarks/codegraph_hot_hax_suite.json`
- `benchmarks/codegraph_search_delivery_hax_suite.json`

The values were not published and are intentionally not reproduced here. Redact the captured environment values, then remove them from the unpublished commit history before retrying the push; adding a later cleanup commit alone may leave the flagged values in the pushed history. If any value is an active credential, rotate it through its issuing provider. The separate bridge commit `6654998` was pushed successfully.

## 3. Filesystem capacity (rechecked 2026-11-09)

The local deployment preflight reported 63% used and about 334 GiB available
on the filesystem containing the service data. This supersedes earlier dated
capacity observations. Continue monitoring capacity before growth; do not
delete AIMEM data as a cleanup shortcut.

## 4. Source validation and CT1/CT2 closure (2026-11-09)

The final CT1/CT2 integration supersedes the earlier transport coverage-gap result. The required `make test TEST_JOBS=32` run completed **198 targets with zero failures**, including ten new transport targets; gold now runs 74 workloads with no declared gaps. The real pinned-QKP fixtures prove successor promotion and interrupted arbitrary-target transfer with independent successors, scoped denial, ordinary-read admission, observer convergence, historical receipts and reverse transfer. [Verification](validation/ct_transport_20261109.md) records the evidence and bounds. This closes the source transport gaps; the live authority/remote ownership rollout conditions in section 1 remain separate operational work.

The earlier required `make test TEST_JOBS=32` run completed 188 targets with two failures. `test-docs-api-counts` found a stale generated KV header count; `make docs-api-counts` refreshed the table and the focused gate now passes. At that stage, `test-parallel-runner` rejected the gold pack's explicit CT1 pinned-write-replication and CT2 fenced-slot-transfer gaps. Those guarantees still required implementation and proof; the test was kept intact. The new AIMEM atomic forget, scoped authorization, source citation, Python SDK, and CodeGraph aggregate targets passed. HAX's final full suite passed 305 tests and lint passed. The local runtime verification is recorded above. On 2026-11-09, the required standard-build full run completed 188 targets with only `test-parallel-runner` failing on the same CT1/CT2 coverage gaps; the gold pack and CodeGraph aggregate passed. The projection-enabled interruption/ranking/authorization fixture also passed against the installed library, followed by the real HAX QKP memory smoke.

## Resolved: expiry sweep and SSTable compaction

The standalone daemon now defaults to a 30-second KV sweep cadence (`--kv-sweep-interval`, with `0` explicitly disabling it). In the earlier 2026-11-05 verification, authenticated QKP `PING` returned `PONG`; INFO reported sweep interval `30`, sweeper running, one live SST file, no degraded SST index, and healthy status. The previous 1,227 live SST files were compacted to one. The suite passed 164 targets at that time. The 2026-11-09 deployment obtained authenticated INFO and verified healthy SST indexing, a 30-second sweep interval and an active sweeper.

## Protected backlog

The bridge backlog was last verified as 260 blocked and 7 queued. No replay, deletion, or mutation was performed; preserve it until separately authorized and investigated.
