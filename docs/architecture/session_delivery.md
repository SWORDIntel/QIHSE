# Session-Delivery Subsystem (U1–U9)

Architecture for the session-delivery workload upgrades specified in
[`SESSION_DELIVERY_UPGRADES.md`](../../SESSION_DELIVERY_UPGRADES.md)
(SparkBench-class multi-tenant clients). **All nine upgrades are implemented**
(September 2026); each ships with the low-clearance/high-data negative test
required by `AGENTS.md` invariant #3, registered in
`tests/security-regression.mk`.

The workload in one paragraph: each client session pulls one *session bundle*
(entitlement key-seed + pattern bundle + tenant script set), executes from it
with plaintext only in the client's protected region, and streams append-mostly
telemetry back. Telemetry is PII-free **by protocol, not by policy**. One
tenant's catch must reach every tenant's kill switch within minutes.

## Tenancy model (U2)

| Piece | Location | Behavior |
|---|---|---|
| `tenant_id` field | `core/qihse_auth_internal.h`, shadow `authz_state_t` in `core/qihse_auth.c` | Tenant `0` = system domain (operator, unrestricted). Non-zero tenants are deny-by-default at the engine boundary. Principal capacity is 65,536 ids per node (`MAX_USERS`, user ids 1–65,535; untouched capacity costs no memory). |
| `qihse_auth_create_tenant_user()` | `core/qihse_auth.c` | Mint a tenant-scoped principal. Same privilege ladder as `qihse_auth_create_user`, plus: a tenant creator may only create inside its **own** tenant; only tenant-0 creators mint system-domain principals; `qihse_auth_create_tenant_user(..., tenant_id=0, ...)` is refused outright. |
| Delegated-creation floor | `create_user_internal()` | A **non-OPERATOR-role** creator (either creation API) always yields role `GUEST`, clearance `0`, SCI `0` — account creation is delegated, never authority. Above-self requests are still denied by the ladder *before* the floor; within-self requests are floored and audited as `USER_CREATE_DELEGATED_FLOOR`. |
| Operator set-clearance | `qihse_auth_modify_user(..., int new_classification, int new_sci)` | Operators may set or raise clearance/SCI at creation (explicit parameters, never floored) and afterwards (`-1` = unchanged; out-of-range rejected; OPERATOR-role targets pinned to `0xFFFF/0xFFFF`). This is the only elevation path — delegated principals cannot modify anyone. |
| Engine tenant gate | `qihse_resp_tenant_scope()` in `src/spinnaker/qihse_resp_engine.c` | Tenant principals may touch only keys under `t:<own-id>/…` or the shared `commons/…` namespace; anything else (including unscoped keys) is refused with `NOPERM` before a handler runs. System-domain principals are exempt. |
| Per-tenant quotas | `include/qihse_quota.h`, `core/qihse_quota.c` | Fixed-window counters keyed `(tenant_id, class)` for bundle pulls, telemetry ingest, ANN queries, KV writes. Enforced in dispatch next to the system-guard hook; **fails closed**; rejections are counted and answered `QUOTA …`. |
| Revocation SLA | `qihse_auth_user_is_active()` + per-command re-validation in dispatch | Destroyed principals lose their live session immediately — the very next command is refused (`NOAUTH Session principal revoked`), including on the unclassified per-row fast path, which intentionally skips per-row identity resolution for throughput. |

## Blob tier (U1)

`include/qihse_blob.h`, `src/black_hole/qihse_blob.c`. KV values are
NUL-terminated C strings with a 512 KiB memtable — unusable for megabyte
binary blobs — so blobs are a dedicated content-addressed store:

- Layout: `<base>/objects/<2-hex>/<94-hex>` for content, `<base>/index.log`
  for an append-only metadata log (replayed on open; torn tails ignored;
  format version 2).
- Content addressing is **SHA-384** (CNSA 2.0 aligned with the rest of the
  suite — auth verifiers are PBKDF2-HMAC-SHA-384; ML-DSA signatures cover
  manifests). Concurrent uploads run fully in parallel: each put streams to a
  unique temp file and takes locks only for the dedup check / index insert /
  log append; identical concurrent content resolves through the dedup path
  (atomic renames of byte-identical files).
- Writes stream through a caller-supplied reader callback (hash-while-writing
  → temp file → fsync → atomic rename). Dedup is content addressing: re-putting
  identical bytes with an identical binding (tenant, tag, classification, SCI)
  bumps a refcount; the same hash with a *different* binding is refused, so a
  tenant can never claim another tenant's object.
- Class tags: `entitlement_seed`, `pattern_bundle`, `script_set`,
  `commons_snapshot`. Commons blobs are readable by every authenticated tenant
  but writable only by the system domain.
- **Every** API takes `qihse_user_t*` and NULL is unconditionally denied
  (invariant #1) — there are no context-free convenience variants. Range
  reads re-check authorization per call so a revoked principal cannot drain a
  transfer.

## PII-free ingest gate (U4)

`include/qihse_ingest_guard.h`, `src/spinnaker/qihse_ingest_guard.c`. Writes
into the telemetry namespace `t:<tenant>/tlm/<record_type>/<label>` must match
a closed whitelist; violations are rejected at ingest (`INGEST record
rejected: …`), never merely logged, and the gate binds the operator too.

| Record type | Fields (positional, `|`-separated; first field repeats the type) |
|---|---|
| `build_record` | hex16 build-hash, hex16 hardware-hash, u64 duration-ms, enum{ok,fail} |
| `symbol_context` | hex16 symbol-hash, u64 kind, u64 frequency |
| `census` | u64 count, u64 window-ms |
| `survival_observation` | u64 session-ms, enum{0..3} |
| `burn_edge` | hex16 src, hex16 dst, u64 weight |

The value alphabet is closed (`[0-9a-zA-Z_|.]`) — free text, account names,
hostnames, IPs, and paths have no representable form. The only machine
identifier is the opaque tenant-scoped hardware hash. Non-telemetry keys are
unaffected.

## Session-bundle delivery (U3)

RESP-native (chosen over `qihse_http_api.c`, which is a single-recv,
no-auth, no-streaming skeleton). Commands:

- `BUNDLE.PREPARE <fingerprint> [have-hash …]` — tenant callers compose for
  their own tenant; system-domain callers pass `<tenant_id> <fingerprint>`.
  Returns a self-contained manifest, so chunk fetches need no server session
  state:
  - `QHSE-BUNDLE 1` header, `tenant:`, `build:` lines
  - `session-key:MLKEM1024 <3136 hex>` — a **fresh** 32-byte session key per
    compose, encapsulated under the tenant client's ML-KEM-1024 public key
    (`qihse_pqc_encapsulate_peer()`, `persistence/qihse_pqc_crypto.c`). The
    key exists only in server memory for the compose and is wiped immediately;
    freshness per session is asserted by the regression test.
  - `blob:<96-hex> <size> <tag>` lines (SHA-384 hashes) — the pattern bundle recorded for the
    build (`t:<id>/bundle/pattern/<fingerprint>`) and the tenant script set
    (`t:<id>/bundle/scripts>`), minus any hash in the have-list (delta pull).
  - optional `sig:MLDSA87 <hex>` — manifest signature when
    `bundle_dsa_private_key_path` is configured.
- `BUNDLE.CHUNK <hash> <offset>` — one ≤64 KiB slice via
  `qihse_blob_get_user(..., session->user)`. Authorization is re-checked per
  chunk; denial and I/O failure are indistinguishable to the client.

**Sanity gate (commons-poisoning defense):** the pattern blob referenced by
the build pointer must be bound to the requesting tenant *and* tagged
`pattern_bundle`; anything else is refused (`sanity gate rejected`) and
audited as `BUNDLE_SANITY_GATE_REJECTED`.

Tenant client keys live in `bundle_keys_dir` as
`tenant-<tenant_id>-kem_pub.pem` (uploaded out-of-band by the operator).

## Killswitch push channel (U8)

- A successful `SET` of a valid `burn_edge` record is bridged
  (`qihse_resp_maybe_publish_killswitch()`) to the fleet-wide `killswitch`
  channel **as a system-domain publisher**, and mirrored to the durable
  commons record `commons/killswitch/latest` that offline clients pick up on
  their next pull.
- Per-channel policy: `qihse_resp_pubsub_set_channel_policy()` adds channel
  specific `(classification, SCI, publish_system_only)` overrides on top of
  the broker-wide default. With `enable_killswitch_channel` set, every
  authenticated tenant may `SUBSCRIBE killswitch` but only system-domain
  principals may `PUBLISH` to it (tenant spoofing is refused `NOPERM`).
- Pushes land on connected subscribers within the publisher's write path
  (loopback ≈ 0 ms; the SLA is minutes); offline clients catch up via the
  durable commons record.

## Vector ANN isolation (U5)

`VECSEARCH`'s `TAG` argument is now a load-bearing collection boundary: the
handler installs a metadata pre-filter (`qihse_vec_tag_match()`) so an
approximate search only considers rows whose stored TAG matches — previously
the TAG was ignored and searches swept the whole index, leaking cross-tenant
neighbors (the known approximate-search trap). Per-row clearance/SCI
filtering at the candidate stage and the mandatory `query.user` were already
in place. `tests/test_vector_tenant_isolation.c` plants a cross-tenant
neighbor that is numerically *closest* to the probe and asserts exclusion.

## Retention / GC (U6)

`kv_sweep_interval_seconds` (server config) starts a background sweeper that
calls `qihse_kv_sweep_expired()` — previously defined with zero callers — on
a fixed cadence under the KV lock. Expiry itself remains lazy-on-read;
the sweeper physically removes expired records. Per-class retention policies
(telemetry rollups, keep-last-N bundles) remain a follow-up on top of this
mechanism. `DBSIZE` is now a real, authorization-aware count (it was
hardcoded `:0`).

## Tenant-subset export (U7)

`qihse_export_tenant_user()` (`include/qihse_export.h`,
`src/black_hole/qihse_export.c`) writes a portable artifact
(`QIHSE-TENANT-EXPORT 1`) containing every KV record in the tenant's
namespace plus `commons/` that the caller may read, and the visible blob
manifest. Records above the caller's clearance are excluded by the
authorization-aware iteration; a tenant principal can only export its own
tenant; NULL user is denied. Deletion/migration of a tenant follows from the
same artifact. (The legacy `qihse_backup.c` remains an empty stub by design —
export is built on the working layer instead.)

## Delivery metrics (U9)

The previously dead `qihse_metrics` registry is instantiated per RESP server
and wired: `qihse_bundle_compose_total`, `qihse_bundle_compose_latency_ms`,
`qihse_bundle_delta_hits`, `qihse_ingest_rejected_total`,
`qihse_killswitch_push_total`, `qihse_quota_rejected_total`.
`METRICS.RENDER` returns Prometheus-style text — system-domain only
(tenants get `NOPERM`).

## Config reference (`qihse_resp_server_config_t`)

| Field | Purpose |
|---|---|
| `quotas` | Caller-owned `qihse_quota_table_t*` (NULL = no quotas) |
| `blobs` | Caller-owned blob store; NULL disables `BUNDLE.*` |
| `bundle_keys_dir` | Directory of per-tenant client KEM public keys |
| `bundle_dsa_private_key_path` | ML-DSA-87 manifest signing key (NULL = unsigned) |
| `enable_killswitch_channel` | Registers the tenant-readable, system-publish-only `killswitch` channel |
| `kv_sweep_interval_seconds` | Background expiry-sweep cadence (0 = off) |

## Key namespace reference

| Pattern | Meaning |
|---|---|
| `t:<tenant_id>/…` | Tenant-private keyspace (enforced at the engine boundary) |
| `commons/…` | Shared, tenant-readable namespace |
| `t:<id>/tlm/<record_type>/<label>` | Telemetry ingest namespace (closed schema) |
| `t:<id>/bundle/pattern/<fingerprint>` | KV pointer (SHA-384 blob hash, 96-hex) to a build's pattern bundle |
| `t:<id>/bundle/scripts` | KV pointer to the tenant's script-set blob |
| `commons/killswitch/latest` | Durable last-valid burn edge |

## Test matrix

Every row is registered in `tests/security-regression.mk`
(`make -f Makefile -f tests/security-regression.mk test-security-regressions`):

| Test | Covers |
|---|---|
| `test_tenant_security_regression` | namespace scoping, deny-by-default, quotas, revocation SLA, operator exemption |
| `test_tenant_privilege_ladder` | creation ladder, delegated floor, operator set-clearance/elevation |
| `test_blob_security_regression` | blob authz, binding-clash dedup, refcounts, cross-tenant denial |
| `test_ingest_guard_regression` | closed telemetry schemas, reject-and-persist-nothing, operator bound too |
| `test_bundle_security_regression` | compose/delta/chunk round-trip, KEM freshness, sanity gate, cross-tenant + mid-transfer revocation |
| `test_killswitch_regression` | fan-out SLA, spoofing denial, durable catch-up, invalid-edge rejection |
| `test_vector_tenant_isolation` | foreign-TAG denial, ANN leakage trap exclusion |
| `test_retention_regression` | background sweep removes expired records |
| `test_export_regression` | tenant artifact scope, clearance filtering, foreign-tenant denial |
| `test_metrics_regression` | counter wiring, `METRICS.RENDER` exposure control |
| `test_sci_compartment_regression` | SCI subset rule at access time: `can_access`, KV records, blob read/write-side possession, NULL-user denial |
| `test_blob_persistence_regression` | SHA-384 NIST known-answer, index.log reopen/replay with refcount survival, torn-tail recovery, range edges |
