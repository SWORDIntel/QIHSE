# QIHSE Cluster Operations Roadmap

Status: current as of the 2026-10-25 migration-hardening + SDK pass. Tracks the
operational workstreams around the 3-node cluster (t420 / 730xd / t320):
native builds, QKP-hardened access, replication, slot migration/GC, and tooling.
`make test` is fully green (all suites + gold workloads).

## Phase 0 — Delivered (in main)

- Native per-node builds: `build-native.sh --auto` detects every SIMD ISA;
  `make all` runs the mandatory host-ISA verification; per-ISA kernels are
  compile-time gated so a binary contains only its machine's ISA.
- Rolling updates: `scripts/cluster_rolling_restart.sh` (deploy + restart
  one node at a time + QKP health probes).
- Replication: read-only QKP-pinned replica daemons (ring topology, one
  namespace per instance) via `scripts/cluster_replica_deploy.sh`; fixed
  the non-Operator replication principal vs KV-Operator-required
  contradiction; replica units carry `LD_LIBRARY_PATH`; 60s pull timeout.
- Admin access: `qihse-admin-cli` + pinned administrator identity
  (`--admin-peer-node-id`/`--admin-peer-dsa-pub` → system operator).
- MACHINEAUTH machine-principal bootstrap (agent-namespace scoped).
- Docs updated across OPERATIONS / GETTING_STARTED / cluster_sharding /
  deployment / hardening-report.

## Phase 1 — Operational closure ✅ (closed 2026-10-24)

| # | Item | Result |
|---|---|---|
| 1.1 | Full deploy+restart cycle via `cluster_rolling_restart.sh` | ✅ ran end-to-end: 3 nodes deployed, restarted, QKP-verified 3/3 |
| 1.2 | End-to-end replication proof | ✅ SET `tool:phase1-probe` on node5 → t320 replica pulled `1 row(s) (ok)` → GET on the replica returned the exact value |
| 1.3 | `qihse-backup` on hardened masters | ✅ 85.6 MB full backup + `verify` result `valid`; it is a local (non-RESP) tool and works on `pqc_require` masters — the node service must be stopped for a consistent snapshot |
| 1.4 | Replica self-reporting in `cluster nodes` | ✅ replicas now carry unique `--bus-port`s (17201/17202 per host) and no longer share the master bus; `CLUSTER NODES` shows only the 3 masters |

Also landed: replica units pin the admin identity and trust the admin pub, so
`qihse-admin-cli` can verify replica contents (read-only).

## Phase 2 — Security & compliance (per repo invariants)

> **Security review (2026-10-25):** all three QKP surfaces are SAFE — the
> admin pin is a strict node-id `strcmp` + constant-time DSA-fingerprint
> `CRYPTO_memcmp` (no TOFU/fallback); the replication principal is non-Operator
> and reachable only via QKP (its password is random + wiped); MACHINEAUTH
> refuses system-tenant/Operator principals and prevents clearance/SCI
> elevation. **Documented caveat:** the replication principal is provisioned
> UINT16_MAX clearance/SCI and the snapshot export filters by glob only, so a
> *compromised* replication principal could exfiltrate the marked namespaces
> — inherent to replication; treat the replication identity key as a
> high-value secret.

| # | Item | Notes |
|---|---|---|
| 2.1 | Negative authorization tests for the new surfaces | ✅ `tests/test_qkp_access_negative.c` (replication principal non-Operator, tenant machine principal, low-clearance/SCI denial, object ACL); wired into the CI `test` aggregate |
| 2.2 | Admin-pin security review | ✅ reviewed safe; remaining: document the rotation flow (unit edit + rolling restart) |
| 2.3 | Replication principal audit | ✅ reviewed; allowlist is REPL.* only; see caveat above |

## Phase 3 — Tooling & automation

| # | Item | Notes |
|---|---|---|
| 3.1 | `qihse` launcher wrappers | `qihse admin ping/cluster-nodes`, `qihse cluster status/rolling-restart/replicas` around the admin CLI + ops scripts |
| 3.2 | Unify cluster scripts | Merge `cluster_rolling_restart.sh` + `cluster_replica_deploy.sh` into one coherent command set with `--status`/`--verify` modes |
| 3.3 | CI integration coverage | Build + deploy a throwaway 3-node cluster in CI; run the replication and admin-path tests (2.1) against it |

## Phase 4 — Cluster capability

| # | Item | Notes |
|---|---|---|
| 4.1 | Slot migration / `--brain-act` | ✅ complete + live-verified. Full-mesh `--migration-peer` pins, QKP handoff (retired AUTH GODMODE_OP), durable-transfer-before-ownership, per-owner config-epoch fix (`1eb9e4d`) + follow-up correction (`07284a0`: stop stamping config_epoch from each topology's local counter on node upsert/health, which made cross-node epoch comparison drift and reject valid slot updates), negative auth test, `--brain-act` gate lifted. Data-safety plan landed: **COPY-not-MOVE** (`e4f9870`) + durable **ownership journal** appended on both ends (`28b658c`, `9cb7623`) + startup replay/adopt-if-newer. GC (reclaim) uses the authenticated key-only iterator (`qihse_kv_foreach_key_user`), runs in bounded post-bind batches when journal entries were replayed, and is also exposed via `CLUSTER RECLAIM [limit]`. Live-verified: migration → restart → ownership restored, key stays accessible |
| 4.2 | Failover & quorum drills | ✅ drilled: stopped node5 → `master,fail`, node0+node1 kept serving → rejoined 3/3 |
| 4.2a | Failover failback | ✅ `fd5aa7e`, `d8ef824`: deterministic fallback successor (smallest node ID, not local uptime), takeover ledger, asynchronous failback after a 3 s stability window over contiguous subranges, bounded exponential retry, and a takeover decided by another node's coordinator is ledgered by this one. Unit coverage `make test-cluster-failover`. Failback handoff reuses the pinned-QKP + journaled migration path |
| 4.3 | Backup/restore strategy | ✅ `qihse-backup restore` implemented + verified round-trip (backup → restore → verify valid); runbook in `docs/plans/backup_restore_runbook.md` |
| 4.4 | Watchdog & alerting | ✅ `scripts/cluster_watchdog.sh` (master PING + replica pull check) |

## Cross-cutting risks

- Slot reclaim (`CLUSTER RECLAIM`, post-bind GC) is bounded and key-only, but
  it still takes the store read lock while enumerating: on a very large
  keyspace a single 256-key batch competes with serving threads. Operators
  should reclaim off-peak or with a small explicit limit.

- Any unit change to a master (pins, principals) requires a rolling restart;
  keep the `.bak-<timestamp>` rotation and the rolling script as the only
  supported change path.
- Hardened masters are QKP-only: every operator tool must go through
  `qihse-admin-cli`; do not reintroduce cleartext AUTH.

## Phase 5 — SDK & platform direction

| # | Item | Notes |
|---|---|---|
| 5.1 | Freeze the C QKP admin ABI as the SDK contract | `qihse_qkp_admin_exec` / `qihse_qkp_admin_free` (`include/qihse_qkp.h`) are the single client surface; every language binding must go through them, never reimplement QKP/ML-KEM/ML-DSA or pin/trust logic |
| 5.2 | Rust `qihse-sys` + safe operator client | **Recommended authoritative SDK/CLI language.** `bindgen` over `include/qihse_qkp.h` → typed, memory-safe FFI; one static binary (no interpreter/`LD_LIBRARY_PATH` on hardened masters). Additive only — the C core and its crypto stay the source of truth |
| 5.3 | Keep Python as the scripting surface | `qihse_admin.py` (ctypes over the same ABI) stays for interactive ops; it must remain a thin wrapper, not the authoritative client |
| 5.4 | Go stays infra-only (`linuxagent`) | cgo interop with liboqs/OpenSSL FIPS + ML-DSA key material is a poor fit for the crypto client; do not fold the operator SDK into Go |
| 5.5 | Complete the sorted-set command surface | ✅ `ZRANK`/`ZREVRANK`/`ZPOPMAX`/`ZPOPMIN`/`ZCOUNT` implemented (`qihse_resp_engine.c`) over `qihse_resp_collect_zset` (they were nil/empty stubs); parity with `ZRANGE`/`ZCARD`/`ZINCRBY` |

## Verification (2026-10-26)

- `make test` is **fully green** (`EXIT=0`, 34m51s): all unit, security-regression, federation, consensus, keystone, task, overlay, DHT, fabric, AIMEM, Bolt, Mongo and gold workloads pass. The gold pack reports 11 areas, 72 workloads, 0 declared coverage gaps.
- Fixed during this run: `test-cluster-bus-bind` failed to link (undefined `qihse_cluster_topology_get_node`/`_get_slot`) because the test compiles the bus translation unit directly and does not link `qihse_cluster_slot.c`; the Makefile target now links it. Both gold workloads that build a `qihse_resp_arg_t` argv were also assigning `char *` into `const uint8_t *` (`gold_backend_busy`, `gold_fusion_recall`); the cast is now `(const uint8_t *)`.
- Data-bearing handoff tests (`test_brain_actuate`, `test_brain_rebalance`) now drive the real pinned-QKP transport instead of the retired cleartext peer (`4f938be`).
- Flake hardening (no production-logic changes): `test_consensus_mesh` retries MOVED/propose until leader/generation convergence (`c36ec42`); `test_federation_ca` issues out-of-scope certs pre-dated so the validity check is second-boundary stable (`fe835d0`); `cluster_loadshift_smoke` asserts the pinned-QKP refusal message (`467aada`).
