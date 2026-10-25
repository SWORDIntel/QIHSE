# QIHSE Cluster Operations Roadmap

Status: current as of the 2026-10-24 cluster hardening pass. Tracks the
operational workstreams around the 3-node cluster (t420 / 730xd / t320):
native builds, QKP-hardened access, replication, and tooling.

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
| 4.1 | Slot migration / `--brain-act` | ✅ complete + live-verified. Full-mesh `--migration-peer` pins, QKP handoff (retired AUTH GODMODE_OP), durable-transfer-before-ownership, per-owner config-epoch fix (`1eb9e4d`), negative auth test, `--brain-act` gate lifted. Data-safety plan landed: **COPY-not-MOVE** (`e4f9870`) + durable **ownership journal** appended on both ends (`28b658c`, `9cb7623`) + startup replay/adopt-if-newer. GC (reclaim) uses the authenticated key-only iterator (`qihse_kv_foreach_key_user`), runs in bounded post-bind batches when journal entries were replayed, and is also exposed via `CLUSTER RECLAIM [limit]`. Live-verified: migration → restart → ownership restored, key stays accessible |
| 4.2 | Failover & quorum drills | ✅ drilled: stopped node5 → `master,fail`, node0+node1 kept serving → rejoined 3/3 |
| 4.3 | Backup/restore strategy | ✅ `qihse-backup restore` implemented + verified round-trip (backup → restore → verify valid); runbook in `docs/plans/backup_restore_runbook.md` |
| 4.4 | Watchdog & alerting | ✅ `scripts/cluster_watchdog.sh` (master PING + replica pull check) |

## Cross-cutting risks

- Any unit change to a master (pins, principals) requires a rolling restart;
  keep the `.bak-<timestamp>` rotation and the rolling script as the only
  supported change path.
- Hardened masters are QKP-only: every operator tool must go through
  `qihse-admin-cli`; do not reintroduce cleartext AUTH.
