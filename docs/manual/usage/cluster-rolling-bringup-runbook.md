# Fastest rolling cluster bring-up (historical runbook)

> **Superseded; do not execute the restart steps below.** The package hashes and
> service drop-ins in this document predate `--startup-maintenance-held` and
> only engage failover pause. That flag does not fence ordinary writers, and a
> replacement process starts its maintenance gate OPEN unless the new flag is
> present. Refresh each host's package from the exact published source, run the
> isolated startup-held/restart acceptance test, and update the service
> `ExecStart` with `--startup-maintenance-held` before using a replacement
> rollout procedure. Require authenticated SYSTEM-domain Operator startup
> credentials; after each fenced restart verify `CLUSTER MAINTENANCE STATUS`
> is HELD with complete coverage and zero active writers. Retrieve the fresh
> token only through authenticated `CLUSTER MAINTENANCE STARTUP_TOKEN`; never
> log or persist it. Release with the existing generation/token RELEASE
> command only after all acceptance gates pass. See `docs/OPERATIONS.md` §3.2.2
> and `docs/API_REFERENCE.md` §8.8b. T320 remains zero-slot/no-replicate/no-export.

This is a retained description of the 2026-10-31 fast-path procedure. It
sequenced owner restarts and held failover, but did not fence ordinary writers
across process restart or require logical snapshots. Keep it for historical
evidence only; the superseding notice above prohibits executing these steps.

Historical run only: 2026-10-31, before the restart-safe writer fence was
implemented. The cited gate surface is documented for reference, not approval
to execute this obsolete rollout.

## Invariants this runbook must preserve

```text
slots 0–5181      -> 730xd (6d11b0dafc601bf09d23ca73ecdb5dca033d6ad1)
slot  5182        -> T420  (ea80ee37b325e2cff8dda3333db75796a275b61a)
slots 5183–16383  -> 730xd
T320 (5112a72f…)  -> zero slots, --no-replicate, no export
```

- Owner restarts sequenced: T420 → 730xd → T320. Never concurrent.
- Every owner starts with `--failover-start-paused`; release only via
  authenticated Operator `CLUSTER FAILOVER.RESUME` after all gates pass.
- 730xd carries exactly one additive grant, `replica-t420`; the existing
  `replica-t320` peer stays.
- T420 keystone/kp14 caches pull only from 730xd (`192.168.1.90`).
- Never run `/opt/QIHSE/bin/*` (old binaries) on T420/730xd; the drop-ins
  below already point at the packages.

## Deployed artifacts (fixed, versioned)

| Host  | Package path | Daemon sha256 |
|-------|--------------|---------------|
| T420  | `/var/lib/qihse-maintenance/t420-cache-native-20261030/release-289f6080-barrier-rpath2` | `dbb092e0ff5b4ce496dfd2ee9798cd813f6e3fd71268674e97a483c8cc5d5d0b` |
| 730xd | `/var/lib/qihse-maintenance/730-native-20261030T2145/candidate/releases/289f60809b4bf22e9a6186f2e1e39c204743cdc9-barrier-rpath2` | `73f8ece37894e6abc80a4b16511c2e7f9a3d676b42d5d8ed5a95ae525940d1fb` |
| T320  | `/var/lib/qihse-maintenance/t320-native-20261030T2030/candidate/releases/289f608-barrier-8b5bfa70-rpathfix` | `8b5bfa70635142bfb87e8f5f81bc2bffc0652a7750eeed30e816b9240679eea7` |

Drop-ins that must exist before any restart:

```text
T420  /etc/systemd/system/qihse-node0.service.d/50-native-gate-20261031.conf
T420  /etc/systemd/system/qihse-replica-keystone.service.d/50-source-730xd-20261031.conf
T420  /etc/systemd/system/qihse-replica-kp14.service.d/50-source-730xd-20261031.conf
730xd /etc/systemd/system/qihse-node5-host.service.d/50-native-gate-20261031.conf
730xd /etc/systemd/system/qihse-node5-host.service.d/60-replica-t420-20261031.conf
T320  /etc/systemd/system/qihse-node1.service.d/99-qihse-native-repair.conf   (unchanged, kept)
T320  /etc/systemd/system/qihse-node1.service.d/99-zz-native-gate-20261031.conf
```

## Phase 0 — preservation (parallel, ~30 s)

Fresh held ZFS snapshots on all three; keep all existing snapshots/holds.

```bash
# T420
s=qhi-fastpath-pre-$(date -u +%Y%m%dT%H%M%SZ)
zfs snapshot rpool/data/db@$s && zfs hold qhi-native-cutover-preserve rpool/data/db@$s
# 730xd
zfs snapshot fast/sys/opt@$s && zfs hold qhi-native-cutover-preserve fast/sys/opt@$s
# T320
zfs snapshot twotb/opt-qihse@$s && zfs hold qhi-native-cutover-preserve twotb/opt-qihse@$s
```

## Phase 1 — pre-flight (parallel, read-only, ~1 min)

1. Package integrity: `cd <pkg> && sha256sum -c SHA256SUMS` on each host.
2. Drop-in inventory: all seven files above present; then
   `systemctl daemon-reload` (no restart).
3. **Journal pre-flight** (the trap that cost a repair once): decode each
   `slot-ownership.journal` (65-byte frames: `u32` magic `0x4A534F51`,
   `u16` start, `u16` end, 41-byte owner id, `u64` epoch, `u64` FNV-1a over
   the first 57 bytes) and simulate replay with adopt-if-newer-per-owner.
   The final map **must** be `0-5181 S, 5182 E, 5183-16383 S`. In
   particular T320's journal must not end with T320 claiming any slot; if
   it does, append a `[0,16383] -> 730xd` frame at the live 730xd epoch
   followed by `[5182,5182] -> T420` at the live T420 epoch (back up the
   file first) — the exact 65-byte writer is in the 2026-10-31 cutover log.

   Journal paths: T420 `/rpool/data/db/qihse-data/node0` (alias
   `/opt/qihse-data/node0`), 730xd `/opt/qihse-data/node5-host`, T320
   `/opt/qihse/data/node1`.

4. Confirm failover is currently released or paused consistently across the
   cluster (`CLUSTER FAILOVER STATUS` from the healthy node) and no pending
   failback ledger exists.

## Phase 2 — sequenced owner restarts (~2–3 min total)

Order: **T420 → 730xd → T320**, one at a time, waiting for the listener
before starting the next.

```bash
systemctl restart qihse-node0        # T420 first
# poll: until ss -ltn | grep -q ":7100 "
systemctl restart qihse-node5-host   # then 730xd; poll ":7115 "
systemctl restart qihse-node1        # then T320; poll ":7101 "
```

Per-node gate immediately after its listener is up (all from T420, using
the T420 package CLI; `admin-t420` with the per-target public key pin):

```bash
pkg=/var/lib/qihse-maintenance/t420-cache-native-20261030/release-289f6080-barrier-rpath2
cli() { h=$1; p=$2; t=$3; shift 3; $pkg/run qihse-admin-cli -H $h -p $p \
  -i /etc/qihse/keys -t /etc/qihse/keys/qihse_dsa_pub_$t.pem \
  -n admin-t420 --timeout-ms 30000 "$@"; }
```

1. `CLUSTER NODES` → canonical map, `cluster_size:2` after 730xd is back.
2. `CLUSTER MAINTENANCE STATUS` → `OPEN`, all 11 `[name, registered]`
   pairs = 1, active counters 0.
3. `CLUSTER FAILOVER STATUS` → `ERR failover is paused during startup`
   (the hold is engaged).
4. `DBSIZE` sane (T420 15, T320 0, 730xd 218k and not decreasing).
5. Process identity (on the node itself): `grep -m1 libqihse.so
   /proc/$PID/maps` must show the **package** lib, and the cmdline must
   contain the package path and `--failover-start-paused`. Do not trust
   `/proc/$PID/exe` (the `run` launcher execs the loader) or
   `systemctl show -p Environment` (T320's `UnsetEnvironment=
   LD_LIBRARY_PATH` is what keeps the loader honest).

## Phase 3 — T420 caches (~2 min)

After 730xd is up and verified, restart keystone then kp14 (the drop-ins
already point at 730xd and the fresh `*-730xd-20261031` data dirs):

```bash
systemctl restart qihse-replica-keystone   # poll ":7201 "
systemctl restart qihse-replica-kp14       # poll ":7202 "
```

Gates: `REPL.STATUS` shows `source=flag` with peer `192.168.1.90` and
`sync=ok`; key-set diff against the source is empty:

```bash
cli 192.168.1.90 7115 730xd KEYS "kp14/*"      | sort > /tmp/src.keys
cli 192.168.1.91 7202 t420 KEYS "kp14/*"       | sort > /tmp/cache.keys
diff /tmp/src.keys /tmp/cache.keys && echo kp14-diff-ok
# same for keystone/* against :7201
```

Do not reuse the old cache dirs (`/opt/qihse-replica/keystone`,
`/opt/qihse-replica/kp14`) — they predate the 730xd source.

## Phase 4 — cluster gates before release (~1 min)

From T420 with `cli` above:

1. Three-node canonical map on all three hosts (`CLUSTER NODES` from
   `:7100`, `:7115`, `:7101`): 730xd owns `0-5181 5183-16383`, T420 owns
   `5182`, T320 owns none.
2. T320 export off: cmdline has `--no-replicate` and **no** `--slot-range`;
   no `replica-t420`/peer grant on T320.
3. 730xd grants: `--replication-allowed-peer replica-t420` present and
   `replica-t320` still present (cmdline grep).
4. `CLUSTER MAINTENANCE STATUS` on each: rejected SLOT_UPDATE/GROUP/
   federation counters and pending failbacks all 0.
5. Cache sources: T420 cache cmdlines contain
   `--replication-source-host 192.168.1.90`, never `192.168.1.250`.
6. Optional bus quiescence: 60 s of logs on 730xd/T420 with no new
   `REJECT`/`takes`/`slot update` churn.

## Phase 5 — release the hold (~30 s)

Authenticated Operator only, in the same order as the restarts:

```bash
cli 192.168.1.91  7100 t420  CLUSTER FAILOVER.RESUME   # +RESUMED
cli 192.168.1.90  7115 730xd CLUSTER FAILOVER.RESUME   # +RESUMED
cli 192.168.1.250 7101 t320  CLUSTER FAILOVER.RESUME   # +RESUMED
```

Then re-check `CLUSTER NODES`/`CLUSTER INFO` on all three (map unchanged,
`cluster_state:ok`) and `systemctl show` for `NRestarts=0` on all five
units.

## Expected wall time

| Phase | Time |
|-------|------|
| 0 preservation (parallel) | ~30 s |
| 1 pre-flight (parallel)   | ~1 min |
| 2 owners (T420 load ~30 s, 730xd ~15–40 s, T320 ~12 s + gates) | ~2–3 min |
| 3 caches (2 × ~45 s)      | ~2 min |
| 4 gates + 5 release       | ~2 min |
| **Total**                 | **~8 min** (parallelize phases 0/1 to shrink) |

## Rollback

- Any failed owner: `systemctl stop <unit>`, remove/rename the host's gate
  drop-in, `systemctl daemon-reload`, start — the old `/opt/QIHSE` units
  are untouched in the base files.
- Journal: T320 keeps the pre-gate backup
  `slot-ownership.journal.pre-gate-20261031`.
- Storage: the held `qhi-fastpath-pre-*` ZFS snapshots; to use one, release
  the hold first (`zfs release qhi-native-cutover-preserve <snap>`) then
  `zfs rollback -r`.
- Cache dirs `*-730xd-20261031` are disposable; the original cache dirs are
  preserved and can be re-pointed by removing the `50-source-*` drop-ins.

## Known traps

- Restarting owners concurrently (never).
- A T320 journal tail granting T320 slots (always pre-flight; see phase 1.3).
- Trusting `/proc/PID/exe` or `Environment=` instead of `/proc/PID/maps`
  for library identity.
- The hold re-engages on every restart (drop-ins carry
  `--failover-start-paused`): forgetting RESUME leaves the cluster running
  but failover-fenced.
- T420 FTS: if `fts autoload skipped` reappears, `FTS.BUILD "*"` then
  `FTS.SAVE` (index rebuilt 2026-10-31, backup under
  `/var/lib/qihse-maintenance/fts-stale-node0-20261031`).
