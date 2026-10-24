# Slot Migration over Pinned QKP — Implementation Plan (4.1)

> Corrects the roadmap premise. The "pinned QKP replication" that landed is
> the **one-way read-only replica pull**; the `--brain-act` gate names a
> *different* path — **data-bearing slot push between masters**. The gate is
> correct as-is and must not be removed until that transport is swapped.

## Where the gate is

`tools/qihse_cluster_daemon.c:1511-1513` — pure early `return 2`. Internally
the brain already honors `act` (`src/spinnaker/qihse_cluster_brain.c:1549`).

## What "pinned QKP for slot migration" actually requires

`qihse_cluster_handoff_range()` (`src/spinnaker/qihse_resp_engine.c:11178`) is
the shared migration path the brain actuates through. For a **non-empty**
range it currently uses legacy cleartext auth:

- requires `server->cluster_migrate_password` (`:11230`) else refuses with
  `"target authentication unavailable"` **before changing ownership**
  (`:11228-11233`);
- plain TCP `qihse_resp_connect_timeout` (`:11238`) + RESP `AUTH` (`:11252`);
- per-key `ASKING`/`SET` (`:11272/:11295`) then local drop (`:11297`).

## Status of the pieces

| Piece | State |
|---|---|
| Brain observe/journal/decide + actuation (R1/R4/R5/R6) | exists, gated |
| `handoff_range` / `set_range_owner` / `range_has_local_keys` | exists |
| Slot ownership transitions (MIGRATING/IMPORTING/STABLE) | exists |
| `CLUSTER MOVESLOTS` + system-domain authz | exists |
| Pinned QKP **replica pull** | exists (wrong path for this) |
| Pinned QKP **slot-push transport** (replace `cluster_migrate_password`) | **MUST BE WRITTEN** |
| Authenticated `qihse_user_t *` context on enumeration/target writes | **MUST BE WRITTEN** (invariant #1) |
| Strand-free recovery (publish ownership only after durable data) | **MUST BE WRITTEN** (CT.2) |

## Order of work

1. Extend daemon/server config with a pinned QKP peer identity per
   slot-transfer target (parallel to `replication_peer_*`, `include/qihse_qkp.h:145`).
2. Add an authenticated enumeration primitive (explicit `qihse_user_t *`) for
   `range_has_local_keys` / `moveslots_collector_t` — invariant #1.
3. Replace the legacy `AUTH`/`ASKING`/`SET` data path in `handoff_range` with a
   pinned QKP session (reuse `qihse_qkp_client_session_is_replication_peer`),
   carrying the authenticated context to target writes.
4. Recovery: publish `set_range_owner(target)` only after the target ACKs
   durable data; reconcile/rollback partial transfers (brain R4 exists at
   `qihse_cluster_brain.c:1675`).
5. Tests (invariant #3): low-clearance/high-data negative (no payload
   disclosure), partial transfer, target failure mid-stream, reconnect,
   rollback, classification/SCI denial, concurrent writes.

This is a multi-step security-critical implementation, not an ungate.
