# Three-owner in-place rolling upgrade

The production cluster has **one active owner service per host**: T420 `qihse-node0.service` (A), T320 `qihse-node1.service` (C), and 730xd `qihse-node5-host.service` (B). The three CT successors and six read-only namespace replicas are disabled and must not be re-enabled by an ordinary upgrade. The owners, on-host ports and split B slot remain declared in `scripts/owner_only_unit.py`.

`${QIHSE_RUNTIME_ROOT}` is the service-facing runtime path. On T320 it is a symlink to the **same physical ZFS installation** at the lowercase path; that alias is not a second deployment. Do not move the mounted dataset as part of a rolling binary upgrade. The old CT-backed data directories, sealed off-host records and root-only owner-data backups are rollback evidence, **not** active installations. This owner-only mode does not provide off-host CT durability.

## Git-first, one host at a time

1. Push the signed change to `main`, then fast-forward the source checkout on each host with `git pull --ff-only origin main`. Leave the running runtime untouched until that host's native build passes. The source checkout may be separate from the runtime directory.
2. Build on each host with `make build-native`. On a GCC installation that needs the system BFD linker for both linkers, use `make build-native CC='gcc -fuse-ld=bfd' CXX='g++ -fuse-ld=bfd'`. Test the matching new daemon and library with `ldd -r` before replacing either. Keep a host-local copy of the previous runtime files; replace the daemon, CLI and library together via temporary files and atomic renames. Never copy a library from another host's native build.
3. From that host's source checkout, run the manifest check as root, with `a` on T420, `c` on T320, or `b` on 730xd:

   ```sh
   PROJECT_ROOT="$(git rev-parse --show-toplevel)"
   sudo env QIHSE_OWNER_DATA_ROOT="$(dirname "$PROJECT_ROOT")/qihse-data" \
       python3 "$PROJECT_ROOT/scripts/owner_only_unit.py" a --check
   ```

   Substitute the host's label. The check validates the existing CT-disabled store and compares the complete effective owner command against the Git-declared three-host topology; it does not restart or write anything. If an override is absent, `--install` may create it **only after** its owner-only data store has been independently restored and verified. A divergent existing override fails closed for manual review; do not delete it merely to force an install.
4. If binaries or the unit changed, restart **only that host's owner**, then use an authenticated, server-pinned Operator QKP session to confirm `CLUSTER NODES` (three connected owners, identical views, each of 16,384 slots owned exactly once), `DBSIZE`, and a scoped write/read/delete on its owned slots. Check the installed executable and mapped library. Proceed to the next host only after these pass. If the build and installed configuration are byte-identical, do not restart the service just to mark the pull complete.
5. Confirm the three owner units are enabled; all nine CT-successor/namespace-replica units must be disabled and inactive. Preserve the old protected stores and previous-runtime backups for explicit recovery.

## Compatibility and storage

The versioned owner-only manifest does not change the QKP protocol or on-disk format. **No additional stored-data migration or reindex is required** for this configuration-only upgrade: the currently active owner-only stores were previously populated using authenticated `BACKUP_OWNER_DATA` exports into fresh CT-disabled directories. A future host without those stores must follow an authenticated, quiesced owner-data backup/restore procedure before installing the owner-only unit. Do not point the owner-only unit at an old CT-enabled store or delete its CT state by hand.

Focused validation: `make test-owner-only-unit`, `make check`, and the affected backup/cluster tests. Follow the operator's test-duration instructions; do not imply a full suite ran when it did not.
