# Principal migration and recovery

**Deployment gate: activation is blocked by the current LAN ownership and GC
conflict. No primary has been stopped or replaced. This runbook does not authorize
DIRECTEYE or production SQL changes and does not claim operational rollout.**

## 1. Capability first; never restart to discover support

Authenticate to the running source through its supported administrative
transport and discover its principal-maintenance capability before planning
an export. The source contract is `include/qihse_auth_maintenance.h`:
`qihse_auth_maintenance_capabilities(actor, &caps)` reports authority mode,
readiness, export/import/checkpoint support and the exact current position.
Require the specific operation to be supported and ready. Presence of a new
header, library or CLI on disk proves nothing about an old running process.

An old running binary with no supported maintenance export is **unsupported
for lossless live principal migration**. Preserve it running and report the
blocker. Do not restart it to load new code: its authoritative accounts may
exist only in memory. Do not substitute `/proc` memory extraction, debugger
attachment, `objdump`, guessed struct layouts, SQL account rows, fake root
objects or `NULL` context reads. Recreating accounts from independently held
credentials/policy would be a separate, explicitly approved reprovisioning
operation, not a lossless migration.

## 2. Prepare an isolated destination and coherent recovery set

- Record source authority/history/node/epoch/generation and intended target
  authority/position. Standalone is permanent local authority, not a consensus
  prefix or an automatic fallback. Unsupported consensus mode must fail closed.
- Preserve the exact binary/library/configuration and one coherent durable
  state generation, private bootstrap verifier file, recipient/signing keys
  and independently verified SHA-384 SPKI pins. Keep keys separately protected
  but associated with that recovery set. Retain the trusted minimum generation
  and expected history outside an accidental snapshot rollback where possible.
- Provision/recover only through the protected pre-serve startup API. Use a
  private, single-writer state directory and dedicated isolated ports with no
  production clients or replication/GC ownership. Never point two processes
  at the same authority directory. A cloned directory on another host is not
  fenced by the source's local file lock.
- Rehearse on an isolated coherent clone before touching the source. Verify
  restored identity, tenant/role/clearance/SCI, ACL, verifier, hardware-token
  requirement/credential, tombstones and lockout state, including denied access
  by lower-clearance principals. Sessions, cached authentication and prior
  hardware-token presence must not be restored.

### Cold-start identity when root requires HWT

Before requiring hardware-token authentication on root, prepare and durably
enroll an independently credentialed, explicitly approved full-clearance/SCI
system Operator service identity. This is an existing account, not automatic
elevated account provisioning by the daemon. Preserve its own protected
password as part of operational recovery preparation. Root HWT policy remains
unchanged, and recovered hardware-token presence is always cleared.

Both daemons accept `QIHSE_AUTH_STARTUP_USER_ID` only for durable standalone
`recover`: strict decimal `1..65535`, with no sign or whitespace. Unset retains
legacy UID 0 selection; an explicitly empty/zero/malformed value fails. Provision
requires UID 0 (leave the variable unset), and volatile mode rejects selection.
On recover, the existing protected captured `QIHSE_OPERATOR_PASSWORD` buffer
contains the **selected identity's own password**, not necessarily root's. The
daemon authenticates that exact ID and checks active system Operator authority,
classification/SCI masks both `65535`, required HWT proof and current readiness.
Missing, revoked, locked-out, wrong-password, insufficient-clearance/SCI or
HWT-unproven identities fail with no fallback. The actual authenticated actor
is passed to privileged constructors, never a fabricated/root lookup or `NULL`.

A password-only cold start cannot supply fresh root HWT proof. If root requires
it, select the already enrolled authorized service Operator and its password;
do not disable root HWT, overwrite root credentials, or reset token policy. An
HWT-required selected service identity without proof also fails. Selection does
not waive the explicit bootstrap/key/pin/history/minimum-generation recovery
requirements above. Never include either password in plaintext logs.

## 3. Export/import with explicit bindings

Exact RESP/QKP grammar and the 253-byte descriptor layout are in
[API_REFERENCE.md §7.1](API_REFERENCE.md#respqkp-maintenance-grammar).
The descriptor contains pinned source/target bindings, never daemon host paths.
For an isolated rehearsal, normal QKP transport/authentication options precede
one maintenance operation, for example:

```sh
./qihse-admin-cli --host "$SOURCE_HOST" --port "$SOURCE_PORT" \
  --identity-dir "$CLIENT_IDENTITY" --trusted-pub "$SOURCE_PIN" \
  --user "$OPERATOR" --password-env OPERATOR_SECRET --authority-capabilities
./qihse-admin-cli --host "$SOURCE_HOST" --port "$SOURCE_PORT" \
  --identity-dir "$CLIENT_IDENTITY" --trusted-pub "$SOURCE_PIN" \
  --user "$OPERATOR" --password-env OPERATOR_SECRET \
  --authority-export ./principal-transfer.sealed --expected-position "$SOURCE_POSITION" \
  --transfer-config ./transfer-descriptor.bin
./qihse-admin-cli --host "$TARGET_HOST" --port "$TARGET_PORT" \
  --identity-dir "$CLIENT_IDENTITY" --trusted-pub "$TARGET_PIN" \
  --user "$TARGET_OPERATOR" --password-env TARGET_OPERATOR_SECRET \
  --authority-import ./principal-transfer.sealed --expected-position "$TARGET_POSITION" \
  --request-id "$REQUEST_ID" --transfer-config ./transfer-descriptor.bin
```

These are templates, not live execution. Discover target capabilities too;
require export on source and import on target. Keep descriptor/archive files
private (owner-only regular files). Export is create-only and must not overwrite
an existing output. Retain the original positions and descriptor for a retry.
The wire path supports one ciphertext of at most **8 MiB**, not the C API's
160 MiB ceiling. Larger transfers are unsupported on this wire path: no
truncation, session handle, resumability or undocumented memory fallback.

Configure explicit server-side `TRANSFER_*` keys/pins separately from local
state keys (see [OPERATIONS.md](OPERATIONS.md#daemon-startup-configuration-source-contract)).
The source needs recipient-public/signer-private; the target needs
recipient-private/signer-public. Target preparation uses the same explicit
authority/history/epoch and a distinct node only with relocation allowed.
Import rejects a foreign authority/history, stale source generation and a
mismatched expected target position; it is not a general older-snapshot restore.

Live maintenance requires an authenticated authoritative system Operator with
full clearance/SCI, verifier and required hardware-token presence. Offline
recovery uses only the opaque capability returned by protected startup.
`qihse_auth_maintenance_export()` returns bounded ciphertext through
`qihse_auth_sealed_data/size`; release it with `qihse_auth_sealed_free()`.
The archive configuration explicitly names recipient/signer key files and pins,
source and target authority/position, purpose and archive ID. Do not silently
reuse local durable-state wrapping keys as transfer trust.

Import uses `qihse_auth_maintenance_import()` or the protected
`qihse_auth_maintenance_recover_import()`, an exact expected target position,
a nonzero 16-byte request ID, explicit transfer binding and the original sealed
bytes. It commits a new local generation; it does not replace protected UID 0,
resurrect tombstones, or provide a hardware-token relaxation mechanism.
Persist the request ID, original expected position, binding, ciphertext digest
and returned position in the operator's recovery record. Treat all state and
archives as secret-bearing, even when encrypted.

## 4. Lost ACK, crash and coherent recovery

On a lost ACK, retry the identical import, including its original expected
position, request ID, binding and ciphertext, using the same authenticated
actor identity/generation or the same authorized recovery route. The durable
receipt returns the recorded result; conflicting reuse fails. A changed
current generation is not proof that this request committed. Do not generate
a second request ID, delete receipts, or retry a different archive as a shortcut.

After an I/O or uncertain commit result, fence service and retain evidence.
Recover the coherent authority using the configured history/node/epoch and
minimum generation; never automatically initialize an empty registry, remove
an unexplained pending file, substitute an older state file, or combine keys,
bootstrap and snapshots from different recoveries. A state-directory lock is
local fencing only. This is crash consistency, **not entire-volume rollback
protection**: rolling back all local state and its configured floor can restore
older coherent authority without a separate trusted monotonic witness.

## 5. Cutover and rollback restrictions

Cutover remains blocked until LAN ownership/GC conflicts are resolved. For an
approved later cutover, fence source writers and all replication/GC paths,
capture the final supported coherent state, verify destination recovery and
authorization checks in isolation, then transfer client ownership exactly once.
Require fresh authentication and hardware-token validation after transition.
Before new writes, reverting routing still requires fencing the destination.
After any new principal or application writes, an old snapshot/source is not a
safe rollback: it can lose accounts, revocations, receipts or data. Reconcile
under a separately approved forward-recovery plan; never run both authorities
or silently rewind accepted writes.
