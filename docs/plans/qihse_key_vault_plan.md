# QIHSE Key Vault — Password-Bound Unlock-Key Storage with Fleet Sync

> **Status: PLANNED — design only, not yet implemented.** No vault code exists
> in this tree as of this writing; every section below is a proposal. Existing
> primitives named in §2 were verified in-tree and are the intended reuse
> points. This plan follows AGENTS.md invariants: security-context-bearing
> read paths (§10), no principal escalation, a negative authorization test for
> the new RESP adapter (§11), and relative paths only.

**Scope:** Store unlock-key material (disk passphrases, SSH keys, agent
capability keys, API secrets) as records in the local QIHSE KV database, with
decryption **bound to a password that itself lives in the same database**, and
**synchronized across every machine running QIHSE** so any enrolled PC can
unlock without a manual password entry. The vault is a tenant-scoped KV
keyspace plus a RESP command surface; it does not introduce a second storage
engine.

---

## 1. Problem and requirements

The fleet runs QIHSE everywhere and syncs (sync/qihse_crdt.c,
sync/qihse_sync_gossip.c). Unlock keys must:

1. Live in the local QIHSE DB (`qihse.db` / `data.qdb`), not in ad-hoc files.
2. Unlock (decrypt) **bound to a password stored in that same DB**, so a
   machine can resolve the binding locally instead of prompting the operator.
3. Sync across all PCs: a key wrapped on machine A is unlockable on machine B,
   and a key revoked on A disappears on B.
4. Never expose plaintext key material in the DB file, in sync traffic, in the
   audit log, or in the FTS/vector indexes.
5. Support rotation of the binding password, enrollment of a new machine, and
   eviction of a lost machine, each as cheap sync operations.

## 2. Existing primitives this builds on

| Primitive | In-tree source | Vault use |
| --- | --- | --- |
| PBKDF2-HMAC-SHA384 password KDF | `qihse_password_compute()`, `core/qihse_auth.c` | Binding password → KEK |
| ML-KEM-1024 encapsulation | `qihse_pqc_encapsulate_peer()` / `qihse_pqc_decapsulate_peer()`, `persistence/qihse_pqc_crypto.h` | Per-machine envelope of the binding password |
| Machine identity keys | `tools/qihse_keygen.c`; identity dir (`qihse_kem_key.pem`), optional YubiKey PIV via `--bind-operator` | Envelope recipients; never synced |
| MACHINEAUTH tokens | `tools/qihse-machine-token.c` | Authenticate fleet agents for enroll/evict |
| CRDT + gossip sync | `sync/qihse_crdt.c`, `sync/qihse_sync_gossip.c` | Record replication, tombstones |
| KV namespaces + NOPERM | `SCHEMA.md` (`t:<tenant>/...` prefixes) | `t:<id>/vault/...` keyspace |
| Audit / quota / rate limit | `core/qihse_audit.h`, `core/qihse_quota.c`, `core/qihse_rate_limit.c` | Unlock auditing, size caps, unwrap throttling |
| UWP TLS transport | `docs/security/UWP_CRYPTO_DESIGN.md` | Plaintext material only ever in-channel |
| Integrity chain / backups | `qihse_integrity.chain`, `tools/qihse_backup_cli.c` | Vault records are covered like any record |

## 3. Key hierarchy (envelope design)

```text
binding password (record t:<id>/vault/passwd, wrapped per machine)
   | PBKDF2-HMAC-SHA384 (salt + iters from the VMK record)
   v
KEK (32 B, derived per unlock, never stored)
   | AES-256-GCM unwrap
   v
VMK  vault master key (32 B random, record t:<id>/vault/vmk/<version>)
   | AES-256-GCM, one AEAD per record
   v
key records  t:<id>/vault/key/<label>  (the actual unlock keys)
```

Two layers, both sync-safe, nothing plaintext at rest or on the wire:

- **Layer 1 — password at rest.** The binding password is a DB record, but it
  is stored as **one ML-KEM-1024 envelope per enrolled machine**:
  `envelope_i = { machine_id, kem_ct, pw_ct }` where `kem_ct` encapsulates a
  fresh 32-byte transport key `tk_i` to machine i's KEM public key and
  `pw_ct = AES-256-GCM(tk_i, password)`. Each machine decapsulates with its
  **local** private KEM key and recovers the password from its own DB copy.
  This is what makes "password stored in the local QIHSE DB" true without
  storing it in plaintext: the record is local, machine-readable, and useless
  to anyone without an enrolled machine's private key.
- **Layer 2 — keys under the password.** All key records are AEAD-wrapped
  under a single VMK, and the VMK record is wrapped under the
  password-derived KEK. **Password rotation rewraps exactly one record**
  (`vault/vmk/<new version>`); key records are untouched. VMK rotation
  (rarer) rewraps all key records under a new VMK version.

Why not wrap each key directly under the password: rotation then costs
O(records) rewraps and forces every synced machine to hold the password in
memory for the whole sweep. The VMK indirection keeps the password on the
critical path only for one small record.

## 4. KV schema additions

All records are JSON strings in the existing KV store, under the tenant
namespace so engine-side NOPERM applies. Proposed prefix registration in
SCHEMA.md:

| Key | Purpose | Shape |
| --- | --- | --- |
| `t:<id>/vault/passwd` | Binding password, per-machine envelopes | `{v, kdf:{alg,salt_b64,iters}, envelopes:[{machine_id, kem_ct_b64, pw_ct_b64, added_at, added_by}]}` |
| `t:<id>/vault/vmk/<version>` | VMK wrapped under the KEK | `{v, version, kdf:{alg,salt_b64,iters}, nonce_b64, ct_b64, created_at}` |
| `t:<id>/vault/key/<label>` | One unlock key | `{v, label, alg:"AES-256-GCM", nonce_b64, ct_b64, key_type, scope, machines:[ids or "*"], origin_machine, created_at, vmk_version}` |
| `t:<id>/vault/manifest` | CRDT-merged index | `{labels:{<label>:{record_hash, vmk_version, deleted, ts, last_machine}}}` |

Notes:

- Key records are **immutable**; any change (rotation, scope edit) writes a
  new `vmk_version`/`record_hash` and bumps the manifest entry. Sync conflicts
  resolve on `(vmk_version, ts)` — see §7.
- `machines` optionally binds a key to a machine subset (e.g. a laptop-only
  disk key); `*` (default) means every enrolled machine may unwrap.
- Envelope arrays and record decoding must follow the bounded-frame rules in
  AGENTS.md: one reusable heap buffer, `goto done` cleanup, validate declared
  lengths against both encoded and algorithm-fixed sizes (`kem_ct` is exactly
  `QIHSE_MLKEM_CIPHERTEXT_SIZE`).

## 5. Unlock flow

```text
client                         QIHSE daemon (this machine)
  |  AUTH / MACHINEAUTH            |
  |------------------------------->| verify session (existing path)
  |  VAULT.UNLOCK <label>          |
  |------------------------------->| 1. load t:<id>/vault/passwd (tenant-scoped, NOPERM-checked)
  |                                | 2. pick envelope[machine_id == self]
  |                                | 3. qihse_pqc_decapsulate_peer() -> tk_i
  |                                | 4. AES-256-GCM open pw_ct -> binding password
  |                                | 5. PBKDF2(vmk record kdf params) -> KEK
  |                                | 6. unwrap VMK <version>
  |                                | 7. unwrap t:<id>/vault/key/<label>
  |                                | 8. qihse_audit_log("vault.unlock", ...label only)
  |<-------------------------------| 9. return key material (in-channel, UWP TLS)
```

- Steps 2–7 are in-daemon; the password exists in process memory only between
  steps 4 and 5 and is zeroized immediately after derivation.
- The KEK is derived per unlock; it is cached only behind the existing
  short-TTL auth-cache pattern from `core/qihse_auth.c` (password-equivalent
  secret, best-effort clear, invalidated on any vault write). `VAULT.UNLOCK
  --no-cache` bypasses caching for one-shot use.
- Result material is delivered to the **authenticated session** only. A
  `--quiet` form returns a handle for in-daemon consumers (e.g. an agent that
  needs the key without ever receiving the bytes over the wire).

## 6. RESP command surface

Following the AIMEM RESP conventions (docs/architecture/aimem_resp_protocol.md):
every command requires an authenticated session; every command audits; the
`vault/*` keyspace is refused for non-vault verbs at the same dispatch layer
that enforces tenant prefixes.

| Command | Auth | Effect |
| --- | --- | --- |
| `VAULT.SET <label> <key_type> <scope>` + payload | operator or delegated tenant write | Wrap under VMK, upsert record + manifest |
| `VAULT.GET <label>` | any authenticated tenant read | Returns record **metadata** (never plaintext) |
| `VAULT.UNLOCK <label> [--quiet] [--no-cache]` | authenticated tenant read | §5 flow; rate-limited |
| `VAULT.LIST [pattern]` | authenticated tenant read | Manifest labels + metadata |
| `VAULT.ROTATE_PASSWORD` | operator | New password → new `vmk/<version>` → rewrap envelopes for all machines |
| `VAULT.ENROLL <machine_kem_pub_b64>` | operator, from an enrolled machine | Add envelope; sync |
| `VAULT.EVICT <machine_id>` | operator | Drop envelope; machine-bound keys become non-unlockable there |
| `VAULT.REVOKE <label>` | operator / delegated write | Manifest tombstone; record GC after grace |
| `VAULT.RECOVERY_EXPORT` | operator | Offline break-glass: VMK wrapped under a printed recovery key |

## 7. Sync semantics

- Each vault record upsert feeds the existing CRDT
  (`qihse_crdt_upsert(vector_id, timestamp, is_deleted, hash)`); the manifest
  is the merge surface, so gossip traffic carries wrapped records and hash
  vectors only.
- Records are immutable per version, so there are no in-place mutation
  conflicts: a newer `vmk_version` supersedes an older one regardless of
  arrival order, and the manifest entry keeps `(record_hash, vmk_version, ts)`.
  Tombstones (`deleted:true, ts`) win over any older-timestamp write for the
  same label — LWW on the CRDT timestamp, not on the payload.
- **Ordering rule:** a machine must not unwrap with an envelope or VMK older
  than its manifest's `vmk_version`; if records race during a rotation, the
  manifest forces convergence to the newest VMK version, and old versions are
  GC-able after a grace window (default 24 h, configurable).

## 8. Ceremonies

**Enroll a new PC.** On the new machine: `qihse_keygen` into its identity dir
(mode 0600, never synced, never in the DB). Present `qihse_kem_pub.pem` to an
operator-authed session on an already-enrolled machine:
`VAULT.ENROLL <pub>` → daemon encapsulates a fresh `tk_new` to that pub,
re-encrypts the password into a new envelope, syncs. The new machine can now
unlock everything `machines:"*"` allows after one gossip round.

**Rotate the binding password.** `VAULT.ROTATE_PASSWORD`: mint a new VMK
version, rewrap the VMK record under the new KEK, re-encapsulate envelopes for
every enrolled machine, bump manifest. Cheap: one record + N envelopes; key
records untouched.

**Recover (break-glass).** `VAULT.RECOVERY_EXPORT` prints a one-time recovery
key (32 B, hex/QR) that wraps the current VMK; store it offline. Any single
enrolled machine (or a bare DB backup plus the recovery key) can re-derive the
VMK and rebuild envelopes after fleet loss. Requires operator AUTH — never
machine tokens.

**Evict a lost machine.** `VAULT.EVICT <machine_id>`: drop its envelope,
rotate the password (belt and braces — the evicted machine may hold a cached
KEK until its TTL), tombstone machine-bound keys.

## 9. Hardening

- **Indexes:** the `t:*/vault/*` keyspace is excluded from FTSIndex
  (`qihse_fts_map.json`) and VectorDB — ciphertext adds nothing to BM25 and
  metadata labels must not leak into semantic search results.
- **Rate limit:** `VAULT.UNLOCK` goes through `core/qihse_rate_limit.c` with a
  per-tenant budget; unwrap failures are audited and escalate to lockout,
  reusing the account-lockout semantics from the AUTH path.
- **Quota:** vault records count against `core/qihse_quota.c` per tenant;
  manifest size caps bound the envelope count.
- **Audit:** `qihse_audit_log` records session, machine, label, and outcome —
  never key material, never the password. `classif`/`sci` flow from the
  session so vault access follows the existing classification model.
- **Memory hygiene:** VMK and derived KEKs live in `mlock`ed pages, zeroized on
  free and on rotation; the password is never written to any log, env, or the
  audit webhook path.
- **Filesystem:** DB files already 0600/0700; identity private keys stay
  outside the DB in the identity dir, 0600, and are never synced — only public
  keys travel.
- **Transport:** plaintext material exists only inside the UWP TLS channel of
  the unlocking session; sync carries wrapped records only.

## 10. Invariant compliance (AGENTS.md)

- §1 security context: every vault read (GET/UNLOCK/LIST) takes the
  authenticated user context from the session; no context-free raw KV read of
  `vault/*` is exposed to any adapter. The keyspace is additionally refused to
  non-vault verbs at the same dispatch layer that enforces tenant prefixes.
- §2 no escalation: `VAULT.ENROLL`/`EVICT`/`ROTATE` are operator-only; machine
  tokens cannot mint envelopes for other machines.
- §3 negative test: `tests/test_vault_resp_neg.c` (§11) authenticates a
  low-clearance principal, places a vault record at higher clearance, and
  asserts `NOPERM` with no ciphertext or plaintext disclosure across the
  normal path, direct label lookup, LIST enumeration, and the manifest read.

## 11. Implementation plan

New code (proposed layout mirrors `core/` + `tests/` conventions):

| File | Contents |
| --- | --- |
| `core/qihse_vault.{c,h}` | Envelope logic, KEK/VMK derivation, wrap/unwrap, zeroization |
| `core/qihse_vault_sync.c` | CRDT upserts, manifest merge, GC grace window |
| RESP dispatch additions | `VAULT.*` verbs beside the AIMEM handlers |
| `tests/test_vault_wrap.c` | Envelope + AEAD round-trips, tamper rejection, envelope-evict |
| `tests/test_vault_sync.c` | Concurrent rotation/enroll merges, tombstone-vs-late-write |
| `tests/test_vault_resp.c` | Happy-path AUTH → SET → UNLOCK over a loop listener |
| `tests/test_vault_resp_neg.c` | §10 negative authorization test (CI-blocking) |

Make targets: `test-vault-wrap`, `test-vault-sync`, `test-vault-resp`,
`test-vault-resp-neg`, mirroring the `test-task-*` pattern. SCHEMA.md gains
the §4 table; docs/architecture/ gains `vault.md` when implementation lands.

## 12. Threat model honesty

**Protected against:** DB-file exfiltration (ciphertext only), sync-path
observation (TLS + wrapped records), cross-tenant access (NOPERM), brute
force (PBKDF2 + rate limit + lockout), lost machine (envelope eviction +
password rotation).

**Not protected against:** root on an enrolled machine — it holds the KEM
private key, the DB, and the daemon, so it can unwrap anything `machines:"*"`
allows. That is inherent to the stated requirement ("all my PCs unlock"), and
the mitigations are operational: keep the envelope set minimal, use
machine-bound keys for the most sensitive labels, and prefer YubiKey/PIV-backed
machine identity (`qihse_keygen --bind-operator` pattern) so the private key
never sits on disk unencrypted.

**Future work:** Argon2id for the KEK KDF (PBKDF2-HMAC-SHA384 is chosen here
purely for consistency with the existing AUTH verifier); TPM sealing of the
per-machine transport key; per-record ACLs beyond `machines`.
