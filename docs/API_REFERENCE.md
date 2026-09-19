# QIHSE API Reference

> **Status: implemented** — every C function in this reference is declared in a
> header under `include/` and is exported by the built `libqihse.so`; the Python
> surface is read from `python/qihse/`. Nothing here is transcribed from a design
> document. The sections that describe something not built are marked `planned`
> or `partial` in place ([§12](#12-known-gaps-and-unverified-areas)).
>
> **Coverage.** The original nine headers of the federation data plane are
> covered in [§1](#1-federation-core--includeqihse_federationh)–[§7](#7-security-and-authentication--includeqihse_authh).
> [§8](#8-additional-public-c-surfaces) adds the public surfaces that were
> outside that set when this reference was first written: replication apply,
> the table-store DML primitives, parallel query, AI memory, the KEYSTONE change
> feed, the MongoDB wire adapter, and the derived cluster-node federation UUID.

This is the reference surface for the public C API, the Python SDK, protocol
compatibility, and configuration knobs. It is deliberately narrower than the
whole repository: it covers the federation data plane, snapshots, rejoin,
replication, transport/mTLS, the key-value store, and security/authentication,
because those are the surfaces an operator or controller is expected to call.

Status vocabulary used across the documentation tree is defined in
[`docs/README.md`](README.md#documentation-status-labels).

## How this reference was verified

Every function named below was checked against the header that declares it, and
the header list was checked against the built shared object:

```
nm -D --defined-only libqihse.so | awk '{print $3}' | sort -u
```

The nine headers of [§1](#1-federation-core--includeqihse_federationh)–[§7](#7-security-and-authentication--includeqihse_authh)
declare 252 `qihse_*` functions between them, and 249 of those resolve to a
symbol in `libqihse.so`. The three that do not are the expected exception:
`qihse_kv_get()`, `qihse_kv_del()` and `qihse_kv_exists()` are `static inline`
wrappers in `include/qihse_kv_store.h`, so they compile into the caller rather
than appearing as library symbols. [§8](#8-additional-public-c-surfaces) adds
the remaining public headers on the same terms. There is no header-only
declaration in any of these areas. That is a stronger statement than "the
source file exists", so a function that appears here is safe to call; a
function that does not appear here has not been verified and should be read in
its header first.

The per-header split, as counted by the command above:

| Header | Declared | Exported |
|---|---|---|
| `include/qihse_federation.h` | 118 | 118 |
| `include/qihse_federation_mtls.h` | 8 | 8 |
| `include/qihse_federation_repl.h` | 13 | 13 |
| `include/qihse_federation_transport.h` | 15 | 15 |
| `include/qihse_federation_rejoin.h` | 6 | 6 |
| `include/qihse_operations.h` | 23 | 23 |
| `include/qihse_backup.h` | 9 | 9 |
| `include/qihse_kv_store.h` | 26 | 23 (3 `static inline`) |
| `include/qihse_auth.h` | 34 | 34 |

## Conventions

- **Security context.** Federation entry points take `void* store_void` (a
  `qihse_kv_store_t*`) and `void* user_void` (a `qihse_user_t*`). The `void*`
  typing is deliberate: `include/qihse_federation.h` does not include the KV or
  auth headers. `user_void` is an authenticated principal, and passing `NULL` is
  rejected by every entry point that documents an explicit user, per
  `AGENTS.md` invariant 1. Do not cast a context-free call into one of these.
- **`NULL` is never an authorization bypass.** Verified in the implementations:
  `qihse_infra_scope_check(NULL, ...)` returns `false`
  (`src/federation/qihse_federation.c`), `qihse_auth_can_access_object(NULL, ...)`
  returns `false`, and `qihse_auth_can_access(NULL, classified, ...)` returns
  `false` while `(NULL, 0, 0)` deliberately allows unclassified data
  (`core/qihse_auth.c`). The context-free KV forms are restricted to
  unclassified data rather than unrestricted.
- **Failure values.** Functions returning `bool` return `false`; functions
  returning a pointer return `NULL`; functions returning a count or offset
  return `0`; functions returning an enum return the "reject"/"error" member of
  that enum. Where a failure has a more specific meaning (for example
  `qihse_federation_watch_next()` returning `false` at end-of-journal rather
  than on error), the specific meaning is stated in the table.
- **Required arguments.** Unless stated otherwise, every function in this
  reference rejects a `NULL` required argument by returning its failure value.
- **Ownership.** Functions that return `char*` transfer ownership of a
  heap allocation to the caller (`free()` it). Functions returning opaque
  handles are released by the matching `_destroy`/`_close`/`_free` function
  named in the same section.
- **Persistence keys.** Federation state is stored in the caller-supplied KV
  store under documented prefixes; see [§11](#11-configuration-knobs) for the
  prefix inventory. Nothing in this API opens its own database.

---

## 1. Federation core — `include/qihse_federation.h`

Source: `src/federation/qihse_federation.c`.
Tests: `tests/test_federation_f0.c` (F0), `tests/test_federation_f1.c` (F1),
`tests/test_federation_f2.c` (F2), `tests/test_federation_f3.c` (F3),
`tests/test_federation_f4.c` (F4), `tests/test_federation_f5.c` (F5),
`tests/test_federation_f8.c` (deterministic scenarios),
`tests/test_federation_bus_trust.c` (bus trust), `tests/test_federation_fuzz.c`
(wire and persisted parsers).

### 1.1 F0 — identity, time, version, fencing

| Function | Purpose | On failure |
|---|---|---|
| `bool qihse_uuid_generate(qihse_uuid_t* out)` | Generate a random UUID. | `false` |
| `bool qihse_uuid_from_seed(const void* seed, size_t seed_len, qihse_uuid_t* out)` | Deterministic SHA-384-derived UUID; same seed yields the same UUID on every node. | `false` |
| `bool qihse_uuid_parse(const char* text, qihse_uuid_t* out)` | Parse `"8-4-4-4-12"` text. | `false` on malformed input |
| `bool qihse_uuid_format(const qihse_uuid_t* id, char out[37])` | Render a UUID as text. | `false` |
| `bool qihse_uuid_is_nil(const qihse_uuid_t* id)` | All-zero test. | `false` if `id` is `NULL` |
| `bool qihse_uuid_equal(const qihse_uuid_t* a, const qihse_uuid_t* b)` | Equality. | `false` if either is `NULL` |
| `void qihse_hlc_init(qihse_hlc_t* clock)` | Zero-initialise a hybrid logical clock. | n/a |
| `void qihse_hlc_tick(qihse_hlc_t* clock, qihse_hlc_t* out)` | Next local event; strictly greater than any prior tick or observed remote stamp. | n/a |
| `void qihse_hlc_observe(qihse_hlc_t* clock, const qihse_hlc_t* remote)` | Receive path: advance past a remote timestamp. | n/a |
| `int qihse_hlc_compare(const qihse_hlc_t* a, const qihse_hlc_t* b)` | Total order across nodes (`-1`, `0`, `+1`). | n/a |
| `uint64_t qihse_hlc_pack(const qihse_hlc_t* clock)` | Sortable 48-bit ms + 16-bit counter encoding. | `0` if `clock` is `NULL` |
| `void qihse_hlc_unpack(uint64_t packed, qihse_hlc_t* out)` | Inverse of `_pack`. | n/a |
| `void qihse_object_version_init(qihse_object_version_t* v, const qihse_uuid_t* object)` | Initialise a generation-tagged object version. | n/a |
| `void qihse_object_version_bump(qihse_object_version_t* v, qihse_hlc_t* clock)` | Next generation, stamped with the clock's next tick. | n/a |
| `int qihse_object_version_compare(const qihse_object_version_t* a, const qihse_object_version_t* b)` | Order by generation, HLC as tie-break. | n/a |
| `void qihse_fencing_token_init(qihse_fencing_token_t* token)` | Initialise a fencing token. | n/a |
| `bool qihse_fencing_acquire(qihse_fencing_token_t* token, uint64_t observed_epoch, const qihse_uuid_t* holder)` | Acquire exclusive state; succeeds only when `observed_epoch` is strictly older, and always advances the epoch. Fails closed. | `false` (stale observation) |
| `bool qihse_fencing_valid(const qihse_fencing_token_t* token, uint64_t observed_epoch)` | Is this token still the highest observed? | `false` |

### 1.2 F1 — consistency classes, namespaces, status

| Function | Purpose | On failure |
|---|---|---|
| `const char* qihse_consistency_class_name(qihse_consistency_class_t c)` | `"LOCAL"`, `"EVENTUAL"`, … | `NULL` for an invalid class |
| `bool qihse_consistency_class_parse(const char* name, qihse_consistency_class_t* out)` | Parse a class name. | `false` on unknown |
| `bool qihse_consistency_class_is_local_safe(qihse_consistency_class_t c)` | May an isolated node keep serving this class? | `false` |
| `bool qihse_consistency_class_is_strong(qihse_consistency_class_t c)` | Does this class require peer agreement? | `false` |
| `const char* qihse_federation_state_name(qihse_federation_state_t s)` | `"CONNECTED"`, `"DEGRADED"`, … | `NULL` |
| `bool qihse_federation_state_parse(const char* name, qihse_federation_state_t* out)` | Parse a federation state. | `false` |
| `const char* qihse_local_db_state_name(qihse_local_db_state_t s)` | `"read-write"` / `"read-only"`. | `NULL` |
| `bool qihse_federation_namespace_writable(const qihse_federation_namespace_t* ns, qihse_federation_state_t state, const qihse_uuid_t* local_node)` | Decide write authorization from consistency class + state. `local_node` is currently unused (reserved); LOCAL-safe classes are always writable, strong classes are writable only in CONNECTED/DEGRADED. | `false` |
| `void qihse_federation_status_init(qihse_federation_status_t* status, const qihse_uuid_t* node_id)` | Initialise a status snapshot. | n/a |
| `void qihse_federation_status_recompute(qihse_federation_status_t* status)` | Recompute derived fields; `local_database` stays READ_WRITE for local-safe namespaces. | n/a |
| `void qihse_federation_status_format(const qihse_federation_status_t* status, char* out, size_t out_cap)` | Render single-line JSON-ish status. | n/a (void) |

Namespace registry, backed by the caller's KV store under `fedns:`:

| Function | Purpose | On failure |
|---|---|---|
| `bool qihse_federation_namespace_register(void* store, void* user, const char* name, qihse_consistency_class_t consistency, const qihse_uuid_t* authority_node, const qihse_uuid_t* local_node)` | Register or replace a namespace; sets `local_authority` when authority is the local node or the class is LOCAL. | `false` on invalid name/class |
| `bool qihse_federation_namespace_lookup(void* store, void* user, const char* name, qihse_federation_namespace_t* out)` | Look up by name. | `false` if not registered |
| `bool qihse_federation_namespace_unregister(void* store, void* user, const char* name)` | Remove a registration. | `false` if not found |
| `void qihse_federation_namespace_foreach(void* store, void* user, qihse_federation_ns_iter_cb cb, void* user_data)` | Iterate; the callback returns `false` to stop. | n/a |

### 1.3 F2 — idempotency ledger, journal, watches

Idempotency ledger (`fedreq:`):

| Function | Purpose | On failure |
|---|---|---|
| `bool qihse_federation_request_record(void* store, void* user, const qihse_federation_request_result_t* result)` | Record a completed request. | `false` if the `request_id` is already present — treat that as a replay and fetch the stored result |
| `bool qihse_federation_request_lookup(void* store, void* user, const qihse_uuid_t* request_id, qihse_federation_request_result_t* out)` | Fetch a recorded result. | `false` if not found |
| `bool qihse_federation_request_seen(void* store, void* user, const qihse_uuid_t* request_id)` | Cheap "already completed?" probe before executing. | `false` if not seen |

Event journal (`federation` topic, SHA-384 hash chain):

| Function | Purpose | On failure |
|---|---|---|
| `qihse_federation_journal_t* qihse_federation_journal_open(const char* log_directory, qihse_es_durability_t durability)` | Open the journal backed by `qihse_event_stream`. | `NULL` |
| `void qihse_federation_journal_destroy(qihse_federation_journal_t* journal)` | Release the journal. | n/a |
| `uint64_t qihse_federation_journal_append(qihse_federation_journal_t* journal, const qihse_federation_mutation_t* mutation, const char* event_type, const char* resource_id, const uint8_t* payload, size_t payload_len, qihse_federation_event_t* out_event)` | Append an event; ticks a zero HLC, mints a nil event id, extends the hash chain. | `0` (note: offset `0` is not a valid append result) |
| `uint64_t qihse_federation_journal_replay(qihse_federation_journal_t* journal, uint64_t from_cursor, qihse_federation_journal_cb cb, void* user_data)` | Replay from a cursor (`0` = beginning); callback returns `false` to stop. | `0` |
| `uint64_t qihse_federation_journal_replay_window(qihse_federation_journal_t* journal, uint64_t from_cursor, uint64_t max_events, qihse_federation_journal_cb cb, void* user_data, uint64_t* out_cursor)` | Bounded replay that reports where to resume; `out_cursor` is unchanged when nothing was delivered, which is what makes a failed round retryable. | `0` |
| `uint64_t qihse_federation_journal_length(qihse_federation_journal_t* journal)` | Offset of the next append. | `0` |

Resumable watches:

| Function | Purpose | On failure |
|---|---|---|
| `qihse_federation_watch_t* qihse_federation_watch_open(qihse_federation_journal_t* journal, const qihse_federation_watch_config_t* config)` | Open a prefix-filtered, resumable cursor. | `NULL` |
| `void qihse_federation_watch_destroy(qihse_federation_watch_t* watch)` | Release the watch. | n/a |
| `bool qihse_federation_watch_next(qihse_federation_watch_t* watch, qihse_federation_event_t* out_event, uint8_t** out_payload, size_t* out_payload_len)` | Deliver the next matching event; advances the cursor but not `last_ack`. | `false` at end-of-journal (poll or sleep); caller frees `*out_payload` |
| `bool qihse_federation_watch_ack(qihse_federation_watch_t* watch, uint64_t offset)` | Acknowledge up to `offset`. At-least-once: unacked events are re-delivered. | `false` |
| `bool qihse_federation_watch_resume(qihse_federation_watch_t* watch, uint64_t cursor)` | Resume from a saved cursor. | `false` |
| `uint64_t qihse_federation_watch_cursor(const qihse_federation_watch_t* watch)` | Current cursor, for persistence. | `0` |
| `uint64_t qihse_federation_watch_last_ack(const qihse_federation_watch_t* watch)` | Highest acknowledged offset. | `0` |
| `size_t qihse_federation_watch_backlog(const qihse_federation_watch_t* watch)` | Unacked event count. | `0` |

### 1.4 F3 — conflict objects, manifests, sync plans

| Function | Purpose | On failure |
|---|---|---|
| `const char* qihse_conflict_policy_name(qihse_conflict_policy_t policy)` | `"LWW_HLC"`, `"MERGE_SET"`, … | `NULL` |
| `bool qihse_conflict_policy_parse(const char* name, qihse_conflict_policy_t* out)` | Parse a policy. | `false` |
| `bool qihse_federation_conflict_record(void* store, void* user, const qihse_federation_conflict_t* conflict)` | Record an explicit conflict object (`fedconf:`). | `false` if the id already exists |
| `bool qihse_federation_conflict_lookup(void* store, void* user, const qihse_uuid_t* conflict_id, qihse_federation_conflict_t* out)` | Look up by id. | `false` |
| `bool qihse_federation_conflict_resolve(void* store, void* user, const qihse_uuid_t* conflict_id, const qihse_uuid_t* resolver)` | Mark resolved. | `false` |
| `void qihse_federation_conflict_foreach(void* store, void* user, qihse_federation_conflict_cb cb, void* user_data)` | Iterate unresolved conflicts. | n/a |
| `bool qihse_federation_manifest_build(void* store, void* user, const char* namespace_name, qihse_federation_manifest_t* out)` | Build a namespace manifest of SHA-384 range digests over sorted `(id, generation, hlc)` tuples; up to `QIHSE_FEDERATION_MANIFEST_MAX_RANGES` (64) ranges. | `false` |
| `size_t qihse_federation_manifest_compare(const qihse_federation_manifest_t* local, const qihse_federation_manifest_t* remote, qihse_federation_manifest_entry_t* out_divergent, size_t out_cap)` | Count divergent ranges and write up to `out_cap` of them; deterministic for the same inputs. | `0` when nothing diverges |
| `size_t qihse_federation_sync_plan(const qihse_federation_manifest_t* local, const qihse_federation_manifest_t* remote, qihse_federation_sync_range_t* out_ranges, size_t out_cap)` | Classify each range as `QIHSE_SYNC_NONE`/`FETCH`/`SEND`/`CONFLICT`. | `0` when no action is needed |

### 1.5 F4 — CAS, epochs, leases, replication groups

| Function | Purpose | On failure |
|---|---|---|
| `bool qihse_federation_object_cas(void* store, void* user, const char* namespace_name, const char* resource_id, uint64_t expected_generation, const char* new_value, qihse_federation_cas_result_t* result)` | Atomic compare-and-swap on `fedobj:<ns>:<id>` (value format `"<generation>\t<value>"`), serialised by the module's CAS lock. | `false`; `result->swapped` is `false` and `old_generation` reports the observed generation, so a failed CAS is not an error |
| `bool qihse_federation_object_get(void* store, void* user, const char* namespace_name, const char* resource_id, uint64_t* out_generation, char* out_value, size_t out_value_cap)` | Read a generation-tagged object. | `false` if not found |
| `uint64_t qihse_federation_epoch_next(void* store, void* user, const qihse_uuid_t* node_id)` | Advance and return the persistent per-node fencing counter (`fedepoch:<node>`); never goes backwards. | `0` on invalid arguments or storage failure |
| `uint64_t qihse_federation_epoch_current(void* store, void* user, const qihse_uuid_t* node_id)` | Read the counter without advancing. | `0` if absent |
| `const char* qihse_lease_state_name(qihse_lease_state_t state)` | `"free"`, `"granted"`, `"expired"`, `"released"`. | `NULL` |
| `bool qihse_federation_lease_acquire(void* store, void* user, const qihse_federation_lease_t* request, qihse_federation_lease_t* out)` | Acquire a lease; a live lease blocks unless the caller's `fencing_epoch` is strictly greater. Idempotent on `request_id`. | `false` (held, stale epoch, or bad request) |
| `bool qihse_federation_lease_renew(void* store, void* user, const qihse_uuid_t* lease_id, uint64_t new_expires_hlc_physical, qihse_federation_lease_t* out)` | Renew; the caller must hold the current lease. | `false` when the lease is not GRANTED |
| `bool qihse_federation_lease_release(void* store, void* user, const qihse_uuid_t* lease_id)` | Release; idempotent — releasing an already-released lease succeeds. | `false` |
| `bool qihse_federation_lease_read(void* store, void* user, const qihse_uuid_t* lease_id, qihse_federation_lease_t* out)` | Read by id. | `false` |
| `bool qihse_federation_group_create(void* store, void* user, const qihse_federation_group_t* group)` | Create a scoped replication group (`fedgrp:`), up to 32 members. | `false` if it already exists |
| `bool qihse_federation_group_lookup(void* store, void* user, const char* group_id, qihse_federation_group_t* out)` | Look up a group. | `false` |
| `bool qihse_federation_group_add_member(void* store, void* user, const char* group_id, const qihse_federation_group_member_t* member)` | Add or update a voter/witness. | `false` |
| `bool qihse_federation_group_remove_member(void* store, void* user, const char* group_id, const qihse_uuid_t* member_id)` | Remove a member. | `false` |
| `uint64_t qihse_federation_group_advance_term(void* store, void* user, const char* group_id)` | Advance and return the group term. | `0` if the group is unknown |
| `void qihse_federation_group_foreach(void* store, void* user, qihse_federation_group_cb cb, void* user_data)` | List groups. | n/a |

The lease high-water mark persists under `fedleaseres:<namespace>:<resource>`
after release, so an equal-or-lower epoch can never re-acquire. Request-id
indexing uses `fedleasereq:`.

**No consensus algorithm is implemented here.** Groups, terms and voters are
data structures; there is no leader election, log matching or commit rule, and
the header says so explicitly.

### 1.6 F5 — trust plane

Scopes and service identities:

| Function | Purpose | On failure |
|---|---|---|
| `const char* qihse_infra_scope_name(qihse_infra_scope_t scope)` | Scope bit name. | `NULL` |
| `bool qihse_infra_scope_parse(const char* name, qihse_infra_scope_t* out)` | Parse a scope name. | `false` |
| `const char* qihse_service_identity_name(qihse_service_identity_t kind)` | Service identity name. | `NULL` |
| `bool qihse_service_identity_parse(const char* name, qihse_service_identity_t* out)` | Parse a service identity. | `false` |
| `qihse_infra_scope_t qihse_service_identity_default_scopes(qihse_service_identity_t kind)` | Default scopes at enrollment; `KEYSTONE_INDEXER` receives read/index scopes only. | `QIHSE_SCOPE_NONE` |
| `bool qihse_infra_scope_check(void* user, qihse_infra_scope_t required)` | Does the authenticated principal hold the scope? The operator principal implicitly holds every scope. | `false` — including when `user` is `NULL` |
| `const char* qihse_trust_state_name(qihse_trust_state_t state)` | `"UNKNOWN"`, `"PENDING"`, `"APPROVED"`, `"REVOKED"`. | `NULL` |
| `bool qihse_trust_state_parse(const char* name, qihse_trust_state_t* out)` | Parse a trust state. | `false` |

Signature algorithm agility:

| Function | Purpose | On failure |
|---|---|---|
| `const char* qihse_sig_alg_name(qihse_sig_alg_t alg)` | `"ED25519"`, `"ML_DSA_44/65/87"`. | `NULL` |
| `bool qihse_sig_alg_parse(const char* name, qihse_sig_alg_t* out)` | Parse an algorithm name. | `false` |
| `size_t qihse_sig_alg_public_key_bytes(qihse_sig_alg_t alg)` | Public-key size for the algorithm. | `0` |
| `size_t qihse_sig_alg_signature_bytes(qihse_sig_alg_t alg)` | Signature size for the algorithm. | `0` |
| `bool qihse_sig_alg_is_post_quantum(qihse_sig_alg_t alg)` | True for ML-DSA. | `false` |

`QIHSE_SIG_ALG_DEFAULT` is `QIHSE_SIG_ML_DSA_87`. `Ed25519` is retained for
reading pre-quantum records and for bootstrap, not as a default.

Node identity and enrollment (`fednode:`):

| Function | Purpose | On failure |
|---|---|---|
| `bool qihse_federation_node_keygen(const char* key_directory, const qihse_uuid_t* node_id, uint8_t* out_public_key, char* out_key_handle, size_t out_key_handle_cap)` | Generate a durable node keypair; the private key is written to `<key_directory>/<node_id>.key` at 0600 and never enters a QIHSE record. **This entry point is Ed25519-only** (the legacy/bootstrap path); use `_alg` for ML-DSA. | `false` if `key_directory` does not exist |
| `bool qihse_federation_node_keygen_alg(const char* key_directory, qihse_sig_alg_t alg, qihse_federation_node_identity_t* out)` | Algorithm-agile keygen; fills `sig_alg`, `public_key`, `public_key_len`, `key_handle`, `fingerprint`. Caller sets `node_id` and `hostname` first. | `false` |
| `bool qihse_federation_node_fingerprint(const uint8_t* public_key, size_t public_key_len, uint8_t* out_fingerprint)` | SHA-384 fingerprint (48 bytes) of a raw public key. | `false` |
| `void* qihse_federation_node_key_load(const char* key_handle)` | Load a private key; returns an opaque `EVP_PKEY*`. | `NULL` |
| `void qihse_federation_node_key_free(void* pkey)` | Release a loaded key. | n/a |
| `bool qihse_federation_node_enroll_request(void* store, void* user, const qihse_federation_node_identity_t* identity)` | Record a PENDING identity; scopes come from the service identity kind, so a requester cannot self-grant. | `false` |
| `bool qihse_federation_node_enroll_approve(void* store, void* user, const qihse_uuid_t* node_id, uint64_t enrollment_epoch)` | Promote PENDING to APPROVED with an enrollment epoch. | `false` |
| `bool qihse_federation_node_revoke(void* store, void* user, const qihse_uuid_t* node_id)` | Mark REVOKED and clear scopes; permanent. | `false` |
| `bool qihse_federation_node_lookup(void* store, void* user, const qihse_uuid_t* node_id, qihse_federation_node_identity_t* out)` | Look up a node record. | `false` |
| `void qihse_federation_node_foreach(void* store, void* user, qihse_federation_node_cb cb, void* user_data)` | List node records. | n/a |

Signed gossip:

| Function | Purpose | On failure |
|---|---|---|
| `const char* qihse_gossip_result_name(qihse_gossip_result_t result)` | Name of an accept/reject result. | `NULL` |
| `bool qihse_federation_gossip_serialize(const qihse_federation_gossip_t* gossip, uint8_t* out, size_t out_cap, size_t* out_len)` | Serialise the signed region (every field except the signature), little-endian and length-prefixed. | `false` |
| `bool qihse_federation_gossip_deserialize(const uint8_t* in, size_t in_len, qihse_federation_gossip_t* out)` | Parse a statement; validates magic, version, algorithm and length fields before returning. | `false` — a malformed frame never reaches the verifier |
| `size_t qihse_federation_gossip_wire_size(qihse_sig_alg_t alg)` | Total wire size for an algorithm at the default statement version. | `0` |
| `size_t qihse_federation_gossip_wire_size_v(uint16_t version, qihse_sig_alg_t alg)` | Total wire size for an explicit version, so a sender can size an older frame as well as the current one. A producer that writes a non-default version must use this form or its size check will not match its frame. | `0` for an unknown version |
| `bool qihse_federation_gossip_sign(void* pkey, qihse_federation_gossip_t* gossip)` | Sign in place with an `EVP_PKEY*` from `_node_key_load`. | `false` |
| `bool qihse_federation_gossip_verify(const uint8_t* public_key, size_t public_key_len, const qihse_federation_gossip_t* gossip)` | Verify against a raw public key using the algorithm named inside the statement. | `false` |
| `bool qihse_federation_heartbeat_serialize(const qihse_federation_heartbeat_t* hb, uint8_t* out, size_t out_cap, size_t* out_len)` | Serialise the cheap 80-byte heartbeat. | `false` |
| `bool qihse_federation_heartbeat_deserialize(const uint8_t* in, size_t in_len, qihse_federation_heartbeat_t* out)` | Parse a heartbeat. | `false` |
| `qihse_gossip_result_t qihse_federation_heartbeat_accept(void* store, void* user, const qihse_federation_heartbeat_t* hb)` | Accept liveness only: requires a recorded signed statement for the same `(sender, boot)`, a matching session id, and an advancing sequence. | a `QIHSE_GOSSIP_REJECT_*` value |
| `bool qihse_federation_membership_from_statement(const qihse_federation_gossip_t* stmt, qihse_federation_membership_t* out)` | The **only** conversion into a membership record; there is deliberately no conversion from a liveness observation. | `false` |
| `bool qihse_federation_gossip_statement_read(void* store, void* user, const qihse_uuid_t* sender_node, const qihse_uuid_t* boot_id, qihse_federation_gossip_t* out)` | Read the recorded statement for a `(sender, boot)`. | `false` if the node has not signed |
| `qihse_gossip_result_t qihse_federation_gossip_accept(void* store, void* user, const qihse_federation_gossip_t* gossip)` | Accept an authority-bearing frame: magic/version, sender trust state, signature against the enrolled key, replay window. | `QIHSE_GOSSIP_REJECT_MALFORMED`/`_VERSION`/`_UNKNOWN_SENDER`/`_UNTRUSTED_SENDER`/`_BAD_SIGNATURE`/`_REPLAY` |
| `bool qihse_federation_replay_state_read(void* store, void* user, const qihse_uuid_t* sender_node, const qihse_uuid_t* boot_id, qihse_federation_replay_state_t* out)` | Read the persistent replay window (`fedreplay:<node>:<boot>`). | `false` |

Algorithm-agile detached signatures (federation upgrade plan §17). The
membership statement above is one consumer of a signature; a durable record that
must be attributable — a brain decision, a supply-chain attestation — is
another. These primitives keep the algorithm knowledge in the module that owns
the algorithm table, so a consumer never hard-codes a key type name:

| Function | Purpose | On failure |
|---|---|---|
| `bool qihse_federation_pkey_sig_alg(void* pkey, qihse_sig_alg_t* out)` | Algorithm of a loaded key handle (an `EVP_PKEY*` from `qihse_federation_node_key_load()`). | `false` for a key type the federation does not support |
| `bool qihse_federation_sign(void* pkey, const uint8_t* data, size_t data_len, uint8_t* out_sig, size_t* in_out_len)` | Sign `data` with a loaded key. `*in_out_len` is the capacity of `out_sig` on entry and receives the bytes written; the capacity must be at least the algorithm's signature size. The caller is responsible for putting the algorithm inside the signed bytes, so an algorithm-downgrade edit invalidates the signature rather than reinterpreting it. | `false` |
| `bool qihse_federation_verify(qihse_sig_alg_t alg, const uint8_t* public_key, size_t public_key_len, const uint8_t* data, size_t data_len, const uint8_t* signature, size_t signature_len)` | Verify a detached signature. The declared key and signature lengths are validated against the algorithm's fixed sizes before any crypto runs, so a truncated or padded signature never reaches the verifier. | `false` |

These three are used in production paths (`src/federation/qihse_federation.c`,
`src/spinnaker/qihse_cluster_brain.c`) and are exercised indirectly — including
an algorithm-downgrade refusal — by `tests/test_brain_fed_journal.c`, which
verifies signed decision envelopes through `qihse_cluster_brain_decision_verify()`.
No test calls them directly, so their own status is
`partial — status unverified` at the entry-point level.

### 1.7 W2.4 — durable node capability records (`federation/node/<uuid>`)

Source: `src/federation/qihse_federation.c`.
Tests: `tests/test_node_cap_records.c` (durability across a restart, both
producer paths, trust and admissibility, malformed-record refusal), and the
`gold-fabric-durable-caps` workload in `tests/gold/pack.v1.gold` for the
topology-node-to-UUID chain that makes the record reachable at all.

The stored values are always a **claim**, never an attested fact: a signature
proves which node made the claim, not that the hardware exists. A self-report
carries `QIHSE_CAP_FLAG_ATTESTED` clear and nothing in the library sets that
flag. The trust state in the record is a snapshot taken at admission, for
attribution and audit — it is not authorization, which is why the admissible
accessor re-reads the identity record.

| Function | Purpose | On failure |
|---|---|---|
| `const char* qihse_capability_source_name(qihse_capability_source_t source)` | `"none"`, `"local-probe"`, `"signed-statement"`, `"operator"`, and `"unknown"` for a value outside the enum. | never `NULL` |
| `bool qihse_federation_node_capability_record_local(void* store_void, void* user_void, const qihse_uuid_t* node_id, const qihse_federation_capability_values_t* values)` | Record the local node's own hardware probe. The trust snapshot is read from the node's identity record when one exists (UNKNOWN otherwise), never supplied by the caller, and the source is always `LOCAL_PROBE`. An out-of-range ISA tier is refused. | `false` |
| `bool qihse_federation_node_capability_lookup(void* store_void, void* user_void, const qihse_uuid_t* node_id, qihse_federation_node_capability_t* out)` | Read the durable record. The body's node id must agree with the key, every field is range-checked and an unknown record version is refused. This does **not** check trust: it returns what is stored, for audit and provenance. | `false` |
| `bool qihse_federation_node_capability_lookup_admissible(void* store_void, void* user_void, const qihse_uuid_t* node_id, qihse_federation_node_capability_t* out)` | Read a capability record **and** require that the node is APPROVED right now. The identity record is re-read, so a revocation invalidates capability data admitted earlier. This is the accessor a placement decision must use. | `false` |

---

## 2. Schema, snapshots, backup, rejoin state, metrics — `include/qihse_operations.h` and `include/qihse_backup.h`

Source: `src/federation/qihse_operations.c` (§2.1, §2.2, §2.4, §2.5) and
`src/federation/qihse_backup.c` (§2.3).
Tests: `tests/test_federation_f8_ops.c`, `tests/test_federation_f8.c`,
`tests/test_federation_backup.c`.

### 2.1 Schema evolution

| Function | Purpose | On failure |
|---|---|---|
| `const char* qihse_schema_result_name(qihse_schema_result_t r)` | Result name. | `NULL` |
| `qihse_schema_result_t qihse_schema_check(const qihse_schema_header_t* header, const qihse_schema_reader_t* reader)` | Decide whether this reader may interpret the object. Fails closed on an unknown required feature or a too-old reader. | `QIHSE_SCHEMA_ERR_MALFORMED`, `_READER_TOO_OLD` or `_UNKNOWN_REQUIRED_FEATURE` |
| `void qihse_schema_header_init(qihse_schema_header_t* header, uint32_t schema_id, uint32_t version)` | Initialise a schema header. | n/a |
| `bool qihse_schema_migration_register(void* store, void* user, const qihse_schema_migration_t* migration)` | Register a forward-only migration (`schema/migration:`). | `false` |
| `bool qihse_schema_migration_lookup(void* store, void* user, uint32_t schema_id, uint32_t from_version, qihse_schema_migration_t* out)` | Look up a migration. | `false` |
| `bool qihse_schema_progress_set(void* store, void* user, uint32_t schema_id, uint32_t version, uint64_t completed_units, uint64_t total_units)` | Record resumable progress (`schema/progress:`). | `false` |
| `bool qihse_schema_progress_get(void* store, void* user, uint32_t schema_id, uint32_t version, uint64_t* out_completed, uint64_t* out_total)` | Read progress. | `false` |
| `bool qihse_schema_progress_complete(void* store, void* user, uint32_t schema_id, uint32_t version)` | True when the migration reached its total. | `false` |

### 2.2 Snapshot manifests

| Function | Purpose | On failure |
|---|---|---|
| `const char* qihse_snapshot_kind_name(qihse_snapshot_kind_t kind)` | `"LOCAL"` / `"COORDINATED"`. | `NULL` |
| `bool qihse_snapshot_kind_parse(const char* name, qihse_snapshot_kind_t* out)` | Parse a snapshot kind. | `false` |
| `bool qihse_snapshot_record(void* store, void* user, qihse_snapshot_manifest_t* manifest)` | Persist a manifest (`snapshot/manifest:`); the checksum is computed by this call, so a caller cannot record a manifest whose digest disagrees with its contents. | `false` (including `group_count > QIHSE_SNAPSHOT_MAX_GROUPS`) |
| `bool qihse_snapshot_lookup(void* store, void* user, const qihse_uuid_t* snapshot_id, qihse_snapshot_manifest_t* out)` | Fetch a manifest. | `false` |
| `bool qihse_snapshot_verify(void* store, void* user, const qihse_uuid_t* snapshot_id)` | Re-verify a stored manifest against its checksum. | `false` if altered or truncated |

A manifest carries the schema header, max generation, WAL continuation offset,
group list, object count, and an `encryption_key_id` (a key id, never key
material). The writer that produces the data a manifest refers to is
`include/qihse_backup.h` — see [§2.3](#23-snapshot-backup--includeqihse_backuph).

### 2.3 Snapshot backup — `include/qihse_backup.h`

Source: `src/federation/qihse_backup.c` (federation writer/reader),
`src/tractable/qihse_backup.c` (legacy whole-store export).
Test: `tests/test_federation_backup.c` (`make test-federation-backup`, part of
the default `make test` list).

The federation backup surface takes a mandatory security context and propagates
it to the KV layer on both export and import, so a principal that may not read a
record may neither back it up nor restore it. A refused call leaves no container
and no partial dataset behind.

| Function | Purpose | On failure |
|---|---|---|
| `qihse_backup_result_t qihse_backup_write(void* store, void* user, const qihse_snapshot_manifest_t* manifest, const char* path, qihse_backup_descriptor_t* out)` | Write the data `manifest` refers to. The manifest must already be recorded and verify, and the caller's authorized view must cover its declared object count. | `QIHSE_BACKUP_ERR_ARGUMENT` (including a `NULL` context), `_ERR_DENIED`, `_ERR_MANIFEST`, `_ERR_COVERAGE`, `_ERR_KEY_MATERIAL`, `_ERR_IO`. `out` is zeroed on entry, so a failed call never returns a partial descriptor |
| `qihse_backup_result_t qihse_backup_restore(void* store, void* user, const qihse_snapshot_manifest_t* manifest, const char* path, qihse_backup_descriptor_t* out)` | Restore the data `manifest` refers to, after verifying the manifest, the container checksum, the snapshot id and the WAL continuation point. | the same enum, plus `_ERR_TRUNCATED`, `_ERR_CHECKSUM`, `_ERR_SNAPSHOT_MISMATCH`, `_ERR_WAL_POINT` |
| `const char* qihse_backup_result_name(qihse_backup_result_t r)` | Result name. | `NULL` |

`qihse_backup_descriptor_t` reports what a written container holds: snapshot id,
WAL continuation offset, max generation, object count, data bytes, the data
SHA-384, the manifest body digest it was bound to, the encryption key id, and
the schema header. **Known boundary, stated in the header:** the container is
integrity-checked but not authenticated — a writer with filesystem access can
substitute a container that agrees with the manifest, because the manifest
carries no signature. Authenticating backups against the node identity key is
the documented follow-up.

Legacy whole-store export, `src/tractable/qihse_backup.c` — **partial, stub**:

| Function | Purpose | On failure |
|---|---|---|
| `int qihse_backup_full_user(qihse_kv_store_t* kv, qihse_user_t* user, const char* output_path, qihse_backup_info_t* info)` | Whole-store export. Requires an authenticated context. | `-1` argument, `-2` denied | `-1` |
| `int qihse_backup_incremental_user(qihse_kv_store_t* kv, qihse_user_t* user, const char* output_path, uint64_t since_lsn, qihse_backup_info_t* info)` | Incremental export. | `-1` |
| `int qihse_restore_user(qihse_kv_store_t* kv, qihse_user_t* user, const char* backup_path)` | Restore from a container. | `-1` argument, `-2` denied |
| `int qihse_backup_list_user(qihse_user_t* user, const char* dir, qihse_backup_info_t** out_backups, size_t* out_count)` | List containers in a directory. | `-1` |
| `int qihse_backup_verify_user(qihse_user_t* user, const char* backup_path)` | Verify a container's checksum. | `-1` argument, `-2` denied |
| `void qihse_backup_info_free(qihse_backup_info_t* info)` | Release a listing entry. | n/a |

> **Contradiction with the code:** the legacy surface is a stub.
> `qihse_backup_full_user()` in `src/tractable/qihse_backup.c` writes an empty data
> section and carries an explicit `TODO: iterate KV store and write all
> key-value pairs`; `data_len` is derived from the file size rather than from
> captured records. These functions take no security context, so they can only
> ever move unclassified data. Use `qihse_backup_write()`/`qihse_backup_restore()`
> for real backups.

### 2.4 Reconciliation sequence and rejoin state

| Function | Purpose | On failure |
|---|---|---|
| `const char* qihse_rejoin_step_name(qihse_rejoin_step_t step)` | Step name. | `NULL` |
| `bool qihse_rejoin_step_parse(const char* name, qihse_rejoin_step_t* out)` | Parse a step name. | `false` |
| `qihse_rejoin_step_t qihse_rejoin_next_step(qihse_rejoin_step_t current)` | Next step in the ordered sequence. | `QIHSE_REJOIN_ABORTED` for a terminal or illegal transition |
| `bool qihse_rejoin_may_publish_ownership(qihse_rejoin_step_t current)` | May exclusive ownership be published at this point? True only after state reconstruction and checksum verification. | `false` |
| `bool qihse_rejoin_state_put(void* store, void* user, const qihse_rejoin_state_t* state)` | Persist resumable rejoin progress (`rejoin/state:`). | `false` |
| `bool qihse_rejoin_state_get(void* store, void* user, const qihse_uuid_t* node_id, qihse_rejoin_state_t* out)` | Read rejoin progress. | `false` |

### 2.5 Observability and performance budgets

| Function | Purpose | On failure |
|---|---|---|
| `void qihse_federation_metrics_init(qihse_federation_metrics_t* m)` | Initialise the 21-series metric set. | n/a |
| `bool qihse_federation_metrics_render(const qihse_federation_metrics_t* m, const char* prefix, char* out, size_t out_cap)` | Render label-bounded Prometheus-style text; `NULL`/empty prefix uses `"qihse"`. No node or namespace labels. | `false` |
| `void qihse_perf_budget_init(qihse_perf_budget_t* b)` | Initialise the default budgets. | n/a |
| `bool qihse_perf_evaluate(const qihse_perf_budget_t* budget, const qihse_perf_measurement_t* measured, qihse_perf_verdict_t* out)` | Compare a measurement against a budget; each metric is checked only if it was measured (non-positive means "not measured"), so a partial harness cannot produce a false failure. | `false` on invalid arguments; a failed verdict is reported in `out->passed`, not by the return value |

---

## 3. Rejoin driver — `include/qihse_federation_rejoin.h`

Source: `src/federation/qihse_federation_rejoin.c`.
Test: `tests/test_federation_rejoin.c`.

The driver owns ordering and gating; it does not own the manifest wire format —
the caller supplies `qihse_rejoin_fetch_manifest_fn`.

| Function | Purpose | On failure |
|---|---|---|
| `bool qihse_rejoin_driver_begin(qihse_rejoin_driver_t* driver, void* store, void* user, const qihse_uuid_t* node_id, const qihse_uuid_t* expected_peer, const char* namespace_name, qihse_fed_tls_session_t* session)` | Start a rejoin. Refuses a transport that cannot name its peer, and refuses a verified session whose identity is a different node than `expected_peer`. | `false` |
| `bool qihse_rejoin_driver_step(qihse_rejoin_driver_t* driver, void* store, void* user, qihse_fed_tls_session_t* session, qihse_repl_transport_t* transport, void* journal_void, qihse_rejoin_fetch_manifest_fn fetch_manifest, void* fetch_ctx)` | Advance one step; a failed manifest fetch aborts rather than being skipped. | `false` when the sequence has aborted |
| `bool qihse_rejoin_driver_run(...same arguments...)` | Run to completion or abort. | `true` only on COMPLETE; `false` on abort |
| `bool qihse_rejoin_driver_may_publish_ownership(const qihse_rejoin_driver_t* driver)` | May this driver publish exclusive ownership yet? True only at VERIFY_CHECKSUMS or COMPLETE with no failed step. | `false` |
| `bool qihse_rejoin_driver_persist(const qihse_rejoin_driver_t* driver, void* store, void* user)` | Persist progress as the step *completed*, so a crash resumes at `next(step)` and never skips work. | `false` |
| `void qihse_rejoin_driver_state(const qihse_rejoin_driver_t* driver, qihse_rejoin_state_t* out)` | Snapshot for observability. | n/a |

---

## 4. Replication — `include/qihse_federation_repl.h`

Source: `src/federation/qihse_federation_repl.c`.
Test: `tests/test_federation_repl.c`.

| Function | Purpose | On failure |
|---|---|---|
| `bool qihse_repl_transport_open(qihse_repl_transport_t* t, const qihse_repl_transport_ops_t* ops, void* ctx, const char* peer)` | Establish a connection through a pluggable transport. | `false` |
| `void qihse_repl_transport_close(qihse_repl_transport_t* t)` | Close the connection. | n/a |
| `bool qihse_repl_loopback_pair(qihse_repl_loopback_t* a, qihse_repl_loopback_t* b)` | Create a connected in-memory pair (`QIHSE_REPL_LOOPBACK_CAP` = 256 KiB per endpoint) with no network dependency. | `false` |
| `const qihse_repl_transport_ops_t* qihse_repl_loopback_ops(void)` | Ops table for the loopback transport. | `NULL` |
| `const char* qihse_repl_phase_name(qihse_repl_phase_t phase)` | `"IDLE"`, `"SENDING"`, `"RECEIVING"`, `"VERIFYING"`, `"COMPLETE"`, `"FAILED"`, `"ABORTED"`. | `NULL` |
| `size_t qihse_repl_record_wire_size(const qihse_repl_record_t* rec)` | Wire size of one journal record. | `0` |
| `bool qihse_repl_record_encode(const qihse_repl_record_t* rec, uint8_t* out, size_t out_cap, size_t* out_len)` | Encode a record. | `false` |
| `bool qihse_repl_record_decode(const uint8_t* in, size_t in_len, qihse_repl_record_t* out)` | Decode a record; the declared payload length is validated against the encoded length, so a decoder refuses a record it could not have produced. | `false` |
| `bool qihse_repl_sync_begin(qihse_repl_sync_t* sync, const char* namespace_name, const qihse_federation_manifest_entry_t* range, bool local_is_sender)` | Begin a transfer for one divergent range; both sides construct it identically from the manifest comparison. | `false` |
| `size_t qihse_repl_sync_round(qihse_repl_sync_t* sync, qihse_repl_transport_t* transport, void* store, void* user, void* journal_void)` | Move one bounded round (`QIHSE_REPL_MAX_RECORDS_PER_ROUND` = 64). A transport error moves the phase to FAILED without advancing the cursor, so retries are safe. | `0` when the round had nothing to do |
| `bool qihse_repl_sync_finish(qihse_repl_sync_t* sync, void* store, void* user)` | Verify the received range against the expected digest and only then declare COMPLETE. | `false` and phase FAILED if verification does not hold |
| `bool qihse_repl_sync_may_publish(const qihse_repl_sync_t* sync)` | May this sync's outcome be published as authoritative? Only after verification. | `false` |
| `bool qihse_repl_transfer_permitted(uint32_t rejoin_step)` | A transfer may only run while the rejoin sequence is at or past TRANSFER_EVENTS. | `false` |

A transport that cannot report a peer fingerprint yields a connection that
**may be used for nothing that carries authority**; `qihse_repl_transport_t`
carries `peer_verified` for exactly that reason.

---

## 5. Transport and mTLS

Sources: `src/federation/qihse_federation_mtls.c`,
`src/federation/qihse_federation_transport.c`.
Tests: `tests/test_federation_mtls.c`, `tests/test_federation_transport.c`.

### 5.1 Federation CA — `include/qihse_federation_mtls.h`

| Function | Purpose | On failure |
|---|---|---|
| `bool qihse_federation_ca_create(const char* dir, qihse_sig_alg_t alg, qihse_federation_ca_t* out)` | Create an ML-DSA federation CA plus self-signed certificate. The private key is written to `<dir>/federation-ca.key` at 0600 and is deliberately never returned or cached. A pre-quantum CA is refused. | `false` |
| `bool qihse_federation_ca_issue_node(const char* ca_key_path, const qihse_federation_ca_t* ca, const qihse_federation_node_identity_t* node, uint64_t enrollment_epoch, char* out_cert_pem, size_t out_cap)` | Issue a node certificate binding the node's existing identity key to its UUID; carries the enrollment epoch. | `false` |
| `bool qihse_federation_cert_fingerprint(const char* cert_pem, uint8_t* out_fingerprint)` | SHA-384 fingerprint of a certificate's public key, computed identically at issuance and verification. | `false` |
| `bool qihse_federation_cert_verify(const char* cert_pem, const qihse_federation_ca_t* ca)` | Verify the certificate's own signature against the CA. | `false` |
| `const char* qihse_peer_verdict_name(qihse_peer_verdict_t v)` | Verdict name. | `NULL` |
| `qihse_peer_verdict_t qihse_federation_peer_verify(void* store, void* user, const uint8_t* cert_fingerprint, size_t fingerprint_len, qihse_uuid_t* out_node_id, qihse_runtime_trust_t* out_trust)` | The three-layer peer decision, layers 2 and 3 (fingerprint match and runtime trust). Layer 1 (key possession) has already happened in the handshake. | `QIHSE_PEER_REJECT_NO_CERT` / `_UNKNOWN_FINGERPRINT` / `_NOT_YET_APPROVED` / `_REVOKED` / `_UNTRUSTED` / `_MALFORMED` |
| `const char* qihse_federation_tls_group_list(void)` | Hybrid post-quantum key-exchange group list (X25519MLKEM768). | `NULL` |
| `const char* qihse_federation_tls_min_version(void)` | Minimum accepted TLS version. | `NULL` |

`QIHSE_FEDERATION_PEM_MAX` is 16384 bytes: an ML-DSA-87 certificate carries a
2592-byte public key and a 4627-byte signature, so a pre-quantum-sized buffer
would silently truncate.

### 5.2 TLS transport — `include/qihse_federation_transport.h`

| Function | Purpose | On failure |
|---|---|---|
| `qihse_fed_tls_server_t* qihse_federation_tls_server_create(const qihse_federation_ca_t* ca, const char* node_cert_pem, const char* node_key_path, void* store, void* user)` | Build an mTLS server context. A pre-quantum CA, or a certificate that does not verify against it, is refused so a misconfigured node fails to start. | `NULL` |
| `void qihse_federation_tls_server_destroy(qihse_fed_tls_server_t* server)` | Release the context. | n/a |
| `bool qihse_federation_tls_server_requires_client_cert(const qihse_fed_tls_server_t* s)` | True by default; exposed so the setting is visible and testable. | `false` |
| `qihse_fed_tls_session_t* qihse_federation_tls_accept_fd(qihse_fed_tls_server_t* server, int fd, qihse_peer_verdict_t* out_verdict)` | Server-side handshake on a connected fd; the three-layer decision runs inside the verify callback, so an unauthorised peer never gets a channel. | `NULL` (no certificate, or refused peer) |
| `qihse_fed_tls_session_t* qihse_federation_tls_connect_fd(qihse_fed_tls_server_t* ctx_holder, int fd, int timeout_ms, qihse_peer_verdict_t* out_verdict)` | Client-side handshake on an already-connected fd. `timeout_ms` bounds the handshake; the same asymmetry as `_connect_to` applies. | `NULL` |
| `void qihse_federation_tls_session_destroy(qihse_fed_tls_session_t* session)` | Close the session. | n/a |
| `bool qihse_federation_tls_peer_identity(const qihse_fed_tls_session_t* session, qihse_uuid_t* out_node_id, qihse_runtime_trust_t* out_trust)` | The verified peer identity. | `false` — never treat as "any peer" |
| `bool qihse_federation_tls_negotiated(const qihse_fed_tls_session_t* session, char* out_group, size_t group_cap, char* out_version, size_t version_cap)` | Negotiated group and TLS version, so a deployment can prove it is running post-quantum key exchange. | `false` |
| `qihse_fed_listener_t* qihse_federation_listener_open(qihse_fed_tls_server_t* server, const char* bind_address, uint16_t port)` | Bind and listen. `bind_address` is required and is never defaulted to a wildcard; port 0 asks the kernel for an ephemeral port. | `NULL` if the address is unusable or the bind fails |
| `void qihse_federation_listener_close(qihse_fed_listener_t* listener)` | Close the listener. | n/a |
| `uint16_t qihse_federation_listener_port(const qihse_fed_listener_t* listener)` | The port actually bound. | `0` |
| `qihse_fed_tls_session_t* qihse_federation_listener_accept(qihse_fed_listener_t* listener, int timeout_ms, qihse_peer_verdict_t* out_verdict)` | Accept one connection and complete the handshake. A timeout is not an error and leaves the listener usable. | `NULL` on timeout or refusal; `out_verdict` distinguishes the two |
| `qihse_fed_tls_session_t* qihse_federation_tls_connect_to(qihse_fed_tls_server_t* server, const char* host, uint16_t port, int timeout_ms, qihse_peer_verdict_t* out_verdict)` | Connect and handshake as a client. | `NULL`. Note the TLS 1.3 asymmetry documented in the header: a completed client handshake means "I verified the peer", **not** "the peer accepted me" |
| `bool qihse_federation_tls_session_peer_gone(qihse_fed_tls_session_t* session, int timeout_ms)` | True if the peer sent a fatal alert or closed. This is the reliable post-handshake refusal check. | `false` if the peer is still there |
| `qihse_repl_transport_ops_t qihse_federation_tls_transport_ops(qihse_fed_tls_session_t* session)` | Transport ops bound to a verified session; `peer_fingerprint` always succeeds by construction. | n/a |

`QIHSE_FED_TLS_HANDSHAKE_TIMEOUT_SEC` is 10.

---

## 6. Key-value store — `include/qihse_kv_store.h`

Source: `src/black_hole/qihse_kv_store.c`.
Tests: `tests/test_kv_read_integrity.c`, `tests/test_kv_security_regression.c`,
`tests/test_blob_persistence_regression.c`.

The KV store is the storage substrate the federation APIs write through. The
`_user` variants are the authorization-aware forms; the context-free forms are
intentionally restricted to unclassified data.

| Function | Purpose | On failure |
|---|---|---|
| `qihse_kv_store_t* qihse_kv_store_create(void)` | Create a store. | `NULL` |
| `void qihse_kv_store_destroy(qihse_kv_store_t* store)` | Destroy a store. | n/a |
| `bool qihse_kv_set(qihse_kv_store_t* store, const char* key, const char* value, uint16_t classification, uint16_t sci_compartment)` | Context-free write, unclassified data only. | `false` |
| `bool qihse_kv_set_user(qihse_kv_store_t* store, const char* key, const char* value, uint16_t classification, uint16_t sci_compartment, qihse_user_t* user)` | Classified/SCI-capable write with an explicit authenticated user. | `false` (denied or storage failure) |
| `char* qihse_kv_get_user(qihse_kv_store_t* store, const char* key, qihse_user_t* user)` | Read with authorization. Caller frees the result. | `NULL` |
| `char* qihse_kv_get(qihse_kv_store_t* store, const char* key)` | Inline wrapper: `qihse_kv_get_user(store, key, NULL)`. | `NULL` |
| `bool qihse_kv_del_user(...)`, `bool qihse_kv_del(...)` | Delete with/without authorization. | `false` |
| `bool qihse_kv_exists_user(...)`, `bool qihse_kv_exists(...)` | Existence with/without authorization. | `false` |
| `bool qihse_kv_expire(qihse_kv_store_t* store, const char* key, uint64_t ttl_ms, qihse_user_t* user)` | Set a TTL. | `false` |
| `int64_t qihse_kv_ttl_ms_user(qihse_kv_store_t* store, const char* key, qihse_user_t* user)` | Remaining TTL in ms. | `-1` when the key has no expiry; `-2` when it is missing, denied, or already expired |
| `void qihse_kv_sweep_expired(qihse_kv_store_t* store)` | Evict expired keys. | n/a |
| `bool qihse_kv_store_is_under_attack(qihse_kv_store_t* store)` | System-guard saturation probe. | `false` |
| `int qihse_kv_save_user(qihse_kv_store_t* store, const char* filepath, qihse_user_t* user)` | Authorized export. Denies the whole export if any live record is outside the caller's clearance/SCI. | non-zero |
| `int qihse_kv_load_user(qihse_kv_store_t* store, const char* filepath, qihse_user_t* user)` | Authorized import, same rule. | non-zero |
| `int qihse_kv_save(...)`, `int qihse_kv_load(...)` | Legacy forms that run as NULL/unclassified and therefore cannot export or import classified records. | non-zero |
| `void qihse_kv_bulk_load_begin(qihse_kv_store_t* store)` / `void qihse_kv_bulk_load_end(...)` | Disable WAL buffering and automatic flush during a bulk load. Authorization rules remain in force. | n/a |
| `bool qihse_kv_foreach_user(qihse_kv_store_t* store, qihse_user_t* user, qihse_kv_iter_cb cb, void* user_data)` | Authorization-aware enumeration; callback returns `false` to stop. | `false` on compaction/storage failure |
| `void qihse_kv_foreach(qihse_kv_store_t* store, qihse_kv_iter_cb cb, void* user_data)` | Context-free enumeration. | n/a |
| `size_t qihse_kv_clear_user(...)`, `size_t qihse_kv_clear(...)` | Clear entries; returns the number removed. | `0` |
| `size_t qihse_kv_count_user(...)`, `size_t qihse_kv_count(...)` | Count entries. | `0` |

---

## 7. Security and authentication — `include/qihse_auth.h`

Source: `core/qihse_auth.c`.
Tests: `tests/test_auth_privilege_boundary.c`, `tests/test_object_acl.c`,
`tests/test_tenant_privilege_ladder.c`, `tests/test_tenant_security_regression.c`,
`tests/test_sci_compartment_regression.c`, `tests/test_operator_mode.c`,
`tests/test_fido_auth.c`.

Roles are `QIHSE_ROLE_OPERATOR` (0), `QIHSE_ROLE_ANALYST` (1),
`QIHSE_ROLE_GUEST` (2). Object ACL flags are `QIHSE_ACL_READ` (0x01),
`QIHSE_ACL_WRITE` (0x02), `QIHSE_ACL_ADMIN` (0x04). Password verifiers are
PBKDF2-HMAC-SHA-384 with a 128-bit salt, a 48-byte hash, and a production
iteration floor of `QIHSE_PW_MIN_ITERATIONS` (600000).

| Function | Purpose | On failure |
|---|---|---|
| `bool qihse_auth_init(void)` | Initialise the auth context. Fails closed if FIPS/crypto policy cannot be satisfied. | `false` |
| `bool qihse_auth_bootstrap_operator(const char* initial_password)` | Create the system operator with an explicit password. | `false` |
| `qihse_user_t* qihse_auth_create_user(const qihse_user_t* creator, uint32_t user_id, uint16_t role, uint16_t classif, uint16_t sci, const char* plaintext_password, bool requires_hw_token)` | Create a user. An operator, or a creator holding `can_create_users`, may create; a non-operator creator cannot produce a principal above itself. | `NULL` |
| `qihse_user_t* qihse_auth_create_tenant_user(const qihse_user_t* creator, uint32_t tenant_id, uint32_t user_id, uint16_t role, uint16_t classif, uint16_t sci, const char* plaintext_password, bool requires_hw_token)` | Tenant-scoped creation. A tenant-scoped creator may only create inside its own tenant and can never create a system-domain (tenant 0) principal. | `NULL` |
| `qihse_user_t* qihse_auth_get_user(uint32_t user_id)` | Look up a live principal. | `NULL` |
| `bool qihse_auth_destroy_user(const qihse_user_t* actor, uint32_t target_user_id)` | Destroy a user; only an OPERATOR may. Destroying the operator requires `QIHSE_ALLOW_DESTROY_OPERATOR`. | `false` |
| `bool qihse_auth_modify_user(const qihse_user_t* operator_user, uint32_t target_user_id, const char* new_username, const char* new_password, int new_requires_hw_token, int new_can_create_users, int new_classification, int new_sci)` | Operator-only modification. `-1`/`NULL` means "do not change". `new_classification`/`new_sci` are the only elevation path; OPERATOR-role targets are pinned to `0xFFFF/0xFFFF`. | `false` |
| `bool qihse_auth_set_hardware_token(qihse_user_t* user, bool present, const char* credential_id)` | Set hardware-token state. | `false` |
| `bool qihse_auth_can_access(const qihse_user_t* user, uint16_t data_classif, uint16_t data_sci)` | Row-level clearance/SCI check. | `false` |
| `bool qihse_auth_can_access_object(const qihse_user_t* user, uint32_t namespace_id, uint64_t resource_id, uint8_t required_flags)` | Object ACL check. A read-only grant cannot satisfy a write requirement. | `false` |
| `bool qihse_auth_grant_object(const qihse_user_t* operator_user, qihse_user_t* target_user, uint32_t namespace_id, uint64_t resource_id, uint8_t access_flags)` | Operator-only ACL grant. | `false` |
| `bool qihse_auth_revoke_object(const qihse_user_t* operator_user, qihse_user_t* target_user, uint32_t namespace_id, uint64_t resource_id)` | Operator-only ACL revoke. | `false` |
| `bool qihse_auth_is_operator_password_default(void)` | True while the operator password is still the default; network services refuse to bind in that state. | `false` |
| `qihse_user_t* qihse_auth_authenticate(const char* username, const char* password)` | Authenticate by username. | `NULL` |
| `qihse_user_t* qihse_auth_authenticate_from(uint32_t source_ip, const char* username, const char* password)` | Authenticate with IP rate limiting. | `NULL` |
| `qihse_user_t* qihse_auth_authenticate_id(uint32_t user_id, const char* password)` | Authenticate by user id. | `NULL` |
| `qihse_user_t* qihse_auth_authenticate_id_from(uint32_t source_ip, uint32_t user_id, const char* password)` | Authenticate by id with IP rate limiting. | `NULL` |

Read-only accessors (authoritatively resolved against internal state, so a
forged handle does not yield privilege):
`qihse_user_get_id`, `qihse_user_get_role`,
`qihse_user_get_classification`, `qihse_user_get_sci`,
`qihse_user_get_tenant_id`, `qihse_user_get_username`,
`qihse_user_get_fido2_credential_id`, `qihse_user_has_hardware_token`,
`qihse_user_requires_hardware_token`, `qihse_user_can_create_users`.

Revocation and liveness:

| Function | Purpose | On failure |
|---|---|---|
| `bool qihse_auth_user_is_active(const qihse_user_t* user)` | Re-validate a presented handle; returns `false` once the principal is destroyed or the handle is forged. Call once per command, not per row. | `false` |
| `void qihse_auth_user_active_and_tenant(const qihse_user_t* user, bool* out_active, uint32_t* out_tenant)` | Combined liveness + tenant probe under one lock round-trip. | `out_active` is `false` |

Auth rate limiting (brute-force protection):

| Function | Purpose | On failure |
|---|---|---|
| `void qihse_auth_init_rate_limiter(uint32_t max_attempts, uint32_t window_seconds, size_t max_entries)` | Configure the limiter (defaults: 5 attempts / 60 s / 1024 entries). | n/a |
| `void qihse_auth_shutdown_rate_limiter(void)` | Shut the limiter down. | n/a |
| `bool qihse_auth_check_rate_limit(uint32_t source_ip)` | Is this source allowed to attempt? | `false` when limited |
| `void qihse_auth_rate_limit_reset(uint32_t source_ip)` | Clear a source's counters. | n/a |
| `void qihse_auth_rate_limit_cleanup(void)` | Expire stale entries. | n/a |

---

## 8. Additional public C surfaces

These are public entry points that sit outside the nine headers of
[§1](#1-federation-core--includeqihse_federationh)–[§7](#7-security-and-authentication--includeqihse_authh).
They are documented here because an operator, a controller or a protocol adapter
is expected to call them; each was verified against its header and against the
built `libqihse.so` by the same method as the sections above.

### 8.1 Replication apply — `include/qihse_repl.h`

Source: `src/spinnaker/qihse_repl.c`.
Tests: `tests/test_repl.c` (`make test-repl`); the replay itself also by the
`repl-apply-wal` workload in `tests/gold/pack.v1.gold`.

`qihse_repl_apply_wal()` **replays** an accepted record into the store bound
with `qihse_repl_set_store()`. The record is not re-parsed here: the bytes are
staged as the single record of a private WAL segment and replayed through
`qihse_wal_replay()`, so the length rules and the CRC32 check that decide
whether a record is valid are the WAL layer's, not a second copy of them. The
store mutation happens in the replay callback, which the WAL layer invokes only
after it accepted the record, so a refused record cannot be partially applied.

| Function | Purpose | On failure |
|---|---|---|
| `int qihse_repl_set_store(qihse_repl_context_t* ctx, qihse_kv_store_t* store)` | Bind the local store that apply replays into. The store is **borrowed**, never owned, and must outlive the context. Passing `NULL` unbinds, after which apply refuses every record. | `-1` for a `NULL` context |
| `qihse_kv_store_t* qihse_repl_get_store(qihse_repl_context_t* ctx)` | The bound store. | `NULL` when none is bound |
| `int qihse_repl_apply_wal(qihse_repl_context_t* ctx, const uint8_t* wal_data, size_t len, uint64_t lsn)` | Apply one received `[LSN][length][data]` frame payload. On success the mutation has reached the store and `replay_lsn`/`flush_lsn` advance to the record's LSN. Ordering is enforced by a monotonic in-memory watermark: a record at or below it is not applied twice and still reports success, so a retransmission is a no-op. | `-1` with nothing applied and no LSN advanced |

Refused, with nothing applied: a `NULL`/empty record, a context with no bound
store, `QIHSE_WAL_INVALID_LSN`, a record whose own LSN is not the `lsn`
argument, declared field lengths that disagree with `len`, bytes the WAL layer
rejects (truncated tail, checksum mismatch, unknown op), and a mutation the
store refuses. The applier writes through the KV layer's unclassified-only
entry points: a WAL record carries no classification or SCI, so it cannot
express a classified write, and a mutation the store refuses (for example an
overwrite of a classified row) refuses the whole record. The watermark is in
memory and is not recovered after a restart, which is safe for
INSERT/UPDATE/DELETE because reaching the same key state twice is idempotent,
but a caller that needs durable exactly-once semantics must persist the
position itself.

### 8.2 Table-store DML primitives — `include/qihse_table_store.h`

Source: `src/tractable/qihse_table_store.c`.
Test: `tests/test_sql_dml_exec.c` (`make test-sql-dml-exec`), which drives
these through `qihse_uwp_sql_execute_dml()`.

The mutable table store is the only in-tree store with in-place update and
delete primitives, which is why the SQL `UPDATE`/`DELETE` executor targets it
(see [sql_engine.md §3.5](architecture/sql_engine.md)).

| Function | Purpose | On failure |
|---|---|---|
| `qihse_table_store_t* qihse_table_store_create(void)` / `void qihse_table_store_destroy(qihse_table_store_t* store)` | Create/destroy the store. | `NULL` |
| `qihse_table_t* qihse_table_store_create_table(qihse_table_store_t* store, const char* name, const qihse_col_def_t* cols, size_t num_cols)` | Create a table. | `NULL` |
| `qihse_table_t* qihse_table_store_find_table(qihse_table_store_t* store, const char* name)` | Look up a table by name. | `NULL` |
| `int qihse_table_insert(qihse_table_t* table, const qihse_col_value_t* values, size_t num_values)` | Insert a row; string values are deep-copied. | `-1` |
| `bool qihse_table_update(qihse_table_t* table, int (*pred)(const qihse_col_value_t* values, size_t num_cols, void* ctx), void* pred_ctx, const int* update_cols, const qihse_col_value_t* new_values, size_t num_updates)` | Update the rows the predicate accepts: the columns in `update_cols` are set to the corresponding `new_values` (strings deep-copied). | `false` when no row matched (not an error) |
| `bool qihse_table_delete(qihse_table_t* table, int (*pred)(const qihse_col_value_t* values, size_t num_cols, void* ctx), void* pred_ctx)` | Delete (tombstone) the rows the predicate accepts; the table is compacted periodically. | `false` when no row matched |
| `size_t qihse_table_row_count(const qihse_table_t* table)` | Live (non-deleted) row count. | `0` |
| `void qihse_table_scan(const qihse_table_t* table, qihse_table_row_cb cb, void* ctx)` | Scan live rows; the callback's value pointer is valid only during the call and returning `false` stops the scan. | n/a |
| `size_t qihse_table_num_cols(const qihse_table_t* table)` / `const qihse_col_def_t* qihse_table_col_def(const qihse_table_t* table, size_t idx)` / `int qihse_table_find_col(const qihse_table_t* table, const char* name)` / `const char* qihse_table_name(const qihse_table_t* table)` | Introspection. | `0` / `NULL` / `-1` |

The SQL executor above these primitives reports the rows actually changed, not
a match count, and refuses a zero-condition DELETE instead of turning it into a
match-all; see [sql_engine.md §3.5](architecture/sql_engine.md) for the
executor-level contract.

### 8.3 Parallel query — `include/qihse_parallel_query.h`

Source: `src/tractable/qihse_parallel_query.c`.
Test: `tests/test_parallel_query.c` (`make test-parallel-query`); also the
`parallel-query` workload in `tests/gold/pack.v1.gold`.

Every entry point returns `QIHSE_PARALLEL_OK` (0) or a negative code, and a
refusal exposes no partial result — so a caller can tell "the query ran and
matched nothing" from "the query could not run".

| Function | Purpose | On failure |
|---|---|---|
| `qihse_parallel_ctx_t* qihse_parallel_init(int num_workers)` | Create a context with 1..`QIHSE_PARALLEL_MAX_WORKERS` (64) workers. A new context has no user bound, i.e. it sees unclassified data only. | `NULL` for an out-of-range worker count or an allocation/mutex failure |
| `int qihse_parallel_set_user(qihse_parallel_ctx_t* ctx, qihse_user_t* user)` / `qihse_user_t* qihse_parallel_get_user(qihse_parallel_ctx_t* ctx)` | Bind (or clear, with `NULL`) the security context inherited by every operation. Borrowed: the caller keeps ownership. | `QIHSE_PARALLEL_ERR_ARGS` / `NULL` |
| `int qihse_parallel_scan(qihse_parallel_ctx_t* ctx, qihse_kv_store_t* kv, const char* table_prefix, qihse_parallel_scan_t* out_scan)` | Scan every key under `table_prefix` and partition the rows across the workers. Success with `total_rows == 0` means the traversal ran and found no key — a KV store has no schema, so an empty table and an absent one are the same thing. | a negative code, `out_scan` zeroed |
| `void qihse_parallel_scan_free(qihse_parallel_scan_t* scan)` | Release the rows and arrays a scan owns. Safe on a zeroed struct. | n/a |
| `void qihse_parallel_cleanup(qihse_parallel_ctx_t* ctx)` | Release the context. | n/a |
| `int qihse_parallel_join(qihse_parallel_ctx_t* ctx, qihse_kv_store_t* kv, const char* left_table, const char* right_table, const char* join_key, qihse_parallel_join_t* out_join)` | Parallel hash join on a shared column name. A row participates when its key is under the table prefix and its final component equals `join_key`; two rows match when their join values are byte-equal. `left_keys`/`right_keys`/`left_join_rows`/`right_join_rows` report what was examined, so success with `matched_rows == 0` is evidence the join ran. | `QIHSE_PARALLEL_ERR_NO_RESULT` when either table has no key carrying the join column — nothing could ever have matched, and reporting that as "0 rows matched" is the false success this module exists to remove |
| `void qihse_parallel_join_free(qihse_parallel_join_t* join)` | Release the pairs a join result owns. Safe on a zeroed struct. | n/a |
| `int qihse_parallel_aggregate(qihse_parallel_ctx_t* ctx, qihse_kv_store_t* kv, const char* table_name, const char* agg_column, const char* agg_func, double* out_result)` | Aggregate the rows under `table_name`. `agg_column` selects the column (final key component) to aggregate; `NULL` aggregates each row's own value. `agg_func` is `count`/`sum`/`avg`/`min`/`max`, case-insensitive. | `count`/`sum` have a defined answer for an empty table (0); `avg`/`min`/`max` return `QIHSE_PARALLEL_ERR_NO_RESULT` rather than 0. A non-numeric value in a numeric aggregate is `_ERR_DATA`; an `agg_column` no key carries is `_ERR_NO_RESULT` for every function |

Error codes: `QIHSE_PARALLEL_ERR_ARGS`, `_UNSUPPORTED`, `_THREAD`, `_NOMEM`,
`_STORE`, `_DATA`, `_NO_RESULT`, `_LIMIT`.

**What is not parallel, stated in the header and here:** `qihse_kv_foreach_user()`
is the only enumeration the KV layer exposes and it has no prefix, range or
resume form, so the keyspace traversal runs once on the calling thread and
materialises the rows before partitioning them. Only the per-row work — the row
copies, the numeric parse, the hash build/probe — is parallel.

### 8.4 AI memory and embeddings — `include/qihse_ai_memory.h`

Source: `src/spinnaker/qihse_ai_memory.c`.
Tests: `tests/test_ai_memory.c` (`make test-ai-memory`, including the RBAC
negative test) and `tests/test_ai_memory_embed.c`
(`make test-ai-memory-embed`); also the `fabric-semantic-recall` workload in
`tests/gold/pack.v1.gold`.

Records live in the `aimem:` KV namespace and are indexed by the FTS engine for
recall; vectors are stored under `aimemv:<id>`, bound to the name of the
embedder that produced them. Every entry point takes an explicit security
context — there is no context-free variant — and every ranking mode resolves
candidates through the same authorization-aware read, so no mode can rank,
score, or even count a record the principal cannot see.

| Function | Purpose | On failure |
|---|---|---|
| `bool qihse_ai_memory_set_embedder(const qihse_ai_memory_embedder_t* provider)` | Install an embedding provider; `NULL` restores the built-in one. A provider declares `name`, `dim` and an `embed` callback. Vectors from different providers are never compared. | `false` |
| `size_t qihse_ai_memory_embedding_dim(void)` | Dimension of the active embedder. Capped at `QIHSE_AIMEM_MAX_DIM` (1024). | `0` |
| `const char* qihse_ai_memory_embedder_name(void)` | The active embedder's name. | `""` when none is usable |
| `bool qihse_ai_memory_store(qihse_resp_server_t* server, qihse_user_t* user, const char* text, uint32_t kind, char out_id[QIHSE_AIMEM_ID_LEN + 1u])` | Remember: store `text` and index it for recall. `kind` is `QIHSE_AIMEM_EPISODIC` (1) or `QIHSE_AIMEM_SEMANTIC` (2). | `false` when the store or index rejects the write, including insufficient clearance |
| `size_t qihse_ai_memory_recall_mode(qihse_resp_server_t* server, qihse_user_t* user, const char* query, size_t limit, qihse_ai_memory_mode_t mode, qihse_ai_memory_hit_t* out, size_t out_cap)` | Recall with an explicit ranking mode: `QIHSE_AIMEM_MODE_BM25` (lexical), `_SEMANTIC` (vector similarity, so a query can match a memory that shares no words with it) or `_HYBRID` (reciprocal rank fusion of both). | number of hits written; `0` when nothing matched |
| `size_t qihse_ai_memory_recall(qihse_resp_server_t* server, qihse_user_t* user, const char* query, size_t limit, qihse_ai_memory_hit_t* out, size_t out_cap)` | BM25 recall over visible memories. | as above |
| `bool qihse_ai_memory_get(qihse_resp_server_t* server, qihse_user_t* user, const char* id, qihse_ai_memory_hit_t* out)` | Fetch one memory by id (RBAC enforced by the store). | `false` |
| `bool qihse_ai_memory_forget(qihse_resp_server_t* server, qihse_user_t* user, const char* id)` | Delete the record. The search index may retain a stale posting; recall skips records whose KV entry is gone. | `false` |
| `size_t qihse_ai_memory_count(qihse_resp_server_t* server, qihse_user_t* user)` | How many memories the caller can see. | `0` |
| `void qihse_ai_memory_hits_free(qihse_ai_memory_hit_t* hits, size_t count)` | Release the `text` of every hit. | n/a |
| `void qihse_ai_memory_reset(void)` | Drop the process-local search index (tests / shutdown). | n/a |

The built-in embedder is a **deterministic lexical vector**, not a learned
model: it hashes tokens into a fixed-width space, so similarity reflects shared
vocabulary rather than meaning. It exists so the storage, ranking, fusion and
filtering paths are complete and testable with no model present; a real model
plugs into the same interface and everything downstream is unchanged.

### 8.5 KEYSTONE change feed — `include/qihse_keystone.h`

Source: `src/black_hole/qihse_keystone.c` (feed), `src/spinnaker/qihse_resp_engine.c`
(the wire surface).
Test: `tests/test_keystone_feed_w25.c` (`make test-keystone-feed-w25`).

The feed lets an indexer consume federation change events **without** becoming
authoritative: the index identity is a tenant-scoped ANALYST holding
`QIHSE_SCOPE_FEDERATION_READ` only, so it cannot publish, enrol, revoke or
create principals. Records above the reader's clearance, outside its SCI
compartments, in another tenant, larger than the configured cap, or malformed
are skipped and counted — never delivered, not even as metadata. The clearance
decision is made per record at delivery time, so rewinding or transplanting a
cursor cannot replay past a denial.

| Function | Purpose | On failure |
|---|---|---|
| `bool qihse_keystone_feed_encode(const qihse_keystone_feed_record_t* record, const void* payload, size_t payload_len, uint8_t* out, size_t out_cap, size_t* out_len)` | Encode header + body (`QIHSE_KEYSTONE_FEED_MAGIC` `"KSFD"`, record version 1). | `false` when the record or body is outside the contract (oversized payload, out-of-range fields) |
| `bool qihse_keystone_feed_decode(const uint8_t* payload, size_t payload_len, qihse_keystone_feed_record_t* out_record, const uint8_t** out_body, size_t* out_body_len)` | Decode a journal payload, validating the declared body length against both the encoded length and the fixed header size. `*out_body` points into the caller's buffer. | `false` — an undecodable record can never reach the index |
| `qihse_user_t* qihse_keystone_feed_identity_provision(const qihse_user_t* creator, uint32_t tenant_id, uint32_t user_id, uint16_t clearance, uint16_t sci, const char* plaintext_password)` | Provision the index identity: a tenant-scoped ANALYST at exactly the requested clearance/SCI, with no user-creation delegation. Refused for tenant 0 and for any creator that does not already hold every privilege it is granting (`AGENTS.md` invariant 2). | `NULL` |
| `bool qihse_keystone_feed_identity_is_indexer(const qihse_user_t* user)` | True only for a principal provisioned by the call above that is still an active ANALYST in a non-system tenant. | `false` |
| `bool qihse_keystone_feed_identity_revoke(const qihse_user_t* actor, uint32_t user_id)` | Operator-only: drop the feed binding so the principal loses change-feed access immediately, without waiting for account destruction. | `false` |
| `bool qihse_keystone_feed_publish(qihse_federation_journal_t* journal, const qihse_user_t* publisher, const qihse_uuid_t* origin_node, const char* event_type, const char* resource_id, const qihse_keystone_feed_record_t* record, const void* payload, size_t payload_len, qihse_federation_event_t* out_event)` | Publish one feed record to the journal. Requires `QIHSE_SCOPE_FEDERATION_WRITE`, so it is denied for the index identity; the publisher may not publish above its own clearance/SCI nor outside its own tenant. | `false` |
| `qihse_keystone_feed_t* qihse_keystone_feed_open(qihse_federation_journal_t* journal, const qihse_user_t* reader, const qihse_keystone_feed_config_t* config)` | Open a feed for an authenticated reader. Allowed for the provisioned index identity and for an operator; any other principal — including a plain analyst — is refused. | `NULL` — including for a `NULL` reader or `NULL` journal |
| `void qihse_keystone_feed_close(qihse_keystone_feed_t* feed)` | Release the feed. | n/a |
| `bool qihse_keystone_feed_next(qihse_keystone_feed_t* feed, qihse_federation_event_t* out_event, qihse_keystone_feed_record_t* out_record, uint8_t** out_payload, size_t* out_payload_len)` | Deliver the next record the reader is cleared for. On success `*out_payload` is a heap copy the caller frees. | `false` at end-of-journal |
| `bool qihse_keystone_feed_ack(qihse_keystone_feed_t* feed, uint64_t offset)` | Acknowledge events up to `offset` (at-least-once: unacked events are re-delivered on resume). | `false` |
| `bool qihse_keystone_feed_resume(qihse_keystone_feed_t* feed, uint64_t cursor)` | Resume from a saved cursor. A cursor beyond the current end of the journal is refused. | `false` |
| `uint64_t qihse_keystone_feed_cursor(const qihse_keystone_feed_t* feed)` / `uint64_t qihse_keystone_feed_last_ack(const qihse_keystone_feed_t* feed)` | Current cursor / highest acknowledged offset. | `0` |
| `size_t qihse_keystone_feed_denied(const qihse_keystone_feed_t* feed)` / `size_t qihse_keystone_feed_malformed(const qihse_keystone_feed_t* feed)` | How many records were withheld and how many were malformed. | `0` |
| `bool qihse_keystone_feed_cursor_save(const qihse_keystone_feed_t* feed, const char* path)` / `bool qihse_keystone_feed_cursor_load(const qihse_user_t* reader, const char* path, uint64_t* out_cursor)` | Persist/restore the resume cursor. The file records the principal that minted it and loading it as a different principal is refused, so a cursor minted for a wider identity cannot be transplanted onto the index identity. Writes are atomic (tmp + rename) and 0600. | `false` |

`qihse_keystone_feed_config_t` carries a resource-id prefix filter ("" = all), a
resume cursor (0 = from the beginning) and a maximum payload size
(0 = `QIHSE_KEYSTONE_FEED_MAX_PAYLOAD`, 256 KiB).

### 8.6 KEYSTONE fabric index — `include/qihse_fabric_index.h`

Source: `src/spinnaker/qihse_fabric_index.c`.
Test: `tests/test_fabric_index.c`.

KEYSTONE is a **soft dependency**: located via `dlopen` at first use, so QIHSE
builds and runs without it and every index call fails closed with
`QIHSE_FABRIC_INDEX_EUNAVAILABLE`. The index keeps candidate postings only —
KEYSTONE never retains artifact content, so no second copy of classified data
exists outside the authoritative KV store.

| Function | Purpose | On failure |
|---|---|---|
| `int qihse_fabric_index_init(const char* index_dir, const char* library)` / `void qihse_fabric_index_shutdown(void)` / `bool qihse_fabric_index_is_available(void)` | Bring the soft dependency up, drop it, and report whether it is usable. `index_dir` falls back to `QIHSE_FABRIC_INDEX_DIR` then a `/tmp` path; `library` falls back to `QIHSE_KEYSTONE_LIB`, then a conventional checkout path, then the loader search path. Init is idempotent: re-initialising with a different configuration returns the current state without reloading. Shutdown is safe to call twice. | `QIHSE_FABRIC_INDEX_OK` when KEYSTONE is loaded, `QIHSE_FABRIC_INDEX_EUNAVAILABLE` when it is not (the index is then a no-op but every call remains safe), `EINVAL` on bad arguments |
| `int qihse_fabric_index_artifact_user(const char* key, const char* value, size_t value_len, uint16_t classification, uint16_t sci_compartment, qihse_user_t* user)` | Classify and trigram-index one artifact. Called from the write path after the KV write is authorized and persisted; the write-time classification/SCI is recorded with the index record so later lookups can be gated, and the caller's context is checked against the declared classification (defence in depth on top of the KV write gate). Keys containing tabs/newlines or exceeding 255 bytes are rejected. | non-zero (`EINVAL` for a bad key, `QIHSE_FABRIC_INDEX_EUNAVAILABLE` when the soft dependency is missing) |
| `int qihse_fabric_index_lookup_user(const char* pattern, qihse_user_t* user, qihse_fabric_index_record_t* out_records, size_t max_records, size_t* out_count)` | Trigram candidate lookup: indexed records whose content contains `pattern`. Candidates are substring postings — verify exact content against the authoritative KV store. Every candidate is filtered through `qihse_auth_can_access()`; a `NULL` user is denied outright. Patterns shorter than three bytes match every record. Records whose artifact was overwritten in KV remain listed until compaction; `seq` orders versions. | non-zero |
| `int qihse_fabric_index_by_class_user(qihse_fabric_index_class_t cls, qihse_user_t* user, qihse_fabric_index_record_t* out_records, size_t max_records, size_t* out_count)` | Semantic-class listing; `QIHSE_FABRIC_CLASS_UNKNOWN` selects low-confidence artifacts. Same authorization rules as `_lookup_user`. | non-zero |
| `size_t qihse_fabric_index_record_count(void)` / `const char* qihse_fabric_index_class_name(qihse_fabric_index_class_t cls)` / `const char* qihse_fabric_index_keystone_version(void)` | Introspection; the version string is `NULL` when the library is unavailable. | `0` / `NULL` |
| `int qihse_fabric_index_export_node_cap(const char* node_id, uint8_t* out_buf, size_t buf_size)` | Export a KEYSTONE NODE_CAP frame (50 bytes) into `out_buf`. | `QIHSE_FABRIC_INDEX_EUNAVAILABLE` when KEYSTONE is not loaded or lacks the symbol |

### 8.7 MongoDB wire protocol — `include/qihse_mongo_wire.h`

Source: `src/spinnaker/qihse_mongo_wire.c`.
Tests: `tests/test_mongo_wire.c` (`make test-mongo-wire`) and
`tests/test_mongo_wire_security.c` (`make test-mongo-wire-security`); also the
`mongo-wire` and `protocol-compat-probe` workloads in `tests/gold/pack.v1.gold`.

Seventeen `mongo_*` / `qihse_mongo_*` symbols are exported by `libqihse.so`.
The adapter is authorization-aware end to end: the catalog carries the bound
principal, the dispatcher refuses a `NULL` principal with code 13 and no
payload, and every reply document passes one gate — the static
`mongo_reply_doc()` in `src/spinnaker/qihse_mongo_wire.c` — which drops any
document the principal may not see and strips the stored classification/SCI
metadata before the frame is written.

| Function | Purpose | On failure |
|---|---|---|
| `int mongo_msg_parse(const uint8_t* data, size_t len, mongo_msg_t* out)` | Parse a framed message. Accepted only when the declared `message_length` fits inside `len`, the opcode is one this adapter implements, and the opcode's own header is present. | `-1`, nothing written to `out`, no byte past `len` read |
| `bson_t* mongo_msg_get_document(const mongo_msg_t* msg, size_t* offset)` | Materialise the next BSON document of the body as a heap copy the caller owns. On the first call (`*offset == 0`) the opcode's own header is skipped automatically, so a caller can walk the documents of an OP_MSG/OP_QUERY/OP_INSERT/OP_UPDATE/OP_DELETE in order. | `NULL` on a malformed document or the end of the body; `*offset` is left untouched when the document is refused |
| `mongo_catalog_t* mongo_catalog_create(qihse_document_store_t* ds)` / `mongo_catalog_t* mongo_catalog_create_auth(qihse_document_store_t* ds, qihse_user_t* user)` | Create the in-memory catalog, with or without a principal bound. The user-less accessors fail closed until a principal is bound. | `NULL` |
| `int mongo_catalog_bind_user(mongo_catalog_t* cat, qihse_user_t* user)` / `qihse_user_t* mongo_catalog_get_user(const mongo_catalog_t* cat)` / `void mongo_catalog_destroy(mongo_catalog_t* cat)` | Bind, read and release the catalog principal. | non-zero / `NULL` / n/a |
| `mongo_database_t* mongo_catalog_get_db(mongo_catalog_t* cat, const char* db)` / `mongo_collection_t* mongo_db_get_collection(mongo_database_t* db, const char* name)` / `mongo_collection_t* mongo_catalog_get_collection(mongo_catalog_t* cat, const char* db, const char* coll)` / `int mongo_catalog_drop_collection(mongo_catalog_t* cat, const char* db, const char* coll)` | Catalog navigation and collection drop. | `NULL` / non-zero |
| `bson_t* mongo_dispatch_command_as(mongo_catalog_t* cat, qihse_user_t* user, const char* db_name, const bson_t* cmd)` / `bson_t* mongo_dispatch_command(mongo_catalog_t* cat, const char* db_name, const bson_t* cmd)` | Dispatch a command document. The `_as` form takes an explicit authenticated principal; a `NULL` user is refused with error code 13 and no document bytes. The user-less form inherits the catalog's bound principal and fails closed the same way when none is bound. Implemented: `ping`, `hello`/`isMaster`, `find`, `count`, `distinct`, `aggregate`, `insert`, `update`, `delete`, `drop`, `dropDatabase`, `listCollections`, `listDatabases`. Refused loudly: `findAndModify`, `getMore` (every cursor is a single batch with id 0), `createIndexes`, `listIndexes`. | a BSON error reply the caller owns |
| `qihse_mongo_server_t* qihse_mongo_server_create(uint16_t port, void* doc_store)` / `int qihse_mongo_server_start(qihse_mongo_server_t* srv)` / `int qihse_mongo_server_stop(qihse_mongo_server_t* srv)` / `void qihse_mongo_server_destroy(qihse_mongo_server_t* srv)` | The TCP server and its per-client threads. | `NULL` / non-zero |
| `int bson_match(const bson_t* doc, const bson_t* filter)` / `int bson_match_operator(const bson_t* doc, const char* key, const bson_element_t* field, const char* op, const bson_element_t* opval, const uint8_t* raw)` / `int bson_apply_update(bson_t* doc, const bson_t* update, int is_insert)` / `bson_t** bson_aggregate(const bson_t* const* input, size_t n_in, const bson_t* pipeline, size_t n_stages, size_t* out_count)` | The matcher, the update applier and the pipeline. Implemented stages: `$match`, `$limit`, `$skip`, `$sort`, `$count`, `$project` (inclusion/exclusion only), `$unwind` and `$group` (`$sum`/`$avg`/`$min`/`$max`/`$first`/`$last`/`$push`). `n_stages == 0` runs every stage in the pipeline. | `0`/negative for the matcher; `NULL` with `*out_count == 0` for the pipeline — `$lookup`, `$facet`, `$graphLookup` and computed `$project` expressions are refused rather than silently dropped, and the dispatcher then answers `NOT_IMPLEMENTED` |

`$where` is not evaluated — there is no server-side JavaScript — and a filter
using it is refused rather than silently matching everything.

### 8.8 Cluster node federation UUID — `include/qihse_cluster_slot.h`

Source: `src/spinnaker/qihse_cluster_slot.c`.
Test: `tests/gold/workloads/gold_fabric_durable_caps.c` (the
`gold-fabric-durable-caps` workload), which asserts that a topology node derives
its federation UUID with no caller setting it and that the derived UUID resolves
to the durable capability record across a restart.

| Function | Purpose | On failure |
|---|---|---|
| `bool qihse_cluster_node_federation_uuid(const char* node_id, uint8_t out[16])` | The federation UUID of a cluster node id: **derived, not configured**. This is the single definition of the mapping; every topology node gets one automatically at upsert, so there is no caller to forget and no node that is silently unreachable in the durable stores. | `false` |

**The result is an index, not a credential.** A topology node id can arrive from
an unauthenticated path — `qihse_bus_handle_meet` upserts nodes straight from a
MEET datagram, and overlay discovery supplies hints of the same kind. What that
buys an attacker is a lookup key that resolves to an identity record they cannot
make APPROVED; enrollment remains the gate, and the durable accessors re-read
the identity record, so a discovered-but-unenrolled node resolves to nothing
usable. Nothing may treat this UUID as evidence of identity.

---

## 9. Python SDK — `python/qihse/`

The Python package is a `ctypes` binding over `libqihse.so`. It is not a
reimplementation: each method calls a C entry point. `python/qihse/__init__.py`
re-exports the engine surface and reports `__version__ = "0.3.0"`; two names are
reachable only from their module (`Container` in `python/qihse/core.py`,
`UWPClient` in `python/qihse/uwp.py`).

| Module | Public names | Notes |
|---|---|---|
| `python/qihse/core.py` | `VectorDB`, `VectorQuery`, `VectorResult`, `DistanceMetric`, `QueryMode`, `Container` (`Container` is not re-exported by `python/qihse/__init__.py`) | Vector engine plus the `.qdb` container pack/unpack path |
| `python/qihse/kv.py` | `KVStore` | `set`/`get`/`delete`/`exists`/`expire`/`keys`/`items`/`iteritems`/`size`/`clear`/`save`/`load`; every method accepts `user=None` and forwards the principal |
| `python/qihse/timeseries.py` | `TimeSeriesDB` | `insert(series_id, timestamp, value, classification=0, sci_compartment=0)`, `average_range`, `flush` |
| `python/qihse/document.py` | `DocumentStore` | `insert_json(doc_id, payload)` over a `KVStore` |
| `python/qihse/event_stream.py` | `EventStream`, `EventRecord`, `Durability` | `append`, `append_record`, `read`, `iterate`, `length`, `replay`, `truncate_torn_tail`, `consume_zero_copy`, `has_event_id` |
| `python/qihse/uwp.py` | `UWPServer` (re-exported), `UWPClient`, `UWPContext`, `UWPError` and subclasses (module-level only) | TLS-first UWP client/server |
| `python/qihse/fts.py` | `FTSIndex`, `FTSResult` | `add_document(..., semantic_class=...)`, `search`, `get_semantic_class`, `save`, `load` |
| `python/qihse/fusion.py` | `MultimodalFusion`, `FusionResult` | Hybrid vector + FTS RRF search |
| `python/qihse/neural.py` | `NeuralClassifier`, `KeystoneClass` | `classify(text) -> (class, name, confidence)` |
| `python/qihse/anchor.py` | `AnchorIndex` | `lower_bound`, `search` |
| `python/qihse/hardware.py` | `HardwareProfiler`, `HardwareProfile` | `get_profile()` |

Selected method signatures:

```python
VectorDB.create(path: str, dims: int) -> VectorDB
VectorDB.open(path: str, read_only: bool = False, mmap: bool = False) -> VectorDB
VectorDB.add_vectors(vectors: np.ndarray, ids: list[int] | None = None,
                     metadata: list[bytes] | None = None) -> None
VectorDB.search(query, k: int | None = None, metric=None,
                include_vectors: bool = False, mode=None) -> list[VectorResult]
VectorDB.build_graph(M: int = 16, ef_construction: int = 200) -> None
VectorDB.start_pg_wire(port: int = 5432, bind_address: str = "127.0.0.1") -> bool

KVStore.set(key, value, classification=0, sci_compartment=0, user=None) -> bool
KVStore.get(key, user=None) -> str | None

EventStream(log_directory, durability=Durability.FDATASYNC, read_only=False)
EventStream.append(topic: str, payload: bytes) -> bool

UWPServer.start(port, bind_address, kv=None, vdb=None, doc=None, tsdb=None,
                tls_cert=None, tls_key=None) -> bool
UWPClient.authenticate(username: str, password: str) -> None
```

Failure behaviour is exception-based where the native call cannot express the
error as a return value:

- `RuntimeError` when a native handle cannot be created or opened
  (`VectorDB.create`, `VectorDB.open`, `EventStream.__init__`).
- `ValueError` for an invalid argument combination that the native layer would
  not reject explicitly (for example `mmap=True` with `read_only=False`).
- `PermissionError` when a write is attempted on a read-only `EventStream`.
- `UWPAuthError` when `UWPServer.start()` is called while the default operator
  password is still active; `UWPConnectionError` when TLS material is missing or
  the TLS context cannot be created; `UWPPermissionError`,
  `UWPRateLimitError`, `UWPProtocolError` for the corresponding wire responses.

`UWPServer.start()` requires a certificate: either `tls_cert`/`tls_key` or the
`QIHSE_UWP_TLS_CERT`/`QIHSE_UWP_TLS_KEY` environment variables. There is no
default cleartext server path in the SDK.

`python/qihse/core.py` resolves `libqihse.so` from the repository root first
(`os.path.dirname` of the package), then from a list of system install
locations. If your build lives elsewhere, make it discoverable to the dynamic
linker rather than editing the search list.

---

## 10. Protocol compatibility

Compatibility surfaces are implemented inside QIHSE. Presence is not a claim of
byte-for-byte upstream equivalence; validate the commands your application
actually depends on.

| Protocol | Implementation | Notes |
|---|---|---|
| RESP2 / RESP3 | `src/spinnaker/qihse_resp_engine.c` | Redis-compatible command set plus the `FEDERATION.*` extension surface |
| PostgreSQL wire | `src/spinnaker/qihse_pg_wire.c` | Simple and extended query flows, transactions, virtual catalogs |
| MongoDB wire | `src/spinnaker/qihse_mongo_wire.c` | BSON, CRUD, query operators, aggregation pipeline, admin commands |
| Bolt / Cypher | `src/spinnaker/qihse_bolt.c`, `src/tractable/qihse_cypher_*.c` | Bolt 4.x handshake, PackStream, message flow |
| HTTP / REST | `src/spinnaker/qihse_http_api.c` | Route registration and JSON responses |
| Elasticsearch-style | `src/spinnaker/qihse_es_api.c` | Document/search/aggregation paths |
| ClickHouse-style | `src/spinnaker/qihse_clickhouse_http.c` | Analytical query and ingestion |
| InfluxDB-style | `src/spinnaker/qihse_influx_api.c` | Line protocol and InfluxQL-oriented paths |
| UWP (native) | `src/spinnaker/qihse_uwp.c`, `src/spinnaker/qihse_uwp_secure.c` | Unified Wire Protocol; TLS 1.3 required by default |
| RESP ↔ UWP bridge | `QIHSE_UWP_TARGET_RESP` (0x0F) | A UWP packet can execute any RESP command for an explicit principal |

### 10.1 The `FEDERATION.*` command surface

`FEDERATION.*` is restricted to the system tenant; a tenant principal receives
`NOPERM`. The following 79 subcommands are dispatched by
`qihse_resp_handle_federation()` (static) in `src/spinnaker/qihse_resp_engine.c` and were
enumerated from that function, not from a design document:

```
STATUS  STATE
NS.REGISTER  NS.UNREGISTER  NS.LIST  NS.WRITABLE
EVENT.APPEND  EVENT.REPLAY  EVENT.LENGTH
WATCH.OPEN  WATCH.NEXT  WATCH.ACK  WATCH.RESUME
OBJECT.CAS  OBJECT.GET
EPOCH.NEXT  EPOCH.CURRENT
LEASE.ACQUIRE  LEASE.READ  LEASE.RENEW  LEASE.RELEASE
MANIFEST  CONFLICT.LIST  CONFLICT.RESOLVE
GROUP.CREATE  GROUP.LIST  GROUP.SHOW  GROUP.ADD  GROUP.REMOVE  GROUP.ADVANCE
NODE.LIST  NODE.SHOW  NODE.ENROLL  NODE.APPROVE  NODE.REVOKE
SCOPE.LIST  SCOPE.CHECK  SCOPE.DEFAULTS
GOSSIP.STATUS
TRUST.STATES  TRUST.ADMISSION  TRUST.SET
SECURITY.IFACES  SECURITY.OBSERVE  SECURITY.AUDIT
SECURITY.PROFILE.GET  SECURITY.PROFILE.SET  SECURITY.NET.GET
BUILD.CREATE  BUILD.SHOW  BUILD.TRANSITION  BUILD.LIST  BUILD.STATES
PKG.MODES  PKG.SET  PKG.GET
BUILDER.CAP  BUILDER.SHOW
PROV.NODE  PROV.SHOW  PROV.EDGE  PROV.TRACE  PROV.IMPACT
SUPPLY.SBOM  SUPPLY.SBOM.GET  SUPPLY.VULN  SUPPLY.VULN.COUNT
SUPPLY.SNAPSHOT  SUPPLY.SNAPSHOT.LIST
SCHEMA.CHECK  SCHEMA.MIGRATE  SCHEMA.PROGRESS  SCHEMA.STATUS
SNAPSHOT.CREATE  SNAPSHOT.SHOW  SNAPSHOT.VERIFY
REJOIN.STEPS  REJOIN.STATUS
METRICS
```

`FEDERATION.METRICS` renders the label-bounded metric set; `FEDERATION.REJOIN.STEPS`
returns the ordered reconciliation sequence; `FEDERATION.STATUS` returns the
status object described in [§1.2](#12-f1--consistency-classes-namespaces-status).

### 10.2 The `FABRIC.*` command surface

The AI compute fabric dispatches over RESP as well. `FABRIC.CAPS` and
`FABRIC.RESULT` are refused outside the system tenant. Enumerated from
`src/spinnaker/qihse_resp_engine.c`:

```
FABRIC.CAPS                                  cluster capability map
FABRIC.SUBMIT [<type>] <min_isa> <need_npu> <payload>
FABRIC.RESULT <job-id>                       read a job record
```

`FABRIC.CAPS` prefers the durable capability record
([§1.7](#17-w24--durable-node-capability-records-federationnodeuuid)) and falls
back to the live in-memory hint, reporting `src=durable` or `src=hint` so a
caller can tell them apart.

`FABRIC.SUBMIT` executes **locally only**. The four job types named in
[ai_fabric.md](architecture/ai_fabric.md) are `embed` and `keystone-ingest`
(executors exist) and `inference` and `index-build` (REFUSED with
`job type not implemented` rather than accepted and ignored). A job whose
best-fit node is another node is recorded `queued` with the chosen target and
never runs — recorded as queued rather than done so the record does not claim a
dispatch that did not happen. Both gaps are recorded in
`tests/gold/pack.v1.gold` under the `ai-fabric` area. Job records live at
`fabric:job:<job-id>` and are what `FABRIC.RESULT` returns. Verified by
`tests/test_fabric_jobs.c` (`make test-fabric-jobs`) and the `fabric-job-model`
gold workload.

---

## 11. Configuration knobs

Environment variables read by `getenv()` in production code. Benchmark-only
knobs (`QIHSE_BENCH_*`) are omitted, and so are the standard environment
variables the tree consults rather than defines (`TMPDIR` for the replication
staging area in `src/spinnaker/qihse_repl.c`, `HOME` for the vector-DB default
configuration location in `src/broad_oak/qihse_vector_db.c`).

The inventory below was enumerated from the tree with
`getenv("...")` over `src/`, `core/`, `persistence/`, `memory/`, `backends/`,
`tools/`, `python/` and `sdks/`: 43 distinct names, of which 38 are QIHSE knobs
listed here, 3 are benchmark-only (`QIHSE_BENCH_DATASET`,
`QIHSE_BENCH_SWEEP`, `QIHSE_BENCH_TRINARY_SCORE`) and 2 are the standard
variables named above. Two further variables are listed because the Python SDK
reads them, through `os.environ` rather than `getenv()`:
`QIHSE_UWP_TLS_CERT` and `QIHSE_UWP_TLS_KEY`.

### 11.1 Storage and paths

| Variable | Read by | Purpose |
|---|---|---|
| `QIHSE_DATA_DIR` | `src/black_hole/qihse_kv_store.c`, `core/qihse_audit.c`, `tools/qihse_redis_server.c` | Base directory for persistent data |
| `QIHSE_CONF_FILE` | `src/broad_oak/qihse_vector_db.c` | Vector DB configuration file |
| `QIHSE_KEY_DIR` | `persistence/qihse_pqc_crypto.h` | Key directory used by the PQC helpers |
| `QIHSE_KEYS_DIR` | `tools/qihse_keygen.c` | Output directory for `qihse_keygen` |
| `QIHSE_FABRIC_INDEX_DIR` | `src/spinnaker/qihse_fabric_index.c` | KEYSTONE fabric index directory |
| `QIHSE_KEYSTONE_LIB` | `src/spinnaker/qihse_fabric_index.c` | Path to the KEYSTONE shared library |
| `QIHSE_GEOIP_DIR` | `src/broad_oak/qihse_quantum_defense.c` | GeoIP MMDB directory |

### 11.2 Security and authentication

| Variable | Read by | Purpose |
|---|---|---|
| `QIHSE_OPERATOR_PASSWORD` | `core/qihse_auth.c` | Bootstraps the operator instead of `qihse_auth_bootstrap_operator()`. Network services refuse to bind while the default password is active |
| `QIHSE_AUTH_PEPPER` | `core/qihse_auth.c` | Optional server-side pepper mixed into the password HMAC |
| `QIHSE_FIPS_MODE` | `core/qihse_auth.c` | `required` binds base and FIPS providers, validates `fips=yes`, and fails closed if unavailable |
| `QIHSE_PW_ITERATIONS` | `core/qihse_auth.c` | PBKDF2 iteration override; test builds only, and downgrades below the production floor are rejected |
| `QIHSE_ALLOW_DESTROY_OPERATOR` | `core/qihse_auth.c` | Permits destroying the operator principal |
| `QIHSE_UWP_ALLOW_INSECURE` | `src/spinnaker/qihse_uwp_secure.c` | Explicit opt-in to cleartext/legacy UWP transport |
| `QIHSE_UWP_TLS_CERT`, `QIHSE_UWP_TLS_KEY` | `python/qihse/uwp.py` | Certificate and key used by `UWPServer.start()` when no explicit arguments are given |
| `QIHSE_DISABLE_PQC` | `core/qihse_audit.c` | Disable post-quantum container crypto |
| `QIHSE_ENFORCE_INTEGRITY`, `QIHSE_SKIP_INTEGRITY` | `persistence/qihse_container.c` | Container integrity enforcement / explicit skip |
| `QIHSE_SKIP_OPTIONAL_SECTIONS` | `persistence/qihse_vector_store.c` | Skip optional sections when loading a vector store |

### 11.3 Networking and cluster

| Variable | Read by | Purpose |
|---|---|---|
| `QIHSE_UWP_REUSEPORT` | `src/spinnaker/qihse_uwp.c`, `src/spinnaker/qihse_uwp_secure.c` | Enable `SO_REUSEPORT` on the UWP listener |
| `QIHSE_XDP_IFACE`, `QIHSE_XDP_OBJ` | `src/spinnaker/qihse_uwp.c`, `src/spinnaker/qihse_uwp_secure.c`, `src/networking/qihse_af_xdp.c` | AF_XDP interface and object file |
| `QIHSE_BRAIN_WORKERS` | `src/spinnaker/qihse_cluster_brain.c` | Brain observe-pass worker count (default `min(cores, 8)`) |

### 11.4 Engines, memory, and CPU paths

| Variable | Read by | Purpose |
|---|---|---|
| `QIHSE_VDB_MAX_MEMORY_BYTES` | `src/broad_oak/qihse_vector_db.c` | Vector DB memory budget |
| `QIHSE_SEARCH_DEFAULT_K` | `src/broad_oak/qihse_vector_db.c` | Default result count |
| `QIHSE_CACHE_MAX_ENTRIES` | `src/broad_oak/qihse_vector_db.c` | Query cache capacity |
| `QIHSE_GRAPH_M`, `QIHSE_GRAPH_EF_CONSTRUCTION` | `src/broad_oak/qihse_vector_db.c` | HNSW build parameters |
| `QIHSE_MEMORY_HOT_THRESHOLD`, `QIHSE_MEMORY_COLD_THRESHOLD`, `QIHSE_MEMORY_MAINTENANCE_INTERVAL` | `src/broad_oak/qihse_vector_db.c` | Memory-maintenance thresholds and cadence |
| `QIHSE_HPU_CACHE_MB` | `memory/src/qihse_uma.c` | HPU cache size |
| `QIHSE_CRC16_BACKEND` | `src/spinnaker/qihse_crc16.c` | CRC16 implementation selection |
| `QIHSE_CRC32C`, `QIHSE_CRC_THREADS`, `QIHSE_PARALLEL_CRC` | `persistence/qihse_container.c`, `persistence/qihse_vector_store.c` | Checksum backend and parallel CRC tuning |
| `QIHSE_ENABLE_AMX`, `QIHSE_ENABLE_AVX512`, `QIHSE_ENABLE_AVX_VNNI`, `QIHSE_FORCE_FULL_FEATURES` | `backends/cpu/qihse_cpu_detect.c` | Force or disable specific CPU execution paths |

### 11.5 Persistence key prefixes

Federation and operations state is namespaced inside the caller's KV store:

| Prefix | Owner |
|---|---|
| `fedns:` | namespace registry |
| `fedreq:` | idempotency ledger |
| `fedconf:` | conflict objects |
| `fedobj:` | CAS-managed objects |
| `fedepoch:` | per-node fencing counters |
| `fedlease:`, `fedleasereq:`, `fedleaseres:` | leases, request index, fencing high-water mark |
| `fedgrp:` | replication groups |
| `fednode:` | node identity records |
| `federation/node/<uuid>` | durable node capability records ([§1.7](#17-w24--durable-node-capability-records-federationnodeuuid)) |
| `fedreplay:` | gossip replay windows |
| `federation` | journal topic in the event stream |
| `schema/migration:`, `schema/progress:` | schema evolution |
| `snapshot/manifest:` | snapshot manifests |
| `rejoin/state:` | resumable rejoin progress |
| `security/runtime-profile:<service>:<version>` | runtime hardening profiles |
| `security/runtime-network-profile:<service>:<version>` | network exposure profiles |
| `security/audit/<node>/<service>/<hlc>` | self-audit evidence records |
| `aimem:` | AI memory records (FTS-indexed) |
| `aimemv:<id>` | AI memory embedding vectors, bound to the embedder name that produced them |
| `fabric:ingest:<job-id>` | fabric artifacts indexed through KEYSTONE |
| `fabric:job:<job-id>` | fabric job records, and the result `FABRIC.RESULT` returns |

---

## 12. Known gaps and unverified areas

Stated plainly rather than omitted:

1. **Backup writer — implemented; the roadmap entry is stale.** The ROADMAP
   follow-up list still says "the writer that produces the referenced data is
   not written". The writer and reader exist in `src/federation/qihse_backup.c`,
   are declared in `include/qihse_backup.h`, are exported by `libqihse.so`, and
   are verified by `tests/test_federation_backup.c`, which is part of the
   default `make test` list. The *legacy* whole-store surface in
   `src/tractable/qihse_backup.c` is still a stub — see
   [§2.3](#23-snapshot-backup--includeqihse_backuph).
2. **Backup authentication — planned.** The backup container is
   integrity-checked but not authenticated; the header states that
   authenticating it against the node identity key is the follow-up.
3. **Federation consensus — planned.** Scoped replication groups, terms and
   voters exist as data structures, and `include/qihse_operations.h` implements
   the ordered rejoin sequence. There is no Raft, no leader election and no
   commit rule in the federation layer, and none is claimed.
4. **The `qihse_raft` module is separate and untested.** `include/qihse_raft.h`
   and `src/spinnaker/qihse_raft.c` implement a Raft-shaped state machine
   (election timeout, AppendEntries handling, ML-DSA-signed WAL entries) with no
   test target in `tests/` and no entry in the CI test list. The cluster
   failover path that *is* tested uses `qihse_cluster_failover`, a coordinator
   rather than Raft. Treat the Raft module as unverified.
5. **Python federation SDK — not written.** The Python package covers the
   engines and UWP; it does not expose the `FEDERATION.*` controller surface.
   Use RESP for controller work.
6. **Rust SDK — implemented, unverified against the C surface.** An earlier
   revision of this document said `sdks/rust/` contained only `Cargo.toml` and
   `Cargo.lock`. It now contains nine modules under `sdks/rust/src/`
   (`lib.rs`, `client.rs`, `query.rs`, `http.rs`, `mongo.rs`, `cdc.rs`,
   `metrics.rs`, `types.rs`, `error.rs`). There is still no Rust test target and
   no entry in the CI test list, so the honest label for this surface is
   `partial — status unverified`: the source exists, nothing in the tree
   exercises it.
7. **Federation transport CA provisioning — external.** QIHSE can create and
   use a federation CA, but certificate provisioning for a real fleet is an
   operator procedure outside the process. The header states this.
8. **Per-connection revocation re-check — not implemented.** The three-layer
   decision *is* wired into the live handshake: `fed_verify_cb()` in
   `src/federation/qihse_federation_transport.c` calls
   `qihse_federation_peer_verify()` from `SSL_VERIFY_PEER |
   SSL_VERIFY_FAIL_IF_NO_PEER_CERT`. What is missing is a re-check of an
   *existing* session when a node is revoked mid-session; reconnect is required
   to observe revocation on the transport.
9. **`local_node` is currently unused** in
   `qihse_federation_namespace_writable()`; the header reserves it for finer
   authority checks. Passing it is still required for future compatibility.
10. **Failure modes not documented in headers.** A few functions (for example
    `qihse_federation_watch_resume()` and `qihse_schema_progress_set()`) return
    `bool` without stating in the header which condition produces `false`. Their
    behaviour is consistent with the module conventions in
    [Conventions](#conventions), but the specific reject reasons are not
    enumerated in the header.
11. **Detached signature primitives have no direct test — `partial — status
    unverified`.** `qihse_federation_sign()`, `qihse_federation_verify()` and
    `qihse_federation_pkey_sig_alg()` ([§1.6](#16-f5--trust-plane)) are used in
    production paths and are reached indirectly by
    `tests/test_brain_fed_journal.c`, but no test calls them directly.
12. **`FABRIC.SUBMIT` does not dispatch to another node — partial.** The two
    local executors and the refusal path are tested
    (`tests/test_fabric_jobs.c`); remote dispatch and the `inference` and
    `index-build` executors are not built. See
    [§10.2](#102-the-fabric-command-surface) and the `ai-fabric` area of
    `tests/gold/pack.v1.gold`.
13. **The Rust, C and Python compatibility SDKs under `sdks/` are outside this
    reference.** Only `python/qihse/` ([§9](#9-python-sdk--pythonqihse)) is
    enumerated here. `sdks/python/` (native CPython bindings),
    `sdks/c/qihse_libpq.h`, `sdks/c/qihse_mongo_c.h` and `sdks/rust/` exist and
    are not verified by this document.
