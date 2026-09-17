# QIHSE API Reference

> **Status: implemented** — every C function in this reference is declared in a
> header under `include/` and is exported by the built `libqihse.so`; the Python
> surface is read from `python/qihse/`. Nothing here is transcribed from a design
> document. The one section that describes something not built is marked
> `planned` in place ([§11](#11-known-gaps-and-unverified-areas)).

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

All 244 functions declared across the nine headers this reference covers —
`include/qihse_federation.h` (110), `include/qihse_federation_mtls.h` (8),
`include/qihse_federation_repl.h` (13),
`include/qihse_federation_transport.h` (15),
`include/qihse_federation_rejoin.h` (6), `include/qihse_operations.h` (23),
`include/qihse_backup.h` (9), `include/qihse_kv_store.h` (26) and
`include/qihse_auth.h` (34) —
resolve to a definition, with one expected exception: `qihse_kv_get()`,
`qihse_kv_del()` and `qihse_kv_exists()` are `static inline` wrappers in
`include/qihse_kv_store.h`, so they compile into the caller rather than
appearing as library symbols. There is no header-only declaration in these
areas. That is a stronger statement than "the source file exists", so a
function that appears here is safe to call; a function that does not appear here
has not been verified and should be read in its header first.

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
  store under documented prefixes; see [§10](#10-configuration-knobs) for the
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
| `size_t qihse_federation_gossip_wire_size(qihse_sig_alg_t alg)` | Total wire size for an algorithm. | `0` |
| `bool qihse_federation_gossip_sign(void* pkey, qihse_federation_gossip_t* gossip)` | Sign in place with an `EVP_PKEY*` from `_node_key_load`. | `false` |
| `bool qihse_federation_gossip_verify(const uint8_t* public_key, size_t public_key_len, const qihse_federation_gossip_t* gossip)` | Verify against a raw public key using the algorithm named inside the statement. | `false` |
| `bool qihse_federation_heartbeat_serialize(const qihse_federation_heartbeat_t* hb, uint8_t* out, size_t out_cap, size_t* out_len)` | Serialise the cheap 80-byte heartbeat. | `false` |
| `bool qihse_federation_heartbeat_deserialize(const uint8_t* in, size_t in_len, qihse_federation_heartbeat_t* out)` | Parse a heartbeat. | `false` |
| `qihse_gossip_result_t qihse_federation_heartbeat_accept(void* store, void* user, const qihse_federation_heartbeat_t* hb)` | Accept liveness only: requires a recorded signed statement for the same `(sender, boot)`, a matching session id, and an advancing sequence. | a `QIHSE_GOSSIP_REJECT_*` value |
| `bool qihse_federation_membership_from_statement(const qihse_federation_gossip_t* stmt, qihse_federation_membership_t* out)` | The **only** conversion into a membership record; there is deliberately no conversion from a liveness observation. | `false` |
| `bool qihse_federation_gossip_statement_read(void* store, void* user, const qihse_uuid_t* sender_node, const qihse_uuid_t* boot_id, qihse_federation_gossip_t* out)` | Read the recorded statement for a `(sender, boot)`. | `false` if the node has not signed |
| `qihse_gossip_result_t qihse_federation_gossip_accept(void* store, void* user, const qihse_federation_gossip_t* gossip)` | Accept an authority-bearing frame: magic/version, sender trust state, signature against the enrolled key, replay window. | `QIHSE_GOSSIP_REJECT_MALFORMED`/`_VERSION`/`_UNKNOWN_SENDER`/`_UNTRUSTED_SENDER`/`_BAD_SIGNATURE`/`_REPLAY` |
| `bool qihse_federation_replay_state_read(void* store, void* user, const qihse_uuid_t* sender_node, const qihse_uuid_t* boot_id, qihse_federation_replay_state_t* out)` | Read the persistent replay window (`fedreplay:<node>:<boot>`). | `false` |

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
| `int qihse_backup_full(qihse_kv_store_t* kv, const char* output_path, qihse_backup_info_t* info)` | Whole-store export. | `-1` |
| `int qihse_backup_incremental(qihse_kv_store_t* kv, const char* output_path, uint64_t since_lsn, qihse_backup_info_t* info)` | Incremental export. | `-1` |
| `int qihse_restore(qihse_kv_store_t* kv, const char* backup_path)` | Restore from a container. | `-1` |
| `int qihse_backup_list(const char* dir, qihse_backup_info_t** out_backups, size_t* out_count)` | List containers in a directory. | `-1` |
| `int qihse_backup_verify(const char* backup_path)` | Verify a container's checksum. | `-1` |
| `void qihse_backup_info_free(qihse_backup_info_t* info)` | Release a listing entry. | n/a |

> **Contradiction with the code:** the legacy surface is a stub.
> `qihse_backup_full()` in `src/tractable/qihse_backup.c` writes an empty data
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
| `qihse_fed_tls_session_t* qihse_federation_tls_connect_fd(qihse_fed_tls_server_t* ctx_holder, int fd, qihse_peer_verdict_t* out_verdict)` | Client-side handshake on a connected fd. | `NULL` |
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

## 8. Python SDK — `python/qihse/`

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

## 9. Protocol compatibility

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

### 9.1 The `FEDERATION.*` command surface

`FEDERATION.*` is restricted to the system tenant; a tenant principal receives
`NOPERM`. The following subcommands are dispatched by
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

---

## 10. Configuration knobs

Environment variables read by `getenv()` in production code. Benchmark-only
knobs (`QIHSE_BENCH_*`) are omitted.

### 10.1 Storage and paths

| Variable | Read by | Purpose |
|---|---|---|
| `QIHSE_DATA_DIR` | `src/black_hole/qihse_kv_store.c`, `core/qihse_audit.c`, `tools/qihse_redis_server.c` | Base directory for persistent data |
| `QIHSE_CONF_FILE` | `src/broad_oak/qihse_vector_db.c` | Vector DB configuration file |
| `QIHSE_KEY_DIR` | `persistence/qihse_pqc_crypto.h` | Key directory used by the PQC helpers |
| `QIHSE_KEYS_DIR` | `tools/qihse_keygen.c` | Output directory for `qihse_keygen` |
| `QIHSE_FABRIC_INDEX_DIR` | `src/spinnaker/qihse_fabric_index.c` | KEYSTONE fabric index directory |
| `QIHSE_KEYSTONE_LIB` | `src/spinnaker/qihse_fabric_index.c` | Path to the KEYSTONE shared library |
| `QIHSE_GEOIP_DIR` | `src/broad_oak/qihse_quantum_defense.c` | GeoIP MMDB directory |

### 10.2 Security and authentication

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

### 10.3 Networking and cluster

| Variable | Read by | Purpose |
|---|---|---|
| `QIHSE_UWP_REUSEPORT` | `src/spinnaker/qihse_uwp.c`, `src/spinnaker/qihse_uwp_secure.c` | Enable `SO_REUSEPORT` on the UWP listener |
| `QIHSE_XDP_IFACE`, `QIHSE_XDP_OBJ` | `src/spinnaker/qihse_uwp.c`, `src/spinnaker/qihse_uwp_secure.c`, `src/networking/qihse_af_xdp.c` | AF_XDP interface and object file |
| `QIHSE_BRAIN_WORKERS` | `src/spinnaker/qihse_cluster_brain.c` | Brain observe-pass worker count (default `min(cores, 8)`) |

### 10.4 Engines, memory, and CPU paths

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

### 10.5 Persistence key prefixes

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
| `fedreplay:` | gossip replay windows |
| `federation` | journal topic in the event stream |
| `schema/migration:`, `schema/progress:` | schema evolution |
| `snapshot/manifest:` | snapshot manifests |
| `rejoin/state:` | resumable rejoin progress |
| `security/runtime-profile:<service>:<version>` | runtime hardening profiles |
| `security/runtime-network-profile:<service>:<version>` | network exposure profiles |
| `security/audit/<node>/<service>/<hlc>` | self-audit evidence records |

---

## 11. Known gaps and unverified areas

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
6. **Rust SDK — planned.** `sdks/rust/` contains `sdks/rust/Cargo.toml` and
   `sdks/rust/Cargo.lock` only; there is no Rust source in the tree.
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
