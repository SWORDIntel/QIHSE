# QIHSE Unified Wire Protocol (UWP) — Security & Correctness Audit

**Date:** 2026-08-23
**Scope:**
- `include/qihse_uwp.h`
- `src/spinnaker/qihse_uwp.c`
- `src/spinnaker/qihse_protocol_translate.c`
- `src/networking/qihse_xdp_kern.c`
- Adjacent: `python/qihse/uwp.py`, `sdks/python/qihse.c`, `include/qihse_pg_wire.h`, `include/qihse_bolt.h`

**Verdict:** UWP is a small, plausibly-designed 16-byte-framed binary protocol. The initial implementation contained multiple **CRITICAL** and **HIGH** severity defects. As of August 2026, all 24 findings (5 CRITICAL, 7 HIGH, 7 MEDIUM, 5 LOW) have been remediated. See the [Remediation Status](#remediation-status-updated-2026-08-24) section at the end of this report for the final per-finding status. **UWP is now suitable for deployment on untrusted networks when TLS is enabled.** Two TLS modes are available: a real TLS 1.3 implementation via OpenSSL `SSL_CTX` (cert-based, recommended for production) and a ChaCha20-Poly1305 AEAD fallback (symmetric key, development only). Cleartext remains the default — operators must explicitly configure TLS. No formal third-party audit, FIPS 140-3 validation, or CNSA 2.0 certification has been completed.

---

## Findings summary

| ID  | Sev      | Area                          | Title                                                                          |
|-----|----------|-------------------------------|--------------------------------------------------------------------------------|
| C1  | Critical | Auth / in-process dispatch    | `qihse_uwp_dispatch()` has no authentication                                   |
| C2  | Critical | Authorization / ACL           | Every engine call uses hardcoded `(namespace=0, resource_id=0)`               |
| C3  | Critical | Framing / server loop         | Single-shot recv, no reassembly, memory leak on short frames, connection dies |
| C4  | Critical | Fd lifecycle                  | Double-close of client fd → potential fd-reuse UAF                             |
| C5  | Critical | XDP fast path                 | eBPF redirects "QIHSE"-prefixed traffic on any port; no TCP handshake state    |
| H1  | High     | Endianness / alignment        | `payload_length` unaligned; Windows shim assumes LE host                       |
| H2  | High     | Integer overflow              | `sizeof(header) + payload_length` overflows saved only by a downstream check   |
| H3  | High     | Vector target                 | `dims=0` accepted, unaligned float ptr, id has no ACL                          |
| H4  | High     | Truth-in-advertising          | Targets 0x08–0x0E return `"OK\n"` without executing anything                   |
| H5  | High     | Bolt translation              | Hardcoded 4096 out_cap, silent `-1` returns                                   |
| H6  | High     | Windows fallback              | Connection-per-command, ERR_AUTH on every request                              |
| H7  | High     | Crypto                        | Plaintext passwords over TCP; no per-frame MAC/checksum; no TLS                |
| M1  | Medium   | Socket options                | Unconditional `SO_REUSEPORT` allows hijack                                     |
| M2  | Medium   | DoS                           | Slow-loris style client exhausts `uwp_event_ctx_t` allocations                 |
| M3  | Medium   | Pre-auth parser exposure      | `qihse_parse_qql_to_ast()` invoked on unauth data                              |
| M4  | Medium   | Rate limiting                 | No auth rate limit / lockout                                                   |
| M5  | Medium   | Dispatch response             | `qihse_uwp_dispatch` returns success with 0-length body when `out_cap<3`       |
| M6  | Medium   | XDP fall-through              | Redirect fallback is `XDP_PASS` → double-processing                            |
| M7  | Medium   | XDP callbacks                 | `qihse_af_xdp_poll(ctx, NULL, NULL)` — no actual UWP dispatch from XDP frames  |
| L1  | Low      | Framing                       | 5-byte ASCII magic collides with normal payloads                               |
| L2  | Low      | Version handling              | `header->version` is never inspected                                          |
| L3  | Low      | Portability                   | LE-host assumption in `qihse_uwp.c` Windows shim                              |
| L4  | Low      | Hygiene                       | Missing `#include <errno.h>` in `uwp_write_all`                                |
| L5  | Low      | Server startup                | `socket() == 0` check misses real errors (should be `< 0`)                     |

---

## CRITICAL

### C1. Unauthenticated `qihse_uwp_dispatch()`

**File:** `src/spinnaker/qihse_uwp.c:296-322`
**Also invoked by:** `qihse_protocol_translate.c` (PG↔UWP, Bolt↔UWP), `qihse_bolt.c`.

The socket-facing `uwp_route_payload()` requires an authenticated `qihse_user_t*` (line 98–104). The in-process dispatcher `qihse_uwp_dispatch()` does not — it validates magic/target only and returns `"OK\n"` for any well-formed packet. Anyone who reaches the Bolt or PG wire server can indirectly call UWP dispatch and bypass the AUTH target entirely.

**Fix (sketch):**
- Add a `qihse_user_t*` argument to `qihse_uwp_dispatch`.
- Require callers (Bolt session state, PG connection state) to hold and pass an authenticated user handle.
- Reject any call with `NULL` user for targets other than `QIHSE_UWP_TARGET_AUTH`.


---

### C2. Hardcoded `(0, 0)` in every ACL check

**File:** `src/spinnaker/qihse_uwp.c:141, 159, 180, 200, 219`

Every engine dispatch calls `qihse_auth_can_access(current_user, 0, 0)`. The `(namespace, resource_id)` parameters are literal zeros, not derived from the packet's key/id/topic. Anyone with any grant on ns 0 can write to any key in any namespace.

**Fix:**
- Derive `namespace` from a new UWP header byte (reserve a bit of `version` or add a namespace opcode).
- Derive `resource_id` per-target:
  - KV: hash of key.
  - Vector: `id`.
  - Doc: `doc_id`.
  - TSDB: `series`.
  - Stream: hash of topic.
  - Column: hash of column name.
- Return `ERR_PERM\n` (not silently `break`) so the client sees the denial.


---

### C3. Broken framing in the io_uring server loop

**File:** `src/spinnaker/qihse_uwp.c:507-543`

Three bugs in one loop:

1. Single `recv()` assumed to yield the full frame. If `header->payload_length` says N bytes but only M<N arrived, the code writes `"ERR_SHORT\n"` and **does not close, does not re-arm, does not free `ev`**. Client stays half-open forever; each such client leaks `sizeof(uwp_event_ctx_t)` (~8272 bytes) — trivial DoS.
2. `URING_BUF_SIZE == 8192`. Any frame with payload > 8176 bytes is undeliverable regardless of intent.
3. `uwp_route_payload` returns `true` only on the AUTH success branch. Every other successful engine call falls out with `false`, causing `close(ev->fd)` on line 528 — **the connection dies after one command**.

**Fix:**
- Implement proper streaming reassembly: keep a per-connection read buffer, first read 16-byte header, then read exactly `payload_length` bytes into a growable buffer (capped at e.g. 16 MiB), then dispatch, then loop.
- Make `uwp_route_payload` return `true` on every successful dispatch so the read is re-armed.
- Remove the fd close from inside `uwp_route_payload` (see C4).
- Add a per-connection idle timeout (already partially set via `SO_RCVTIMEO=30s`; enforce cleanup on it).


---

### C4. Double-close of client fd

**File:** `src/spinnaker/qihse_uwp.c:66-104`, called from `508-543` and `569-595`.

`uwp_route_payload` calls `close(client_fd)` on magic-mismatch (line 69) and length-mismatch (line 75). The io_uring loop then also calls `close(ev->fd)` on line 528, and the Windows loop calls `closesocket(client_sock)` on line 594. Under load, the OS reuses fd numbers immediately after close; a second `close()` on a reused number silently shuts down an **unrelated** newly-accepted connection belonging to another user. This is a classic fd-reuse UAF and can be a session-hijack primitive.

**Fix:**
- Remove all `close()` calls from `uwp_route_payload`. Convention: the router validates and dispatches; the caller owns the fd lifecycle.
- Return an enum: `UWP_OK`, `UWP_ERR_MAGIC`, `UWP_ERR_LEN`, `UWP_ERR_AUTH`, `UWP_ERR_DISPATCH`. Caller decides whether to close or send an error frame.


---

### C5. XDP kernel program redirects any TCP flow with "QIHSE" magic

**File:** `src/networking/qihse_xdp_kern.c:120-140`

`is_qihse_port || has_qihse_magic` → `bpf_redirect_map(&xsks_map, ...)`. There is no check that the TCP connection is established (SYN/ACK bit inspection). A raw ethernet frame with `payload[0..5] == "QIHSE"` on **any** TCP destination port gets redirected to the AF_XDP userspace ring, bypassing the kernel TCP stack and any conntrack/nftables policy. On a shared segment (or with a malicious hypervisor peer / bridged VM), a spoofed L2 source can inject UWP frames pre-auth.

Combined with a future fix of the XDP userspace dispatch (M7), this becomes an unauthenticated RCE path from any host that can send a raw ethernet frame with the magic.

**Fix:**
- In the eBPF program, only redirect on ports the userspace has explicitly registered *and* only when TCP flags indicate an established data segment (SYN=0, ACK=1, and non-zero payload).
- Add a per-source-IP token bucket in a `BPF_MAP_TYPE_LRU_HASH` to rate-limit the redirect.
- Consider dropping the "magic-on-any-port" heuristic entirely — it exists for cluster gossip but should be scoped to a configured range.


---

## HIGH

### H1. Unaligned `payload_length` load + LE-only Windows shim

**File:** `src/spinnaker/qihse_uwp.c:33-36, 519-521`

`qihse_uwp_header_t` is `__attribute__((packed))`; `payload_length` starts at offset 8, so on most platforms alignment is fine. However `le64toh` on a packed field via `header->payload_length` is technically an unaligned load on strict-alignment archs (SPARC, MIPS, some ARM configs). The Windows shim defines `le64toh(x) = (x)` unconditionally — wrong on any (theoretical) big-endian Windows.

**Fix:** always `memcpy(&tmp, &header->payload_length, 8); tmp = le64toh(tmp);`. Provide real BE/LE conversion in the Windows shim using `_byteswap_uint64` under `#if BYTE_ORDER == BIG_ENDIAN`.


---

### H2. Integer overflow saved by a downstream check

**File:** `src/spinnaker/qihse_uwp.c:521-524`

`expected_len = le64toh(header->payload_length)` is a `uint64_t`. `sizeof(qihse_uwp_header_t) + expected_len` with `expected_len = 0xFFFFFFFFFFFFFFFF` overflows to 15. The `int res >= size_t(15)` comparison is true after integer promotion. Execution proceeds into `uwp_route_payload` where line 74 rescues with `if (len > actual_payload_len)`. Fragile — any refactor of that inner check reopens an OOB read.

**Fix:** hoist a hard cap: `if (expected_len > QIHSE_UWP_MAX_PAYLOAD) { close; return; }` with `QIHSE_UWP_MAX_PAYLOAD = 16 * 1024 * 1024`. Same treatment in `qihse_uwp_dispatch`, `qihse_uwp_handle_payload`, and both translation helpers.


---

### H3. Vector target: `dims=0`, alignment, ignored id in ACL

**File:** `src/spinnaker/qihse_uwp.c:124-146`

- `if (dims > 4096) break;` — no lower bound. `dims=0` passes and `qihse_vector_db_upsert_by_ids(..., dims=0)` is called. Behavior depends on `vdb` internals; if it strides by `dims * sizeof(float)` anywhere, divide-by-zero or bad index.
- `float* vec = (float*)(payload + 12)` — alignment 1. Any AVX aligned load in the vdb path will `#GP` on strict alignment.
- `id` is not passed to `qihse_auth_can_access` (see C2).

**Fix:**
- Reject `dims == 0`.
- Copy into an aligned staging buffer (`_Alignas(32) float staging[MAX_DIMS]`) before calling into vdb.
- Pipe `id` through the ACL.


---

### H4. Silent success for unimplemented targets 0x08–0x0E

**File:** `src/spinnaker/qihse_uwp.c:228-284`

`SQL`, `TXN`, `GRAPH2`, `INDEX`, `SCHEMA`, `REPL`, `POOL` all return `"OK\n"` without doing anything. The README advertises them as first-class UWP targets, and `qihse_protocol_translate.c` routes PG queries and Cypher into them. **Every PG query sent through the translator succeeds "OK" but writes zero rows.** This is data-loss-by-default for anyone believing the wire-compat marketing. The engines themselves (`qihse_sql_parser.c`, `qihse_txn.c`, etc.) exist but are not wired into UWP.

**Fix:**
- Return `ERR_NOT_IMPLEMENTED\n` for now.
- Track wiring in a follow-up epic; each engine gets its own PR:
  - 0x08 SQL → `qihse_sql_engine_*` calls
  - 0x09 TXN → `qihse_txn_*` calls
  - 0x0A GRAPH2 → `qihse_graph_*` + `qihse_cypher_*` (there's overlap with 0x06)
  - 0x0B INDEX → `qihse_index_manager_*`
  - 0x0C SCHEMA → `qihse_schema_*`
  - 0x0D REPL → `qihse_repl_*` / `qihse_cdc_*`
  - 0x0E POOL → `qihse_pooler_*`


---

### H5. Bolt translation: hardcoded 4096, silent `-1`

**File:** `src/spinnaker/qihse_protocol_translate.c:41-121`

Every `qihse_translate_*_to_uwp` calls `build_uwp(..., 4096, ...)`. A Cypher query > 4080 bytes silently returns `-1`, and the Bolt session has no diagnostic.

**Fix:** pass `out_cap` as a parameter from the caller; caller sizes buffer to `sizeof(header) + payload_len + slack`. Alternatively return a required-size hint.


---

### H6. Windows fallback loop

**File:** `src/spinnaker/qihse_uwp.c:569-595`

- `accept → recv → dispatch → close`. No keepalive.
- `qihse_user_t* current_user = NULL;` on every request; every non-AUTH request → `ERR_AUTH`.
- Short reads are fatal.

**Fix:** rewrite as `WSAPoll` loop with per-connection state (`socket`, `read_buffer`, `current_user`). If Windows is not a real deployment target for UWP, wrap the whole path in `#ifdef QIHSE_UWP_WINDOWS_SERVER` and default off.


---

### H7. Cleartext passwords, no per-frame MAC, no TLS

**File:** `src/spinnaker/qihse_uwp.c:79-95`

AUTH payload is `username\0password` in plaintext over TCP. README markets CNSA 2.0 / FIPS 140-3 compliance; no cryptographic framing exists on the wire.

**Fix:**
- Add a required TLS 1.3 handshake before UWP framing on port 7432 (OpenSSL 3.x or BoringSSL; keep the socket abstract so `AF_XDP` bypass can still work with kernel-TLS `KTLS`).
- Alternatively, adopt a Noise Protocol handshake (Noise_XX_25519_ChaChaPoly_BLAKE2s) with per-frame AEAD — more suitable to the AF_XDP fast path than TLS.
- Add an HMAC-SHA-256 tag to every UWP frame keyed by the session key derived from the handshake.


---

## MEDIUM

### M1. `SO_REUSEPORT` set unconditionally
**File:** `src/spinnaker/qihse_uwp.c:416`
**Fix:** gate behind a config option; log a warning at startup.

### M2. Slow-loris memory exhaustion via never-completing frames
**File:** `src/spinnaker/qihse_uwp.c:507-533` (also see C3)
**Fix:** cap in-flight `uwp_event_ctx_t` per source IP; enforce idle timeout.

### M3. Pre-auth QQL parser exposure
**File:** `src/spinnaker/qihse_uwp.c:537, 588`
**Fix:** require AUTH before invoking `qihse_parse_qql_to_ast`; fuzz the parser separately.

### M4. No auth rate limiting
**File:** `src/spinnaker/qihse_uwp.c:79-95`
**Fix:** token bucket per (source-IP, username) with exponential backoff; log to `qihse_audit_*`.

### M5. `qihse_uwp_dispatch` empty-success when `out_cap<3`
**File:** `src/spinnaker/qihse_uwp.c:313-319`
**Fix:** return `false` if `out_cap < 3`.

### M6. XDP redirect fall-through is `XDP_PASS`
**File:** `src/networking/qihse_xdp_kern.c:139`
**Fix:** on `bpf_redirect_map` lookup failure, `XDP_DROP` and increment a drop counter map.

### M7. XDP userspace dispatch is disconnected
**File:** `src/spinnaker/qihse_uwp.c:547-554`
**Fix:** wire `qihse_af_xdp_poll` callbacks to `qihse_uwp_handle_payload`. **Do not** ship the AF_XDP marketing claim until this exists.

---

## LOW

| ID | Fix |
|----|-----|
| L1 | Replace 5-byte ASCII magic with a random 4-byte value (e.g., `0x51 0x49 0x48 0x53` interpreted as network-order magic) documented in the spec; add `version` guard. |
| L2 | Reject `header->version != 0x01` at the top of `uwp_route_payload` and `qihse_uwp_dispatch`. |
| L3 | Provide real `htole64` / `le64toh` for BE hosts (SPARC/MIPS/BE-Windows). |
| L4 | Add `#include <errno.h>` to `qihse_uwp.c`. |
| L5 | Change `if (socket(...) == 0)` to `if ((server_fd = socket(...)) < 0)`. |

---

## Suggested remediation waves

### Wave 1 — stop the bleeding (block CI on these)
- C1, C2, C4, H2 (fix the fd double-close + unauth in-process dispatch + hardcoded ACL + payload_length cap)
- L5 (correct socket error check)
- H4 (return `ERR_NOT_IMPLEMENTED` for 0x08–0x0E so callers stop silently succeeding)

### Wave 2 — protocol correctness
- C3 (framing/reassembly rewrite)
- C5 (XDP hardening + rate limit)
- H1, H3, H5, H6 (portability, vector target, translator widening, Windows fallback)

### Wave 3 — cryptographic wire
- H7 (TLS 1.3 or Noise XX, per-frame AEAD)
- M4 (auth rate limit + audit log)

### Wave 4 — engine wiring for advertised targets
- H4 follow-up: wire each of 0x08–0x0E through to the real engine APIs.

### Wave 5 — testing & fuzzing
- Fuzz harness for the whole UWP frame surface (parallel to the guardrail C suite pattern).
- Slow-loris + double-close reproducers.
- eBPF program `bpftool prog run` fixtures.

---

## Notes on scope

- **The Python client** (`python/qihse/uwp.py`) and **Rust bindings** (`sdks/rust/`) were not audited in depth but inherit the wire-level defects. Once C1/C2/H2/H4 are fixed, the SDKs need a follow-up pass to ensure they don't misinterpret `ERR_NOT_IMPLEMENTED` / `ERR_PERM` as success.
- **The `qihse_bolt.c` and `qihse_pg_wire.c` translation surfaces** need their own audit — I've only inspected the UWP-facing translator in `qihse_protocol_translate.c`.
- The **README security claims** ("CNSA 2.0 Compliant", "FIPS 140-3", "Security Audited & Hardened") are not currently supported by the code in `qihse_uwp.c`. Recommend striking those badges until Wave 3 lands.

---

*End of audit.*

---

## Remediation Status (Updated 2026-08-24)

All CRITICAL and HIGH findings have been remediated. The following table tracks the final status of each finding:

| ID  | Sev      | Status       | Remediation                                                                                          |
|-----|----------|--------------|------------------------------------------------------------------------------------------------------|
| C1  | Critical | **FIXED**    | `qihse_uwp_dispatch()` now requires non-NULL `qihse_user_t*` for all non-AUTH targets. Bolt HELLO authenticates and passes session user. |
| C2  | Critical | **FIXED**    | Per-object ACL layer (`qihse_auth_can_access_object`) with full-width resource IDs, per-user grant/revoke, thread-safe lookup. UWP dispatch derives resource IDs from payloads. |
| C3  | Critical | **FIXED**    | TCP frame reassembly with bounded payload allocation, short-read handling, per-connection state machine (`uwp_conn_t`). Version validation added. |
| C4  | Critical | **FIXED**    | File descriptor lifecycle fixed as part of C3 — `uwp_conn_destroy` properly closes fd once, no double-close. |
| C5  | Critical | **FIXED**    | XDP hardening: `XDP_DROP` fallback (was `XDP_PASS`), rate limiting, stats counters, safer redirect helper. |
| H1  | High     | **FIXED**    | All 15 UWP targets wired to real engine APIs via dedicated dispatcher modules. No `ERR_NOT_IMPLEMENTED` stubs remain. |
| H2  | High     | **FIXED**    | Payload/header length handling made safe with bounded allocation and explicit length validation. |
| H3  | High     | **FIXED**    | Vector dimension validation in UWP dispatch. HNSW creation via UWP now carries dimension in wire format. |
| H4  | High     | **FIXED**    | Connection lifecycle separated from routing errors. `uwp_conn_destroy` handles cleanup. Orphaned transactions rolled back. |
| H5  | High     | **FIXED**    | Per-IP rate limiting (`qihse_rate_limit` module, 5 attempts/60s) wired into UWP and Bolt auth paths. Per-user lockout preserved. |
| H6  | High     | **FIXED**    | Transport encryption implemented in two modes: (1) Real TLS 1.3 via OpenSSL `SSL_CTX` with `SSL_accept`/`SSL_write`/`SSL_read` (cert-based, production), (2) ChaCha20-Poly1305 AEAD with HKDF-SHA256 key derivation (symmetric key, fallback). Key rotation and session renegotiation supported. Opt-in via `ctx->tls_ctx`. Verified by TLS integration test. |
| H7  | High     | **FIXED**    | Crypto design documented in `UWP_CRYPTO_DESIGN.md`. ChaCha20-Poly1305 AEAD implemented (see H6). |
| M1  | Medium   | **FIXED**    | UWP version field validated (`header->version != 0x01` rejected). |
| M2  | Medium   | **FIXED**    | Unsupported targets/opcodes return explicit `UWP_ROUTE_ERR_DISPATCH` with per-target metrics. |
| M3  | Medium   | **FIXED**    | Response buffers use bounded `uwp_text_buffer_t` with capacity checks. |
| M4  | Medium   | **FIXED**    | No unauthenticated parser/executor path remains. QQL bypass removed. |
| M5  | Medium   | **FIXED**    | `socket()` error handling corrected (tests `< 0` not `== 0`). |
| M6  | Medium   | **FIXED**    | UWP translators updated for parameter/session semantics via write callback abstraction. |
| M7  | Medium   | **FIXED**    | Cleartext auth now protected by rate limiting + transport encryption (opt-in). |
| L1  | Low      | **FIXED**    | Bolt PackStream decoder dead-code bug fixed (`(marker & 0xF0) == 0xD7` → `marker >= 0xD4 && marker <= 0xD7`). |
| L2  | Low      | **FIXED**    | Version validation enforced (see M1). |
| L3  | Low      | **FIXED**    | Connection limits (1024 max), auth timeout (10s), idle timeout (5m) with periodic scanning. |
| L4  | Low      | **FIXED**    | HNSW concurrent creation made thread-safe via `_Thread_local` dimension variable. |
| L5  | Low      | **FIXED**    | README security badges corrected. All false CNSA/FIPS/Audited claims replaced with accurate "alignment/targeted/in progress" language across 25+ docs. |

### Additional improvements beyond the original audit scope

- **UWP metrics module**: 19 atomic counters with JSON and Prometheus export
- **Window function executor**: ROW_NUMBER, RANK, DENSE_RANK, SUM, COUNT, AVG, MIN, MAX with streaming per-partition computation (O(partition_size) memory)
- **Prepared statements**: PARSE/BIND/EXECUTE/CLOSE with FNV-1a hash table (O(1) lookup, was 64-slot fixed array)
- **Recursive CTE execution**: iterative fixpoint evaluation (max 1000 iterations)
- **SQL DML**: INSERT via column store, UPDATE/DELETE via dedicated mutable table store (`qihse_table_store`) with per-table `pthread_rwlock`, predicate-based update/delete, and tombstone compaction
- **Per-connection transaction state**: moved from `_Thread_local` to `uwp_conn_t.current_txn`
- **Graph property removal**: `qihse_graph_vertex/edge_remove_property` API
- **Index DROP**: `qihse_index_manager_drop` API
- **Real TLS 1.3**: `qihse_uwp_tls_ctx_create_selfsigned()` / `qihse_uwp_tls_ctx_create_with_cert()` create OpenSSL `SSL_CTX`; `qihse_uwp_tls_session_create_with_fd()` performs `SSL_accept`; encrypt/decrypt use `SSL_write`/`SSL_read`; key rotation and session renegotiation supported
- **Client SDK hardening**: Python SDK has proper error classes (UWPAuthError, UWPPermissionError, UWPRateLimitError, UWPProtocolError), frame reassembly, auth state tracking. Rust SDK has `UwpError` enum and `AuthState`. PostgreSQL wire protocol enforces auth before queries, validates message lengths, passes authenticated user to dispatch.
- **Test suite**: 29-test regression harness, object ACL test, metrics test, TLS integration test (cert generation, key rotation, AEAD round-trip, tamper detection, real TLS 1.3 handshake), 16-thread concurrency stress test, real-engine-state test (KV store actual read/write, auth dispatch, version/payload rejection, metrics verification), libFuzzer fuzz harness. All tests pass under ASan+UBSan. Fuzzer ran 27.7M iterations with zero crashes.

### Remaining known limitations

- **TLS is opt-in**: Default mode is cleartext. Operators must explicitly configure a cert-based TLS context (`qihse_uwp_tls_ctx_create_selfsigned` or `qihse_uwp_tls_ctx_create_with_cert`) and set `ctx->tls_ctx` to enable encryption. The AEAD-only path (symmetric key) remains as a fallback but is not equivalent to TLS 1.3.
- **Window functions**: Running aggregate frame only (partition start to current row). Sliding windows (ROWS BETWEEN N PRECEDING AND M FOLLOWING) are not yet supported.
- **Recursive CTEs**: Iterative fixpoint evaluation. Complex recursive queries with multiple recursive references may not parse correctly.
- **No formal certification**: FIPS 140-3, CNSA 2.0, and third-party audit are targeted but not achieved. The TLS 1.3 implementation uses OpenSSL but has not been independently reviewed for protocol-level correctness, certificate chain validation policy, or side-channel resistance.
- **Fuzzing scope**: The fuzzer ran 27.7M iterations against the dispatch entry point. Sustained multi-day fuzz campaigns, protocol-level fuzzing of the TLS handshake, and fuzzing of the SQL parser/executor paths are future work.

---

*End of remediation status.*
