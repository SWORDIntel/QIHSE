# QIHSE Security Hardening Report

A comprehensive multi-pass security audit and verification identified and remediated vulnerabilities across the entire codebase, including low-level memory safety, cryptographic hygiene, authorization architecture, and wire protocols.

## Remediation Summary

### Unsafe C Functions (Mechanically Verified)
- All `system()` calls replaced with `fork`/`execvp`
- All `strcpy` and `sprintf` replaced with bounded `snprintf`/`strncpy`/`memcpy` across all production subsystems (aggregate executor, cluster bus, ClickHouse SQL, ML engine, quantization, and memory management)
- All `atoi` replaced with `strtol` (with range validation)
- All `atof` replaced with `strtof`/`strtod`
- All `strtok` replaced with reentrant `strtok_r`
- Zero unsafe function calls remain in production code

### Cryptographic Hygiene & Password Storage (CNSA 2.0 / FIPS 140-3 Aligned)
- Upgraded password verifiers to **PBKDF2-HMAC-SHA-384**:
  - Algorithm: PBKDF2 with HMAC-SHA-384 digest
  - Salt: 128-bit (16 bytes) cryptographically secure random salt generated via `RAND_bytes` DRBG
  - Work factor: Default floor of 600,000 iterations (configurable/calibrated)
  - Optional server-side pepper key via `QIHSE_AUTH_PEPPER`
  - Constant-time verification using `CRYPTO_memcmp`
  - Temporary password/verifier buffers cleansed immediately via `OPENSSL_cleanse`
- Container integrity protected via **HMAC-SHA-384**
- Sensitive credentials locked in memory with `mlock`/`munlock`
- **AES-256-GCM** encrypt/decrypt with integer overflow checks on input lengths
- **TLS 1.3** with PQC: ML-KEM-1024 key exchange, ML-DSA-87 signatures
- TLS client certificate verification enforced via `SSL_CTX_set_verify`
- Weak PRNG (`rand()`/`srand(time(NULL))`) replaced with OpenSSL `RAND_bytes` across all subsystems

### Authorization Architecture Hardening
- **Object ACL Flag Enforcement**: Replaced permissive boolean ACL checks with discrete permission flags (`QIHSE_ACL_READ`, `QIHSE_ACL_WRITE`, `QIHSE_ACL_ADMIN`). UWP mutations strictly require `QIHSE_ACL_WRITE`. A read-only grant cannot execute any mutation.
- **Opaque User Isolation**: `qihse_user_t` is an opaque pointer in public headers. Callers cannot mutate privilege fields, roles, clearance levels, hardware token states, or ACLs. All properties are accessed through authoritatively validated getters.
- **Authoritative Resolution**: Every access decision (`qihse_auth_can_access`, `qihse_auth_can_access_object`, `qihse_auth_grant_object`, `qihse_auth_revoke_object`, `qihse_auth_create_user`, `qihse_auth_modify_user`, `qihse_auth_destroy_user`) authoritatively resolves the presented user against internal security state under mutex synchronization. Forged stack or heap user objects are immediately rejected.
- **Elimination of Hardcoded God-Mode Credentials**: Removed seeded `GODMODE_OP` password and Python SDK auto-login. The operator must be explicitly bootstrapped via `qihse_auth_bootstrap_operator()` or the `QIHSE_OPERATOR_PASSWORD` environment variable. Network services refuse to bind while operator credentials remain default/unset.
- **Unified Authentication Rate Limiting & Lockout**: Both username-based (`qihse_auth_authenticate`, `qihse_auth_authenticate_from`) and ID-based (`qihse_auth_authenticate_id`) authentication route through a single canonical verifier sharing IP rate limiting, attempt counters, and lockout thresholds.
- **Authorized User Destruction**: `qihse_auth_destroy_user(actor, target_user_id)` requires an authoritative operator actor context; unauthorized callers cannot destroy accounts.
- **Rate Limiter Concurrency**: Mutex held across the entire check, cleanup, and shutdown lifecycle, preventing use-after-free races.

### DoS Prevention & Query Resource Budgets
- **Aggregate Executor Hardening**: Added explicit cardinality and memory limits:
  - Max groups per query: 65,536
  - Max distinct values per group: 4,096
  - Max group key length: 32,768 bytes
  - Query memory budget: 64 MB
  - Checked `size_t` arithmetic and checked `malloc`/`calloc`/`realloc`/`strdup` allocations
- Vector dimensions capped at 4,096 in UWP protocol
- SSTable key length capped at 1MB, value length at 16MB

### Network Protocol Hardening
- Partial writes eliminated via `uwp_write_all()` / `resp_write_all()` helpers
- `SIGPIPE` crashes prevented with `MSG_NOSIGNAL` on all `send()` calls
- Socket timeouts added to prevent Slowloris attacks
- Unaligned pointer dereferences fixed with `memcpy`+`leNtoh` patterns in UWP protocol
- Unchecked `write()` return values fixed across UWP, RESP wire, and instrumentation subsystems

### Post-Quantum Cryptography & liboqs Integration
- **`liboqs` & `oqs-provider` Built by Default**: Added as submodules (`vendor/liboqs` and `vendor/oqs-provider`) and wired directly into the default `make lib` build pipeline with Ninja.
- **ML-DSA-87 Default Activation**: Enabled OpenSSL 3.5.7 / `oqsprovider` native ML-DSA-87 digital signatures by default for audit log signing and container verification, removing requirements for manual opt-in flags.
- **CI Security & Sanitizer Gates**: Integrated AddressSanitizer (ASan), UndefinedBehaviorSanitizer (UBSan), and dedicated security regression targets into GitHub Actions CI (`.github/workflows/build-and-test.yml`).

## Files Modified in Audit & Remediation
- `include/qihse_auth.h` — Opaque user, ACL required_flags, PBKDF2 definitions, getters
- `core/qihse_auth_internal.h` — Internal isolated struct definitions
- `core/qihse_auth.c` — PBKDF2-HMAC-SHA-384, authoritative resolution, unified rate limiting, safe lifetime
- `core/qihse_audit.c` — Default ML-DSA-87 audit signing and oqsprovider integration
- `src/spinnaker/qihse_uwp.c` — Enforce `QIHSE_ACL_WRITE` on all mutation routes
- `src/broad_oak/qihse_vector_db.c` — Authoritative getter access for query cache hashing
- `src/spinnaker/qihse_uwp_repl_pool.c` — Authoritative role getter in replication pool
- `src/spinnaker/qihse_resp_engine.c` — Replaced embedded unauthenticated user struct with registered pointer
- `src/tractable/qihse_aggregate_executor.c` — Memory budget, cardinality bounds, checked allocations, safe copy
- `src/spinnaker/qihse_cluster_bus.c` — Safe string copy
- `src/tractable/qihse_clickhouse_sql.c` — Safe string copy
- `ml/src/qihse_ml.c` — Bounded snprintf throughout telemetry logging
- `quantization/src/qihse_quantization.c` — Bounded snprintf in pipeline and recommendation reasoning
- `memory/src/qihse_memory.c` — Bounded snprintf in memory migration planning
- `algorithms/qihse_verification.c` — Safe bounded copy in verification error messages
- `sdks/python/qihse.c` — Removed hardcoded auto-login, updated destroy_user to pass actor
- `python/qihse/core.py` — Added bootstrap_operator and is_operator_password_default bindings
- `python/qihse/kv.py` — Added user security context propagation to `qihse_kv_expire`
- `python/qihse/timeseries.py` — Corrected ctypes signatures for `qihse_tsdb_insert` and `qihse_tsdb_average_range`
- `tests/test_auth_privilege_boundary.c` — Regression tests for authorization invariance and rate limiting
- `tests/test_object_acl.c` — Regression tests for discrete READ/WRITE/ADMIN flags
- `tests/test_aggregate_hardened.c` — Regression tests for group and distinct cardinality budgets
- `Makefile` — Added liboqs/oqs-provider default dependencies, new test targets, and ASan integration
- `.github/workflows/build-and-test.yml` — Automated sanitizer gates in CI
