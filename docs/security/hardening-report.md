# QIHSE Security Hardening Report

A comprehensive multi-pass security audit identified and remediated vulnerabilities across the entire codebase.

## Remediation Summary

### Unsafe C Functions
- All `system()` calls replaced with `fork`/`execvp`
- All `strcpy`/`sprintf` replaced with bounded `snprintf`/`strncpy`
- All `atoi` replaced with `strtol` (with validation)
- All `atof` replaced with `strtof`/`strtod`
- All `strtok` replaced with reentrant `strtok_r`
- Zero unsafe function calls remain

### Cryptographic Hygiene
- Container integrity upgraded from CRC64 to **HMAC-SHA-384**
- Password buffers cleansed with `OPENSSL_cleanse` before free
- Sensitive data locked with `mlock`/`munlock`
- Constant-time comparison for hash verification
- **AES-256-GCM** encrypt/decrypt with integer overflow checks on input lengths
- **TLS 1.3** with PQC: ML-KEM-1024 key exchange, ML-DSA-87 signatures
- TLS client certificate verification enforced via `SSL_CTX_set_verify`
- Weak PRNG (`rand()`/`srand(time(NULL))`) replaced with OpenSSL `RAND_bytes` across all subsystems (telemetry, raft, hetero, uma, ml_optimizer, math, hnsw)

### File System Hardening
- `fopen` replaced with `open`+`fdopen`+`O_NOFOLLOW` on all security-critical file operations (keys, WAL, sstables, models, MMDB, optimization DB)
- File permissions tightened to `0600` on all security-critical file creation
- Relative paths replaced with absolute paths (`/etc/qihse/keys/`, `/etc/qihse/qihse.conf`, `QIHSE_DATA_DIR`)
- `opendir(".")` replaced with `opendir(QIHSE_DATA_DIR)` to prevent CWD injection
- Path traversal validation on `QIHSE_CONF_FILE` and `QIHSE_XDP_OBJ` environment variables

### Network Protocol Hardening
- Partial writes eliminated via `uwp_write_all()` / `resp_write_all()` helpers
- `SIGPIPE` crashes prevented with `MSG_NOSIGNAL` on all `send()` calls
- Socket timeouts added to prevent Slowloris attacks
- Unaligned pointer dereferences fixed with `memcpy`+`leNtoh` patterns (UWP protocol)
- Unchecked `write()` return values fixed across UWP, RESP wire, and instrumentation subsystems

### DoS Prevention
- Vector dimensions capped at 4096 in UWP protocol
- SSTable key length capped at 1MB, value length at 16MB
- `malloc` NULL checks added on all security-critical allocation paths

### Authentication & Access Control
- Authentication rate limiting enforced
- Lua/WASM sandboxes hardened
- Library loading restricted to absolute paths

## Files Modified

Rounds 5-13 touched approximately 25 files across:
- `src/spinnaker/` — UWP protocol, RESP wire, PG wire, Raft, HTTP telemetry
- `src/black_hole/` — KV store, WAL, SSTables
- `src/broad_oak/` — Vector DB, search, MMDB, quantum defense
- `src/bombe/` — Heterogeneous compute, instrumentation, math
- `src/tractable/` — QQL parser
- `src/networking/` — AF_XDP
- `src/qihse_uma.c` — UMA memory management
- `src/qihse_ml_optimizer.c` — ML optimizer
- `core/qihse_audit.c` — Audit logging
- `persistence/qihse_pqc_crypto.c` — PQC cryptography
