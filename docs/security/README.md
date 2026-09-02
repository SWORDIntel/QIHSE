# QIHSE Security Guide

This guide details the security features, access control architecture, and CNSA 2.0 alignment in QIHSE. **Note:** QIHSE has not yet achieved formal third-party CNSA 2.0 compliance or FIPS 140-3 validation. Transport encryption requires certificate-backed TLS 1.3 by default for network listeners (`QIHSE_UWP_ALLOW_INSECURE=1` is required for cleartext/dev opt-in). Post-quantum cryptography (`liboqs` / `oqs-provider` with ML-DSA-87 and ML-KEM-1024) is built and enabled by default. Passwords use CNSA 2.0 / FIPS-aligned PBKDF2-HMAC-SHA-384. See [`UWP_AUDIT_2026-08.md`](UWP_AUDIT_2026-08.md) and [`hardening-report.md`](hardening-report.md) for the audit remediation history.

## Table of Contents

1. [Security Architecture](#security-architecture)
2. [CNSA 2.0 Alignment (In Progress)](#cnsa-20-alignment-in-progress)
3. [Cryptographic Operations](#cryptographic-operations)
4. [Key Management](#key-management)
5. [Access Control](#access-control)
6. [Audit and Logging](#audit-and-logging)
7. [Secure Communication](#secure-communication)
8. [Threat Mitigation](#threat-mitigation)
9. [Compliance Verification](#compliance-verification)

## Security Architecture

### Defense in Depth

QIHSE implements a comprehensive security architecture following defense-in-depth principles:

```
┌─────────────────────────────────────────────────────────┐
│                   EXTERNAL NETWORK                      │
├─────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────  ┐     │
│  │   Network   │  │   API       │  │ Application   │     │
│  │  Security   │  │  Security   │  │   Security    │     │
│  │             │  │             │  │               │     │
│  │ • Firewall  │  │ • AuthN     │  │ • Input       │     │
│  │ • IDS/IPS   │  │ • AuthZ     │  │ • Validation  │     │
│  │ • TLS 1.3   │  │ • Rate      │  │ • Sanitization│     │
│  │             │  │ • Limiting  │  │               │     │
│  └─────────────┘  └─────────────┘  └─────────────  ┘     │
├─────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────  ┐     │
│  │   Data      │  │   System    │  │   Runtime     │     │
│  │  Security   │  │  Security   │  │  Security     │     │
│  │             │  │             │  │               │     │
│  │ • Encryption│  │ • Secure    │  │ • ASLR        │     │
│  │ • Integrity │  │ • Boot      │  │ • DEP         │     │
│  │ • Backup    │  │ • Updates   │  │ • Stack       │     │
│  │             │  │             │  │ • Protection  │     │
│  └─────────────┘  └─────────────┘  └─────────────  ┘     │
├─────────────────────────────────────────────────────────┤
│                 SECURE INFRASTRUCTURE                  │
├─────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────  ┐     │
│  │   CNSA 2.0  │  │   FIPS      │  │   Hardware    │     │
│  │  Alignment │  │  Targeted   │  │  Security     │     │
│  └─────────────┘  └─────────────┘  └─────────────  ┘     │
└─────────────────────────────────────────────────────────┘
```

### Security Components

#### **Cryptographic Module**
- CNSA 2.0 approved algorithms (targeted alignment)
- FIPS 140-3 validation targeted (not yet completed)
- Hardware Security Module (HSM) integration
- Secure key management and rotation

#### **Access Control System**
- Role-Based Access Control (RBAC)
- Multi-factor authentication
- Certificate-based authentication
- Session management and timeout

#### **Audit and Monitoring**
- Comprehensive security event logging
- Real-time security monitoring
- Automated alerting and response
- Cryptographic log integrity

#### **Network Security**
- TLS 1.3 enforced by default with post-quantum key exchange (ML-KEM-1024 / ML-DSA-87 via OpenSSL 3.5+ and oqsprovider)
- Mutual TLS (mTLS) for service communication and client certificate verification
- Network segmentation and isolation
- DDoS protection and centralized IP rate limiting / account lockout

## CNSA 2.0 Alignment (In Progress)

> **Status:** QIHSE targets CNSA 2.0 alignment but has **not** completed formal compliance certification. The algorithms below are implemented and active for `.qdb` container encryption, audit log signing, and transport encryption. See [`hardening-report.md`](hardening-report.md) for the current security posture.

### Approved Cryptographic Algorithms

QIHSE implements or targets the following CNSA 2.0 approved algorithms for higher assurance applications:

#### **Symmetric Encryption**
- **AES-256-GCM** (primary)
- **AES-256-CBC** (legacy compatibility)

#### **Digital Signatures**
- **ML-DSA-87** (primary post-quantum)
- **ECDSA P-384** (legacy compatibility)

#### **Key Exchange / Encapsulation**
- **ML-KEM-1024** (primary post-quantum)
- **ECDH P-384** (legacy compatibility)

#### **Data At Rest (.qdb Container)**
- **AES-256-GCM** symmetric payload encryption
- **ML-KEM-1024** symmetric key encapsulation (`SEC_KEY`)
- **ML-DSA-87** manifest and payload signatures (`SEC_SIGNATURE`)

#### **Hash Functions**
- **SHA-384** (primary for HMAC)
- **SHA-512** (highest assurance)

#### **Message Authentication**
- **HMAC-SHA384** (primary)
- **HMAC-SHA512** (highest assurance)

### Phased Implementation

**Current Phase (2025):**
- ✅ AES-256-GCM encryption
- ✅ ECDSA P-384 signatures
- ✅ ECDH P-384 key exchange
- ✅ HMAC-SHA384 authentication
- ✅ SHA-384 hashing

**Future Phase (2026):**
- 🔄 Post-quantum algorithms (CRYSTALS-Kyber, CRYSTALS-Dilithium)
- 🔄 Enhanced key exchange protocols

### Algorithm Selection Guidelines

```c
// CNSA 2.0 aligned algorithm selection
qihse_crypto_config_t crypto_config = {
    .encryption_algorithm = QIHSE_CRYPTO_AES256_GCM,
    .signature_algorithm = QIHSE_CRYPTO_ECDSA_P384,
    .key_exchange_algorithm = QIHSE_CRYPTO_ECDH_P384,
    .mac_algorithm = QIHSE_CRYPTO_HMAC_SHA384,
    .hash_algorithm = QIHSE_CRYPTO_SHA384,
    .min_key_size_bits = 256,  // Minimum for AES
    .ec_curve = QIHSE_CRYPTO_CURVE_P384
};

// Validate configuration against CNSA 2.0 requirements
qihse_error_t ret = qihse_crypto_validate_config(&crypto_config);
if (ret != QIHSE_SUCCESS) {
    // Configuration violates CNSA 2.0 requirements
    qihse_log_security_event(QIHSE_SECURITY_CONFIG_VIOLATION,
                           "Invalid cryptographic configuration");
    return ret;
}
```

## Cryptographic Operations

### Secure Random Number Generation

```c
// CNSA 2.0 aligned random number generation
qihse_crypto_rng_t* rng = qihse_crypto_rng_init();

// Generate cryptographic keys
uint8_t aes_key[32];  // 256-bit AES key
qihse_crypto_rng_generate(rng, aes_key, sizeof(aes_key));

// Generate initialization vectors
uint8_t iv[16];  // 128-bit IV for AES-GCM
qihse_crypto_rng_generate(rng, iv, sizeof(iv));

// Generate nonces for AEAD operations
uint8_t nonce[12];  // 96-bit nonce for AES-GCM
qihse_crypto_rng_generate(rng, nonce, sizeof(nonce));

qihse_crypto_rng_destroy(rng);
```

### Symmetric Encryption

```c
// AES-256-GCM encryption (CNSA 2.0 approved)
qihse_crypto_aes_gcm_t* ctx = qihse_crypto_aes_gcm_init(key, sizeof(key));

// Encrypt data with additional authenticated data (AAD)
uint8_t* ciphertext = NULL;
size_t ciphertext_len = 0;
uint8_t tag[16];  // 128-bit authentication tag

qihse_error_t ret = qihse_crypto_aes_gcm_encrypt(ctx,
                                               plaintext, plaintext_len,
                                               aad, aad_len,
                                               nonce, sizeof(nonce),
                                               &ciphertext, &ciphertext_len,
                                               tag, sizeof(tag));

// Transmit: ciphertext + tag + nonce

qihse_crypto_aes_gcm_destroy(ctx);
```

### Digital Signatures

```c
// ECDSA P-384 signature generation (CNSA 2.0 approved)
qihse_crypto_ecdsa_t* ecdsa = qihse_crypto_ecdsa_init(private_key);

// Generate signature
uint8_t signature[96];  // P-384 signature (48 bytes r + 48 bytes s)
qihse_crypto_ecdsa_sign(ecdsa, message, message_len, signature, sizeof(signature));

// Verify signature
bool valid = qihse_crypto_ecdsa_verify(ecdsa, message, message_len,
                                     signature, sizeof(signature));

qihse_crypto_ecdsa_destroy(ecdsa);
```

### Key Derivation

```c
// PBKDF2 key derivation (CNSA 2.0 recommended)
qihse_crypto_pbkdf2_t* pbkdf2 = qihse_crypto_pbkdf2_init();

// Derive key from password
uint8_t derived_key[48];  // 384-bit key for HMAC-SHA384
qihse_crypto_pbkdf2_derive(pbkdf2,
                          password, password_len,
                          salt, salt_len,
                          100000,  // 100,000 iterations (CNSA 2.0 minimum)
                          derived_key, sizeof(derived_key));

qihse_crypto_pbkdf2_destroy(pbkdf2);
```

## Key Management

### Key Lifecycle Management

```c
// Initialize key management system
qihse_key_manager_t* km = qihse_key_manager_init(&key_config);

// Generate new key pair
qihse_key_pair_t* key_pair = qihse_key_manager_generate_key(km,
                                                          QIHSE_KEY_TYPE_ECDSA_P384,
                                                          "master-signing-key");

// Store key securely
qihse_key_manager_store(km, key_pair, QIHSE_KEY_STORAGE_HSM);

// Set key rotation policy
qihse_key_rotation_policy_t policy = {
    .rotation_interval_days = 90,
    .advance_notice_hours = 24,
    .backup_required = true,
    .audit_required = true
};

qihse_key_manager_set_rotation_policy(km, key_pair->key_id, &policy);

// Automatic key rotation
qihse_key_manager_rotate_keys(km);

qihse_key_manager_destroy(km);
```

### Hardware Security Module Integration

```c
// HSM configuration for key storage
qihse_hsm_config_t hsm_config = {
    .hsm_library_path = "/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so",
    .token_label = "QIHSE-HSM",
    .user_pin = NULL,  // Retrieved from secure source
    .key_backup_enabled = true,
    .tamper_detection = true
};

// Initialize HSM connection
qihse_hsm_t* hsm = qihse_hsm_init(&hsm_config);

// Generate key in HSM
qihse_key_attributes_t attrs = {
    .key_type = QIHSE_KEY_TYPE_AES256,
    .usage_flags = QIHSE_KEY_USAGE_ENCRYPT | QIHSE_KEY_USAGE_DECRYPT,
    .extractable = false,  // Key cannot be exported
    .sensitive = true      // Key is sensitive
};

qihse_key_handle_t key_handle = qihse_hsm_generate_key(hsm, &attrs, "data-encryption-key");

// Use key for encryption operations
qihse_crypto_aes_gcm_encrypt_hsm(hsm, key_handle, plaintext, plaintext_len, ...);

qihse_hsm_destroy(hsm);
```

### Key Distribution and Synchronization

```c
// Distributed key synchronization (for clustered deployments)
qihse_key_distribution_t* kd = qihse_key_distribution_init(cluster_config);

// Share key with cluster nodes
qihse_key_manager_share_key(km, key_pair->key_id, kd);

// Verify key consistency across nodes
qihse_error_t ret = qihse_key_distribution_verify_consistency(kd, key_pair->key_id);
if (ret != QIHSE_SUCCESS) {
    qihse_security_incident_report(QIHSE_INCIDENT_KEY_INCONSISTENCY,
                                 "Key inconsistency detected in cluster");
}

qihse_key_distribution_destroy(kd);
```

## Access Control & Security Clearances

### System-Wide Cell-Level Authorization

QIHSE implements a pervasive, military-grade classification and compartmentation system designed to mirror US/Five Eyes/SCI clearance levels. This cell-level authorization is embedded natively across all 8 storage engines (Vector, Document, Graph, KV, Columnar, Time-Series, Full-Text Search, and Event Stream) to ensure zero data leakage.

Every record in QIHSE is tagged with a mandatory `classification` (uint16) and `sci_compartment` (uint16) bitmask. Access is verified dynamically at the engine level during query execution.

#### Classification Levels
- `QIHSE_CLASS_UNCLASSIFIED` (0)
- `QIHSE_CLASS_RESTRICTED` (1)
- `QIHSE_CLASS_CONFIDENTIAL` (2)
- `QIHSE_CLASS_SECRET` (3)
- `QIHSE_CLASS_TOP_SECRET` (4)

#### Utilizing Cell-Level Authorization

By default, if no `qihse_user_t` authentication context is provided (i.e., passed as `NULL`), the system defaults to **full access**. This ensures seamless out-of-the-box usage for users who do not require military-grade security clearances.

```c
#include "qihse_auth.h"

// 1. Initialize the Auth sub-system
qihse_auth_init();

// 2. Create a user context with specific clearances
// Example: Operator with TOP SECRET (4) clearance and SCI compartment access bitmask (0)
qihse_user_t* u_operator = qihse_auth_create_user(
    1001,                   // User ID
    QIHSE_ROLE_OPERATOR,    // Role
    QIHSE_CLASS_TOP_SECRET, // Max Classification Clearance
    0                       // SCI Compartment Bitmask
);

// 3. Insert classified data into the system
// E.g. Inserting into the Time-Series DB with SECRET classification
qihse_tsdb_insert(tsdb, series_id, timestamp, value, QIHSE_CLASS_SECRET, 0);

// 4. Querying automatically enforces constraints
// Data exceeding the user's clearance is silently dropped from the query pipeline.
double avg = qihse_tsdb_average_range_user(tsdb, start_ts, end_ts, u_operator);

// 5. Cleanup (requires canonical operator actor context)
qihse_auth_destroy_user(u_operator, 1001);
```

### Hardware Token Enforcement (YubiKey / FIDO2)

By design, hardware token enforcement can be applied natively at the system level. 
- **God-Mode Operators (Role 0)**: Strictly required to present a hardware token. There is no bypass for this policy.
- **Analysts (Role 1)**: Strictly required to present a hardware token to access any data, including unclassified data.
- **Configurability**: When creating a user via `qihse_auth_create_user`, an Operator (or an authorized delegate with `can_create_users == true`) can define whether that specific account mandates hardware token authentication via the `requires_hw_token` boolean. 

### Delegated User Administration & Privilege Invariants

In accordance with architectural Invariant 2, **no principal may create, promote, or modify another principal to a privilege level greater than its own**.
- `can_create_users` delegates account creation only. It does not delegate Operator authority and cannot permit creation or promotion of a principal above the creator's role, clearance, or SCI compartments.
- Identity modifications via `bool qihse_auth_modify_user(operator_user, ...)` and account destruction via `bool qihse_auth_destroy_user(actor, ...)` mandate an authoritative operator user context, fully audited under reader-writer lock synchronization (`pthread_rwlock_t`).

### High-Throughput Authorization Concurrency & Query Performance
- **O(1) Authoritative User Resolution**: `resolve_authoritative_user_locked()` verifies caller identity in constant time $O(1)$ via direct index lookup (`users[uid] == presented && authz_states[uid].active`), eliminating linear table scans.
- **Reader-Writer Lock (`pthread_rwlock_t`)**: Read-only authorization queries (`qihse_auth_can_access`, `qihse_auth_can_access_object`, getters) execute concurrently under shared read locks without blocking each other.
- **OpenSSL 3 Algorithm Fetch Caching**: `EVP_MD_fetch` instances for SHA-384 are cached during initialization with `pthread_once`, avoiding repeated algorithm lookups and internal libcrypto locks.
- **Dynamic Aggregate Hash Table Scaling**: The aggregate query engine automatically rehashes when load factor exceeds 0.75, uses 64-bit precomputed hash filtering, and scales group capacities geometrically.
- **Vector DB Set-Associative Query Cache**: Cache lookups utilize $O(1)$ bounded hash-probing with constant-time direct eviction, avoiding array shifts and linear scans.
- **Zero-Heap Framing Fast Paths**: UWP wire frames $\le 4096$ bytes utilize a stack-allocated buffer for AES-GCM record encryption and decryption, eliminating memory allocator thrashing.
- **Vectorized WAL I/O**: WAL appends serialize record headers, keys, and values into a single `writev` system call, reducing kernel context switches by up to ~80%.

### CNSA 2.0 / FIPS-Aligned Password-Verifier Profile (PBKDF2-HMAC-SHA-384)

Passwords require a minimum length of 12 characters and use a **CNSA 2.0 / FIPS-aligned password-verifier profile using PBKDF2-HMAC-SHA-384** (combining NIST SP 800-132 password derivation with the CNSA 2.0-approved SHA-384 hash function):
- **Salt**: 128-bit (16-byte) per-user cryptographically random salt generated via `RAND_bytes`.
- **Iteration Work Factor**: Enforces a strict runtime production floor of 600,000 iterations (`QIHSE_PW_MIN_ITERATIONS`), rejecting below-policy iteration counts. Compile-time overrides (`QIHSE_TESTING`) are restricted strictly to testing harnesses.
- **Metadata Validation**: Version and algorithm IDs (`QIHSE_PW_VERIFIER_VERSION_1`, `QIHSE_PW_ALG_PBKDF2_HMAC_SHA384`) are verified on every authentication attempt.
- **FIPS Fail-Closed Mode**: When `QIHSE_FIPS_MODE=required` is set, `qihse_auth_init()` binds the OpenSSL `fips` and `base` providers, activates `fips=yes`, and fails closed immediately if the validated provider is absent or disabled.
- **Verification**: Constant-time comparison using `CRYPTO_memcmp` with validated `HMAC` execution.
- **Memory Erasure**: Sensitive plaintext and intermediate buffers are purged with `OPENSSL_cleanse` and locked via `mlock`.
- **Optional Pepper**: Configurable via `QIHSE_AUTH_PEPPER`.

### Role-Based Access Control (RBAC)

```c
// Define security roles
qihse_security_role_t admin_role = {
    .name = "administrator",
    .permissions = QIHSE_PERM_ALL,
    .session_timeout_minutes = 60,
    .mfa_required = true,
    .audit_level = QIHSE_AUDIT_ALL
};

qihse_security_role_t user_role = {
    .name = "user",
    .permissions = QIHSE_PERM_READ | QIHSE_PERM_SEARCH,
    .session_timeout_minutes = 480,  // 8 hours
    .mfa_required = false,
    .audit_level = QIHSE_AUDIT_ACCESS
};

// Register roles
qihse_security_register_role(&admin_role);
qihse_security_register_role(&user_role);

// Assign role to user
qihse_security_assign_role(user_certificate, "user");
```

### Authentication and Authorization

```c
// Certificate-based authentication
qihse_auth_config_t auth_config = {
    .method = QIHSE_AUTH_CERTIFICATE,
    .ca_certificate_path = "/etc/qihse/certs/ca.pem",
    .crl_path = "/etc/qihse/certs/crl.pem",
    .ocsp_url = "http://ocsp.qihse.internal",
    .certificate_revocation_check = true
};

// Initialize authentication
qihse_auth_t* auth = qihse_auth_init(&auth_config);

// Authenticate user
qihse_user_session_t* session = qihse_auth_authenticate(auth, client_certificate);
if (!session) {
    qihse_security_access_denied(QIHSE_ACCESS_AUTH_FAILED, "Certificate authentication failed");
    return QIHSE_ERROR_ACCESS_DENIED;
}

// Authorize operation
qihse_operation_t operation = { .type = QIHSE_OP_SEARCH, .resource = "dataset:sift1m" };
bool authorized = qihse_auth_authorize(session, &operation);

if (!authorized) {
    qihse_security_access_denied(QIHSE_ACCESS_AUTHZ_FAILED,
                               "Operation not authorized for user");
    qihse_auth_session_destroy(session);
    return QIHSE_ERROR_ACCESS_DENIED;
}

// Perform authorized operation
perform_operation(&operation);

// Log access
qihse_security_audit_log(QIHSE_AUDIT_ACCESS_GRANTED,
                        session->user_id, &operation);

qihse_auth_session_destroy(session);
```

### Rate Limiting and DDoS Protection

```c
// Configure rate limiting
qihse_rate_limit_config_t rate_config = {
    .requests_per_minute = 1000,
    .burst_limit = 100,
    .backoff_multiplier = 2.0,
    .max_backoff_seconds = 300,
    .distributed_rate_limiting = true
};

// Initialize rate limiter
qihse_rate_limiter_t* limiter = qihse_rate_limiter_init(&rate_config);

// Check rate limit before operation
qihse_rate_limit_result_t result = qihse_rate_limiter_check(limiter, client_ip);

if (result.allowed) {
    // Perform operation
    perform_operation();
} else {
    // Rate limit exceeded
    qihse_security_rate_limit_exceeded(client_ip, result.retry_after_seconds);
    return QIHSE_ERROR_RATE_LIMITED;
}

qihse_rate_limiter_destroy(limiter);
```

## Audit and Logging

### Security Event Logging

```c
// Security event types
typedef enum qihse_security_event_type_e {
    QIHSE_SECURITY_AUTH_SUCCESS,
    QIHSE_SECURITY_AUTH_FAILURE,
    QIHSE_SECURITY_ACCESS_GRANTED,
    QIHSE_SECURITY_ACCESS_DENIED,
    QIHSE_SECURITY_CONFIG_CHANGE,
    QIHSE_SECURITY_KEY_ROTATION,
    QIHSE_SECURITY_INTEGRITY_CHECK,
    QIHSE_SECURITY_TAMPER_DETECTED,
    QIHSE_SECURITY_RATE_LIMIT_EXCEEDED,
    QIHSE_SECURITY_ENCRYPTION_ERROR,
    QIHSE_SECURITY_DECRYPTION_ERROR
} qihse_security_event_type_t;

// Log security event
qihse_security_event_t event = {
    .type = QIHSE_SECURITY_AUTH_SUCCESS,
    .timestamp = qihse_get_current_time(),
    .user_id = authenticated_user_id,
    .ip_address = client_ip,
    .resource = accessed_resource,
    .action = "search",
    .result = "success",
    .additional_data = NULL
};

qihse_security_log_event(&event);
```

### Cryptographic Log Integrity & Auditable Hash Chain

```c
// Initialize tamper-evident audit logging
qihse_secure_log_config_t log_config = {
    .log_file_path = "qihse_integrity.chain", // Primary integrity chain file
    .max_log_size_mb = 100,
    .max_log_files = 10,
    .integrity_check_interval_seconds = 300,
    .tamper_detection_enabled = true,
    .forward_secure_signing = true,
    .cnsa_lockdown_enforcement = true
};

qihse_secure_log_t* secure_log = qihse_secure_log_init(&log_config);

// Log with cryptographic integrity
qihse_secure_log_entry_t entry = {
    .timestamp = qihse_get_current_time(),
    .event_type = QIHSE_SECURITY_AUTH_SUCCESS,
    .user_id = "user123",
    .details = "User authenticated successfully",
    .integrity_hash = NULL  // Computed automatically from the running hash chain
};

qihse_secure_log_append(secure_log, &entry);

// Verify audit hash chain integrity
qihse_log_integrity_status_t status = qihse_secure_log_verify_integrity(secure_log);
if (status != QIHSE_LOG_INTEGRITY_VALID) {
    qihse_security_incident_report(QIHSE_INCIDENT_LOG_TAMPERING,
                                 "Log integrity compromised. Hashes do not align.");
    // Initiates authenticated lockdown: a Role 0 Operator or Role 1 Analyst
    // must present credentials at the terminal to resume execution.
    qihse_auth_lockdown();
}

qihse_secure_log_destroy(secure_log);
```

### Audit Trail Management

```c
// Configure audit trail
qihse_audit_config_t audit_config = {
    .audit_all_operations = true,
    .retain_audit_logs_days = 2555,  // 7 years for CNSA 2.0 alignment
    .compress_old_logs = true,
    .encrypt_audit_logs = true,
    .audit_key_rotation_days = 365,
    .remote_audit_backup = true
};

qihse_audit_t* audit = qihse_audit_init(&audit_config);

// Query audit trail
qihse_audit_query_t query = {
    .start_time = start_timestamp,
    .end_time = end_timestamp,
    .user_id = "user123",  // Optional filter
    .event_type = QIHSE_SECURITY_ACCESS_GRANTED,  // Optional filter
    .max_results = 1000
};

qihse_audit_results_t* results = qihse_audit_query(audit, &query);

// Export audit trail for compliance review
qihse_audit_export(audit, "/secure/audit_export.enc", &export_config);

qihse_audit_destroy(audit);
```

## Secure Communication

### TLS 1.3 Configuration

```c
// TLS 1.3 configuration with CNSA 2.0 approved ciphers
qihse_tls_config_t tls_config = {
    .version = QIHSE_TLS_1_3,
    .cipher_suites = {
        "TLS_AES_256_GCM_SHA384",  // CNSA 2.0 approved
        "TLS_AES_128_GCM_SHA256",  // Additional cipher
        NULL
    },
    .key_exchange_groups = {
        "secp384r1",  // P-384 for CNSA 2.0 alignment
        NULL
    },
    .certificate_path = "/etc/qihse/certs/server.pem",
    .private_key_path = "/etc/qihse/certs/server.key",
    .ca_certificate_path = "/etc/qihse/certs/ca.pem",
    .client_certificate_required = true,  // Mutual TLS
    .session_tickets_enabled = false,     // Security best practice
    .ocsp_stapling_enabled = true,
    .certificate_transparency_enabled = true
};

// Initialize TLS context
qihse_tls_context_t* tls_ctx = qihse_tls_init(&tls_config);

// Accept secure connection
qihse_tls_connection_t* conn = qihse_tls_accept(tls_ctx, client_socket);

// Perform secure communication
qihse_tls_read(conn, buffer, buffer_size);
qihse_tls_write(conn, data, data_size);

qihse_tls_connection_destroy(conn);
qihse_tls_destroy(tls_ctx);
```

### Mutual TLS (mTLS) for Service Communication

```c
// mTLS configuration for internal service communication
qihse_mtls_config_t mtls_config = {
    .server_certificate = "/etc/qihse/certs/service.pem",
    .server_key = "/etc/qihse/certs/service.key",
    .ca_certificate = "/etc/qihse/certs/ca.pem",
    .client_ca_certificate = "/etc/qihse/certs/client-ca.pem",
    .verify_client_certificate = true,
    .crl_check_enabled = true,
    .certificate_revocation_check = true
};

// Initialize mTLS for service mesh
qihse_service_mesh_t* mesh = qihse_service_mesh_init(&mtls_config);

// Register services with mTLS authentication
qihse_service_register(mesh, "search-service", 8080);
qihse_service_register(mesh, "ml-service", 8081);
qihse_service_register(mesh, "coordinator-service", 8082);

// Secure inter-service communication
qihse_service_call(mesh, "ml-service", "/predict", request_data, &response);

qihse_service_mesh_destroy(mesh);
```

## Threat Mitigation

### Input Validation and Sanitization

```c
// Comprehensive input validation
qihse_input_validation_config_t validation_config = {
    .max_input_size_bytes = 1048576,  // 1MB limit
    .allowed_characters = "alphanumeric+special",  // Define allowed charset
    .sql_injection_protection = true,
    .xss_protection = true,
    .command_injection_protection = true,
    .path_traversal_protection = true,
    .null_byte_injection_protection = true
};

qihse_input_validator_t* validator = qihse_input_validator_init(&validation_config);

// Validate user input
qihse_validation_result_t result = qihse_input_validate(validator, user_input, input_type);

if (!result.valid) {
    qihse_security_input_validation_failed(user_input, result.error_message);
    return QIHSE_ERROR_INVALID_INPUT;
}

// Sanitize validated input
char* sanitized_input = qihse_input_sanitize(validator, user_input);

qihse_input_validator_destroy(validator);
```

### Buffer Overflow Protection

```c
// Bounds-checked memory operations
qihse_secure_memory_config_t mem_config = {
    .enable_bounds_checking = true,
    .enable_address_sanitizer = true,
    .enable_memory_tagging = true,  // ARM MTE or Intel CET
    .poison_freed_memory = true,
    .detect_use_after_free = true,
    .detect_double_free = true
};

qihse_secure_memory_init(&mem_config);

// Secure string operations
qihse_secure_strncpy(dest, src, dest_size);
qihse_secure_strncat(dest, src, dest_size);
qihse_secure_snprintf(buffer, buffer_size, format, ...);

// Secure memory allocation with overflow detection
void* secure_ptr = qihse_secure_malloc(size);
if (!secure_ptr) {
    qihse_security_memory_allocation_failed(size);
    return QIHSE_ERROR_OUT_OF_MEMORY;
}

// Automatic cleanup on error paths
qihse_secure_free(secure_ptr);
```

### Side-Channel Attack Mitigation

```c
// Constant-time cryptographic operations
qihse_crypto_constant_time_config_t ct_config = {
    .enable_constant_time_operations = true,
    .mask_branch_prediction = true,
    .prevent_timing_attacks = true,
    .flush_microarchitectural_state = true
};

qihse_crypto_enable_constant_time(&ct_config);

// Timing-attack resistant comparison
bool equal = qihse_crypto_constant_time_compare(secret1, secret2, length);

// Cache-timing attack protection
qihse_crypto_cache_timing_protect();

// Branch prediction attack mitigation
qihse_crypto_branch_prediction_protect();
```

## Compliance Verification (Targeted — Not Yet Certified)

### CNSA 2.0 Alignment Checking

```c
// Comprehensive compliance verification
qihse_cnsa_compliance_config_t compliance_config = {
    .check_algorithms = true,
    .check_key_sizes = true,
    .check_key_lifetimes = true,
    .check_random_generation = true,
    .check_cryptographic_protocols = true,
    .generate_compliance_report = true,
    .report_path = "/var/log/qihse/compliance_report.json"
};

qihse_cnsa_checker_t* checker = qihse_cnsa_checker_init(&compliance_config);

// Run compliance check
qihse_cnsa_compliance_result_t result = qihse_cnsa_checker_run(checker);

if (result.overall_compliant) {
    printf("System meets CNSA 2.0 alignment targets\n");
} else {
    printf("Compliance violations found:\n");
    for (size_t i = 0; i < result.violation_count; i++) {
        printf("  - %s\n", result.violations[i].description);
    }
    // Enter restricted mode or shutdown for critical violations
    qihse_security_enter_restricted_mode();
}

qihse_cnsa_checker_destroy(checker);
```

### Security Health Monitoring

```c
// Continuous security monitoring
qihse_security_monitor_config_t monitor_config = {
    .monitor_authentication_failures = true,
    .monitor_authorization_failures = true,
    .monitor_cryptographic_errors = true,
    .monitor_network_anomalies = true,
    .monitor_system_integrity = true,
    .alert_threshold_auth_failures = 5,  // Per minute
    .alert_threshold_crypto_errors = 1,  // Per minute
    .enable_automatic_response = true
};

qihse_security_monitor_t* monitor = qihse_security_monitor_init(&monitor_config);

// Security health check
qihse_security_health_t health = qihse_security_monitor_check_health(monitor);

if (health.overall_health != QIHSE_SECURITY_HEALTH_GOOD) {
    printf("Security health issues detected:\n");
    if (health.auth_failure_rate > monitor_config.alert_threshold_auth_failures) {
        printf("  - High authentication failure rate\n");
    }
    if (health.crypto_error_rate > monitor_config.alert_threshold_crypto_errors) {
        printf("  - High cryptographic error rate\n");
    }
    // Take corrective action
    qihse_security_incident_response(&health);
}

qihse_security_monitor_destroy(monitor);
```

### Automated Security Testing

```c
// Security regression testing
qihse_security_test_config_t test_config = {
    .test_cryptography = true,
    .test_authentication = true,
    .test_authorization = true,
    .test_input_validation = true,
    .test_access_control = true,
    .test_network_security = true,
    .test_cnsa_compliance = true,
    .generate_security_report = true,
    .report_path = "/var/log/qihse/security_test_report.html"
};

qihse_security_tester_t* tester = qihse_security_tester_init(&test_config);

// Run security test suite
qihse_security_test_results_t results = qihse_security_tester_run(tester);

printf("Security Test Results:\n");
printf("  Tests Passed: %zu/%zu\n", results.tests_passed, results.total_tests);
printf("  Critical Issues: %zu\n", results.critical_issues);
printf("  High Issues: %zu\n", results.high_issues);
printf("  Medium Issues: %zu\n", results.medium_issues);
printf("  Low Issues: %zu\n", results.low_issues);

if (results.critical_issues > 0) {
    qihse_security_critical_issues_detected(&results);
    // May require system shutdown or restricted mode
}

qihse_security_tester_destroy(tester);
```

---

This security guide provides comprehensive coverage of QIHSE's security architecture and CNSA 2.0 alignment goals. **QIHSE has not yet completed formal CNSA 2.0 compliance certification or FIPS 140-3 validation, and transport encryption is not yet implemented.** For deployment-specific security configurations, see the [Deployment Guide](deployment/). For security incident response procedures, contact your security operations center.
