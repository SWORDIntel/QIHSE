#include "qihse_auth.h"
#include "qihse_auth_internal.h"
#include "qihse_audit.h"
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <pthread.h>
#include <stdio.h>
#include <time.h>
#include <errno.h>
#include <limits.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <openssl/provider.h>
#ifndef _WIN32
#include <sys/mman.h>
#endif

// ---------------------------------------------------------------------------
// IP-based auth rate limiter (brute-force protection)
// ---------------------------------------------------------------------------
// Lazy-initialized global singleton. Defaults: 5 attempts / 60s / 1024 slots.
// Protected by g_rate_limiter_mutex across the entire check/modify operation.
static qihse_rate_limiter_t* g_auth_rate_limiter = NULL;
static pthread_mutex_t g_rate_limiter_mutex = PTHREAD_MUTEX_INITIALIZER;

void qihse_auth_init_rate_limiter(uint32_t max_attempts, uint32_t window_seconds, size_t max_entries) {
    pthread_mutex_lock(&g_rate_limiter_mutex);
    if (g_auth_rate_limiter) {
        qihse_rate_limiter_destroy(g_auth_rate_limiter);
        g_auth_rate_limiter = NULL;
    }
    if (max_attempts == 0) max_attempts = QIHSE_AUTH_RATE_LIMIT_DEFAULT_MAX_ATTEMPTS;
    if (window_seconds == 0) window_seconds = QIHSE_AUTH_RATE_LIMIT_DEFAULT_WINDOW_SEC;
    if (max_entries == 0) max_entries = QIHSE_AUTH_RATE_LIMIT_DEFAULT_MAX_ENTRIES;
    g_auth_rate_limiter = qihse_rate_limiter_create(max_entries, max_attempts, window_seconds);
    pthread_mutex_unlock(&g_rate_limiter_mutex);
}

void qihse_auth_shutdown_rate_limiter(void) {
    pthread_mutex_lock(&g_rate_limiter_mutex);
    if (g_auth_rate_limiter) {
        qihse_rate_limiter_destroy(g_auth_rate_limiter);
        g_auth_rate_limiter = NULL;
    }
    pthread_mutex_unlock(&g_rate_limiter_mutex);
}

bool qihse_auth_check_rate_limit(uint32_t source_ip) {
    bool allowed = true;
    pthread_mutex_lock(&g_rate_limiter_mutex);
    if (!g_auth_rate_limiter) {
        g_auth_rate_limiter = qihse_rate_limiter_create(
            QIHSE_AUTH_RATE_LIMIT_DEFAULT_MAX_ENTRIES,
            QIHSE_AUTH_RATE_LIMIT_DEFAULT_MAX_ATTEMPTS,
            QIHSE_AUTH_RATE_LIMIT_DEFAULT_WINDOW_SEC);
    }
    if (g_auth_rate_limiter) {
        allowed = qihse_rate_limiter_check(g_auth_rate_limiter, source_ip);
    }
    pthread_mutex_unlock(&g_rate_limiter_mutex);
    return allowed;
}

void qihse_auth_rate_limit_reset(uint32_t source_ip) {
    pthread_mutex_lock(&g_rate_limiter_mutex);
    if (g_auth_rate_limiter) {
        qihse_rate_limiter_reset(g_auth_rate_limiter, source_ip);
    }
    pthread_mutex_unlock(&g_rate_limiter_mutex);
}

void qihse_auth_rate_limit_cleanup(void) {
    pthread_mutex_lock(&g_rate_limiter_mutex);
    if (g_auth_rate_limiter) {
        qihse_rate_limiter_cleanup(g_auth_rate_limiter);
    }
    pthread_mutex_unlock(&g_rate_limiter_mutex);
}

#define MAX_USERS 1024
#define MAX_AUTH_ATTEMPTS 5
#define AUTH_LOCKOUT_SECONDS 300

typedef struct {
    uint32_t failed_count;
    time_t lockout_until;
} auth_rate_limit_t;

/* Authoritative internal authorization and security state.
 * Any presented user pointer MUST be authoritatively verified against this state. */
typedef struct {
    bool active;
    uint16_t role;
    uint16_t classification_level;
    uint16_t sci_compartments;
    bool requires_hardware_token;
    bool hardware_token_present;
    bool can_create_users;
    bool password_set;
    qihse_password_verifier_t verifier;
} authz_state_t;

static qihse_user_t* users[MAX_USERS];
static authz_state_t authz_states[MAX_USERS];
static pthread_mutex_t auth_mutex = PTHREAD_MUTEX_INITIALIZER;
static uint32_t active_user_count = 0;
static auth_rate_limit_t rate_limits[MAX_USERS];

#ifdef QIHSE_TESTING
#define QIHSE_PW_MIN_ALLOWED_ITERATIONS 1000u
#else
#define QIHSE_PW_MIN_ALLOWED_ITERATIONS QIHSE_PW_MIN_ITERATIONS
#endif

static uint32_t get_password_iterations(void) {
    const char* env = getenv("QIHSE_PW_ITERATIONS");
    if (env) {
        char* endptr = NULL;
        errno = 0;
        long v = strtol(env, &endptr, 10);
        if (errno != 0 || endptr == env || *endptr != '\0') {
            fprintf(stderr, "[SECURITY ERROR] Malformed QIHSE_PW_ITERATIONS environment variable.\n");
            return 0;
        }
        if (v < (long)QIHSE_PW_MIN_ALLOWED_ITERATIONS || v > (long)INT_MAX) {
            fprintf(stderr,
                    "[SECURITY ERROR] QIHSE_PW_ITERATIONS outside permitted range (minimum %u).\n",
                    QIHSE_PW_MIN_ALLOWED_ITERATIONS);
            return 0;
        }
        return (uint32_t)v;
    }
    return QIHSE_PW_MIN_ITERATIONS;
}

bool qihse_password_compute(const char* password,
                            uint32_t iterations,
                            qihse_password_verifier_t* out_verifier) {
    if (!password || !out_verifier) return false;
    size_t pw_len = strlen(password);
    if (pw_len < 12) return false;

    uint32_t iters = iterations ? iterations : get_password_iterations();
    if (iters < QIHSE_PW_MIN_ALLOWED_ITERATIONS || iters > (uint32_t)INT_MAX) {
        return false;
    }

    out_verifier->version = QIHSE_PW_VERIFIER_VERSION_1;
    out_verifier->algorithm = QIHSE_PW_ALG_PBKDF2_HMAC_SHA384;
    out_verifier->iterations = iters;

    if (RAND_bytes(out_verifier->salt, QIHSE_PW_SALT_BYTES) != 1) {
        return false;
    }

    uint8_t intermediate[QIHSE_PW_HASH_BYTES];
    if (PKCS5_PBKDF2_HMAC(password, (int)pw_len,
                          out_verifier->salt, QIHSE_PW_SALT_BYTES,
                          (int)out_verifier->iterations,
                          EVP_sha384(),
                          sizeof(intermediate), intermediate) != 1) {
        OPENSSL_cleanse(intermediate, sizeof(intermediate));
        return false;
    }

    const char* pepper = getenv("QIHSE_AUTH_PEPPER");
    if (pepper && strlen(pepper) > 0) {
        unsigned int hmac_len = 0;
        if (HMAC(EVP_sha384(), pepper, (int)strlen(pepper),
                 intermediate, sizeof(intermediate),
                 out_verifier->verifier, &hmac_len) == NULL ||
            hmac_len != QIHSE_PW_HASH_BYTES) {
            OPENSSL_cleanse(intermediate, sizeof(intermediate));
            OPENSSL_cleanse(out_verifier->verifier, sizeof(out_verifier->verifier));
            return false;
        }
    } else {
        memcpy(out_verifier->verifier, intermediate, sizeof(intermediate));
    }
    OPENSSL_cleanse(intermediate, sizeof(intermediate));
    return true;
}

bool qihse_password_verify(const char* password,
                           const qihse_password_verifier_t* verifier) {
    if (!password || !verifier) return false;
    if (verifier->version != QIHSE_PW_VERIFIER_VERSION_1 ||
        verifier->algorithm != QIHSE_PW_ALG_PBKDF2_HMAC_SHA384 ||
        verifier->iterations < QIHSE_PW_MIN_ALLOWED_ITERATIONS ||
        verifier->iterations > (uint32_t)INT_MAX) {
        return false;
    }
    size_t pw_len = strlen(password);

    uint8_t intermediate[QIHSE_PW_HASH_BYTES];
    if (PKCS5_PBKDF2_HMAC(password, (int)pw_len,
                          verifier->salt, QIHSE_PW_SALT_BYTES,
                          (int)verifier->iterations,
                          EVP_sha384(),
                          sizeof(intermediate), intermediate) != 1) {
        OPENSSL_cleanse(intermediate, sizeof(intermediate));
        return false;
    }

    uint8_t expected[QIHSE_PW_HASH_BYTES];
    const char* pepper = getenv("QIHSE_AUTH_PEPPER");
    if (pepper && strlen(pepper) > 0) {
        unsigned int hmac_len = 0;
        if (HMAC(EVP_sha384(), pepper, (int)strlen(pepper),
                 intermediate, sizeof(intermediate),
                 expected, &hmac_len) == NULL ||
            hmac_len != QIHSE_PW_HASH_BYTES) {
            OPENSSL_cleanse(intermediate, sizeof(intermediate));
            OPENSSL_cleanse(expected, sizeof(expected));
            return false;
        }
    } else {
        memcpy(expected, intermediate, sizeof(intermediate));
    }
    OPENSSL_cleanse(intermediate, sizeof(intermediate));

    int match = CRYPTO_memcmp(expected, verifier->verifier, sizeof(expected));
    OPENSSL_cleanse(expected, sizeof(expected));
    return match == 0;
}

static inline bool compute_password_verifier(const char* password,
                                             uint32_t iterations,
                                             qihse_password_verifier_t* out_verifier) {
    return qihse_password_compute(password, iterations, out_verifier);
}

static inline bool verify_password(const char* password,
                                   const qihse_password_verifier_t* verifier) {
    return qihse_password_verify(password, verifier);
}

/* auth_mutex must be held. */
static bool resolve_authoritative_user_locked(const qihse_user_t* presented,
                                              uint32_t* out_user_id,
                                              authz_state_t* out_state) {
    if (!presented) return false;
    for (uint32_t i = 0; i < MAX_USERS; i++) {
        if (users[i] == presented && authz_states[i].active) {
            if (out_user_id) *out_user_id = i;
            if (out_state) *out_state = authz_states[i];
            return true;
        }
    }
    return false;
}

static void set_authz_state_locked(uint32_t user_id, const qihse_user_t* user) {
    if (user_id >= MAX_USERS || !user) return;
    authz_states[user_id].active = true;
    authz_states[user_id].role = user->role;
    authz_states[user_id].classification_level = user->classification_level;
    authz_states[user_id].sci_compartments = user->sci_compartments;
    authz_states[user_id].requires_hardware_token = user->requires_hardware_token;
    authz_states[user_id].hardware_token_present = user->hardware_token_present;
    authz_states[user_id].can_create_users = user->can_create_users;
    authz_states[user_id].password_set = user->password_set;
    authz_states[user_id].verifier = user->verifier;
}

static bool check_fips_compliance(void) {
    const char* fips_env = getenv("QIHSE_FIPS_MODE");
    if (fips_env && (strcmp(fips_env, "1") == 0 || strcasecmp(fips_env, "required") == 0)) {
        OSSL_PROVIDER *base = OSSL_PROVIDER_load(NULL, "base");
        OSSL_PROVIDER *fips = OSSL_PROVIDER_load(NULL, "fips");
        if (!base || !fips) {
            fprintf(stderr, "[FIPS ERROR] QIHSE_FIPS_MODE=required but FIPS/base provider failed to load in OpenSSL.\n");
            return false;
        }
        if (EVP_default_properties_enable_fips(NULL, 1) != 1) {
            fprintf(stderr, "[FIPS ERROR] QIHSE_FIPS_MODE=required but EVP_default_properties_enable_fips failed.\n");
            return false;
        }
        if (!EVP_default_properties_is_fips_enabled(NULL)) {
            fprintf(stderr, "[FIPS ERROR] QIHSE_FIPS_MODE=required but FIPS provider is not active in OpenSSL.\n");
            return false;
        }
    }
    return true;
}

bool qihse_auth_init(void) {
    if (!check_fips_compliance()) {
        pthread_mutex_lock(&auth_mutex);
        for (uint32_t i = 0; i < MAX_USERS; i++) {
            if (users[i]) {
                OPENSSL_cleanse(users[i], sizeof(qihse_user_t));
#ifndef _WIN32
                munlock(users[i], sizeof(qihse_user_t));
#endif
                free(users[i]);
                users[i] = NULL;
            }
        }
        memset(users, 0, sizeof(users));
        memset(authz_states, 0, sizeof(authz_states));
        memset(rate_limits, 0, sizeof(rate_limits));
        active_user_count = 0;
        pthread_mutex_unlock(&auth_mutex);
        return false;
    }

    qihse_audit_init();

    pthread_mutex_lock(&auth_mutex);
    for (uint32_t i = 0; i < MAX_USERS; i++) {
        if (users[i]) {
            OPENSSL_cleanse(users[i], sizeof(qihse_user_t));
#ifndef _WIN32
            munlock(users[i], sizeof(qihse_user_t));
#endif
            free(users[i]);
            users[i] = NULL;
        }
    }
    memset(users, 0, sizeof(users));
    memset(authz_states, 0, sizeof(authz_states));
    memset(rate_limits, 0, sizeof(rate_limits));
    active_user_count = 0;

    // PRE-SEED SYSTEM OPERATOR (User ID 0)
    // No hardcoded default credentials. Password must be explicitly set via
    // qihse_auth_bootstrap_operator(), qihse_auth_modify_user(), or QIHSE_OPERATOR_PASSWORD.
    qihse_user_t* op = calloc(1, sizeof(qihse_user_t));
    if (op) {
        op->user_id = 0;
        op->role = QIHSE_ROLE_OPERATOR;
        op->classification_level = 0xFFFF;
        op->sci_compartments = 0xFFFF;
        op->hardware_token_present = true;
        op->requires_hardware_token = false;
        op->can_create_users = true;
        strncpy(op->username, "GODMODE_OP", 63);
        strncpy(op->fido2_credential_id, "OP-GODMODE-YUBIKEY-0001", 63);

        const char* initial_pass = getenv("QIHSE_OPERATOR_PASSWORD");
        if (initial_pass && strlen(initial_pass) >= 12) {
            compute_password_verifier(initial_pass, 0, &op->verifier);
            op->password_set = true;
        } else {
            op->password_set = false;
        }

#ifndef _WIN32
        mlock(op, sizeof(qihse_user_t));
#endif
        users[0] = op;
        set_authz_state_locked(0, op);
        active_user_count = 1;
    }

    pthread_mutex_unlock(&auth_mutex);
    return true;
}

bool qihse_auth_bootstrap_operator(const char* initial_password) {
    if (!initial_password || strlen(initial_password) < 12) return false;

    pthread_mutex_lock(&auth_mutex);
    if (!users[0] || !authz_states[0].active) {
        pthread_mutex_unlock(&auth_mutex);
        return false;
    }
    if (authz_states[0].password_set) {
        // Already bootstrapped; must rotate through modify_user with operator credentials
        pthread_mutex_unlock(&auth_mutex);
        return false;
    }

    if (!compute_password_verifier(initial_password, 0, &users[0]->verifier)) {
        pthread_mutex_unlock(&auth_mutex);
        return false;
    }
    users[0]->password_set = true;
    authz_states[0].verifier = users[0]->verifier;
    authz_states[0].password_set = true;
    pthread_mutex_unlock(&auth_mutex);
    return true;
}

bool qihse_auth_is_operator_password_default(void) {
    pthread_mutex_lock(&auth_mutex);
    bool is_default = true;
    if (users[0] && authz_states[0].active) {
        is_default = !authz_states[0].password_set;
    }
    pthread_mutex_unlock(&auth_mutex);
    return is_default;
}

qihse_user_t* qihse_auth_create_user(const qihse_user_t* creator, uint32_t user_id,
                                     uint16_t role, uint16_t classif,
                                     uint16_t sci, const char* plaintext_password,
                                     bool requires_hw_token) {
    if (user_id >= MAX_USERS) return NULL;
    if (!plaintext_password || strlen(plaintext_password) < 12) {
        fprintf(stderr, "[SECURITY ERROR] Password for User ID %u rejected: minimum 12 characters required.\n", user_id);
        return NULL;
    }

    pthread_mutex_lock(&auth_mutex);

    // Operator password must be set before creating other users
    if (user_id != 0 && !authz_states[0].password_set) {
        fprintf(stderr, "[SECURITY ERROR] Operator password must be configured before creating users.\n");
        pthread_mutex_unlock(&auth_mutex);
        return NULL;
    }

    uint32_t creator_id = 0xFFFFFFFFu;
    authz_state_t creator_authz;
    if (!resolve_authoritative_user_locked(creator, &creator_id, &creator_authz)) {
        qihse_audit_log("USER_CREATE_DENIED_INVALID_CREATOR", creator_id, user_id, classif, sci);
        pthread_mutex_unlock(&auth_mutex);
        return NULL;
    }

    // Only authoritative OPERATOR or delegated user can create new users
    if (creator_authz.role != QIHSE_ROLE_OPERATOR && !creator_authz.can_create_users) {
        qihse_audit_log("USER_CREATE_DENIED_DELEGATION", creator_id, user_id, classif, sci);
        pthread_mutex_unlock(&auth_mutex);
        return NULL;
    }

    // Principal cannot create a principal above itself
    if (role < creator_authz.role) {
        qihse_audit_log("USER_CREATE_DENIED_ROLE", creator_id, user_id, classif, sci);
        pthread_mutex_unlock(&auth_mutex);
        return NULL;
    }

    // Creator must possess the clearance they attempt to grant
    if (classif > creator_authz.classification_level) {
        qihse_audit_log("USER_CREATE_DENIED_CLEARANCE", creator_id, user_id, classif, sci);
        pthread_mutex_unlock(&auth_mutex);
        return NULL;
    }
    if ((sci & creator_authz.sci_compartments) != sci) {
        qihse_audit_log("USER_CREATE_DENIED_SCI", creator_id, user_id, classif, sci);
        pthread_mutex_unlock(&auth_mutex);
        return NULL;
    }

    // Delegation must not weaken an enforced hardware-token requirement
    if (creator_authz.role != QIHSE_ROLE_OPERATOR &&
        creator_authz.requires_hardware_token && !requires_hw_token) {
        qihse_audit_log("USER_CREATE_DENIED_TOKEN_POLICY", creator_id, user_id, classif, sci);
        pthread_mutex_unlock(&auth_mutex);
        return NULL;
    }

    if (users[user_id] != NULL) {
        pthread_mutex_unlock(&auth_mutex);
        return NULL;
    }

    qihse_user_t* u = calloc(1, sizeof(qihse_user_t));
    if (!u) {
        pthread_mutex_unlock(&auth_mutex);
        return NULL;
    }

    u->user_id = user_id;
    u->role = role;

    if (role == QIHSE_ROLE_OPERATOR) {
        u->classification_level = 0xFFFF;
        u->sci_compartments = 0xFFFF;
    } else {
        u->classification_level = classif;
        u->sci_compartments = sci;
    }

    if (!compute_password_verifier(plaintext_password, 0, &u->verifier)) {
        free(u);
        pthread_mutex_unlock(&auth_mutex);
        return NULL;
    }
    u->password_set = true;
    u->requires_hardware_token = requires_hw_token;
    u->can_create_users = false;
    snprintf(u->username, 64, "User_%u", user_id);

    users[user_id] = u;
    set_authz_state_locked(user_id, u);
    active_user_count++;
#ifndef _WIN32
    mlock(u, sizeof(qihse_user_t));
#endif

    qihse_audit_log("USER_CREATE", creator_id, user_id, u->classification_level, u->sci_compartments);
    pthread_mutex_unlock(&auth_mutex);
    return u;
}

qihse_user_t* qihse_auth_get_user(uint32_t user_id) {
    if (user_id >= MAX_USERS) return NULL;
    pthread_mutex_lock(&auth_mutex);
    qihse_user_t* u = NULL;
    if (authz_states[user_id].active) {
        u = users[user_id];
    }
    pthread_mutex_unlock(&auth_mutex);
    return u;
}

bool qihse_auth_destroy_user(const qihse_user_t* actor, uint32_t target_user_id) {
    if (target_user_id >= MAX_USERS) return false;

    pthread_mutex_lock(&auth_mutex);
    uint32_t actor_id = 0xFFFFFFFFu;
    authz_state_t actor_authz;
    if (!resolve_authoritative_user_locked(actor, &actor_id, &actor_authz) ||
        actor_authz.role != QIHSE_ROLE_OPERATOR) {
        pthread_mutex_unlock(&auth_mutex);
        qihse_audit_log("USER_DESTROY_DENIED", actor_id, target_user_id, 0, 0);
        return false;
    }

    if (target_user_id == 0) {
        const char* allow_kill = getenv("QIHSE_ALLOW_DESTROY_OPERATOR");
        if (!allow_kill || strcmp(allow_kill, "1") != 0) {
            pthread_mutex_unlock(&auth_mutex);
            return false;
        }
    }

    if (users[target_user_id] && authz_states[target_user_id].active) {
        qihse_audit_log("USER_DESTROY", actor_id, target_user_id,
                        authz_states[target_user_id].classification_level,
                        authz_states[target_user_id].sci_compartments);
        OPENSSL_cleanse(users[target_user_id], sizeof(qihse_user_t));
#ifndef _WIN32
        munlock(users[target_user_id], sizeof(qihse_user_t));
#endif
        free(users[target_user_id]);
        users[target_user_id] = NULL;
        memset(&authz_states[target_user_id], 0, sizeof(authz_states[target_user_id]));
        memset(&rate_limits[target_user_id], 0, sizeof(rate_limits[target_user_id]));
        active_user_count--;
        pthread_mutex_unlock(&auth_mutex);
        return true;
    }

    pthread_mutex_unlock(&auth_mutex);
    return false;
}

bool qihse_auth_modify_user(const qihse_user_t* operator_user, uint32_t target_user_id,
                            const char* new_username, const char* new_password,
                            int new_requires_hw_token, int new_can_create_users) {
    if (target_user_id >= MAX_USERS) return false;
    if (new_password != NULL && strlen(new_password) < 12) {
        fprintf(stderr, "[SECURITY ERROR] Password for User ID %u rejected: minimum 12 characters required.\n", target_user_id);
        return false;
    }

    pthread_mutex_lock(&auth_mutex);
    uint32_t operator_id = 0xFFFFFFFFu;
    authz_state_t operator_authz;
    if (!resolve_authoritative_user_locked(operator_user, &operator_id, &operator_authz) ||
        operator_authz.role != QIHSE_ROLE_OPERATOR) {
        pthread_mutex_unlock(&auth_mutex);
        qihse_audit_log("USER_MODIFY_DENIED", operator_id, target_user_id, 0, 0);
        return false;
    }

    if (target_user_id != 0 && !authz_states[0].password_set) {
        fprintf(stderr, "[SECURITY ERROR] Operator password must be set before modifying other users.\n");
        pthread_mutex_unlock(&auth_mutex);
        return false;
    }

    qihse_user_t* target = users[target_user_id];
    if (!target || !authz_states[target_user_id].active) {
        pthread_mutex_unlock(&auth_mutex);
        return false;
    }

    if (new_username != NULL) {
        strncpy(target->username, new_username, 63);
        target->username[63] = '\0';
    }

    if (new_password != NULL) {
        if (!compute_password_verifier(new_password, 0, &target->verifier)) {
            pthread_mutex_unlock(&auth_mutex);
            return false;
        }
        target->password_set = true;
        authz_states[target_user_id].verifier = target->verifier;
        authz_states[target_user_id].password_set = true;
    }

    if (new_requires_hw_token != -1) {
        bool value = (new_requires_hw_token != 0);
        target->requires_hardware_token = value;
        authz_states[target_user_id].requires_hardware_token = value;
    }

    if (new_can_create_users != -1) {
        bool value = (new_can_create_users != 0);
        target->can_create_users = value;
        authz_states[target_user_id].can_create_users = value;
    }

    qihse_audit_log("USER_MODIFY", operator_id, target_user_id,
                    authz_states[target_user_id].classification_level,
                    authz_states[target_user_id].sci_compartments);
    pthread_mutex_unlock(&auth_mutex);
    return true;
}

bool qihse_auth_set_hardware_token(qihse_user_t* user, bool present, const char* credential_id) {
    if (!user) return false;
    pthread_mutex_lock(&auth_mutex);
    uint32_t uid = 0xFFFFFFFF;
    if (!resolve_authoritative_user_locked(user, &uid, NULL)) {
        pthread_mutex_unlock(&auth_mutex);
        return false;
    }
    user->hardware_token_present = present;
    authz_states[uid].hardware_token_present = present;
    if (credential_id) {
        strncpy(user->fido2_credential_id, credential_id, sizeof(user->fido2_credential_id) - 1);
        user->fido2_credential_id[sizeof(user->fido2_credential_id) - 1] = '\0';
    }
    pthread_mutex_unlock(&auth_mutex);
    return true;
}

bool qihse_auth_can_access(const qihse_user_t* user, uint16_t data_classif, uint16_t data_sci) {
    if (data_classif > 0) {
        uint32_t uid = 0xFFFFFFFF;
        if (user) {
            pthread_mutex_lock(&auth_mutex);
            resolve_authoritative_user_locked(user, &uid, NULL);
            pthread_mutex_unlock(&auth_mutex);
        }
        qihse_audit_webhook_ping(uid, data_classif, data_sci);
    }

    // Invariant 1: No classified read primitive without an explicit user/security context!
    // NULL MUST NOT accidentally become an authorization bypass.
    if (!user) {
        if (data_classif > 0 || data_sci > 0) {
            qihse_audit_log("ACCESS_DENIED_NULL_USER_CLASSIFIED", 0xFFFFFFFF, 0, data_classif, data_sci);
            return false;
        }
        return true; /* Unclassified data allowed when unauthenticated */
    }

    pthread_mutex_lock(&auth_mutex);
    uint32_t uid = 0xFFFFFFFF;
    authz_state_t authz;
    if (!resolve_authoritative_user_locked(user, &uid, &authz)) {
        pthread_mutex_unlock(&auth_mutex);
        qihse_audit_log("ACCESS_DENIED_UNREGISTERED_USER", 0xFFFFFFFF, 0, data_classif, data_sci);
        return false;
    }

    // Hardware Token Enforcement — checked against authoritative state
    if (authz.requires_hardware_token && !authz.hardware_token_present && authz.role != QIHSE_ROLE_OPERATOR) {
        pthread_mutex_unlock(&auth_mutex);
        qihse_audit_log("ACCESS_DENIED_MISSING_TOKEN", uid, 0, data_classif, data_sci);
        return false;
    }

    // Operator has God Mode
    if (authz.role == QIHSE_ROLE_OPERATOR) {
        pthread_mutex_unlock(&auth_mutex);
        if (data_classif > 0) {
            qihse_audit_log("ACCESS_GRANTED_OPERATOR", uid, 0, data_classif, data_sci);
        }
        return true;
    }

    // Clearance Check
    if (authz.classification_level < data_classif) {
        pthread_mutex_unlock(&auth_mutex);
        qihse_audit_log("ACCESS_DENIED_CLEARANCE", uid, 0, data_classif, data_sci);
        return false;
    }

    // SCI Check
    if ((data_sci & authz.sci_compartments) != data_sci) {
        pthread_mutex_unlock(&auth_mutex);
        qihse_audit_log("ACCESS_DENIED_SCI", uid, 0, data_classif, data_sci);
        return false;
    }

    pthread_mutex_unlock(&auth_mutex);
    qihse_audit_log("ACCESS_GRANTED", uid, 0, data_classif, data_sci);
    return true;
}

bool qihse_auth_can_access_object(const qihse_user_t* user, uint32_t namespace_id, uint64_t resource_id, uint8_t required_flags) {
    if (!user || required_flags == 0) return false;

    pthread_mutex_lock(&auth_mutex);
    uint32_t uid = 0xFFFFFFFF;
    authz_state_t authz;
    if (!resolve_authoritative_user_locked(user, &uid, &authz)) {
        pthread_mutex_unlock(&auth_mutex);
        return false;
    }

    if (authz.role == QIHSE_ROLE_OPERATOR) {
        pthread_mutex_unlock(&auth_mutex);
        return true;
    }

    bool allowed = false;
    const qihse_user_t* author_user = users[uid];
    for (uint8_t i = 0; i < author_user->object_acl_count; i++) {
        const qihse_acl_entry_t* entry = &author_user->object_acl[i];
        if (entry->namespace_id == namespace_id && entry->resource_id == resource_id) {
            if ((entry->access_flags & required_flags) == required_flags) {
                allowed = true;
            }
            break;
        }
    }
    pthread_mutex_unlock(&auth_mutex);
    return allowed;
}

bool qihse_auth_grant_object(const qihse_user_t* operator_user, qihse_user_t* target_user,
                             uint32_t namespace_id, uint64_t resource_id, uint8_t access_flags) {
    const uint8_t valid_flags = QIHSE_ACL_READ | QIHSE_ACL_WRITE | QIHSE_ACL_ADMIN;
    if (!operator_user || !target_user || access_flags == 0 ||
        (access_flags & (uint8_t)~valid_flags) != 0) {
        return false;
    }

    pthread_mutex_lock(&auth_mutex);
    uint32_t op_id = 0xFFFFFFFF;
    authz_state_t op_authz;
    if (!resolve_authoritative_user_locked(operator_user, &op_id, &op_authz) ||
        op_authz.role != QIHSE_ROLE_OPERATOR) {
        pthread_mutex_unlock(&auth_mutex);
        return false;
    }

    uint32_t target_id = 0xFFFFFFFF;
    if (!resolve_authoritative_user_locked(target_user, &target_id, NULL)) {
        pthread_mutex_unlock(&auth_mutex);
        return false;
    }

    qihse_user_t* target = users[target_id];
    for (uint8_t i = 0; i < target->object_acl_count; i++) {
        qihse_acl_entry_t* entry = &target->object_acl[i];
        if (entry->namespace_id == namespace_id && entry->resource_id == resource_id) {
            entry->access_flags = access_flags;
            pthread_mutex_unlock(&auth_mutex);
            return true;
        }
    }

    if (target->object_acl_count >= QIHSE_OBJECT_ACL_MAX_ENTRIES) {
        pthread_mutex_unlock(&auth_mutex);
        return false;
    }

    qihse_acl_entry_t* entry = &target->object_acl[target->object_acl_count++];
    entry->namespace_id = namespace_id;
    entry->resource_id = resource_id;
    entry->access_flags = access_flags;
    pthread_mutex_unlock(&auth_mutex);
    return true;
}

bool qihse_auth_revoke_object(const qihse_user_t* operator_user, qihse_user_t* target_user,
                              uint32_t namespace_id, uint64_t resource_id) {
    if (!operator_user || !target_user) return false;

    pthread_mutex_lock(&auth_mutex);
    uint32_t op_id = 0xFFFFFFFF;
    authz_state_t op_authz;
    if (!resolve_authoritative_user_locked(operator_user, &op_id, &op_authz) ||
        op_authz.role != QIHSE_ROLE_OPERATOR) {
        pthread_mutex_unlock(&auth_mutex);
        return false;
    }

    uint32_t target_id = 0xFFFFFFFF;
    if (!resolve_authoritative_user_locked(target_user, &target_id, NULL)) {
        pthread_mutex_unlock(&auth_mutex);
        return false;
    }

    qihse_user_t* target = users[target_id];
    for (uint8_t i = 0; i < target->object_acl_count; i++) {
        qihse_acl_entry_t* entry = &target->object_acl[i];
        if (entry->namespace_id == namespace_id && entry->resource_id == resource_id) {
            uint8_t last = --target->object_acl_count;
            if (i != last) target->object_acl[i] = target->object_acl[last];
            memset(&target->object_acl[last], 0, sizeof(target->object_acl[last]));
            pthread_mutex_unlock(&auth_mutex);
            return true;
        }
    }
    pthread_mutex_unlock(&auth_mutex);
    return false;
}

static qihse_user_t* authenticate_user_internal(uint32_t source_ip, uint32_t user_id, const char* password) {
    if (user_id >= MAX_USERS || !password) return NULL;

    if (!qihse_auth_check_rate_limit(source_ip)) {
        fprintf(stderr, "[AUTH] Rate limit exceeded for source IP %u. Authentication rejected.\n", source_ip);
        return NULL;
    }

    pthread_mutex_lock(&auth_mutex);
    qihse_user_t* u = users[user_id];
    if (!u || !authz_states[user_id].active || !authz_states[user_id].password_set) {
        pthread_mutex_unlock(&auth_mutex);
        return NULL;
    }

    time_t now = time(NULL);
    if (rate_limits[user_id].lockout_until > now) {
        fprintf(stderr, "[AUTH] User '%s' (ID %u) is locked out. Try again in %ld seconds.\n",
                u->username, user_id, (long)(rate_limits[user_id].lockout_until - now));
        pthread_mutex_unlock(&auth_mutex);
        return NULL;
    }

    bool matched = verify_password(password, &authz_states[user_id].verifier);
    if (matched) {
        rate_limits[user_id].failed_count = 0;
        rate_limits[user_id].lockout_until = 0;
        pthread_mutex_unlock(&auth_mutex);
        qihse_auth_rate_limit_reset(source_ip);
        return u;
    } else {
        rate_limits[user_id].failed_count++;
        if (rate_limits[user_id].failed_count >= MAX_AUTH_ATTEMPTS) {
            rate_limits[user_id].lockout_until = now + AUTH_LOCKOUT_SECONDS;
            rate_limits[user_id].failed_count = 0;
            fprintf(stderr, "[AUTH] User '%s' (ID %u) locked out after %d failed attempts for %d seconds.\n",
                    u->username, user_id, MAX_AUTH_ATTEMPTS, AUTH_LOCKOUT_SECONDS);
        }
        pthread_mutex_unlock(&auth_mutex);
        return NULL;
    }
}

qihse_user_t* qihse_auth_authenticate_from(uint32_t source_ip, const char* username, const char* password) {
    if (!username || !password) return NULL;

    pthread_mutex_lock(&auth_mutex);
    uint32_t target_id = MAX_USERS;
    for (uint32_t i = 0; i < MAX_USERS; i++) {
        if (users[i] && authz_states[i].active && strcmp(users[i]->username, username) == 0) {
            target_id = i;
            break;
        }
    }
    pthread_mutex_unlock(&auth_mutex);

    if (target_id == MAX_USERS) {
        qihse_auth_check_rate_limit(source_ip);
        return NULL;
    }

    return authenticate_user_internal(source_ip, target_id, password);
}

qihse_user_t* qihse_auth_authenticate(const char* username, const char* password) {
    return qihse_auth_authenticate_from(0, username, password);
}

qihse_user_t* qihse_auth_authenticate_id_from(uint32_t source_ip, uint32_t user_id, const char* password) {
    return authenticate_user_internal(source_ip, user_id, password);
}

qihse_user_t* qihse_auth_authenticate_id(uint32_t user_id, const char* password) {
    return authenticate_user_internal(0, user_id, password);
}

// ---------------------------------------------------------------------------
// Authoritative Getters for qihse_user_t
// ---------------------------------------------------------------------------

uint32_t qihse_user_get_id(const qihse_user_t* user) {
    if (!user) return UINT32_MAX;
    pthread_mutex_lock(&auth_mutex);
    uint32_t uid = UINT32_MAX;
    if (resolve_authoritative_user_locked(user, &uid, NULL)) {
        pthread_mutex_unlock(&auth_mutex);
        return uid;
    }
    pthread_mutex_unlock(&auth_mutex);
    return UINT32_MAX;
}

uint16_t qihse_user_get_role(const qihse_user_t* user) {
    if (!user) return QIHSE_ROLE_GUEST;
    pthread_mutex_lock(&auth_mutex);
    uint32_t uid;
    authz_state_t authz;
    if (resolve_authoritative_user_locked(user, &uid, &authz)) {
        pthread_mutex_unlock(&auth_mutex);
        return authz.role;
    }
    pthread_mutex_unlock(&auth_mutex);
    return QIHSE_ROLE_GUEST;
}

uint16_t qihse_user_get_classification(const qihse_user_t* user) {
    if (!user) return 0;
    pthread_mutex_lock(&auth_mutex);
    uint32_t uid;
    authz_state_t authz;
    if (resolve_authoritative_user_locked(user, &uid, &authz)) {
        pthread_mutex_unlock(&auth_mutex);
        return authz.classification_level;
    }
    pthread_mutex_unlock(&auth_mutex);
    return 0;
}

uint16_t qihse_user_get_sci(const qihse_user_t* user) {
    if (!user) return 0;
    pthread_mutex_lock(&auth_mutex);
    uint32_t uid;
    authz_state_t authz;
    if (resolve_authoritative_user_locked(user, &uid, &authz)) {
        pthread_mutex_unlock(&auth_mutex);
        return authz.sci_compartments;
    }
    pthread_mutex_unlock(&auth_mutex);
    return 0;
}

const char* qihse_user_get_username(const qihse_user_t* user) {
    if (!user) return NULL;
    pthread_mutex_lock(&auth_mutex);
    uint32_t uid;
    if (resolve_authoritative_user_locked(user, &uid, NULL)) {
        const char* name = users[uid]->username;
        pthread_mutex_unlock(&auth_mutex);
        return name;
    }
    pthread_mutex_unlock(&auth_mutex);
    return NULL;
}

bool qihse_user_has_hardware_token(const qihse_user_t* user) {
    if (!user) return false;
    pthread_mutex_lock(&auth_mutex);
    uint32_t uid;
    authz_state_t authz;
    if (resolve_authoritative_user_locked(user, &uid, &authz)) {
        pthread_mutex_unlock(&auth_mutex);
        return authz.hardware_token_present;
    }
    pthread_mutex_unlock(&auth_mutex);
    return false;
}

bool qihse_user_requires_hardware_token(const qihse_user_t* user) {
    if (!user) return false;
    pthread_mutex_lock(&auth_mutex);
    uint32_t uid;
    authz_state_t authz;
    if (resolve_authoritative_user_locked(user, &uid, &authz)) {
        pthread_mutex_unlock(&auth_mutex);
        return authz.requires_hardware_token;
    }
    pthread_mutex_unlock(&auth_mutex);
    return false;
}

bool qihse_user_can_create_users(const qihse_user_t* user) {
    if (!user) return false;
    pthread_mutex_lock(&auth_mutex);
    uint32_t uid;
    authz_state_t authz;
    if (resolve_authoritative_user_locked(user, &uid, &authz)) {
        pthread_mutex_unlock(&auth_mutex);
        return authz.can_create_users;
    }
    pthread_mutex_unlock(&auth_mutex);
    return false;
}
