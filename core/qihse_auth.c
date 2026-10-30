#include "qihse_auth.h"
#include "qihse_audit.h"
#include "qihse_auth_internal.h"
#include "qihse_auth_registry.h"
#include "qihse_auth_durable.h"
#include "qihse_principal_record.h"
#include "qihse_pqc_crypto.h"
#include <errno.h>
#include <limits.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/pem.h>
#include <openssl/provider.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/x509.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>
#ifndef _WIN32
#include <sys/mman.h>
#endif

// ---------------------------------------------------------------------------
// IP-based auth rate limiter (brute-force protection)
// ---------------------------------------------------------------------------
// Lazy-initialized global singleton. Defaults: 5 attempts / 60s / 1024 slots.
// Protected by g_rate_limiter_mutex across the entire check/modify operation.
static qihse_rate_limiter_t *g_auth_rate_limiter = NULL;
static pthread_mutex_t g_rate_limiter_mutex = PTHREAD_MUTEX_INITIALIZER;

void qihse_auth_init_rate_limiter(uint32_t max_attempts,
                                  uint32_t window_seconds, size_t max_entries) {
  pthread_mutex_lock(&g_rate_limiter_mutex);
  if (g_auth_rate_limiter) {
    qihse_rate_limiter_destroy(g_auth_rate_limiter);
    g_auth_rate_limiter = NULL;
  }
  if (max_attempts == 0)
    max_attempts = QIHSE_AUTH_RATE_LIMIT_DEFAULT_MAX_ATTEMPTS;
  if (window_seconds == 0)
    window_seconds = QIHSE_AUTH_RATE_LIMIT_DEFAULT_WINDOW_SEC;
  if (max_entries == 0)
    max_entries = QIHSE_AUTH_RATE_LIMIT_DEFAULT_MAX_ENTRIES;
  g_auth_rate_limiter =
      qihse_rate_limiter_create(max_entries, max_attempts, window_seconds);
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
  bool allowed = false;
  pthread_mutex_lock(&g_rate_limiter_mutex);
  if (!g_auth_rate_limiter) {
    g_auth_rate_limiter =
        qihse_rate_limiter_create(QIHSE_AUTH_RATE_LIMIT_DEFAULT_MAX_ENTRIES,
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

// ---------------------------------------------------------------------------
// IP-based AUTH volume limiting (auth-storm protection)
// ---------------------------------------------------------------------------
// Second instance of the same generic limiter engine. Unlike the brute-force
// limiter, a successful authentication never resets it: a client that
// re-authenticates in a tight loop is throttled whether or not the
// credentials are correct. Defaults are deliberately generous (120/min/IP);
// QIHSE_AUTH_VOLUME_MAX / QIHSE_AUTH_VOLUME_WINDOW override them at first use.
static qihse_rate_limiter_t *g_auth_volume_limiter = NULL;
static pthread_mutex_t g_volume_limiter_mutex = PTHREAD_MUTEX_INITIALIZER;

/* QIHSE_AUTH_VOLUME_MAX / QIHSE_AUTH_VOLUME_WINDOW override the compiled-in
 * defaults; an explicit nonzero argument always wins over both. */
static void volume_limit_resolve_defaults(uint32_t *max_attempts,
                                          uint32_t *window_seconds) {
  if (*max_attempts == 0) {
    const char *env_max = getenv("QIHSE_AUTH_VOLUME_MAX");
    if (env_max && *env_max) {
      long v = strtol(env_max, NULL, 10);
      if (v > 0 && v <= (long)INT_MAX)
        *max_attempts = (uint32_t)v;
    }
    if (*max_attempts == 0)
      *max_attempts = QIHSE_AUTH_VOLUME_DEFAULT_MAX_ATTEMPTS;
  }
  if (*window_seconds == 0) {
    const char *env_window = getenv("QIHSE_AUTH_VOLUME_WINDOW");
    if (env_window && *env_window) {
      long v = strtol(env_window, NULL, 10);
      if (v > 0 && v <= (long)INT_MAX)
        *window_seconds = (uint32_t)v;
    }
    if (*window_seconds == 0)
      *window_seconds = QIHSE_AUTH_VOLUME_DEFAULT_WINDOW_SEC;
  }
}

static qihse_rate_limiter_t *volume_limiter_get_locked(void) {
  if (g_auth_volume_limiter)
    return g_auth_volume_limiter;
  uint32_t max_attempts = 0;
  uint32_t window_seconds = 0;
  volume_limit_resolve_defaults(&max_attempts, &window_seconds);
  g_auth_volume_limiter = qihse_rate_limiter_create(
      QIHSE_AUTH_VOLUME_DEFAULT_MAX_ENTRIES, max_attempts, window_seconds);
  return g_auth_volume_limiter;
}

void qihse_auth_init_volume_limiter(uint32_t max_attempts,
                                    uint32_t window_seconds,
                                    size_t max_entries) {
  pthread_mutex_lock(&g_volume_limiter_mutex);
  if (g_auth_volume_limiter) {
    qihse_rate_limiter_destroy(g_auth_volume_limiter);
    g_auth_volume_limiter = NULL;
  }
  volume_limit_resolve_defaults(&max_attempts, &window_seconds);
  if (max_entries == 0)
    max_entries = QIHSE_AUTH_VOLUME_DEFAULT_MAX_ENTRIES;
  g_auth_volume_limiter =
      qihse_rate_limiter_create(max_entries, max_attempts, window_seconds);
  pthread_mutex_unlock(&g_volume_limiter_mutex);
}

void qihse_auth_shutdown_volume_limiter(void) {
  pthread_mutex_lock(&g_volume_limiter_mutex);
  if (g_auth_volume_limiter) {
    qihse_rate_limiter_destroy(g_auth_volume_limiter);
    g_auth_volume_limiter = NULL;
  }
  pthread_mutex_unlock(&g_volume_limiter_mutex);
}

bool qihse_auth_check_volume_limit(uint32_t source_ip) {
  bool allowed = false;
  pthread_mutex_lock(&g_volume_limiter_mutex);
  qihse_rate_limiter_t *rl = volume_limiter_get_locked();
  if (rl)
    allowed = qihse_rate_limiter_check(rl, source_ip);
  pthread_mutex_unlock(&g_volume_limiter_mutex);
  return allowed;
}

void qihse_auth_volume_limit_reset(uint32_t source_ip) {
  pthread_mutex_lock(&g_volume_limiter_mutex);
  if (g_auth_volume_limiter) {
    qihse_rate_limiter_reset(g_auth_volume_limiter, source_ip);
  }
  pthread_mutex_unlock(&g_volume_limiter_mutex);
}

// ---------------------------------------------------------------------------
// Password verifier cache
// ---------------------------------------------------------------------------
// Direct-mapped table of recent successful verifications. The stored value is
// a SHA-256 key binding user_id, the verifier's salt and iteration count, and
// the presented password — never the password and never the verifier. A hit
// replaces ONLY the PBKDF2 computation: account liveness, per-user lockout,
// both rate limiters, and the post-KDF verifier-identity re-validation all
// still run on every authentication. Because the key includes the account's
// current salt, a rotated password changes the key and the old cached entry
// can never authenticate again.
#define AUTH_CACHE_DOMAIN "QIHSE-AUTHCACHE-v1"

typedef struct {
  bool valid;
  time_t expires;
  uint8_t key[32];
} auth_cache_entry_t;

static auth_cache_entry_t *g_auth_cache = NULL;
static size_t g_auth_cache_cap = 0;
static uint32_t g_auth_cache_ttl =
    QIHSE_AUTH_CACHE_DEFAULT_TTL_SECONDS; /* 0 = disabled */
static uint64_t g_auth_cache_hits = 0;
static uint64_t g_auth_cache_misses = 0;
static uint64_t g_auth_cache_stores = 0;
static pthread_mutex_t g_auth_cache_mutex = PTHREAD_MUTEX_INITIALIZER;

static void auth_cache_key_compute(uint32_t user_id,
                                   const qihse_password_verifier_t *verifier,
                                   const char *password, uint8_t out_key[32]) {
  uint8_t digest_in[64];
  /* Fixed-width little-endian encoding so the key does not depend on
   * struct packing or endianness. */
  digest_in[0] = (uint8_t)(user_id & 0xFFu);
  digest_in[1] = (uint8_t)((user_id >> 8) & 0xFFu);
  digest_in[2] = (uint8_t)((user_id >> 16) & 0xFFu);
  digest_in[3] = (uint8_t)((user_id >> 24) & 0xFFu);
  digest_in[4] = (uint8_t)(verifier->version & 0xFFu);
  digest_in[5] = (uint8_t)((verifier->version >> 8) & 0xFFu);
  digest_in[6] = (uint8_t)(verifier->algorithm & 0xFFu);
  digest_in[7] = (uint8_t)((verifier->algorithm >> 8) & 0xFFu);
  digest_in[8] = (uint8_t)(verifier->iterations & 0xFFu);
  digest_in[9] = (uint8_t)((verifier->iterations >> 8) & 0xFFu);
  digest_in[10] = (uint8_t)((verifier->iterations >> 16) & 0xFFu);
  digest_in[11] = (uint8_t)((verifier->iterations >> 24) & 0xFFu);
  memcpy(digest_in + 12, verifier->salt, QIHSE_PW_SALT_BYTES);

  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  bool ok = ctx != NULL && EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) == 1 &&
            EVP_DigestUpdate(ctx, AUTH_CACHE_DOMAIN,
                             sizeof(AUTH_CACHE_DOMAIN)) == 1 &&
            EVP_DigestUpdate(ctx, digest_in, 12u + QIHSE_PW_SALT_BYTES) == 1 &&
            EVP_DigestUpdate(ctx, password, strlen(password)) == 1;
  unsigned int md_len = 0;
  if (ok)
    ok = EVP_DigestFinal_ex(ctx, out_key, &md_len) == 1 && md_len == 32u;
  EVP_MD_CTX_free(ctx);
  OPENSSL_cleanse(digest_in, sizeof(digest_in));
  if (!ok)
    memset(out_key, 0, 32u);
}

static size_t auth_cache_slot(const uint8_t key[32]) {
  uint64_t v = 0;
  for (int i = 0; i < 8; i++)
    v = (v << 8) | key[i];
  return (size_t)(v % (uint64_t)g_auth_cache_cap);
}

static void auth_cache_ensure_allocated_locked(void) {
  if (g_auth_cache || g_auth_cache_cap == 0)
    return;
  g_auth_cache = (auth_cache_entry_t *)calloc(g_auth_cache_cap,
                                              sizeof(auth_cache_entry_t));
  if (g_auth_cache) {
#ifndef _WIN32
    /* Best effort: the cached keys are password-equivalent secrets. */
    (void)mlock(g_auth_cache, g_auth_cache_cap * sizeof(auth_cache_entry_t));
#endif
  } else {
    g_auth_cache_cap = 0; /* allocation failed: cache stays disabled */
  }
}

static uint32_t auth_cache_ttl_effective(void) {
  /* QIHSE_AUTH_CACHE_TTL_SECONDS overrides the compiled-in default on
   * first use. Benign race: worst case the env var is parsed twice. */
  static int env_read = 0;
  static uint32_t env_ttl = UINT32_MAX;
  if (!env_read) {
    env_read = 1;
    const char *env = getenv("QIHSE_AUTH_CACHE_TTL_SECONDS");
    if (env && *env) {
      char *end = NULL;
      long v = strtol(env, &end, 10);
      if (end && *end == '\0' && v >= 0 &&
          v <= (long)QIHSE_AUTH_CACHE_MAX_TTL_SECONDS) {
        env_ttl = (uint32_t)v;
      }
    }
  }
  return env_ttl != UINT32_MAX ? env_ttl : g_auth_cache_ttl;
}

/* Returns true when this exact (user, verifier, password) presentation was
 * successfully verified recently. Only ever called after the caller copied
 * the verifier under the auth lock, mirroring the KDF contract. */
static bool auth_cache_probe(uint32_t user_id,
                             const qihse_password_verifier_t *verifier,
                             const char *password) {
  uint32_t ttl = auth_cache_ttl_effective();
  if (ttl == 0 || !password || !verifier)
    return false;
  uint8_t key[32];
  auth_cache_key_compute(user_id, verifier, password, key);

  pthread_mutex_lock(&g_auth_cache_mutex);
  auth_cache_ensure_allocated_locked();
  bool hit = false;
  if (g_auth_cache) {
    auth_cache_entry_t *entry = &g_auth_cache[auth_cache_slot(key)];
    if (entry->valid && entry->expires > time(NULL) &&
        CRYPTO_memcmp(entry->key, key, sizeof(key)) == 0) {
      hit = true;
    }
  }
  if (hit)
    g_auth_cache_hits++;
  else
    g_auth_cache_misses++;
  pthread_mutex_unlock(&g_auth_cache_mutex);
  return hit;
}

static void auth_cache_store(uint32_t user_id,
                             const qihse_password_verifier_t *verifier,
                             const char *password) {
  uint32_t ttl = auth_cache_ttl_effective();
  if (ttl == 0 || !password || !verifier)
    return;
  uint8_t key[32];
  auth_cache_key_compute(user_id, verifier, password, key);

  pthread_mutex_lock(&g_auth_cache_mutex);
  auth_cache_ensure_allocated_locked();
  if (g_auth_cache) {
    auth_cache_entry_t *entry = &g_auth_cache[auth_cache_slot(key)];
    if (entry->valid)
      OPENSSL_cleanse(entry->key, sizeof(entry->key));
    entry->valid = true;
    entry->expires = time(NULL) + (time_t)ttl;
    memcpy(entry->key, key, sizeof(entry->key));
    g_auth_cache_stores++;
  }
  pthread_mutex_unlock(&g_auth_cache_mutex);
  OPENSSL_cleanse(key, sizeof(key));
}

void qihse_auth_cache_configure(uint32_t ttl_seconds, size_t capacity) {
  pthread_mutex_lock(&g_auth_cache_mutex);
  if (capacity == 0)
    capacity = QIHSE_AUTH_CACHE_DEFAULT_CAPACITY;
  if (ttl_seconds > QIHSE_AUTH_CACHE_MAX_TTL_SECONDS)
    ttl_seconds = QIHSE_AUTH_CACHE_MAX_TTL_SECONDS;
  if (g_auth_cache && capacity != g_auth_cache_cap) {
    for (size_t i = 0; i < g_auth_cache_cap; i++) {
      if (g_auth_cache[i].valid) {
        OPENSSL_cleanse(g_auth_cache[i].key, sizeof(g_auth_cache[i].key));
      }
    }
    OPENSSL_cleanse(g_auth_cache,
                    g_auth_cache_cap * sizeof(auth_cache_entry_t));
#ifndef _WIN32
    munlock(g_auth_cache, g_auth_cache_cap * sizeof(auth_cache_entry_t));
#endif
    free(g_auth_cache);
    g_auth_cache = NULL;
  }
  g_auth_cache_cap = capacity;
  g_auth_cache_ttl = ttl_seconds;
  auth_cache_ensure_allocated_locked();
  pthread_mutex_unlock(&g_auth_cache_mutex);
}

void qihse_auth_cache_clear(void) {
  pthread_mutex_lock(&g_auth_cache_mutex);
  if (g_auth_cache) {
    for (size_t i = 0; i < g_auth_cache_cap; i++) {
      if (g_auth_cache[i].valid)
        OPENSSL_cleanse(g_auth_cache[i].key, sizeof(g_auth_cache[i].key));
    }
    memset(g_auth_cache, 0, g_auth_cache_cap * sizeof(auth_cache_entry_t));
  }
  g_auth_cache_hits = 0;
  g_auth_cache_misses = 0;
  g_auth_cache_stores = 0;
  pthread_mutex_unlock(&g_auth_cache_mutex);
}

void qihse_auth_cache_stats(uint64_t *out_hits, uint64_t *out_misses,
                            uint64_t *out_stores) {
  pthread_mutex_lock(&g_auth_cache_mutex);
  if (out_hits)
    *out_hits = g_auth_cache_hits;
  if (out_misses)
    *out_misses = g_auth_cache_misses;
  if (out_stores)
    *out_stores = g_auth_cache_stores;
  pthread_mutex_unlock(&g_auth_cache_mutex);
}

/* Principal capacity per node. Sized for large multi-tenant fleets (65,536):
 * the registry and shadow-authz arrays are static but untouched pages cost
 * nothing until principals are created (~104 B/authz slot, ~1 KB mlocked per
 * live principal). user_id is u32; ids must stay below MAX_USERS. */
#define MAX_USERS 65536
#define MAX_AUTH_ATTEMPTS 5
#define AUTH_LOCKOUT_SECONDS 300

typedef struct {
  uint32_t failed_count;
  time_t lockout_until;
} auth_rate_limit_t;

/* Authoritative internal authorization and security state.
 * Any presented user pointer MUST be authoritatively verified against this
 * state. */
typedef struct {
  bool active;
  uint16_t role;
  uint16_t classification_level;
  uint16_t sci_compartments;
  uint32_t tenant_id;
  bool requires_hardware_token;
  bool hardware_token_present;
  bool can_create_users;
  bool password_set;
  /* True only when a real PBKDF2 verifier has been computed (via
   * QIHSE_OPERATOR_PASSWORD at init, bootstrap_operator, create_user, or
   * modify_user). Distinct from password_set, which operator-only mode
   * reports as true even before any password exists. */
  bool verifier_configured;
  uint64_t principal_generation;
  uint64_t ref_count;
  qihse_password_verifier_t verifier;
} authz_state_t;

static qihse_user_t *users[MAX_USERS];
/* Unscoped legacy handles may outlive every scoped reference. Never modify,
 * free or reuse retired storage, even when scoped refs reach zero: raw readers
 * are untracked. Policy rotations and imports share this bounded pool. */
static qihse_user_t *retired_principals[MAX_USERS];
static uint64_t retired_refs[MAX_USERS];
static size_t retired_count;
static authz_state_t authz_states[MAX_USERS];
static pthread_rwlock_t auth_rwlock = PTHREAD_RWLOCK_INITIALIZER;
pthread_mutex_t qihse_auth_lifecycle_mutex;
static pthread_once_t lifecycle_once = PTHREAD_ONCE_INIT;
static __thread bool auth_writer;
static void lifecycle_init(void) {
 pthread_mutexattr_t attr;
 pthread_mutexattr_init(&attr);
 pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
 pthread_mutex_init(&qihse_auth_lifecycle_mutex, &attr);
 pthread_mutexattr_destroy(&attr);
}
void qihse_auth_lifecycle_enter(void) {
 pthread_once(&lifecycle_once, lifecycle_init);
 pthread_mutex_lock(&qihse_auth_lifecycle_mutex);
}
void qihse_auth_lifecycle_leave(void) {
 pthread_mutex_unlock(&qihse_auth_lifecycle_mutex);
}
static void auth_write_lock(void) {
 qihse_auth_lifecycle_enter();
 pthread_rwlock_wrlock(&auth_rwlock);
 auth_writer = true;
}
static void auth_unlock(void) {
 bool writer = auth_writer;
 auth_writer = false;
 pthread_rwlock_unlock(&auth_rwlock);
 if (writer) qihse_auth_lifecycle_leave();
}
static bool auth_durable_stage_locked(uint32_t uid, const qihse_user_t *candidate,
 bool active, uint32_t failures, time_t until, bool bump_generation);
static qihse_auth_image_t *auth_image_capture_locked(
 const qihse_auth_image_context_t *context);
static uint32_t active_user_count = 0;
/* One-way guard for a future committed registry. The auth table still needs
 * an atomic, generation-bound publication path before this can be enabled. */
static bool auth_direct_mutations_fenced = false;
/* Registry startup must be the first auth initialization in this process.
 * Until a committed snapshot is published, it issues no login handles. */
static bool auth_initialized_once = false;
/* Published only after both the audit writer and principal table are ready. */
static bool auth_service_ready = false;
static bool auth_registry_pre_serve = false;
static bool auth_init_pending = false;
static auth_rate_limit_t rate_limits[MAX_USERS];

/* Username -> user_id map: open-addressed linear-probe table with twice the
 * capacity of MAX_USERS (load factor <= 0.5), so the per-login lookup in
 * qihse_auth_authenticate_from is O(1) instead of a 65,536-entry strcmp scan.
 * Slot value = user_id + 1; 0 = empty, UINT32_MAX = tombstone.
 * All access is under auth_rwlock. */
#define AUTH_NAME_MAP_CAP (1u << 17)
static uint32_t g_name_map[AUTH_NAME_MAP_CAP];

static uint32_t auth_name_hash(const char *s) {
  uint32_t h = 2166136261u;
  while (*s) {
    h ^= (uint8_t)*s++;
    h *= 16777619u;
  }
  return h;
}

/* Returns the map slot index for `username`, or -1 if absent. */
static int64_t auth_name_find_slot(const char *username) {
  uint32_t h = auth_name_hash(username) & (AUTH_NAME_MAP_CAP - 1u);
  for (uint32_t i = 0; i < AUTH_NAME_MAP_CAP; i++) {
    uint32_t slot = g_name_map[(h + i) & (AUTH_NAME_MAP_CAP - 1u)];
    if (slot == 0u)
      return -1;
    if (slot == UINT32_MAX)
      continue;
    uint32_t uid = slot - 1u;
    if (uid < MAX_USERS && users[uid] &&
        strcmp(users[uid]->username, username) == 0)
      return (int64_t)((h + i) & (AUTH_NAME_MAP_CAP - 1u));
  }
  return -1;
}

static void auth_name_insert_locked(const char *username, uint32_t user_id) {
  if (!username || !username[0])
    return;
  uint32_t h = auth_name_hash(username) & (AUTH_NAME_MAP_CAP - 1u);
  for (uint32_t i = 0; i < AUTH_NAME_MAP_CAP; i++) {
    uint32_t pos = (h + i) & (AUTH_NAME_MAP_CAP - 1u);
    uint32_t slot = g_name_map[pos];
    if (slot == 0u || slot == UINT32_MAX) {
      g_name_map[pos] = user_id + 1u;
      return;
    }
    uint32_t uid = slot - 1u;
    if (uid < MAX_USERS && users[uid] &&
        strcmp(users[uid]->username, username) == 0) {
      g_name_map[pos] =
          user_id + 1u; /* remap (username moved to a different id) */
      return;
    }
  }
}

static void auth_name_remove_locked(const char *username) {
  if (!username)
    return;
  int64_t slot = auth_name_find_slot(username);
  if (slot >= 0)
    g_name_map[slot] = UINT32_MAX;
}

static void auth_name_map_clear_locked(void) {
  memset(g_name_map, 0, sizeof(g_name_map));
}

/* O(1) username -> active user_id lookup; returns MAX_USERS on miss.
 * Caller must hold auth_rwlock (read or write). */
static uint32_t auth_name_lookup_locked(const char *username) {
  int64_t slot = auth_name_find_slot(username);
  if (slot < 0)
    return MAX_USERS;
  uint32_t uid = g_name_map[slot] - 1u;
  if (uid >= MAX_USERS || !users[uid] || !authz_states[uid].active ||
      strcmp(users[uid]->username, username) != 0)
    return MAX_USERS;
  return uid;
}
/* Set when any principal requires a hardware token. While zero, the
 * unclassified fast path in qihse_auth_can_access may skip the authoritative
 * resolve; once set it never clears, so the flag cannot be tampered with via
 * user-struct memory and MFA-gated principals always take the full check. */
static uint8_t g_any_token_required = 0;

static EVP_MD *g_cached_sha384 = NULL;
static pthread_once_t g_evp_fetch_once = PTHREAD_ONCE_INIT;
static void fetch_evp_algorithms(void) {
  g_cached_sha384 = EVP_MD_fetch(NULL, "SHA-384", NULL);
}
static const EVP_MD *get_sha384_md(void) {
  pthread_once(&g_evp_fetch_once, fetch_evp_algorithms);
  return g_cached_sha384 ? g_cached_sha384 : EVP_sha384();
}

#ifdef QIHSE_TESTING
#define QIHSE_PW_MIN_ALLOWED_ITERATIONS 1000u
#else
#define QIHSE_PW_MIN_ALLOWED_ITERATIONS QIHSE_PW_MIN_ITERATIONS
#endif

static uint32_t get_password_iterations(void) {
  const char *env = getenv("QIHSE_PW_ITERATIONS");
  if (env) {
    char *endptr = NULL;
    errno = 0;
    long v = strtol(env, &endptr, 10);
    if (errno != 0 || endptr == env || *endptr != '\0') {
      fprintf(stderr, "[SECURITY ERROR] Malformed QIHSE_PW_ITERATIONS "
                      "environment variable.\n");
      return 0;
    }
    if (v < (long)QIHSE_PW_MIN_ALLOWED_ITERATIONS || v > (long)INT_MAX) {
      fprintf(stderr,
              "[SECURITY ERROR] QIHSE_PW_ITERATIONS outside permitted range "
              "(minimum %u).\n",
              QIHSE_PW_MIN_ALLOWED_ITERATIONS);
      return 0;
    }
    return (uint32_t)v;
  }
  return QIHSE_PW_MIN_ITERATIONS;
}

bool qihse_password_compute(const char *password, uint32_t iterations,
                            qihse_password_verifier_t *out_verifier) {
  if (!password || !out_verifier)
    return false;
  size_t pw_len = strlen(password);
  if (pw_len < 12)
    return false;

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
  if (PKCS5_PBKDF2_HMAC(password, (int)pw_len, out_verifier->salt,
                        QIHSE_PW_SALT_BYTES, (int)out_verifier->iterations,
                        get_sha384_md(), sizeof(intermediate),
                        intermediate) != 1) {
    OPENSSL_cleanse(intermediate, sizeof(intermediate));
    return false;
  }

  const char *pepper = getenv("QIHSE_AUTH_PEPPER");
  if (pepper && strlen(pepper) > 0) {
    unsigned int hmac_len = 0;
    if (HMAC(get_sha384_md(), pepper, (int)strlen(pepper), intermediate,
             sizeof(intermediate), out_verifier->verifier, &hmac_len) == NULL ||
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

bool qihse_password_verify(const char *password,
                           const qihse_password_verifier_t *verifier) {
  if (!password || !verifier)
    return false;
  if (verifier->version != QIHSE_PW_VERIFIER_VERSION_1 ||
      verifier->algorithm != QIHSE_PW_ALG_PBKDF2_HMAC_SHA384 ||
      verifier->iterations < QIHSE_PW_MIN_ALLOWED_ITERATIONS ||
      verifier->iterations > (uint32_t)INT_MAX) {
    return false;
  }
  size_t pw_len = strlen(password);

  uint8_t intermediate[QIHSE_PW_HASH_BYTES];
  if (PKCS5_PBKDF2_HMAC(password, (int)pw_len, verifier->salt,
                        QIHSE_PW_SALT_BYTES, (int)verifier->iterations,
                        get_sha384_md(), sizeof(intermediate),
                        intermediate) != 1) {
    OPENSSL_cleanse(intermediate, sizeof(intermediate));
    return false;
  }

  uint8_t expected[QIHSE_PW_HASH_BYTES];
  const char *pepper = getenv("QIHSE_AUTH_PEPPER");
  if (pepper && strlen(pepper) > 0) {
    unsigned int hmac_len = 0;
    if (HMAC(get_sha384_md(), pepper, (int)strlen(pepper), intermediate,
             sizeof(intermediate), expected, &hmac_len) == NULL ||
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

static inline bool
compute_password_verifier(const char *password, uint32_t iterations,
                          qihse_password_verifier_t *out_verifier) {
  return qihse_password_compute(password, iterations, out_verifier);
}

static inline bool verify_password(const char *password,
                                   const qihse_password_verifier_t *verifier) {
  return qihse_password_verify(password, verifier);
}

/* auth_rwlock must be held (read or write). */
static bool resolve_authoritative_user_locked(const qihse_user_t *presented,
                                              uint32_t *out_user_id,
                                              authz_state_t *out_state) {
  if (!presented || !__atomic_load_n(&auth_service_ready, __ATOMIC_ACQUIRE) ||
      (qihse_auth_durable_active() && !qihse_auth_durable_ready()))
    return false;
  uint32_t uid = MAX_USERS;
  for (uint32_t i = 0; i < MAX_USERS; i++) {
    if (users[i] == presented && authz_states[i].active) {
      uid = i;
      break;
    }
  }
  if (uid == MAX_USERS)
    return false;

  if (out_user_id)
    *out_user_id = uid;
  if (out_state)
    *out_state = authz_states[uid];
  return true;
}

static void set_authz_state_locked(uint32_t user_id, const qihse_user_t *user) {
  if (user_id >= MAX_USERS || !user)
    return;
  authz_states[user_id].active = true;
  authz_states[user_id].role = user->role;
  authz_states[user_id].classification_level = user->classification_level;
  authz_states[user_id].sci_compartments = user->sci_compartments;
  authz_states[user_id].tenant_id = user->tenant_id;
  authz_states[user_id].requires_hardware_token = user->requires_hardware_token;
  authz_states[user_id].hardware_token_present = user->hardware_token_present;
  authz_states[user_id].can_create_users = user->can_create_users;
  authz_states[user_id].password_set = user->password_set;
  authz_states[user_id].verifier = user->verifier;
  if (authz_states[user_id].principal_generation == 0) {
    authz_states[user_id].principal_generation = 1;
  }
}

/* Public handle fields are not authority. Preserve the registered shadow
 * policy when staging a mutation that changes only a subset of it. */
static qihse_user_t auth_policy_snapshot_locked(uint32_t uid) {
  qihse_user_t candidate = *users[uid];
  const authz_state_t *state = &authz_states[uid];
  candidate.user_id = uid;
  candidate.role = state->role;
  candidate.tenant_id = state->tenant_id;
  candidate.classification_level = state->classification_level;
  candidate.sci_compartments = state->sci_compartments;
  candidate.requires_hardware_token = state->requires_hardware_token;
  candidate.hardware_token_present = state->hardware_token_present;
  candidate.can_create_users = state->can_create_users;
  candidate.password_set = state->password_set;
  candidate.verifier = state->verifier;
  return candidate;
}

/* Caller preflights capacity and holds auth_rwlock for writing.
 * Scoped borrows belong to the allocation, not the UID. */
static void auth_retire_principal_locked(uint32_t uid) {
  retired_principals[retired_count] = users[uid];
  retired_refs[retired_count++] = authz_states[uid].ref_count;
  authz_states[uid].ref_count = 0;
}

static bool auth_policy_commit_locked(uint32_t uid,
                                      const qihse_user_t *candidate,
                                      bool active) {
  bool durable = qihse_auth_durable_active();
  qihse_user_t *replacement = NULL;
  if (durable) {
    if (retired_count >= MAX_USERS)
      return false;
    replacement = calloc(1, sizeof(*replacement));
    if (!replacement)
      return false;
    if (active)
      *replacement = *candidate;
#ifndef _WIN32
    mlock(replacement, sizeof(*replacement));
#endif
  }
  if (!auth_durable_stage_locked(uid, candidate, active,
                                active ? rate_limits[uid].failed_count : 0,
                                active ? rate_limits[uid].lockout_until : 0, true)) {
    if (replacement) {
      OPENSSL_cleanse(replacement, sizeof(*replacement));
#ifndef _WIN32
      munlock(replacement, sizeof(*replacement));
#endif
      free(replacement);
    }
    return false;
  }
  /* No allocation or fallible operation remains after durable success. */
  auth_name_remove_locked(users[uid]->username);
  if (durable) {
    auth_retire_principal_locked(uid);
    users[uid] = replacement;
  } else if (active) {
    *users[uid] = *candidate;
  }
  if (active) {
    authz_states[uid].principal_generation++;
    set_authz_state_locked(uid, users[uid]);
    auth_name_insert_locked(users[uid]->username, uid);
    if (users[uid]->requires_hardware_token)
      __atomic_store_n(&g_any_token_required, (uint8_t)1, __ATOMIC_RELEASE);
  }
  return true;
}

static bool check_fips_compliance(void) {
  const char *fips_env = getenv("QIHSE_FIPS_MODE");
  if (fips_env &&
      (strcmp(fips_env, "1") == 0 || strcasecmp(fips_env, "required") == 0)) {
    OSSL_PROVIDER *base = OSSL_PROVIDER_load(NULL, "base");
    OSSL_PROVIDER *fips = OSSL_PROVIDER_load(NULL, "fips");
    if (!base || !fips) {
      fprintf(stderr, "[FIPS ERROR] QIHSE_FIPS_MODE=required but FIPS/base "
                      "provider failed to load in OpenSSL.\n");
      if (fips)
        OSSL_PROVIDER_unload(fips);
      if (base)
        OSSL_PROVIDER_unload(base);
      return false;
    }
    if (EVP_default_properties_enable_fips(NULL, 1) != 1) {
      fprintf(stderr, "[FIPS ERROR] QIHSE_FIPS_MODE=required but "
                      "EVP_default_properties_enable_fips failed.\n");
      OSSL_PROVIDER_unload(fips);
      OSSL_PROVIDER_unload(base);
      return false;
    }
    if (!EVP_default_properties_is_fips_enabled(NULL)) {
      fprintf(stderr, "[FIPS ERROR] QIHSE_FIPS_MODE=required but FIPS provider "
                      "is not active in OpenSSL.\n");
      (void)EVP_default_properties_enable_fips(NULL, 0);
      OSSL_PROVIDER_unload(fips);
      OSSL_PROVIDER_unload(base);
      return false;
    }
  }
  return true;
}

static bool auth_init_mode(bool registry_pre_serve) {
  auth_write_lock();
  bool permitted = !qihse_auth_durable_active() && !auth_direct_mutations_fenced && !auth_init_pending &&
                   (!registry_pre_serve || !auth_initialized_once);
  if (permitted) {
    auth_initialized_once = true;
    auth_init_pending = true;
    if (registry_pre_serve)
      auth_registry_pre_serve = true;
  }
  auth_unlock();
  if (!permitted)
    return false;
  __atomic_store_n(&auth_service_ready, false, __ATOMIC_RELEASE);
  qihse_audit_init();
  if (!check_fips_compliance()) {
    auth_write_lock();
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
    auth_name_map_clear_locked();
    active_user_count = 0;
    if (!registry_pre_serve)
      auth_init_pending = false;
    auth_unlock();
    return false;
  }

  auth_write_lock();
  if (auth_direct_mutations_fenced || (qihse_auth_durable_active() && !qihse_auth_durable_ready())) {
    auth_unlock();
    return false;
  }
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
  auth_name_map_clear_locked();
  active_user_count = 0;

  // PRE-SEED SYSTEM OPERATOR (User ID 0)
  // In operator-only mode the operator is active with no password
  // required. QIHSE_OPERATOR_PASSWORD may still be set to require
  // password authentication, but it is not needed for normal
  // operator-only operation.
  qihse_user_t *op = calloc(1, sizeof(qihse_user_t));
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

    bool operator_verifier_configured = false;
    const char *initial_pass = getenv("QIHSE_OPERATOR_PASSWORD");
    if (initial_pass && strlen(initial_pass) >= 12) {
      operator_verifier_configured =
          compute_password_verifier(initial_pass, 0, &op->verifier);
    }
    op->password_set = true;

#ifndef _WIN32
    mlock(op, sizeof(qihse_user_t));
#endif
    users[0] = op;
    auth_name_insert_locked(op->username, 0);
    set_authz_state_locked(0, op);
    authz_states[0].verifier_configured = operator_verifier_configured;
    active_user_count = 1;
  }

  bool ready = op != NULL;
  if (registry_pre_serve) {
    ready = ready && authz_states[0].verifier_configured;
    if (ready) {
      auth_direct_mutations_fenced = true;
      auth_registry_pre_serve = true;
    } else if (op) {
      OPENSSL_cleanse(op, sizeof(*op));
#ifndef _WIN32
      munlock(op, sizeof(*op));
#endif
      free(op);
      users[0] = NULL;
      memset(&authz_states[0], 0, sizeof(authz_states[0]));
      auth_name_map_clear_locked();
      active_user_count = 0;
    }
  } else {
    auth_init_pending = false;
  }
  auth_unlock();
  __atomic_store_n(&auth_service_ready, ready, __ATOMIC_RELEASE);
  return ready;
}

bool qihse_auth_init(void) { return auth_init_mode(false); }

bool qihse_auth_init_registry_pre_serve(void) { return auth_init_mode(true); }

bool qihse_auth_fence_direct_mutations(void) {
  auth_write_lock();
  bool ready = !auth_init_pending && active_user_count == 1u && users[0] &&
               authz_states[0].active && authz_states[0].verifier_configured;
  if (ready)
    auth_direct_mutations_fenced = true;
  auth_unlock();
  return ready;
}

bool qihse_auth_bootstrap_operator(const char *initial_password) {
  if (!initial_password || strlen(initial_password) < 12)
    return false;

  auth_write_lock();
  if (auth_direct_mutations_fenced || !users[0] || !authz_states[0].active) {
    auth_unlock();
    return false;
  }
  if (authz_states[0].verifier_configured) {
    // Already bootstrapped (env password or prior bootstrap); must rotate
    // through modify_user with operator credentials
    auth_unlock();
    return false;
  }

  qihse_user_t staged = auth_policy_snapshot_locked(0);
  if (!compute_password_verifier(initial_password, 0, &staged.verifier)) {
    OPENSSL_cleanse(&staged, sizeof(staged));
    auth_unlock();
    return false;
  }
  staged.password_set = true;
  if (!auth_policy_commit_locked(0, &staged, true)) {
    OPENSSL_cleanse(&staged, sizeof(staged)); auth_unlock(); return false;
  }
  OPENSSL_cleanse(&staged, sizeof(staged));
  authz_states[0].verifier_configured = true;
  auth_unlock();
  return true;
}

bool qihse_auth_is_operator_password_default(void) {
  pthread_rwlock_rdlock(&auth_rwlock);
  bool is_default = true;
  if (users[0] && authz_states[0].active) {
    /* Aligned with bootstrap's own gate: "default" means no password
     * verifier is configured.  password_set is true from init even in
     * operator-only mode, so it can never carry this signal — the old
     * check made this function permanently false and every
     * still-on-default guard unreachable. */
    is_default = !authz_states[0].verifier_configured;
  }
  auth_unlock();
  return is_default;
}

static qihse_user_t *create_user_internal(const qihse_user_t *creator,
                                          uint32_t tenant_id, uint32_t user_id,
                                          uint16_t role, uint16_t classif,
                                          uint16_t sci,
                                          const char *plaintext_password,
                                          bool requires_hw_token) {
  if (user_id >= MAX_USERS || role > QIHSE_ROLE_GUEST)
    return NULL;
  if (!plaintext_password || strlen(plaintext_password) < 12) {
    fprintf(stderr,
            "[SECURITY ERROR] Password for User ID %u rejected: minimum 12 "
            "characters required.\n",
            user_id);
    return NULL;
  }

  auth_write_lock();
  if (auth_direct_mutations_fenced || (qihse_auth_durable_active() && !qihse_auth_durable_ready())) {
    auth_unlock();
    return NULL;
  }

  // Operator password must be set before creating other users
  if (user_id != 0 && !authz_states[0].password_set) {
    fprintf(stderr, "[SECURITY ERROR] Operator password must be set before "
                    "creating users.\n");
    auth_unlock();
    return NULL;
  }

  uint32_t creator_id = 0xFFFFFFFFu;
  authz_state_t creator_authz;
  if (!resolve_authoritative_user_locked(creator, &creator_id,
                                         &creator_authz)) {
    qihse_audit_log("USER_CREATE_DENIED_INVALID_CREATOR", creator_id, user_id,
                    classif, sci);
    auth_unlock();
    return NULL;
  }

  // Only authoritative OPERATOR or delegated user can create new users
  if ((creator_authz.requires_hardware_token && !creator_authz.hardware_token_present) ||
      (creator_authz.role != QIHSE_ROLE_OPERATOR && !creator_authz.can_create_users)) {
    qihse_audit_log("USER_CREATE_DENIED_DELEGATION", creator_id, user_id,
                    classif, sci);
    auth_unlock();
    return NULL;
  }

  // Principal cannot create a principal above itself
  if (role < creator_authz.role ||
      (role == QIHSE_ROLE_OPERATOR &&
       (creator_authz.classification_level != UINT16_MAX ||
        creator_authz.sci_compartments != UINT16_MAX))) {
    qihse_audit_log("USER_CREATE_DENIED_ROLE", creator_id, user_id, classif,
                    sci);
    auth_unlock();
    return NULL;
  }

  // Creator must possess the clearance they attempt to grant
  if (classif > creator_authz.classification_level) {
    qihse_audit_log("USER_CREATE_DENIED_CLEARANCE", creator_id, user_id,
                    classif, sci);
    auth_unlock();
    return NULL;
  }
  if ((sci & creator_authz.sci_compartments) != sci) {
    qihse_audit_log("USER_CREATE_DENIED_SCI", creator_id, user_id, classif,
                    sci);
    auth_unlock();
    return NULL;
  }

  // Tenant scope ladder (invariant #2): a tenant-scoped creator may only
  // create principals inside its own tenant — never in another tenant and
  // never in the system domain. Only system-domain (tenant 0) creators can
  // mint system-domain principals, and only via qihse_auth_create_user.
  if (creator_authz.tenant_id != QIHSE_TENANT_SYSTEM &&
      tenant_id != creator_authz.tenant_id) {
    qihse_audit_log("USER_CREATE_DENIED_TENANT", creator_id, user_id, classif,
                    sci);
    auth_unlock();
    return NULL;
  }

  // Delegation must not weaken an enforced hardware-token requirement
  if (creator_authz.requires_hardware_token && !requires_hw_token) {
    qihse_audit_log("USER_CREATE_DENIED_TOKEN_POLICY", creator_id, user_id,
                    classif, sci);
    auth_unlock();
    return NULL;
  }

  // Delegated creation floors the new principal to the LOWEST rank
  // (invariant #2: can_create_users delegates account creation, never
  // authority — a delegated creator cannot duplicate its own rank either).
  // Elevation afterwards is a separate operator action (modify_user is
  // operator-only). OPERATOR-role creators mint explicitly; the ladder
  // checks above still bound what they may grant.
  if (creator_authz.role != QIHSE_ROLE_OPERATOR) {
    uint16_t requested_classif = classif;
    uint16_t requested_sci = sci;
    role = QIHSE_ROLE_GUEST;
    classif = 0;
    sci = 0;
    if (requested_classif != 0u || requested_sci != 0u) {
      qihse_audit_log("USER_CREATE_DELEGATED_FLOOR", creator_id, user_id,
                      requested_classif, requested_sci);
    }
  }

  if (users[user_id] != NULL) {
    auth_unlock();
    return NULL;
  }

  qihse_user_t *u = calloc(1, sizeof(qihse_user_t));
  if (!u) {
    auth_unlock();
    return NULL;
  }

  u->user_id = user_id;
  u->role = role;
  u->tenant_id = tenant_id;

  if (role == QIHSE_ROLE_OPERATOR) {
    u->classification_level = 0xFFFF;
    u->sci_compartments = 0xFFFF;
  } else {
    u->classification_level = classif;
    u->sci_compartments = sci;
  }

  if (!compute_password_verifier(plaintext_password, 0, &u->verifier)) {
    free(u);
    auth_unlock();
    return NULL;
  }
  u->password_set = true;
  u->requires_hardware_token = requires_hw_token;
  u->can_create_users = false;
  snprintf(u->username, 64, "User_%u", user_id);
  if (auth_name_lookup_locked(u->username)!=MAX_USERS) {
    OPENSSL_cleanse(u,sizeof(*u)); free(u); auth_unlock(); return NULL;
  }

  if (!auth_durable_stage_locked(user_id, u, true, 0, 0, true)) {
    OPENSSL_cleanse(u, sizeof(*u)); free(u); auth_unlock(); return NULL;
  }
  users[user_id] = u;
  if (requires_hw_token)
    __atomic_store_n(&g_any_token_required, (uint8_t)1, __ATOMIC_RELEASE);
  auth_name_insert_locked(u->username, user_id);
  set_authz_state_locked(user_id, u);
  authz_states[user_id].verifier_configured = true;
  active_user_count++;
#ifndef _WIN32
  mlock(u, sizeof(qihse_user_t));
#endif

  qihse_audit_log("USER_CREATE", creator_id, user_id, u->classification_level,
                  u->sci_compartments);
  auth_unlock();
  return u;
}

qihse_user_t *qihse_auth_create_user(const qihse_user_t *creator,
                                     uint32_t user_id, uint16_t role,
                                     uint16_t classif, uint16_t sci,
                                     const char *plaintext_password,
                                     bool requires_hw_token) {
  return create_user_internal(creator, QIHSE_TENANT_SYSTEM, user_id, role,
                              classif, sci, plaintext_password,
                              requires_hw_token);
}

qihse_user_t *qihse_auth_create_tenant_user(const qihse_user_t *creator,
                                            uint32_t tenant_id,
                                            uint32_t user_id, uint16_t role,
                                            uint16_t classif, uint16_t sci,
                                            const char *plaintext_password,
                                            bool requires_hw_token) {
  if (tenant_id == QIHSE_TENANT_SYSTEM) {
    // System-domain principals go through qihse_auth_create_user only.
    qihse_audit_log("USER_CREATE_DENIED_TENANT", 0xFFFFFFFFu, user_id, classif,
                    sci);
    return NULL;
  }
  return create_user_internal(creator, tenant_id, user_id, role, classif, sci,
                              plaintext_password, requires_hw_token);
}

qihse_user_t *qihse_auth_get_user(uint32_t user_id) {
  if (user_id >= MAX_USERS)
    return NULL;
  pthread_rwlock_rdlock(&auth_rwlock);
  qihse_user_t *u = NULL;
  if (authz_states[user_id].active &&
      (!qihse_auth_durable_active() || qihse_auth_durable_ready())) {
    u = users[user_id];
  }
  auth_unlock();
  return u;
}

bool qihse_auth_destroy_user(const qihse_user_t *actor,
                             uint32_t target_user_id) {
  if (target_user_id >= MAX_USERS)
    return false;

  auth_write_lock();
  if (auth_direct_mutations_fenced || (qihse_auth_durable_active() && !qihse_auth_durable_ready())) {
    auth_unlock();
    return false;
  }
  uint32_t actor_id = 0xFFFFFFFFu;
  authz_state_t actor_authz;
  if (!resolve_authoritative_user_locked(actor, &actor_id, &actor_authz) ||
      actor_authz.role != QIHSE_ROLE_OPERATOR ||
      (actor_authz.requires_hardware_token && !actor_authz.hardware_token_present)) {
    auth_unlock();
    qihse_audit_log("USER_DESTROY_DENIED", actor_id, target_user_id, 0, 0);
    return false;
  }

  if (!users[target_user_id] || !authz_states[target_user_id].active) {
    auth_unlock();
    return false;
  }

  // Tenant boundary scoping: non-system operator can only delete users in its
  // own tenant
  if (actor_authz.tenant_id != QIHSE_TENANT_SYSTEM &&
      authz_states[target_user_id].tenant_id != actor_authz.tenant_id) {
    auth_unlock();
    qihse_audit_log("USER_DESTROY_DENIED_TENANT", actor_id, target_user_id, 0,
                    0);
    return false;
  }

  // Tenant operators cannot delete User 0; system operators require
  // QIHSE_ALLOW_DESTROY_OPERATOR
  if (target_user_id == 0) {
    if (actor_authz.tenant_id != QIHSE_TENANT_SYSTEM) {
      auth_unlock();
      qihse_audit_log("USER_DESTROY_DENIED", actor_id, target_user_id, 0, 0);
      return false;
    }
    const char *allow_kill = getenv("QIHSE_ALLOW_DESTROY_OPERATOR");
    if (!allow_kill || strcmp(allow_kill, "1") != 0) {
      auth_unlock();
      return false;
    }
  }

  if (users[target_user_id] && authz_states[target_user_id].active) {
    if ((qihse_auth_durable_active() && target_user_id == 0) ||
        !auth_policy_commit_locked(target_user_id, users[target_user_id], false)) {
      auth_unlock(); return false;
    }
    uint64_t deleted_generation = authz_states[target_user_id].principal_generation + 1;
    uint64_t retained_refs = authz_states[target_user_id].ref_count;
    qihse_audit_log("USER_DESTROY", actor_id, target_user_id,
                    authz_states[target_user_id].classification_level,
                    authz_states[target_user_id].sci_compartments);
    /* Volatile mode retains its original in-place tombstone. Durable mode
     * already retired the old allocation and installed a fresh tombstone,
     * so cleansing here never races readers of the retired handle. Occupied
     * tombstone slots cannot be recreated or alias another principal. */
    OPENSSL_cleanse(users[target_user_id], sizeof(qihse_user_t));
#ifndef _WIN32
    munlock(users[target_user_id], sizeof(qihse_user_t));
#endif
    memset(&authz_states[target_user_id], 0,
           sizeof(authz_states[target_user_id]));
    authz_states[target_user_id].principal_generation = deleted_generation;
    authz_states[target_user_id].ref_count = retained_refs;
    memset(&rate_limits[target_user_id], 0,
           sizeof(rate_limits[target_user_id]));
    active_user_count--;
    auth_unlock();
    return true;
  }

  auth_unlock();
  return false;
}

bool qihse_auth_modify_user(const qihse_user_t *operator_user,
                            uint32_t target_user_id, const char *new_username,
                            const char *new_password, int new_requires_hw_token,
                            int new_can_create_users, int new_classification,
                            int new_sci) {
  if (target_user_id >= MAX_USERS || new_requires_hw_token < -1 ||
      new_requires_hw_token > 1 || new_can_create_users < -1 || new_can_create_users > 1)
    return false;
  if (new_password != NULL && strlen(new_password) < 12) {
    fprintf(stderr,
            "[SECURITY ERROR] Password for User ID %u rejected: minimum 12 "
            "characters required.\n",
            target_user_id);
    return false;
  }
  if (new_classification < -1 || new_classification > 0xFFFF || new_sci < -1 ||
      new_sci > 0xFFFF) {
    fprintf(stderr,
            "[SECURITY ERROR] Clearance/SCI for User ID %u rejected: out of "
            "range.\n",
            target_user_id);
    return false;
  }

  auth_write_lock();
  if (auth_direct_mutations_fenced || (qihse_auth_durable_active() && !qihse_auth_durable_ready())) {
    auth_unlock();
    return false;
  }
  uint32_t operator_id = 0xFFFFFFFFu;
  authz_state_t operator_authz;
  if (!resolve_authoritative_user_locked(operator_user, &operator_id,
                                         &operator_authz) ||
      operator_authz.role != QIHSE_ROLE_OPERATOR ||
      (operator_authz.requires_hardware_token && !operator_authz.hardware_token_present)) {
    auth_unlock();
    qihse_audit_log("USER_MODIFY_DENIED", operator_id, target_user_id, 0, 0);
    return false;
  }

  // Explicitly disallow modifying User 0 by any actor other than User 0 itself
  if (target_user_id == 0 && operator_id != 0) {
    fprintf(stderr, "[SECURITY ERROR] User 0 cannot be modified by any actor "
                    "other than User 0 itself.\n");
    auth_unlock();
    qihse_audit_log("USER_MODIFY_DENIED", operator_id, target_user_id, 0, 0);
    return false;
  }

  if (target_user_id != 0 && !authz_states[0].password_set) {
    fprintf(stderr, "[SECURITY ERROR] Operator password must be set before "
                    "modifying other users.\n");
    auth_unlock();
    return false;
  }

  qihse_user_t *target = users[target_user_id];
  if (!target || !authz_states[target_user_id].active) {
    auth_unlock();
    return false;
  }

  // Enforce tenant boundary scoping: non-system operator can ONLY modify users
  // within its own tenant, never in another tenant or in QIHSE_TENANT_SYSTEM
  if (operator_authz.tenant_id != QIHSE_TENANT_SYSTEM &&
      (target->tenant_id != operator_authz.tenant_id ||
       target->tenant_id == QIHSE_TENANT_SYSTEM)) {
    auth_unlock();
    qihse_audit_log("USER_MODIFY_DENIED", operator_id, target_user_id, 0, 0);
    return false;
  }

  uint16_t classif_value =
      new_classification == -1
          ? authz_states[target_user_id].classification_level
          : (uint16_t)new_classification;
  uint16_t sci_value = new_sci == -1
                           ? authz_states[target_user_id].sci_compartments
                           : (uint16_t)new_sci;
  if (target->role == QIHSE_ROLE_OPERATOR) {
    classif_value = UINT16_MAX;
    sci_value = UINT16_MAX;
  }
  bool requires_token =
      new_requires_hw_token == -1
          ? authz_states[target_user_id].requires_hardware_token
          : new_requires_hw_token != 0;
  bool delegates_creation = new_can_create_users == -1
                                ? authz_states[target_user_id].can_create_users
                                : new_can_create_users != 0;
  uint32_t existing_name_id = new_username && new_username[0]
                                  ? auth_name_lookup_locked(new_username)
                                  : MAX_USERS;
  if (target->role < operator_authz.role ||
      classif_value > operator_authz.classification_level ||
      (sci_value & operator_authz.sci_compartments) != sci_value ||
      (delegates_creation && !operator_authz.can_create_users) ||
      (operator_authz.requires_hardware_token && !requires_token) ||
      (new_username && (new_username[0] == '\0' ||
                        strlen(new_username) >= sizeof(target->username) ||
                        (existing_name_id != MAX_USERS &&
                         existing_name_id != target_user_id)))) {
    auth_unlock();
    qihse_audit_log("USER_MODIFY_DENIED_PRIVILEGE", operator_id, target_user_id,
                    classif_value, sci_value);
    return false;
  }

  qihse_password_verifier_t new_verifier;
  memset(&new_verifier, 0, sizeof(new_verifier));
  if (new_password &&
      !compute_password_verifier(new_password, 0, &new_verifier)) {
    OPENSSL_cleanse(&new_verifier, sizeof(new_verifier));
    auth_unlock();
    return false;
  }

  qihse_user_t staged = auth_policy_snapshot_locked(target_user_id);
  if (new_username) { memset(staged.username, 0, sizeof(staged.username));
    memcpy(staged.username, new_username, strlen(new_username)); }
  if (new_password) { staged.verifier = new_verifier; staged.password_set = true; }
  staged.requires_hardware_token = requires_token;
  staged.can_create_users = delegates_creation;
  staged.classification_level = classif_value; staged.sci_compartments = sci_value;
  if (!auth_policy_commit_locked(target_user_id, &staged, true)) {
    OPENSSL_cleanse(&staged, sizeof(staged));
    OPENSSL_cleanse(&new_verifier, sizeof(new_verifier)); auth_unlock(); return false;
  }
  OPENSSL_cleanse(&staged, sizeof(staged));
  if (new_password != NULL)
    authz_states[target_user_id].verifier_configured = true;
  OPENSSL_cleanse(&new_verifier, sizeof(new_verifier));

  qihse_audit_log("USER_MODIFY", operator_id, target_user_id,
                  authz_states[target_user_id].classification_level,
                  authz_states[target_user_id].sci_compartments);
  auth_unlock();
  return true;
}

bool qihse_auth_set_hardware_token(qihse_user_t *user, bool present,
                                   const char *credential_id) {
  if (!user)
    return false;
  auth_write_lock();
  if (auth_direct_mutations_fenced || (qihse_auth_durable_active() && !qihse_auth_durable_ready())) {
    auth_unlock();
    return false;
  }
  uint32_t uid = 0xFFFFFFFF;
  if (!resolve_authoritative_user_locked(user, &uid, NULL)) {
    auth_unlock();
    return false;
  }
  qihse_user_t staged = auth_policy_snapshot_locked(uid);
  staged.hardware_token_present = present;
  if (credential_id) {
    if (strlen(credential_id) >= sizeof(staged.fido2_credential_id)) {
      OPENSSL_cleanse(&staged, sizeof(staged)); auth_unlock(); return false;
    }
    memset(staged.fido2_credential_id, 0, sizeof(staged.fido2_credential_id));
    memcpy(staged.fido2_credential_id, credential_id, strlen(credential_id));
    if (!auth_policy_commit_locked(uid, &staged, true)) {
      OPENSSL_cleanse(&staged, sizeof(staged)); auth_unlock(); return false;
    }
  } else {
    user->hardware_token_present = present;
    authz_states[uid].hardware_token_present = present;
  }
  OPENSSL_cleanse(&staged, sizeof(staged));
  auth_unlock();
  return true;
}

bool qihse_auth_can_access(const qihse_user_t *user, uint16_t data_classif,
                           uint16_t data_sci) {
  /* A failed startup has no audit writer. Preserve public, anonymous
   * reads, but deny every classified or principal-bearing request. */
  if (!__atomic_load_n(&auth_service_ready, __ATOMIC_ACQUIRE))
    return !qihse_auth_durable_active() && !user && data_classif == 0 && data_sci == 0;
  if (data_classif > 0) {
    uint32_t uid = 0xFFFFFFFF;
    if (user) {
      pthread_rwlock_rdlock(&auth_rwlock);
      resolve_authoritative_user_locked(user, &uid, NULL);
      auth_unlock();
    }
    qihse_audit_webhook_ping(uid, data_classif, data_sci);
  }

  // Invariant 1: No classified read primitive without an explicit user/security
  // context! NULL MUST NOT accidentally become an authorization bypass.
  if (!user) {
    if (data_classif > 0 || data_sci > 0) {
      qihse_audit_log("ACCESS_DENIED_NULL_USER_CLASSIFIED", 0xFFFFFFFF, 0,
                      data_classif, data_sci);
      return false;
    }
    return true; /* Unclassified data allowed when unauthenticated */
  }

  /* Fast path: unclassified data is accessible to any authenticated caller
   * that is not subject to hardware-token (MFA) enforcement. Consistent with
   * the NULL-user path above — unclassified data is already open to
   * unauthenticated callers, so any authenticated user trivially passes the
   * clearance (0 <= any level) and SCI (0 ⊆ any compartments) checks. The
   * global g_any_token_required flag is tamper-proof (kernel-owned state,
   * never cleared), so MFA-gated principals always fall through to the
   * authoritative check below. This avoids a per-row rwlock acquisition
   * during search over unclassified datasets when no MFA policy exists. */
  if (data_classif == 0 && data_sci == 0 &&
      !qihse_auth_durable_active() &&
      !__atomic_load_n(&g_any_token_required, __ATOMIC_ACQUIRE)) {
    return true;
  }

  pthread_rwlock_rdlock(&auth_rwlock);
  uint32_t uid = 0xFFFFFFFF;
  authz_state_t authz;
  if (!resolve_authoritative_user_locked(user, &uid, &authz)) {
    auth_unlock();
    qihse_audit_log("ACCESS_DENIED_UNREGISTERED_USER", 0xFFFFFFFF, 0,
                    data_classif, data_sci);
    return false;
  }

  // Hardware Token Enforcement — checked against authoritative state
  if (authz.requires_hardware_token && !authz.hardware_token_present) {
    auth_unlock();
    qihse_audit_log("ACCESS_DENIED_MISSING_TOKEN", uid, 0, data_classif,
                    data_sci);
    return false;
  }

  // Operator has God Mode
  if (authz.role == QIHSE_ROLE_OPERATOR) {
    auth_unlock();
    if (data_classif > 0) {
      /* Counted, not per-record: the signer emits one chained, signed
       * ACCESS_COUNT summary per (uid, label) window. */
      qihse_audit_access_granted(uid, data_classif, data_sci);
    }
    return true;
  }

  // Clearance Check
  if (authz.classification_level < data_classif) {
    auth_unlock();
    qihse_audit_log("ACCESS_DENIED_CLEARANCE", uid, 0, data_classif, data_sci);
    return false;
  }

  // SCI Check
  if ((data_sci & authz.sci_compartments) != data_sci) {
    auth_unlock();
    qihse_audit_log("ACCESS_DENIED_SCI", uid, 0, data_classif, data_sci);
    return false;
  }

  auth_unlock();
  /* Granted classified access is counted per (uid, classification, SCI)
   * window and summarized by the signer as one chained, signed
   * ACCESS_COUNT record per window — the old per-row record made every
   * classified KV access an ML-DSA-87 signature plus an fsync, turning
   * ordinary traffic into megabytes of audit I/O per minute. Denials
   * above keep per-record logging. */
  if (data_classif > 0 || data_sci != 0) {
    qihse_audit_access_granted(uid, data_classif, data_sci);
  }
  return true;
}

bool qihse_auth_can_access_object(const qihse_user_t *user,
                                  uint32_t namespace_id, uint64_t resource_id,
                                  uint8_t required_flags) {
  if (!user || required_flags == 0)
    return false;

  pthread_rwlock_rdlock(&auth_rwlock);
  uint32_t uid = 0xFFFFFFFF;
  authz_state_t authz;
  if (!resolve_authoritative_user_locked(user, &uid, &authz)) {
    auth_unlock();
    return false;
  }

  if (authz.requires_hardware_token && !authz.hardware_token_present) {
    auth_unlock(); return false;
  }
  if (authz.role == QIHSE_ROLE_OPERATOR) {
    auth_unlock();
    return true;
  }

  bool allowed = false;
  const qihse_user_t *author_user = users[uid];
  for (uint8_t i = 0; i < author_user->object_acl_count; i++) {
    const qihse_acl_entry_t *entry = &author_user->object_acl[i];
    if (entry->namespace_id == namespace_id &&
        entry->resource_id == resource_id) {
      if ((entry->access_flags & required_flags) == required_flags) {
        allowed = true;
      }
      break;
    }
  }
  auth_unlock();
  return allowed;
}

bool qihse_auth_grant_object(const qihse_user_t *operator_user,
                             qihse_user_t *target_user, uint32_t namespace_id,
                             uint64_t resource_id, uint8_t access_flags) {
  const uint8_t valid_flags =
      QIHSE_ACL_READ | QIHSE_ACL_WRITE | QIHSE_ACL_ADMIN;
  if (!operator_user || !target_user || access_flags == 0 ||
      (access_flags & (uint8_t)~valid_flags) != 0) {
    return false;
  }

  auth_write_lock();
  if (auth_direct_mutations_fenced || (qihse_auth_durable_active() && !qihse_auth_durable_ready())) {
    auth_unlock();
    return false;
  }
  uint32_t op_id = 0xFFFFFFFF;
  authz_state_t op_authz;
  if (!resolve_authoritative_user_locked(operator_user, &op_id, &op_authz) ||
      op_authz.role != QIHSE_ROLE_OPERATOR ||
      (op_authz.requires_hardware_token && !op_authz.hardware_token_present)) {
    auth_unlock();
    return false;
  }

  uint32_t target_id = 0xFFFFFFFF;
  if (!resolve_authoritative_user_locked(target_user, &target_id, NULL)) {
    auth_unlock();
    return false;
  }

  if ((target_id == 0u && op_id != 0u) ||
      (op_authz.tenant_id != QIHSE_TENANT_SYSTEM &&
       (authz_states[target_id].tenant_id != op_authz.tenant_id ||
        authz_states[target_id].tenant_id == QIHSE_TENANT_SYSTEM))) {
    auth_unlock();
    return false;
  }

  qihse_user_t staged = auth_policy_snapshot_locked(target_id);
  size_t slot = staged.object_acl_count;
  for (size_t i = 0; i < staged.object_acl_count; ++i)
    if (staged.object_acl[i].namespace_id == namespace_id &&
        staged.object_acl[i].resource_id == resource_id) { slot = i; break; }
  if (slot == QIHSE_OBJECT_ACL_MAX_ENTRIES) {
    OPENSSL_cleanse(&staged, sizeof(staged)); auth_unlock(); return false;
  }
  if (slot == staged.object_acl_count) staged.object_acl_count++;
  staged.object_acl[slot].namespace_id = namespace_id;
  staged.object_acl[slot].resource_id = resource_id;
  staged.object_acl[slot].access_flags = access_flags;
  if (!auth_policy_commit_locked(target_id, &staged, true)) {
    OPENSSL_cleanse(&staged, sizeof(staged)); auth_unlock(); return false;
  }
  OPENSSL_cleanse(&staged, sizeof(staged));
  auth_unlock();
  return true;
}

bool qihse_auth_revoke_object(const qihse_user_t *operator_user,
                              qihse_user_t *target_user, uint32_t namespace_id,
                              uint64_t resource_id) {
  if (!operator_user || !target_user)
    return false;

  auth_write_lock();
  if (auth_direct_mutations_fenced || (qihse_auth_durable_active() && !qihse_auth_durable_ready())) {
    auth_unlock();
    return false;
  }
  uint32_t op_id = 0xFFFFFFFF;
  authz_state_t op_authz;
  if (!resolve_authoritative_user_locked(operator_user, &op_id, &op_authz) ||
      op_authz.role != QIHSE_ROLE_OPERATOR ||
      (op_authz.requires_hardware_token && !op_authz.hardware_token_present)) {
    auth_unlock();
    return false;
  }

  uint32_t target_id = 0xFFFFFFFF;
  if (!resolve_authoritative_user_locked(target_user, &target_id, NULL)) {
    auth_unlock();
    return false;
  }

  if ((target_id == 0u && op_id != 0u) ||
      (op_authz.tenant_id != QIHSE_TENANT_SYSTEM &&
       (authz_states[target_id].tenant_id != op_authz.tenant_id ||
        authz_states[target_id].tenant_id == QIHSE_TENANT_SYSTEM))) {
    auth_unlock();
    return false;
  }

  qihse_user_t *target = users[target_id];
  for (uint8_t i = 0; i < target->object_acl_count; i++) {
    qihse_acl_entry_t *entry = &target->object_acl[i];
    if (entry->namespace_id == namespace_id &&
        entry->resource_id == resource_id) {
      qihse_user_t staged = auth_policy_snapshot_locked(target_id);
      uint8_t staged_last = --staged.object_acl_count;
      if (i != staged_last) staged.object_acl[i] = staged.object_acl[staged_last];
      memset(&staged.object_acl[staged_last], 0, sizeof(staged.object_acl[staged_last]));
      if (!auth_policy_commit_locked(target_id, &staged, true)) {
        OPENSSL_cleanse(&staged, sizeof(staged)); auth_unlock(); return false;
      }
      OPENSSL_cleanse(&staged, sizeof(staged));
      auth_unlock();
      return true;
    }
  }
  auth_unlock();
  return false;
}

static qihse_user_t *authenticate_user_internal(uint32_t source_ip,
                                                uint32_t user_id,
                                                const char *password, const char *expected_username) {
  if (user_id >= MAX_USERS || !password)
    return NULL;

  if (!qihse_auth_check_rate_limit(source_ip)) {
    fprintf(stderr,
            "[AUTH] Rate limit exceeded for source IP %u. Authentication "
            "rejected.\n",
            source_ip);
    return NULL;
  }

  if (!qihse_auth_check_volume_limit(source_ip)) {
    fprintf(stderr,
            "[AUTH] Volume limit exceeded for source IP %u. Authentication "
            "rejected.\n",
            source_ip);
    return NULL;
  }

  auth_write_lock();
  if (auth_registry_pre_serve || !__atomic_load_n(&auth_service_ready, __ATOMIC_ACQUIRE) ||
      (qihse_auth_durable_active() && !qihse_auth_durable_ready())) {
    auth_unlock();
    return NULL;
  }
  qihse_user_t *u = users[user_id];
  if (!u || !authz_states[user_id].active ||
      !authz_states[user_id].password_set ||
      (expected_username && strcmp(u->username,expected_username))) {
    auth_unlock();
    return NULL;
  }

  time_t now = time(NULL);
  if (rate_limits[user_id].lockout_until > now) {
    fprintf(
        stderr,
        "[AUTH] User '%s' (ID %u) is locked out. Try again in %ld seconds.\n",
        u->username, user_id, (long)(rate_limits[user_id].lockout_until - now));
    auth_unlock();
    return NULL;
  }

  /* Copy the verifier and run PBKDF2 without holding the lock.  The KDF
   * costs tens of milliseconds; running it under the write lock serialized
   * every concurrent login behind each attempt. */
  qihse_password_verifier_t verifier_copy = authz_states[user_id].verifier;
  uint64_t generation_copy=authz_states[user_id].principal_generation;
  auth_unlock();

  /* Verifier cache first: a repeat presentation of the same credentials
   * skips only the KDF. Everything below — account re-validation, lockout,
   * rate-limit reset — runs exactly as it did before this cache existed. */
  bool matched = auth_cache_probe(user_id, &verifier_copy, password);
  if (!matched) {
    matched = verify_password(password, &verifier_copy);
    if (matched)
      auth_cache_store(user_id, &verifier_copy, password);
  }

  auth_write_lock();
  now = time(NULL);
  /* Re-validate: the account may have been disabled/deleted, the password
   * rotated, or a parallel failure lockout applied while the KDF ran. */
  if ((qihse_auth_durable_active() && !qihse_auth_durable_ready()) ||
      users[user_id] != u || !authz_states[user_id].active ||
      authz_states[user_id].principal_generation!=generation_copy ||
      !authz_states[user_id].password_set ||
      memcmp(&authz_states[user_id].verifier, &verifier_copy,
             sizeof(verifier_copy)) != 0 ||
      rate_limits[user_id].lockout_until > now) {
    auth_unlock();
    return NULL;
  }
  uint32_t failures = matched ? 0 : rate_limits[user_id].failed_count + 1;
  time_t until = matched ? 0 : rate_limits[user_id].lockout_until;
  if (!matched && failures >= MAX_AUTH_ATTEMPTS) { failures = 0; until = now + AUTH_LOCKOUT_SECONDS; }
  if (!auth_durable_stage_locked(user_id, u, true, failures, until, false)) {
    auth_unlock(); return NULL;
  }
  if (matched) {
    rate_limits[user_id].failed_count = 0;
    rate_limits[user_id].lockout_until = 0;
    auth_unlock();
    qihse_auth_rate_limit_reset(source_ip);
    return u;
  } else {
    rate_limits[user_id].failed_count++;
    if (rate_limits[user_id].failed_count >= MAX_AUTH_ATTEMPTS) {
      rate_limits[user_id].lockout_until = now + AUTH_LOCKOUT_SECONDS;
      rate_limits[user_id].failed_count = 0;
      fprintf(stderr,
              "[AUTH] User '%s' (ID %u) locked out after %d failed attempts "
              "for %d seconds.\n",
              u->username, user_id, MAX_AUTH_ATTEMPTS, AUTH_LOCKOUT_SECONDS);
    }
    auth_unlock();
    return NULL;
  }
}

qihse_user_t *qihse_auth_authenticate_from(uint32_t source_ip,
                                           const char *username,
                                           const char *password) {
  if (!username || !password)
    return NULL;

  pthread_rwlock_rdlock(&auth_rwlock);
  uint32_t target_id = auth_name_lookup_locked(username);
  auth_unlock();

  if (target_id == MAX_USERS) {
    qihse_auth_check_rate_limit(source_ip);
    /* SEC-29: Constant-time dummy PBKDF2 hash on username lookup miss to defeat
     * timing enumeration. */
    static const uint8_t dummy_salt[QIHSE_PW_SALT_BYTES] = {
        0x24, 0x8a, 0x19, 0xf6, 0x93, 0xbb, 0x4e, 0x5a,
        0x01, 0xd8, 0x3c, 0x77, 0x42, 0xe9, 0x6b, 0x1f};
    uint32_t iters = get_password_iterations();
    if (iters < QIHSE_PW_MIN_ALLOWED_ITERATIONS)
      iters = QIHSE_PW_MIN_ITERATIONS;
    qihse_password_verifier_t dummy_verifier;
    memset(&dummy_verifier, 0, sizeof(dummy_verifier));
    dummy_verifier.version = QIHSE_PW_VERIFIER_VERSION_1;
    dummy_verifier.algorithm = QIHSE_PW_ALG_PBKDF2_HMAC_SHA384;
    dummy_verifier.iterations = iters;
    memcpy(dummy_verifier.salt, dummy_salt, QIHSE_PW_SALT_BYTES);
    verify_password(password, &dummy_verifier);
    return NULL;
  }

  return authenticate_user_internal(source_ip, target_id, password, username);
}

qihse_user_t *qihse_auth_authenticate(const char *username,
                                      const char *password) {
  return qihse_auth_authenticate_from(0, username, password);
}

qihse_user_t *qihse_auth_authenticate_id_from(uint32_t source_ip,
                                              uint32_t user_id,
                                              const char *password) {
  return authenticate_user_internal(source_ip, user_id, password, NULL);
}

qihse_user_t *qihse_auth_authenticate_id(uint32_t user_id,
                                         const char *password) {
  return authenticate_user_internal(0, user_id, password, NULL);
}

// ---------------------------------------------------------------------------
// Authoritative Getters for qihse_user_t
// ---------------------------------------------------------------------------

uint32_t qihse_user_get_id(const qihse_user_t *user) {
  if (!user)
    return UINT32_MAX;
  pthread_rwlock_rdlock(&auth_rwlock);
  uint32_t uid = UINT32_MAX;
  if (resolve_authoritative_user_locked(user, &uid, NULL)) {
    auth_unlock();
    return uid;
  }
  auth_unlock();
  return UINT32_MAX;
}

uint16_t qihse_user_get_role(const qihse_user_t *user) {
  if (!user)
    return QIHSE_ROLE_GUEST;
  pthread_rwlock_rdlock(&auth_rwlock);
  uint32_t uid;
  authz_state_t authz;
  if (resolve_authoritative_user_locked(user, &uid, &authz)) {
    auth_unlock();
    return authz.role;
  }
  auth_unlock();
  return QIHSE_ROLE_GUEST;
}

uint16_t qihse_user_get_classification(const qihse_user_t *user) {
  if (!user)
    return 0;
  pthread_rwlock_rdlock(&auth_rwlock);
  uint32_t uid;
  authz_state_t authz;
  if (resolve_authoritative_user_locked(user, &uid, &authz)) {
    auth_unlock();
    return authz.classification_level;
  }
  auth_unlock();
  return 0;
}

uint16_t qihse_user_get_sci(const qihse_user_t *user) {
  if (!user)
    return 0;
  pthread_rwlock_rdlock(&auth_rwlock);
  uint32_t uid;
  authz_state_t authz;
  if (resolve_authoritative_user_locked(user, &uid, &authz)) {
    auth_unlock();
    return authz.sci_compartments;
  }
  auth_unlock();
  return 0;
}

const char *qihse_user_get_username(const qihse_user_t *user) {
  if (!user)
    return NULL;
  pthread_rwlock_rdlock(&auth_rwlock);
  uint32_t uid;
  if (resolve_authoritative_user_locked(user, &uid, NULL)) {
    const char *name = users[uid]->username;
    auth_unlock();
    return name;
  }
  auth_unlock();
  return NULL;
}

bool qihse_user_copy_username(const qihse_user_t *user, char *dst,
                              size_t dst_capacity) {
  if (!user || !dst || dst_capacity == 0)
    return false;
  pthread_rwlock_rdlock(&auth_rwlock);
  uint32_t uid;
  if (resolve_authoritative_user_locked(user, &uid, NULL)) {
    strncpy(dst, users[uid]->username, dst_capacity - 1);
    dst[dst_capacity - 1] = '\0';
    auth_unlock();
    return true;
  }
  auth_unlock();
  return false;
}

const char *qihse_user_get_fido2_credential_id(const qihse_user_t *user) {
  if (!user)
    return NULL;
  pthread_rwlock_rdlock(&auth_rwlock);
  uint32_t uid;
  if (resolve_authoritative_user_locked(user, &uid, NULL)) {
    const char *credential = users[uid]->fido2_credential_id;
    auth_unlock();
    return credential;
  }
  auth_unlock();
  return NULL;
}

bool qihse_user_has_hardware_token(const qihse_user_t *user) {
  if (!user)
    return false;
  pthread_rwlock_rdlock(&auth_rwlock);
  uint32_t uid;
  authz_state_t authz;
  if (resolve_authoritative_user_locked(user, &uid, &authz)) {
    auth_unlock();
    return authz.hardware_token_present;
  }
  auth_unlock();
  return false;
}

bool qihse_user_requires_hardware_token(const qihse_user_t *user) {
  if (!user)
    return false;
  pthread_rwlock_rdlock(&auth_rwlock);
  uint32_t uid;
  authz_state_t authz;
  if (resolve_authoritative_user_locked(user, &uid, &authz)) {
    auth_unlock();
    return authz.requires_hardware_token;
  }
  auth_unlock();
  return false;
}

bool qihse_user_can_create_users(const qihse_user_t *user) {
  if (!user)
    return false;
  pthread_rwlock_rdlock(&auth_rwlock);
  uint32_t uid;
  authz_state_t authz;
  if (resolve_authoritative_user_locked(user, &uid, &authz)) {
    auth_unlock();
    return authz.can_create_users;
  }
  auth_unlock();
  return false;
}

uint32_t qihse_user_get_tenant_id(const qihse_user_t *user) {
  if (!user)
    return QIHSE_TENANT_INVALID;
  pthread_rwlock_rdlock(&auth_rwlock);
  uint32_t uid;
  authz_state_t authz;
  if (resolve_authoritative_user_locked(user, &uid, &authz)) {
    auth_unlock();
    return authz.tenant_id;
  }
  auth_unlock();
  return QIHSE_TENANT_INVALID;
}

bool qihse_auth_user_is_active(const qihse_user_t *user) {
  if (!user)
    return false;
  pthread_rwlock_rdlock(&auth_rwlock);
  uint32_t uid;
  bool active = resolve_authoritative_user_locked(user, &uid, NULL);
  auth_unlock();
  return active;
}

/* Combined liveness + tenant probe under a single rdlock round-trip — one
 * lock acquisition instead of two for callers that need both (the RESP
 * dispatch path).  Still a live lookup: no caching, revocation is honored
 * on the very next command. */
void qihse_auth_user_active_and_tenant(const qihse_user_t *user,
                                       bool *out_active, uint32_t *out_tenant) {
  bool active = false;
  uint32_t tenant = QIHSE_TENANT_INVALID;
  if (user) {
    pthread_rwlock_rdlock(&auth_rwlock);
    uint32_t uid;
    authz_state_t authz;
    active = resolve_authoritative_user_locked(user, &uid, &authz);
    if (active)
      tenant = authz.tenant_id;
    auth_unlock();
  }
  if (out_active)
    *out_active = active;
  if (out_tenant)
    *out_tenant = tenant;
}

// ── Principal Registry Hydration & Generation Verification (ROADMAP Item 8) ─

typedef struct {
  const uint8_t *ptr;
  size_t len;
} resp_slice_t;

static bool parse_canonical_u64_slice(const resp_slice_t *slice,
                                      uint64_t *out) {
  if (!slice || slice->len == 0 || slice->len > 20)
    return false;
  if (slice->len > 1 && slice->ptr[0] == '0')
    return false;
  uint64_t val = 0;
  for (size_t i = 0; i < slice->len; i++) {
    uint8_t c = slice->ptr[i];
    if (c < '0' || c > '9')
      return false;
    uint64_t digit=(uint64_t)(c-'0');
    if (val>(UINT64_MAX-digit)/10u) return false;
    val=val*10u+digit;
  }
  *out = val;
  return true;
}

bool qihse_auth_hydrate_from_attestation(
    const uint8_t *expected_history_id, uint64_t expected_writer_epoch,
    uint64_t expected_committed_index, const uint8_t *attestation_payload,
    size_t attestation_len, const uint8_t *peer_dsa_pub,
    size_t peer_dsa_pub_len, qihse_user_t **out_principal,
    uint64_t *out_generation) {
  if (out_principal) *out_principal=NULL;
  if (out_generation) *out_generation=0;
  if (!expected_history_id || !attestation_payload || attestation_len == 0 ||
      attestation_len>1024u+QIHSE_MLDSA_SIGNATURE_SIZE ||
      !peer_dsa_pub || !peer_dsa_pub_len || peer_dsa_pub_len>16384u ||
      qihse_auth_durable_active())
    return false;
  if (expected_writer_epoch == 0 || expected_committed_index == 0)
    return false;

  size_t payload_data_len = attestation_len;

  if (peer_dsa_pub != NULL && peer_dsa_pub_len > 0) {
    if (attestation_len < QIHSE_MLDSA_SIGNATURE_SIZE)
      return false;

    EVP_PKEY *pub_key = NULL;
    BIO *bio =
        BIO_new_mem_buf((const void *)peer_dsa_pub, (int)peer_dsa_pub_len);
    if (bio) {
      pub_key = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
      BIO_free(bio);
    }
    if (!pub_key) {
      const unsigned char *p = peer_dsa_pub;
      pub_key = d2i_PUBKEY(NULL, &p, (long)peer_dsa_pub_len);
    }
    if (!pub_key && peer_dsa_pub_len < 1024) {
      char path_buf[1024];
      size_t copy_len = peer_dsa_pub_len;
      if (copy_len >= sizeof(path_buf))
        copy_len = sizeof(path_buf) - 1;
      memcpy(path_buf, peer_dsa_pub, copy_len);
      path_buf[copy_len] = '\0';
      if (access(path_buf, R_OK) == 0) {
        FILE *f = fopen(path_buf, "r");
        if (f) {
          pub_key = PEM_read_PUBKEY(f, NULL, NULL, NULL);
          fclose(f);
        }
      }
    }
    if (!pub_key)
      return false;

    size_t signed_data_len = attestation_len - QIHSE_MLDSA_SIGNATURE_SIZE;
    const uint8_t *sig = attestation_payload + signed_data_len;
    bool sig_valid = qihse_pqc_verify_with_key(attestation_payload,
                                               signed_data_len, sig, pub_key);
    EVP_PKEY_free(pub_key);
    if (!sig_valid)
      return false;

    payload_data_len = signed_data_len;
  }

  if (payload_data_len < 5 || payload_data_len > 1024)
    return false;
  if (memcmp(attestation_payload, "*18\r\n", 5) != 0)
    return false;

  resp_slice_t fields[18];
  size_t at = 5;
  for (int i = 0; i < 18; i++) {
    if (at >= payload_data_len || attestation_payload[at] != '$')
      return false;
    at++;
    size_t start = at;
    while (at < payload_data_len && attestation_payload[at] >= '0' &&
           attestation_payload[at] <= '9') {
      at++;
      if (at - start > 2)
        return false;
    }
    resp_slice_t len_slice = {.ptr = attestation_payload + start,
                              .len = at - start};
    uint64_t item_len = 0;
    if (!parse_canonical_u64_slice(&len_slice, &item_len) || item_len > 64)
      return false;
    if (at + 2 > payload_data_len || attestation_payload[at] != '\r' ||
        attestation_payload[at + 1] != '\n')
      return false;
    at += 2;
    if (at + (size_t)item_len + 2 > payload_data_len)
      return false;
    fields[i].ptr = attestation_payload + at;
    fields[i].len = (size_t)item_len;
    at += (size_t)item_len;
    if (attestation_payload[at] != '\r' || attestation_payload[at + 1] != '\n')
      return false;
    at += 2;
  }
  if (at != payload_data_len)
    return false;

  // Field 0: protocol tag
  if (fields[0].len != 19 ||
      memcmp(fields[0].ptr, "QIHSE.ID1.ATTEST.V1", 19) != 0)
    return false;

  // Field 1: nonce (32 raw bytes)
  if (fields[1].len != 32)
    return false;

  // Field 2: group ID (1..63 ASCII, no nulls)
  if (fields[2].len == 0 || fields[2].len > 63)
    return false;
  for (size_t i = 0; i < fields[2].len; i++) {
    if ((fields[2].ptr[i] & 0x80) != 0 || fields[2].ptr[i] == 0)
      return false;
  }

  // Field 3: history ID (32 raw bytes)
  if (fields[3].len != 32 ||
      memcmp(fields[3].ptr, expected_history_id, 32) != 0)
    return false;

  // Field 4: writer epoch
  uint64_t writer_epoch = 0;
  if (!parse_canonical_u64_slice(&fields[4], &writer_epoch) ||
      writer_epoch == 0 || writer_epoch != expected_writer_epoch)
    return false;

  // Field 5: committed index
  uint64_t committed_index = 0;
  if (!parse_canonical_u64_slice(&fields[5], &committed_index) ||
      committed_index == 0 || committed_index != expected_committed_index)
    return false;

  // Field 6: registry applied index
  uint64_t registry_applied_index = 0;
  if (!parse_canonical_u64_slice(&fields[6], &registry_applied_index) ||
      registry_applied_index != committed_index)
    return false;

  // Field 7: registry generation
  uint64_t registry_generation = 0;
  if (!parse_canonical_u64_slice(&fields[7], &registry_generation) ||
      registry_generation == 0)
    return false;

  // Field 8: principal generation
  uint64_t principal_generation = 0;
  if (!parse_canonical_u64_slice(&fields[8], &principal_generation) ||
      principal_generation == 0)
    return false;

  // Field 9: user ID: must be 1
  uint64_t user_id = 0;
  if (!parse_canonical_u64_slice(&fields[9], &user_id) || user_id != 1)
    return false;

  // Field 10: username: must be "Hypercube"
  if (fields[10].len != 9 || memcmp(fields[10].ptr, "Hypercube", 9) != 0)
    return false;

  // Field 11: role: must be 0 (QIHSE_ROLE_OPERATOR)
  uint64_t role = 0;
  if (!parse_canonical_u64_slice(&fields[11], &role) || role != 0)
    return false;

  // Field 12: classification: must be 0xFFFF (65535)
  uint64_t classification = 0;
  if (!parse_canonical_u64_slice(&fields[12], &classification) ||
      classification != 0xFFFF)
    return false;

  // Field 13: SCI: must be 0xFFFF (65535)
  uint64_t sci = 0;
  if (!parse_canonical_u64_slice(&fields[13], &sci) || sci != 0xFFFF)
    return false;

  // Field 14: tenant ID: must be 0
  uint64_t tenant_id = 0;
  if (!parse_canonical_u64_slice(&fields[14], &tenant_id) || tenant_id != 0)
    return false;

  // Field 15: can_create_users: must be '1'
  if (fields[15].len != 1 || fields[15].ptr[0] != '1')
    return false;

  // Field 16: requires_hardware_token: '0' or '1'
  if (fields[16].len != 1 ||
      (fields[16].ptr[0] != '0' && fields[16].ptr[0] != '1'))
    return false;
  bool requires_hw_token = (fields[16].ptr[0] == '1');

  // Field 17: hardware_token_present: '0' or '1'
  if (fields[17].len != 1 ||
      (fields[17].ptr[0] != '0' && fields[17].ptr[0] != '1'))
    return false;
  /* Remote presence is not evidence of a locally verified hardware token. */
  bool hw_token_present = false;

  auth_write_lock();
  if (qihse_auth_durable_active() || !peer_dsa_pub || !peer_dsa_pub_len ||
      !auth_registry_pre_serve || !auth_direct_mutations_fenced ||
      !__atomic_load_n(&auth_service_ready, __ATOMIC_ACQUIRE) ||
      (authz_states[1].principal_generation &&
       principal_generation <= authz_states[1].principal_generation)) {
    auth_unlock(); return false;
  }
  qihse_user_t *u = users[1];
  if (!u) {
    u = (qihse_user_t *)calloc(1, sizeof(qihse_user_t));
    if (!u) {
      auth_unlock();
      return false;
    }
    users[1] = u;
#ifndef _WIN32
    mlock(u, sizeof(qihse_user_t));
#endif
  } else {
    OPENSSL_cleanse(u, sizeof(qihse_user_t));
  }

  u->user_id = 1;
  u->role = QIHSE_ROLE_OPERATOR;
  u->classification_level = 0xFFFF;
  u->sci_compartments = 0xFFFF;
  u->tenant_id = 0;
  strncpy(u->username, "Hypercube", sizeof(u->username) - 1);
  u->can_create_users = true;
  u->requires_hardware_token = requires_hw_token;
  u->hardware_token_present = hw_token_present;
  u->password_set = false;

  auth_name_insert_locked("Hypercube", 1);

  bool was_active = authz_states[1].active;
  authz_states[1].active = true;
  authz_states[1].role = QIHSE_ROLE_OPERATOR;
  authz_states[1].classification_level = 0xFFFF;
  authz_states[1].sci_compartments = 0xFFFF;
  authz_states[1].tenant_id = 0;
  authz_states[1].can_create_users = true;
  authz_states[1].requires_hardware_token = requires_hw_token;
  authz_states[1].hardware_token_present = hw_token_present;
  authz_states[1].principal_generation = principal_generation;
  authz_states[1].verifier_configured = true;

  if (!was_active) {
    active_user_count++;
  }

  /* Attestation refresh cannot manufacture startup readiness. */
  auth_direct_mutations_fenced = true;

  if (out_principal) {
    *out_principal = u;
  }
  if (out_generation) {
    *out_generation = principal_generation;
  }

  qihse_audit_log("PRINCIPAL_HYDRATED_FROM_ATTESTATION", 1, 1, 0xFFFF, 0xFFFF);
  auth_unlock();
  return true;
}

bool qihse_auth_validate_handle_generation(const qihse_user_t *user,
                                           uint64_t expected_generation) {
  if (!user || expected_generation == 0)
    return false;
  pthread_rwlock_rdlock(&auth_rwlock);
  uint32_t uid;
  authz_state_t authz;
  if (!resolve_authoritative_user_locked(user, &uid, &authz)) {
    auth_unlock();
    return false;
  }
  bool ok = (authz.principal_generation == expected_generation);
  auth_unlock();
  return ok;
}

qihse_user_t *qihse_auth_borrow_principal_scoped(uint32_t user_id,
                                                 uint64_t *out_generation) {
  if (user_id >= MAX_USERS)
    return NULL;
  auth_write_lock();
  if (!users[user_id] || !authz_states[user_id].active ||
      (qihse_auth_durable_active() && !qihse_auth_durable_ready())) {
    auth_unlock();
    return NULL;
  }
  if (authz_states[user_id].ref_count==UINT64_MAX) { auth_unlock(); return NULL; }
  authz_states[user_id].ref_count++;
  if (out_generation) {
    *out_generation = authz_states[user_id].principal_generation;
  }
  qihse_user_t *u = users[user_id];
  auth_unlock();
  return u;
}

void qihse_auth_release_principal_scoped(qihse_user_t *user) {
  if (!user)
    return;
  auth_write_lock();
  bool found=false;
  for (uint32_t uid=0;uid<MAX_USERS;++uid) {
    if (users[uid]==user) {
      if (authz_states[uid].ref_count) authz_states[uid].ref_count--;
      found=true; break;
    }
  }
  if (!found) for (size_t i=0;i<retired_count;++i) if (retired_principals[i]==user) {
    if (retired_refs[i]) retired_refs[i]--;
    break;
  }
  /* Retired allocations remain immutable, bounded and never reused. A zero
   * scoped count cannot exclude unscoped readers, so it permits neither
   * cleansing nor freeing. Release never restores authority to an old handle. */
  auth_unlock();
}

/* Maintenance reads use the same authoritative table, never a replay catalog. */
bool qihse_auth_actor_identity(const qihse_user_t *actor, uint32_t *uid,
 uint64_t *generation) {
 pthread_rwlock_rdlock(&auth_rwlock);
 authz_state_t state;
 bool valid = resolve_authoritative_user_locked(actor, uid, &state);
 if (valid && generation) *generation = state.principal_generation;
 auth_unlock(); return valid;
}
bool qihse_auth_maintenance_actor_valid(const qihse_user_t *actor) {
 pthread_rwlock_rdlock(&auth_rwlock);
 authz_state_t state;
 bool valid = resolve_authoritative_user_locked(actor, NULL, &state) &&
  state.role == QIHSE_ROLE_OPERATOR && state.tenant_id == QIHSE_TENANT_SYSTEM &&
  state.classification_level == UINT16_MAX && state.sci_compartments == UINT16_MAX &&
  state.verifier_configured && (!state.requires_hardware_token || state.hardware_token_present);
 auth_unlock(); return valid;
}
void qihse_auth_durable_set_ready(bool ready) {
 __atomic_store_n(&auth_service_ready, ready, __ATOMIC_RELEASE);
}
bool qihse_auth_durable_prepare(const qihse_user_t *root) {
 if (!root || root->user_id != 0) return false;
 qihse_audit_init();
 if (!check_fips_compliance()) return false;
 auth_write_lock();
 if (auth_initialized_once || active_user_count || auth_init_pending) {
  auth_unlock(); return false;
 }
 auth_initialized_once = true; auth_init_pending = true;
 auth_registry_pre_serve = true;
 qihse_user_t *u = calloc(1, sizeof(*u));
 if (!u) { auth_unlock(); return false; }
 *u = *root; u->hardware_token_present = false;
 users[0] = u; set_authz_state_locked(0, u);
 authz_states[0].verifier_configured = true;
 active_user_count = 1;
 auth_name_insert_locked(u->username, 0);
 if (u->requires_hardware_token) __atomic_store_n(&g_any_token_required, 1, __ATOMIC_RELEASE);
#ifndef _WIN32
 mlock(u, sizeof(*u));
#endif
 auth_unlock(); return true;
}
static qihse_auth_image_t *auth_image_capture_locked(
 const qihse_auth_image_context_t *context) {
 /* A recovery capability is required under the write lock, so validation
  * never recursively acquires auth_rwlock. Live callers validate before it. */
 if (!context || !context->recovery || !qihse_auth_recovery_valid(context->recovery)) return NULL;
 qihse_auth_image_t *image = calloc(1, sizeof(*image));
 if (!image) return NULL;
 if (!qihse_auth_durable_image_metadata(context,image)) { free(image); return NULL; }
 image->root_generation = authz_states[0].principal_generation;
 image->root_failed_count = rate_limits[0].failed_count;
 image->root_lockout_until = (uint64_t)rate_limits[0].lockout_until;
 for (uint32_t i=1; i<MAX_USERS; ++i) if (users[i]) image->count++;
 if (image->count) {
  image->rows = calloc(image->count, sizeof(*image->rows));
  if (!image->rows) { qihse_auth_image_free(image); return NULL; }
 }
 size_t n=0;
 for (uint32_t i=1; i<MAX_USERS; ++i) if (users[i]) {
  qihse_auth_image_row_t *row = &image->rows[n++];
  row->user_id=i; row->active=authz_states[i].active;
  row->generation=authz_states[i].principal_generation;
  if (!row->generation) row->generation=1;
  row->failed_count=rate_limits[i].failed_count;
  row->lockout_until=(uint64_t)rate_limits[i].lockout_until;
  if (row->active) {
   row->principal=*users[i];
   row->principal.user_id=i;
   row->principal.role=authz_states[i].role;
   row->principal.classification_level=authz_states[i].classification_level;
   row->principal.sci_compartments=authz_states[i].sci_compartments;
   row->principal.tenant_id=authz_states[i].tenant_id;
   row->principal.requires_hardware_token=authz_states[i].requires_hardware_token;
   row->principal.can_create_users=authz_states[i].can_create_users;
   row->principal.password_set=authz_states[i].verifier_configured;
   row->principal.verifier=authz_states[i].verifier;
   row->principal.hardware_token_present=false;
  }
 }
 return image;
}
qihse_auth_maintenance_status_t qihse_auth_image_capture(
 const qihse_auth_image_context_t *context, qihse_auth_image_t **out) {
 if (!out) return QIHSE_AUTH_MAINT_INVALID;
 *out=NULL;
 if (!qihse_auth_image_context_valid(context)) return QIHSE_AUTH_MAINT_DENIED;
 qihse_auth_image_context_t recovery = {NULL, qihse_auth_durable_recovery_context()};
 auth_write_lock();
 *out=auth_image_capture_locked(&recovery);
 auth_unlock();
 return *out ? QIHSE_AUTH_MAINT_OK : QIHSE_AUTH_MAINT_LIMIT;
}
static bool auth_durable_stage_locked(uint32_t uid, const qihse_user_t *candidate,
 bool active, uint32_t failures, time_t until, bool bump_generation) {
 if (!candidate || uid>=MAX_USERS ||
     (bump_generation && authz_states[uid].principal_generation==UINT64_MAX)) return false;
 if (!qihse_auth_durable_active()) return true;
 if (!qihse_auth_durable_ready() || !users[0]) return false;
 if (!bump_generation && rate_limits[uid].failed_count==failures &&
     rate_limits[uid].lockout_until==until) return true;
 qihse_auth_image_context_t context = {NULL, qihse_auth_durable_recovery_context()};
 qihse_auth_image_t *image=auth_image_capture_locked(&context);
 if (!image) return false;
 qihse_user_t root=*users[0]; root.hardware_token_present=false;
 if (!uid) {
  if (!active) { qihse_auth_image_free(image); return false; }
  root=*candidate; root.hardware_token_present=false;
  if (bump_generation) image->root_generation++;
  image->root_failed_count=failures; image->root_lockout_until=(uint64_t)until;
 } else {
  size_t slot=0;
  while (slot<image->count && image->rows[slot].user_id!=uid) slot++;
  if (slot==image->count) {
   qihse_auth_image_row_t *rows=realloc(image->rows, (image->count+1)*sizeof(*rows));
   if (!rows) { qihse_auth_image_free(image); return false; }
   image->rows=rows; image->count++;
  }
  qihse_auth_image_row_t *row=&image->rows[slot];
  memset(row, 0, sizeof(*row)); row->user_id=uid; row->active=active;
  row->generation=authz_states[uid].principal_generation;
  if (bump_generation) row->generation++;
  if (!row->generation) row->generation=1;
  row->failed_count=failures; row->lockout_until=(uint64_t)until;
  if (active) { row->principal=*candidate; row->principal.hardware_token_present=false; }
  /* Canonical images are strictly ordered by UID. */
  for (size_t i=slot; i>0 && image->rows[i].user_id<image->rows[i-1].user_id; --i) {
   qihse_auth_image_row_t swap=image->rows[i]; image->rows[i]=image->rows[i-1]; image->rows[i-1]=swap;
  }
 }
 qihse_auth_maintenance_status_t status=qihse_auth_durable_commit(&context, image, &root);
 OPENSSL_cleanse(&root, sizeof(root)); qihse_auth_image_free(image);
 if (status==QIHSE_AUTH_MAINT_OK) qihse_auth_cache_clear();
 return status==QIHSE_AUTH_MAINT_OK;
}
qihse_auth_maintenance_status_t qihse_auth_image_publish(
 const qihse_auth_image_context_t *context, qihse_auth_image_t *image) {
 if (!image || !qihse_auth_image_context_valid(context)) return QIHSE_AUTH_MAINT_DENIED;
 if (image->count>QIHSE_AUTH_IMAGE_MAX_PRINCIPALS || (image->count && !image->rows) ||
     !image->root_generation || image->root_lockout_until>(uint64_t)INT64_MAX ||
     image->retry_count>QIHSE_AUTH_RETRY_MAX) return QIHSE_AUTH_MAINT_CORRUPT;
 qihse_user_t **replacement=calloc(MAX_USERS, sizeof(*replacement));
 if (!replacement) return QIHSE_AUTH_MAINT_LIMIT;
 qihse_auth_maintenance_status_t status=QIHSE_AUTH_MAINT_OK;
 uint32_t previous=0;
 for (size_t i=0; i<image->count; ++i) {
  const qihse_auth_image_row_t *row=&image->rows[i];
  if (!row->user_id || row->user_id>=MAX_USERS || row->user_id<=previous || !row->generation ||
      row->lockout_until>(uint64_t)INT64_MAX ||
      (row->active && (row->principal.user_id!=row->user_id ||
       !qihse_principal_fields_valid(&row->principal,false)))) {
   status=QIHSE_AUTH_MAINT_CORRUPT; goto done;
  }
  previous=row->user_id;
  replacement[row->user_id]=calloc(1,sizeof(qihse_user_t));
  if (!replacement[row->user_id]) { status=QIHSE_AUTH_MAINT_LIMIT; goto done; }
  if (row->active) { *replacement[row->user_id]=row->principal;
   replacement[row->user_id]->hardware_token_present=false; }
 }
 auth_write_lock();
 size_t retiring=0;
 for (size_t i=1;i<MAX_USERS;++i) if (users[i]) retiring++;
 if (retired_count+retiring>MAX_USERS) { auth_unlock(); status=QIHSE_AUTH_MAINT_LIMIT; goto done; }
 qihse_auth_image_context_t recovery={NULL,qihse_auth_durable_recovery_context()};
 /* On startup durable bytes were already verified; live imports are committed
  * before any auth-table change, with every allocation already complete. */
 if (!auth_init_pending) {
  status=qihse_auth_durable_commit(&recovery,image,users[0]);
  if (status!=QIHSE_AUTH_MAINT_OK) { auth_unlock(); goto done; }
 }
 for (size_t i=1;i<MAX_USERS;++i) {
  if (users[i]) auth_retire_principal_locked((uint32_t)i);
  users[i]=replacement[i]; replacement[i]=NULL;
  memset(&authz_states[i],0,sizeof(authz_states[i]));
  memset(&rate_limits[i],0,sizeof(rate_limits[i]));
 }
 auth_name_map_clear_locked(); auth_name_insert_locked(users[0]->username,0);
 active_user_count=1;
 for (size_t i=0;i<image->count;++i) {
  const qihse_auth_image_row_t *row=&image->rows[i]; uint32_t uid=row->user_id;
  authz_states[uid].principal_generation=row->generation;
  if (row->active) {
   set_authz_state_locked(uid,users[uid]); authz_states[uid].verifier_configured=true;
   auth_name_insert_locked(users[uid]->username,uid); active_user_count++;
   if (users[uid]->requires_hardware_token) __atomic_store_n(&g_any_token_required,1,__ATOMIC_RELEASE);
  }
  rate_limits[uid].failed_count=row->failed_count;
  rate_limits[uid].lockout_until=(time_t)row->lockout_until;
 }
 authz_states[0].principal_generation=image->root_generation;
 rate_limits[0].failed_count=image->root_failed_count;
 rate_limits[0].lockout_until=(time_t)image->root_lockout_until;
 auth_init_pending=false; auth_registry_pre_serve=false; auth_direct_mutations_fenced=false;
 auth_unlock(); qihse_auth_cache_clear();
 qihse_auth_durable_verified();
 done:
 for (size_t i=1;i<MAX_USERS;++i) if (replacement[i]) {
  OPENSSL_cleanse(replacement[i],sizeof(*replacement[i])); free(replacement[i]);
 }
 free(replacement); return status;
}

void qihse_auth_set_direct_mutations_fenced(bool fenced) {
  auth_write_lock();
  if (qihse_auth_durable_active()) {
    /* This legacy switch must never reopen or rewrite durable authority. */
    if (fenced) qihse_auth_durable_fence();
    auth_unlock();
    return;
  }
  auth_direct_mutations_fenced = fenced;
  if (!fenced) {
    if (users[1]) {
      auth_name_remove_locked(users[1]->username);
      OPENSSL_cleanse(users[1], sizeof(qihse_user_t));
#ifndef _WIN32
      munlock(users[1], sizeof(qihse_user_t));
#endif
      /* Retain the tombstone: ID1 handles may still be borrowed. */
      if (authz_states[1].active) {
        active_user_count--;
      }
      uint64_t generation = authz_states[1].principal_generation;
      uint64_t refs = authz_states[1].ref_count;
      memset(&authz_states[1], 0, sizeof(authz_states[1]));
      authz_states[1].principal_generation = generation;
      authz_states[1].ref_count = refs;
      memset(&rate_limits[1], 0, sizeof(rate_limits[1]));
    }
  }
  auth_unlock();
}
