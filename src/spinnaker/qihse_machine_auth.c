#include "qihse_machine_auth.h"

#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <time.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

/* Machine-token verification over a plain RESP connection.
 *
 * Trust anchors are the file-configured ML-DSA public keys the node already
 * loads for the cluster bus (--pqc-trusted-pub). An anchor is loaded once at
 * configure time and kept as an EVP_PKEY; re-reading PEMs per authentication
 * would turn the disk into a per-AUTH cost and a TOCTOU surface.
 *
 * The nonce ledger is bounded and never evicts a live entry (fail closed on
 * full) — the same rule as the fabric dispatch replay ledger. Entries expire
 * with their token, so the bound is a ceiling on live tokens, not a leak. */

#define QIHSE_MACHINE_MAX_ANCHORS 16u
#define QIHSE_MACHINE_LEDGER_CAP 256u
#define QIHSE_MACHINE_CLOCK_SKEW_MS QIHSE_FABRIC_TOKEN_CLOCK_SKEW_MS

typedef struct {
    qihse_uuid_t nonce;
    uint64_t expires_ms;
    bool used;
} machine_ledger_entry_t;

static struct {
    char* paths[QIHSE_MACHINE_MAX_ANCHORS];
    EVP_PKEY* keys[QIHSE_MACHINE_MAX_ANCHORS];
    size_t count;
    machine_ledger_entry_t ledger[QIHSE_MACHINE_LEDGER_CAP];
    pthread_mutex_t mutex;
} g_machine = {
    .mutex = PTHREAD_MUTEX_INITIALIZER,
};

const char* qihse_machine_auth_verdict_name(qihse_machine_auth_verdict_t v) {
    switch (v) {
        case QIHSE_MACHINE_AUTH_OK:              return "ok";
        case QIHSE_MACHINE_AUTH_DISABLED:        return "disabled";
        case QIHSE_MACHINE_AUTH_MALFORMED:       return "malformed-token";
        case QIHSE_MACHINE_AUTH_BAD_SIGNATURE:   return "bad-signature";
        case QIHSE_MACHINE_AUTH_WRONG_PURPOSE:   return "wrong-purpose";
        case QIHSE_MACHINE_AUTH_SCOPE_REFUSED:   return "scope-refused";
        case QIHSE_MACHINE_AUTH_ISSUED_IN_FUTURE: return "issued-in-future";
        case QIHSE_MACHINE_AUTH_EXPIRED:         return "expired-token";
        case QIHSE_MACHINE_AUTH_TTL_TOO_LONG:    return "ttl-too-long";
        case QIHSE_MACHINE_AUTH_REPLAY:          return "replayed-nonce";
        case QIHSE_MACHINE_AUTH_LEDGER_FULL:     return "ledger-full";
        case QIHSE_MACHINE_AUTH_NO_TRUST:        return "untrusted-signer";
    }
    return "unknown";
}

static uint64_t machine_now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000ull + (uint64_t)(ts.tv_nsec / 1000000u);
}

/* SHA-384 of the empty payload — the only digest a MACHINE token may bind.
 * Computed once (a hardcoded constant here would be an unverified trust
 * anchor in its own right). */
static const uint8_t* machine_empty_payload_digest(void) {
    static uint8_t digest[48];
    static int computed = 0;
    if (!computed) {
        SHA384((const unsigned char*)"", 0u, digest);
        computed = 1;
    }
    return digest;
}

static void machine_anchor_free_locked(void) {
    for (size_t i = 0; i < g_machine.count; i++) {
        free(g_machine.paths[i]);
        g_machine.paths[i] = NULL;
        if (g_machine.keys[i]) EVP_PKEY_free(g_machine.keys[i]);
        g_machine.keys[i] = NULL;
    }
    g_machine.count = 0;
}

bool qihse_machine_auth_configure(const char* const* trusted_pub_paths, size_t count) {
    if (trusted_pub_paths && count > QIHSE_MACHINE_MAX_ANCHORS) count = QIHSE_MACHINE_MAX_ANCHORS;

    pthread_mutex_lock(&g_machine.mutex);
    machine_anchor_free_locked();
    memset(g_machine.ledger, 0, sizeof(g_machine.ledger));
    if (!trusted_pub_paths || count == 0) {
        pthread_mutex_unlock(&g_machine.mutex);
        return false; /* disabled, not an error: callers may run without anchors */
    }
    size_t loaded = 0;
    for (size_t i = 0; i < count; i++) {
        const char* path = trusted_pub_paths[i];
        if (!path || !*path) continue;
        FILE* f = fopen(path, "rb");
        if (!f) continue;
        EVP_PKEY* key = PEM_read_PUBKEY(f, NULL, NULL, NULL);
        fclose(f);
        if (!key) continue;
        g_machine.paths[loaded] = strdup(path);
        g_machine.keys[loaded] = key;
        if (!g_machine.paths[loaded]) {
            EVP_PKEY_free(key);
            continue;
        }
        loaded++;
    }
    g_machine.count = loaded;
    bool ok = loaded > 0;
    pthread_mutex_unlock(&g_machine.mutex);
    return ok;
}

size_t qihse_machine_auth_trusted_count(void) {
    pthread_mutex_lock(&g_machine.mutex);
    size_t n = g_machine.count;
    pthread_mutex_unlock(&g_machine.mutex);
    return n;
}

void qihse_machine_auth_reset(void) {
    pthread_mutex_lock(&g_machine.mutex);
    machine_anchor_free_locked();
    memset(g_machine.ledger, 0, sizeof(g_machine.ledger));
    pthread_mutex_unlock(&g_machine.mutex);
}

size_t qihse_machine_auth_ledger_live(void) {
    uint64_t now = machine_now_ms();
    size_t live = 0;
    pthread_mutex_lock(&g_machine.mutex);
    for (size_t i = 0; i < QIHSE_MACHINE_LEDGER_CAP; i++) {
        if (g_machine.ledger[i].used && g_machine.ledger[i].expires_ms > now) live++;
    }
    pthread_mutex_unlock(&g_machine.mutex);
    return live;
}

/* Caller holds g_machine.mutex. Purges expired entries, then records the
 * nonce. DISTINCT outcomes: replay (live nonce reuse) and full (no slot —
 * fail closed, never evict a live entry). */
typedef enum {
    MACHINE_LEDGER_OK = 0,
    MACHINE_LEDGER_REPLAY,
    MACHINE_LEDGER_FULL
} machine_ledger_outcome_t;

static machine_ledger_outcome_t machine_ledger_consume_locked(
        const qihse_uuid_t* nonce, uint64_t expires_ms, uint64_t now) {
    ssize_t free_slot = -1;
    for (size_t i = 0; i < QIHSE_MACHINE_LEDGER_CAP; i++) {
        machine_ledger_entry_t* e = &g_machine.ledger[i];
        if (e->used && e->expires_ms <= now) {
            memset(e, 0, sizeof(*e)); /* expired: purge */
        }
        if (e->used && memcmp(e->nonce.bytes, nonce->bytes, QIHSE_UUID_BYTES) == 0) {
            return MACHINE_LEDGER_REPLAY;
        }
        if (!e->used && free_slot < 0) free_slot = (ssize_t)i;
    }
    if (free_slot < 0) return MACHINE_LEDGER_FULL;
    machine_ledger_entry_t* e = &g_machine.ledger[free_slot];
    e->nonce = *nonce;
    e->expires_ms = expires_ms;
    e->used = true;
    return MACHINE_LEDGER_OK;
}

static bool machine_signature_verifies_locked(const uint8_t* region, size_t region_len,
                                              const uint8_t* sig, size_t sig_len) {
    for (size_t i = 0; i < g_machine.count; i++) {
        EVP_MD_CTX* ctx = EVP_MD_CTX_new();
        if (!ctx) continue;
        bool ok = EVP_DigestVerifyInit(ctx, NULL, NULL, NULL, g_machine.keys[i]) == 1 &&
                  EVP_DigestVerify(ctx, sig, sig_len, region, region_len) == 1;
        EVP_MD_CTX_free(ctx);
        if (ok) return true;
        ERR_clear_error(); /* one anchor failing is expected; keep the error queue clean */
    }
    return false;
}

qihse_machine_auth_verdict_t qihse_machine_auth_check(
        const uint8_t* blob, size_t blob_len, uint64_t now_ms,
        qihse_fabric_token_t* out_claims) {
    pthread_mutex_lock(&g_machine.mutex);
    bool enabled = g_machine.count > 0;
    pthread_mutex_unlock(&g_machine.mutex);
    if (!enabled) return QIHSE_MACHINE_AUTH_DISABLED;
    if (!blob || blob_len == 0 || !out_claims) return QIHSE_MACHINE_AUTH_MALFORMED;

    qihse_fabric_token_t parsed;
    size_t region_len = 0, total_len = 0;
    if (!qihse_fabric_token_parse(blob, blob_len, &parsed, &region_len, &total_len)) {
        return QIHSE_MACHINE_AUTH_MALFORMED;
    }

    if (parsed.purpose != QIHSE_FABRIC_TOKEN_PURPOSE_MACHINE ||
        parsed.job_type != QIHSE_FABRIC_JOB_NONE) {
        return QIHSE_MACHINE_AUTH_WRONG_PURPOSE;
    }
    if (parsed.scope != 0u) {
        return QIHSE_MACHINE_AUTH_SCOPE_REFUSED;
    }
    if (parsed.payload_len != 0u ||
        memcmp(parsed.payload_digest, machine_empty_payload_digest(),
               sizeof(parsed.payload_digest)) != 0) {
        return QIHSE_MACHINE_AUTH_MALFORMED;
    }

    uint64_t now = now_ms ? now_ms : machine_now_ms();
    if (parsed.issued_ms > now + QIHSE_MACHINE_CLOCK_SKEW_MS) {
        return QIHSE_MACHINE_AUTH_ISSUED_IN_FUTURE;
    }
    if (parsed.expires_ms < parsed.issued_ms) {
        return QIHSE_MACHINE_AUTH_MALFORMED;
    }
    if (parsed.expires_ms - parsed.issued_ms > QIHSE_MACHINE_TOKEN_MAX_TTL_MS) {
        return QIHSE_MACHINE_AUTH_TTL_TOO_LONG;
    }
    if (parsed.expires_ms + QIHSE_MACHINE_CLOCK_SKEW_MS < now) {
        return QIHSE_MACHINE_AUTH_EXPIRED;
    }

    /* The signature covers the serialized region only; it follows it in the
     * blob at the length parse() validated. */
    if (total_len < region_len || region_len == 0) return QIHSE_MACHINE_AUTH_MALFORMED;
    const uint8_t* region = blob;
    const uint8_t* sig = blob + region_len;
    size_t sig_len = total_len - region_len;

    pthread_mutex_lock(&g_machine.mutex);
    bool trusted = machine_signature_verifies_locked(region, region_len, sig, sig_len);
    pthread_mutex_unlock(&g_machine.mutex);
    if (!trusted) return QIHSE_MACHINE_AUTH_NO_TRUST;

    pthread_mutex_lock(&g_machine.mutex);
    machine_ledger_outcome_t ledger = machine_ledger_consume_locked(&parsed.nonce, parsed.expires_ms, now);
    pthread_mutex_unlock(&g_machine.mutex);
    if (ledger == MACHINE_LEDGER_REPLAY) return QIHSE_MACHINE_AUTH_REPLAY;
    if (ledger == MACHINE_LEDGER_FULL) return QIHSE_MACHINE_AUTH_LEDGER_FULL;

    *out_claims = parsed;
    return QIHSE_MACHINE_AUTH_OK;
}
