#include "qihse_ct1_authority_service.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

bool qihse_ct1_authority_service_evaluate_pair(
    const qihse_ct1_authority_pair_evidence_t *e)
{
    unsigned char canonical[QIHSE_CT1_RECOVERY_WIRE_SIZE];
    qihse_ct1_recovery_manifest_t decoded;
    struct timespec now;
    uint64_t now_ms;
    const qihse_ct1_authority_challenge_t *challenge;

    if (!e || !e->manifest_wire ||
        e->manifest_len != sizeof(canonical) || !e->expected_manifest ||
        !e->replication_principal ||
        qihse_user_get_role(e->replication_principal) == QIHSE_ROLE_OPERATOR ||
        !e->challenge || !e->source_quote || !e->target_quote ||
        e->source_quote_len != QIHSE_CT1_NODE_QUOTE_SIZE ||
        e->target_quote_len != QIHSE_CT1_NODE_QUOTE_SIZE ||
        !e->source_pub_path || !*e->source_pub_path ||
        !e->target_pub_path || !*e->target_pub_path ||
        !e->source_expected || !e->target_expected ||
        !e->frozen_source_dir || !*e->frozen_source_dir ||
        !e->frozen_target_dir || !*e->frozen_target_dir ||
        !qihse_ct1_recovery_encode(e->expected_manifest, false, false, canonical) ||
        CRYPTO_memcmp(canonical, e->manifest_wire, sizeof(canonical)) ||
        !qihse_ct1_recovery_decode(e->manifest_wire, e->manifest_len,
            false, &decoded, NULL)) return false;

    challenge = e->challenge;
    if (!challenge->epoch || decoded.epoch != challenge->epoch ||
        decoded.issued_ms != challenge->issued_ms ||
        decoded.expires_ms != challenge->expires_ms ||
        CRYPTO_memcmp(decoded.nonce, challenge->nonce, sizeof(challenge->nonce)) ||
        !challenge->issued_ms || challenge->expires_ms <= challenge->issued_ms ||
        challenge->expires_ms - challenge->issued_ms > QIHSE_CT1_RECOVERY_MAX_AGE_MS ||
        clock_gettime(CLOCK_REALTIME, &now) || now.tv_sec < 0 ||
        (uint64_t)now.tv_sec > (UINT64_MAX - 999u) / 1000u) return false;
    now_ms = (uint64_t)now.tv_sec * 1000u + (uint64_t)now.tv_nsec / 1000000u;
    if (now_ms < challenge->issued_ms || now_ms >= challenge->expires_ms ||
        !qihse_ct1_recovery_verify_frozen(e->replication_principal,
            e->frozen_source_dir, &decoded, true) ||
        !qihse_ct1_recovery_verify_frozen(e->replication_principal,
            e->frozen_target_dir, &decoded, false))
        return false;

    return qihse_ct1_node_quote_verify_paired_stale(
        e->source_quote, e->source_quote_len, e->target_quote,
        e->target_quote_len, e->manifest_wire, e->manifest_len,
        challenge->nonce, e->source_pub_path, e->target_pub_path,
        e->source_expected, e->target_expected);
}

bool qihse_ct1_authority_service_evaluate_pair_bound(
    qihse_ct1_authority_store_t *store,
    const qihse_ct1_authority_pair_evidence_t *e)
{
    return e && !qihse_ct1_authority_store_check_bound(store, e->challenge,
        e->manifest_wire, e->manifest_len) &&
        qihse_ct1_authority_service_evaluate_pair(e);
}

/* Private locked bridge. Never call store functions from the evaluator. */
extern int qihse_ct1_authority_store_evaluate_and_retire_bound(
    qihse_ct1_authority_store_t *store,
    const qihse_ct1_authority_challenge_t *challenge,
    const unsigned char *canonical_b, size_t length,
    int (*evaluate)(void *), void *context);

static int evaluate_locked_pair(void *context)
{
    return qihse_ct1_authority_service_evaluate_pair(context);
}

bool qihse_ct1_authority_service_check_and_retire_pair(
    qihse_ct1_authority_store_t *store,
    const qihse_ct1_authority_pair_evidence_t *e)
{
    return e && !qihse_ct1_authority_store_evaluate_and_retire_bound(store,
        e->challenge, e->manifest_wire, e->manifest_len, evaluate_locked_pair,
        (void *)e);
}

unsigned qihse_ct1_authority_service_blockers(void)
{
    return QIHSE_CT1_AUTHORITY_BLOCK_OPERATOR_SESSION |
           QIHSE_CT1_AUTHORITY_BLOCK_INDEPENDENT_ANCHOR |
           QIHSE_CT1_AUTHORITY_BLOCK_LIVE_NODE_COMMAND |
           QIHSE_CT1_AUTHORITY_BLOCK_MANIFEST_CONSUMPTION;
}

const char *qihse_ct1_authority_service_diagnostic(void)
{
    return "DISABLED: no server-bound configured QKP Operator command admission "
           "(RESP QKP_ADMIN lives in connection-local server state); the strict "
           "root checkpoint outside B UID has strict-only manifest bookkeeping "
           "but no Operator-bound one-use grant consumption; live role quote "
           "commands exist but no host-side fresh jointly verified Operator-bound "
           "approval or "
           "production protected executor exists. A separate local root-host "
           "no-op receipt is not recovery authority. Frozen rosters, manifest digests, quote "
           "signatures and caller QKP pointers cannot approve recovery. "
           "Signed-grant verification is not authorization or consumption. "
           "No live state was checked; no grant was issued or consumed.";
}

qihse_ct1_authority_service_result_t qihse_ct1_authority_service_authorize(
    const void *evidence, size_t evidence_len)
{
    (void)evidence;
    (void)evidence_len;
    return QIHSE_CT1_AUTHORITY_SERVICE_DISABLED;
}

qihse_ct1_authority_service_result_t qihse_ct1_authority_service_consume(
    const void *grant, size_t grant_len)
{
    (void)grant;
    (void)grant_len;
    return QIHSE_CT1_AUTHORITY_SERVICE_DISABLED;
}

int qihse_ct1_authority_service_verify_grant(
    const unsigned char *grant, size_t grant_len,
    const qihse_ct1_recovery_manifest_t *expected,
    const qihse_ct1_authority_challenge_t *challenge,
    const char *operator_pub_path, const unsigned char operator_pin[32])
{
    unsigned char canonical[QIHSE_CT1_RECOVERY_WIRE_SIZE];
    unsigned char actual_pin[SHA256_DIGEST_LENGTH];
    unsigned char *der = NULL, *cursor;
    EVP_PKEY *key = NULL;
    EVP_MD_CTX *ctx = NULL;
    FILE *file = NULL;
    struct timespec now;
    int der_len, ok = 0;

    if (!grant || grant_len != QIHSE_CT1_AUTHORITY_GRANT_SIZE || !expected ||
        !challenge || !operator_pub_path || !*operator_pub_path || !operator_pin ||
        memcmp(grant, "CT1G\1\0\0\0", 8) ||
        !qihse_ct1_recovery_encode(expected, false, false, canonical) ||
        CRYPTO_memcmp(grant + 8, canonical, sizeof(canonical)) ||
        !expected->epoch || expected->epoch != challenge->epoch ||
        expected->issued_ms != challenge->issued_ms ||
        expected->expires_ms != challenge->expires_ms ||
        CRYPTO_memcmp(expected->nonce, challenge->nonce, sizeof(challenge->nonce)) ||
        CRYPTO_memcmp(expected->issuer_operator_pin, operator_pin, 32) ||
        !expected->issued_ms || expected->expires_ms <= expected->issued_ms ||
        expected->expires_ms - expected->issued_ms > QIHSE_CT1_RECOVERY_MAX_AGE_MS ||
        clock_gettime(CLOCK_REALTIME, &now) || now.tv_sec < 0 ||
        (uint64_t)now.tv_sec > UINT64_MAX / 1000u ||
        (uint64_t)now.tv_sec * 1000u + (uint64_t)now.tv_nsec / 1000000u < expected->issued_ms ||
        (uint64_t)now.tv_sec * 1000u + (uint64_t)now.tv_nsec / 1000000u >= expected->expires_ms)
        return 0;

    file = fopen(operator_pub_path, "rb");
    if (!file) goto done;
    key = PEM_read_PUBKEY(file, NULL, NULL, NULL);
    fclose(file);
    file = NULL;
    if (!key || !EVP_PKEY_is_a(key, "ML-DSA-87")) goto done;
    der_len = i2d_PUBKEY(key, NULL);
    if (der_len <= 0 || der_len > 8192) goto done;
    der = OPENSSL_malloc((size_t)der_len);
    cursor = der;
    if (!der || i2d_PUBKEY(key, &cursor) != der_len ||
        !SHA256(der, (size_t)der_len, actual_pin) ||
        CRYPTO_memcmp(actual_pin, operator_pin, sizeof(actual_pin))) goto done;
    ctx = EVP_MD_CTX_new();
    if (!ctx || EVP_DigestVerifyInit(ctx, NULL, NULL, NULL, key) != 1) goto done;
    ok = EVP_DigestVerify(ctx, grant + QIHSE_CT1_AUTHORITY_GRANT_SIGNED_SIZE,
        grant_len - QIHSE_CT1_AUTHORITY_GRANT_SIGNED_SIZE,
        grant, QIHSE_CT1_AUTHORITY_GRANT_SIGNED_SIZE) == 1;
done:
    if (file) fclose(file);
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(key);
    OPENSSL_clear_free(der, der ? (size_t)der_len : 0);
    return ok;
}
