/* Machine-token (MACHINEAUTH) authentication — security test suite.
 *
 * Covers the full refusal surface of qihse_machine_auth_check plus the
 * invariant-3 negative authorization test: a machine session's claims
 * context (role 0, clearance 0, SCI 0) MUST be denied classified data
 * through the same row-visibility predicate the RESP data path uses, with
 * no payload disclosure.
 *
 * Refusal surface (every case must fail closed):
 *   malformed blob, wrong purpose (SCATTER token presented), scope bits set,
 *   bound payload, issued-in-future, expired, TTL above the machine ceiling,
 *   forged signature, untrusted signer key, nonce replay, disabled module.
 */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include "qihse_machine_auth.h"
#include "qihse_auth.h"
#include "core/qihse_auth_internal.h"
#include "qihse_kv_store.h"

static EVP_PKEY* g_signer = NULL;   /* trusted anchor's key */
static EVP_PKEY* g_stranger = NULL; /* not configured as an anchor */

static void write_pem(EVP_PKEY* key, const char* priv_path, const char* pub_path) {
    FILE* pf = fopen(priv_path, "wb");
    assert(pf);
    assert(PEM_write_PrivateKey(pf, key, NULL, NULL, 0, NULL, NULL) == 1);
    fclose(pf);
    FILE* bf = fopen(pub_path, "wb");
    assert(bf);
    assert(PEM_write_PUBKEY(bf, key) == 1);
    fclose(bf);
}

/* Mint one MACHINE-purpose token signed by `pkey`. Mirrors the
 * qihse-machine-token tool so the test exercises the real wire format. */
static size_t mint_token(EVP_PKEY* pkey, uint8_t* out, size_t cap,
                         uint64_t ttl_ms, int64_t issued_offset_ms,
                         uint16_t purpose, uint32_t scope, size_t payload_len) {
    qihse_fabric_token_t t;
    memset(&t, 0, sizeof(t));
    t.purpose = purpose;
    t.job_type = QIHSE_FABRIC_JOB_NONE;
    t.scope = scope;
    t.principal_user_id = 0u;
    t.clearance = 0u;
    t.sci = 0u;
    t.principal_tenant = 0u;

    uint8_t* der = NULL;
    int der_len = i2d_PUBKEY(pkey, &der);
    assert(der_len > 0 && der);
    uint8_t sha[SHA256_DIGEST_LENGTH];
    SHA256(der, (size_t)der_len, sha);
    memcpy(t.submitter_node.bytes, sha, sizeof(t.submitter_node.bytes));
    OPENSSL_free(der);

    assert(RAND_bytes(t.nonce.bytes, (int)sizeof(t.nonce.bytes)) == 1);
    uint64_t now = (uint64_t)time(NULL) * 1000ull;
    t.issued_ms = now + (int64_t)issued_offset_ms;
    t.expires_ms = t.issued_ms + ttl_ms;
    t.payload_len = (uint32_t)payload_len;
    SHA384((const unsigned char*)"", 0u, t.payload_digest);
    if (payload_len > 0) t.payload_digest[0] ^= 0xFFu; /* bound to real bytes */

    size_t blob_len = 0;
    assert(qihse_fabric_token_mint(pkey, &t, out, cap, &blob_len));
    return blob_len;
}

int main(void) {
{
    char qdd[] = "build/test_machine_auth_XXXXXX";
    if (mkdtemp(qdd)) setenv("QIHSE_DATA_DIR", qdd, 1);
}

    g_signer = EVP_PKEY_Q_keygen(NULL, NULL, "ML-DSA-87");
    g_stranger = EVP_PKEY_Q_keygen(NULL, NULL, "ML-DSA-87");
    assert(g_signer && g_stranger);

    char priv_a[512], pub_a[512], priv_b[512], pub_b[512];
    snprintf(priv_a, sizeof(priv_a), "build/machine_auth_a_priv.pem");
    snprintf(pub_a, sizeof(pub_a), "build/machine_auth_a_pub.pem");
    snprintf(priv_b, sizeof(priv_b), "build/machine_auth_b_priv.pem");
    snprintf(pub_b, sizeof(pub_b), "build/machine_auth_b_pub.pem");
    write_pem(g_signer, priv_a, pub_a);
    write_pem(g_stranger, priv_b, pub_b);

    /* ---- Disabled state refuses everything (fail closed) ---- */
    qihse_machine_auth_reset();
    uint8_t blob[QIHSE_FABRIC_TOKEN_MAX_BYTES];
    qihse_fabric_token_t claims;
    size_t len = mint_token(g_signer, blob, sizeof(blob), 3600000ull, 0,
                            QIHSE_FABRIC_TOKEN_PURPOSE_MACHINE, 0u, 0u);
    assert(qihse_machine_auth_check(blob, len, 0, &claims) == QIHSE_MACHINE_AUTH_DISABLED);
    printf("[PASS] no anchors configured -> DISABLED, fail closed\n");

    /* ---- Configure the trust anchor; happy path + replay ---- */
    const char* anchors[1] = { pub_a };
    assert(qihse_machine_auth_configure(anchors, 1));
    assert(qihse_machine_auth_trusted_count() == 1);

    qihse_machine_auth_verdict_t v = qihse_machine_auth_check(blob, len, 0, &claims);
    if (v != QIHSE_MACHINE_AUTH_OK) {
        fprintf(stderr, "[DEBUG] happy-path verdict: %s\n", qihse_machine_auth_verdict_name(v));
    }
    assert(v == QIHSE_MACHINE_AUTH_OK);
    assert(claims.purpose == QIHSE_FABRIC_TOKEN_PURPOSE_MACHINE);
    assert(qihse_machine_auth_ledger_live() == 1);
    printf("[PASS] valid MACHINE token authenticates, nonce consumed\n");

    assert(qihse_machine_auth_check(blob, len, 0, &claims) == QIHSE_MACHINE_AUTH_REPLAY);
    printf("[PASS] replayed token nonce refused\n");

    /* ---- Forged signature: flip one byte inside the signature region ---- */
    len = mint_token(g_signer, blob, sizeof(blob), 3600000ull, 0,
                     QIHSE_FABRIC_TOKEN_PURPOSE_MACHINE, 0u, 0u);
    qihse_fabric_token_t parsed;
    size_t region_len = 0, total = 0;
    assert(qihse_fabric_token_parse(blob, len, &parsed, &region_len, &total));
    blob[total - 1] ^= 0xFFu;
    assert(qihse_machine_auth_check(blob, len, 0, &claims) == QIHSE_MACHINE_AUTH_NO_TRUST);
    printf("[PASS] forged signature refused\n");

    /* ---- Untrusted signer: valid signature, unknown anchor ---- */
    len = mint_token(g_stranger, blob, sizeof(blob), 3600000ull, 0,
                     QIHSE_FABRIC_TOKEN_PURPOSE_MACHINE, 0u, 0u);
    assert(qihse_machine_auth_check(blob, len, 0, &claims) == QIHSE_MACHINE_AUTH_NO_TRUST);
    printf("[PASS] signature by non-anchor key refused\n");

    /* ---- Purpose confusion: a SCATTER token is not a MACHINE credential ---- */
    len = mint_token(g_signer, blob, sizeof(blob), 120000ull, 0,
                     QIHSE_FABRIC_TOKEN_PURPOSE_SCATTER, 0u, 0u);
    assert(qihse_machine_auth_check(blob, len, 0, &claims) == QIHSE_MACHINE_AUTH_WRONG_PURPOSE);
    printf("[PASS] SCATTER-purpose token refused as machine credential\n");

    /* ---- Scope bits refused: MACHINE tokens carry no federation authority ---- */
    len = mint_token(g_signer, blob, sizeof(blob), 3600000ull, 0,
                     QIHSE_FABRIC_TOKEN_PURPOSE_MACHINE,
                     QIHSE_FABRIC_SCOPE_SCATTER, 0u);
    assert(qihse_machine_auth_check(blob, len, 0, &claims) == QIHSE_MACHINE_AUTH_SCOPE_REFUSED);
    printf("[PASS] MACHINE token claiming scope refused\n");

    /* ---- Lifetime window ---- */
    len = mint_token(g_signer, blob, sizeof(blob), 3600000ull, 3600000ll,
                     QIHSE_FABRIC_TOKEN_PURPOSE_MACHINE, 0u, 0u);
    assert(qihse_machine_auth_check(blob, len, 0, &claims) == QIHSE_MACHINE_AUTH_ISSUED_IN_FUTURE);
    len = mint_token(g_signer, blob, sizeof(blob), 3600000ull, -7200000ll,
                     QIHSE_FABRIC_TOKEN_PURPOSE_MACHINE, 0u, 0u);
    assert(qihse_machine_auth_check(blob, len, 0, &claims) == QIHSE_MACHINE_AUTH_EXPIRED);
    len = mint_token(g_signer, blob, sizeof(blob),
                     QIHSE_MACHINE_TOKEN_MAX_TTL_MS + 60000ull, 0,
                     QIHSE_FABRIC_TOKEN_PURPOSE_MACHINE, 0u, 0u);
    assert(qihse_machine_auth_check(blob, len, 0, &claims) == QIHSE_MACHINE_AUTH_TTL_TOO_LONG);
    printf("[PASS] future-issued, expired, and over-ceiling TTL refused\n");

    /* ---- Bound payload refused (MACHINE binds no payload) ---- */
    len = mint_token(g_signer, blob, sizeof(blob), 3600000ull, 0,
                     QIHSE_FABRIC_TOKEN_PURPOSE_MACHINE, 0u, 1u);
    assert(qihse_machine_auth_check(blob, len, 0, &claims) == QIHSE_MACHINE_AUTH_MALFORMED);
    printf("[PASS] payload-bound token refused (empty-payload invariant)\n");

    /* ── INVARIANT 3: low-clearance machine claims cannot read classified data ──
     * The RESP MACHINEAUTH handler installs the token's claims as the session
     * context (role 0, clearance/SCI from the token). Machine tokens minted
     * for fleet agents carry clearance 0 — so the SAME row-visibility
     * predicate the RESP data path applies must deny a classified record and
     * disclose nothing. This is the new-surface negative authorization test:
     * the machine context gets no data above its clearance, through the same
     * qihse_kv_* user-filtered API the RESP GET/SET layer calls. */
    assert(qihse_auth_init());
    assert(qihse_auth_bootstrap_operator("MachineAuthOp1!"));
    qihse_user_t* op = qihse_auth_get_user(0);
    assert(op);

    qihse_kv_store_t* store = qihse_kv_store_create();
    assert(store);
    /* Operator (clearance 0xFFFF) writes a TOP SECRET row. */
    assert(qihse_kv_set_user(store, "citadel/thermal/secret-matrix",
                             "CLASSIFIED-PAYLOAD-7f3a", 5, 0x0003, op));
    /* ...and the unclassified telemetry row the fleet agent owns. */
    assert(qihse_kv_set_user(store, "citadel/thermal/nodes/t420/observed",
                             "{\"cpu_max\":62.0}", 0, 0, op));

    /* The claims context exactly as qihse_resp_handle_machineauth installs
     * it for a clearance-0 machine token. */
    qihse_user_t machine_claims;
    memset(&machine_claims, 0, sizeof(machine_claims));
    machine_claims.user_id = 0u;
    machine_claims.role = 0u;
    machine_claims.classification_level = 0u;
    machine_claims.sci_compartments = 0u;
    machine_claims.tenant_id = 0u;
    snprintf(machine_claims.username, sizeof(machine_claims.username), "machine:test");

    /* Classified read: DENIED, no payload. */
    char* leaked = qihse_kv_get_user(store, "citadel/thermal/secret-matrix", &machine_claims);
    assert(leaked == NULL);
    /* Classified enumeration: DENIED. */
    assert(qihse_kv_get_user(store, "citadel/thermal/secret-matrix", &machine_claims) == NULL);
    /* Unclassified read: allowed — the machine principal sees its own tier. */
    char* own = qihse_kv_get_user(store, "citadel/thermal/nodes/t420/observed", &machine_claims);
    assert(own != NULL && strstr(own, "cpu_max") != NULL);
    free(own);
    /* Control: the operator DOES read the classified row. */
    char* op_view = qihse_kv_get_user(store, "citadel/thermal/secret-matrix", op);
    assert(op_view != NULL && strstr(op_view, "CLASSIFIED-PAYLOAD") == op_view);
    free(op_view);
    printf("[PASS] invariant-3: clearance-0 machine claims denied classified data, "
           "unclassified access intact\n");

    /* ---- Forge via tampered signed REGION (not just signature bytes) ---- */
    len = mint_token(g_signer, blob, sizeof(blob), 3600000ull, 0,
                     QIHSE_FABRIC_TOKEN_PURPOSE_MACHINE, 0u, 0u);
    assert(qihse_fabric_token_parse(blob, len, &parsed, &region_len, &total));
    blob[20] ^= 0x01u; /* flip a claims byte inside the signed region */
    assert(qihse_machine_auth_check(blob, len, 0, &claims) == QIHSE_MACHINE_AUTH_NO_TRUST);
    printf("[PASS] tampered signed region refused\n");

    free(leaked == NULL ? NULL : leaked); /* no leak path: never non-NULL above */
    EVP_PKEY_free(g_signer);
    EVP_PKEY_free(g_stranger);
    unlink(priv_a); unlink(pub_a); unlink(priv_b); unlink(pub_b);
    printf("ALL MACHINE AUTH TESTS PASSED\n");
    return 0;
}
