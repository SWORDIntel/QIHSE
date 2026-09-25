/*
 * test_federation_crl.c — node-side consumption of the CA tool's CRL file.
 *
 * The out-of-process CA tool appends revocation records to a file
 * (QIHSE-FED-CRL-V1, written by qihse_ca_provision_revoke).  The running
 * node previously learned about revocations ONLY through the KV "fednode:"
 * record.  The claim under test is that the file is now a SECOND, composing
 * source enforced at layer 2 of the peer decision:
 *
 *   - revoked in the CRL          -> peer refused at verification, with the
 *                                    same verdict a KV-revoked node gets
 *   - unrevoked peer              -> still accepted against the same list
 *   - malformed/truncated/partial -> the WHOLE check fails closed; an
 *                                    unrevoked, fully approved peer is
 *                                    refused too — never verified as clean
 *   - KV-revoked                  -> still refused (sources compose: either
 *                                    one suffices, and a revocation that
 *                                    exists only in the CRL refuses a peer
 *                                    whose KV record says APPROVED)
 *   - authorization               -> NULL and a low-clearance principal
 *                                    cannot load the CRL (negative
 *                                    authorization for this new surface)
 *
 * Cross-check: a CRL actually produced by the CA TOOL's code path — this
 * test links src/federation/qihse_ca_provision.c and calls its exported
 * writer qihse_ca_provision_revoke(), so the bytes on disk come from the
 * tool's encoder, not from a re-implementation.  Malformed variants and
 * hand-shaped records (fingerprint-only entries) are constructed in-test,
 * because the tool's writer can only ever emit well-formed lines; where
 * that happens the test says so.
 */
#include "qihse_auth.h"
#include "qihse_ca_provision.h"
#include "qihse_federation.h"
#include "qihse_federation_mtls.h"
#include "qihse_kv_store.h"
#include "qihse_runtime_trust.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static qihse_kv_store_t* g_store;
static qihse_user_t* g_op;       /* operator principal */
static qihse_user_t* g_analyst;  /* low-privilege principal */

/* ── helpers ───────────────────────────────────────────────────────────── */

static void path_under(const char* base, const char* name, char* out,
                       size_t cap) {
    snprintf(out, cap, "%s/%s", base, name);
}

static void enroll_node(const char* key_dir, qihse_sig_alg_t alg,
                        const char* seed, qihse_federation_node_identity_t* out) {
    memset(out, 0, sizeof(*out));
    assert(qihse_uuid_from_seed(seed, strlen(seed), &out->node_id));
    snprintf(out->hostname, sizeof(out->hostname), "%s", seed);
    snprintf(out->boot_id, sizeof(out->boot_id), "%s-boot", seed);
    out->identity_kind = QIHSE_IDENTITY_HOST_AGENT;
    assert(qihse_federation_node_keygen_alg(key_dir, alg, out));
}

/* The exact peer-decision input the transport's certificate verify callback
 * produces: SHA-384 over the certificate's raw public key. */
static void cert_fingerprint_of(const qihse_federation_ca_t* ca,
                                const char* ca_key_path,
                                const qihse_federation_node_identity_t* node,
                                uint64_t epoch, uint8_t* out_fp) {
    char cert[QIHSE_FEDERATION_PEM_MAX];
    assert(qihse_federation_ca_issue_node(ca_key_path, ca, node, epoch,
                                          cert, sizeof(cert)));
    assert(qihse_federation_cert_fingerprint(cert, out_fp));
    /* Layer 1 still holds: the certificate itself verifies against the CA. */
    assert(qihse_federation_cert_verify(cert, ca));
}

static qihse_peer_verdict_t verify_fp(const uint8_t* fp) {
    qihse_uuid_t resolved;
    qihse_runtime_trust_t trust;
    return qihse_federation_peer_verify(g_store, g_op, fp,
                                        QIHSE_FEDERATION_NODE_FINGERPRINT_BYTES,
                                        &resolved, &trust);
}

/* Write raw bytes to a path — for the malformed/hand-shaped files the
 * tool's writer can never produce. */
static void write_bytes(const char* path, const char* bytes, size_t len) {
    FILE* f = fopen(path, "wb");
    assert(f);
    assert(fwrite(bytes, 1, len, f) == len);
    assert(fclose(f) == 0);
}

/* ── negative authorization for the new reachable surface ─────────────── */

static void test_load_authorization(const char* dir) {
    char missing[512], good[512];
    path_under(dir, "no-such.crl", missing, sizeof(missing));
    path_under(dir, "empty.crl", good, sizeof(good));
    write_bytes(good, "", 0);

    /* NULL is never an authorization bypass; an ANALYST holds neither
     * NODE_REVOKE nor any trust-plane write scope. */
    assert(!qihse_federation_crl_load(NULL, good));
    assert(!qihse_federation_crl_load(g_analyst, good));
    assert(!qihse_federation_crl_load(NULL, NULL));

    /* An absent file is an EMPTY list (valid, nothing revoked), mirroring
     * the tool's qihse_ca_provision_crl_check. */
    assert(qihse_federation_crl_load(g_op, missing));
    qihse_federation_crl_status_t st;
    qihse_federation_crl_state(&st);
    assert(st.configured && !st.failed && st.entry_count == 0);

    qihse_uuid_t whoever;
    assert(qihse_uuid_from_seed("crl-whoever", strlen("crl-whoever"), &whoever));
    bool revoked = true;
    assert(qihse_federation_crl_check(&whoever, NULL, &revoked));
    assert(!revoked);

    /* Explicit authorized opt-out clears the source entirely. */
    assert(qihse_federation_crl_load(g_op, NULL));
    qihse_federation_crl_state(&st);
    assert(!st.configured && !st.failed && st.entry_count == 0);

    printf("PASS load authorization: NULL/analyst refused, absent file is an "
           "empty list, explicit clear works\n");
}

/* ── revoked-in-CRL refused at verification; unrevoked accepted ───────── */

static void test_revoked_in_crl_refused(const char* dir, const char* ca_dir,
                                        const char* key_dir) {
    qihse_federation_ca_t ca;
    assert(qihse_federation_ca_create(ca_dir, QIHSE_SIG_ML_DSA_87, &ca));
    char ca_key[512];
    path_under(ca_dir, "federation-ca.key", ca_key, sizeof(ca_key));

    qihse_federation_node_identity_t bad, good;
    enroll_node(key_dir, QIHSE_SIG_ML_DSA_65, "crl-node-bad", &bad);
    enroll_node(key_dir, QIHSE_SIG_ML_DSA_65, "crl-node-good", &good);
    assert(qihse_federation_node_enroll_request(g_store, g_op, &bad));
    assert(qihse_federation_node_enroll_request(g_store, g_op, &good));
    assert(qihse_federation_node_enroll_approve(g_store, g_op, &bad.node_id, 4));
    assert(qihse_federation_node_enroll_approve(g_store, g_op, &good.node_id, 5));

    uint8_t bad_fp[QIHSE_FEDERATION_NODE_FINGERPRINT_BYTES];
    uint8_t good_fp[QIHSE_FEDERATION_NODE_FINGERPRINT_BYTES];
    cert_fingerprint_of(&ca, ca_key, &bad, 4, bad_fp);
    cert_fingerprint_of(&ca, ca_key, &good, 5, good_fp);

    /* Baseline: both peers accepted before any CRL exists, and the file
     * source is inactive. */
    assert(verify_fp(bad_fp) == QIHSE_PEER_ACCEPT);
    assert(verify_fp(good_fp) == QIHSE_PEER_ACCEPT);

    /* A CRL produced by the CA TOOL's code path (the exported writer is
     * linked into this test binary), not by a re-implementation. */
    char crl[512];
    path_under(dir, "tool-written.crl", crl, sizeof(crl));
    assert(qihse_ca_provision_revoke(g_op, crl, &bad.node_id, bad.fingerprint,
                                     4, "compromised"));
    /* The file really is in the tool's wire format. */
    FILE* peek = fopen(crl, "rb");
    assert(peek);
    char head[64] = {0};
    size_t got = fread(head, 1, sizeof(head) - 1u, peek);
    fclose(peek);
    assert(got > 0 && strncmp(head, QIHSE_CA_PROVISION_CRL_MAGIC,
                              strlen(QIHSE_CA_PROVISION_CRL_MAGIC)) == 0);

    assert(qihse_federation_crl_load(g_op, crl));
    qihse_federation_crl_status_t st;
    qihse_federation_crl_state(&st);
    assert(st.configured && !st.failed && st.entry_count == 1);

    /* THE PROPERTY: revoked in the file, refused at verification, with the
     * same verdict a KV-revoked node produces — while the unrevoked peer
     * is still accepted against the same list. */
    assert(verify_fp(bad_fp) == QIHSE_PEER_REJECT_REVOKED);
    assert(verify_fp(good_fp) == QIHSE_PEER_ACCEPT);

    /* The node-side check and the tool's own check agree on the same
     * file: same revoked bit for both nodes. */
    bool tool_rev = false, node_rev = false;
    assert(qihse_ca_provision_crl_check(crl, &bad.node_id, bad.fingerprint,
                                        &tool_rev));
    assert(qihse_federation_crl_check(&bad.node_id, bad_fp, &node_rev));
    assert(tool_rev && node_rev);
    assert(qihse_ca_provision_crl_check(crl, &good.node_id, good.fingerprint,
                                        &tool_rev));
    assert(qihse_federation_crl_check(&good.node_id, good_fp, &node_rev));
    assert(!tool_rev && !node_rev);

    /* The refusal came from the file, not from a lingering KV revocation:
     * an authorized clear restores the session (KV record is APPROVED). */
    assert(qihse_federation_crl_load(g_op, NULL));
    assert(verify_fp(bad_fp) == QIHSE_PEER_ACCEPT);

    printf("PASS revoked-in-CRL: tool-written CRL refuses the revoked peer "
           "at verification, unrevoked accepted, clear restores\n");
}

/* ── malformed / truncated / partial-line: the whole check fails closed ── */

static void test_fail_closed(const char* dir, const char* ca_dir,
                             const char* key_dir) {
    qihse_federation_ca_t ca;
    assert(qihse_federation_ca_create(ca_dir, QIHSE_SIG_ML_DSA_87, &ca));
    char ca_key[512];
    path_under(ca_dir, "federation-ca.key", ca_key, sizeof(ca_key));

    qihse_federation_node_identity_t clean;
    enroll_node(key_dir, QIHSE_SIG_ML_DSA_65, "crl-node-clean", &clean);
    assert(qihse_federation_node_enroll_request(g_store, g_op, &clean));
    assert(qihse_federation_node_enroll_approve(g_store, g_op, &clean.node_id, 6));
    uint8_t clean_fp[QIHSE_FEDERATION_NODE_FINGERPRINT_BYTES];
    cert_fingerprint_of(&ca, ca_key, &clean, 6, clean_fp);

    char node_str[QIHSE_UUID_STR_LEN + 1u];
    assert(qihse_uuid_format(&clean.node_id, node_str));
    bool revoked_dummy = false;

    /* Every variant below is constructed IN-TEST: the tool's writer can
     * only emit well-formed lines, so no tool path produces these bytes. */
    struct { const char* name; const char* bytes; } bad_files[] = {
        { "garbage",        "this is not a crl record\n" },
        { "wrong-magic",    "QIHSE-FED-CRL-V2\t00000000-0000-0000-0000-000000000000\t1\t-\t0\tx\n" },
        { "truncated",      "QIHSE-FED-CRL-V1\t" },
        { "partial-line",   "QIHSE-FED-CRL-V1\t123e4567-e89b-12d3-a456-426614174000\t7\n" },
        { "short-fp",       "QIHSE-FED-CRL-V1\t123e4567-e89b-12d3-a456-426614174000\t7\tAB\t0\tx\n" },
        { "bad-uuid-len",   "QIHSE-FED-CRL-V1\t123e4567-e89b-12d3-a456-42661417\t7\t-\t0\tx\n" },
        { "non-numeric-ser","QIHSE-FED-CRL-V1\t123e4567-e89b-12d3-a456-426614174000\tseven\t-\t0\tx\n" },
        { "non-numeric-time","QIHSE-FED-CRL-V1\t123e4567-e89b-12d3-a456-426614174000\t7\t-\tlater\tx\n" },
        { "extra-tab",      "QIHSE-FED-CRL-V1\t123e4567-e89b-12d3-a456-426614174000\t7\t-\t0\tx\ty\n" },
        { "no-tab",         "QIHSE-FED-CRL-V1 123e4567-e89b-12d3-a456-426614174000 7 - 0 x\n" },
    };

    char path[512];
    for (size_t i = 0; i < sizeof(bad_files) / sizeof(bad_files[0]); i++) {
        path_under(dir, bad_files[i].name, path, sizeof(path));
        write_bytes(path, bad_files[i].bytes, strlen(bad_files[i].bytes));

        /* The load fails... */
        if (qihse_federation_crl_load(g_op, path)) {
            fprintf(stderr, "FAIL: malformed CRL '%s' loaded as valid\n",
                    bad_files[i].name);
            abort();
        }
        qihse_federation_crl_status_t st;
        qihse_federation_crl_state(&st);
        assert(st.failed && !st.configured && st.entry_count == 0);

        /* ...the whole check fails closed: never verifies as clean, for an
         * UNREVOKED, fully APPROVED peer... */
        bool revoked = true;
        if (qihse_federation_crl_check(&clean.node_id, clean_fp, &revoked)) {
            fprintf(stderr, "FAIL: check succeeded against poisoned CRL '%s'\n",
                    bad_files[i].name);
            abort();
        }
        if (verify_fp(clean_fp) != QIHSE_PEER_REJECT_CRL) {
            fprintf(stderr, "FAIL: peer verified against poisoned CRL '%s' "
                    "(verdict %s)\n", bad_files[i].name,
                    qihse_peer_verdict_name(verify_fp(clean_fp)));
            abort();
        }
        /* ...and the tool's own parser refuses the same bytes — the
         * fail-closed semantics are the tool's, not a local invention. */
        bool tool_rev = false;
        assert(!qihse_ca_provision_crl_check(path, &clean.node_id, clean_fp,
                                             &tool_rev));
        assert(!tool_rev);
    }

    /* A 96-char fingerprint field with non-hex characters: constructed
     * byte-exact here so the length check passes and only the decoding
     * fails (a hand-typed literal could get the count wrong and silently
     * test the wrong thing). */
    char bad_hex[97];
    memset(bad_hex, '0', 96);
    bad_hex[94] = 'z';
    bad_hex[95] = 'z';
    bad_hex[96] = '\0';
    char nonhex[512];
    int n = snprintf(nonhex, sizeof(nonhex),
                     "%s\t123e4567-e89b-12d3-a456-426614174000\t7\t%s\t0\tx\n",
                     QIHSE_CA_PROVISION_CRL_MAGIC, bad_hex);
    assert(n > 0 && (size_t)n < sizeof(nonhex));
    path_under(dir, "nonhex-fp", path, sizeof(path));
    write_bytes(path, nonhex, (size_t)n);
    assert(!qihse_federation_crl_load(g_op, path));
    assert(!qihse_federation_crl_check(&clean.node_id, clean_fp, &revoked_dummy));
    assert(verify_fp(clean_fp) == QIHSE_PEER_REJECT_CRL);

    /* An overlong line: the reason is padded past the reader's line bound
     * (QIHSE_CA_PROVISION_CRL_LINE_MAX), so fgets cannot see the newline
     * and the line must be refused rather than split.  Built with a loop
     * because the length that matters is the tool's constant, not a number
     * typed here. */
    char* huge = (char*)malloc(QIHSE_CA_PROVISION_CRL_LINE_MAX + 128u);
    assert(huge);
    int m = snprintf(huge, QIHSE_CA_PROVISION_CRL_LINE_MAX + 128u,
                     "%s\t123e4567-e89b-12d3-a456-426614174000\t7\t-\t0\t",
                     QIHSE_CA_PROVISION_CRL_MAGIC);
    assert(m > 0);
    while ((size_t)m < QIHSE_CA_PROVISION_CRL_LINE_MAX + 40u) {
        huge[m++] = 'r';
    }
    huge[m++] = '\n';
    huge[m] = '\0';
    path_under(dir, "overlong-line", path, sizeof(path));
    write_bytes(path, huge, (size_t)m);
    free(huge);
    assert(!qihse_federation_crl_load(g_op, path));
    assert(!qihse_federation_crl_check(&clean.node_id, clean_fp, &revoked_dummy));
    assert(verify_fp(clean_fp) == QIHSE_PEER_REJECT_CRL);
    {   /* The tool's parser refuses the same two files as well. */
        bool tool_rev = false;
        path_under(dir, "nonhex-fp", path, sizeof(path));
        assert(!qihse_ca_provision_crl_check(path, &clean.node_id, clean_fp,
                                             &tool_rev));
        path_under(dir, "overlong-line", path, sizeof(path));
        assert(!qihse_ca_provision_crl_check(path, &clean.node_id, clean_fp,
                                             &tool_rev));
    }

    /* Also fail closed for a GOOD record followed by garbage: a malformed
     * line anywhere in the file poisons the whole list, it is not skipped. */
    char mixed[512];
    path_under(dir, "mixed.crl", mixed, sizeof(mixed));
    assert(qihse_ca_provision_revoke(g_op, mixed, &clean.node_id,
                                     clean.fingerprint, 6, "real-revocation"));
    FILE* app = fopen(mixed, "a");
    assert(app);
    assert(fputs("garbage appended by an attacker\n", app) != EOF);
    assert(fclose(app) == 0);
    assert(!qihse_federation_crl_load(g_op, mixed));
    assert(verify_fp(clean_fp) == QIHSE_PEER_REJECT_CRL);

    /* An unenrolled fingerprint is still refused by layer 2's first gate
     * even while the CRL state is poisoned — the decision's layer order
     * is unchanged. */
    uint8_t unknown_fp[QIHSE_FEDERATION_NODE_FINGERPRINT_BYTES] = {0};
    assert(verify_fp(unknown_fp) == QIHSE_PEER_REJECT_UNKNOWN_FINGERPRINT);

    /* Recovery: a valid load clears the sticky failure. */
    char good_crl[512];
    path_under(dir, "recover.crl", good_crl, sizeof(good_crl));
    assert(qihse_ca_provision_revoke(g_op, good_crl, &clean.node_id, NULL, 6,
                                     "decommissioned"));
    assert(qihse_federation_crl_load(g_op, good_crl));
    bool revoked2 = false;
    assert(qihse_federation_crl_check(&clean.node_id, clean_fp, &revoked2));
    assert(revoked2); /* uuid-only entry still matches (fingerprint NULL) */
    assert(verify_fp(clean_fp) == QIHSE_PEER_REJECT_REVOKED);

    printf("PASS fail-closed: %zu literal + 2 byte-exact malformed variants "
           "+ appended garbage refuse the whole check; valid reload recovers\n",
           sizeof(bad_files) / sizeof(bad_files[0]));
}

/* ── composition with the KV record ────────────────────────────────────── */

static void test_kv_compose(const char* dir, const char* ca_dir,
                            const char* key_dir) {
    qihse_federation_ca_t ca;
    assert(qihse_federation_ca_create(ca_dir, QIHSE_SIG_ML_DSA_87, &ca));
    char ca_key[512];
    path_under(ca_dir, "federation-ca.key", ca_key, sizeof(ca_key));

    qihse_federation_node_identity_t kv_only, crl_only, both, escapee;
    enroll_node(key_dir, QIHSE_SIG_ML_DSA_65, "crl-node-kvonly", &kv_only);
    enroll_node(key_dir, QIHSE_SIG_ML_DSA_65, "crl-node-crlonly", &crl_only);
    enroll_node(key_dir, QIHSE_SIG_ML_DSA_65, "crl-node-both", &both);
    enroll_node(key_dir, QIHSE_SIG_ML_DSA_65, "crl-node-escapee", &escapee);

    qihse_federation_node_identity_t* nodes[] =
        { &kv_only, &crl_only, &both, &escapee };
    for (size_t i = 0; i < 4u; i++) {
        assert(qihse_federation_node_enroll_request(g_store, g_op, nodes[i]));
        assert(qihse_federation_node_enroll_approve(g_store, g_op,
                                                    &nodes[i]->node_id, 7));
    }

    uint8_t kv_fp[QIHSE_FEDERATION_NODE_FINGERPRINT_BYTES];
    uint8_t crl_fp[QIHSE_FEDERATION_NODE_FINGERPRINT_BYTES];
    uint8_t both_fp[QIHSE_FEDERATION_NODE_FINGERPRINT_BYTES];
    uint8_t escapee_fp[QIHSE_FEDERATION_NODE_FINGERPRINT_BYTES];
    cert_fingerprint_of(&ca, ca_key, &kv_only, 7, kv_fp);
    cert_fingerprint_of(&ca, ca_key, &crl_only, 7, crl_fp);
    cert_fingerprint_of(&ca, ca_key, &both, 7, both_fp);
    cert_fingerprint_of(&ca, ca_key, &escapee, 7, escapee_fp);

    /* Start from a clean file source. */
    assert(qihse_federation_crl_load(g_op, NULL));

    /* Source 1 alone (KV): existing behavior is preserved — a KV-revoked
     * node is refused with REJECT_REVOKED. */
    assert(verify_fp(kv_fp) == QIHSE_PEER_ACCEPT);
    assert(qihse_federation_node_revoke(g_store, g_op, &kv_only.node_id));
    assert(verify_fp(kv_fp) == QIHSE_PEER_REJECT_REVOKED);

    /* Source 2 alone (file): a revocation recorded ONLY in the CRL
     * refuses a peer whose KV record still says APPROVED. */
    char crl[512];
    path_under(dir, "compose.crl", crl, sizeof(crl));
    assert(qihse_ca_provision_revoke(g_op, crl, &crl_only.node_id,
                                     crl_only.fingerprint, 7, "key-rotation"));
    assert(qihse_federation_crl_load(g_op, crl));
    assert(verify_fp(crl_fp) == QIHSE_PEER_REJECT_REVOKED);

    /* Both sources: same refusal, one verdict — the sources COMPOSE, the
     * file does not replace the KV record. */
    assert(qihse_ca_provision_revoke(g_op, crl, &both.node_id,
                                     both.fingerprint, 7, "both"));
    assert(qihse_federation_crl_load(g_op, crl));
    assert(qihse_federation_node_revoke(g_store, g_op, &both.node_id));
    assert(verify_fp(both_fp) == QIHSE_PEER_REJECT_REVOKED);

    /* The escapee: APPROVED in the KV record and named by no CRL entry —
     * still accepted, so composition has not become "refuse everyone". */
    assert(verify_fp(escapee_fp) == QIHSE_PEER_ACCEPT);

    /* Fingerprint-only matching: an entry whose UUID is NOT the peer's but
     * whose fingerprint IS.  Constructed in-test — the tool's writer always
     * writes the uuid and fingerprint of the SAME node, but the format (and
     * the tool's own parser) match on either field, so the node must too:
     * a re-keyed node that kept its certificate must not escape a
     * fingerprint-recorded revocation just because the uuid differs. */
    char esc_str[QIHSE_UUID_STR_LEN + 1u], other_str[QIHSE_UUID_STR_LEN + 1u];
    assert(qihse_uuid_format(&escapee.node_id, esc_str));
    qihse_uuid_t unrelated;
    assert(qihse_uuid_from_seed("crl-unrelated-uuid", 18, &unrelated));
    assert(qihse_uuid_format(&unrelated, other_str));
    char fp_hex[QIHSE_FEDERATION_NODE_FINGERPRINT_BYTES * 2u + 1u];
    for (size_t i = 0; i < QIHSE_FEDERATION_NODE_FINGERPRINT_BYTES; i++) {
        snprintf(fp_hex + i * 2, 3, "%02x", escapee.fingerprint[i]);
    }
    char fp_only[512];
    path_under(dir, "fp-only.crl", fp_only, sizeof(fp_only));
    char line[QIHSE_CA_PROVISION_CRL_LINE_MAX];
    int n = snprintf(line, sizeof(line), "%s\t%s\t7\t%s\t%llu\tfp-path\n",
                     QIHSE_CA_PROVISION_CRL_MAGIC, other_str, fp_hex, 7ull);
    assert(n > 0 && (size_t)n < sizeof(line));
    write_bytes(fp_only, line, (size_t)n);
    assert(qihse_federation_crl_load(g_op, fp_only));
    assert(verify_fp(escapee_fp) == QIHSE_PEER_REJECT_REVOKED);

    /* Clean up the file source for the tests that follow. */
    assert(qihse_federation_crl_load(g_op, NULL));

    printf("PASS compose: KV-only, CRL-only (KV says APPROVED), and both "
           "sources all refuse; unlisted peer accepted; fp-only entries match\n");
}

/* ── verdict surface ───────────────────────────────────────────────────── */

static void test_verdict_surface(void) {
    assert(strcmp(qihse_peer_verdict_name(QIHSE_PEER_REJECT_CRL),
                  "reject_crl") == 0);
    assert(strcmp(qihse_peer_verdict_name(QIHSE_PEER_REJECT_REVOKED),
                  "reject_revoked") == 0);
    /* The new value was appended: existing verdict numbering is unchanged. */
    assert(QIHSE_PEER_ACCEPT == 0 && QIHSE_PEER_REJECT_MALFORMED == 6);

    printf("PASS verdict surface: reject_crl name stable, existing values "
           "unrenumbered\n");
}

int main(void) {
    /* Artifacts under $TMPDIR with a relative fallback (path policy). */
    const char* base = getenv("TMPDIR");
    if (!base || *base == '\0') base = "build";
    char data_root[448];
    snprintf(data_root, sizeof(data_root), "%s/qihse_fed_crl_XXXXXX", base);
    assert(mkdtemp(data_root));
    char ca_dir[512], key_dir[512];
    snprintf(ca_dir, sizeof(ca_dir), "%s/ca", data_root);
    snprintf(key_dir, sizeof(key_dir), "%s/keys", data_root);
    assert(mkdir(ca_dir, 0700) == 0);
    assert(mkdir(key_dir, 0700) == 0);
    setenv("QIHSE_DATA_DIR", data_root, 1);

    /* Operator context plus a low-privilege ANALYST principal for the
     * negative authorization tests, mirroring tests/test_federation_ca.c. */
    assert(qihse_auth_init());
    if (!qihse_auth_bootstrap_operator("FedCrlPass1!")) {
        setenv("QIHSE_OPERATOR_PASSWORD", "FedCrlPass1!", 1);
        assert(qihse_auth_init());
    }
    g_op = qihse_auth_get_user(0);
    assert(g_op);
    g_analyst = qihse_auth_create_user(g_op, 41, QIHSE_ROLE_ANALYST, 90, 0,
                                       "CrlAnalyst1!", false);
    assert(g_analyst);
    g_store = qihse_kv_store_create();
    assert(g_store);

    test_load_authorization(data_root);
    test_revoked_in_crl_refused(data_root, ca_dir, key_dir);
    test_fail_closed(data_root, ca_dir, key_dir);
    test_kv_compose(data_root, ca_dir, key_dir);
    test_verdict_surface();

    qihse_kv_store_destroy(g_store);
    printf("federation CRL tests passed\n");
    return 0;
}
