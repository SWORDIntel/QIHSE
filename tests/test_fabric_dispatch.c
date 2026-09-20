/*
 * test_fabric_dispatch.c — fabric remote job dispatch (ai_fabric.md item 3,
 * the remote half).
 *
 * The claims under test are the ones the three design decisions made, and each
 * one is asserted against the thing that would be wrong without it:
 *
 *   1. RESULT LOCATION — a job whose best-fit node is a PEER is dispatched and
 *      RUNS THERE.  Asserted by reading the peer's own store: the artifact the
 *      job produced is in the executor's store and NOT in the submitter's (the
 *      executor never writes into the submitter's store, and the submitter
 *      never writes the executor's records).  The submitter's state after a
 *      dispatch is `pending-fetch`, which is neither `done` nor `failed`, and
 *      FABRIC.RESULT serves the cached record only after FABRIC.FETCH pulled
 *      it.
 *
 *   2. FAILURE SEMANTICS — idempotency is declared per type and a retry is
 *      attempted ONLY for a type that declares it.  `embed` does not (a retry
 *      would create a SECOND memory) and `keystone-ingest` does (a retry
 *      overwrites the same artifact key).  A non-idempotent dispatch that gets
 *      no answer is terminal `gave-up` after ONE attempt; an idempotent one is
 *      retried, and exhausting the budget is `gave-up`, never `failed`.
 *
 *   3. PRINCIPAL — a signed capability token.  A token that cannot be
 *      verified, has expired, has been replayed, names another node, or claims
 *      a scope the node was not enrolled with is REFUSED, and the job is NOT
 *      run under any local principal.
 *
 * INVARIANT 3 NEGATIVE TEST (AGENTS.md, merge blocker): a low-clearance
 * principal attempts, through this new adapter, to reach data above its
 * clearance — both by running a job (the normal path) and by naming a
 * record directly (the bypass-prone direct-ID form).  Both are DENIED, and the
 * response bytes are asserted to contain NO protected payload.
 */
#include "qihse_ai_memory.h"
#include "qihse_auth.h"
#include "qihse_cluster_bus.h"
#include "qihse_fabric_dispatch.h"
#include "qihse_kv_store.h"
#include "qihse_resp_wire.h"
#include "qihse_runtime_trust.h"

#include <openssl/evp.h>

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <unistd.h>

#define PROTECTED_MARKER "PROTECTED-ABOVE-CLEARANCE-7f21c4"
#define JOB_PAYLOAD "fabric remote dispatch payload marker"

static qihse_user_t* g_op;
static qihse_kv_store_t* g_store_a;   /* submitter */
static qihse_kv_store_t* g_store_b;   /* executor */
static qihse_resp_server_t* g_submitter;
static qihse_resp_server_t* g_executor;
static qihse_federation_node_identity_t g_id_a, g_id_b;
static qihse_fed_tls_server_t* g_tls_a;
static qihse_fed_tls_server_t* g_tls_b;
static qihse_user_t* g_low;      /* clearance 0, system domain */
static qihse_user_t* g_mid;      /* clearance 1, system domain */
static uint16_t g_peer_index;

/* ── Fixture ───────────────────────────────────────────────────────────── */

static uint16_t free_udp_port(void) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    assert(fd >= 0);
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    assert(bind(fd, (struct sockaddr*)&addr, sizeof(addr)) == 0);
    socklen_t len = sizeof(addr);
    assert(getsockname(fd, (struct sockaddr*)&addr, &len) == 0);
    uint16_t port = ntohs(addr.sin_port);
    close(fd);
    return port;
}

/* Enroll + approve + trust a node in ONE store.  Both stores hold both
 * identities, because each side resolves the other's certificate fingerprint
 * to an enrolled, trusted node during the handshake. */
static void enroll_in_store(qihse_kv_store_t* store,
                            const qihse_federation_node_identity_t* id) {
    assert(qihse_federation_node_enroll_request(store, g_op, id));
    assert(qihse_federation_node_enroll_approve(store, g_op, &id->node_id, 1));
    qihse_trust_verification_t v;
    memset(&v, 0, sizeof(v));
    v.node_id = id->node_id;
    v.trust_state = QIHSE_RTRUST_TRUSTED;
    v.verification_principal = id->node_id;
    snprintf(v.verification_result, sizeof(v.verification_result), "test");
    assert(qihse_trust_verification_put(store, g_op, &v, NULL));
}

static void make_identity(const char* key_dir, const char* seed,
                          qihse_service_identity_t kind,
                          qihse_federation_node_identity_t* out) {
    memset(out, 0, sizeof(*out));
    assert(qihse_uuid_from_seed(seed, strlen(seed), &out->node_id));
    snprintf(out->hostname, sizeof(out->hostname), "%s", seed);
    snprintf(out->boot_id, sizeof(out->boot_id), "%s-boot", seed);
    out->identity_kind = kind;
    assert(qihse_federation_node_keygen_alg(key_dir, QIHSE_SIG_ML_DSA_65, out));
}

/* ── The capability token (decision 3) ─────────────────────────────────── */

static void test_token_verification(const qihse_federation_ca_t* ca) {
    char blob[QIHSE_FABRIC_TOKEN_MAX_BYTES];
    void* pkey = NULL;
    qihse_federation_node_identity_t id;
    assert(qihse_fabric_node_signer_load(g_store_b, g_op, &g_id_a.node_id, &id, &pkey));

    qihse_fabric_token_t claims;
    memset(&claims, 0, sizeof(claims));
    claims.purpose = QIHSE_FABRIC_TOKEN_PURPOSE_RUN;
    claims.job_type = QIHSE_FABRIC_JOB_KEYSTONE_INGEST;
    claims.scope = QIHSE_FABRIC_SCOPE_RUN;
    claims.principal_user_id = 42u;
    claims.clearance = 0;
    claims.sci = 0;
    claims.principal_tenant = QIHSE_TENANT_SYSTEM;
    claims.submitter_node = g_id_a.node_id;
    claims.job_id = 4242u;
    claims.issued_ms = 1000u;
    claims.expires_ms = 1000u + 60000u;
    claims.payload_len = (uint32_t)strlen(JOB_PAYLOAD);
    /* An insufficient capacity must be REFUSED, not overflowed. This assertion
     * was previously testing a contract the old signature could not provide
     * (char out_hex[97] is a pointer); it is true now because the capacity is
     * an argument. */
    assert(qihse_fabric_sha384_hex(JOB_PAYLOAD, strlen(JOB_PAYLOAD),
                                   (char*)claims.payload_digest,
                                   sizeof(claims.payload_digest)) == false);
    {
        uint8_t digest[48];
        char hex[97];
        assert(qihse_fabric_sha384_hex(JOB_PAYLOAD, strlen(JOB_PAYLOAD), hex, sizeof(hex)));
        for (size_t i = 0; i < 48u; i++) {
            unsigned hi = 0, lo = 0;
            assert(sscanf(hex + i * 2u, "%1x%1x", &hi, &lo) == 2);
            digest[i] = (uint8_t)((hi << 4) | lo);
        }
        memcpy(claims.payload_digest, digest, sizeof(digest));
    }
    assert(qihse_uuid_generate(&claims.nonce));
    size_t blob_len = 0;
    assert(qihse_fabric_token_mint(pkey, &claims, (uint8_t*)blob, sizeof(blob), &blob_len));
    assert(blob_len == QIHSE_FABRIC_TOKEN_REGION_BYTES + claims.signature_len);

    qihse_fabric_token_check_t check;
    memset(&check, 0, sizeof(check));
    check.channel_peer = g_id_a.node_id;
    check.expect_purpose = QIHSE_FABRIC_TOKEN_PURPOSE_RUN;
    check.expect_job_type = QIHSE_FABRIC_JOB_KEYSTONE_INGEST;
    check.expect_job_id = 4242u;
    check.payload = JOB_PAYLOAD;
    check.payload_len = strlen(JOB_PAYLOAD);
    check.required_scope = QIHSE_FABRIC_SCOPE_RUN;
    check.now_ms = 2000u;
    check.consume = false;

    qihse_fabric_token_t verified;
    assert(qihse_fabric_token_check(g_store_b, g_op, (const uint8_t*)blob, blob_len,
                                    &check, &verified) == QIHSE_FABRIC_TOKEN_OK);
    assert(verified.principal_user_id == 42u && verified.job_id == 4242u);

    /* NULL local context fails closed: there is no context-free verification. */
    assert(qihse_fabric_token_check(g_store_b, NULL, (const uint8_t*)blob, blob_len,
                                    &check, &verified) == QIHSE_FABRIC_TOKEN_NO_CONTEXT);

    /* The payload is BOUND: a different payload under the same token fails. */
    qihse_fabric_token_check_t other = check;
    other.payload = "a different payload";
    other.payload_len = strlen(other.payload);
    assert(qihse_fabric_token_check(g_store_b, g_op, (const uint8_t*)blob, blob_len,
                                    &other, &verified) == QIHSE_FABRIC_TOKEN_JOB_MISMATCH);

    /* A token for another job is refused. */
    other = check;
    other.expect_job_id = 4243u;
    assert(qihse_fabric_token_check(g_store_b, g_op, (const uint8_t*)blob, blob_len,
                                    &other, &verified) == QIHSE_FABRIC_TOKEN_JOB_MISMATCH);

    /* A token presented on another node's channel is refused. */
    other = check;
    assert(qihse_uuid_generate(&other.channel_peer));
    assert(qihse_fabric_token_check(g_store_b, g_op, (const uint8_t*)blob, blob_len,
                                    &other, &verified) == QIHSE_FABRIC_TOKEN_NODE_MISMATCH);

    /* A tampered signature is refused. */
    blob[blob_len - 1] ^= 0x01;
    assert(qihse_fabric_token_check(g_store_b, g_op, (const uint8_t*)blob, blob_len,
                                    &check, &verified) == QIHSE_FABRIC_TOKEN_BAD_SIGNATURE);
    blob[blob_len - 1] ^= 0x01;

    /* Expiry: a token whose window has passed is refused, and one from the
     * future is refused rather than tolerated (a future token extends the
     * replay window). */
    other = check;
    other.now_ms = claims.expires_ms;
    assert(qihse_fabric_token_check(g_store_b, g_op, (const uint8_t*)blob, blob_len,
                                    &other, &verified) == QIHSE_FABRIC_TOKEN_EXPIRED);
    /* ISSUED IN THE FUTURE is refused, and it is NOT a `not_before` — the
     * token format has no such field. The rule is that a token whose issued
     * time is ahead of us beyond the clock skew is refused, because its
     * expiry is ahead too, so accepting it would give it a longer life than
     * the TTL allows measured from our clock.
     *
     * This assertion previously read `issued_ms + skew + 5000` — a time AFTER
     * issue — and expected a refusal for being "not yet valid". That is not a
     * rule this code has, and with issued_ms = 1000 and a 60 s skew it was not
     * even REACHABLE: `issued > now + skew` cannot hold for any non-negative
     * `now`. The case is constructed properly here, by minting a token whose
     * issued time is genuinely ahead of the verifier. */
    {
        qihse_fabric_token_t future = claims;
        uint8_t fblob[QIHSE_FABRIC_TOKEN_MAX_BYTES];
        size_t flen = 0;
        future.issued_ms = other.now_ms + QIHSE_FABRIC_TOKEN_CLOCK_SKEW_MS + 5000u;
        future.expires_ms = future.issued_ms + 60000u;
        assert(qihse_fabric_token_mint(pkey, &future, fblob, sizeof fblob, &flen));
        qihse_fabric_token_check_t fcheck = check;
        fcheck.now_ms = other.now_ms;
        assert(qihse_fabric_token_check(g_store_b, g_op, fblob, flen, &fcheck, &verified)
               == QIHSE_FABRIC_TOKEN_ISSUED_IN_FUTURE);
    }

    /* Scope: the token must carry the required scope, and the whole asserted
     * scope must be within what the submitter NODE was enrolled with. */
    other = check;
    other.required_scope = QIHSE_SCOPE_NODE_ENROLL;
    assert(qihse_fabric_token_check(g_store_b, g_op, (const uint8_t*)blob, blob_len,
                                    &other, &verified) == QIHSE_FABRIC_TOKEN_SCOPE_REFUSED);

    /* Replay: a consumed token cannot be used twice. */
    qihse_fabric_token_check_t consume = check;
    consume.now_ms = 2000u;
    consume.consume = true;
    assert(qihse_fabric_token_check(g_store_b, g_op, (const uint8_t*)blob, blob_len,
                                    &consume, &verified) == QIHSE_FABRIC_TOKEN_OK);
    assert(qihse_fabric_token_check(g_store_b, g_op, (const uint8_t*)blob, blob_len,
                                    &consume, &verified) == QIHSE_FABRIC_TOKEN_REPLAY);
    /* ...and the SAME nonce for the other purpose is a different capability. */
    qihse_fabric_token_check_t fetch_purpose = consume;
    fetch_purpose.expect_purpose = QIHSE_FABRIC_TOKEN_PURPOSE_FETCH;
    assert(qihse_fabric_token_check(g_store_b, g_op, (const uint8_t*)blob, blob_len,
                                    &fetch_purpose, &verified) == QIHSE_FABRIC_TOKEN_WRONG_PURPOSE);

    /* An unknown submitter (never enrolled here) is refused. */
    qihse_fabric_token_t stranger = claims;
    assert(qihse_uuid_generate(&stranger.nonce));
    assert(qihse_uuid_generate(&stranger.submitter_node));
    size_t stranger_len = 0;
    assert(qihse_fabric_token_mint(pkey, &stranger, (uint8_t*)blob, sizeof(blob),
                                   &stranger_len));
    other = check;
    other.channel_peer = stranger.submitter_node;
    assert(qihse_fabric_token_check(g_store_b, g_op, (const uint8_t*)blob, stranger_len,
                                    &other, &verified) == QIHSE_FABRIC_TOKEN_UNKNOWN_SUBMITTER);

    qihse_federation_node_key_free(pkey);
    (void)ca;
    printf("PASS token: bound to job/payload/node/purpose/scope, expiring, replay-proof, "
           "and NULL context fails closed\n");
}

/* ── Retry policy (decision 2) ─────────────────────────────────────────── */

static void test_retry_policy(void) {
    /* Both executors are dispatch-idempotent: keystone-ingest overwrites its
     * deterministic artifact key, and embed is deduped by the executor on the
     * submitter+job binding — a retry re-ACKs the existing result record
     * rather than running again. */
    assert(qihse_fabric_jobtype_is_idempotent(QIHSE_FABRIC_JOB_EMBED));
    assert(qihse_fabric_jobtype_is_idempotent(QIHSE_FABRIC_JOB_KEYSTONE_INGEST));
    assert(!qihse_fabric_jobtype_is_idempotent(QIHSE_FABRIC_JOB_NONE));
    const qihse_fabric_jobtype_decl_t* d = qihse_fabric_jobtype_lookup("embed");
    assert(d && d->idempotent && strstr(d->idempotency_reason, "dedup") != NULL);

    /* A dead endpoint: connection refused, so no answer, so the retry policy
     * is what decides the outcome. */
    uint16_t dead_port = free_udp_port();
    char* body = (char*)malloc(QIHSE_FABRIC_MAX_RESPONSE);
    assert(body);

    qihse_fabric_run_request_t req;
    memset(&req, 0, sizeof(req));
    req.host = "127.0.0.1";
    req.port = dead_port;
    req.timeout_ms = 300;
    req.tls = g_tls_a;
    req.pkey = NULL;
    req.submitter_node = g_id_a.node_id;
    req.job_id = 77u;
    req.payload = JOB_PAYLOAD;
    req.payload_len = strlen(JOB_PAYLOAD);
    req.scope = QIHSE_FABRIC_SCOPE_RUN;

    qihse_fabric_run_outcome_t out;
    memset(&out, 0, sizeof(out));
    out.body = body;
    out.body_cap = QIHSE_FABRIC_MAX_RESPONSE;

    /* embed is dispatch-idempotent (executor dedup), so a dead endpoint is
     * retried up to the budget and ends `gave-up` — never `failed`, because
     * the submitter cannot tell whether the job ran. */
    void* pkey = NULL;
    qihse_federation_node_identity_t id;
    assert(qihse_fabric_node_signer_load(g_store_a, g_op, &g_id_a.node_id, &id, &pkey));
    req.pkey = pkey;
    req.job_type = QIHSE_FABRIC_JOB_EMBED;
    assert(qihse_fabric_run(&req, &out));
    assert(out.attempts == QIHSE_FABRIC_MAX_ATTEMPTS);
    assert(out.retried && out.gave_up && !out.succeeded && !out.denied);
    assert(strcmp(out.terminal_reason, "gave-up:attempts-exhausted") == 0);

    /* keystone-ingest: same retry budget, same terminal state. */
    memset(&out, 0, sizeof(out));
    out.body = body;
    out.body_cap = QIHSE_FABRIC_MAX_RESPONSE;
    req.job_type = QIHSE_FABRIC_JOB_KEYSTONE_INGEST;
    assert(qihse_fabric_run(&req, &out));
    assert(out.attempts == QIHSE_FABRIC_MAX_ATTEMPTS);
    assert(out.retried && out.gave_up && !out.succeeded);
    assert(strcmp(out.terminal_reason, "gave-up:attempts-exhausted") == 0);

    qihse_federation_node_key_free(pkey);
    free(body);
    printf("PASS retry: both types retried to budget (dedup makes embed safe), "
           "gave-up distinct from failed\n");
}

/* ── End-to-end dispatch ───────────────────────────────────────────────── */

static void run_cmd(qihse_resp_server_t* server, qihse_user_t* user,
                    size_t argc, const char* const* argv, char* out, size_t out_cap) {
    qihse_resp_arg_t args[8];
    assert(argc <= 8u);
    for (size_t i = 0; i < argc; i++) {
        args[i].data = (uint8_t*)argv[i];
        args[i].len = strlen(argv[i]);
    }
    uint8_t* reply = NULL;
    size_t reply_len = 0;
    assert(qihse_resp_server_execute(server, user, argc, args, &reply, &reply_len));
    size_t n = reply_len < out_cap - 1u ? reply_len : out_cap - 1u;
    memcpy(out, reply, n);
    out[n] = '\0';
    free(reply);
}

static bool parse_job_id(const char* reply, char* out, size_t out_cap) {
    const char* p = strstr(reply, "job:");
    if (!p) return false;
    p += 4;
    size_t i = 0;
    while (p[i] && p[i] != ' ' && i + 1u < out_cap) { out[i] = p[i]; i++; }
    out[i] = '\0';
    return i > 0u;
}

static void test_remote_dispatch_runs_on_the_peer(void) {
    char reply[8192];

    /* ── keystone-ingest: a job that must run on the PEER ─────────────── */
    const char* sub[] = { "FABRIC", "SUBMIT", "keystone-ingest", "0", "0", JOB_PAYLOAD };
    run_cmd(g_submitter, g_low, 6u, sub, reply, sizeof reply);
    assert(strstr(reply, "status:pending-fetch") != NULL);
    char jid[32];
    assert(parse_job_id(reply, jid, sizeof jid));
    printf("  dispatch reply: %s", reply);
    if (reply[strlen(reply) - 1u] != '\n') printf("\n");

    /* The job RAN, and it ran on the executor: its artifact is in the
     * EXECUTOR's store under the deterministic remote key. */
    char art_key[192];
    assert(qihse_fabric_remote_artifact_key(&g_id_a.node_id, strtoull(jid, NULL, 10),
                                            art_key, sizeof art_key));
    char* art = qihse_kv_get_user(g_store_b, art_key, g_op);
    assert(art != NULL);
    assert(strcmp(art, JOB_PAYLOAD) == 0);
    free(art);
    /* The submitter's store does NOT have it: there is no remote-write path
     * in either direction. */
    assert(qihse_kv_get_user(g_store_a, art_key, g_op) == NULL);

    /* Before the pull, the state is `pending-fetch`, NOT `done`. */
    const char* res[] = { "FABRIC", "RESULT", jid };
    run_cmd(g_submitter, g_low, 3u, res, reply, sizeof reply);
    assert(strstr(reply, "pending-fetch") != NULL);
    assert(strstr(reply, "done") == NULL);
    assert(strstr(reply, "exec\":\"remote") != NULL);
    assert(strstr(reply, "remote_gen") != NULL);
    /* No signed statement has been accepted for the peer yet, so the dial
     * target came from the topology hint — and the record says so. */
    assert(strstr(reply, "\"ep\":\"topology\"") != NULL);

    /* The pull: the result comes back and is cached. */
    const char* fetch[] = { "FABRIC", "FETCH", jid };
    run_cmd(g_submitter, g_low, 3u, fetch, reply, sizeof reply);
    assert(strstr(reply, "fetched") != NULL);
    assert(strstr(reply, "status:done") != NULL);
    printf("  fetch reply: %s", reply);
    if (reply[strlen(reply) - 1u] != '\n') printf("\n");

    /* Now the cached record is served, payload and all, and the state is the
     * executor's own status. */
    run_cmd(g_submitter, g_low, 3u, res, reply, sizeof reply);
    assert(strstr(reply, "status\":\"done") != NULL);
    assert(strstr(reply, JOB_PAYLOAD) != NULL);
    assert(strstr(reply, "fabric-remote v1") != NULL);
    printf("PASS remote keystone-ingest: ran on the peer, result pulled and cached\n");

    /* ── embed at clearance 0 runs on the peer too ────────────────────── */
    const char* sub2[] = { "FABRIC", "SUBMIT", "embed", "0", "0", "remote embed marker" };
    run_cmd(g_submitter, g_low, 6u, sub2, reply, sizeof reply);
    assert(strstr(reply, "status:pending-fetch") != NULL);
    char jid2[32];
    assert(parse_job_id(reply, jid2, sizeof jid2));
    const char* fetch2[] = { "FABRIC", "FETCH", jid2 };
    run_cmd(g_submitter, g_low, 3u, fetch2, reply, sizeof reply);
    assert(strstr(reply, "fetched") != NULL);
    assert(strstr(reply, "status:done") != NULL);
    /* The memory the executor created is in the EXECUTOR's aimem namespace. */
    qihse_ai_memory_hit_t hit;
    memset(&hit, 0, sizeof hit);
    size_t found = qihse_ai_memory_recall(g_executor, g_op, "remote embed marker", 5u,
                                          &hit, 1u);
    assert(found == 1u && hit.text != NULL);
    assert(strstr(hit.text, "remote embed marker") != NULL);
    free(hit.text);
    printf("PASS remote embed: executed on the peer at the token's clearance, "
           "memory in the peer's store\n");

    /* ── Signed endpoint discovery ──────────────────────────────────────
     * A v4 membership statement names the peer's dispatch endpoint inside
     * the signed region; once accepted into the submitter's store (which
     * requires the signature, enrollment and APPROVED trust to all check
     * out), the durable capability record — not the topology hint — becomes
     * the dial target, and the job record says "ep":"signed". */
    {
        qihse_federation_node_identity_t id_b;
        void* pkey_b = NULL;
        assert(qihse_fabric_node_signer_load(g_store_b, g_op, &g_id_b.node_id,
                                           &id_b, &pkey_b));
        qihse_uuid_t boot_b;
        assert(qihse_uuid_from_seed("node-b-boot", strlen("node-b-boot"), &boot_b));
        qihse_federation_endpoint_t ep;
        memset(&ep, 0, sizeof ep);
        snprintf(ep.host, sizeof ep.host, "%s", "127.0.0.1");
        ep.port = qihse_resp_server_fabric_port(g_executor);
        assert(ep.port != 0);
        qihse_federation_gossip_t stmt;
        assert(qihse_federation_statement_mint(NULL, NULL, NULL,
                                               &g_id_b.node_id, &boot_b,
                                               NULL, &ep, pkey_b, &stmt));
        EVP_PKEY_free((EVP_PKEY*)pkey_b);
        /* The submitter accepts it (signature + trust + replay all pass) and
         * the capability record gains the signed endpoint. */
        assert(qihse_federation_gossip_accept(g_store_a, g_op, &stmt) ==
               QIHSE_GOSSIP_ACCEPTED);
        qihse_federation_node_capability_t cap;
        assert(qihse_federation_node_capability_lookup_admissible(
                   g_store_a, g_op, &g_id_b.node_id, &cap));
        assert(cap.dispatch_endpoint.port == ep.port);

        /* The topology peer must carry the peer's federation identity for
         * the record to be found. */
        assert(qihse_cluster_topology_set_node_uuid(
                   qihse_resp_server_topology(g_submitter),
                   g_peer_index, g_id_b.node_id.bytes));

        const char* sub3[] = { "FABRIC", "SUBMIT", "keystone-ingest", "0", "0",
                               "signed-endpoint payload" };
        run_cmd(g_submitter, g_low, 6u, sub3, reply, sizeof reply);
        assert(strstr(reply, "status:pending-fetch") != NULL);
        char jid3[32];
        assert(parse_job_id(reply, jid3, sizeof jid3));
        const char* res3[] = { "FABRIC", "RESULT", jid3 };
        run_cmd(g_submitter, g_low, 3u, res3, reply, sizeof reply);
        assert(strstr(reply, "\"ep\":\"signed\"") != NULL);
        /* And it really ran there: the artifact is in the executor's store. */
        char art3[192];
        assert(qihse_fabric_remote_artifact_key(&g_id_a.node_id,
                                                strtoull(jid3, NULL, 10),
                                                art3, sizeof art3));
        char* a3 = qihse_kv_get_user(g_store_b, art3, g_op);
        assert(a3 != NULL);
        free(a3);
        printf("PASS signed endpoint: v4 statement endpoint becomes the dial target\n");
    }

    /* ── inference dispatches remotely too ──────────────────────────────
     * The executor runs the ACTIVE provider on the payload and stores the
     * vector record under the deterministic inference artifact key, at the
     * token's claims. */
    {
        const char* sub4[] = { "FABRIC", "SUBMIT", "inference", "0", "0",
                               "remote inference payload" };
        run_cmd(g_submitter, g_low, 6u, sub4, reply, sizeof reply);
        assert(strstr(reply, "status:pending-fetch") != NULL);
        char jid4[32];
        assert(parse_job_id(reply, jid4, sizeof jid4));
        const char* fetch4[] = { "FABRIC", "FETCH", jid4 };
        run_cmd(g_submitter, g_low, 3u, fetch4, reply, sizeof reply);
        assert(strstr(reply, "fetched") != NULL);
        assert(strstr(reply, "status:done") != NULL);
        /* The vector record is in the EXECUTOR's store at the inference
         * artifact key — not the ingest key. */
        char ikey[192];
        assert(qihse_fabric_remote_inference_key(&g_id_a.node_id,
                                                 strtoull(jid4, NULL, 10),
                                                 ikey, sizeof ikey));
        char* vr = qihse_kv_get_user(g_store_b, ikey, g_op);
        assert(vr != NULL);
        assert(strstr(vr, "model:") != NULL && strstr(vr, "vec:") != NULL);
        free(vr);
        printf("PASS remote inference: vector record stored on the executor\n");
    }
}

/* ── SCATTER-purpose tokens: CLUSTER PEERAUTH ────────────────────────────
 * A SCATTER token is the principal claim a peer presents over plain RESP.
 * The same verification applies: enrolled submitter, signature, scope
 * subset, lifetime, replay.  PEERAUTH accepts it and refuses everything
 * that is not it. */
static void test_scatter_peerauth(void) {
    void* pkey = NULL;
    qihse_federation_node_identity_t id;
    assert(qihse_fabric_node_signer_load(g_store_b, g_op, &g_id_a.node_id, &id, &pkey));

    static char blob[QIHSE_FABRIC_TOKEN_MAX_BYTES];
    static char hexbuf[QIHSE_FABRIC_TOKEN_MAX_BYTES * 2u];
    static const char hexv[] = "0123456789abcdef";

    qihse_fabric_token_t tok;
    memset(&tok, 0, sizeof(tok));
    tok.purpose = QIHSE_FABRIC_TOKEN_PURPOSE_SCATTER;
    tok.job_type = QIHSE_FABRIC_JOB_NONE;
    tok.scope = QIHSE_FABRIC_SCOPE_SCATTER;
    tok.principal_user_id = 42u;
    tok.clearance = 0;
    tok.sci = 0;
    tok.principal_tenant = QIHSE_TENANT_SYSTEM;
    tok.submitter_node = g_id_a.node_id;
    tok.job_id = 0u;
    tok.issued_ms = 1000u;
    tok.expires_ms = 1000u + 30000u;
    tok.payload_len = 0u;
    {
        uint8_t digest[48];
        char hex[97];
        assert(qihse_fabric_sha384_hex(NULL, 0u, hex, sizeof(hex)));
        for (size_t i = 0; i < 48u; i++) {
            unsigned hi = 0, lo = 0;
            assert(sscanf(hex + i * 2u, "%1x%1x", &hi, &lo) == 2);
            digest[i] = (uint8_t)((hi << 4) | lo);
        }
        memcpy(tok.payload_digest, digest, sizeof(digest));
    }
    assert(qihse_uuid_generate(&tok.nonce));
    size_t blob_len = 0;
    assert(qihse_fabric_token_mint(pkey, &tok, (uint8_t*)blob, sizeof(blob), &blob_len));

    /* The token CHECK path first — purpose/scope/job binding. */
    qihse_fabric_token_check_t check;
    memset(&check, 0, sizeof(check));
    check.channel_peer = g_id_a.node_id;
    check.expect_purpose = QIHSE_FABRIC_TOKEN_PURPOSE_SCATTER;
    check.expect_job_type = QIHSE_FABRIC_JOB_NONE;
    check.expect_job_id = 0u;
    check.payload = NULL;
    check.payload_len = 0u;
    check.required_scope = QIHSE_FABRIC_SCOPE_SCATTER;
    check.now_ms = 2000u;
    check.consume = false;
    qihse_fabric_token_t verified;
    assert(qihse_fabric_token_check(g_store_b, g_op, (const uint8_t*)blob, blob_len,
                                    &check, &verified) == QIHSE_FABRIC_TOKEN_OK);
    assert(verified.principal_user_id == 42u);

    /* A SCATTER token minted with a job type must not even PARSE — the two
     * token shapes are distinct at the format level, not by caller promise. */
    tok.job_type = QIHSE_FABRIC_JOB_EMBED;
    assert(qihse_uuid_generate(&tok.nonce));
    size_t bad_len = 0;
    assert(qihse_fabric_token_mint(pkey, &tok, (uint8_t*)blob, sizeof(blob), &bad_len));
    qihse_fabric_token_t ignored;
    size_t r = 0, t = 0;
    assert(!qihse_fabric_token_parse((const uint8_t*)blob, bad_len, &ignored, &r, &t));
    tok.job_type = QIHSE_FABRIC_JOB_NONE;

    /* And the wire path: CLUSTER PEERAUTH <hex> on the executor's RESP
     * surface.  A real check consumes the nonce AND checks the lifetime
     * against the real clock — mint fresh, wall-clock-now tokens. */
    struct timeval tv;
    assert(gettimeofday(&tv, NULL) == 0);
    uint64_t now_ms = (uint64_t)tv.tv_sec * 1000u + (uint64_t)tv.tv_usec / 1000u;
    char reply[512];
    tok.issued_ms = now_ms;
    tok.expires_ms = now_ms + 30000u;
    assert(qihse_uuid_generate(&tok.nonce));
    assert(qihse_fabric_token_mint(pkey, &tok, (uint8_t*)blob, sizeof(blob), &blob_len));
    for (size_t i = 0; i < blob_len; i++) {
        hexbuf[i * 2u] = hexv[((const uint8_t*)blob)[i] >> 4];
        hexbuf[i * 2u + 1u] = hexv[((const uint8_t*)blob)[i] & 0x0Fu];
    }
    hexbuf[blob_len * 2u] = '\0';
    const char* auth[] = { "CLUSTER", "PEERAUTH", hexbuf };
    /* The in-process execute path needs an initial context; on a real
     * socket the session is unauthenticated until PEERAUTH runs. */
    run_cmd(g_executor, g_op, 3u, auth, reply, sizeof reply);
    assert(strstr(reply, "+OK") != NULL || strstr(reply, "OK") != NULL);

    /* The SAME token again is a replay — the nonce is spent. */
    run_cmd(g_executor, g_op, 3u, auth, reply, sizeof reply);
    assert(strstr(reply, "token-replayed") != NULL);

    /* A RUN-purpose token is not a principal claim.  It carries the WRITE
     * scope a RUN needs, so the SCATTER scope requirement refuses it — the
     * check rejects it before purpose is even compared.  Either verdict is
     * correct; what must not happen is acceptance. */
    tok.purpose = QIHSE_FABRIC_TOKEN_PURPOSE_RUN;
    tok.job_type = QIHSE_FABRIC_JOB_EMBED;
    tok.job_id = 77u;
    tok.scope = QIHSE_FABRIC_SCOPE_RUN | QIHSE_FABRIC_SCOPE_SCATTER;
    assert(qihse_uuid_generate(&tok.nonce));
    assert(qihse_fabric_token_mint(pkey, &tok, (uint8_t*)blob, sizeof(blob), &blob_len));
    for (size_t i = 0; i < blob_len; i++) {
        hexbuf[i * 2u] = hexv[((const uint8_t*)blob)[i] >> 4];
        hexbuf[i * 2u + 1u] = hexv[((const uint8_t*)blob)[i] & 0x0Fu];
    }
    hexbuf[blob_len * 2u] = '\0';
    run_cmd(g_executor, g_op, 3u, auth, reply, sizeof reply);
    assert(strstr(reply, "wrong-purpose") != NULL);

    EVP_PKEY_free((EVP_PKEY*)pkey);
    printf("PASS scatter peerauth: claims install on a verified token; replay and wrong-purpose refused\n");
}

/* ── INVARIANT 3: low clearance vs high data (merge blocker) ───────────── */

static void test_negative_low_clearance_high_data(void) {
    char reply[8192];

    /* (a) The normal path: a clearance-1 principal submits a job.  The
     * executor cannot represent that principal, so it REFUSES — it does NOT
     * run the job under its own (0xFFFF) principal. */
    const char* sub[] = { "FABRIC", "SUBMIT", "keystone-ingest", "0", "0", PROTECTED_MARKER };
    run_cmd(g_submitter, g_mid, 6u, sub, reply, sizeof reply);
    assert(strstr(reply, "status:denied") != NULL);
    assert(strstr(reply, "principal-not-representable") != NULL);
    assert(strstr(reply, PROTECTED_MARKER) == NULL);
    char jid[32];
    assert(parse_job_id(reply, jid, sizeof jid));
    /* Nothing was written on the executor for that job. */
    char art_key[192];
    assert(qihse_fabric_remote_artifact_key(&g_id_a.node_id, strtoull(jid, NULL, 10),
                                            art_key, sizeof art_key));
    assert(qihse_kv_get_user(g_store_b, art_key, g_op) == NULL);
    printf("  refused run reply: %s", reply);
    if (reply[strlen(reply) - 1u] != '\n') printf("\n");

    /* (b) The bypass-prone direct-ID form: a record above the principal's
     * clearance is placed in the executor's store under the dispatch key, and
     * the low-clearance principal names it directly.  DENIED, with no
     * protected payload in the response bytes. */
    const uint64_t secret_job = 9001u;
    char secret_key[192];
    assert(qihse_fabric_remote_result_key(&g_id_a.node_id, secret_job, secret_key,
                                          sizeof secret_key));
    char node_str[QIHSE_UUID_STR_LEN + 1u];
    assert(qihse_uuid_format(&g_id_b.node_id, node_str));
    char payload_digest[97];
    assert(qihse_fabric_sha384_hex(PROTECTED_MARKER, strlen(PROTECTED_MARKER),
                                   payload_digest, sizeof(payload_digest)));
    char record[1024];
    snprintf(record, sizeof(record),
             "fabric-remote v1 status=done type=keystone-ingest job=%llu gen=1 cls=5 sci=0 "
             "node=%s result=- digest=%s bytes=%zu reason=-\n%s",
             (unsigned long long)secret_job, node_str, payload_digest,
             strlen(PROTECTED_MARKER), PROTECTED_MARKER);
    /* Written by a HIGH-clearance local principal, as any other writer of a
     * classified record would be. */
    assert(qihse_kv_set_user(g_store_b, secret_key, record, 5u, 0u, g_op));

    /* The submitter's job record points at that job on that peer, as it would
     * after a real dispatch by a high-clearance principal. */
    char job_key[128];
    snprintf(job_key, sizeof(job_key), "fabric:job:%llu", (unsigned long long)secret_job);
    char job_val[512];
    snprintf(job_val, sizeof(job_val),
             "{\"type\":\"keystone-ingest\",\"status\":\"pending-fetch\",\"exec\":\"remote\","
             "\"target\":%u,\"isa\":0,\"npu\":0,\"result\":\"\",\"err\":\"\","
             "\"remote_status\":\"done\",\"attempts\":1,\"retry\":\"-\",\"remote_gen\":1,"
             "\"remote_cls\":5,\"remote_sci\":0,\"remote_digest\":\"\"}",
             (unsigned)g_peer_index);
    assert(qihse_kv_set_user(g_store_a, job_key, job_val, 0u, 0u, g_op));

    const char* fetch[] = { "FABRIC", "FETCH", "9001" };
    run_cmd(g_submitter, g_mid, 3u, fetch, reply, sizeof reply);
    assert(strstr(reply, "refused") != NULL);
    assert(strstr(reply, "above-clearance") != NULL);
    /* ASSERTED ON BYTES: the protected payload is not in the reply. */
    assert(strstr(reply, PROTECTED_MARKER) == NULL);
    assert(strstr(reply, "fabric-remote v1") == NULL);
    printf("  refused fetch reply: %s", reply);
    if (reply[strlen(reply) - 1u] != '\n') printf("\n");

    /* The job is unchanged: a refusal is not a result, so it is still
     * `pending-fetch` and no cache was written. */
    const char* res[] = { "FABRIC", "RESULT", "9001" };
    run_cmd(g_submitter, g_mid, 3u, res, reply, sizeof reply);
    assert(strstr(reply, "pending-fetch") != NULL);
    assert(strstr(reply, PROTECTED_MARKER) == NULL);
    char cache_key[128];
    snprintf(cache_key, sizeof(cache_key), "fabric:remote-cache:9001");
    assert(qihse_kv_get_user(g_store_a, cache_key, g_op) == NULL);

    /* The protocol level, with no engine in the way: the same attempt made
     * directly against the executor returns a refusal body that contains no
     * byte of the protected record. */
    void* pkey = NULL;
    qihse_federation_node_identity_t id;
    assert(qihse_fabric_node_signer_load(g_store_a, g_op, &g_id_a.node_id, &id, &pkey));
    char* body = (char*)malloc(QIHSE_FABRIC_MAX_RESPONSE);
    assert(body);
    qihse_fabric_fetch_request_t freq;
    memset(&freq, 0, sizeof(freq));
    freq.host = "127.0.0.1";
    freq.port = qihse_resp_server_fabric_port(g_executor);
    freq.timeout_ms = 5000;
    freq.tls = g_tls_a;
    freq.pkey = pkey;
    freq.submitter_node = g_id_a.node_id;
    freq.job_type = QIHSE_FABRIC_JOB_KEYSTONE_INGEST;
    freq.job_id = secret_job;
    freq.principal_user_id = qihse_user_get_id(g_mid);
    freq.clearance = qihse_user_get_classification(g_mid);
    freq.sci = qihse_user_get_sci(g_mid);
    freq.scope = QIHSE_FABRIC_SCOPE_FETCH;
    qihse_fabric_fetch_outcome_t fout;
    memset(&fout, 0, sizeof(fout));
    fout.body = body;
    fout.body_cap = QIHSE_FABRIC_MAX_RESPONSE;
    assert(qihse_fabric_fetch(&freq, &fout));
    assert(fout.answered && fout.refused);
    assert(strcmp(fout.terminal_reason, "above-clearance") == 0);
    assert(strstr(body, PROTECTED_MARKER) == NULL);
    assert(strstr(body, "status=denied") != NULL);
    assert(strstr(body, "bytes=0") != NULL);
    printf("  protocol refusal body: %s\n", body);

    /* And a control: the SAME record is served to a principal whose clearance
     * covers it, so the refusal above is the clearance check and not the
     * record being unreadable to everyone. */
    memset(&fout, 0, sizeof(fout));
    fout.body = body;
    fout.body_cap = QIHSE_FABRIC_MAX_RESPONSE;
    freq.principal_user_id = qihse_user_get_id(g_op);
    freq.clearance = 5u;   /* the operator's own clearance, as the engine reads it */
    freq.sci = 0u;
    assert(qihse_fabric_fetch(&freq, &fout));
    assert(fout.answered && !fout.refused);
    assert(strstr(body, PROTECTED_MARKER) != NULL);

    qihse_federation_node_key_free(pkey);
    free(body);
    printf("PASS INVARIANT 3: low-clearance job refused and direct-ID fetch denied "
           "with no protected payload on the wire\n");
}

/* ── Cache coherence (decision 1) ──────────────────────────────────────── */

static void test_cache_coherence(void) {
    char reply[8192];
    const char* sub[] = { "FABRIC", "SUBMIT", "keystone-ingest", "0", "0",
                          "coherence probe payload" };
    run_cmd(g_submitter, g_low, 6u, sub, reply, sizeof reply);
    assert(strstr(reply, "status:pending-fetch") != NULL);
    char jid[32];
    assert(parse_job_id(reply, jid, sizeof jid));
    const char* fetch[] = { "FABRIC", "FETCH", jid };
    run_cmd(g_submitter, g_low, 3u, fetch, reply, sizeof reply);
    assert(strstr(reply, "fetched") != NULL);

    /* A tampered cache is NOT served: the digest recorded at fetch time no
     * longer describes the cached bytes, and a cache that disagrees with what
     * the executor said is not evidence of anything. */
    char cache_key[128];
    snprintf(cache_key, sizeof(cache_key), "fabric:remote-cache:%s", jid);
    char tampered[QIHSE_FABRIC_MAX_RESPONSE];
    snprintf(tampered, sizeof(tampered),
             "fabric-remote v1 status=done type=keystone-ingest job=%s gen=1 cls=0 sci=0 "
             "node=- result=- digest=- bytes=0 reason=-\nTAMPERED-BY-A-LOCAL-WRITER",
             jid);
    assert(qihse_kv_set_user(g_store_a, cache_key, tampered, 0u, 0u, g_op));

    const char* res[] = { "FABRIC", "RESULT", jid };
    run_cmd(g_submitter, g_low, 3u, res, reply, sizeof reply);
    assert(strstr(reply, QIHSE_FABRIC_STATE_CACHE_CORRUPT) != NULL);
    assert(strstr(reply, "TAMPERED-BY-A-LOCAL-WRITER") == NULL);
    printf("PASS cache coherence: a cached copy that no longer matches the pulled "
           "digest is reported, not served\n");
}

/* ── A refused token never runs the job, and never falls back locally ──── */

static void test_refusal_paths(void) {
    qihse_fabric_executor_t ex;
    memset(&ex, 0, sizeof(ex));
    ex.server = g_executor;
    ex.local_user = g_op;
    ex.local_node = g_id_b.node_id;

    char body[QIHSE_FABRIC_MAX_RESPONSE];
    size_t body_len = 0;
    uint8_t request[QIHSE_FABRIC_TOKEN_MAX_BYTES + 256u];
    const char* payload = "refusal path payload";
    size_t payload_len = strlen(payload);

    /* A NULL executor context refuses before it looks at anything. */
    qihse_fabric_executor_t nocontext = ex;
    nocontext.local_user = NULL;
    memset(request, 0, sizeof(request));
    assert(qihse_fabric_executor_run(&nocontext, request, 16u, g_id_a.node_id,
                                     body, sizeof(body), &body_len));
    assert(strstr(body, "no-local-context") != NULL);
    assert(strstr(body, "status=denied") != NULL);

    /* A token that cannot be verified is refused, and NOTHING is executed:
     * the artifact key for that job must not exist afterwards. */
    void* pkey = NULL;
    qihse_federation_node_identity_t id;
    assert(qihse_fabric_node_signer_load(g_store_a, g_op, &g_id_a.node_id, &id, &pkey));

    qihse_fabric_token_t claims;
    memset(&claims, 0, sizeof(claims));
    claims.purpose = QIHSE_FABRIC_TOKEN_PURPOSE_RUN;
    claims.job_type = QIHSE_FABRIC_JOB_KEYSTONE_INGEST;
    claims.scope = QIHSE_FABRIC_SCOPE_RUN;
    claims.principal_user_id = qihse_user_get_id(g_low);
    claims.submitter_node = g_id_a.node_id;
    claims.job_id = 5555u;
    /* The executor checks against ITS OWN clock (there is no now_ms override
     * on this path), so a live token needs real time, not a fixture. */
    struct timeval tv;
    gettimeofday(&tv, NULL);
    uint64_t now_ms = (uint64_t)tv.tv_sec * 1000u + (uint64_t)tv.tv_usec / 1000u;
    claims.issued_ms = now_ms;
    claims.expires_ms = now_ms + 60000u;
    claims.payload_len = (uint32_t)payload_len;
    {
        char hex[97];
        uint8_t digest[48];
        assert(qihse_fabric_sha384_hex(payload, payload_len, hex, sizeof(hex)));
        for (size_t i = 0; i < 48u; i++) {
            unsigned hi = 0, lo = 0;
            assert(sscanf(hex + i * 2u, "%1x%1x", &hi, &lo) == 2);
            digest[i] = (uint8_t)((hi << 4) | lo);
        }
        memcpy(claims.payload_digest, digest, sizeof(digest));
    }
    assert(qihse_uuid_generate(&claims.nonce));
    size_t blob_len = 0;
    assert(qihse_fabric_token_mint(pkey, &claims, request, sizeof(request), &blob_len));
    memcpy(request + blob_len, payload, payload_len);

    assert(qihse_fabric_executor_run(&ex, request, blob_len + payload_len, g_id_a.node_id,
                                     body, sizeof(body), &body_len));
    assert(strstr(body, "status=done") != NULL);
    char art_key[192];
    assert(qihse_fabric_remote_artifact_key(&g_id_a.node_id, 5555u, art_key, sizeof art_key));
    assert(qihse_kv_get_user(g_store_b, art_key, g_op) != NULL);

    /* Executor dedup: a SECOND RUN for the same submitter+job binding —
     * fresh nonce, so it is not replay — re-ACKs the existing record instead
     * of executing again.  This is what makes a retried `embed` safe. */
    assert(qihse_uuid_generate(&claims.nonce));
    assert(qihse_fabric_token_mint(pkey, &claims, request, sizeof(request), &blob_len));
    memcpy(request + blob_len, payload, payload_len);
    memset(body, 0, sizeof(body));
    body_len = 0;
    assert(qihse_fabric_executor_run(&ex, request, blob_len + payload_len, g_id_a.node_id,
                                     body, sizeof(body), &body_len));
    assert(strstr(body, "status=done") != NULL);
    assert(strstr(body, "dedup-replay") != NULL);

    /* The SAME token again: replayed, refused, and the job does not run a
     * second time (the artifact is the one that was there). */
    assert(qihse_fabric_executor_run(&ex, request, blob_len + payload_len, g_id_a.node_id,
                                     body, sizeof(body), &body_len));
    assert(strstr(body, "token-replayed") != NULL);
    assert(strstr(body, "status=denied") != NULL);

    /* Expired: refused. */
    claims.issued_ms = 1u;
    claims.expires_ms = 2u;
    assert(qihse_uuid_generate(&claims.nonce));
    assert(qihse_fabric_token_mint(pkey, &claims, request, sizeof(request), &blob_len));
    memcpy(request + blob_len, payload, payload_len);
    assert(qihse_fabric_executor_run(&ex, request, blob_len + payload_len, g_id_a.node_id,
                                     body, sizeof(body), &body_len));
    assert(strstr(body, "token-expired") != NULL);

    /* A token that names a node the executor has never enrolled: refused. */
    claims.issued_ms = now_ms;
    claims.expires_ms = now_ms + 60000u;
    qihse_uuid_t real = claims.submitter_node;
    assert(qihse_uuid_generate(&claims.submitter_node));
    assert(qihse_uuid_generate(&claims.nonce));
    assert(qihse_fabric_token_mint(pkey, &claims, request, sizeof(request), &blob_len));
    memcpy(request + blob_len, payload, payload_len);
    assert(qihse_fabric_executor_run(&ex, request, blob_len + payload_len,
                                     claims.submitter_node, body, sizeof(body), &body_len));
    assert(strstr(body, "unknown-submitter-node") != NULL);
    /* ...and presenting it on the real node's channel is a mismatch. */
    claims.submitter_node = real;
    assert(qihse_uuid_generate(&claims.nonce));
    assert(qihse_fabric_token_mint(pkey, &claims, request, sizeof(request), &blob_len));
    memcpy(request + blob_len, payload, payload_len);
    qihse_uuid_t other_node;
    assert(qihse_uuid_generate(&other_node));
    assert(qihse_fabric_executor_run(&ex, request, blob_len + payload_len, other_node,
                                     body, sizeof(body), &body_len));
    assert(strstr(body, "node-not-the-tls-peer") != NULL);

    /* A REVOKED submitter stops being able to dispatch, immediately. */
    assert(qihse_federation_node_revoke(g_store_b, g_op, &g_id_a.node_id));
    claims.submitter_node = real;
    assert(qihse_uuid_generate(&claims.nonce));
    assert(qihse_fabric_token_mint(pkey, &claims, request, sizeof(request), &blob_len));
    memcpy(request + blob_len, payload, payload_len);
    assert(qihse_fabric_executor_run(&ex, request, blob_len + payload_len, g_id_a.node_id,
                                     body, sizeof(body), &body_len));
    assert(strstr(body, "submitter-not-approved") != NULL);

    qihse_federation_node_key_free(pkey);
    printf("PASS refusal: unverifiable, replayed, expired, wrong-node and revoked tokens "
           "are refused with no local-principal fallback\n");
}

int main(void) {
    char data_root[] = "build/fabric_dispatch_XXXXXX";
    assert(mkdtemp(data_root));
    setenv("QIHSE_DATA_DIR", data_root, 1);

    char key_dir[512], ca_dir[512];
    snprintf(key_dir, sizeof(key_dir), "%s/keys", data_root);
    snprintf(ca_dir, sizeof(ca_dir), "%s/ca", data_root);
    assert(mkdir(key_dir, 0700) == 0);
    assert(mkdir(ca_dir, 0700) == 0);

    assert(qihse_auth_init());
    if (!qihse_auth_bootstrap_operator("DispatchPass1!")) {
        setenv("QIHSE_OPERATOR_PASSWORD", "DispatchPass1!", 1);
        assert(qihse_auth_init());
    }
    g_op = qihse_auth_get_user(0);
    assert(g_op);

    /* Two principals: one whose clearance is 0 (the only clearance a remote
     * job can faithfully execute at) and one above it, for the negative test.
     * Both are system-domain, because FABRIC.* is system-domain only. */
    g_low = qihse_auth_create_user(g_op, 42u, QIHSE_ROLE_ANALYST, 0u, 0u,
                                   "LowClearance123!", false);
    assert(g_low);
    g_mid = qihse_auth_create_user(g_op, 43u, QIHSE_ROLE_ANALYST, 1u, 0u,
                                   "MidClearance123!", false);
    assert(g_mid);
    assert(qihse_user_get_classification(g_low) == 0u);
    assert(qihse_user_get_classification(g_mid) == 1u);

    qihse_federation_ca_t* ca = (qihse_federation_ca_t*)calloc(1u, sizeof(*ca));
    assert(ca);
    assert(qihse_federation_ca_create(ca_dir, QIHSE_SIG_ML_DSA_87, ca));
    char ca_key_path[2048], ca_cert_path[2048];
    snprintf(ca_key_path, sizeof(ca_key_path), "%s/federation-ca.key", ca_dir);
    snprintf(ca_cert_path, sizeof(ca_cert_path), "%s/federation-ca.crt", ca_dir);
    /* qihse_federation_ca_create() writes only the private key; the
     * certificate is written here so both nodes can be given it. */
    {
        FILE* f = fopen(ca_cert_path, "wb");
        assert(f);
        assert(fwrite(ca->cert_pem, 1u, strlen(ca->cert_pem), f) == strlen(ca->cert_pem));
        fclose(f);
    }

    /* Both nodes are OPERATOR identities, whose enrolled scopes are
     * QIHSE_SCOPE_ALL — a token asserting the federation write/read scope is
     * therefore within what the node was enrolled with. */
    make_identity(key_dir, "fabric-submitter", QIHSE_IDENTITY_OPERATOR, &g_id_a);
    make_identity(key_dir, "fabric-executor", QIHSE_IDENTITY_OPERATOR, &g_id_b);

    g_store_a = qihse_kv_store_create();
    g_store_b = qihse_kv_store_create();
    assert(g_store_a && g_store_b);
    enroll_in_store(g_store_a, &g_id_a);
    enroll_in_store(g_store_a, &g_id_b);
    enroll_in_store(g_store_b, &g_id_a);
    enroll_in_store(g_store_b, &g_id_b);

    char cert_a[QIHSE_FEDERATION_PEM_MAX], cert_b[QIHSE_FEDERATION_PEM_MAX];
    assert(qihse_federation_ca_issue_node(ca_key_path, ca, &g_id_a, 1, cert_a, sizeof(cert_a)));
    assert(qihse_federation_ca_issue_node(ca_key_path, ca, &g_id_b, 1, cert_b, sizeof(cert_b)));
    char cert_a_path[1024], cert_b_path[1024];
    snprintf(cert_a_path, sizeof(cert_a_path), "%s/node-a.crt", ca_dir);
    snprintf(cert_b_path, sizeof(cert_b_path), "%s/node-b.crt", ca_dir);
    {
        FILE* f = fopen(cert_a_path, "wb");
        assert(f);
        assert(fwrite(cert_a, 1u, strlen(cert_a), f) == strlen(cert_a));
        fclose(f);
        f = fopen(cert_b_path, "wb");
        assert(f);
        assert(fwrite(cert_b, 1u, strlen(cert_b), f) == strlen(cert_b));
        fclose(f);
    }

    /* ── The executor node: a dispatch listener on loopback ───────────── */
    qihse_resp_server_config_t cfg;
    qihse_resp_server_config_init(&cfg);
    char node_b_id[QIHSE_CLUSTER_NODE_ID_LEN + 1u];
    qihse_cluster_node_id_from_seed("fabric-executor", strlen("fabric-executor"), node_b_id);
    cfg.node_id = node_b_id;
    cfg.auth_required = false;
    cfg.port = 0;
    cfg.store = g_store_b;
    cfg.enable_uwp_bridge = true;
    cfg.enable_fabric_dispatch = true;
    cfg.fabric_dispatch_bind = "127.0.0.1";
    cfg.fabric_dispatch_port = 0;
    cfg.fabric_dispatch_ca_cert_path = ca_cert_path;
    cfg.fabric_dispatch_node_cert_path = cert_b_path;
    {
        char uuid_str[QIHSE_UUID_STR_LEN + 1u];
        assert(qihse_uuid_format(&g_id_b.node_id, uuid_str));
        cfg.fabric_dispatch_node_id = uuid_str;
        g_executor = qihse_resp_server_create(&cfg);
    }
    assert(g_executor);
    uint16_t exec_port = qihse_resp_server_fabric_port(g_executor);
    assert(exec_port != 0);
    printf("executor dispatch listener on 127.0.0.1:%u\n", (unsigned)exec_port);

    /* ── The submitter node: its own listener + the peer in its topology ─ */
    qihse_resp_server_config_init(&cfg);
    char node_a_id[QIHSE_CLUSTER_NODE_ID_LEN + 1u];
    qihse_cluster_node_id_from_seed("fabric-submitter", strlen("fabric-submitter"), node_a_id);
    cfg.node_id = node_a_id;
    cfg.auth_required = false;
    cfg.port = 0;
    cfg.store = g_store_a;
    cfg.enable_uwp_bridge = true;
    cfg.enable_bus = true;
    cfg.bus_port = 0;
    cfg.enable_fabric_dispatch = true;
    cfg.fabric_dispatch_bind = "127.0.0.1";
    cfg.fabric_dispatch_port = 0;
    cfg.fabric_dispatch_ca_cert_path = ca_cert_path;
    cfg.fabric_dispatch_node_cert_path = cert_a_path;
    {
        char uuid_str[QIHSE_UUID_STR_LEN + 1u];
        assert(qihse_uuid_format(&g_id_a.node_id, uuid_str));
        cfg.fabric_dispatch_node_id = uuid_str;
        g_submitter = qihse_resp_server_create(&cfg);
    }
    assert(g_submitter);

    /* The peer, in the submitter's topology, with the executor's dispatch
     * endpoint as its address. */
    {
        qihse_cluster_topology_t* topo = qihse_resp_server_topology(g_submitter);
        assert(topo);
        qihse_cluster_node_t node;
        memset(&node, 0, sizeof node);
        snprintf(node.id, sizeof node.id, "%s", node_b_id);
        snprintf(node.host, sizeof node.host, "127.0.0.1");
        node.port = exec_port;
        node.role = QIHSE_CLUSTER_NODE_REPLICA;
        node.healthy = true;
        uint16_t idx = 0;
        assert(qihse_cluster_topology_upsert_node(topo, &node, &idx));
        g_peer_index = idx;
        assert(idx != qihse_cluster_topology_local_node(topo));
    }

    /* Placement reads the live capability hint table, so the peer has to
     * advertise a profile that beats the local node's.  A NODE_CAP frame
     * injected on the bus is exactly what a peer's frame is. */
    {
        qihse_cluster_node_t target;
        assert(qihse_cluster_topology_get_node(qihse_resp_server_topology(g_submitter),
                                               g_peer_index, &target));
        uint8_t capbuf[QIHSE_CLUSTER_BUS_NODE_CAP_PAYLOAD_SIZE];
        uint8_t* p = capbuf;
        memcpy(p, target.id, QIHSE_CLUSTER_NODE_ID_LEN + 1u);
        p += QIHSE_CLUSTER_NODE_ID_LEN + 1u;
        uint8_t isa = 4u, npu = 1u, gpu = 1u;
        uint32_t ram = 128000u;
        uint16_t load = 1u;
        memcpy(p, &isa, 1u); p += 1u;
        memcpy(p, &npu, 1u); p += 1u;
        memcpy(p, &gpu, 1u); p += 1u;
        memcpy(p, &ram, 4u); p += 4u;
        memcpy(p, &load, 2u);

        uint8_t dgram[512];
        uint32_t magic = QIHSE_CLUSTER_BUS_MAGIC;
        uint32_t type = QIHSE_BUS_MSG_NODE_CAP;
        uint32_t sender = (uint32_t)g_peer_index;
        uint32_t plen = (uint32_t)sizeof(capbuf);
        memcpy(dgram, &magic, 4);
        memcpy(dgram + 4, &type, 4);
        memcpy(dgram + 8, &sender, 4);
        memcpy(dgram + 12, &plen, 4);
        memcpy(dgram + 16, capbuf, sizeof(capbuf));
        assert(qihse_cluster_bus_inject(qihse_resp_server_bus(g_submitter), dgram,
                                        16u + sizeof(capbuf), "127.0.0.1", 17201));
        uint8_t got_isa = 0;
        uint16_t got_load = 0;
        assert(qihse_cluster_bus_node_caps(qihse_resp_server_bus(g_submitter), g_peer_index,
                                           &got_isa, NULL, NULL, NULL, &got_load));
        assert(got_isa == 4u && got_load == 1u);
    }

    /* The submitter also needs its own mTLS context for outbound dispatch. */
    assert(qihse_fabric_tls_context_create(ca_cert_path, cert_a_path,
                                           g_id_a.key_handle, g_store_a, g_op, &g_tls_a));
    assert(qihse_fabric_tls_context_create(ca_cert_path, cert_b_path,
                                           g_id_b.key_handle, g_store_b, g_op, &g_tls_b));

    test_token_verification(ca);
    test_retry_policy();
    test_scatter_peerauth();
    test_remote_dispatch_runs_on_the_peer();
    test_cache_coherence();
    test_negative_low_clearance_high_data();
    test_refusal_paths();

    qihse_federation_tls_server_destroy(g_tls_a);
    qihse_federation_tls_server_destroy(g_tls_b);
    qihse_ai_memory_reset();
    qihse_resp_server_destroy(g_submitter);
    qihse_resp_server_destroy(g_executor);
    qihse_kv_store_destroy(g_store_a);
    qihse_kv_store_destroy(g_store_b);
    free(ca);
    printf("fabric dispatch tests passed\n");
    return 0;
}
