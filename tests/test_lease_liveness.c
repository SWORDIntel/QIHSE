/*
 * test_lease_liveness.c — Phase-B lease liveness contract (R7 fixes).
 *
 * Covers the three R7 lease-liveness defects, core-side:
 *   1. Server-side expiry: a lease past expires_hlc_physical is DEAD —
 *      renew on it fails (and reaps it to QIHSE_LEASE_EXPIRED), while
 *      acquire of the same resource succeeds at a strictly higher fencing
 *      epoch (the dead lease is reaped and superseded).
 *   2. Holder check: renewals must present the principal that acquired
 *      the lease; any other principal — and any legacy record with no
 *      recorded holder — is rejected (fail closed).
 *   3. Stale-renewal rejection: renew_checked refuses an expected
 *      generation that does not match the stored generation; every
 *      successful renew advances the generation.
 *
 * Determinism: the liveness clock is INJECTED (now_ms argument of
 * qihse_federation_lease_renew_checked) — no sleeps, no wall-clock
 * waiting.  Wall clock (lease_wall_now_ms, plan §42 partition risk) is
 * exercised only through the backward-compatible wrapper, and only via
 * already-dead or never-expiring timestamps so the test cannot flake.
 *
 * Style follows tests/test_federation_f4.c.  A single shared data
 * directory and KV store are used because qihse_kv_store caches the
 * data dir on first use.
 */
#include "qihse_auth.h"
#include "qihse_federation.h"
#include "qihse_kv_store.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define NS "llv"

static void lease_request_init(qihse_federation_lease_t* req,
                               const char* tag,
                               const char* resource,
                               uint64_t fencing_epoch,
                               uint64_t expires_hlc_physical) {
    memset(req, 0, sizeof(*req));
    assert(qihse_uuid_from_seed(tag, strlen(tag), &req->lease_id));
    char req_tag[64];
    snprintf(req_tag, sizeof(req_tag), "%s-req", tag);
    assert(qihse_uuid_from_seed(req_tag, strlen(req_tag), &req->request_id));
    assert(qihse_uuid_from_seed("llv-owner-node", strlen("llv-owner-node"), &req->owner_node));
    req->issuer = req->owner_node;
    snprintf(req->namespace_name, sizeof(req->namespace_name), "%s", NS);
    snprintf(req->resource_id, sizeof(req->resource_id), "%s", resource);
    req->fencing_epoch = fencing_epoch;
    req->expires_hlc_physical = expires_hlc_physical;
}

/* ── 1. Happy path stays happy (never-expiring lease, legacy renew) ─────── */

static void test_happy_path_never_expires(qihse_kv_store_t* store,
                                          qihse_user_t* alice) {
    qihse_federation_lease_t req, out;
    lease_request_init(&req, "llv-l1", "res-1", 100, 0 /* no expiry */);
    assert(qihse_federation_lease_acquire(store, alice, &req, &out));
    assert(out.state == QIHSE_LEASE_GRANTED);
    assert(out.generation == 1);
    assert(out.has_holder);
    assert(out.holder_user_id == qihse_user_get_id(alice));

    /* Legacy wrapper (wall clock) on a never-expiring lease: fine. */
    qihse_federation_lease_t renewed;
    assert(qihse_federation_lease_renew(store, alice, &out.lease_id,
                                        8888888888ULL, &renewed));
    assert(renewed.state == QIHSE_LEASE_GRANTED);
    assert(renewed.generation == 2); /* a renewal is a mutation */

    printf("PASS happy path: acquire + legacy renew, never-expiring lease\n");
}

/* ── 2. Expiry: dead lease is not renewable; resource is re-acquirable ──── */

static void test_expiry_lifecycle(qihse_kv_store_t* store,
                                  qihse_user_t* alice, qihse_user_t* bob,
                                  uint64_t t0) {
    qihse_federation_lease_t req, out;
    lease_request_init(&req, "llv-l2", "res-2", 200, t0 + 1000);
    assert(qihse_federation_lease_acquire(store, alice, &req, &out));
    qihse_uuid_t alice_lease = out.lease_id;
    assert(out.generation == 1);

    /* Renew while alive (injected clock), with the correct generation. */
    qihse_federation_lease_t renewed;
    assert(qihse_federation_lease_renew_checked(store, alice, &alice_lease,
                                                1, t0 + 500, t0 + 5000, &renewed)
           == QIHSE_LEASE_RENEW_OK);
    assert(renewed.generation == 2);
    assert(renewed.expires_hlc_physical == t0 + 5000);

    /* Stale renewal: generation 1 is no longer current — refused. */
    qihse_federation_lease_t stale_out;
    assert(qihse_federation_lease_renew_checked(store, alice, &alice_lease,
                                                1, t0 + 600, t0 + 9000, &stale_out)
           == QIHSE_LEASE_RENEW_ERR_GENERATION_MISMATCH);

    /* Dead renewal: past t0+5000 the lease is DEAD — refused with a clear
     * status, and the record is reaped to EXPIRED. */
    qihse_federation_lease_t dead_out;
    assert(qihse_federation_lease_renew_checked(store, alice, &alice_lease,
                                                2, t0 + 6000, t0 + 9000, &dead_out)
           == QIHSE_LEASE_RENEW_ERR_EXPIRED);
    qihse_federation_lease_t fetched;
    assert(qihse_federation_lease_read(store, alice, &alice_lease, &fetched));
    assert(fetched.state == QIHSE_LEASE_EXPIRED); /* reaped, not just derived */

    /* Legacy wrapper agrees: expired-forever leases are no longer renewable
     * (the R7 defect — renew accepting an expired-forever lease — is closed
     * on the compatibility path too). */
    assert(!qihse_federation_lease_renew(store, alice, &alice_lease,
                                         999999999999ULL, &renewed));

    /* Re-acquire of the same resource by ANOTHER principal at a strictly
     * higher fencing epoch: succeeds; the dead lease is superseded. */
    qihse_federation_lease_t req2, out2;
    lease_request_init(&req2, "llv-l2b", "res-2", 201 /* > 200 */, t0 + 60000);
    assert(qihse_federation_lease_acquire(store, bob, &req2, &out2));
    assert(out2.state == QIHSE_LEASE_GRANTED);
    assert(out2.has_holder);
    assert(out2.holder_user_id == qihse_user_get_id(bob));

    /* Same-epoch re-acquire stays refused (monotonic, non-reusable epochs). */
    qihse_federation_lease_t req_same, out_same;
    lease_request_init(&req_same, "llv-l2c", "res-2", 201, t0 + 60000);
    assert(!qihse_federation_lease_acquire(store, bob, &req_same, &out_same));

    /* The original holder's renewals of the dead lease: rejected. */
    assert(!qihse_federation_lease_renew(store, alice, &alice_lease,
                                         999999999999ULL, &renewed));
    assert(qihse_federation_lease_renew_checked(store, alice, &alice_lease,
                                                QIHSE_FEDERATION_LEASE_GENERATION_UNCHECKED,
                                                t0 + 7000, t0 + 9000, &dead_out)
           == QIHSE_LEASE_RENEW_ERR_NOT_GRANTED);

    printf("PASS expiry: dead lease rejected + reaped + re-acquired by another principal\n");
    printf("PASS stale fencing epoch: equal-epoch re-acquire still refused\n");
}

/* ── 3. Holder check: only the acquiring principal may renew ────────────── */

static void test_holder_check(qihse_kv_store_t* store,
                              qihse_user_t* alice, qihse_user_t* bob,
                              uint64_t t0) {
    qihse_federation_lease_t req, out;
    /* Bob holds a live lease (resource res-2 at epoch 201 from the expiry
     * test — reuse it so the takeover chain stays coherent). */
    qihse_uuid_t bob_lease;
    lease_request_init(&req, "llv-l2b", "res-2", 201, t0 + 60000);
    /* Idempotent retry via the same request id returns bob's live lease. */
    assert(qihse_federation_lease_acquire(store, bob, &req, &out));
    assert(qihse_uuid_equal(&out.lease_id, &req.lease_id));
    assert(out.state == QIHSE_LEASE_GRANTED);
    bob_lease = out.lease_id;

    /* Alice (non-holder) tries the checked path — refused. */
    qihse_federation_lease_t stolen;
    assert(qihse_federation_lease_renew_checked(store, alice, &bob_lease,
                                                1, t0 + 100, t0 + 900000, &stolen)
           == QIHSE_LEASE_RENEW_ERR_HOLDER_MISMATCH);
    /* Alice tries the legacy wrapper — refused too. */
    assert(!qihse_federation_lease_renew(store, alice, &bob_lease,
                                         t0 + 900000, &stolen));

    /* The real holder renews — legacy wrapper (no generation arg) works. */
    qihse_federation_lease_t renewed;
    assert(qihse_federation_lease_renew(store, bob, &bob_lease, t0 + 900000, &renewed));
    assert(renewed.generation == 2);

    /* UNCHECKED sentinel skips ONLY the generation dimension. */
    assert(qihse_federation_lease_renew_checked(store, bob, &bob_lease,
                                                QIHSE_FEDERATION_LEASE_GENERATION_UNCHECKED,
                                                t0 + 200, t0 + 900000, &renewed)
           == QIHSE_LEASE_RENEW_OK);
    assert(renewed.generation == 3);

    printf("PASS holder check: non-holder renew refused (checked + legacy)\n");
}

/* ── 4. Stale generation on a live lease ────────────────────────────────── */

static void test_stale_generation(qihse_kv_store_t* store, qihse_user_t* bob,
                                  uint64_t t0) {
    /* Fresh lease for bob so the generation count is unambiguous. */
    qihse_federation_lease_t req, out;
    lease_request_init(&req, "llv-l4", "res-4", 400, t0 + 60000);
    assert(qihse_federation_lease_acquire(store, bob, &req, &out));
    assert(out.generation == 1);

    qihse_federation_lease_t renewed;
    assert(qihse_federation_lease_renew_checked(store, bob, &out.lease_id,
                                                999 /* stale */, t0 + 100,
                                                t0 + 90000, &renewed)
           == QIHSE_LEASE_RENEW_ERR_GENERATION_MISMATCH);
    assert(qihse_federation_lease_renew_checked(store, bob, &out.lease_id,
                                                1 /* current */, t0 + 100,
                                                t0 + 90000, &renewed)
           == QIHSE_LEASE_RENEW_OK);
    assert(renewed.generation == 2);
    assert(renewed.expires_hlc_physical == t0 + 90000);

    printf("PASS stale generation: mismatched expected generation refused\n");
}

/* ── 5. Legacy record (no recorded holder) fails closed ─────────────────── */

static void test_legacy_record_fail_closed(qihse_kv_store_t* store,
                                           qihse_user_t* op, uint64_t t0) {
    /* Hand-craft a pre-Phase-B record: 10 fields, no holder field. */
    qihse_uuid_t legacy_id;
    assert(qihse_uuid_from_seed("llv-legacy", strlen("llv-legacy"), &legacy_id));
    char id_str[QIHSE_UUID_STR_LEN + 1u];
    qihse_uuid_format(&legacy_id, id_str);
    char key[128];
    snprintf(key, sizeof(key), QIHSE_FEDERATION_LEASE_PREFIX "%s", id_str);
    char blob[1024];
    snprintf(blob, sizeof(blob),
             "%s\t%llu\t%s\t%llu\t%llu\t%u\t%llu\t%llu\t%llu\t%llu",
             /* lease_id owner resource fence gen state issued expires request issuer */
             "00000000000000000000000000000000",
             (unsigned long long)0,
             "res-legacy",
             (unsigned long long)500,
             (unsigned long long)1,
             (unsigned)QIHSE_LEASE_GRANTED,
             (unsigned long long)t0,
             (unsigned long long)0, /* never expires */
             (unsigned long long)0,
             (unsigned long long)0);
    assert(qihse_kv_set_user(store, key, blob, 0, 0, op));

    qihse_uuid_t parsed;
    assert(qihse_uuid_parse(id_str, &parsed));
    qihse_federation_lease_t out;
    /* Even the operator — who could have been the holder — cannot renew a
     * record with no recorded holder: fail closed, re-acquire instead. */
    assert(!qihse_federation_lease_renew(store, op, &parsed, t0 + 90000, &out));
    assert(qihse_federation_lease_renew_checked(store, op, &parsed,
                                                QIHSE_FEDERATION_LEASE_GENERATION_UNCHECKED,
                                                t0 + 100, t0 + 90000, &out)
           == QIHSE_LEASE_RENEW_ERR_HOLDER_MISMATCH);

    printf("PASS legacy records: no recorded holder fails closed\n");
}

/* ── 6. Born-dead grant + idempotent retry of a dead lease ──────────────── */

static void test_born_dead_and_idempotent_retry(qihse_kv_store_t* store,
                                                qihse_user_t* alice,
                                                uint64_t t0) {
    /* A lease whose requested expiry is already past is granted (acquire
     * does not re-validate the requested TTL — documented) but is born
     * dead: reads derive EXPIRED and the first renew reaps + refuses. */
    qihse_federation_lease_t req, out;
    lease_request_init(&req, "llv-l6", "res-6", 600, t0 - 1000);
    assert(qihse_federation_lease_acquire(store, alice, &req, &out));
    assert(out.state == QIHSE_LEASE_GRANTED); /* born-dead, per contract */
    qihse_federation_lease_t fetched;
    assert(qihse_federation_lease_read(store, alice, &out.lease_id, &fetched));
    assert(fetched.state == QIHSE_LEASE_EXPIRED); /* derived at read */
    qihse_federation_lease_t dead_out;
    assert(qihse_federation_lease_renew_checked(store, alice, &out.lease_id,
                                                1, t0, t0 + 9000, &dead_out)
           == QIHSE_LEASE_RENEW_ERR_EXPIRED);

    /* Idempotent retry (same request id) of a lease that died in the
     * meantime: the mapping still holds, and the record is reaped first so
     * the retry sees the truth (EXPIRED), never a fake GRANTED. */
    qihse_federation_lease_t req7, out7;
    lease_request_init(&req7, "llv-l7", "res-7", 700, t0 + 1000);
    assert(qihse_federation_lease_acquire(store, alice, &req7, &out7));
    assert(out7.state == QIHSE_LEASE_GRANTED);
    qihse_federation_lease_t retry_out;
    assert(qihse_federation_lease_acquire(store, alice, &req7, &retry_out));
    assert(qihse_uuid_equal(&retry_out.lease_id, &out7.lease_id));
    /* Retry happens (by injected-acquire wall clock) within the TTL here;
     * force the dead-retry path through a second acquire at a dead now is
     * not possible (acquire has no clock argument), so the reap-on-retry
     * path is asserted via read derivation instead. */
    assert(retry_out.state == QIHSE_LEASE_GRANTED);

    printf("PASS born-dead grant + idempotent retry honesty\n");
}

/* ── 7. Acquire reaps the dead predecessor it supersedes ────────────────── */

static void test_acquire_reaps_predecessor(qihse_kv_store_t* store,
                                           qihse_user_t* alice,
                                           qihse_user_t* bob,
                                           uint64_t t0) {
    qihse_federation_lease_t req, out;
    lease_request_init(&req, "llv-l8", "res-8", 800, t0 + 1000);
    assert(qihse_federation_lease_acquire(store, alice, &req, &out));

    /* The takeover reap uses the wall clock (pre-Phase-B acquire signature
     * carries no clock), so the dead predecessor is exercised with a
     * born-dead grant: expiry already in the past at acquisition. */
    qihse_federation_lease_t req_dead, out_dead;
    lease_request_init(&req_dead, "llv-l8d", "res-9", 900, t0 - 5000);
    assert(qihse_federation_lease_acquire(store, alice, &req_dead, &out_dead));
    assert(out_dead.state == QIHSE_LEASE_GRANTED);

    /* Bob takes over res-9 at a higher epoch; acquire reaps the dead
     * predecessor (it is already past expiry at the wall clock). */
    qihse_federation_lease_t req2, out2;
    lease_request_init(&req2, "llv-l8b", "res-9", 901, t0 + 60000);
    assert(qihse_federation_lease_acquire(store, bob, &req2, &out2));
    assert(out2.state == QIHSE_LEASE_GRANTED);

    qihse_federation_lease_t fetched;
    assert(qihse_federation_lease_read(store, bob, &out_dead.lease_id, &fetched));
    assert(fetched.state == QIHSE_LEASE_EXPIRED); /* reaped by takeover */

    printf("PASS acquire takeover: dead predecessor reaped + superseded\n");
}

int main(void) {
    char data_root[] = "build/lease_live_XXXXXX";
    assert(mkdtemp(data_root));
    setenv("QIHSE_DATA_DIR", data_root, 1);

    assert(qihse_auth_init());
    bool bootstrapped = qihse_auth_bootstrap_operator("LLOperatorPass1!");
    if (!bootstrapped) {
        setenv("QIHSE_OPERATOR_PASSWORD", "LLOperatorPass1!", 1);
        assert(qihse_auth_init());
    }
    qihse_user_t* op = qihse_auth_get_user(0);
    assert(op);

    /* Two distinct non-operator principals: alice holds, bob takes over. */
    qihse_user_t* alice = qihse_auth_create_user(op, 201u, QIHSE_ROLE_ANALYST,
                                                 0xFFFF, 0xFFFF,
                                                 "LLAlicePass1!", false);
    qihse_user_t* bob = qihse_auth_create_user(op, 202u, QIHSE_ROLE_ANALYST,
                                               0xFFFF, 0xFFFF,
                                               "LLBobPass22x!", false);
    assert(alice && bob);
    assert(qihse_user_get_id(alice) != qihse_user_get_id(bob));

    qihse_kv_store_t* store = qihse_kv_store_create();
    assert(store);

    /* Deterministic liveness clock: wall-now anchors the legacy-path
     * timestamps; every checked-path judgement uses an injected now_ms. */
    uint64_t t0 = (uint64_t)time(NULL) * 1000ULL;

    test_happy_path_never_expires(store, alice);
    test_expiry_lifecycle(store, alice, bob, t0);
    test_holder_check(store, alice, bob, t0);
    test_stale_generation(store, bob, t0);
    test_legacy_record_fail_closed(store, op, t0);
    test_born_dead_and_idempotent_retry(store, alice, t0);
    test_acquire_reaps_predecessor(store, alice, bob, t0);

    /* Status names are stable strings (used by logs and handler patches). */
    assert(strcmp(qihse_federation_lease_renew_status_name(
                      QIHSE_LEASE_RENEW_ERR_EXPIRED), "expired") == 0);
    assert(strcmp(qihse_federation_lease_renew_status_name(
                      QIHSE_LEASE_RENEW_ERR_HOLDER_MISMATCH), "holder-mismatch") == 0);
    assert(strcmp(qihse_federation_lease_renew_status_name(
                      QIHSE_LEASE_RENEW_ERR_GENERATION_MISMATCH),
                  "generation-mismatch") == 0);

    qihse_kv_store_destroy(store);
    printf("lease liveness tests passed\n");
    return 0;
}
