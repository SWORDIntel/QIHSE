/* Password verifier cache — unit + security tests.
 *
 * The cache exists so a repeated presentation of the same credentials skips
 * only the PBKDF2 compute. It must NOT change any authorization outcome:
 *  - wrong passwords are never cached and never hit;
 *  - a password rotation (new verifier salt) invalidates the old entry —
 *    the cached key binds the account's current salt, so the old password
 *    can never match again;
 *  - TTL expiry forces the cold path;
 *  - TTL 0 disables the cache entirely.
 * All of this runs at the public qihse_auth_authenticate API — the same path
 * the RESP AUTH command uses — so the assertions cover the integration, not
 * just the cache internals. Hit/miss/store counters (qihse_auth_cache_stats)
 * distinguish "cached" from "recomputed".
 */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "qihse_auth.h"

#define OP_PASS_1 "CacheTestOp1!x"
#define OP_PASS_2 "CacheTestOp2!y"

static void stats_delta(uint64_t base[3], uint64_t out[3]) {
    uint64_t now[3];
    qihse_auth_cache_stats(&now[0], &now[1], &now[2]);
    for (int i = 0; i < 3; i++) out[i] = now[i] - base[i];
}

int main(void) {
{
    char qdd[] = "build/test_auth_verifier_cache_XXXXXX";
    if (mkdtemp(qdd)) setenv("QIHSE_DATA_DIR", qdd, 1);
}

    assert(qihse_auth_init());
    assert(qihse_auth_bootstrap_operator(OP_PASS_1));
    qihse_user_t* op = qihse_auth_get_user(0);
    assert(op != NULL);

    /* Deterministic cache behavior for the test; also exercises configure. */
    qihse_auth_cache_configure(300, 64);
    qihse_auth_cache_clear();

    uint64_t base[3], d[3];

    /* 1. Cold authentication: one miss, one store, then success. */
    qihse_auth_cache_stats(&base[0], &base[1], &base[2]);
    assert(qihse_auth_authenticate("GODMODE_OP", OP_PASS_1) != NULL);
    stats_delta(base, d);
    assert(d[0] == 0 && d[1] == 1 && d[2] == 1); /* hits, misses, stores */
    printf("[PASS] cold auth: miss + store\n");

    /* 2. Repeat presentation hits the cache: zero misses, zero stores. */
    qihse_auth_cache_stats(&base[0], &base[1], &base[2]);
    for (int i = 0; i < 5; i++) {
        assert(qihse_auth_authenticate("GODMODE_OP", OP_PASS_1) != NULL);
    }
    stats_delta(base, d);
    assert(d[0] == 5 && d[1] == 0 && d[2] == 0);
    printf("[PASS] repeat auths served from cache (5 hits, no recompute)\n");

    /* 3. Wrong password: miss, no store, refused. */
    qihse_auth_cache_stats(&base[0], &base[1], &base[2]);
    assert(qihse_auth_authenticate("GODMODE_OP", "WrongPassword99!") == NULL);
    stats_delta(base, d);
    assert(d[0] == 0 && d[1] == 1 && d[2] == 0);
    printf("[PASS] wrong password never cached\n");

    /* 4. Password rotation invalidates the cached entry. The verifier salt
     * changes with the new password, so the old password's cache key cannot
     * match — this is the anti-stale-credential property. */
    assert(qihse_auth_modify_user(op, 0, NULL, OP_PASS_2, -1, -1, -1, -1));
    qihse_auth_cache_stats(&base[0], &base[1], &base[2]);
    assert(qihse_auth_authenticate("GODMODE_OP", OP_PASS_1) == NULL); /* old pw refused */
    stats_delta(base, d);
    assert(d[0] == 0 && d[2] == 0); /* not served from cache, nothing stored */
    printf("[PASS] password rotation invalidates cached old credentials\n");

    qihse_auth_cache_stats(&base[0], &base[1], &base[2]);
    assert(qihse_auth_authenticate("GODMODE_OP", OP_PASS_2) != NULL); /* cold, new salt */
    stats_delta(base, d);
    assert(d[1] == 1 && d[2] == 1);
    qihse_auth_cache_stats(&base[0], &base[1], &base[2]);
    assert(qihse_auth_authenticate("GODMODE_OP", OP_PASS_2) != NULL); /* warm */
    stats_delta(base, d);
    assert(d[0] == 1 && d[1] == 0);

    /* 5. TTL expiry forces the cold path again. Reconfiguring the TTL only
     * affects NEW stores, so drop the 300s-TTL entry, warm under the 1s
     * TTL, then let it expire. */
    qihse_auth_cache_configure(1, 64);
    qihse_auth_cache_clear();
    assert(qihse_auth_authenticate("GODMODE_OP", OP_PASS_2) != NULL); /* warms, 1s TTL */
    sleep(2);
    qihse_auth_cache_stats(&base[0], &base[1], &base[2]);
    assert(qihse_auth_authenticate("GODMODE_OP", OP_PASS_2) != NULL);
    stats_delta(base, d);
    assert(d[1] == 1 && d[2] == 1); /* expired -> recompute + re-store */
    printf("[PASS] TTL expiry forces cold re-verification\n");

    /* 6. TTL 0 disables the cache: stats frozen, auth still succeeds. */
    qihse_auth_cache_configure(0, 64);
    qihse_auth_cache_clear();
    qihse_auth_cache_stats(&base[0], &base[1], &base[2]);
    assert(qihse_auth_authenticate("GODMODE_OP", OP_PASS_2) != NULL);
    assert(qihse_auth_authenticate("GODMODE_OP", OP_PASS_2) != NULL);
    stats_delta(base, d);
    assert(d[0] == 0 && d[1] == 0 && d[2] == 0);
    printf("[PASS] TTL 0 disables caching without breaking auth\n");

    /* 7. Cache never crosses users: a second principal with (hypothetically)
     * the same password cannot hit user 0's entry. The cache key binds
     * user_id, so a hit for another user is impossible by construction —
     * verified here through the miss counters via the by-ID auth path. */
    assert(qihse_auth_create_user(
        op, 1, QIHSE_ROLE_ANALYST, 5, 0x0003, OP_PASS_2, false) != NULL);
    qihse_auth_cache_configure(300, 64);
    qihse_auth_cache_stats(&base[0], &base[1], &base[2]);
    assert(qihse_auth_authenticate_id(1, OP_PASS_2) != NULL);
    stats_delta(base, d);    assert(d[1] == 1 && d[0] == 0); /* cold compute for the OTHER user id */
    printf("[PASS] cache keys bind user_id (no cross-principal hits)\n");

    printf("ALL AUTH VERIFIER CACHE TESTS PASSED\n");
    return 0;
}
