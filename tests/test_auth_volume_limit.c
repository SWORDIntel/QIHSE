/* AUTH volume limiter — unit + integration tests.
 *
 * The volume limiter complements the brute-force limiter: it counts EVERY
 * authentication attempt per source IP regardless of outcome and never
 * resets on success, so a correctly-authenticating client in a reconnect
 * storm is still throttled. Tests cover:
 *  - per-IP accounting with independent buckets;
 *  - exhaustion, explicit reset, and window expiry;
 *  - environment overrides;
 *  - end-to-end: an authenticate() call from a volume-exhausted IP is
 *    refused even with CORRECT credentials, and works again once the
 *    limiter is re-initialized with defaults.
 */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "qihse_auth.h"

#define OP_PASS "VolumeLimitOp1!"

int main(void) {
{
    char qdd[] = "build/test_auth_volume_limit_XXXXXX";
    if (mkdtemp(qdd)) setenv("QIHSE_DATA_DIR", qdd, 1);
}

    assert(qihse_auth_init());
    assert(qihse_auth_bootstrap_operator(OP_PASS));

    /* --- 1. Per-IP accounting, exhaustion, explicit reset --- */
    qihse_auth_init_volume_limiter(5, 60, 64);
    uint32_t ip_a = 0x0A0A0A01u, ip_b = 0x0A0A0A02u;
    for (int i = 0; i < 5; i++) {
        assert(qihse_auth_check_volume_limit(ip_a) == true);
    }
    assert(qihse_auth_check_volume_limit(ip_a) == false); /* 6th refused */
    assert(qihse_auth_check_volume_limit(ip_b) == true);  /* other IP unaffected */
    qihse_auth_volume_limit_reset(ip_a);
    assert(qihse_auth_check_volume_limit(ip_a) == true);
    printf("[PASS] per-IP buckets, exhaustion, explicit reset\n");

    /* --- 2. Window expiry reopens the bucket --- */
    qihse_auth_init_volume_limiter(3, 1, 8);
    uint32_t ip_c = 0x0A0A0A03u;
    assert(qihse_auth_check_volume_limit(ip_c));
    assert(qihse_auth_check_volume_limit(ip_c));
    assert(qihse_auth_check_volume_limit(ip_c));
    assert(qihse_auth_check_volume_limit(ip_c) == false);
    sleep(2); /* window is 1s */
    assert(qihse_auth_check_volume_limit(ip_c) == true);
    printf("[PASS] window expiry reopens the bucket\n");

    /* --- 3. Environment override at first use --- */
    setenv("QIHSE_AUTH_VOLUME_MAX", "2", 1);
    setenv("QIHSE_AUTH_VOLUME_WINDOW", "60", 1);
    qihse_auth_init_volume_limiter(0, 0, 0); /* 0 = use defaults/env */
    uint32_t ip_d = 0x0A0A0A04u;
    assert(qihse_auth_check_volume_limit(ip_d));
    assert(qihse_auth_check_volume_limit(ip_d));
    assert(qihse_auth_check_volume_limit(ip_d) == false); /* env cap 2 */
    unsetenv("QIHSE_AUTH_VOLUME_MAX");
    unsetenv("QIHSE_AUTH_VOLUME_WINDOW");
    printf("[PASS] QIHSE_AUTH_VOLUME_* env override honored\n");

    /* --- 4. End-to-end: correct credentials refused from an exhausted IP ---
     * Distinct IP from any bucket above, so only this test's budget applies.
     * Four failures, not five: the per-USER brute-force lockout trips at 5
     * and would poison the final assertion. */
    qihse_auth_init_volume_limiter(4, 60, 8);
    uint32_t ip_e = 0x0A0A0A05u;
    for (int i = 0; i < 4; i++) {
        assert(qihse_auth_authenticate_from(ip_e, "GODMODE_OP", "DefinitelyWrong1!") == NULL);
    }
    assert(qihse_auth_authenticate_from(ip_e, "GODMODE_OP", OP_PASS) == NULL);
    printf("[PASS] exhausted IP refuses auth even with correct credentials\n");

    /* --- 5. Re-init with defaults (120/min) unblocks the same IP ---
     * The brute-force limiter legitimately counted all five attempts above,
     * so clear its bucket for this IP before proving auth works again. */
    qihse_auth_init_volume_limiter(0, 0, 0);
    qihse_auth_rate_limit_reset(ip_e);
    assert(qihse_auth_authenticate_from(ip_e, "GODMODE_OP", OP_PASS) != NULL);
    printf("[PASS] re-initialized limiter unblocks the IP; auth succeeds\n");

    printf("ALL AUTH VOLUME LIMIT TESTS PASSED\n");
    return 0;
}
