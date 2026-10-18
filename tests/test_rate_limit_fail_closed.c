#include <assert.h>
#include <stdio.h>
#include <stdint.h>
#include "qihse_rate_limit.h"

/* A missing limiter must NOT turn an auth endpoint into an unlimited one.
 * Real OOM injection is reserved for the allocation-failure sanitizer fixture. */
int main(void) {
    assert(!qihse_rate_limiter_check(NULL, 0x7f000001u));
    assert(qihse_rate_limiter_create(0, 1, 60) == NULL);
    qihse_rate_limiter_t* rl = qihse_rate_limiter_create(8, 2, 60);
    assert(rl != NULL);
    assert(qihse_rate_limiter_check(rl, 0x7f000001u));
    assert(qihse_rate_limiter_check(rl, 0x7f000001u));
    assert(!qihse_rate_limiter_check(rl, 0x7f000001u));
    qihse_rate_limiter_reset(rl, 0x7f000001u);
    assert(qihse_rate_limiter_check(rl, 0x7f000001u));
    qihse_rate_limiter_destroy(rl);
    puts("PASS: missing limiter denies; normal limiter caps attempts");
    return 0;
}
