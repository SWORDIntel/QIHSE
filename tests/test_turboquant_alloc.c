/* Optional GNU-linker allocation fault checks. No production integration. */
#include "quantization/include/qihse_turboquant.h"
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void *__real_malloc(size_t size);
void *__real_calloc(size_t count, size_t size);
void __real_free(void *pointer);
static size_t attempt, fail_at = SIZE_MAX, live;
void *__wrap_malloc(size_t size) {
    void *p;
    if (attempt++ == fail_at) return NULL;
    p = __real_malloc(size); if (p) ++live; return p;
}
void *__wrap_calloc(size_t count, size_t size) {
    void *p;
    if (attempt++ == fail_at) return NULL;
    p = __real_calloc(count, size); if (p) ++live; return p;
}
void __wrap_free(void *p) {
    if (p) { assert(live > 0); --live; }
    __real_free(p);
}
static void fail(size_t nth) { attempt = 0; fail_at = nth; }
static void allow(void) { fail(SIZE_MAX); }
int main(void) {
    qihse_tq_config c = {9, 3, QIHSE_TQ_PRODUCT, 42, 43};
    qihse_tq_profile *p = NULL, *copy;
    qihse_tq_query *q;
    float vector[9] = {1, -2, 3, 4, 5, 0, 0.5f, -0.25f, 2};
    double output[9], original_output[9];
    uint8_t code[80], original_code[80];
    size_t size, i, baseline;
    int rc;
    assert(qihse_tq_code_size(&c, &size) == 0 && size <= sizeof(code));
    /* All six create allocations, including QR scratch unwind. */
    for (i = 0; i < 6; ++i) {
        p = (qihse_tq_profile *)(uintptr_t)1;
        fail(i); rc = qihse_tq_profile_create(&c, &p); allow();
        assert(rc == ENOMEM && p == NULL && live == 0);
    }
    assert(qihse_tq_profile_create(&c, &p) == 0);
    baseline = live;
    for (i = 0; i < 3; ++i) {
        copy = (qihse_tq_profile *)(uintptr_t)1;
        fail(i); rc = qihse_tq_profile_reseed_projection(p, 55, &copy); allow();
        assert(rc == ENOMEM && copy == NULL && live == baseline);
    }
    memset(original_code, 0xa5, sizeof(original_code));
    for (i = 0; i < 2; ++i) {
        memcpy(code, original_code, sizeof(code));
        fail(i); rc = qihse_tq_encode(p, vector, 9, code, size); allow();
        assert(rc == ENOMEM && live == baseline);
        assert(memcmp(code, original_code, sizeof(code)) == 0);
    }
    assert(qihse_tq_encode(p, vector, 9, code, size) == 0);
    for (i = 0; i < 9; ++i) original_output[i] = output[i] = 123.0+i;
    fail(0); rc = qihse_tq_decode(p, code, size, output, 9); allow();
    assert(rc == ENOMEM && live == baseline);
    assert(memcmp(output, original_output, sizeof(output)) == 0);
    fail(0); rc = qihse_tq_decode_mse(p, code, size, output, 9); allow();
    assert(rc == ENOMEM && live == baseline);
    assert(memcmp(output, original_output, sizeof(output)) == 0);
    for (i = 0; i < 4; ++i) {
        q = (qihse_tq_query *)(uintptr_t)1;
        fail(i); rc = qihse_tq_prepare_query(p, vector, 9, &q); allow();
        assert(rc == ENOMEM && q == NULL && live == baseline);
    }
    assert(qihse_tq_prepare_query(p, vector, 9, &q) == 0);
    /* Prepared direct score performs no allocation, even with failure armed. */
    fail(0); rc = qihse_tq_score(p, q, code, size, QIHSE_TQ_DOT, output);
    assert(rc == 0 && attempt == 0); allow();
    qihse_tq_query_destroy(q); qihse_tq_profile_destroy(p);
    assert(live == 0);
    puts("W12.1 allocation fault/unwind and allocation-free scoring tests passed");
    return 0;
}
