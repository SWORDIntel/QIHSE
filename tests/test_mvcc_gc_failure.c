#include "qihse_mvcc.h"
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static unsigned fail_allocation;
static unsigned fail_malloc;
void* __real_malloc(size_t);
void* __wrap_malloc(size_t size) {
    if (fail_malloc && --fail_malloc == 0) return NULL;
    return __real_malloc(size);
}
void* __real_qihse_arena_alloc(qihse_arena_t*, size_t);
void* __wrap_qihse_arena_alloc(qihse_arena_t* arena, size_t size) {
    if (fail_allocation && --fail_allocation == 0) return NULL;
    return __real_qihse_arena_alloc(arena, size);
}

static bool committed_mask(void* ctx, uint64_t id) {
    uint64_t mask = *(uint64_t*)ctx;
    return id < 64 && (mask & (UINT64_C(1) << id));
}

static void expect(qihse_mvcc_store_t* store, uint64_t mask, const char* value) {
    const void* got = NULL; size_t size = 0;
    assert(qihse_mvcc_read(store, 0, "key", 3, 10,
                           committed_mask, &mask, &got, &size));
    assert(size == strlen(value) && memcmp(got, value, size) == 0);
}

static void test_gc_preserves_rollback(void) {
    qihse_mvcc_store_t* store = qihse_mvcc_store_create(16); assert(store);
    assert(qihse_mvcc_insert(store, 0, "key", 3, "v1", 2, 1) == 0);
    assert(qihse_mvcc_update(store, 0, "key", 3, "v2", 2, 2) == 0);
    assert(qihse_mvcc_update(store, 0, "key", 3, "aborted", 7, 3) == 0);
    uint64_t committed = (UINT64_C(1) << 1) | (UINT64_C(1) << 2);
    expect(store, committed, "v2");
    assert(qihse_mvcc_gc(store, 4) == 0);
    assert(qihse_mvcc_vacuum(store, 4) == 0);
    assert(qihse_mvcc_gc_committed(store, 4, committed_mask, &committed) == 1);
    assert(qihse_mvcc_version_count(store) == 2);
    expect(store, committed, "v2");
    errno = 0;
    assert(qihse_mvcc_gc_committed(store, 4, NULL, NULL) == -1 && errno == EINVAL);
    qihse_mvcc_store_destroy(store);
}

static void test_failed_mutation_is_unchanged(void) {
    qihse_mvcc_store_t* store = qihse_mvcc_store_create(16); assert(store);
    assert(qihse_mvcc_insert(store, 0, "key", 3, "old", 3, 1) == 0);
    fail_allocation = 1;
    assert(qihse_mvcc_update(store, 0, "key", 3, "new", 3, 2) == -1);
    assert(!fail_allocation);
    assert(qihse_mvcc_version_count(store) == 1);
    expect(store, UINT64_C(6), "old");
    fail_allocation = 1;
    assert(qihse_mvcc_insert(store, 0, "absent", 6, "new", 3, 2) == -1);
    assert(!fail_allocation && qihse_mvcc_row_count(store) == 1);
    assert(qihse_mvcc_version_count(store) == 1);
    assert(qihse_mvcc_update(store, 0, "key", 3, NULL, 3, 2) == -1);
    assert(qihse_mvcc_update(store, 0, "key", 3, "new", SIZE_MAX, 2) == -1);
    expect(store, UINT64_C(6), "old");
    for (unsigned allocation = 1; allocation <= 2; allocation++) {
        const void* got = (const void*)1; size_t size = 99;
        uint64_t committed = UINT64_C(6);
        fail_malloc = allocation;
        assert(!qihse_mvcc_read(store, 0, "key", 3, 2,
            committed_mask, &committed, &got, &size));
        assert(errno == ENOMEM && !fail_malloc && got == NULL && size == 0);
        expect(store, committed, "old");
    }
    qihse_mvcc_store_destroy(store);
    errno = 0;
    assert(qihse_mvcc_store_create(SIZE_MAX) == NULL && errno == EOVERFLOW);
}

typedef struct { qihse_mvcc_store_t* store; unsigned calls[4]; bool change; } callback_ctx;
static bool reentrant_commit(void* opaque, uint64_t id) {
    callback_ctx* ctx = opaque;
    assert(qihse_mvcc_row_count(ctx->store) == 1); /* must not hold store lock */
    if (id >= 4) return false;
    ctx->calls[id]++;
    return !ctx->change || id != 2 || ctx->calls[id] > 1;
}

static void test_status_callbacks_and_read_view(void) {
    qihse_mvcc_store_t* store = qihse_mvcc_store_create(16); assert(store);
    assert(qihse_mvcc_insert(store, 0, "key", 3, "old", 3, 1) == 0);
    assert(qihse_mvcc_update(store, 0, "key", 3, "new", 3, 2) == 0);
    callback_ctx ctx = {.store = store, .change = true};
    const void* got = NULL; size_t size = 0;
    assert(qihse_mvcc_read(store, 0, "key", 3, 2, reentrant_commit, &ctx, &got, &size));
    assert(size == 3 && memcmp(got, "old", 3) == 0 && ctx.calls[2] == 1);
    ctx.change = false;
    assert(qihse_mvcc_gc_committed(store, 3, reentrant_commit, &ctx) == 1);
    assert(qihse_mvcc_version_count(store) == 1);
    expect(store, UINT64_C(6), "new");
    qihse_mvcc_store_destroy(store);
}

int main(void) {
    alarm(5);
    test_gc_preserves_rollback();
    test_failed_mutation_is_unchanged();
    test_status_callbacks_and_read_view();
    alarm(0);
    puts("PASS MVCC rollback-safe GC, atomic allocation failures, and unlocked stable commit callbacks");
    return 0;
}
