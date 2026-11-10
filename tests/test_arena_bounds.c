#include "qihse_arena.h"
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

static size_t expected_alignment(void) {
    return sizeof(void *) == 8 ? 16 : 8;
}

static void check_aligned(void *ptr) {
    assert(ptr != NULL);
    assert(((uintptr_t)ptr % expected_alignment()) == 0);
}

int main(void) {
    assert(qihse_arena_create(0) == NULL);
    assert(qihse_arena_create(SIZE_MAX) == NULL);
    qihse_arena_t *arena = qihse_arena_create(32);
    assert(arena != NULL);
    assert(qihse_arena_alloc(arena, 0) == NULL);

    /* Overflowing size rounding and impossible block totals must fail. */
    for (size_t i = 0; i < expected_alignment(); ++i)
        assert(qihse_arena_alloc(arena, SIZE_MAX - i) == NULL);

    void *a = qihse_arena_alloc(arena, 1);
    void *b = qihse_arena_alloc(arena, expected_alignment());
    void *c = qihse_arena_alloc(arena, expected_alignment() + 1);
    void *large = qihse_arena_alloc(arena, 257);
    check_aligned(a); check_aligned(b); check_aligned(c); check_aligned(large);
    assert(a != b && b != c && c != large);

    qihse_arena_reset(arena);
    void *after_reset = qihse_arena_alloc(arena, 1);
    check_aligned(after_reset);
    assert(after_reset == a);
    void *reused_second_block = qihse_arena_alloc(arena, expected_alignment() + 1);
    check_aligned(reused_second_block);
    qihse_arena_destroy(arena);

    puts("arena bounds/alignment/reset checks passed");
    return 0;
}
