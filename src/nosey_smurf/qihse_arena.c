#include "qihse_arena.h"
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>

typedef struct qihse_arena_block {
    struct qihse_arena_block* next;
    size_t used;
    size_t capacity;
    uint8_t data[];
} qihse_arena_block_t;

struct qihse_arena {
    size_t block_size;
    qihse_arena_block_t* head_block;
    qihse_arena_block_t* current_block;
};

static qihse_arena_block_t* alloc_block(size_t capacity) {
    qihse_arena_block_t* block = (qihse_arena_block_t*)malloc(sizeof(qihse_arena_block_t) + capacity);
    if (!block) return NULL;
    block->next = NULL;
    block->used = 0;
    block->capacity = capacity;
    return block;
}

qihse_arena_t* qihse_arena_create(size_t block_size) {
    if (block_size == 0) return NULL;
    qihse_arena_t* arena = (qihse_arena_t*)malloc(sizeof(qihse_arena_t));
    if (!arena) return NULL;
    arena->block_size = block_size;
    arena->head_block = alloc_block(block_size);
    if (!arena->head_block) {
        free(arena);
        return NULL;
    }
    arena->current_block = arena->head_block;
    return arena;
}

void qihse_arena_destroy(qihse_arena_t* arena) {
    if (!arena) return;
    qihse_arena_block_t* block = arena->head_block;
    while (block) {
        qihse_arena_block_t* next = block->next;
        free(block);
        block = next;
    }
    free(arena);
}

void* qihse_arena_alloc(qihse_arena_t* arena, size_t size) {
    if (!arena || size == 0) return NULL;

    size_t align = sizeof(void*) == 8 ? 16 : 8;
    size = (size + align - 1) & ~(align - 1);

    if (arena->current_block->capacity - arena->current_block->used >= size) {
        void* ptr = arena->current_block->data + arena->current_block->used;
        arena->current_block->used += size;
        return ptr;
    }

    qihse_arena_block_t* prev = arena->current_block;
    qihse_arena_block_t* block = prev->next;

    while (block) {
        if (block->capacity - block->used >= size) {
            arena->current_block = block;
            void* ptr = arena->current_block->data + arena->current_block->used;
            arena->current_block->used += size;
            return ptr;
        }
        prev = block;
        block = block->next;
    }

    size_t new_cap = arena->block_size;
    if (size > new_cap) {
        new_cap = size;
    }
    
    qihse_arena_block_t* new_block = alloc_block(new_cap);
    if (!new_block) return NULL;

    prev->next = new_block;
    arena->current_block = new_block;

    void* ptr = arena->current_block->data + arena->current_block->used;
    arena->current_block->used += size;
    return ptr;
}

void qihse_arena_reset(qihse_arena_t* arena) {
    if (!arena) return;
    qihse_arena_block_t* block = arena->head_block;
    while (block) {
        block->used = 0;
        block = block->next;
    }
    arena->current_block = arena->head_block;
}
