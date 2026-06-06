#ifndef QIHSE_ARENA_H
#define QIHSE_ARENA_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

/**
 * @brief Opaque handle for a memory arena allocator.
 */
typedef struct qihse_arena qihse_arena_t;

/**
 * @brief Creates a new memory arena with a specific block size.
 * @param block_size The size of each contiguous memory block (e.g., 64KB).
 * @return Pointer to the new arena, or NULL on failure.
 */
qihse_arena_t* qihse_arena_create(size_t block_size);

/**
 * @brief Destroys the arena and frees all underlying blocks at once.
 * @param arena The arena to destroy.
 */
void qihse_arena_destroy(qihse_arena_t* arena);

/**
 * @brief Allocates contiguous memory from the arena.
 * This is an O(1) operation that bumps a pointer, preventing fragmentation.
 * @param arena The arena.
 * @param size The number of bytes to allocate.
 * @return Pointer to the allocated memory, or NULL if out of memory.
 */
void* qihse_arena_alloc(qihse_arena_t* arena, size_t size);

/**
 * @brief Resets the arena, reclaiming all memory without freeing the blocks back to the OS.
 * @param arena The arena to reset.
 */
void qihse_arena_reset(qihse_arena_t* arena);

#endif /* QIHSE_ARENA_H */
