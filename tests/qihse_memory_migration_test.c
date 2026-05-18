#include "../core/qihse_abi.h"
#include "../memory/include/qihse_memory.h"
#include "../memory/include/qihse_memory_coherence.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define TEST_ASSERT(cond, msg) do { \
    if (!(cond)) { \
        fprintf(stderr, "FAIL: %s (%s:%d)\n", msg, __FILE__, __LINE__); \
        return false; \
    } \
} while (0)

static bool test_copy_required_migration_preserves_data(void) {
    qihse_context_t ctx = NULL;
    qihse_memory_manager_t manager = NULL;
    qihse_memory_buffer_t* buffer = NULL;
    qihse_memory_stats_t stats;
    uint8_t* bytes;

    TEST_ASSERT(qihse_context_create(NULL, &ctx) == QIHSE_OK,
                "context should be created");
    manager = qihse_memory_manager_create(ctx, "uma");
    TEST_ASSERT(manager != NULL, "memory manager should be created");

    buffer = qihse_memory_allocate(
        manager,
        64u,
        QIHSE_MEM_DEVICE,
        QIHSE_ACCESS_SEQUENTIAL,
        QIHSE_MEM_ZERO);
    TEST_ASSERT(buffer != NULL, "device buffer should be allocated");

    bytes = (uint8_t*)buffer->abi_buffer.data;
    for (size_t i = 0u; i < buffer->logical_size; i++) {
        bytes[i] = (uint8_t)(i + 1u);
    }

    TEST_ASSERT(qihse_memory_migrate(manager, buffer, 0, QIHSE_MEM_HOST),
                "device to host migration should copy through host-backed path");
    TEST_ASSERT(buffer->mem_type == QIHSE_MEM_HOST,
                "migrated buffer should report target type");
    TEST_ASSERT(buffer->preferred_device == 0,
                "migrated buffer should report target device");
    TEST_ASSERT(buffer->coherence_state == QIHSE_MEMORY_COHERENCE_CLEAN,
                "migrated buffer should be coherent clean");
    TEST_ASSERT(buffer->coherence_version == 2u,
                "migration should advance coherence version");

    bytes = (uint8_t*)buffer->abi_buffer.data;
    for (size_t i = 0u; i < buffer->logical_size; i++) {
        TEST_ASSERT(bytes[i] == (uint8_t)(i + 1u),
                    "migration should preserve payload bytes");
    }

    TEST_ASSERT(qihse_memory_get_stats(manager, &stats),
                "stats should be readable");
    TEST_ASSERT(stats.device_memory == 0u,
                "device accounting should be released after migration");
    TEST_ASSERT(stats.host_memory >= buffer->allocated_size,
                "host accounting should include migrated buffer");
    TEST_ASSERT(stats.total_migrations == 1u,
                "migration counter should increment");

    qihse_memory_free(manager, buffer);
    qihse_memory_manager_destroy(manager);
    qihse_context_destroy(ctx);
    return true;
}

static bool test_zero_copy_migration_keeps_pointer(void) {
    qihse_context_t ctx = NULL;
    qihse_memory_manager_t manager = NULL;
    qihse_memory_buffer_t* buffer = NULL;
    void* original_data;

    TEST_ASSERT(qihse_context_create(NULL, &ctx) == QIHSE_OK,
                "context should be created");
    manager = qihse_memory_manager_create(ctx, "uma");
    TEST_ASSERT(manager != NULL, "memory manager should be created");

    buffer = qihse_memory_allocate(
        manager,
        64u,
        QIHSE_MEM_HMA_SUPERPOSITION,
        QIHSE_ACCESS_SIMD,
        QIHSE_MEM_ZERO);
    TEST_ASSERT(buffer != NULL, "hma buffer should be allocated");
    original_data = buffer->abi_buffer.data;

    TEST_ASSERT(qihse_memory_migrate(manager, buffer, 1, QIHSE_MEM_HMA_INTERACTION),
                "hma to hma migration should be zero-copy");
    TEST_ASSERT(buffer->abi_buffer.data == original_data,
                "zero-copy migration should keep pointer stable");
    TEST_ASSERT(buffer->mem_type == QIHSE_MEM_HMA_INTERACTION,
                "zero-copy migration should update type");
    TEST_ASSERT(buffer->coherence_version == 2u,
                "zero-copy migration should advance coherence version");

    qihse_memory_free(manager, buffer);
    qihse_memory_manager_destroy(manager);
    qihse_context_destroy(ctx);
    return true;
}

int main(void) {
    struct {
        const char* name;
        bool (*fn)(void);
    } tests[] = {
        {"copy-required migration", test_copy_required_migration_preserves_data},
        {"zero-copy migration", test_zero_copy_migration_keeps_pointer},
    };

    for (size_t i = 0u; i < sizeof(tests) / sizeof(tests[0]); i++) {
        printf("RUN  %s\n", tests[i].name);
        if (!tests[i].fn()) {
            printf("FAIL %s\n", tests[i].name);
            return 1;
        }
        printf("PASS %s\n", tests[i].name);
    }

    printf("PASS all qihse memory migration tests\n");
    return 0;
}
