/*
 * QIHSE - Memory Migration Backend Tests
 */

#include "../memory/include/qihse_memory_migration_backend.h"

#include <assert.h>
#include <string.h>

static void test_host_memcpy_preserves_bytes(void) {
    unsigned char src[16];
    unsigned char dst[16];
    qihse_memory_migration_backend_request_t request;
    qihse_memory_migration_backend_plan_t plan;
    size_t i;

    for (i = 0u; i < sizeof(src); ++i) {
        src[i] = (unsigned char)(i * 7u + 3u);
        dst[i] = 0u;
    }

    request = qihse_memory_migration_backend_request(
        dst,
        src,
        sizeof(src),
        QIHSE_MEMORY_MIGRATION_BACKEND_HOST_MEMCPY
    );

    assert(qihse_memory_migration_backend_plan(&request, &plan) ==
        QIHSE_MEMORY_MIGRATION_BACKEND_OK);
    assert(plan.executable);
    assert(plan.preserves_bytes);
    assert(qihse_memory_migration_backend_execute_plan(&request, &plan) ==
        QIHSE_MEMORY_MIGRATION_BACKEND_OK);
    assert(memcmp(dst, src, sizeof(src)) == 0);
}

static void test_zero_byte_copy_accepts_null_ranges(void) {
    qihse_memory_migration_backend_request_t request;
    qihse_memory_migration_backend_plan_t plan;

    request = qihse_memory_migration_backend_request(
        NULL,
        NULL,
        0u,
        QIHSE_MEMORY_MIGRATION_BACKEND_HOST_MEMCPY
    );

    assert(qihse_memory_migration_backend_plan(&request, &plan) ==
        QIHSE_MEMORY_MIGRATION_BACKEND_OK);
    assert(qihse_memory_migration_backend_execute(&request) ==
        QIHSE_MEMORY_MIGRATION_BACKEND_OK);
}

static void test_rejects_overlapping_host_memcpy_ranges(void) {
    unsigned char bytes[16];
    qihse_memory_migration_backend_request_t request;

    request = qihse_memory_migration_backend_request(
        bytes + 1,
        bytes,
        8u,
        QIHSE_MEMORY_MIGRATION_BACKEND_HOST_MEMCPY
    );

    assert(qihse_memory_migration_backend_execute(&request) ==
        QIHSE_MEMORY_MIGRATION_BACKEND_OVERLAP_UNSUPPORTED);
}

static void test_reports_unsupported_dma_cleanly(void) {
    unsigned char src[4] = {1u, 2u, 3u, 4u};
    unsigned char dst[4] = {0u, 0u, 0u, 0u};
    qihse_memory_migration_backend_request_t request;
    qihse_memory_migration_backend_plan_t plan;

    request = qihse_memory_migration_backend_request(
        dst,
        src,
        sizeof(src),
        QIHSE_MEMORY_MIGRATION_BACKEND_HARDWARE_DMA
    );

    assert(!qihse_memory_migration_backend_is_supported(
        QIHSE_MEMORY_MIGRATION_BACKEND_HARDWARE_DMA));
    assert(qihse_memory_migration_backend_plan(&request, &plan) ==
        QIHSE_MEMORY_MIGRATION_BACKEND_UNSUPPORTED_DMA);
    assert(!plan.executable);
    assert(!plan.preserves_bytes);
    assert(strcmp(qihse_memory_migration_backend_status_name(plan.status),
        "unsupported_dma") == 0);
    assert(memcmp(dst, src, sizeof(src)) != 0);
}

int main(void) {
    test_host_memcpy_preserves_bytes();
    test_zero_byte_copy_accepts_null_ranges();
    test_rejects_overlapping_host_memcpy_ranges();
    test_reports_unsupported_dma_cleanly();

    return 0;
}
