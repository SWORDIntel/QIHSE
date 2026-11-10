#include "qihse_hnsw.h"

#include <assert.h>
#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

void *__real_malloc(size_t size);
int __real_posix_memalign(void **memptr, size_t alignment, size_t size);

static bool fail_next_aligned_allocation;
static bool fail_neighbor_buffer_allocation;
static bool fail_next_malloc;

void *__wrap_malloc(size_t size) {
    if (fail_next_malloc) {
        fail_next_malloc = false;
        errno = ENOMEM;
        return NULL;
    }
    return __real_malloc(size);
}

int __wrap_posix_memalign(void **memptr, size_t alignment, size_t size) {
    if (fail_next_aligned_allocation) {
        fail_next_aligned_allocation = false;
        return ENOMEM;
    }
    int rc = __real_posix_memalign(memptr, alignment, size);
    if (rc == 0 && alignment == 32u && fail_neighbor_buffer_allocation) {
        fail_neighbor_buffer_allocation = false;
        fail_next_malloc = true;
    }
    return rc;
}

static float distance_squared(const float *a, const float *b, size_t dim) {
    float sum = 0.0f;
    for (size_t i = 0; i < dim; ++i) {
        float d = a[i] - b[i];
        sum += d * d;
    }
    return sum;
}

static const float *lookup_vector(void *ctx, uint32_t node_id) {
    const float *vectors = (const float *)ctx;
    return vectors + (size_t)node_id * 2u;
}

static qihse_hnsw_index_t *new_index(const float *vectors) {
    qihse_hnsw_index_t *index = hnsw_create();
    assert(index);
    index->params.M = 2u;
    index->params.M0 = 2u;
    index->params.ef_construction = 8u;
    index->params.ef_search = 8u;
    index->params.mult = 0.0f; /* deterministic level zero */
    index->params.dim = 2u;
    index->params.distance_fn = distance_squared;
    index->params.get_vector_fn = lookup_vector;
    index->params.user_context = (void *)vectors;
    index->max_level = -1;
    return index;
}

static void test_layer_allocation_failure(void) {
    const float vectors[] = {0.0f, 0.0f};
    qihse_hnsw_index_t *index = new_index(vectors);
    fail_next_aligned_allocation = true;
    assert(!hnsw_try_insert(index, 0u, vectors, 2u));
    assert(index->num_nodes == 0u);
    assert(index->max_level == -1);
    hnsw_destroy(index);
}

static void test_neighbor_buffer_failure_is_not_published(void) {
    const float vectors[] = {0.0f, 0.0f, 1.0f, 0.0f};
    qihse_hnsw_index_t *index = new_index(vectors);
    assert(hnsw_try_insert(index, 0u, vectors, 2u));
    assert(index->num_nodes == 1u);

    fail_neighbor_buffer_allocation = true;
    assert(!hnsw_try_insert(index, 1u, vectors + 2u, 2u));
    assert(index->num_nodes == 1u);
    assert(index->layers[0]->links[1] == NULL);
    hnsw_destroy(index);
}

int main(void) {
    test_layer_allocation_failure();
    test_neighbor_buffer_failure_is_not_published();
    puts("PASS HNSW insertion allocation failures remain detectable");
    return 0;
}
