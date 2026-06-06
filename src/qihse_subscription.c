#include "qihse_subscription.h"
#include <stdlib.h>
#include <string.h>
#include <math.h>

/* Internal structure for a subscription node */
typedef struct qihse_subscription_s {
    uint64_t sub_id;
    float* target_vector;
    size_t dimensions;
    float similarity_threshold;
    
    qihse_subscription_callback_t callback;
    void* user_data;
    
    struct qihse_subscription_s* next;
} qihse_subscription_t;

/* Internal structure for the registry */
struct qihse_subscription_registry_s {
    qihse_subscription_t* head;
    uint64_t next_id;
};

qihse_subscription_registry_t* qihse_subscription_registry_create(void) {
    qihse_subscription_registry_t* reg = (qihse_subscription_registry_t*)malloc(sizeof(qihse_subscription_registry_t));
    if (reg) {
        reg->head = NULL;
        reg->next_id = 1;
    }
    return reg;
}

void qihse_subscription_registry_destroy(qihse_subscription_registry_t* registry) {
    if (!registry) return;
    
    qihse_subscription_t* current = registry->head;
    while (current) {
        qihse_subscription_t* next = current->next;
        if (current->target_vector) {
            free(current->target_vector);
        }
        free(current);
        current = next;
    }
    free(registry);
}

uint64_t qihse_subscription_register(
    qihse_subscription_registry_t* registry,
    const qihse_subscription_query_t* query,
    qihse_subscription_callback_t callback,
    void* user_data
) {
    if (!registry || !query || !query->target_vector || !callback) return 0;
    
    qihse_subscription_t* sub = (qihse_subscription_t*)malloc(sizeof(qihse_subscription_t));
    if (!sub) return 0;
    
    sub->sub_id = registry->next_id++;
    sub->dimensions = query->dimensions;
    sub->similarity_threshold = query->similarity_threshold;
    sub->callback = callback;
    sub->user_data = user_data;
    
    sub->target_vector = (float*)malloc(query->dimensions * sizeof(float));
    if (!sub->target_vector) {
        free(sub);
        return 0;
    }
    memcpy(sub->target_vector, query->target_vector, query->dimensions * sizeof(float));
    
    /* Prepend to the linked list */
    sub->next = registry->head;
    registry->head = sub;
    
    return sub->sub_id;
}

bool qihse_subscription_unregister(
    qihse_subscription_registry_t* registry,
    uint64_t sub_id
) {
    if (!registry) return false;
    
    qihse_subscription_t** current = &registry->head;
    while (*current) {
        if ((*current)->sub_id == sub_id) {
            qihse_subscription_t* to_delete = *current;
            *current = (*current)->next;
            
            if (to_delete->target_vector) {
                free(to_delete->target_vector);
            }
            free(to_delete);
            return true;
        }
        current = &(*current)->next;
    }
    return false;
}

/* Helper function to compute cosine similarity */
static float compute_cosine_similarity(const float* v1, const float* v2, size_t dims) {
    float dot = 0.0f;
    float norm1 = 0.0f;
    float norm2 = 0.0f;
    
    for (size_t i = 0; i < dims; i++) {
        dot += v1[i] * v2[i];
        norm1 += v1[i] * v1[i];
        norm2 += v2[i] * v2[i];
    }
    
    if (norm1 == 0.0f || norm2 == 0.0f) {
        return 0.0f;
    }
    return dot / (sqrtf(norm1) * sqrtf(norm2));
}

void qihse_trigger_subscriptions(
    qihse_subscription_registry_t* registry,
    uint64_t vector_id,
    const float* vector_data,
    size_t dimensions
) {
    if (!registry || !vector_data) return;
    
    qihse_subscription_t* current = registry->head;
    while (current) {
        /* Only compare if dimensions match */
        if (current->dimensions == dimensions) {
            float similarity = compute_cosine_similarity(current->target_vector, vector_data, dimensions);
            if (similarity >= current->similarity_threshold) {
                current->callback(vector_id, vector_data, dimensions, current->user_data);
            }
        }
        current = current->next;
    }
}
