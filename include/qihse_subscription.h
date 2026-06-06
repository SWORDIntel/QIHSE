#ifndef QIHSE_SUBSCRIPTION_H
#define QIHSE_SUBSCRIPTION_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Subscription registry handle
 */
typedef struct qihse_subscription_registry_s qihse_subscription_registry_t;

/**
 * @brief Callback function type for a matched subscription
 * 
 * @param vector_id ID of the newly inserted vector
 * @param vector_data Pointer to the vector's data
 * @param dimensions Number of dimensions in the vector
 * @param user_data User-provided context pointer
 */
typedef void (*qihse_subscription_callback_t)(uint64_t vector_id, const float* vector_data, size_t dimensions, void* user_data);

/**
 * @brief Query specification for a streaming subscription
 */
typedef struct qihse_subscription_query_s {
    const float* target_vector;   /**< The query vector to match against */
    size_t dimensions;            /**< Dimensionality of the query vector */
    float similarity_threshold;   /**< Minimum similarity threshold (e.g., cosine similarity) */
} qihse_subscription_query_t;

/**
 * @brief Creates a new subscription registry
 * 
 * @return qihse_subscription_registry_t* Pointer to the registry or NULL on failure
 */
qihse_subscription_registry_t* qihse_subscription_registry_create(void);

/**
 * @brief Destroys a subscription registry and frees its resources
 * 
 * @param registry The registry to destroy
 */
void qihse_subscription_registry_destroy(qihse_subscription_registry_t* registry);

/**
 * @brief Registers a new continuous subscription
 * 
 * @param registry The subscription registry
 * @param query The query parameters for the subscription
 * @param callback The function to call when a matching vector is inserted
 * @param user_data Context pointer passed to the callback
 * @return uint64_t A unique subscription ID, or 0 on failure
 */
uint64_t qihse_subscription_register(
    qihse_subscription_registry_t* registry,
    const qihse_subscription_query_t* query,
    qihse_subscription_callback_t callback,
    void* user_data
);

/**
 * @brief Unregisters an existing subscription
 * 
 * @param registry The subscription registry
 * @param sub_id The subscription ID to remove
 * @return bool true if successfully removed, false otherwise
 */
bool qihse_subscription_unregister(
    qihse_subscription_registry_t* registry,
    uint64_t sub_id
);

/**
 * @brief Tests an incoming vector against all open subscriptions in the registry
 * 
 * This function should be called whenever a new vector is added to the database.
 * 
 * @param registry The subscription registry
 * @param vector_id The ID of the newly inserted vector
 * @param vector_data Pointer to the vector data
 * @param dimensions Dimensionality of the new vector
 */
void qihse_trigger_subscriptions(
    qihse_subscription_registry_t* registry,
    uint64_t vector_id,
    const float* vector_data,
    size_t dimensions
);

#ifdef __cplusplus
}
#endif

#endif /* QIHSE_SUBSCRIPTION_H */
