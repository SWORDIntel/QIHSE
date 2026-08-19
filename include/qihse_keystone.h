#ifndef QIHSE_KEYSTONE_H
#define QIHSE_KEYSTONE_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include "qihse_kv_store.h"
#include "qihse_cluster_slot.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * 6-Class Semantic Micro-Model Target Classes
 */
typedef enum {
    QIHSE_KEYSTONE_CLASS_UNKNOWN = 0,
    QIHSE_KEYSTONE_CLASS_FINANCIAL = 1,
    QIHSE_KEYSTONE_CLASS_CORPORATE = 2,
    QIHSE_KEYSTONE_CLASS_GOVERNMENT = 3,
    QIHSE_KEYSTONE_CLASS_INFRASTRUCTURE = 4,
    QIHSE_KEYSTONE_CLASS_CONSUMER = 5
} qihse_keystone_class_t;

/**
 * Result structure for an extracted intelligence artifact
 */
typedef struct {
    char key[256];
    char value[512];
    uint32_t slot;
    qihse_keystone_class_t semantic_class;
    float confidence;
} qihse_keystone_artifact_t;

/**
 * High-throughput SIMD zero-allocation dirty log ingestion.
 *
 * Scans raw stealer logs/breaches in 16/32-byte SIMD strides, extracts credentials
 * (email:password), URLs, tokens, runs neural context classification, and routes
 * records into the Black Hole KV store across 16,384 CRC16 hash slots.
 *
 * @param kv Local KV store handle.
 * @param topo Cluster topology (optional, for cluster sharding).
 * @param buffer Raw dirty log bytes.
 * @param len Length of buffer.
 * @param clearance Default SCI clearance level.
 * @param compartment Default SCI compartment mask.
 * @return Total number of artifacts extracted and indexed.
 */
size_t qihse_keystone_ingest_dirty_logs(
    qihse_kv_store_t* kv,
    qihse_cluster_topology_t* topo,
    const char* buffer,
    size_t len,
    uint16_t clearance,
    uint16_t compartment
);

/**
 * Runs the native 6-class neural micro-model on a 256-byte context window.
 *
 * @param context Input context text surrounding a candidate token.
 * @param len Length of context string.
 * @param out_class Pointer to receive the highest-scoring class enum.
 * @param out_confidence Pointer to receive the classification confidence (0.0 to 1.0).
 * @return 0 on success, negative on error.
 */
int qihse_keystone_classify_context(
    const char* context,
    size_t len,
    qihse_keystone_class_t* out_class,
    float* out_confidence
);

/**
 * Converts a semantic class enum to human-readable string.
 */
const char* qihse_keystone_class_name(qihse_keystone_class_t cls);

/**
 * Interpolation anchor-guided search for sorted 64-bit integer arrays.
 * Achieves O(log log N) lookup latency (< 70ns).
 *
 * @param arr Sorted array of 64-bit integers.
 * @param n Number of elements.
 * @param key Target value to search for.
 * @return Index of element if found, or -1 if not found.
 */
int64_t qihse_keystone_anchor_search(const int64_t* arr, size_t n, int64_t key);

/**
 * Interpolation anchor-guided lower-bound for sorted 64-bit integer arrays.
 * Returns the index of the first element >= key using the same O(log log N)
 * interpolation core as qihse_keystone_anchor_search. Used for index range
 * lookups (replacing binary search) in the Frieze Column Store and Marmalade
 * Time-Series Engine.
 *
 * @param arr Sorted array of 64-bit integers.
 * @param n Number of elements.
 * @param key Target lower-bound value.
 * @return Index of first element >= key, or n if all elements are < key.
 */
size_t qihse_keystone_anchor_lower_bound(const int64_t* arr, size_t n, int64_t key);

/**
 * Interpolation anchor-guided upper-bound for sorted 64-bit integer arrays.
 * Returns the index of the first element > key using the same O(log log N)
 * interpolation core as qihse_keystone_anchor_search.
 *
 * @param arr Sorted array of 64-bit integers.
 * @param n Number of elements.
 * @param key Target upper-bound value.
 * @return Index of first element > key, or n if all elements are <= key.
 */
size_t qihse_keystone_anchor_upper_bound(const int64_t* arr, size_t n, int64_t key);

#ifdef __cplusplus
}
#endif

#endif // QIHSE_KEYSTONE_H
