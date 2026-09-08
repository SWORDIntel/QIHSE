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

typedef enum {
    QIHSE_KEYSTONE_CLASS_UNKNOWN = 0,
    QIHSE_KEYSTONE_CLASS_FINANCIAL = 1,
    QIHSE_KEYSTONE_CLASS_CORPORATE = 2,
    QIHSE_KEYSTONE_CLASS_GOVERNMENT = 3,
    QIHSE_KEYSTONE_CLASS_INFRASTRUCTURE = 4,
    QIHSE_KEYSTONE_CLASS_CONSUMER = 5
} qihse_keystone_class_t;

typedef struct {
    char key[256];
    char value[512];
    uint32_t slot;
    qihse_keystone_class_t semantic_class;
    float confidence;
} qihse_keystone_artifact_t;

/*
 * Principal-aware dirty-log ingestion. Classified/SCI ingestion MUST use this
 * function. Target classification is checked before parsing and every KV write
 * is performed through qihse_kv_set_user(). Only successfully persisted
 * artifacts are included in the returned count.
 */
size_t qihse_keystone_ingest_dirty_logs_user(
    qihse_kv_store_t* kv,
    qihse_cluster_topology_t* topo,
    const char* buffer,
    size_t len,
    uint16_t clearance,
    uint16_t compartment,
    qihse_user_t* user);

/*
 * Legacy ABI retained for unclassified ingestion. It delegates to the
 * principal-aware path with a NULL principal, therefore classification/SCI > 0
 * is denied rather than becoming an implicit authorization bypass.
 */
size_t qihse_keystone_ingest_dirty_logs(
    qihse_kv_store_t* kv,
    qihse_cluster_topology_t* topo,
    const char* buffer,
    size_t len,
    uint16_t clearance,
    uint16_t compartment);

int qihse_keystone_classify_context(
    const char* context,
    size_t len,
    qihse_keystone_class_t* out_class,
    float* out_confidence);

const char* qihse_keystone_class_name(qihse_keystone_class_t cls);

int64_t qihse_keystone_anchor_search(const int64_t* arr, size_t n, int64_t key);
size_t qihse_keystone_anchor_lower_bound(const int64_t* arr, size_t n, int64_t key);
size_t qihse_keystone_anchor_upper_bound(const int64_t* arr, size_t n, int64_t key);

#ifdef __cplusplus
}
#endif

#endif /* QIHSE_KEYSTONE_H */
