#ifndef QIHSE_FABRIC_INDEX_H
#define QIHSE_FABRIC_INDEX_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#include "qihse_auth.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * AI compute fabric artifact indexing (ai_fabric.md build item 2).
 *
 * Every artifact stored under the `fabric:` KV prefix is handed to KEYSTONE
 * (~/Documents/KEYSTONE, C11/SIMD) once at the QIHSE ingest boundary so it is
 * semantically classified (DSMIL micro-model) and trigram indexed (candidate
 * postings only — KEYSTONE never retains artifact content, so no second copy
 * of classified data exists outside the authoritative KV store).
 *
 * KEYSTONE is a SOFT dependency: the library is located via dlopen at first
 * use (no link-time dependency). When it is absent, QIHSE builds and runs
 * normally and every function below fails closed with
 * QIHSE_FABRIC_INDEX_EUNAVAILABLE.
 *
 * Security posture (AGENTS.md invariants):
 *  - Lookup primitives are classified-capable search surfaces and therefore
 *    REQUIRE an authenticated qihse_user_t. NULL is denied, never a bypass.
 *  - Per-record authorization is enforced with qihse_auth_can_access() against
 *    the classification/SCI recorded at ingest time before any key material
 *    is disclosed.
 */

/* Semantic classes mirror KEYSTONE's dsmil_classification_t labels. */
typedef enum {
    QIHSE_FABRIC_CLASS_GENERIC = 0,
    QIHSE_FABRIC_CLASS_FINANCIAL = 1,
    QIHSE_FABRIC_CLASS_CORPORATE = 2,
    QIHSE_FABRIC_CLASS_GOVERNMENT = 3,
    QIHSE_FABRIC_CLASS_HEALTHCARE = 4,
    QIHSE_FABRIC_CLASS_TECHNOLOGY = 5,
    QIHSE_FABRIC_CLASS_UNKNOWN = 99 /* model confidence below threshold */
} qihse_fabric_index_class_t;

typedef enum {
    QIHSE_FABRIC_INDEX_OK = 0,
    QIHSE_FABRIC_INDEX_EINVAL = -1,      /* invalid parameters */
    QIHSE_FABRIC_INDEX_EUNAVAILABLE = -2, /* KEYSTONE library not present */
    QIHSE_FABRIC_INDEX_EDENIED = -3,      /* missing/insufficient user context */
    QIHSE_FABRIC_INDEX_EIO = -4,          /* index segment or manifest failure */
    QIHSE_FABRIC_INDEX_EFULL = -5         /* record capacity exceeded */
} qihse_fabric_index_result_t;

typedef struct {
    uint64_t seq; /* monotonically increasing index sequence number */
    char key[256];
    qihse_fabric_index_class_t semantic_class;
    float confidence;
    uint16_t classification;    /* data classification at ingest */
    uint16_t sci_compartment;   /* SCI compartment at ingest */
} qihse_fabric_index_record_t;

/*
 * Explicitly configure and initialize the fabric index.
 *
 * index_dir: persistent index/manifest directory. NULL selects
 *            $QIHSE_FABRIC_INDEX_DIR, then /var/lib/qihse/fabric_index with a
 *            /tmp/qihse_fabric_index fallback.
 * library:   explicit libkeystone.so path. NULL selects $QIHSE_KEYSTONE_LIB,
 *            then $HOME/Documents/KEYSTONE/libkeystone.so, ./libkeystone.so,
 *            then the loader search path.
 *
 * Idempotent: re-initialization with a different configuration returns the
 * current state without reloading. Returns QIHSE_FABRIC_INDEX_OK when KEYSTONE
 * is loaded, QIHSE_FABRIC_INDEX_EUNAVAILABLE when it is not (the index is then
 * a no-op but all calls remain safe), EINVAL on bad arguments.
 */
int qihse_fabric_index_init(const char* index_dir, const char* library);

/* Release the KEYSTONE handle and cached state. Safe to call twice. */
void qihse_fabric_index_shutdown(void);

/* True once the KEYSTONE library has been successfully loaded. */
bool qihse_fabric_index_is_available(void);

/*
 * Classify + index one fabric artifact. Called from the write path after the
 * KV write is authorized and persisted; the write-time classification/SCI
 * context is recorded with the index record so later lookups can be gated.
 * The caller's user context is authorization-checked against the declared
 * classification (defense in depth on top of the KV write gate).
 * Keys containing tabs/newlines or exceeding 255 bytes are rejected (EINVAL).
 */
int qihse_fabric_index_artifact_user(const char* key,
                                     const char* value,
                                     size_t value_len,
                                     uint16_t classification,
                                     uint16_t sci_compartment,
                                     qihse_user_t* user);

/*
 * Trigram candidate lookup: returns indexed fabric records whose content
 * contains `pattern` (substring candidates from KEYSTONE postings; verify
 * exact content against the authoritative KV store). Candidates are filtered
 * per-record through qihse_auth_can_access(); an unauthenticated (NULL) user
 * is denied outright. Patterns shorter than three bytes match every record.
 * Records whose artifact was overwritten in KV remain listed until compaction;
 * `seq` orders versions.
 */
int qihse_fabric_index_lookup_user(const char* pattern,
                                   qihse_user_t* user,
                                   qihse_fabric_index_record_t* out_records,
                                   size_t max_records,
                                   size_t* out_count);

/*
 * Semantic-class listing: returns indexed fabric records classified as `cls`
 * (QIHSE_FABRIC_CLASS_UNKNOWN selects low-confidence artifacts). Same
 * authorization rules as qihse_fabric_index_lookup_user().
 */
int qihse_fabric_index_by_class_user(qihse_fabric_index_class_t cls,
                                     qihse_user_t* user,
                                     qihse_fabric_index_record_t* out_records,
                                     size_t max_records,
                                     size_t* out_count);

/* Number of indexed fabric records currently tracked. */
size_t qihse_fabric_index_record_count(void);

const char* qihse_fabric_index_class_name(qihse_fabric_index_class_t cls);

/* KEYSTONE version string, or NULL when the library is unavailable. */
const char* qihse_fabric_index_keystone_version(void);

#ifdef __cplusplus
}
#endif

#endif /* QIHSE_FABRIC_INDEX_H */
