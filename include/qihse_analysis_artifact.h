#ifndef QIHSE_ANALYSIS_ARTIFACT_H
#define QIHSE_ANALYSIS_ARTIFACT_H

/* KP14 analysis artifact manifest v1. This is a bounded, in-memory contract,
 * NOT a durable ingest or read API. See docs/KP14_ANALYSIS_ARTIFACT.md. */
#include <stdbool.h>
#include <stdint.h>
#include "qihse_auth.h"
#include "qihse_blob.h"

#define QIHSE_ANALYSIS_ARTIFACT_VERSION 1u
#define QIHSE_ANALYSIS_ARTIFACT_MAX_INPUTS 8u
#define QIHSE_ANALYSIS_ARTIFACT_TEXT_BYTES 64u
#define QIHSE_ANALYSIS_ARTIFACT_CONTEXT_BYTES 32u
#define QIHSE_ANALYSIS_ARTIFACT_MAX_MANIFEST_BYTES 4096u

typedef enum {
    QIHSE_ANALYSIS_BINARY = 1,
    QIHSE_ANALYSIS_DISASSEMBLY,
    QIHSE_ANALYSIS_CFG,
    QIHSE_ANALYSIS_TRACE,
    QIHSE_ANALYSIS_SOLVER,
    QIHSE_ANALYSIS_VERDICT,
    QIHSE_ANALYSIS_REPORT
} qihse_analysis_kind_t;

typedef enum {
    QIHSE_ANALYSIS_PARTIAL = 1,
    QIHSE_ANALYSIS_COMPLETE
} qihse_analysis_completion_t;

typedef enum {
    QIHSE_ANALYSIS_FIDELITY_UNASSESSED = 1,
    QIHSE_ANALYSIS_FIDELITY_PARTIAL,
    QIHSE_ANALYSIS_FIDELITY_VALIDATED
} qihse_analysis_fidelity_t;

typedef struct {
    uint16_t version;
    uint16_t kind;
    uint16_t completion;
    uint16_t fidelity;
    uint32_t tenant_id;
    uint16_t classification;
    uint16_t sci;
    char artifact_schema[QIHSE_ANALYSIS_ARTIFACT_TEXT_BYTES];
    char producer[QIHSE_ANALYSIS_ARTIFACT_TEXT_BYTES];
    char producer_version[QIHSE_ANALYSIS_ARTIFACT_TEXT_BYTES];
    uint8_t run_id[16];
    uint64_t generation;
    uint8_t binary_sha384[QIHSE_BLOB_HASH_BYTES];
    char isa[QIHSE_ANALYSIS_ARTIFACT_CONTEXT_BYTES];
    char mode[QIHSE_ANALYSIS_ARTIFACT_CONTEXT_BYTES];
    uint16_t address_bits;
    /* Zero means this artifact does not depend on that authority/pack. */
    uint8_t isanity_catalogue_sha384[QIHSE_BLOB_HASH_BYTES];
    uint8_t vexel_pack_sha384[QIHSE_BLOB_HASH_BYTES];
    uint64_t payload_size;
    uint8_t payload_sha384[QIHSE_BLOB_HASH_BYTES];
    uint8_t input_count;
    uint8_t input_ids[QIHSE_ANALYSIS_ARTIFACT_MAX_INPUTS][QIHSE_BLOB_HASH_BYTES];
    /* SHA-384 of the canonical field stream, not C struct bytes. */
    uint8_t artifact_id[QIHSE_BLOB_HASH_BYTES];
} qihse_analysis_artifact_v1_t;

/* Build-time size ceiling; a future wire encoding must have its own bounded
 * decoder and may not treat compiler-specific struct layout as wire bytes. */
typedef char qihse_analysis_artifact_size_check[
    sizeof(qihse_analysis_artifact_v1_t) <= QIHSE_ANALYSIS_ARTIFACT_MAX_MANIFEST_BYTES ? 1 : -1];

/* Pure format validator and canonical identity computation. Neither reads
 * classified data; neither proves that payload or input IDs exist. */
bool qihse_analysis_artifact_compute_id(const qihse_analysis_artifact_v1_t* manifest,
                                        uint8_t out_id[QIHSE_BLOB_HASH_BYTES]);
bool qihse_analysis_artifact_validate(const qihse_analysis_artifact_v1_t* manifest);

/* Mandatory visibility gate for future classified-capable manifest reads and
 * exports. NULL, revoked, cross-tenant, above-clearance and missing SCI are
 * denied. Only a system-domain Operator may cross tenants. This is NOT
 * publisher/write authorization: ingestion needs a separate role/scope gate.
 * Never replace this with a context-free adapter. */
bool qihse_analysis_artifact_authorize_user(const qihse_analysis_artifact_v1_t* manifest,
                                            const qihse_user_t* user);

/* Publisher scope is separate from read clearance. Operators may publish
 * across tenants; tenant Analysts require an explicit per-tenant WRITE ACL.
 * Guests and system-domain Analysts cannot publish. */
#define QIHSE_ANALYSIS_PUBLISH_ACL_NAMESPACE 0x4b503134u /* "KP14" */
bool qihse_analysis_artifact_authorize_publisher(const qihse_analysis_artifact_v1_t* manifest,
                                                 const qihse_user_t* publisher);

/* Fail-closed, bounded candidate preflight. This does not write to a store,
 * reserve an ID, pin payload, or publish a feed event. The reader is invoked
 * only after publisher authorization; it must return 0 for EOF, <0 on error,
 * or 1..capacity bytes. No protected data is returned to the caller.
 * Derived artifacts deliberately remain LINEAGE_UNRESOLVED until an
 * authenticated immutable manifest store can prove every input. */
typedef enum {
    QIHSE_ANALYSIS_PREFLIGHT_DENIED = 0,
    QIHSE_ANALYSIS_PREFLIGHT_INVALID,
    QIHSE_ANALYSIS_PREFLIGHT_PAYLOAD_MISMATCH,
    QIHSE_ANALYSIS_PREFLIGHT_READ_ERROR,
    QIHSE_ANALYSIS_PREFLIGHT_LINEAGE_UNRESOLVED,
    QIHSE_ANALYSIS_PREFLIGHT_BINARY_VERIFIED
} qihse_analysis_preflight_result_t;
qihse_analysis_preflight_result_t qihse_analysis_artifact_preflight_user(
    const qihse_analysis_artifact_v1_t* manifest, qihse_user_t* publisher,
    qihse_blob_read_fn payload_reader, void* reader_opaque);

#endif
