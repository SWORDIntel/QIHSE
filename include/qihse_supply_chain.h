#ifndef QIHSE_SUPPLY_CHAIN_H
#define QIHSE_SUPPLY_CHAIN_H

/*
 * QIHSE supply-chain substrate — federation stage F6.
 *
 * Makes QIHSE the authoritative provenance graph for Citadel software
 * artifacts, and the durable coordination state for the Adaptive Federated
 * Build Fabric.
 * See docs/plans/qihse_federation_upgrade_plan.md §27–§35.
 *
 * Boundaries (plan §28, §42):
 *   QIHSE stores job state, source identity, builder capability metadata,
 *   lease state, artifact references, verification state, and audit trail.
 *   QIHSE does NOT invoke compilers or execute arbitrary commands, and it
 *   never holds private signing keys (plan §32).
 *
 * Every primitive takes an explicit authenticated user (AGENTS.md
 * invariant 1).  The KEYSTONE indexer holds FEDERATION_READ only, so it can
 * index these records without becoming authoritative (acceptance criterion
 * 22).
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "qihse_federation.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ────────────────────────────────────────────────────────────────────────
 * Provenance graph (plan §31)
 * ──────────────────────────────────────────────────────────────────────── */

/* Core entity types. */
typedef enum {
    QIHSE_PROV_SOURCE_REPOSITORY = 0,
    QIHSE_PROV_SOURCE_REVISION,
    QIHSE_PROV_SOURCE_ARCHIVE,
    QIHSE_PROV_PATCHSET,
    QIHSE_PROV_BUILD_RECIPE,
    QIHSE_PROV_BUILD_PROFILE,
    QIHSE_PROV_TOOLCHAIN,
    QIHSE_PROV_BUILD_DEPENDENCY,
    QIHSE_PROV_BUILDER_NODE,
    QIHSE_PROV_BUILD_WORKER_IMAGE,
    QIHSE_PROV_BUILD_JOB,
    QIHSE_PROV_TEST_RESULT,
    QIHSE_PROV_OUTPUT_ARTIFACT,
    QIHSE_PROV_DEB_PACKAGE,
    QIHSE_PROV_SBOM,
    QIHSE_PROV_ATTESTATION,
    QIHSE_PROV_APT_REPOSITORY_SNAPSHOT,
    QIHSE_PROV_ROOT_IMAGE,
    QIHSE_PROV_DEPLOYMENT,
    QIHSE_PROV_NODE,
    QIHSE_PROV_VULNERABILITY_OBSERVATION,
    QIHSE_PROV_ENTITY_COUNT
} qihse_prov_entity_t;

const char* qihse_prov_entity_name(qihse_prov_entity_t entity);
bool qihse_prov_entity_parse(const char* name, qihse_prov_entity_t* out);

/* Representative edges. */
typedef enum {
    QIHSE_PROV_EDGE_DERIVED_FROM = 0,
    QIHSE_PROV_EDGE_PATCHED_BY,
    QIHSE_PROV_EDGE_BUILT_WITH,
    QIHSE_PROV_EDGE_BUILD_DEPENDS_ON,
    QIHSE_PROV_EDGE_BUILT_ON,
    QIHSE_PROV_EDGE_BUILT_IN,
    QIHSE_PROV_EDGE_PRODUCES,
    QIHSE_PROV_EDGE_DESCRIBED_BY,
    QIHSE_PROV_EDGE_ATTESTED_BY,
    QIHSE_PROV_EDGE_PUBLISHED_IN,
    QIHSE_PROV_EDGE_CONTAINED_IN,
    QIHSE_PROV_EDGE_DEPLOYED_TO,
    QIHSE_PROV_EDGE_AFFECTED_BY,
    QIHSE_PROV_EDGE_SUPERSEDES,
    QIHSE_PROV_EDGE_VERIFIED_AGAINST,
    QIHSE_PROV_EDGE_COUNT
} qihse_prov_edge_t;

const char* qihse_prov_edge_name(qihse_prov_edge_t edge);
bool qihse_prov_edge_parse(const char* name, qihse_prov_edge_t* out);

/* A graph node.  Artifact-bearing entities use a cryptographic digest as
 * their stable identity (plan §31). */
#define QIHSE_PROV_ID_MAX 128u
#define QIHSE_PROV_LABEL_MAX 192u
#define QIHSE_PROV_DIGEST_MAX 64u   /* lowercase hex, e.g. sha384 = 96 chars */

typedef struct {
    qihse_prov_entity_t entity;
    char id[QIHSE_PROV_ID_MAX + 1u];        /* digest or UUID, entity-scoped */
    char label[QIHSE_PROV_LABEL_MAX + 1u];  /* human-readable, optional */
    char digest[QIHSE_PROV_DIGEST_MAX * 2u + 1u]; /* content digest, optional */
    uint64_t created_hlc_physical;
    qihse_uuid_t created_by;
    bool immutable;  /* set for SBOM/attestation/snapshot records */
} qihse_prov_node_t;

#define QIHSE_PROV_NODE_PREFIX "provnode:"
#define QIHSE_PROV_EDGE_PREFIX "provedge:"

/* Upsert a graph node.  Immutable nodes cannot be overwritten once created
 * (acceptance criterion 20). */
bool qihse_provenance_node_put(void* store_void, void* user_void,
                               const qihse_prov_node_t* node);
bool qihse_provenance_node_get(void* store_void, void* user_void,
                               qihse_prov_entity_t entity, const char* id,
                               qihse_prov_node_t* out);
bool qihse_provenance_node_delete(void* store_void, void* user_void,
                                  qihse_prov_entity_t entity, const char* id);

/* Record an edge from -> to.  Idempotent: re-recording the same edge is a
 * no-op that returns true. */
bool qihse_provenance_edge_put(void* store_void, void* user_void,
                               qihse_prov_entity_t from_entity, const char* from_id,
                               qihse_prov_edge_t edge,
                               qihse_prov_entity_t to_entity, const char* to_id);
bool qihse_provenance_edge_has(void* store_void, void* user_void,
                               qihse_prov_entity_t from_entity, const char* from_id,
                               qihse_prov_edge_t edge,
                               qihse_prov_entity_t to_entity, const char* to_id);

/* A traversal hit. */
typedef struct {
    qihse_prov_entity_t entity;
    char id[QIHSE_PROV_ID_MAX + 1u];
    qihse_prov_edge_t via_edge;
    uint32_t depth;
} qihse_prov_hit_t;

/* Traversal visitor.  Returning false stops the walk. */
typedef bool (*qihse_prov_visit_cb)(const qihse_prov_hit_t* hit, void* user_data);

/* Walk edges forward from a node: "what did this produce / where did this
 * go?".  Used for artifact -> deployment questions. */
size_t qihse_provenance_trace_forward(void* store_void, void* user_void,
                                      qihse_prov_entity_t entity, const char* id,
                                      uint32_t max_depth,
                                      qihse_prov_visit_cb cb, void* user_data);

/* Walk edges backward from a node: "what produced this / where is it
 * deployed?".  This is the acceptance-criterion 15 (trace a deployed
 * package back to source) and criterion 21 (reverse-impact) direction. */
size_t qihse_provenance_trace_reverse(void* store_void, void* user_void,
                                      qihse_prov_entity_t entity, const char* id,
                                      uint32_t max_depth,
                                      qihse_prov_visit_cb cb, void* user_data);

/* Restrict a reverse trace to hits of one entity type (e.g. NODE for a
 * reverse-impact query).  Returns the number of matching hits. */
size_t qihse_provenance_reverse_impact(void* store_void, void* user_void,
                                       qihse_prov_entity_t from_entity, const char* from_id,
                                       qihse_prov_entity_t want_entity,
                                       uint32_t max_depth,
                                       qihse_prov_visit_cb cb, void* user_data);

/* ────────────────────────────────────────────────────────────────────────
 * Package override policy (plan §27)
 * ──────────────────────────────────────────────────────────────────────── */

typedef enum {
    QIHSE_PKG_UPSTREAM_BINARY = 0,
    QIHSE_PKG_UPSTREAM_SOURCE_REBUILD,
    QIHSE_PKG_CITADEL_OVERLAY,
    QIHSE_PKG_CITADEL_FORK,
    QIHSE_PKG_FORBIDDEN,
    QIHSE_PKG_ISOLATED_EXCEPTION
} qihse_pkg_mode_t;

const char* qihse_pkg_mode_name(qihse_pkg_mode_t mode);
bool qihse_pkg_mode_parse(const char* name, qihse_pkg_mode_t* out);

typedef struct {
    char package[128];
    qihse_pkg_mode_t mode;
    char reason[256];              /* required — every override has a reason */
    qihse_uuid_t decided_by;
    uint64_t decided_hlc_physical;
    uint64_t policy_generation;
} qihse_pkg_policy_t;

#define QIHSE_PKG_POLICY_PREFIX "pkgpolicy:"

/* Set a package policy.  A reason is mandatory: an override without a
 * recorded reason is refused. */
bool qihse_pkg_policy_set(void* store_void, void* user_void,
                          const qihse_pkg_policy_t* policy);
bool qihse_pkg_policy_get(void* store_void, void* user_void,
                          const char* package, qihse_pkg_policy_t* out);

/* ────────────────────────────────────────────────────────────────────────
 * Build job state machine (plan §28)
 * ──────────────────────────────────────────────────────────────────────── */

typedef enum {
    QIHSE_BUILD_QUEUED = 0,
    QIHSE_BUILD_PLANNING,
    QIHSE_BUILD_LEASED,
    QIHSE_BUILD_BUILDING,
    QIHSE_BUILD_TESTING,
    QIHSE_BUILD_VERIFYING,
    QIHSE_BUILD_SIGNING,
    QIHSE_BUILD_PUBLISHED,
    /* failure / terminal states */
    QIHSE_BUILD_FAILED,
    QIHSE_BUILD_RETRYABLE,
    QIHSE_BUILD_QUARANTINED,
    QIHSE_BUILD_CANCELLED
} qihse_build_state_t;

const char* qihse_build_state_name(qihse_build_state_t state);
bool qihse_build_state_parse(const char* name, qihse_build_state_t* out);
/* True for FAILED / RETRYABLE / QUARANTINED / CANCELLED. */
bool qihse_build_state_is_failure(qihse_build_state_t state);
/* True when no further transition is legal. */
bool qihse_build_state_is_terminal(qihse_build_state_t state);

typedef struct {
    qihse_uuid_t build_id;
    char package[128];
    char source_revision[128];
    char profile[64];
    char toolchain[64];
    qihse_build_state_t state;
    uint64_t generation;          /* bumped on every accepted transition */
    qihse_uuid_t owner_node;      /* builder holding the lease, if any */
    qihse_uuid_t lease_id;
    char artifact_digest[QIHSE_PROV_DIGEST_MAX * 2u + 1u];
    char failure_reason[256];
    uint64_t created_hlc_physical;
    uint64_t updated_hlc_physical;
    qihse_uuid_t last_request_id; /* idempotency for the last transition */
} qihse_build_job_t;

#define QIHSE_BUILD_JOB_PREFIX "buildjob:"
#define QIHSE_BUILD_REQ_PREFIX "buildreq:"

/* Create a build job in QUEUED.  Idempotent on build_id: a repeated create
 * returns the existing job rather than resetting its state. */
bool qihse_build_job_create(void* store_void, void* user_void,
                            const qihse_build_job_t* job,
                            qihse_build_job_t* out);
bool qihse_build_job_get(void* store_void, void* user_void,
                         const qihse_uuid_t* build_id, qihse_build_job_t* out);

/* Transition a job.  Enforces the legal state graph, requires a request_id
 * for idempotency, and bumps the generation.  A repeated request_id is a
 * no-op that returns the current job (acceptance criterion 18). */
bool qihse_build_job_transition(void* store_void, void* user_void,
                                const qihse_uuid_t* build_id,
                                qihse_build_state_t next,
                                const qihse_uuid_t* request_id,
                                const char* failure_reason,
                                qihse_build_job_t* out);

typedef bool (*qihse_build_job_cb)(const qihse_build_job_t* job, void* user_data);
void qihse_build_job_foreach(void* store_void, void* user_void,
                             qihse_build_job_cb cb, void* user_data);

/* ────────────────────────────────────────────────────────────────────────
 * Builder capability and historical performance (plan §29)
 * ──────────────────────────────────────────────────────────────────────── */

typedef struct {
    qihse_uuid_t node_id;
    char cpu_model[128];
    uint32_t cores_total;
    uint32_t cores_available;
    uint64_t ram_total_gb;
    uint64_t ram_available_gb;
    uint64_t scratch_available_gb;
    char isa[128];                 /* comma-separated, e.g. "sse4.2,avx2,fma" */
    uint32_t load_1m_milli;        /* load average x1000, integer-only */
    uint32_t thermal_headroom_milli; /* 0..1000 */
    uint32_t build_queue_depth;
    qihse_trust_state_t trust_state;
    uint64_t observed_hlc_physical;
} qihse_builder_capability_t;

#define QIHSE_BUILDER_CAP_PREFIX "buildcap:"

bool qihse_builder_capability_put(void* store_void, void* user_void,
                                  const qihse_builder_capability_t* cap);
bool qihse_builder_capability_get(void* store_void, void* user_void,
                                  const qihse_uuid_t* node_id,
                                  qihse_builder_capability_t* out);

/* A historical build execution record.  These let Citadel estimate
 * completion time from real measurements rather than nominal specs. */
typedef struct {
    qihse_uuid_t execution_id;
    qihse_uuid_t build_id;
    char package[128];
    char source_revision[128];
    char profile[64];
    char toolchain[64];
    qihse_uuid_t builder_node;
    uint32_t allocated_cores;
    uint64_t peak_ram_mb;
    uint64_t build_duration_ms;
    uint64_t test_duration_ms;
    uint64_t artifact_size_bytes;
    bool succeeded;
} qihse_build_history_t;

#define QIHSE_BUILD_HISTORY_PREFIX "buildhist:"

bool qihse_build_history_record(void* store_void, void* user_void,
                                const qihse_build_history_t* rec);
/* Mean build duration in ms for a package across recorded executions.
 * Returns false when no history exists. */
bool qihse_build_history_mean_duration(void* store_void, void* user_void,
                                       const char* package, uint64_t* out_mean_ms);

/* ────────────────────────────────────────────────────────────────────────
 * SBOM and attestation records (plan §32)
 * ──────────────────────────────────────────────────────────────────────── */

typedef struct {
    qihse_uuid_t sbom_id;
    char artifact_digest[QIHSE_PROV_DIGEST_MAX * 2u + 1u];
    char sbom_digest[QIHSE_PROV_DIGEST_MAX * 2u + 1u];
    char provenance_digest[QIHSE_PROV_DIGEST_MAX * 2u + 1u];
    char signing_identity[128];
    char signature_algorithm[64];
    char signature[512];
    /* A key handle, never the key itself — QIHSE holds no private signing
     * keys (plan §32, acceptance criterion 17). */
    char signing_key_handle[160];
    uint64_t signature_hlc_physical;
    uint64_t policy_generation;
    char verification_status[32];
    char format[32];               /* spdx | cyclonedx | internal */
} qihse_sbom_record_t;

#define QIHSE_SBOM_PREFIX "supply/sbom:"
#define QIHSE_ATTESTATION_PREFIX "supply/attestation:"

/* Record an SBOM.  Immutable: a second record for the same sbom_id is
 * refused, so historical signed evidence is never rewritten (criterion 20). */
bool qihse_sbom_record_put(void* store_void, void* user_void,
                           const qihse_sbom_record_t* rec);
bool qihse_sbom_record_get(void* store_void, void* user_void,
                           const qihse_uuid_t* sbom_id,
                           qihse_sbom_record_t* out);
/* Find SBOMs describing an artifact digest.  Returns the number found. */
size_t qihse_sbom_find_by_artifact(void* store_void, void* user_void,
                                   const char* artifact_digest,
                                   qihse_uuid_t* out_ids, size_t out_cap);

/* ────────────────────────────────────────────────────────────────────────
 * Immutable vulnerability observations (plan §33)
 * ──────────────────────────────────────────────────────────────────────── */

typedef struct {
    qihse_uuid_t observation_id;
    char component[192];           /* affected component identity */
    char component_digest[QIHSE_PROV_DIGEST_MAX * 2u + 1u];
    char advisory_id[64];          /* CVE / GHSA / vendor id */
    char severity[16];             /* none | low | medium | high | critical */
    char status[24];               /* open | fixed | wont_fix | under_review */
    char scanner[64];
    char evidence[256];
    uint64_t observed_hlc_physical;
} qihse_vuln_observation_t;

#define QIHSE_VULN_PREFIX "supply/vuln:"

/* Record an observation.  Observations are append-only: recording a new
 * observation never mutates a historical SBOM (plan §33, criterion 20). */
bool qihse_vuln_observation_put(void* store_void, void* user_void,
                                const qihse_vuln_observation_t* obs);
bool qihse_vuln_observation_get(void* store_void, void* user_void,
                                const qihse_uuid_t* observation_id,
                                qihse_vuln_observation_t* out);
/* Count observations for a component digest. */
size_t qihse_vuln_count_by_component(void* store_void, void* user_void,
                                     const char* component_digest);

/* ────────────────────────────────────────────────────────────────────────
 * Immutable repository snapshots (plan §32, criterion 19)
 * ──────────────────────────────────────────────────────────────────────── */

typedef struct {
    qihse_uuid_t snapshot_id;
    char repository[128];
    char snapshot_digest[QIHSE_PROV_DIGEST_MAX * 2u + 1u];
    char release[64];
    uint64_t package_count;
    char signing_key_handle[160];  /* handle only, never a private key */
    uint64_t created_hlc_physical;
    qihse_uuid_t created_by;
} qihse_repo_snapshot_t;

#define QIHSE_REPO_SNAPSHOT_PREFIX "supply/repository-snapshot:"

/* Record a snapshot.  Immutable and queryable (criterion 19). */
bool qihse_repo_snapshot_put(void* store_void, void* user_void,
                             const qihse_repo_snapshot_t* snap);
bool qihse_repo_snapshot_get(void* store_void, void* user_void,
                             const qihse_uuid_t* snapshot_id,
                             qihse_repo_snapshot_t* out);
typedef bool (*qihse_repo_snapshot_cb)(const qihse_repo_snapshot_t* snap, void* user_data);
void qihse_repo_snapshot_foreach(void* store_void, void* user_void,
                                 const char* repository,
                                 qihse_repo_snapshot_cb cb, void* user_data);

#ifdef __cplusplus
}
#endif

#endif /* QIHSE_SUPPLY_CHAIN_H */
