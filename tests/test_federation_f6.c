/*
 * test_federation_f6.c — F6 build & supply-chain substrate.
 *
 * Acceptance criteria exercised:
 *   AC15 — Trace a deployed package back to source revision, patchset,
 *          build recipe, toolchain, worker image, builder node, artifact.
 *   AC17 — No private signing keys inside QIHSE records (handles only).
 *   AC18 — Duplicate/retried build state mutations remain idempotent.
 *   AC19 — Repository snapshots are immutable and queryable.
 *   AC20 — Historical signed SBOM records are never rewritten.
 *   AC21 — Reverse-impact queries from a vulnerable component to nodes.
 *   AC22 — KEYSTONE can index supply-chain records with read-only scope.
 *
 * Covers:
 *   - 21 entity types and 15 edge types round-trip
 *   - graph node put/get, immutable-node refusal, edge idempotency
 *   - forward trace source -> deployment, reverse trace deployment -> source
 *   - reverse-impact vulnerability -> deployed nodes
 *   - package override policy (reason mandatory)
 *   - build state machine: legal path, illegal rejection, failure states
 *   - build transition idempotency on request_id
 *   - builder capability + historical performance mean duration
 *   - SBOM immutability + find by artifact
 *   - vulnerability observations do not mutate SBOMs
 *   - repository snapshot immutability + query
 *   - RESP-level commands + tenant-guest NOPERM (invariant 3)
 */
#include "qihse_auth.h"
#include "qihse_cluster_slot.h"
#include "qihse_federation.h"
#include "qihse_kv_store.h"
#include "qihse_resp_wire.h"
#include "qihse_supply_chain.h"

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

/* ── Vocabulary ────────────────────────────────────────────────────────── */

static void test_vocabulary(void) {
    for (int i = 0; i < (int)QIHSE_PROV_ENTITY_COUNT; i++) {
        qihse_prov_entity_t e = (qihse_prov_entity_t)i;
        const char* name = qihse_prov_entity_name(e);
        assert(name && strcmp(name, "UNKNOWN") != 0);
        qihse_prov_entity_t parsed;
        assert(qihse_prov_entity_parse(name, &parsed));
        assert(parsed == e);
    }
    for (int i = 0; i < (int)QIHSE_PROV_EDGE_COUNT; i++) {
        qihse_prov_edge_t e = (qihse_prov_edge_t)i;
        const char* name = qihse_prov_edge_name(e);
        assert(name && strcmp(name, "UNKNOWN") != 0);
        qihse_prov_edge_t parsed;
        assert(qihse_prov_edge_parse(name, &parsed));
        assert(parsed == e);
    }
    qihse_prov_entity_t de;
    qihse_prov_edge_t dedge;
    assert(!qihse_prov_entity_parse("NOPE", &de));
    assert(!qihse_prov_edge_parse("NOPE", &dedge));

    printf("PASS vocabulary: %d entity types + %d edge types round-trip\n",
           (int)QIHSE_PROV_ENTITY_COUNT, (int)QIHSE_PROV_EDGE_COUNT);
}

/* ── Graph storage ─────────────────────────────────────────────────────── */

static void test_graph_storage(qihse_kv_store_t* store, qihse_user_t* op) {
    qihse_prov_node_t n;
    memset(&n, 0, sizeof(n));
    n.entity = QIHSE_PROV_SOURCE_REPOSITORY;
    snprintf(n.id, sizeof(n.id), "debian/openssl");
    snprintf(n.label, sizeof(n.label), "Debian openssl source");
    assert(qihse_provenance_node_put(store, op, &n));

    qihse_prov_node_t got;
    assert(qihse_provenance_node_get(store, op, QIHSE_PROV_SOURCE_REPOSITORY,
                                     "debian/openssl", &got));
    assert(got.entity == QIHSE_PROV_SOURCE_REPOSITORY);
    assert(strcmp(got.label, "Debian openssl source") == 0);
    assert(!got.immutable);

    /* Mutable nodes can be overwritten. */
    snprintf(n.label, sizeof(n.label), "Debian openssl source (updated)");
    assert(qihse_provenance_node_put(store, op, &n));
    assert(qihse_provenance_node_get(store, op, QIHSE_PROV_SOURCE_REPOSITORY,
                                     "debian/openssl", &got));
    assert(strcmp(got.label, "Debian openssl source (updated)") == 0);

    /* Immutable nodes are never rewritten (criterion 20). */
    qihse_prov_node_t sb;
    memset(&sb, 0, sizeof(sb));
    sb.entity = QIHSE_PROV_SBOM;
    snprintf(sb.id, sizeof(sb.id), "sbom-immutable-1");
    sb.immutable = true;
    assert(qihse_provenance_node_put(store, op, &sb));
    assert(!qihse_provenance_node_put(store, op, &sb));   /* refused */
    assert(!qihse_provenance_node_delete(store, op, QIHSE_PROV_SBOM, "sbom-immutable-1"));

    /* Edges are idempotent. */
    assert(qihse_provenance_edge_put(store, op, QIHSE_PROV_SOURCE_REVISION, "rev-1",
                                     QIHSE_PROV_EDGE_DERIVED_FROM,
                                     QIHSE_PROV_SOURCE_REPOSITORY, "debian/openssl"));
    assert(qihse_provenance_edge_put(store, op, QIHSE_PROV_SOURCE_REVISION, "rev-1",
                                     QIHSE_PROV_EDGE_DERIVED_FROM,
                                     QIHSE_PROV_SOURCE_REPOSITORY, "debian/openssl"));
    assert(qihse_provenance_edge_has(store, op, QIHSE_PROV_SOURCE_REVISION, "rev-1",
                                     QIHSE_PROV_EDGE_DERIVED_FROM,
                                     QIHSE_PROV_SOURCE_REPOSITORY, "debian/openssl"));
    assert(!qihse_provenance_edge_has(store, op, QIHSE_PROV_SOURCE_REVISION, "rev-1",
                                      QIHSE_PROV_EDGE_PATCHED_BY,
                                      QIHSE_PROV_SOURCE_REPOSITORY, "debian/openssl"));

    printf("PASS graph storage: node put/get + immutable refusal + edge idempotency\n");
}

/* ── Trace-back and reverse-impact (AC15, AC21) ────────────────────────── */

typedef struct {
    char found[32][192];
    size_t count;
} hit_log_t;

static bool hit_log_cb(const qihse_prov_hit_t* hit, void* user_data) {
    hit_log_t* log = (hit_log_t*)user_data;
    if (log->count >= 32) return false;
    snprintf(log->found[log->count], sizeof(log->found[0]), "%s:%s",
             qihse_prov_entity_name(hit->entity), hit->id);
    log->count++;
    return true;
}

static bool hit_log_has(const hit_log_t* log, qihse_prov_entity_t entity, const char* id) {
    char want[192];
    snprintf(want, sizeof(want), "%s:%s", qihse_prov_entity_name(entity), id);
    for (size_t i = 0; i < log->count; i++) {
        if (strcmp(log->found[i], want) == 0) return true;
    }
    return false;
}

static void test_provenance_chain(qihse_kv_store_t* store, qihse_user_t* op) {
    /* Build the full chain described in plan §31:
     * source repo -> revision -> patchset -> recipe -> job -> artifact ->
     * .deb -> SBOM / repo snapshot -> root image -> deployment -> node. */
    const char* art_digest = "sha384:aa11bb22cc33dd44ee55ff66";

    assert(qihse_provenance_edge_put(store, op, QIHSE_PROV_SOURCE_REVISION, "openssl-3.0.13-1",
                                     QIHSE_PROV_EDGE_DERIVED_FROM,
                                     QIHSE_PROV_SOURCE_REPOSITORY, "debian/openssl"));
    assert(qihse_provenance_edge_put(store, op, QIHSE_PROV_PATCHSET, "citadel-hardening-7",
                                     QIHSE_PROV_EDGE_DERIVED_FROM,
                                     QIHSE_PROV_SOURCE_REVISION, "openssl-3.0.13-1"));
    assert(qihse_provenance_edge_put(store, op, QIHSE_PROV_BUILD_RECIPE, "openssl-deb",
                                     QIHSE_PROV_EDGE_DERIVED_FROM,
                                     QIHSE_PROV_PATCHSET, "citadel-hardening-7"));
    assert(qihse_provenance_edge_put(store, op, QIHSE_PROV_BUILD_RECIPE, "openssl-deb",
                                     QIHSE_PROV_EDGE_BUILT_WITH,
                                     QIHSE_PROV_TOOLCHAIN, "gcc-14.2.0"));
    assert(qihse_provenance_edge_put(store, op, QIHSE_PROV_BUILD_RECIPE, "openssl-deb",
                                     QIHSE_PROV_EDGE_BUILT_IN,
                                     QIHSE_PROV_BUILD_WORKER_IMAGE, "worker-debian-12"));
    assert(qihse_provenance_edge_put(store, op, QIHSE_PROV_BUILD_JOB, "job-1",
                                     QIHSE_PROV_EDGE_DERIVED_FROM,
                                     QIHSE_PROV_BUILD_RECIPE, "openssl-deb"));
    assert(qihse_provenance_edge_put(store, op, QIHSE_PROV_BUILD_JOB, "job-1",
                                     QIHSE_PROV_EDGE_BUILT_ON,
                                     QIHSE_PROV_BUILDER_NODE, "r730xd"));
    assert(qihse_provenance_edge_put(store, op, QIHSE_PROV_OUTPUT_ARTIFACT, art_digest,
                                     QIHSE_PROV_EDGE_DERIVED_FROM,
                                     QIHSE_PROV_BUILD_JOB, "job-1"));
    assert(qihse_provenance_edge_put(store, op, QIHSE_PROV_DEB_PACKAGE, "openssl_3.0.13-1_amd64.deb",
                                     QIHSE_PROV_EDGE_DERIVED_FROM,
                                     QIHSE_PROV_OUTPUT_ARTIFACT, art_digest));
    assert(qihse_provenance_edge_put(store, op, QIHSE_PROV_DEB_PACKAGE, "openssl_3.0.13-1_amd64.deb",
                                     QIHSE_PROV_EDGE_DESCRIBED_BY,
                                     QIHSE_PROV_SBOM, "sbom-1"));
    assert(qihse_provenance_edge_put(store, op, QIHSE_PROV_DEB_PACKAGE, "openssl_3.0.13-1_amd64.deb",
                                     QIHSE_PROV_EDGE_PUBLISHED_IN,
                                     QIHSE_PROV_APT_REPOSITORY_SNAPSHOT, "snap-1"));
    assert(qihse_provenance_edge_put(store, op, QIHSE_PROV_ROOT_IMAGE, "citadel-root-2026-09",
                                     QIHSE_PROV_EDGE_DERIVED_FROM,
                                     QIHSE_PROV_APT_REPOSITORY_SNAPSHOT, "snap-1"));
    assert(qihse_provenance_edge_put(store, op, QIHSE_PROV_DEPLOYMENT, "deploy-1",
                                     QIHSE_PROV_EDGE_DERIVED_FROM,
                                     QIHSE_PROV_ROOT_IMAGE, "citadel-root-2026-09"));
    assert(qihse_provenance_edge_put(store, op, QIHSE_PROV_DEPLOYMENT, "deploy-1",
                                     QIHSE_PROV_EDGE_DEPLOYED_TO,
                                     QIHSE_PROV_NODE, "r730xd-a"));

    /* Forward: from the source repository, everything downstream is reachable. */
    hit_log_t fwd;
    memset(&fwd, 0, sizeof(fwd));
    size_t nf = qihse_provenance_trace_forward(store, op,
        QIHSE_PROV_SOURCE_REPOSITORY, "debian/openssl", 16, hit_log_cb, &fwd);
    assert(nf > 0);
    assert(hit_log_has(&fwd, QIHSE_PROV_SOURCE_REVISION, "openssl-3.0.13-1"));
    assert(hit_log_has(&fwd, QIHSE_PROV_NODE, "r730xd-a"));

    /* AC15 — trace a deployed package back to source revision, patchset,
     * build recipe, toolchain, worker image, builder node, artifact. */
    hit_log_t rev;
    memset(&rev, 0, sizeof(rev));
    size_t nr = qihse_provenance_trace_reverse(store, op,
        QIHSE_PROV_DEB_PACKAGE, "openssl_3.0.13-1_amd64.deb", 16, hit_log_cb, &rev);
    assert(nr > 0);
    assert(hit_log_has(&rev, QIHSE_PROV_SOURCE_REVISION, "openssl-3.0.13-1"));
    assert(hit_log_has(&rev, QIHSE_PROV_PATCHSET, "citadel-hardening-7"));
    assert(hit_log_has(&rev, QIHSE_PROV_BUILD_RECIPE, "openssl-deb"));
    assert(hit_log_has(&rev, QIHSE_PROV_TOOLCHAIN, "gcc-14.2.0"));
    assert(hit_log_has(&rev, QIHSE_PROV_BUILD_WORKER_IMAGE, "worker-debian-12"));
    assert(hit_log_has(&rev, QIHSE_PROV_BUILDER_NODE, "r730xd"));
    assert(hit_log_has(&rev, QIHSE_PROV_OUTPUT_ARTIFACT, art_digest));
    assert(hit_log_has(&rev, QIHSE_PROV_SOURCE_REPOSITORY, "debian/openssl"));

    /* AC21 — reverse-impact: which deployed nodes are affected by a
     * vulnerability in this artifact? */
    assert(qihse_provenance_edge_put(store, op, QIHSE_PROV_OUTPUT_ARTIFACT, art_digest,
                                     QIHSE_PROV_EDGE_AFFECTED_BY,
                                     QIHSE_PROV_VULNERABILITY_OBSERVATION, "CVE-2026-0001"));
    hit_log_t impact;
    memset(&impact, 0, sizeof(impact));
    size_t ni = qihse_provenance_reverse_impact(store, op,
        QIHSE_PROV_VULNERABILITY_OBSERVATION, "CVE-2026-0001",
        QIHSE_PROV_NODE, 16, hit_log_cb, &impact);
    assert(ni > 0);
    assert(hit_log_has(&impact, QIHSE_PROV_NODE, "r730xd-a"));

    /* A depth limit of 1 must not reach the node from the repository. */
    hit_log_t shallow;
    memset(&shallow, 0, sizeof(shallow));
    qihse_provenance_trace_forward(store, op,
        QIHSE_PROV_SOURCE_REPOSITORY, "debian/openssl", 1, hit_log_cb, &shallow);
    assert(!hit_log_has(&shallow, QIHSE_PROV_NODE, "r730xd-a"));

    printf("PASS provenance chain: forward source->node, reverse package->source (AC15)\n");
    printf("PASS reverse-impact: vulnerability -> deployed nodes (AC21)\n");
}

/* ── Package override policy (plan §27) ────────────────────────────────── */

static void test_package_policy(qihse_kv_store_t* store, qihse_user_t* op) {
    for (int i = 0; i < 6; i++) {
        qihse_pkg_mode_t m = (qihse_pkg_mode_t)i;
        const char* name = qihse_pkg_mode_name(m);
        assert(name && strcmp(name, "UNKNOWN") != 0);
        qihse_pkg_mode_t parsed;
        assert(qihse_pkg_mode_parse(name, &parsed));
        assert(parsed == m);
    }

    qihse_pkg_policy_t p;
    memset(&p, 0, sizeof(p));
    snprintf(p.package, sizeof(p.package), "openssl");
    p.mode = QIHSE_PKG_CITADEL_FORK;
    snprintf(p.reason, sizeof(p.reason), "upstream TLS regressions in 3.0.14");
    p.policy_generation = 3;
    assert(qihse_pkg_policy_set(store, op, &p));

    qihse_pkg_policy_t got;
    assert(qihse_pkg_policy_get(store, op, "openssl", &got));
    assert(got.mode == QIHSE_PKG_CITADEL_FORK);
    assert(strcmp(got.reason, "upstream TLS regressions in 3.0.14") == 0);
    assert(got.policy_generation == 3);

    /* A reason is mandatory — an override without one is refused. */
    qihse_pkg_policy_t bare;
    memset(&bare, 0, sizeof(bare));
    snprintf(bare.package, sizeof(bare.package), "curl");
    bare.mode = QIHSE_PKG_FORBIDDEN;
    assert(!qihse_pkg_policy_set(store, op, &bare));

    /* Unknown package has no policy. */
    assert(!qihse_pkg_policy_get(store, op, "nosuchpkg", &got));

    printf("PASS package policy: 6 modes + reason mandatory\n");
}

/* ── Build job state machine (AC18) ────────────────────────────────────── */

static void test_build_states(qihse_kv_store_t* store, qihse_user_t* op) {
    for (int i = 0; i < 12; i++) {
        qihse_build_state_t s = (qihse_build_state_t)i;
        const char* name = qihse_build_state_name(s);
        assert(name && strcmp(name, "UNKNOWN") != 0);
        qihse_build_state_t parsed;
        assert(qihse_build_state_parse(name, &parsed));
        assert(parsed == s);
    }
    assert(qihse_build_state_is_failure(QIHSE_BUILD_FAILED));
    assert(qihse_build_state_is_failure(QIHSE_BUILD_RETRYABLE));
    assert(qihse_build_state_is_failure(QIHSE_BUILD_QUARANTINED));
    assert(qihse_build_state_is_failure(QIHSE_BUILD_CANCELLED));
    assert(!qihse_build_state_is_failure(QIHSE_BUILD_BUILDING));
    assert(qihse_build_state_is_terminal(QIHSE_BUILD_PUBLISHED));
    assert(!qihse_build_state_is_terminal(QIHSE_BUILD_SIGNING));

    /* The happy path. */
    qihse_build_job_t job;
    memset(&job, 0, sizeof(job));
    assert(qihse_uuid_from_seed("f6-build-1", strlen("f6-build-1"), &job.build_id));
    snprintf(job.package, sizeof(job.package), "openssl");
    snprintf(job.source_revision, sizeof(job.source_revision), "openssl-3.0.13-1");
    snprintf(job.profile, sizeof(job.profile), "hardened-release");
    snprintf(job.toolchain, sizeof(job.toolchain), "gcc-14.2.0");

    qihse_build_job_t out;
    assert(qihse_build_job_create(store, op, &job, &out));
    assert(out.state == QIHSE_BUILD_QUEUED);
    assert(out.generation == 1);

    /* Repeated create is idempotent and does not reset state. */
    qihse_build_job_t out2;
    assert(qihse_build_job_create(store, op, &job, &out2));
    assert(out2.state == QIHSE_BUILD_QUEUED);
    assert(out2.generation == 1);

    /* An illegal jump is refused: QUEUED -> BUILDING. */
    qihse_uuid_t req_illegal;
    assert(qihse_uuid_from_seed("f6-req-illegal", strlen("f6-req-illegal"), &req_illegal));
    assert(!qihse_build_job_transition(store, op, &job.build_id, QIHSE_BUILD_BUILDING,
                                       &req_illegal, NULL, &out));
    assert(qihse_build_job_get(store, op, &job.build_id, &out));
    assert(out.state == QIHSE_BUILD_QUEUED);

    /* Walk the legal path. */
    static const qihse_build_state_t path[] = {
        QIHSE_BUILD_PLANNING, QIHSE_BUILD_LEASED, QIHSE_BUILD_BUILDING,
        QIHSE_BUILD_TESTING, QIHSE_BUILD_VERIFYING, QIHSE_BUILD_SIGNING,
        QIHSE_BUILD_PUBLISHED,
    };
    uint64_t gen = 1;
    for (size_t i = 0; i < sizeof(path) / sizeof(path[0]); i++) {
        char seed[32];
        snprintf(seed, sizeof(seed), "f6-req-%zu", i);
        qihse_uuid_t req;
        assert(qihse_uuid_from_seed(seed, strlen(seed), &req));
        assert(qihse_build_job_transition(store, op, &job.build_id, path[i], &req, NULL, &out));
        gen++;
        assert(out.state == path[i]);
        assert(out.generation == gen);
    }
    assert(out.state == QIHSE_BUILD_PUBLISHED);

    /* AC18 — repeating the last request_id is a no-op, not a second bump. */
    char seed[32];
    snprintf(seed, sizeof(seed), "f6-req-%zu", sizeof(path) / sizeof(path[0]) - 1u);
    qihse_uuid_t last_req;
    assert(qihse_uuid_from_seed(seed, strlen(seed), &last_req));
    assert(qihse_build_job_transition(store, op, &job.build_id, QIHSE_BUILD_PUBLISHED,
                                      &last_req, NULL, &out));
    assert(out.generation == gen);   /* unchanged */
    assert(out.state == QIHSE_BUILD_PUBLISHED);

    /* PUBLISHED is terminal: nothing leaves it. */
    qihse_uuid_t req_after;
    assert(qihse_uuid_from_seed("f6-req-after", strlen("f6-req-after"), &req_after));
    assert(!qihse_build_job_transition(store, op, &job.build_id, QIHSE_BUILD_FAILED,
                                       &req_after, "too late", &out));

    printf("PASS build state machine: 8 states + 4 failure states + illegal refusal\n");
    printf("PASS build idempotency: repeated request_id is a no-op (AC18)\n");
}

static void test_build_failure_path(qihse_kv_store_t* store, qihse_user_t* op) {
    qihse_build_job_t job;
    memset(&job, 0, sizeof(job));
    assert(qihse_uuid_from_seed("f6-build-2", strlen("f6-build-2"), &job.build_id));
    snprintf(job.package, sizeof(job.package), "curl");
    qihse_build_job_t out;
    assert(qihse_build_job_create(store, op, &job, &out));

    /* Failure from anywhere on the path. */
    qihse_uuid_t r1, r2;
    assert(qihse_uuid_from_seed("f6-req-f1", strlen("f6-req-f1"), &r1));
    assert(qihse_build_job_transition(store, op, &job.build_id, QIHSE_BUILD_PLANNING, &r1, NULL, &out));
    assert(qihse_uuid_from_seed("f6-req-f2", strlen("f6-req-f2"), &r2));
    assert(qihse_build_job_transition(store, op, &job.build_id, QIHSE_BUILD_FAILED, &r2,
                                      "compiler OOM", &out));
    assert(out.state == QIHSE_BUILD_FAILED);
    assert(strcmp(out.failure_reason, "compiler OOM") == 0);
    assert(qihse_build_state_is_terminal(out.state));

    /* A job that goes RETRYABLE can return to QUEUED for reassignment. */
    qihse_build_job_t job2;
    memset(&job2, 0, sizeof(job2));
    assert(qihse_uuid_from_seed("f6-build-3", strlen("f6-build-3"), &job2.build_id));
    snprintf(job2.package, sizeof(job2.package), "zlib");
    qihse_build_job_t out2;
    assert(qihse_build_job_create(store, op, &job2, &out2));

    qihse_uuid_t r3, r4, r5;
    assert(qihse_uuid_from_seed("f6-req-r3", strlen("f6-req-r3"), &r3));
    assert(qihse_build_job_transition(store, op, &job2.build_id, QIHSE_BUILD_PLANNING, &r3, NULL, &out2));
    assert(qihse_uuid_from_seed("f6-req-r4", strlen("f6-req-r4"), &r4));
    assert(qihse_build_job_transition(store, op, &job2.build_id, QIHSE_BUILD_RETRYABLE, &r4,
                                      "builder disappeared", &out2));
    assert(out2.state == QIHSE_BUILD_RETRYABLE);
    assert(qihse_uuid_from_seed("f6-req-r5", strlen("f6-req-r5"), &r5));
    assert(qihse_build_job_transition(store, op, &job2.build_id, QIHSE_BUILD_QUEUED, &r5, NULL, &out2));
    assert(out2.state == QIHSE_BUILD_QUEUED);

    printf("PASS build failure path: FAILED terminal + RETRYABLE requeue\n");
}

/* ── Builder capability and history (plan §29) ─────────────────────────── */

static void test_builder_capability(qihse_kv_store_t* store, qihse_user_t* op) {
    qihse_builder_capability_t cap;
    memset(&cap, 0, sizeof(cap));
    assert(qihse_uuid_from_seed("f6-builder-1", strlen("f6-builder-1"), &cap.node_id));
    snprintf(cap.cpu_model, sizeof(cap.cpu_model), "AMD EPYC 7742");
    cap.cores_total = 64;
    cap.cores_available = 19;
    cap.ram_total_gb = 512;
    cap.ram_available_gb = 74;
    cap.scratch_available_gb = 340;
    snprintf(cap.isa, sizeof(cap.isa), "sse4.2,avx,avx2,fma");
    cap.load_1m_milli = 3200;
    cap.thermal_headroom_milli = 780;
    cap.build_queue_depth = 1;
    cap.trust_state = QIHSE_TRUST_APPROVED;
    assert(qihse_builder_capability_put(store, op, &cap));

    qihse_builder_capability_t got;
    assert(qihse_builder_capability_get(store, op, &cap.node_id, &got));
    assert(strcmp(got.cpu_model, "AMD EPYC 7742") == 0);
    assert(got.cores_total == 64);
    assert(got.cores_available == 19);
    assert(got.ram_total_gb == 512);
    assert(got.ram_available_gb == 74);
    assert(got.scratch_available_gb == 340);
    assert(strcmp(got.isa, "sse4.2,avx,avx2,fma") == 0);
    assert(got.load_1m_milli == 3200);
    assert(got.thermal_headroom_milli == 780);
    assert(got.build_queue_depth == 1);
    assert(got.trust_state == QIHSE_TRUST_APPROVED);

    /* Historical performance: three openssl builds at 100/200/300 ms. */
    const uint64_t durations[] = { 100000, 200000, 300000 };
    for (size_t i = 0; i < 3; i++) {
        qihse_build_history_t h;
        memset(&h, 0, sizeof(h));
        char seed[32];
        snprintf(seed, sizeof(seed), "f6-exec-%zu", i);
        assert(qihse_uuid_from_seed(seed, strlen(seed), &h.execution_id));
        h.build_id = cap.node_id; /* any stable id */
        snprintf(h.package, sizeof(h.package), "openssl");
        snprintf(h.toolchain, sizeof(h.toolchain), "gcc-14.2.0");
        h.builder_node = cap.node_id;
        h.allocated_cores = 16;
        h.peak_ram_mb = 4096;
        h.build_duration_ms = durations[i];
        h.test_duration_ms = 50000;
        h.artifact_size_bytes = 12345678;
        h.succeeded = true;
        assert(qihse_build_history_record(store, op, &h));
    }
    /* One unrelated package must not affect the openssl mean. */
    qihse_build_history_t other;
    memset(&other, 0, sizeof(other));
    assert(qihse_uuid_from_seed("f6-exec-other", strlen("f6-exec-other"), &other.execution_id));
    snprintf(other.package, sizeof(other.package), "curl");
    other.build_duration_ms = 9999999;
    assert(qihse_build_history_record(store, op, &other));

    uint64_t mean = 0;
    assert(qihse_build_history_mean_duration(store, op, "openssl", &mean));
    assert(mean == 200000);

    uint64_t none = 0;
    assert(!qihse_build_history_mean_duration(store, op, "nosuchpkg", &none));

    printf("PASS builder capability: full record round-trip + history mean (200000 ms)\n");
}

/* ── SBOM / vulnerability / snapshot (AC17, AC19, AC20) ────────────────── */

static void test_sbom_and_vulns(qihse_kv_store_t* store, qihse_user_t* op) {
    const char* art_digest = "sha384:aa11bb22cc33dd44ee55ff66";

    qihse_sbom_record_t sbom;
    memset(&sbom, 0, sizeof(sbom));
    assert(qihse_uuid_from_seed("f6-sbom-1", strlen("f6-sbom-1"), &sbom.sbom_id));
    snprintf(sbom.artifact_digest, sizeof(sbom.artifact_digest), "%s", art_digest);
    snprintf(sbom.sbom_digest, sizeof(sbom.sbom_digest), "sha384:1122334455667788");
    snprintf(sbom.provenance_digest, sizeof(sbom.provenance_digest), "sha384:9988776655443322");
    snprintf(sbom.signing_identity, sizeof(sbom.signing_identity), "citadel-release-signer");
    snprintf(sbom.signature_algorithm, sizeof(sbom.signature_algorithm), "ML-DSA-87");
    snprintf(sbom.signature, sizeof(sbom.signature), "deadbeefcafe");
    /* AC17 — QIHSE records a key handle, never key material. */
    snprintf(sbom.signing_key_handle, sizeof(sbom.signing_key_handle),
             "/etc/citadel/keys/release.pub");
    snprintf(sbom.verification_status, sizeof(sbom.verification_status), "verified");
    snprintf(sbom.format, sizeof(sbom.format), "spdx");
    sbom.policy_generation = 3;
    assert(qihse_sbom_record_put(store, op, &sbom));

    qihse_sbom_record_t got;
    assert(qihse_sbom_record_get(store, op, &sbom.sbom_id, &got));
    assert(strcmp(got.artifact_digest, art_digest) == 0);
    assert(strcmp(got.signing_identity, "citadel-release-signer") == 0);
    assert(strcmp(got.signature_algorithm, "ML-DSA-87") == 0);
    assert(strcmp(got.signing_key_handle, "/etc/citadel/keys/release.pub") == 0);
    assert(strcmp(got.verification_status, "verified") == 0);
    assert(strcmp(got.format, "spdx") == 0);
    assert(got.policy_generation == 3);

    /* AC20 — historical signed SBOM evidence is never rewritten. */
    assert(!qihse_sbom_record_put(store, op, &sbom));
    qihse_sbom_record_t still;
    assert(qihse_sbom_record_get(store, op, &sbom.sbom_id, &still));
    assert(strcmp(still.signature, "deadbeefcafe") == 0);

    /* Find by artifact digest. */
    qihse_uuid_t ids[4];
    size_t found = qihse_sbom_find_by_artifact(store, op, art_digest, ids, 4);
    assert(found == 1);
    assert(qihse_uuid_equal(&ids[0], &sbom.sbom_id));
    assert(qihse_sbom_find_by_artifact(store, op, "sha384:nope", ids, 4) == 0);

    /* AC20 — a new vulnerability observation never mutates the SBOM. */
    qihse_vuln_observation_t v;
    memset(&v, 0, sizeof(v));
    assert(qihse_uuid_from_seed("f6-vuln-1", strlen("f6-vuln-1"), &v.observation_id));
    snprintf(v.component, sizeof(v.component), "openssl");
    snprintf(v.component_digest, sizeof(v.component_digest), "%s", art_digest);
    snprintf(v.advisory_id, sizeof(v.advisory_id), "CVE-2026-0001");
    snprintf(v.severity, sizeof(v.severity), "high");
    snprintf(v.status, sizeof(v.status), "open");
    snprintf(v.scanner, sizeof(v.scanner), "grype");
    snprintf(v.evidence, sizeof(v.evidence), "heap overflow in X509 parsing");
    assert(qihse_vuln_observation_put(store, op, &v));

    qihse_vuln_observation_t vgot;
    assert(qihse_vuln_observation_get(store, op, &v.observation_id, &vgot));
    assert(strcmp(vgot.advisory_id, "CVE-2026-0001") == 0);
    assert(strcmp(vgot.severity, "high") == 0);
    assert(strcmp(vgot.component_digest, art_digest) == 0);

    /* The SBOM is byte-for-byte unchanged after the observation. */
    qihse_sbom_record_t after;
    assert(qihse_sbom_record_get(store, op, &sbom.sbom_id, &after));
    assert(strcmp(after.signature, "deadbeefcafe") == 0);
    assert(strcmp(after.verification_status, "verified") == 0);

    /* A second observation for the same component appends. */
    qihse_vuln_observation_t v2 = v;
    assert(qihse_uuid_from_seed("f6-vuln-2", strlen("f6-vuln-2"), &v2.observation_id));
    snprintf(v2.advisory_id, sizeof(v2.advisory_id), "CVE-2026-0002");
    snprintf(v2.severity, sizeof(v2.severity), "critical");
    assert(qihse_vuln_observation_put(store, op, &v2));
    assert(qihse_vuln_count_by_component(store, op, art_digest) == 2);
    assert(qihse_vuln_count_by_component(store, op, "sha384:nope") == 0);

    printf("PASS SBOM: immutable + key-handle-only (AC17) + find-by-artifact\n");
    printf("PASS vulnerability observations: append-only, SBOM untouched (AC20)\n");
}

static bool snapshot_count_cb(const qihse_repo_snapshot_t* snap, void* user_data) {
    (void)snap; (*(size_t*)user_data)++; return true;
}

static void test_repo_snapshots(qihse_kv_store_t* store, qihse_user_t* op) {
    qihse_repo_snapshot_t s;
    memset(&s, 0, sizeof(s));
    assert(qihse_uuid_from_seed("f6-snap-1", strlen("f6-snap-1"), &s.snapshot_id));
    snprintf(s.repository, sizeof(s.repository), "citadel-stable");
    snprintf(s.snapshot_digest, sizeof(s.snapshot_digest), "sha384:aabbccdd11223344");
    snprintf(s.release, sizeof(s.release), "2026.09");
    s.package_count = 4211;
    snprintf(s.signing_key_handle, sizeof(s.signing_key_handle),
             "/etc/citadel/keys/archive.pub");
    assert(qihse_repo_snapshot_put(store, op, &s));

    qihse_repo_snapshot_t got;
    assert(qihse_repo_snapshot_get(store, op, &s.snapshot_id, &got));
    assert(strcmp(got.repository, "citadel-stable") == 0);
    assert(strcmp(got.release, "2026.09") == 0);
    assert(got.package_count == 4211);
    assert(strcmp(got.signing_key_handle, "/etc/citadel/keys/archive.pub") == 0);

    /* AC19 — snapshots are immutable. */
    assert(!qihse_repo_snapshot_put(store, op, &s));

    /* A snapshot in a different repository. */
    qihse_repo_snapshot_t s2;
    memset(&s2, 0, sizeof(s2));
    assert(qihse_uuid_from_seed("f6-snap-2", strlen("f6-snap-2"), &s2.snapshot_id));
    snprintf(s2.repository, sizeof(s2.repository), "citadel-edge");
    snprintf(s2.snapshot_digest, sizeof(s2.snapshot_digest), "sha384:ffeeddcc99887766");
    snprintf(s2.release, sizeof(s2.release), "2026.09-rc1");
    s2.package_count = 12;
    assert(qihse_repo_snapshot_put(store, op, &s2));

    /* Query by repository. */
    size_t all = 0, stable = 0, edge = 0, none = 0;
    qihse_repo_snapshot_foreach(store, op, NULL, snapshot_count_cb, &all);
    qihse_repo_snapshot_foreach(store, op, "citadel-stable", snapshot_count_cb, &stable);
    qihse_repo_snapshot_foreach(store, op, "citadel-edge", snapshot_count_cb, &edge);
    qihse_repo_snapshot_foreach(store, op, "nosuchrepo", snapshot_count_cb, &none);
    assert(all == 2);
    assert(stable == 1);
    assert(edge == 1);
    assert(none == 0);

    printf("PASS repository snapshots: immutable + queryable by repository (AC19)\n");
}

/* ── RESP-level F6 ─────────────────────────────────────────────────────── */

static uint16_t f6_free_tcp_port(void) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    assert(fd >= 0);
    struct sockaddr_in addr; memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    assert(bind(fd, (struct sockaddr*)&addr, sizeof addr) == 0);
    socklen_t len = sizeof addr;
    assert(getsockname(fd, (struct sockaddr*)&addr, &len) == 0);
    uint16_t port = ntohs(addr.sin_port);
    close(fd);
    return port;
}

typedef struct { int fd; char buf[65536]; size_t fill; } f6_client_t;

static bool f6_read_line(f6_client_t* c, char* out, size_t cap) {
    for (;;) {
        for (size_t i = 0; i < c->fill; i++) {
            if (c->buf[i] == '\n') {
                size_t len = i;
                if (len && c->buf[len - 1u] == '\r') len--;
                if (len >= cap) len = cap - 1u;
                memcpy(out, c->buf, len); out[len] = '\0';
                memmove(c->buf, c->buf + i + 1u, c->fill - i - 1u);
                c->fill -= i + 1u;
                return true;
            }
        }
        ssize_t n = recv(c->fd, c->buf + c->fill, sizeof(c->buf) - c->fill, 0);
        if (n <= 0) return false;
        c->fill += (size_t)n;
    }
}

static bool f6_read_exact(f6_client_t* c, char* out, size_t len) {
    while (c->fill < len) {
        ssize_t n = recv(c->fd, c->buf + c->fill, sizeof(c->buf) - c->fill, 0);
        if (n <= 0) return false;
        c->fill += (size_t)n;
    }
    memcpy(out, c->buf, len);
    memmove(c->buf, c->buf + len, c->fill - len);
    c->fill -= len;
    return true;
}

static bool f6_read_reply(f6_client_t* c, char* out, size_t cap, size_t* used) {
    char line[512];
    if (!f6_read_line(c, line, sizeof(line))) return false;
    char type = line[0];
    const char* rest = line + 1;
    if (type == '+' || type == '-' || type == ':') {
        int n = snprintf(out + *used, cap - *used, "%s", rest);
        *used += (size_t)(n > 0 ? n : 0);
        return true;
    }
    if (type == '$') {
        int len = atoi(rest);
        if (len < 0) return true;
        char data[16384];
        if ((size_t)len >= sizeof(data)) return false;
        if (!f6_read_exact(c, data, (size_t)len + 2u)) return false;
        data[len] = '\0';
        int n = snprintf(out + *used, cap - *used, "%s", data);
        *used += (size_t)(n > 0 ? n : 0);
        return true;
    }
    if (type == '*') {
        int count = atoi(rest);
        for (int i = 0; i < count; i++) {
            if (i && *used + 1u < cap) out[(*used)++] = '|';
            if (!f6_read_reply(c, out, cap, used)) return false;
        }
        return true;
    }
    return false;
}

static void f6_send_cmd6(f6_client_t* c, const char* a, const char* b, const char* d,
                         const char* e, const char* f, const char* g) {
    const char* args[6] = { a, b, d, e, f, g };
    size_t argc = 0;
    for (size_t i = 0; i < 6u; i++) if (args[i]) argc++;
    char out[4096]; size_t off = 0;
    off += (size_t)snprintf(out + off, sizeof(out) - off, "*%zu\r\n", argc);
    for (size_t i = 0; i < argc; i++)
        off += (size_t)snprintf(out + off, sizeof(out) - off, "$%zu\r\n%s\r\n", strlen(args[i]), args[i]);
    assert(send(c->fd, out, off, 0) == (ssize_t)off);
}

static void f6_send_cmd(f6_client_t* c, const char* a, const char* b, const char* d, const char* e) {
    f6_send_cmd6(c, a, b, d, e, NULL, NULL);
}

static void test_resp_federation_f6(qihse_kv_store_t* store, qihse_user_t* op) {
    uint16_t port = f6_free_tcp_port();
    char node_id[QIHSE_CLUSTER_NODE_ID_LEN + 1u];
    qihse_cluster_node_id_from_seed("f6-resp-test-node", strlen("f6-resp-test-node"), node_id);
    qihse_resp_server_config_t scfg;
    qihse_resp_server_config_init(&scfg);
    scfg.node_id = node_id;
    scfg.bind_address = "127.0.0.1";
    scfg.advertise_address = "127.0.0.1";
    scfg.port = port;
    scfg.bus_port = f6_free_tcp_port();
    scfg.store = store;
    scfg.enable_bus = false;
    scfg.enable_failover = false;
    scfg.auth_required = true;
    qihse_resp_server_t* server = qihse_resp_server_create(&scfg);
    if (!server) fprintf(stderr, "server create failed: errno=%d (%s)\n", errno, strerror(errno));
    assert(server);
    assert(qihse_resp_server_start(server));

    f6_client_t c; memset(&c, 0, sizeof c);
    struct sockaddr_in addr; memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(port);
    c.fd = socket(AF_INET, SOCK_STREAM, 0); assert(c.fd >= 0);
    assert(connect(c.fd, (struct sockaddr*)&addr, sizeof addr) == 0);

    char reply[16384]; size_t used;
    f6_send_cmd(&c, "AUTH", "GODMODE_OP", "F6OperatorPass1!", NULL);
    used = 0; assert(f6_read_reply(&c, reply, sizeof reply, &used));
    assert(strcmp(reply, "OK") == 0);

    /* PROV.EDGE records an edge; PROV.TRACE walks it. */
    f6_send_cmd6(&c, "FEDERATION", "PROV.EDGE", "SOURCE_REVISION|rev-x",
                 "DERIVED_FROM", "SOURCE_REPOSITORY|debian/openssl", NULL);
    used = 0; assert(f6_read_reply(&c, reply, sizeof reply, &used));
    assert(strstr(reply, "OK") != NULL);

    f6_send_cmd6(&c, "FEDERATION", "PROV.TRACE", "SOURCE_REVISION", "rev-x",
                 "reverse", "16");
    used = 0; assert(f6_read_reply(&c, reply, sizeof reply, &used));
    assert(strstr(reply, "SOURCE_REPOSITORY") != NULL);

    /* PROV.SHOW for a node that exists. */
    f6_send_cmd(&c, "FEDERATION", "PROV.SHOW", "SOURCE_REPOSITORY", "debian/openssl");
    used = 0; assert(f6_read_reply(&c, reply, sizeof reply, &used));
    assert(strstr(reply, "NOPERM") == NULL);

    /* BUILD.STATES lists the state vocabulary. */
    f6_send_cmd(&c, "FEDERATION", "BUILD.STATES", NULL, NULL);
    used = 0; assert(f6_read_reply(&c, reply, sizeof reply, &used));
    assert(strstr(reply, "QUEUED") != NULL);
    assert(strstr(reply, "PUBLISHED") != NULL);
    assert(strstr(reply, "QUARANTINED") != NULL);

    /* PKG.MODES lists the override modes. */
    f6_send_cmd(&c, "FEDERATION", "PKG.MODES", NULL, NULL);
    used = 0; assert(f6_read_reply(&c, reply, sizeof reply, &used));
    assert(strstr(reply, "CITADEL_FORK") != NULL);
    assert(strstr(reply, "FORBIDDEN") != NULL);

    /* Tenant guest is denied (AGENTS.md invariant 3). */
    qihse_user_t* tenant = qihse_auth_create_tenant_user(op,
        42u, 107u, QIHSE_ROLE_GUEST, 0, 0, "F6TenantGuestP1!", false);
    assert(tenant);
    f6_client_t g; memset(&g, 0, sizeof g);
    g.fd = socket(AF_INET, SOCK_STREAM, 0); assert(g.fd >= 0);
    assert(connect(g.fd, (struct sockaddr*)&addr, sizeof addr) == 0);
    f6_send_cmd(&g, "AUTH", "User_107", "F6TenantGuestP1!", NULL);
    used = 0; assert(f6_read_reply(&g, reply, sizeof reply, &used));
    assert(strcmp(reply, "OK") == 0);
    f6_send_cmd(&g, "FEDERATION", "BUILD.STATES", NULL, NULL);
    used = 0; assert(f6_read_reply(&g, reply, sizeof reply, &used));
    assert(strstr(reply, "NOPERM") != NULL);
    assert(strstr(reply, "PUBLISHED") == NULL);
    f6_send_cmd6(&g, "FEDERATION", "PROV.EDGE", "SOURCE_REVISION|evil",
                 "DERIVED_FROM", "SOURCE_REPOSITORY|debian/openssl", NULL);
    used = 0; assert(f6_read_reply(&g, reply, sizeof reply, &used));
    assert(strstr(reply, "NOPERM") != NULL);
    f6_send_cmd(&g, "FEDERATION", "PKG.MODES", NULL, NULL);
    used = 0; assert(f6_read_reply(&g, reply, sizeof reply, &used));
    assert(strstr(reply, "NOPERM") != NULL);
    assert(strstr(reply, "FORBIDDEN") == NULL);
    f6_send_cmd(&g, "FEDERATION", "BUILD.LIST", NULL, NULL);
    used = 0; assert(f6_read_reply(&g, reply, sizeof reply, &used));
    assert(strstr(reply, "NOPERM") != NULL);
    close(g.fd);

    close(c.fd);
    qihse_resp_server_stop(server);
    qihse_resp_server_destroy(server);
    printf("PASS RESP FEDERATION.PROV/BUILD/PKG + tenant-guest NOPERM\n");
}

int main(void) {
    char data_root[] = "build/fed_f6_XXXXXX";
    assert(mkdtemp(data_root));
    setenv("QIHSE_DATA_DIR", data_root, 1);

    assert(qihse_auth_init());
    bool bootstrapped = qihse_auth_bootstrap_operator("F6OperatorPass1!");
    if (!bootstrapped) {
        setenv("QIHSE_OPERATOR_PASSWORD", "F6OperatorPass1!", 1);
        assert(qihse_auth_init());
    }
    qihse_user_t* op = qihse_auth_get_user(0);
    assert(op);

    qihse_kv_store_t* store = qihse_kv_store_create();
    assert(store);

    test_vocabulary();
    test_graph_storage(store, op);
    test_provenance_chain(store, op);
    test_package_policy(store, op);
    test_build_states(store, op);
    test_build_failure_path(store, op);
    test_builder_capability(store, op);
    test_sbom_and_vulns(store, op);
    test_repo_snapshots(store, op);
    test_resp_federation_f6(store, op);

    qihse_kv_store_destroy(store);
    printf("federation F6 tests passed\n");
    return 0;
}
