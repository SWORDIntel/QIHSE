#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>

#include "qihse_analysis_artifact.h"
#include "qihse_audit.h"
#include "qihse_auth.h"
#include "qihse_blob.h"
#include "qihse_federation.h"
#include "qihse_keystone.h"

#define TEST_TENANT 77u
#define TEST_OP_PW "OpKeystonePass1!"
#define TEST_ANALYST_PW "AnalystKeystonePass1!"
#define TEST_INDEXER_PW "IndexerKeystonePass1!"
#define TEST_LOW_PW "LowKeystonePass1!"

static void remove_dir_recursive(const char* path) {
    char cmd[768];
    snprintf(cmd, sizeof(cmd), "rm -rf '%s'", path);
    (void)system(cmd);
}

static qihse_analysis_artifact_v1_t make_binary_manifest(uint32_t tenant, uint16_t classif, uint16_t sci,
                                                         const uint8_t* payload, size_t payload_len) {
    qihse_analysis_artifact_v1_t m = {0};
    m.version = QIHSE_ANALYSIS_ARTIFACT_VERSION;
    m.kind = QIHSE_ANALYSIS_BINARY;
    m.completion = QIHSE_ANALYSIS_COMPLETE;
    m.fidelity = QIHSE_ANALYSIS_FIDELITY_VALIDATED;
    m.tenant_id = tenant;
    m.classification = classif;
    m.sci = sci;
    snprintf(m.artifact_schema, sizeof(m.artifact_schema), "kp14.binary.v1");
    snprintf(m.producer, sizeof(m.producer), "toolchain");
    snprintf(m.producer_version, sizeof(m.producer_version), "1.0.0");
    memset(m.run_id, 0x11, sizeof(m.run_id));
    m.generation = 1;
    snprintf(m.isa, sizeof(m.isa), "x86");
    snprintf(m.mode, sizeof(m.mode), "long64");
    m.address_bits = 64;
    m.payload_size = payload_len;

    unsigned int dlen = 0;
    assert(EVP_Digest(payload, payload_len, m.payload_sha384, &dlen, EVP_sha384(), NULL) == 1);
    assert(dlen == QIHSE_BLOB_HASH_BYTES);
    memcpy(m.binary_sha384, m.payload_sha384, QIHSE_BLOB_HASH_BYTES);
    m.input_count = 0;
    assert(qihse_analysis_artifact_compute_id(&m, m.artifact_id));
    return m;
}

static qihse_analysis_artifact_v1_t make_derived_manifest(uint16_t kind, const char* schema,
                                                          uint32_t tenant, uint16_t classif, uint16_t sci,
                                                          const uint8_t root_binary[QIHSE_BLOB_HASH_BYTES],
                                                          const uint8_t input_id[QIHSE_BLOB_HASH_BYTES],
                                                          const uint8_t* payload, size_t payload_len,
                                                          uint64_t generation) {
    qihse_analysis_artifact_v1_t m = {0};
    m.version = QIHSE_ANALYSIS_ARTIFACT_VERSION;
    m.kind = kind;
    m.completion = QIHSE_ANALYSIS_COMPLETE;
    m.fidelity = QIHSE_ANALYSIS_FIDELITY_VALIDATED;
    m.tenant_id = tenant;
    m.classification = classif;
    m.sci = sci;
    snprintf(m.artifact_schema, sizeof(m.artifact_schema), "%s", schema);
    snprintf(m.producer, sizeof(m.producer), "radare3");
    snprintf(m.producer_version, sizeof(m.producer_version), "0.2.0");
    memset(m.run_id, 0x22, sizeof(m.run_id));
    m.generation = generation;
    memcpy(m.binary_sha384, root_binary, QIHSE_BLOB_HASH_BYTES);
    snprintf(m.isa, sizeof(m.isa), "x86");
    snprintf(m.mode, sizeof(m.mode), "long64");
    m.address_bits = 64;
    m.payload_size = payload_len;

    unsigned int dlen = 0;
    assert(EVP_Digest(payload, payload_len, m.payload_sha384, &dlen, EVP_sha384(), NULL) == 1);
    assert(dlen == QIHSE_BLOB_HASH_BYTES);
    m.input_count = 1;
    memcpy(m.input_ids[0], input_id, QIHSE_BLOB_HASH_BYTES);
    assert(qihse_analysis_artifact_compute_id(&m, m.artifact_id));
    return m;
}

int main(void) {
    char dir[] = "./build/test_kp14_keystone_integration_XXXXXX";
    assert(mkdir("./build", 0700) == 0 || errno == EEXIST);
    assert(mkdtemp(dir) != NULL);
    assert(setenv("QIHSE_DATA_DIR", dir, 1) == 0);
    assert(setenv("QIHSE_FIPS_MODE", "disabled", 1) == 0);

    /* Initialize authentication */
    assert(qihse_auth_init());
    assert(qihse_auth_bootstrap_operator(TEST_OP_PW));
    qihse_user_t* op = qihse_auth_get_user(0);
    assert(op);

    /* Authorized Analyst: tenant 77, clearance 2, SCI 1, with KP14 WRITE ACL */
    qihse_user_t* analyst = qihse_auth_create_tenant_user(
        op, TEST_TENANT, 3001, QIHSE_ROLE_ANALYST, 2, 1, TEST_ANALYST_PW, false);
    assert(analyst);
    assert(qihse_auth_grant_object(op, analyst, QIHSE_ANALYSIS_PUBLISH_ACL_NAMESPACE,
                                   TEST_TENANT, QIHSE_ACL_WRITE));

    /* KEYSTONE Feed Index Identity: tenant 77, clearance 2, SCI 1 */
    qihse_user_t* indexer = qihse_keystone_feed_identity_provision(
        op, TEST_TENANT, 3002, 2, 1, TEST_INDEXER_PW);
    assert(indexer);
    assert(qihse_keystone_feed_identity_is_indexer(indexer));

    /* Low-clearance User: tenant 77, clearance 1, SCI 0 */
    qihse_user_t* low = qihse_auth_create_tenant_user(
        op, TEST_TENANT, 3003, QIHSE_ROLE_ANALYST, 1, 0, TEST_LOW_PW, false);
    assert(low);

    /* Open federation journal for KEYSTONE feed */
    char journal_dir[576];
    snprintf(journal_dir, sizeof(journal_dir), "%s/journal", dir);
    qihse_federation_journal_t* journal = qihse_federation_journal_open(
        journal_dir, QIHSE_ES_DURABILITY_FDATASYNC);
    assert(journal != NULL);

    /* Open durable artifact store with feed journal attached */
    char store_dir[576];
    snprintf(store_dir, sizeof(store_dir), "%s/artifact_store", dir);
    qihse_uuid_t origin_node;
    assert(qihse_uuid_from_seed("keystone-test-node-1", 20, &origin_node));

    qihse_analysis_artifact_store_t* store = qihse_analysis_artifact_store_open(
        store_dir, NULL, journal, &origin_node);
    assert(store != NULL);

    /* ── Phase 1: Storage & Publication Pipeline ─────────────────────────── */
    printf("Phase 1: Ingesting complete DAG into QIHSE store and publishing feed projections...\n");

    /* 1. Binary */
    const char bin_raw[] = "ELF-METHRA-VM9211-TARGET-CORE-BINARY-PAYLOAD-001";
    size_t bin_len = strlen(bin_raw);
    qihse_analysis_artifact_v1_t bin_m = make_binary_manifest(
        TEST_TENANT, 2, 1, (const uint8_t*)bin_raw, bin_len);
    uint8_t bin_id[QIHSE_BLOB_HASH_BYTES];
    assert(qihse_analysis_artifact_ingest_buffer_user(
        store, &bin_m, (const uint8_t*)bin_raw, bin_len, analyst, bin_id) == QIHSE_ANALYSIS_STORE_OK);

    /* 2. Disassembly */
    const char disasm_raw[] = "DISASM: entry 0x401000: xor rax, rax; call 0x402000; ret";
    size_t disasm_len = strlen(disasm_raw);
    qihse_analysis_artifact_v1_t disasm_m = make_derived_manifest(
        QIHSE_ANALYSIS_DISASSEMBLY, "kp14.disassembly.v1",
        TEST_TENANT, 2, 1, bin_m.binary_sha384, bin_id,
        (const uint8_t*)disasm_raw, disasm_len, 1);
    uint8_t disasm_id[QIHSE_BLOB_HASH_BYTES];
    assert(qihse_analysis_artifact_ingest_buffer_user(
        store, &disasm_m, (const uint8_t*)disasm_raw, disasm_len, analyst, disasm_id) == QIHSE_ANALYSIS_STORE_OK);

    /* 3. CFG */
    const char cfg_raw[] = "CFG: blocks={0x401000, 0x402000}, edges={0x401000->0x402000}";
    size_t cfg_len = strlen(cfg_raw);
    qihse_analysis_artifact_v1_t cfg_m = make_derived_manifest(
        QIHSE_ANALYSIS_CFG, "kp14.cfg.v1",
        TEST_TENANT, 2, 1, bin_m.binary_sha384, disasm_id,
        (const uint8_t*)cfg_raw, cfg_len, 1);
    uint8_t cfg_id[QIHSE_BLOB_HASH_BYTES];
    assert(qihse_analysis_artifact_ingest_buffer_user(
        store, &cfg_m, (const uint8_t*)cfg_raw, cfg_len, analyst, cfg_id) == QIHSE_ANALYSIS_STORE_OK);

    /* 4. Trace */
    const char trace_raw[] = "TRACE: exec sequence: 0x401000 -> 0x402000 -> 0x401007 [exit 0]";
    size_t trace_len = strlen(trace_raw);
    qihse_analysis_artifact_v1_t trace_m = make_derived_manifest(
        QIHSE_ANALYSIS_TRACE, "kp14.trace.v1",
        TEST_TENANT, 2, 1, bin_m.binary_sha384, cfg_id,
        (const uint8_t*)trace_raw, trace_len, 1);
    uint8_t trace_id[QIHSE_BLOB_HASH_BYTES];
    assert(qihse_analysis_artifact_ingest_buffer_user(
        store, &trace_m, (const uint8_t*)trace_raw, trace_len, analyst, trace_id) == QIHSE_ANALYSIS_STORE_OK);

    /* 5. Solver */
    const char solver_raw[] = "SOLVER: z3 reachability: SAT, constraints satisfied";
    size_t solver_len = strlen(solver_raw);
    qihse_analysis_artifact_v1_t solver_m = make_derived_manifest(
        QIHSE_ANALYSIS_SOLVER, "kp14.solver.v1",
        TEST_TENANT, 2, 1, bin_m.binary_sha384, trace_id,
        (const uint8_t*)solver_raw, solver_len, 1);
    uint8_t solver_id[QIHSE_BLOB_HASH_BYTES];
    assert(qihse_analysis_artifact_ingest_buffer_user(
        store, &solver_m, (const uint8_t*)solver_raw, solver_len, analyst, solver_id) == QIHSE_ANALYSIS_STORE_OK);

    /* 6. Verdict */
    const char verdict_raw[] = "VERDICT: constraint safety CONFIRMED";
    size_t verdict_len = strlen(verdict_raw);
    qihse_analysis_artifact_v1_t verdict_m = make_derived_manifest(
        QIHSE_ANALYSIS_VERDICT, "kp14.verdict.v1",
        TEST_TENANT, 2, 1, bin_m.binary_sha384, solver_id,
        (const uint8_t*)verdict_raw, verdict_len, 1);
    uint8_t verdict_id[QIHSE_BLOB_HASH_BYTES];
    assert(qihse_analysis_artifact_ingest_buffer_user(
        store, &verdict_m, (const uint8_t*)verdict_raw, verdict_len, analyst, verdict_id) == QIHSE_ANALYSIS_STORE_OK);

    /* 7. Report */
    const char report_raw[] = "REPORT: VM9211 full verification suite PASSED with 100% confidence";
    size_t report_len = strlen(report_raw);
    qihse_analysis_artifact_v1_t report_m = make_derived_manifest(
        QIHSE_ANALYSIS_REPORT, "kp14.report.v1",
        TEST_TENANT, 2, 1, bin_m.binary_sha384, verdict_id,
        (const uint8_t*)report_raw, report_len, 1);
    uint8_t report_id[QIHSE_BLOB_HASH_BYTES];
    assert(qihse_analysis_artifact_ingest_buffer_user(
        store, &report_m, (const uint8_t*)report_raw, report_len, analyst, report_id) == QIHSE_ANALYSIS_STORE_OK);

    /* Verify payload bytes are safely stored in QIHSE blobs and protected from deletion */
    qihse_blob_store_t* blob_store = qihse_analysis_artifact_store_get_blob_store(store);
    assert(blob_store != NULL);
    bool is_pinned = false;
    assert(qihse_blob_is_pinned_user(blob_store, report_m.payload_sha384, analyst, &is_pinned));
    assert(is_pinned);
    assert(!qihse_blob_delete_user(blob_store, report_m.payload_sha384, analyst));

    /* ── Phase 2: KEYSTONE Feed Consumption & Candidate Indexing ─────────── */
    printf("Phase 2: Consuming projections via KEYSTONE feed and indexing candidates...\n");

    qihse_keystone_feed_t* feed = qihse_keystone_feed_open(journal, indexer, NULL);
    assert(feed != NULL);

    size_t received_events = 0;
    uint8_t indexed_report_id[QIHSE_BLOB_HASH_BYTES] = {0};
    uint8_t indexed_solver_id[QIHSE_BLOB_HASH_BYTES] = {0};
    bool found_report_candidate = false;

    qihse_federation_event_t ev;
    qihse_keystone_feed_record_t rec;
    uint8_t* payload = NULL;
    size_t payload_len = 0;

    while (qihse_keystone_feed_next(feed, &ev, &rec, &payload, &payload_len)) {
        received_events++;
        assert(ev.resource_id != NULL);
        assert(rec.classification == 2);
        assert(rec.sci == 1);
        assert(rec.tenant_id == TEST_TENANT);
        assert((rec.flags & QIHSE_KEYSTONE_FEED_FLAG_EVENT) != 0);

        /* Decode bounded projection */
        qihse_analysis_projection_t proj;
        assert(qihse_analysis_projection_decode(payload, payload_len, &proj));
        assert(!proj.is_tombstone);
        assert(proj.tenant_id == TEST_TENANT);
        assert(proj.classification == 2);
        assert(proj.sci == 1);
        assert(memcmp(proj.binary_sha384, bin_m.binary_sha384, QIHSE_BLOB_HASH_BYTES) == 0);

        /* Crucial contract check: raw payload bytes are NOT carried in the feed projection! */
        assert(memmem(payload, payload_len, "VM9211 full verification suite", 30) == NULL);
        assert(memmem(payload, payload_len, "z3 reachability", 15) == NULL);

        if (proj.kind == QIHSE_ANALYSIS_REPORT) {
            found_report_candidate = true;
            memcpy(indexed_report_id, proj.artifact_id, QIHSE_BLOB_HASH_BYTES);
            assert(memcmp(proj.artifact_id, report_id, QIHSE_BLOB_HASH_BYTES) == 0);
            assert(proj.input_count == 1);
            assert(memcmp(proj.input_ids[0], verdict_id, QIHSE_BLOB_HASH_BYTES) == 0);
        } else if (proj.kind == QIHSE_ANALYSIS_SOLVER) {
            memcpy(indexed_solver_id, proj.artifact_id, QIHSE_BLOB_HASH_BYTES);
            assert(memcmp(proj.artifact_id, solver_id, QIHSE_BLOB_HASH_BYTES) == 0);
        }

        free(payload);
        payload = NULL;
    }

    assert(received_events == 7);
    assert(found_report_candidate);

    /* Freshness checks */
    uint64_t latest_off = 0, lag = 999;
    assert(qihse_keystone_feed_freshness(feed, &latest_off, &lag));
    assert(latest_off > 0 && lag == 0);

    uint64_t s_latest = 0, s_lag = 999;
    assert(qihse_analysis_artifact_feed_freshness(store, latest_off, &s_latest, &s_lag));
    assert(s_latest == latest_off && s_lag == 0);

    /* ── Phase 3: QIHSE Reauthorization & Exact Verification ─────────────── */
    printf("Phase 3: QIHSE reauthorization and exact cryptographic verification...\n");

    /* Negative authorization: Low-clearance user denied access */
    qihse_analysis_artifact_v1_t low_m;
    memset(&low_m, 0x55, sizeof(low_m));
    assert(qihse_analysis_artifact_get_manifest_user(store, indexed_report_id, low, &low_m) == QIHSE_ANALYSIS_STORE_DENIED);
    assert(low_m.version == 0x5555);

    uint8_t low_buf[256];
    memset(low_buf, 0x66, sizeof(low_buf));
    size_t low_read = 0;
    assert(qihse_analysis_artifact_get_payload_user(store, indexed_report_id, 0, low_buf, sizeof(low_buf), &low_read, low) == QIHSE_ANALYSIS_STORE_DENIED);
    assert(low_read == 0 && low_buf[0] == 0x66);

    /* Positive authorization: Analyst user retrieves authoritative manifest & payload */
    qihse_analysis_artifact_v1_t auth_m;
    assert(qihse_analysis_artifact_get_manifest_user(store, indexed_report_id, analyst, &auth_m) == QIHSE_ANALYSIS_STORE_OK);
    assert(memcmp(auth_m.artifact_id, report_id, QIHSE_BLOB_HASH_BYTES) == 0);
    assert(auth_m.payload_size == report_len);

    uint8_t auth_payload[256] = {0};
    size_t auth_read = 0;
    assert(qihse_analysis_artifact_get_payload_user(store, indexed_report_id, 0, auth_payload, sizeof(auth_payload), &auth_read, analyst) == QIHSE_ANALYSIS_STORE_OK);
    assert(auth_read == report_len);
    assert(memcmp(auth_payload, report_raw, report_len) == 0);

    /* Exact cryptographic check: SHA-384 of delivered payload matches manifest */
    uint8_t verified_sha[QIHSE_BLOB_HASH_BYTES];
    unsigned int vlen = 0;
    assert(EVP_Digest(auth_payload, auth_read, verified_sha, &vlen, EVP_sha384(), NULL) == 1);
    assert(vlen == QIHSE_BLOB_HASH_BYTES);
    assert(memcmp(verified_sha, auth_m.payload_sha384, QIHSE_BLOB_HASH_BYTES) == 0);

    /* Complete lineage verification across entire DAG */
    assert(qihse_analysis_artifact_verify_lineage_user(store, indexed_report_id, analyst) == QIHSE_ANALYSIS_STORE_OK);

    /* ── Phase 4: Tombstone & Rebuild ────────────────────────────────────── */
    printf("Phase 4: Tombstoning solver artifact and rebuilding with generation 2...\n");

    /* Tombstone solver artifact */
    assert(qihse_analysis_artifact_tombstone_user(store, indexed_solver_id, "patch upgrade gen 2", analyst) == QIHSE_ANALYSIS_STORE_OK);

    /* Blob is unpinned */
    assert(qihse_blob_is_pinned_user(blob_store, solver_m.payload_sha384, analyst, &is_pinned));
    assert(!is_pinned);

    /* Feed consumer observes tombstone projection */
    bool saw_tombstone_event = false;
    while (qihse_keystone_feed_next(feed, &ev, &rec, &payload, &payload_len)) {
        assert((rec.flags & QIHSE_KEYSTONE_FEED_FLAG_TOMBSTONE) != 0);
        qihse_analysis_projection_t tomb_proj;
        assert(qihse_analysis_projection_decode(payload, payload_len, &tomb_proj));
        assert(tomb_proj.is_tombstone);
        assert(memcmp(tomb_proj.artifact_id, indexed_solver_id, QIHSE_BLOB_HASH_BYTES) == 0);
        assert(strstr(tomb_proj.tombstone_reason, "patch upgrade gen 2") != NULL);
        saw_tombstone_event = true;
        free(payload);
        payload = NULL;
    }
    assert(saw_tombstone_event);

    /* ── Phase 5: Selective Invalidation ─────────────────────────────────── */
    printf("Phase 5: Verifying selective invalidation of downstream artifacts...\n");

    /* Direct read of tombstoned solver returns TOMBSTONED */
    qihse_analysis_artifact_v1_t dummy_m;
    assert(qihse_analysis_artifact_get_manifest_user(store, indexed_solver_id, analyst, &dummy_m) == QIHSE_ANALYSIS_STORE_TOMBSTONED);

    /* Downstream report artifact lineage check now fails because parent solver is tombstoned! */
    assert(qihse_analysis_artifact_verify_lineage_user(store, indexed_report_id, analyst) == QIHSE_ANALYSIS_STORE_LINEAGE_ERROR);

    /* Ingesting a new artifact depending on the tombstoned solver fails */
    qihse_analysis_artifact_v1_t bad_desc = make_derived_manifest(
        QIHSE_ANALYSIS_REPORT, "kp14.report.v1",
        TEST_TENANT, 2, 1, bin_m.binary_sha384, indexed_solver_id,
        (const uint8_t*)report_raw, report_len, 2);
    uint8_t bad_desc_id[QIHSE_BLOB_HASH_BYTES];
    assert(qihse_analysis_artifact_ingest_buffer_user(
        store, &bad_desc, (const uint8_t*)report_raw, report_len, analyst, bad_desc_id) == QIHSE_ANALYSIS_STORE_LINEAGE_ERROR);

    /* Rebuild: Ingest new Solver (gen 2) depending on Trace */
    const char solver2_raw[] = "SOLVER: z3 reachability: SAT, model verified under patch gen 2";
    size_t solver2_len = strlen(solver2_raw);
    qihse_analysis_artifact_v1_t solver2_m = make_derived_manifest(
        QIHSE_ANALYSIS_SOLVER, "kp14.solver.v1",
        TEST_TENANT, 2, 1, bin_m.binary_sha384, trace_id,
        (const uint8_t*)solver2_raw, solver2_len, 2);
    uint8_t solver2_id[QIHSE_BLOB_HASH_BYTES];
    assert(qihse_analysis_artifact_ingest_buffer_user(
        store, &solver2_m, (const uint8_t*)solver2_raw, solver2_len, analyst, solver2_id) == QIHSE_ANALYSIS_STORE_OK);

    /* Ingest new Verdict (gen 2) depending on Solver 2 */
    qihse_analysis_artifact_v1_t verdict2_m = make_derived_manifest(
        QIHSE_ANALYSIS_VERDICT, "kp14.verdict.v1",
        TEST_TENANT, 2, 1, bin_m.binary_sha384, solver2_id,
        (const uint8_t*)verdict_raw, verdict_len, 2);
    uint8_t verdict2_id[QIHSE_BLOB_HASH_BYTES];
    assert(qihse_analysis_artifact_ingest_buffer_user(
        store, &verdict2_m, (const uint8_t*)verdict_raw, verdict_len, analyst, verdict2_id) == QIHSE_ANALYSIS_STORE_OK);

    /* Ingest new Report (gen 2) depending on Verdict 2 */
    qihse_analysis_artifact_v1_t report2_m = make_derived_manifest(
        QIHSE_ANALYSIS_REPORT, "kp14.report.v1",
        TEST_TENANT, 2, 1, bin_m.binary_sha384, verdict2_id,
        (const uint8_t*)report_raw, report_len, 2);
    uint8_t report2_id[QIHSE_BLOB_HASH_BYTES];
    assert(qihse_analysis_artifact_ingest_buffer_user(
        store, &report2_m, (const uint8_t*)report_raw, report_len, analyst, report2_id) == QIHSE_ANALYSIS_STORE_OK);

    /* Lineage verification on the rebuilt Report 2 succeeds! */
    assert(qihse_analysis_artifact_verify_lineage_user(store, report2_id, analyst) == QIHSE_ANALYSIS_STORE_OK);

    /* ── Phase 6: Index-Unavailable & Authoritative Persistence ─────────── */
    printf("Phase 6: Testing index-unavailable status and authoritative store recovery...\n");

    qihse_keystone_feed_close(feed);
    qihse_analysis_artifact_store_close(store);
    qihse_federation_journal_destroy(journal);

    /* Reopen store WITHOUT feed journal (index unavailable scenario) */
    qihse_analysis_artifact_store_t* standalone = qihse_analysis_artifact_store_open(
        store_dir, NULL, NULL, NULL);
    assert(standalone != NULL);

    /* Freshness check returns false (index/journal unavailable) */
    uint64_t unavail_latest = 0, unavail_lag = 0;
    assert(!qihse_analysis_artifact_feed_freshness(standalone, 0, &unavail_latest, &unavail_lag));

    /* But authoritative artifacts are completely intact and accessible! */
    qihse_analysis_artifact_v1_t recov_m;
    assert(qihse_analysis_artifact_get_manifest_user(standalone, report2_id, analyst, &recov_m) == QIHSE_ANALYSIS_STORE_OK);
    assert(recov_m.generation == 2);

    memset(auth_payload, 0, sizeof(auth_payload));
    assert(qihse_analysis_artifact_get_payload_user(standalone, report2_id, 0, auth_payload, sizeof(auth_payload), &auth_read, analyst) == QIHSE_ANALYSIS_STORE_OK);
    assert(auth_read == report_len && memcmp(auth_payload, report_raw, report_len) == 0);

    /* Rebuilt lineage verified on recovered store */
    assert(qihse_analysis_artifact_verify_lineage_user(standalone, report2_id, analyst) == QIHSE_ANALYSIS_STORE_OK);

    /* Original invalidated report lineage still fails on recovered store */
    assert(qihse_analysis_artifact_verify_lineage_user(standalone, indexed_report_id, analyst) == QIHSE_ANALYSIS_STORE_LINEAGE_ERROR);

    qihse_analysis_artifact_store_close(standalone);

    /* Clean shutdown and directory cleanup: ZERO residue */
    qihse_audit_shutdown();
    remove_dir_recursive(dir);

    printf("test_analysis_artifact_keystone_integration: all assertions passed cleanly with zero residue!\n");
    return 0;
}
