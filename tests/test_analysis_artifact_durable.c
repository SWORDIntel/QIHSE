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

#include "qihse_analysis_artifact.h"
#include "qihse_audit.h"
#include "qihse_auth.h"
#include "qihse_blob.h"

#define TEST_TENANT 77u
#define TEST_OTHER_TENANT 78u
#define TEST_OP_PW "OpDurablePass1!"
#define TEST_ANALYST_PW "AnalystDurablePass1!"
#define TEST_LOW_PW "LowDurablePass1!"
#define TEST_NOSCI_PW "NoSciDurablePass1!"
#define TEST_FOREIGN_PW "ForeignDurablePass1!"

#define CLASSIFIED_PAYLOAD_SECRET "TOPSECRET-KP14-DURABLE-ARTIFACT-PAYLOAD-9941"

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

typedef struct {
    size_t count;
    uint8_t ids[16][QIHSE_BLOB_HASH_BYTES];
} list_capture_t;

static bool list_cb(const qihse_analysis_artifact_v1_t* m, bool is_tombstone, void* opaque) {
    (void)is_tombstone;
    list_capture_t* cap = opaque;
    if (cap->count < 16) {
        memcpy(cap->ids[cap->count++], m->artifact_id, QIHSE_BLOB_HASH_BYTES);
    }
    return true;
}

int main(void) {
    char dir[] = "./build/test_analysis_artifact_durable_XXXXXX";
    assert(mkdir("./build", 0700) == 0 || errno == EEXIST);
    assert(mkdtemp(dir) != NULL);
    assert(setenv("QIHSE_DATA_DIR", dir, 1) == 0);
    assert(setenv("QIHSE_FIPS_MODE", "disabled", 1) == 0);

    assert(qihse_auth_init());
    assert(qihse_auth_bootstrap_operator(TEST_OP_PW));
    qihse_user_t* op = qihse_auth_get_user(0);
    assert(op);

    /* Authorized Analyst in tenant 77: clearance 2, SCI 1, with KP14 WRITE ACL */
    qihse_user_t* analyst = qihse_auth_create_tenant_user(
        op, TEST_TENANT, 1001, QIHSE_ROLE_ANALYST, 2, 1, TEST_ANALYST_PW, false);
    assert(analyst);
    assert(qihse_auth_grant_object(op, analyst, QIHSE_ANALYSIS_PUBLISH_ACL_NAMESPACE,
                                   TEST_TENANT, QIHSE_ACL_WRITE));

    /* Low-clearance Analyst in tenant 77: clearance 1, SCI 0 */
    qihse_user_t* low = qihse_auth_create_tenant_user(
        op, TEST_TENANT, 1002, QIHSE_ROLE_ANALYST, 1, 0, TEST_LOW_PW, false);
    assert(low);

    /* Missing-SCI Analyst in tenant 77: clearance 2, SCI 0 */
    qihse_user_t* no_sci = qihse_auth_create_tenant_user(
        op, TEST_TENANT, 1003, QIHSE_ROLE_ANALYST, 2, 0, TEST_NOSCI_PW, false);
    assert(no_sci);

    /* Foreign Tenant Analyst in tenant 78: clearance 2, SCI 1 */
    qihse_user_t* foreign = qihse_auth_create_tenant_user(
        op, TEST_OTHER_TENANT, 1004, QIHSE_ROLE_ANALYST, 2, 1, TEST_FOREIGN_PW, false);
    assert(foreign);

    /* Revoked user */
    qihse_user_t* revoked = qihse_auth_create_tenant_user(
        op, TEST_TENANT, 1005, QIHSE_ROLE_ANALYST, 2, 1, "RevokedPass1!", false);
    assert(revoked);
    assert(qihse_auth_destroy_user(op, 1005));

    /* Open durable artifact store */
    char store_dir[512];
    snprintf(store_dir, sizeof(store_dir), "%s/artifact_store", dir);
    qihse_analysis_artifact_store_t* store = qihse_analysis_artifact_store_open(
        store_dir, NULL, NULL, NULL);
    assert(store != NULL);

    /* ── 1. Ingest/Read Path: Binary artifact ─────────────────────────────── */
    const char bin_bytes[] = "ELF-X86_64-BINARY-SAMPLE-CODE-FOR-TESTING-12345";
    size_t bin_len = strlen(bin_bytes);
    qihse_analysis_artifact_v1_t bin_m = make_binary_manifest(
        TEST_TENANT, 2, 1, (const uint8_t*)bin_bytes, bin_len);

    uint8_t bin_id[QIHSE_BLOB_HASH_BYTES];
    assert(qihse_analysis_artifact_ingest_buffer_user(
        store, &bin_m, (const uint8_t*)bin_bytes, bin_len, analyst, bin_id) == QIHSE_ANALYSIS_STORE_OK);
    assert(memcmp(bin_id, bin_m.artifact_id, QIHSE_BLOB_HASH_BYTES) == 0);

    /* Read back binary manifest and payload */
    qihse_analysis_artifact_v1_t read_m;
    assert(qihse_analysis_artifact_get_manifest_user(store, bin_id, analyst, &read_m) == QIHSE_ANALYSIS_STORE_OK);
    assert(memcmp(read_m.artifact_id, bin_id, QIHSE_BLOB_HASH_BYTES) == 0);
    assert(read_m.payload_size == bin_len);

    uint8_t read_payload[128] = {0};
    size_t out_read = 0;
    assert(qihse_analysis_artifact_get_payload_user(
        store, bin_id, 0, read_payload, sizeof(read_payload), &out_read, analyst) == QIHSE_ANALYSIS_STORE_OK);
    assert(out_read == bin_len);
    assert(memcmp(read_payload, bin_bytes, bin_len) == 0);

    /* Idempotent retry of identical binary */
    uint8_t bin_id_dup[QIHSE_BLOB_HASH_BYTES];
    assert(qihse_analysis_artifact_ingest_buffer_user(
        store, &bin_m, (const uint8_t*)bin_bytes, bin_len, analyst, bin_id_dup) == QIHSE_ANALYSIS_STORE_OK);
    assert(memcmp(bin_id_dup, bin_id, QIHSE_BLOB_HASH_BYTES) == 0);

    /* ── 2. Lineage verification across artifact kinds ─────────────────────── */
    /* Ingest Disassembly depending on Binary */
    const char disasm_bytes[] = "0x1000: mov eax, 1\n0x1005: ret\n";
    size_t disasm_len = strlen(disasm_bytes);
    qihse_analysis_artifact_v1_t disasm_m = make_derived_manifest(
        QIHSE_ANALYSIS_DISASSEMBLY, "kp14.disassembly.v1",
        TEST_TENANT, 2, 1, bin_m.binary_sha384, bin_id,
        (const uint8_t*)disasm_bytes, disasm_len, 1);

    uint8_t disasm_id[QIHSE_BLOB_HASH_BYTES];
    assert(qihse_analysis_artifact_ingest_buffer_user(
        store, &disasm_m, (const uint8_t*)disasm_bytes, disasm_len, analyst, disasm_id) == QIHSE_ANALYSIS_STORE_OK);

    /* Ingest CFG depending on Disassembly */
    const char cfg_bytes[] = "CFG: BB1 -> BB2 (ret)";
    size_t cfg_len = strlen(cfg_bytes);
    qihse_analysis_artifact_v1_t cfg_m = make_derived_manifest(
        QIHSE_ANALYSIS_CFG, "kp14.cfg.v1",
        TEST_TENANT, 2, 1, bin_m.binary_sha384, disasm_id,
        (const uint8_t*)cfg_bytes, cfg_len, 1);

    uint8_t cfg_id[QIHSE_BLOB_HASH_BYTES];
    assert(qihse_analysis_artifact_ingest_buffer_user(
        store, &cfg_m, (const uint8_t*)cfg_bytes, cfg_len, analyst, cfg_id) == QIHSE_ANALYSIS_STORE_OK);

    /* Ingest Trace depending on CFG */
    const char trace_bytes[] = "TRACE: exec 0x1000, 0x1005";
    size_t trace_len = strlen(trace_bytes);
    qihse_analysis_artifact_v1_t trace_m = make_derived_manifest(
        QIHSE_ANALYSIS_TRACE, "kp14.trace.v1",
        TEST_TENANT, 2, 1, bin_m.binary_sha384, cfg_id,
        (const uint8_t*)trace_bytes, trace_len, 1);

    uint8_t trace_id[QIHSE_BLOB_HASH_BYTES];
    assert(qihse_analysis_artifact_ingest_buffer_user(
        store, &trace_m, (const uint8_t*)trace_bytes, trace_len, analyst, trace_id) == QIHSE_ANALYSIS_STORE_OK);

    /* Ingest Solver Evidence depending on Trace */
    const char solver_bytes[] = "SOLVER: sat model={eax=1}";
    size_t solver_len = strlen(solver_bytes);
    qihse_analysis_artifact_v1_t solver_m = make_derived_manifest(
        QIHSE_ANALYSIS_SOLVER, "kp14.solver.v1",
        TEST_TENANT, 2, 1, bin_m.binary_sha384, trace_id,
        (const uint8_t*)solver_bytes, solver_len, 1);

    uint8_t solver_id[QIHSE_BLOB_HASH_BYTES];
    assert(qihse_analysis_artifact_ingest_buffer_user(
        store, &solver_m, (const uint8_t*)solver_bytes, solver_len, analyst, solver_id) == QIHSE_ANALYSIS_STORE_OK);

    /* Ingest Verdict depending on Solver */
    const char verdict_bytes[] = "VERDICT: reachability verified";
    size_t verdict_len = strlen(verdict_bytes);
    qihse_analysis_artifact_v1_t verdict_m = make_derived_manifest(
        QIHSE_ANALYSIS_VERDICT, "kp14.verdict.v1",
        TEST_TENANT, 2, 1, bin_m.binary_sha384, solver_id,
        (const uint8_t*)verdict_bytes, verdict_len, 1);

    uint8_t verdict_id[QIHSE_BLOB_HASH_BYTES];
    assert(qihse_analysis_artifact_ingest_buffer_user(
        store, &verdict_m, (const uint8_t*)verdict_bytes, verdict_len, analyst, verdict_id) == QIHSE_ANALYSIS_STORE_OK);

    /* Ingest Report depending on Verdict */
    const char report_bytes[] = "REPORT: summary pass 100%";
    size_t report_len = strlen(report_bytes);
    qihse_analysis_artifact_v1_t report_m = make_derived_manifest(
        QIHSE_ANALYSIS_REPORT, "kp14.report.v1",
        TEST_TENANT, 2, 1, bin_m.binary_sha384, verdict_id,
        (const uint8_t*)report_bytes, report_len, 1);

    uint8_t report_id[QIHSE_BLOB_HASH_BYTES];
    assert(qihse_analysis_artifact_ingest_buffer_user(
        store, &report_m, (const uint8_t*)report_bytes, report_len, analyst, report_id) == QIHSE_ANALYSIS_STORE_OK);

    /* Verify complete lineage chain from report down to binary */
    assert(qihse_analysis_artifact_verify_lineage_user(store, report_id, analyst) == QIHSE_ANALYSIS_STORE_OK);

    /* Lineage negative: attempt to ingest artifact referencing nonexistent parent */
    uint8_t fake_parent[QIHSE_BLOB_HASH_BYTES];
    memset(fake_parent, 0x99, sizeof(fake_parent));
    qihse_analysis_artifact_v1_t orphan_m = make_derived_manifest(
        QIHSE_ANALYSIS_CFG, "kp14.cfg.v1",
        TEST_TENANT, 2, 1, bin_m.binary_sha384, fake_parent,
        (const uint8_t*)cfg_bytes, cfg_len, 2);
    uint8_t orphan_id[QIHSE_BLOB_HASH_BYTES];
    assert(qihse_analysis_artifact_ingest_buffer_user(
        store, &orphan_m, (const uint8_t*)cfg_bytes, cfg_len, analyst, orphan_id) == QIHSE_ANALYSIS_STORE_LINEAGE_ERROR);

    /* Lineage negative: mismatched binary root */
    uint8_t wrong_root[QIHSE_BLOB_HASH_BYTES];
    memset(wrong_root, 0xaa, sizeof(wrong_root));
    qihse_analysis_artifact_v1_t wrong_root_m = make_derived_manifest(
        QIHSE_ANALYSIS_CFG, "kp14.cfg.v1",
        TEST_TENANT, 2, 1, wrong_root, disasm_id,
        (const uint8_t*)cfg_bytes, cfg_len, 3);
    assert(qihse_analysis_artifact_ingest_buffer_user(
        store, &wrong_root_m, (const uint8_t*)cfg_bytes, cfg_len, analyst, orphan_id) == QIHSE_ANALYSIS_STORE_LINEAGE_ERROR);

    /* ── 3. Protect referenced blobs from deletion ─────────────────────────── */
    /* Verify that the blob referenced by bin_m is pinned and cannot be deleted by public delete */
    qihse_blob_store_t* blob_store = qihse_analysis_artifact_store_get_blob_store(store);
    assert(blob_store != NULL);
    bool is_pinned = false;
    assert(qihse_blob_is_pinned_user(blob_store, bin_m.payload_sha384, analyst, &is_pinned));
    assert(is_pinned);

    /* Direct deletion attempt of referenced blob must be refused! */
    assert(!qihse_blob_delete_user(blob_store, bin_m.payload_sha384, analyst));
    assert(!qihse_blob_delete_user(blob_store, bin_m.payload_sha384, op));

    /* Payload read through artifact API must still succeed */
    memset(read_payload, 0, sizeof(read_payload));
    assert(qihse_analysis_artifact_get_payload_user(
        store, bin_id, 0, read_payload, sizeof(read_payload), &out_read, analyst) == QIHSE_ANALYSIS_STORE_OK);
    assert(out_read == bin_len);

    /* ── 4. Replacement & Tombstones ───────────────────────────────────────── */
    /* Ingest artifact to be tombstoned */
    const char tmp_bytes[] = "TEMP-DISASM-FOR-TOMBSTONE";
    size_t tmp_len = strlen(tmp_bytes);
    qihse_analysis_artifact_v1_t tmp_m = make_derived_manifest(
        QIHSE_ANALYSIS_DISASSEMBLY, "kp14.disassembly.v1",
        TEST_TENANT, 2, 1, bin_m.binary_sha384, bin_id,
        (const uint8_t*)tmp_bytes, tmp_len, 50);

    uint8_t tmp_id[QIHSE_BLOB_HASH_BYTES];
    assert(qihse_analysis_artifact_ingest_buffer_user(
        store, &tmp_m, (const uint8_t*)tmp_bytes, tmp_len, analyst, tmp_id) == QIHSE_ANALYSIS_STORE_OK);

    /* Ingest child depending on tmp_m */
    const char tmp_child_bytes[] = "TEMP-CHILD-CFG";
    size_t tmp_child_len = strlen(tmp_child_bytes);
    qihse_analysis_artifact_v1_t tmp_child_m = make_derived_manifest(
        QIHSE_ANALYSIS_CFG, "kp14.cfg.v1",
        TEST_TENANT, 2, 1, bin_m.binary_sha384, tmp_id,
        (const uint8_t*)tmp_child_bytes, tmp_child_len, 51);
    uint8_t tmp_child_id[QIHSE_BLOB_HASH_BYTES];
    assert(qihse_analysis_artifact_ingest_buffer_user(
        store, &tmp_child_m, (const uint8_t*)tmp_child_bytes, tmp_child_len, analyst, tmp_child_id) == QIHSE_ANALYSIS_STORE_OK);

    /* Tombstone tmp_m */
    assert(qihse_analysis_artifact_tombstone_user(store, tmp_id, "superseded by gen 52", analyst) == QIHSE_ANALYSIS_STORE_OK);

    /* Direct read of tombstoned manifest returns TOMBSTONED */
    qihse_analysis_artifact_v1_t tomb_read_m;
    assert(qihse_analysis_artifact_get_manifest_user(store, tmp_id, analyst, &tomb_read_m) == QIHSE_ANALYSIS_STORE_TOMBSTONED);
    assert(qihse_analysis_artifact_get_payload_user(store, tmp_id, 0, read_payload, sizeof(read_payload), &out_read, analyst) == QIHSE_ANALYSIS_STORE_TOMBSTONED);

    /* Selective invalidation: child artifact's lineage check fails because parent is tombstoned! */
    assert(qihse_analysis_artifact_verify_lineage_user(store, tmp_child_id, analyst) == QIHSE_ANALYSIS_STORE_LINEAGE_ERROR);

    /* Ingesting a new artifact referencing the tombstoned parent must fail */
    qihse_analysis_artifact_v1_t bad_descendant = make_derived_manifest(
        QIHSE_ANALYSIS_TRACE, "kp14.trace.v1",
        TEST_TENANT, 2, 1, bin_m.binary_sha384, tmp_id,
        (const uint8_t*)trace_bytes, trace_len, 52);
    uint8_t bad_desc_id[QIHSE_BLOB_HASH_BYTES];
    assert(qihse_analysis_artifact_ingest_buffer_user(
        store, &bad_descendant, (const uint8_t*)trace_bytes, trace_len, analyst, bad_desc_id) == QIHSE_ANALYSIS_STORE_LINEAGE_ERROR);

    /* Blob unpinning: after tombstone, the blob referenced by tmp_m is unpinned */
    assert(qihse_blob_is_pinned_user(blob_store, tmp_m.payload_sha384, analyst, &is_pinned));
    assert(!is_pinned);

    /* ── 5. Authenticated Security Context & Negative Tests ────────────────── */
    /* Store classified high-data artifact: clearance 2, SCI 1, tenant 77 */
    const char secret_payload[] = CLASSIFIED_PAYLOAD_SECRET;
    size_t secret_len = strlen(secret_payload);
    qihse_analysis_artifact_v1_t secret_m = make_derived_manifest(
        QIHSE_ANALYSIS_REPORT, "kp14.secret.report.v1",
        TEST_TENANT, 2, 1, bin_m.binary_sha384, bin_id,
        (const uint8_t*)secret_payload, secret_len, 99);
    uint8_t secret_id[QIHSE_BLOB_HASH_BYTES];
    assert(qihse_analysis_artifact_ingest_buffer_user(
        store, &secret_m, (const uint8_t*)secret_payload, secret_len, analyst, secret_id) == QIHSE_ANALYSIS_STORE_OK);

    /* Low-clearance negative tests (clearance 1, SCI 0) */
    qihse_analysis_artifact_v1_t denied_m;
    memset(&denied_m, 0xaa, sizeof(denied_m));
    assert(qihse_analysis_artifact_get_manifest_user(store, secret_id, low, &denied_m) == QIHSE_ANALYSIS_STORE_DENIED);
    /* Output struct untouched */
    assert(denied_m.version == 0xaaaa);

    uint8_t secret_buf[256];
    memset(secret_buf, 0xbb, sizeof(secret_buf));
    out_read = 999;
    assert(qihse_analysis_artifact_get_payload_user(
        store, secret_id, 0, secret_buf, sizeof(secret_buf), &out_read, low) == QIHSE_ANALYSIS_STORE_DENIED);
    assert(out_read == 999 && secret_buf[0] == 0xbb);
    assert(memmem(secret_buf, sizeof(secret_buf), "TOPSECRET", 9) == NULL);

    /* Missing-SCI negative tests (clearance 2, SCI 0) */
    assert(qihse_analysis_artifact_get_manifest_user(store, secret_id, no_sci, &denied_m) == QIHSE_ANALYSIS_STORE_DENIED);
    assert(qihse_analysis_artifact_get_payload_user(
        store, secret_id, 0, secret_buf, sizeof(secret_buf), &out_read, no_sci) == QIHSE_ANALYSIS_STORE_DENIED);
    assert(memmem(secret_buf, sizeof(secret_buf), "TOPSECRET", 9) == NULL);

    /* Foreign tenant negative tests (tenant 78) */
    assert(qihse_analysis_artifact_get_manifest_user(store, secret_id, foreign, &denied_m) == QIHSE_ANALYSIS_STORE_DENIED);
    assert(qihse_analysis_artifact_get_payload_user(
        store, secret_id, 0, secret_buf, sizeof(secret_buf), &out_read, foreign) == QIHSE_ANALYSIS_STORE_DENIED);

    /* NULL user negative tests */
    assert(qihse_analysis_artifact_get_manifest_user(store, secret_id, NULL, &denied_m) == QIHSE_ANALYSIS_STORE_DENIED);
    assert(qihse_analysis_artifact_get_payload_user(
        store, secret_id, 0, secret_buf, sizeof(secret_buf), &out_read, NULL) == QIHSE_ANALYSIS_STORE_DENIED);

    /* Revoked user negative tests */
    assert(qihse_analysis_artifact_get_manifest_user(store, secret_id, revoked, &denied_m) == QIHSE_ANALYSIS_STORE_DENIED);
    assert(qihse_analysis_artifact_get_payload_user(
        store, secret_id, 0, secret_buf, sizeof(secret_buf), &out_read, revoked) == QIHSE_ANALYSIS_STORE_DENIED);

    /* Enumeration negative test: low-clearance user cannot see secret_m in list */
    list_capture_t low_list = {0};
    assert(qihse_analysis_artifact_list_user(store, low, list_cb, &low_list) == QIHSE_ANALYSIS_STORE_OK);
    for (size_t i = 0; i < low_list.count; i++) {
        assert(memcmp(low_list.ids[i], secret_id, QIHSE_BLOB_HASH_BYTES) != 0);
    }

    /* Search negative test: low-clearance user gets zero search hits for secret schema */
    qihse_analysis_search_filter_t sec_filter = {0};
    snprintf(sec_filter.artifact_schema, sizeof(sec_filter.artifact_schema), "kp14.secret.report.v1");
    uint8_t search_hits[8][QIHSE_BLOB_HASH_BYTES];
    size_t hit_count = 999;
    assert(qihse_analysis_artifact_search_user(store, &sec_filter, low, search_hits, 8, &hit_count) == QIHSE_ANALYSIS_STORE_OK);
    assert(hit_count == 0);

    /* Export negative test: low-clearance user denied export */
    uint8_t export_buf[1024];
    memset(export_buf, 0xcc, sizeof(export_buf));
    size_t export_len = 999;
    assert(qihse_analysis_artifact_export_user(store, secret_id, low, export_buf, sizeof(export_buf), &export_len) == QIHSE_ANALYSIS_STORE_DENIED);
    assert(export_len == 0 && export_buf[0] == 0xcc);

    /* Authorized user CAN export */
    assert(qihse_analysis_artifact_export_user(store, secret_id, analyst, export_buf, sizeof(export_buf), &export_len) == QIHSE_ANALYSIS_STORE_OK);
    assert(export_len == QIHSE_ANALYSIS_EXPORT_FRAME_BYTES);

    /* ── 6. Crash Recovery & Replay ────────────────────────────────────────── */
    qihse_analysis_artifact_store_close(store);

    /* Reopen the store from the same directory and assert everything recovers */
    qihse_analysis_artifact_store_t* reopened = qihse_analysis_artifact_store_open(
        store_dir, NULL, NULL, NULL);
    assert(reopened != NULL);

    /* Binary artifact survives restart */
    assert(qihse_analysis_artifact_get_manifest_user(reopened, bin_id, analyst, &read_m) == QIHSE_ANALYSIS_STORE_OK);
    assert(memcmp(read_m.artifact_id, bin_id, QIHSE_BLOB_HASH_BYTES) == 0);
    assert(qihse_analysis_artifact_get_payload_user(reopened, bin_id, 0, read_payload, sizeof(read_payload), &out_read, analyst) == QIHSE_ANALYSIS_STORE_OK);
    assert(out_read == bin_len && memcmp(read_payload, bin_bytes, bin_len) == 0);

    /* Tombstone state survives restart */
    assert(qihse_analysis_artifact_get_manifest_user(reopened, tmp_id, analyst, &tomb_read_m) == QIHSE_ANALYSIS_STORE_TOMBSTONED);

    /* Lineage verification survives restart */
    assert(qihse_analysis_artifact_verify_lineage_user(reopened, report_id, analyst) == QIHSE_ANALYSIS_STORE_OK);

    /* Protected pin survives restart */
    assert(qihse_blob_is_pinned_user(qihse_analysis_artifact_store_get_blob_store(reopened), bin_m.payload_sha384, analyst, &is_pinned));
    assert(is_pinned);
    assert(!qihse_blob_delete_user(qihse_analysis_artifact_store_get_blob_store(reopened), bin_m.payload_sha384, analyst));

    qihse_analysis_artifact_store_close(reopened);

    /* Drain audit and clean up fixture directory with ZERO residue */
    qihse_audit_shutdown();
    remove_dir_recursive(dir);

    printf("test_analysis_artifact_durable: all assertions passed cleanly with zero residue\n");
    return 0;
}
