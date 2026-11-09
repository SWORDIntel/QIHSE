#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "qihse_ct_target.h"
#include "qihse_kv_store.h"

#include <assert.h>
#include <errno.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

struct qihse_user_s { uint32_t id, tenant; uint16_t role, classif, sci; bool active; };
struct qihse_cluster_topology { int marker; };
struct qihse_kv_ct_proof { int marker; };
struct qihse_resp_ct_abort_request { int marker; };
struct qihse_resp_ct_activation_request { int marker; };
static qihse_cluster_ownership_txn_t txn;
static unsigned char seal_sha[32];
static struct qihse_resp_ct_activation_request activation_request;
static bool journal_finalized;

bool qihse_resp_ct_abort_request_fields(const qihse_resp_ct_abort_request_t *request,
    const char **transfer, const char **topo_source, const char **topo_target,
    const char **qkp_source, const char **qkp_target, const char **generation,
    uint16_t *first, uint16_t *last, uint64_t *source_lsn, uint64_t *config_epoch,
    unsigned char checksum[32]);
bool qihse_resp_ct_activation_request_fields(
    const qihse_resp_ct_activation_request_t *request,
    const char **transfer, const char **topo_source, const char **topo_target,
    const char **qkp_source, const char **qkp_target, const char **generation,
    uint16_t *first, uint16_t *last, uint64_t *source_lsn,
    uint64_t *config_epoch, uint64_t *target_lsn, unsigned char checksum[32]);

const char *qihse_kv_store_data_directory(qihse_kv_store_t *store) {
    assert(store == (void *)(uintptr_t)2);
    return "/unused-test-journal";
}
int qihse_cluster_ownership_journal_replay_txn(const char *data_dir,
    qihse_cluster_ownership_txn_cb callback, void *context, bool *unresolved) {
    assert(data_dir && callback && unresolved);
    (void)context;
    *unresolved = false;
    if (journal_finalized) {
        qihse_cluster_ownership_txn_t final = txn;
        final.phase = QIHSE_OWNERSHIP_FINALIZED;
        final.target_lsn = 100;
        memcpy(final.proof_digest, seal_sha, sizeof(final.proof_digest));
        strcpy(final.owner_id, final.target_id);
        assert(callback(&final, context));
    }
    return 0;
}

bool qihse_resp_ct_activation_request_fields(
    const qihse_resp_ct_activation_request_t *request,
    const char **transfer, const char **topo_source, const char **topo_target,
    const char **qkp_source, const char **qkp_target, const char **generation,
    uint16_t *first, uint16_t *last, uint64_t *source_lsn,
    uint64_t *config_epoch, uint64_t *target_lsn, unsigned char checksum[32]) {
    assert(request == &activation_request);
    *transfer = txn.transfer_id; *topo_source = txn.source_id; *topo_target = txn.target_id;
    *qkp_source = txn.source_qkp_id; *qkp_target = txn.target_qkp_id;
    *generation = txn.generation; *first = txn.start; *last = txn.end;
    *source_lsn = txn.source_lsn; *config_epoch = txn.config_epoch;
    *target_lsn = 100; memcpy(checksum, seal_sha, 32);
    return true;
}

static qihse_user_t control = {.id=0, .tenant=0, .role=QIHSE_ROLE_OPERATOR,
    .classif=UINT16_MAX, .sci=UINT16_MAX, .active=true};
static qihse_user_t data = {.id=17, .tenant=0, .role=QIHSE_ROLE_ANALYST,
    .classif=UINT16_MAX, .sci=UINT16_MAX, .active=true};
static qihse_user_t low = {.id=18, .tenant=0, .role=QIHSE_ROLE_ANALYST,
    .classif=1, .sci=0, .active=true};
static unsigned import_calls;
static const unsigned char source_image[] = "QFS test classified row bytes";
static unsigned char image_sha[32];
static struct qihse_resp_ct_abort_request abort_request;
static char stage_root[256];

bool qihse_auth_user_is_active(const qihse_user_t *u) { return u && u->active; }
uint16_t qihse_user_get_role(const qihse_user_t *u) { return u->role; }
uint32_t qihse_user_get_tenant_id(const qihse_user_t *u) { return u->tenant; }
uint32_t qihse_user_get_id(const qihse_user_t *u) { return u->id; }
uint16_t qihse_user_get_classification(const qihse_user_t *u) { return u->classif; }
uint16_t qihse_user_get_sci(const qihse_user_t *u) { return u->sci; }
bool qihse_auth_can_access(const qihse_user_t *u, uint16_t c, uint16_t s) {
    return u && u->active && u->classif >= c && (u->sci & s) == s;
}

bool qihse_cluster_topology_find_node(const qihse_cluster_topology_t *t,
    const char *id, uint16_t *out) {
    if (!t || !id || !out) return false;
    if (!strcmp(id, "node-a")) { *out = 0; return true; }
    if (!strcmp(id, "node-c")) { *out = 1; return true; }
    return false;
}
bool qihse_cluster_topology_get_node(const qihse_cluster_topology_t *t,
    uint16_t index, qihse_cluster_node_t *out) {
    if (!t || !out || index > 1) return false;
    memset(out, 0, sizeof(*out));
    snprintf(out->id, sizeof(out->id), "node-%c", index == 0 ? 'a' : 'c');
    out->index = index;
    out->role = QIHSE_CLUSTER_NODE_PRIMARY;
    out->healthy = true;
    return true;
}
uint16_t qihse_cluster_topology_local_node(const qihse_cluster_topology_t *t) {
    return t ? 1 : QIHSE_CLUSTER_NODE_NONE;
}

static bool peer_id(void *context, const char *topology_id,
                    char out[QIHSE_OWNERSHIP_ID_MAX + 1u]) {
    (void)context;
    if (!strcmp(topology_id, "node-a")) strcpy(out, "qkp-a");
    else if (!strcmp(topology_id, "node-c")) strcpy(out, "qkp-c");
    else return false;
    return true;
}

bool qihse_kv_ct_owner_token_get(qihse_kv_store_t *store, qihse_user_t *principal,
                                  unsigned char out[QIHSE_KV_CT_TOKEN_BYTES]) {
    assert(store && principal == &control && out);
    memset(out, 0xa5, QIHSE_KV_CT_TOKEN_BYTES);
    return true;
}

bool qihse_kv_ct_range_import(qihse_kv_store_t *store, qihse_user_t *principal,
    qihse_user_t *data_principal, const char *transfer_id, const char *source_id,
    const char *generation, uint16_t first, uint16_t last, uint64_t source_cut,
    const char *snapshot_path, const unsigned char sha[32],
    const unsigned char token[QIHSE_KV_CT_TOKEN_BYTES], uint64_t *out_position) {
    assert(store && principal == &control && data_principal == &data);
    assert(!strcmp(transfer_id, txn.transfer_id) && !strcmp(source_id, txn.source_qkp_id));
    assert(!strcmp(generation, txn.generation) && first == txn.start && last == txn.end);
    assert(source_cut == txn.source_lsn && memcmp(sha, image_sha, 32) == 0 && token[0] == 0xa5);
    FILE *f = fopen(snapshot_path, "rb");
    assert(f);
    unsigned char buf[sizeof(source_image)];
    size_t n = fread(buf, 1, sizeof(buf), f);
    fclose(f);
    assert(n == sizeof(source_image) && memcmp(buf, source_image, n) == 0);
    import_calls++;
    *out_position = 100;
    return true;
}

qihse_kv_ct_proof_t *qihse_kv_ct_target_seal_create(qihse_kv_store_t *store,
    qihse_user_t *principal, qihse_user_t *data_principal,
    const char *transfer, const char *src,
    const char *dst, const char *generation, uint16_t first, uint16_t last,
    uint64_t source_lsn) {
    assert(store && principal == &control && data_principal == &data &&
           !strcmp(transfer, txn.transfer_id));
    assert(!strcmp(src, txn.source_qkp_id) && !strcmp(dst, txn.target_qkp_id));
    assert(!strcmp(generation, txn.generation) && first == txn.start && last == txn.end);
    assert(source_lsn == txn.source_lsn);
    return (qihse_kv_ct_proof_t *)(uintptr_t)1;
}

bool qihse_kv_ct_proof_fields(qihse_kv_store_t *store, qihse_user_t *principal,
    qihse_user_t *data_principal, const qihse_kv_ct_proof_t *proof,
    const char **id, const char **src,
    const char **dst, const char **generation, uint16_t *first, uint16_t *last,
    uint64_t *source_lsn, uint64_t *target_lsn, unsigned char checksum[32]) {
    assert(store && principal == &control && data_principal == &data &&
           proof == (void *)(uintptr_t)1);
    *id = txn.transfer_id; *src = txn.source_qkp_id; *dst = txn.target_qkp_id;
    *generation = txn.generation; *first = txn.start; *last = txn.end;
    *source_lsn = txn.source_lsn; *target_lsn = 100;
    memcpy(checksum, seal_sha, 32);
    return true;
}
bool qihse_resp_ct_abort_request_fields(const qihse_resp_ct_abort_request_t *request,
    const char **transfer, const char **topo_source, const char **topo_target,
    const char **qkp_source, const char **qkp_target, const char **generation,
    uint16_t *first, uint16_t *last, uint64_t *source_lsn, uint64_t *config_epoch,
    unsigned char checksum[32]) {
    assert(request == &abort_request);
    *transfer = txn.transfer_id; *topo_source = txn.source_id; *topo_target = txn.target_id;
    *qkp_source = txn.source_qkp_id; *qkp_target = txn.target_qkp_id;
    *generation = txn.generation; *first = txn.start; *last = txn.end;
    *source_lsn = txn.source_lsn; *config_epoch = txn.config_epoch;
    memcpy(checksum, seal_sha, 32);
    return true;
}
void qihse_kv_ct_proof_destroy(qihse_kv_ct_proof_t *proof) {
    assert(proof == (void *)(uintptr_t)1);
}

static void expect_denied(qihse_ct_target_t *target, const char *why) {
    char err[256];
    uint64_t offset = 0, total = 0;
    qihse_ct_target_state_t state = QIHSE_CT_TARGET_ABSENT;
    assert(!qihse_ct_target_begin(target, &low, "qkp-a", &txn,
        sizeof(source_image), image_sha, seal_sha, 2, &offset, err, sizeof(err)));
    assert(!qihse_ct_target_status(target, &low, "qkp-a", txn.transfer_id,
        &txn, sizeof(source_image), image_sha, seal_sha, 2,
        &offset, &total, &state, err, sizeof(err)));
    printf("PASS CT2 target refused low-authority BEGIN (%s)\n", why);
}

int main(void) {
    if (mkdir("./build", 0700) != 0 && errno != EEXIST) return 1;
    snprintf(stage_root, sizeof(stage_root), "./build/ct-target-%ld-XXXXXX", (long)getpid());
    assert(mkdtemp(stage_root));
    assert(chmod(stage_root, 0700) == 0);
    unsigned int digest_len = 0;
    assert(EVP_Digest(source_image, sizeof(source_image), image_sha, &digest_len,
        EVP_sha256(), NULL) == 1 && digest_len == 32);
    memset(seal_sha, 0x3c, sizeof(seal_sha));
    memset(&txn, 0, sizeof(txn));
    txn.phase = QIHSE_OWNERSHIP_PREPARED;
    strcpy(txn.transfer_id, "ct2-target-test");
    strcpy(txn.source_id, "node-a"); strcpy(txn.target_id, "node-c");
    strcpy(txn.owner_id, "node-a");
    strcpy(txn.source_qkp_id, "qkp-a"); strcpy(txn.target_qkp_id, "qkp-c");
    strcpy(txn.generation, "0123456789abcdef0123456789abcdef");
    txn.start = 15; txn.end = 16; txn.config_epoch = 9; txn.source_lsn = 7;

    qihse_cluster_ownership_context_t ownership = {0};
    ownership.topology = (qihse_cluster_topology_t *)(uintptr_t)1;
    ownership.store = (qihse_kv_store_t *)(uintptr_t)2;
    ownership.principal = &control;
    ownership.peer_id = peer_id;
    char err[256] = {0};
    qihse_ct_target_t *target = qihse_ct_target_create(&ownership, stage_root,
        "qkp-c", err, sizeof(err));
    assert(target && !err[0]);
    expect_denied(target, "low clearance");

    uint64_t offset = UINT64_MAX;
    assert(qihse_ct_target_begin(target, &data, "qkp-a", &txn,
        sizeof(source_image), image_sha, seal_sha, 2, &offset, err, sizeof(err)));
    assert(offset == 0);
    const size_t split = 9;
    uint64_t next = 0;
    assert(qihse_ct_target_chunk(target, &data, "qkp-a", txn.transfer_id,
        0, sizeof(source_image), image_sha, source_image, split, &next, err, sizeof(err)));
    assert(next == split);
    assert(qihse_ct_target_chunk(target, &data, "qkp-a", txn.transfer_id,
        0, sizeof(source_image), image_sha, source_image, split, &next, err, sizeof(err)));
    assert(next == split);
    assert(!qihse_ct_target_chunk(target, &data, "qkp-wrong", txn.transfer_id,
        split, sizeof(source_image), image_sha, source_image + split,
        sizeof(source_image) - split, &next, err, sizeof(err)));
    assert(!qihse_ct_target_chunk(target, &data, "qkp-a", txn.transfer_id,
        split + 1, sizeof(source_image), image_sha, source_image + split,
        sizeof(source_image) - split, &next, err, sizeof(err)));
    assert(qihse_ct_target_chunk(target, &data, "qkp-a", txn.transfer_id,
        split, sizeof(source_image), image_sha, source_image + split,
        sizeof(source_image) - split, &next, err, sizeof(err)));
    assert(next == sizeof(source_image));

    uint64_t status_offset = 0, status_total = 0;
    qihse_ct_target_state_t state = QIHSE_CT_TARGET_ABSENT;
    assert(qihse_ct_target_status(target, &data, "qkp-a", txn.transfer_id,
        &txn, sizeof(source_image), image_sha, seal_sha, 2, &status_offset, &status_total,
        &state, err, sizeof(err)));
    assert(status_offset == sizeof(source_image) && status_total == sizeof(source_image) &&
           state == QIHSE_CT_TARGET_RECEIVING);
    unsigned char wrong_sha[32];
    memcpy(wrong_sha, image_sha, sizeof(wrong_sha));
    wrong_sha[0] ^= 1u;
    uint64_t target_lsn = 0;
    unsigned char checksum[32] = {0};
    assert(!qihse_ct_target_seal(target, &data, "qkp-a", &txn,
        sizeof(source_image), wrong_sha, seal_sha,
        &target_lsn, checksum, err, sizeof(err)) && import_calls == 0);
    assert(!qihse_ct_target_seal(target, &data, "qkp-a", &txn,
        sizeof(source_image) + 1u, image_sha, seal_sha,
        &target_lsn, checksum, err, sizeof(err)) && import_calls == 0);

    assert(qihse_ct_target_cleanup_aborted(target, &data, "qkp-a", &abort_request,
        err, sizeof(err)));
    assert(!qihse_ct_target_status(target, &data, "qkp-a", txn.transfer_id,
        NULL, 0, NULL, NULL, 0, &status_offset, &status_total,
        &state, err, sizeof(err)));
    assert(qihse_ct_target_begin(target, &data, "qkp-a", &txn,
        sizeof(source_image), image_sha, seal_sha, 2, &offset, err, sizeof(err)));
    assert(offset == 0);
    assert(qihse_ct_target_chunk(target, &data, "qkp-a", txn.transfer_id,
        0, sizeof(source_image), image_sha, source_image, sizeof(source_image),
        &next, err, sizeof(err)));

    bool sealed_ok = qihse_ct_target_seal(target, &data, "qkp-a", &txn,
        sizeof(source_image), image_sha, seal_sha,
        &target_lsn, checksum, err, sizeof(err));
    if (!sealed_ok) fprintf(stderr, "seal failed: %s errno=%d\n", err, errno);
    assert(sealed_ok);
    assert(import_calls == 1 && target_lsn == 100 && memcmp(checksum, seal_sha, 32) == 0);
    assert(qihse_ct_target_receipt(target, &data, "qkp-a", &txn,
        seal_sha, &target_lsn, checksum, err, sizeof(err)));
    assert(target_lsn == 100 && memcmp(checksum, seal_sha, 32) == 0);
    journal_finalized = true;
    assert(qihse_ct_target_finalize(target, &data, "qkp-a", &activation_request,
        err, sizeof(err)));
    assert(qihse_ct_target_status(target, &data, "qkp-a", txn.transfer_id,
        &txn, sizeof(source_image), image_sha, seal_sha, 2,
        &status_offset, &status_total, &state, err, sizeof(err)));
    assert(state == QIHSE_CT_TARGET_FINALIZED);

    qihse_ct_target_destroy(target);
    target = qihse_ct_target_create(&ownership, stage_root, "qkp-c", err, sizeof(err));
    assert(target);
    expect_denied(target, "low clearance after restart");
    assert(qihse_ct_target_status(target, &data, "qkp-a", txn.transfer_id,
        &txn, sizeof(source_image), image_sha, seal_sha, 2, &status_offset, &status_total,
        &state, err, sizeof(err)));
    assert(state == QIHSE_CT_TARGET_FINALIZED && status_offset == sizeof(source_image));
    assert(qihse_ct_target_seal(target, &data, "qkp-a", &txn,
        sizeof(source_image), image_sha, seal_sha,
        &target_lsn, checksum, err, sizeof(err)) && import_calls == 1);
    qihse_ct_target_destroy(target);
    puts("CT2 target staging tests passed: auth, source binding, durable duplicate/gap handling, seal, receipt, restart");
    return 0;
}
