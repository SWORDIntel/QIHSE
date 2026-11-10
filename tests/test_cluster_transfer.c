#include "qihse_cluster_transfer.h"
#include "qihse_kv_store.h"
#include "qihse_resp_wire.h"

#include <assert.h>
#include <errno.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* This focused manager test mocks only the authenticated storage boundary and
 * pinned QKP peer RPC. The real storage/auth and QKP adapters have their own
 * negative and transport tests. */
static const unsigned char image[] = "classified-row-a\0classified-row-b\n";
static unsigned char received[sizeof(image)];
static uint64_t durable_offset;
static int dropped_first_chunk_ack;
static int fail_owner_token;
static int read_calls;
static int publish_calls;
static int abort_calls;
static bool force_prepare_failure_after_fence;
static bool prepare_diagnostic;
static bool force_prepare_definite_failure;
static bool suppress_prepared_recovery;
static unsigned prepared_lookup_count;
static bool force_export_failure;
static int export_failure_errno;
static bool force_abort_failure;
static uint64_t snapshot_size_override;
static int activated;
static char events[32][24];
static size_t event_count;
static qihse_cluster_ownership_txn_t pending;
static qihse_cluster_ownership_txn_t committed;
static qihse_cluster_ownership_txn_t finalized;
static unsigned char image_sha[32];
static unsigned char sealed_sha[32];
static unsigned char range_sha[32];
static uint16_t mock_role = QIHSE_ROLE_OPERATOR;
static uint32_t mock_tenant = QIHSE_TENANT_SYSTEM;
static bool mock_active = true;
static bool mock_data_access = true;
static uint16_t test_first = 10, test_last = 12;

struct qihse_cluster_topology { int marker; };

bool qihse_cluster_topology_get_node(const qihse_cluster_topology_t *topology,
    uint16_t index, qihse_cluster_node_t *out) {
    if (!topology || !out || (index != 1 && index != 2)) return false;
    memset(out, 0, sizeof(*out));
    out->index = index;
    snprintf(out->id, sizeof(out->id), "node-%c", index == 1 ? 'a' : 'b');
    out->role = QIHSE_CLUSTER_NODE_PRIMARY;
    out->healthy = true;
    return true;
}
uint16_t qihse_cluster_topology_local_node(const qihse_cluster_topology_t *topology) {
    return topology ? 1 : QIHSE_CLUSTER_NODE_NONE;
}
bool qihse_cluster_topology_get_slot(const qihse_cluster_topology_t *topology,
    uint16_t slot, uint16_t *owner, qihse_cluster_slot_state_t *state, uint16_t *peer) {
    (void)peer;
    if (!topology || slot < test_first || slot > test_last) return false;
    if (owner) *owner = 1;
    if (state) *state = QIHSE_CLUSTER_SLOT_STABLE;
    return true;
}
static bool peer_id(void *ctx, const char *node_id, char out[QIHSE_KV_CT_ID_MAX + 1u]) {
    (void)ctx;
    if (!strcmp(node_id, "node-a")) strcpy(out, "qkp-a");
    else if (!strcmp(node_id, "node-b")) strcpy(out, "qkp-b");
    else return false;
    return true;
}

struct qihse_cluster_ct_peer_receipt { int marker; };
struct qihse_cluster_ct_activation_receipt { int marker; };

bool qihse_auth_user_is_active(const qihse_user_t *user) { return user && mock_active; }
bool qihse_auth_can_access(const qihse_user_t *user, uint16_t c, uint16_t sci) {
    (void)c; (void)sci;
    return user && mock_active && mock_data_access;
}
uint16_t qihse_user_get_role(const qihse_user_t *user) { (void)user; return mock_role; }
uint32_t qihse_user_get_tenant_id(const qihse_user_t *user) { (void)user; return mock_tenant; }

static void event(const char *name) {
    assert(event_count < sizeof(events) / sizeof(events[0]));
    snprintf(events[event_count++], sizeof(events[0]), "%s", name);
}

static void integer_reply(qihse_resp_ct_reply_t *reply, uint64_t n) {
    char text[40];
    int len = snprintf(text, sizeof(text), ":%llu\r\n", (unsigned long long)n);
    reply->data = malloc((size_t)len);
    assert(reply->data);
    memcpy(reply->data, text, (size_t)len);
    reply->len = (size_t)len;
}

static void assert_hex_byte(const qihse_resp_ct_arg_t *arg, unsigned char value) {
    static const char digits[] = "0123456789abcdef";
    assert(arg && arg->len == 64);
    for (size_t i = 0; i < 32; ++i) {
        assert(((const char *)arg->data)[2u * i] == digits[value >> 4]);
        assert(((const char *)arg->data)[2u * i + 1u] == digits[value & 15u]);
    }
}

bool qihse_resp_ct_peer_command_to(qihse_resp_server_t *server,
    uint16_t target_index, const char *expected_qkp,
    const qihse_resp_ct_arg_t *argv, size_t argc, qihse_resp_ct_reply_t *out) {
    assert(server && target_index == 2 && expected_qkp && !strcmp(expected_qkp, "qkp-b"));
    assert(argv && argc >= 3 && out);
    const char *verb = argv[1].data;
    if (!strcmp(verb, "BEGIN")) {
        assert(argc == 15);
        assert(!strcmp(argv[2].data, pending.transfer_id));
        assert(!strcmp(argv[3].data, pending.source_id));
        assert(!strcmp(argv[4].data, pending.target_id));
        assert(!strcmp(argv[5].data, pending.source_qkp_id));
        assert(!strcmp(argv[6].data, pending.target_qkp_id));
        assert(!strcmp(argv[11].data, "7"));
        assert(argv[13].len == 64);
        assert_hex_byte(&argv[14], 0x42);
        event("begin");
        integer_reply(out, durable_offset);
        return true;
    }
    if (!strcmp(verb, "STATUS")) {
        assert(argc == 15);
        event("status");
        integer_reply(out, durable_offset);
        return true;
    }
    if (!strcmp(verb, "CHUNK")) {
        assert(argc == 7);
        uint64_t off = strtoull(argv[3].data, NULL, 10);
        uint64_t total = strtoull(argv[4].data, NULL, 10);
        assert(total == sizeof(image));
        assert(argv[5].len == 64);
        assert(off == durable_offset);
        assert(argv[6].len && off + argv[6].len <= sizeof(received));
        memcpy(received + off, argv[6].data, argv[6].len);
        durable_offset += argv[6].len;
        event("chunk");
        if (!dropped_first_chunk_ack) {
            dropped_first_chunk_ack = 1;
            return false; /* Simulate a delivered chunk with lost ACK. */
        }
        integer_reply(out, durable_offset);
        return true;
    }
    if (!strcmp(verb, "SEAL")) {
        assert(argc == 15 && durable_offset == sizeof(image));
        assert(!strcmp(argv[2].data, pending.transfer_id));
        assert(!strcmp(argv[3].data, pending.source_id));
        assert(!strcmp(argv[4].data, pending.target_id));
        assert(!strcmp(argv[5].data, pending.source_qkp_id));
        assert(!strcmp(argv[6].data, pending.target_qkp_id));
        assert(!strcmp(argv[11].data, "7"));
        assert(strtoull(argv[12].data, NULL, 10) == sizeof(image));
        assert(argv[13].len == 64);
        assert_hex_byte(&argv[14], 0x42);
        event("seal");
        out->data = malloc(5);
        assert(out->data);
        memcpy(out->data, "+OK\r\n", 5);
        out->len = 5;
        return true;
    }
    if (!strcmp(verb, "ACTIVATE")) {
        /* ACTIVATE is intentionally idempotent: a source may retry after
         * FINALIZED if the first bus announcement was lost. */
        assert(argc == 14);
        assert(!strcmp(argv[11].data, "7"));
        assert(!strcmp(argv[12].data, "6"));
        event("activate");
        out->data = malloc(5);
        assert(out->data);
        memcpy(out->data, "+OK\r\n", 5);
        out->len = 5;
        return true;
    }
    assert(!"unexpected CT2 command");
    return false;
}

void qihse_resp_ct_reply_free(qihse_resp_ct_reply_t *reply) {
    if (reply) { free(reply->data); memset(reply, 0, sizeof(*reply)); }
}

int qihse_kv_ct_range_export(qihse_kv_store_t *store, qihse_user_t *principal,
    qihse_user_t *data_principal,
    const char *transfer_id, const char *target_id, const char *generation,
    uint16_t first, uint16_t last, const unsigned char token[32],
    qihse_kv_ct_range_snapshot_t **out, uint64_t *cut, unsigned char sha[32]) {
    assert(store && principal && data_principal && transfer_id && target_id && generation && token && out && cut && sha);
    assert(first == pending.start && last == pending.end);
    event("export");
    if (force_export_failure) { errno = export_failure_errno; return -1; }
    unsigned int n = 0;
    assert(EVP_Digest(image, sizeof(image), image_sha, &n, EVP_sha256(), NULL) == 1 && n == 32);
    memcpy(sha, image_sha, 32);
    *cut = pending.source_lsn;
    *out = (qihse_kv_ct_range_snapshot_t *)(uintptr_t)1;
    return 0;
}

qihse_kv_ct_proof_t *qihse_kv_ct_source_transfer_proof_create(
    qihse_kv_store_t *store, qihse_user_t *principal, qihse_user_t *data_principal,
    const char *transfer,
    const char *source, const char *target, const char *generation,
    uint16_t first, uint16_t last, uint64_t source_lsn) {
    assert(store && principal && data_principal && !strcmp(transfer, pending.transfer_id));
    assert(!strcmp(source, pending.source_qkp_id) && !strcmp(target, pending.target_qkp_id));
    assert(!strcmp(generation, pending.generation) && first == pending.start &&
           last == pending.end && source_lsn == pending.source_lsn);
    memset(range_sha, 0x42, sizeof(range_sha));
    return (qihse_kv_ct_proof_t *)(uintptr_t)2;
}

bool qihse_kv_ct_proof_validate(qihse_kv_store_t *store, qihse_user_t *principal,
    qihse_user_t *data_principal,
    const qihse_kv_ct_proof_t *proof) {
    return store && principal && data_principal && proof == (const void *)(uintptr_t)2;
}

bool qihse_kv_ct_proof_fields(qihse_kv_store_t *store, qihse_user_t *principal,
    qihse_user_t *data_principal,
    const qihse_kv_ct_proof_t *proof, const char **transfer, const char **source,
    const char **target, const char **generation, uint16_t *first, uint16_t *last,
    uint64_t *source_lsn, uint64_t *target_lsn, unsigned char checksum[32]) {
    assert(store && principal && data_principal && proof == (const void *)(uintptr_t)2);
    *transfer = pending.transfer_id; *source = pending.source_qkp_id;
    *target = pending.target_qkp_id; *generation = pending.generation;
    *first = pending.start; *last = pending.end; *source_lsn = pending.source_lsn;
    *target_lsn = 0; memcpy(checksum, range_sha, 32);
    return true;
}

void qihse_kv_ct_proof_destroy(qihse_kv_ct_proof_t *proof) {
    assert(proof == (void *)(uintptr_t)2);
}

bool qihse_kv_ct_owner_token_get(qihse_kv_store_t *store, qihse_user_t *principal,
                                  unsigned char out[32]) {
    assert(store && principal && out);
    if (fail_owner_token) return false;
    memset(out, 0x5a, 32);
    return true;
}

bool qihse_kv_ct_range_snapshot_size(qihse_kv_ct_range_snapshot_t *snapshot,
                                      qihse_user_t *principal, uint64_t *size) {
    assert(snapshot == (qihse_kv_ct_range_snapshot_t *)(uintptr_t)1 && principal == (void *)(uintptr_t)3 && size);
    *size = snapshot_size_override ? snapshot_size_override : sizeof(image);
    return true;
}

bool qihse_kv_ct_range_snapshot_read(qihse_kv_ct_range_snapshot_t *snapshot,
    qihse_user_t *principal, uint64_t offset, void *out, size_t cap, size_t *got) {
    assert(snapshot == (qihse_kv_ct_range_snapshot_t *)(uintptr_t)1 && principal == (void *)(uintptr_t)3 && out && got);
    read_calls++;
    size_t len = sizeof(image) - (size_t)offset;
    if (len > cap) len = cap;
    memcpy(out, image + offset, len);
    *got = len;
    return true;
}

void qihse_kv_ct_range_snapshot_destroy(qihse_kv_ct_range_snapshot_t *snapshot) {
    assert(snapshot == (qihse_kv_ct_range_snapshot_t *)(uintptr_t)1);
    event("destroy");
}

bool qihse_cluster_ownership_transfer_get_prepared(qihse_cluster_ownership_context_t *c,
    const char *id, qihse_cluster_ownership_txn_t *out, char *err, size_t cap) {
    (void)c; (void)err; (void)cap;
    if (force_prepare_failure_after_fence && prepared_lookup_count++ == 0)
        return false;
    if (suppress_prepared_recovery) return false;
    if (pending.phase != QIHSE_OWNERSHIP_PREPARED || strcmp(id, pending.transfer_id)) return false;
    *out = pending;
    return true;
}

bool qihse_cluster_ownership_transfer_get_committed(qihse_cluster_ownership_context_t *c,
    const char *id, qihse_cluster_ownership_txn_t *out, char *err, size_t cap) {
    (void)c; (void)err; (void)cap;
    if (committed.phase != QIHSE_OWNERSHIP_COMMITTED || strcmp(id, committed.transfer_id)) return false;
    *out = committed;
    return true;
}

bool qihse_cluster_ownership_transfer_get_finalized(qihse_cluster_ownership_context_t *c,
    const char *id, qihse_cluster_ownership_txn_t *out, char *err, size_t cap) {
    (void)c; (void)err; (void)cap;
    if (finalized.phase != QIHSE_OWNERSHIP_FINALIZED || strcmp(id, finalized.transfer_id))
        return false;
    *out = finalized;
    return true;
}

bool qihse_cluster_ownership_transfer_prepare_ex(qihse_cluster_ownership_context_t *c,
    const char *id, uint16_t src, uint16_t dst, uint16_t first, uint16_t last,
    uint64_t *cut, bool *fence_may_be_active, char *err, size_t cap) {
    (void)err; (void)cap;
    assert(fence_may_be_active);
    *fence_may_be_active = false;
    event("prepare");
    if (force_prepare_definite_failure) return false;
    memset(&pending, 0, sizeof(pending));
    pending.phase = QIHSE_OWNERSHIP_PREPARED;
    strcpy(pending.transfer_id, id);
    strcpy(pending.source_id, "node-a");
    strcpy(pending.target_id, "node-b");
    strcpy(pending.owner_id, "node-a");
    strcpy(pending.source_qkp_id, "qkp-a");
    strcpy(pending.target_qkp_id, "qkp-b");
    strcpy(pending.generation, "0123456789abcdef0123456789abcdef");
    pending.start = first; pending.end = last;
    pending.config_epoch = 7;
    pending.source_lsn = 4;
    *cut = pending.source_lsn;
    *fence_may_be_active = true;
    if (force_prepare_failure_after_fence && prepare_diagnostic && err && cap)
        snprintf(err,cap,"injected PREPARED journal write failure");
    assert(src == 1 && dst == 2);
    c->topology = (qihse_cluster_topology_t *)(uintptr_t)3;
    c->peer_id = peer_id;
    return !force_prepare_failure_after_fence;
}

bool qihse_cluster_ownership_transfer_commit(qihse_cluster_ownership_context_t *c,
    const char *id, uint16_t src, uint16_t dst,
    const qihse_cluster_ct_peer_receipt_t *receipt, char *err, size_t cap) {
    (void)c; (void)err; (void)cap;
    assert(receipt && !strcmp(id, pending.transfer_id) && src == 1 && dst == 2);
    event("source-commit");
    committed = pending;
    committed.phase = QIHSE_OWNERSHIP_COMMITTED;
    strcpy(committed.owner_id, committed.target_id);
    committed.target_lsn = 6;
    memcpy(committed.proof_digest, sealed_sha, 32);
    pending.phase = 0;
    return true;
}

bool qihse_cluster_ownership_transfer_publish(qihse_cluster_ownership_context_t *c,
    const char *id, const qihse_cluster_ct_activation_receipt_t *receipt,
    char *err, size_t cap) {
    (void)c; (void)err; (void)cap;
    assert(receipt && !strcmp(id, committed.transfer_id) && activated);
    event("publish");
    publish_calls++;
    return true;
}

bool qihse_cluster_ownership_transfer_abort(qihse_cluster_ownership_context_t *c,
    const char *id, uint16_t src, uint16_t dst, char *err, size_t cap) {
    (void)c; (void)err; (void)cap;
    assert(id && !strcmp(id, pending.transfer_id) && src == 1 && dst == 2);
    assert(pending.phase == QIHSE_OWNERSHIP_PREPARED);
    event("abort");
    abort_calls++;
    if (force_abort_failure) return false;
    pending.phase = QIHSE_OWNERSHIP_ABORTED;
    return true;
}

bool qihse_resp_ct_peer_receipt_query_to(qihse_resp_server_t *server, uint16_t target_index,
    const char *target_qkp,
    const char *transfer, const char *topo_src, const char *topo_dst,
    const char *qkp_src, const char *qkp_dst, const char *generation,
    uint16_t first, uint16_t last, uint64_t source_lsn,
    uint64_t config_epoch,
    qihse_cluster_ct_peer_receipt_t **out) {
    assert(server && target_index == 2 && !strcmp(target_qkp, "qkp-b") &&
           !strcmp(transfer, pending.transfer_id));
    assert(!strcmp(topo_src, pending.source_id) && !strcmp(topo_dst, pending.target_id));
    assert(!strcmp(qkp_src, pending.source_qkp_id) && !strcmp(qkp_dst, pending.target_qkp_id));
    assert(!strcmp(generation, pending.generation) && first == pending.start && last == pending.end);
    assert(source_lsn == pending.source_lsn && config_epoch == pending.config_epoch &&
           memcmp(received, image, sizeof(image)) == 0);
    event("receipt");
    *out = calloc(1, sizeof(**out));
    return *out != NULL;
}

bool qihse_resp_ct_peer_receipt_validate(const qihse_cluster_ct_peer_receipt_t *receipt,
    const char *transfer, const char *topo_src, const char *topo_dst,
    const char *qkp_src, const char *qkp_dst, const char *generation,
    uint16_t first, uint16_t last, uint64_t source_lsn,
    uint64_t config_epoch,
    uint64_t *target_lsn, unsigned char checksum[32]) {
    assert(receipt && !strcmp(transfer, pending.transfer_id));
    assert(!strcmp(topo_src, pending.source_id) && !strcmp(topo_dst, pending.target_id));
    assert(!strcmp(qkp_src, pending.source_qkp_id) && !strcmp(qkp_dst, pending.target_qkp_id));
    assert(!strcmp(generation, pending.generation) && first == pending.start && last == pending.end);
    assert(source_lsn == pending.source_lsn && target_lsn && checksum);
    if (config_epoch != pending.config_epoch) return false;
    *target_lsn = 6;
    memcpy(checksum, sealed_sha, 32);
    return true;
}

void qihse_resp_ct_peer_receipt_free(qihse_cluster_ct_peer_receipt_t *receipt) { free(receipt); }

bool qihse_resp_ct_peer_activation_receipt_query_to(qihse_resp_server_t *server,
    uint16_t target_index, const char *target_qkp, const char *transfer,
    const char *topo_src, const char *topo_dst, const char *qkp_src, const char *qkp_dst,
    const char *generation, uint16_t first, uint16_t last, uint64_t source_lsn,
    uint64_t config_epoch,
    uint64_t target_lsn, const unsigned char checksum[32],
    qihse_cluster_ct_activation_receipt_t **out) {
    assert(server && target_index == 2 && !strcmp(target_qkp, "qkp-b") &&
           !strcmp(transfer, committed.transfer_id));
    assert(!strcmp(topo_src, committed.source_id) && !strcmp(topo_dst, committed.target_id));
    assert(!strcmp(qkp_src, committed.source_qkp_id) && !strcmp(qkp_dst, committed.target_qkp_id));
    assert(!strcmp(generation, committed.generation) && first == committed.start && last == committed.end);
    assert(source_lsn == committed.source_lsn && config_epoch == committed.config_epoch &&
           target_lsn == committed.target_lsn);
    assert(memcmp(checksum, committed.proof_digest, 32) == 0);
    activated = 1;
    event("activation-receipt");
    *out = calloc(1, sizeof(**out));
    return *out != NULL;
}

bool qihse_resp_ct_activation_receipt_validate(const qihse_cluster_ct_activation_receipt_t *r,
    const char *transfer, const char *topo_src, const char *topo_dst,
    const char *qkp_src, const char *qkp_dst, const char *generation,
    uint16_t first, uint16_t last, uint64_t source_lsn,
    uint64_t config_epoch,
    uint64_t *target_lsn, unsigned char checksum[32]) {
    assert(r && !strcmp(transfer, committed.transfer_id));
    assert(!strcmp(topo_src, committed.source_id) && !strcmp(topo_dst, committed.target_id));
    assert(!strcmp(qkp_src, committed.source_qkp_id) && !strcmp(qkp_dst, committed.target_qkp_id));
    assert(!strcmp(generation, committed.generation) && first == committed.start && last == committed.end);
    assert(source_lsn == committed.source_lsn && target_lsn && checksum);
    if (config_epoch != committed.config_epoch) return false;
    *target_lsn = committed.target_lsn;
    memcpy(checksum, committed.proof_digest, 32);
    return activated;
}

void qihse_resp_ct_activation_receipt_free(qihse_cluster_ct_activation_receipt_t *r) { free(r); }

static void test_low_authorization_refused_before_export_or_qkp(void) {
    qihse_cluster_ownership_context_t ownership = {0};
    ownership.store = (qihse_kv_store_t *)(uintptr_t)1;
    ownership.principal = (qihse_user_t *)(uintptr_t)2;
    ownership.data_principal = (qihse_user_t *)(uintptr_t)3;
    ownership.resp_server = (qihse_resp_server_t *)(uintptr_t)3;
    ownership.topology = (qihse_cluster_topology_t *)(uintptr_t)4;
    ownership.peer_id = peer_id;
    qihse_cluster_transfer_context_t context = {.ownership = &ownership};
    mock_role = QIHSE_ROLE_ANALYST;
    fail_owner_token = 0;
    assert(qihse_cluster_transfer_range(&context, "transfer-1", 1, 2, 10, 12,
                                        NULL, 0) == QIHSE_CLUSTER_TRANSFER_REJECTED);
    assert(read_calls == 0 && event_count == 0);
    mock_role = QIHSE_ROLE_OPERATOR;
    mock_data_access = false;
    event_count = 0;
    assert(qihse_cluster_transfer_range(&context, "transfer-low-data", 1, 2, 10, 12,
                                        NULL, 0) == QIHSE_CLUSTER_TRANSFER_REJECTED);
    assert(read_calls == 0 && event_count == 0);
    mock_data_access = true;
    fail_owner_token = 1;
    assert(qihse_cluster_transfer_range(&context, "transfer-1", 1, 2, 10, 12,
                                        NULL, 0) == QIHSE_CLUSTER_TRANSFER_REJECTED);
    assert(read_calls == 0 && event_count == 2 &&
           !strcmp(events[0], "prepare") && !strcmp(events[1], "abort"));
    fail_owner_token = 0;
}

static void test_pre_wire_failures_abort_only_new_prepare(void) {
    qihse_cluster_ownership_context_t ownership = {0};
    ownership.store = (qihse_kv_store_t *)(uintptr_t)1;
    ownership.principal = (qihse_user_t *)(uintptr_t)2;
    ownership.data_principal = (qihse_user_t *)(uintptr_t)3;
    ownership.resp_server = (qihse_resp_server_t *)(uintptr_t)3;
    ownership.topology = (qihse_cluster_topology_t *)(uintptr_t)4;
    ownership.peer_id = peer_id;
    qihse_cluster_transfer_context_t context = {.ownership = &ownership};
    int abort_before;
    event_count = 0; read_calls = 0; fail_owner_token = 0;
    force_export_failure = false;
    /* An export-layer failure is splittable only after a proven source abort. */
    force_export_failure = true;
    export_failure_errno = E2BIG;
    snapshot_size_override = 0;
    event_count = 0;
    assert(qihse_cluster_transfer_range(&context, "transfer-row-limit", 1, 2,
        10, 12, NULL, 0) == QIHSE_CLUSTER_TRANSFER_TOO_LARGE);
    assert(event_count == 3 && !strcmp(events[2], "abort"));
    force_abort_failure = true;
    event_count = 0;
    assert(qihse_cluster_transfer_range(&context, "transfer-abort-fails", 1, 2,
        10, 12, NULL, 0) == QIHSE_CLUSTER_TRANSFER_PENDING);
    assert(pending.phase == QIHSE_OWNERSHIP_PREPARED);
    force_abort_failure = false;

    /* A pre-existing PREPARED transfer may already have reached the peer.
     * Keep it fenced if local export fails; the operator can resume it. */
    memset(&pending, 0, sizeof(pending));
    pending.phase = QIHSE_OWNERSHIP_PREPARED;
    strcpy(pending.transfer_id, "transfer-retry");
    strcpy(pending.source_id, "node-a"); strcpy(pending.target_id, "node-b");
    strcpy(pending.owner_id, "node-a");
    strcpy(pending.source_qkp_id, "qkp-a"); strcpy(pending.target_qkp_id, "qkp-b");
    strcpy(pending.generation, "0123456789abcdef0123456789abcdef");
    pending.start = 10; pending.end = 12; pending.config_epoch = 7; pending.source_lsn = 4;
    event_count = 0;
    force_export_failure = true;
    snapshot_size_override = 0;
    abort_before = abort_calls;
    assert(qihse_cluster_transfer_range(&context, "transfer-retry", 1, 2,
        10, 12, NULL, 0) == QIHSE_CLUSTER_TRANSFER_PENDING);
    assert(abort_calls == abort_before && event_count == 1 &&
           !strcmp(events[0], "export"));
    force_export_failure = false;
    export_failure_errno = 0;
    snapshot_size_override = 0;
}

static void test_prepare_failure_after_fence_is_pending(void) {
    qihse_cluster_ownership_context_t ownership = {0};
    ownership.store = (qihse_kv_store_t *)(uintptr_t)1;
    ownership.principal = (qihse_user_t *)(uintptr_t)2;
    ownership.data_principal = (qihse_user_t *)(uintptr_t)3;
    ownership.resp_server = (qihse_resp_server_t *)(uintptr_t)3;
    ownership.topology = (qihse_cluster_topology_t *)(uintptr_t)4;
    ownership.peer_id = peer_id;
    qihse_cluster_transfer_context_t context = {.ownership = &ownership};
    event_count = 0;
    read_calls = 0;
    force_prepare_failure_after_fence = true;
    prepared_lookup_count = 0;
    char err[192] = {0};
    assert(qihse_cluster_transfer_range(&context, "transfer-prepare-fault",
        1, 2, 10, 12, err, sizeof(err)) == QIHSE_CLUSTER_TRANSFER_PENDING);
    assert(strstr(err, "source remains fenced") != NULL);
    assert(event_count == 1 && !strcmp(events[0], "prepare"));
    assert(read_calls == 0);
    force_prepare_failure_after_fence = false;
    prepared_lookup_count = 0;

    /* If journal replay cannot recover PREPARED, the explicit outcome flag
     * still prevents a false REJECTED result after fence acquisition began. */
    pending.phase = 0;
    force_prepare_failure_after_fence = true;
    suppress_prepared_recovery = true;
    prepare_diagnostic = true;
    prepared_lookup_count = 0;
    memset(err, 0, sizeof(err));
    assert(qihse_cluster_transfer_range(&context, "transfer-prepare-unknown",
        1, 2, 10, 12, err, sizeof(err)) == QIHSE_CLUSTER_TRANSFER_PENDING);
    assert(!strcmp(err, "injected PREPARED journal write failure"));
    assert(read_calls == 0);
    suppress_prepared_recovery = false;
    prepare_diagnostic = false;
    force_prepare_failure_after_fence = false;
    prepared_lookup_count = 0;
}

static void test_definite_prepare_rejection_stays_rejected(void) {
    qihse_cluster_ownership_context_t ownership = {0};
    ownership.store = (qihse_kv_store_t *)(uintptr_t)1;
    ownership.principal = (qihse_user_t *)(uintptr_t)2;
    ownership.data_principal = (qihse_user_t *)(uintptr_t)3;
    ownership.resp_server = (qihse_resp_server_t *)(uintptr_t)3;
    ownership.topology = (qihse_cluster_topology_t *)(uintptr_t)4;
    ownership.peer_id = peer_id;
    qihse_cluster_transfer_context_t context = {.ownership = &ownership};
    event_count = 0;
    read_calls = 0;
    force_prepare_definite_failure = true;
    assert(qihse_cluster_transfer_range(&context, "transfer-definite-reject",
        1, 2, 10, 12, NULL, 0) == QIHSE_CLUSTER_TRANSFER_REJECTED);
    assert(event_count == 1 && !strcmp(events[0], "prepare"));
    assert(read_calls == 0);
    force_prepare_definite_failure = false;
}

static void test_pinned_qkp_transfer_resumes_and_activates_before_publish(void) {
    qihse_cluster_ownership_context_t ownership = {0};
    ownership.store = (qihse_kv_store_t *)(uintptr_t)1;
    ownership.principal = (qihse_user_t *)(uintptr_t)2;
    ownership.data_principal = (qihse_user_t *)(uintptr_t)3;
    ownership.resp_server = (qihse_resp_server_t *)(uintptr_t)3;
    ownership.topology = (qihse_cluster_topology_t *)(uintptr_t)4;
    ownership.peer_id = peer_id;
    qihse_cluster_transfer_context_t context = {
        .ownership = &ownership,
        .chunk_bytes = 8,
    };
    unsigned int n = 0;
    assert(EVP_Digest(image, sizeof(image), sealed_sha, &n, EVP_sha256(), NULL) == 1 && n == 32);
    assert(qihse_cluster_transfer_range(&context, "transfer-1", 1, 2, 10, 12,
                                        NULL, 0) == QIHSE_CLUSTER_TRANSFER_COMMITTED);
    assert(publish_calls == 1 && activated && read_calls >= 2);
    size_t commit = event_count, activation = event_count, publish = event_count;
    for (size_t i = 0; i < event_count; ++i) {
        if (!strcmp(events[i], "source-commit")) commit = i;
        if (!strcmp(events[i], "activate")) activation = i;
        if (!strcmp(events[i], "publish")) publish = i;
    }
    assert(commit < activation && activation < publish);
    assert(memcmp(received, image, sizeof(image)) == 0);
    /* A finalized retry repairs a lost one-shot publication by repeating the
     * idempotent pinned activation and refreshing proof-bearing publication. */
    finalized = committed;
    finalized.phase = QIHSE_OWNERSHIP_FINALIZED;
    size_t events_before_retry = event_count;
    int reads_before_retry = read_calls;
    int publishes_before_retry = publish_calls;
    assert(qihse_cluster_transfer_range(&context, "transfer-1", 1, 2, 10, 12,
        NULL, 0) == QIHSE_CLUSTER_TRANSFER_COMMITTED);
    assert(event_count == events_before_retry + 3 &&
           read_calls == reads_before_retry &&
           publish_calls == publishes_before_retry + 1);
    assert(!strcmp(events[events_before_retry], "activate") &&
           !strcmp(events[events_before_retry + 1], "activation-receipt") &&
           !strcmp(events[events_before_retry + 2], "publish"));
    /* Reusing an immutable finalized ID with a different range is refused. */
    assert(qihse_cluster_transfer_range(&context, "transfer-1", 1, 2, 11, 12,
        NULL, 0) == QIHSE_CLUSTER_TRANSFER_REJECTED);
    assert(event_count == events_before_retry + 3 && read_calls == reads_before_retry &&
           publish_calls == publishes_before_retry + 1);
    qihse_cluster_ct_peer_receipt_t staged = {0};
    uint64_t target_lsn = 0;
    unsigned char checksum[32] = {0};
    assert(!qihse_resp_ct_peer_receipt_validate(&staged, pending.transfer_id,
        pending.source_id, pending.target_id, pending.source_qkp_id,
        pending.target_qkp_id, pending.generation, pending.start, pending.end,
        pending.source_lsn, pending.config_epoch + 1, &target_lsn, checksum));
    qihse_cluster_ct_activation_receipt_t active_receipt = {0};
    assert(!qihse_resp_ct_activation_receipt_validate(&active_receipt,
        committed.transfer_id, committed.source_id, committed.target_id,
        committed.source_qkp_id, committed.target_qkp_id, committed.generation,
        committed.start, committed.end, committed.source_lsn,
        committed.config_epoch + 1, &target_lsn, checksum));
    puts("CT2 manager tests passed: explicit auth context, resumable pinned transfer, activation before publish");
}

int main(void) {
    test_low_authorization_refused_before_export_or_qkp();
    test_pre_wire_failures_abort_only_new_prepare();
    test_prepare_failure_after_fence_is_pending();
    test_definite_prepare_rejection_stays_rejected();
    event_count = 0; read_calls = 0; publish_calls = 0; activated = 0;
    durable_offset = 0; dropped_first_chunk_ack = 0;
    memset(received, 0, sizeof(received));
    test_pinned_qkp_transfer_resumes_and_activates_before_publish();
    return 0;
}
