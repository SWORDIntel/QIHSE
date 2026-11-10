#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "qihse_cluster_certificate_recovery.h"
#include "qihse_resp_wire.h"
#include "aimem_fixture_cleanup.h"
#include <openssl/evp.h>
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

static const char lane[] = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
static unsigned calls, applied;
static bool pin_available = true;
enum { VALID, BAD_LENGTH, BAD_DIGEST, BAD_SIGNATURE, WRONG_LANE, NO_PROGRESS, EMPTY, UNFINALIZED };
static unsigned variant;

static void hex(const uint8_t in[32], char out[65]) {
    for (size_t i = 0; i < 32; ++i) snprintf(out + 2u * i, 3u, "%02x", in[i]);
}
static void certificate(unsigned n, uint8_t out[3], uint8_t digest[32]) {
    out[0] = (uint8_t)n; out[1] = 0; out[2] = 255;
    unsigned size = 0;
    assert(EVP_Digest(out, 3, digest, &size, EVP_sha256(), NULL) == 1 && size == 32);
}
bool qihse_cluster_topology_get_node(const qihse_cluster_topology_t* t,
    uint16_t index, qihse_cluster_node_t* node) {
    assert(t && index == 2); memset(node, 0, sizeof(*node));
    strcpy(node->id, "target-c"); return true;
}
static bool peer(void* ctx, const char* topology, char out[65]) {
    (void)ctx; assert(!strcmp(topology, "target-c"));
    if (!pin_available) return false;
    strcpy(out, "qkp-c"); return true;
}

bool qihse_resp_ct_peer_command_to(qihse_resp_server_t* server, uint16_t index,
    const char* qkp, const qihse_resp_ct_arg_t* args, size_t count,
    qihse_resp_ct_reply_t* reply) {
    assert(server && index == 2 && !strcmp(qkp, "qkp-c") && count == 5);
    assert(args[0].len == 8 && !memcmp(args[0].data, "REPL.CT1", 8));
    assert(args[1].len == 8 && !memcmp(args[1].data, "CERTPAGE", 8));
    assert(args[2].len == 64 && !memcmp(args[2].data, lane, 64));
    calls++;
    unsigned n = 1;
    char cursor[65]; memcpy(cursor, args[3].data, 64); cursor[64] = 0;
    for (unsigned i = 1; i <= 3; ++i) {
        uint8_t bytes[3], digest[32]; char previous[65];
        certificate(i, bytes, digest); hex(digest, previous);
        if (!strcmp(cursor, previous)) n = i + 1;
    }
    if (variant == NO_PROGRESS) n = 1;
    uint8_t page[39] = {0}; size_t page_size = 39;
    if (variant == EMPTY || n > 3) page_size = 0;
    if (page_size) {
        page[3] = 3;
        certificate(n, page + 36, page + 4);
        if (variant == BAD_LENGTH) { page[2] = 255; page[3] = 255; }
        if (variant == BAD_DIGEST) page[4] ^= 1;
    }
    char header[32]; int h = snprintf(header, sizeof(header), "$%zu\r\n", page_size);
    assert(h > 0);
    reply->len = (size_t)h + page_size + 2;
    reply->data = malloc(reply->len); assert(reply->data);
    memcpy(reply->data, header, (size_t)h);
    memcpy(reply->data + h, page, page_size);
    memcpy(reply->data + h + page_size, "\r\n", 2);
    return true;
}
void qihse_resp_ct_reply_free(qihse_resp_ct_reply_t* reply) {
    free(reply->data); memset(reply, 0, sizeof(*reply));
}
bool qihse_cluster_bus_ct1_certificate_verify(qihse_cluster_bus_t* bus,
    const void* bytes, size_t size,
    qihse_cluster_bus_ct1_promotion_update_v2_t* update, qihse_uuid_t* signer) {
    assert(bus);
    if (variant == BAD_SIGNATURE || size != 3) return false;
    memset(update, 0, sizeof(*update)); memset(signer, 0, sizeof(*signer));
    strcpy(update->lane_id, lane);
    if (variant == WRONG_LANE) update->lane_id[0] = 'b';
    memset(update->event_digest, *(const uint8_t*)bytes, 32);
    update->base.durable_cursor = *(const uint8_t*)bytes;
    return true;
}
static bool committed(void* opaque, qihse_user_t* principal,
    const qihse_cluster_ownership_txn_t* t, char* error, size_t cap) {
    (void)opaque; (void)error; (void)cap; assert(principal);
    return variant != UNFINALIZED || t->source_lsn != 2;
}
bool qihse_cluster_ownership_receive_ct1_promotion_chain(
    qihse_cluster_ownership_context_t* ctx, const uint8_t* const* records,
    const size_t* sizes, size_t count, char* error, size_t cap) {
    (void)error; (void)cap; assert(ctx && count == (variant == UNFINALIZED ? 2u : 3u));
    for (size_t i = 0; i < count; ++i)
        assert(sizes[i] == 3 && records[i][0] == (variant == UNFINALIZED && i == 1 ? 3 : i + 1));
    applied++; return true;
}

int main(void) {
    assert(mkdir("build", 0700) == 0 || errno == EEXIST);
    char directory[] = "build/certificate-recovery-XXXXXX"; assert(mkdtemp(directory));
    assert(!setenv("QIHSE_DATA_DIR", directory, 1));
    assert(!setenv("QIHSE_AUTH_STATE_DIR", directory, 1));
    assert(!setenv("QIHSE_AUDIT_DIR", directory, 1));
    assert(qihse_auth_init());
    qihse_user_t* op = qihse_auth_get_user(0);
    qihse_user_t* low = qihse_auth_create_user(op, 63994, QIHSE_ROLE_ANALYST,
        0, 0, "CertificateRecovery1!", false); assert(low);
    qihse_cluster_ownership_context_t ctx = {0};
    ctx.principal = low; ctx.peer_id = peer;
    ctx.range_check_finalized = committed;
    ctx.topology = (qihse_cluster_topology_t*)(uintptr_t)1;
    ctx.resp_server = (qihse_resp_server_t*)(uintptr_t)2;
    ctx.bus = (qihse_cluster_bus_t*)(uintptr_t)3;
    uint8_t through[32]; memset(through, 3, 32);
    char error[160];
    assert(!qihse_cluster_ownership_pull_ct1_promotion_chain(&ctx, 2, lane, through, 1000, error, sizeof(error)));
    assert(!calls && !applied);
    ctx.principal = NULL;
    assert(!qihse_cluster_ownership_pull_ct1_promotion_chain(&ctx, 2, lane, through, 1000, error, sizeof(error)));
    assert(!calls && !applied);
    ctx.principal = op; pin_available = false;
    assert(!qihse_cluster_ownership_pull_ct1_promotion_chain(&ctx, 2, lane, through, 1000, error, sizeof(error)));
    assert(!calls && !applied);
    pin_available = true;
    assert(qihse_cluster_ownership_pull_ct1_promotion_chain(&ctx, 2, lane, through, 1000, error, sizeof(error)));
    assert(calls == 3 && applied == 1);
    for (variant = BAD_LENGTH; variant <= EMPTY; ++variant) {
        calls = applied = 0;
        assert(!qihse_cluster_ownership_pull_ct1_promotion_chain(&ctx, 2, lane, through, 1000, error, sizeof(error)));
        assert(calls && !applied && error[0]);
    }
    variant = UNFINALIZED; calls = applied = 0;
    assert(qihse_cluster_ownership_pull_ct1_promotion_chain(&ctx, 2, lane, through, 1000, error, sizeof(error)));
    assert(calls == 3 && applied == 1);
    aimem_fixture_cleanup(directory);
    puts("PASS certificate recovery: scoped pinned pagination and complete verified-chain admission");
    return 0;
}
