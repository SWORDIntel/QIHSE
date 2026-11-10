/* SPDX-License-Identifier: LicenseRef-SRSL-1.1 */
/* Command-level regression for per-lane CT ownership on one RESP process. */
#define _GNU_SOURCE
#include "qihse_auth.h"
#include "qihse_ct_group_config.h"
#include "qihse_kv_store.h"
#include "qihse_resp_wire.h"
#include "qihse_cluster_slot.h"
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define ID_A "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
#define ID_B "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
#define ID_C "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
#define ID_LOCAL "1111111111111111111111111111111111111111111111111111111111111111"
#define GEN_A "11111111111111111111111111111111"
#define GEN_B "22222222222222222222222222222222"
#define GEN_C "33333333333333333333333333333333"
#define LANE_A "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
#define LANE_B "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
#define LANE_C "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
#define ACK_TIMEOUT_MS 3000u

typedef struct {
    qihse_kv_store_t *store;
    qihse_user_t *peer;
    atomic_bool stop;
    atomic_uint ack_count;
} ack_context_t;

static bool topology_qkp_id(void *context, const char *topology_id,
                            char out[QIHSE_QKP_NODE_ID_LEN + 1u]) {
    (void)context;
    const char *id = NULL;
    if (!strcmp(topology_id, "local")) id = ID_LOCAL;
    else if (!strcmp(topology_id, "peer-a")) id = ID_A;
    else if (!strcmp(topology_id, "peer-b")) id = ID_B;
    else if (!strcmp(topology_id, "peer-c")) id = ID_C;
    if (!id) return false;
    memcpy(out, id, QIHSE_QKP_NODE_ID_LEN);
    out[QIHSE_QKP_NODE_ID_LEN] = '\0';
    return true;
}

static void *ack_main(void *opaque) {
    ack_context_t *ctx = opaque;
    const char *lanes[] = {LANE_A, LANE_B};
    const char *peers[] = {ID_A, ID_B};
    const char *gens[] = {GEN_A, GEN_B};
    uint64_t positions[2] = {0u, 0u};
    while (!atomic_load_explicit(&ctx->stop, memory_order_relaxed)) {
        for (size_t i = 0; i < 2u; ++i) {
            qihse_kv_ct_group_t *groups = NULL;
            size_t count = 0u;
            uint64_t resume = 0u;
            if (qihse_kv_ct_lane_source_read(ctx->store, ctx->peer, lanes[i],
                    gens[i], positions[i], 64u, 1u << 20, &groups, &count, &resume)) {
                if (count && qihse_kv_ct_lane_source_ack(ctx->store, ctx->peer,
                        lanes[i], peers[i], gens[i], resume)) {
                    atomic_fetch_add_explicit(&ctx->ack_count, (unsigned)count,
                                              memory_order_relaxed);
                    positions[i] = resume;
                }
                qihse_kv_ct_groups_free(groups, count);
            }
        }
        struct timespec pause = {.tv_sec = 0, .tv_nsec = 1000000L};
        nanosleep(&pause, NULL);
    }
    return NULL;
}

static char *key_for_slot(const char *prefix, uint16_t wanted_slot) {
    char candidate[128];
    for (unsigned i = 0; i < 1000000u; ++i) {
        int n = snprintf(candidate, sizeof(candidate), "%s%u", prefix, i);
        assert(n > 0 && (size_t)n < sizeof(candidate));
        if (qihse_cluster_key_slot(candidate, (size_t)n) == wanted_slot)
            return strdup(candidate);
    }
    assert(!"could not find key for test slot");
    return NULL;
}

static void check_reply(qihse_resp_server_t *server, qihse_user_t *user,
                        size_t argc, const char *const *argv,
                        const char *prefix, const char *contains) {
    qihse_resp_arg_t args[16];
    assert(argc <= sizeof(args) / sizeof(args[0]));
    for (size_t i = 0; i < argc; ++i) {
        args[i].data = (const uint8_t *)argv[i];
        args[i].len = strlen(argv[i]);
    }
    uint8_t *reply = NULL;
    size_t reply_len = 0u;
    assert(qihse_resp_server_execute(server, user, argc, args,
                                     &reply, &reply_len));
    assert(reply && reply_len > 0u);
    assert(reply[0] == (uint8_t)prefix[0]);
    if (contains) {
        char *text = malloc(reply_len + 1u);
        assert(text);
        memcpy(text, reply, reply_len);
        text[reply_len] = '\0';
        assert(strstr(text, contains) != NULL);
        free(text);
    }
    free(reply);
}

static void assert_reply(qihse_resp_server_t *server, qihse_user_t *user,
                         size_t argc, const char *const *argv,
                         const char *expected) {
    qihse_resp_arg_t args[16];
    assert(argc <= sizeof(args) / sizeof(args[0]));
    for (size_t i = 0; i < argc; ++i) {
        args[i].data = (const uint8_t *)argv[i];
        args[i].len = strlen(argv[i]);
    }
    uint8_t *reply = NULL;
    size_t reply_len = 0u;
    assert(qihse_resp_server_execute(server, user, argc, args,
                                     &reply, &reply_len));
    assert(reply && reply_len == strlen(expected));
    assert(memcmp(reply, expected, reply_len) == 0);
    free(reply);
}

static void assert_value(qihse_kv_store_t *store, qihse_user_t *user,
                         const char *key, const char *expected) {
    char *value = qihse_kv_get_user(store, key, user);
    if (!expected) assert(value == NULL);
    else { assert(value && strcmp(value, expected) == 0); free(value); }
}

int main(void) {
    umask(0077);
    char data_dir[] = "/tmp/qihse-ct-lane-commands-XXXXXX";
    assert(mkdtemp(data_dir));
    assert(setenv("QIHSE_DATA_DIR", data_dir, 1) == 0);
    assert(setenv("QIHSE_FIPS_MODE", "disabled", 1) == 0);
    assert(qihse_auth_init());
    static const char operator_password[] = "CTLaneCommandsOperator1!";
    assert(qihse_auth_bootstrap_operator(operator_password));
    qihse_user_t *op = qihse_auth_authenticate_id(0u, operator_password);
    qihse_user_t *peer = qihse_auth_create_user(op, 9901u, QIHSE_ROLE_ANALYST,
        5u, 3u, "CTLaneCommandsPeer1!", false);
    assert(op && peer);

    qihse_ct_group_config_t configs[3];
    char spec_a[256], spec_b[256], spec_c[256];
    snprintf(spec_a, sizeof(spec_a), "%s,local,peer-a,%s,127", LANE_A, GEN_A);
    snprintf(spec_b, sizeof(spec_b), "%s,local,peer-b,%s,12000", LANE_B, GEN_B);
    snprintf(spec_c, sizeof(spec_c), "%s,peer-c,local,%s,14000", LANE_C, GEN_C);
    assert(qihse_ct_group_config_parse(spec_a, &configs[0]));
    assert(qihse_ct_group_config_parse(spec_b, &configs[1]));
    assert(qihse_ct_group_config_parse(spec_c, &configs[2]));
    assert(qihse_ct_group_configs_validate(configs, 3u));

    qihse_kv_store_t *store = qihse_kv_store_create_user(op);
    assert(store);
    qihse_kv_store_set_replication_principal_id(store, qihse_user_get_id(peer));
    unsigned char token_a[QIHSE_KV_CT_TOKEN_BYTES], token_b[QIHSE_KV_CT_TOKEN_BYTES];
    unsigned char token_c[QIHSE_KV_CT_TOKEN_BYTES];
    assert(qihse_kv_ct_lane_source_enable(store, op, LANE_A,
        configs[0].slot_bitmap, ID_LOCAL, ID_A, GEN_A, token_a, 1u << 20));
    assert(qihse_kv_ct_lane_source_enable(store, op, LANE_B,
        configs[1].slot_bitmap, ID_LOCAL, ID_B, GEN_B, token_b, 1u << 20));
    assert(qihse_kv_ct_lane_receiver_bind(store, op, LANE_C,
        configs[2].slot_bitmap, ID_C, ID_LOCAL, GEN_C,
        QIHSE_KV_CT_TENANT_SYSTEM_ALL, 0u, 0u, token_c));
    unsigned char empty_digest[32];
    assert(qihse_kv_ct_lane_receiver_empty_baseline_seal(store, op, LANE_C,
        token_c, empty_digest));

    const char *lanes[] = {LANE_A, LANE_B};
    const char *peer_ids[] = {ID_A, ID_B};
    const char *gens[] = {GEN_A, GEN_B};
    for (size_t i = 0; i < 2u; ++i) {
        qihse_kv_replica_snapshot_t *baseline = NULL;
        uint64_t row_seq = UINT64_MAX;
        unsigned char digest[32];
        assert(qihse_kv_ct_lane_source_baseline_snapshot_create(store, op,
            lanes[i], &baseline, &row_seq, digest) == 0);
        assert(baseline && row_seq == 0u);
        assert(qihse_kv_ct_lane_source_reconcile_peer(store, op, peer,
            lanes[i], peer_ids[i], gens[i], digest, 0u));
        qihse_kv_replica_snapshot_destroy(baseline);
    }

    ack_context_t ack = {.store = store, .peer = peer};
    atomic_init(&ack.stop, false);
    atomic_init(&ack.ack_count, 0u);
    pthread_t ack_thread;
    assert(pthread_create(&ack_thread, NULL, ack_main, &ack) == 0);

    qihse_resp_server_config_t config;
    qihse_resp_server_config_init(&config);
    config.store = store;
    config.auth_required = true;
    config.enable_uwp_bridge = true;
    config.ct_control_principal = op;
    config.replication_service_principal = peer;
    config.ct_topology_qkp_id = topology_qkp_id;
    config.ct_groups = configs;
    config.ct_group_count = 3u;
    config.pqc.require = true;
    config.pqc.node_id = ID_LOCAL;
    qihse_resp_server_t *server = qihse_resp_server_create(&config);
    assert(server);

    char *a = key_for_slot("lane-a-", 127u);
    char *b = key_for_slot("lane-b-", 12000u);
    char *a2 = key_for_slot("lane-a2-", 127u);
    const char *cross_mset[] = {"MSET", a, "new-a", b, "new-b"};
    check_reply(server, op, 5u, cross_mset, "-", "CROSSSLOT");
    assert_value(store, op, a, NULL);
    assert_value(store, op, b, NULL);

    const char *set_a[] = {"SET", a, "old-a"};
    const char *set_b[] = {"SET", b, "old-b"};
    check_reply(server, op, 3u, set_a, "+", NULL);
    check_reply(server, op, 3u, set_b, "+", NULL);
    assert_value(store, op, a, "old-a");
    assert_value(store, op, b, "old-b");
    const char *cross_del[] = {"DEL", a, b};
    check_reply(server, op, 3u, cross_del, "-", "CROSSSLOT");
    assert_value(store, op, a, "old-a");
    assert_value(store, op, b, "old-b");

    const char *same_mset[] = {"MSET", a, "v1", a2, "v2"};
    check_reply(server, op, 5u, same_mset, "+", NULL);
    const char *get_a[] = {"GET", a};
    check_reply(server, op, 2u, get_a, "$", "v1");
    const char *dbsize[] = {"DBSIZE"};
    assert_reply(server, op, 1u, dbsize, ":3\r\n");

    /* Node-local AIMEM keys are outside slot lanes but remain writable. */
    const char *aimem_set[] = {"SET", "t:42/aimem:ct-lane-regression", "local"};
    check_reply(server, op, 3u, aimem_set, "+", NULL);
    assert_value(store, op, "t:42/aimem:ct-lane-regression", "local");

    /* Expiry maintenance must append lane tombstones without fencing the
     * whole store or breaking subsequent ordinary source-lane writes. */
    char *expire_key = key_for_slot("lane-a-expire-", 127u);
    const char *expiring[] = {"SET", expire_key, "gone", "PX", "2"};
    check_reply(server, op, 5u, expiring, "+", NULL);
    struct timespec wait = {.tv_sec = 0, .tv_nsec = 10000000L};
    nanosleep(&wait, NULL);
    qihse_kv_sweep_expired(store);
    assert_value(store, op, expire_key, NULL);
    const char *after_expiry[] = {"SET", a, "after-expiry"};
    check_reply(server, op, 3u, after_expiry, "+", NULL);
    assert_value(store, op, a, "after-expiry");
    assert(atomic_load_explicit(&ack.ack_count, memory_order_relaxed) > 0u);

    qihse_resp_server_destroy(server);
    atomic_store_explicit(&ack.stop, true, memory_order_relaxed);
    assert(pthread_join(ack_thread, NULL) == 0);
    qihse_kv_store_destroy(store);
    free(a); free(b); free(a2); free(expire_key);
    qihse_auth_release_principal_scoped(peer);
    qihse_auth_release_principal_scoped(op);
    puts("CT lane RESP command regression passed");
    return 0;
}
