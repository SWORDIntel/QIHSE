/* test_slot_migration_auth.c — negative authorization tests for the pinned
 * slot-migration QKP surface (repo invariant 3).
 *
 * A pinned migration peer (QIHSE_RESP_AUTH_QKP_MIGRATION) may run only the
 * data-movement commands (ASKING/SET/GET/DEL) — never operator/administrative
 * commands. This exercises the allowlist primitive directly.
 */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "qihse_auth.h"
#include "qihse_cluster_ops.h"
#include "qihse_cluster_ownership_journal.h"
#include "qihse_cluster_slot.h"
#include "qihse_kv_store.h"
#include "qihse_resp_cluster.h"
#include "qihse_resp_wire.h"

static void check(const char* cmd, int expect_allowed) {
    int got = qihse_resp_migration_command_allowed(cmd, strlen(cmd)) ? 1 : 0;
    if (got != expect_allowed) {
        fprintf(stderr, "FAIL: '%s' expected %s, got %s\n", cmd,
                expect_allowed ? "allowed" : "denied", got ? "allowed" : "denied");
        abort();
    }
}

typedef struct {
    int count;
    uint16_t first;
    uint16_t last;
} journal_result_t;

static void on_journal(const qihse_cluster_ownership_entry_t* entry, void* user) {
    journal_result_t* result = user;
    result->count++;
    result->first = entry->start;
    result->last = entry->end;
}

static void test_handoff_guards(void) {
    char dir[] = "build/slot-migration-guard-XXXXXX";
    assert(mkdtemp(dir));
    assert(setenv("QIHSE_DATA_DIR", dir, 1) == 0);
    assert(qihse_auth_init());
    assert(qihse_auth_bootstrap_operator("SlotMigrationOperator123!"));
    qihse_user_t* op = qihse_auth_authenticate_id(0u, "SlotMigrationOperator123!");
    assert(op);
    qihse_user_t* low = qihse_auth_create_user(op, 86u, QIHSE_ROLE_GUEST,
                                               0u, 0u, "SlotMigrationLow123!", false);
    assert(low);
    assert(qihse_auth_authenticate_id(86u, "SlotMigrationLow123!") == low);
    qihse_kv_store_t* store = qihse_kv_store_create_user(op);
    assert(store);
    const char* protected_key = "slot-guard-protected";
    const char* protected_value = "HIGH-CLASSIFICATION-SCI-PAYLOAD";
    assert(qihse_kv_set_user(store, protected_key, protected_value, 5u, 9u, op));
    assert(qihse_kv_get_user(store, protected_key, low) == NULL);

    qihse_resp_server_config_t config;
    qihse_resp_server_config_init(&config);
    config.store = store;
    config.auth_required = true;
    config.port = 0u;
    qihse_resp_server_t* server = qihse_resp_server_create(&config);
    assert(server);
    qihse_cluster_topology_t* topology = qihse_resp_server_topology(server);
    assert(topology);
    uint16_t local = qihse_cluster_topology_local_node(topology);
    qihse_cluster_node_t target = {0};
    qihse_cluster_node_id_from_seed("slot-guard-target", strlen("slot-guard-target"), target.id);
    snprintf(target.host, sizeof(target.host), "127.0.0.1");
    target.port = 1u;
    target.role = QIHSE_CLUSTER_NODE_PRIMARY;
    target.primary_index = QIHSE_CLUSTER_NODE_NONE;
    target.healthy = true;
    uint16_t peer = QIHSE_CLUSTER_NODE_NONE;
    assert(qihse_cluster_topology_upsert_node(topology, &target, &peer));
    uint16_t protected_slot = qihse_cluster_key_slot(protected_key, strlen(protected_key));
    assert(qihse_cluster_topology_assign_range(topology, protected_slot, protected_slot, local));

    uint64_t moved = UINT64_MAX, collected = UINT64_MAX;
    char error[160];
    assert(qihse_cluster_handoff_range(server, protected_slot, protected_slot, peer,
                                       &moved, &collected, error, sizeof(error)) == -1);
    assert(moved == 0u && collected == 0u);
    assert(strstr(error, "all-writer fence"));
    assert(strstr(error, protected_value) == NULL);
    uint16_t owner = QIHSE_CLUSTER_NODE_NONE;
    assert(qihse_cluster_topology_get_slot(topology, protected_slot, &owner, NULL, NULL));
    assert(owner == local);
    assert(qihse_kv_get_user(store, protected_key, low) == NULL);

    uint16_t empty_slot = (uint16_t)((protected_slot + 1u) % QIHSE_CLUSTER_SLOT_COUNT);
    char plain_key[64];
    uint16_t plain_slot = protected_slot;
    for (unsigned candidate = 0; candidate < QIHSE_CLUSTER_SLOT_COUNT; candidate++) {
        snprintf(plain_key, sizeof(plain_key), "slot-guard-plain-%u", candidate);
        plain_slot = qihse_cluster_key_slot(plain_key, strlen(plain_key));
        if (plain_slot != protected_slot && plain_slot != empty_slot) break;
    }
    assert(plain_slot != protected_slot && plain_slot != empty_slot);
    assert(qihse_kv_set_user(store, plain_key, "unclassified", 0u, 0u, op));
    assert(qihse_cluster_topology_assign_range(topology, plain_slot, plain_slot, local));
    assert(qihse_cluster_handoff_range(server, plain_slot, plain_slot, peer,
                                       &moved, &collected, error, sizeof(error)) == -1);
    assert(moved == 0u && collected == 0u);
    assert(strstr(error, "all-writer fence"));
    assert(qihse_cluster_topology_get_slot(topology, plain_slot, &owner, NULL, NULL));
    assert(owner == local);

    assert(qihse_cluster_topology_assign_range(topology, empty_slot, empty_slot, local));
    assert(qihse_cluster_handoff_range(server, empty_slot, empty_slot, peer,
                                       &moved, &collected, error, sizeof(error)) == -1);
    assert(moved == 0u && collected == 0u);
    assert(strstr(error, "all-writer fence"));
    assert(qihse_cluster_topology_get_slot(topology, empty_slot, &owner, NULL, NULL));
    assert(owner == local);

    assert(qihse_cluster_handoff_range(server, 2u, 1u, peer,
                                       &moved, &collected, error, sizeof(error)) == -1);
    assert(strstr(error, "invalid slot range"));
    journal_result_t before = {0};
    assert(qihse_cluster_ownership_journal_replay(dir, on_journal, &before) == 0);
    assert(qihse_cluster_topology_get_slot(topology, empty_slot, &owner, NULL, NULL));
    assert(owner == local);
    qihse_resp_server_destroy(server);
    qihse_kv_store_destroy(store);
    printf("[PASS] classified, plain, and empty handoffs leave journal and ownership unchanged\n");
}

int main(void) {
    test_handoff_guards();
    /* data-movement commands are permitted */
    check("ASKING", 1);
    check("asking", 1); /* case-insensitive */
    check("SET", 1);
    check("GET", 1);
    check("DEL", 1);
    printf("[PASS] migration peer may run ASKING/SET/GET/DEL (case-insensitive)\n");

    /* operator / administrative / other commands are denied */
    check("CLUSTER", 0);
    check("FTS.SEARCH", 0);
    check("KEYS", 0);
    check("QIHSE.USER.CREATE", 0);
    check("REPL.DELTA", 0);
    check("MACHINEAUTH", 0);
    check("AUTH", 0);
    check("SETEX", 0);
    check("SETRANGE", 0); /* only exact SET, not the family */
    check("", 0);
    check("SETTING", 0); /* prefix match is NOT enough */
    printf("[PASS] migration peer denied operator/administrative commands\n");

    printf("All slot-migration auth tests passed.\n");
    return 0;
}
