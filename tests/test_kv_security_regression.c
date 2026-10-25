#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "qihse_auth.h"
#include "qihse_audit.h"
#include "qihse_cluster_reclaim.h"
#include "qihse_cluster_slot.h"
#include "qihse_kv_store.h"

static size_t iter_count = 0;
static bool iter_saw_secret = false;
static bool key_iter_saw_secret = false;
static size_t key_iter_count = 0u;

static bool count_key_visible(const char* key, void* user_data) {
    (void)user_data;
    key_iter_count++;
    if (strcmp(key, "secret:sstable") == 0) key_iter_saw_secret = true;
    return true;
}

static bool count_visible(const char* key, const char* value, void* user_data) {
    (void)value;
    (void)user_data;
    iter_count++;
    if (strcmp(key, "secret:sstable") == 0) iter_saw_secret = true;
    return true;
}

static void write_file(const char* path, const void* data, size_t len) {
    FILE* f = fopen(path, "wb");
    assert(f != NULL);
    assert(fwrite(data, 1, len, f) == len);
    assert(fclose(f) == 0);
}

int main(void) {
    char data_dir[] = "build/qihse-kv-sec-XXXXXX";
    assert(mkdtemp(data_dir) != NULL);
    assert(setenv("QIHSE_DATA_DIR", data_dir, 1) == 0);
    assert(setenv("QIHSE_FIPS_MODE", "disabled", 1) == 0);

    assert(qihse_auth_init());
    assert(qihse_auth_bootstrap_operator("KVSecurityPass1!"));
    qihse_user_t* operator_user = qihse_auth_get_user(0);
    assert(operator_user != NULL);

    qihse_user_t* guest = qihse_auth_create_user(
        operator_user, 91, QIHSE_ROLE_GUEST, 0, 0,
        "GuestKVPass1!", false);
    assert(guest != NULL);

    qihse_kv_store_t* store = qihse_kv_store_create();
    assert(store != NULL);

    /* Legacy context-free writes are unclassified only. */
    assert(qihse_kv_set(store, "public:legacy", "ok", 0, 0));
    assert(!qihse_kv_set(store, "secret:legacy", "blocked", 5, 0));

    /* A caller may not create/relabel data above its own target clearance. */
    assert(!qihse_kv_set_user(store, "secret:target", "blocked", 5, 0, guest));
    assert(qihse_kv_set_user(store, "secret:sstable", "classified-value", 5, 0, operator_user));

    /* Force the protected record into an SSTable, then verify the low-clearance
     * caller cannot shadow it with a new unclassified memtable value. */
    size_t large_len = 600u * 1024u;
    char* large = (char*)malloc(large_len + 1u);
    assert(large != NULL);
    memset(large, 'A', large_len);
    large[large_len] = '\0';
    assert(qihse_kv_set_user(store, "public:flush-trigger", large, 0, 0, operator_user));
    free(large);

    assert(!qihse_kv_set_user(store, "secret:sstable", "downgraded", 0, 0, guest));
    char* secret = qihse_kv_get_user(store, "secret:sstable", operator_user);
    assert(secret != NULL && strcmp(secret, "classified-value") == 0);
    free(secret);
    assert(qihse_kv_get_user(store, "secret:sstable", guest) == NULL);

    /* Bulk metadata APIs expose only the caller-visible logical dataset. */
    iter_count = 0;
    iter_saw_secret = false;
    assert(qihse_kv_foreach_user(store, guest, count_visible, NULL));
    assert(!iter_saw_secret);
    assert(iter_count == qihse_kv_count_user(store, guest));
    assert(qihse_kv_count_user(store, operator_user) > qihse_kv_count_user(store, guest));
    key_iter_count = 0u;
    key_iter_saw_secret = false;
    assert(qihse_kv_foreach_key_user(store, guest, count_key_visible, NULL));
    assert(!key_iter_saw_secret);
    assert(key_iter_count == qihse_kv_count_user(store, guest));
    key_iter_count = 0u;
    key_iter_saw_secret = false;
    assert(qihse_kv_foreach_key_user(store, operator_user, count_key_visible, NULL));
    assert(key_iter_saw_secret);
    assert(key_iter_count == qihse_kv_count_user(store, operator_user));
    assert(!qihse_kv_foreach_key_user(store, NULL, count_key_visible, NULL));

    /* Partial classified export is forbidden. */
    char guest_snapshot[512];
    char op_snapshot[512];
    snprintf(guest_snapshot, sizeof(guest_snapshot), "%s/guest.snapshot", data_dir);
    snprintf(op_snapshot, sizeof(op_snapshot), "%s/operator.snapshot", data_dir);
    assert(qihse_kv_save_user(store, guest_snapshot, guest) != 0);
    assert(access(guest_snapshot, F_OK) != 0);
    assert(qihse_kv_save_user(store, op_snapshot, operator_user) == 0);

    /* A guest clear cannot erase data it cannot see. */
    size_t removed = qihse_kv_clear_user(store, guest);
    assert(removed >= 1u);
    secret = qihse_kv_get_user(store, "secret:sstable", operator_user);
    assert(secret != NULL && strcmp(secret, "classified-value") == 0);
    free(secret);

    /* SSTable-only deletion must stay deleted instead of exposing an older copy. */
    assert(qihse_kv_del_user(store, "secret:sstable", operator_user));
    assert(qihse_kv_get_user(store, "secret:sstable", operator_user) == NULL);
    assert(qihse_kv_foreach_user(store, operator_user, count_visible, NULL));
    assert(qihse_kv_get_user(store, "secret:sstable", operator_user) == NULL);

    /* Malformed restore is transactional: live state survives failed parsing. */
    assert(qihse_kv_set_user(store, "live:before-bad-load", "preserve-me", 0, 0, guest));
    char malformed[512];
    snprintf(malformed, sizeof(malformed), "%s/malformed.snapshot", data_dir);
    static const unsigned char junk[] = {0xff, 0x00, 0x7f, 'x', '\n'};
    write_file(malformed, junk, sizeof(junk));
    assert(qihse_kv_load_user(store, malformed, operator_user) != 0);
    char* preserved = qihse_kv_get_user(store, "live:before-bad-load", guest);
    assert(preserved != NULL && strcmp(preserved, "preserve-me") == 0);
    free(preserved);

    /* Cluster reclaim bounded + STABLE-slot + node-local bookkeeping checks. */
    {
        qihse_cluster_topology_t* topo = qihse_cluster_topology_create();
        assert(topo != NULL);
        qihse_cluster_node_t n0 = {0}, n1 = {0};
        qihse_cluster_node_id_from_seed("node0", 5u, n0.id);
        snprintf(n0.host, sizeof(n0.host), "127.0.0.1");
        n0.port = 7100; n0.bus_port = 17100; n0.role = QIHSE_CLUSTER_NODE_PRIMARY; n0.healthy = true;
        qihse_cluster_node_id_from_seed("node1", 5u, n1.id);
        snprintf(n1.host, sizeof(n1.host), "127.0.0.1");
        n1.port = 7101; n1.bus_port = 17101; n1.role = QIHSE_CLUSTER_NODE_PRIMARY; n1.healthy = true;
        uint16_t idx0 = 0, idx1 = 0;
        assert(qihse_cluster_topology_upsert_node(topo, &n0, &idx0));
        assert(qihse_cluster_topology_upsert_node(topo, &n1, &idx1));
        assert(qihse_cluster_topology_set_local_node(topo, idx0));
        assert(qihse_cluster_topology_assign_range(topo, 0u, 16383u, idx1));

        assert(qihse_kv_set_user(store, "aimem:local-bookkeeping", "keep", 0, 0, operator_user));
        assert(qihse_kv_set_user(store, "reclaim:foreign:1", "drop1", 0, 0, operator_user));
        assert(qihse_kv_set_user(store, "reclaim:foreign:2", "drop2", 0, 0, operator_user));

        /* MIGRATING slots must not be reclaimed while in flight. */
        uint16_t slot1 = qihse_cluster_key_slot("reclaim:foreign:1", strlen("reclaim:foreign:1"));
        assert(qihse_cluster_topology_set_migrating(topo, slot1, idx1, idx0));
        bool has_more = false;
        size_t del = qihse_cluster_reclaim_foreign_slots_bounded(
            store, topo, idx0, operator_user, 1u, &has_more);
        assert(del == 1u);
        char* keep_mig = qihse_kv_get_user(store, "reclaim:foreign:1", operator_user);
        assert(keep_mig != NULL);
        free(keep_mig);
        char* keep_local = qihse_kv_get_user(store, "aimem:local-bookkeeping", operator_user);
        assert(keep_local != NULL);
        free(keep_local);

        /* Once STABLE on foreign owner, reclaim deletes it. */
        assert(qihse_cluster_topology_set_stable(topo, slot1, idx1));
        del = qihse_cluster_reclaim_foreign_slots(store, topo, idx0, operator_user);
        assert(del >= 1u);
        assert(qihse_kv_get_user(store, "reclaim:foreign:1", operator_user) == NULL);
        keep_local = qihse_kv_get_user(store, "aimem:local-bookkeeping", operator_user);
        assert(keep_local != NULL);
        free(keep_local);
        qihse_cluster_topology_destroy(topo);
    }

    qihse_kv_store_destroy(store);

    qihse_audit_shutdown();
    unlink(guest_snapshot);
    unlink(op_snapshot);
    unlink(malformed);
    char command[768];
    snprintf(command, sizeof(command), "rm -rf -- '%s'", data_dir);
    assert(system(command) == 0);

    puts("[ALL PASS] KV security regression tests");
    return 0;
}
