/*
 * gold_fabric_durable_caps.c — the check that would have caught the gap that
 * made three shipped fabric features do nothing.
 *
 * For three commits, FABRIC.CAPS, the brain's placement scoring and the fabric
 * job model all read durable capability records through a topology node's
 * federation UUID — and nothing populated that UUID. Every one of those paths
 * was correct code resolving to nothing, and nothing reported it, because
 * "found no record" and "the record says no" are the same answer to a caller.
 *
 * This workload asserts the whole chain end to end:
 *
 *   1. A node upserted into a topology gets a federation UUID WITHOUT anyone
 *      setting one. That is the specific regression.
 *   2. Its durable capability record is retrievable through that derived UUID.
 *   3. Both survive a RESTART — the record is read from disk by a fresh store,
 *      which is the property the whole durable path exists for.
 *   4. An unenrolled node's derived UUID resolves to nothing USABLE. The UUID
 *      is an index, not a credential: a node id can arrive from an
 *      unauthenticated MEET, so deriving the UUID must not confer trust.
 *
 * Emits the `GOLD: OK` evidence line the pack requires, and exits non-zero on
 * failure so a broken chain is reported FAIL rather than as a defect.
 */
#include "qihse_auth.h"
#include "qihse_cluster_slot.h"
#include "qihse_federation.h"
#include "qihse_kv_store.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    char data_root[] = "build/gold_fabric_caps_XXXXXX";
    assert(mkdtemp(data_root));
    setenv("QIHSE_DATA_DIR", data_root, 1);

    assert(qihse_auth_init());
    assert(qihse_auth_bootstrap_operator("GoldFabricPass1!"));
    qihse_user_t* op = qihse_auth_get_user(0);
    assert(op);

    /* A node id must be exactly 40 lowercase hex characters. */
    char node_id[QIHSE_CLUSTER_NODE_ID_LEN + 1u];
    qihse_cluster_node_id_from_seed("gold-fabric-node", strlen("gold-fabric-node"), node_id);

    qihse_uuid_t derived;
    uint8_t node_uuid[16];

    /* ── 1. the topology populates the UUID itself ────────────────────── */
    {
        qihse_cluster_topology_t* topo = qihse_cluster_topology_create();
        assert(topo);
        qihse_cluster_node_t node;
        memset(&node, 0, sizeof node);
        snprintf(node.id, sizeof node.id, "%s", node_id);
        snprintf(node.host, sizeof node.host, "127.0.0.1");
        node.port = 7901;
        node.role = QIHSE_CLUSTER_NODE_PRIMARY;
        node.healthy = true;
        uint16_t idx = 0;
        assert(qihse_cluster_topology_upsert_node(topo, &node, &idx));

        qihse_cluster_node_t back[8];
        size_t n = qihse_cluster_topology_nodes(topo, back, 8u);
        assert(n == 1u);
        /* THE REGRESSION: nobody set this. If it is false, the durable path
         * resolves to nothing for every consumer. */
        assert(back[0].has_uuid);
        assert(qihse_cluster_node_federation_uuid(node_id, node_uuid));
        assert(memcmp(back[0].node_uuid, node_uuid, 16u) == 0);
        memcpy(derived.bytes, node_uuid, sizeof derived.bytes);
        qihse_cluster_topology_destroy(topo);
    }

    /* ── 2. the durable record resolves through the derived UUID ──────── */
    {
        qihse_kv_store_t* store = qihse_kv_store_create();
        assert(store);
        qihse_federation_capability_values_t vals;
        memset(&vals, 0, sizeof vals);
        vals.isa_tier = 4;
        vals.npu = 1;
        vals.gpu = 1;
        vals.free_ram_mb = 32768;
        vals.load_pct = 7;
        assert(qihse_federation_node_capability_record_local(store, op, &derived, &vals));

        qihse_federation_node_capability_t rec;
        memset(&rec, 0, sizeof rec);
        assert(qihse_federation_node_capability_lookup(store, op, &derived, &rec));
        assert(rec.values.isa_tier == 4u && rec.values.npu == 1u);
        assert(rec.values.free_ram_mb == 32768u && rec.values.load_pct == 7u);
        qihse_kv_store_destroy(store);
    }

    /* ── 3. it survives a restart, which is what durable MEANS ────────── */
    {
        qihse_kv_store_t* reopened = qihse_kv_store_create();
        assert(reopened);
        qihse_federation_node_capability_t rec;
        memset(&rec, 0, sizeof rec);
        if (!qihse_federation_node_capability_lookup(reopened, op, &derived, &rec)) {
            fprintf(stderr, "gold_fabric_durable_caps: capability did not survive restart\n");
            return 1;
        }
        assert(rec.values.isa_tier == 4u);
        assert(rec.values.free_ram_mb == 32768u);

        /* ── 4. an unenrolled node's UUID is an index, not a credential ── */
        /* A second node id, derived the same way, with no identity record and
         * therefore no enrollment. Deriving its UUID must not make its claims
         * usable — a node id can arrive from an unauthenticated MEET. */
        char other_id[QIHSE_CLUSTER_NODE_ID_LEN + 1u];
        qihse_cluster_node_id_from_seed("gold-unenrolled", strlen("gold-unenrolled"), other_id);
        uint8_t other_uuid[16];
        assert(qihse_cluster_node_federation_uuid(other_id, other_uuid));
        assert(memcmp(other_uuid, node_uuid, 16u) != 0);
        qihse_uuid_t other;
        memcpy(other.bytes, other_uuid, sizeof other.bytes);
        qihse_federation_node_capability_t absent;
        memset(&absent, 0, sizeof absent);
        /* No record at all: the derived UUID resolved to nothing. */
        assert(!qihse_federation_node_capability_lookup(reopened, op, &other, &absent));
        /* And even with a record, admissibility requires enrollment. */
        qihse_federation_capability_values_t ov;
        memset(&ov, 0, sizeof ov);
        ov.isa_tier = 2;
        assert(qihse_federation_node_capability_record_local(reopened, op, &other, &ov));
        qihse_federation_node_capability_t unadm;
        memset(&unadm, 0, sizeof unadm);
        assert(!qihse_federation_node_capability_lookup_admissible(reopened, op, &other, &unadm));
        /* The raw lookup still returns it, for audit — the difference between
         * "somebody claimed this" and "this is usable" is the whole point. */
        qihse_federation_node_capability_t raw;
        memset(&raw, 0, sizeof raw);
        assert(qihse_federation_node_capability_lookup(reopened, op, &other, &raw));
        assert(raw.values.isa_tier == 2u);

        qihse_kv_store_destroy(reopened);
    }

    printf("GOLD: OK gold_fabric_durable_caps durable-caps-reachable: a topology node "
           "derives its federation UUID with no caller setting it, its durable "
           "capability record resolves through that UUID and survives a restart, and "
           "an unenrolled node's derived UUID is an index that resolves to nothing "
           "usable — admissibility still requires enrollment\n");
    return 0;
}
