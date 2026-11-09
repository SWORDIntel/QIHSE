/*
 * test_cluster_failover.c — Unit tests for the QIHSE cluster failover coordinator.
 */
#include <unistd.h>
#include "qihse_cluster_failover.h"
#include "qihse_cluster_bus.h"
#include "qihse_cluster_slot.h"
#include "qihse_platform.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

static void make_node(qihse_cluster_node_t* node, const char* id_seed, const char* host, uint16_t port, uint16_t bus_port,
                      qihse_cluster_node_role_t role, uint16_t primary_index) {
    memset(node, 0, sizeof(*node));
    qihse_cluster_node_id_from_seed(id_seed, strlen(id_seed), node->id);
    strncpy(node->host, host, QIHSE_CLUSTER_HOST_LEN);
    node->port = port;
    node->bus_port = bus_port;
    node->role = role;
    node->primary_index = primary_index;
    node->healthy = true;
}

/* Test 1: an unproven replica cannot inherit a primary's slots. */
static void test_primary_failover(void) {
    qihse_cluster_topology_t* topo = qihse_cluster_topology_create();
    assert(topo);

    qihse_cluster_node_t primary, replica;
    make_node(&primary, "primary1", "10.0.0.1", 7000, 17000, QIHSE_CLUSTER_NODE_PRIMARY, QIHSE_CLUSTER_NODE_NONE);
    make_node(&replica, "replica1", "10.0.0.2", 7001, 17001, QIHSE_CLUSTER_NODE_REPLICA, 0);
    uint16_t idx_p, idx_r;
    assert(qihse_cluster_topology_upsert_node(topo, &primary, &idx_p));
    assert(qihse_cluster_topology_upsert_node(topo, &replica, &idx_r));

    /* Assign slots 0-99 to the primary */
    assert(qihse_cluster_topology_assign_range(topo, 0, 99, idx_p));

    /* Create failover coordinator (local node = replica, so it can be promoted) */
    qihse_cluster_failover_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.topology = topo;
    cfg.bus = NULL;
    cfg.local_node_index = idx_r;
    cfg.single_coordinator = false;
    qihse_cluster_failover_t* fo = qihse_cluster_failover_create(&cfg);
    assert(fo);

    /* Mark the primary as failed */
    qihse_cluster_topology_set_node_health(topo, idx_p, false);

    /* Trigger failover; health alone is not durable data proof. */
    uint16_t promoted = qihse_cluster_failover_handle(fo, idx_p);
    assert(promoted == QIHSE_CLUSTER_NODE_NONE);
    assert(qihse_cluster_failover_events(fo) == 0);

    /* The replica's role and the old owner's ranges stay unchanged. */
    qihse_cluster_node_t check;
    assert(qihse_cluster_topology_get_node(topo, idx_r, &check));
    assert(check.role == QIHSE_CLUSTER_NODE_REPLICA);
    assert(check.primary_index == idx_p);

    /* Routing must not point to a successor without the preseeded data. */
    uint16_t owner;
    qihse_cluster_slot_state_t state;
    assert(qihse_cluster_topology_get_slot(topo, 0, &owner, &state, NULL));
    assert(owner == idx_p);
    assert(qihse_cluster_topology_get_slot(topo, 50, &owner, &state, NULL));
    assert(owner == idx_p);
    assert(qihse_cluster_topology_get_slot(topo, 99, &owner, &state, NULL));
    assert(owner == idx_p);

    qihse_cluster_failover_destroy(fo);
    qihse_cluster_topology_destroy(topo);
    printf("PASS unproven replica failover refused\n");
}

/* Test 2: No replica available — failover should not occur. */
static void test_no_replica(void) {
    qihse_cluster_topology_t* topo = qihse_cluster_topology_create();
    assert(topo);

    qihse_cluster_node_t primary;
    make_node(&primary, "primary1", "10.0.0.1", 7000, 17000, QIHSE_CLUSTER_NODE_PRIMARY, QIHSE_CLUSTER_NODE_NONE);
    uint16_t idx_p;
    assert(qihse_cluster_topology_upsert_node(topo, &primary, &idx_p));
    assert(qihse_cluster_topology_assign_range(topo, 0, 99, idx_p));

    qihse_cluster_failover_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.topology = topo;
    cfg.local_node_index = idx_p;
    cfg.single_coordinator = false;
    qihse_cluster_failover_t* fo = qihse_cluster_failover_create(&cfg);
    assert(fo);

    qihse_cluster_topology_set_node_health(topo, idx_p, false);
    uint16_t promoted = qihse_cluster_failover_handle(fo, idx_p);
    assert(promoted == QIHSE_CLUSTER_NODE_NONE);
    assert(qihse_cluster_failover_events(fo) == 0);

    qihse_cluster_failover_destroy(fo);
    qihse_cluster_topology_destroy(topo);
    printf("PASS no replica\n");
}

/* Test 3: Failed node is a replica (not a primary) — no failover needed. */
static void test_replica_failure(void) {
    qihse_cluster_topology_t* topo = qihse_cluster_topology_create();
    assert(topo);

    qihse_cluster_node_t primary, replica;
    make_node(&primary, "primary1", "10.0.0.1", 7000, 17000, QIHSE_CLUSTER_NODE_PRIMARY, QIHSE_CLUSTER_NODE_NONE);
    make_node(&replica, "replica1", "10.0.0.2", 7001, 17001, QIHSE_CLUSTER_NODE_REPLICA, 0);
    uint16_t idx_p, idx_r;
    assert(qihse_cluster_topology_upsert_node(topo, &primary, &idx_p));
    assert(qihse_cluster_topology_upsert_node(topo, &replica, &idx_r));
    assert(qihse_cluster_topology_assign_range(topo, 0, 99, idx_p));

    qihse_cluster_failover_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.topology = topo;
    cfg.local_node_index = idx_p;
    cfg.single_coordinator = false;
    qihse_cluster_failover_t* fo = qihse_cluster_failover_create(&cfg);
    assert(fo);

    /* Mark the replica as failed */
    qihse_cluster_topology_set_node_health(topo, idx_r, false);
    uint16_t promoted = qihse_cluster_failover_handle(fo, idx_r);
    assert(promoted == QIHSE_CLUSTER_NODE_NONE);
    assert(qihse_cluster_failover_events(fo) == 0);

    /* Primary's slots should be unchanged */
    uint16_t owner;
    qihse_cluster_slot_state_t state;
    assert(qihse_cluster_topology_get_slot(topo, 50, &owner, &state, NULL));
    assert(owner == idx_p);

    qihse_cluster_failover_destroy(fo);
    qihse_cluster_topology_destroy(topo);
    printf("PASS replica failure (no failover)\n");
}

/* Test 4: Best replica selection — multiple replicas, lowest index wins. */
static void test_best_replica_selection(void) {
    qihse_cluster_topology_t* topo = qihse_cluster_topology_create();
    assert(topo);

    qihse_cluster_node_t primary, r1, r2, r3;
    make_node(&primary, "primary1", "10.0.0.1", 7000, 17000, QIHSE_CLUSTER_NODE_PRIMARY, QIHSE_CLUSTER_NODE_NONE);
    make_node(&r1, "replica1", "10.0.0.2", 7001, 17001, QIHSE_CLUSTER_NODE_REPLICA, 0);
    make_node(&r2, "replica2", "10.0.0.3", 7002, 17002, QIHSE_CLUSTER_NODE_REPLICA, 0);
    make_node(&r3, "replica3", "10.0.0.4", 7003, 17003, QIHSE_CLUSTER_NODE_REPLICA, 0);
    uint16_t idx_p, idx_r1, idx_r2, idx_r3;
    assert(qihse_cluster_topology_upsert_node(topo, &primary, &idx_p));
    assert(qihse_cluster_topology_upsert_node(topo, &r1, &idx_r1));
    assert(qihse_cluster_topology_upsert_node(topo, &r2, &idx_r2));
    assert(qihse_cluster_topology_upsert_node(topo, &r3, &idx_r3));

    /* Mark r2 as unhealthy — should not be selected */
    qihse_cluster_topology_set_node_health(topo, idx_r2, false);

    uint16_t best = qihse_cluster_failover_best_replica(topo, idx_p);
    /* r1 should be the best (lowest index, healthy) */
    assert(best == idx_r1);

    qihse_cluster_topology_destroy(topo);
    printf("PASS best replica selection\n");
}

/* Test 5: Failover via bus on_fail callback. */
static void test_bus_failover_callback(void) {
    qihse_cluster_topology_t* topo = qihse_cluster_topology_create();
    assert(topo);

    qihse_cluster_node_t primary, replica;
    make_node(&primary, "primary1", "127.0.0.1", 7000, 17000, QIHSE_CLUSTER_NODE_PRIMARY, QIHSE_CLUSTER_NODE_NONE);
    make_node(&replica, "replica1", "127.0.0.1", 7001, 17001, QIHSE_CLUSTER_NODE_REPLICA, 0);
    uint16_t idx_p, idx_r;
    assert(qihse_cluster_topology_upsert_node(topo, &primary, &idx_p));
    assert(qihse_cluster_topology_upsert_node(topo, &replica, &idx_r));
    assert(qihse_cluster_topology_assign_range(topo, 0, 49, idx_p));

    /* Create failover coordinator first */
    qihse_cluster_failover_config_t fo_cfg;
    memset(&fo_cfg, 0, sizeof(fo_cfg));
    fo_cfg.topology = topo;
    fo_cfg.bus = NULL;
    fo_cfg.local_node_index = idx_r;
    fo_cfg.single_coordinator = false;
    qihse_cluster_failover_t* fo = qihse_cluster_failover_create(&fo_cfg);
    assert(fo);

    /* Create bus with failover callback */
    qihse_cluster_bus_config_t bus_cfg;
    memset(&bus_cfg, 0, sizeof(bus_cfg));
    bus_cfg.topology = topo;
    bus_cfg.local_node_index = idx_r;
    bus_cfg.bus_port = 0;
    bus_cfg.on_fail = qihse_cluster_failover_on_fail_cb;
    bus_cfg.on_fail_user_data = fo;
    qihse_cluster_bus_t* bus = qihse_cluster_bus_create(&bus_cfg);
    assert(bus);

    /* Inject a FAIL message for the primary */
    uint8_t datagram[64];
    uint32_t magic = QIHSE_CLUSTER_BUS_MAGIC;
    uint32_t type = QIHSE_BUS_MSG_FAIL;
    uint32_t sender = (uint32_t)idx_r;
    uint32_t payload_len = QIHSE_CLUSTER_NODE_ID_LEN + 1;
    memcpy(datagram, &magic, 4);
    memcpy(datagram + 4, &type, 4);
    memcpy(datagram + 8, &sender, 4);
    memcpy(datagram + 12, &payload_len, 4);
    memcpy(datagram + 16, primary.id, QIHSE_CLUSTER_NODE_ID_LEN + 1);

    assert(qihse_cluster_bus_inject(bus, datagram, 16 + payload_len, "127.0.0.1", 17001));

    /* Bus failure notifications cannot bypass the durable-proof gate. */
    assert(qihse_cluster_failover_events(fo) == 0);
    qihse_cluster_node_t check;
    assert(qihse_cluster_topology_get_node(topo, idx_r, &check));
    assert(check.role == QIHSE_CLUSTER_NODE_REPLICA);

    uint16_t owner;
    qihse_cluster_slot_state_t state;
    assert(qihse_cluster_topology_get_slot(topo, 25, &owner, &state, NULL));
    assert(owner == idx_p);

    qihse_cluster_bus_destroy(bus);
    qihse_cluster_failover_destroy(fo);
    qihse_cluster_topology_destroy(topo);
    printf("PASS bus callback refuses unproven failover\n");
}


/* ── failback ────────────────────────────────────────────────────────────── */

typedef struct {
    int calls;
    int fail_remaining;      /* fail this many calls before succeeding */
    uint16_t last_first, last_last, last_target;
    qihse_cluster_topology_t* topo;   /* flip ownership on success, like handoff */
} fb_probe_t;

static int fb_cb(void* ud, uint16_t first, uint16_t last, uint16_t target, char* err, size_t cap) {
    fb_probe_t* p = (fb_probe_t*)ud;
    p->calls++;
    if (p->fail_remaining > 0) {
        p->fail_remaining--;
        snprintf(err, cap, "simulated transfer failure");
        return -1;                         /* ownership must NOT change */
    }
    p->last_first = first; p->last_last = last; p->last_target = target;
    assert(qihse_cluster_topology_assign_range(p->topo, first, last, target));
    return 0;
}

static void sleep_ms_fb(unsigned ms) { usleep(ms * 1000u); }

static bool wait_for(int (*pred)(void*), void* arg, unsigned timeout_ms) {
    for (unsigned t = 0; t < timeout_ms; t += 20) {
        if (pred(arg)) return true;
        sleep_ms_fb(20);
    }
    return pred(arg) != 0;
}

typedef struct { qihse_cluster_failover_t* fo; fb_probe_t* probe; qihse_cluster_topology_t* topo;
                 uint16_t slot; uint16_t want_owner; uint64_t want_failbacks; } fb_wait_t;
static int fb_owner_is(void* a) {
    fb_wait_t* w = (fb_wait_t*)a;
    uint16_t o; qihse_cluster_slot_state_t st;
    return qihse_cluster_topology_get_slot(w->topo, w->slot, &o, &st, NULL) && o == w->want_owner;
}
static int fb_count_reached(void* a) {
    fb_wait_t* w = (fb_wait_t*)a;
    return qihse_cluster_failover_failbacks(w->fo) >= w->want_failbacks;
}

/* Different insertion orders cannot bypass the unproven-data refusal. */
static void test_deterministic_successor(void) {
    for (int perspective = 0; perspective < 3; perspective++) {
        qihse_cluster_topology_t* topo = qihse_cluster_topology_create();
        qihse_cluster_node_t n[3];
        make_node(&n[0], "alpha", "10.0.1.1", 7000, 17000, QIHSE_CLUSTER_NODE_PRIMARY, QIHSE_CLUSTER_NODE_NONE);
        make_node(&n[1], "bravo", "10.0.1.2", 7001, 17001, QIHSE_CLUSTER_NODE_PRIMARY, QIHSE_CLUSTER_NODE_NONE);
        make_node(&n[2], "charlie", "10.0.1.3", 7002, 17002, QIHSE_CLUSTER_NODE_PRIMARY, QIHSE_CLUSTER_NODE_NONE);
        /* Different insertion order per node: indexes differ between "nodes". */
        uint16_t idx[3];
        for (int k = 0; k < 3; k++) assert(qihse_cluster_topology_upsert_node(topo, &n[(k + perspective) % 3], &idx[(k + perspective) % 3]));
        for (int k = 0; k < 3; k++) assert(qihse_cluster_topology_assign_range(topo, (uint16_t)(k * 100), (uint16_t)(k * 100 + 99), idx[k]));

        qihse_cluster_failover_config_t cfg; memset(&cfg, 0, sizeof(cfg));
        cfg.topology = topo; cfg.local_node_index = idx[perspective]; cfg.single_coordinator = false;
        qihse_cluster_failover_t* fo = qihse_cluster_failover_create(&cfg);
        assert(fo);
        /* Fail node 0 ("alpha"); no healthy primary proves it has its data. */
        qihse_cluster_topology_set_node_health(topo, idx[0], false);
        assert(qihse_cluster_failover_handle(fo, idx[0]) == QIHSE_CLUSTER_NODE_NONE);
        assert(qihse_cluster_failover_events(fo) == 0);
        uint16_t owner;
        assert(qihse_cluster_topology_get_slot(topo, 50, &owner, NULL, NULL));
        assert(owner == idx[0]);
        qihse_cluster_failover_destroy(fo);
        qihse_cluster_topology_destroy(topo);
    }
    printf("PASS unproven fallback refused from every insertion order\n");
}

static void failback_fixture(qihse_cluster_topology_t** topo_out, qihse_cluster_failover_t** fo_out,
                             fb_probe_t* probe, uint16_t* idx_failed, uint16_t* idx_succ,
                             uint32_t stable_ms) {
    qihse_cluster_topology_t* topo = qihse_cluster_topology_create();
    qihse_cluster_node_t a, b;
    make_node(&a, "owner-node", "10.0.2.1", 7000, 17000, QIHSE_CLUSTER_NODE_PRIMARY, QIHSE_CLUSTER_NODE_NONE);
    make_node(&b, "successor-node", "10.0.2.2", 7001, 17001, QIHSE_CLUSTER_NODE_PRIMARY, QIHSE_CLUSTER_NODE_NONE);
    uint16_t ia, ib;
    assert(qihse_cluster_topology_upsert_node(topo, &a, &ia));
    assert(qihse_cluster_topology_upsert_node(topo, &b, &ib));
    assert(qihse_cluster_topology_assign_range(topo, 0, 99, ia));
    assert(qihse_cluster_topology_assign_range(topo, 100, 199, ib));
    probe->topo = topo;
    qihse_cluster_failover_config_t cfg; memset(&cfg, 0, sizeof(cfg));
    cfg.topology = topo; cfg.local_node_index = ib; cfg.single_coordinator = false;
    cfg.failback_fn = fb_cb; cfg.failback_user_data = probe;
    cfg.failback_stable_ms = stable_ms; cfg.failback_poll_ms = 40;
    *fo_out = qihse_cluster_failover_create(&cfg);
    assert(*fo_out);
    *topo_out = topo; *idx_failed = ia; *idx_succ = ib;
}
/* Simulate a previously completed external handoff for failback state-machine
 * testing. This fixture does not prove durability. */
static void seed_completed_handoff(qihse_cluster_topology_t* topo,
                                   qihse_cluster_failover_t* fo,
                                   uint16_t previous, uint16_t successor) {
    assert(qihse_cluster_topology_assign_range(topo, 0, 99, successor));
    qihse_cluster_failover_on_takeover_cb(topo, previous, 0, 99, fo);
}

static void test_failback_returns_range(void) {
    fb_probe_t probe; memset(&probe, 0, sizeof(probe));
    qihse_cluster_topology_t* topo; qihse_cluster_failover_t* fo; uint16_t ia, ib;
    failback_fixture(&topo, &fo, &probe, &ia, &ib, 200);

    qihse_cluster_topology_set_node_health(topo, ia, false);
    assert(qihse_cluster_failover_handle(fo, ia) == QIHSE_CLUSTER_NODE_NONE);
    seed_completed_handoff(topo, fo, ia, ib);
    assert(qihse_cluster_failover_pending_failbacks(fo) == 1u);
    fb_wait_t w = { fo, &probe, topo, 50, ib, 0 };
    assert(fb_owner_is(&w));

    /* Owner still down: nothing may be handed back. */
    sleep_ms_fb(500);
    assert(probe.calls == 0);
    assert(fb_owner_is(&w));

    /* Owner returns: after the stability window the range is handed back. */
    qihse_cluster_topology_set_node_health(topo, ia, true);
    fb_wait_t back = { fo, &probe, topo, 50, ia, 1 };
    assert(wait_for(fb_owner_is, &back, 3000));
    assert(wait_for(fb_count_reached, &back, 3000));
    assert(probe.last_first == 0 && probe.last_last == 99 && probe.last_target == ia);
    assert(qihse_cluster_failover_pending_failbacks(fo) == 0u);
    /* The successor's OWN range is untouched. */
    uint16_t o; qihse_cluster_slot_state_t st;
    assert(qihse_cluster_topology_get_slot(topo, 150, &o, &st, NULL) && o == ib);

    qihse_cluster_failover_destroy(fo);
    qihse_cluster_topology_destroy(topo);
    printf("PASS failback returns the range after the owner is stable\n");
}

static void test_failback_flap_damping(void) {
    fb_probe_t probe; memset(&probe, 0, sizeof(probe));
    qihse_cluster_topology_t* topo; qihse_cluster_failover_t* fo; uint16_t ia, ib;
    failback_fixture(&topo, &fo, &probe, &ia, &ib, 600);

    qihse_cluster_topology_set_node_health(topo, ia, false);
    assert(qihse_cluster_failover_handle(fo, ia) == QIHSE_CLUSTER_NODE_NONE);
    seed_completed_handoff(topo, fo, ia, ib);
    /* Flap faster than the stability window: no transfer may start. */
    for (int i = 0; i < 6; i++) {
        qihse_cluster_topology_set_node_health(topo, ia, true);
        sleep_ms_fb(250);
        qihse_cluster_topology_set_node_health(topo, ia, false);
        sleep_ms_fb(120);
    }
    assert(probe.calls == 0);
    assert(qihse_cluster_failover_pending_failbacks(fo) == 1u);

    qihse_cluster_failover_destroy(fo);
    qihse_cluster_topology_destroy(topo);
    printf("PASS failback ignores a flapping owner (needs continuous health)\n");
}

static void test_failback_retries_after_failure(void) {
    fb_probe_t probe; memset(&probe, 0, sizeof(probe));
    probe.fail_remaining = 2;
    qihse_cluster_topology_t* topo; qihse_cluster_failover_t* fo; uint16_t ia, ib;
    failback_fixture(&topo, &fo, &probe, &ia, &ib, 100);

    qihse_cluster_topology_set_node_health(topo, ia, false);
    assert(qihse_cluster_failover_handle(fo, ia) == QIHSE_CLUSTER_NODE_NONE);
    seed_completed_handoff(topo, fo, ia, ib);
    qihse_cluster_topology_set_node_health(topo, ia, true);

    fb_wait_t done = { fo, &probe, topo, 50, ia, 1 };
    assert(wait_for(fb_count_reached, &done, 8000));
    assert(probe.calls == 3);                       /* 2 failures + 1 success */
    assert(fb_owner_is(&done));
    /* While it was failing, the successor kept serving: ownership only ever
     * flipped inside a SUCCESSFUL callback (fb_cb), never on failure. */
    qihse_cluster_failover_destroy(fo);
    qihse_cluster_topology_destroy(topo);
    printf("PASS failback retries a failed transfer without losing ownership\n");
}

static void test_failback_skips_dedicated_replica(void) {
    fb_probe_t probe; memset(&probe, 0, sizeof(probe));
    qihse_cluster_topology_t* topo = qihse_cluster_topology_create();
    qihse_cluster_node_t p, r;
    make_node(&p, "primary-x", "10.0.3.1", 7000, 17000, QIHSE_CLUSTER_NODE_PRIMARY, QIHSE_CLUSTER_NODE_NONE);
    make_node(&r, "replica-x", "10.0.3.2", 7001, 17001, QIHSE_CLUSTER_NODE_REPLICA, 0);
    uint16_t ip, ir;
    assert(qihse_cluster_topology_upsert_node(topo, &p, &ip));
    assert(qihse_cluster_topology_upsert_node(topo, &r, &ir));
    assert(qihse_cluster_topology_assign_range(topo, 0, 99, ip));
    probe.topo = topo;
    qihse_cluster_failover_config_t cfg; memset(&cfg, 0, sizeof(cfg));
    cfg.topology = topo; cfg.local_node_index = ir; cfg.single_coordinator = false;
    cfg.failback_fn = fb_cb; cfg.failback_user_data = &probe;
    cfg.failback_stable_ms = 50; cfg.failback_poll_ms = 40;
    qihse_cluster_failover_t* fo = qihse_cluster_failover_create(&cfg);
    assert(fo);
    qihse_cluster_topology_set_node_health(topo, ip, false);
    assert(qihse_cluster_failover_handle(fo, ip) == QIHSE_CLUSTER_NODE_NONE);
    assert(qihse_cluster_failover_pending_failbacks(fo) == 0u);
    uint16_t owner;
    assert(qihse_cluster_topology_get_slot(topo, 50, &owner, NULL, NULL));
    assert(owner == ip);
    qihse_cluster_topology_set_node_health(topo, ip, true);
    sleep_ms_fb(400);
    assert(probe.calls == 0);
    qihse_cluster_failover_destroy(fo);
    qihse_cluster_topology_destroy(topo);
    printf("PASS unproven dedicated replica neither promotes nor incurs failback debt\n");
}

static void test_failback_respects_resplit_range(void) {
    fb_probe_t probe; memset(&probe, 0, sizeof(probe));
    qihse_cluster_topology_t* topo; qihse_cluster_failover_t* fo; uint16_t ia, ib;
    failback_fixture(&topo, &fo, &probe, &ia, &ib, 100);
    qihse_cluster_topology_set_node_health(topo, ia, false);
    assert(qihse_cluster_failover_handle(fo, ia) == QIHSE_CLUSTER_NODE_NONE);
    seed_completed_handoff(topo, fo, ia, ib);
    /* An operator re-homes 40-59 elsewhere while the owner is down. */
    assert(qihse_cluster_topology_assign_range(topo, 40, 59, ia));
    qihse_cluster_topology_set_node_health(topo, ia, true);
    fb_wait_t done = { fo, &probe, topo, 10, ia, 1 };
    assert(wait_for(fb_count_reached, &done, 4000));
    /* Only the slots still owned by the successor were handed back: two calls
     * (0-39, 60-99), none covering 40-59. */
    assert(probe.calls == 2);
    qihse_cluster_failover_destroy(fo);
    qihse_cluster_topology_destroy(topo);
    printf("PASS failback hands back only the slots the successor still owns\n");
}

/* The failover coordinator that notices a failure may be on a DIFFERENT node
 * from the one it picks as successor. The successor learns of the takeover only
 * as a slot update over the bus, and it is the one that owes the range back. */
static void test_failback_on_remote_takeover(void) {
    fb_probe_t probe; memset(&probe, 0, sizeof(probe));
    qihse_cluster_topology_t* topo = qihse_cluster_topology_create();
    qihse_cluster_node_t a, c;
    make_node(&a, "remote-owner", "127.0.0.1", 7000, 17000, QIHSE_CLUSTER_NODE_PRIMARY, QIHSE_CLUSTER_NODE_NONE);
    make_node(&c, "remote-successor", "127.0.0.1", 7001, 17001, QIHSE_CLUSTER_NODE_PRIMARY, QIHSE_CLUSTER_NODE_NONE);
    uint16_t ia, ic;
    assert(qihse_cluster_topology_upsert_node(topo, &a, &ia));
    assert(qihse_cluster_topology_upsert_node(topo, &c, &ic));
    assert(qihse_cluster_topology_assign_range(topo, 0, 99, ia));
    probe.topo = topo;

    qihse_cluster_failover_config_t fcfg; memset(&fcfg, 0, sizeof(fcfg));
    fcfg.topology = topo; fcfg.local_node_index = ic;
    fcfg.failback_fn = fb_cb; fcfg.failback_user_data = &probe;
    fcfg.failback_stable_ms = 150; fcfg.failback_poll_ms = 40;
    qihse_cluster_failover_t* fo = qihse_cluster_failover_create_paused(&fcfg);
    assert(fo);

    qihse_cluster_bus_config_t bcfg; memset(&bcfg, 0, sizeof(bcfg));
    bcfg.topology = topo; bcfg.local_node_index = ic; bcfg.bus_port = 0;
    qihse_cluster_bus_t* bus = qihse_cluster_bus_create(&bcfg);
    assert(bus);
    qihse_cluster_bus_set_takeover_callback(bus, qihse_cluster_failover_on_takeover_cb, fo);

    /* The owner is down, and another node announces an unproven takeover. */
    qihse_cluster_topology_set_node_health(topo, ia, false);
    qihse_cluster_node_t self;
    assert(qihse_cluster_topology_get_node(topo, ic, &self));
    qihse_cluster_bus_slot_update_t upd; memset(&upd, 0, sizeof(upd));
    upd.start = 0; upd.end = 99; upd.owner_index = ic;
    memcpy(upd.owner_id, self.id, QIHSE_CLUSTER_NODE_ID_LEN + 1u);
    upd.config_epoch = 50;
    uint8_t dg[QIHSE_CLUSTER_BUS_HEADER_SIZE + sizeof(upd)];
    uint32_t magic = QIHSE_CLUSTER_BUS_MAGIC, type = QIHSE_BUS_MSG_SLOT_UPDATE,
             sender = 99, plen = (uint32_t)sizeof(upd);
    memcpy(dg, &magic, 4); memcpy(dg + 4, &type, 4); memcpy(dg + 8, &sender, 4); memcpy(dg + 12, &plen, 4);
    memcpy(dg + QIHSE_CLUSTER_BUS_HEADER_SIZE, &upd, sizeof(upd));
    assert(qihse_cluster_bus_inject(bus, dg, sizeof(dg), "127.0.0.1", 17000));

    uint16_t o; qihse_cluster_slot_state_t st;
    assert(qihse_cluster_topology_get_slot(topo, 50, &o, &st, NULL) && o == ia);
    assert(qihse_cluster_failover_pending_failbacks(fo) == 0u);

    /* Refused gossip cannot create failback debt, including under the hold. */
    assert(qihse_cluster_failover_is_paused(fo));
    assert(qihse_cluster_failover_pause_startup(fo));
    assert(probe.calls == 0);
    qihse_cluster_topology_set_node_health(topo, ia, true);
    assert(qihse_cluster_failover_resume(fo));
    assert(!qihse_cluster_failover_pause_startup(fo));
    assert(qihse_cluster_topology_get_slot(topo, 50, &o, &st, NULL) && o == ia);
    assert(qihse_cluster_failover_pending_failbacks(fo) == 0u);
    assert(probe.calls == 0);

    qihse_cluster_bus_destroy(bus);
    qihse_cluster_failover_destroy(fo);
    qihse_cluster_topology_destroy(topo);
    printf("PASS remote unproven slot update leaves owner and failback debt unchanged\n");
}

/* Race two refused ownership paths against the real bus mutex. The watchdog
 * bounds a hang and all slot/role/debt invariants are checked afterward. */
typedef struct {
    qihse_cluster_failover_t* fo;
    qihse_cluster_bus_t* bus;
    qihse_cluster_topology_t* topo;
    uint16_t owner, promotion_owner;
    pthread_barrier_t gate;
    uint8_t datagram[QIHSE_CLUSTER_BUS_HEADER_SIZE + sizeof(qihse_cluster_bus_slot_update_t)];
    unsigned callbacks;
} takeover_race_t;

static void takeover_race_cb(qihse_cluster_topology_t* topo, uint16_t previous,
                              uint16_t first, uint16_t last, void* user) {
    (void)topo; (void)previous; (void)first; (void)last;
    takeover_race_t* race = user;
    race->callbacks++;
}

static void* takeover_race_inject(void* user) {
    takeover_race_t* race = user;
    pthread_barrier_wait(&race->gate);
    for (unsigned i = 0; i < 128; i++) {
        assert(qihse_cluster_bus_inject(race->bus, race->datagram,
                                        sizeof(race->datagram), "127.0.0.1", 17000));
    }
    return NULL;
}

static void test_takeover_promotion_lock_order(void) {
    takeover_race_t race; memset(&race, 0, sizeof(race));
    race.topo = qihse_cluster_topology_create();
    assert(race.topo);
    qihse_cluster_node_t owner, local, other;
    make_node(&owner, "lock-owner", "127.0.0.1", 7000, 17000,
              QIHSE_CLUSTER_NODE_PRIMARY, QIHSE_CLUSTER_NODE_NONE);
    make_node(&local, "lock-local", "127.0.0.1", 7001, 17001,
              QIHSE_CLUSTER_NODE_PRIMARY, QIHSE_CLUSTER_NODE_NONE);
    uint16_t self;
    assert(qihse_cluster_topology_upsert_node(race.topo, &owner, &race.owner));
    assert(qihse_cluster_topology_upsert_node(race.topo, &local, &self));
    make_node(&other, "lock-other-owner", "127.0.0.1", 7002, 17002,
              QIHSE_CLUSTER_NODE_PRIMARY, QIHSE_CLUSTER_NODE_NONE);
    assert(qihse_cluster_topology_upsert_node(race.topo, &other, &race.promotion_owner));
    assert(qihse_cluster_topology_assign_range(race.topo, 0, 99, race.owner));
    assert(qihse_cluster_topology_assign_range(race.topo, 100, 199, race.promotion_owner));
    qihse_cluster_topology_set_node_health(race.topo, race.owner, false);
    qihse_cluster_topology_set_node_health(race.topo, race.promotion_owner, false);
    qihse_cluster_bus_config_t bcfg; memset(&bcfg, 0, sizeof(bcfg));
    bcfg.topology = race.topo; bcfg.local_node_index = self;
    race.bus = qihse_cluster_bus_create(&bcfg);
    assert(race.bus);
    fb_probe_t probe; memset(&probe, 0, sizeof(probe));
    probe.topo = race.topo;
    qihse_cluster_failover_config_t cfg; memset(&cfg, 0, sizeof(cfg));
    cfg.topology = race.topo; cfg.bus = race.bus; cfg.local_node_index = self;
    cfg.failback_fn = fb_cb; cfg.failback_user_data = &probe;
    race.fo = qihse_cluster_failover_create(&cfg);
    assert(race.fo);
    assert(pthread_barrier_init(&race.gate, NULL, 2) == 0);
    qihse_cluster_bus_set_takeover_callback(race.bus, takeover_race_cb, &race);
    qihse_cluster_bus_slot_update_t upd; memset(&upd, 0, sizeof(upd));
    upd.start = 0; upd.end = 99; upd.owner_index = self;
    memcpy(upd.owner_id, local.id, QIHSE_CLUSTER_NODE_ID_LEN + 1u);
    upd.config_epoch = 0; /* Static announcements remain valid across rounds. */
    uint32_t header[] = { QIHSE_CLUSTER_BUS_MAGIC, QIHSE_BUS_MSG_SLOT_UPDATE,
                          99, (uint32_t)sizeof(upd) };
    memcpy(race.datagram, header, sizeof(header));
    memcpy(race.datagram + QIHSE_CLUSTER_BUS_HEADER_SIZE, &upd, sizeof(upd));
    pthread_t injector;
    alarm(20);
    assert(pthread_create(&injector, NULL, takeover_race_inject, &race) == 0);
    pthread_barrier_wait(&race.gate);
    for (unsigned i = 0; i < 128; i++) {
        assert(!qihse_cluster_failover_promote(race.fo, race.promotion_owner, self));
        uint16_t owner_index;
        assert(qihse_cluster_topology_get_slot(race.topo, 150, &owner_index, NULL, NULL));
        assert(owner_index == race.promotion_owner);
    }
    assert(pthread_join(injector, NULL) == 0);
    alarm(0);
    assert(race.callbacks == 0);
    uint16_t owner_index;
    assert(qihse_cluster_topology_get_slot(race.topo, 50, &owner_index, NULL, NULL));
    assert(owner_index == race.owner);
    assert(qihse_cluster_topology_get_slot(race.topo, 150, &owner_index, NULL, NULL));
    assert(owner_index == race.promotion_owner);
    assert(qihse_cluster_failover_pending_failbacks(race.fo) == 0u);
    assert(qihse_cluster_failover_events(race.fo) == 0u);
    assert(!qihse_cluster_failover_pause_startup(race.fo));
    assert(probe.calls == 0);
    pthread_barrier_destroy(&race.gate);
    qihse_cluster_failover_destroy(race.fo);
    qihse_cluster_bus_destroy(race.bus);
    qihse_cluster_topology_destroy(race.topo);
    printf("PASS concurrent refused slot update and promotion leave owners unchanged\n");
}

/* When a non-coordinator (or asymmetry-deferred cycle) sees on_fail first,
 * last_attempt_ms must NOT be stamped until promotion is actually attempted;
 * otherwise a subsequent cycle on the same coordinator (or after the current
 * coordinator also fails) would be locked out for 30s. */
static void test_non_coordinator_does_not_trip_cooldown(void) {
    qihse_cluster_topology_t* topo = qihse_cluster_topology_create();
    qihse_cluster_node_t n0, n1, n2;
    make_node(&n0, "coord-0", "127.0.0.1", 7000, 17000, QIHSE_CLUSTER_NODE_PRIMARY, QIHSE_CLUSTER_NODE_NONE);
    make_node(&n1, "coord-1", "127.0.0.1", 7001, 17001, QIHSE_CLUSTER_NODE_PRIMARY, QIHSE_CLUSTER_NODE_NONE);
    make_node(&n2, "victim-2", "127.0.0.1", 7002, 17002, QIHSE_CLUSTER_NODE_PRIMARY, QIHSE_CLUSTER_NODE_NONE);
    uint16_t i0, i1, i2;
    assert(qihse_cluster_topology_upsert_node(topo, &n0, &i0));
    assert(qihse_cluster_topology_upsert_node(topo, &n1, &i1));
    assert(qihse_cluster_topology_upsert_node(topo, &n2, &i2));
    /* The failed node owns no slots: this is a safe role-only promotion
     * fixture for the cooldown logic, not a data-bearing takeover. */

    qihse_cluster_failover_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.topology = topo;
    cfg.local_node_index = i1;
    cfg.single_coordinator = true;
    qihse_cluster_failover_t* fo = qihse_cluster_failover_create(&cfg);
    assert(fo);

    /* Victim fails while i0 is still healthy (so i0 is coordinator, not i1). */
    qihse_cluster_topology_set_node_health(topo, i2, false);
    assert(qihse_cluster_failover_handle(fo, i2) == QIHSE_CLUSTER_NODE_NONE);

    /* Now i0 also fails -> i1 becomes coordinator and may immediately make
     * the slot-free role change without being blocked by the 30s cooldown. */
    qihse_cluster_topology_set_node_health(topo, i0, false);
    assert(qihse_cluster_failover_handle(fo, i2) == i1);

    qihse_cluster_failover_destroy(fo);
    qihse_cluster_topology_destroy(topo);
    printf("PASS deferred/non-coordinator on_fail does not trip 30s cooldown\n");
}

static void test_maintenance_fences_failover_callbacks(void) {
    qihse_cluster_maintenance_t* gate = qihse_cluster_maintenance_create();
    assert(gate);
    assert(qihse_cluster_maintenance_register(gate, QIHSE_MAINT_WRITER_RESP, true));
    assert(qihse_cluster_maintenance_register(gate, QIHSE_MAINT_WRITER_BGSAVE, true));
    assert(qihse_cluster_maintenance_register(gate, QIHSE_MAINT_WRITER_BUS_SLOT, true));
    assert(qihse_cluster_maintenance_register(gate, QIHSE_MAINT_WRITER_RECLAIM, true));
    assert(qihse_cluster_maintenance_register(gate, QIHSE_MAINT_WRITER_BUS_GROUP, true));
    assert(qihse_cluster_maintenance_register(gate, QIHSE_MAINT_WRITER_BUS_FEDERATION, true));
    assert(qihse_cluster_maintenance_register(gate, QIHSE_MAINT_WRITER_REPLICA, true));
    assert(qihse_cluster_maintenance_register(gate, QIHSE_MAINT_WRITER_EXPIRY, true));
    assert(qihse_cluster_maintenance_register(gate, QIHSE_MAINT_WRITER_TASK_WORKER, true));
    assert(qihse_cluster_maintenance_register(gate, QIHSE_MAINT_WRITER_BRAIN, true));
    qihse_cluster_topology_t* topo = qihse_cluster_topology_create();
    assert(topo);
    qihse_cluster_node_t primary, replica;
    make_node(&primary, "maint-primary", "127.0.0.1", 7000, 17000,
              QIHSE_CLUSTER_NODE_PRIMARY, QIHSE_CLUSTER_NODE_NONE);
    uint16_t pi, ri;
    assert(qihse_cluster_topology_upsert_node(topo, &primary, &pi));
    make_node(&replica, "maint-replica", "127.0.0.1", 7001, 17001,
              QIHSE_CLUSTER_NODE_REPLICA, pi);
    assert(qihse_cluster_topology_upsert_node(topo, &replica, &ri));
    /* Slot-free role change lets this test isolate the maintenance fence
     * without claiming a data-bearing successor is ready. */
    qihse_cluster_failover_config_t cfg = {0};
    cfg.topology = topo;
    cfg.local_node_index = ri;
    cfg.maintenance_gate = gate;
    qihse_cluster_failover_t* fo = qihse_cluster_failover_create(&cfg);
    assert(fo);
    assert(qihse_cluster_failover_register_maintenance(fo));
    uint64_t generation;
    uint8_t token[32];
    assert(qihse_cluster_maintenance_begin(gate, 0, 5000, &generation, token));
    assert(qihse_cluster_failover_promote(fo, pi, ri) == false);
    qihse_cluster_node_t check;
    assert(qihse_cluster_topology_get_node(topo, ri, &check));
    assert(check.role == QIHSE_CLUSTER_NODE_REPLICA);
    assert(qihse_cluster_maintenance_release_trusted(gate, generation, token));
    assert(qihse_cluster_failover_promote(fo, pi, ri));
    assert(qihse_cluster_topology_get_node(topo, ri, &check));
    assert(check.role == QIHSE_CLUSTER_NODE_PRIMARY);
    qihse_cluster_failover_destroy(fo);
    qihse_cluster_topology_destroy(topo);
    qihse_cluster_maintenance_destroy(gate);
    printf("PASS maintenance fences manual promotion\n");
}

int main(void) {
{
    /* Per-test audit/chain isolation (parallel aggregates). */
    char qdd[] = "build/test_cluster_failover_XXXXXX";
    if (mkdtemp(qdd)) setenv("QIHSE_DATA_DIR", qdd, 1);
}
    test_primary_failover();
    test_no_replica();
    test_replica_failure();
    test_best_replica_selection();
    test_bus_failover_callback();
    test_deterministic_successor();
    test_failback_returns_range();
    test_failback_flap_damping();
    test_failback_retries_after_failure();
    test_failback_skips_dedicated_replica();
    test_failback_respects_resplit_range();
    test_failback_on_remote_takeover();
    test_takeover_promotion_lock_order();
    test_non_coordinator_does_not_trip_cooldown();
    test_maintenance_fences_failover_callbacks();
    printf("cluster failover tests passed\n");
    return 0;
}
