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

/* Test 1: Primary fails, replica is promoted and slots are reassigned. */
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

    /* Trigger failover */
    uint16_t promoted = qihse_cluster_failover_handle(fo, idx_p);
    assert(promoted == idx_r);
    assert(qihse_cluster_failover_events(fo) == 1);

    /* Verify the replica is now a primary */
    qihse_cluster_node_t check;
    assert(qihse_cluster_topology_get_node(topo, idx_r, &check));
    assert(check.role == QIHSE_CLUSTER_NODE_PRIMARY);
    assert(check.primary_index == QIHSE_CLUSTER_NODE_NONE);

    /* Verify slots 0-99 are now owned by the promoted replica */
    uint16_t owner;
    qihse_cluster_slot_state_t state;
    assert(qihse_cluster_topology_get_slot(topo, 0, &owner, &state, NULL));
    assert(owner == idx_r);
    assert(qihse_cluster_topology_get_slot(topo, 50, &owner, &state, NULL));
    assert(owner == idx_r);
    assert(qihse_cluster_topology_get_slot(topo, 99, &owner, &state, NULL));
    assert(owner == idx_r);

    qihse_cluster_failover_destroy(fo);
    qihse_cluster_topology_destroy(topo);
    printf("PASS primary failover\n");
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

    /* Verify failover occurred */
    assert(qihse_cluster_failover_events(fo) == 1);
    qihse_cluster_node_t check;
    assert(qihse_cluster_topology_get_node(topo, idx_r, &check));
    assert(check.role == QIHSE_CLUSTER_NODE_PRIMARY);

    uint16_t owner;
    qihse_cluster_slot_state_t state;
    assert(qihse_cluster_topology_get_slot(topo, 25, &owner, &state, NULL));
    assert(owner == idx_r);

    qihse_cluster_bus_destroy(bus);
    qihse_cluster_failover_destroy(fo);
    qihse_cluster_topology_destroy(topo);
    printf("PASS bus failover callback\n");
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

/* Three primaries. Node IDs decide the successor, not local indexes or uptime. */
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
        /* Fail node 0 ("alpha"): the successor must be the smaller node ID of the
         * two survivors, whichever node is asking. */
        qihse_cluster_node_t b, c;
        assert(qihse_cluster_topology_get_node(topo, idx[1], &b));
        assert(qihse_cluster_topology_get_node(topo, idx[2], &c));
        uint16_t expect = strcmp(b.id, c.id) < 0 ? idx[1] : idx[2];
        qihse_cluster_topology_set_node_health(topo, idx[0], false);
        assert(qihse_cluster_failover_handle(fo, idx[0]) == expect);
        qihse_cluster_failover_destroy(fo);
        qihse_cluster_topology_destroy(topo);
    }
    printf("PASS deterministic fallback successor (same choice from every node)\n");
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

static void test_failback_returns_range(void) {
    fb_probe_t probe; memset(&probe, 0, sizeof(probe));
    qihse_cluster_topology_t* topo; qihse_cluster_failover_t* fo; uint16_t ia, ib;
    failback_fixture(&topo, &fo, &probe, &ia, &ib, 200);

    qihse_cluster_topology_set_node_health(topo, ia, false);
    assert(qihse_cluster_failover_handle(fo, ia) == ib);          /* successor takes 0-99 */
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
    assert(qihse_cluster_failover_handle(fo, ia) == ib);
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
    assert(qihse_cluster_failover_handle(fo, ia) == ib);
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
    assert(qihse_cluster_failover_handle(fo, ip) == ir);
    assert(qihse_cluster_failover_pending_failbacks(fo) == 0u);  /* replica had the data */
    qihse_cluster_topology_set_node_health(topo, ip, true);
    sleep_ms_fb(400);
    assert(probe.calls == 0);
    qihse_cluster_failover_destroy(fo);
    qihse_cluster_topology_destroy(topo);
    printf("PASS dedicated-replica promotion is not failed back\n");
}

static void test_failback_respects_resplit_range(void) {
    fb_probe_t probe; memset(&probe, 0, sizeof(probe));
    qihse_cluster_topology_t* topo; qihse_cluster_failover_t* fo; uint16_t ia, ib;
    failback_fixture(&topo, &fo, &probe, &ia, &ib, 100);
    qihse_cluster_topology_set_node_health(topo, ia, false);
    assert(qihse_cluster_failover_handle(fo, ia) == ib);          /* ib owns 0-99 */
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
    qihse_cluster_failover_t* fo = qihse_cluster_failover_create(&fcfg);
    assert(fo);

    qihse_cluster_bus_config_t bcfg; memset(&bcfg, 0, sizeof(bcfg));
    bcfg.topology = topo; bcfg.local_node_index = ic; bcfg.bus_port = 0;
    qihse_cluster_bus_t* bus = qihse_cluster_bus_create(&bcfg);
    assert(bus);
    qihse_cluster_bus_set_takeover_callback(bus, qihse_cluster_failover_on_takeover_cb, fo);

    /* The owner is down, and ANOTHER node's coordinator announces that THIS node
     * (the successor) now owns 0-99. */
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
    assert(qihse_cluster_topology_get_slot(topo, 50, &o, &st, NULL) && o == ic);
    assert(qihse_cluster_failover_pending_failbacks(fo) == 1u);   /* ledgered via the bus */

    qihse_cluster_topology_set_node_health(topo, ia, true);
    fb_wait_t w = { fo, &probe, topo, 50, ia, 1 };
    assert(wait_for(fb_owner_is, &w, 3000));
    assert(wait_for(fb_count_reached, &w, 3000));
    assert(probe.last_target == ia && probe.last_first == 0 && probe.last_last == 99);

    qihse_cluster_bus_destroy(bus);
    qihse_cluster_failover_destroy(fo);
    qihse_cluster_topology_destroy(topo);
    printf("PASS successor ledgers and fails back a takeover decided by another node\n");
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
    assert(qihse_cluster_topology_assign_range(topo, 0, 99, i2));

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

    /* Now i0 also fails -> i1 becomes coordinator and must immediately promote
     * without being blocked by the 30s cooldown. */
    qihse_cluster_topology_set_node_health(topo, i0, false);
    assert(qihse_cluster_failover_handle(fo, i2) == i1);

    qihse_cluster_failover_destroy(fo);
    qihse_cluster_topology_destroy(topo);
    printf("PASS deferred/non-coordinator on_fail does not trip 30s cooldown\n");
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
    test_non_coordinator_does_not_trip_cooldown();
    printf("cluster failover tests passed\n");
    return 0;
}
