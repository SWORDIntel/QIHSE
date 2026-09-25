/*
 * test_consensus.c — scoped replication-group consensus state machine.
 *
 * Deterministic scenarios (plan §44.2 mandatory set, scoped to one group):
 *   (a) election completes, exactly one leader per term;
 *   (b) partition: no progress on the isolated side, and LOCAL namespaces
 *       stay read-write (core federation invariant; acceptance criteria 1-3);
 *   (c) log commitment only after a strict majority acknowledges;
 *   (d) higher-term step-down and stale fencing-epoch rejection (AC4);
 *   (e) persistence round-trip: restart mid-log resumes correctly;
 *   (f) hostile decoder input: corrupt/truncated records fail closed;
 *   (g) AGENTS.md invariant 1 negative authorization test — a low-clearance
 *       principal cannot read a committed classified entry through this
 *       surface, and NULL is never a bypass.
 *
 * Log-compaction / snapshot-install scenarios:
 *   (h) a far-behind follower catches up via snapshot + tail and converges
 *       with the leader byte-for-byte;
 *   (i) compaction under churn: repeated compact / catch-up cycles across
 *       multiple terms, with leader restarts between rounds;
 *   (j) tampered-digest, stale-epoch, and malformed snapshots are refused,
 *       the follower keeps its state, and the counters increment;
 *   (k) persistence: snapshot + tail survive restart, and the three
 *       crash-mid-compaction points (before the S write, after the
 *       snapshot write, after the truncation record) all recover the
 *       correct durable state;
 *   (f2) hostile decoder input for the snapshot records themselves;
 *   (l) committed-read visibility after compaction is identical to
 *       pre-compaction for an operator and a low-clearance principal, and
 *       NULL is still refused (invariant 1 holds post-compaction);
 *   (m) compaction determinism: the same scenario hashes identically on
 *       two independent runs.
 *
 * Membership-change scenarios (single-server transitions):
 *   (n) remove/remove/add transitions each commit, quorum arithmetic flips
 *       observably in both directions, a second proposal while a
 *       transition is in flight is refused (nothing appended), and
 *       unauthorized principals (NULL, non-operator) are refused;
 *   (o) election safety across a config boundary: a removed node never
 *       wins any term and no term ever elects two leaders, whether the
 *       removed node learned of its removal or is stuck on the old
 *       config; its fencing floor still applies;
 *   (p) leader change mid-transition resolves exactly as documented —
 *       held entry completes as a commit prefix, absent entry truncates
 *       and the group reverts to the previous config;
 *   (q) restart mid-transition: replay lands on the config of the last
 *       config entry in the log (committed or the single in-flight one);
 *       a torn LC write fails closed and rolls back to the previous
 *       config;
 *   (f3) hostile decoder input for the config records themselves;
 *   (r) membership determinism: the same transition scenario hashes
 *       identically on two independent runs.
 *
 * Everything runs on a virtual clock and an in-memory queue transport: no
 * threads, no sockets, no wall-clock.  Record files live under a relative
 * mkdtemp directory.
 */
#include "qihse_consensus.h"
#include "qihse_federation.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Local hex helper (mirrors the module's encoding for crafted records). */
static void t_hex_encode(const uint8_t* in, size_t len, char* out) {
    static const char digits[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        out[2 * i] = digits[in[i] >> 4];
        out[2 * i + 1] = digits[in[i] & 0x0Fu];
    }
    out[2 * len] = '\0';
}

/* ── Queue transport harness ─────────────────────────────────────────────── */

#define N 5u
#define QCAP_INIT 64u

typedef struct {
    qihse_consensus_t* node[N];
    qihse_uuid_t id[N];
    char dir[128];
    char recpath[N][192];
    bool drop[N][N];
    qihse_consensus_msg_t* msgs;
    size_t msg_count, msg_cap;
    uint64_t dropped;
    uint64_t now;
    uint64_t thresh;               /* snapshot_threshold all nodes open with */
    qihse_consensus_msg_t snap_msg; /* last SNAPSHOT message seen on the wire */
    bool snap_seen;
    /* Optional 6th node (index N in h_index) for ADD transitions; closed
     * and inert in every legacy scenario.  extra_down is its partition
     * switch; per-node drop[][] keeps governing the base five. */
    qihse_consensus_t* extra;
    qihse_uuid_t extra_id;
    char extra_path[192];
    bool extra_open;
    bool extra_down;
} harness_t;

static void h_send(void* transport, const qihse_consensus_msg_t* msg) {
    harness_t* h = (harness_t*)transport;
    if (!h || !msg) return;
    if (msg->type == QIHSE_CONSENSUS_MSG_SNAPSHOT) {
        h->snap_msg = *msg; /* pristine copy for the tamper tests */
        h->snap_seen = true;
    }
    if (h->msg_count == h->msg_cap) {
        size_t ncap = h->msg_cap ? h->msg_cap * 2u : QCAP_INIT;
        qihse_consensus_msg_t* nm = realloc(h->msgs, ncap * sizeof(*nm));
        assert(nm);
        h->msgs = nm;
        h->msg_cap = ncap;
    }
    h->msgs[h->msg_count++] = *msg;
}

static int h_index(const harness_t* h, const qihse_uuid_t* id) {
    for (size_t i = 0; i < N; i++) {
        if (qihse_uuid_equal(&h->id[i], id)) return (int)i;
    }
    if (h->extra_open && qihse_uuid_equal(&h->extra_id, id)) return (int)N;
    return -1;
}

static qihse_consensus_t* h_node_at(const harness_t* h, int i) {
    if (i < 0) return NULL;
    if (i < (int)N) return h->node[i];
    if (i == (int)N) return h->extra;
    return NULL;
}

static void h_deliver(harness_t* h, const qihse_consensus_msg_t* m) {
    int fi = h_index(h, &m->from);
    int ti = h_index(h, &m->to);
    qihse_consensus_t* dst = h_node_at(h, ti);
    if (fi < 0 || ti < 0 || !dst) {
        h->dropped++;
        return;
    }
    bool blocked = (fi == (int)N || ti == (int)N)
                       ? h->extra_down
                       : h->drop[fi][ti];
    if (blocked) {
        h->dropped++;
        return;
    }
    qihse_consensus_receive(dst, m);
}

static void h_pump_all(harness_t* h) {
    unsigned guard = 0u;
    while (h->msg_count > 0u) {
        qihse_consensus_msg_t m = h->msgs[0];
        memmove(&h->msgs[0], &h->msgs[1], (h->msg_count - 1u) * sizeof(*h->msgs));
        h->msg_count--;
        h_deliver(h, &m);
        if (++guard > 100000u) { assert(!"message pump runaway"); }
    }
}

/* Deliver only traffic exchanged between nodes a and b (either direction);
 * everything else stays queued.  Used to control exactly which followers
 * acknowledge an append. */
static void h_pump_pair(harness_t* h, int a, int b) {
    unsigned guard = 0u;
    bool again = true;
    while (again && ++guard <= 10000u) {
        again = false;
        for (size_t i = 0; i < h->msg_count; i++) {
            qihse_consensus_msg_t m = h->msgs[i];
            int fi = h_index(h, &m.from);
            int ti = h_index(h, &m.to);
            if ((fi == a && ti == b) || (fi == b && ti == a)) {
                memmove(&h->msgs[i], &h->msgs[i + 1u],
                        (h->msg_count - i - 1u) * sizeof(*h->msgs));
                h->msg_count--;
                h_deliver(h, &m);
                again = true;
                break;
            }
        }
    }
}

static void h_tick(harness_t* h, uint64_t step_ms) {
    h->now += step_ms;
    for (size_t i = 0; i < N; i++) {
        if (h->node[i]) qihse_consensus_tick(h->node[i], h->now);
    }
    if (h->extra) qihse_consensus_tick(h->extra, h->now);
    h_pump_all(h);
}

/* Advance time and tick ONE node (no automatic pumping). */
static void h_tick_one(harness_t* h, size_t i, uint64_t step_ms) {
    h->now += step_ms;
    assert(h->node[i]);
    qihse_consensus_tick(h->node[i], h->now);
}

static int h_leader(const harness_t* h) {
    int leader = -1;
    unsigned count = 0u;
    for (size_t i = 0; i < N; i++) {
        if (h->node[i] && qihse_consensus_role(h->node[i]) == QIHSE_CONSENSUS_LEADER) {
            leader = (int)i;
            count++;
        }
    }
    return (count == 1u) ? leader : (count ? -2 : -1);
}

static void h_init_ex(harness_t* h, const char* seed, uint64_t snapshot_threshold) {
    memset(h, 0, sizeof(*h));
    h->thresh = snapshot_threshold;

    snprintf(h->dir, sizeof(h->dir), "build/test_consensus_XXXXXX");
    if (!mkdtemp(h->dir)) {
        snprintf(h->dir, sizeof(h->dir), "test_consensus_XXXXXX");
        assert(mkdtemp(h->dir));
    }

    for (size_t i = 0; i < N; i++) {
        char buf[96];
        snprintf(buf, sizeof(buf), "consensus-%s-%zu", seed, i);
        assert(qihse_uuid_from_seed(buf, strlen(buf), &h->id[i]));
        snprintf(h->recpath[i], sizeof(h->recpath[i]), "%s/node%zu.rec", h->dir, i);
    }

    for (size_t i = 0; i < N; i++) {
        qihse_consensus_config_t cfg;
        memset(&cfg, 0, sizeof(cfg));
        snprintf(cfg.group_id, sizeof(cfg.group_id), "group/%s", seed);
        cfg.self = h->id[i];
        cfg.member_count = N;
        for (size_t j = 0; j < N; j++) cfg.members[j] = h->id[j];
        cfg.election_timeout_base_ms = 150u;
        cfg.election_timeout_spread_ms = 300u;
        cfg.heartbeat_interval_ms = 50u;
        cfg.snapshot_threshold = snapshot_threshold;
        snprintf(cfg.record_path, sizeof(cfg.record_path), "%s", h->recpath[i]);
        h->node[i] = qihse_consensus_open(&cfg, h, h_send);
        assert(h->node[i]);
    }
}

static void h_init(harness_t* h, const char* seed) {
    h_init_ex(h, seed, 0u); /* compaction disabled: legacy behavior */
}

static void h_free(harness_t* h) {
    for (size_t i = 0; i < N; i++) {
        if (h->node[i]) qihse_consensus_close(h->node[i]);
        h->node[i] = NULL;
    }
    if (h->extra) qihse_consensus_close(h->extra);
    h->extra = NULL;
    h->extra_open = false;
    h->extra_down = false;
    free(h->msgs);
    h->msgs = NULL;
    h->msg_count = h->msg_cap = 0u;
    /* Leave no record files behind. */
    for (size_t i = 0; i < N; i++) remove(h->recpath[i]);
    remove(h->extra_path);
    rmdir(h->dir);
}

/* Reopen node i against its existing record file (restart). */
static void h_restart(harness_t* h, size_t i, const char* seed) {
    qihse_consensus_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    snprintf(cfg.group_id, sizeof(cfg.group_id), "group/%s", seed);
    cfg.self = h->id[i];
    cfg.member_count = N;
    for (size_t j = 0; j < N; j++) cfg.members[j] = h->id[j];
    cfg.election_timeout_base_ms = 150u;
    cfg.election_timeout_spread_ms = 300u;
    cfg.heartbeat_interval_ms = 50u;
    cfg.snapshot_threshold = h->thresh;
    snprintf(cfg.record_path, sizeof(cfg.record_path), "%s", h->recpath[i]);
    if (h->node[i]) qihse_consensus_close(h->node[i]);
    h->node[i] = qihse_consensus_open(&cfg, h, h_send);
    assert(h->node[i]);
}

/* Elect a leader, ticking until exactly one node leads. */
static int h_elect(harness_t* h) {
    for (unsigned i = 0; i < 600u; i++) {
        h_tick(h, 10u);
        int leader = h_leader(h);
        if (leader >= 0) return leader;
    }
    return -1;
}

/* Wait until every open node reports commit >= want. */
static bool h_commit_reached(harness_t* h, uint64_t want) {
    for (unsigned i = 0; i < 400u; i++) {
        bool all = true;
        for (size_t j = 0; j < N; j++) {
            if (h->node[j] && qihse_consensus_commit_index(h->node[j]) < want) {
                all = false;
                break;
            }
        }
        if (all) return true;
        h_tick(h, 10u);
    }
    return false;
}

/* Same, ignoring one node (used while it is partitioned away). */
static bool h_commit_reached_skip(harness_t* h, uint64_t want, int skip) {
    for (unsigned i = 0; i < 400u; i++) {
        bool all = true;
        for (size_t j = 0; j < N; j++) {
            if ((int)j == skip || !h->node[j]) continue;
            if (qihse_consensus_commit_index(h->node[j]) < want) {
                all = false;
                break;
            }
        }
        if (all) return true;
        h_tick(h, 10u);
    }
    return false;
}

/* ── Membership-test helpers ─────────────────────────────────────────────── */

/* Give the harness its 6th node identity + record path (not yet opened). */
static void h_seed_extra(harness_t* h, const char* seed) {
    char buf[96];
    snprintf(buf, sizeof(buf), "consensus-%s-x", seed);
    assert(qihse_uuid_from_seed(buf, strlen(buf), &h->extra_id));
    snprintf(h->extra_path, sizeof(h->extra_path), "%s/extra.rec", h->dir);
    h->extra_open = true;
}

/* Open (or reopen after close) the extra node with an explicit baseline
 * member list that must include the extra UUID itself. */
static void h_open_extra(harness_t* h, const char* seed,
                         const qihse_uuid_t* members, size_t member_count) {
    qihse_consensus_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    snprintf(cfg.group_id, sizeof(cfg.group_id), "group/%s", seed);
    cfg.self = h->extra_id;
    cfg.member_count = member_count;
    for (size_t j = 0; j < member_count; j++) cfg.members[j] = members[j];
    cfg.election_timeout_base_ms = 150u;
    cfg.election_timeout_spread_ms = 300u;
    cfg.heartbeat_interval_ms = 50u;
    cfg.snapshot_threshold = h->thresh;
    snprintf(cfg.record_path, sizeof(cfg.record_path), "%s", h->extra_path);
    if (h->extra) qihse_consensus_close(h->extra);
    h->extra = qihse_consensus_open(&cfg, h, h_send);
    assert(h->extra);
}

static void x_heal(harness_t* h) { h->extra_down = false; }

/* Elect a leader among a chosen subset of the base five. */
static int h_elect_among(harness_t* h, const bool* may_lead) {
    for (unsigned i = 0; i < 600u; i++) {
        h_tick(h, 10u);
        int leader = -1;
        unsigned count = 0u;
        for (size_t j = 0; j < N; j++) {
            if (may_lead[j] && h->node[j] &&
                qihse_consensus_role(h->node[j]) == QIHSE_CONSENSUS_LEADER) {
                leader = (int)j;
                count++;
            }
        }
        if (count == 1u) return leader;
    }
    return -1;
}

/* Per-term leader tracker: the election-safety property, asserted rather
 * than assumed — no term may ever have two distinct leaders. */
typedef struct {
    uint64_t term;
    int node; /* 0..N-1, or N for the extra node */
} t_term_leader_t;

static void t_track_leader(t_term_leader_t* seen, size_t cap, size_t* used,
                           uint64_t term, int node) {
    for (size_t i = 0; i < *used; i++) {
        if (seen[i].term == term) {
            assert(seen[i].node == node); /* TWO leaders in one term */
            return;
        }
    }
    assert(*used < cap);
    seen[*used].term = term;
    seen[*used].node = node;
    (*used)++;
}

static void t_scan_leaders(harness_t* h, t_term_leader_t* seen, size_t cap,
                           size_t* used) {
    for (size_t j = 0; j < N; j++) {
        if (h->node[j] &&
            qihse_consensus_role(h->node[j]) == QIHSE_CONSENSUS_LEADER) {
            t_track_leader(seen, cap, used,
                           qihse_consensus_term(h->node[j]), (int)j);
        }
    }
    if (h->extra &&
        qihse_consensus_role(h->extra) == QIHSE_CONSENSUS_LEADER) {
        t_track_leader(seen, cap, used, qihse_consensus_term(h->extra),
                       (int)N);
    }
}

/* Membership getter on a base node, with a caller-friendly name. */
static void t_membership(const qihse_consensus_t* cs,
                         qihse_consensus_membership_t* out) {
    assert(qihse_consensus_get_membership(cs, out));
}

/* Leader across every open node, extra included: 0..N-1, N for the extra. */
static int h_leader_any(harness_t* h) {
    int leader = -1;
    unsigned count = 0u;
    for (size_t i = 0; i < N; i++) {
        if (h->node[i] &&
            qihse_consensus_role(h->node[i]) == QIHSE_CONSENSUS_LEADER) {
            leader = (int)i;
            count++;
        }
    }
    if (h->extra && qihse_consensus_role(h->extra) == QIHSE_CONSENSUS_LEADER) {
        leader = (int)N;
        count++;
    }
    return (count == 1u) ? leader : (count ? -2 : -1);
}

/* ── (a) Election: completes, exactly one leader per term ────────────────── */

static void test_election_single_leader(void) {
    harness_t h;
    h_init(&h, "elect");

    /* term -> set of nodes ever observed leading that term */
    bool term_leader[8][N];
    memset(term_leader, 0, sizeof(term_leader));

    int leader = -1;
    for (unsigned i = 0; i < 600u; i++) {
        h_tick(&h, 10u);
        for (size_t j = 0; j < N; j++) {
            if (h.node[j] &&
                qihse_consensus_role(h.node[j]) == QIHSE_CONSENSUS_LEADER) {
                uint64_t t = qihse_consensus_term(h.node[j]);
                assert(t < 8u);
                assert(!term_leader[t][j]); /* same node twice in one term */
                for (size_t k = 0; k < N; k++) {
                    if (k != j) {
                        assert(!term_leader[t][k]); /* TWO leaders, one term */
                    }
                }
                term_leader[t][j] = true;
            }
        }
        leader = h_leader(&h);
        if (leader >= 0) break;
    }
    assert(leader >= 0);
    printf("  elected leader node %d in term %llu\n", leader,
           (unsigned long long)qihse_consensus_term(h.node[leader]));

    /* Everyone agrees on the term and follows the same leader. */
    uint64_t term = qihse_consensus_term(h.node[leader]);
    qihse_uuid_t lid;
    assert(qihse_consensus_leader_id(h.node[leader], &lid));
    for (size_t j = 0; j < N; j++) {
        if (!h.node[j]) continue;
        assert(qihse_consensus_term(h.node[j]) == term);
        if ((int)j == leader) continue;
        assert(qihse_consensus_role(h.node[j]) == QIHSE_CONSENSUS_FOLLOWER);
        qihse_uuid_t fl;
        assert(qihse_consensus_leader_id(h.node[j], &fl));
        assert(qihse_uuid_equal(&fl, &lid));
        /* Every follower recorded a durable vote in this term. */
        qihse_uuid_t voted;
        assert(qihse_consensus_voted_for(h.node[j], &voted));
        assert(qihse_uuid_equal(&voted, &lid));
    }

    /* Soak: the leader is stable, no term churn, group stays available. */
    for (unsigned i = 0; i < 200u; i++) {
        h_tick(&h, 10u);
        assert(h_leader(&h) == leader);
    }
    for (size_t j = 0; j < N; j++) {
        assert(qihse_consensus_group_available(h.node[j], h.now));
    }

    qihse_consensus_counters_t c;
    qihse_consensus_get_counters(h.node[leader], &c);
    assert(c.elections_won == 1u);

    h_free(&h);
    printf("PASS (a) election completes, exactly one leader per term\n");
}

/* ── (b) Partition: no progress, LOCAL stays read-write ──────────────────── */

static void test_partition_local_rw(void) {
    harness_t h;
    h_init(&h, "part");

    int leader = h_elect(&h);
    assert(leader >= 0);
    uint64_t old_term = qihse_consensus_term(h.node[leader]);

    /* Baseline committed entry on the healthy group. */
    qihse_hlc_t hlc = {100u, 0u};
    assert(qihse_consensus_propose(h.node[leader], NULL, 100u, hlc, 0u, 0u,
                                    "baseline", 8u));
    assert(h_commit_reached(&h, 1u));

    /* The namespace lenses the core federation invariant runs through. */
    qihse_federation_namespace_t local_ns;
    memset(&local_ns, 0, sizeof(local_ns));
    snprintf(local_ns.name, sizeof(local_ns.name), "host-local");
    local_ns.consistency = QIHSE_CONSISTENCY_LOCAL;
    local_ns.local_authority = true;
    local_ns.authority_node = h.id[leader];

    qihse_federation_namespace_t strong_ns;
    memset(&strong_ns, 0, sizeof(strong_ns));
    snprintf(strong_ns.name, sizeof(strong_ns.name), "core-security");
    strong_ns.consistency = QIHSE_CONSISTENCY_QUORUM;
    strong_ns.local_authority = false;
    strong_ns.authority_node = h.id[(leader + 1u) % N];

    /* Isolate the leader completely: it keeps its title but loses quorum. */
    for (size_t j = 0; j < N; j++) {
        h.drop[leader][j] = true;
        h.drop[j][leader] = true;
    }

    qihse_hlc_t hlc2 = {200u, 0u};
    assert(qihse_consensus_propose(h.node[leader], NULL, 101u, hlc2, 0u, 0u,
                                    "isolated", 8u));
    assert(qihse_consensus_last_log_index(h.node[leader]) == 2u);

    uint64_t dropped_before = h.dropped;
    for (unsigned i = 0; i < 120u; i++) h_tick(&h, 10u); /* 1.2s virtual */
    assert(h.dropped > dropped_before); /* the partition really dropped */

    /* No progress on the isolated node: the entry never commits. */
    assert(qihse_consensus_commit_index(h.node[leader]) == 1u);
    assert(!qihse_consensus_group_available(h.node[leader], h.now));

    /* LOCAL namespaces are NEVER gated on consensus progress: the node is
     * ISOLATED for this group and still read-write locally (AC1, AC2). */
    assert(qihse_federation_namespace_writable(
        &local_ns, QIHSE_FEDERATION_STATE_ISOLATED, &h.id[leader]));
    /* Strong namespaces fail closed under insufficient consensus (AC3). */
    assert(!qihse_federation_namespace_writable(
        &strong_ns, QIHSE_FEDERATION_STATE_ISOLATED, &h.id[leader]));

    /* The majority side (4 nodes) elects a new leader in a new term. */
    int new_leader = -1;
    for (unsigned i = 0; i < 600u; i++) {
        h_tick(&h, 10u);
        int count = 0, cand = -1;
        for (size_t j = 0; j < N; j++) {
            if ((int)j == leader || !h.node[j]) continue;
            if (qihse_consensus_role(h.node[j]) == QIHSE_CONSENSUS_LEADER) {
                cand = (int)j;
                count++;
            }
        }
        if (count == 1) { new_leader = cand; break; }
    }
    assert(new_leader >= 0);
    assert(qihse_consensus_term(h.node[new_leader]) > old_term);
    assert(qihse_consensus_group_available(h.node[new_leader], h.now));

    /* Heal: the stale leader must step down on the higher term and its
     * uncommitted entry must lose to the new leader's entry. */
    memset(h.drop, 0, sizeof(h.drop));
    for (unsigned i = 0; i < 100u && qihse_consensus_role(h.node[leader]) !=
         QIHSE_CONSENSUS_FOLLOWER; i++) {
        h_tick(&h, 10u);
    }
    assert(qihse_consensus_role(h.node[leader]) == QIHSE_CONSENSUS_FOLLOWER);
    assert(qihse_consensus_term(h.node[leader]) ==
           qihse_consensus_term(h.node[new_leader]));

    qihse_hlc_t hlc3 = {300u, 0u};
    assert(qihse_consensus_propose(h.node[new_leader], NULL, 102u, hlc3, 0u, 0u,
                                    "healed", 6u));
    assert(h_commit_reached(&h, 2u));

    qihse_consensus_counters_t c;
    qihse_consensus_get_counters(h.node[leader], &c);
    assert(c.log_conflicts >= 1u); /* the isolated entry was replaced */

    /* LOCAL stayed writable at every phase of the partition. */
    assert(qihse_federation_namespace_writable(
        &local_ns, QIHSE_FEDERATION_STATE_CONNECTED, &h.id[leader]));

    h_free(&h);
    printf("PASS (b) partition: no quorum progress, LOCAL stays read-write, "
           "stale leader steps down on heal\n");
}

/* ── (c) Commitment requires a strict majority ───────────────────────────── */

static void test_commit_requires_majority(void) {
    harness_t h;
    h_init(&h, "majority");

    int leader = h_elect(&h);
    assert(leader >= 0);
    int f1 = (leader + 1u) % N;
    int f2 = (leader + 2u) % N;

    qihse_hlc_t hlc = {500u, 7u};
    assert(qihse_consensus_propose(h.node[leader], NULL, 200u, hlc, 0u, 0u,
                                    "needs-quorum", 13u));

    /* Replicate to exactly one follower (leader + 1 ack = 2 of 5). */
    h_tick_one(&h, leader, 10u);
    h_pump_pair(&h, leader, f1);
    assert(qihse_consensus_last_log_index(h.node[f1]) == 1u);
    assert(qihse_consensus_commit_index(h.node[leader]) == 0u);
    /* 2 of 5 is below the strict majority: nothing is committed, so no
     * committed entry exists to read at any clearance. */

    /* Second follower acknowledges: 3 of 5 is a strict majority. */
    h_pump_pair(&h, leader, f2);
    assert(qihse_consensus_commit_index(h.node[leader]) == 1u);

    /* Followers learn the commit only from the leader's next heartbeat. */
    assert(qihse_consensus_commit_index(h.node[f1]) == 0u);
    h_tick(&h, 10u);
    for (unsigned i = 0; i < 50u && !h_commit_reached(&h, 1u); i++) {
        h_tick(&h, 10u);
    }
    for (size_t j = 0; j < N; j++) {
        assert(qihse_consensus_commit_index(h.node[j]) == 1u);
    }

    h_free(&h);
    printf("PASS (c) commit advances only on majority acknowledgment "
           "(2/5 no, 3/5 yes)\n");
}

/* ── (d) Higher-term step-down + stale fencing epoch ─────────────────────── */

static void test_stepdown_and_stale_epoch(void) {
    harness_t h;
    h_init(&h, "fence");

    int leader = h_elect(&h);
    assert(leader >= 0);
    uint64_t term = qihse_consensus_term(h.node[leader]);
    uint64_t epoch = qihse_consensus_fencing_epoch(h.node[leader]);
    assert(epoch >= term);

    /* A follower with a fully up-to-date log (empty) is our fencing probe. */
    int probe = (leader + 1u) % N;
    uint64_t probe_log = qihse_consensus_last_log_index(h.node[probe]);

    /* Stale fencing epoch, CURRENT term: fenced before any term logic. */
    qihse_consensus_msg_t inj;
    memset(&inj, 0, sizeof(inj));
    inj.type = QIHSE_CONSENSUS_MSG_APPEND;
    snprintf(inj.group_id, sizeof(inj.group_id), "%s", "group/fence");
    inj.from = h.id[leader];
    inj.to = h.id[probe];
    inj.term = term;
    inj.fencing_epoch = epoch - 1u; /* stale */
    inj.u.append.prev_log_index = probe_log;
    inj.u.append.prev_log_term = 0u;
    inj.u.append.leader_commit = probe_log;
    inj.u.append.entry_count = 1u;
    inj.u.append.entries[0].index = probe_log + 1u;
    inj.u.append.entries[0].term = term;
    inj.u.append.entries[0].journal_generation = 900u;
    inj.u.append.entries[0].payload_len = 2u;
    memcpy(inj.u.append.entries[0].payload, "zz", 2u);

    qihse_consensus_counters_t before;
    qihse_consensus_get_counters(h.node[probe], &before);
    qihse_consensus_receive(h.node[probe], &inj);

    qihse_consensus_counters_t after;
    qihse_consensus_get_counters(h.node[probe], &after);
    assert(after.stale_epoch_rejections == before.stale_epoch_rejections + 1u);
    assert(qihse_consensus_last_log_index(h.node[probe]) == probe_log);
    assert(qihse_consensus_commit_index(h.node[probe]) == 0u);
    assert(qihse_consensus_is_stale_epoch(h.node[probe], epoch - 1u));
    assert(!qihse_consensus_is_stale_epoch(h.node[probe], epoch));
    (void)before; (void)after; /* used above via asserts */

    /* Organic higher-term step-down: 3-node majority elects a new leader
     * while the old leader sits in a 2-node minority. */
    int side[3], side_count = 0;
    for (size_t j = 0; j < N && side_count < 3; j++) {
        if ((int)j != leader && (int)j != probe) side[side_count++] = (int)j;
    }
    assert(side_count == 3);
    /* Minority {leader, probe} | majority {side[0..2]}: sever every link
     * that crosses the split, in both directions. */
    for (size_t j = 0; j < N; j++) {
        bool in_majority = false;
        for (int k = 0; k < 3; k++) in_majority = in_majority || (side[k] == (int)j);
        if (in_majority) {
            h.drop[leader][j] = true;
            h.drop[j][leader] = true;
            h.drop[probe][j] = true;
            h.drop[j][probe] = true;
        }
    }

    int new_leader = -1;
    for (unsigned i = 0; i < 600u; i++) {
        h_tick(&h, 10u);
        int count = 0, cand = -1;
        for (int k = 0; k < 3; k++) {
            if (qihse_consensus_role(h.node[side[k]]) == QIHSE_CONSENSUS_LEADER) {
                cand = side[k];
                count++;
            }
        }
        if (count == 1) { new_leader = cand; break; }
    }
    assert(new_leader >= 0);
    assert(qihse_consensus_term(h.node[new_leader]) > term);

    /* Heal: the old leader must adopt the higher term and step down. */
    memset(h.drop, 0, sizeof(h.drop));
    for (unsigned i = 0; i < 100u && qihse_consensus_role(h.node[leader]) !=
         QIHSE_CONSENSUS_FOLLOWER; i++) {
        h_tick(&h, 10u);
    }
    assert(qihse_consensus_role(h.node[leader]) == QIHSE_CONSENSUS_FOLLOWER);
    assert(qihse_consensus_term(h.node[leader]) ==
           qihse_consensus_term(h.node[new_leader]));

    /* An old-term append is rejected on term grounds: its fencing epoch is
     * current (so it survives the fence check) but its term is not. */
    qihse_consensus_msg_t stale;
    memset(&stale, 0, sizeof(stale));
    stale.type = QIHSE_CONSENSUS_MSG_APPEND;
    snprintf(stale.group_id, sizeof(stale.group_id), "%s", "group/fence");
    stale.from = h.id[leader];
    stale.to = h.id[side[1]];
    stale.term = term;
    stale.fencing_epoch = qihse_consensus_fencing_epoch(h.node[side[1]]);
    stale.u.append.prev_log_index = 0u;
    stale.u.append.prev_log_term = 0u;
    stale.u.append.leader_commit = 0u;

    uint64_t log_before = qihse_consensus_last_log_index(h.node[side[1]]);
    qihse_consensus_counters_t b2;
    qihse_consensus_get_counters(h.node[side[1]], &b2);
    qihse_consensus_receive(h.node[side[1]], &stale);
    qihse_consensus_counters_t a2;
    qihse_consensus_get_counters(h.node[side[1]], &a2);
    assert(a2.term_rejections == b2.term_rejections + 1u);
    assert(qihse_consensus_last_log_index(h.node[side[1]]) == log_before);
    assert(qihse_consensus_term(h.node[side[1]]) ==
           qihse_consensus_term(h.node[new_leader]));
    /* Everything below the surviving epoch floor is fenced off. */
    assert(qihse_consensus_is_stale_epoch(h.node[side[1]], epoch));

    h_free(&h);
    printf("PASS (d) higher-term step-down + stale-epoch and stale-term "
           "rejection (AC4)\n");
}

/* ── (e) Persistence round-trip: restart mid-log ─────────────────────────── */

static void test_persistence_roundtrip(void) {
    harness_t h;
    h_init(&h, "persist");

    int leader = h_elect(&h);
    assert(leader >= 0);
    uint64_t term = qihse_consensus_term(h.node[leader]);

    for (uint64_t g = 300u; g <= 302u; g++) {
        char payload[32];
        snprintf(payload, sizeof(payload), "entry-%llu", (unsigned long long)g);
        qihse_hlc_t hlc = {g * 10u, (uint32_t)(g & 0xFu)};
        assert(qihse_consensus_propose(h.node[leader], NULL, g, hlc, 0u, 0u,
                                        payload, strlen(payload)));
    }
    assert(h_commit_reached(&h, 3u));

    /* Restart the leader and one follower from their record files. */
    h_restart(&h, leader, "persist");
    assert(qihse_consensus_term(h.node[leader]) == term);
    assert(qihse_consensus_commit_index(h.node[leader]) == 3u);
    assert(qihse_consensus_last_log_index(h.node[leader]) == 3u);
    assert(qihse_consensus_role(h.node[leader]) == QIHSE_CONSENSUS_FOLLOWER);
    qihse_uuid_t voted;
    assert(qihse_consensus_voted_for(h.node[leader], &voted));
    assert(qihse_uuid_equal(&voted, &h.id[leader]));

    h_restart(&h, (leader + 3u) % N, "persist");
    assert(qihse_consensus_commit_index(h.node[(leader + 3u) % N]) == 3u);
    assert(qihse_consensus_last_log_index(h.node[(leader + 3u) % N]) == 3u);

    /* The restarted group keeps making progress. */
    int new_leader = h_elect(&h);
    assert(new_leader >= 0);
    assert(qihse_consensus_term(h.node[new_leader]) > term);
    qihse_hlc_t hlc4 = {4000u, 1u};
    assert(qihse_consensus_propose(h.node[new_leader], NULL, 304u, hlc4, 0u, 0u,
                                    "after-restart", 13u));
    assert(h_commit_reached(&h, 4u));

    /* Mid-log restart: crash a follower, advance the group without it,
     * then bring it back and let it catch up from its own record file. */
    int lag = (new_leader + 1u) % N;
    qihse_consensus_close(h.node[lag]);
    h.node[lag] = NULL;

    qihse_hlc_t hlc5 = {5000u, 2u};
    assert(qihse_consensus_propose(h.node[new_leader], NULL, 305u, hlc5, 0u, 0u,
                                    "while-down", 10u));
    for (unsigned i = 0; i < 400u; i++) {
        bool all = true;
        for (size_t j = 0; j < N; j++) {
            if (h.node[j] && qihse_consensus_commit_index(h.node[j]) < 5u) {
                all = false;
            }
        }
        if (all) break;
        h_tick(&h, 10u);
    }
    for (size_t j = 0; j < N; j++) {
        if (h.node[j]) assert(qihse_consensus_commit_index(h.node[j]) == 5u);
    }

    h_restart(&h, lag, "persist");
    assert(qihse_consensus_last_log_index(h.node[lag]) == 4u); /* mid-log */
    assert(qihse_consensus_commit_index(h.node[lag]) == 4u);
    for (unsigned i = 0; i < 400u &&
         qihse_consensus_commit_index(h.node[lag]) < 5u; i++) {
        h_tick(&h, 10u);
    }
    assert(qihse_consensus_commit_index(h.node[lag]) == 5u);
    assert(qihse_consensus_last_log_index(h.node[lag]) == 5u);

    h_free(&h);
    printf("PASS (e) persistence round-trip: restart resumes term/log/commit "
           "and catches up mid-log\n");
}

/* ── (f) Hostile decoder input fails closed ──────────────────────────────── */

static uint64_t t_fnv(const char* s, size_t n) {
    uint64_t hv = 0xCBF2CE48D222D25BULL;
    for (size_t i = 0; i < n; i++) {
        hv ^= (uint8_t)s[i];
        hv *= 0x100000001B3ULL;
    }
    return hv;
}

static void t_wline(FILE* f, const char* body) {
    fprintf(f, "%s %016llx\n", body, (unsigned long long)t_fnv(body, strlen(body)));
}

static bool hostile_open(const char* path, const qihse_uuid_t* self,
                         const char* self_hex) {
    qihse_consensus_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    snprintf(cfg.group_id, sizeof(cfg.group_id), "group/hostile");
    cfg.self = *self;
    cfg.member_count = 1u;
    cfg.members[0] = *self;
    cfg.election_timeout_base_ms = 150u;
    cfg.election_timeout_spread_ms = 300u;
    cfg.heartbeat_interval_ms = 50u;
    snprintf(cfg.record_path, sizeof(cfg.record_path), "%s", path);
    (void)self_hex;
    qihse_consensus_t* cs = qihse_consensus_open(&cfg, NULL, NULL);
    if (!cs) return false;
    qihse_consensus_close(cs);
    return true;
}

static void test_decoder_hostile(const char* dir, const qihse_uuid_t* self,
                                 const char* self_hex) {
    char path[192];
    char body[512];

    struct { const char* name; const char* text; bool raw; bool ok; } cases[] = {
        {"empty file", "", true, false},
        {"garbage", "\x01\x02not a record\xff\n", true, false},
        {"no trailing newline", "QHCNS 1 group/hostile", true, false},
        {"foreign group id", NULL, false, false},
        {"bad header version", NULL, false, false},
        {"record before header", NULL, false, false},
        {"torn final record", NULL, false, false},
        {"checksum mismatch", NULL, false, false},
        {"log index gap", NULL, false, false},
        {"entry term above current", NULL, false, false},
        {"journal generation regressed", NULL, false, false},
        {"odd payload hex", NULL, false, false},
        {"oversized payload", NULL, false, false},
        {"epoch below term", NULL, false, false},
        {"commit past log tail", NULL, false, false},
        {"unknown record type", NULL, false, false},
        {"valid minimal file", NULL, false, true},
    };

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        snprintf(path, sizeof(path), "%s/hostile%zu.rec", dir, i);
        FILE* f = fopen(path, "w");
        assert(f);

        if (cases[i].raw) {
            fputs(cases[i].text, f);
        } else if (strcmp(cases[i].name, "foreign group id") == 0) {
            t_wline(f, "QHCNS 1 group/other");
        } else if (strcmp(cases[i].name, "bad header version") == 0) {
            t_wline(f, "QHCNS 2 group/hostile");
        } else if (strcmp(cases[i].name, "record before header") == 0) {
            t_wline(f, "C 0");
            t_wline(f, "QHCNS 1 group/hostile");
        } else if (strcmp(cases[i].name, "torn final record") == 0) {
            t_wline(f, "QHCNS 1 group/hostile");
            t_wline(f, "V 3 - 3");
            fputs("L 1 3 50 600 2 0 0 deadbe", f); /* no newline, mid-write */
        } else if (strcmp(cases[i].name, "checksum mismatch") == 0) {
            t_wline(f, "QHCNS 1 group/hostile");
            fprintf(f, "C 1 %016llx\n",
                    (unsigned long long)t_fnv("C 2", 3u)); /* wrong body */
        } else if (strcmp(cases[i].name, "log index gap") == 0) {
            t_wline(f, "QHCNS 1 group/hostile");
            t_wline(f, "V 1 - 1");
            t_wline(f, "L 1 1 10 100 0 0 0 aa");
            t_wline(f, "L 3 1 11 101 0 0 0 bb");
        } else if (strcmp(cases[i].name, "entry term above current") == 0) {
            t_wline(f, "QHCNS 1 group/hostile");
            t_wline(f, "V 1 - 1");
            t_wline(f, "L 1 9 10 100 0 0 0 aa");
        } else if (strcmp(cases[i].name, "journal generation regressed") == 0) {
            t_wline(f, "QHCNS 1 group/hostile");
            t_wline(f, "V 2 - 2");
            t_wline(f, "L 1 1 10 100 0 0 0 aa");
            t_wline(f, "L 2 2 10 101 0 0 0 bb");
        } else if (strcmp(cases[i].name, "odd payload hex") == 0) {
            t_wline(f, "QHCNS 1 group/hostile");
            t_wline(f, "V 1 - 1");
            t_wline(f, "L 1 1 10 100 0 0 0 aab");
        } else if (strcmp(cases[i].name, "oversized payload") == 0) {
            char big[300]; /* 300 hex chars > 2*PAYLOAD_MAX (256) */
            memset(big, 'a', sizeof(big));
            big[sizeof(big) - 1u] = '\0';
            t_wline(f, "QHCNS 1 group/hostile");
            t_wline(f, "V 1 - 1");
            snprintf(body, sizeof(body), "L 1 1 10 100 0 0 0 %s", big);
            t_wline(f, body);
        } else if (strcmp(cases[i].name, "epoch below term") == 0) {
            t_wline(f, "QHCNS 1 group/hostile");
            t_wline(f, "V 5 - 4");
        } else if (strcmp(cases[i].name, "commit past log tail") == 0) {
            t_wline(f, "QHCNS 1 group/hostile");
            t_wline(f, "V 1 - 1");
            t_wline(f, "L 1 1 10 100 0 0 0 aa");
            t_wline(f, "C 2");
        } else if (strcmp(cases[i].name, "unknown record type") == 0) {
            t_wline(f, "QHCNS 1 group/hostile");
            t_wline(f, "X 1 2 3");
        } else if (strcmp(cases[i].name, "valid minimal file") == 0) {
            t_wline(f, "QHCNS 1 group/hostile");
            snprintf(body, sizeof(body), "V 1 %s 1", self_hex);
            t_wline(f, body);
            t_wline(f, "L 1 1 42 700 3 0 0 deadbeef");
            t_wline(f, "C 1");
        } else {
            assert(!"unreachable case");
        }
        fclose(f);

        bool opened = hostile_open(path, self, self_hex);
        if (cases[i].ok) {
            assert(opened);
        } else {
            assert(!opened);
        }
        printf("  decoder %-28s -> %s\n", cases[i].name,
               opened ? "accepted" : "refused");
        remove(path);
    }

    /* The accepted file must decode into the exact persisted state. */
    snprintf(path, sizeof(path), "%s/hostile-valid.recheck", dir);
    FILE* f = fopen(path, "w");
    assert(f);
    t_wline(f, "QHCNS 1 group/hostile");
    snprintf(body, sizeof(body), "V 1 %s 1", self_hex);
    t_wline(f, body);
    t_wline(f, "L 1 1 42 700 3 0 0 deadbeef");
    t_wline(f, "C 1");
    fclose(f);

    qihse_consensus_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    snprintf(cfg.group_id, sizeof(cfg.group_id), "group/hostile");
    cfg.self = *self;
    cfg.member_count = 1u;
    cfg.members[0] = *self;
    cfg.election_timeout_base_ms = 150u;
    cfg.election_timeout_spread_ms = 300u;
    cfg.heartbeat_interval_ms = 50u;
    snprintf(cfg.record_path, sizeof(cfg.record_path), "%s", path);
    qihse_consensus_t* cs = qihse_consensus_open(&cfg, NULL, NULL);
    assert(cs);
    assert(qihse_consensus_term(cs) == 1u);
    assert(qihse_consensus_fencing_epoch(cs) == 1u);
    assert(qihse_consensus_last_log_index(cs) == 1u);
    assert(qihse_consensus_commit_index(cs) == 1u);
    qihse_uuid_t voted;
    assert(qihse_consensus_voted_for(cs, &voted));
    assert(qihse_uuid_equal(&voted, self));
    qihse_consensus_close(cs);
    remove(path);

    printf("PASS (f) decoder hostile input: every corruption fails closed, "
           "valid records decode exactly\n");
}

/* ── (g) Invariant 1: classified reads need a principal ──────────────────── */

static void test_invariant1_classified_access(qihse_user_t* op) {
    assert(op);

    /* Low-clearance principal created BY the operator (invariant 2: the
     * analyst cannot create anything, and nobody creates above themselves). */
    qihse_user_t* analyst =
        qihse_auth_create_user(op, 61001u, QIHSE_ROLE_ANALYST,
                               1u, 0u, "AnalystPass1!", false);
    assert(analyst);

    harness_t h;
    h_init(&h, "class");

    int leader = h_elect(&h);
    assert(leader >= 0);

    /* Entry 1: unclassified. Entry 2: above the analyst's clearance. */
    qihse_hlc_t hlc1 = {800u, 0u};
    assert(qihse_consensus_propose(h.node[leader], op, 400u, hlc1, 0u, 0u,
                                    "open-data", 9u));
    qihse_hlc_t hlc2 = {810u, 0u};
    assert(qihse_consensus_propose(h.node[leader], op, 401u, hlc2, 3u, 0u,
                                    "secret-payload", 14u));
    assert(h_commit_reached(&h, 2u));

    /* A zero-length payload is refused at the boundary: the record encoder
     * would write an empty hex token the replay decoder cannot accept, so an
     * accepted empty proposal would be durable in memory but unreplayable
     * after restart.  Nothing may be appended by the refusal. */
    assert(!qihse_consensus_propose(h.node[leader], op, 402u, hlc2, 0u, 0u,
                                    "x", 0u));
    assert(!qihse_consensus_propose(h.node[leader], op, 403u, hlc2, 0u, 0u,
                                    NULL, 4u));
    assert(qihse_consensus_last_log_index(h.node[leader]) == 2u);

    /* Operator sees both committed entries. */
    qihse_consensus_entry_t out[4];
    size_t got = 0;
    assert(qihse_consensus_read_committed(h.node[leader], op, 1u, out, 4u, &got));
    assert(got == 2u);
    assert(out[1].classif == 3u);
    assert(memcmp(out[1].payload, "secret-payload", 14u) == 0);

    /* Analyst: the classified entry is withheld — never disclosed. */
    got = 0;
    memset(out, 0, sizeof(out));
    assert(qihse_consensus_read_committed(h.node[leader], analyst, 1u, out, 4u, &got));
    assert(got == 1u);
    assert(memcmp(out[0].payload, "open-data", 9u) == 0);
    for (size_t j = 0; j < got; j++) {
        assert(out[j].classif == 0u);
        assert(memcmp(out[j].payload, "secret", 6u) != 0);
    }

    qihse_consensus_counters_t c;
    qihse_consensus_get_counters(h.node[leader], &c);
    assert(c.auth_failures >= 1u); /* the withheld entry was denied, logged */

    /* NULL principal: refused outright, fail closed. */
    got = 99u;
    assert(!qihse_consensus_read_committed(h.node[leader], NULL, 1u, out, 4u, &got));
    assert(got == 0u);

    /* Write path enforces the same boundary: the analyst cannot propose a
     * payload above its own clearance, and NULL cannot propose classified. */
    qihse_hlc_t hlc3 = {820u, 0u};
    assert(!qihse_consensus_propose(h.node[leader], analyst, 402u, hlc3, 3u, 0u,
                                     "smuggle", 7u));
    assert(!qihse_consensus_propose(h.node[leader], NULL, 403u, hlc3, 3u, 5u,
                                     "anon", 4u));
    assert(qihse_consensus_last_log_index(h.node[leader]) == 2u);
    /* An unclassified propose with no principal is still allowed. */
    assert(qihse_consensus_propose(h.node[leader], NULL, 404u, hlc3, 0u, 0u,
                                    "plain", 5u));

    h_free(&h);
    printf("PASS (g) invariant 1: low-clearance principal denied classified "
           "committed entry; NULL user never a bypass\n");
}

/* ── Shared compaction-test helpers ──────────────────────────────────────── */

/* Full-field entry equality: what "byte-identical convergence" means here. */
static bool t_entry_eq(const qihse_consensus_entry_t* a,
                       const qihse_consensus_entry_t* b) {
    if (a->index != b->index || a->term != b->term ||
        a->journal_generation != b->journal_generation) return false;
    if (a->hlc.physical_ms != b->hlc.physical_ms ||
        a->hlc.logical != b->hlc.logical) return false;
    if (a->classif != b->classif || a->sci != b->sci) return false;
    if (a->payload_len != b->payload_len) return false;
    return memcmp(a->payload, b->payload, a->payload_len) == 0;
}

/* Read every committed entry visible to `user` (indices 1..commit). */
static size_t t_read_all(const qihse_consensus_t* node, const qihse_user_t* user,
                         qihse_consensus_entry_t* out, size_t cap) {
    size_t got = 0;
    assert(qihse_consensus_read_committed(node, user, 1u, out, cap, &got));
    return got;
}

/* Every node's committed view must equal the leader's, entry for entry. */
static void t_assert_views_match(harness_t* h, int leader, const qihse_user_t* user,
                                 size_t cap) {
    static qihse_consensus_entry_t ref[64];
    static qihse_consensus_entry_t got[64];
    assert(cap <= 64u);
    size_t nref = t_read_all(h->node[leader], user, ref, cap);
    for (size_t j = 0; j < N; j++) {
        if (!h->node[j]) continue;
        size_t ngot = t_read_all(h->node[j], user, got, cap);
        assert(ngot == nref);
        for (size_t k = 0; k < nref; k++) {
            if (!t_entry_eq(&ref[k], &got[k])) {
                fprintf(stderr, "view mismatch node %zu idx %llu\n", j,
                        (unsigned long long)got[k].index);
                assert(!"view mismatch");
            }
        }
    }
}

static void t_sever(harness_t* h, int a) {
    for (size_t j = 0; j < N; j++) {
        h->drop[a][j] = true;
        h->drop[j][a] = true;
    }
}

static void t_heal(harness_t* h) {
    memset(h->drop, 0, sizeof(h->drop));
}

/* Test-side mirror of the module's canonical snapshot digest (documented
 * in the header), used to craft structurally valid record files. */
static uint64_t t_fold64(uint64_t h, uint64_t v) {
    for (unsigned i = 0; i < 8u; i++) {
        h ^= (uint8_t)(v & 0xFFu);
        h *= 0x100000001B3ULL;
        v >>= 8;
    }
    return h;
}

static uint64_t t_snap_digest(const qihse_consensus_entry_t* es, size_t n) {
    uint64_t h = 0xCBF2CE48D222D25BULL;
    for (size_t i = 0; i < n; i++) {
        h = t_fold64(h, es[i].index);
        h = t_fold64(h, es[i].term);
        h = t_fold64(h, es[i].journal_generation);
        h = t_fold64(h, es[i].hlc.physical_ms);
        h = t_fold64(h, es[i].hlc.logical);
        h = t_fold64(h, es[i].classif);
        h = t_fold64(h, es[i].sci);
        h = t_fold64(h, (uint64_t)es[i].type);
        h = t_fold64(h, (uint64_t)es[i].payload_len);
        for (size_t b = 0; b < es[i].payload_len; b++) {
            h ^= es[i].payload[b];
            h *= 0x100000001B3ULL;
        }
    }
    return h;
}

/* Crafted-record writers mirroring the module's encoder exactly. */
static void t_write_entry_line(FILE* f, const char* tag,
                               const qihse_consensus_entry_t* e) {
    char hex[2 * QIHSE_CONSENSUS_PAYLOAD_MAX + 1u];
    char body[512];
    t_hex_encode(e->payload, e->payload_len, hex);
    snprintf(body, sizeof(body), "%s %llu %llu %llu %llu %u %u %u %s",
             tag,
             (unsigned long long)e->index, (unsigned long long)e->term,
             (unsigned long long)e->journal_generation,
             (unsigned long long)e->hlc.physical_ms,
             (unsigned)e->hlc.logical, (unsigned)e->classif,
             (unsigned)e->sci, hex);
    t_wline(f, body);
}

static void t_write_snapshot_header(FILE* f, uint64_t last, uint64_t lterm,
                                    uint64_t epoch, uint64_t gen,
                                    uint64_t digest, uint64_t count) {
    char body[128];
    snprintf(body, sizeof(body), "S %llu %llu %llu %llu %016llx %llu",
             (unsigned long long)last, (unsigned long long)lterm,
             (unsigned long long)epoch, (unsigned long long)gen,
             (unsigned long long)digest, (unsigned long long)count);
    t_wline(f, body);
}

/* Single-member open for crafted files (mirrors hostile_open). */
static qihse_consensus_t* t_open_single(const char* path,
                                        const qihse_uuid_t* self) {
    qihse_consensus_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    snprintf(cfg.group_id, sizeof(cfg.group_id), "group/hostile");
    cfg.self = *self;
    cfg.member_count = 1u;
    cfg.members[0] = *self;
    cfg.election_timeout_base_ms = 150u;
    cfg.election_timeout_spread_ms = 300u;
    cfg.heartbeat_interval_ms = 50u;
    snprintf(cfg.record_path, sizeof(cfg.record_path), "%s", path);
    return qihse_consensus_open(&cfg, NULL, NULL);
}

/* Build a crafted entry with a small deterministic payload. */
static qihse_consensus_entry_t t_craft_entry(uint64_t idx, uint64_t term,
                                             uint64_t gen) {
    qihse_consensus_entry_t e;
    memset(&e, 0, sizeof(e));
    e.index = idx;
    e.term = term;
    e.journal_generation = gen;
    e.hlc.physical_ms = 100u + idx;
    e.hlc.logical = 0u;
    e.classif = 0u;
    e.sci = 0u;
    e.payload[0] = (uint8_t)('a' + (idx % 26u));
    e.payload[1] = (uint8_t)('0' + (idx % 10u));
    e.payload_len = 2u;
    return e;
}

/* ── (h) Far-behind follower catches up via snapshot + tail ──────────────── */

static void test_snapshot_catchup(const qihse_user_t* op) {
    harness_t h;
    h_init_ex(&h, "snap", 3u);

    int leader = h_elect(&h);
    assert(leader >= 0);
    uint64_t term = qihse_consensus_term(h.node[leader]);

    /* Follower F is partitioned away BEFORE any entry exists. */
    int lag = (leader + 2u) % N;
    t_sever(&h, lag);

    /* Four entries: enough to cross the threshold and force a compaction
     * (retained log 4 > threshold 3, all committed). */
    for (uint64_t g = 100u; g <= 103u; g++) {
        char payload[32];
        snprintf(payload, sizeof(payload), "snap-%llu", (unsigned long long)g);
        qihse_hlc_t hlc = {g * 10u, 0u};
        assert(qihse_consensus_propose(h.node[leader], op, g, hlc, 0u, 0u,
                                        payload, strlen(payload)));
    }
    assert(h_commit_reached_skip(&h, 4u, lag));

    qihse_consensus_counters_t lc;
    qihse_consensus_get_counters(h.node[leader], &lc);
    assert(lc.snapshots_created >= 1u);
    uint64_t snap_idx = qihse_consensus_snapshot_index(h.node[leader]);
    assert(snap_idx >= 1u && snap_idx <= 4u);

    /* Three more entries stay uncompacted (3 <= threshold beyond the
     * boundary): the tail a catching-up follower must still receive as
     * plain appends after the snapshot. */
    for (uint64_t g = 104u; g <= 106u; g++) {
        char payload[32];
        snprintf(payload, sizeof(payload), "tail-%llu", (unsigned long long)g);
        qihse_hlc_t hlc = {g * 10u, 0u};
        assert(qihse_consensus_propose(h.node[leader], op, g, hlc, 0u, 0u,
                                        payload, strlen(payload)));
    }
    assert(h_commit_reached_skip(&h, 7u, lag));
    assert(qihse_consensus_last_log_index(h.node[leader]) == 7u);
    assert(qihse_consensus_commit_index(h.node[lag]) == 0u); /* still far behind */

    /* Heal: F must catch up through snapshot + tail and converge. */
    t_heal(&h);
    bool converged = false;
    for (unsigned i = 0; i < 600u && !converged; i++) {
        h_tick(&h, 10u);
        converged = qihse_consensus_commit_index(h.node[lag]) == 7u &&
                    qihse_consensus_last_log_index(h.node[lag]) == 7u &&
                    qihse_consensus_snapshot_index(h.node[lag]) == snap_idx;
    }
    assert(converged);
    assert(h.snap_seen);

    qihse_consensus_counters_t fc;
    qihse_consensus_get_counters(h.node[lag], &fc);
    assert(fc.snapshots_installed >= 1u); /* the snapshot really was used */
    assert(fc.snapshot_rejections == 0u);

    /* Byte/state equality across the whole group. */
    t_assert_views_match(&h, leader, op, 16u);
    for (size_t j = 0; j < N; j++) {
        assert(qihse_consensus_term(h.node[j]) >= term);
        assert(qihse_consensus_commit_index(h.node[j]) == 7u);
    }

    h_free(&h);
    printf("PASS (h) far-behind follower catches up via snapshot + tail, "
           "converges byte-identically\n");
}

/* ── (i) Compaction under churn across multiple terms ────────────────────── */

static void test_compaction_churn(const qihse_user_t* op) {
    harness_t h;
    h_init_ex(&h, "churn", 2u);

    uint64_t gen = 500u;
    uint64_t total = 0u;
    uint64_t prev_term = 0u;
    uint64_t compactions = 0u;

    for (unsigned round = 0u; round < 3u; round++) {
        int leader = h_elect(&h);
        assert(leader >= 0);
        uint64_t term = qihse_consensus_term(h.node[leader]);
        assert(term > prev_term);
        prev_term = term;

        /* A different laggard every round. */
        int lag = (leader + 1u + (int)round) % N;
        t_sever(&h, lag);

        for (uint64_t k = 0u; k < 5u; k++) {
            char payload[32];
            snprintf(payload, sizeof(payload), "churn-r%u-k%llu", round,
                     (unsigned long long)k);
            qihse_hlc_t hlc = {gen * 10u, 0u};
            assert(qihse_consensus_propose(h.node[leader], op, gen, hlc,
                                            (uint16_t)(k == 2u ? 3u : 0u),
                                            0u, payload, strlen(payload)));
            gen++;
            total++;
        }
        assert(h_commit_reached_skip(&h, total, lag));

        qihse_consensus_counters_t lc;
        qihse_consensus_get_counters(h.node[leader], &lc);
        assert(lc.snapshots_created >= 1u);
        compactions += lc.snapshots_created;
        assert(qihse_consensus_snapshot_index(h.node[leader]) > 0u);

        t_heal(&h);
        bool converged = false;
        for (unsigned i = 0; i < 600u && !converged; i++) {
            h_tick(&h, 10u);
            converged = qihse_consensus_commit_index(h.node[lag]) == total;
        }
        assert(converged);
        t_assert_views_match(&h, leader, op, 64u);

        /* Restart the leader: it reloads snapshot + tail from its record
         * file, steps down, and the next round elects in a fresh term. */
        h_restart(&h, leader, "churn");
        assert(qihse_consensus_commit_index(h.node[leader]) == total);
        assert(qihse_consensus_snapshot_index(h.node[leader]) > 0u);
        for (unsigned i = 0; i < 400u; i++) h_tick(&h, 10u);
    }

    assert(compactions >= 3u);
    for (size_t j = 0; j < N; j++) {
        assert(qihse_consensus_commit_index(h.node[j]) == total);
    }
    t_assert_views_match(&h, h_leader(&h) >= 0 ? h_leader(&h) : 0, op, 64u);

    h_free(&h);
    printf("PASS (i) compaction under churn: %llu entries, repeated "
           "compact/catch-up cycles across terms\n", (unsigned long long)total);
}

/* ── (j) Tampered / stale snapshots refused ──────────────────────────────── */

static void test_snapshot_tamper_refused(void) {
    harness_t h;
    h_init_ex(&h, "tamper", 3u);

    int leader = h_elect(&h);
    assert(leader >= 0);
    int lag = (leader + 2u) % N;
    t_sever(&h, lag);

    for (uint64_t g = 200u; g <= 205u; g++) {
        char payload[32];
        snprintf(payload, sizeof(payload), "tamper-%llu", (unsigned long long)g);
        qihse_hlc_t hlc = {g * 10u, 0u};
        assert(qihse_consensus_propose(h.node[leader], NULL, g, hlc, 0u, 0u,
                                        payload, strlen(payload)));
    }
    assert(h_commit_reached_skip(&h, 6u, lag));
    assert(qihse_consensus_snapshot_index(h.node[leader]) > 0u);

    /* A real SNAPSHOT message was emitted toward the laggard (and dropped
     * by the harness partition); the pristine copy is our test vector. */
    bool saw = false;
    for (unsigned i = 0; i < 200u && !saw; i++) {
        h_tick_one(&h, leader, 10u);
        saw = h.snap_seen && h_index(&h, &h.snap_msg.to) == lag;
    }
    assert(saw);

    uint64_t lag_log = qihse_consensus_last_log_index(h.node[lag]);
    uint64_t lag_commit = qihse_consensus_commit_index(h.node[lag]);
    assert(lag_log < qihse_consensus_snapshot_index(h.node[leader]));

    qihse_consensus_counters_t before;
    qihse_consensus_get_counters(h.node[lag], &before);

    /* The laggard campaigned while partitioned, so its term/epoch run
     * ahead of the captured message; refresh the envelope to the
     * receiver's current values (as a re-delivery would) so each probe
     * isolates exactly one refusal reason. */
    uint64_t lag_term = qihse_consensus_term(h.node[lag]);
    uint64_t lag_epoch = qihse_consensus_fencing_epoch(h.node[lag]);

    /* (1) Tampered digest: refused, state untouched. */
    qihse_consensus_msg_t m = h.snap_msg;
    m.term = lag_term;
    m.fencing_epoch = lag_epoch;
    m.u.snapshot.digest ^= 0xA5A5A5A5A5A5A5A5ULL;
    qihse_consensus_receive(h.node[lag], &m);
    qihse_consensus_counters_t after;
    qihse_consensus_get_counters(h.node[lag], &after);
    assert(after.snapshot_rejections == before.snapshot_rejections + 1u);
    assert(qihse_consensus_last_log_index(h.node[lag]) == lag_log);
    assert(qihse_consensus_commit_index(h.node[lag]) == lag_commit);
    assert(qihse_consensus_snapshot_index(h.node[lag]) == 0u);

    /* (2) Tampered payload under a valid digest claim: refused. */
    m = h.snap_msg;
    m.term = lag_term;
    m.fencing_epoch = lag_epoch;
    m.u.snapshot.entries[1].payload[0] ^= 0xFFu;
    qihse_consensus_receive(h.node[lag], &m);
    qihse_consensus_get_counters(h.node[lag], &after);
    assert(after.snapshot_rejections == before.snapshot_rejections + 2u);
    assert(qihse_consensus_snapshot_index(h.node[lag]) == 0u);

    /* (3) Malformed: count disagrees with last_included_index. */
    m = h.snap_msg;
    m.term = lag_term;
    m.fencing_epoch = lag_epoch;
    m.u.snapshot.entry_count = m.u.snapshot.last_included_index + 1u;
    qihse_consensus_receive(h.node[lag], &m);
    qihse_consensus_get_counters(h.node[lag], &after);
    assert(after.snapshot_rejections == before.snapshot_rejections + 3u);

    /* (4) Stale fencing epoch: fenced before any snapshot logic runs. */
    m = h.snap_msg;
    m.term = lag_term;
    m.fencing_epoch = lag_epoch - 1u;
    qihse_consensus_receive(h.node[lag], &m);
    qihse_consensus_get_counters(h.node[lag], &after);
    assert(after.stale_epoch_rejections == before.stale_epoch_rejections + 1u);
    assert(qihse_consensus_snapshot_index(h.node[lag]) == 0u);
    assert(qihse_consensus_last_log_index(h.node[lag]) == lag_log);
    assert(qihse_consensus_commit_index(h.node[lag]) == lag_commit);

    /* (5) Positive control: the pristine snapshot installs. */
    m = h.snap_msg;
    m.term = lag_term;
    m.fencing_epoch = lag_epoch;
    qihse_consensus_receive(h.node[lag], &m);
    qihse_consensus_get_counters(h.node[lag], &after);
    assert(after.snapshots_installed == before.snapshots_installed + 1u);
    assert(qihse_consensus_snapshot_index(h.node[lag]) ==
           h.snap_msg.u.snapshot.last_included_index);

    /* And the group still converges after all the abuse. */
    t_heal(&h);
    bool converged = false;
    for (unsigned i = 0; i < 600u && !converged; i++) {
        h_tick(&h, 10u);
        converged = qihse_consensus_commit_index(h.node[lag]) == 6u;
    }
    assert(converged);

    h_free(&h);
    printf("PASS (j) tampered digest/payload/count and stale-epoch snapshots "
           "refused; counters increment; pristine installs; group converges\n");
}

/* ── (k) Snapshot persistence + crash-mid-compaction recovery ────────────── */

static void test_snapshot_restart_and_crash(const qihse_uuid_t* self,
                                            const qihse_user_t* op) {
    char path[192];
    char dir[128];
    snprintf(dir, sizeof(dir), "build/test_consensus_crash_XXXXXX");
    if (!mkdtemp(dir)) {
        snprintf(dir, sizeof(dir), "test_consensus_crash_XXXXXX");
        assert(mkdtemp(dir));
    }

    /* Live persistence first: real compaction, snapshot + tail on disk. */
    {
        harness_t h;
        h_init_ex(&h, "srestart", 3u);
        int leader = h_elect(&h);
        assert(leader >= 0);

        for (uint64_t g = 300u; g <= 307u; g++) {
            char payload[32];
            snprintf(payload, sizeof(payload), "durable-%llu",
                     (unsigned long long)g);
            qihse_hlc_t hlc = {g * 10u, 0u};
            assert(qihse_consensus_propose(h.node[leader], op, g, hlc, 0u, 0u,
                                            payload, strlen(payload)));
        }
        assert(h_commit_reached(&h, 8u));
        for (uint64_t g = 308u; g <= 309u; g++) {
            char payload[32];
            snprintf(payload, sizeof(payload), "tail-%llu",
                     (unsigned long long)g);
            qihse_hlc_t hlc = {g * 10u, 0u};
            assert(qihse_consensus_propose(h.node[leader], op, g, hlc, 0u, 0u,
                                            payload, strlen(payload)));
        }
        assert(h_commit_reached(&h, 10u));

        uint64_t term = qihse_consensus_term(h.node[leader]);
        uint64_t epoch = qihse_consensus_fencing_epoch(h.node[leader]);
        uint64_t snap = qihse_consensus_snapshot_index(h.node[leader]);
        assert(snap >= 1u);

        static qihse_consensus_entry_t before[16];
        size_t nbefore = t_read_all(h.node[leader], op, before, 16u);
        assert(nbefore == 10u);

        h_restart(&h, leader, "srestart");
        assert(qihse_consensus_term(h.node[leader]) == term);
        assert(qihse_consensus_fencing_epoch(h.node[leader]) == epoch);
        assert(qihse_consensus_commit_index(h.node[leader]) == 10u);
        assert(qihse_consensus_last_log_index(h.node[leader]) == 10u);
        assert(qihse_consensus_snapshot_index(h.node[leader]) == snap);

        static qihse_consensus_entry_t after[16];
        size_t nafter = t_read_all(h.node[leader], op, after, 16u);
        assert(nafter == nbefore);
        for (size_t i = 0u; i < nbefore; i++) {
            assert(t_entry_eq(&before[i], &after[i]));
        }
        h_free(&h);
    }

    /* Crafted crash points.  History: 6 entries in term 1, all committed;
     * a compaction to 4 was in flight. */
    qihse_consensus_entry_t e[6];
    for (uint64_t i = 0u; i < 6u; i++) {
        e[i] = t_craft_entry(i + 1u, 1u, 10u + i);
    }
    uint64_t dig4 = t_snap_digest(e, 4u);

    /* Case 1: crash AFTER the snapshot write, BEFORE the swap record —
     * an S header and two SE lines, no T.  The previous durable state
     * (the uncompacted 6-entry log) must survive untouched. */
    for (int torn = 0; torn < 2; torn++) {
        snprintf(path, sizeof(path), "%s/crash%d.rec", dir, torn);
        FILE* f = fopen(path, "w");
        assert(f);
        t_wline(f, "QHCNS 1 group/hostile");
        t_wline(f, "V 1 - 1");
        for (uint64_t i = 0u; i < 6u; i++) t_write_entry_line(f, "L", &e[i]);
        t_wline(f, "C 6");
        t_write_snapshot_header(f, 4u, 1u, 1u, 13u, dig4, 4u);
        t_write_entry_line(f, "SE", &e[0]);
        t_write_entry_line(f, "SE", &e[1]);
        if (torn) {
            /* Torn third SE line: bytes reached the file, no newline. */
            fputs("SE 3 1 12 103 0 0 0 aa", f);
        }
        fclose(f);

        qihse_consensus_t* cs = t_open_single(path, self);
        assert(cs); /* rolled back, not lost */
        assert(qihse_consensus_snapshot_index(cs) == 0u);
        assert(qihse_consensus_last_log_index(cs) == 6u);
        assert(qihse_consensus_commit_index(cs) == 6u);
        qihse_consensus_close(cs);
        remove(path);
        printf("  crash %s -> uncompacted state preserved\n",
               torn ? "torn SE tail" : "snapshot written, no swap");
    }

    /* Case 2: crash AFTER the swap record: the transaction is complete,
     * the compacted state (snapshot 4 + tail 2) is exactly what loads. */
    snprintf(path, sizeof(path), "%s/crash2.rec", dir);
    {
        FILE* f = fopen(path, "w");
        assert(f);
        t_wline(f, "QHCNS 1 group/hostile");
        t_wline(f, "V 1 - 1");
        for (uint64_t i = 0u; i < 6u; i++) t_write_entry_line(f, "L", &e[i]);
        t_wline(f, "C 6");
        t_write_snapshot_header(f, 4u, 1u, 1u, 13u, dig4, 4u);
        for (uint64_t i = 0u; i < 4u; i++) t_write_entry_line(f, "SE", &e[i]);
        t_wline(f, "T 5");
        /* Entries appended after the compaction continue the log. */
        qihse_consensus_entry_t e7 = t_craft_entry(7u, 1u, 17u);
        qihse_consensus_entry_t e8 = t_craft_entry(8u, 1u, 18u);
        t_write_entry_line(f, "L", &e7);
        t_write_entry_line(f, "L", &e8);
        t_wline(f, "C 8");
        fclose(f);

        qihse_consensus_t* cs = t_open_single(path, self);
        assert(cs);
        assert(qihse_consensus_snapshot_index(cs) == 4u);
        assert(qihse_consensus_last_log_index(cs) == 8u);
        assert(qihse_consensus_commit_index(cs) == 8u);
        /* Committed reads span snapshot and tail, byte-exact. */
        qihse_consensus_entry_t out[8];
        size_t got = 0u;
        assert(qihse_consensus_read_committed(cs, op, 1u, out, 8u, &got));
        assert(got == 8u);
        for (uint64_t i = 0u; i < 6u; i++) assert(t_entry_eq(&out[i], &e[i]));
        assert(t_entry_eq(&out[6], &e7));
        assert(t_entry_eq(&out[7], &e8));
        qihse_consensus_close(cs);
        remove(path);
        printf("  crash after swap -> snapshot + tail loaded exactly\n");
    }

    rmdir(dir);
    printf("PASS (k) snapshot + tail persist through restart; every "
           "crash-mid-compaction point recovers the correct durable state\n");
}

/* ── (f2) Hostile decoder input: the snapshot records ────────────────────── */

static void test_decoder_hostile_snapshot(const char* dir,
                                          const qihse_uuid_t* self) {
    char path[192];

    qihse_consensus_entry_t e[4];
    for (uint64_t i = 0u; i < 4u; i++) {
        e[i] = t_craft_entry(i + 1u, 1u, 10u + i);
    }
    uint64_t dig = t_snap_digest(e, 4u);

    struct {
        const char* name;
        bool ok;
    } cases[] = {
        {"snapshot digest mismatch", false},
        {"snapshot count != last index", false},
        {"SE outside a transaction", false},
        {"SE index gap in block", false},
        {"SE diverges from replayed log", false},
        {"T does not match pending", false},
        {"record inside open transaction", false},
        {"SE oversized payload", false},
        {"SE overlong line", false},
        {"second snapshot not newer", false},
        {"snapshot epoch below last term", false},
        {"SE term above current term", false},
        {"snapshot last term mismatches tail", false},
        {"valid snapshot + tail", true},
    };

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        snprintf(path, sizeof(path), "%s/hsnap%zu.rec", dir, i);
        FILE* f = fopen(path, "w");
        assert(f);
        t_wline(f, "QHCNS 1 group/hostile");
        t_wline(f, "V 2 - 2");
        for (uint64_t k = 0u; k < 4u; k++) t_write_entry_line(f, "L", &e[k]);
        t_wline(f, "C 4");

        if (strcmp(cases[i].name, "snapshot digest mismatch") == 0) {
            t_write_snapshot_header(f, 4u, 1u, 2u, 13u, dig ^ 1u, 4u);
            for (uint64_t k = 0u; k < 4u; k++) t_write_entry_line(f, "SE", &e[k]);
            t_wline(f, "T 5");
        } else if (strcmp(cases[i].name, "snapshot count != last index") == 0) {
            t_write_snapshot_header(f, 4u, 1u, 2u, 13u, dig, 3u);
            for (uint64_t k = 0u; k < 4u; k++) t_write_entry_line(f, "SE", &e[k]);
            t_wline(f, "T 5");
        } else if (strcmp(cases[i].name, "SE outside a transaction") == 0) {
            t_write_entry_line(f, "SE", &e[0]);
        } else if (strcmp(cases[i].name, "SE index gap in block") == 0) {
            t_write_snapshot_header(f, 4u, 1u, 2u, 13u, dig, 4u);
            t_write_entry_line(f, "SE", &e[0]);
            qihse_consensus_entry_t gap = t_craft_entry(3u, 1u, 12u);
            t_write_entry_line(f, "SE", &gap); /* index 3, expected 2 */
            t_wline(f, "T 5");
        } else if (strcmp(cases[i].name, "SE diverges from replayed log") == 0) {
            /* SE 2 restates L 2 with the same (index, term) but a
             * different payload: the block must fail closed, not
             * overwrite replayed history. */
            qihse_consensus_entry_t bad = t_craft_entry(2u, 1u, 11u);
            bad.payload[0] = (uint8_t)(bad.payload[0] ^ 0x20u);
            t_write_snapshot_header(f, 4u, 1u, 2u, 13u, dig, 4u);
            t_write_entry_line(f, "SE", &e[0]);
            t_write_entry_line(f, "SE", &bad);
            t_write_entry_line(f, "SE", &e[2]);
            t_write_entry_line(f, "SE", &e[3]);
            t_wline(f, "T 5");
        } else if (strcmp(cases[i].name, "T does not match pending") == 0) {
            t_write_snapshot_header(f, 4u, 1u, 2u, 13u, dig, 4u);
            for (uint64_t k = 0u; k < 4u; k++) t_write_entry_line(f, "SE", &e[k]);
            t_wline(f, "T 6"); /* expected T 5 */
        } else if (strcmp(cases[i].name, "record inside open transaction") == 0) {
            t_write_snapshot_header(f, 4u, 1u, 2u, 13u, dig, 4u);
            t_write_entry_line(f, "SE", &e[0]);
            t_wline(f, "V 2 - 2"); /* non-SE/T inside the transaction */
        } else if (strcmp(cases[i].name, "SE oversized payload") == 0) {
            char big[300];
            memset(big, 'a', sizeof(big));
            big[sizeof(big) - 1u] = '\0';
            char body[512];
            t_write_snapshot_header(f, 4u, 1u, 2u, 13u, dig, 4u);
            snprintf(body, sizeof(body), "SE 1 1 10 101 0 0 0 %s", big);
            t_wline(f, body);
        } else if (strcmp(cases[i].name, "SE overlong line") == 0) {
            char big[1300];
            memset(big, 'b', sizeof(big));
            big[sizeof(big) - 1u] = '\0';
            char body[1400];
            t_write_snapshot_header(f, 4u, 1u, 2u, 13u, dig, 4u);
            snprintf(body, sizeof(body), "SE 1 1 10 101 0 0 0 %s", big);
            t_wline(f, body);
        } else if (strcmp(cases[i].name, "second snapshot not newer") == 0) {
            t_write_snapshot_header(f, 4u, 1u, 2u, 13u, dig, 4u);
            for (uint64_t k = 0u; k < 4u; k++) t_write_entry_line(f, "SE", &e[k]);
            t_wline(f, "T 5");
            t_write_snapshot_header(f, 4u, 1u, 2u, 13u, dig, 4u); /* not newer */
            t_write_entry_line(f, "SE", &e[0]);
        } else if (strcmp(cases[i].name, "snapshot epoch below last term") == 0) {
            t_write_snapshot_header(f, 4u, 5u, 4u, 13u, dig, 4u); /* epoch < lterm */
            for (uint64_t k = 0u; k < 4u; k++) t_write_entry_line(f, "SE", &e[k]);
            t_wline(f, "T 5");
        } else if (strcmp(cases[i].name, "SE term above current term") == 0) {
            /* Follower-style file: only L 1..2 replayed, so the SEs for
             * 3..4 are novel and the term check is what must fire. */
            fclose(f);
            f = fopen(path, "w");
            assert(f);
            t_wline(f, "QHCNS 1 group/hostile");
            t_wline(f, "V 2 - 2");
            t_write_entry_line(f, "L", &e[0]);
            t_write_entry_line(f, "L", &e[1]);
            t_wline(f, "C 2");
            t_write_snapshot_header(f, 4u, 1u, 2u, 13u, dig, 4u);
            t_write_entry_line(f, "SE", &e[0]);
            t_write_entry_line(f, "SE", &e[1]);
            qihse_consensus_entry_t hot = t_craft_entry(3u, 9u, 12u); /* term 9 */
            t_write_entry_line(f, "SE", &hot);
            t_wline(f, "T 5");
        } else if (strcmp(cases[i].name,
                          "snapshot last term mismatches tail") == 0) {
            t_write_snapshot_header(f, 4u, 2u, 2u, 13u, dig, 4u); /* lterm != 1 */
            for (uint64_t k = 0u; k < 4u; k++) t_write_entry_line(f, "SE", &e[k]);
            t_wline(f, "T 5");
        } else if (strcmp(cases[i].name, "valid snapshot + tail") == 0) {
            t_write_snapshot_header(f, 4u, 1u, 2u, 13u, dig, 4u);
            for (uint64_t k = 0u; k < 4u; k++) t_write_entry_line(f, "SE", &e[k]);
            t_wline(f, "T 5");
            qihse_consensus_entry_t e5 = t_craft_entry(5u, 2u, 14u);
            t_write_entry_line(f, "L", &e5);
            t_wline(f, "C 5");
        } else {
            assert(!"unreachable case");
        }
        fclose(f);

        qihse_consensus_t* cs = t_open_single(path, self);
        if (cases[i].ok) {
            assert(cs);
            assert(qihse_consensus_snapshot_index(cs) == 4u);
            assert(qihse_consensus_last_log_index(cs) == 5u);
            assert(qihse_consensus_commit_index(cs) == 5u);
            qihse_consensus_close(cs);
        } else {
            assert(!cs);
        }
        printf("  decoder snapshot %-34s -> %s\n", cases[i].name,
               cs ? "accepted" : "refused");
        remove(path);
    }

    printf("PASS (f2) decoder hostile input: snapshot records fail closed, "
           "valid snapshot + tail decode exactly\n");
}

/* ── (l) Committed-read visibility across compaction ─────────────────────── */

static void test_visibility_after_compaction(qihse_user_t* op) {
    assert(op);
    qihse_user_t* analyst =
        qihse_auth_create_user(op, 61002u, QIHSE_ROLE_ANALYST,
                               1u, 0u, "AnalystPass2!", false);
    assert(analyst);

    harness_t h;
    h_init_ex(&h, "vis", 3u);

    int leader = h_elect(&h);
    assert(leader >= 0);

    /* Four committed entries: unclassified and classified interleaved. */
    uint64_t gen = 700u;
    const char* payloads[4] = {"open-one", "sec-one", "open-two", "sec-two"};
    for (uint64_t k = 0u; k < 4u; k++) {
        qihse_hlc_t hlc = {gen * 10u, 0u};
        assert(qihse_consensus_propose(h.node[leader], op, gen, hlc,
                                        (uint16_t)(k & 1u ? 3u : 0u), 0u,
                                        payloads[k], strlen(payloads[k])));
        gen++;
    }
    assert(h_commit_reached(&h, 4u));

    /* Pre-compaction visibility baseline. */
    static qihse_consensus_entry_t op_before[32], an_before[32];
    size_t op_n = t_read_all(h.node[leader], op, op_before, 32u);
    size_t an_n = t_read_all(h.node[leader], analyst, an_before, 32u);
    assert(op_n == 4u);
    assert(an_n == 2u); /* only the unclassified pair */
    for (size_t i = 0u; i < an_n; i++) assert(an_before[i].classif == 0u);

    /* Push the group past the threshold so the classified entries end up
     * BELOW the snapshot boundary. */
    for (uint64_t k = 0u; k < 6u; k++) {
        char payload[32];
        snprintf(payload, sizeof(payload), "post-%llu", (unsigned long long)k);
        qihse_hlc_t hlc = {gen * 10u, 0u};
        assert(qihse_consensus_propose(h.node[leader], op, gen, hlc, 0u, 0u,
                                        payload, strlen(payload)));
        gen++;
    }
    assert(h_commit_reached(&h, 10u));
    uint64_t snap = qihse_consensus_snapshot_index(h.node[leader]);
    assert(snap >= 4u); /* the classified entries are compacted */

    /* Post-compaction: the operator's view of the first four entries is
     * byte-identical to the pre-compaction capture. */
    static qihse_consensus_entry_t op_after[32], an_after[32];
    size_t op_n2 = t_read_all(h.node[leader], op, op_after, 32u);
    size_t an_n2 = t_read_all(h.node[leader], analyst, an_after, 32u);
    assert(op_n2 == 10u);
    assert(an_n2 == 8u); /* six more unclassified entries, never the secrets */
    for (uint64_t i = 0u; i < 4u; i++) {
        assert(t_entry_eq(&op_before[i], &op_after[i]));
    }
    for (size_t i = 0u; i < an_n2; i++) assert(an_after[i].classif == 0u);
    for (size_t i = 0u; i < an_n; i++) {
        assert(t_entry_eq(&an_before[i], &an_after[i]));
    }
    /* The classified payloads are nowhere in the analyst's view. */
    for (size_t i = 0u; i < an_n2; i++) {
        assert(memmem(an_after[i].payload, an_after[i].payload_len,
                      "sec-", 4u) == NULL);
    }

    /* NULL principal is still refused outright — snapshots never widen it. */
    qihse_consensus_entry_t sink[4];
    size_t got = 99u;
    assert(!qihse_consensus_read_committed(h.node[leader], NULL, snap + 1u,
                                           sink, 4u, &got));
    assert(got == 0u);

    qihse_consensus_counters_t c;
    qihse_consensus_get_counters(h.node[leader], &c);
    assert(c.auth_failures >= 2u); /* withheld entries + the NULL refusal */

    /* The same holds on a follower that installed a snapshot. */
    int lag = (leader + 3u) % N;
    t_sever(&h, lag);
    for (uint64_t k = 0u; k < 5u; k++) {
        char payload[32];
        snprintf(payload, sizeof(payload), "lag-%llu", (unsigned long long)k);
        qihse_hlc_t hlc = {gen * 10u, 0u};
        assert(qihse_consensus_propose(h.node[leader], op, gen, hlc, 0u, 0u,
                                        payload, strlen(payload)));
        gen++;
    }
    assert(h_commit_reached_skip(&h, 15u, lag));
    assert(qihse_consensus_snapshot_index(h.node[leader]) > snap);
    t_heal(&h);
    for (unsigned i = 0; i < 600u &&
         qihse_consensus_commit_index(h.node[lag]) < 15u; i++) {
        h_tick(&h, 10u);
    }
    assert(qihse_consensus_commit_index(h.node[lag]) == 15u);
    qihse_consensus_counters_t lagc;
    qihse_consensus_get_counters(h.node[lag], &lagc);
    assert(lagc.snapshots_installed >= 1u);

    static qihse_consensus_entry_t lag_op[32], lag_an[32];
    size_t lag_opn = t_read_all(h.node[lag], op, lag_op, 32u);
    size_t lag_ann = t_read_all(h.node[lag], analyst, lag_an, 32u);
    assert(lag_opn == 15u);
    assert(lag_ann == 13u);
    for (size_t i = 0u; i < lag_ann; i++) assert(lag_an[i].classif == 0u);
    for (size_t i = 0u; i < an_n2; i++) {
        assert(t_entry_eq(&an_after[i], &lag_an[i]));
    }
    for (size_t i = 0u; i < lag_ann; i++) {
        assert(memmem(lag_an[i].payload, lag_an[i].payload_len,
                      "sec-", 4u) == NULL);
    }

    h_free(&h);
    printf("PASS (l) committed-read visibility after compaction identical to "
           "pre-compaction; analyst and NULL still fenced (invariant 1)\n");
}

/* ── (m) Compaction determinism ──────────────────────────────────────────── */

/* Run one fixed compaction scenario and fold every observable (per node:
 * role, term, epoch, commit, snapshot index, log tail, counters) into a
 * rolling hash after every tick.  Two runs must hash identically. */
static uint64_t t_determinism_run(void) {
    harness_t h;
    h_init_ex(&h, "det", 3u); /* same seed: same members, same timeouts */

    uint64_t hv = 0xCBF2CE48D222D25BULL;
    int leader = -1;
    for (unsigned i = 0u; i < 600u && leader < 0; i++) {
        h_tick(&h, 10u);
        leader = h_leader(&h);
        hv = t_fold64(hv, 0xE1u);
    }
    assert(leader >= 0);

    int lag = (leader + 2u) % N;
    t_sever(&h, lag);
    uint64_t gen = 900u;
    for (uint64_t k = 0u; k < 7u; k++) {
        char payload[32];
        snprintf(payload, sizeof(payload), "det-%llu", (unsigned long long)k);
        qihse_hlc_t hlc = {gen * 10u, 0u};
        assert(qihse_consensus_propose(h.node[leader], NULL, gen, hlc, 0u, 0u,
                                        payload, strlen(payload)));
        gen++;
        for (unsigned t = 0u; t < 30u; t++) h_tick(&h, 10u);
        hv = t_fold64(hv, gen);
    }
    assert(h_commit_reached_skip(&h, 7u, lag));
    assert(qihse_consensus_snapshot_index(h.node[leader]) > 0u);

    t_heal(&h);
    for (unsigned i = 0u; i < 600u; i++) {
        h_tick(&h, 10u);
        hv = t_fold64(hv, qihse_consensus_commit_index(h.node[lag]));
    }
    assert(qihse_consensus_commit_index(h.node[lag]) == 7u);

    for (size_t j = 0u; j < N; j++) {
        hv = t_fold64(hv, (uint64_t)qihse_consensus_role(h.node[j]));
        hv = t_fold64(hv, qihse_consensus_term(h.node[j]));
        hv = t_fold64(hv, qihse_consensus_fencing_epoch(h.node[j]));
        hv = t_fold64(hv, qihse_consensus_commit_index(h.node[j]));
        hv = t_fold64(hv, qihse_consensus_snapshot_index(h.node[j]));
        hv = t_fold64(hv, qihse_consensus_last_log_index(h.node[j]));
        qihse_consensus_counters_t c;
        qihse_consensus_get_counters(h.node[j], &c);
        hv = t_fold64(hv, c.messages_sent);
        hv = t_fold64(hv, c.messages_received);
        hv = t_fold64(hv, c.snapshots_created);
        hv = t_fold64(hv, c.snapshots_installed);
        hv = t_fold64(hv, c.snapshot_rejections);
        hv = t_fold64(hv, c.record_writes);
    }
    h_free(&h);
    return hv;
}

static void test_compaction_determinism(void) {
    uint64_t a = t_determinism_run();
    uint64_t b = t_determinism_run();
    assert(a == b);
    printf("PASS (m) compaction determinism: identical trajectory hash on "
           "two independent runs (%016llx)\n", (unsigned long long)a);
}

/* ── Membership-change helpers ─────────────────────────────────────────── */

/* One-way partition: a may talk to b, b's replies never land. */
static void t_mute_one_way(harness_t* h, int from, int to) {
    h->drop[from][to] = true;
}

/* Crafted-config open: explicit baseline member list (unlike the single-
 * member hostile opener) so LC records have room to fold. */
static qihse_consensus_t* t_open_cfg(const char* path, const qihse_uuid_t* self,
                                     const qihse_uuid_t* members, size_t count) {
    qihse_consensus_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    snprintf(cfg.group_id, sizeof(cfg.group_id), "group/hostile");
    cfg.self = *self;
    cfg.member_count = count;
    for (size_t i = 0; i < count; i++) cfg.members[i] = members[i];
    cfg.election_timeout_base_ms = 150u;
    cfg.election_timeout_spread_ms = 300u;
    cfg.heartbeat_interval_ms = 50u;
    snprintf(cfg.record_path, sizeof(cfg.record_path), "%s", path);
    return qihse_consensus_open(&cfg, NULL, NULL);
}

/* Write "LC <A|R> <uuid-hex> <index> <term> <gen>" exactly as the encoder. */
static void t_write_config_line(FILE* f, char op, const qihse_uuid_t* uid,
                                uint64_t idx, uint64_t term, uint64_t gen) {
    char hex[2 * QIHSE_UUID_BYTES + 1u];
    char body[128];
    t_hex_encode(uid->bytes, QIHSE_UUID_BYTES, hex);
    snprintf(body, sizeof(body), "LC %c %s %llu %llu %llu", op, hex,
             (unsigned long long)idx, (unsigned long long)term,
             (unsigned long long)gen);
    t_wline(f, body);
}

/* ── (n) Transitions: remove, remove, add — quorum arithmetic flips ─────── */

static void test_membership_transitions(qihse_user_t* op) {
    assert(op);
    qihse_user_t* analyst =
        qihse_auth_create_user(op, 61004u, QIHSE_ROLE_ANALYST,
                               1u, 0u, "AnalystPass4!", false);
    assert(analyst);

    harness_t h;
    h_init(&h, "member");
    t_term_leader_t seen[32];
    size_t seen_n = 0u;

    int L = h_elect(&h);
    assert(L >= 0);
    int R1 = (L + 1u) % N;   /* first removal, partitioned before it learns */
    int A = (L + 2u) % N;
    int B = (L + 3u) % N;    /* second removal */
    int C = (L + 4u) % N;

    /* Baseline data entry. */
    qihse_hlc_t hlc = {100u, 0u};
    assert(qihse_consensus_propose(h.node[L], NULL, 1000u, hlc, 0u, 0u,
                                    "base", 4u));
    assert(h_commit_reached_skip(&h, 1u, R1));

    /* ── Removal 1: R1 out (partitioned first, so it keeps the old config). */
    t_sever(&h, R1);
    assert(qihse_consensus_propose_membership(
        h.node[L], op, QIHSE_CONSENSUS_MEMBER_REMOVE, &h.id[R1]));

    /* Effect-on-append: the transition is in force immediately, and while
     * it is uncommitted a second proposal is refused — nothing queued. */
    qihse_consensus_membership_t m;
    t_membership(h.node[L], &m);
    assert(m.member_count == 4u && m.majority_needed == 3u);
    assert(m.last_config_index == 2u && m.pending_config_index == 2u);
    uint64_t idx_after = qihse_consensus_last_log_index(h.node[L]);
    assert(!qihse_consensus_propose_membership(
        h.node[L], op, QIHSE_CONSENSUS_MEMBER_REMOVE, &h.id[B]));
    assert(qihse_consensus_last_log_index(h.node[L]) == idx_after);

    assert(h_commit_reached_skip(&h, 2u, R1));
    t_membership(h.node[L], &m);
    assert(m.member_count == 4u && m.majority_needed == 3u);
    assert(m.pending_config_index == 0u && m.last_config_index == 2u);
    for (int j = 0; j < (int)N; j++) {
        if (j == R1) continue;
        t_membership(h.node[j], &m);
        assert(m.member_count == 4u && m.pending_config_index == 0u);
    }
    t_membership(h.node[R1], &m);
    assert(m.member_count == 5u); /* stale: never saw the transition */

    /* The config entry is a first-class entry in the committed log, under
     * the same per-entry authz as everything else. */
    qihse_consensus_entry_t out[4];
    size_t got = 0u;
    assert(qihse_consensus_read_committed(h.node[L], op, 2u, out, 4u, &got));
    assert(got == 1u);
    assert(out[0].type == QIHSE_CONSENSUS_ENTRY_CONFIG_REMOVE);
    assert(out[0].payload_len == QIHSE_UUID_BYTES);
    assert(memcmp(out[0].payload, h.id[R1].bytes, QIHSE_UUID_BYTES) == 0);

    /* R1 campaigns on its stale config; while severed its traffic dies in
     * the partition, and once healed (below) every surviving member
     * membership-fences its vote requests — either way, never a leader. */
    uint64_t dropped_before = h.dropped;
    for (unsigned i = 0u; i < 80u; i++) {
        h_tick(&h, 10u);
        t_scan_leaders(&h, seen, 32u, &seen_n);
        assert(qihse_consensus_role(h.node[R1]) != QIHSE_CONSENSUS_LEADER);
    }
    assert(h.dropped > dropped_before);

    /* ── Quorum arithmetic at 4 members (majority 3): a 2-node side stalls. */
    t_sever(&h, A);
    t_sever(&h, B); /* only L and C remain connected */
    qihse_hlc_t hlc2 = {200u, 0u};
    assert(qihse_consensus_propose(h.node[L], NULL, 1002u, hlc2, 0u, 0u,
                                    "stall", 5u));
    for (unsigned i = 0u; i < 60u; i++) {
        h_tick(&h, 10u);
        t_scan_leaders(&h, seen, 32u, &seen_n);
    }
    assert(qihse_consensus_commit_index(h.node[L]) == 2u); /* 2 of 4 < 3 */

    /* ── Removal 2: B out while partitioned; config drops to 3 (majority 2). */
    assert(qihse_consensus_propose_membership(
        h.node[L], op, QIHSE_CONSENSUS_MEMBER_REMOVE, &h.id[B]));
    t_membership(h.node[L], &m);
    assert(m.member_count == 3u && m.majority_needed == 2u);
    /* Same connectivity as the stall above, and now it COMMITS: the quorum
     * arithmetic observably changed. */
    for (unsigned i = 0u; i < 400u; i++) {
        h_tick(&h, 10u);
        t_scan_leaders(&h, seen, 32u, &seen_n);
        if (qihse_consensus_commit_index(h.node[L]) >= 4u &&
            qihse_consensus_commit_index(h.node[C]) >= 4u) break;
    }
    assert(qihse_consensus_commit_index(h.node[L]) == 4u);
    assert(qihse_consensus_commit_index(h.node[C]) == 4u);
    t_membership(h.node[L], &m);
    assert(m.member_count == 3u && m.majority_needed == 2u &&
           m.pending_config_index == 0u);

    t_heal(&h); /* A catches up on both transitions */
    for (unsigned i = 0u; i < 400u; i++) {
        h_tick(&h, 10u);
        t_scan_leaders(&h, seen, 32u, &seen_n);
        t_membership(h.node[A], &m);
        if (m.member_count == 3u) break;
    }
    t_membership(h.node[A], &m);
    assert(m.member_count == 3u && m.pending_config_index == 0u);

    /* ── Addition: the extra node joins; config grows to 4 (majority 3). */
    h_seed_extra(&h, "member");
    qihse_uuid_t members4[4];
    size_t mc = 0u;
    for (int j = 0; j < (int)N; j++) {
        if (j == R1 || j == B) continue;
        members4[mc++] = h.id[j]; /* fold order: survivors, adds appended */
    }
    members4[mc++] = h.extra_id;
    assert(mc == 4u);
    x_heal(&h);
    h_open_extra(&h, "member", members4, 4u);

    assert(qihse_consensus_propose_membership(
        h.node[L], op, QIHSE_CONSENSUS_MEMBER_ADD, &h.extra_id));
    t_membership(h.node[L], &m);
    assert(m.member_count == 4u && m.majority_needed == 3u &&
           m.pending_config_index == 5u);
    for (unsigned i = 0u; i < 600u; i++) {
        h_tick(&h, 10u);
        t_scan_leaders(&h, seen, 32u, &seen_n);
        bool all = qihse_consensus_commit_index(h.node[L]) >= 5u;
        for (int j = 0; all && j < (int)N; j++) {
            if (j == R1 || j == B) continue;
            all = qihse_consensus_commit_index(h.node[j]) >= 5u;
        }
        all = all && qihse_consensus_commit_index(h.extra) >= 5u;
        if (all) break;
    }
    for (int j = 0; j < (int)N; j++) {
        if (j == R1 || j == B) continue;
        t_membership(h.node[j], &m);
        assert(m.member_count == 4u && m.pending_config_index == 0u);
    }
    t_membership(h.extra, &m);
    assert(m.member_count == 4u && m.pending_config_index == 0u);

    /* Quorum arithmetic flips back: 2 of 4 stalls again. */
    t_sever(&h, A);
    t_sever(&h, C); /* only L and the extra remain connected */
    qihse_hlc_t hlc3 = {300u, 0u};
    assert(qihse_consensus_propose(h.node[L], NULL, 1006u, hlc3, 0u, 0u,
                                    "stall2", 6u));
    for (unsigned i = 0u; i < 60u; i++) {
        h_tick(&h, 10u);
        t_scan_leaders(&h, seen, 32u, &seen_n);
    }
    assert(qihse_consensus_commit_index(h.node[L]) == 5u); /* 2 of 4 < 3 */

    /* Heal: the isolated members return with higher terms, the stall
     * resolves through a fresh leader (possibly the extra node), and the
     * group keeps progressing. */
    t_heal(&h);
    bool reached6 = false;
    for (unsigned round = 0u; round < 6u && !reached6; round++) {
        for (unsigned i = 0u; i < 300u; i++) {
            h_tick(&h, 10u);
            t_scan_leaders(&h, seen, 32u, &seen_n);
            if (h_leader_any(&h) >= 0) break;
        }
        int Ld = h_leader_any(&h);
        if (Ld < 0) continue;
        qihse_consensus_t* lead = h_node_at(&h, Ld);
        assert(lead);
        qihse_hlc_t hlc4 = {400u + (uint64_t)round, 0u};
        if (!qihse_consensus_propose(lead, NULL, 1007u + (uint64_t)round,
                                     hlc4, 0u, 0u, "post", 4u)) {
            continue; /* leadership moved under us; retry */
        }
        for (unsigned i = 0u; i < 300u; i++) {
            h_tick(&h, 10u);
            t_scan_leaders(&h, seen, 32u, &seen_n);
            bool all = qihse_consensus_commit_index(lead) >= 6u;
            for (int j = 0; all && j < (int)N; j++) {
                if (j == R1 || j == B) continue;
                all = qihse_consensus_commit_index(h.node[j]) >= 6u;
            }
            if (all) { reached6 = true; break; }
        }
    }
    assert(reached6);

    /* ── Negative proposals: authorization and validity, all refused with
     * nothing appended.  (AGENTS.md invariants 1 and 2.) */
    int Ld2 = h_leader_any(&h);
    assert(Ld2 >= 0); /* a leader exists; negatives need one */
    qihse_consensus_t* lead2 = h_node_at(&h, Ld2);
    assert(lead2);
    qihse_consensus_counters_t rc0;
    qihse_consensus_get_counters(lead2, &rc0);
    uint64_t idx0 = qihse_consensus_last_log_index(lead2);
    qihse_uuid_t nil;
    memset(&nil, 0, sizeof(nil));
    assert(!qihse_consensus_propose_membership(
        lead2, NULL, QIHSE_CONSENSUS_MEMBER_ADD, &h.extra_id));
    assert(!qihse_consensus_propose_membership(
        lead2, analyst, QIHSE_CONSENSUS_MEMBER_ADD, &h.extra_id));
    assert(!qihse_consensus_propose_membership(
        lead2, op, QIHSE_CONSENSUS_MEMBER_ADD, &nil));
    assert(!qihse_consensus_propose_membership( /* already a member */
        lead2, op, QIHSE_CONSENSUS_MEMBER_ADD, &h.extra_id));
    assert(!qihse_consensus_propose_membership( /* not a member anymore */
        lead2, op, QIHSE_CONSENSUS_MEMBER_REMOVE, &h.id[R1]));
    assert(!qihse_consensus_propose_membership( /* follower, not leader */
        h.node[C], op, QIHSE_CONSENSUS_MEMBER_REMOVE, &h.id[A]));
    assert(qihse_consensus_last_log_index(lead2) == idx0);
    qihse_consensus_counters_t rc1;
    qihse_consensus_get_counters(lead2, &rc1);
    assert(rc1.membership_proposals_refused ==
           rc0.membership_proposals_refused + 5u); /* five on the leader */
    qihse_consensus_get_counters(h.node[C], &rc1);
    assert(rc1.membership_proposals_refused >= 1u); /* one on the follower */

    h_free(&h);
    printf("PASS (n) membership transitions: remove/remove/add each commit; "
           "quorum arithmetic flips 3->2->3 observably; one-in-flight "
           "refused; unauthorized principals refused\n");
}

/* ── (o) Election safety across a config boundary ───────────────────────── */

static void test_membership_election_safety(qihse_user_t* op) {
    assert(op);
    harness_t h;
    h_init(&h, "safety");
    t_term_leader_t seen[32];
    size_t seen_n = 0u;

    int L = h_elect(&h);
    assert(L >= 0);
    int E = (L + 1u) % N; /* the node that will be removed */

    /* Phase 1: E is CONNECTED when its removal replicates — it folds the
     * transition, steps down cleanly, and never campaigns again. */
    assert(qihse_consensus_propose_membership(
        h.node[L], op, QIHSE_CONSENSUS_MEMBER_REMOVE, &h.id[E]));
    for (unsigned i = 0u; i < 400u; i++) {
        h_tick(&h, 10u);
        t_scan_leaders(&h, seen, 32u, &seen_n);
        bool all = qihse_consensus_commit_index(h.node[L]) >= 1u;
        for (int j = 0; all && j < (int)N; j++) {
            if (j == E) continue;
            all = qihse_consensus_commit_index(h.node[j]) >= 1u;
        }
        if (all) break;
    }
    qihse_consensus_membership_t m;
    t_membership(h.node[E], &m);
    assert(m.self_removed && m.member_count == 4u);
    assert(qihse_consensus_role(h.node[E]) == QIHSE_CONSENSUS_FOLLOWER);
    assert(!qihse_consensus_group_available(h.node[E], h.now));
    qihse_consensus_counters_t et0;
    qihse_consensus_get_counters(h.node[E], &et0);
    for (unsigned i = 0u; i < 80u; i++) {
        h_tick(&h, 10u);
        t_scan_leaders(&h, seen, 32u, &seen_n);
        assert(qihse_consensus_role(h.node[E]) != QIHSE_CONSENSUS_LEADER);
    }
    qihse_consensus_counters_t et1;
    qihse_consensus_get_counters(h.node[E], &et1);
    assert(et1.election_timeouts == et0.election_timeouts); /* stood down */

    /* E can rejoin through the front door: a committed ADD. */
    assert(qihse_consensus_propose_membership(
        h.node[L], op, QIHSE_CONSENSUS_MEMBER_ADD, &h.id[E]));
    for (unsigned i = 0u; i < 400u; i++) {
        h_tick(&h, 10u);
        t_scan_leaders(&h, seen, 32u, &seen_n);
        t_membership(h.node[E], &m);
        if (!m.self_removed &&
            qihse_consensus_commit_index(h.node[E]) >= 2u) break;
    }
    t_membership(h.node[E], &m);
    assert(!m.self_removed && m.member_count == 5u);

    /* Phase 2: the adversarial shape — F is removed while partitioned, so
     * it keeps the OLD 5-member config in which {F, x, y} is a majority.
     * Old-majority votes must be unreachable: every remaining member
     * filters F's traffic at the membership check, so no two leaders can
     * ever emerge in one term on opposite sides of the boundary. */
    int F = (L + 2u) % N;
    t_sever(&h, F);
    assert(qihse_consensus_propose_membership(
        h.node[L], op, QIHSE_CONSENSUS_MEMBER_REMOVE, &h.id[F]));
    for (unsigned i = 0u; i < 400u; i++) {
        h_tick(&h, 10u);
        t_scan_leaders(&h, seen, 32u, &seen_n);
        if (qihse_consensus_commit_index(h.node[L]) >= 3u) break;
    }
    assert(qihse_consensus_commit_index(h.node[L]) >= 3u);

    t_heal(&h); /* F returns; grace catch-up hands it the transition entry */
    for (unsigned i = 0u; i < 400u; i++) {
        h_tick(&h, 10u);
        t_scan_leaders(&h, seen, 32u, &seen_n);
        assert(qihse_consensus_role(h.node[F]) != QIHSE_CONSENSUS_LEADER);
        t_membership(h.node[F], &m);
        if (m.self_removed) break;
    }
    t_membership(h.node[F], &m);
    assert(m.self_removed && m.member_count == 4u); /* learned and folded */
    for (unsigned i = 0u; i < 80u; i++) {
        h_tick(&h, 10u);
        t_scan_leaders(&h, seen, 32u, &seen_n);
        assert(qihse_consensus_role(h.node[F]) != QIHSE_CONSENSUS_LEADER);
    }

    /* Old-config vote traffic is membership-fenced: a synthetic RequestVote
     * from a uuid no config of this group ever held is counted and dropped
     * BEFORE any term logic — it cannot manufacture an old-config majority
     * and cannot even inflate the receiver's term. */
    qihse_uuid_t ghost;
    assert(qihse_uuid_from_seed("safety-ghost", 12u, &ghost));
    qihse_consensus_msg_t rv;
    memset(&rv, 0, sizeof(rv));
    rv.type = QIHSE_CONSENSUS_MSG_REQUEST_VOTE;
    snprintf(rv.group_id, sizeof(rv.group_id), "%s", "group/safety");
    rv.from = ghost;
    rv.to = h.id[L];
    rv.term = qihse_consensus_term(h.node[L]) + 100u;
    rv.fencing_epoch = qihse_consensus_fencing_epoch(h.node[L]) + 100u;
    rv.u.vote.last_log_index = qihse_consensus_last_log_index(h.node[L]);
    rv.u.vote.last_log_term = qihse_consensus_last_log_term(h.node[L]);
    qihse_consensus_counters_t gv0, gv1;
    qihse_consensus_get_counters(h.node[L], &gv0);
    uint64_t term_before = qihse_consensus_term(h.node[L]);
    qihse_consensus_receive(h.node[L], &rv);
    qihse_consensus_get_counters(h.node[L], &gv1);
    assert(gv1.messages_ignored == gv0.messages_ignored + 1u);
    assert(qihse_consensus_term(h.node[L]) == term_before);

    /* F's own fencing floor still applies while removed: stale-epoch
     * traffic from a still-member is rejected before any log logic. */
    qihse_consensus_msg_t inj;
    memset(&inj, 0, sizeof(inj));
    inj.type = QIHSE_CONSENSUS_MSG_APPEND;
    snprintf(inj.group_id, sizeof(inj.group_id), "%s", "group/safety");
    inj.from = h.id[L]; /* member of F's (stale) config */
    inj.to = h.id[F];
    inj.term = qihse_consensus_term(h.node[F]);
    inj.fencing_epoch = qihse_consensus_fencing_epoch(h.node[F]) - 1u;
    qihse_consensus_counters_t g0, g1;
    qihse_consensus_get_counters(h.node[F], &g0);
    qihse_consensus_receive(h.node[F], &inj);
    qihse_consensus_get_counters(h.node[F], &g1);
    assert(g1.stale_epoch_rejections == g0.stale_epoch_rejections + 1u);
    assert(qihse_consensus_is_stale_epoch(
        h.node[F], qihse_consensus_fencing_epoch(h.node[F]) - 1u));

    h_free(&h);
    printf("PASS (o) election safety across the config boundary: removed "
           "node never wins any term, no term ever has two leaders, "
           "stale-config votes membership-fenced, fencing floor intact\n");
}

/* ── (p) Leader change mid-transition: complete, and abort/revert ───────── */

static void test_membership_leader_change_midflight(void) {
    qihse_user_t* op = qihse_auth_get_user(0);
    assert(op);

    /* Part 1 — COMPLETE: the new leader holds the pending entry. */
    {
        harness_t h;
        h_init(&h, "midair1");
        t_term_leader_t seen[16];
        size_t seen_n = 0u;

        int L1 = h_elect(&h);
        assert(L1 >= 0);
        int R = (L1 + 1u) % N;   /* to be removed, isolated throughout */
        int F1 = (L1 + 2u) % N;
        int F2 = (L1 + 3u) % N;
        int F3 = (L1 + 4u) % N;

        qihse_hlc_t hlc = {10u, 0u};
        assert(qihse_consensus_propose(h.node[L1], NULL, 2000u, hlc, 0u, 0u,
                                        "base", 4u));
        assert(h_commit_reached(&h, 1u));

        t_sever(&h, R);
        /* One-way mutes: every follower RECEIVES L1's appends but no
         * acknowledgement ever returns, so the transition below stays
         * uncommitted (1 of 4) while all three followers hold it. */
        t_mute_one_way(&h, F1, L1);
        t_mute_one_way(&h, F2, L1);
        t_mute_one_way(&h, F3, L1);
        for (unsigned i = 0u;
             i < 300u &&
             qihse_consensus_role(h.node[L1]) != QIHSE_CONSENSUS_LEADER;
             i++) {
            h_tick(&h, 10u);
            t_scan_leaders(&h, seen, 16u, &seen_n);
        }
        assert(qihse_consensus_role(h.node[L1]) == QIHSE_CONSENSUS_LEADER);

        /* The transition is appended and delivered one-way to all three
         * followers — held by four nodes, acked by none, in flight. */
        assert(qihse_consensus_propose_membership(
            h.node[L1], op, QIHSE_CONSENSUS_MEMBER_REMOVE, &h.id[R]));
        qihse_consensus_membership_t m;
        t_membership(h.node[L1], &m);
        assert(m.pending_config_index == 2u && m.member_count == 4u);
        for (unsigned i = 0u; i < 50u; i++) h_tick(&h, 10u);
        assert(qihse_consensus_last_log_index(h.node[F1]) == 2u); /* held */
        assert(qihse_consensus_last_log_index(h.node[F2]) == 2u);
        assert(qihse_consensus_last_log_index(h.node[F3]) == 2u);
        assert(qihse_consensus_commit_index(h.node[L1]) == 1u); /* 1 of 4 */
        t_membership(h.node[F2], &m);
        assert(m.member_count == 4u && m.pending_config_index == 2u);

        /* Leader change: L1 and the removed R drop out; every survivor
         * (F1, F2, F3) HOLDS the pending transition and sits on the new
         * config, whose majority (3 of 4) is exactly the surviving set. */
        memset(h.drop, 0, sizeof(h.drop));
        t_sever(&h, L1);
        t_sever(&h, R);
        bool may[5] = {false, false, false, false, false};
        may[F1] = may[F2] = may[F3] = true;
        int L2 = h_elect_among(&h, may);
        assert(L2 == F1 || L2 == F2 || L2 == F3);
        t_membership(h.node[L2], &m);
        assert(m.pending_config_index == 2u && m.member_count == 4u);

        /* Completion: the new leader's own current-term entry commits and
         * carries the pending config entry with it (current-term rule).
         * The severed L1 may return with a higher term and re-lead, so
         * the drive is leadership-churn-robust: propose on whoever leads
         * until every node settles on the transition being committed. */
        t_heal(&h);
        bool settled = false;
        for (unsigned round = 0u; round < 8u && !settled; round++) {
            for (unsigned i = 0u; i < 300u; i++) {
                h_tick(&h, 10u);
                t_scan_leaders(&h, seen, 16u, &seen_n);
                if (h_leader(&h) >= 0) break;
            }
            int Ld = h_leader(&h);
            if (Ld < 0) continue;
            qihse_hlc_t hlcx = {20u + (uint64_t)round, 0u};
            if (!qihse_consensus_propose(h.node[Ld], NULL,
                                         2002u + (uint64_t)round, hlcx,
                                         0u, 0u, "finish", 6u)) {
                continue;
            }
            for (unsigned i = 0u; i < 400u; i++) {
                h_tick(&h, 10u);
                t_scan_leaders(&h, seen, 16u, &seen_n);
                bool all = true;
                for (int j = 0; all && j < (int)N; j++) {
                    t_membership(h.node[j], &m);
                    all = (m.pending_config_index == 0u);
                }
                if (all) { settled = true; break; }
            }
        }
        assert(settled);
        for (int j = 0; j < (int)N; j++) {
            t_membership(h.node[j], &m);
            assert(m.member_count == 4u && m.pending_config_index == 0u);
            if (j != R) {
                assert(qihse_consensus_commit_index(h.node[j]) >= 3u);
            }
        }
        /* R folded its own removal through grace catch-up and stands down. */
        for (unsigned i = 0u; i < 40u; i++) {
            h_tick(&h, 10u);
            t_scan_leaders(&h, seen, 16u, &seen_n);
            assert(qihse_consensus_role(h.node[R]) != QIHSE_CONSENSUS_LEADER);
        }

        h_free(&h);
        printf("  mid-flight (complete): new leader held the entry and "
               "committed it as a prefix\n");
    }

    /* Part 2 — ABORT/REVERT: the new leader lacks the pending entry; the
     * conflicting suffix truncates it and the fold reverts the config. */
    {
        harness_t h;
        h_init(&h, "midair2");
        t_term_leader_t seen[16];
        size_t seen_n = 0u;

        int L1 = h_elect(&h);
        assert(L1 >= 0);
        int R = (L1 + 1u) % N;
        int F1 = (L1 + 2u) % N;
        int F2 = (L1 + 3u) % N;
        int F3 = (L1 + 4u) % N;

        qihse_hlc_t hlc = {30u, 0u};
        assert(qihse_consensus_propose(h.node[L1], NULL, 2100u, hlc, 0u, 0u,
                                        "base", 4u));
        assert(h_commit_reached(&h, 1u));

        t_sever(&h, F2);
        t_sever(&h, F3);
        t_sever(&h, R); /* R must not learn of its own removal yet: the
                         * grace catch-up would otherwise let it fold and
                         * stand down, and the revert case needs R still
                         * campaigning on the old config */
        assert(qihse_consensus_propose_membership(
            h.node[L1], op, QIHSE_CONSENSUS_MEMBER_REMOVE, &h.id[R]));
        for (unsigned i = 0u; i < 50u; i++) h_tick(&h, 10u);
        qihse_consensus_membership_t m;
        t_membership(h.node[L1], &m);
        assert(m.pending_config_index == 2u && m.member_count == 4u);
        t_membership(h.node[F1], &m);
        assert(m.member_count == 4u && m.pending_config_index == 2u);
        assert(qihse_consensus_commit_index(h.node[L1]) == 1u); /* 2/5 */

        memset(h.drop, 0, sizeof(h.drop));
        t_sever(&h, L1);
        t_sever(&h, F1);
        bool may[5] = {false, false, false, false, false};
        may[F2] = may[F3] = may[R] = true;
        int L2 = h_elect_among(&h, may);
        assert(L2 >= 0 && L2 != F1 && L2 != L1);
        t_membership(h.node[L2], &m);
        assert(m.member_count == 5u && m.last_config_index == 0u);

        /* L2 never saw the transition.  BEFORE healing, it commits its
         * own current-term entry at the conflicting index — the trio is
         * an old-config majority — so the group's authoritative log is
         * now the one WITHOUT the config entry. */
        qihse_hlc_t hlcy = {40u, 0u};
        assert(qihse_consensus_propose(h.node[L2], NULL, 2102u, hlcy,
                                       0u, 0u, "revert", 6u));
        for (unsigned i = 0u; i < 400u; i++) {
            h_tick(&h, 10u);
            t_scan_leaders(&h, seen, 16u, &seen_n);
            if (qihse_consensus_commit_index(h.node[L2]) >= 2u) break;
        }
        assert(qihse_consensus_commit_index(h.node[L2]) >= 2u);

        /* Heal: L2's higher-last-term log beats L1's pending config entry
         * at the conflicting index — truncation removes it from L1/F1 and
         * the fold reverts every node to the previous config.  The drive
         * is robust to the severed pair returning with higher terms. */
        t_heal(&h);
        bool reverted = false;
        for (unsigned round = 0u; round < 8u && !reverted; round++) {
            for (unsigned i = 0u; i < 300u; i++) {
                h_tick(&h, 10u);
                t_scan_leaders(&h, seen, 16u, &seen_n);
                if (h_leader(&h) >= 0) break;
            }
            int Ld = h_leader(&h);
            if (Ld < 0) continue;
            if (qihse_consensus_commit_index(h.node[Ld]) >= 2u &&
                qihse_consensus_last_log_index(h.node[Ld]) >= 2u) {
                /* nothing more needed from this leader; just converge */
            } else {
                qihse_hlc_t hlcz = {50u + (uint64_t)round, 0u};
                if (!qihse_consensus_propose(h.node[Ld], NULL,
                                             2103u + (uint64_t)round, hlcz,
                                             0u, 0u, "settle", 6u)) {
                    continue;
                }
            }
            for (unsigned i = 0u; i < 400u; i++) {
                h_tick(&h, 10u);
                t_scan_leaders(&h, seen, 16u, &seen_n);
                bool all = true;
                for (int j = 0; all && j < (int)N; j++) {
                    t_membership(h.node[j], &m);
                    all = (m.member_count == 5u &&
                           m.last_config_index == 0u);
                }
                if (all) { reverted = true; break; }
            }
        }
        assert(reverted);
        for (int j = 0; j < (int)N; j++) {
            t_membership(h.node[j], &m);
            assert(m.member_count == 5u && m.last_config_index == 0u &&
                   m.pending_config_index == 0u);
        }

        h_free(&h);
        printf("  mid-flight (revert): new leader lacked the entry; "
               "truncation reverted every node to the previous config\n");
    }

    printf("PASS (p) leader change mid-transition: complete-by-prefix when "
           "held, abort-and-revert when not; consistent on every node\n");
}

/* ── (q) Restart mid-transition; torn config write ──────────────────────── */

static void test_membership_restart(const char* dir, const qihse_uuid_t* self,
                                    qihse_user_t* op) {
    /* Live: F holds the uncommitted config entry (its replies muted), then
     * restarts.  Replay lands on the config of the last config entry in
     * the reconstructed log, transition still in flight. */
    harness_t h;
    h_init(&h, "mrestart");
    t_term_leader_t seen[16];
    size_t seen_n = 0u;

    int L = h_elect(&h);
    assert(L >= 0);
    int R = (L + 1u) % N;
    int F = (L + 2u) % N;
    int G = (L + 3u) % N;

    t_sever(&h, R);
    t_sever(&h, G);
    t_mute_one_way(&h, F, L);
    assert(qihse_consensus_propose_membership(
        h.node[L], op, QIHSE_CONSENSUS_MEMBER_REMOVE, &h.id[R]));
    for (unsigned i = 0u; i < 50u; i++) h_tick(&h, 10u);
    assert(qihse_consensus_last_log_index(h.node[F]) == 1u);
    assert(qihse_consensus_commit_index(h.node[L]) == 0u);

    qihse_consensus_membership_t m;
    h_restart(&h, F, "mrestart"); /* crash + replay with the entry on disk */
    t_membership(h.node[F], &m);
    assert(m.member_count == 4u);        /* lands on the appended config */
    assert(m.last_config_index == 1u && m.pending_config_index == 1u);

    h_restart(&h, G, "mrestart"); /* never received the record */
    t_membership(h.node[G], &m);
    assert(m.member_count == 5u && m.last_config_index == 0u);

    /* Heal and re-drive: the election churn means the new leader holds a
     * term above the transition entry's, so committing it needs one
     * current-term entry (current-term commit rule). */
    t_heal(&h);
    {
        bool settledq = false;
        for (unsigned round = 0u; round < 8u && !settledq; round++) {
            for (unsigned i = 0u; i < 300u; i++) {
                h_tick(&h, 10u);
                t_scan_leaders(&h, seen, 16u, &seen_n);
                if (h_leader(&h) >= 0) break;
            }
            int Ld = h_leader(&h);
            if (Ld < 0) continue;
            qihse_hlc_t hlcz = {60u + (uint64_t)round, 0u};
            if (!qihse_consensus_propose(h.node[Ld], NULL,
                                         3000u + (uint64_t)round, hlcz,
                                         0u, 0u, "drive", 5u)) {
                continue;
            }
            for (unsigned i = 0u; i < 400u; i++) {
                h_tick(&h, 10u);
                t_scan_leaders(&h, seen, 16u, &seen_n);
                bool all = true;
                for (int j = 0; all && j < (int)N; j++) {
                    if (j == R) continue;
                    t_membership(h.node[j], &m);
                    all = (m.member_count == 4u && m.pending_config_index == 0u);
                }
                if (all) { settledq = true; break; }
            }
        }
        assert(settledq);
    }
    for (int j = 0; j < (int)N; j++) {
        if (j == R) continue;
        t_membership(h.node[j], &m);
        assert(m.member_count == 4u && m.pending_config_index == 0u);
    }
    h_free(&h);

    /* Crafted files: the write-then-swap discipline for config records.
     * The LC line IS the swap point; a torn one fails the load closed. */
    char path[192];
    qihse_uuid_t other;
    assert(qihse_uuid_from_seed("q-other", 7u, &other));
    qihse_uuid_t members2[2] = {*self, other};
    char hex[2 * QIHSE_UUID_BYTES + 1u];
    t_hex_encode(other.bytes, QIHSE_UUID_BYTES, hex);

    /* Torn tail: bytes reached the file, no newline, checksum absent. */
    snprintf(path, sizeof(path), "%s/mrestart-torn.rec", dir);
    {
        FILE* f = fopen(path, "w");
        assert(f);
        t_wline(f, "QHCNS 1 group/hostile");
        t_wline(f, "V 1 - 1");
        fprintf(f, "LC R %s 1 1 1", hex); /* torn mid-write */
        fclose(f);
        qihse_consensus_t* cs = t_open_cfg(path, self, members2, 2u);
        assert(!cs); /* fail closed */
        remove(path);
    }
    /* Roll the torn tail back (as crash recovery tooling would): the file
     * opens on the PREVIOUS config — nothing was swapped. */
    snprintf(path, sizeof(path), "%s/mrestart-rollback.rec", dir);
    {
        FILE* f = fopen(path, "w");
        assert(f);
        t_wline(f, "QHCNS 1 group/hostile");
        t_wline(f, "V 1 - 1");
        fclose(f);
        qihse_consensus_t* cs = t_open_cfg(path, self, members2, 2u);
        assert(cs);
        qihse_consensus_membership_t m2;
        t_membership(cs, &m2);
        assert(m2.member_count == 2u && m2.last_config_index == 0u);
        qihse_consensus_close(cs);
        remove(path);
    }
    /* Swap point landed (committed): opens on the new config, transition
     * complete, and the entry reads back under per-entry authz. */
    snprintf(path, sizeof(path), "%s/mrestart-swapped.rec", dir);
    {
        FILE* f = fopen(path, "w");
        assert(f);
        t_wline(f, "QHCNS 1 group/hostile");
        t_wline(f, "V 1 - 1");
        t_write_config_line(f, 'R', &other, 1u, 1u, 1u);
        t_wline(f, "C 1");
        fclose(f);
        qihse_consensus_t* cs = t_open_cfg(path, self, members2, 2u);
        assert(cs);
        qihse_consensus_membership_t m2;
        t_membership(cs, &m2);
        assert(m2.member_count == 1u && m2.last_config_index == 1u &&
               m2.pending_config_index == 0u);
        qihse_consensus_entry_t out[2];
        size_t got = 0u;
        assert(qihse_consensus_read_committed(cs, op, 1u, out, 2u, &got));
        assert(got == 1u);
        assert(out[0].type == QIHSE_CONSENSUS_ENTRY_CONFIG_REMOVE);
        assert(memcmp(out[0].payload, other.bytes, QIHSE_UUID_BYTES) == 0);
        qihse_consensus_close(cs);
        remove(path);
    }
    /* Swap point landed but uncommitted: restart replays the config
     * history and the transition is exactly "in flight" again. */
    snprintf(path, sizeof(path), "%s/mrestart-inflight.rec", dir);
    {
        FILE* f = fopen(path, "w");
        assert(f);
        t_wline(f, "QHCNS 1 group/hostile");
        t_wline(f, "V 1 - 1");
        t_write_config_line(f, 'R', &other, 1u, 1u, 1u);
        fclose(f);
        qihse_consensus_t* cs = t_open_cfg(path, self, members2, 2u);
        assert(cs);
        qihse_consensus_membership_t m2;
        t_membership(cs, &m2);
        assert(m2.member_count == 1u && m2.pending_config_index == 1u);
        qihse_consensus_close(cs);
        remove(path);
    }

    printf("PASS (q) restart mid-transition: replay lands on the appended "
           "config with the transition in flight; after the swap point the "
           "committed config loads; torn LC write fails closed and rolls "
           "back to the previous config\n");
}

/* ── (f3) Hostile decoder input: the config records ─────────────────────── */

static void test_decoder_hostile_config(const char* dir,
                                        const qihse_uuid_t* self) {
    char path[192];

    qihse_uuid_t other, third;
    assert(qihse_uuid_from_seed("f3-other", 8u, &other));
    assert(qihse_uuid_from_seed("f3-third", 8u, &third));
    qihse_uuid_t members2[2] = {*self, other};
    char hexo[2 * QIHSE_UUID_BYTES + 1u];
    char hext[2 * QIHSE_UUID_BYTES + 1u];
    char hexs[2 * QIHSE_UUID_BYTES + 1u];
    t_hex_encode(other.bytes, QIHSE_UUID_BYTES, hexo);
    t_hex_encode(third.bytes, QIHSE_UUID_BYTES, hext);
    t_hex_encode(self->bytes, QIHSE_UUID_BYTES, hexs);

    struct { const char* name; bool ok; } cases[] = {
        {"LC bad op char", false},
        {"LC uuid short hex", false},
        {"LC uuid long hex", false},
        {"LC uuid non-hex", false},
        {"LC nil uuid", false},
        {"LC index gap", false},
        {"LC term above current", false},
        {"LC generation regressed", false},
        {"LC extra token", false},
        {"LC removes last member", false},
        {"LC adds beyond MAX_MEMBERS", false},
        {"valid LC add + commit", true},
    };

    for (size_t i = 0u; i < sizeof(cases) / sizeof(cases[0]); i++) {
        snprintf(path, sizeof(path), "%s/hcfg%zu.rec", dir, i);
        FILE* f = fopen(path, "w");
        assert(f);
        t_wline(f, "QHCNS 1 group/hostile");
        t_wline(f, "V 1 - 1");

        if (strcmp(cases[i].name, "LC bad op char") == 0) {
            char body[128];
            snprintf(body, sizeof(body), "LC X %s 1 1 1", hexo);
            t_wline(f, body);
        } else if (strcmp(cases[i].name, "LC uuid short hex") == 0) {
            char body[128];
            snprintf(body, sizeof(body), "LC A %.30s 1 1 1", hexo);
            t_wline(f, body);
        } else if (strcmp(cases[i].name, "LC uuid long hex") == 0) {
            char body[128];
            snprintf(body, sizeof(body), "LC A %saa 1 1 1", hexo);
            t_wline(f, body);
        } else if (strcmp(cases[i].name, "LC uuid non-hex") == 0) {
            char body[128];
            snprintf(body, sizeof(body), "LC A %.32s 1 1 1", "zzzzzzzz");
            t_wline(f, body);
        } else if (strcmp(cases[i].name, "LC nil uuid") == 0) {
            char body[128];
            snprintf(body, sizeof(body), "LC A %s 1 1 1", "00000000000000000000000000000000");
            t_wline(f, body);
        } else if (strcmp(cases[i].name, "LC index gap") == 0) {
            char body[128];
            snprintf(body, sizeof(body), "LC A %s 2 1 1", hexo);
            t_wline(f, body);
        } else if (strcmp(cases[i].name, "LC term above current") == 0) {
            char body[128];
            snprintf(body, sizeof(body), "LC A %s 1 5 1", hexo);
            t_wline(f, body);
        } else if (strcmp(cases[i].name, "LC generation regressed") == 0) {
            qihse_consensus_entry_t e1 = t_craft_entry(1u, 1u, 50u);
            t_write_entry_line(f, "L", &e1);
            char body[128];
            snprintf(body, sizeof(body), "LC A %s 2 1 49", hexo);
            t_wline(f, body);
        } else if (strcmp(cases[i].name, "LC extra token") == 0) {
            char body[128];
            snprintf(body, sizeof(body), "LC A %s 1 1 1 7", hexo);
            t_wline(f, body);
        } else if (strcmp(cases[i].name, "LC removes last member") == 0) {
            /* Written twice by mistake is pointless; what matters is the
             * opener below: against a SINGLE-member baseline {self}, an
             * LC R <self> would fold the group to EMPTY — fail closed. */
            char body[128];
            snprintf(body, sizeof(body), "LC R %s 1 1 1", hexs);
            t_wline(f, body);
        } else if (strcmp(cases[i].name, "LC adds beyond MAX_MEMBERS") == 0) {
            for (size_t k = 0u; k < QIHSE_CONSENSUS_MAX_MEMBERS; k++) {
                qihse_uuid_t u;
                char seed[48], body[128], hexu[2 * QIHSE_UUID_BYTES + 1u];
                snprintf(seed, sizeof(seed), "f3-add-%zu", k);
                assert(qihse_uuid_from_seed(seed, strlen(seed), &u));
                t_hex_encode(u.bytes, QIHSE_UUID_BYTES, hexu);
                snprintf(body, sizeof(body), "LC A %s %zu 1 %zu", hexu,
                         k + 1u, k + 1u);
                t_wline(f, body);
            }
        } else if (strcmp(cases[i].name, "valid LC add + commit") == 0) {
            t_write_config_line(f, 'A', &third, 1u, 1u, 1u);
            t_wline(f, "C 1");
        } else {
            assert(!"unreachable case");
        }
        fclose(f);

        qihse_consensus_t* cs;
        if (strcmp(cases[i].name, "LC removes last member") == 0) {
            qihse_uuid_t solo[1] = {*self};
            cs = t_open_cfg(path, self, solo, 1u);
        } else {
            cs = t_open_cfg(path, self, members2, 2u);
        }
        if (cases[i].ok) {
            assert(cs);
            qihse_consensus_membership_t m;
            t_membership(cs, &m);
            assert(m.member_count == 3u && m.last_config_index == 1u &&
                   m.pending_config_index == 0u);
            qihse_consensus_close(cs);
        } else {
            assert(!cs);
        }
        printf("  decoder config %-30s -> %s\n", cases[i].name,
               cs ? "accepted" : "refused");
        remove(path);
    }

    printf("PASS (f3) decoder hostile input: config records fail closed, "
           "valid LC add decodes exactly\n");
}

/* ── (r) Membership determinism ─────────────────────────────────────────── */

static uint64_t t_membership_determinism_run(void) {
    harness_t h;
    h_init(&h, "memdet");
    uint64_t hv = 0xCBF2CE48D222D25BULL;

    int L = h_elect(&h);
    assert(L >= 0);
    hv = t_fold64(hv, (uint64_t)L);
    int R1 = (L + 1u) % N;
    int B = (L + 3u) % N;

    qihse_user_t* op = qihse_auth_get_user(0);
    assert(op);

    t_sever(&h, R1);
    assert(qihse_consensus_propose_membership(
        h.node[L], op, QIHSE_CONSENSUS_MEMBER_REMOVE, &h.id[R1]));
    assert(h_commit_reached_skip(&h, 1u, R1));
    assert(qihse_consensus_propose_membership(
        h.node[L], op, QIHSE_CONSENSUS_MEMBER_REMOVE, &h.id[B]));
    for (unsigned i = 0u; i < 400u; i++) {
        h_tick(&h, 10u);
        if (qihse_consensus_commit_index(h.node[L]) >= 2u) break;
    }
    assert(qihse_consensus_commit_index(h.node[L]) >= 2u);

    h_seed_extra(&h, "memdet");
    qihse_uuid_t members4[4];
    size_t mc = 0u;
    for (int j = 0; j < (int)N; j++) {
        if (j == R1 || j == B) continue;
        members4[mc++] = h.id[j];
    }
    members4[mc++] = h.extra_id;
    x_heal(&h);
    h_open_extra(&h, "memdet", members4, 4u);
    assert(qihse_consensus_propose_membership(
        h.node[L], op, QIHSE_CONSENSUS_MEMBER_ADD, &h.extra_id));
    for (unsigned i = 0u; i < 600u; i++) {
        h_tick(&h, 10u);
        bool all = qihse_consensus_commit_index(h.node[L]) >= 3u;
        all = all && qihse_consensus_commit_index(h.extra) >= 3u;
        if (all) break;
    }
    assert(qihse_consensus_commit_index(h.extra) >= 3u);

    qihse_hlc_t hlc = {50u, 0u};
    assert(qihse_consensus_propose(h.node[L], NULL, 500u, hlc, 0u, 0u,
                                    "det", 3u));
    for (unsigned i = 0u; i < 400u; i++) {
        h_tick(&h, 10u);
        if (qihse_consensus_commit_index(h.node[L]) >= 4u) break;
    }

    qihse_consensus_membership_t m;
    for (size_t j = 0u; j < N; j++) {
        hv = t_fold64(hv, qihse_consensus_term(h.node[j]));
        hv = t_fold64(hv, qihse_consensus_commit_index(h.node[j]));
        hv = t_fold64(hv, qihse_consensus_last_log_index(h.node[j]));
        t_membership(h.node[j], &m);
        hv = t_fold64(hv, (uint64_t)m.member_count);
        hv = t_fold64(hv, (uint64_t)m.majority_needed);
        hv = t_fold64(hv, m.pending_config_index);
        hv = t_fold64(hv, m.last_config_index);
        hv = t_fold64(hv, m.self_removed ? 1u : 0u);
        qihse_consensus_counters_t c;
        qihse_consensus_get_counters(h.node[j], &c);
        hv = t_fold64(hv, c.membership_changes_applied);
        hv = t_fold64(hv, c.membership_proposals_refused);
        hv = t_fold64(hv, c.record_writes);
    }
    t_membership(h.extra, &m);
    hv = t_fold64(hv, (uint64_t)m.member_count);
    hv = t_fold64(hv, m.pending_config_index);
    hv = t_fold64(hv, (uint64_t)qihse_consensus_commit_index(h.extra));
    hv = t_fold64(hv, (uint64_t)qihse_consensus_role(h.extra));

    h_free(&h);
    return hv;
}

static void test_membership_determinism(void) {
    uint64_t a = t_membership_determinism_run();
    uint64_t b = t_membership_determinism_run();
    assert(a == b);
    printf("PASS (r) membership determinism: identical trajectory hash on "
           "two independent runs with transitions enabled (%016llx)\n",
           (unsigned long long)a);
}



int main(void) {
    /* Relative record-file directory only (repo rule: no absolute paths). */
    char dir[128];
    snprintf(dir, sizeof(dir), "build/test_consensus_hostile_XXXXXX");
    if (!mkdtemp(dir)) {
        snprintf(dir, sizeof(dir), "test_consensus_hostile_XXXXXX");
        assert(mkdtemp(dir));
    }

    assert(qihse_auth_init());
    bool bootstrapped = qihse_auth_bootstrap_operator("ConsensusOperator1!");
    if (!bootstrapped) {
        setenv("QIHSE_OPERATOR_PASSWORD", "ConsensusOperator1!", 1);
        assert(qihse_auth_init());
    }
    qihse_user_t* op = qihse_auth_get_user(0);
    assert(op);

    printf("consensus tests: record dir %s\n", dir);

    test_election_single_leader();
    test_partition_local_rw();
    test_commit_requires_majority();
    test_stepdown_and_stale_epoch();
    test_persistence_roundtrip();

    qihse_uuid_t hostile_self;
    char hostile_hex[2 * QIHSE_UUID_BYTES + 1u];
    assert(qihse_uuid_from_seed("hostile-self", 12u, &hostile_self));
    t_hex_encode(hostile_self.bytes, QIHSE_UUID_BYTES, hostile_hex);
    test_decoder_hostile(dir, &hostile_self, hostile_hex);

    test_invariant1_classified_access(op);

    /* Log compaction / snapshot install scenarios. */
    test_snapshot_catchup(op);
    test_compaction_churn(op);
    test_snapshot_tamper_refused();
    test_snapshot_restart_and_crash(&hostile_self, op);
    test_decoder_hostile_snapshot(dir, &hostile_self);
    test_visibility_after_compaction(op);
    test_compaction_determinism();

    /* Membership-change scenarios (single-server transitions). */
    test_membership_transitions(op);
    test_membership_election_safety(op);
    test_membership_leader_change_midflight();
    test_membership_restart(dir, &hostile_self, op);
    test_decoder_hostile_config(dir, &hostile_self);
    test_membership_determinism();

    rmdir(dir);
    printf("all consensus tests passed\n");
    return 0;
}
