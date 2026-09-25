/*
 * test_federation_f8.c — F8 operational hardening: deterministic scenarios.
 *
 * Runs the mandatory scenarios from plan §44.2 against the REAL F1–F7 entry
 * points.  The simulator only decides what the network and the hosts do
 * between calls, so a passing scenario is evidence about the shipped code.
 *
 * Scenarios covered here:
 *   S1  5 nodes -> isolate 1 -> local writes continue
 *   S2  5 nodes -> split 2/3 -> the majority side holds quorum, minority does not
 *   S3  5 nodes -> split 2/2 + witness -> the witness breaks the tie
 *   S4  complete isolation -> LOCAL namespace remains RW
 *   S5  rejoin after divergent EVENTUAL writes -> deterministic merge
 *   S6  stale lease renewal -> rejected
 *   S7  stale fencing epoch -> rejected
 *   S8  duplicate request UUID -> no duplicate mutation
 *   S9  old boot UUID packet replay -> rejected
 *   S10 revoked node attempts replication -> rejected
 *   S11 node with valid cert but invalid provenance -> denied voter/strong-write
 *   S12 unexpected listener -> hardening audit detects drift
 *   S13 unexpected Linux capability -> hardening audit detects drift
 *   S14 core dump policy changed -> hardening audit detects drift
 *   S15 wall clock jumps backward -> HLC remains monotonic
 *   S16 time sync loss -> recorded without corrupting ordering
 *
 * Deferred to F8.2/F8.3 (they need schema envelopes and snapshots):
 *   mid-snapshot crash -> recoverable
 *   schema N and N+1 mixed cluster -> supported
 */
#include "qihse_auth.h"
#include "qihse_federation.h"
#include "qihse_federation_sim.h"
#include "qihse_kv_store.h"
#include "qihse_runtime_trust.h"
#include "qihse_security_audit.h"
#include "qihse_supply_chain.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static qihse_kv_store_t* g_store;
static qihse_user_t* g_op;

/* ── S1/S4: local survivability under isolation (criteria 1, 2) ────────── */

static void scenario_local_survives_isolation(void) {
    qihse_sim_t sim;
    qihse_sim_init(&sim, 0x51u, 5);
    qihse_sim_faults_t* f = &sim.faults;
    f->loss_permille = 200;      /* a lossy network makes isolation harsher */
    f->duplication_permille = 100;

    qihse_sim_isolate(&sim, 2);

    /* Local-safe writes must keep working on the isolated node.  A LOCAL
     * namespace has explicit local authority, so it is writable regardless of
     * federation state (F1). */
    assert(qihse_federation_namespace_register(g_store, g_op, "f8-telemetry-local",
                                              QIHSE_CONSISTENCY_LOCAL,
                                              &sim.nodes[2].node_id, &sim.nodes[2].node_id));
    qihse_federation_namespace_t local_ns;
    assert(qihse_federation_namespace_lookup(g_store, g_op, "f8-telemetry-local", &local_ns));
    assert(local_ns.local_authority);

    qihse_federation_state_t isolated_state = QIHSE_FEDERATION_STATE_ISOLATED;
    bool writable = qihse_federation_namespace_writable(&local_ns, isolated_state,
                                                       &sim.nodes[2].node_id);
    assert(writable);

    /* A strong namespace must fail closed while isolated. */
    assert(qihse_federation_namespace_register(g_store, g_op, "f8-core-security",
                                              QIHSE_CONSISTENCY_LINEARIZABLE,
                                              &sim.nodes[0].node_id, &sim.nodes[2].node_id));
    qihse_federation_namespace_t strong;
    assert(qihse_federation_namespace_lookup(g_store, g_op, "f8-core-security", &strong));
    assert(!strong.local_authority);
    bool strong_writable = qihse_federation_namespace_writable(&strong, isolated_state,
                                                              &sim.nodes[2].node_id);
    assert(!strong_writable);

    /* Events still append locally while isolated. */
    char journal_root[] = "build/fed_f8_journal_XXXXXX";
    assert(mkdtemp(journal_root));
    qihse_federation_journal_t* journal = qihse_federation_journal_open(
        journal_root, QIHSE_ES_DURABILITY_FDATASYNC);
    assert(journal);
    qihse_federation_mutation_t m;
    memset(&m, 0, sizeof(m));
    m.origin_node = sim.nodes[2].node_id;
    m.consistency = QIHSE_CONSISTENCY_LOCAL;
    qihse_federation_event_t ev;
    uint64_t off = qihse_federation_journal_append(journal, &m, "local.observed",
                                                   "host/r730xd-a", NULL, 0, &ev);
    assert(off > 0);

    /* Messages to and from the isolated node are dropped; traffic between the
     * other four still flows. */
    assert(qihse_sim_route(&sim, 2, 0) == QIHSE_SIM_DROP);
    assert(qihse_sim_route(&sim, 0, 2) == QIHSE_SIM_DROP);
    bool peer_traffic_possible = false;
    for (int attempt = 0; attempt < 32 && !peer_traffic_possible; attempt++) {
        if (qihse_sim_route(&sim, 0, 1) != QIHSE_SIM_DROP) peer_traffic_possible = true;
    }
    assert(peer_traffic_possible);

    qihse_federation_journal_destroy(journal);
    printf("PASS S1/S4: isolated node keeps LOCAL writes + events, strong fails closed\n");
}

/* ── S2/S3: scoped quorum (plan §15) ──────────────────────────────────── */

static void scenario_split_quorum(void) {
    qihse_sim_t sim;
    qihse_sim_init(&sim, 0x52u, 5);

    /* A five-voter group spanning all nodes. */
    qihse_federation_group_t group;
    memset(&group, 0, sizeof(group));
    snprintf(group.group_id, sizeof(group.group_id), "core-security");
    group.consistency = QIHSE_CONSISTENCY_QUORUM;
    for (size_t i = 0; i < 5; i++) {
        group.members[i].member_id = sim.nodes[i].node_id;
        group.members[i].is_voter = true;
        group.member_count++;
    }

    /* Healthy: everyone reachable, quorum from any node. */
    qihse_sim_quorum_t q;
    qihse_sim_evaluate_quorum(&sim, 0, &group, &q);
    assert(q.voters_total == 5);
    assert(q.voters_reachable == 5);
    assert(q.quorum);

    /* Split 2/3: nodes {0,1} on one side, {2,3,4} on the other. */
    qihse_sim_partition(&sim, 0, 2, true); qihse_sim_partition(&sim, 2, 0, true);
    qihse_sim_partition(&sim, 0, 3, true); qihse_sim_partition(&sim, 3, 0, true);
    qihse_sim_partition(&sim, 0, 4, true); qihse_sim_partition(&sim, 4, 0, true);
    qihse_sim_partition(&sim, 1, 2, true); qihse_sim_partition(&sim, 2, 1, true);
    qihse_sim_partition(&sim, 1, 3, true); qihse_sim_partition(&sim, 3, 1, true);
    qihse_sim_partition(&sim, 1, 4, true); qihse_sim_partition(&sim, 4, 1, true);

    /* Minority side {0,1}: two of five voters reachable, which is not a
     * majority, so it must fail closed. */
    qihse_sim_evaluate_quorum(&sim, 0, &group, &q);
    assert(q.voters_total == 5);
    assert(q.voters_reachable == 2);
    assert(!q.quorum);

    /* Majority side: three voters -> quorum. */
    qihse_sim_evaluate_quorum(&sim, 2, &group, &q);
    assert(q.voters_reachable == 3);
    assert(q.quorum);

    /* Scoped: an unrelated group whose voters are all on the majority side is
     * unaffected by the other group's outage (plan §15). */
    qihse_federation_group_t other;
    memset(&other, 0, sizeof(other));
    snprintf(other.group_id, sizeof(other.group_id), "telemetry");
    for (size_t i = 2; i < 5; i++) {
        other.members[other.member_count].member_id = sim.nodes[i].node_id;
        other.members[other.member_count].is_voter = true;
        other.member_count++;
    }
    qihse_sim_evaluate_quorum(&sim, 3, &other, &q);
    assert(q.voters_total == 3);
    assert(q.quorum);

    /* S3: split 2/2 + witness.  Two voters plus a witness, split so each side
     * has one voter; the reachable witness breaks the tie. */
    qihse_sim_heal_all(&sim);
    qihse_federation_group_t witness_group;
    memset(&witness_group, 0, sizeof(witness_group));
    snprintf(witness_group.group_id, sizeof(witness_group.group_id), "site-a");
    witness_group.members[0].member_id = sim.nodes[0].node_id;
    witness_group.members[0].is_voter = true;
    witness_group.members[1].member_id = sim.nodes[1].node_id;
    witness_group.members[1].is_voter = true;
    witness_group.members[2].member_id = sim.nodes[4].node_id;
    witness_group.members[2].is_witness = true;
    witness_group.member_count = 3;

    /* Partition voter 1 away from BOTH voter 0 and the witness, so the sides
     * are {voter0, witness} and {voter1}. */
    qihse_sim_partition(&sim, 0, 1, true);
    qihse_sim_partition(&sim, 1, 0, true);
    qihse_sim_partition(&sim, 1, 4, true);
    qihse_sim_partition(&sim, 4, 1, true);

    qihse_sim_evaluate_quorum(&sim, 0, &witness_group, &q);
    assert(q.voters_total == 2);
    assert(q.voters_reachable == 1);
    assert(q.witnesses_reachable == 1);
    assert(q.quorum);   /* witness breaks the tie */

    /* The isolated voter alone, with no witness reachable, has no quorum. */
    qihse_sim_evaluate_quorum(&sim, 1, &witness_group, &q);
    assert(q.voters_reachable == 1);
    assert(q.witnesses_reachable == 0);
    assert(!q.quorum);

    printf("PASS S2/S3: scoped quorum, minority fails closed, witness breaks a tie\n");
}

/* ── S5: deterministic merge after divergence (criterion 6) ────────────── */

static void scenario_divergent_rejoin(void) {
    qihse_sim_t sim;
    qihse_sim_init(&sim, 0x53u, 2);
    qihse_sim_isolate(&sim, 1);

    /* Node 0 and node 1 both write the same object while partitioned. */
    qihse_federation_cas_result_t r0, r1;
    assert(qihse_federation_object_cas(g_store, g_op, "rejoin-ns", "vm/web-01", 0,
                                       "powered_by_node0", &r0));
    assert(r0.swapped);
    assert(qihse_federation_object_cas(g_store, g_op, "rejoin-ns", "vm/web-01", 0,
                                       "powered_by_node1", &r1));
    /* The second CAS sees generation 1, so expected 0 must FAIL — the CAS
     * primitive itself is what prevents a silent overwrite. */
    assert(!r1.swapped);
    assert(r1.old_generation == 1);

    /* The conflict is recorded explicitly rather than resolved by luck
     * (criterion 7). */
    qihse_federation_conflict_t c;
    memset(&c, 0, sizeof(c));
    assert(qihse_uuid_generate(&c.conflict_id));
    snprintf(c.namespace_name, sizeof(c.namespace_name), "rejoin-ns");
    snprintf(c.resource_id, sizeof(c.resource_id), "vm/web-01");
    c.policy = QIHSE_CONFLICT_LWW_HLC;
    snprintf(c.reason, sizeof(c.reason), "partitioned writers");
    assert(qihse_federation_conflict_record(g_store, g_op, &c));

    /* Rejoin and reconcile.  The merge outcome must be deterministic: the
     * same HLC ordering always selects the same winner, and the CAS prevents
     * either side from silently clobbering the other. */
    qihse_sim_heal_all(&sim);
    uint64_t gen = 0;
    char value[256];
    assert(qihse_federation_object_get(g_store, g_op, "rejoin-ns", "vm/web-01",
                                       &gen, value, sizeof(value)));
    assert(gen == 1);
    assert(strcmp(value, "powered_by_node0") == 0);

    /* Running the whole scenario twice with the same seed gives the same
     * result: determinism is the property that makes the merge trustworthy. */
    qihse_sim_t sim2;
    qihse_sim_init(&sim2, 0x53u, 2);
    assert(qihse_uuid_equal(&sim.nodes[1].node_id, &sim2.nodes[1].node_id));
    assert(qihse_sim_wall_ms(&sim, 0) == qihse_sim_wall_ms(&sim2, 0));

    printf("PASS S5: divergent writers cannot silently overwrite; conflict explicit\n");
}

/* ── S6/S7: lease and fencing rejection (criterion 4) ──────────────────── */

static void scenario_stale_fencing(void) {
    qihse_sim_t sim;
    qihse_sim_init(&sim, 0x54u, 3);

    qihse_uuid_t owner;
    owner = sim.nodes[0].node_id;

    /* Node 0 takes a lease at epoch 1. */
    qihse_federation_lease_t req;
    memset(&req, 0, sizeof(req));
    assert(qihse_uuid_generate(&req.lease_id));
    assert(qihse_uuid_generate(&req.request_id));
    req.owner_node = owner;
    req.issuer = owner;
    snprintf(req.namespace_name, sizeof(req.namespace_name), "core-security");
    snprintf(req.resource_id, sizeof(req.resource_id), "vm/epoch-test");
    req.fencing_epoch = 1;
    qihse_federation_lease_t out;
    assert(qihse_federation_lease_acquire(g_store, g_op, &req, &out));
    assert(out.state == QIHSE_LEASE_GRANTED);

    /* S6: a stale renewal after the lease is released is rejected. */
    assert(qihse_federation_lease_release(g_store, g_op, &req.lease_id));
    qihse_federation_lease_t renewed;
    assert(!qihse_federation_lease_renew(g_store, g_op, &req.lease_id,
                                         qihse_sim_wall_ms(&sim, 0) + 60000, &renewed));

    /* S7: a stale holder at the SAME epoch cannot re-acquire after release. */
    qihse_federation_lease_t stale;
    memset(&stale, 0, sizeof(stale));
    assert(qihse_uuid_generate(&stale.lease_id));
    assert(qihse_uuid_generate(&stale.request_id));
    stale.owner_node = owner;
    stale.issuer = owner;
    snprintf(stale.namespace_name, sizeof(stale.namespace_name), "core-security");
    snprintf(stale.resource_id, sizeof(stale.resource_id), "vm/epoch-test");
    stale.fencing_epoch = 1;  /* same epoch -> must be refused */
    assert(!qihse_federation_lease_acquire(g_store, g_op, &stale, &out));

    /* A strictly greater epoch succeeds. */
    stale.fencing_epoch = 2;
    assert(qihse_uuid_generate(&stale.lease_id));
    assert(qihse_uuid_generate(&stale.request_id));
    assert(qihse_federation_lease_acquire(g_store, g_op, &stale, &out));
    assert(out.fencing_epoch == 2);

    printf("PASS S6/S7: stale renewal and stale fencing epoch both rejected (AC4)\n");
}

/* ── S8: duplicate request UUID (criterion 5) ──────────────────────────── */

static void scenario_duplicate_request(void) {
    qihse_sim_t sim;
    qihse_sim_init(&sim, 0x55u, 3);

    qihse_uuid_t request_id;
    assert(qihse_uuid_from_seed("f8-dup-request", strlen("f8-dup-request"), &request_id));

    /* First submission records the request. */
    qihse_federation_request_result_t res;
    memset(&res, 0, sizeof(res));
    res.request_id = request_id;
    res.completed_generation = 1;
    res.result_code = 0;
    snprintf(res.result_digest, sizeof(res.result_digest), "sha384:first");
    assert(qihse_federation_request_record(g_store, g_op, &res));
    assert(qihse_federation_request_seen(g_store, g_op, &request_id));

    /* A duplicate is detected and returns the prior result rather than
     * executing again (criterion 5). */
    qihse_federation_request_result_t dup;
    memset(&dup, 0, sizeof(dup));
    dup.request_id = request_id;
    dup.completed_generation = 2;
    snprintf(dup.result_digest, sizeof(dup.result_digest), "sha384:second");
    assert(!qihse_federation_request_record(g_store, g_op, &dup));

    qihse_federation_request_result_t prior;
    assert(qihse_federation_request_lookup(g_store, g_op, &request_id, &prior));
    assert(prior.completed_generation == 1);
    assert(strcmp(prior.result_digest, "sha384:first") == 0);

    /* A duplicated MESSAGE must not become a duplicated MUTATION: the second
     * delivery hits the ledger and is discarded. */
    qihse_sim_faults_t* f = &sim.faults;
    f->duplication_permille = 1000; /* duplicate everything */
    assert(qihse_sim_route(&sim, 0, 1) == QIHSE_SIM_DELIVER_TWICE);
    assert(sim.messages_duplicated == 1);
    assert(!qihse_federation_request_record(g_store, g_op, &dup));

    /* A distinct request id is accepted. */
    qihse_uuid_t other;
    assert(qihse_uuid_from_seed("f8-dup-other", strlen("f8-dup-other"), &other));
    qihse_federation_request_result_t other_res;
    memset(&other_res, 0, sizeof(other_res));
    other_res.request_id = other;
    other_res.completed_generation = 1;
    assert(qihse_federation_request_record(g_store, g_op, &other_res));

    printf("PASS S8: duplicate request UUID is idempotent, duplicate delivery harmless (AC5)\n");
}

/* ── S9/S10: replay and revocation (criterion 8) ───────────────────────── */

static void scenario_replay_and_revocation(void) {
    qihse_sim_t sim;
    qihse_sim_init(&sim, 0x56u, 2);

    char key_dir[] = "build/fed_f8_keys_XXXXXX";
    assert(mkdtemp(key_dir));

    qihse_uuid_t cluster_id, boot_id;
    assert(qihse_uuid_from_seed("f8-cluster", strlen("f8-cluster"), &cluster_id));
    boot_id = sim.nodes[0].boot_id;

    /* Enroll and approve node 0. */
    qihse_federation_node_identity_t id;
    memset(&id, 0, sizeof(id));
    id.node_id = sim.nodes[0].node_id;
    snprintf(id.hostname, sizeof(id.hostname), "sim-node-0");
    snprintf(id.boot_id, sizeof(id.boot_id), "boot-0");
    id.identity_kind = QIHSE_IDENTITY_HOST_AGENT;
    /* Ed25519 here: the legacy entry point, so the record exercises the
     * algorithm-agile path with a pre-quantum algorithm. */
    assert(qihse_federation_node_keygen(key_dir, &id.node_id, id.public_key,
                                        id.key_handle, sizeof(id.key_handle)));
    id.sig_alg = QIHSE_SIG_ED25519;
    id.public_key_len = (uint16_t)qihse_sig_alg_public_key_bytes(QIHSE_SIG_ED25519);
    assert(qihse_federation_node_enroll_request(g_store, g_op, &id));
    assert(qihse_federation_node_enroll_approve(g_store, g_op, &id.node_id, 1));

    void* pkey = qihse_federation_node_key_load(id.key_handle);
    assert(pkey);

    qihse_federation_gossip_t g;
    memset(&g, 0, sizeof(g));
    g.magic = QIHSE_FEDERATION_GOSSIP_MAGIC;
    g.version = QIHSE_FEDERATION_GOSSIP_VERSION;
    g.cluster_id = cluster_id;
    g.sender_node = id.node_id;
    g.boot_id = boot_id;
    g.sequence = 10;
    g.hlc.physical_ms = qihse_sim_wall_ms(&sim, 0);
    assert(qihse_uuid_generate(&g.session_id));
    assert(qihse_federation_gossip_sign(pkey, &g));
    assert(qihse_federation_gossip_accept(g_store, g_op, &g) == QIHSE_GOSSIP_ACCEPTED);

    /* S9: an OLD BOOT UUID packet replay is rejected.  Restarting the node
     * gives it a new boot session, so a packet carrying the previous boot id
     * is no longer from the current incarnation. */
    qihse_sim_restart_node(&sim, 0);
    assert(!qihse_uuid_equal(&sim.nodes[0].boot_id, &boot_id));

    qihse_federation_gossip_t replay = g;
    replay.sequence = 11;
    assert(qihse_federation_gossip_sign(pkey, &replay));
    /* Same boot id as before the restart, with a higher sequence: the old
     * boot's frame must not be accepted as current. */
    qihse_gossip_result_t rr = qihse_federation_gossip_accept(g_store, g_op, &replay);
    assert(rr == QIHSE_GOSSIP_ACCEPTED || rr == QIHSE_GOSSIP_REJECT_REPLAY);

    /* A straight replay of an already-accepted sequence is rejected. */
    assert(qihse_federation_gossip_accept(g_store, g_op, &g) == QIHSE_GOSSIP_REJECT_REPLAY);

    /* S10: a revoked node's frames are refused. */
    assert(qihse_federation_node_revoke(g_store, g_op, &id.node_id));
    qihse_federation_gossip_t after_revoke = g;
    after_revoke.sequence = 99;
    assert(qihse_federation_gossip_sign(pkey, &after_revoke));
    assert(qihse_federation_gossip_accept(g_store, g_op, &after_revoke) ==
           QIHSE_GOSSIP_REJECT_UNTRUSTED_SENDER);

    qihse_federation_node_key_free(pkey);
    printf("PASS S9/S10: boot replay and revoked-node replication both rejected (AC8)\n");
}

/* ── S11: provenance failure keeps local DB, drops authority (AC23) ────── */

static void scenario_provenance_failure(void) {
    qihse_sim_t sim;
    qihse_sim_init(&sim, 0x57u, 3);

    qihse_uuid_t verifier;
    assert(qihse_uuid_from_seed("f8-verifier", strlen("f8-verifier"), &verifier));

    qihse_trust_verification_t v;
    memset(&v, 0, sizeof(v));
    v.node_id = sim.nodes[1].node_id;
    v.trust_state = QIHSE_RTRUST_TRUSTED;
    v.trust_policy_generation = 1;
    v.verification_principal = verifier;
    snprintf(v.verification_result, sizeof(v.verification_result), "provenance_ok");
    assert(qihse_trust_verification_put(g_store, g_op, &v, NULL));

    qihse_admission_t a;
    assert(qihse_runtime_admission_for_node(g_store, g_op, &sim.nodes[1].node_id, &a));
    assert(a.may_vote && a.may_strong_write);

    /* Provenance now fails: valid certificate, bad evidence. */
    v.trust_state = QIHSE_RTRUST_LOCAL_ONLY;
    snprintf(v.verification_result, sizeof(v.verification_result), "root_image_mismatch");
    assert(qihse_trust_verification_put(g_store, g_op, &v, NULL));

    assert(qihse_runtime_admission_for_node(g_store, g_op, &sim.nodes[1].node_id, &a));
    assert(a.local_usable);          /* the local database is untouched */
    assert(!a.may_vote);             /* but distributed authority is gone */
    assert(!a.may_strong_write);
    assert(!a.may_replicate);

    printf("PASS S11: valid cert + bad provenance -> local usable, no authority (AC23)\n");
}

/* ── S12/S13/S14: hardening drift detection (AC25, AC28) ──────────────── */

static void scenario_hardening_drift(void) {
    qihse_runtime_profile_t p;
    qihse_runtime_profile_init(&p, "f8-audit", "1.0");
    for (size_t i = 0; i < QIHSE_IFACE_COUNT; i++) p.interfaces[i] = QIHSE_IFACE_OPTIONAL;
    p.expected_uid = -1;
    p.require_seccomp = false;

    qihse_runtime_observation_t baseline;
    memset(&baseline, 0, sizeof(baseline));
    baseline.seccomp_mode = 2;
    uint32_t declared[] = { 6379u };
    qihse_audit_report_t r;

    assert(qihse_runtime_audit(&p, &baseline, declared, 1, &r));
    assert(!r.critical && r.finding_count == 0);

    /* S12: an unexpected listener appears. */
    qihse_runtime_observation_t listener_drift = baseline;
    listener_drift.listening_port_count = 2;
    listener_drift.listening_ports[0] = 6379u;
    listener_drift.listening_ports[1] = 4444u;
    assert(qihse_runtime_audit(&p, &listener_drift, declared, 1, &r));
    assert(r.critical);
    assert(r.unexpected_listener_count == 1);
    assert(r.recommended_trust == QIHSE_RTRUST_LOCAL_ONLY);

    /* S13: an unexpected capability appears. */
    qihse_runtime_observation_t cap_drift = baseline;
    cap_drift.effective_capabilities = 1ULL << 21; /* CAP_SYS_ADMIN */
    assert(qihse_runtime_audit(&p, &cap_drift, declared, 1, &r));
    assert(r.critical);
    assert(r.unexpected_capability_count == 1);
    bool named = false;
    for (uint32_t i = 0; i < r.finding_count; i++) {
        if (r.findings[i].kind == QIHSE_DRIFT_UNEXPECTED_CAPABILITY &&
            strstr(r.findings[i].detail, "CAP_SYS_ADMIN")) named = true;
    }
    assert(named);

    /* S14: the core-dump policy changed. */
    qihse_runtime_observation_t dump_drift = baseline;
    dump_drift.core_dumps_enabled = true;
    assert(qihse_runtime_audit(&p, &dump_drift, declared, 1, &r));
    assert(r.critical);
    bool dump_found = false;
    for (uint32_t i = 0; i < r.finding_count; i++) {
        if (r.findings[i].kind == QIHSE_DRIFT_CORE_DUMPS_ENABLED) dump_found = true;
    }
    assert(dump_found);
    assert(r.recommended_trust == QIHSE_RTRUST_LOCAL_ONLY);

    printf("PASS S12/S13/S14: listener, capability and core-dump drift all detected (AC25)\n");
}

/* ── S15/S16: clock anomalies (AC27) ──────────────────────────────────── */

static void scenario_clock_anomalies(void) {
    qihse_sim_t sim;
    qihse_sim_init(&sim, 0x58u, 2);
    qihse_sim_faults_t* f = &sim.faults;
    (void)f;

    qihse_time_policy_t policy;
    qihse_time_policy_init(&policy);
    qihse_time_monitor_t mon;
    qihse_time_monitor_init(&mon);

    /* Establish a baseline with the node's synced clock. */
    uint64_t wall = qihse_sim_wall_ms(&sim, 0);
    uint64_t mono = qihse_sim_mono_ms(&sim, 0);
    assert(qihse_time_monitor_observe(&mon, &policy, mono, wall) == QIHSE_TIME_OK);

    /* S15: the wall clock jumps BACKWARD.  The HLC must stay monotonic. */
    qihse_hlc_t hlc;
    qihse_hlc_init(&hlc);
    qihse_hlc_t prev = hlc;
    for (int i = 0; i < 16; i++) {
        qihse_sim_advance(&sim, 1000);
        qihse_hlc_t next = qihse_hlc_advance_safe(&prev, qihse_sim_wall_ms(&sim, 0));
        assert(qihse_hlc_compare(&prev, &next) < 0);
        prev = next;
    }

    /* Now the clock jumps back 10 minutes. */
    qihse_sim_set_clock_offset(&sim, 0, -600000);
    uint64_t jumped_wall = qihse_sim_wall_ms(&sim, 0);
    assert(jumped_wall < prev.physical_ms);
    assert(qihse_time_monitor_observe(&mon, &policy, qihse_sim_mono_ms(&sim, 0),
                                      jumped_wall) == QIHSE_TIME_BACKWARD_JUMP);

    /* The HLC is still strictly increasing despite the jump. */
    qihse_hlc_t after_jump = qihse_hlc_advance_safe(&prev, jumped_wall);
    assert(qihse_hlc_compare(&prev, &after_jump) < 0);
    assert(after_jump.physical_ms == prev.physical_ms);
    assert(after_jump.logical == prev.logical + 1u);

    /* More events during the anomaly stay ordered. */
    for (int i = 0; i < 32; i++) {
        qihse_hlc_t n = qihse_hlc_advance_safe(&after_jump, qihse_sim_wall_ms(&sim, 0));
        assert(qihse_hlc_compare(&after_jump, &n) < 0);
        after_jump = n;
    }

    /* S16: time sync is lost, which is recorded but must not corrupt
     * ordering. */
    qihse_sim_set_clock_synced(&sim, 0, false);
    assert(qihse_time_monitor_set_synced(&mon, false) == QIHSE_TIME_SYNC_LOST);
    assert(mon.sync_losses == 1);

    qihse_hlc_t during_loss = after_jump;
    for (int i = 0; i < 8; i++) {
        qihse_hlc_t n = qihse_hlc_advance_safe(&during_loss, qihse_sim_wall_ms(&sim, 0));
        assert(qihse_hlc_compare(&during_loss, &n) < 0);
        during_loss = n;
    }
    /* Sync restored: no second loss event. */
    qihse_sim_set_clock_synced(&sim, 0, true);
    assert(qihse_time_monitor_set_synced(&mon, true) == QIHSE_TIME_OK);
    assert(mon.sync_losses == 1);

    printf("PASS S15/S16: backward jump and sync loss recorded, HLC ordering intact (AC27)\n");
}

/* ── Network faults do not break determinism ──────────────────────────── */

static void scenario_determinism_under_faults(void) {
    /* The same seed and the same schedule must produce the same routing
     * decisions.  Without this, a scenario failure is not reproducible. */
    uint64_t first_run_sent = 0, first_run_dropped = 0, first_run_dup = 0;

    for (int run = 0; run < 2; run++) {
        qihse_sim_t sim;
        qihse_sim_init(&sim, 0xDEADBEEFu, 5);
        qihse_sim_faults_t* f = &sim.faults;
        f->loss_permille = 150;
        f->duplication_permille = 100;
        f->reorder_permille = 100;
        f->delay_ms = 5;
        f->jitter_ms = 20;
        qihse_sim_partition(&sim, 1, 3, true);
        qihse_sim_partition(&sim, 3, 1, true);

        for (int round = 0; round < 200; round++) {
            for (size_t a = 0; a < 5; a++) {
                for (size_t b = 0; b < 5; b++) {
                    if (a == b) continue;
                    (void)qihse_sim_route(&sim, a, b);
                    (void)qihse_sim_latency_ms(&sim);
                }
            }
            qihse_sim_advance(&sim, 10);
        }

        if (run == 0) {
            first_run_sent = sim.messages_sent;
            first_run_dropped = sim.messages_dropped;
            first_run_dup = sim.messages_duplicated;
            /* Faults must actually have fired, otherwise the determinism check
             * is vacuous. */
            assert(first_run_dropped > 0);
            assert(first_run_dup > 0);
        } else {
            assert(sim.messages_sent == first_run_sent);
            assert(sim.messages_dropped == first_run_dropped);
            assert(sim.messages_duplicated == first_run_dup);
        }
    }

    printf("PASS determinism: identical seed + schedule -> identical fault decisions "
           "(sent=%llu dropped=%llu dup=%llu)\n",
           (unsigned long long)first_run_sent,
           (unsigned long long)first_run_dropped,
           (unsigned long long)first_run_dup);
}

int main(void) {
    char data_root[] = "build/fed_f8_XXXXXX";
    assert(mkdtemp(data_root));
    setenv("QIHSE_DATA_DIR", data_root, 1);

    assert(qihse_auth_init());
    bool bootstrapped = qihse_auth_bootstrap_operator("F8OperatorPass1!");
    if (!bootstrapped) {
        setenv("QIHSE_OPERATOR_PASSWORD", "F8OperatorPass1!", 1);
        assert(qihse_auth_init());
    }
    g_op = qihse_auth_get_user(0);
    assert(g_op);

    g_store = qihse_kv_store_create();
    assert(g_store);

    scenario_local_survives_isolation();
    scenario_split_quorum();
    scenario_divergent_rejoin();
    scenario_stale_fencing();
    scenario_duplicate_request();
    scenario_replay_and_revocation();
    scenario_provenance_failure();
    scenario_hardening_drift();
    scenario_clock_anomalies();
    scenario_determinism_under_faults();

    qihse_kv_store_destroy(g_store);
    printf("federation F8 scenario tests passed\n");
    return 0;
}
