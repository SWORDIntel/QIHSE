/*
 * test_federation_f7.c — F7 runtime trust and hardening.
 *
 * Acceptance criteria exercised:
 *   AC23 — A node with valid credentials but failed provenance can remain
 *          locally usable while being denied trusted federation authority.
 *   AC24 — QIHSE exposes a runtime hardening audit based on actual
 *          process/system state.
 *   AC25 — Unexpected listeners, capabilities, provenance drift and
 *          runtime-profile drift are detectable.
 *   AC26 — QIHSE requires no unrestricted Internet egress.
 *   AC27 — Wall-clock anomalies do not break HLC ordering.
 *   AC28 — Production core-dump policy and sensitive kernel-interface
 *          policy are explicitly testable.
 *
 * Covers:
 *   - trust state vocabulary + admission decision for every state
 *   - evidence bundle immutability and verification records
 *   - time monitor anomaly detection (backward/forward/monotonic/sync)
 *   - HLC monotonicity under injected bad wall clocks
 *   - interface classification vocabulary and production defaults
 *   - runtime profile put/get
 *   - runtime observation reads ACTUAL kernel state
 *   - audit drift detection for capabilities, core dumps, listeners, ifaces
 *   - network profile egress restriction + unexpected listener detection
 *   - RESP-level commands + tenant-guest NOPERM (invariant 3)
 */
#include "qihse_auth.h"
#include "qihse_cluster_slot.h"
#include "qihse_federation.h"
#include "qihse_kv_store.h"
#include "qihse_resp_wire.h"
#include "qihse_runtime_trust.h"
#include "qihse_security_audit.h"

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

/* ── Trust states and admission (AC23) ─────────────────────────────────── */

static void test_trust_vocabulary(void) {
    for (int i = 0; i <= (int)QIHSE_RTRUST_REVOKED; i++) {
        qihse_runtime_trust_t t = (qihse_runtime_trust_t)i;
        const char* name = qihse_runtime_trust_name(t);
        assert(name != NULL);
        /* UNKNOWN is a real state here, not a lookup failure. */
        qihse_runtime_trust_t parsed;
        assert(qihse_runtime_trust_parse(name, &parsed));
        assert(parsed == t);
    }
    qihse_runtime_trust_t dummy;
    assert(!qihse_runtime_trust_parse("NOPE", &dummy));
    printf("PASS runtime trust vocabulary: 6 states round-trip\n");
}

static void test_admission(void) {
    /* AC23: local usability is NEVER gated on federation trust. */
    for (int i = 0; i <= (int)QIHSE_RTRUST_REVOKED; i++) {
        qihse_admission_t a;
        qihse_runtime_admission_evaluate((qihse_runtime_trust_t)i, &a);
        assert(a.local_usable);
        assert(a.reason[0] != '\0');
    }

    /* Only TRUSTED gets full distributed authority. */
    qihse_admission_t t;
    qihse_runtime_admission_evaluate(QIHSE_RTRUST_TRUSTED, &t);
    assert(t.may_replicate && t.may_read_remote && t.may_strong_write && t.may_vote);

    /* Degraded keeps reads but loses strong-write and vote. */
    qihse_admission_t d;
    qihse_runtime_admission_evaluate(QIHSE_RTRUST_TRUSTED_DEGRADED, &d);
    assert(d.local_usable);
    assert(d.may_replicate && d.may_read_remote);
    assert(!d.may_strong_write && !d.may_vote);

    /* LOCAL_ONLY, QUARANTINED and REVOKED lose all federation authority but
     * keep the local database. */
    for (int i = (int)QIHSE_RTRUST_LOCAL_ONLY; i <= (int)QIHSE_RTRUST_REVOKED; i++) {
        qihse_admission_t a;
        qihse_runtime_admission_evaluate((qihse_runtime_trust_t)i, &a);
        assert(a.local_usable);
        assert(!a.may_replicate && !a.may_read_remote);
        assert(!a.may_strong_write && !a.may_vote);
    }

    /* UNKNOWN withholds authority too. */
    qihse_admission_t u;
    qihse_runtime_admission_evaluate(QIHSE_RTRUST_UNKNOWN, &u);
    assert(u.local_usable && !u.may_vote && !u.may_strong_write);

    printf("PASS admission: local_usable true in every state, authority tiered (AC23)\n");
}

/* ── Evidence and verification (AC25) ──────────────────────────────────── */

static void test_evidence(qihse_kv_store_t* store, qihse_user_t* op) {
    qihse_uuid_t node_id, boot_id;
    assert(qihse_uuid_from_seed("f7-node-1", strlen("f7-node-1"), &node_id));
    assert(qihse_uuid_from_seed("f7-boot-1", strlen("f7-boot-1"), &boot_id));

    qihse_trust_evidence_t e;
    memset(&e, 0, sizeof(e));
    e.node_id = node_id;
    e.boot_id = boot_id;
    snprintf(e.citadel_release, sizeof(e.citadel_release), "citadel-2026.09");
    snprintf(e.root_image_digest, sizeof(e.root_image_digest), "sha384:rootimage");
    snprintf(e.qihse_artifact_digest, sizeof(e.qihse_artifact_digest), "sha384:qihse-artifact");
    snprintf(e.qihse_sbom_digest, sizeof(e.qihse_sbom_digest), "sha384:qihse-sbom");
    snprintf(e.qihse_provenance_digest, sizeof(e.qihse_provenance_digest), "sha384:qihse-prov");
    snprintf(e.kernel_image, sizeof(e.kernel_image), "linux-6.12.9");
    snprintf(e.xen_image, sizeof(e.xen_image), "xen-4.19");
    snprintf(e.measured_boot_state, sizeof(e.measured_boot_state), "pcr-ok");
    snprintf(e.tpm_attestation_ref, sizeof(e.tpm_attestation_ref), "tpm-quote-7");
    e.policy_generation = 11;
    e.hardening_audit_generation = 4;

    assert(qihse_trust_evidence_put(store, op, &e));
    /* Evidence is immutable per boot. */
    assert(!qihse_trust_evidence_put(store, op, &e));

    qihse_trust_evidence_t got;
    assert(qihse_trust_evidence_get(store, op, &node_id, &boot_id, &got));
    assert(strcmp(got.citadel_release, "citadel-2026.09") == 0);
    assert(strcmp(got.qihse_sbom_digest, "sha384:qihse-sbom") == 0);
    assert(strcmp(got.qihse_provenance_digest, "sha384:qihse-prov") == 0);
    assert(strcmp(got.kernel_image, "linux-6.12.9") == 0);
    assert(strcmp(got.tpm_attestation_ref, "tpm-quote-7") == 0);
    assert(got.policy_generation == 11);
    assert(got.hardening_audit_generation == 4);

    /* An unknown boot has no evidence. */
    qihse_uuid_t other_boot;
    assert(qihse_uuid_from_seed("f7-boot-other", strlen("f7-boot-other"), &other_boot));
    assert(!qihse_trust_evidence_get(store, op, &node_id, &other_boot, &got));

    printf("PASS evidence: full bundle round-trip + immutable per boot\n");
}

static void test_verification_and_journal(qihse_kv_store_t* store, qihse_user_t* op) {
    /* A journal lets us prove that a trust change emits an audit event. */
    char journal_root[] = "build/fed_f7_journal_XXXXXX";
    assert(mkdtemp(journal_root));
    qihse_federation_journal_t* journal = qihse_federation_journal_open(
        journal_root, QIHSE_ES_DURABILITY_FDATASYNC);
    assert(journal);

    qihse_uuid_t node_id, verifier, boot_id;
    assert(qihse_uuid_from_seed("f7-node-verify", strlen("f7-node-verify"), &node_id));
    assert(qihse_uuid_from_seed("f7-verifier", strlen("f7-verifier"), &verifier));
    assert(qihse_uuid_from_seed("f7-boot-verify", strlen("f7-boot-verify"), &boot_id));

    /* Node with valid credentials but FAILED provenance: start TRUSTED, then
     * downgrade to LOCAL_ONLY.  This is AC23's scenario. */
    qihse_trust_verification_t v;
    memset(&v, 0, sizeof(v));
    v.node_id = node_id;
    v.trust_state = QIHSE_RTRUST_TRUSTED;
    v.trust_policy_generation = 11;
    v.evidence_bundle_id = boot_id;
    v.verification_principal = verifier;
    snprintf(v.verification_result, sizeof(v.verification_result), "provenance_ok");
    assert(qihse_trust_verification_put(store, op, &v, journal));

    uint64_t before = qihse_federation_journal_length(journal);

    /* Provenance now fails. */
    v.trust_state = QIHSE_RTRUST_LOCAL_ONLY;
    snprintf(v.verification_result, sizeof(v.verification_result), "provenance_digest_mismatch");
    assert(qihse_trust_verification_put(store, op, &v, journal));

    /* The trust change emitted an immutable audit event. */
    uint64_t after = qihse_federation_journal_length(journal);
    assert(after > before);

    qihse_trust_verification_t got;
    assert(qihse_trust_verification_get(store, op, &node_id, &got));
    assert(got.trust_state == QIHSE_RTRUST_LOCAL_ONLY);
    assert(strcmp(got.verification_result, "provenance_digest_mismatch") == 0);

    /* Admission for that node: local database stays usable, federation
     * authority is gone. */
    qihse_admission_t a;
    assert(qihse_runtime_admission_for_node(store, op, &node_id, &a));
    assert(a.local_usable);
    assert(!a.may_replicate && !a.may_vote && !a.may_strong_write);

    /* A node with no verification record is UNKNOWN, still locally usable. */
    qihse_uuid_t stranger;
    assert(qihse_uuid_from_seed("f7-node-stranger", strlen("f7-node-stranger"), &stranger));
    assert(qihse_runtime_admission_for_node(store, op, &stranger, &a));
    assert(a.local_usable);
    assert(a.trust_state == QIHSE_RTRUST_UNKNOWN);
    assert(!a.may_vote);

    qihse_federation_journal_destroy(journal);
    printf("PASS verification: failed provenance keeps local DB, drops authority (AC23)\n");
    printf("PASS trust change emits an immutable journal event\n");
}

/* ── Time integrity (AC27) ─────────────────────────────────────────────── */

static void test_time_monitor(void) {
    qihse_time_policy_t policy;
    qihse_time_policy_init(&policy);
    assert(policy.forward_jump_threshold_ms == 5u * 60u * 1000u);
    assert(policy.backward_jump_threshold_ms == 1000u);

    qihse_time_monitor_t mon;
    qihse_time_monitor_init(&mon);

    /* First sample establishes the baseline. */
    assert(qihse_time_monitor_observe(&mon, &policy, 1000, 1000000) == QIHSE_TIME_OK);
    /* Normal progress. */
    assert(qihse_time_monitor_observe(&mon, &policy, 2000, 1001000) == QIHSE_TIME_OK);

    /* Backward wall-clock jump beyond tolerance. */
    assert(qihse_time_monitor_observe(&mon, &policy, 3000, 500000) == QIHSE_TIME_BACKWARD_JUMP);
    assert(mon.wall_jumps == 1);

    /* Large forward wall-clock jump. */
    qihse_time_monitor_t mon2;
    qihse_time_monitor_init(&mon2);
    assert(qihse_time_monitor_observe(&mon2, &policy, 1000, 1000000) == QIHSE_TIME_OK);
    assert(qihse_time_monitor_observe(&mon2, &policy, 2000, 1000000 + 10u * 60u * 1000u)
           == QIHSE_TIME_FORWARD_JUMP);

    /* Monotonic regression is its own, worse, condition. */
    qihse_time_monitor_t mon3;
    qihse_time_monitor_init(&mon3);
    assert(qihse_time_monitor_observe(&mon3, &policy, 5000, 1000000) == QIHSE_TIME_OK);
    assert(qihse_time_monitor_observe(&mon3, &policy, 4000, 1001000)
           == QIHSE_TIME_MONOTONIC_REGRESSION);
    assert(mon3.monotonic_regressions == 1);

    /* Sync loss is reported once on the transition. */
    qihse_time_monitor_t mon4;
    qihse_time_monitor_init(&mon4);
    assert(mon4.synced);
    assert(qihse_time_monitor_set_synced(&mon4, false) == QIHSE_TIME_SYNC_LOST);
    assert(qihse_time_monitor_set_synced(&mon4, false) == QIHSE_TIME_OK);
    assert(mon4.sync_losses == 1);

    /* Peer skew classification. */
    assert(qihse_time_check_peer_skew(&policy, 1000000, 1001000) == QIHSE_TIME_OK);
    assert(qihse_time_check_peer_skew(&policy, 1000000, 1000000 + 60u * 1000u)
           == QIHSE_TIME_FORWARD_JUMP);

    printf("PASS time monitor: backward/forward/monotonic/sync anomalies detected\n");
}

static void test_hlc_under_bad_clocks(void) {
    /* AC27: a wall-clock anomaly must not break HLC ordering.  These calls
     * take the wall reading as a parameter, so a broken clock can be injected
     * deterministically instead of having to move the system clock. */
    qihse_hlc_t prev;
    prev.physical_ms = 1000;
    prev.logical = 0;

    /* Wall clock jumps BACKWARD by 500 ms. */
    qihse_hlc_t a = qihse_hlc_advance_safe(&prev, 500);
    assert(qihse_hlc_compare(&prev, &a) < 0);
    assert(a.physical_ms == 1000);
    assert(a.logical == 1);

    /* Backwards again. */
    qihse_hlc_t b = qihse_hlc_advance_safe(&a, 400);
    assert(qihse_hlc_compare(&a, &b) < 0);
    assert(b.logical == 2);

    /* Wall clock jumps far FORWARD. */
    qihse_hlc_t c = qihse_hlc_advance_safe(&b, 100000000u);
    assert(qihse_hlc_compare(&b, &c) < 0);
    assert(c.physical_ms == 100000000u);
    assert(c.logical == 0);

    /* Then backwards again from the new high-water mark. */
    qihse_hlc_t d = qihse_hlc_advance_safe(&c, 1000);
    assert(qihse_hlc_compare(&c, &d) < 0);
    assert(d.physical_ms == 100000000u);

    /* A long run of backwards clocks must stay strictly increasing. */
    qihse_hlc_t run = prev;
    for (int i = 0; i < 5000; i++) {
        qihse_hlc_t next = qihse_hlc_advance_safe(&run, 100); /* always "past" */
        assert(qihse_hlc_compare(&run, &next) < 0);
        run = next;
    }

    /* Merge with a remote clock that is AHEAD and one that is BEHIND. */
    qihse_hlc_t local;
    local.physical_ms = 2000;
    local.logical = 3;
    qihse_hlc_t remote_ahead;
    remote_ahead.physical_ms = 9000;
    remote_ahead.logical = 0;
    qihse_hlc_t m1 = qihse_hlc_merge_safe(&local, &remote_ahead, 2000);
    assert(qihse_hlc_compare(&local, &m1) < 0);
    assert(qihse_hlc_compare(&remote_ahead, &m1) < 0);

    qihse_hlc_t remote_behind;
    remote_behind.physical_ms = 100;
    remote_behind.logical = 50;
    qihse_hlc_t m2 = qihse_hlc_merge_safe(&local, &remote_behind, 2000);
    assert(qihse_hlc_compare(&local, &m2) < 0);

    printf("PASS HLC ordering survives backward and forward wall-clock jumps (AC27)\n");
}

/* ── Interface classification and runtime profile (AC28) ───────────────── */

static void test_interface_vocabulary(void) {
    for (int i = 0; i <= (int)QIHSE_IFACE_UNKNOWN; i++) {
        qihse_iface_class_t c = (qihse_iface_class_t)i;
        const char* name = qihse_iface_class_name(c);
        assert(name != NULL);
        qihse_iface_class_t parsed;
        assert(qihse_iface_class_parse(name, &parsed));
        assert(parsed == c);
    }
    for (int i = 0; i < (int)QIHSE_IFACE_COUNT; i++) {
        qihse_kernel_iface_t k = (qihse_kernel_iface_t)i;
        const char* name = qihse_kernel_iface_name(k);
        assert(name && strcmp(name, "UNKNOWN") != 0);
        qihse_kernel_iface_t parsed;
        assert(qihse_kernel_iface_parse(name, &parsed));
        assert(parsed == k);
    }
    printf("PASS interface vocabulary: 4 classes + %d audited interfaces\n",
           (int)QIHSE_IFACE_COUNT);
}

static void test_runtime_profile(qihse_kv_store_t* store, qihse_user_t* op) {
    qihse_runtime_profile_t p;
    qihse_runtime_profile_init(&p, "qihse", "3.0.0");

    /* Production defaults are conservative (plan §36). */
    assert(p.allowed_capabilities == 0);
    assert(!p.core_dumps_allowed);
    assert(p.require_seccomp);
    for (size_t i = 0; i < QIHSE_IFACE_COUNT; i++) {
        assert(p.interfaces[i] == QIHSE_IFACE_UNKNOWN);
    }

    /* Classify deliberately: AF_NETLINK is required, AF_PACKET is forbidden. */
    p.interfaces[QIHSE_IFACE_AF_NETLINK] = QIHSE_IFACE_REQUIRED;
    p.interfaces[QIHSE_IFACE_AF_PACKET] = QIHSE_IFACE_FORBIDDEN;
    p.interfaces[QIHSE_IFACE_IO_URING] = QIHSE_IFACE_OPTIONAL;
    p.expected_uid = (int32_t)geteuid();
    p.generation = 17;

    assert(qihse_runtime_profile_put(store, op, &p));

    qihse_runtime_profile_t got;
    assert(qihse_runtime_profile_get(store, op, "qihse", "3.0.0", &got));
    assert(strcmp(got.service, "qihse") == 0);
    assert(got.generation == 17);
    assert(got.interfaces[QIHSE_IFACE_AF_NETLINK] == QIHSE_IFACE_REQUIRED);
    assert(got.interfaces[QIHSE_IFACE_AF_PACKET] == QIHSE_IFACE_FORBIDDEN);
    assert(got.interfaces[QIHSE_IFACE_IO_URING] == QIHSE_IFACE_OPTIONAL);
    assert(got.expected_uid == (int32_t)geteuid());

    assert(!qihse_runtime_profile_get(store, op, "nosuch", "0", &got));

    printf("PASS runtime profile: conservative defaults + round-trip (AC28)\n");
}

/* ── Actual runtime observation and audit (AC24, AC25, AC28) ───────────── */

static void test_runtime_observe(void) {
    qihse_runtime_observation_t o;
    assert(qihse_runtime_observe(&o));

    /* These are read from the kernel, not from configuration. */
    assert(o.uid == (int32_t)getuid());
    assert(o.euid == (int32_t)geteuid());
    assert(o.gid == (int32_t)getgid());
    assert(o.observed_hlc_physical > 0);
    assert(o.seccomp_mode >= 0 && o.seccomp_mode <= 2);

    printf("PASS runtime observation reads actual state: uid=%d euid=%d caps=0x%llx "
           "core_dumps=%d seccomp=%d listeners=%u\n",
           (int)o.uid, (int)o.euid,
           (unsigned long long)o.effective_capabilities,
           o.core_dumps_enabled ? 1 : 0, o.seccomp_mode, o.listening_port_count);
}

static void test_audit_drift(qihse_kv_store_t* store, qihse_user_t* op) {
    qihse_runtime_profile_t p;
    qihse_runtime_profile_init(&p, "qihse-audit", "1.0");
    /* Classify every interface so the only findings are the ones we inject. */
    for (size_t i = 0; i < QIHSE_IFACE_COUNT; i++) {
        p.interfaces[i] = QIHSE_IFACE_OPTIONAL;
    }
    p.allowed_capabilities = 0;
    p.core_dumps_allowed = false;
    p.require_seccomp = false;
    p.expected_uid = -1; /* any uid */

    /* A clean observation: no capabilities, no core dumps, no listeners. */
    qihse_runtime_observation_t clean;
    memset(&clean, 0, sizeof(clean));
    clean.seccomp_mode = 2;

    uint32_t declared[] = { 6379u };
    qihse_audit_report_t r;
    assert(qihse_runtime_audit(&p, &clean, declared, 1, &r));
    assert(!r.critical);
    assert(r.finding_count == 0);
    assert(r.recommended_trust == QIHSE_RTRUST_TRUSTED);

    /* An unexpected capability is critical drift (criterion 25). */
    qihse_runtime_observation_t caps = clean;
    caps.effective_capabilities = (1ULL << 21) | (1ULL << 12); /* SYS_ADMIN, NET_ADMIN */
    assert(qihse_runtime_audit(&p, &caps, declared, 1, &r));
    assert(r.critical);
    assert(r.unexpected_capability_count == 2);
    assert(r.recommended_trust == QIHSE_RTRUST_LOCAL_ONLY);
    bool found_cap = false;
    for (uint32_t i = 0; i < r.finding_count; i++) {
        if (r.findings[i].kind == QIHSE_DRIFT_UNEXPECTED_CAPABILITY) {
            found_cap = true;
            assert(strstr(r.findings[i].detail, "CAP_SYS_ADMIN") != NULL);
            assert(strstr(r.findings[i].detail, "CAP_NET_ADMIN") != NULL);
        }
    }
    assert(found_cap);

    /* Core dumps enabled against a profile that forbids them (criterion 28). */
    qihse_runtime_observation_t dumps = clean;
    dumps.core_dumps_enabled = true;
    assert(qihse_runtime_audit(&p, &dumps, declared, 1, &r));
    assert(r.critical);
    bool found_dump = false;
    for (uint32_t i = 0; i < r.finding_count; i++) {
        if (r.findings[i].kind == QIHSE_DRIFT_CORE_DUMPS_ENABLED) found_dump = true;
    }
    assert(found_dump);
    assert(r.recommended_trust == QIHSE_RTRUST_LOCAL_ONLY);

    /* An undeclared listener is critical drift (criterion 25). */
    qihse_runtime_observation_t listen = clean;
    listen.listening_port_count = 2;
    listen.listening_ports[0] = 6379u;  /* declared */
    listen.listening_ports[1] = 9999u;  /* not declared */
    assert(qihse_runtime_audit(&p, &listen, declared, 1, &r));
    assert(r.critical);
    assert(r.unexpected_listener_count == 1);
    bool found_port = false;
    for (uint32_t i = 0; i < r.finding_count; i++) {
        if (r.findings[i].kind == QIHSE_DRIFT_UNEXPECTED_LISTENER) {
            assert(strstr(r.findings[i].detail, "9999") != NULL);
            found_port = true;
        }
    }
    assert(found_port);

    /* A FORBIDDEN interface is critical (criterion 28). */
    qihse_runtime_profile_t p_forbidden = p;
    p_forbidden.interfaces[QIHSE_IFACE_BPF] = QIHSE_IFACE_FORBIDDEN;
    assert(qihse_runtime_audit(&p_forbidden, &clean, declared, 1, &r));
    assert(r.forbidden_interface_count == 1);
    assert(r.critical);
    assert(r.recommended_trust == QIHSE_RTRUST_LOCAL_ONLY);

    /* UNKNOWN interfaces are a review failure but not critical: they degrade
     * trust rather than removing federation authority outright. */
    qihse_runtime_profile_t p2;
    qihse_runtime_profile_init(&p2, "qihse-audit2", "1.0");
    p2.require_seccomp = false;
    assert(qihse_runtime_audit(&p2, &clean, declared, 1, &r));
    assert(!r.critical);
    assert(r.unclassified_interface_count == QIHSE_IFACE_COUNT);
    assert(r.recommended_trust == QIHSE_RTRUST_TRUSTED_DEGRADED);

    /* A missing profile is critical: nothing was classified. */
    assert(qihse_runtime_audit(NULL, &clean, declared, 1, &r));
    assert(!r.profile_found);
    assert(r.critical);

    /* Reports persist as immutable versioned evidence (criterion 24). */
    qihse_uuid_t node_id;
    assert(qihse_uuid_from_seed("f7-audit-node", strlen("f7-audit-node"), &node_id));
    assert(qihse_runtime_audit(&p, &caps, declared, 1, &r));
    assert(qihse_runtime_audit_record(store, op, &node_id, &r));

    printf("PASS audit drift: capabilities, core dumps, listeners, interfaces (AC25, AC28)\n");
}

/* ── Network exposure (AC26) ───────────────────────────────────────────── */

static void test_net_profile(qihse_kv_store_t* store, qihse_user_t* op) {
    qihse_net_profile_t p;
    qihse_net_profile_init(&p, "qihse", "3.0.0");

    /* AC26: the default posture never requires unrestricted Internet egress. */
    assert(qihse_net_profile_is_egress_restricted(&p));
    assert(p.egress[QIHSE_EGRESS_FEDERATION_PEERS]);
    assert(p.egress[QIHSE_EGRESS_LOCAL_CITADEL]);
    assert(!p.egress[QIHSE_EGRESS_UNRESTRICTED_INTERNET]);

    /* Declare a listener with the required attributes (plan §37). */
    p.ports[0] = 6379u;
    snprintf(p.bind_addresses[0], sizeof(p.bind_addresses[0]), "127.0.0.1");
    p.listener_requires_auth[0] = true;
    p.max_request_bytes[0] = 65536u;
    p.listener_count = 1;
    p.egress[QIHSE_EGRESS_BACKUP_TARGET] = true;
    p.generation = 9;
    assert(qihse_net_profile_put(store, op, &p));

    qihse_net_profile_t got;
    assert(qihse_net_profile_get(store, op, "qihse", "3.0.0", &got));
    assert(got.listener_count == 1);
    assert(got.ports[0] == 6379u);
    assert(strcmp(got.bind_addresses[0], "127.0.0.1") == 0);
    assert(got.listener_requires_auth[0]);
    assert(got.max_request_bytes[0] == 65536u);
    assert(got.egress[QIHSE_EGRESS_BACKUP_TARGET]);
    assert(got.generation == 9);
    assert(qihse_net_profile_is_egress_restricted(&got));

    /* A profile that declares unrestricted Internet egress is not restricted. */
    got.egress[QIHSE_EGRESS_UNRESTRICTED_INTERNET] = true;
    assert(!qihse_net_profile_is_egress_restricted(&got));

    /* Unexpected listener detection. */
    qihse_runtime_observation_t o;
    memset(&o, 0, sizeof(o));
    o.listening_port_count = 2;
    o.listening_ports[0] = 6379u;
    o.listening_ports[1] = 12345u;
    uint32_t unexpected[4];
    size_t n = qihse_net_profile_unexpected_listeners(&p, &o, unexpected, 4);
    assert(n == 1);
    assert(unexpected[0] == 12345u);

    printf("PASS network profile: egress restricted by default (AC26) + listener drift\n");
}

/* ── RESP-level F7 ─────────────────────────────────────────────────────── */

static uint16_t f7_free_tcp_port(void) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    assert(fd >= 0);
    struct sockaddr_in addr; memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    assert(bind(fd, (struct sockaddr*)&addr, sizeof addr) == 0);
    socklen_t len = sizeof addr;
    assert(getsockname(fd, (struct sockaddr*)&addr, &len) == 0);
    uint16_t port = ntohs(addr.sin_port);
    close(fd);
    return port;
}

typedef struct { int fd; char buf[65536]; size_t fill; } f7_client_t;

static bool f7_read_line(f7_client_t* c, char* out, size_t cap) {
    for (;;) {
        for (size_t i = 0; i < c->fill; i++) {
            if (c->buf[i] == '\n') {
                size_t len = i;
                if (len && c->buf[len - 1u] == '\r') len--;
                if (len >= cap) len = cap - 1u;
                memcpy(out, c->buf, len); out[len] = '\0';
                memmove(c->buf, c->buf + i + 1u, c->fill - i - 1u);
                c->fill -= i + 1u;
                return true;
            }
        }
        ssize_t n = recv(c->fd, c->buf + c->fill, sizeof(c->buf) - c->fill, 0);
        if (n <= 0) return false;
        c->fill += (size_t)n;
    }
}

static bool f7_read_exact(f7_client_t* c, char* out, size_t len) {
    while (c->fill < len) {
        ssize_t n = recv(c->fd, c->buf + c->fill, sizeof(c->buf) - c->fill, 0);
        if (n <= 0) return false;
        c->fill += (size_t)n;
    }
    memcpy(out, c->buf, len);
    memmove(c->buf, c->buf + len, c->fill - len);
    c->fill -= len;
    return true;
}

static bool f7_read_reply(f7_client_t* c, char* out, size_t cap, size_t* used) {
    char line[512];
    if (!f7_read_line(c, line, sizeof(line))) return false;
    char type = line[0];
    const char* rest = line + 1;
    if (type == '+' || type == '-' || type == ':') {
        int n = snprintf(out + *used, cap - *used, "%s", rest);
        *used += (size_t)(n > 0 ? n : 0);
        return true;
    }
    if (type == '$') {
        int len = atoi(rest);
        if (len < 0) return true;
        char data[16384];
        if ((size_t)len >= sizeof(data)) return false;
        if (!f7_read_exact(c, data, (size_t)len + 2u)) return false;
        data[len] = '\0';
        int n = snprintf(out + *used, cap - *used, "%s", data);
        *used += (size_t)(n > 0 ? n : 0);
        return true;
    }
    if (type == '*') {
        int count = atoi(rest);
        for (int i = 0; i < count; i++) {
            if (i && *used + 1u < cap) out[(*used)++] = '|';
            if (!f7_read_reply(c, out, cap, used)) return false;
        }
        return true;
    }
    return false;
}

static void f7_send_cmd6(f7_client_t* c, const char* a, const char* b, const char* d,
                         const char* e, const char* f, const char* g) {
    const char* args[6] = { a, b, d, e, f, g };
    size_t argc = 0;
    for (size_t i = 0; i < 6u; i++) if (args[i]) argc++;
    char out[4096]; size_t off = 0;
    off += (size_t)snprintf(out + off, sizeof(out) - off, "*%zu\r\n", argc);
    for (size_t i = 0; i < argc; i++)
        off += (size_t)snprintf(out + off, sizeof(out) - off, "$%zu\r\n%s\r\n", strlen(args[i]), args[i]);
    assert(send(c->fd, out, off, 0) == (ssize_t)off);
}

static void f7_send_cmd(f7_client_t* c, const char* a, const char* b, const char* d, const char* e) {
    f7_send_cmd6(c, a, b, d, e, NULL, NULL);
}

static void test_resp_federation_f7(qihse_kv_store_t* store, qihse_user_t* op) {
    uint16_t port = f7_free_tcp_port();
    char node_id[QIHSE_CLUSTER_NODE_ID_LEN + 1u];
    qihse_cluster_node_id_from_seed("f7-resp-test-node", strlen("f7-resp-test-node"), node_id);
    qihse_resp_server_config_t scfg;
    qihse_resp_server_config_init(&scfg);
    scfg.node_id = node_id;
    scfg.bind_address = "127.0.0.1";
    scfg.advertise_address = "127.0.0.1";
    scfg.port = port;
    scfg.bus_port = f7_free_tcp_port();
    scfg.store = store;
    scfg.enable_bus = false;
    scfg.enable_failover = false;
    scfg.auth_required = true;
    qihse_resp_server_t* server = qihse_resp_server_create(&scfg);
    if (!server) fprintf(stderr, "server create failed: errno=%d (%s)\n", errno, strerror(errno));
    assert(server);
    assert(qihse_resp_server_start(server));

    f7_client_t c; memset(&c, 0, sizeof c);
    struct sockaddr_in addr; memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(port);
    c.fd = socket(AF_INET, SOCK_STREAM, 0); assert(c.fd >= 0);
    assert(connect(c.fd, (struct sockaddr*)&addr, sizeof addr) == 0);

    char reply[16384]; size_t used;
    f7_send_cmd(&c, "AUTH", "GODMODE_OP", "F7OperatorPass1!", NULL);
    used = 0; assert(f7_read_reply(&c, reply, sizeof reply, &used));
    assert(strcmp(reply, "OK") == 0);

    /* SECURITY.TRUST.STATES lists the vocabulary. */
    f7_send_cmd(&c, "FEDERATION", "TRUST.STATES", NULL, NULL);
    used = 0; assert(f7_read_reply(&c, reply, sizeof reply, &used));
    assert(strstr(reply, "TRUSTED_DEGRADED") != NULL);
    assert(strstr(reply, "QUARANTINED") != NULL);
    assert(strstr(reply, "REVOKED") != NULL);

    /* SECURITY.IFACES lists the audited kernel interfaces. */
    f7_send_cmd(&c, "FEDERATION", "SECURITY.IFACES", NULL, NULL);
    used = 0; assert(f7_read_reply(&c, reply, sizeof reply, &used));
    assert(strstr(reply, "AF_PACKET") != NULL);
    assert(strstr(reply, "IO_URING") != NULL);

    /* SECURITY.OBSERVE returns real process state. */
    f7_send_cmd(&c, "FEDERATION", "SECURITY.OBSERVE", NULL, NULL);
    used = 0; assert(f7_read_reply(&c, reply, sizeof reply, &used));
    assert(strstr(reply, "NOPERM") == NULL);
    assert(strstr(reply, "ERR") == NULL);

    /* SECURITY.AUDIT runs the audit and reports the recommended trust. */
    f7_send_cmd(&c, "FEDERATION", "SECURITY.AUDIT", NULL, NULL);
    used = 0; assert(f7_read_reply(&c, reply, sizeof reply, &used));
    assert(strstr(reply, "NOPERM") == NULL);

    /* TRUST.ADMISSION for an unknown node: locally usable, no authority. */
    f7_send_cmd6(&c, "FEDERATION", "TRUST.ADMISSION",
                 "00000000-0000-0000-0000-000000000000", NULL, NULL, NULL);
    used = 0; assert(f7_read_reply(&c, reply, sizeof reply, &used));
    assert(strstr(reply, "local_usable") != NULL || strstr(reply, "UNKNOWN") != NULL);

    /* Tenant guest is denied (AGENTS.md invariant 3). */
    qihse_user_t* tenant = qihse_auth_create_tenant_user(op,
        42u, 108u, QIHSE_ROLE_GUEST, 0, 0, "F7TenantGuestP1!", false);
    assert(tenant);
    f7_client_t g; memset(&g, 0, sizeof g);
    g.fd = socket(AF_INET, SOCK_STREAM, 0); assert(g.fd >= 0);
    assert(connect(g.fd, (struct sockaddr*)&addr, sizeof addr) == 0);
    f7_send_cmd(&g, "AUTH", "User_108", "F7TenantGuestP1!", NULL);
    used = 0; assert(f7_read_reply(&g, reply, sizeof reply, &used));
    assert(strcmp(reply, "OK") == 0);
    f7_send_cmd(&g, "FEDERATION", "TRUST.STATES", NULL, NULL);
    used = 0; assert(f7_read_reply(&g, reply, sizeof reply, &used));
    assert(strstr(reply, "NOPERM") != NULL);
    assert(strstr(reply, "QUARANTINED") == NULL);
    f7_send_cmd(&g, "FEDERATION", "SECURITY.OBSERVE", NULL, NULL);
    used = 0; assert(f7_read_reply(&g, reply, sizeof reply, &used));
    assert(strstr(reply, "NOPERM") != NULL);
    f7_send_cmd(&g, "FEDERATION", "SECURITY.AUDIT", NULL, NULL);
    used = 0; assert(f7_read_reply(&g, reply, sizeof reply, &used));
    assert(strstr(reply, "NOPERM") != NULL);
    close(g.fd);

    close(c.fd);
    qihse_resp_server_stop(server);
    qihse_resp_server_destroy(server);
    printf("PASS RESP FEDERATION.TRUST/SECURITY + tenant-guest NOPERM\n");
}

int main(void) {
    char data_root[] = "build/fed_f7_XXXXXX";
    assert(mkdtemp(data_root));
    setenv("QIHSE_DATA_DIR", data_root, 1);

    assert(qihse_auth_init());
    bool bootstrapped = qihse_auth_bootstrap_operator("F7OperatorPass1!");
    if (!bootstrapped) {
        setenv("QIHSE_OPERATOR_PASSWORD", "F7OperatorPass1!", 1);
        assert(qihse_auth_init());
    }
    qihse_user_t* op = qihse_auth_get_user(0);
    assert(op);

    qihse_kv_store_t* store = qihse_kv_store_create();
    assert(store);

    test_trust_vocabulary();
    test_admission();
    test_evidence(store, op);
    test_verification_and_journal(store, op);
    test_time_monitor();
    test_hlc_under_bad_clocks();
    test_interface_vocabulary();
    test_runtime_profile(store, op);
    test_runtime_observe();
    test_audit_drift(store, op);
    test_net_profile(store, op);
    test_resp_federation_f7(store, op);

    qihse_kv_store_destroy(store);
    printf("federation F7 tests passed\n");
    return 0;
}
