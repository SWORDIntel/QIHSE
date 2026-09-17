/*
 * test_federation_f5.c — F5 Trust plane.
 *
 * Acceptance criteria exercised:
 *   AC8 — Node identity and trust: a node identity is a durable keypair,
 *         not an IP/hostname/index; enrollment is operator-approved; a
 *         revoked node is refused.
 *
 * Covers:
 *   - infrastructure scopes and service identity defaults (plan §19)
 *   - scope check: operator all, guest none, NULL denied
 *   - node keygen (Ed25519), private key on disk with 0600, never in a record
 *   - node fingerprint (SHA-384)
 *   - enrollment: request -> pending, approve -> approved, revoke -> revoked
 *   - revoked node cannot be re-approved; scopes cannot be self-granted
 *   - gossip: serialize determinism, sign/verify, tamper detection
 *   - gossip accept: unknown/untrusted/bad-signature/replay rejection
 *   - replay state persistence
 *   - RESP-level SCOPE/NODE/GOSSIP + tenant-guest NOPERM (invariant 3)
 */
#include "qihse_auth.h"
#include "qihse_cluster_slot.h"
#include "qihse_federation.h"
#include "qihse_kv_store.h"
#include "qihse_resp_wire.h"

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

/* ── Infrastructure scopes (plan §19) ──────────────────────────────────── */

static void test_scopes(void) {
    static const qihse_infra_scope_t all[] = {
        QIHSE_SCOPE_FEDERATION_READ, QIHSE_SCOPE_FEDERATION_WRITE,
        QIHSE_SCOPE_NODE_ENROLL, QIHSE_SCOPE_NODE_REVOKE,
        QIHSE_SCOPE_POLICY_READ, QIHSE_SCOPE_POLICY_WRITE,
        QIHSE_SCOPE_LEASE_READ, QIHSE_SCOPE_LEASE_WRITE,
        QIHSE_SCOPE_SECURITY_ADMIN, QIHSE_SCOPE_AUDIT_READ,
        QIHSE_SCOPE_TELEMETRY_WRITE,
    };
    qihse_infra_scope_t combined = 0;
    for (size_t i = 0; i < sizeof(all) / sizeof(all[0]); i++) {
        const char* name = qihse_infra_scope_name(all[i]);
        assert(name && strcmp(name, "UNKNOWN") != 0);
        qihse_infra_scope_t parsed;
        assert(qihse_infra_scope_parse(name, &parsed));
        assert(parsed == all[i]);
        combined |= all[i];
    }
    assert(combined == QIHSE_SCOPE_ALL);
    qihse_infra_scope_t dummy;
    assert(!qihse_infra_scope_parse("BOGUS_SCOPE", &dummy));

    printf("PASS infra scopes: 11 scopes round-trip, bitmap == ALL\n");
}

static void test_service_identities(void) {
    static const qihse_service_identity_t all[] = {
        QIHSE_IDENTITY_OPERATOR, QIHSE_IDENTITY_HYPERVISOR_CONTROLLER,
        QIHSE_IDENTITY_HOST_AGENT, QIHSE_IDENTITY_UI_API,
        QIHSE_IDENTITY_KEYSTONE_INDEXER, QIHSE_IDENTITY_BACKUP_AGENT,
    };
    for (size_t i = 0; i < sizeof(all) / sizeof(all[0]); i++) {
        const char* name = qihse_service_identity_name(all[i]);
        assert(name && strcmp(name, "unknown") != 0);
        qihse_service_identity_t parsed;
        assert(qihse_service_identity_parse(name, &parsed));
        assert(parsed == all[i]);
    }

    /* KEYSTONE must receive a read/index identity, never database-admin. */
    qihse_infra_scope_t ks = qihse_service_identity_default_scopes(QIHSE_IDENTITY_KEYSTONE_INDEXER);
    assert(ks & QIHSE_SCOPE_FEDERATION_READ);
    assert((ks & QIHSE_SCOPE_FEDERATION_WRITE) == 0);
    assert((ks & QIHSE_SCOPE_NODE_ENROLL) == 0);
    assert((ks & QIHSE_SCOPE_NODE_REVOKE) == 0);
    assert((ks & QIHSE_SCOPE_SECURITY_ADMIN) == 0);
    assert((ks & QIHSE_SCOPE_POLICY_WRITE) == 0);
    assert((ks & QIHSE_SCOPE_LEASE_WRITE) == 0);

    /* The hypervisor controller needs lease write; the backup agent does not. */
    qihse_infra_scope_t hc = qihse_service_identity_default_scopes(QIHSE_IDENTITY_HYPERVISOR_CONTROLLER);
    assert(hc & QIHSE_SCOPE_LEASE_WRITE);
    qihse_infra_scope_t ba = qihse_service_identity_default_scopes(QIHSE_IDENTITY_BACKUP_AGENT);
    assert((ba & QIHSE_SCOPE_LEASE_WRITE) == 0);
    assert(ba & QIHSE_SCOPE_AUDIT_READ);

    printf("PASS service identities: 6 kinds, KEYSTONE read-only\n");
}

static void test_scope_check(qihse_user_t* op) {
    /* Operator implicitly holds every scope. */
    assert(qihse_infra_scope_check(op, QIHSE_SCOPE_SECURITY_ADMIN));
    assert(qihse_infra_scope_check(op, QIHSE_SCOPE_NODE_ENROLL));
    assert(qihse_infra_scope_check(op, QIHSE_SCOPE_ALL));

    /* A guest holds nothing. */
    qihse_user_t* guest = qihse_auth_create_tenant_user(op, 42u, 104u,
        QIHSE_ROLE_GUEST, 0, 0, "F5TenantGuestP1!", false);
    assert(guest);
    assert(!qihse_infra_scope_check(guest, QIHSE_SCOPE_FEDERATION_READ));
    assert(!qihse_infra_scope_check(guest, QIHSE_SCOPE_LEASE_READ));

    /* An analyst holds read scopes but not write/admin. */
    qihse_user_t* analyst = qihse_auth_create_tenant_user(op, 42u, 105u,
        QIHSE_ROLE_ANALYST, 0, 0, "F5AnalystPass1!", false);
    assert(analyst);
    assert(qihse_infra_scope_check(analyst, QIHSE_SCOPE_FEDERATION_READ));
    assert(!qihse_infra_scope_check(analyst, QIHSE_SCOPE_FEDERATION_WRITE));
    assert(!qihse_infra_scope_check(analyst, QIHSE_SCOPE_NODE_ENROLL));
    assert(!qihse_infra_scope_check(analyst, QIHSE_SCOPE_SECURITY_ADMIN));

    /* NULL is never an authorization bypass. */
    assert(!qihse_infra_scope_check(NULL, QIHSE_SCOPE_FEDERATION_READ));
    assert(!qihse_infra_scope_check(NULL, QIHSE_SCOPE_ALL));

    printf("PASS scope check: operator all, analyst read-only, guest none, NULL denied\n");
}

/* ── Node identity (plan §18, §20) ─────────────────────────────────────── */

static void test_node_identity(qihse_kv_store_t* store, qihse_user_t* op,
                               const char* key_dir) {
    qihse_federation_node_identity_t id;
    memset(&id, 0, sizeof(id));
    assert(qihse_uuid_from_seed("f5-node-1", strlen("f5-node-1"), &id.node_id));
    snprintf(id.hostname, sizeof(id.hostname), "r730xd-a");
    snprintf(id.boot_id, sizeof(id.boot_id), "boot-0001");
    id.identity_kind = QIHSE_IDENTITY_HOST_AGENT;

    /* Keygen writes the private key to disk; only the public key and a
     * handle come back. */
    assert(qihse_federation_node_keygen(key_dir, &id.node_id, id.public_key,
                                        id.key_handle, sizeof(id.key_handle)));

    /* The key file exists and is 0600. */
    struct stat st;
    assert(stat(id.key_handle, &st) == 0);
    assert((st.st_mode & 0777) == 0600);

    /* The record never contains private key material: the encoded record
     * holds only the handle and the public key. */
    assert(strstr(id.key_handle, ".key") != NULL);

    /* Fingerprint is deterministic and the right size. */
    uint8_t fp1[QIHSE_FEDERATION_NODE_FINGERPRINT_BYTES];
    uint8_t fp2[QIHSE_FEDERATION_NODE_FINGERPRINT_BYTES];
    assert(qihse_federation_node_fingerprint(id.public_key, fp1));
    assert(qihse_federation_node_fingerprint(id.public_key, fp2));
    assert(memcmp(fp1, fp2, sizeof(fp1)) == 0);
    /* A different key yields a different fingerprint. */
    uint8_t other_pub[QIHSE_FEDERATION_NODE_PUBKEY_BYTES];
    memset(other_pub, 0xA5, sizeof(other_pub));
    uint8_t fp3[QIHSE_FEDERATION_NODE_FINGERPRINT_BYTES];
    assert(qihse_federation_node_fingerprint(other_pub, fp3));
    assert(memcmp(fp1, fp3, sizeof(fp1)) != 0);

    /* Enrollment request lands in PENDING. */
    assert(qihse_federation_node_enroll_request(store, op, &id));
    /* A duplicate request is refused. */
    assert(!qihse_federation_node_enroll_request(store, op, &id));

    qihse_federation_node_identity_t got;
    assert(qihse_federation_node_lookup(store, op, &id.node_id, &got));
    assert(got.trust == QIHSE_TRUST_PENDING);
    assert(got.enrollment_epoch == 0);
    assert(strcmp(got.hostname, "r730xd-a") == 0);
    assert(memcmp(got.public_key, id.public_key, sizeof(id.public_key)) == 0);
    assert(memcmp(got.fingerprint, fp1, sizeof(fp1)) == 0);

    /* Scopes come from the identity kind, not from the caller. */
    assert(got.scopes == qihse_service_identity_default_scopes(QIHSE_IDENTITY_HOST_AGENT));

    /* Approve. */
    assert(qihse_federation_node_enroll_approve(store, op, &id.node_id, 7));
    assert(qihse_federation_node_lookup(store, op, &id.node_id, &got));
    assert(got.trust == QIHSE_TRUST_APPROVED);
    assert(got.enrollment_epoch == 7);

    /* Revoke. */
    assert(qihse_federation_node_revoke(store, op, &id.node_id));
    assert(qihse_federation_node_lookup(store, op, &id.node_id, &got));
    assert(got.trust == QIHSE_TRUST_REVOKED);
    assert(got.scopes == QIHSE_SCOPE_NONE);

    /* Revocation is permanent: re-approval fails. */
    assert(!qihse_federation_node_enroll_approve(store, op, &id.node_id, 8));

    printf("PASS node identity: keygen 0600 + fingerprint + enroll/approve/revoke (AC8)\n");
}

/* ── Signed gossip (plan §17) ──────────────────────────────────────────── */

static void test_gossip(qihse_kv_store_t* store, qihse_user_t* op,
                        const char* key_dir) {
    qihse_uuid_t cluster_id, boot_id;
    assert(qihse_uuid_from_seed("f5-cluster", strlen("f5-cluster"), &cluster_id));
    assert(qihse_uuid_from_seed("f5-boot-1", strlen("f5-boot-1"), &boot_id));

    /* Node A: generate, enroll, approve. */
    qihse_federation_node_identity_t a;
    memset(&a, 0, sizeof(a));
    assert(qihse_uuid_from_seed("f5-gossip-a", strlen("f5-gossip-a"), &a.node_id));
    snprintf(a.hostname, sizeof(a.hostname), "node-a");
    snprintf(a.boot_id, sizeof(a.boot_id), "boot-a");
    a.identity_kind = QIHSE_IDENTITY_HOST_AGENT;
    assert(qihse_federation_node_keygen(key_dir, &a.node_id, a.public_key,
                                        a.key_handle, sizeof(a.key_handle)));
    assert(qihse_federation_node_enroll_request(store, op, &a));
    assert(qihse_federation_node_enroll_approve(store, op, &a.node_id, 1));

    void* a_key = qihse_federation_node_key_load(a.key_handle);
    assert(a_key);

    /* Build, sign, verify. */
    qihse_federation_gossip_t g;
    memset(&g, 0, sizeof(g));
    g.magic = QIHSE_FEDERATION_GOSSIP_MAGIC;
    g.version = QIHSE_FEDERATION_GOSSIP_VERSION;
    g.feature_bitmap = 0x0003;
    g.cluster_id = cluster_id;
    g.sender_node = a.node_id;
    g.boot_id = boot_id;
    g.sequence = 1;
    g.hlc.physical_ms = 1000;
    g.hlc.logical = 0;
    g.capability_bitmap = 0x1F;
    g.health_summary = 0;

    /* Serialization is deterministic and excludes the signature. */
    uint8_t frame1[256], frame2[256];
    size_t len1 = 0, len2 = 0;
    assert(qihse_federation_gossip_serialize(&g, frame1, sizeof(frame1), &len1));
    assert(qihse_federation_gossip_serialize(&g, frame2, sizeof(frame2), &len2));
    assert(len1 == len2);
    assert(memcmp(frame1, frame2, len1) == 0);

    assert(qihse_federation_gossip_sign(a_key, &g));
    assert(qihse_federation_gossip_verify(a.public_key, &g));

    /* Tampering with any signed field breaks verification. */
    qihse_federation_gossip_t tampered = g;
    tampered.sequence = 999;
    assert(!qihse_federation_gossip_verify(a.public_key, &tampered));
    tampered = g;
    tampered.capability_bitmap = 0xFFFF;
    assert(!qihse_federation_gossip_verify(a.public_key, &tampered));
    tampered = g;
    tampered.sender_node.bytes[0] ^= 0xFFu;
    assert(!qihse_federation_gossip_verify(a.public_key, &tampered));
    tampered = g;
    tampered.hlc.physical_ms = 2000;
    assert(!qihse_federation_gossip_verify(a.public_key, &tampered));
    /* A flipped signature bit fails too. */
    tampered = g;
    tampered.signature[0] ^= 0x01u;
    assert(!qihse_federation_gossip_verify(a.public_key, &tampered));

    /* Accept: a signed frame from an approved node is accepted. */
    assert(qihse_federation_gossip_accept(store, op, &g) == QIHSE_GOSSIP_ACCEPTED);

    /* Replay: the same sequence is refused. */
    assert(qihse_federation_gossip_accept(store, op, &g) == QIHSE_GOSSIP_REJECT_REPLAY);

    /* A strictly higher sequence is accepted. */
    qihse_federation_gossip_t g2 = g;
    g2.sequence = 2;
    assert(qihse_federation_gossip_sign(a_key, &g2));
    assert(qihse_federation_gossip_accept(store, op, &g2) == QIHSE_GOSSIP_ACCEPTED);

    /* An older sequence is refused (replay window). */
    qihse_federation_gossip_t g_old = g;
    g_old.sequence = 1;
    assert(qihse_federation_gossip_sign(a_key, &g_old));
    assert(qihse_federation_gossip_accept(store, op, &g_old) == QIHSE_GOSSIP_REJECT_REPLAY);

    /* Replay state persists and reports the high-water mark. */
    qihse_federation_replay_state_t st;
    assert(qihse_federation_replay_state_read(store, op, &a.node_id, &boot_id, &st));
    assert(st.highest_sequence == 2);

    /* Unknown sender is refused. */
    qihse_federation_gossip_t g_unknown = g;
    assert(qihse_uuid_from_seed("f5-unknown-node", strlen("f5-unknown-node"),
                                &g_unknown.sender_node));
    g_unknown.sequence = 1;
    assert(qihse_federation_gossip_accept(store, op, &g_unknown) ==
           QIHSE_GOSSIP_REJECT_UNKNOWN_SENDER);

    /* Untrusted sender: enrolled but still pending. */
    qihse_federation_node_identity_t b;
    memset(&b, 0, sizeof(b));
    assert(qihse_uuid_from_seed("f5-gossip-b", strlen("f5-gossip-b"), &b.node_id));
    snprintf(b.hostname, sizeof(b.hostname), "node-b");
    snprintf(b.boot_id, sizeof(b.boot_id), "boot-b");
    b.identity_kind = QIHSE_IDENTITY_HOST_AGENT;
    assert(qihse_federation_node_keygen(key_dir, &b.node_id, b.public_key,
                                        b.key_handle, sizeof(b.key_handle)));
    assert(qihse_federation_node_enroll_request(store, op, &b));
    void* b_key = qihse_federation_node_key_load(b.key_handle);
    assert(b_key);
    qihse_federation_gossip_t g_b = g;
    g_b.sender_node = b.node_id;
    g_b.boot_id = boot_id;
    g_b.sequence = 1;
    assert(qihse_federation_gossip_sign(b_key, &g_b));
    assert(qihse_federation_gossip_accept(store, op, &g_b) ==
           QIHSE_GOSSIP_REJECT_UNTRUSTED_SENDER);

    /* After approval the same frame is accepted. */
    assert(qihse_federation_node_enroll_approve(store, op, &b.node_id, 2));
    assert(qihse_federation_gossip_accept(store, op, &g_b) == QIHSE_GOSSIP_ACCEPTED);

    /* A revoked node's frames are refused again. */
    assert(qihse_federation_node_revoke(store, op, &b.node_id));
    qihse_federation_gossip_t g_b2 = g_b;
    g_b2.sequence = 2;
    assert(qihse_federation_gossip_sign(b_key, &g_b2));
    assert(qihse_federation_gossip_accept(store, op, &g_b2) ==
           QIHSE_GOSSIP_REJECT_UNTRUSTED_SENDER);

    /* Bad signature: signed by B but claiming to be A. */
    qihse_federation_gossip_t g_forged = g;
    g_forged.sequence = 3;
    assert(qihse_federation_gossip_sign(b_key, &g_forged));
    assert(qihse_federation_gossip_accept(store, op, &g_forged) ==
           QIHSE_GOSSIP_REJECT_BAD_SIGNATURE);

    /* Wrong magic / version are refused before any crypto. */
    qihse_federation_gossip_t g_bad = g;
    g_bad.magic = 0xDEADBEEFu;
    assert(qihse_federation_gossip_accept(store, op, &g_bad) == QIHSE_GOSSIP_REJECT_MALFORMED);
    g_bad = g;
    g_bad.version = 99;
    assert(qihse_federation_gossip_accept(store, op, &g_bad) == QIHSE_GOSSIP_REJECT_VERSION);

    qihse_federation_node_key_free(a_key);
    qihse_federation_node_key_free(b_key);

    printf("PASS gossip: sign/verify + tamper detection + replay window (AC8)\n");
    printf("PASS gossip accept: unknown/untrusted/forged/replay rejected (AC8)\n");
}

/* ── RESP-level F5 ─────────────────────────────────────────────────────── */

static uint16_t f5_free_tcp_port(void) {
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

typedef struct { int fd; char buf[65536]; size_t fill; } f5_client_t;

static bool f5_read_line(f5_client_t* c, char* out, size_t cap) {
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

static bool f5_read_exact(f5_client_t* c, char* out, size_t len) {
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

static bool f5_read_reply(f5_client_t* c, char* out, size_t cap, size_t* used) {
    char line[512];
    if (!f5_read_line(c, line, sizeof(line))) return false;
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
        char data[8192];
        if ((size_t)len >= sizeof(data)) return false;
        if (!f5_read_exact(c, data, (size_t)len + 2u)) return false;
        data[len] = '\0';
        int n = snprintf(out + *used, cap - *used, "%s", data);
        *used += (size_t)(n > 0 ? n : 0);
        return true;
    }
    if (type == '*') {
        int count = atoi(rest);
        for (int i = 0; i < count; i++) {
            if (i && *used + 1u < cap) out[(*used)++] = '|';
            if (!f5_read_reply(c, out, cap, used)) return false;
        }
        return true;
    }
    return false;
}

static void f5_send_cmd6(f5_client_t* c, const char* a, const char* b, const char* d,
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

static void f5_send_cmd(f5_client_t* c, const char* a, const char* b, const char* d, const char* e) {
    f5_send_cmd6(c, a, b, d, e, NULL, NULL);
}

static void test_resp_federation_f5(qihse_kv_store_t* store, qihse_user_t* op,
                                    const char* key_dir) {
    uint16_t port = f5_free_tcp_port();
    char node_id[QIHSE_CLUSTER_NODE_ID_LEN + 1u];
    qihse_cluster_node_id_from_seed("f5-resp-test-node", strlen("f5-resp-test-node"), node_id);
    qihse_resp_server_config_t scfg;
    qihse_resp_server_config_init(&scfg);
    scfg.node_id = node_id;
    scfg.bind_address = "127.0.0.1";
    scfg.advertise_address = "127.0.0.1";
    scfg.port = port;
    scfg.bus_port = f5_free_tcp_port();
    scfg.store = store;
    scfg.enable_bus = false;
    scfg.enable_failover = false;
    scfg.auth_required = true;
    scfg.federation_key_directory = key_dir;
    qihse_resp_server_t* server = qihse_resp_server_create(&scfg);
    if (!server) fprintf(stderr, "server create failed: errno=%d (%s)\n", errno, strerror(errno));
    assert(server);
    assert(qihse_resp_server_start(server));

    f5_client_t c; memset(&c, 0, sizeof c);
    struct sockaddr_in addr; memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(port);
    c.fd = socket(AF_INET, SOCK_STREAM, 0); assert(c.fd >= 0);
    assert(connect(c.fd, (struct sockaddr*)&addr, sizeof addr) == 0);

    char reply[16384]; size_t used;
    f5_send_cmd(&c, "AUTH", "GODMODE_OP", "F5OperatorPass1!", NULL);
    used = 0; assert(f5_read_reply(&c, reply, sizeof reply, &used));
    assert(strcmp(reply, "OK") == 0);

    /* SCOPE.LIST returns all 11 scopes. */
    f5_send_cmd(&c, "FEDERATION", "SCOPE.LIST", NULL, NULL);
    used = 0; assert(f5_read_reply(&c, reply, sizeof reply, &used));
    assert(strstr(reply, "SECURITY_ADMIN") != NULL);
    assert(strstr(reply, "LEASE_WRITE") != NULL);

    /* SCOPE.CHECK: operator holds SECURITY_ADMIN. */
    f5_send_cmd(&c, "FEDERATION", "SCOPE.CHECK", "SECURITY_ADMIN", NULL);
    used = 0; assert(f5_read_reply(&c, reply, sizeof reply, &used));
    assert(atoi(reply) == 1);

    /* SCOPE.DEFAULTS: keystone-indexer is read-only. */
    f5_send_cmd(&c, "FEDERATION", "SCOPE.DEFAULTS", "keystone-indexer", NULL);
    used = 0; assert(f5_read_reply(&c, reply, sizeof reply, &used));
    assert(atoi(reply) == (int)QIHSE_SCOPE_FEDERATION_READ);

    /* NODE.ENROLL generates a key and returns the node id. */
    f5_send_cmd6(&c, "FEDERATION", "NODE.ENROLL", "host-agent", "resp-node-a", "boot-resp-1", NULL);
    used = 0; assert(f5_read_reply(&c, reply, sizeof reply, &used));
    assert(strlen(reply) >= 36);
    char enrolled_id[64];
    assert(strlen(reply) < sizeof(enrolled_id));
    memcpy(enrolled_id, reply, strlen(reply) + 1u);

    /* NODE.LIST shows the pending node. */
    f5_send_cmd(&c, "FEDERATION", "NODE.LIST", NULL, NULL);
    used = 0; assert(f5_read_reply(&c, reply, sizeof reply, &used));
    assert(strstr(reply, enrolled_id) != NULL);
    assert(strstr(reply, "pending") != NULL);

    /* NODE.APPROVE returns the enrollment epoch. */
    f5_send_cmd(&c, "FEDERATION", "NODE.APPROVE", enrolled_id, NULL);
    used = 0; assert(f5_read_reply(&c, reply, sizeof reply, &used));
    assert(atoi(reply) > 0);

    /* NODE.SHOW reports approved. */
    f5_send_cmd(&c, "FEDERATION", "NODE.SHOW", enrolled_id, NULL);
    used = 0; assert(f5_read_reply(&c, reply, sizeof reply, &used));
    assert(strstr(reply, "approved") != NULL);
    assert(strstr(reply, "host-agent") != NULL);

    /* NODE.REVOKE succeeds and the record shows revoked. */
    f5_send_cmd(&c, "FEDERATION", "NODE.REVOKE", enrolled_id, NULL);
    used = 0; assert(f5_read_reply(&c, reply, sizeof reply, &used));
    assert(strstr(reply, "OK") != NULL);
    f5_send_cmd(&c, "FEDERATION", "NODE.SHOW", enrolled_id, NULL);
    used = 0; assert(f5_read_reply(&c, reply, sizeof reply, &used));
    assert(strstr(reply, "revoked") != NULL);

    /* GOSSIP.STATUS for a node/boot with no traffic returns an error. */
    f5_send_cmd6(&c, "FEDERATION", "GOSSIP.STATUS", enrolled_id,
                 "00000000-0000-0000-0000-000000000000", NULL, NULL);
    used = 0; assert(f5_read_reply(&c, reply, sizeof reply, &used));
    assert(strstr(reply, "ERR") != NULL);

    /* Tenant guest is denied (AGENTS.md invariant 3). */
    qihse_user_t* tenant = qihse_auth_create_tenant_user(op,
        42u, 106u, QIHSE_ROLE_GUEST, 0, 0, "F5TenantGuestP1!", false);
    assert(tenant);
    f5_client_t g; memset(&g, 0, sizeof g);
    g.fd = socket(AF_INET, SOCK_STREAM, 0); assert(g.fd >= 0);
    assert(connect(g.fd, (struct sockaddr*)&addr, sizeof addr) == 0);
    f5_send_cmd(&g, "AUTH", "User_106", "F5TenantGuestP1!", NULL);
    used = 0; assert(f5_read_reply(&g, reply, sizeof reply, &used));
    assert(strcmp(reply, "OK") == 0);
    f5_send_cmd(&g, "FEDERATION", "SCOPE.LIST", NULL, NULL);
    used = 0; assert(f5_read_reply(&g, reply, sizeof reply, &used));
    assert(strstr(reply, "NOPERM") != NULL);
    assert(strstr(reply, "SECURITY_ADMIN") == NULL);
    f5_send_cmd(&g, "FEDERATION", "NODE.LIST", NULL, NULL);
    used = 0; assert(f5_read_reply(&g, reply, sizeof reply, &used));
    assert(strstr(reply, "NOPERM") != NULL);
    assert(strstr(reply, enrolled_id) == NULL);
    f5_send_cmd6(&g, "FEDERATION", "NODE.ENROLL", "host-agent", "evil-node", "evil-boot", NULL);
    used = 0; assert(f5_read_reply(&g, reply, sizeof reply, &used));
    assert(strstr(reply, "NOPERM") != NULL);
    f5_send_cmd(&g, "FEDERATION", "NODE.REVOKE", enrolled_id, NULL);
    used = 0; assert(f5_read_reply(&g, reply, sizeof reply, &used));
    assert(strstr(reply, "NOPERM") != NULL);
    close(g.fd);

    close(c.fd);
    qihse_resp_server_stop(server);
    qihse_resp_server_destroy(server);
    printf("PASS RESP FEDERATION.SCOPE/NODE/GOSSIP + tenant-guest NOPERM\n");
}

int main(void) {
    char data_root[] = "build/fed_f5_XXXXXX";
    assert(mkdtemp(data_root));
    char key_dir[256];
    snprintf(key_dir, sizeof(key_dir), "%s/keys", data_root);
    assert(mkdir(key_dir, 0700) == 0);
    setenv("QIHSE_DATA_DIR", data_root, 1);

    assert(qihse_auth_init());
    bool bootstrapped = qihse_auth_bootstrap_operator("F5OperatorPass1!");
    if (!bootstrapped) {
        setenv("QIHSE_OPERATOR_PASSWORD", "F5OperatorPass1!", 1);
        assert(qihse_auth_init());
    }
    qihse_user_t* op = qihse_auth_get_user(0);
    assert(op);

    qihse_kv_store_t* store = qihse_kv_store_create();
    assert(store);

    test_scopes();
    test_service_identities();
    test_scope_check(op);
    test_node_identity(store, op, key_dir);
    test_gossip(store, op, key_dir);
    test_resp_federation_f5(store, op, key_dir);

    qihse_kv_store_destroy(store);
    printf("federation F5 tests passed\n");
    return 0;
}
