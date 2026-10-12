#include "qihse_consensus_mesh.h"
#include "qihse_pqc_crypto.h"
#include "qihse_resp_wire.h"

#include <assert.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <pthread.h>
#include <spawn.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/prctl.h>
#include <unistd.h>
#include <sys/wait.h>

#define NODE_COUNT 3u

extern char** environ;

static bool build_member_ids(qihse_uuid_t members[NODE_COUNT]) {
    for (size_t i = 0; i < NODE_COUNT; i++) {
        char seed[32];
        int len = snprintf(seed, sizeof(seed), "mesh-member-%zu", i);
        if (len <= 0 || !qihse_uuid_from_seed(seed, (size_t)len, &members[i]))
            return false;
    }
    return true;
}

/* Isolated node-0 process used by the crash/restart integration case. */
static int run_mesh_leader_child(const char* root, uint16_t ports[NODE_COUNT]) {
    (void)prctl(PR_SET_PDEATHSIG, SIGKILL);
    char data[320], dirs[NODE_COUNT][320], blob_dirs[NODE_COUNT][320];
    char dsa_private[NODE_COUNT][384], kem_private[NODE_COUNT][384];
    char kem_public[NODE_COUNT][384], dsa_public[NODE_COUNT][384];
    qihse_uuid_t members[NODE_COUNT];
    if (!root || !build_member_ids(members) ||
        snprintf(data, sizeof(data), "%s/data-child", root) <= 0 ||
        (mkdir(data, 0700) != 0 && errno != EEXIST) ||
        setenv("QIHSE_DATA_DIR", data, 1) != 0 ||
        setenv("QIHSE_FIPS_MODE", "disabled", 1) != 0 ||
        qihse_pqc_init_providers() != 0 || !qihse_auth_init() ||
        !qihse_auth_bootstrap_operator("ConsensusMeshOperator1!")) {
        fprintf(stderr, "mesh leader child: crypto/auth initialization failed\n");
        return 2;
    }
    qihse_user_t* operator_user = qihse_auth_get_user(0u);
    if (!operator_user) return 3;
    qihse_blob_store_t* blobs = NULL;
    qihse_consensus_blob_context_t blob_context;
    qihse_consensus_mesh_config_t mesh_config;
    memset(&mesh_config, 0, sizeof(mesh_config));
    qihse_consensus_config_t* consensus = &mesh_config.consensus;
    snprintf(consensus->group_id, sizeof(consensus->group_id), "%s", "mesh-test");
    consensus->self = members[0];
    consensus->member_count = NODE_COUNT;
    memcpy(consensus->members, members, sizeof(members));
    consensus->election_timeout_base_ms = 800u;
    consensus->election_timeout_spread_ms = 600u;
    consensus->heartbeat_interval_ms = 100u;
    if (snprintf(consensus->record_path, sizeof(consensus->record_path),
                 "%s/consensus-0.rec", root) <= 0 ||
        snprintf(dirs[0], sizeof(dirs[0]), "%s/node-0", root) <= 0 ||
        snprintf(blob_dirs[0], sizeof(blob_dirs[0]), "%s/blobs-0", root) <= 0)
        return 4;
    for (size_t i = 1; i < NODE_COUNT; i++) {
        if (snprintf(dirs[i], sizeof(dirs[i]), "%s/node-%zu", root, i) <= 0)
            return 4;
        snprintf(dsa_public[i], sizeof(dsa_public[i]), "%s/qihse_dsa_pub.pem", dirs[i]);
    }
    blobs = qihse_blob_store_create(blob_dirs[0]);
    if (!blobs || !qihse_consensus_blob_context_init(&blob_context, blobs,
            operator_user, "mesh-test") ||
        !qihse_consensus_blob_bind_config(&blob_context, consensus)) {
        fprintf(stderr, "mesh leader child: blob setup failed\n");
        return 5;
    }
    snprintf(dsa_private[0], sizeof(dsa_private[0]), "%s/qihse_dsa_key.pem", dirs[0]);
    snprintf(kem_private[0], sizeof(kem_private[0]), "%s/qihse_kem_key.pem", dirs[0]);
    snprintf(kem_public[0], sizeof(kem_public[0]), "%s/qihse_kem_pub.pem", dirs[0]);
    snprintf(dsa_public[0], sizeof(dsa_public[0]), "%s/qihse_dsa_pub.pem", dirs[0]);
    mesh_config.system_principal = operator_user;
    mesh_config.blob_context = &blob_context;
    static char stage_path[384];
    snprintf(stage_path, sizeof(stage_path), "%s/snapshot-stage-0.rec", root);
    mesh_config.snapshot_stage_path = stage_path;
    mesh_config.listen_wireguard_ipv4 = "127.0.0.1";
    mesh_config.listen_port = ports[0];
    mesh_config.peer_count = NODE_COUNT - 1u;
    mesh_config.qkp.require = true;
    mesh_config.qkp.node_id = "mesh-node-0";
    mesh_config.qkp.dsa_key_path = dsa_private[0];
    mesh_config.qkp.kem_key_path = kem_private[0];
    mesh_config.qkp.kem_pub_path = kem_public[0];
    static const char* trusted[2];
    trusted[0] = dsa_public[1];
    trusted[1] = dsa_public[2];
    mesh_config.qkp.trusted_pubs = trusted;
    mesh_config.qkp.trusted_count = 2u;
    for (size_t i = 1; i < NODE_COUNT; i++) {
        qihse_consensus_mesh_peer_t* peer = &mesh_config.peers[i - 1u];
        peer->member_uuid = members[i];
        peer->qkp_node_id = i == 1u ? "mesh-node-1" : "mesh-node-2";
        peer->dsa_public_key_path = dsa_public[i];
        peer->wireguard_ipv4 = "127.0.0.1";
        peer->port = ports[i];
        peer->snapshot_chunks_supported = i == 2u;
    }
    qihse_consensus_mesh_t* mesh = qihse_consensus_mesh_create(&mesh_config);
    if (!mesh || !qihse_consensus_mesh_start(mesh)) {
        fprintf(stderr, "mesh leader child: mesh create/start failed\n");
        return 6;
    }
    puts("mesh leader process ready");
    fflush(stdout);
    char ready_path[384];
    if (snprintf(ready_path, sizeof(ready_path), "%s/mesh-leader-ready", root) <= 0)
        return 7;
    int ready_fd = open(ready_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (ready_fd < 0) return 7;
    if (write(ready_fd, "ready\n", 6u) != 6 || fsync(ready_fd) != 0) {
        close(ready_fd);
        return 7;
    }
    close(ready_fd);
    for (;;) pause();
}

static pid_t spawn_mesh_leader(const char* program, const char* root,
                               const uint16_t ports[NODE_COUNT]) {
    char p0[16], p1[16], p2[16];
    snprintf(p0, sizeof(p0), "%u", (unsigned)ports[0]);
    snprintf(p1, sizeof(p1), "%u", (unsigned)ports[1]);
    snprintf(p2, sizeof(p2), "%u", (unsigned)ports[2]);
    char* argv[] = {(char*)program, (char*)"--mesh-leader-child", (char*)root,
                    p0, p1, p2, NULL};
    pid_t pid = -1;
    int rc = posix_spawn(&pid, program, NULL, NULL, argv, environ);
    assert(rc == 0 && pid > 0);
    return pid;
}

static void wait_mesh_leader_ready(const char* root, pid_t child) {
    char ready_path[384];
    assert(snprintf(ready_path, sizeof(ready_path), "%s/mesh-leader-ready", root) > 0);
    for (unsigned attempt = 0; attempt < 1000u; attempt++) {
        int status = 0;
        pid_t state = waitpid(child, &status, WNOHANG);
        assert(state == 0);
        if (access(ready_path, R_OK) == 0) return;
        usleep(10000u);
    }
    assert(!"timed out waiting for mesh leader process readiness");
}

typedef struct {
    qihse_consensus_mesh_t* mesh;
    qihse_user_t* principal;
    const void* transaction;
    size_t transaction_len;
    qihse_hlc_t hlc;
    uint64_t generation;
    uint64_t index;
    bool ok;
} proposal_thread_t;

static void* propose_auto_thread(void* opaque) {
    proposal_thread_t* job = opaque;
    job->ok = qihse_consensus_mesh_propose_transaction_auto_generation(
        job->mesh, job->principal, job->hlc, 0u, 0u,
        job->transaction, job->transaction_len, 10000u, 5000u,
        &job->generation, &job->index);
    return NULL;
}

static char* run_resp(qihse_resp_server_t* server, qihse_user_t* principal,
                     const char* const* parts, size_t count) {
    qihse_resp_arg_t args[8];
    assert(count <= sizeof(args) / sizeof(args[0]));
    for (size_t i = 0; i < count; i++) {
        args[i].data = (const uint8_t*)parts[i];
        args[i].len = strlen(parts[i]);
    }
    uint8_t* reply = NULL;
    size_t reply_len = 0u;
    assert(qihse_resp_server_execute(server, principal, count, args,
                                     &reply, &reply_len));
    char* text = malloc(reply_len + 1u);
    assert(text);
    memcpy(text, reply, reply_len);
    text[reply_len] = '\0';
    free(reply);
    return text;
}

static uint16_t free_loopback_port(void) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    assert(fd >= 0);
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    assert(bind(fd, (struct sockaddr*)&addr, sizeof(addr)) == 0);
    socklen_t len = sizeof(addr);
    assert(getsockname(fd, (struct sockaddr*)&addr, &len) == 0);
    uint16_t port = ntohs(addr.sin_port);
    close(fd);
    return port;
}

static void seed_large_snapshot(const qihse_consensus_config_t* config,
                                qihse_user_t* operator_user,
                                const qihse_uuid_t* source_member) {
    const size_t count = 32u;
    qihse_consensus_entry_t entries[32];
    qihse_uuid_t temporary;
    assert(qihse_uuid_from_seed("large-snapshot-temporary-member", 31u,
                                &temporary));
    for (size_t i = 0; i < count; i++) {
        qihse_consensus_entry_t* entry = &entries[i];
        memset(entry, 0, sizeof(*entry));
        entry->index = i + 1u;
        entry->term = 1u;
        entry->journal_generation = i + 1u;
        entry->type = (i % 2u) ? QIHSE_CONSENSUS_ENTRY_CONFIG_REMOVE
                               : QIHSE_CONSENSUS_ENTRY_CONFIG_ADD;
        memcpy(entry->payload, temporary.bytes, sizeof(temporary.bytes));
        entry->payload_len = sizeof(temporary.bytes);
    }
    qihse_consensus_t* consensus = qihse_consensus_open(config, NULL, NULL);
    assert(consensus);
    qihse_consensus_snapshot_descriptor_t descriptor;
    memset(&descriptor, 0, sizeof(descriptor));
    snprintf(descriptor.group_id, sizeof(descriptor.group_id), "%s",
             config->group_id);
    descriptor.from = *source_member;
    descriptor.to = config->self;
    descriptor.term = 1u;
    descriptor.fencing_epoch = 1u;
    descriptor.last_included_index = count;
    descriptor.last_included_term = 1u;
    descriptor.snapshot_fencing_epoch = 1u;
    descriptor.journal_generation = count;
    descriptor.digest = qihse_consensus_snapshot_entries_digest(entries, count);
    assert(qihse_consensus_install_snapshot_prefix(consensus, operator_user,
        &descriptor, entries, count));
    qihse_consensus_close(consensus);
    consensus = qihse_consensus_open(config, NULL, NULL);
    assert(consensus);
    qihse_consensus_close(consensus);
}

typedef struct {
    qihse_consensus_msg_t last;
    size_t sent;
    bool chunk_peer_enabled;
    qihse_uuid_t chunk_peer;
} snapshot_ack_capture_t;

static void snapshot_ack_capture_send(void* opaque,
                                     const qihse_consensus_msg_t* message) {
    snapshot_ack_capture_t* capture = opaque;
    if (!capture || !message) return;
    capture->last = *message;
    capture->sent++;
}

static bool snapshot_ack_chunks_supported(void* opaque,
                                          const qihse_uuid_t* peer) {
    snapshot_ack_capture_t* capture = opaque;
    return capture && capture->chunk_peer_enabled && peer &&
           qihse_uuid_equal(peer, &capture->chunk_peer);
}

static void snapshot_ack_reply(qihse_consensus_t* consensus,
                               const qihse_consensus_config_t* config,
                               const qihse_uuid_t* from,
                               qihse_consensus_msg_type_t type,
                               bool success, uint64_t match_index) {
    qihse_consensus_msg_t reply;
    memset(&reply, 0, sizeof(reply));
    reply.type = type;
    snprintf(reply.group_id, sizeof(reply.group_id), "%s", config->group_id);
    reply.from = *from;
    reply.to = config->self;
    reply.term = qihse_consensus_term(consensus);
    reply.fencing_epoch = qihse_consensus_fencing_epoch(consensus);
    if (type == QIHSE_CONSENSUS_MSG_APPEND_REPLY) {
        reply.u.append_reply.success = success;
        reply.u.append_reply.match_index = match_index;
    } else {
        reply.u.snapshot_reply.success = success;
        reply.u.snapshot_reply.match_index = match_index;
    }
    qihse_consensus_receive(consensus, &reply);
}

/* The legacy snapshot reply's partial-stage high-watermark is bounded by the
 * committed snapshot prefix. It cannot count the retained current-term tail
 * beyond that boundary toward quorum; that tail needs its own append ACK. */
static void test_snapshot_staging_is_not_commit_evidence(
    const char* root, qihse_user_t* operator_user,
    const qihse_uuid_t members[NODE_COUNT]) {
    qihse_consensus_config_t config;
    memset(&config, 0, sizeof(config));
    snprintf(config.group_id, sizeof(config.group_id), "%s", "mesh-ack-test");
    config.self = members[0];
    config.member_count = NODE_COUNT;
    memcpy(config.members, members, sizeof(config.members[0]) * NODE_COUNT);
    config.election_timeout_base_ms = 1000u;
    config.election_timeout_spread_ms = 3u;
    config.heartbeat_interval_ms = 100u;
    assert(snprintf(config.record_path, sizeof(config.record_path),
                    "%s/consensus-snapshot-ack.rec", root) > 0);
    seed_large_snapshot(&config, operator_user, &members[1]);

    snapshot_ack_capture_t capture;
    memset(&capture, 0, sizeof(capture));
    capture.chunk_peer_enabled = true;
    capture.chunk_peer = members[2];
    config.snapshot_chunks_supported = snapshot_ack_chunks_supported;
    config.snapshot_chunks_context = &capture;
    qihse_consensus_t* consensus = qihse_consensus_open(
        &config, &capture, snapshot_ack_capture_send);
    assert(consensus);
    assert(qihse_consensus_commit_index(consensus) == 32u);

    uint64_t now = 0u;
    while (qihse_consensus_role(consensus) == QIHSE_CONSENSUS_FOLLOWER &&
           now < 30000u) {
        now += 10u;
        qihse_consensus_tick(consensus, now);
    }
    assert(qihse_consensus_role(consensus) == QIHSE_CONSENSUS_CANDIDATE);
    qihse_consensus_msg_t vote;
    memset(&vote, 0, sizeof(vote));
    vote.type = QIHSE_CONSENSUS_MSG_VOTE_REPLY;
    snprintf(vote.group_id, sizeof(vote.group_id), "%s", config.group_id);
    vote.from = members[1]; vote.to = config.self;
    vote.term = qihse_consensus_term(consensus);
    vote.fencing_epoch = qihse_consensus_fencing_epoch(consensus);
    vote.u.vote_reply.granted = true;
    qihse_consensus_receive(consensus, &vote);
    assert(qihse_consensus_role(consensus) == QIHSE_CONSENSUS_LEADER);

    qihse_hlc_t hlc = {1900000000000u, 0u};
    assert(qihse_consensus_propose(consensus, operator_user, 33u, hlc,
        0u, 0u, "current-term-tail", 17u));
    assert(qihse_consensus_last_log_index(consensus) == 33u);
    assert(qihse_consensus_commit_index(consensus) == 32u);

    snapshot_ack_reply(consensus, &config, &members[2],
        QIHSE_CONSENSUS_MSG_APPEND_REPLY, false, 0u);
    snapshot_ack_reply(consensus, &config, &members[2],
        QIHSE_CONSENSUS_MSG_APPEND_REPLY, true, 0u);
    now += 200u;
    qihse_consensus_tick(consensus, now);
    assert(capture.last.type == QIHSE_CONSENSUS_MSG_SNAPSHOT_CHUNK);
    assert(capture.last.u.snapshot_chunk.first_entry_index == 1u);

    /* An accepted partial durable stage reports only entries 1..8. It can
     * refresh peer liveness and advance transfer, but quorum remains below
     * the current-term proposal at index 33. */
    snapshot_ack_reply(consensus, &config, &members[2],
        QIHSE_CONSENSUS_MSG_SNAPSHOT_REPLY, true, 8u);
    assert(qihse_consensus_commit_index(consensus) == 32u);
    assert(qihse_consensus_group_available(consensus, now + 1u));

    now += 200u;
    qihse_consensus_tick(consensus, now);
    assert(capture.last.type == QIHSE_CONSENSUS_MSG_SNAPSHOT_CHUNK);
    assert(capture.last.u.snapshot_chunk.first_entry_index == 9u);

    /* Complete publication acknowledges exactly the already-committed
     * snapshot boundary, which still cannot commit the index-33 tail. */
    snapshot_ack_reply(consensus, &config, &members[2],
        QIHSE_CONSENSUS_MSG_SNAPSHOT_REPLY, true, 32u);
    assert(qihse_consensus_commit_index(consensus) == 32u);
    snapshot_ack_reply(consensus, &config, &members[2],
        QIHSE_CONSENSUS_MSG_APPEND_REPLY, true, 33u);
    assert(qihse_consensus_commit_index(consensus) == 33u);

    qihse_consensus_close(consensus);
}

int main(int argc, char** argv) {
    if (argc == 6 && strcmp(argv[1], "--mesh-leader-child") == 0) {
        uint16_t ports[NODE_COUNT];
        for (size_t i = 0; i < NODE_COUNT; i++) {
            char* end = NULL;
            unsigned long value = strtoul(argv[i + 3u], &end, 10);
            if (!end || *end || value == 0u || value > UINT16_MAX) return 64;
            ports[i] = (uint16_t)value;
        }
        return run_mesh_leader_child(argv[2], ports);
    }
    char root[] = "build/test_consensus_mesh_XXXXXX";
    assert(mkdtemp(root));
    char data[256], dirs[NODE_COUNT][256], blob_dirs[NODE_COUNT][256];
    assert(snprintf(data, sizeof(data), "%s/data", root) > 0);
    assert(mkdir(data, 0700) == 0);
    assert(setenv("QIHSE_DATA_DIR", data, 1) == 0);
    assert(setenv("QIHSE_FIPS_MODE", "disabled", 1) == 0);
    assert(qihse_pqc_init_providers() == 0);
    assert(qihse_auth_init());
    assert(qihse_auth_bootstrap_operator("ConsensusMeshOperator1!"));
    qihse_user_t* operator_user = qihse_auth_get_user(0u);
    assert(operator_user);
    qihse_blob_store_t* blob_stores[NODE_COUNT] = {0};
    qihse_consensus_blob_context_t blob_contexts[NODE_COUNT];

    qihse_uuid_t members[NODE_COUNT];
    uint16_t ports[NODE_COUNT];
    char dsa_private[NODE_COUNT][320], kem_private[NODE_COUNT][320];
    char kem_public[NODE_COUNT][320], dsa_public[NODE_COUNT][320];
    for (size_t i = 0; i < NODE_COUNT; i++) {
        char seed[32]; int seed_len = snprintf(seed, sizeof(seed), "mesh-member-%zu", i);
        assert(seed_len > 0 && qihse_uuid_from_seed(seed, (size_t)seed_len, &members[i]));
        assert(snprintf(dirs[i], sizeof(dirs[i]), "%s/node-%zu", root, i) > 0);
        assert(mkdir(dirs[i], 0700) == 0);
        assert(snprintf(blob_dirs[i], sizeof(blob_dirs[i]), "%s/blobs-%zu", root, i) > 0);
        blob_stores[i] = qihse_blob_store_create(blob_dirs[i]);
        assert(blob_stores[i]);
        assert(qihse_consensus_blob_context_init(&blob_contexts[i], blob_stores[i],
                                                   operator_user, "mesh-test"));
        assert(qihse_pqc_keygen(dirs[i]));
        assert(snprintf(dsa_private[i], sizeof(dsa_private[i]), "%s/qihse_dsa_key.pem", dirs[i]) > 0);
        assert(snprintf(kem_private[i], sizeof(kem_private[i]), "%s/qihse_kem_key.pem", dirs[i]) > 0);
        assert(snprintf(kem_public[i], sizeof(kem_public[i]), "%s/qihse_kem_pub.pem", dirs[i]) > 0);
        assert(snprintf(dsa_public[i], sizeof(dsa_public[i]), "%s/qihse_dsa_pub.pem", dirs[i]) > 0);
        ports[i] = free_loopback_port();
    }

    test_snapshot_staging_is_not_commit_evidence(root, operator_user, members);

    qihse_consensus_mesh_t* meshes[NODE_COUNT] = {0};
    qihse_consensus_mesh_config_t mesh_configs[NODE_COUNT];
    for (size_t i = 0; i < NODE_COUNT; i++) {
        qihse_consensus_mesh_config_t* config = &mesh_configs[i];
        memset(config, 0, sizeof(*config));
        qihse_consensus_config_t* consensus = &config->consensus;
        snprintf(consensus->group_id, sizeof(consensus->group_id), "%s", "mesh-test");
        consensus->self = members[i];
        consensus->member_count = NODE_COUNT;
        memcpy(consensus->members, members, sizeof(members));
        consensus->election_timeout_base_ms = 800u;
        consensus->election_timeout_spread_ms = 600u;
        consensus->heartbeat_interval_ms = 100u;
        if (i == 1u) /* Lower-priority voter waits for preferred candidates. */
            consensus->election_priority_delay_ms = 1200u;
        assert(qihse_consensus_blob_bind_config(&blob_contexts[i], consensus));
        assert(snprintf(consensus->record_path, sizeof(consensus->record_path),
                        "%s/consensus-%zu.rec", root, i) > 0);
        config->system_principal = operator_user;
        config->blob_context = &blob_contexts[i];
        char stage_path[320];
        assert(snprintf(stage_path, sizeof(stage_path), "%s/snapshot-stage-%zu.rec",
                        root, i) > 0);
        static char stage_paths[NODE_COUNT][320];
        snprintf(stage_paths[i], sizeof(stage_paths[i]), "%s", stage_path);
        config->snapshot_stage_path = stage_paths[i];
        config->listen_wireguard_ipv4 = "127.0.0.1";
        config->listen_port = ports[i];
        config->peer_count = NODE_COUNT - 1u;
        config->qkp.require = true;
        config->qkp.node_id = i == 0u ? "mesh-node-0" : (i == 1u ? "mesh-node-1" : "mesh-node-2");
        config->qkp.dsa_key_path = dsa_private[i];
        config->qkp.kem_key_path = kem_private[i];
        config->qkp.kem_pub_path = kem_public[i];
        static const char* trusted[NODE_COUNT][NODE_COUNT - 1u];
        size_t ti = 0u;
        for (size_t j = 0; j < NODE_COUNT; j++) if (i != j) trusted[i][ti++] = dsa_public[j];
        config->qkp.trusted_pubs = trusted[i];
        config->qkp.trusted_count = NODE_COUNT - 1u;
        size_t pi = 0u;
        for (size_t j = 0; j < NODE_COUNT; j++) {
            if (i == j) continue;
            qihse_consensus_mesh_peer_t* peer = &config->peers[pi++];
            peer->member_uuid = members[j];
            peer->qkp_node_id = j == 0u ? "mesh-node-0" : (j == 1u ? "mesh-node-1" : "mesh-node-2");
            peer->dsa_public_key_path = dsa_public[j];
            peer->wireguard_ipv4 = "127.0.0.1";
            peer->port = ports[j];
            /* The node 0 image explicitly opts into chunk snapshots
             * only for node 2. Node 1 exercises the safe legacy gate. */
            peer->snapshot_chunks_supported = (i == 0u && j == 2u);
        }
        if (i == 0u)
            seed_large_snapshot(consensus, operator_user, &members[1]);
        if (i != 0u) {
            meshes[i] = qihse_consensus_mesh_create(config);
            assert(meshes[i]);
        }
    }
    pid_t leader_process = spawn_mesh_leader(argv[0], root, ports);
    wait_mesh_leader_ready(root, leader_process);
    /* Hold node 2's first chunk ACK so its durable stage can be resumed after
     * the leader process restarts. Node 0 is peer slot 0 on node 2's config. */
    assert(qihse_consensus_mesh_test_drop_next_snapshot_ack(meshes[2], 0u, 100u));
    for (size_t i = 1; i < NODE_COUNT; i++) {
        assert(qihse_consensus_mesh_start(meshes[i]));
        fprintf(stderr, "test mesh node %zu listening on %u (expected %u)\n", i,
                (unsigned)qihse_consensus_mesh_port(meshes[i]), (unsigned)ports[i]);
        assert(qihse_consensus_mesh_port(meshes[i]) == ports[i]);
    }

    bool converged = false;
    for (unsigned attempt = 0; attempt < 1200u && !converged; attempt++) {
        converged = true;
        for (size_t i = 1; i < NODE_COUNT; i++) {
            qihse_uuid_t leader;
            if (!qihse_consensus_mesh_leader_id(meshes[i], &leader) ||
                !qihse_uuid_equal(&leader, &members[0]) ||
                qihse_consensus_mesh_role(meshes[i]) == QIHSE_CONSENSUS_LEADER)
                converged = false;
        }
        if (!converged) usleep(10000u);
    }
    if (!converged) {
        for (size_t i = 1; i < NODE_COUNT; i++) {
            qihse_uuid_t leader = {{0}};
            bool has_leader = qihse_consensus_mesh_leader_id(meshes[i], &leader);
            fprintf(stderr, "mesh process restart diagnostic node=%zu role=%d term=%llu leader=%d id=%02x%02x\n",
                i, (int)qihse_consensus_mesh_role(meshes[i]),
                (unsigned long long)qihse_consensus_mesh_term(meshes[i]),
                has_leader ? 1 : 0, leader.bytes[0], leader.bytes[1]);
        }
        int status = 0;
        pid_t child_state = waitpid(leader_process, &status, WNOHANG);
        fprintf(stderr, "mesh process restart diagnostic child_state=%d status=%d\n",
                (int)child_state, status);
    }
    assert(converged);
    qihse_uuid_t elected;
    int leader_index = 0; /* node 0 is the exec'd leader process */
    assert(qihse_consensus_mesh_leader_id(meshes[2], &elected));
    assert(qihse_uuid_equal(&elected, &members[0]));

    size_t snapshot_receiver = 2u;
    qihse_consensus_snapshot_stage_progress_t stage_progress;
    /* Node 0 is provisioned to send chunks, but this receiver has not opted in.
     * The authenticated stream may carry type 7; it must be closed without
     * staging any data until the receiving side is provisioned too. */
    usleep(300000u);
    assert(qihse_consensus_mesh_test_snapshot_progress(
        meshes[snapshot_receiver], operator_user, &stage_progress));
    assert(!stage_progress.has_transfer && stage_progress.next_entry_index == 1u);
    assert(qihse_consensus_mesh_test_set_snapshot_chunks_supported(
        meshes[snapshot_receiver], 0u, true));
    bool first_chunk_staged = false;
    for (unsigned attempt = 0; attempt < 1000u && !first_chunk_staged; attempt++) {
        first_chunk_staged = qihse_consensus_mesh_test_snapshot_progress(
            meshes[snapshot_receiver], operator_user, &stage_progress) &&
            stage_progress.has_transfer && stage_progress.next_entry_index >= 9u;
        if (!first_chunk_staged) usleep(10000u);
    }
    assert(first_chunk_staged);
    for (unsigned attempt = 0; attempt < 100u &&
         qihse_consensus_mesh_test_snapshot_ack_drops(
             meshes[snapshot_receiver]) == 0u; attempt++) usleep(10000u);
    assert(qihse_consensus_mesh_test_snapshot_ack_drops(meshes[snapshot_receiver]) > 0u);
    uint64_t term_before_leader_crash =
        qihse_consensus_mesh_term(meshes[snapshot_receiver]);
    uint64_t transfer_id_before_leader_crash = stage_progress.transfer_id;
    assert(!stage_progress.complete && stage_progress.next_entry_index == 9u);
    /* Keep node 2 from electing a competing leader during the restart window;
     * with only node 2 available it cannot form quorum, and the restarted
     * up-to-date node 0 must obtain its vote. */
    qihse_consensus_mesh_stop(meshes[1u]);
    qihse_consensus_mesh_destroy(meshes[1u]);
    meshes[1u] = NULL;
    assert(kill(leader_process, SIGKILL) == 0);
    int leader_status = 0;
    assert(waitpid(leader_process, &leader_status, 0) == leader_process);
    assert(WIFSIGNALED(leader_status) && WTERMSIG(leader_status) == SIGKILL);

    /* Exec a fresh leader process against the same durable consensus record.
     * The receiver must retain its partial prefix while the new leader adopts
     * a higher term, then resume that exact snapshot transfer. */
    char ready_path[384];
    assert(snprintf(ready_path, sizeof(ready_path), "%s/mesh-leader-ready", root) > 0);
    assert(unlink(ready_path) == 0);
    leader_process = spawn_mesh_leader(argv[0], root, ports);
    wait_mesh_leader_ready(root, leader_process);
    size_t leader_peer_on_receiver = 0u;
    assert(qihse_consensus_mesh_test_set_snapshot_ack_drops(
        meshes[snapshot_receiver], leader_peer_on_receiver, 0u));
    bool snapshot_caught_up = false;
    for (unsigned attempt = 0; attempt < 2000u && !snapshot_caught_up; attempt++) {
        qihse_consensus_mesh_test_snapshot_progress(meshes[snapshot_receiver],
            operator_user, &stage_progress);
        qihse_uuid_t leader;
        snapshot_caught_up = stage_progress.complete &&
            stage_progress.next_entry_index == 33u &&
            stage_progress.transfer_id == transfer_id_before_leader_crash &&
            qihse_consensus_mesh_term(meshes[snapshot_receiver]) >
                term_before_leader_crash &&
            qihse_consensus_mesh_leader_id(meshes[snapshot_receiver], &leader) &&
            qihse_uuid_equal(&leader, &members[0]) &&
            qihse_consensus_mesh_commit_index(meshes[snapshot_receiver]) >= 32u;
        if (!snapshot_caught_up) usleep(10000u);
    }
    if (!snapshot_caught_up) {
        qihse_uuid_t current_leader = {{0}};
        bool has_leader = qihse_consensus_mesh_leader_id(
            meshes[snapshot_receiver], &current_leader);
        fprintf(stderr, "mesh restart resume diagnostic: term_before=%llu term_after=%llu stage=%d complete=%d next=%llu total=%llu transfer=%llu expected_transfer=%llu commit=%llu leader=%d id=%02x%02x role=%d\n",
            (unsigned long long)term_before_leader_crash,
            (unsigned long long)qihse_consensus_mesh_term(meshes[snapshot_receiver]),
            stage_progress.has_transfer ? 1 : 0, stage_progress.complete ? 1 : 0,
            (unsigned long long)stage_progress.next_entry_index,
            (unsigned long long)stage_progress.total_entries,
            (unsigned long long)stage_progress.transfer_id,
            (unsigned long long)transfer_id_before_leader_crash,
            (unsigned long long)qihse_consensus_mesh_commit_index(meshes[snapshot_receiver]),
            has_leader ? 1 : 0, current_leader.bytes[0], current_leader.bytes[1],
            (int)qihse_consensus_mesh_role(meshes[snapshot_receiver]));
    }
    assert(snapshot_caught_up);
    qihse_consensus_mesh_stop(meshes[snapshot_receiver]);
    qihse_consensus_mesh_destroy(meshes[snapshot_receiver]);
    meshes[snapshot_receiver] = NULL;
    assert(kill(leader_process, SIGKILL) == 0);
    assert(waitpid(leader_process, &leader_status, 0) == leader_process);
    assert(WIFSIGNALED(leader_status) && WTERMSIG(leader_status) == SIGKILL);

    /* Reopen node 0 in this test process so later proposal and RESP checks can
     * exercise the same recovered consensus state through the public API. */
    meshes[0] = qihse_consensus_mesh_create(&mesh_configs[0]);
    assert(meshes[0]);
    meshes[snapshot_receiver] = qihse_consensus_mesh_create(
        &mesh_configs[snapshot_receiver]);
    assert(meshes[snapshot_receiver]);
    assert(qihse_consensus_mesh_start(meshes[0]));
    assert(qihse_consensus_mesh_start(meshes[snapshot_receiver]));
    meshes[1u] = qihse_consensus_mesh_create(&mesh_configs[1u]);
    assert(meshes[1u] && qihse_consensus_mesh_start(meshes[1u]));
    bool local_leader_recovered = false;
    for (unsigned attempt = 0; attempt < 1500u && !local_leader_recovered; attempt++) {
        local_leader_recovered =
            qihse_consensus_mesh_role(meshes[0]) == QIHSE_CONSENSUS_LEADER;
        if (!local_leader_recovered) usleep(10000u);
    }
    if (!local_leader_recovered) {
        qihse_uuid_t leader = {{0}};
        bool has_leader = qihse_consensus_mesh_leader_id(meshes[2], &leader);
        fprintf(stderr, "local leader restore diagnostic: node0 role=%d term=%llu node2 role=%d term=%llu leader=%d id=%02x%02x\n",
            (int)qihse_consensus_mesh_role(meshes[0]),
            (unsigned long long)qihse_consensus_mesh_term(meshes[0]),
            (int)qihse_consensus_mesh_role(meshes[2]),
            (unsigned long long)qihse_consensus_mesh_term(meshes[2]),
            has_leader ? 1 : 0, leader.bytes[0], leader.bytes[1]);
    }
    assert(local_leader_recovered);
    leader_index = 0;
    bool relay_reports_main = false;
    for (unsigned attempt = 0; attempt < 1000u && !relay_reports_main; attempt++) {
        qihse_uuid_t current_leader;
        relay_reports_main = qihse_consensus_mesh_leader_id(meshes[1u],
            &current_leader) && qihse_uuid_equal(&current_leader, &members[0]);
        if (!relay_reports_main) usleep(10000u);
    }
    assert(relay_reports_main);

    /* Force the first successful stage ACK from each remote to be lost. The
     * remote has already imported the QBR1 object; success therefore requires
     * reconnecting and completing the duplicate HAVE retry before quorum. */
    for (size_t i = 0; i < NODE_COUNT; i++) {
        if ((int)i == leader_index) continue;
        size_t peer_index = i < (size_t)leader_index ? i : i - 1u;
        assert(qihse_consensus_mesh_test_drop_next_stage_ack(
            meshes[leader_index], peer_index, 1u));
    }
    qihse_hlc_t hlc = {1800000000000u, 0u};
    static const uint8_t transactions[2][40] = {
        "mesh-transaction-concurrent-a",
        "mesh-transaction-concurrent-b"
    };
    proposal_thread_t jobs[2] = {
        {.mesh = meshes[leader_index], .principal = operator_user,
         .transaction = transactions[0], .transaction_len = strlen((const char*)transactions[0]), .hlc = hlc},
        {.mesh = meshes[leader_index], .principal = operator_user,
         .transaction = transactions[1], .transaction_len = strlen((const char*)transactions[1]), .hlc = hlc}
    };
    pthread_t proposal_threads[2];
    for (size_t i = 0; i < 2u; i++)
        assert(pthread_create(&proposal_threads[i], NULL, propose_auto_thread, &jobs[i]) == 0);
    for (size_t i = 0; i < 2u; i++) {
        assert(pthread_join(proposal_threads[i], NULL) == 0);
        assert(jobs[i].ok);
        assert(jobs[i].index > 0u);
    }
    assert(qihse_consensus_mesh_test_stage_ack_drops(meshes[leader_index]) ==
           NODE_COUNT - 1u);
    assert(jobs[0].generation != jobs[1].generation);
    assert((jobs[0].generation == 33u && jobs[1].generation == 34u) ||
           (jobs[0].generation == 34u && jobs[1].generation == 33u));
    uint64_t committed_index = jobs[0].index > jobs[1].index ? jobs[0].index : jobs[1].index;
    bool chunk_peer_caught_up = false;
    for (unsigned attempt = 0; attempt < 1500u && !chunk_peer_caught_up; attempt++) {
        chunk_peer_caught_up =
            qihse_consensus_mesh_commit_index(meshes[0]) >= committed_index &&
            qihse_consensus_mesh_commit_index(meshes[2]) >= committed_index;
        if (!chunk_peer_caught_up) usleep(10000u);
    }
    assert(chunk_peer_caught_up);
    assert(qihse_consensus_mesh_commit_index(meshes[1]) < 32u);
    for (size_t i = 0; i < NODE_COUNT; i += 2u) {
        qihse_consensus_entry_t entries[2]; size_t count = 0u;
        assert(qihse_consensus_mesh_read_committed(meshes[i], operator_user,
            33u, entries, 2u, &count));
        assert(count == 2u);
        assert(entries[0].journal_generation == 33u && entries[1].journal_generation == 34u);
        for (size_t j = 0; j < count; j++) {
            assert(entries[j].payload_len == QIHSE_CONSENSUS_BLOB_REF_BYTES);
            assert(qihse_consensus_blob_validate(&blob_contexts[i], &entries[j]));
            uint64_t staged_size = 0u;
            assert(qihse_blob_size_user(blob_stores[i], entries[j].payload + 64u,
                                        &staged_size, operator_user));
            assert(staged_size > QIHSE_CONSENSUS_BLOB_HEADER_BYTES);
        }
    }

    /* A legacy-configured peer is held at the safe gate until explicit
     * capability provisioning; then the same automatic path catches it up. */
    size_t legacy_peer = NODE_COUNT;
    for (size_t i = 0; i < mesh_configs[leader_index].peer_count; i++)
        if (qihse_uuid_equal(&mesh_configs[leader_index].peers[i].member_uuid,
                             &members[1])) legacy_peer = i;
    assert(legacy_peer < NODE_COUNT);
    assert(qihse_consensus_mesh_test_set_snapshot_chunks_supported(
        meshes[leader_index], legacy_peer, true));
    size_t leader_peer_on_legacy = NODE_COUNT;
    for (size_t i = 0; i < mesh_configs[1u].peer_count; i++)
        if (qihse_uuid_equal(&mesh_configs[1u].peers[i].member_uuid,
                             &members[leader_index])) leader_peer_on_legacy = i;
    assert(leader_peer_on_legacy < NODE_COUNT);
    assert(qihse_consensus_mesh_test_set_snapshot_chunks_supported(
        meshes[1u], leader_peer_on_legacy, true));
    bool legacy_caught_up = false;
    for (unsigned attempt = 0; attempt < 1500u && !legacy_caught_up; attempt++) {
        legacy_caught_up = qihse_consensus_mesh_commit_index(meshes[1]) >= committed_index;
        if (!legacy_caught_up) usleep(10000u);
    }
    assert(legacy_caught_up);
    puts("PASS QCS1 snapshot chunks: automatic opt-in catch-up, legacy capability gate, durable same-descriptor resume after lost ACK and leader process restart");

    qihse_resp_server_config_t resp_config;
    qihse_resp_server_config_init(&resp_config);
    resp_config.enable_uwp_bridge = true;
    resp_config.consensus_mesh = meshes[leader_index];
    resp_config.consensus_blob_context = &blob_contexts[leader_index];
    resp_config.consensus_allow_client_proposals = true;
    qihse_resp_server_t* resp = qihse_resp_server_create(&resp_config);
    assert(resp);
    qihse_user_t* analyst = qihse_auth_create_user(operator_user, 63002u,
        QIHSE_ROLE_ANALYST, 1u, 0u, "MeshAnalystPass1!", false);
    assert(analyst);
    static const char protected_payload[] = "protected-no-leak-marker";
    const char* protected_propose[] = {"QIHSE.TXN.PROPOSE", "3", "8", "34",
                                       protected_payload};
    assert(qihse_consensus_mesh_role(meshes[leader_index]) == QIHSE_CONSENSUS_LEADER);
    size_t follower_index = (size_t)((leader_index + 1) % (int)NODE_COUNT);
    qihse_resp_server_config_t follower_config;
    qihse_resp_server_config_init(&follower_config);
    follower_config.enable_uwp_bridge = true;
    follower_config.consensus_mesh = meshes[follower_index];
    follower_config.consensus_blob_context = &blob_contexts[follower_index];
    follower_config.consensus_allow_client_proposals = true;
    qihse_resp_server_t* follower_resp = qihse_resp_server_create(&follower_config);
    assert(follower_resp);
    const char* redirect_propose[] = {"QIHSE.TXN.PROPOSE", "0", "0", "0",
                                      "redirect-check"};
    char* wire_reply = run_resp(follower_resp, operator_user, redirect_propose, 5u);
    assert(strstr(wire_reply, "MOVED ") && !strstr(wire_reply, "redirect-check"));
    free(wire_reply);
    const char* redirect_read[] = {"QIHSE.TXN.READ", "1", "16"};
    wire_reply = run_resp(follower_resp, operator_user, redirect_read, 3u);
    assert(strstr(wire_reply, "MOVED ") &&
           !strstr(wire_reply, protected_payload));
    free(wire_reply);
    qihse_resp_server_destroy(follower_resp);
    qihse_resp_server_config_t relay_readonly_config;
    qihse_resp_server_config_init(&relay_readonly_config);
    relay_readonly_config.enable_uwp_bridge = true;
    relay_readonly_config.consensus_mesh = meshes[1u];
    relay_readonly_config.consensus_blob_context = &blob_contexts[1u];
    qihse_resp_server_t* relay_readonly_resp =
        qihse_resp_server_create(&relay_readonly_config);
    assert(relay_readonly_resp);
    wire_reply = run_resp(relay_readonly_resp, operator_user,
                          protected_propose, 5u);
    assert(strstr(wire_reply,
        "READONLY client proposals are disabled on this member") &&
        !strstr(wire_reply, protected_payload));
    free(wire_reply);
    const char* relay_read[] = {"QIHSE.TXN.READ", "1", "16"};
    wire_reply = run_resp(relay_readonly_resp, operator_user, relay_read, 3u);
    assert(strstr(wire_reply, "MOVED ") &&
           !strstr(wire_reply, protected_payload));
    free(wire_reply);
    qihse_resp_server_destroy(relay_readonly_resp);
    qihse_resp_server_config_t unauth_config;
    qihse_resp_server_config_init(&unauth_config);
    unauth_config.auth_required = false;
    unauth_config.enable_uwp_bridge = true;
    unauth_config.consensus_mesh = meshes[leader_index];
    unauth_config.consensus_blob_context = &blob_contexts[leader_index];
    qihse_resp_server_t* unauth_resp = qihse_resp_server_create(&unauth_config);
    assert(unauth_resp);
    wire_reply = run_resp(unauth_resp, operator_user, redirect_propose, 5u);
    assert(strstr(wire_reply, "NOAUTH") && !strstr(wire_reply, "redirect-check"));
    free(wire_reply);
    qihse_resp_server_destroy(unauth_resp);
    const char* denied_propose[] = {"QIHSE.TXN.PROPOSE", "3", "8", "34",
                                    protected_payload};
    wire_reply = run_resp(resp, analyst, denied_propose, 5u);
    assert(strstr(wire_reply, "NOPERM") &&
           !strstr(wire_reply, protected_payload));
    free(wire_reply);
    wire_reply = run_resp(resp, operator_user, protected_propose, 5u);
    assert(strstr(wire_reply, "*4\r\n") && strstr(wire_reply, ":35\r\n"));
    free(wire_reply);
    bool protected_committed = false;
    for (unsigned attempt = 0; attempt < 1500u && !protected_committed; attempt++) {
        protected_committed =
            qihse_consensus_mesh_commit_index(meshes[leader_index]) >= 35u;
        if (!protected_committed) usleep(10000u);
    }
    assert(protected_committed);
    const char* stale_propose[] = {"QIHSE.TXN.PROPOSE", "0", "0", "2",
                                   "stale-generation-must-not-commit"};
    wire_reply = run_resp(resp, operator_user, stale_propose, 5u);
    assert(strstr(wire_reply, "TRYAGAIN application generation changed") &&
           !strstr(wire_reply, "stale-generation-must-not-commit"));
    free(wire_reply);
    const char* denied_read[] = {"QIHSE.TXN.READ", "35", "16"};
    wire_reply = run_resp(resp, analyst, denied_read, 3u);
    assert(strstr(wire_reply, "NOPERM committed transaction read denied") &&
           !strstr(wire_reply, "*2\r\n") &&
           !strstr(wire_reply, protected_payload));
    free(wire_reply);
    const char* denied_local_read[] = {"QIHSE.TXN.READLOCAL", "35", "16"};
    wire_reply = run_resp(resp, analyst, denied_local_read, 3u);
    assert(strstr(wire_reply, "NOPERM") &&
           !strstr(wire_reply, "*2\r\n") &&
           !strstr(wire_reply, protected_payload));
    free(wire_reply);
    wire_reply = run_resp(resp, operator_user, denied_read, 3u);
    assert(strstr(wire_reply, "*2\r\n") &&
           strstr(wire_reply, protected_payload));
    free(wire_reply);
    qihse_resp_server_destroy(resp);

    /* Node 0 loss must elect node 2 before the lower-priority node 1. */
    qihse_consensus_mesh_destroy(meshes[0u]);
    meshes[0u] = NULL;
    bool secondary_leader = false;
    for (unsigned attempt = 0; attempt < 600u && !secondary_leader; attempt++) {
        qihse_uuid_t leader;
        secondary_leader =
            qihse_consensus_mesh_role(meshes[2u]) == QIHSE_CONSENSUS_LEADER &&
            qihse_consensus_mesh_role(meshes[1u]) != QIHSE_CONSENSUS_LEADER &&
            qihse_consensus_mesh_leader_id(meshes[1u], &leader) &&
            qihse_uuid_equal(&leader, &members[2u]);
        if (!secondary_leader) usleep(10000u);
    }
    assert(secondary_leader);
    leader_index = 2;
    static const uint8_t pair_transaction[] = "main-plus-one-peer-commit";
    uint64_t pair_index = 0u;
    uint64_t pair_generation = 0u;
    hlc.physical_ms++;
    assert(qihse_consensus_mesh_propose_transaction_auto_generation(meshes[leader_index],
        operator_user, hlc, 0u, 0u, pair_transaction,
        sizeof(pair_transaction) - 1u, 5000u, 5000u,
        &pair_generation, &pair_index));
    assert(pair_generation == 36u);
    bool pair_caught_up = false;
    for (unsigned attempt = 0; attempt < 500u && !pair_caught_up; attempt++) {
        pair_caught_up = true;
        for (size_t i = 0; i < NODE_COUNT; i++)
            if (meshes[i] && qihse_consensus_mesh_commit_index(meshes[i]) < pair_index)
                pair_caught_up = false;
        if (!pair_caught_up) usleep(10000u);
    }
    assert(pair_caught_up);
    for (size_t i = 0; i < NODE_COUNT; i++) {
        if (!meshes[i]) continue;
        assert(qihse_consensus_mesh_commit_index(meshes[i]) >= pair_index);
        qihse_consensus_entry_t entries[2]; size_t count = 0u;
        assert(qihse_consensus_mesh_read_committed(meshes[i], operator_user,
            pair_index, entries, 2u, &count));
        assert(count == 1u && entries[0].journal_generation == 36u);
        assert(qihse_consensus_blob_validate(&blob_contexts[i], &entries[0]));
    }

    size_t remaining_index = 2u;
    qihse_consensus_mesh_destroy(meshes[1u]);
    meshes[1u] = NULL;
    static const uint8_t solo_transaction[] = "must-not-commit-alone";
    uint64_t solo_index = 0u;
    hlc.physical_ms++;
    assert(!qihse_consensus_mesh_propose_transaction(meshes[remaining_index],
        operator_user, 37u, hlc, 0u, 0u, solo_transaction,
        sizeof(solo_transaction) - 1u, 250u, 500u, &solo_index));
    assert(qihse_consensus_mesh_commit_index(meshes[remaining_index]) == pair_index);
    puts("PASS 3-node QKP mesh: durable payload quorum, surviving pair commit, and no single-node commit");

    for (size_t i = 0; i < NODE_COUNT; i++) if (meshes[i]) qihse_consensus_mesh_destroy(meshes[i]);
    for (size_t i = 0; i < NODE_COUNT; i++) qihse_blob_store_destroy(blob_stores[i]);
    return 0;
}
