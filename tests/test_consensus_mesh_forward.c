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


int main(void) {
    char root[] = "build/test_consensus_forward_XXXXXX";
    assert(mkdtemp(root));
    char data[256], dirs[NODE_COUNT][256], blob_dirs[NODE_COUNT][256];
    assert(snprintf(data, sizeof(data), "%s/data", root) > 0);
    assert(mkdir(data, 0700) == 0);
    assert(setenv("QIHSE_DATA_DIR", data, 1) == 0);
    assert(setenv("QIHSE_FIPS_MODE", "disabled", 1) == 0);
    assert(qihse_pqc_init_providers() >= 0);
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
            consensus->election_priority_delay_ms = 1800u;
        else if (i == 2u)
            consensus->election_priority_delay_ms = 800u;
        assert(qihse_consensus_blob_bind_config(&blob_contexts[i], consensus));
        assert(snprintf(consensus->record_path, sizeof(consensus->record_path),
                        "%s/consensus-%zu.rec", root, i) > 0);
        config->system_principal = operator_user;
        config->authority_proposals_enabled = true;
        consensus->writer_epoch_floor = 1u;
        memset(consensus->history_id, 0x42, sizeof(consensus->history_id));
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
        {
            meshes[i] = qihse_consensus_mesh_create(config);
            assert(meshes[i]);
        }
    }
    for (size_t i = 0; i < NODE_COUNT; ++i) assert(qihse_consensus_mesh_start(meshes[i]));
    size_t leader = NODE_COUNT;
    for (unsigned attempt = 0; attempt < 1500u; ++attempt) {
        for (size_t i = 0; i < NODE_COUNT; ++i)
            if (qihse_consensus_mesh_role(meshes[i]) == QIHSE_CONSENSUS_LEADER) leader = i;
        if (leader < NODE_COUNT) break;
        usleep(10000u);
    }
    assert(leader < NODE_COUNT);
    size_t follower = (leader+1u)%NODE_COUNT;
    uint8_t intent[164] = {'Q','C','F','1'};
    memset(intent+4u, 'a', 40u); memset(intent+44u, 'b', 40u);
    memset(intent+84u, 'c', 40u); memset(intent+124u, 'd', 32u); intent[163] = 7u;
    qihse_user_t* low = qihse_auth_create_user(operator_user, 63003u,
        QIHSE_ROLE_ANALYST, 0u, 0u, "MeshForwardAnalyst1!", false);
    assert(low);
    uint64_t index = 99u;
    assert(!qihse_consensus_mesh_propose_authority(meshes[follower], low,
        intent, sizeof(intent), 1000u, &index) && !index);
    assert(!qihse_consensus_mesh_propose_authority(meshes[follower], NULL,
        intent, sizeof(intent), 1000u, &index) && !index);
    /* Both peers of a follower remain connected while the second control
     * stream carries the request. Give the initial leader announcement time. */
    bool accepted = false;
    for (unsigned attempt = 0; attempt < 10u && !accepted; ++attempt) {
        accepted = qihse_consensus_mesh_propose_authority(meshes[follower], operator_user,
            intent, sizeof(intent), 3000u, &index);
        if (!accepted) usleep(100000u);
    }
    assert(accepted && index);
    uint64_t retry_index = 0u;
    assert(qihse_consensus_mesh_propose_authority(meshes[follower], operator_user,
        intent, sizeof(intent), 3000u, &retry_index) && retry_index == index);
    intent[163] = 8u;
    assert(qihse_consensus_mesh_propose_authority(meshes[follower], operator_user,
        intent, sizeof(intent), 3000u, &retry_index) && retry_index > index);
    index = retry_index;
    intent[163] = 7u;
    assert(!qihse_consensus_mesh_propose_authority(meshes[follower], operator_user,
        intent, sizeof(intent), 1000u, &retry_index));
    intent[163] = 8u;
    intent[44] = 'e';
    assert(!qihse_consensus_mesh_propose_authority(meshes[follower], operator_user,
        intent, sizeof(intent), 1000u, &retry_index));
    intent[44] = 'b';
    assert(qihse_consensus_mesh_propose_authority(meshes[leader], operator_user,
        intent, sizeof(intent), 1000u, &retry_index) && retry_index == index);
    puts("PASS follower authority forwarding: pinned history-bound quorum commit, local verification, exact retry and conflict denial");
    /* Persist an intent on all voters, withhold ACK processing so it is
     * explicitly uncommitted, then kill its leader. The surviving leader
     * must reject a conflicting winner and commit an exact current-term retry. */
    intent[124] = 'e';
    assert(qihse_consensus_mesh_test_hold_append_replies(meshes[leader], true));
    uint64_t pending = 0u;
    assert(!qihse_consensus_mesh_propose_authority(meshes[leader], operator_user,
        intent, sizeof(intent), 500u, &pending) && pending);
    assert(qihse_consensus_mesh_commit_index(meshes[leader]) < pending);
    for (unsigned attempt = 0; attempt < 1000u; ++attempt) {
        bool all_have = true;
        for (size_t i = 0; i < NODE_COUNT; ++i) {
            qihse_consensus_mesh_status_t status;
            assert(qihse_consensus_mesh_status(meshes[i], &status));
            if (status.last_log_index < pending) all_have = false;
        }
        if (all_have) break;
        assert(attempt < 999u); usleep(10000u);
    }
    size_t old_leader = leader;
    qihse_consensus_mesh_destroy(meshes[old_leader]); meshes[old_leader] = NULL;
    leader = NODE_COUNT;
    for (unsigned attempt = 0; attempt < 1500u; ++attempt) {
        for (size_t i = 0; i < NODE_COUNT; ++i)
            if (meshes[i] && qihse_consensus_mesh_role(meshes[i]) == QIHSE_CONSENSUS_LEADER) leader = i;
        if (leader < NODE_COUNT) break;
        usleep(10000u);
    }
    assert(leader < NODE_COUNT);
    follower = 3u-leader-old_leader;
    intent[44] = 'e';
    assert(!qihse_consensus_mesh_propose_authority(meshes[leader], operator_user,
        intent, sizeof(intent), 1000u, &retry_index));
    intent[44] = 'b';
    accepted = false;
    for (unsigned attempt = 0; attempt < 10u && !accepted; ++attempt) {
        accepted = qihse_consensus_mesh_propose_authority(meshes[follower], operator_user,
            intent, sizeof(intent), 3000u, &retry_index);
        if (!accepted) usleep(100000u);
    }
    assert(accepted && retry_index > pending);
    index = retry_index;
    puts("PASS inherited uncommitted intent: leader loss, conflicting winner denial and current-term retry commit");
    /* Remove the third member; forwarding must still commit using leader plus
     * requesting follower. The request must not block that follower's ACKs. */
    size_t third = 3u-leader-follower;
    if (meshes[third]) qihse_consensus_mesh_destroy(meshes[third]);
    meshes[third] = NULL;
    intent[124] = 'f';
    assert(qihse_consensus_mesh_propose_authority(meshes[follower], operator_user,
        intent, sizeof(intent), 5000u, &retry_index));
    assert(retry_index > index);
    puts("PASS surviving pair commits while authority request awaits its reply");
    qihse_consensus_mesh_destroy(meshes[leader]); meshes[leader] = NULL;
    intent[124] = 'a';
    assert(!qihse_consensus_mesh_propose_authority(meshes[follower], operator_user,
        intent, sizeof(intent), 500u, &index));
    puts("PASS no quorum denies authority; low-clearance and NULL callers receive no index");
    for (size_t i = 0; i < NODE_COUNT; ++i) if (meshes[i]) qihse_consensus_mesh_destroy(meshes[i]);
    for (size_t i = 0; i < NODE_COUNT; ++i) qihse_blob_store_destroy(blob_stores[i]);
    return 0;
}
