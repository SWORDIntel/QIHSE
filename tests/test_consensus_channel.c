#include "qihse_consensus_channel.h"
#include "qihse_pqc_crypto.h"

#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

typedef struct {
    int fd;
    qihse_qkp_config_t* config;
    qihse_qkp_result_t result;
    qihse_qkp_session_t* session;
} server_handshake_t;

static void* negotiate_server(void* opaque) {
    server_handshake_t* state = opaque;
    state->result = qihse_qkp_server_negotiate(state->fd, state->config,
                                                &state->session);
    return NULL;
}

int main(void) {
    char root[] = "build/test_consensus_channel_XXXXXX";
    assert(mkdtemp(root));
    char data[256], server_dir[256], client_dir[256];
    assert(snprintf(data, sizeof(data), "%s/data", root) > 0);
    assert(snprintf(server_dir, sizeof(server_dir), "%s/server", root) > 0);
    assert(snprintf(client_dir, sizeof(client_dir), "%s/client", root) > 0);
    assert(mkdir(data, 0700) == 0 && mkdir(server_dir, 0700) == 0 && mkdir(client_dir, 0700) == 0);
    assert(setenv("QIHSE_DATA_DIR", data, 1) == 0);
    assert(setenv("QIHSE_FIPS_MODE", "disabled", 1) == 0);
    assert(qihse_pqc_init_providers() == 0);
    assert(qihse_pqc_keygen(server_dir) && qihse_pqc_keygen(client_dir));
    assert(qihse_auth_init());
    assert(qihse_auth_bootstrap_operator("ConsensusChannelOperator1!"));
    qihse_user_t* op = qihse_auth_get_user(0u);
    assert(op);
    qihse_user_t* analyst = qihse_auth_create_user(
        op, 63001u, QIHSE_ROLE_ANALYST, 1u, 0u, "ChannelAnalystPass1!", false);
    assert(analyst);

    char server_dsa[320], server_kem[320], server_kem_pub[320];
    char server_pub[320], client_dsa[320], client_pub[320];
    assert(snprintf(server_dsa, sizeof(server_dsa), "%s/qihse_dsa_key.pem", server_dir) > 0);
    assert(snprintf(server_kem, sizeof(server_kem), "%s/qihse_kem_key.pem", server_dir) > 0);
    assert(snprintf(server_kem_pub, sizeof(server_kem_pub), "%s/qihse_kem_pub.pem", server_dir) > 0);
    assert(snprintf(server_pub, sizeof(server_pub), "%s/qihse_dsa_pub.pem", server_dir) > 0);
    assert(snprintf(client_dsa, sizeof(client_dsa), "%s/qihse_dsa_key.pem", client_dir) > 0);
    assert(snprintf(client_pub, sizeof(client_pub), "%s/qihse_dsa_pub.pem", client_dir) > 0);

    static const char* server_trust[1]; server_trust[0] = client_pub;
    static const char* client_trust[1]; client_trust[0] = server_pub;
    qihse_qkp_config_t server_config = {0};
    server_config.dsa_key_path = server_dsa;
    server_config.kem_key_path = server_kem;
    server_config.kem_pub_path = server_kem_pub;
    server_config.trusted_pubs = server_trust;
    server_config.trusted_count = 1u;
    server_config.node_id = "member-b";
    server_config.require = true;
    qihse_qkp_config_t client_config = {0};
    client_config.dsa_key_path = client_dsa;
    client_config.trusted_pubs = client_trust;
    client_config.trusted_count = 1u;
    client_config.node_id = "member-a";
    client_config.require = true;

    int fds[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);
    server_handshake_t server = {.fd=fds[1], .config=&server_config};
    pthread_t thread;
    assert(pthread_create(&thread, NULL, negotiate_server, &server) == 0);
    qihse_qkp_session_t* client_session = NULL;
    assert(qihse_qkp_client_negotiate(fds[0], &client_config, &client_session) == QIHSE_QKP_SECURE);
    assert(pthread_join(thread, NULL) == 0);
    assert(server.result == QIHSE_QKP_SECURE && server.session);

    qihse_uuid_t member_a, member_b;
    assert(qihse_uuid_from_seed("member-a", 8u, &member_a));
    assert(qihse_uuid_from_seed("member-b", 8u, &member_b));
    qihse_consensus_channel_config_t client_channel = {
        .group_id="sample.group", .local_member=member_a, .peer_member=member_b,
        .peer_node_id="member-b", .peer_dsa_pub_path=server_pub
    };
    qihse_consensus_channel_config_t server_channel = {
        .group_id="sample.group", .local_member=member_b, .peer_member=member_a,
        .peer_node_id="member-a", .peer_dsa_pub_path=client_pub
    };

    qihse_consensus_msg_t message;
    memset(&message, 0, sizeof(message));
    message.type = QIHSE_CONSENSUS_MSG_APPEND;
    snprintf(message.group_id, sizeof(message.group_id), "%s", "sample.group");
    message.from = member_a; message.to = member_b;
    message.term = 2u; message.fencing_epoch = 2u;
    message.u.append.entry_count = 1u;
    message.u.append.entries[0].index = 1u;
    message.u.append.entries[0].term = 2u;
    message.u.append.entries[0].journal_generation = 1u;
    message.u.append.entries[0].type = QIHSE_CONSENSUS_ENTRY_DATA;
    message.u.append.entries[0].classif = 3u;
    message.u.append.entries[0].sci = 8u;
    message.u.append.entries[0].payload_len = 6u;
    memcpy(message.u.append.entries[0].payload, "secret", 6u);
    qihse_consensus_channel_config_t wrong_pin = client_channel;
    wrong_pin.peer_dsa_pub_path = client_pub;
    assert(!qihse_consensus_channel_send(client_session, fds[0], &wrong_pin, op, &message));
    qihse_consensus_channel_config_t wrong_group = client_channel;
    wrong_group.group_id = "different.group";
    assert(!qihse_consensus_channel_send(client_session, fds[0], &wrong_group, op, &message));
    assert(qihse_consensus_channel_send(client_session, fds[0], &client_channel, op, &message));
    qihse_consensus_msg_t decoded;
    memset(&decoded, 0xa5, sizeof(decoded));
    qihse_consensus_msg_t untouched = decoded;
    assert(!qihse_consensus_channel_receive(server.session, fds[1], &server_channel,
                                            analyst, &decoded));
    assert(memcmp(&decoded, &untouched, sizeof(decoded)) == 0);

    /* An authorized unclassified append crosses the exact same pinned channel. */
    message.u.append.entries[0].classif = 0u;
    message.u.append.entries[0].sci = 0u;
    assert(qihse_consensus_channel_send(client_session, fds[0], &client_channel, op, &message));
    assert(qihse_consensus_channel_receive(server.session, fds[1], &server_channel,
                                           analyst, &decoded));
    assert(qihse_uuid_equal(&decoded.from, &member_a));
    assert(qihse_uuid_equal(&decoded.to, &member_b));
    assert(decoded.u.append.entries[0].payload_len == 6u);
    assert(memcmp(decoded.u.append.entries[0].payload, "secret", 6u) == 0);

    qihse_qkp_session_free(client_session);
    qihse_qkp_session_free(server.session);
    close(fds[0]); close(fds[1]);
    assert(qihse_auth_destroy_user(op, qihse_user_get_id(analyst)));
    puts("PASS consensus QKP channel: pinned identities, member binding, and SCI denial");
    return 0;
}
