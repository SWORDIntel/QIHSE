#include "qihse_consensus_blob_channel.h"
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
} handshake_t;

typedef struct {
    qihse_consensus_blob_context_t* blobs;
    qihse_qkp_session_t* session;
    int fd;
    qihse_consensus_channel_config_t* channel;
    qihse_user_t* principal;
    bool result;
    qihse_consensus_entry_t entry;
} receive_t;

static void* negotiate_server(void* opaque) {
    handshake_t* state = opaque;
    state->result = qihse_qkp_server_negotiate(state->fd, state->config,
                                               &state->session);
    return NULL;
}

static void* receive_blob(void* opaque) {
    receive_t* state = opaque;
    state->result = qihse_consensus_blob_channel_receive(state->blobs,
        state->session, state->fd, state->channel, state->principal,
        &state->entry);
    return NULL;
}

static bool run_receive(receive_t* receiver,
                        qihse_consensus_blob_context_t* sender_blobs,
                        qihse_qkp_session_t* client_session, int client_fd,
                        qihse_consensus_channel_config_t* client_channel,
                        qihse_user_t* client_principal,
                        const qihse_consensus_entry_t* entry) {
    pthread_t thread;
    assert(pthread_create(&thread, NULL, receive_blob, receiver) == 0);
    bool sent = qihse_consensus_blob_channel_send(sender_blobs, client_session,
        client_fd, client_channel, client_principal, entry);
    assert(pthread_join(thread, NULL) == 0);
    assert(sent == receiver->result);
    return sent;
}

int main(void) {
    char root[] = "build/test_consensus_blob_channel_XXXXXX";
    assert(mkdtemp(root));
    char data[256], server_dir[256], client_dir[256], blob_a_dir[256], blob_b_dir[256];
    assert(snprintf(data, sizeof(data), "%s/data", root) > 0);
    assert(snprintf(server_dir, sizeof(server_dir), "%s/server", root) > 0);
    assert(snprintf(client_dir, sizeof(client_dir), "%s/client", root) > 0);
    assert(snprintf(blob_a_dir, sizeof(blob_a_dir), "%s/blobs-a", root) > 0);
    assert(snprintf(blob_b_dir, sizeof(blob_b_dir), "%s/blobs-b", root) > 0);
    assert(mkdir(data, 0700) == 0 && mkdir(server_dir, 0700) == 0 &&
           mkdir(client_dir, 0700) == 0);
    assert(setenv("QIHSE_DATA_DIR", data, 1) == 0);
    assert(setenv("QIHSE_FIPS_MODE", "disabled", 1) == 0);
    assert(qihse_pqc_init_providers() == 0);
    assert(qihse_pqc_keygen(server_dir) && qihse_pqc_keygen(client_dir));
    assert(qihse_auth_init());
    assert(qihse_auth_bootstrap_operator("BlobChannelOperator1!"));
    qihse_user_t* operator_user = qihse_auth_get_user(0u);
    qihse_user_t* analyst = qihse_auth_create_user(operator_user, 63002u,
        QIHSE_ROLE_ANALYST, 1u, 0u, "BlobChannelAnalystPass1!", false);
    assert(operator_user && analyst);

    qihse_blob_store_t* blobs_a = qihse_blob_store_create(blob_a_dir);
    qihse_blob_store_t* blobs_b = qihse_blob_store_create(blob_b_dir);
    assert(blobs_a && blobs_b);
    qihse_consensus_blob_context_t ctx_a, ctx_b;
    assert(qihse_consensus_blob_context_init(&ctx_a, blobs_a, operator_user,
                                              "qihse.test.app"));
    assert(qihse_consensus_blob_context_init(&ctx_b, blobs_b, operator_user,
                                              "qihse.test.app"));

    uint8_t transaction[131071];
    for (size_t i = 0; i < sizeof(transaction); i++)
        transaction[i] = (uint8_t)((i * 37u + (i >> 7u)) & 0xffu);
    qihse_consensus_entry_t entry;
    memset(&entry, 0, sizeof(entry));
    entry.journal_generation = 1u;
    entry.hlc.physical_ms = 1800000000000u;
    entry.hlc.logical = 7u;
    entry.classif = 3u;
    entry.sci = 8u;
    entry.type = QIHSE_CONSENSUS_ENTRY_DATA;
    entry.payload_len = QIHSE_CONSENSUS_BLOB_REF_BYTES;
    assert(qihse_consensus_blob_stage_user(&ctx_a, entry.journal_generation,
        entry.classif, entry.sci, transaction, sizeof(transaction), entry.payload));
    assert(qihse_consensus_blob_validate(&ctx_a, &entry));

    char server_dsa[320], server_kem[320], server_kem_pub[320], server_pub[320];
    char client_dsa[320], client_pub[320];
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
    server_config.node_id = "blob-voter-b";
    server_config.require = true;
    qihse_qkp_config_t client_config = {0};
    client_config.dsa_key_path = client_dsa;
    client_config.trusted_pubs = client_trust;
    client_config.trusted_count = 1u;
    client_config.node_id = "blob-voter-a";
    client_config.require = true;

    int fds[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);
    handshake_t server = {.fd=fds[1], .config=&server_config};
    pthread_t thread;
    assert(pthread_create(&thread, NULL, negotiate_server, &server) == 0);
    qihse_qkp_session_t* client_session = NULL;
    assert(qihse_qkp_client_negotiate(fds[0], &client_config, &client_session) == QIHSE_QKP_SECURE);
    assert(pthread_join(thread, NULL) == 0);
    assert(server.result == QIHSE_QKP_SECURE && server.session);

    qihse_uuid_t member_a, member_b;
    assert(qihse_uuid_from_seed("blob-voter-a", 12u, &member_a));
    assert(qihse_uuid_from_seed("blob-voter-b", 12u, &member_b));
    qihse_consensus_channel_config_t client_channel = {
        .group_id="qihse.test.app", .local_member=member_a, .peer_member=member_b,
        .peer_node_id="blob-voter-b", .peer_dsa_pub_path=server_pub
    };
    qihse_consensus_channel_config_t server_channel = {
        .group_id="qihse.test.app", .local_member=member_b, .peer_member=member_a,
        .peer_node_id="blob-voter-a", .peer_dsa_pub_path=client_pub
    };

    uint64_t remote_size = 0u;
    assert(!qihse_blob_size_user(blobs_b, entry.payload + 64u, &remote_size, operator_user));
    receive_t receiver = {.blobs=&ctx_b, .session=server.session, .fd=fds[1],
                          .channel=&server_channel, .principal=analyst};
    assert(!run_receive(&receiver, &ctx_a, client_session, fds[0],
                       &client_channel, operator_user, &entry));
    assert(!qihse_blob_size_user(blobs_b, entry.payload + 64u, &remote_size, operator_user));

    receiver.principal = operator_user;
    assert(run_receive(&receiver, &ctx_a, client_session, fds[0],
                       &client_channel, operator_user, &entry));
    assert(receiver.entry.journal_generation == entry.journal_generation);
    assert(receiver.entry.classif == entry.classif && receiver.entry.sci == entry.sci);
    assert(qihse_consensus_blob_validate(&ctx_b, &receiver.entry));
    assert(qihse_blob_size_user(blobs_b, entry.payload + 64u, &remote_size, operator_user));
    assert(remote_size == sizeof(transaction) + QIHSE_CONSENSUS_BLOB_HEADER_BYTES);

    /* A retry after reconnect is idempotent: the receiver reports HAVE and
     * does not append a second reference to the blob index. */
    int retry_fds[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, retry_fds) == 0);
    handshake_t retry_server = {.fd=retry_fds[1], .config=&server_config};
    pthread_t retry_thread;
    assert(pthread_create(&retry_thread, NULL, negotiate_server,
                          &retry_server) == 0);
    qihse_qkp_session_t* retry_client_session = NULL;
    assert(qihse_qkp_client_negotiate(retry_fds[0], &client_config,
                                     &retry_client_session) == QIHSE_QKP_SECURE);
    assert(pthread_join(retry_thread, NULL) == 0);
    assert(retry_server.result == QIHSE_QKP_SECURE && retry_server.session);
    receiver.session = retry_server.session;
    receiver.fd = retry_fds[1];
    assert(run_receive(&receiver, &ctx_a, retry_client_session, retry_fds[0],
                       &client_channel, operator_user, &entry));
    assert(qihse_blob_size_user(blobs_b, entry.payload + 64u, &remote_size,
                                operator_user));
    assert(remote_size == sizeof(transaction) + QIHSE_CONSENSUS_BLOB_HEADER_BYTES);
    puts("PASS consensus QBR1 channel: pinned QKP transfer, durable import, idempotent HAVE, and SCI denial");

    qihse_qkp_session_free(retry_client_session);
    qihse_qkp_session_free(retry_server.session);
    close(retry_fds[0]); close(retry_fds[1]);
    qihse_qkp_session_free(client_session);
    qihse_qkp_session_free(server.session);
    close(fds[0]); close(fds[1]);
    qihse_blob_store_destroy(blobs_a);
    qihse_blob_store_destroy(blobs_b);
    return 0;
}
