#include "qihse_consensus_mesh.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <openssl/evp.h>
#include <poll.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#define QCM_QUEUE_PER_PEER 128u
#define QCM_RX_QUEUE 512u
#define QCM_TEXT_MAX 512u

typedef struct {
    pthread_mutex_t lock;
    unsigned int refs;
    bool done;
    bool success;
    qihse_consensus_entry_t entry;
} qcm_stage_job_t;

typedef enum {
    QCM_TX_CONSENSUS = 1,
    QCM_TX_STAGE_BLOB = 2
} qcm_tx_kind_t;

typedef struct {
    qcm_tx_kind_t kind;
    union {
        qihse_consensus_msg_t* consensus;
        qcm_stage_job_t* stage;
    } value;
} qcm_tx_item_t;

typedef struct {
    qihse_uuid_t uuid;
    char node_id[QIHSE_QKP_NODE_ID_LEN + 1u];
    char public_key[QCM_TEXT_MAX];
    char ipv4[INET_ADDRSTRLEN];
    uint16_t port;
    bool snapshot_chunks_supported;
    qcm_tx_item_t* tx[QCM_QUEUE_PER_PEER];
    size_t tx_head;
    size_t tx_count;
    int tx_fd;
    int rx_fd;
    int authority_rx_fd;
} qcm_peer_t;

/* Select the oldest queued consensus item when present. Removing an interior
 * item shifts only the logical queue suffix, preserving FIFO within each kind. */
static qcm_tx_item_t* qcm_tx_dequeue(qcm_peer_t* peer) {
    if (!peer || !peer->tx_count) return NULL;
    size_t selected = 0u;
    for (size_t i = 0; i < peer->tx_count; ++i) {
        size_t slot = (peer->tx_head + i) % QCM_QUEUE_PER_PEER;
        if (peer->tx[slot] && peer->tx[slot]->kind == QCM_TX_CONSENSUS) {
            selected = i;
            break;
        }
    }
    size_t slot = (peer->tx_head + selected) % QCM_QUEUE_PER_PEER;
    qcm_tx_item_t* item = peer->tx[slot];
    for (size_t i = selected; i + 1u < peer->tx_count; ++i) {
        size_t dst = (peer->tx_head + i) % QCM_QUEUE_PER_PEER;
        size_t src = (peer->tx_head + i + 1u) % QCM_QUEUE_PER_PEER;
        peer->tx[dst] = peer->tx[src];
    }
    size_t tail = (peer->tx_head + peer->tx_count - 1u) % QCM_QUEUE_PER_PEER;
    peer->tx[tail] = NULL;
    peer->tx_count--;
    return item;
}

#ifdef QIHSE_CONSENSUS_MESH_TESTING
bool qihse_consensus_mesh_test_tx_priority(void) {
    qcm_peer_t peer = {0};
    qcm_tx_item_t items[5] = {
        {.kind = QCM_TX_STAGE_BLOB}, {.kind = QCM_TX_CONSENSUS},
        {.kind = QCM_TX_STAGE_BLOB}, {.kind = QCM_TX_CONSENSUS},
        {.kind = QCM_TX_STAGE_BLOB}
    };
    peer.tx_head = QCM_QUEUE_PER_PEER - 2u;
    for (size_t i = 0; i < 5u; ++i)
        peer.tx[(peer.tx_head + i) % QCM_QUEUE_PER_PEER] = &items[i];
    peer.tx_count = 5u;
    const size_t expected[] = {1u, 3u, 0u, 2u, 4u};
    for (size_t i = 0; i < 5u; ++i)
        if (qcm_tx_dequeue(&peer) != &items[expected[i]]) return false;
    return peer.tx_count == 0u;
}
#endif

typedef struct {
    qihse_consensus_mesh_t* mesh;
    size_t peer_index;
} qcm_tx_arg_t;

struct qihse_consensus_mesh {
    qihse_consensus_config_t consensus_config;
    qihse_qkp_config_t qkp_config;
    char qkp_dsa_key[QCM_TEXT_MAX];
    char qkp_kem_key[QCM_TEXT_MAX];
    char qkp_kem_pub[QCM_TEXT_MAX];
    char qkp_node_id[QIHSE_QKP_NODE_ID_LEN + 1u];
    char listen_ipv4[INET_ADDRSTRLEN];
    uint16_t listen_port;
    size_t peer_count;
    qcm_peer_t peers[QIHSE_CONSENSUS_MESH_MAX_PEERS];
    const char* trusted_key_storage[QIHSE_CONSENSUS_MAX_MEMBERS];
    char trusted_key_paths[QIHSE_CONSENSUS_MAX_MEMBERS][QCM_TEXT_MAX];
    qihse_user_t* principal;
    qihse_consensus_blob_context_t* blob_context;
    qihse_consensus_snapshot_stage_t* snapshot_stage;
    char snapshot_stage_path[QIHSE_CONSENSUS_RECORD_PATH_MAX + 1u];
    uint32_t tick_ms;
    bool authority_proposals_enabled;

    qihse_consensus_t* consensus;
    int listener_fd;
    uint64_t start_ms;
    pthread_t event_thread;
    pthread_t accept_thread;
    pthread_t tx_threads[QIHSE_CONSENSUS_MESH_MAX_PEERS];
    qcm_tx_arg_t tx_args[QIHSE_CONSENSUS_MESH_MAX_PEERS];
    bool event_started;
    bool accept_started;
    bool tx_started[QIHSE_CONSENSUS_MESH_MAX_PEERS];
    bool started;
    volatile int stopping;

    pthread_mutex_t queue_lock;
    pthread_mutex_t proposal_lock;
    pthread_cond_t queue_changed;
    pthread_cond_t rx_changed;
    bool queue_lock_ready;
    bool proposal_lock_ready;
    bool state_lock_ready;
    bool queue_changed_ready;
    bool rx_changed_ready;
    qihse_consensus_msg_t* rx[QCM_RX_QUEUE];
    size_t rx_head;
    size_t rx_count;
    size_t rx_active;
    pthread_mutex_t state_lock;
    uint64_t queue_drops;
#ifdef QIHSE_CONSENSUS_MESH_TESTING
    bool test_hold_append_replies;
    unsigned int test_stage_ack_drops[QIHSE_CONSENSUS_MESH_MAX_PEERS];
    unsigned int test_stage_ack_drops_consumed;
    unsigned int test_snapshot_ack_drops[QIHSE_CONSENSUS_MESH_MAX_PEERS];
    unsigned int test_snapshot_ack_drops_consumed;
#endif
};

#ifdef QIHSE_CONSENSUS_MESH_TESTING
bool qihse_consensus_mesh_test_hold_append_replies(qihse_consensus_mesh_t* mesh, bool hold) {
    if (!mesh) return false;
    __atomic_store_n(&mesh->test_hold_append_replies, hold, __ATOMIC_RELEASE);
    return true;
}

static bool qcm_test_consume_stage_ack_drop(qihse_consensus_mesh_t* mesh,
                                             size_t peer_index) {
    if (!mesh || peer_index >= mesh->peer_count) return false;
    unsigned int pending = __atomic_load_n(
        &mesh->test_stage_ack_drops[peer_index], __ATOMIC_ACQUIRE);
    while (pending) {
        if (__atomic_compare_exchange_n(&mesh->test_stage_ack_drops[peer_index],
                &pending, pending - 1u, false, __ATOMIC_ACQ_REL,
                __ATOMIC_ACQUIRE)) {
            (void)__atomic_fetch_add(&mesh->test_stage_ack_drops_consumed, 1u,
                                     __ATOMIC_RELAXED);
            return true;
        }
    }
    return false;
}

bool qihse_consensus_mesh_test_drop_next_stage_ack(
    qihse_consensus_mesh_t* mesh, size_t peer_index, unsigned int count) {
    if (!mesh || peer_index >= mesh->peer_count || !count) return false;
    (void)__atomic_fetch_add(&mesh->test_stage_ack_drops[peer_index], count,
                             __ATOMIC_RELEASE);
    return true;
}

unsigned int qihse_consensus_mesh_test_stage_ack_drops(
    qihse_consensus_mesh_t* mesh) {
    return mesh ? __atomic_load_n(&mesh->test_stage_ack_drops_consumed,
                                  __ATOMIC_ACQUIRE) : 0u;
}

bool qihse_consensus_mesh_test_drop_next_snapshot_ack(
    qihse_consensus_mesh_t* mesh, size_t peer_index, unsigned int count) {
    if (!mesh || peer_index >= mesh->peer_count || !count) return false;
    (void)__atomic_fetch_add(&mesh->test_snapshot_ack_drops[peer_index], count,
                             __ATOMIC_RELEASE);
    return true;
}

bool qihse_consensus_mesh_test_set_snapshot_ack_drops(
    qihse_consensus_mesh_t* mesh, size_t peer_index, unsigned int count) {
    if (!mesh || peer_index >= mesh->peer_count) return false;
    __atomic_store_n(&mesh->test_snapshot_ack_drops[peer_index], count,
                     __ATOMIC_RELEASE);
    return true;
}

unsigned int qihse_consensus_mesh_test_snapshot_ack_drops(
    qihse_consensus_mesh_t* mesh) {
    return mesh ? __atomic_load_n(&mesh->test_snapshot_ack_drops_consumed,
                                  __ATOMIC_ACQUIRE) : 0u;
}

bool qihse_consensus_mesh_test_set_snapshot_chunks_supported(
    qihse_consensus_mesh_t* mesh, size_t peer_index, bool supported) {
    if (!mesh || peer_index >= mesh->peer_count) return false;
    __atomic_store_n(&mesh->peers[peer_index].snapshot_chunks_supported,
                     supported, __ATOMIC_RELEASE);
    return true;
}

bool qihse_consensus_mesh_test_snapshot_progress(
    qihse_consensus_mesh_t* mesh, const qihse_user_t* principal,
    qihse_consensus_snapshot_stage_progress_t* out) {
    return mesh && mesh->snapshot_stage &&
        qihse_consensus_snapshot_stage_get_progress(mesh->snapshot_stage,
                                                    principal, out);
}

static bool qcm_test_consume_snapshot_ack_drop(qihse_consensus_mesh_t* mesh,
                                               size_t peer_index) {
    if (!mesh || peer_index >= mesh->peer_count) return false;
    unsigned int pending = __atomic_load_n(
        &mesh->test_snapshot_ack_drops[peer_index], __ATOMIC_ACQUIRE);
    while (pending) {
        if (__atomic_compare_exchange_n(&mesh->test_snapshot_ack_drops[peer_index],
                &pending, pending - 1u, false, __ATOMIC_ACQ_REL,
                __ATOMIC_ACQUIRE)) {
            (void)__atomic_fetch_add(&mesh->test_snapshot_ack_drops_consumed, 1u,
                                     __ATOMIC_RELAXED);
            return true;
        }
    }
    return false;
}

#endif

typedef struct {
    qihse_consensus_mesh_t* mesh;
    size_t peer_index;
    int fd;
    qihse_qkp_session_t* session;
} qcm_rx_ctx_t;

static void qcm_stage_release(qcm_stage_job_t* job) {
    if (!job) return;
    unsigned int old = __atomic_fetch_sub(&job->refs, 1u, __ATOMIC_ACQ_REL);
    if (old == 1u) {
        pthread_mutex_destroy(&job->lock);
        free(job);
    }
}

static void qcm_stage_finish(qcm_stage_job_t* job, bool success) {
    if (!job) return;
    pthread_mutex_lock(&job->lock);
    if (!job->done) {
        job->done = true;
        job->success = success;
    }
    pthread_mutex_unlock(&job->lock);
    qcm_stage_release(job); /* queue/worker reference */
}

static bool qcm_stage_state(qcm_stage_job_t* job, bool* done) {
    if (!job) { if (done) *done = true; return false; }
    pthread_mutex_lock(&job->lock);
    bool finished = job->done;
    bool success = job->success;
    pthread_mutex_unlock(&job->lock);
    if (done) *done = finished;
    return success;
}

static void qcm_tx_item_destroy(qcm_tx_item_t* item, bool success) {
    if (!item) return;
    if (item->kind == QCM_TX_CONSENSUS) free(item->value.consensus);
    else if (item->kind == QCM_TX_STAGE_BLOB) qcm_stage_finish(item->value.stage, success);
    free(item);
}

static bool qcm_copy(char* dst, size_t cap, const char* src) {
    if (!dst || cap == 0u || !src || !*src) return false;
    size_t n = strlen(src);
    if (n >= cap) return false;
    memcpy(dst, src, n + 1u);
    return true;
}

static bool qcm_ipv4_allowed(const char* text, struct in_addr* out) {
    if (!text || !out || inet_pton(AF_INET, text, out) != 1) return false;
    uint32_t host = ntohl(out->s_addr);
    return (host >> 24) == 10u || (host >> 20) == 0xAC1u ||
           (host >> 16) == 0xC0A8u || (host >> 24) == 127u;
}

static uint64_t qcm_now_ms(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) return 0u;
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

static bool qcm_stopping(const qihse_consensus_mesh_t* mesh) {
    return __atomic_load_n(&mesh->stopping, __ATOMIC_ACQUIRE) != 0;
}

static void qcm_debug(const char* format, ...) {
    if (!getenv("QIHSE_CONSENSUS_MESH_DEBUG")) return;
    va_list args;
    va_start(args, format);
    fputs("[qihse-consensus-mesh] ", stderr);
    vfprintf(stderr, format, args);
    fputc('\n', stderr);
    va_end(args);
}

static int qcm_peer_index(const qihse_consensus_mesh_t* mesh,
                          const qihse_uuid_t* uuid) {
    for (size_t i = 0; i < mesh->peer_count; i++)
        if (qihse_uuid_equal(&mesh->peers[i].uuid, uuid)) return (int)i;
    return -1;
}

static void qcm_send(void* opaque, const qihse_consensus_msg_t* message) {
    qihse_consensus_mesh_t* mesh = opaque;
    if (!mesh || !message || qcm_stopping(mesh)) return;
    int peer = qcm_peer_index(mesh, &message->to);
    if (peer < 0) return;
    qihse_consensus_msg_t* copy = malloc(sizeof(*copy));
    qcm_tx_item_t* item = calloc(1u, sizeof(*item));
    if (!copy || !item) {
        free(copy); free(item);
        pthread_mutex_lock(&mesh->queue_lock);
        mesh->queue_drops++;
        pthread_mutex_unlock(&mesh->queue_lock);
        return;
    }
    *copy = *message;
    item->kind = QCM_TX_CONSENSUS;
    item->value.consensus = copy;
    pthread_mutex_lock(&mesh->queue_lock);
    qcm_peer_t* p = &mesh->peers[peer];
    if (p->tx_count == QCM_QUEUE_PER_PEER) {
        mesh->queue_drops++;
        free(item); free(copy);
    } else {
        size_t tail = (p->tx_head + p->tx_count) % QCM_QUEUE_PER_PEER;
        p->tx[tail] = item;
        p->tx_count++;
        pthread_cond_broadcast(&mesh->queue_changed);
    }
    pthread_mutex_unlock(&mesh->queue_lock);
}

static qcm_stage_job_t* qcm_stage_enqueue(qihse_consensus_mesh_t* mesh,
                                          size_t peer_index,
                                          const qihse_consensus_entry_t* entry) {
    if (!mesh || !entry || peer_index >= mesh->peer_count) return NULL;
    qcm_stage_job_t* job = calloc(1u, sizeof(*job));
    qcm_tx_item_t* item = calloc(1u, sizeof(*item));
    if (!job || !item || pthread_mutex_init(&job->lock, NULL) != 0) {
        free(job); free(item); return NULL;
    }
    job->refs = 2u; /* caller and queued worker */
    job->entry = *entry;
    item->kind = QCM_TX_STAGE_BLOB;
    item->value.stage = job;
    pthread_mutex_lock(&mesh->queue_lock);
    qcm_peer_t* peer = &mesh->peers[peer_index];
    if (qcm_stopping(mesh) || peer->tx_count == QCM_QUEUE_PER_PEER) {
        pthread_mutex_unlock(&mesh->queue_lock);
        pthread_mutex_destroy(&job->lock);
        free(job); free(item); return NULL;
    }
    size_t tail = (peer->tx_head + peer->tx_count) % QCM_QUEUE_PER_PEER;
    peer->tx[tail] = item;
    peer->tx_count++;
    pthread_cond_broadcast(&mesh->queue_changed);
    pthread_mutex_unlock(&mesh->queue_lock);
    return job;
}

static int qcm_listener_open(const char* address, uint16_t port,
                             uint16_t* out_port) {
    struct in_addr bind_addr;
    if (!qcm_ipv4_allowed(address, &bind_addr)) return -1;
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    int one = 1;
    (void)setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr = bind_addr;
    addr.sin_port = htons(port);
    if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) != 0 || listen(fd, 32) != 0) {
        close(fd); return -1;
    }
    socklen_t len = sizeof(addr);
    if (getsockname(fd, (struct sockaddr*)&addr, &len) != 0) {
        close(fd); return -1;
    }
    if (out_port) *out_port = ntohs(addr.sin_port);
    return fd;
}

static int qcm_connect(const char* address, uint16_t port) {
    struct in_addr peer_addr;
    if (!qcm_ipv4_allowed(address, &peer_addr) || port == 0u) return -1;
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        close(fd); return -1;
    }
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr = peer_addr;
    addr.sin_port = htons(port);
    int rc = connect(fd, (struct sockaddr*)&addr, sizeof(addr));
    if (rc != 0 && errno != EINPROGRESS) { close(fd); return -1; }
    if (rc != 0) {
        struct pollfd pfd = {fd, POLLOUT, 0};
        int ready = poll(&pfd, 1, 1000);
        if (ready <= 0) { if (ready == 0) errno = ETIMEDOUT; close(fd); return -1; }
        int error = 0; socklen_t len = sizeof(error);
        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &len) != 0) {
            close(fd); return -1;
        }
        if (error != 0) { errno = error; close(fd); return -1; }
    }
    if (fcntl(fd, F_SETFL, flags) < 0) { close(fd); return -1; }
    struct timeval timeout = {4, 0};
    (void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    (void)setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    return fd;
}

static qihse_consensus_channel_config_t qcm_channel(
    qihse_consensus_mesh_t* mesh, size_t peer_index) {
    qihse_consensus_channel_config_t channel;
    memset(&channel, 0, sizeof(channel));
    channel.group_id = mesh->consensus_config.group_id;
    memcpy(channel.history_id, mesh->consensus_config.history_id,
           sizeof(channel.history_id));
    channel.writer_epoch = mesh->consensus_config.writer_epoch_floor;
    channel.local_member = mesh->consensus_config.self;
    channel.peer_member = mesh->peers[peer_index].uuid;
    channel.peer_node_id = mesh->peers[peer_index].node_id;
    channel.peer_dsa_pub_path = mesh->peers[peer_index].public_key;
    return channel;
}

static void qcm_rx_done(qcm_rx_ctx_t* ctx) {
    qihse_consensus_mesh_t* mesh = ctx->mesh;
    pthread_mutex_lock(&mesh->queue_lock);
    if (mesh->peers[ctx->peer_index].rx_fd == ctx->fd)
        mesh->peers[ctx->peer_index].rx_fd = -1;
    if (mesh->peers[ctx->peer_index].authority_rx_fd == ctx->fd)
        mesh->peers[ctx->peer_index].authority_rx_fd = -1;
    if (mesh->rx_active) mesh->rx_active--;
    pthread_cond_broadcast(&mesh->rx_changed);
    pthread_mutex_unlock(&mesh->queue_lock);
    if (ctx->session) qihse_qkp_session_free(ctx->session);
    if (ctx->fd >= 0) close(ctx->fd);
    free(ctx);
}

static bool qcm_authority_receive(qcm_rx_ctx_t* ctx, const uint8_t* wire, size_t size);
static bool qcm_range_receive(qcm_rx_ctx_t* ctx, const uint8_t* wire, size_t size);

static void* qcm_rx_main(void* opaque) {
    qcm_rx_ctx_t* ctx = opaque;
    qihse_consensus_mesh_t* mesh = ctx->mesh;
    qihse_consensus_channel_config_t channel = qcm_channel(mesh, ctx->peer_index);
    bool history_hello_seen = channel.writer_epoch == 0u;
    while (!qcm_stopping(mesh)) {
        struct pollfd pfd = {ctx->fd, POLLIN, 0};
        int ready = poll(&pfd, 1, 250);
        if (ready == 0) continue;
        if (ready < 0) { if (errno == EINTR) continue; break; }
        if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) break;
        uint8_t wire[QIHSE_QKP_MAX_PAYLOAD];
        ssize_t received = qihse_qkp_recv_sealed(ctx->session, ctx->fd,
                                                  wire, sizeof(wire));
        if (received <= 0 || (size_t)received > sizeof(wire)) {
            qcm_debug("receive from %s failed", mesh->peers[ctx->peer_index].node_id);
            break;
        }
        if (!history_hello_seen) {
            if (!qihse_consensus_channel_decode_hello(ctx->session, &channel,
                    mesh->principal, wire, (size_t)received)) {
                qcm_debug("history binding from %s rejected",
                          mesh->peers[ctx->peer_index].node_id);
                break;
            }
            history_hello_seen = true;
            continue;
        }
        if ((size_t)received >= 4u && memcmp(wire, "QAF1", 4u) == 0) {
            (void)qcm_authority_receive(ctx, wire, (size_t)received);
            break; /* Dedicated request stream; ordinary ACK stream stays live. */
        }
        if ((size_t)received >= 4u && memcmp(wire, "QRF2", 4u) == 0) {
            (void)qcm_range_receive(ctx, wire, (size_t)received);
            break; /* Range authority forwarding uses a dedicated request stream. */
        }
        if ((size_t)received >= 4u &&
            (memcmp(wire, "QBT1", 4u) == 0 || memcmp(wire, "QBT2", 4u) == 0)) {
            qihse_consensus_entry_t entry;
            if (!mesh->blob_context ||
                !qihse_consensus_blob_channel_receive_prefix(mesh->blob_context,
                    ctx->session, ctx->fd, &channel, mesh->principal,
                    wire, (size_t)received, &entry)) {
                qcm_debug("blob stage from %s rejected", mesh->peers[ctx->peer_index].node_id);
                break;
            }
            continue;
        }
        qihse_consensus_msg_t msg;
        if (!qihse_consensus_channel_decode(ctx->session, &channel,
                mesh->principal, wire, (size_t)received, &msg)) {
            qcm_debug("consensus message from %s rejected", mesh->peers[ctx->peer_index].node_id);
            break;
        }
        /* QCS1 type 7 has no in-band negotiation. Both ends must explicitly
         * provision support until a versioned QKP handshake can authenticate
         * capabilities. Treat a chunk from an unmarked peer like an unknown
         * message, before it can affect term or durable stage state. */
        if (msg.type == QIHSE_CONSENSUS_MSG_SNAPSHOT_CHUNK &&
            !__atomic_load_n(
                &mesh->peers[ctx->peer_index].snapshot_chunks_supported,
                __ATOMIC_ACQUIRE)) {
            qcm_debug("unprovisioned snapshot chunk from %s rejected",
                      mesh->peers[ctx->peer_index].node_id);
            break;
        }
        qihse_consensus_msg_t* copy = malloc(sizeof(*copy));
        if (!copy) break;
        *copy = msg;
        pthread_mutex_lock(&mesh->queue_lock);
        if (mesh->rx_count == QCM_RX_QUEUE) {
            mesh->queue_drops++;
            pthread_mutex_unlock(&mesh->queue_lock);
            free(copy);
            break;
        }
        size_t tail = (mesh->rx_head + mesh->rx_count) % QCM_RX_QUEUE;
        mesh->rx[tail] = copy;
        mesh->rx_count++;
        pthread_cond_broadcast(&mesh->queue_changed);
        pthread_mutex_unlock(&mesh->queue_lock);
    }
    qcm_rx_done(ctx);
    return NULL;
}

static int qcm_find_authenticated_peer(qihse_consensus_mesh_t* mesh,
                                        qihse_qkp_session_t* session) {
    for (size_t i = 0; i < mesh->peer_count; i++)
        if (qihse_qkp_session_is_replication_peer(session,
                mesh->peers[i].node_id, mesh->peers[i].public_key)) return (int)i;
    return -1;
}

static void* qcm_accept_main(void* opaque) {
    qihse_consensus_mesh_t* mesh = opaque;
    while (!qcm_stopping(mesh)) {
        struct pollfd pfd = {mesh->listener_fd, POLLIN, 0};
        int ready = poll(&pfd, 1, 250);
        if (ready == 0) continue;
        if (ready < 0) { if (errno == EINTR) continue; break; }
        if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) break;
        int fd = accept(mesh->listener_fd, NULL, NULL);
        if (fd < 0) { if (errno == EINTR || errno == EAGAIN) continue; break; }
        struct timeval timeout = {4, 0};
        (void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
        (void)setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
        qihse_qkp_session_t* session = NULL;
        if (qihse_qkp_server_negotiate(fd, &mesh->qkp_config, &session) != QIHSE_QKP_SECURE || !session) {
            qcm_debug("inbound QKP handshake rejected");
            if (session) qihse_qkp_session_free(session);
            close(fd); continue;
        }
        int pi = qcm_find_authenticated_peer(mesh, session);
        if (pi < 0) { qcm_debug("inbound QKP signer is not a configured member"); qihse_qkp_session_free(session); close(fd); continue; }
        qcm_rx_ctx_t* ctx = calloc(1u, sizeof(*ctx));
        if (!ctx) { qihse_qkp_session_free(session); close(fd); continue; }
        ctx->mesh = mesh; ctx->peer_index = (size_t)pi; ctx->fd = fd; ctx->session = session;
        pthread_mutex_lock(&mesh->queue_lock);
        if ((mesh->peers[pi].rx_fd >= 0 && mesh->peers[pi].authority_rx_fd >= 0) ||
            qcm_stopping(mesh)) {
            pthread_mutex_unlock(&mesh->queue_lock);
            qihse_qkp_session_free(session); close(fd); free(ctx); continue;
        }
        if (mesh->peers[pi].rx_fd < 0) mesh->peers[pi].rx_fd = fd;
        else mesh->peers[pi].authority_rx_fd = fd;
        mesh->rx_active++;
        pthread_mutex_unlock(&mesh->queue_lock);
        qcm_debug("accepted inbound peer %s", mesh->peers[pi].node_id);
        pthread_t thread;
        if (pthread_create(&thread, NULL, qcm_rx_main, ctx) != 0) {
            qcm_rx_done(ctx); continue;
        }
        pthread_detach(thread);
    }
    return NULL;
}

static void* qcm_tx_main(void* opaque) {
    qcm_tx_arg_t* arg = opaque;
    size_t peer_index = arg->peer_index;
    qihse_consensus_mesh_t* mesh = arg->mesh;
    if (!mesh || peer_index >= mesh->peer_count) return NULL;
    qihse_consensus_channel_config_t channel = qcm_channel(mesh, peer_index);
    while (!qcm_stopping(mesh)) {
        qcm_debug("dial %s at %s:%u", mesh->peers[peer_index].node_id,
                  mesh->peers[peer_index].ipv4, (unsigned)mesh->peers[peer_index].port);
        int fd = qcm_connect(mesh->peers[peer_index].ipv4, mesh->peers[peer_index].port);
        if (fd < 0) {
            qcm_debug("connect to %s failed: %s", mesh->peers[peer_index].node_id, strerror(errno));
            struct timespec pause = {0, 250000000L}; nanosleep(&pause, NULL); continue;
        }
        pthread_mutex_lock(&mesh->queue_lock);
        mesh->peers[peer_index].tx_fd = fd;
        pthread_mutex_unlock(&mesh->queue_lock);
        qihse_qkp_session_t* session = NULL;
        if (qihse_qkp_client_negotiate(fd, &mesh->qkp_config, &session) != QIHSE_QKP_SECURE ||
            !session || !qihse_qkp_client_session_is_replication_peer(session,
                mesh->peers[peer_index].node_id, mesh->peers[peer_index].public_key)) {
            qcm_debug("outbound QKP handshake/pin failed for %s", mesh->peers[peer_index].node_id);
            if (session) qihse_qkp_session_free(session);
            pthread_mutex_lock(&mesh->queue_lock);
            if (mesh->peers[peer_index].tx_fd == fd) mesh->peers[peer_index].tx_fd = -1;
            pthread_mutex_unlock(&mesh->queue_lock);
            close(fd);
            struct timespec pause = {0, 250000000L}; nanosleep(&pause, NULL);
            continue;
        }
        if (channel.writer_epoch != 0u &&
            !qihse_consensus_channel_send_hello(session, fd, &channel,
                                                mesh->principal)) {
            qcm_debug("history binding to %s failed",
                      mesh->peers[peer_index].node_id);
            qihse_qkp_session_free(session);
            pthread_mutex_lock(&mesh->queue_lock);
            if (mesh->peers[peer_index].tx_fd == fd)
                mesh->peers[peer_index].tx_fd = -1;
            pthread_mutex_unlock(&mesh->queue_lock);
            close(fd);
            continue;
        }
        qcm_debug("connected to peer %s", mesh->peers[peer_index].node_id);
        /* A restarted receiver has forgotten its volatile leader identity.
         * Reassert the current leader on every authenticated stream before
         * queued snapshot chunks can arrive; this empty prefix probe is also
         * understood by legacy QCS1 peers. */
        qihse_consensus_msg_t leader_probe;
        memset(&leader_probe, 0, sizeof(leader_probe));
        pthread_mutex_lock(&mesh->state_lock);
        bool probe_is_leader = qihse_consensus_role(mesh->consensus) ==
                               QIHSE_CONSENSUS_LEADER;
        if (probe_is_leader) {
            leader_probe.type = QIHSE_CONSENSUS_MSG_APPEND;
            snprintf(leader_probe.group_id, sizeof(leader_probe.group_id),
                     "%s", mesh->consensus_config.group_id);
            leader_probe.from = mesh->consensus_config.self;
            leader_probe.to = mesh->peers[peer_index].uuid;
            leader_probe.term = qihse_consensus_term(mesh->consensus);
            leader_probe.fencing_epoch =
                qihse_consensus_fencing_epoch(mesh->consensus);
            leader_probe.u.append.leader_commit =
                qihse_consensus_commit_index(mesh->consensus);
        }
        pthread_mutex_unlock(&mesh->state_lock);
        if (probe_is_leader && !qihse_consensus_channel_send(session, fd,
                &channel, mesh->principal, &leader_probe)) {
            qcm_debug("leader-contact probe to %s failed",
                      mesh->peers[peer_index].node_id);
            qihse_qkp_session_free(session);
            pthread_mutex_lock(&mesh->queue_lock);
            if (mesh->peers[peer_index].tx_fd == fd)
                mesh->peers[peer_index].tx_fd = -1;
            pthread_mutex_unlock(&mesh->queue_lock);
            shutdown(fd, SHUT_RDWR);
            close(fd);
            continue;
        }
        while (!qcm_stopping(mesh)) {
            pthread_mutex_lock(&mesh->queue_lock);
            while (!mesh->peers[peer_index].tx_count && !qcm_stopping(mesh)) {
                struct timespec deadline;
                clock_gettime(CLOCK_REALTIME, &deadline);
                deadline.tv_nsec += 200000000L;
                if (deadline.tv_nsec >= 1000000000L) { deadline.tv_sec++; deadline.tv_nsec -= 1000000000L; }
                (void)pthread_cond_timedwait(&mesh->queue_changed, &mesh->queue_lock, &deadline);
            }
            qcm_tx_item_t* item = NULL;
            if (mesh->peers[peer_index].tx_count)
                item = qcm_tx_dequeue(&mesh->peers[peer_index]);
            pthread_mutex_unlock(&mesh->queue_lock);
            if (qcm_stopping(mesh)) { qcm_tx_item_destroy(item, false); break; }
            if (!item) continue;
            bool sent = false;
            if (item->kind == QCM_TX_CONSENSUS && item->value.consensus) {
                qihse_consensus_msg_t* message = item->value.consensus;
                sent = qihse_consensus_channel_send(session, fd, &channel,
                                                     mesh->principal, message);
                if (!sent) qcm_debug("send to %s failed for msg type %d term %llu",
                    mesh->peers[peer_index].node_id, (int)message->type,
                    (unsigned long long)message->term);
            } else if (item->kind == QCM_TX_STAGE_BLOB && item->value.stage) {
                sent = qihse_consensus_blob_channel_send(mesh->blob_context,
                    session, fd, &channel, mesh->principal,
                    &item->value.stage->entry);
#ifdef QIHSE_CONSENSUS_MESH_TESTING
                /* The receive side has durably imported the blob before the
                 * channel returns success. Treating that ACK as lost forces
                 * the next stage attempt onto a fresh QKP session, where the
                 * receiver must answer HAVE for the existing object. */
                if (sent && qcm_test_consume_stage_ack_drop(mesh, peer_index))
                    sent = false;
#endif
                qcm_debug("payload stage to %s %s", mesh->peers[peer_index].node_id,
                          sent ? "acknowledged" : "failed");
            }
            qcm_tx_item_destroy(item, sent);
            if (!sent) break;
        }
        qihse_qkp_session_free(session);
        pthread_mutex_lock(&mesh->queue_lock);
        if (mesh->peers[peer_index].tx_fd == fd) mesh->peers[peer_index].tx_fd = -1;
        pthread_mutex_unlock(&mesh->queue_lock);
        shutdown(fd, SHUT_RDWR); close(fd);
        struct timespec pause = {0, 100000000L}; nanosleep(&pause, NULL);
    }
    return NULL;
}

static void qcm_handle_snapshot_chunk(qihse_consensus_mesh_t* mesh,
                                      const qihse_consensus_msg_t* message);

static void* qcm_event_main(void* opaque) {
    qihse_consensus_mesh_t* mesh = opaque;
    uint32_t tick_ms = mesh->tick_ms ? mesh->tick_ms : 10u;
    while (!qcm_stopping(mesh)) {
        for (size_t n = 0; n < 256u; n++) {
            pthread_mutex_lock(&mesh->queue_lock);
            qihse_consensus_msg_t* message = NULL;
            if (mesh->rx_count) {
                message = mesh->rx[mesh->rx_head]; mesh->rx[mesh->rx_head] = NULL;
                mesh->rx_head = (mesh->rx_head + 1u) % QCM_RX_QUEUE;
                mesh->rx_count--;
            }
            pthread_mutex_unlock(&mesh->queue_lock);
            if (!message) break;
#ifdef QIHSE_CONSENSUS_MESH_TESTING
            if (message->type == QIHSE_CONSENSUS_MSG_APPEND_REPLY &&
                __atomic_load_n(&mesh->test_hold_append_replies, __ATOMIC_ACQUIRE)) {
                free(message); continue;
            }
#endif
            if (message->type == QIHSE_CONSENSUS_MSG_SNAPSHOT_CHUNK) {
                qcm_handle_snapshot_chunk(mesh, message);
            } else {
                pthread_mutex_lock(&mesh->state_lock);
                qihse_consensus_receive(mesh->consensus, message);
                pthread_mutex_unlock(&mesh->state_lock);
            }
            free(message);
        }
        uint64_t now = qcm_now_ms();
        uint64_t elapsed = now >= mesh->start_ms ? now - mesh->start_ms : 0u;
        pthread_mutex_lock(&mesh->state_lock);
        qihse_consensus_tick(mesh->consensus, elapsed);
        pthread_mutex_unlock(&mesh->state_lock);
        struct timespec pause = {(time_t)(tick_ms / 1000u), (long)(tick_ms % 1000u) * 1000000L};
        nanosleep(&pause, NULL);
    }
    return NULL;
}

static bool qcm_snapshot_chunks_supported(void* opaque,
                                          const qihse_uuid_t* peer) {
    qihse_consensus_mesh_t* mesh = opaque;
    int index = mesh && peer ? qcm_peer_index(mesh, peer) : -1;
    return index >= 0 && __atomic_load_n(
        &mesh->peers[index].snapshot_chunks_supported, __ATOMIC_ACQUIRE);
}

static void qcm_handle_snapshot_chunk(qihse_consensus_mesh_t* mesh,
                                      const qihse_consensus_msg_t* message) {
    if (!mesh || !message) return;
    qihse_consensus_msg_t ack;
    memset(&ack, 0, sizeof(ack));
    pthread_mutex_lock(&mesh->state_lock);
    /* Let consensus durably adopt a newer term/fencing floor before staging.
     * The chunk is still ignored by the core state machine; its durable stage
     * and publication are owned by this mesh adapter. */
    qihse_consensus_receive(mesh->consensus, message);
    uint64_t term = qihse_consensus_term(mesh->consensus);
    uint64_t epoch = qihse_consensus_fencing_epoch(mesh->consensus);
    qihse_uuid_t current_leader;
    bool is_current_leader = term == message->term &&
        epoch == message->fencing_epoch &&
        qihse_consensus_role(mesh->consensus) == QIHSE_CONSENSUS_FOLLOWER &&
        qihse_consensus_leader_id(mesh->consensus, &current_leader) &&
        qihse_uuid_equal(&current_leader, &message->from);

    bool accepted = false;
    bool staged = false;
    qihse_consensus_snapshot_stage_progress_t progress = {0};
    if (is_current_leader && mesh->snapshot_stage) {
        qihse_consensus_snapshot_stage_result_t result =
            qihse_consensus_snapshot_stage_accept(mesh->snapshot_stage,
                mesh->principal, message);
        if (result == QIHSE_SNAPSHOT_STAGE_CONFLICT) {
            /* Consensus has durably adopted this authenticated current
             * leader above. Preserve the receiver's synced high-watermark
             * only when the new term/epoch presents the exact same snapshot
             * descriptor. If the new leader has compacted a newer committed
             * prefix, atomically replace only an incomplete stage, then start
             * that descriptor from its first chunk. */
            qihse_consensus_snapshot_stage_result_t rebound =
                qihse_consensus_snapshot_stage_rebind(mesh->snapshot_stage,
                    mesh->principal, message);
            if (rebound == QIHSE_SNAPSHOT_STAGE_OK)
                result = qihse_consensus_snapshot_stage_accept(
                    mesh->snapshot_stage, mesh->principal, message);
            else if (rebound == QIHSE_SNAPSHOT_STAGE_CONFLICT) {
                qihse_consensus_snapshot_stage_result_t replaced =
                    qihse_consensus_snapshot_stage_replace(
                        mesh->snapshot_stage, mesh->principal,
                        &current_leader, message);
                if (replaced == QIHSE_SNAPSHOT_STAGE_OK)
                    result = qihse_consensus_snapshot_stage_accept(
                        mesh->snapshot_stage, mesh->principal, message);
            }
        }
        bool stage_result_ok = result == QIHSE_SNAPSHOT_STAGE_OK ||
                               result == QIHSE_SNAPSHOT_STAGE_DUPLICATE;
        if (stage_result_ok && qihse_consensus_snapshot_stage_get_progress(
                mesh->snapshot_stage, mesh->principal, &progress) &&
            progress.next_entry_index > 0u) {
            staged = true;
            accepted = true;
            if (progress.complete) {
                /* Full digest, continuity, DATA validation, SCI authorization,
                 * and consensus fold are rechecked by publish before swap. */
                accepted = qihse_consensus_snapshot_stage_publish(
                    mesh->snapshot_stage, mesh->principal, mesh->consensus);
            }
        }
        if (!accepted)
            qcm_debug("snapshot chunk rejected from authenticated peer (stage=%s)",
                qihse_consensus_snapshot_stage_result_name(result));
    }

    ack.type = QIHSE_CONSENSUS_MSG_SNAPSHOT_REPLY;
    snprintf(ack.group_id, sizeof(ack.group_id), "%s",
             mesh->consensus_config.group_id);
    ack.from = mesh->consensus_config.self;
    ack.to = message->from;
    ack.term = qihse_consensus_term(mesh->consensus);
    ack.fencing_epoch = qihse_consensus_fencing_epoch(mesh->consensus);
    ack.u.snapshot_reply.success = accepted;
    ack.u.snapshot_reply.match_index = staged && progress.next_entry_index > 0u
        ? progress.next_entry_index - 1u : 0u;
    pthread_mutex_unlock(&mesh->state_lock);

#ifdef QIHSE_CONSENSUS_MESH_TESTING
    int peer_index = qcm_peer_index(mesh, &message->from);
    if (staged && peer_index >= 0 &&
        qcm_test_consume_snapshot_ack_drop(mesh, (size_t)peer_index)) {
        qcm_debug("snapshot chunk ACK intentionally dropped after durable stage");
        return;
    }
#endif
    qcm_send(mesh, &ack);
}

static bool qcm_copy_config(qihse_consensus_mesh_t* mesh,
                            const qihse_consensus_mesh_config_t* cfg) {
    if (!cfg || cfg->peer_count == 0u || cfg->peer_count >= QIHSE_CONSENSUS_MAX_MEMBERS ||
        !cfg->system_principal ||
        !cfg->blob_context || !cfg->blob_context->blobs ||
        !qihse_auth_user_is_active(cfg->system_principal) ||
        qihse_user_get_role(cfg->system_principal) != QIHSE_ROLE_OPERATOR ||
        qihse_user_get_tenant_id(cfg->system_principal) != 0u ||
        !cfg->qkp.require || cfg->qkp.trusted_count != cfg->peer_count ||
        !cfg->qkp.trusted_pubs || !cfg->qkp.node_id ||
        !cfg->listen_wireguard_ipv4 || !cfg->consensus.require_data_validator ||
        cfg->consensus.validate_data != qihse_consensus_blob_validate ||
        cfg->consensus.validate_data_context != cfg->blob_context) return false;
    struct in_addr bind_addr;
    if (!qcm_ipv4_allowed(cfg->listen_wireguard_ipv4, &bind_addr) ||
        !qcm_copy(mesh->listen_ipv4, sizeof(mesh->listen_ipv4), cfg->listen_wireguard_ipv4) ||
        !qcm_copy(mesh->qkp_node_id, sizeof(mesh->qkp_node_id), cfg->qkp.node_id) ||
        !qcm_copy(mesh->qkp_dsa_key, sizeof(mesh->qkp_dsa_key), cfg->qkp.dsa_key_path) ||
        !qcm_copy(mesh->qkp_kem_key, sizeof(mesh->qkp_kem_key), cfg->qkp.kem_key_path) ||
        !qcm_copy(mesh->qkp_kem_pub, sizeof(mesh->qkp_kem_pub), cfg->qkp.kem_pub_path)) return false;
    bool self_found = false;
    for (size_t i = 0; i < cfg->consensus.member_count; i++)
        if (qihse_uuid_equal(&cfg->consensus.members[i], &cfg->consensus.self)) self_found = true;
    if (!self_found && !cfg->consensus.allow_unadmitted_self) return false;
    mesh->consensus_config = cfg->consensus;
    mesh->consensus_config.snapshot_chunks_supported =
        qcm_snapshot_chunks_supported;
    mesh->consensus_config.snapshot_chunks_context = mesh;
    mesh->qkp_config = cfg->qkp;
    mesh->qkp_config.node_id = mesh->qkp_node_id;
    mesh->qkp_config.dsa_key_path = mesh->qkp_dsa_key;
    mesh->qkp_config.kem_key_path = mesh->qkp_kem_key;
    mesh->qkp_config.kem_pub_path = mesh->qkp_kem_pub;
    mesh->peer_count = cfg->peer_count;
    mesh->principal = cfg->system_principal;
    mesh->authority_proposals_enabled = cfg->authority_proposals_enabled;
    mesh->blob_context = cfg->blob_context;
    if (cfg->snapshot_stage_path && *cfg->snapshot_stage_path &&
        !qcm_copy(mesh->snapshot_stage_path,
                  sizeof(mesh->snapshot_stage_path),
                  cfg->snapshot_stage_path)) return false;
    mesh->tick_ms = cfg->tick_interval_ms;
    mesh->listen_port = cfg->listen_port;
    for (size_t i = 0; i < cfg->qkp.trusted_count; i++) {
        if (!qcm_copy(mesh->trusted_key_paths[i], sizeof(mesh->trusted_key_paths[i]), cfg->qkp.trusted_pubs[i])) return false;
        mesh->trusted_key_storage[i] = mesh->trusted_key_paths[i];
    }
    mesh->qkp_config.trusted_pubs = mesh->trusted_key_storage;
    for (size_t i = 0; i < cfg->peer_count; i++) {
        qcm_peer_t* dst = &mesh->peers[i];
        const qihse_consensus_mesh_peer_t* src = &cfg->peers[i];
        if (qihse_uuid_is_nil(&src->member_uuid) || qihse_uuid_equal(&src->member_uuid, &cfg->consensus.self) ||
            !src->port || !qcm_copy(dst->node_id, sizeof(dst->node_id), src->qkp_node_id) ||
            !qcm_copy(dst->public_key, sizeof(dst->public_key), src->dsa_public_key_path) ||
            !qcm_copy(dst->ipv4, sizeof(dst->ipv4), src->wireguard_ipv4) ||
            !qcm_ipv4_allowed(dst->ipv4, &bind_addr)) return false;
        dst->uuid = src->member_uuid;
        dst->port = src->port;
        dst->snapshot_chunks_supported = src->snapshot_chunks_supported;
        dst->tx_fd = -1;
        dst->rx_fd = -1;
        dst->authority_rx_fd = -1;
        for (size_t j = i + 1u; j < cfg->peer_count; j++)
            if (qihse_uuid_equal(&src->member_uuid, &cfg->peers[j].member_uuid)) return false;
        /* Transport provisioning is independent of the durable membership
         * baseline. A staged future member may be dialled before its logged
         * ADD, and a removed member's peer can be omitted after restart. The
         * consensus core still filters voting/append traffic by its folded
         * log membership, never by this transport list. */
    }
    return true;
}

qihse_consensus_mesh_t* qihse_consensus_mesh_create(
    const qihse_consensus_mesh_config_t* config) {
    qihse_consensus_mesh_t* mesh = calloc(1u, sizeof(*mesh));
    if (!mesh) return NULL;
    mesh->listener_fd = -1;
    if (pthread_mutex_init(&mesh->queue_lock, NULL) != 0) { free(mesh); return NULL; }
    mesh->queue_lock_ready = true;
    if (pthread_mutex_init(&mesh->proposal_lock, NULL) != 0) goto init_fail;
    mesh->proposal_lock_ready = true;
    if (pthread_mutex_init(&mesh->state_lock, NULL) != 0) goto init_fail;
    mesh->state_lock_ready = true;
    if (pthread_cond_init(&mesh->queue_changed, NULL) != 0) goto init_fail;
    mesh->queue_changed_ready = true;
    if (pthread_cond_init(&mesh->rx_changed, NULL) != 0) goto init_fail;
    mesh->rx_changed_ready = true;
    if (!qcm_copy_config(mesh, config)) goto init_fail;
    if (mesh->snapshot_stage_path[0]) {
        bool stage_opened = mesh->consensus_config.writer_epoch_floor
            ? qihse_consensus_snapshot_stage_open_bound(
                  mesh->snapshot_stage_path,
                  mesh->consensus_config.group_id,
                  mesh->consensus_config.history_id,
                  mesh->consensus_config.writer_epoch_floor,
                  mesh->principal, mesh->consensus_config.validate_data,
                  mesh->consensus_config.validate_data_context,
                  mesh->consensus_config.require_data_validator,
                  &mesh->snapshot_stage)
            : qihse_consensus_snapshot_stage_open(
                  mesh->snapshot_stage_path,
                  mesh->consensus_config.group_id, mesh->principal,
                  mesh->consensus_config.validate_data,
                  mesh->consensus_config.validate_data_context,
                  mesh->consensus_config.require_data_validator,
                  &mesh->snapshot_stage);
        if (!stage_opened) goto init_fail;
    }
    mesh->consensus = qihse_consensus_open(&mesh->consensus_config, mesh, qcm_send);
    if (!mesh->consensus) goto init_fail;
    return mesh;
init_fail:
    if (mesh->snapshot_stage)
        qihse_consensus_snapshot_stage_close(mesh->snapshot_stage);
    if (mesh->rx_changed_ready) pthread_cond_destroy(&mesh->rx_changed);
    if (mesh->queue_changed_ready) pthread_cond_destroy(&mesh->queue_changed);
    if (mesh->state_lock_ready) pthread_mutex_destroy(&mesh->state_lock);
    if (mesh->proposal_lock_ready) pthread_mutex_destroy(&mesh->proposal_lock);
    if (mesh->queue_lock_ready) pthread_mutex_destroy(&mesh->queue_lock);
    free(mesh);
    return NULL;
}

bool qihse_consensus_mesh_start(qihse_consensus_mesh_t* mesh) {
    if (!mesh || mesh->started || qcm_stopping(mesh)) return false;
    mesh->listener_fd = qcm_listener_open(mesh->listen_ipv4, mesh->listen_port, &mesh->listen_port);
    if (mesh->listener_fd < 0) return false;
    qcm_debug("listening on %s:%u", mesh->listen_ipv4, (unsigned)mesh->listen_port);
    mesh->start_ms = qcm_now_ms();
    if (pthread_create(&mesh->event_thread, NULL, qcm_event_main, mesh) != 0) goto fail;
    mesh->event_started = true;
    if (pthread_create(&mesh->accept_thread, NULL, qcm_accept_main, mesh) != 0) goto fail;
    mesh->accept_started = true;
    for (size_t i = 0; i < mesh->peer_count; i++) {
        /* Every node dials every peer. Each direction has its own QKP stream,
         * so response traffic never shares a socket writer. */
        mesh->tx_args[i].mesh = mesh;
        mesh->tx_args[i].peer_index = i;
        if (pthread_create(&mesh->tx_threads[i], NULL, qcm_tx_main, &mesh->tx_args[i]) != 0) goto fail;
        mesh->tx_started[i] = true;
    }
    mesh->started = true;
    return true;
fail:
    qihse_consensus_mesh_stop(mesh);
    return false;
}

void qihse_consensus_mesh_stop(qihse_consensus_mesh_t* mesh) {
    if (!mesh) return;
    __atomic_store_n(&mesh->stopping, 1, __ATOMIC_RELEASE);
    pthread_mutex_lock(&mesh->queue_lock);
    pthread_cond_broadcast(&mesh->queue_changed);
    if (mesh->listener_fd >= 0) shutdown(mesh->listener_fd, SHUT_RDWR);
    for (size_t i = 0; i < mesh->peer_count; i++) {
        if (mesh->peers[i].tx_fd >= 0) shutdown(mesh->peers[i].tx_fd, SHUT_RDWR);
        if (mesh->peers[i].rx_fd >= 0) shutdown(mesh->peers[i].rx_fd, SHUT_RDWR);
        if (mesh->peers[i].authority_rx_fd >= 0)
            shutdown(mesh->peers[i].authority_rx_fd, SHUT_RDWR);
    }
    pthread_mutex_unlock(&mesh->queue_lock);
    if (mesh->accept_started) { pthread_join(mesh->accept_thread, NULL); mesh->accept_started = false; }
    for (size_t i = 0; i < mesh->peer_count; i++)
        if (mesh->tx_started[i]) { pthread_join(mesh->tx_threads[i], NULL); mesh->tx_started[i] = false; }
    if (mesh->listener_fd >= 0) { close(mesh->listener_fd); mesh->listener_fd = -1; }
    pthread_mutex_lock(&mesh->queue_lock);
    while (mesh->rx_active) pthread_cond_wait(&mesh->rx_changed, &mesh->queue_lock);
    pthread_mutex_unlock(&mesh->queue_lock);
    if (mesh->event_started) { pthread_join(mesh->event_thread, NULL); mesh->event_started = false; }
    mesh->started = false;
}

void qihse_consensus_mesh_destroy(qihse_consensus_mesh_t* mesh) {
    if (!mesh) return;
    qihse_consensus_mesh_stop(mesh);
    if (mesh->consensus) qihse_consensus_close(mesh->consensus);
    if (mesh->snapshot_stage)
        qihse_consensus_snapshot_stage_close(mesh->snapshot_stage);
    for (size_t i = 0; i < mesh->peer_count; i++) {
        for (size_t j = 0; j < mesh->peers[i].tx_count; j++)
            qcm_tx_item_destroy(mesh->peers[i].tx[(mesh->peers[i].tx_head + j) % QCM_QUEUE_PER_PEER], false);
    }
    for (size_t i = 0; i < mesh->rx_count; i++)
        free(mesh->rx[(mesh->rx_head + i) % QCM_RX_QUEUE]);
    if (mesh->rx_changed_ready) pthread_cond_destroy(&mesh->rx_changed);
    if (mesh->queue_changed_ready) pthread_cond_destroy(&mesh->queue_changed);
    if (mesh->state_lock_ready) pthread_mutex_destroy(&mesh->state_lock);
    if (mesh->proposal_lock_ready) pthread_mutex_destroy(&mesh->proposal_lock);
    if (mesh->queue_lock_ready) pthread_mutex_destroy(&mesh->queue_lock);
    free(mesh);
}

uint16_t qihse_consensus_mesh_port(const qihse_consensus_mesh_t* mesh) {
    return mesh ? mesh->listen_port : 0u;
}

bool qihse_consensus_mesh_status(qihse_consensus_mesh_t* mesh,
                                 qihse_consensus_mesh_status_t* out) {
    if (!mesh || !out) return false;
    memset(out, 0, sizeof(*out));
    pthread_mutex_lock(&mesh->state_lock);
    out->role = qihse_consensus_role(mesh->consensus);
    out->term = qihse_consensus_term(mesh->consensus);
    out->commit_index = qihse_consensus_commit_index(mesh->consensus);
    out->last_log_index = qihse_consensus_last_log_index(mesh->consensus);
    out->has_leader = qihse_consensus_leader_id(mesh->consensus,
                                                &out->leader_id);
    /* A freshly elected leader may not yet have installed its own UUID in
     * the core's leader field. Its configured member UUID is authoritative. */
    if (!out->has_leader && out->role == QIHSE_CONSENSUS_LEADER) {
        out->leader_id = mesh->consensus_config.self;
        out->has_leader = true;
    }
    pthread_mutex_unlock(&mesh->state_lock);
    return true;
}

bool qihse_consensus_mesh_history_identity(
    qihse_consensus_mesh_t* mesh, qihse_consensus_mesh_identity_t* out) {
    if (out) memset(out, 0, sizeof(*out));
    if (!mesh || !out) return false;
    pthread_mutex_lock(&mesh->state_lock);
    bool opened = mesh->consensus != NULL;
    if (opened) {
        memcpy(out->group_id, mesh->consensus_config.group_id,
               sizeof(out->group_id));
        memcpy(out->history_id, mesh->consensus_config.history_id,
               sizeof(out->history_id));
        out->writer_epoch_floor = mesh->consensus_config.writer_epoch_floor;
    }
    pthread_mutex_unlock(&mesh->state_lock);
    return opened;
}

bool qihse_consensus_mesh_export_prefix_evidence_user(
    qihse_consensus_mesh_t* mesh, const qihse_user_t* requester,
    uint64_t max_entries, qihse_consensus_mesh_prefix_evidence_t* out) {
    if (out) memset(out, 0, sizeof(*out));
    if (!mesh || !requester || !out ||
        max_entries > QIHSE_MESH_EVIDENCE_MAX_ENTRIES) return false;
    bool active = false;
    uint32_t tenant = QIHSE_TENANT_INVALID;
    qihse_auth_user_active_and_tenant(requester, &active, &tenant);
    if (!active || tenant != QIHSE_TENANT_SYSTEM ||
        qihse_user_get_role(requester) != QIHSE_ROLE_OPERATOR) return false;

    pthread_mutex_lock(&mesh->state_lock);
    uint64_t committed = mesh->consensus
        ? qihse_consensus_commit_index(mesh->consensus) : UINT64_MAX;
    bool ok = committed <= max_entries &&
        qihse_consensus_committed_prefix_sha256(
            mesh->consensus, requester, committed,
            out->committed_prefix_sha256);
    if (ok) {
        memcpy(out->group_id, mesh->consensus_config.group_id,
               sizeof(out->group_id));
        memcpy(out->history_id, mesh->consensus_config.history_id,
               sizeof(out->history_id));
        out->writer_epoch_floor = mesh->consensus_config.writer_epoch_floor;
        out->commit_index = committed;
        out->member_uuid = mesh->consensus_config.self;
        memcpy(out->qkp_node_id, mesh->qkp_node_id,
               sizeof(out->qkp_node_id));
    }
    pthread_mutex_unlock(&mesh->state_lock);
    /* Keep the final liveness check outside state_lock. The core hash must
     * authorize each entry while the state is stable, but no extra auth
     * lookup should extend that nested lock interval. */
    if (ok) {
        qihse_auth_user_active_and_tenant(requester, &active, &tenant);
        ok = active && tenant == QIHSE_TENANT_SYSTEM &&
             qihse_user_get_role(requester) == QIHSE_ROLE_OPERATOR;
    }
    if (!ok) memset(out, 0, sizeof(*out));
    return ok;
}

bool qihse_consensus_mesh_export_prefix_point_user(
    qihse_consensus_mesh_t* mesh, const qihse_user_t* requester,
    uint64_t through_index, qihse_consensus_mesh_prefix_point_t* out) {
    if (out) memset(out, 0, sizeof(*out));
    if (!mesh || !requester || !out ||
        through_index > QIHSE_MESH_EVIDENCE_MAX_ENTRIES) return false;

    bool active = false;
    uint32_t tenant = QIHSE_TENANT_INVALID;
    qihse_auth_user_active_and_tenant(requester, &active, &tenant);
    if (!active || tenant != QIHSE_TENANT_SYSTEM ||
        qihse_user_get_role(requester) != QIHSE_ROLE_OPERATOR) return false;

    pthread_mutex_lock(&mesh->state_lock);
    uint64_t committed = mesh->consensus
        ? qihse_consensus_commit_index(mesh->consensus) : 0u;
    bool ok = mesh->consensus && through_index <= committed &&
        qihse_consensus_committed_prefix_sha256(
            mesh->consensus, requester, through_index,
            out->prefix.committed_prefix_sha256);
    if (ok) {
        memcpy(out->prefix.group_id, mesh->consensus_config.group_id,
               sizeof(out->prefix.group_id));
        memcpy(out->prefix.history_id, mesh->consensus_config.history_id,
               sizeof(out->prefix.history_id));
        out->prefix.writer_epoch_floor =
            mesh->consensus_config.writer_epoch_floor;
        out->prefix.commit_index = through_index;
        out->prefix.member_uuid = mesh->consensus_config.self;
        memcpy(out->prefix.qkp_node_id, mesh->qkp_node_id,
               sizeof(out->prefix.qkp_node_id));
        out->observed_commit_index = committed;
    }
    pthread_mutex_unlock(&mesh->state_lock);

    if (ok) {
        qihse_auth_user_active_and_tenant(requester, &active, &tenant);
        ok = active && tenant == QIHSE_TENANT_SYSTEM &&
             qihse_user_get_role(requester) == QIHSE_ROLE_OPERATOR;
    }
    if (!ok) memset(out, 0, sizeof(*out));
    return ok;
}

qihse_consensus_role_t qihse_consensus_mesh_role(qihse_consensus_mesh_t* mesh) {
    if (!mesh) return QIHSE_CONSENSUS_FOLLOWER;
    pthread_mutex_lock(&mesh->state_lock);
    qihse_consensus_role_t role = qihse_consensus_role(mesh->consensus);
    pthread_mutex_unlock(&mesh->state_lock);
    return role;
}

uint64_t qihse_consensus_mesh_term(qihse_consensus_mesh_t* mesh) {
    if (!mesh) return 0u;
    pthread_mutex_lock(&mesh->state_lock);
    uint64_t term = qihse_consensus_term(mesh->consensus);
    pthread_mutex_unlock(&mesh->state_lock);
    return term;
}

uint64_t qihse_consensus_mesh_commit_index(qihse_consensus_mesh_t* mesh) {
    if (!mesh) return 0u;
    pthread_mutex_lock(&mesh->state_lock);
    uint64_t index = qihse_consensus_commit_index(mesh->consensus);
    pthread_mutex_unlock(&mesh->state_lock);
    return index;
}

bool qihse_consensus_mesh_leader_id(qihse_consensus_mesh_t* mesh,
                                    qihse_uuid_t* out) {
    if (!mesh || !out) return false;
    pthread_mutex_lock(&mesh->state_lock);
    bool ok = qihse_consensus_leader_id(mesh->consensus, out);
    pthread_mutex_unlock(&mesh->state_lock);
    return ok;
}

bool qihse_consensus_mesh_propose_membership(
    qihse_consensus_mesh_t* mesh, const qihse_user_t* principal,
    qihse_consensus_membership_op_t op, const qihse_uuid_t* member,
    uint32_t timeout_ms, uint64_t* out_index) {
    if (out_index) *out_index = 0u;
    if (!mesh || !mesh->started || !principal || !member || !out_index ||
        !timeout_ms || qihse_uuid_is_nil(member) ||
        (op != QIHSE_CONSENSUS_MEMBER_ADD &&
         op != QIHSE_CONSENSUS_MEMBER_REMOVE)) return false;

    bool active = false;
    uint32_t tenant = 0u;
    qihse_auth_user_active_and_tenant(principal, &active, &tenant);
    if (!active || tenant != QIHSE_TENANT_SYSTEM ||
        qihse_user_get_role(principal) != QIHSE_ROLE_OPERATOR) return false;

    pthread_mutex_lock(&mesh->proposal_lock);
    pthread_mutex_lock(&mesh->state_lock);
    qihse_consensus_membership_t membership;
    bool allowed = qihse_consensus_get_membership(mesh->consensus, &membership);
    if (allowed && op == QIHSE_CONSENSUS_MEMBER_REMOVE) {
        /* Do not allow this operational API to turn a two-voter deployment
         * into a one-voter deployment, even though the consensus core permits
         * that configuration. A leader cannot remove itself here. */
        size_t remaining_voters = 0u;
        for (size_t i = 0; i < membership.member_count; i++)
            if (!qihse_uuid_equal(member, &membership.members[i]) &&
                membership.member_roles[i] != QIHSE_CONSENSUS_ROLE_LEARNER)
                remaining_voters++;
        allowed = remaining_voters >= 2u &&
            !qihse_uuid_equal(member, &mesh->consensus_config.self);
    } else if (allowed && op == QIHSE_CONSENSUS_MEMBER_ADD) {
        /* The mesh cannot dial an unprovisioned peer. Transport identity and
         * trust must exist on every node before the logged addition. */
        allowed = qcm_peer_index(mesh, member) >= 0;
    }
    if (allowed) allowed = qihse_consensus_propose_membership(
        mesh->consensus, principal, op, member);
    uint64_t index = allowed ? qihse_consensus_last_log_index(mesh->consensus) : 0u;
    uint64_t term = allowed ? qihse_consensus_term(mesh->consensus) : 0u;
    uint64_t generation = allowed ?
        qihse_consensus_last_journal_generation(mesh->consensus) : 0u;
    pthread_mutex_unlock(&mesh->state_lock);
    if (!allowed) {
        pthread_mutex_unlock(&mesh->proposal_lock);
        return false;
    }

    *out_index = index;
    const uint64_t deadline = qcm_now_ms() + timeout_ms;
    bool committed = false;
    do {
        if (qcm_stopping(mesh)) break;
        pthread_mutex_lock(&mesh->state_lock);
        if (qihse_consensus_commit_index(mesh->consensus) >= index) {
            qihse_consensus_entry_t entry;
            size_t count = 0u;
            committed = qihse_consensus_read_committed_exact(
                mesh->consensus, principal, index, &entry, 1u, &count) &&
                count == 1u && entry.index == index && entry.term == term &&
                entry.journal_generation == generation &&
                entry.type == (op == QIHSE_CONSENSUS_MEMBER_ADD
                    ? QIHSE_CONSENSUS_ENTRY_CONFIG_ADD
                    : QIHSE_CONSENSUS_ENTRY_CONFIG_REMOVE) &&
                entry.payload_len == QIHSE_UUID_BYTES &&
                memcmp(entry.payload, member->bytes, QIHSE_UUID_BYTES) == 0;
            pthread_mutex_unlock(&mesh->state_lock);
            break; /* An overwritten entry at this index is not success. */
        }
        pthread_mutex_unlock(&mesh->state_lock);
        struct timespec pause = {0, 5000000L};
        nanosleep(&pause, NULL);
    } while (qcm_now_ms() < deadline);
    pthread_mutex_unlock(&mesh->proposal_lock);
    return committed;
}

static bool qcm_mesh_reserved_record(const void *payload, size_t payload_len) {
  if (!payload || payload_len < 4u)
    return false;
  static const char *const reserved[] = {"QCA3", "QRG1", "QRR1",
                                         "QRF1", "QRB1", "QBR1"};
  for (size_t i = 0; i < sizeof(reserved) / sizeof(reserved[0]); ++i)
    if (memcmp(payload, reserved[i], 4u) == 0)
      return true;
  return false;
}

static bool qcm_mesh_propose_locked(qihse_consensus_mesh_t* mesh,
                                    const qihse_user_t* principal,
                                    uint64_t generation, qihse_hlc_t hlc,
                                    uint16_t classification, uint16_t sci,
                                    const void* payload, size_t payload_len,
                                    uint32_t timeout_ms, uint64_t* out_index) {
    if (!mesh || !mesh->started || !principal || !out_index || !timeout_ms) return false;
    *out_index = 0u;
    pthread_mutex_lock(&mesh->state_lock);
    bool accepted = qihse_consensus_propose(mesh->consensus, principal,
        generation, hlc, classification, sci, payload, payload_len);
    uint64_t index = accepted ? qihse_consensus_last_log_index(mesh->consensus) : 0u;
    pthread_mutex_unlock(&mesh->state_lock);
    if (!accepted) return false;
    *out_index = index;
    const uint64_t deadline = qcm_now_ms() + timeout_ms;
    do {
        if (qcm_stopping(mesh)) return false;
        if (qihse_consensus_mesh_commit_index(mesh) >= index) return true;
        struct timespec pause = {0, 5000000L}; nanosleep(&pause, NULL);
    } while (qcm_now_ms() < deadline);
    return qihse_consensus_mesh_commit_index(mesh) >= index;
}

bool qihse_consensus_mesh_propose(qihse_consensus_mesh_t* mesh,
                                  const qihse_user_t* principal,
                                  uint64_t generation, qihse_hlc_t hlc,
                                  uint16_t classification, uint16_t sci,
                                  const void* payload, size_t payload_len,
                                  uint32_t timeout_ms, uint64_t* out_index) {
    if (!mesh || !out_index || qcm_mesh_reserved_record(payload, payload_len)) return false;
    pthread_mutex_lock(&mesh->proposal_lock);
    bool ok = qcm_mesh_propose_locked(mesh, principal, generation, hlc,
        classification, sci, payload, payload_len, timeout_ms, out_index);
    pthread_mutex_unlock(&mesh->proposal_lock);
    return ok;
}

static bool qcm_mesh_propose_transaction_locked(
    qihse_consensus_mesh_t* mesh, const qihse_user_t* principal,
    uint64_t generation, qihse_hlc_t hlc, uint16_t classification,
    uint16_t sci, const void* transaction, size_t transaction_len,
    uint32_t stage_timeout_ms, uint32_t commit_timeout_ms, uint64_t* out_index) {
    if (!mesh || !mesh->started || !principal || !stage_timeout_ms ||
        !commit_timeout_ms || !out_index || !transaction || transaction_len == 0u ||
        !qihse_auth_user_is_active(principal) ||
        !qihse_auth_can_access((qihse_user_t*)principal, classification, sci)) return false;
    qihse_consensus_membership_t membership;
    uint16_t peer_weight[QIHSE_CONSENSUS_MESH_MAX_PEERS] = {0};
    uint64_t self_weight = 0u, available_remote_weight = 0u;
    pthread_mutex_lock(&mesh->state_lock);
    bool have_membership = qihse_consensus_get_membership(
        mesh->consensus, &membership);
    pthread_mutex_unlock(&mesh->state_lock);
    if (!have_membership || membership.joint_active ||
        membership.pending_config_index) return false;
    for (size_t j = 0; j < membership.member_count; j++) {
        if (membership.member_roles[j] == QIHSE_CONSENSUS_ROLE_LEARNER)
            continue;
        /* A zero role weight is the legacy encoding for a weight-one voter. */
        uint16_t weight = membership.member_weights[j]
            ? membership.member_weights[j] : 1u;
        if (qihse_uuid_equal(&membership.members[j],
                             &mesh->consensus_config.self)) {
            self_weight = weight;
            continue;
        }
        int peer = qcm_peer_index(mesh, &membership.members[j]);
        if (peer >= 0) {
            peer_weight[peer] = weight;
            available_remote_weight += peer_weight[peer];
        }
    }
    if (!self_weight || membership.majority_weight <= self_weight) return false;
    uint64_t remote_required = membership.majority_weight - self_weight;
    if (available_remote_weight < remote_required) return false;

    qihse_consensus_entry_t entry;
    memset(&entry, 0, sizeof(entry));
    entry.journal_generation = generation;
    entry.hlc = hlc;
    entry.classif = classification;
    entry.sci = sci;
    entry.type = QIHSE_CONSENSUS_ENTRY_DATA;
    entry.payload_len = QIHSE_CONSENSUS_BLOB_REF_BYTES;
    if (!qihse_consensus_blob_stage_user(mesh->blob_context, generation,
            classification, sci, transaction, transaction_len, entry.payload) ||
        !qihse_consensus_blob_validate(mesh->blob_context, &entry)) return false;

    qcm_stage_job_t* jobs[QIHSE_CONSENSUS_MESH_MAX_PEERS] = {0};
    bool staged_peer[QIHSE_CONSENSUS_MESH_MAX_PEERS] = {false};
    uint64_t deadline = qcm_now_ms() + stage_timeout_ms;
    uint64_t staged = 0u;
    while (staged < remote_required && qcm_now_ms() < deadline &&
           !qcm_stopping(mesh)) {
        for (size_t i = 0; i < mesh->peer_count; i++) {
            if (!peer_weight[i] || staged_peer[i]) continue;
            if (jobs[i]) {
                bool done = false;
                bool success = qcm_stage_state(jobs[i], &done);
                if (!done) continue;
                qcm_stage_release(jobs[i]);
                jobs[i] = NULL;
                if (success) {
                    staged_peer[i] = true;
                    staged += peer_weight[i];
                    continue;
                }
            }
            /* A transient disconnect, lost acknowledgement, or full peer
             * queue can fail one transfer without exhausting the proposal's
             * staging budget. Re-enqueue only after the previous job finishes;
             * QBR1's content-addressed validation makes duplicate delivery safe. */
            jobs[i] = qcm_stage_enqueue(mesh, i, &entry);
        }
        if (staged >= remote_required) break;
        struct timespec pause = {0, 5000000L}; nanosleep(&pause, NULL);
    }
    for (size_t i = 0; i < mesh->peer_count; i++)
        qcm_stage_release(jobs[i]);
    if (staged < remote_required || qcm_stopping(mesh)) return false;

    return qcm_mesh_propose_locked(mesh, principal, generation, hlc,
        classification, sci, entry.payload, entry.payload_len,
        commit_timeout_ms, out_index);
}

bool qihse_consensus_mesh_propose_transaction(
    qihse_consensus_mesh_t* mesh, const qihse_user_t* principal,
    uint64_t generation, qihse_hlc_t hlc, uint16_t classification,
    uint16_t sci, const void* transaction, size_t transaction_len,
    uint32_t stage_timeout_ms, uint32_t commit_timeout_ms, uint64_t* out_index) {
    if (qcm_mesh_reserved_record(transaction, transaction_len)) {
        if (out_index) *out_index = 0u;
        return false;
    }

    if (!mesh || !out_index) return false;
    pthread_mutex_lock(&mesh->proposal_lock);
    bool ok = qcm_mesh_propose_transaction_locked(mesh, principal, generation,
        hlc, classification, sci, transaction, transaction_len,
        stage_timeout_ms, commit_timeout_ms, out_index);
    pthread_mutex_unlock(&mesh->proposal_lock);
    return ok;
}

bool qihse_consensus_mesh_propose_transaction_auto_generation(
    qihse_consensus_mesh_t* mesh, const qihse_user_t* principal,
    qihse_hlc_t hlc, uint16_t classification, uint16_t sci,
    const void* transaction, size_t transaction_len,
    uint32_t stage_timeout_ms, uint32_t commit_timeout_ms,
    uint64_t* out_generation, uint64_t* out_index) {
    if (qcm_mesh_reserved_record(transaction, transaction_len)) {
        if (out_index) *out_index = 0u;
        return false;
    }

    if (out_generation) *out_generation = 0u;
    if (out_index) *out_index = 0u;
    if (!mesh || !out_generation || !out_index) return false;
    pthread_mutex_lock(&mesh->proposal_lock);
    pthread_mutex_lock(&mesh->state_lock);
    uint64_t previous = qihse_consensus_last_journal_generation(mesh->consensus);
    pthread_mutex_unlock(&mesh->state_lock);
    if (previous == UINT64_MAX) {
        pthread_mutex_unlock(&mesh->proposal_lock);
        return false;
    }
    uint64_t generation = previous + 1u;
    *out_generation = generation;
    bool ok = qcm_mesh_propose_transaction_locked(mesh, principal, generation,
        hlc, classification, sci, transaction, transaction_len,
        stage_timeout_ms, commit_timeout_ms, out_index);
    pthread_mutex_unlock(&mesh->proposal_lock);
    return ok;
}

bool qihse_consensus_mesh_propose_transaction_if_generation(
    qihse_consensus_mesh_t* mesh, const qihse_user_t* principal,
    uint64_t expected_generation, qihse_hlc_t hlc,
    uint16_t classification, uint16_t sci,
    const void* transaction, size_t transaction_len,
    uint32_t stage_timeout_ms, uint32_t commit_timeout_ms,
    uint64_t* out_generation, uint64_t* out_index) {
    if (qcm_mesh_reserved_record(transaction, transaction_len)) {
        if (out_index) *out_index = 0u;
        return false;
    }

    if (out_generation) *out_generation = 0u;
    if (out_index) *out_index = 0u;
    if (!mesh || !out_generation || !out_index) return false;
    pthread_mutex_lock(&mesh->proposal_lock);
    pthread_mutex_lock(&mesh->state_lock);
    uint64_t current = qihse_consensus_last_journal_generation(mesh->consensus);
    pthread_mutex_unlock(&mesh->state_lock);
    if (current != expected_generation || current == UINT64_MAX) {
        pthread_mutex_unlock(&mesh->proposal_lock);
        return false;
    }
    uint64_t generation = current + 1u;
    *out_generation = generation;
    bool ok = qcm_mesh_propose_transaction_locked(mesh, principal, generation,
        hlc, classification, sci, transaction, transaction_len,
        stage_timeout_ms, commit_timeout_ms, out_index);
    pthread_mutex_unlock(&mesh->proposal_lock);
    return ok;
}

bool qihse_consensus_mesh_read_committed(qihse_consensus_mesh_t* mesh,
                                         const qihse_user_t* principal,
                                         uint64_t from_index,
                                         qihse_consensus_entry_t* out_entries,
                                         size_t out_cap, size_t* out_count) {
    uint64_t ignored_commit_index = 0u;
    return qihse_consensus_mesh_read_committed_page(mesh, principal,
        from_index, out_entries, out_cap, out_count, &ignored_commit_index);
}

bool qihse_consensus_mesh_read_committed_page(
    qihse_consensus_mesh_t* mesh, const qihse_user_t* principal,
    uint64_t from_index, qihse_consensus_entry_t* out_entries,
    size_t out_cap, size_t* out_count, uint64_t* out_commit_index) {
    if (out_commit_index) *out_commit_index = 0u;
    if (!mesh || !out_commit_index) return false;
    pthread_mutex_lock(&mesh->state_lock);
    bool ok = qihse_consensus_read_committed_exact(mesh->consensus, principal,
        from_index, out_entries, out_cap, out_count);
    if (ok) *out_commit_index = qihse_consensus_commit_index(mesh->consensus);
    pthread_mutex_unlock(&mesh->state_lock);
    return ok;
}

/* QCF1 decisions are control metadata, not an arbitrary log-write proxy.
 * Canonical SHA-256 commitments fit the consensus core's 128-byte payload. */
#define QCM_AUTHORITY_INPUT 164u
#define QCM_AUTHORITY_RECORD 108u
#define QCM_AUTHORITY_WIRE 276u

static bool qcm_authority_operator(const qihse_user_t* user) {
    return user && qihse_auth_user_is_active(user) &&
        qihse_user_get_role(user) == QIHSE_ROLE_OPERATOR &&
        qihse_user_get_tenant_id(user) == QIHSE_TENANT_SYSTEM;
}

static bool qcm_sha256(const void* bytes, size_t size, uint8_t out[32]) {
    unsigned int len = 0u;
    return EVP_Digest(bytes, size, out, &len, EVP_sha256(), NULL) == 1 && len == 32u;
}

static void qcm_auth_put64(uint8_t* p, uint64_t n) {
    for (size_t i = 0; i < 8u; ++i) p[7u-i] = (uint8_t)(n >> (i*8u));
}
static uint64_t qcm_auth_get64(const uint8_t* p) {
    uint64_t n = 0u;
    for (size_t i = 0; i < 8u; ++i) n = (n << 8u) | p[i];
    return n;
}

static bool qcm_authority_record(const void* payload, size_t len,
                                  uint8_t record[QCM_AUTHORITY_RECORD]) {
    const uint8_t* p = payload;
    if (!p || len != QCM_AUTHORITY_INPUT || memcmp(p, "QCF1", 4u)) return false;
    for (size_t column = 0; column < 3u; ++column) {
        bool ended = false;
        const uint8_t* id = p + 4u + column*40u;
        if (!id[0]) return false;
        for (size_t i = 0; i < 40u; ++i) {
            if (!id[i]) ended = true;
            else if (ended || id[i] < 33u || id[i] > 126u) return false;
        }
    }
    if (!memcmp(p+4u, p+44u, 40u) || !memcmp(p+4u, p+84u, 40u) ||
        !memcmp(p+44u, p+84u, 40u)) return false;
    for (size_t i = 124u; i < 156u; ++i)
        if (!((p[i] >= '0' && p[i] <= '9') || (p[i] >= 'a' && p[i] <= 'f')))
            return false;
    uint8_t identity[72];
    memcpy(identity, p+4u, 40u); memcpy(identity+40u, p+124u, 32u);
    memcpy(record, "QCA3", 4u);
    memcpy(record+100u, p+156u, 8u);
    return qcm_sha256(identity, sizeof(identity), record+4u) &&
        qcm_sha256(p, len, record+36u) && qcm_sha256(p, 156u, record+68u);
}

static bool qcm_authority_exact_locked(qihse_consensus_mesh_t* mesh,
        const qihse_user_t* principal, uint64_t index, const uint8_t* record) {
    uint8_t bytes[QCM_AUTHORITY_RECORD];
    size_t len = 0u;
    return qihse_consensus_blob_read_committed_transaction_user(mesh->blob_context,
        mesh->consensus, (qihse_user_t*)principal, index, bytes, sizeof(bytes), &len) &&
        len == sizeof(bytes) && !memcmp(bytes, record, sizeof(bytes));
}

static bool qcm_authority_local(qihse_consensus_mesh_t* mesh,
        const qihse_user_t* principal, const uint8_t* record,
        uint32_t timeout_ms, uint64_t* out_index) {
    bool ok = false;
    uint64_t deadline = qcm_now_ms() + timeout_ms;
    while (pthread_mutex_trylock(&mesh->proposal_lock) != 0) {
        if (qcm_stopping(mesh) || qcm_now_ms() >= deadline) return false;
        struct timespec pause = {0, 1000000L}; nanosleep(&pause, NULL);
    }
    pthread_mutex_lock(&mesh->state_lock);
    uint64_t committed = qihse_consensus_commit_index(mesh->consensus);
    uint64_t last = qihse_consensus_last_log_index(mesh->consensus);
    uint64_t generation = qihse_consensus_last_journal_generation(mesh->consensus);
    if (!qcm_authority_operator(principal) ||
        qihse_consensus_role(mesh->consensus) != QIHSE_CONSENSUS_LEADER ||
        last > QIHSE_MESH_EVIDENCE_MAX_ENTRIES ||
        generation == UINT64_MAX) goto unlock_state;
    /* Include inherited uncommitted intents before selecting a winner.
     * A current-term duplicate can commit an exact inherited decision. */
    uint64_t existing_index = 0u;
    for (uint64_t i = 1u; i <= last; ++i) {
        qihse_consensus_entry_t entry;
        if (!qihse_consensus_read_durable_entry_user(mesh->consensus, principal,
                i, &entry) || entry.index != i) goto unlock_state;
        if (entry.type != QIHSE_CONSENSUS_ENTRY_DATA ||
            entry.payload_len != QIHSE_CONSENSUS_BLOB_REF_BYTES ||
            memcmp(entry.payload, "QBR1", 4u) ||
            qcm_auth_get64(entry.payload+112u) !=
                QIHSE_CONSENSUS_BLOB_HEADER_BYTES+QCM_AUTHORITY_RECORD) continue;
        uint8_t existing[QCM_AUTHORITY_RECORD];
        size_t len = 0u;
        if (!qihse_consensus_blob_read_durable_transaction_user(mesh->blob_context,
                mesh->consensus, (qihse_user_t*)principal, i, existing,
                sizeof(existing), &len) || len != sizeof(existing)) goto unlock_state;
        if (memcmp(existing, "QCA3", 4u) || memcmp(existing+4u, record+4u, 32u)) continue;
        if (entry.classif != 0u || entry.sci != 0u ||
            memcmp(existing+68u, record+68u, 32u) ||
            qcm_auth_get64(existing+100u) > qcm_auth_get64(record+100u)) goto unlock_state;
        if (!memcmp(existing, record, QCM_AUTHORITY_RECORD) && !existing_index)
            existing_index = i;
    }
    if (existing_index && existing_index <= committed) {
        *out_index = existing_index; ok = true; goto unlock_state;
    }
    pthread_mutex_unlock(&mesh->state_lock);
    qihse_hlc_t hlc = {0};
    hlc.physical_ms = qcm_now_ms();
    uint64_t now = qcm_now_ms();
    uint32_t half = now < deadline ? (uint32_t)((deadline-now)/2u) : 0u;
    if (half) ok = qcm_mesh_propose_transaction_locked(mesh, principal, generation+1u, hlc,
        0u, 0u, record, QCM_AUTHORITY_RECORD, half, half, out_index);
    if (ok) {
        pthread_mutex_lock(&mesh->state_lock);
        ok = qcm_authority_operator(principal) &&
            qcm_authority_exact_locked(mesh, principal, *out_index, record);
        pthread_mutex_unlock(&mesh->state_lock);
    }
    pthread_mutex_unlock(&mesh->proposal_lock);
    return ok;
unlock_state:
    pthread_mutex_unlock(&mesh->state_lock);
    pthread_mutex_unlock(&mesh->proposal_lock);
    return ok;
}

static bool qcm_authority_voter(qihse_consensus_mesh_t* mesh,
                                 const qihse_uuid_t* uuid) {
    qihse_consensus_membership_t membership;
    bool allowed = false;
    pthread_mutex_lock(&mesh->state_lock);
    if (qihse_consensus_get_membership(mesh->consensus, &membership) &&
        !membership.joint_active && !membership.pending_config_index) {
        for (size_t i = 0; i < membership.member_count; ++i)
            if (qihse_uuid_equal(uuid, &membership.members[i]) &&
                membership.member_roles[i] != QIHSE_CONSENSUS_ROLE_LEARNER)
                allowed = true;
    }
    pthread_mutex_unlock(&mesh->state_lock);
    return allowed;
}

static bool qcm_authority_receive(qcm_rx_ctx_t* ctx, const uint8_t* wire,
                                    size_t size) {
    qihse_consensus_mesh_t* mesh = ctx->mesh;
    uint8_t group_hash[32], record[QCM_AUTHORITY_RECORD], reply[13] = {'Q','A','R','1'};
    if (!mesh->authority_proposals_enabled || !mesh->consensus_config.writer_epoch_floor ||
        !qcm_authority_operator(mesh->principal) || size != QCM_AUTHORITY_WIRE ||
        memcmp(wire, "QAF1", 4u) ||
        memcmp(wire+4u, mesh->consensus_config.history_id, 32u) ||
        qcm_auth_get64(wire+36u) != mesh->consensus_config.writer_epoch_floor ||
        !qcm_sha256(mesh->consensus_config.group_id,
            strlen(mesh->consensus_config.group_id), group_hash) ||
        memcmp(wire+44u, group_hash, 32u) ||
        memcmp(wire+76u, mesh->peers[ctx->peer_index].uuid.bytes, 16u) ||
        memcmp(wire+92u, mesh->consensus_config.self.bytes, 16u) ||
        !qcm_authority_voter(mesh, &mesh->peers[ctx->peer_index].uuid) ||
        !qcm_authority_record(wire+112u, QCM_AUTHORITY_INPUT, record)) return false;
    uint32_t timeout = ((uint32_t)wire[108]<<24u) | ((uint32_t)wire[109]<<16u) |
        ((uint32_t)wire[110]<<8u) | wire[111];
    if (!timeout || timeout > 30000u) return false;
    uint64_t index = 0u;
    reply[4] = qcm_authority_local(mesh, mesh->principal, record, timeout, &index);
    qcm_auth_put64(reply+5u, index);
    return qihse_qkp_send_sealed(ctx->session, ctx->fd, reply, sizeof(reply));
}

/* Shutdown, rather than close, the live descriptor on deadline. Joining
 * before its close prevents a timeout from touching a reused descriptor. */
typedef struct { int socket_fd, cancel_fd; uint64_t deadline; } qcm_authority_guard_t;
static void* qcm_authority_deadline(void* opaque) {
    qcm_authority_guard_t* guard = opaque;
    for (;;) {
        uint64_t now = qcm_now_ms();
        if (now >= guard->deadline) { shutdown(guard->socket_fd, SHUT_RDWR); break; }
        struct pollfd pfd = {guard->cancel_fd, POLLIN, 0};
        int ready = poll(&pfd, 1, (int)(guard->deadline-now));
        if (ready > 0) break;
        if (ready < 0 && errno != EINTR) break;
    }
    return NULL;
}

bool qihse_consensus_mesh_propose_authority(qihse_consensus_mesh_t* mesh,
        const qihse_user_t* principal, const void* payload, size_t payload_len,
        uint32_t timeout_ms, uint64_t* out_index) {
    if (out_index) *out_index = 0u;
    uint8_t record[QCM_AUTHORITY_RECORD];
    if (!mesh || !mesh->started || !out_index || !timeout_ms || timeout_ms > 30000u ||
        !mesh->authority_proposals_enabled || !mesh->consensus_config.writer_epoch_floor ||
        !qcm_authority_operator(principal) ||
        !qcm_authority_record(payload, payload_len, record) ||
        !qcm_authority_voter(mesh, &mesh->consensus_config.self)) return false;
    uint64_t deadline = qcm_now_ms()+timeout_ms;
    qihse_uuid_t leader;
    pthread_mutex_lock(&mesh->state_lock);
    bool local = qihse_consensus_role(mesh->consensus) == QIHSE_CONSENSUS_LEADER;
    bool known = qihse_consensus_leader_id(mesh->consensus, &leader);
    pthread_mutex_unlock(&mesh->state_lock);
    if (local) return qcm_authority_local(mesh, principal, record, timeout_ms, out_index);
    int peer = known ? qcm_peer_index(mesh, &leader) : -1;
    if (peer < 0 || !qcm_authority_voter(mesh, &leader)) return false;
    int fd = qcm_connect(mesh->peers[peer].ipv4, mesh->peers[peer].port);
    if (fd < 0) return false;
    int cancel[2];
    if (pipe(cancel) != 0) { close(fd); return false; }
    qcm_authority_guard_t guard = {fd, cancel[0], deadline};
    pthread_t guard_thread;
    if (pthread_create(&guard_thread, NULL, qcm_authority_deadline, &guard) != 0) {
        close(cancel[0]); close(cancel[1]); close(fd); return false;
    }
    struct timeval timeout = {(time_t)(timeout_ms/1000u), (suseconds_t)((timeout_ms%1000u)*1000u)};
    (void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    (void)setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    qihse_qkp_session_t* session = NULL;
    bool ok = qihse_qkp_client_negotiate(fd, &mesh->qkp_config, &session) == QIHSE_QKP_SECURE &&
        session && qihse_qkp_client_session_is_replication_peer(session,
            mesh->peers[peer].node_id, mesh->peers[peer].public_key);
    qihse_consensus_channel_config_t channel = qcm_channel(mesh, (size_t)peer);
    uint8_t wire[QCM_AUTHORITY_WIRE] = {'Q','A','F','1'};
    memcpy(wire+4u, mesh->consensus_config.history_id, 32u);
    qcm_auth_put64(wire+36u, mesh->consensus_config.writer_epoch_floor);
    ok = ok && qcm_sha256(mesh->consensus_config.group_id,
        strlen(mesh->consensus_config.group_id), wire+44u);
    memcpy(wire+76u, mesh->consensus_config.self.bytes, 16u);
    memcpy(wire+92u, leader.bytes, 16u);
    uint64_t now = qcm_now_ms();
    uint32_t remaining = now < deadline ? (uint32_t)(deadline-now) : 0u;
    if (!remaining) ok = false;
    wire[108] = (uint8_t)(remaining>>24u); wire[109] = (uint8_t)(remaining>>16u);
    wire[110] = (uint8_t)(remaining>>8u); wire[111] = (uint8_t)remaining;
    memcpy(wire+112u, payload, payload_len);
    ok = ok && qcm_authority_operator(principal) &&
        qihse_consensus_channel_send_hello(session, fd, &channel, principal) &&
        qihse_qkp_send_sealed(session, fd, wire, sizeof(wire));
    uint8_t reply[13];
    if (ok) ok = qihse_qkp_recv_sealed(session, fd, reply, sizeof(reply)) == (ssize_t)sizeof(reply) &&
        !memcmp(reply, "QAR1", 4u) && reply[4] == 1u;
    uint64_t index = ok ? qcm_auth_get64(reply+5u) : 0u;
    close(cancel[1]);
    (void)pthread_join(guard_thread, NULL);
    close(cancel[0]);
    if (session)
      qihse_qkp_session_free(session);
    close(fd);
    if (!ok || !index)
      return false;
    *out_index = index;
    do {
      pthread_mutex_lock(&mesh->state_lock);
      ok = qcm_authority_operator(principal) &&
           qcm_authority_exact_locked(mesh, principal, index, record);
      pthread_mutex_unlock(&mesh->state_lock);
      if (ok)
        return true;
      if (qcm_stopping(mesh))
        return false;
      struct timespec pause = {0, 5000000L};
      nanosleep(&pause, NULL);
    } while (qcm_now_ms() < deadline);
    return false;
}

/* Range authority uses ordinary quorum-staged QBR1 transactions. The records
 * below are byte codecs (never native C layouts) so they remain portable. */
#define QCM_RANGE_SLOT_WIRE (2u + 41u + 65u + 65u + 8u)
#define QCM_RANGE_REQUEST_WIRE                                                 \
  (1u + 65u + 41u + 65u + 65u + 41u + 65u + 65u + 41u + 65u + 33u + 33u + 8u + \
   QIHSE_CONSENSUS_RANGE_BITMAP_BYTES + 32u)
#define QCM_RANGE_GENESIS_WIRE                                                 \
  (4u + QIHSE_CONSENSUS_RANGE_SLOT_COUNT * QCM_RANGE_SLOT_WIRE)
#define QCM_RANGE_RESERVE_WIRE (4u + QCM_RANGE_REQUEST_WIRE + 8u)
#define QCM_RANGE_TERMINAL_WIRE (4u + 8u + 32u + 32u + 32u)

typedef struct {
  qihse_consensus_range_request_t request;
  qihse_consensus_range_grant_t grant;
  bool committed;
  bool terminal;
  bool finalized;
  bool pending_terminal;
  bool pending_finalized;
  uint64_t pending_terminal_index;
  uint8_t pending_evidence_digest[32];
  qihse_consensus_range_decision_t decision;
  size_t active_prev; /* index + 1 in range_state.active_head/tail */
  size_t active_next;
  uint64_t transfer_hash;
  uint64_t reserve_hash;
} qcm_range_pending_t;

typedef struct {
  qihse_consensus_range_slot_t *slots;
  qcm_range_pending_t *pending;
  size_t pending_count;
  size_t pending_cap;
  size_t *transfer_index; /* open-addressed pending index + 1 */
  size_t *reserve_index;  /* open-addressed pending index + 1 */
  size_t index_cap;
  size_t *active_by_slot; /* pending index + 1; only nonterminal intents */
  size_t active_head;     /* pending index + 1, in durable-log order */
  size_t active_tail;
  bool initialized;
  uint64_t genesis_index;
  uint8_t genesis_digest[32];
  uint64_t last_index;
} qcm_range_state_t;

static bool qcm_range_operator(const qihse_user_t *user) {
  return qcm_authority_operator(user);
}

static bool qcm_range_mesh_valid(const qihse_consensus_mesh_t *mesh) {
  if (!mesh || !mesh->started || !mesh->consensus_config.writer_epoch_floor ||
      !mesh->consensus_config.group_id[0])
    return false;
  uint8_t nonzero = 0;
  for (size_t i = 0; i < sizeof(mesh->consensus_config.history_id); ++i)
    nonzero |= mesh->consensus_config.history_id[i];
  return nonzero != 0;
}

static bool qcm_range_lower_hex(const char *text, size_t length) {
  if (!text || strlen(text) != length)
    return false;
  for (size_t i = 0; i < length; ++i)
    if (!((text[i] >= '0' && text[i] <= '9') ||
          (text[i] >= 'a' && text[i] <= 'f')))
      return false;
  return true;
}

static void qcm_range_put16(uint8_t *p, uint16_t v) {
  p[0] = (uint8_t)(v >> 8u);
  p[1] = (uint8_t)v;
}
static uint16_t qcm_range_get16(const uint8_t *p) {
  return (uint16_t)(((uint16_t)p[0] << 8u) | p[1]);
}
static void qcm_range_put64(uint8_t *p, uint64_t v) { qcm_auth_put64(p, v); }

static bool qcm_range_text(const char *s, size_t width, bool allow_empty) {
  size_t n = strnlen(s, width);
  if (n == width || (!allow_empty && !n))
    return false;
  for (size_t i = 0; i < n; ++i)
    if ((unsigned char)s[i] < 33u || (unsigned char)s[i] > 126u)
      return false;
  return true;
}

static void qcm_range_put_text(uint8_t **p, const char *s, size_t width) {
  size_t n = strnlen(s, width);
  memset(*p, 0, width);
  memcpy(*p, s, n);
  *p += width;
}
static bool qcm_range_get_text(const uint8_t **p, char *out, size_t width,
                               bool allow_empty) {
  const uint8_t *src = *p;
  const uint8_t *z = memchr(src, 0, width);
  if (!z || (!allow_empty && z == src))
    return false;
  size_t n = (size_t)(z - src);
  for (size_t i = 0; i < n; ++i)
    if (src[i] < 33u || src[i] > 126u)
      return false;
  memcpy(out, src, n);
  out[n] = 0;
  *p += width;
  return true;
}

static void qcm_range_encode_request(const qihse_consensus_range_request_t *r,
                                     uint8_t *out) {
  uint8_t *p = out;
  *p++ = (uint8_t)r->op;
  qcm_range_put_text(&p, r->transfer_id, 65);
  qcm_range_put_text(&p, r->source_topology_id, 41);
  qcm_range_put_text(&p, r->source_qkp_id, 65);
  qcm_range_put_text(&p, r->source_group_id, 65);
  qcm_range_put_text(&p, r->target_topology_id, 41);
  qcm_range_put_text(&p, r->target_qkp_id, 65);
  qcm_range_put_text(&p, r->target_group_id, 65);
  qcm_range_put_text(&p, r->successor_topology_id, 41);
  qcm_range_put_text(&p, r->successor_qkp_id, 65);
  qcm_range_put_text(&p, r->source_generation, 33);
  qcm_range_put_text(&p, r->target_generation, 33);
  qcm_range_put64(p, r->durable_cursor);
  p += 8;
  memcpy(p, r->slots, sizeof(r->slots));
  p += sizeof(r->slots);
  memcpy(p, r->expected_state_digest, 32);
}

static bool qcm_range_decode_request(const uint8_t *p, size_t len,
                                     qihse_consensus_range_request_t *r) {
  if (!p || !r || len != QCM_RANGE_REQUEST_WIRE)
    return false;
  memset(r, 0, sizeof(*r));
  r->op = (qihse_consensus_range_op_t)*p++;
  if (r->op != QIHSE_RANGE_OP_TRANSFER && r->op != QIHSE_RANGE_OP_PROMOTION)
    return false;
  if (!qcm_range_get_text(&p, r->transfer_id, 65, false) ||
      !qcm_range_get_text(&p, r->source_topology_id, 41, false) ||
      !qcm_range_get_text(&p, r->source_qkp_id, 65, false) ||
      !qcm_range_get_text(&p, r->source_group_id, 65, false) ||
      !qcm_range_get_text(&p, r->target_topology_id, 41, false) ||
      !qcm_range_get_text(&p, r->target_qkp_id, 65, false) ||
      !qcm_range_get_text(&p, r->target_group_id, 65, false) ||
      !qcm_range_get_text(&p, r->successor_topology_id, 41, true) ||
      !qcm_range_get_text(&p, r->successor_qkp_id, 65, true) ||
      !qcm_range_get_text(&p, r->source_generation, 33, false) ||
      !qcm_range_get_text(&p, r->target_generation, 33, false))
    return false;
  if (!qcm_range_lower_hex(r->source_generation, 32) ||
      !qcm_range_lower_hex(r->target_generation, 32) ||
      !qcm_range_lower_hex(r->source_group_id, 64) ||
      !qcm_range_lower_hex(r->target_group_id, 64))
    return false;
  r->durable_cursor = qcm_auth_get64(p);
  p += 8;
  memcpy(r->slots, p, sizeof(r->slots));
  p += sizeof(r->slots);
  memcpy(r->expected_state_digest, p, 32);
  if (!memcmp(r->slots, (uint8_t[QIHSE_CONSENSUS_RANGE_BITMAP_BYTES]){0},
              sizeof(r->slots)))
    return false;
  bool promotion = r->op == QIHSE_RANGE_OP_PROMOTION;
  bool has_successor_topology = r->successor_topology_id[0] != '\0';
  bool has_successor_qkp = r->successor_qkp_id[0] != '\0';
  if (has_successor_topology != has_successor_qkp ||
      (promotion && !has_successor_topology))
    return false;
  if (!strcmp(r->successor_topology_id, r->target_topology_id) ||
      !strcmp(r->successor_qkp_id, r->target_qkp_id))
    return false;
  if (promotion && strcmp(r->source_group_id, r->target_group_id))
    return false;
  return true;
}

static bool qcm_range_digest(const void *data, size_t n, uint8_t out[32]) {
  return qcm_sha256(data, n, out);
}

static uint64_t qcm_range_hash_id(const char *id) {
  uint64_t h = UINT64_C(14695981039346656037);
  for (const unsigned char *p = (const unsigned char *)id; *p; ++p) {
    h ^= *p;
    h *= UINT64_C(1099511628211);
  }
  return h ? h : 1u;
}

static uint64_t qcm_range_hash_u64(uint64_t v) {
  v ^= v >> 30u;
  v *= UINT64_C(0xbf58476d1ce4e5b9);
  v ^= v >> 27u;
  v *= UINT64_C(0x94d049bb133111eb);
  v ^= v >> 31u;
  return v ? v : 1u;
}

static bool qcm_range_selected(const uint8_t *bitmap, uint16_t slot);

static bool qcm_range_index_insert(size_t *table, size_t cap,
                                  const qcm_range_state_t *s, size_t index,
                                  bool by_transfer) {
  const qcm_range_pending_t *p = &s->pending[index];
  uint64_t hash = by_transfer ? p->transfer_hash : p->reserve_hash;
  size_t slot = (size_t)hash & (cap - 1u);
  while (table[slot]) {
    size_t existing = table[slot] - 1u;
    if (by_transfer ? !strcmp(s->pending[existing].request.transfer_id,
                              p->request.transfer_id)
                    : s->pending[existing].grant.reserve_index ==
                          p->grant.reserve_index)
      return false;
    slot = (slot + 1u) & (cap - 1u);
  }
  table[slot] = index + 1u;
  return true;
}

static bool qcm_range_index_grow(qcm_range_state_t *s, size_t required) {
  size_t cap = s->index_cap ? s->index_cap : 32u;
  while (required >= cap - cap / 3u) {
    if (cap > SIZE_MAX / 2u)
      return false;
    cap *= 2u;
  }
  if (cap == s->index_cap)
    return true;
  if (cap > SIZE_MAX / sizeof(size_t))
    return false;
  size_t *transfer = calloc(cap, sizeof(*transfer));
  size_t *reserve = calloc(cap, sizeof(*reserve));
  if (!transfer || !reserve) {
    free(transfer);
    free(reserve);
    return false;
  }
  for (size_t i = 0; i < s->pending_count; ++i)
    if (!qcm_range_index_insert(transfer, cap, s, i, true) ||
        !qcm_range_index_insert(reserve, cap, s, i, false)) {
      free(transfer);
      free(reserve);
      return false;
    }
  free(s->transfer_index);
  free(s->reserve_index);
  s->transfer_index = transfer;
  s->reserve_index = reserve;
  s->index_cap = cap;
  return true;
}

static size_t qcm_range_find_transfer(const qcm_range_state_t *s,
                                      const char *transfer_id) {
  if (!s->index_cap || !s->transfer_index)
    return SIZE_MAX;
  uint64_t hash = qcm_range_hash_id(transfer_id);
  size_t slot = (size_t)hash & (s->index_cap - 1u);
  while (s->transfer_index[slot]) {
    size_t index = s->transfer_index[slot] - 1u;
    if (s->pending[index].transfer_hash == hash &&
        !strcmp(s->pending[index].request.transfer_id, transfer_id))
      return index;
    slot = (slot + 1u) & (s->index_cap - 1u);
  }
  return SIZE_MAX;
}

static size_t qcm_range_find_reserve(const qcm_range_state_t *s,
                                     uint64_t reserve_index) {
  if (!s->index_cap || !s->reserve_index)
    return SIZE_MAX;
  uint64_t hash = qcm_range_hash_u64(reserve_index);
  size_t slot = (size_t)hash & (s->index_cap - 1u);
  while (s->reserve_index[slot]) {
    size_t index = s->reserve_index[slot] - 1u;
    if (s->pending[index].reserve_hash == hash &&
        s->pending[index].grant.reserve_index == reserve_index)
      return index;
    slot = (slot + 1u) & (s->index_cap - 1u);
  }
  return SIZE_MAX;
}

static void qcm_range_active_add(qcm_range_state_t *s, size_t index) {
  qcm_range_pending_t *p = &s->pending[index];
  p->active_prev = s->active_tail;
  p->active_next = 0u;
  if (s->active_tail)
    s->pending[s->active_tail - 1u].active_next = index + 1u;
  else
    s->active_head = index + 1u;
  s->active_tail = index + 1u;
  for (uint16_t slot = 0; slot < QIHSE_CONSENSUS_RANGE_SLOT_COUNT; ++slot)
    if (qcm_range_selected(p->request.slots, slot))
      s->active_by_slot[slot] = index + 1u;
}

static void qcm_range_active_remove(qcm_range_state_t *s, size_t index) {
  qcm_range_pending_t *p = &s->pending[index];
  if (p->active_prev)
    s->pending[p->active_prev - 1u].active_next = p->active_next;
  else
    s->active_head = p->active_next;
  if (p->active_next)
    s->pending[p->active_next - 1u].active_prev = p->active_prev;
  else
    s->active_tail = p->active_prev;
  for (uint16_t slot = 0; slot < QIHSE_CONSENSUS_RANGE_SLOT_COUNT; ++slot)
    if (qcm_range_selected(p->request.slots, slot) &&
        s->active_by_slot[slot] == index + 1u)
      s->active_by_slot[slot] = 0u;
  p->active_prev = 0u;
  p->active_next = 0u;
}

static bool qcm_range_append_pending(qcm_range_state_t *s,
                                     const qcm_range_pending_t *p) {
  if (s->pending_count == SIZE_MAX ||
      !qcm_range_index_grow(s, s->pending_count + 1u))
    return false;
  if (s->pending_count == s->pending_cap) {
    size_t cap = s->pending_cap ? s->pending_cap * 2u : 16u;
    if (cap <= s->pending_count || cap > SIZE_MAX / sizeof(*s->pending))
      return false;
    qcm_range_pending_t *n = realloc(s->pending, cap * sizeof(*n));
    if (!n)
      return false;
    s->pending = n;
    s->pending_cap = cap;
  }
  size_t index = s->pending_count;
  s->pending[index] = *p;
  s->pending[index].transfer_hash =
      qcm_range_hash_id(s->pending[index].request.transfer_id);
  s->pending[index].reserve_hash =
      qcm_range_hash_u64(s->pending[index].grant.reserve_index);
  if (!qcm_range_index_insert(s->transfer_index, s->index_cap, s, index, true) ||
      !qcm_range_index_insert(s->reserve_index, s->index_cap, s, index, false))
    return false;
  s->pending_count++;
  qcm_range_active_add(s, index);
  return true;
}

static bool qcm_range_get_transaction(qihse_consensus_mesh_t *m,
                                      const qihse_user_t *u, uint64_t index,
                                      bool durable, uint8_t **out,
                                      size_t *out_len) {
  qihse_consensus_entry_t e;
  memset(&e, 0, sizeof(e));
  size_t count = 0;
  bool ok = durable
                ? qihse_consensus_read_durable_entry_user(
                      m->consensus, (qihse_user_t *)u, index, &e)
                : qihse_consensus_read_committed_exact(
                      m->consensus, (qihse_user_t *)u, index, &e, 1, &count);
  if (!ok || e.index != index || e.type != QIHSE_CONSENSUS_ENTRY_DATA ||
      e.payload_len != QIHSE_CONSENSUS_BLOB_REF_BYTES ||
      memcmp(e.payload, "QBR1", 4u))
    return false;
  uint64_t cap = qcm_auth_get64(e.payload + 112u);
  if (cap < QIHSE_CONSENSUS_BLOB_HEADER_BYTES || cap > QIHSE_BLOB_MAX_SIZE)
    return false;
  size_t n = (size_t)cap - QIHSE_CONSENSUS_BLOB_HEADER_BYTES;
  uint8_t *b = malloc(n ? n : 1u);
  if (!b)
    return false;
  size_t got = 0;
  ok = durable ? qihse_consensus_blob_read_durable_transaction_user(
                     m->blob_context, m->consensus, (qihse_user_t *)u, index, b,
                     n, &got)
               : qihse_consensus_blob_read_committed_transaction_user(
                     m->blob_context, m->consensus, (qihse_user_t *)u, index, b,
                     n, &got);
  if (!ok || got != n) {
    free(b);
    return false;
  }
  *out = b;
  *out_len = n;
  return true;
}

static bool qcm_range_slot_valid(const qihse_consensus_range_slot_t *s,
                                 uint16_t i) {
  return s && s->slot == i &&
         qcm_range_text(s->owner_topology_id, sizeof(s->owner_topology_id),
                        true) &&
         qcm_range_text(s->owner_qkp_id, sizeof(s->owner_qkp_id), true) &&
         qcm_range_text(s->group_id, sizeof(s->group_id), true) &&
         (!s->group_id[0] || qcm_range_lower_hex(s->group_id, 64)) &&
         ((s->owner_topology_id[0] && s->owner_qkp_id[0] && s->group_id[0]) ||
          (!s->owner_topology_id[0] && !s->owner_qkp_id[0] && !s->group_id[0]));
}

static void qcm_range_encode_slot(const qihse_consensus_range_slot_t *s,
                                  uint8_t *out) {
  uint8_t *p = out;
  qcm_range_put16(p, s->slot);
  p += 2;
  qcm_range_put_text(&p, s->owner_topology_id, 41);
  qcm_range_put_text(&p, s->owner_qkp_id, 65);
  qcm_range_put_text(&p, s->group_id, 65);
  qcm_range_put64(p, s->epoch);
}
static bool qcm_range_decode_slot(const uint8_t *b,
                                  qihse_consensus_range_slot_t *s, uint16_t i) {
  const uint8_t *p = b;
  memset(s, 0, sizeof(*s));
  s->slot = qcm_range_get16(p);
  p += 2;
  return qcm_range_get_text(&p, s->owner_topology_id, 41, true) &&
         qcm_range_get_text(&p, s->owner_qkp_id, 65, true) &&
         qcm_range_get_text(&p, s->group_id, 65, true) &&
         ((s->epoch = qcm_auth_get64(p)), qcm_range_slot_valid(s, i));
}

static bool qcm_range_selected(const uint8_t *bitmap, uint16_t slot) {
  return (bitmap[slot / 8u] & (uint8_t)(1u << (slot % 8u))) != 0;
}
static bool qcm_range_any(const uint8_t *bitmap) {
  for (size_t i = 0; i < QIHSE_CONSENSUS_RANGE_BITMAP_BYTES; i++)
    if (bitmap[i])
      return true;
  return false;
}
static bool qcm_range_overlap(const uint8_t *a, const uint8_t *b) {
  for (size_t i = 0; i < QIHSE_CONSENSUS_RANGE_BITMAP_BYTES; i++)
    if (a[i] & b[i])
      return true;
  return false;
}

static bool qcm_range_digest_state(const qcm_range_state_t *s,
                                   const uint8_t *bitmap, uint8_t out[32]) {
  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  if (!ctx)
    return false;
  bool ok = EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) == 1;
  static const uint8_t tag[] = "QIHSE-RANGE-STATE-1";
  ok = ok && EVP_DigestUpdate(ctx, tag, sizeof(tag)) == 1;
  uint8_t wire[QCM_RANGE_SLOT_WIRE];
  for (uint16_t i = 0; ok && i < QIHSE_CONSENSUS_RANGE_SLOT_COUNT; i++)
    if (qcm_range_selected(bitmap, i)) {
      qcm_range_encode_slot(&s->slots[i], wire);
      ok = EVP_DigestUpdate(ctx, wire, sizeof(wire)) == 1;
    }
  for (size_t link = s->active_head; ok && link;
       link = s->pending[link - 1u].active_next) {
    const qcm_range_pending_t *pending = &s->pending[link - 1u];
    if (qcm_range_overlap(bitmap, pending->request.slots)) {
      uint8_t id[32];
      uint8_t req[QCM_RANGE_REQUEST_WIRE];
      qcm_range_encode_request(&pending->request, req);
      ok = qcm_range_digest(req, sizeof(req), id) &&
           EVP_DigestUpdate(ctx, "P", 1) == 1 &&
           EVP_DigestUpdate(ctx, id, sizeof(id)) == 1;
    }
  }
  unsigned int n = 0;
  if (ok)
    ok = EVP_DigestFinal_ex(ctx, out, &n) == 1 && n == 32;
  EVP_MD_CTX_free(ctx);
  return ok;
}

/* Replay committed state and durable uncommitted intent together. An intent
 * in the durable tail blocks conflicting reservations because a later
 * current-term append can commit that inherited prefix. */
static bool qcm_range_replay_locked(qihse_consensus_mesh_t *m,
                                    const qihse_user_t *u, qcm_range_state_t *s,
                                    uint64_t *commit_out) {
  memset(s, 0, sizeof(*s));
  s->slots = calloc(QIHSE_CONSENSUS_RANGE_SLOT_COUNT, sizeof(*s->slots));
  s->active_by_slot = calloc(QIHSE_CONSENSUS_RANGE_SLOT_COUNT,
                             sizeof(*s->active_by_slot));
  if (!s->slots || !s->active_by_slot) {
    free(s->slots);
    free(s->active_by_slot);
    memset(s, 0, sizeof(*s));
    return false;
  }
  uint64_t commit = qihse_consensus_commit_index(m->consensus);
  uint64_t last = qihse_consensus_last_log_index(m->consensus);
  if (commit_out)
    *commit_out = commit;
  for (uint64_t i = 1; i <= last; i++) {
    uint8_t *b = NULL;
    size_t n = 0;
    bool committed = i <= commit;
    qihse_consensus_entry_t e;
    memset(&e, 0, sizeof(e));
    if (!qihse_consensus_read_durable_entry_user(m->consensus,
                                                 (qihse_user_t *)u, i, &e) ||
        e.index != i)
      goto fail;
    if (e.type != QIHSE_CONSENSUS_ENTRY_DATA ||
        e.payload_len != QIHSE_CONSENSUS_BLOB_REF_BYTES ||
        memcmp(e.payload, "QBR1", 4))
      continue;
    uint64_t blob_len = qcm_auth_get64(e.payload + 112u);
    if (blob_len !=
            QIHSE_CONSENSUS_BLOB_HEADER_BYTES + QCM_RANGE_GENESIS_WIRE &&
        blob_len !=
            QIHSE_CONSENSUS_BLOB_HEADER_BYTES + QCM_RANGE_RESERVE_WIRE &&
        blob_len != QIHSE_CONSENSUS_BLOB_HEADER_BYTES + QCM_RANGE_TERMINAL_WIRE)
      continue;
    if (!qcm_range_get_transaction(m, u, i, !committed, &b, &n))
      goto fail;
    if (n >= 4 && !memcmp(b, "QRG1", 4)) {
      uint8_t gd[32];
      if (n != QCM_RANGE_GENESIS_WIRE || !qcm_range_digest(b, n, gd)) {
        free(b);
        goto fail;
      }
      if (s->initialized) {
        if (memcmp(gd, s->genesis_digest, 32)) {
          free(b);
          goto fail;
        }
      } else {
        for (uint16_t k = 0; k < QIHSE_CONSENSUS_RANGE_SLOT_COUNT; k++)
          if (!qcm_range_decode_slot(b + 4u + (size_t)k * QCM_RANGE_SLOT_WIRE,
                                     &s->slots[k], k)) {
            free(b);
            goto fail;
          }
        s->initialized = true;
        s->genesis_index = i;
        memcpy(s->genesis_digest, gd, 32);
      }
    } else if (n == QCM_RANGE_RESERVE_WIRE && !memcmp(b, "QRR1", 4)) {
      if (!s->initialized) {
        free(b);
        goto fail;
      }
      qcm_range_pending_t p;
      memset(&p, 0, sizeof(p));
      if (!qcm_range_decode_request(b + 4, QCM_RANGE_REQUEST_WIRE,
                                    &p.request)) {
        free(b);
        goto fail;
      }
      p.grant.reserve_index = i;
      p.grant.grant_epoch = qcm_auth_get64(b + 4u + QCM_RANGE_REQUEST_WIRE);
      p.committed = committed;
      if (!qcm_range_digest(b, QCM_RANGE_RESERVE_WIRE,
                            p.grant.reserve_digest)) {
        free(b);
        goto fail;
      }
      bool bad = false;
      size_t prior_index = qcm_range_find_transfer(s, p.request.transfer_id);
      if (prior_index != SIZE_MAX) {
        qcm_range_pending_t *old = &s->pending[prior_index];
        uint8_t x[QCM_RANGE_REQUEST_WIRE], y[QCM_RANGE_REQUEST_WIRE];
        qcm_range_encode_request(&old->request, x);
        qcm_range_encode_request(&p.request, y);
        if (memcmp(x, y, sizeof(x)))
          bad = true;
        else { /* exact retries share the first grant and its commit state */
          old->committed = old->committed || committed;
          if (old->grant.reserve_index < i)
            p = *old;
        }
      } else {
        for (uint16_t slot = 0; slot < QIHSE_CONSENSUS_RANGE_SLOT_COUNT; ++slot)
          if (qcm_range_selected(p.request.slots, slot) &&
              s->active_by_slot[slot]) {
            bad = true;
            break;
          }
      }
      if (bad) {
        free(b);
        goto fail;
      }
      if (prior_index == SIZE_MAX && !qcm_range_append_pending(s, &p)) {
        free(b);
        goto fail;
      }
    } else if (n == QCM_RANGE_TERMINAL_WIRE &&
               (!memcmp(b, "QRF1", 4) || !memcmp(b, "QRB1", 4))) {
      uint64_t reserve_idx = qcm_auth_get64(b + 4);
      size_t pending_index = qcm_range_find_reserve(s, reserve_idx);
      qcm_range_pending_t *p = pending_index == SIZE_MAX
                                   ? NULL
                                   : &s->pending[pending_index];
      if (!p || memcmp(p->grant.reserve_digest, b + 12, 32)) {
        free(b);
        goto fail;
      }
      uint8_t reqwire[QCM_RANGE_REQUEST_WIRE], reqdigest[32];
      qcm_range_encode_request(&p->request, reqwire);
      if (!qcm_range_digest(reqwire, sizeof(reqwire), reqdigest) ||
          memcmp(reqdigest, b + 44, 32)) {
        free(b);
        goto fail;
      }
      bool finalized = !memcmp(b, "QRF1", 4);
      if (p->pending_terminal &&
          (p->pending_finalized != finalized ||
           memcmp(p->pending_evidence_digest, b + 76, 32))) {
        free(b);
        goto fail;
      }
      if (!p->pending_terminal) {
        p->pending_terminal = true;
        p->pending_finalized = finalized;
        p->pending_terminal_index = i;
        memcpy(p->pending_evidence_digest, b + 76, 32);
      }
      bool newly_terminal = committed && !p->terminal;
      p->terminal = committed;
      p->finalized = finalized;
      p->decision.decision_index = p->pending_terminal_index;
      p->decision.grant_epoch = p->grant.grant_epoch;
      memcpy(p->decision.evidence_digest, p->pending_evidence_digest, 32);
      uint8_t canonical_terminal[QCM_RANGE_TERMINAL_WIRE];
      memcpy(canonical_terminal, b, sizeof(canonical_terminal));
      if (p->pending_terminal_index != i) {
        /* The original record in an inherited tail is at an earlier index;
         * its exact bytes are the authority reference for an idempotent retry.
         */
        uint8_t *original = NULL;
        size_t original_len = 0;
        if (!qcm_range_get_transaction(m, u, p->pending_terminal_index,
                                       p->pending_terminal_index > commit,
                                       &original, &original_len) ||
            original_len != QCM_RANGE_TERMINAL_WIRE) {
          free(original);
          free(b);
          goto fail;
        }
        memcpy(canonical_terminal, original, sizeof(canonical_terminal));
        free(original);
      }
      if (!qcm_range_digest(canonical_terminal, sizeof(canonical_terminal),
                            p->decision.decision_digest)) {
        free(b);
        goto fail;
      }
      /* Only committed terminal entries change the public owner map. */
      if (newly_terminal) {
        qcm_range_active_remove(s, pending_index);
      }
      if (committed && p->finalized)
        for (uint16_t k = 0; k < QIHSE_CONSENSUS_RANGE_SLOT_COUNT; k++)
          if (qcm_range_selected(p->request.slots, k)) {
            qihse_consensus_range_slot_t *dst = &s->slots[k];
            dst->epoch = p->grant.grant_epoch;
            snprintf(dst->owner_topology_id, sizeof(dst->owner_topology_id),
                     "%s", p->request.target_topology_id);
            snprintf(dst->owner_qkp_id, sizeof(dst->owner_qkp_id), "%s",
                     p->request.target_qkp_id);
            snprintf(dst->group_id, sizeof(dst->group_id), "%s",
                     p->request.target_group_id);
          }
    }
    free(b);
    s->last_index = i;
  }
  return true;
fail:
  free(s->pending);
  free(s->slots);
  free(s->transfer_index);
  free(s->reserve_index);
  free(s->active_by_slot);
  memset(s, 0, sizeof(*s));
  return false;
}

static void qcm_range_state_free(qcm_range_state_t *s) {
  free(s->pending);
  free(s->slots);
  free(s->transfer_index);
  free(s->reserve_index);
  free(s->active_by_slot);
  memset(s, 0, sizeof(*s));
}

static bool qcm_range_is_local_leader(qihse_consensus_mesh_t *mesh);
static bool qcm_range_forward(qihse_consensus_mesh_t *mesh,
                              const qihse_user_t *principal, uint8_t operation,
                              const uint8_t *payload, size_t payload_len,
                              uint32_t timeout_ms, uint64_t *out_index,
                              uint64_t *out_epoch, uint8_t out_digest[32]);

bool qihse_consensus_mesh_range_genesis_user(
    qihse_consensus_mesh_t *m, const qihse_user_t *u,
    const qihse_consensus_range_slot_t slots[QIHSE_CONSENSUS_RANGE_SLOT_COUNT],
    uint32_t timeout, uint64_t *out_index, uint8_t out_digest[32]) {
  if (out_index)
    *out_index = 0;
  if (!qcm_range_mesh_valid(m) || !slots || !timeout || !out_index ||
      !out_digest || !qcm_range_operator(u))
    return false;
  uint8_t *wire = malloc(QCM_RANGE_GENESIS_WIRE);
  if (!wire)
    return false;
  memcpy(wire, "QRG1", 4);
  bool ok = true;
  for (uint16_t i = 0; i < QIHSE_CONSENSUS_RANGE_SLOT_COUNT; i++) {
    if (!qcm_range_slot_valid(&slots[i], i)) {
      ok = false;
      break;
    }
    qcm_range_encode_slot(&slots[i],
                          wire + 4u + (size_t)i * QCM_RANGE_SLOT_WIRE);
  }
  if (ok)
    ok = qcm_range_digest(wire, QCM_RANGE_GENESIS_WIRE, out_digest);
  if (ok && !qcm_range_is_local_leader(m)) {
    size_t payload_len = QCM_RANGE_GENESIS_WIRE + 1u;
    uint8_t *payload = malloc(payload_len);
    if (!payload) {
      free(wire);
      return false;
    }
    payload[0] = 1u;
    memcpy(payload + 1u, wire, QCM_RANGE_GENESIS_WIRE);
    uint64_t committed = 0, ignored_epoch = 0;
    uint8_t ignored_digest[32];
    ok = qcm_range_forward(m, u, 1u, payload, payload_len, timeout, &committed,
                           &ignored_epoch, ignored_digest);
    free(payload);
    uint64_t verify_deadline = qcm_now_ms() + timeout;
    while (ok) {
      pthread_mutex_lock(&m->state_lock);
      qcm_range_state_t state;
      uint64_t local_commit = 0;
      ok = qcm_range_replay_locked(m, u, &state, &local_commit);
      bool verified = ok && state.initialized &&
                      !memcmp(state.genesis_digest, out_digest, 32) &&
                      local_commit >= committed;
      if (verified)
        *out_index = state.genesis_index;
      qcm_range_state_free(&state);
      pthread_mutex_unlock(&m->state_lock);
      if (verified)
        break;
      if (!ok || qcm_now_ms() >= verify_deadline) {
        ok = false;
        break;
      }
      struct timespec pause = {0, 5000000L};
      nanosleep(&pause, NULL);
    }
    free(wire);
    return ok;
  }
  pthread_mutex_lock(&m->proposal_lock);
  bool already = false;
  if (ok) {
    pthread_mutex_lock(&m->state_lock);
    qcm_range_state_t state;
    uint64_t c = 0;
    ok = qcm_range_replay_locked(m, u, &state, &c);
    if (ok && state.initialized) {
      if (memcmp(state.genesis_digest, out_digest, 32))
        ok = false;
      else {
        *out_index = state.genesis_index;
        already = state.genesis_index <= c;
      }
    }
    qcm_range_state_free(&state);
    pthread_mutex_unlock(&m->state_lock);
  }
  if (ok && !already) {
    pthread_mutex_lock(&m->state_lock);
    uint64_t gen = qihse_consensus_last_journal_generation(m->consensus);
    pthread_mutex_unlock(&m->state_lock);
    if (gen == UINT64_MAX)
      ok = false;
    else {
      qihse_hlc_t hlc = {0};
      hlc.physical_ms = qcm_now_ms();
      ok = qcm_mesh_propose_transaction_locked(m, u, gen + 1u, hlc, 0, 0, wire,
                                               QCM_RANGE_GENESIS_WIRE, timeout,
                                               timeout, out_index);
    }
  }
  pthread_mutex_unlock(&m->proposal_lock);
  free(wire);
  return ok;
}

bool qihse_consensus_mesh_range_state_user(
    qihse_consensus_mesh_t *m, const qihse_user_t *u,
    const uint8_t bitmap[QIHSE_CONSENSUS_RANGE_BITMAP_BYTES], uint32_t timeout,
    qihse_consensus_range_slot_t out_slots[QIHSE_CONSENSUS_RANGE_SLOT_COUNT],
    uint8_t out_digest[32], uint64_t *out_index) {
  if (out_index)
    *out_index = 0;
  if (out_digest)
    memset(out_digest, 0, 32);
  if (out_slots)
    memset(out_slots, 0, QIHSE_CONSENSUS_RANGE_SLOT_COUNT * sizeof(*out_slots));
  if (!qcm_range_mesh_valid(m) || !bitmap || !out_slots || !out_digest ||
      !out_index || !timeout || !qcm_range_operator(u))
    return false;
  pthread_mutex_lock(&m->state_lock);
  qcm_range_state_t s;
  uint64_t commit = 0;
  bool ok = qcm_range_replay_locked(m, u, &s, &commit) && s.initialized &&
            s.genesis_index <= commit && qcm_range_any(bitmap) &&
            qcm_range_digest_state(&s, bitmap, out_digest);
  if (ok) {
    for (uint16_t i = 0; i < QIHSE_CONSENSUS_RANGE_SLOT_COUNT; i++)
      if (qcm_range_selected(bitmap, i))
        out_slots[i] = s.slots[i];
      else
        memset(&out_slots[i], 0, sizeof(out_slots[i]));
    *out_index = commit;
  }
  qcm_range_state_free(&s);
  pthread_mutex_unlock(&m->state_lock);
  return ok;
}

bool qihse_consensus_mesh_range_reserve_user(
    qihse_consensus_mesh_t *m, const qihse_user_t *u,
    const qihse_consensus_range_request_t *request, uint32_t timeout,
    qihse_consensus_range_grant_t *out) {
  if (out)
    memset(out, 0, sizeof(*out));
  if (!qcm_range_mesh_valid(m) || !request || !out || !timeout ||
      !qcm_range_operator(u))
    return false;
  uint8_t encoded[QCM_RANGE_REQUEST_WIRE];
  qcm_range_encode_request(request, encoded);
  qihse_consensus_range_request_t checked;
  if (!qcm_range_decode_request(encoded, sizeof(encoded), &checked))
    return false;
  if (!qcm_range_is_local_leader(m)) {
    uint64_t idx = 0, epoch = 0;
    uint8_t digest[32];
    if (!qcm_range_forward(m, u, 2u, encoded, sizeof(encoded), timeout, &idx,
                           &epoch, digest))
      return false;
    uint64_t verify_deadline = qcm_now_ms() + timeout;
    bool forwarded = false;
    do {
      pthread_mutex_lock(&m->state_lock);
      qcm_range_state_t state;
      uint64_t commit = 0;
      forwarded =
          qcm_range_replay_locked(m, u, &state, &commit) && commit >= idx;
      if (forwarded) {
        size_t index = qcm_range_find_transfer(&state, request->transfer_id);
        forwarded = false;
        if (index != SIZE_MAX) {
          qcm_range_pending_t *p = &state.pending[index];
          uint8_t actual[QCM_RANGE_REQUEST_WIRE];
          qcm_range_encode_request(&p->request, actual);
          if (p->committed && p->grant.reserve_index == idx &&
              p->grant.grant_epoch == epoch &&
              !memcmp(p->grant.reserve_digest, digest, 32) &&
              !memcmp(actual, encoded, sizeof(actual))) {
            *out = p->grant;
            forwarded = true;
          }
        }
      }
      qcm_range_state_free(&state);
      pthread_mutex_unlock(&m->state_lock);
      if (forwarded || qcm_now_ms() >= verify_deadline)
        break;
      struct timespec pause = {0, 5000000L};
      nanosleep(&pause, NULL);
    } while (!forwarded);
    return forwarded;
  }
  uint8_t *tx = malloc(QCM_RANGE_RESERVE_WIRE);
  if (!tx)
    return false;
  memcpy(tx, "QRR1", 4);
  memcpy(tx + 4, encoded, sizeof(encoded));
  bool ok = false, do_propose = true;
  pthread_mutex_lock(&m->proposal_lock);
  pthread_mutex_lock(&m->state_lock);
  qcm_range_state_t s;
  uint64_t commit = 0;
  ok = qcm_range_replay_locked(m, u, &s, &commit) && s.initialized &&
       s.genesis_index <= commit;
  bool exact = false;
  qcm_range_pending_t *existing = NULL;
  if (ok) {
    size_t index = qcm_range_find_transfer(&s, request->transfer_id);
    if (index != SIZE_MAX)
      existing = &s.pending[index];
  }
  if (ok && existing) {
    uint8_t old[QCM_RANGE_REQUEST_WIRE];
    qcm_range_encode_request(&existing->request, old);
    ok = !memcmp(old, encoded, sizeof(old));
    if (ok) {
      exact = true;
      *out = existing->grant;
      qcm_range_put64(tx + 4 + sizeof(encoded), existing->grant.grant_epoch);
      if (existing->terminal)
        do_propose = false;
      else if (existing->committed)
        do_propose = false;
    }
  }
  if (ok && !exact) {
    uint8_t digest[32];
    ok = qcm_range_digest_state(&s, request->slots, digest) &&
         !memcmp(digest, request->expected_state_digest, 32);
  }
  uint64_t max_epoch = 0;
  for (uint16_t i = 0; ok && i < QIHSE_CONSENSUS_RANGE_SLOT_COUNT; i++)
    if (qcm_range_selected(request->slots, i)) {
      qihse_consensus_range_slot_t *slot = &s.slots[i];
      if (!exact &&
          (strcmp(slot->owner_topology_id, request->source_topology_id) ||
           strcmp(slot->owner_qkp_id, request->source_qkp_id) ||
           strcmp(slot->group_id, request->source_group_id)))
        ok = false;
      if (slot->epoch > max_epoch)
        max_epoch = slot->epoch;
    }
  for (uint16_t i = 0; ok && !exact && i < QIHSE_CONSENSUS_RANGE_SLOT_COUNT;
       ++i)
    if (qcm_range_selected(request->slots, i) && s.active_by_slot[i])
      ok = false;
  if (ok && !exact) {
    if (max_epoch == UINT64_MAX)
      ok = false;
    else
      qcm_range_put64(tx + 4 + sizeof(encoded), max_epoch + 1u);
  }
  qcm_range_state_free(&s);
  pthread_mutex_unlock(&m->state_lock);
  if (ok && do_propose) {
    uint64_t idx = 0;
    pthread_mutex_lock(&m->state_lock);
    uint64_t gen = qihse_consensus_last_journal_generation(m->consensus);
    pthread_mutex_unlock(&m->state_lock);
    if (gen == UINT64_MAX)
      ok = false;
    else {
      qihse_hlc_t hlc = {0};
      hlc.physical_ms = qcm_now_ms();
      ok = qcm_mesh_propose_transaction_locked(m, u, gen + 1u, hlc, 0, 0, tx,
                                               QCM_RANGE_RESERVE_WIRE, timeout,
                                               timeout, &idx);
    }
    if (ok) {
      pthread_mutex_lock(&m->state_lock);
      qcm_range_state_t after;
      uint64_t c = 0;
      ok = qcm_range_replay_locked(m, u, &after, &c);
      if (ok) {
        size_t index = qcm_range_find_transfer(&after, request->transfer_id);
        if (index == SIZE_MAX)
          ok = false;
        else
          *out = after.pending[index].grant;
      }
      qcm_range_state_free(&after);
      pthread_mutex_unlock(&m->state_lock);
    }
  }
  pthread_mutex_unlock(&m->proposal_lock);
  free(tx);
  return ok;
}

static bool qcm_range_terminal(qihse_consensus_mesh_t *m, const qihse_user_t *u,
                               const qihse_consensus_range_request_t *request,
                               const qihse_consensus_range_grant_t *grant,
                               const uint8_t evidence[32], uint32_t timeout,
                               bool finalize,
                               qihse_consensus_range_decision_t *out) {
  if (out)
    memset(out, 0, sizeof(*out));
  if (!qcm_range_mesh_valid(m) || !request || !grant || !evidence || !timeout ||
      !out || !qcm_range_operator(u))
    return false;
  uint8_t reqwire[QCM_RANGE_REQUEST_WIRE];
  qcm_range_encode_request(request, reqwire);
  if (!qcm_range_is_local_leader(m)) {
    uint8_t payload[1u + QCM_RANGE_REQUEST_WIRE + 72u + 32u];
    size_t pos = 0;
    payload[pos++] = finalize ? 3u : 4u;
    memcpy(payload + pos, reqwire, sizeof(reqwire));
    pos += sizeof(reqwire);
    qcm_auth_put64(payload + pos, grant->reserve_index);
    pos += 8;
    qcm_auth_put64(payload + pos, grant->grant_epoch);
    pos += 8;
    memcpy(payload + pos, grant->reserve_digest, 32);
    pos += 32;
    memcpy(payload + pos, evidence, 32);
    pos += 32;
    uint64_t idx = 0, epoch = 0;
    uint8_t digest[32];
    if (!qcm_range_forward(m, u, payload[0], payload, pos, timeout, &idx,
                           &epoch, digest))
      return false;
    uint64_t verify_deadline = qcm_now_ms() + timeout;
    bool ok = false;
    do {
      pthread_mutex_lock(&m->state_lock);
      qcm_range_state_t after;
      uint64_t commit = 0;
      bool replayed = qcm_range_replay_locked(m, u, &after, &commit);
      if (replayed && commit >= idx) {
        size_t index = qcm_range_find_transfer(&after, request->transfer_id);
        if (index != SIZE_MAX) {
          qcm_range_pending_t *p = &after.pending[index];
          if (p->decision.decision_index == idx &&
              p->decision.grant_epoch == epoch &&
              !memcmp(p->decision.decision_digest, digest, 32) &&
              p->finalized == finalize && p->terminal) {
            *out = p->decision;
            ok = true;
          }
        }
      }
      qcm_range_state_free(&after);
      pthread_mutex_unlock(&m->state_lock);
      if (ok || !replayed || qcm_now_ms() >= verify_deadline)
        break;
      struct timespec pause = {0, 5000000L};
      nanosleep(&pause, NULL);
    } while (!ok);
    return ok;
  }
  qcm_range_state_t s;
  bool ok;
  pthread_mutex_lock(&m->proposal_lock);
  pthread_mutex_lock(&m->state_lock);
  uint64_t commit = 0;
  ok = qcm_range_replay_locked(m, u, &s, &commit) && s.initialized &&
       s.genesis_index <= commit;
  qcm_range_pending_t *p = NULL;
  bool already = false;
  if (ok) {
    size_t index = qcm_range_find_transfer(&s, request->transfer_id);
    if (index != SIZE_MAX)
      p = &s.pending[index];
  }
  if (ok) {
    uint8_t stored[QCM_RANGE_REQUEST_WIRE];
    ok = p && p->grant.reserve_index == grant->reserve_index &&
         p->grant.grant_epoch == grant->grant_epoch &&
         !memcmp(p->grant.reserve_digest, grant->reserve_digest, 32);
    if (ok) {
      qcm_range_encode_request(&p->request, stored);
      ok = !memcmp(stored, reqwire, sizeof(stored));
    }
    if (ok && p->pending_terminal) {
      ok = (p->pending_finalized == finalize &&
            !memcmp(p->pending_evidence_digest, evidence, 32));
      if (ok && p->terminal) {
        *out = p->decision;
        already = true;
      }
    }
  }
  if (ok && !already && p->committed && !p->terminal) {
    for (uint16_t i = 0; i < QIHSE_CONSENSUS_RANGE_SLOT_COUNT; i++)
      if (qcm_range_selected(request->slots, i)) {
        qihse_consensus_range_slot_t *slot = &s.slots[i];
        if (strcmp(slot->owner_topology_id, request->source_topology_id) ||
            strcmp(slot->owner_qkp_id, request->source_qkp_id) ||
            strcmp(slot->group_id, request->source_group_id)) {
          ok = false;
          break;
        }
      }
  }
  qcm_range_state_free(&s);
  pthread_mutex_unlock(&m->state_lock);
  uint8_t tx[QCM_RANGE_TERMINAL_WIRE];
  if (ok && !already) {
    memcpy(tx, finalize ? "QRF1" : "QRB1", 4);
    qcm_auth_put64(tx + 4, grant->reserve_index);
    memcpy(tx + 12, grant->reserve_digest, 32);
    ok = qcm_range_digest(reqwire, sizeof(reqwire), tx + 44);
    memcpy(tx + 76, evidence, 32);
  }
  uint64_t idx = 0;
  if (ok && !already) {
    pthread_mutex_lock(&m->state_lock);
    uint64_t gen = qihse_consensus_last_journal_generation(m->consensus);
    pthread_mutex_unlock(&m->state_lock);
    if (gen == UINT64_MAX)
      ok = false;
    else {
      qihse_hlc_t hlc = {0};
      hlc.physical_ms = qcm_now_ms();
      ok = qcm_mesh_propose_transaction_locked(
          m, u, gen + 1u, hlc, 0, 0, tx, sizeof(tx), timeout, timeout, &idx);
    }
  }
  if (ok && !already) {
    pthread_mutex_lock(&m->state_lock);
    qcm_range_state_t after;
    uint64_t c = 0;
    ok = qcm_range_replay_locked(m, u, &after, &c);
    if (ok) {
      size_t index = qcm_range_find_transfer(&after, request->transfer_id);
      if (index == SIZE_MAX || !after.pending[index].terminal ||
          after.pending[index].finalized != finalize ||
          memcmp(after.pending[index].decision.evidence_digest, evidence, 32))
        ok = false;
      else
        *out = after.pending[index].decision;
    }
    qcm_range_state_free(&after);
    pthread_mutex_unlock(&m->state_lock);
  }
  pthread_mutex_unlock(&m->proposal_lock);
  return ok;
}

bool qihse_consensus_mesh_range_finalize_user(
    qihse_consensus_mesh_t *m, const qihse_user_t *u,
    const qihse_consensus_range_request_t *r,
    const qihse_consensus_range_grant_t *g, const uint8_t evidence[32],
    uint32_t timeout, qihse_consensus_range_decision_t *out) {
  return qcm_range_terminal(m, u, r, g, evidence, timeout, true, out);
}
bool qihse_consensus_mesh_range_abort_user(
    qihse_consensus_mesh_t *m, const qihse_user_t *u,
    const qihse_consensus_range_request_t *r,
    const qihse_consensus_range_grant_t *g, const uint8_t evidence[32],
    uint32_t timeout, qihse_consensus_range_decision_t *out) {
  return qcm_range_terminal(m, u, r, g, evidence, timeout, false, out);
}

bool qihse_consensus_mesh_range_lookup_user(
    qihse_consensus_mesh_t *m, const qihse_user_t *u, const char *transfer_id,
    qihse_consensus_range_request_t *request,
    qihse_consensus_range_grant_t *grant,
    qihse_consensus_range_decision_t *decision,
    qihse_consensus_range_phase_t *phase) {
  if (phase)
    *phase = QIHSE_RANGE_PHASE_NONE;
  if (request)
    memset(request, 0, sizeof(*request));
  if (grant)
    memset(grant, 0, sizeof(*grant));
  if (decision)
    memset(decision, 0, sizeof(*decision));
  if (!qcm_range_mesh_valid(m) || !transfer_id || !request || !grant ||
      !decision || !phase || !qcm_range_text(transfer_id, 65, false) ||
      !qcm_range_operator(u))
    return false;
  pthread_mutex_lock(&m->state_lock);
  qcm_range_state_t s;
  uint64_t commit = 0;
  bool ok = qcm_range_replay_locked(m, u, &s, &commit) && s.initialized &&
            s.genesis_index <= commit;
  if (ok) {
    size_t index = qcm_range_find_transfer(&s, transfer_id);
    if (index != SIZE_MAX && s.pending[index].committed) {
      *request = s.pending[index].request;
      *grant = s.pending[index].grant;
      if (s.pending[index].terminal)
        *decision = s.pending[index].decision;
      *phase = !s.pending[index].terminal
                   ? QIHSE_RANGE_PHASE_RESERVED
                   : (s.pending[index].finalized ? QIHSE_RANGE_PHASE_FINALIZED
                                                 : QIHSE_RANGE_PHASE_ABORTED);
    }
  }
  qcm_range_state_free(&s);
  pthread_mutex_unlock(&m->state_lock);
  return ok;
}

bool qihse_consensus_mesh_range_transition_user(
    qihse_consensus_mesh_t *m, const qihse_user_t *u, uint64_t decision_index,
    qihse_consensus_range_request_t *request,
    qihse_consensus_range_decision_t *decision) {
  if (request)
    memset(request, 0, sizeof(*request));
  if (decision)
    memset(decision, 0, sizeof(*decision));
  if (!qcm_range_mesh_valid(m) || !decision_index || !request || !decision ||
      !qcm_range_operator(u))
    return false;
  pthread_mutex_lock(&m->state_lock);
  qcm_range_state_t s;
  uint64_t commit = 0;
  bool ok = qcm_range_replay_locked(m, u, &s, &commit) && s.initialized &&
            s.genesis_index <= commit && decision_index <= commit;
  if (ok) {
    ok = false;
    for (size_t i = 0; i < s.pending_count; i++)
      if (s.pending[i].terminal && s.pending[i].committed &&
          s.pending[i].decision.decision_index == decision_index) {
        *request = s.pending[i].request;
        *decision = s.pending[i].decision;
        ok = true;
        break;
      }
  }
  qcm_range_state_free(&s);
  pthread_mutex_unlock(&m->state_lock);
  return ok;
}

bool qihse_consensus_mesh_range_group_transition_user(
    qihse_consensus_mesh_t *m, const qihse_user_t *u, const char *group_id,
    qihse_consensus_range_request_t *request,
    qihse_consensus_range_decision_t *decision, bool *found) {
  if (request)
    memset(request, 0, sizeof(*request));
  if (decision)
    memset(decision, 0, sizeof(*decision));
  if (found)
    *found = false;
  if (!qcm_range_mesh_valid(m) || !group_id || !request || !decision ||
      !found || !qcm_range_lower_hex(group_id, 64) || !qcm_range_operator(u))
    return false;

  pthread_mutex_lock(&m->state_lock);
  qcm_range_state_t s;
  uint64_t commit = 0;
  bool ok = qcm_range_replay_locked(m, u, &s, &commit) && s.initialized &&
            s.genesis_index <= commit;
  qihse_consensus_range_request_t latest_request = {0};
  qihse_consensus_range_decision_t latest_decision = {0};
  uint64_t latest_index = 0;
  if (ok) {
    for (size_t i = 0; i < s.pending_count; ++i) {
      const qcm_range_pending_t *p = &s.pending[i];
      if (!p->committed || !p->terminal || !p->finalized ||
          p->request.op != QIHSE_RANGE_OP_PROMOTION ||
          p->decision.decision_index > commit ||
          p->decision.decision_index <= latest_index ||
          strcmp(p->request.source_group_id, group_id) ||
          strcmp(p->request.target_group_id, group_id))
        continue;
      latest_request = p->request;
      latest_decision = p->decision;
      latest_index = p->decision.decision_index;
    }
    if (latest_index) {
      *request = latest_request;
      *decision = latest_decision;
      *found = true;
    }
  }
  qcm_range_state_free(&s);
  pthread_mutex_unlock(&m->state_lock);
  if (!ok) {
    memset(request, 0, sizeof(*request));
    memset(decision, 0, sizeof(*decision));
    *found = false;
  }
  return ok;
}

#define QCM_RANGE_FORWARD_HEADER 153u
#define QCM_RANGE_FORWARD_REPLY 53u
#define QCM_RANGE_CHUNK_HEADER 16u

static bool qcm_range_is_local_leader(qihse_consensus_mesh_t *mesh) {
  if (!mesh || !mesh->started)
    return false;
  pthread_mutex_lock(&mesh->state_lock);
  bool local = qihse_consensus_role(mesh->consensus) == QIHSE_CONSENSUS_LEADER;
  pthread_mutex_unlock(&mesh->state_lock);
  return local;
}

static bool qcm_range_read_exact(qihse_qkp_session_t *session, int fd,
                                 void *out, size_t n) {
  uint8_t *p = out;
  size_t done = 0;
  while (done < n) {
    ssize_t got = qihse_qkp_recv_sealed(session, fd, p + done, n - done);
    if (got <= 0)
      return false;
    done += (size_t)got;
  }
  return true;
}

static bool qcm_range_receive(qcm_rx_ctx_t *ctx, const uint8_t *wire,
                              size_t size) {
  qihse_consensus_mesh_t *m = ctx->mesh;
  uint8_t group_hash[32], digest[32], reply[QCM_RANGE_FORWARD_REPLY] = {0};
  memcpy(reply, "QRR2", 4);
  if (size != QCM_RANGE_FORWARD_HEADER ||
      !m->consensus_config.writer_epoch_floor ||
      !qcm_range_operator(m->principal) || memcmp(wire, "QRF2", 4) ||
      memcmp(wire + 4, m->consensus_config.history_id, 32) ||
      qcm_auth_get64(wire + 36) != m->consensus_config.writer_epoch_floor ||
      !qcm_sha256(m->consensus_config.group_id,
                  strlen(m->consensus_config.group_id), group_hash) ||
      memcmp(wire + 44, group_hash, 32) ||
      memcmp(wire + 76, m->peers[ctx->peer_index].uuid.bytes, 16) ||
      memcmp(wire + 92, m->consensus_config.self.bytes, 16) ||
      !qcm_authority_voter(m, &m->peers[ctx->peer_index].uuid)) {
    qcm_debug("range forward header rejected (size=%zu op=%u peer=%zu)", size,
              size > 112u ? (unsigned)wire[112] : 0u, ctx->peer_index);
    return false;
  }
  uint32_t timeout = ((uint32_t)wire[108] << 24) | ((uint32_t)wire[109] << 16) |
                     ((uint32_t)wire[110] << 8) | wire[111];
  uint8_t operation = wire[112];
  uint64_t length = qcm_auth_get64(wire + 113);
  if (!timeout || timeout > 30000u || length > QIHSE_BLOB_MAX_SIZE ||
      (operation < 1u || operation > 4u))
    return false;
  struct timeval tv = {(time_t)(timeout / 1000u),
                       (suseconds_t)((timeout % 1000u) * 1000u)};
  (void)setsockopt(ctx->fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
  uint8_t *payload = malloc(length ? (size_t)length : 1u);
  if (!payload)
    return false;
  size_t copied = 0;
  bool ok = true;
  while (copied < (size_t)length) {
    uint8_t chunk[QIHSE_QKP_MAX_PAYLOAD];
    ssize_t got =
        qihse_qkp_recv_sealed(ctx->session, ctx->fd, chunk, sizeof(chunk));
    if (got < (ssize_t)QCM_RANGE_CHUNK_HEADER || memcmp(chunk, "QRC2", 4)) {
      ok = false;
      break;
    }
    uint64_t offset = qcm_auth_get64(chunk + 4);
    uint32_t amount = ((uint32_t)chunk[12] << 24) |
                      ((uint32_t)chunk[13] << 16) | ((uint32_t)chunk[14] << 8) |
                      chunk[15];
    if (offset != copied ||
        amount != (uint32_t)((size_t)got - QCM_RANGE_CHUNK_HEADER) || !amount ||
        amount > (size_t)length - copied) {
      ok = false;
      break;
    }
    memcpy(payload + copied, chunk + QCM_RANGE_CHUNK_HEADER, amount);
    copied += amount;
  }
  uint8_t end[44];
  if (ok)
    ok = qcm_range_read_exact(ctx->session, ctx->fd, end, sizeof(end)) &&
         !memcmp(end, "QRE2", 4) && qcm_auth_get64(end + 4) == length &&
         qcm_range_digest(payload, (size_t)length, digest) &&
         !memcmp(digest, wire + 121, 32) && !memcmp(end + 12, digest, 32);
  uint64_t index = 0, epoch = 0;
  uint8_t result_digest[32] = {0};
  if (ok && operation == 1u && length == QCM_RANGE_GENESIS_WIRE + 1u &&
      payload[0] == 1u && !memcmp(payload + 1, "QRG1", 4)) {
    qihse_consensus_range_slot_t *slots =
        calloc(QIHSE_CONSENSUS_RANGE_SLOT_COUNT, sizeof(*slots));
    if (!slots)
      ok = false;
    for (uint16_t i = 0; ok && i < QIHSE_CONSENSUS_RANGE_SLOT_COUNT; i++)
      if (!qcm_range_decode_slot(payload + 5u + (size_t)i * QCM_RANGE_SLOT_WIRE,
                                 &slots[i], i))
        ok = false;
    if (ok)
      ok = qihse_consensus_mesh_range_genesis_user(
          m, m->principal, slots, timeout, &index, result_digest);
    free(slots);
  } else if (ok && operation == 2u && length == QCM_RANGE_REQUEST_WIRE) {
    qihse_consensus_range_request_t request;
    qihse_consensus_range_grant_t grant;
    ok = qcm_range_decode_request(payload, (size_t)length, &request) &&
         qihse_consensus_mesh_range_reserve_user(m, m->principal, &request,
                                                 timeout, &grant);
    if (ok) {
      index = grant.reserve_index;
      epoch = grant.grant_epoch;
      memcpy(result_digest, grant.reserve_digest, 32);
    }
  } else if (ok && (operation == 3u || operation == 4u) &&
             length == 1u + QCM_RANGE_REQUEST_WIRE + 80u &&
             payload[0] == operation) {
    qihse_consensus_range_request_t request;
    qihse_consensus_range_grant_t grant;
    qihse_consensus_range_decision_t decision;
    ok =
        qcm_range_decode_request(payload + 1, QCM_RANGE_REQUEST_WIRE, &request);
    size_t off = 1u + QCM_RANGE_REQUEST_WIRE;
    if (ok) {
      grant.reserve_index = qcm_auth_get64(payload + off);
      off += 8;
      grant.grant_epoch = qcm_auth_get64(payload + off);
      off += 8;
      memcpy(grant.reserve_digest, payload + off, 32);
      off += 32;
    }
    if (ok)
      ok = (operation == 3u) ? qihse_consensus_mesh_range_finalize_user(
                                   m, m->principal, &request, &grant,
                                   payload + off, timeout, &decision)
                             : qihse_consensus_mesh_range_abort_user(
                                   m, m->principal, &request, &grant,
                                   payload + off, timeout, &decision);
    if (ok) {
      index = decision.decision_index;
      epoch = decision.grant_epoch;
      memcpy(result_digest, decision.decision_digest, 32);
    }
  } else
    ok = false;
  qcm_debug("range forward operation %u %s at index %llu", operation,
            ok ? "committed" : "failed", (unsigned long long)index);
  free(payload);
  reply[4] = ok ? 1u : 0u;
  qcm_auth_put64(reply + 5, index);
  qcm_auth_put64(reply + 13, epoch);
  memcpy(reply + 21, result_digest, 32);
  return qihse_qkp_send_sealed(ctx->session, ctx->fd, reply, sizeof(reply));
}

static bool qcm_range_forward(qihse_consensus_mesh_t *m,
                              const qihse_user_t *principal, uint8_t operation,
                              const uint8_t *payload, size_t payload_len,
                              uint32_t timeout_ms, uint64_t *out_index,
                              uint64_t *out_epoch, uint8_t out_digest[32]) {
  if (out_index)
    *out_index = 0;
  if (out_epoch)
    *out_epoch = 0;
  if (!qcm_range_mesh_valid(m) || !payload || !payload_len ||
      payload_len > QIHSE_BLOB_MAX_SIZE || !timeout_ms || timeout_ms > 30000u ||
      !out_index || !out_epoch || !out_digest ||
      !qcm_range_operator(principal) || operation < 1u || operation > 4u)
    return false;
  uint64_t deadline = qcm_now_ms() + timeout_ms;
  qihse_uuid_t leader;
  pthread_mutex_lock(&m->state_lock);
  bool known = qihse_consensus_leader_id(m->consensus, &leader);
  pthread_mutex_unlock(&m->state_lock);
  if (!known) {
    qcm_debug("range forward operation %u has no known leader", operation);
    return false;
  }
  int peer = qcm_peer_index(m, &leader);
  if (peer < 0 || !qcm_authority_voter(m, &leader)) {
    qcm_debug("range forward operation %u leader unavailable/voter denied",
              operation);
    return false;
  }
  int fd = qcm_connect(m->peers[peer].ipv4, m->peers[peer].port);
  if (fd < 0) {
    qcm_debug("range forward operation %u connect failed: %s", operation,
              strerror(errno));
    return false;
  }
  int cancel[2];
  if (pipe(cancel) != 0) {
    close(fd);
    return false;
  }
  qcm_authority_guard_t guard = {fd, cancel[0], deadline};
  pthread_t thread;
  if (pthread_create(&thread, NULL, qcm_authority_deadline, &guard) != 0) {
    close(cancel[0]);
    close(cancel[1]);
    close(fd);
    return false;
  }
  struct timeval tv = {(time_t)(timeout_ms / 1000u),
                       (suseconds_t)((timeout_ms % 1000u) * 1000u)};
  (void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
  (void)setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
  qihse_qkp_session_t *session = NULL;
  bool ok = qihse_qkp_client_negotiate(fd, &m->qkp_config, &session) ==
                QIHSE_QKP_SECURE &&
            session &&
            qihse_qkp_client_session_is_replication_peer(
                session, m->peers[peer].node_id, m->peers[peer].public_key);
  qihse_consensus_channel_config_t channel = qcm_channel(m, (size_t)peer);
  uint8_t header[QCM_RANGE_FORWARD_HEADER] = {0};
  memcpy(header, "QRF2", 4);
  memcpy(header + 4, m->consensus_config.history_id, 32);
  qcm_auth_put64(header + 36, m->consensus_config.writer_epoch_floor);
  ok = ok && qcm_sha256(m->consensus_config.group_id,
                        strlen(m->consensus_config.group_id), header + 44);
  memcpy(header + 76, m->consensus_config.self.bytes, 16);
  memcpy(header + 92, leader.bytes, 16);
  header[108] = (uint8_t)(timeout_ms >> 24);
  header[109] = (uint8_t)(timeout_ms >> 16);
  header[110] = (uint8_t)(timeout_ms >> 8);
  header[111] = (uint8_t)timeout_ms;
  header[112] = operation;
  qcm_auth_put64(header + 113, (uint64_t)payload_len);
  uint8_t digest[32];
  ok = ok && qcm_range_digest(payload, payload_len, digest);
  if (ok)
    memcpy(header + 121, digest, 32);
  ok = ok &&
       qihse_consensus_channel_send_hello(session, fd, &channel, principal) &&
       qihse_qkp_send_sealed(session, fd, header, sizeof(header));
  size_t offset = 0;
  while (ok && offset < payload_len) {
    size_t amount = payload_len - offset;
    if (amount > QIHSE_QKP_MAX_PAYLOAD - QCM_RANGE_CHUNK_HEADER)
      amount = QIHSE_QKP_MAX_PAYLOAD - QCM_RANGE_CHUNK_HEADER;
    uint8_t chunk[QIHSE_QKP_MAX_PAYLOAD];
    memcpy(chunk, "QRC2", 4);
    qcm_auth_put64(chunk + 4, offset);
    chunk[12] = (uint8_t)(amount >> 24);
    chunk[13] = (uint8_t)(amount >> 16);
    chunk[14] = (uint8_t)(amount >> 8);
    chunk[15] = (uint8_t)amount;
    memcpy(chunk + QCM_RANGE_CHUNK_HEADER, payload + offset, amount);
    ok = qihse_qkp_send_sealed(session, fd, chunk,
                               QCM_RANGE_CHUNK_HEADER + amount);
    offset += amount;
  }
  uint8_t end[44] = {0};
  memcpy(end, "QRE2", 4);
  qcm_auth_put64(end + 4, payload_len);
  memcpy(end + 12, digest, 32);
  ok = ok && qihse_qkp_send_sealed(session, fd, end, sizeof(end));
  uint8_t reply[QCM_RANGE_FORWARD_REPLY];
  ok = ok && qcm_range_read_exact(session, fd, reply, sizeof(reply)) &&
       !memcmp(reply, "QRR2", 4) && reply[4] == 1u;
  if (ok) {
    *out_index = qcm_auth_get64(reply + 5);
    *out_epoch = qcm_auth_get64(reply + 13);
    memcpy(out_digest, reply + 21, 32);
    ok = *out_index > 0;
  }
    qcm_debug("range forward operation %u %s; remote index %llu", operation,
              ok ? "verified reply" : "failed", (unsigned long long)*out_index);
    close(cancel[1]);
  (void)pthread_join(thread, NULL);
  close(cancel[0]);
  if (session)
    qihse_qkp_session_free(session);
  close(fd);
  return ok;
}
