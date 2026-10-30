#include "qihse_consensus_mesh.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
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
    unsigned int test_stage_ack_drops[QIHSE_CONSENSUS_MESH_MAX_PEERS];
    unsigned int test_stage_ack_drops_consumed;
    unsigned int test_snapshot_ack_drops[QIHSE_CONSENSUS_MESH_MAX_PEERS];
    unsigned int test_snapshot_ack_drops_consumed;
#endif
};

#ifdef QIHSE_CONSENSUS_MESH_TESTING
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
    if (mesh->rx_active) mesh->rx_active--;
    pthread_cond_broadcast(&mesh->rx_changed);
    pthread_mutex_unlock(&mesh->queue_lock);
    if (ctx->session) qihse_qkp_session_free(ctx->session);
    if (ctx->fd >= 0) close(ctx->fd);
    free(ctx);
}

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
        if (mesh->peers[pi].rx_fd >= 0 || qcm_stopping(mesh)) {
            pthread_mutex_unlock(&mesh->queue_lock);
            qihse_qkp_session_free(session); close(fd); free(ctx); continue;
        }
        mesh->peers[pi].rx_fd = fd;
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
    if (!mesh || !out_index) return false;
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
